"""External decompilers (api_minor 92, feature "external-decompilers";
docs/providers.md) through the SDK and MCP: the providers and the sandbox,
ILSpy on a .NET class library imported as a program (built here with
dotnet when the SDK is installed), a JVM decompiler on a jar inside a zip
opened as a file system (built here with javac), the cache, reading the
output's files, and the settings. Each part skips when its tool isn't
installed."""

import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from revkit import Client, Daemon, InvalidArgument, NotFound
from revkit.v1 import provider_pb2

NAMES = {"ilspy", "jadx", "vineflower", "cfr", "unluac", "pycdc", "webcrack", "wasm-decompile"}


@pytest.fixture(scope="module")
def daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture(scope="module")
def dotnet_dll(tmp_path_factory):
    if not shutil.which("dotnet"):
        pytest.skip("no .NET SDK")
    d = tmp_path_factory.mktemp("dotnet")
    env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1")
    subprocess.run(["dotnet", "new", "classlib", "-n", "Tiny", "-o", str(d / "Tiny"), "--force"], env=env, check=True,
                   capture_output=True)
    (d / "Tiny" / "Class1.cs").write_text(
        "namespace Tiny;\npublic class Calc {\n"
        "  public static int Add(int a, int b) { int c = a + b; if (c > 10) c -= 3; return c * 2; }\n"
        "  public static string Hello(string n) => \"hi \" + n.Length;\n}\n"
        "public class Other { public int Twice(int x) => x * 2; }\n")
    subprocess.run(["dotnet", "build", "-c", "Release", "-o", str(d / "out")], cwd=d / "Tiny", env=env, check=True,
                   capture_output=True)
    return d / "out" / "Tiny.dll"


@pytest.fixture(scope="module")
def jar_zip(tmp_path_factory):
    if not shutil.which("javac") or not shutil.which("jar"):
        pytest.skip("no JDK")
    d = tmp_path_factory.mktemp("java")
    (d / "src" / "tiny").mkdir(parents=True)
    (d / "src" / "tiny" / "Tiny.java").write_text(
        "package tiny;\npublic class Tiny {\n"
        "  public static int add(int a, int b) { int c = a + b; if (c > 10) c -= 3; return c * 2; }\n}\n")
    subprocess.run(["javac", "--release", "8", "-nowarn", "-d", str(d / "classes"), str(d / "src/tiny/Tiny.java")],
                   check=True, capture_output=True)
    subprocess.run(["jar", "cf", str(d / "tiny.jar"), "tiny/Tiny.class"], cwd=d / "classes", check=True)
    with zipfile.ZipFile(d / "bundle.zip", "w") as z:
        z.write(d / "tiny.jar", "lib/tiny.jar")
        z.writestr("readme.txt", "not bytecode\n")
    return d / "bundle.zip"


def _mcp(target, calls):  # [(tool, args)] in order
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server
    server = create_server(target, agent="claude", agent_version="test", session="mcp-providers")

    async def run():
        out = []
        async with mcp_client.Client(server) as mcp:
            for name, args in calls:
                res = await mcp.call_tool(name, args)
                out.append(json.loads(res.content[0].text))
        return out

    return anyio.run(run)


def _available(rk, name):
    p = next(p for p in rk.providers().providers if p.name == name)
    return p.available, p.reason


def test_providers_and_the_sandbox(daemon):
    with Client(daemon.grpc_target) as rk:
        assert "external-decompilers" in rk.server_info().features
        r = rk.providers()
        assert {p.name for p in r.providers} == NAMES
        ilspy = next(p for p in r.providers if p.name == "ilspy")
        assert ilspy.license == "MIT" and list(ilspy.kinds) == ["dotnet"] and ilspy.output == "tree"
        assert ilspy.language == "csharp"
        for p in r.providers:
            assert p.available or p.reason, p
        assert "seccomp" in r.sandbox, r.sandbox
        assert r.limits.timeout_seconds == 120 and r.limits.memory_bytes == 4 << 30


def test_ilspy_on_a_program(daemon, dotnet_dll):
    with Client(daemon.grpc_target) as rk:
        ok, why = _available(rk, "ilspy")
        if not ok:
            pytest.skip(f"ilspycmd: {why}")
        prog = rk.program(rk.import_program("default", path=str(dotnet_dll), name="Tiny.dll").program.program_id)
        info = prog.providers()
        assert info.input_kind.kind == "dotnet" and info.default_provider == "ilspy"
        assert list(info.applicable) == ["ilspy"] and not info.cached
        ext = prog.decompile_external()
        assert ext.ok, (ext.status, ext.response.detail, ext.response.stderr_tail)
        assert ext.provider == "ilspy" and ext.version and not ext.cached
        assert ext.response.language == "csharp" and ext.response.output == "tree"
        cs = dict(ext.sources())
        text = "\n".join(cs.values())
        assert "public static int Add(int a, int b)" in text and 'return "hi " + n.Length;' in text, text
        assert "public int Twice(int x)" in text
        assert ext.main_file.endswith(".cs") and ext.text() in cs.values()
        # Again: from the cache, and ListProviders says so.
        again = prog.decompile_external()
        assert again.cached and again.files == ext.files
        assert list(prog.providers().cached) == ["ilspy"]
        # Every file reads back; one that isn't there doesn't.
        for f in ext.response.files:
            assert len(ext.read(f.path)) == f.size
        with pytest.raises(NotFound):
            ext.read("../result")
        # A provider that doesn't take .NET.
        with pytest.raises(InvalidArgument):
            prog.decompile_external(provider="no-such-decompiler")
        with pytest.raises(InvalidArgument):  # jadx doesn't take .NET
            prog.decompile_external(provider="jadx")

        list_out, dec, read = _mcp(daemon.grpc_target, [
            ("list_providers", {"program_id": prog.id}),
            ("decompile_external", {"program_id": prog.id, "max_chars": 100000}),
            ("read_provider_output", {"program_id": prog.id, "file": ext.files[-1], "max_chars": 50}),
        ])
        assert list_out["input_kind"] == "dotnet" and list_out["default_provider"] == "ilspy", list_out
        assert dec["status"] == "ok" and dec["cached"] and dec["provider"] == "ilspy", dec
        assert dec["main_file"] == ext.main_file and dec["main_text"] == ext.text()
        assert read["file"] == ext.files[-1] and len(read["text"]) <= 50


def test_a_jar_inside_a_zip(daemon, jar_zip):
    with Client(daemon.grpc_target) as rk:
        r = rk.providers()
        java = [p.name for p in r.providers if p.name in ("vineflower", "cfr", "jadx") and p.available]
        if not java:
            pytest.skip("no JVM decompiler installed")
        with rk.open_filesystem("default", file=str(jar_zip)) as fs:
            info = fs.providers("/lib/tiny.jar")
            assert info.input_kind.kind == "jar"
            assert list(info.applicable) == ["vineflower", "cfr", "jadx"]
            assert info.default_provider == next(n for n in info.applicable if n in java)
            assert fs.providers("/readme.txt").input_kind.kind == ""
            with pytest.raises(Exception):
                fs.decompile_external("/readme.txt")
            for name in java:
                ext = fs.decompile_external("/lib/tiny.jar", provider=name)
                assert ext.ok, (name, ext.response.detail, ext.response.stderr_tail)
                text = "\n".join(t for _, t in ext.sources())
                assert "add(int" in text, (name, text)

    # MCP, over a file system session of its own.
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server
    server = create_server(daemon.grpc_target, agent="claude", agent_version="test", session="mcp-providers-fs")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(name, **args):
                return json.loads((await mcp.call_tool(name, args)).content[0].text)
            opened = await call("open_filesystem", project_id="default", file=str(jar_zip))
            listed = await call("list_providers", session_id=opened["session_id"], path="/lib/tiny.jar")
            dec = await call("decompile_external", session_id=opened["session_id"], path="/lib/tiny.jar")
            await call("close_filesystem", session_id=opened["session_id"])
            return listed, dec

    listed, dec = anyio.run(run)
    assert listed["input_kind"] == "jar" and listed["applicable"] == ["vineflower", "cfr", "jadx"], listed
    assert dec["status"] == "ok" and "add(int" in dec["main_text"], dec


def test_settings(daemon):
    with Client(daemon.grpc_target) as rk:
        before = rk.provider_settings()
        assert before.settings.enabled and before.cache_dir
        s = provider_pb2.ProviderSettings()
        s.CopyFrom(before.settings)
        s.providers.add(name="ilspy", disabled=True)
        s.timeout_seconds = 60
        after = rk.set_provider_settings(s)
        ilspy = next(p for p in after.providers if p.name == "ilspy")
        assert ilspy.disabled and not ilspy.available and "turned off" in ilspy.reason
        assert after.settings.timeout_seconds == 60
        assert rk.providers().limits.timeout_seconds == 60
        bad = provider_pb2.ProviderSettings(enabled=True)
        bad.providers.add(name="no-such-decompiler")
        with pytest.raises(InvalidArgument):
            rk.set_provider_settings(bad)
        rel = provider_pb2.ProviderSettings(enabled=True, java_path="java")
        with pytest.raises(InvalidArgument):
            rk.set_provider_settings(rel)
        rk.set_provider_settings(before.settings)
        assert not next(p for p in rk.providers().providers if p.name == "ilspy").disabled
