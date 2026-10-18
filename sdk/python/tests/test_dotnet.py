""".NET assemblies (api_minor 94, feature "dotnet"; docs/bytecode-lifting.md): a class
library built by the dotnet SDK here (skipped without it) is recognised by its CLR
header, imported without code analysis (its code is IL, not x86), and says so in
ProgramInfo.dotnet, the import's warnings, Program.dotnet() and MCP's program_summary.
The file browser names it too (content kind "dotnet:il")."""

import json
import os
import shutil
import subprocess

import pytest

from revkit import Client, Daemon


@pytest.fixture(scope="module")
def assembly(tmp_path_factory):
    if not shutil.which("dotnet"):
        pytest.skip("no dotnet SDK")
    d = tmp_path_factory.mktemp("dotnet")
    (d / "lib.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                                  '<TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>\n')
    (d / "A.cs").write_text("public class A { public int Add(int a, int b) => a + b; "
                            "public string Hello(string n) => \"hi \" + n.Length; }\n")
    env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1", DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1")
    r = subprocess.run(["dotnet", "build", "-c", "Release", "-o", "out", "--disable-build-servers", "-nodeReuse:false",
                        "-p:UseSharedCompilation=false"], cwd=d, env=env, capture_output=True, timeout=300)
    if r.returncode != 0:
        pytest.skip("dotnet build failed: " + r.stdout.decode(errors="replace")[-400:])
    return d / "out" / "lib.dll"


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_il_only_assembly(image_daemon, assembly):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as rk:
        info = rk.server_info()
        assert "dotnet" in info.features and info.api_minor >= 94
        r = rk.import_program("default", path=str(assembly), name="lib.dll")
        d = r.program.dotnet
        assert r.program.format == "pe" and r.program.HasField("dotnet")
        assert d.il_only and not d.mixed_mode and d.code_analysis_skipped
        assert d.metadata_version == "v4.0.30319" and d.runtime_version == "2.5"
        assert "#~" in d.streams and "#Strings" in d.streams
        assert d.description.startswith("IL-only .NET assembly, metadata v4.0.30319")
        assert any("imported without code analysis" in w for w in r.warnings), r.warnings
        p = rk.program(r.program.program_id)
        assert p.dotnet().il_only
        # No IL decoded as x86: no functions at all.
        assert list(p.functions()) == []
        # Listed in the project with the same summary.
        listed = [x for x in rk.programs("default") if x.program_id == r.program.program_id]
        assert listed and listed[0].dotnet.il_only


def test_filesystem_names_it(image_daemon, assembly):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=120) as rk:
        with rk.open_filesystem("default", host_path=str(assembly.parent)) as fs:
            e = next(x for x in fs.entries("/", detect=True) if x.name == "lib.dll")
            assert e.detected_kind == "pe" and e.content_kind == "dotnet:il"
            assert ".NET assembly (IL-only" in e.detected


def test_mcp_summary(image_daemon, assembly):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-dotnet")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                res = await mcp.call_tool(tool, args)
                assert not res.is_error, res
                return json.loads(res.content[0].text)

            r = await call("import_program", project_id="default", path=str(assembly), name="mcp-lib.dll")
            s = await call("program_summary", program_id=r["program"]["program_id"])
            assert s["dotnet"]["il_only"] and s["dotnet"]["code_analysis_skipped"]
            assert s["dotnet"]["metadata_version"] == "v4.0.30319"
            assert s["function_count"] == 0

    anyio.run(run)
