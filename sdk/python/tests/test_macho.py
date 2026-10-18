"""Mach-O through the Python SDK and MCP (api_minor 90, feature "macho", and 91, "objc";
docs/macho.md), on tests/data/macho's fixtures built with clang and
ld64.lld (skipped without them): a universal file's default slice and
another by program_file, and the Mach-O summary."""

import json
import pathlib
import shutil
import subprocess

import pytest

from revkit import Client, Daemon

FIXTURE = pathlib.Path(__file__).resolve().parents[3] / "tests" / "data" / "macho"


def _tool(*names):
    for n in names:
        if shutil.which(n):
            return shutil.which(n)
    return None


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    tools = [_tool("clang"), _tool("ld64.lld", "ld64.lld-18"), _tool("llvm-lipo", "llvm-lipo-18"),
             _tool("llvm-nm", "llvm-nm-18"), _tool("llvm-objdump", "llvm-objdump-18")]
    if not all(tools):
        pytest.skip("no clang, ld64.lld or llvm tools")
    d = tmp_path_factory.mktemp("macho")
    subprocess.run(["sh", str(FIXTURE / "build.sh"), *tools, str(d)], check=True, capture_output=True)
    return d


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_feature(image_daemon):
    with Client(image_daemon.grpc_target) as rk:
        info = rk.server_info()
        assert "macho" in info.features and info.api_minor >= 90


def test_universal_slices(image_daemon, fixtures):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as rk:
        fat = rk.import_program("default", path=str(fixtures / "hello-fat"), name="hello-fat")
        assert fat.program.format == "macho"
        assert fat.program.macho_slice == "arm64"
        assert list(fat.program.macho_slices) == ["x86_64", "arm64"]
        m = rk.program(fat.program.program_id).macho()
        assert m.arch == "arm64" and m.file_type == "execute" and m.platform == "macos"
        assert [s.arch for s in m.slices] == ["x86_64", "arm64"] and m.slice_index == 1
        assert len(m.uuid) == 36 and m.code_signed and not m.encrypted
        assert m.dylibs[0].name == "/usr/lib/libSystem.B.dylib"

        x86 = rk.import_program("default", program_file=fat.program.program_id, macho_slice="x86_64")
        assert x86.program.macho_slice == "x86_64" and x86.program.language_id == "x86:LE:64:default"
        names = {f.name for f in rk.program(x86.program.program_id).functions()}
        assert {"_main", "_add", "_printf"} <= names

        # A thin file has no slices; an ELF no Mach-O summary.
        thin = rk.import_program("default", path=str(fixtures / "hello-arm64-chained"))
        assert thin.program.macho_slice == "" and not thin.program.macho_slices
        assert rk.program(thin.program.program_id).macho().fixups == "chained"


def test_mcp_summary(image_daemon, fixtures):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-macho")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                res = await mcp.call_tool(tool, args)
                assert not res.is_error, res
                return json.loads(res.content[0].text)

            r = await call("import_program", project_id="default", path=str(fixtures / "hello-fat"), name="mcp-fat",
                           macho_slice="x86_64")
            pid = r["program"]["program_id"]
            s = await call("program_summary", program_id=pid)
            assert s["language"] == "x86:LE:64:default"
            assert s["macho"]["arch"] == "x86_64" and s["macho"]["slices"] == ["x86_64", "arm64"]
            assert s["macho"]["slice"] == "x86_64" and s["macho"]["dylibs"][0]["kind"] == "load"
            objc = await call("import_program", project_id="default", path=str(fixtures / "objc-arm64"), name="mcp-objc")
            c = await call("list_objc_classes", program_id=objc["program"]["program_id"], name_contains="point")
            assert [x["name"] for x in c["classes"]] == ["Point"] and c["total"] == 1
            assert c["classes"][0]["methods"][4] == {"selector": "diff", "types": "i16@0:8", "class_method": False,
                                                     "category": "Extra", "address": c["classes"][0]["methods"][4]["address"],
                                                     "function": "-[Point(Extra) diff]"}
            assert c["protocols"] == []  # the filter is on names
            every = await call("list_objc_classes", program_id=objc["program"]["program_id"])
            assert every["protocols"] == [{"name": "Named", "methods": ["name"]}] and every["total"] == 2

    anyio.run(run)


def test_objc_classes(image_daemon, fixtures):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as rk:
        r = rk.import_program("default", path=str(fixtures / "objc-arm64"), name="objc")
        assert any(w.startswith("analysis:objc: 1 objc categories, 2 objc classes") for w in r.warnings), r.warnings
        p = rk.program(r.program.program_id)
        md = p.objc_classes()
        point = next(c for c in md.classes if c.name == "Point")
        assert point.superclass == "Base" and list(point.categories) == ["Extra"]
        assert [m.selector for m in point.methods] == ["sum", "name", "x", "setX:", "diff"]
        assert point.methods[0].function_name == "-[Point sum]"
        assert [p.name for p in md.protocols] == ["Named"]
        assert [c.name for c in p.objc_classes("BASE").classes] == ["Base"]
        sum_ = next(f for f in p.functions() if f.name == "-[Point sum]")
        assert "struct Point *self" in sum_.prototype
        assert "self->y" in p.decompile(sum_.entry.offset).text
