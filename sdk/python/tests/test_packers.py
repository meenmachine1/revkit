"""Packed executables and content kinds end to end (api_minor 95 and 96, features
"content-kinds" and "packed-executables"; docs/filesystems.md): a PyInstaller-style
executable from tests/data/bytecode/make_packed.py imports as a program whose
ProgramInfo.payload_format names its archive, opens as a file system by its program
id, and lists in a host directory as a program that is also a container; its scripts
come out as .pyc files with their content kind; importing bytecode itself says what
it is; MCP's listing carries the content kinds."""

import json
import pathlib
import subprocess
import sys

import pytest

from revkit import Client, Daemon

ROOT = pathlib.Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def packed(tmp_path_factory):
    d = tmp_path_factory.mktemp("packed")
    subprocess.run([sys.executable, "-I", str(ROOT / "tests" / "data" / "bytecode" / "make_packed.py"), "/bin/true",
                    str(d)], check=True, capture_output=True)
    subprocess.run([sys.executable, "-I", "-c", "import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2])",
                    str(ROOT / "scripts" / "survey_summary.py"), str(d / "tool.pyc")], check=True)
    return d


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_packed_program(image_daemon, packed):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=120) as rk:
        info = rk.server_info()
        assert "packed-executables" in info.features and "content-kinds" in info.features and info.api_minor >= 96
        r = rk.import_program("default", path=str(packed / "pyinstaller-appended"), name="frozen")
        assert r.program.format == "elf" and r.program.payload_format == "pyinstaller"
        listed = [p for p in rk.programs("default") if p.program_id == r.program.program_id]
        assert listed[0].payload_format == "pyinstaller"
        with rk.open_filesystem("default", program_id=r.program.program_id) as fs:
            assert fs.root.format == "pyinstaller"
            entries = {e.path: e for e in fs.entries("/", recursive=True)}
            main = entries["/main.pyc"]
            assert main.content_kind.startswith("pyc:3.") and main.detected_kind == "bytecode"
            data = fs.read("/main.pyc")
            assert data[2:4] == b"\r\n" and len(data) == main.size
            pyz = {e.path: e for e in fs.entries("/PYZ.pyz!/", recursive=True)}
            assert pyz["/PYZ.pyz!/pkg/util.pyc"].content_kind.startswith("pyc:")


def test_listing_marks_packed_programs(image_daemon, packed):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=120) as rk:
        with rk.open_filesystem("default", host_path=str(packed)) as fs:
            entries = {e.name: e for e in fs.entries("/", detect=True)}
            for name, fmt in [("pyinstaller-appended", "pyinstaller"), ("pkg", "pkg"), ("nexe4", "nexe"),
                              ("bun", "bun"), ("zip-appended", "zip")]:
                e = entries[name]
                assert e.detected_kind == "elf" and e.container_format == fmt, (name, e)
            assert entries["lua-firmware"].container_format == "lua-chunks"
            assert entries["tool.pyc"].content_kind.startswith("pyc:3.")
            # Inside, in place.
            js = {e.path: e for e in fs.entries("/pkg!/snapshot/app")}
            assert js["/pkg!/snapshot/app/index.js"].content_kind == "js-source"
            assert fs.read("/pkg!/snapshot/app/index.js") == b"console.log('pkg main')\n"
            # A batch import's plan takes the packed executables as programs.
            plan = fs.import_(["/"], descend=True, programs_only=True, preview=True)
            actions = {pathlib.PurePosixPath(i.path).name: i.action for i in plan.items}
            assert actions["pyinstaller-appended"] == "import" and actions["tool.pyc"] == "skipped"


def test_importing_bytecode_says_what_it_is(image_daemon, packed):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=120) as rk:
        from revkit.client import FailedPrecondition
        with pytest.raises(FailedPrecondition) as err:
            rk.import_program("default", path=str(packed / "tool.pyc"))
        assert "Python 3." in str(err.value) and "pyc:3." in str(err.value)


def test_mcp_content_kinds(image_daemon, packed):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-packers")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                res = await mcp.call_tool(tool, args)
                assert not res.is_error, res
                return json.loads(res.content[0].text)

            s = await call("open_filesystem", project_id="default", host_path=str(packed / "pyinstaller-appended"))
            assert s["format"] == "pyinstaller"
            listing = await call("list_filesystem", session_id=s["session_id"], path="/")
            rows = {e["name"]: e for e in listing["entries"]}
            assert rows["main.pyc"]["content_kind"].startswith("pyc:3.")
            await call("close_filesystem", session_id=s["session_id"])

    anyio.run(run)
