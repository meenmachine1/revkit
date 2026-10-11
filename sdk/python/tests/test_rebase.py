"""Rebase through the SDK, revkit.script and MCP (api_minor 42, feature
"rebase"; docs/memory-map.md, "Rebase: setting the image base"): a program
with a user's work moved to a new image base and back, the work moving with
it; undo; the hand-assembled ARM firmware of test_memory_map.py imported at
a wrong base and fixed."""

import io
import json
import shutil
import subprocess

import pytest

from revkit import Client, Daemon, InvalidArgument
from revkit.v1 import project_pb2

from test_memory_map import FIRMWARE

PROGRAM = r"""
int counter;
__attribute__((noinline)) int twice(int x) { counter++; return x * 2; }
int main(int argc, char **argv) { return twice(argc); }
"""


@pytest.fixture(scope="module")
def exe(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("rebase")
    src, out = d / "prog.c", d / "prog"
    src.write_text(PROGRAM)
    subprocess.run([cc, "-O1", "-fno-inline", "-o", str(out), str(src)], check=True)
    return out


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture()
def rk(image_daemon):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as c:
        yield c


def entry(prog, name):
    return next(f.entry.offset for f in prog.functions() if f.name == name)


def test_feature(image_daemon):
    with Client(image_daemon.grpc_target) as rk:
        info = rk.server_info()
        assert "rebase" in info.features and info.api_minor >= 42


def test_moves_with_its_work_and_back(rk, exe):
    prog = rk.program(rk.import_program("default", path=str(exe), name="prog").program.program_id)
    base = prog.image_base()
    assert prog.import_image_base() == base
    twice = entry(prog, "twice")
    prog.rename(twice, "double_it")
    prog.comment(twice, "doubles", kind="plate")
    ram = prog.add_memory_region("scratch", 0x40000000, 0x1000)

    with pytest.raises(InvalidArgument):
        prog.set_image_base(2**64 - 0x100)
    assert prog.set_image_base(base + 0x10000, validate_only=True).image_base == base + 0x10000
    assert prog.image_base() == base  # nothing changed

    r = prog.set_image_base(base + 0x10000, reason="match the debugger")
    assert r.previous_image_base == base and r.import_image_base == base
    assert r.assertion.seq and r.assertion.body.image_base.image_base == base + 0x10000
    assert prog.image_base() == base + 0x10000 and prog.import_image_base() == base
    assert entry(prog, "double_it") == twice + 0x10000
    assert "double_it" in prog.decompile(entry(prog, "main")).text
    assert any(b.name == "scratch" and b.range.first.offset == 0x40010000 for b in prog.memory_map())
    # The history moved too: the rename's target reads at its new address.
    renames = [a for a in prog.assertions() if a.body.HasField("rename") and a.body.rename.name == "double_it"]
    assert renames and renames[0].body.rename.target.address.offset == twice + 0x10000

    # Undo is moving back.
    prog.retract(r.assertion.seq)
    assert prog.image_base() == base
    assert entry(prog, "double_it") == twice
    assert any(b.name == "scratch" and b.range.first.offset == 0x40000000 for b in prog.memory_map())
    prog.retract(ram.assertion.seq)


def test_script_and_a_wrong_firmware_base(rk, tmp_path):
    from revkit.script import HeadlessHost, run_script

    opts = project_pb2.ImportOptions(format="raw", language_id="ARM:LE:32:v4t", raw_permissions="r-x",
                                     has_image_base=True, image_base=0x8000)
    req = project_pb2.ImportProgramRequest(project_id="default", name="fw.bin", content=FIRMWARE, options=opts)
    prog = rk.program(rk.stubs.projects.ImportProgram(req).program.program_id)
    prog.rename(0x8040, "read_ram")  # a function at 0x40 of the image
    script = tmp_path / "fix_base.py"
    script.write_text("from revkit.script import *\nprint(hex(image_base()))\nset_image_base(0)\nprint(hex(image_base()))\n")
    host = HeadlessHost(None, out=io.StringIO(), err=io.StringIO(), interactive=False)
    res = run_script(script, client=rk, program_id=prog.id, host=host)
    assert res.ok, res.traceback
    assert host.out.getvalue().split() == ["0x8000", "0x0"]
    assert prog.image_base() == 0
    assert entry(prog, "read_ram") == 0x40
    # The code's literal pool now points into RAM it can be given.
    assert "uRam20000000" in prog.decompile(0x40).text or "DAT_20000000" in prog.decompile(0x40).text


mcp_client = pytest.importorskip("mcp.client.client")
anyio = pytest.importorskip("anyio")


def test_mcp(image_daemon, rk, exe):
    from revkit.mcp_server import create_server

    pid = rk.import_program("default", path=str(exe), name="prog-mcp").program.program_id
    base = rk.program(pid).image_base()
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-rebase")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                r = await mcp.call_tool(tool, args)
                assert not r.is_error, r
                out = json.loads(r.content[0].text)
                assert "error" not in out, (tool, out)
                return out

            assert "set_image_base" in {t.name for t in (await mcp.list_tools()).tools}
            moved = await call("set_image_base", program_id=pid, image_base=hex(base + 0x20000), reason="test")
            assert moved["image_base"] == hex(base + 0x20000) and moved["seq"]
            assert moved["provenance"] == "agent:claude@test"
            s = await call("program_summary", program_id=pid)
            assert s["image_base"] == hex(base + 0x20000) and s["import_image_base"] == hex(base)
            await call("undo_changes", program_id=pid, seqs=[moved["seq"]], reason="back")
            s = await call("program_summary", program_id=pid)
            assert s["image_base"] == hex(base)

    anyio.run(run)
