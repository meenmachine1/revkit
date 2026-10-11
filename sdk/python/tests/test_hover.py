"""Previews through the SDK, revkit.script and MCP (api_minor 47, feature
"hover"; docs/ui.md "Hover cards"): what the UI's hover cards show (a
function's signature and first lines of C, a global's listing rows, a
scalar's spellings with the symbol at it) for any client."""

import io
import json
import shutil
import subprocess

import pytest

from revkit import Client, Daemon, preview_lines, scalar_text

PROGRAM = r"""
int counter = 7;
__attribute__((noinline)) int twice(int x) {
  int y = x * 2;
  counter += y;
  if (counter > 100) counter = 0;
  return y + 0x41;
}
int main(int argc, char **argv) { return twice(argc); }
"""


def test_scalar_text():
    assert scalar_text(0x41, 32) == {"hex": "0x41", "unsigned": "65", "signed": "65", "chars": "'A'"}
    assert scalar_text(-1, 8) == {"hex": "0xff", "unsigned": "255", "signed": "-1", "chars": None}
    assert scalar_text(0x454C46, 32)["chars"] == "'ELF'"
    assert scalar_text(0x0A, 8)["chars"] == "'\\n'"
    assert scalar_text(0, 32)["chars"] is None
    assert scalar_text(0x80000000, 32)["signed"] == "-2147483648"


@pytest.fixture(scope="module")
def exe(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("hover")
    src, out = d / "prog.c", d / "prog"
    src.write_text(PROGRAM)
    subprocess.run([cc, "-O1", "-fno-inline", "-o", str(out), str(src)], check=True)
    return out


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture(scope="module")
def rk(image_daemon):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as c:
        yield c


@pytest.fixture(scope="module")
def prog(rk, exe):
    return rk.program(rk.import_program("default", path=str(exe), name="prog-hover").program.program_id)


def symbol(prog, name):
    return next(s.address.offset for s in prog.symbols(name_equals=name))


def test_feature(image_daemon):
    with Client(image_daemon.grpc_target) as rk:
        info = rk.server_info()
        assert "hover" in info.features and info.api_minor >= 47


def test_preview_a_function(prog):
    twice = symbol(prog, "twice")
    p = prog.preview(twice)
    assert p["kind"] == "function" and p["name"] == "twice" and p["address"] == twice
    assert "twice(" in p["signature"]
    assert "twice(" in p["lines"][0] and "{" in p["lines"]
    assert len(p["lines"]) <= 12 + 1
    # The same lines as the decompiler's, from the top.
    assert p["lines"] == preview_lines(prog.decompile(twice))


def test_preview_data_and_a_scalar(prog):
    counter = symbol(prog, "counter")
    p = prog.preview(counter)
    assert p["kind"] == "data" and p["name"] == "counter"
    assert p["lines"] and f"{counter:x}" in p["lines"][0]
    s = prog.describe_scalar(counter, 64)
    assert s["symbol"] == "counter" and s["block"] and s["hex"] == hex(counter)
    s = prog.describe_scalar(0x41, 32)
    assert s["chars"] == "'A'" and s["symbol"] == ""


def test_script(rk, prog, tmp_path):
    from revkit.script import HeadlessHost, run_script

    script = tmp_path / "peek.py"
    script.write_text("from revkit.script import *\n"
                      "p = preview('twice')\n"
                      "print(p['kind'], p['name'])\n")
    host = HeadlessHost(None, out=io.StringIO(), err=io.StringIO(), interactive=False)
    res = run_script(script, client=rk, program_id=prog.id, host=host)
    assert res.ok, res.traceback
    assert host.out.getvalue().split() == ["function", "twice"]


mcp_client = pytest.importorskip("mcp.client.client")
anyio = pytest.importorskip("anyio")


def test_mcp(image_daemon, prog):
    from revkit.mcp_server import create_server

    twice, counter = symbol(prog, "twice"), symbol(prog, "counter")
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-hover")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                r = await mcp.call_tool(tool, args)
                assert not r.is_error, r
                out = json.loads(r.content[0].text)
                assert "error" not in out, (tool, out)
                return out

            tools = {t.name for t in (await mcp.list_tools()).tools}
            assert {"preview", "describe_value"} <= tools
            p = await call("preview", program_id=prog.id, address=hex(twice))
            assert p["kind"] == "function" and p["address"] == hex(twice) and "twice(" in p["signature"]
            v = await call("describe_value", program_id=prog.id, value=hex(counter))
            assert v["symbol"] == "counter"
            v = await call("describe_value", program_id=prog.id, value="0x41", bits=8)
            assert v["chars"] == "'A'" and v["hex"] == "0x41"

    anyio.run(run)
