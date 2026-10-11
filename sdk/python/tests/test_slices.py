"""Def-use chains and data-flow slices through the SDK and MCP (api_minor 57,
feature "decompile-slices"; docs/api.md "Slices"): Program.slice from a
variable by name, a token or a varnode, and the slice_decompiled tool."""

import json
import shutil
import subprocess

import pytest

from revkit import Client, Daemon

PROGRAM = r"""
int g;
__attribute__((noinline)) int f(int a, int b) {
  g = b + 7;
  return a * 3 + 1;
}
int main(int argc, char **argv) { (void)argv; return f(argc, argc + 1); }
"""


@pytest.fixture(scope="module")
def exe(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("slices")
    src, out = d / "prog.c", d / "prog"
    src.write_text(PROGRAM)
    subprocess.run([cc, "-O1", "-g", "-fno-inline", "-o", str(out), str(src)], check=True)
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
    return rk.program(rk.import_program("default", path=str(exe), name="prog-slices").program.program_id)


def f_entry(prog):
    return next(s.address.offset for s in prog.symbols(name_equals="f"))


def texts(fn, r):
    return [fn.lines[p.line].tokens[p.token].text for p in r.tokens]


def test_feature(image_daemon):
    with Client(image_daemon.grpc_target) as rk:
        info = rk.server_info()
        assert "decompile-slices" in info.features and info.api_minor >= 57


def test_slices_by_variable_token_and_varnode(prog):
    f = f_entry(prog)
    fn = prog.decompile(f, text=False)
    fwd = prog.slice(f, "forward", variable="b")
    assert fwd.start == "b" and "g" in texts(fn, fwd) and "a" not in texts(fn, fwd)
    assert fwd.addresses and all(a.offset >= f for a in fwd.addresses)
    back = prog.slice(f, "backward", variable="a")
    assert "a" in texts(fn, back) and "b" not in texts(fn, back)
    # From the return keyword's token: its operands.
    ret = next((i, j) for i, line in enumerate(fn.lines) for j, t in enumerate(line.tokens) if t.text == "return")
    r = prog.slice(f, "backward", token=ret)
    assert "a" in texts(fn, r) and "b" not in texts(fn, r)
    du = prog.slice(f, "def_use", varnode=r.varnode_indices[0])
    assert du.tokens
    with pytest.raises(ValueError):
        prog.slice(f, "sideways", variable="a")
    with pytest.raises(ValueError):
        prog.slice(f, "forward", variable="nope")


def test_mcp_tool(image_daemon, prog):
    mcp_client = pytest.importorskip("mcp.client.client")
    import anyio

    from revkit.mcp_server import create_server

    server = create_server(image_daemon.grpc_target, agent="claude", session="mcp-slices")
    f = f_entry(prog)

    async def run():
        async with mcp_client.Client(server) as mcp:
            r = await mcp.call_tool("slice_decompiled", {"program_id": prog.id, "function_address": hex(f),
                                                         "variable": "b", "kind": "forward"})
            assert not r.is_error, r
            out = json.loads(r.content[0].text)
            assert out["start"] == "b" and out["addresses"], out
            assert any("g" in line["tokens"] for line in out["lines"]), out

    anyio.run(run)
    server.revkit_client.close()
