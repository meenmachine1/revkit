"""Value tracing across calls (api_minor 89, feature "value-trace"; docs/api.md
"Tracing a value across calls") through the SDK and MCP, on a program whose
flows are known: combine(x, y) = pick(scale(x), y), called from main with
argc and strlen(argv[0])."""

import json
import shutil
import subprocess

import pytest

from revkit import Client, Daemon

PROGRAM = r"""
#include <string.h>
__attribute__((noinline)) int scale(int v) { return v * 3 + 1; }
__attribute__((noinline)) int pick(int a, int b) { return a > b ? a : b; }
__attribute__((noinline)) int combine(int x, int y) { int s = scale(x); return pick(s, y); }
__attribute__((noinline)) int other(int q) { return scale(q + 5); }
int (*volatile hook)(int) = other;
int main(int argc, char **argv) {
  int r = combine(argc, (int)strlen(argv[0]));
  r += hook(r);
  return r + other(argc);
}
"""


@pytest.fixture(scope="module")
def exe(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("trace")
    (d / "prog.c").write_text(PROGRAM)
    out = d / "prog"
    subprocess.run([cc, "-O1", "-g", "-fno-inline", "-fno-optimize-sibling-calls", "-fno-pie", "-no-pie", "-o", str(out),
                    str(d / "prog.c")], check=True)
    return out


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_sdk_and_mcp(image_daemon, exe):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as rk:
        assert "value-trace" in rk.server_info().features
        prog = rk.program(rk.import_program("default", path=str(exe), name="prog-trace").program.program_id)
        combine = next(prog.symbols(name_equals="combine")).address.offset
        r = prog.trace(combine, "forward", variable="x")
        names = [f.name for f in r.functions]
        assert names[0] == "combine" and {"scale", "pick", "main"} <= set(names) and "other" not in names, names
        assert r.start == "x" and not r.truncated
        kinds = {u.kind for u in r.unknowns}
        from revkit.v1 import query_pb2
        assert {query_pb2.TRACE_UNKNOWN_KIND_INDIRECT_CALL, query_pb2.TRACE_UNKNOWN_KIND_NO_CALLERS} <= kinds, r.unknowns
        back = prog.trace(combine, "backward", variable="y", max_depth=1)
        assert [f.name for f in back.functions] == ["combine", "main"], back.functions
        assert any("strlen" in u.detail for u in back.unknowns), back.unknowns
        with pytest.raises(ValueError):
            prog.trace(combine, "sideways", variable="x")

    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-trace")

    async def run():
        async with mcp_client.Client(server) as mcp:
            res = await mcp.call_tool("trace_value", {"program_id": prog.id, "function_address": "combine",
                                                      "variable": "x", "direction": "forward"})
            return json.loads(res.content[0].text)

    out = anyio.run(run)
    assert out["start"] == "x" and out["direction"] == "forward", out
    fns = {f["function"]: f for f in out["functions"]}
    assert fns["scale"]["depth"] == 1 and fns["main"]["depth"] == -1
    assert any("scale(x)" in line["text"] for line in fns["combine"]["lines"]), fns["combine"]
    assert any(c["kind"] == "argument" and c["to"].startswith("scale:") for c in out["calls_crossed"]), out["calls_crossed"]
    assert {u["kind"] for u in out["unknowns"]} >= {"indirect_call", "no_callers"}, out["unknowns"]
