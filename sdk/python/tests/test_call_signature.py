"""Call-site signature overrides and finding uses of a type or field
(api_minor 53, features "call-signature-override" and "type-uses";
docs/api.md "Call-site signature overrides" and "Find uses of a type or
field") through the SDK and the MCP tools on the image backend, on a
program compiled here: a varargs call and a computed call given their
arguments, shown in the listing and on the decompiler's token, undone by a
retraction and by Remove; what is refused; every use of a struct and of
each field with its access, progress and cancelling."""

import json
import shutil
import subprocess
import threading

import pytest

from revkit import Client, Daemon, InvalidArgument
from revkit.v1 import common_pb2, listing_pb2, query_pb2

SOURCE = r"""
#include <stdarg.h>
struct pt { int x; int y; long tag; };
struct pt g_pt;
int (*volatile hook)(int, int, int);
__attribute__((noinline)) int sum(int n, ...) {
  va_list ap; va_start(ap, n); int s = 0;
  for (int i = 0; i < n; i++) s += va_arg(ap, int);
  va_end(ap); return s;
}
__attribute__((noinline)) int add3(int a, int b, int c) { return a + b * 2 + c * 3; }
__attribute__((noinline)) void setx(struct pt *p, int v) { p->x = v; p->tag += 1; }
__attribute__((noinline)) int gety(struct pt *p) { return p->y; }
__attribute__((noinline)) int *addr_y(struct pt *p) { return &p->y; }
__attribute__((noinline)) int calls(int a) { return sum(3, a, a + 1, a + 2) + hook(a, 2, 3); }
int main(int argc, char **argv) {
  (void)argv;
  hook = add3;
  setx(&g_pt, argc);
  return calls(argc) + gety(&g_pt) + *addr_y(&g_pt);
}
"""


@pytest.fixture(scope="module")
def target(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("callsig")
    (d / "callsig.c").write_text(SOURCE)
    out = d / "callsig"
    subprocess.run([cc, "-O1", "-g", "-fno-pie", "-no-pie", "-w", "-o", str(out), str(d / "callsig.c")], check=True)
    return out


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture()
def rk(image_daemon):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as c:
        yield c


@pytest.fixture()
def prog(rk, target):
    return rk.program(rk.import_program("default", path=str(target)).program.program_id)


def sym(prog, name) -> int:
    return list(prog.symbols(name_equals=name))[0].address.offset


def call_rows(prog, entry):
    return [r for r in prog.listing(entry, max_rows=80).rows
            if r.kind == listing_pb2.LISTING_ROW_KIND_INSTRUCTION and r.function.offset == entry
            and r.flow in (listing_pb2.FLOW_KIND_CALL, listing_pb2.FLOW_KIND_INDIRECT_CALL)]


def call_line(text, callee):
    return next(line.strip() for line in text.splitlines() if callee in line and "(" in line and "=" in line)


def test_call_signature_override(rk, prog):
    assert {"call-signature-override", "type-uses"} <= set(rk.server_info().features)
    calls = sym(prog, "calls")
    direct, computed = call_rows(prog, calls)
    assert direct.flow == listing_pb2.FLOW_KIND_CALL and computed.flow == listing_pb2.FLOW_KIND_INDIRECT_CALL
    before = prog.decompile(calls).text
    assert "(ulong)" in call_line(before, "sum(")  # varargs: the arguments as the registers hold them
    assert call_line(before, "(*hook)") .endswith("(*hook)(a,2,3);")

    r1 = prog.override_call_signature(direct.address.offset, "int sum(int n, int a, int b, int c)")
    assert r1.assertions[0].key.kind == common_pb2.FACT_KIND_CALL_SIGNATURE
    r2 = prog.override_call_signature(computed.address.offset, "int f(int a)", reason="one argument")
    after = prog.decompile(calls)
    assert call_line(after.text, "sum(") == "iVar1 = sum(3,a,a + 1,a + 2);"
    assert call_line(after.text, "(*hook)") == "iVar2 = (*hook)(a);"
    # The listing's markup and the decompiler's token show it.
    assert prog.call_signature(direct.address.offset) == "int sum(int n, int a, int b, int c)"
    assert prog.call_signature(computed.address.offset) == "int (int a)"
    tok = [t for line in after.lines for t in line.tokens if t.call_signature]
    assert [(t.text, t.call_signature) for t in tok] == [("sum", "int sum(int n, int a, int b, int c)")]
    # Blame: who set it.
    blame = prog.blame(prog.key("call_signature", direct.address.offset))
    assert blame.value_text == "int (int n, int a, int b, int c)"
    assert blame.origin.asserted.provenance.id == "alice"

    # Undo one, Remove the other.
    prog.retract(*[a.seq for a in r2.assertions])
    assert call_line(prog.decompile(calls).text, "(*hook)").endswith("(*hook)(a,2,3);")
    assert prog.call_signature(computed.address.offset) == ""
    prog.remove_call_signature(direct.address.offset)
    assert "(ulong)" in call_line(prog.decompile(calls).text, "sum(")
    assert prog.call_signature(direct.address.offset) == ""

    # Refused: not a call, a prototype that doesn't parse, a non-function type.
    with pytest.raises(InvalidArgument, match="not a call"):
        prog.override_call_signature(calls, "int f(int a)")
    with pytest.raises(InvalidArgument, match="parse"):
        prog.override_call_signature(direct.address.offset, "int f(struct nosuch a")
    pt = prog.composite_type("struct pt")
    with pytest.raises(InvalidArgument, match="not a function type"):
        prog.override_call_signature(direct.address.offset, type_hash=pt.hash)


def test_find_type_uses(prog):
    names = {n: sym(prog, n) for n in ("setx", "gety", "addr_y")}
    seen = []
    every = prog.find_type_uses("struct pt", progress=seen.append)
    last = prog.last_search
    assert last.done and not last.truncated and last.functions_done == last.functions_total > 0
    rw = {query_pb2.FIELD_ACCESS_READ: "r", query_pb2.FIELD_ACCESS_WRITE: "w",
          query_pb2.FIELD_ACCESS_READ_WRITE: "rw", query_pb2.FIELD_ACCESS_ADDRESS: "&"}
    fields = sorted((u.function_name, u.field_name, rw[u.access]) for u in every if u.kind == query_pb2.TYPE_USE_KIND_FIELD)
    assert fields == [("addr_y", "y", "&"), ("gety", "y", "r"), ("setx", "tag", "r"), ("setx", "tag", "w"),
                      ("setx", "x", "w")]
    # The struct named in the three prototypes.
    typed = {u.function_name for u in every if u.kind == query_pb2.TYPE_USE_KIND_TYPE}
    assert typed == {"setx", "gety", "addr_y"}
    for u in every:
        assert u.function.offset == names[u.function_name]
        assert u.text[u.match_start:u.match_start + u.match_length] == (u.field_name or "pt")
    # One field, by name or by offset.
    y = prog.find_type_uses("struct pt", "y")
    assert sorted(u.function_name for u in y) == ["addr_y", "gety"]
    assert all(u.field_offset == 4 for u in y)
    assert [u.function_name for u in prog.find_type_uses("pt", 0)] == ["setx"]
    # Some functions only.
    assert {u.function_name for u in prog.find_type_uses("struct pt", functions=[names["gety"]])} == {"gety"}
    # Cancelled from its progress callback: stops early, no error.
    stop = threading.Event()
    prog.find_type_uses("struct pt", progress=lambda m: stop.set(), cancel=stop, parallelism=1)


def test_mcp_tools(image_daemon, target):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        pid = rk.import_program("default", path=str(target)).program.program_id
        prog = rk.program(pid)
        calls = sym(prog, "calls")
        direct = call_rows(prog, calls)[0].address.offset
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-callsig")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                r = await mcp.call_tool(tool, args)
                assert not r.is_error, r
                out = json.loads(r.content[0].text)
                assert "error" not in out, (tool, out)
                return out

            uses = await call("find_type_uses", program_id=pid, struct="struct pt", field="tag")
            assert sorted(u["access"] for u in uses["uses"]) == ["read", "write"]
            assert all(u["function_name"] == "setx" and u["offset"] == "0x8" for u in uses["uses"])
            r = await call("override_call_signature", program_id=pid, call_address=hex(direct),
                           prototype="int sum(int n, int a, int b, int c)", reason="three ints follow n")
            assert r["call_signature"] == "int sum(int n, int a, int b, int c)"
            c = (await call("decompile", program_id=pid, function_address="calls"))["c"]
            assert "sum(3,a,a + 1,a + 2)" in c
            await call("undo_changes", program_id=pid, seqs=[r["seq"]], reason="checking undo")
            c = (await call("decompile", program_id=pid, function_address="calls"))["c"]
            assert "(ulong)" in c

    anyio.run(run)
