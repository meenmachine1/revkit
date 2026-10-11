"""The MCP tools that close the gap with the daemon and the UI: about, Go To
expressions wherever an address is taken (revkit.expr, Program.resolve),
find_next and overview (api_minor 44), rename_field and retype_field
(Program.rename_field / retype_field, as the UI's Types view edits a field),
paged results with a "more" hint, results cut to a budget, and errors as
text rather than tracebacks."""

import json
import shutil
import subprocess

import pytest

from revkit import Client, Daemon
from revkit.expr import ExprError, Resolver, evaluate_text, parse_expr

SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
struct node { int value; struct node *next; char tag[4]; };
__attribute__((noinline)) int sum(struct node *n) { int s = 0; for (; n; n = n->next) s += n->value; return s; }
__attribute__((noinline)) void tagit(struct node *n, char c) { n->tag[0] = c; n->value++; }
int main(int argc, char **argv) {
  (void)argv;
  struct node *a = calloc(1, sizeof *a), *b = calloc(1, sizeof *b);
  a->value = argc; a->next = b; b->value = 7; tagit(a, 'x');
  printf("%d\n", sum(a));
  return 0;
}
"""
HEADER = "struct node { int value; struct node *next; char tag[4]; };"


# -- expressions, without a daemon ------------------------------------------------

SYMBOLS = {"main": 0x401000, "tbl": 0x404000, "add": 0x401200, "ns::f": 0x401300}
RESOLVER = Resolver(symbol=SYMBOLS.get, file_offset=lambda o: 0x400000 + o if o < 0x1000 else None,
                    is_space=lambda n: n == "mem", space_address=lambda n, o: 0x10000000 + o)


@pytest.mark.parametrize("text, value", [
    ("0x401000", 0x401000),
    ("401000", 0x401000),          # bare numbers are hex, as the listing prints addresses
    ("1000h", 0x1000),
    ("main", 0x401000),
    ("main+0x10", 0x401010),
    ("main + 10", 0x401010),
    ("tbl + 4*8", 0x404020),
    ("(tbl - 8) / 2", (0x404000 - 8) // 2),
    ("-1", (1 << 64) - 1),
    ("add", 0x401200),             # a symbol before the hex number it also spells
    ("face", 0xface),              # no symbol: the number
    ("ns::f+4", 0x401304),
    ("file:0x200", 0x400200),
    ("mem:0x100", 0x10000100),
])
def test_expressions(text, value):
    assert evaluate_text(text, RESOLVER) == value


@pytest.mark.parametrize("text, message", [
    ("", "empty"),
    ("nosuch", 'no symbol "nosuch"'),
    ("main +", "expected a number or a name"),
    ("(main", 'expected ")"'),
    ("main % 2", 'unexpected "%"'),
    ("file:0x5000", "isn't loaded"),
    ("code:0x10", 'no address space "code"'),
    ("main / 0", "division by zero"),
])
def test_expression_errors(text, message):
    with pytest.raises(ExprError, match=message.replace("(", r"\(").replace(")", r"\)")):
        evaluate_text(text, RESOLVER)
    assert issubclass(ExprError, ValueError)


def test_expression_tree():
    assert parse_expr("a + 2*b") == ("bin", "+", ("sym", "a", 0xa), ("bin", "*", ("num", 2), ("sym", "b", 0xb)))


# -- the result budget, without a daemon ---------------------------------------------

def test_results_are_cut_to_a_budget():
    pytest.importorskip("mcp.server.mcpserver")
    from revkit.mcp_server import _fit, _size

    items = [{"address": hex(0x401000 + i), "name": f"FUN_{i:08x}"} for i in range(5000)]
    paged = _fit({"functions": items, "offset": 100}, budget=4000)
    assert _size(paged) <= 4000 and paged["truncated"]
    kept = len(paged["functions"])
    assert 0 < kept < 5000 and paged["next_offset"] == 100 + kept and "offset=" in paged["more"]

    found = _fit({"matches": items, "truncated": False}, budget=4000)
    assert found["truncated"] and f"start={found['matches'][-1]['address']}" in found["more"]

    text = _fit({"c": "x" * 10000, "name": "f"}, budget=2000)
    assert _size(text) <= 2000 and text["truncated"] and "characters cut" in text["c"]

    small = {"functions": items[:3]}
    assert _fit(small) is small


# -- the tools, against a daemon ------------------------------------------------------

mcp_client = pytest.importorskip("mcp.client.client")
anyio = pytest.importorskip("anyio")

from revkit.mcp_server import create_server  # noqa: E402


def _json(result):
    assert not result.is_error, result
    return json.loads(result.content[0].text)


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("mcp_parity")
    (d / "prog.c").write_text(SOURCE)
    subprocess.run([cc, "-O1", "-fno-inline", "-fno-pie", "-no-pie", "-w", "-o", str(d / "prog"), str(d / "prog.c")],
                   check=True)
    return d / "prog"


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_parity_tools(image_daemon, binary):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        pid = rk.import_program("default", path=str(binary)).program.program_id
        prog = rk.program(pid)
        # A struct of alice's: it outranks an agent's edit of it (the agent defines its own below).
        prog.import_header("struct pair { int a; int b; };", actor=None, categories="none")
        entries = {f.name: f.entry.offset for f in prog.functions()}
        main, total, tagit = entries["main"], entries["sum"], entries["tagit"]
        # main's file offset, for file: expressions.
        block = next(b for b in prog.memory_map() if b.has_file_offset and b.range.first.offset <= main <= b.range.last.offset)
        main_file = block.file_offset + (main - block.range.first.offset)
        assert prog.resolve("main+4") == main + 4 and prog.resolve(f"file:{main_file:x}") == main
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-parity")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                r = _json(await mcp.call_tool(tool, args))
                assert "error" not in r, (tool, r)
                return r

            async def fails(tool, **args):
                r = _json(await mcp.call_tool(tool, args))
                assert r.get("error") == "INVALID_ARGUMENT", (tool, r)
                return r["message"]

            tools = {t.name for t in (await mcp.list_tools()).tools}
            assert {"about", "find_next", "overview", "rename_field", "retype_field"} <= tools
            await call("import_header", program_id=pid, c_text=HEADER, reason="the list node")
            await call("retype", program_id=pid, address="sum", c_declaration="int sum(struct node *n)", reason="r")
            await call("retype", program_id=pid, address="tagit", c_declaration="void tagit(struct node *n, char c)",
                       reason="r")

            # about: the workflow, the address syntax, who edits are recorded as, the daemon's features.
            about = await call("about")
            assert any("list_programs" in line for line in about["workflow"])
            assert "main+0x10" in about["addresses"] and "more" in about["paging"]
            assert about["you"]["edits_recorded_as"] == "agent:claude@test" and about["you"]["session"] == "mcp-parity"
            assert {"find-next", "overview", "search", "equates"} <= set(about["daemon"]["features"])

            # Addresses: hex, bare hex, names and expressions, everywhere.
            at_main = await call("disassemble", program_id=pid, address=hex(main), max_rows=3)
            relative = f"sum + 0x{main - total:x}" if main > total else f"sum - 0x{total - main:x}"
            for spelling in ("main", f"{main:x}", "main+0", f"file:0x{main_file:x}", relative):
                assert (await call("disassemble", program_id=pid, address=spelling, max_rows=3))["listing"] == \
                    at_main["listing"], spelling
            assert int(at_main["next"], 16) > main
            mem = await call("read_memory", program_id=pid, address="main+2", length=4)
            assert mem["address"] == hex(main + 2)
            assert "no symbol" in await fails("disassemble", program_id=pid, address="nosuch+4")
            assert (await call("decompile", program_id=pid, function_address="sum+4"))["name"] == "sum"  # containing

            # find_next: functions after main's, in order, each with its row; nothing before the first.
            nxt = await call("find_next", program_id=pid, address="main", kind="function", count=2)
            found = [int(f["address"], 16) for f in nxt["found"]]
            assert found and found == sorted(found) and found[0] > main and all(a in entries.values() for a in found)
            assert nxt["found"][0]["row"]
            back = await call("find_next", program_id=pid, address="sum", kind="function", backward=True)
            assert back["found"] and int(back["found"][0]["address"], 16) < total
            first = min(entries.values())
            none = await call("find_next", program_id=pid, address=hex(first), kind="function", backward=True)
            if not none["found"]:
                assert "note" in none
            assert "kind is one of" in await fails("find_next", program_id=pid, address="main", kind="sideways")

            # overview: blocks with bytes by kind, slices with entropy.
            ov = await call("overview", program_id=pid, slices=16)
            assert ov["total_bytes"] > 0 and ov["blocks"] and ov["slices"]
            assert any(s["kind"] == "code" for s in ov["slices"])
            assert all(0 <= s["entropy"] <= 8 for s in ov["slices"])

            # rename_field / retype_field: the struct by name or by the hash decompile gives.
            dec = await call("decompile", program_id=pid, function_address="sum")
            assert "->value" in dec["c"]
            node_hash = next(f["struct_hash"] for f in dec["fields"] if f["name"] == "value")
            done = await call("rename_field", program_id=pid, struct="node", field="value", new_name="weight",
                              reason="it is summed")
            assert done["struct"] == "struct node" and done["offset"] == "0x0" and "weight" in done["c_definition"]
            assert done["provenance"] == "agent:claude@test" and done["seqs"]
            dec = await call("decompile", program_id=pid, function_address="sum")
            assert "->weight" in dec["c"] and "->value" not in dec["c"]
            # By the old hash (the version decompile showed before): the current version is edited.
            typed = await call("retype_field", program_id=pid, struct=node_hash, field="0x0", c_type="long long",
                               reason="fills the padding")
            assert "long long weight" in typed["c_definition"] and "/* 0x8 */" in typed["c_definition"]
            over = await fails("retype_field", program_id=pid, struct="struct node", field="weight", c_type="char[12]",
                               reason="too big")
            assert "next" in over and "0x8" in over
            assert "no field" in await fails("rename_field", program_id=pid, struct="node", field="nosuch",
                                             new_name="x", reason="r")
            assert "C name" in await fails("rename_field", program_id=pid, struct="node", field="tag",
                                           new_name="not a name", reason="r")
            assert "no struct or union" in await fails("rename_field", program_id=pid, struct="nosuch", field="x",
                                                       new_name="y", reason="r")
            await call("undo_changes", program_id=pid, seqs=typed["seqs"] + done["seqs"], reason="back")
            assert "->value" in (await call("decompile", program_id=pid, function_address="sum"))["c"]

            # A human's struct outranks the agent's edit of it, and the result says so.
            shadowed = await call("rename_field", program_id=pid, struct="pair", field="b", new_name="second",
                                  reason="r")
            assert shadowed["status"] == "ASSERTION_STATUS_SHADOWED" and "SHADOWED" in shadowed["note"]

            # Paging: a page, the next one, and the hint saying how.
            one = await call("list_functions", program_id=pid, limit=1)
            assert one["truncated"] and one["next_offset"] == 1 and "offset=1" in one["more"]
            two = await call("list_functions", program_id=pid, limit=1, offset=1)
            assert two["functions"][0]["address"] != one["functions"][0]["address"]
            named = await call("list_functions", program_id=pid, named="named", limit=500)
            assert all(not f["name"].startswith("FUN_") for f in named["functions"])
            page = await call("decompile", program_id=pid, function_address="main", max_lines=2, variables=False)
            assert page["c"].count("\n") == 1 and page["next_start_line"] == 2 and "variables" not in page
            rest = await call("decompile", program_id=pid, function_address="main", start_line=2, max_lines=1000)
            assert not rest.get("truncated") and rest["lines"] == page["lines"]
            refs = await call("xrefs", program_id=pid, address="sum", limit=1)
            assert refs["total"] >= 1 and len(refs["xrefs"]) == 1
            assert refs["xrefs"][0]["kind"] == "call" and refs["xrefs"][0]["from_function"] == "main"
            graph = await call("function_graph", program_id=pid, function_address="sum", instructions=False, max_blocks=1)
            assert len(graph["blocks"]) == 1 and "instructions" not in graph["blocks"][0]
            if graph["block_count"] > 1:
                assert graph["next_block_offset"] == 1
            syms = await call("search_symbols", program_id=pid, name_contains="", limit=2)
            assert syms["truncated"] and syms["next_offset"] == 2

            # Errors are text the model can act on, never a traceback.
            assert "direction is one of" in await fails("xrefs", program_id=pid, address="main", direction="sideways")
            assert "kind is one of" in await fails("set_flow_override", program_id=pid, address="main", kind="sideways",
                                                   reason="r")
            assert "kind is one of" in await fails("set_comment", program_id=pid, address="main", text="t", kind="side",
                                                   reason="r")
            assert "not an address" in await fails("emu_read_memory", session_id="none", address="main")

    try:
        anyio.run(run)
    finally:
        server.revkit_client.close()
