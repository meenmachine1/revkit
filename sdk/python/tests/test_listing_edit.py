"""Editing what bytes are, from the listing (api_minor 30, feature
"listing-edit"; docs/listing-edit.md), through the SDK on the image backend:
Define data (an integer, a builtin, a struct with its field rows, an array,
strings), Clear and Disassemble here (a function goes and comes back), data
killed by a later edit over part of it, constant and volatile ranges in the
decompiler, undo by retracting, and the same edits from a script (one
revision, script provenance, revert)."""

import io
import shutil
import subprocess

import pytest

from revkit import Client, Daemon, InvalidArgument, define_data_body
from revkit.script import HeadlessHost, run_script
from revkit.v1 import assertion_pb2, common_pb2, listing_pb2

SOURCE = r"""
#include <stdint.h>
#include <stdio.h>
struct pair { int a; short b; short c; };
uint32_t threshold = 0x12345678;
struct pair pair_g = {1, 2, 3};
char greeting[] = "hello";
uint32_t table[4] = {10, 20, 30, 40};
__attribute__((noinline)) uint32_t get_threshold(void) { return threshold; }
__attribute__((noinline)) int helper(int x) { return x * 3 + 1; }
__attribute__((noinline)) int use_pair(void) { return pair_g.a + pair_g.b + pair_g.c; }
int main(int argc, char **argv) {
  table[argc & 3] += 1;
  printf("%s %u\n", greeting, get_threshold());
  return helper(argc) + use_pair() + (int)table[1];
}
"""

PAIR = "struct pair { int a; short b; short c; };"
DATA = listing_pb2.LISTING_ROW_KIND_DATA
INSTRUCTION = listing_pb2.LISTING_ROW_KIND_INSTRUCTION
UNDEFINED = listing_pb2.LISTING_ROW_KIND_UNDEFINED
CONSTANT_TEXT = ("0x12345678", "305419896")


def compile_target(directory):
    """SOURCE compiled to ``directory``/listing_target (skips without a C compiler)."""
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    src = directory / "listing_target.c"
    src.write_text(SOURCE)
    out = directory / "listing_target"
    subprocess.run([cc, "-O1", "-fno-inline", "-w", "-o", str(out), str(src)], check=True)
    return out


@pytest.fixture(scope="module")
def target(tmp_path_factory):
    return compile_target(tmp_path_factory.mktemp("listing-edit"))


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture()
def rk(image_daemon):
    # Generous: the first decompilation starts a worker (slow under sanitizers).
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as c:
        yield c


@pytest.fixture()
def prog(rk, target):
    """A fresh import per test, so edits never leak between tests."""
    return rk.program(rk.import_program("default", path=str(target)).program.program_id)


def sym(prog, name) -> int:
    hits = [s for s in prog.symbols(name_equals=name)]
    assert hits, f"no symbol {name}"
    return hits[0].address.offset


def fn_entries(prog) -> set:
    return {f.entry.offset for f in prog.functions()}


def rows_at(prog, addr, max_rows=40):
    """Listing rows from ``addr`` (header rows aside)."""
    return [r for r in prog.listing(addr, max_rows=max_rows).rows if r.kind != listing_pb2.LISTING_ROW_KIND_HEADER]


def row_at(prog, addr):
    """The code unit's own row at ``addr`` (not one of its field rows)."""
    for r in rows_at(prog, addr):
        if r.address.offset == addr and not r.data_field:
            return r
        if r.address.offset > addr:
            break
    # The address may be inside an undefined run that starts before it.
    r = rows_at(prog, addr)[0]
    assert r.address.offset <= addr < r.address.offset + max(r.length, 1), (hex(addr), r)
    return r


def field_rows(prog, item):
    return [r for r in rows_at(prog, item) if r.data_field and r.data_parent.offset == item]


def edit_of(resp):
    """The listing or mutability edit in a response (a parsed type adds TYPE_DEF assertions)."""
    return next(a for a in resp.assertions if a.body.WhichOneof("kind") in ("listing_edit", "mutability"))


def undo(prog, resp):
    """Retracts every assertion an edit made (a parsed type's TYPE_DEFs too)."""
    prog.retract(*[a.seq for a in resp.assertions])


def decompiled(prog, name) -> str:
    return prog.decompile(sym(prog, name)).text


def test_feature(image_daemon):
    with Client(image_daemon.grpc_target) as rk:
        info = rk.server_info()
        assert "listing-edit" in info.features and info.api_minor >= 30


def test_body_builders_check_their_arguments():
    with pytest.raises(ValueError):
        define_data_body(0x10)  # no type, type_hash or string
    with pytest.raises(ValueError):
        define_data_body(0x10, "char", layout="fixed")  # a layout without a string
    with pytest.raises(ValueError):
        define_data_body(0x10, string="utf7")
    b = define_data_body(0x10, string="utf16").listing_edit.data
    assert b.string == assertion_pb2.STRING_ENCODING_UTF16 and b.layout == assertion_pb2.STRING_LAYOUT_TERMINATED
    assert not b.HasField("collapsed") and not b.HasField("type")
    b = define_data_body(0x10, "uint32_t", count=4, collapsed=False).listing_edit.data
    assert b.type.c_declaration == "uint32_t" and b.count == 4 and b.HasField("collapsed") and not b.collapsed
    assert define_data_body(0x10, type_hash="abc").listing_edit.data.type.type_hash == "abc"


def test_define_integers_and_undo(prog):
    threshold = sym(prog, "threshold")
    before = row_at(prog, threshold)

    r = prog.define_data(threshold, "uint32_t", reason="a 32-bit limit")
    a = edit_of(r)
    assert a.key.kind == common_pb2.FACT_KIND_CODE_UNIT and a.key.sub == "data"
    d = a.body.listing_edit.data
    assert d.size == 4 and d.type_hash and d.type_name == "uint32_t"
    row = row_at(prog, threshold)
    assert row.kind == DATA and row.length == 4 and row.data_type == "uint32_t", row
    assert row.unit_origin.HasField("asserted")
    blame = prog.blame(prog.key("code_unit", threshold, "data"))
    assert blame.origin.asserted.seq == a.seq

    # A Ghidra builtin name, over the same bytes: the newest edit wins.
    dw = prog.define_data(threshold, "dword")
    assert edit_of(dw).body.listing_edit.data.size == 4
    row = row_at(prog, threshold)
    assert row.kind == DATA and row.length == 4 and row.data_type == edit_of(dw).body.listing_edit.data.type_name

    undo(prog, dw)
    assert row_at(prog, threshold).data_type == "uint32_t"
    undo(prog, r)
    after = row_at(prog, threshold)
    assert (after.kind, after.length, after.data_type) == (before.kind, before.length, before.data_type)
    assert not after.unit_origin.HasField("asserted")


def test_define_struct_with_field_rows(prog):
    pair = sym(prog, "pair_g")
    prog.import_header(PAIR, actor=None)
    r = prog.define_data(pair, "struct pair")
    d = edit_of(r).body.listing_edit.data
    assert d.size == 8 and d.type_name == "struct pair"

    row = row_at(prog, pair)
    assert row.kind == DATA and row.length == 8 and row.data_type == "struct pair", row
    assert row.data_components == 3 and not row.data_collapsed  # structs default to expanded
    fields = field_rows(prog, pair)
    assert [f.data_field for f in fields] == ["a", "b", "c"], fields
    assert [f.address.offset - pair for f in fields] == [0, 4, 6]
    assert all(f.kind == DATA and f.data_depth == 1 for f in fields)
    assert all(f.data_type for f in fields) and [f.length for f in fields] == [4, 2, 2]

    # Collapsed: one row.
    c = prog.define_data(pair, "struct pair", collapsed=True)
    row = row_at(prog, pair)
    assert row.data_collapsed and row.data_components == 3 and not field_rows(prog, pair)
    undo(prog, c)
    assert len(field_rows(prog, pair)) == 3


def test_define_arrays_and_strings(prog):
    table = sym(prog, "table")
    r = prog.define_data(table, "uint32_t", count=4)
    assert edit_of(r).body.listing_edit.data.size == 16
    row = row_at(prog, table)
    assert row.kind == DATA and row.length == 16 and row.data_type == "uint32_t[4]", row
    assert row.data_collapsed and row.data_components == 4  # arrays default to one row
    assert any(d.address.offset == table for d in prog.data("defined"))

    prog.define_data(table, "uint32_t", count=4, collapsed=False)
    assert [f.data_field for f in field_rows(prog, table)] == ["[0]", "[1]", "[2]", "[3]"]

    greeting = sym(prog, "greeting")
    s = prog.define_data(greeting, string="utf8")
    d = edit_of(s).body.listing_edit.data
    assert d.size == 6  # "hello" and its NUL
    row = row_at(prog, greeting)
    assert row.kind == DATA and row.length == 6 and row.data_type == "char[6]", row

    fixed = prog.define_data(greeting, string="utf8", layout="fixed", count=3)
    assert edit_of(fixed).body.listing_edit.data.size == 3
    assert row_at(prog, greeting).length == 3
    undo(prog, fixed)
    assert row_at(prog, greeting).length == 6


def test_a_later_edit_over_part_of_an_item_removes_it(prog):
    table = sym(prog, "table")
    whole = prog.define_data(table, "uint32_t", count=4)
    assert row_at(prog, table).data_type == "uint32_t[4]"
    part = prog.define_data(table + 4, "uint32_t")
    assert row_at(prog, table + 4).data_type == "uint32_t"
    # The array no longer owns all its bytes: it is gone and its bytes are undefined.
    assert row_at(prog, table).kind == UNDEFINED
    undo(prog, part)
    assert row_at(prog, table).data_type == "uint32_t[4]"
    undo(prog, whole)


def test_clear_then_disassemble_brings_a_function_back(prog):
    entry = sym(prog, "helper")
    size = prog.function(entry).size
    assert entry in fn_entries(prog) and size > 0

    cleared = prog.clear_code(entry, size, reason="not code")
    a = edit_of(cleared)
    assert a.key.kind == common_pb2.FACT_KIND_CODE_UNIT and a.key.sub == f"clear:{size:x}"
    assert entry not in fn_entries(prog)  # main still calls it, but nothing starts in cleared bytes
    assert row_at(prog, entry).kind == UNDEFINED

    code = prog.disassemble(entry, function=True)
    assert edit_of(code).key.sub == "code"
    assert edit_of(code).body.listing_edit.disassemble.function
    assert entry in fn_entries(prog)
    row = row_at(prog, entry)
    assert row.kind == INSTRUCTION and row.unit_origin.HasField("asserted")

    undo(prog, code)
    assert entry not in fn_entries(prog)
    undo(prog, cleared)
    assert entry in fn_entries(prog) and row_at(prog, entry).kind == INSTRUCTION


def test_clear_flow_takes_a_function_in_one_undo_step(prog):
    """Clear Flow and Repair (api_minor 83, feature "clear-flow"): helper's
    whole flow, planned, cleared in one revision, and undone at once."""
    entry = sym(prog, "helper")
    plan = prog.plan_clear_flow(entry)
    assert plan.ranges and plan.ranges[0].address.offset == entry and plan.kept == 0
    assert [f.offset for f in plan.functions] == [entry]
    assert sum(r.length for r in plan.ranges) == prog.function(entry).size
    plan2, resp = prog.clear_flow(entry, reason="not code")
    assert plan2 == plan and len(resp.assertions) == len(plan.ranges)
    assert entry not in fn_entries(prog) and row_at(prog, entry).kind == UNDEFINED
    prog.retract(*(a.seq for a in resp.assertions), reason="undo")
    assert entry in fn_entries(prog) and row_at(prog, entry).kind == INSTRUCTION


def test_fallthrough_override_moves_flow_and_clears(prog):
    """Set Fallthrough (api_minor 84, feature "fallthrough-override"): main's
    call to helper goes on two instructions later; then nowhere; cleared,
    then undone, as analysis had it."""
    main = sym(prog, "main")
    helper = sym(prog, "helper")
    insns = list(prog.instructions(function=main, pcode=False))
    k = next(i for i, x in enumerate(insns) if helper in [t.offset for t in x.flow_targets])
    call, skipped, target = insns[k].address.offset, insns[k + 1].address.offset, insns[k + 2].address.offset
    size = prog.function(main).size

    moved = prog.set_fallthrough(call, target, reason="skips an instruction")
    a = moved.assertions[0]
    assert a.key.kind == common_pb2.FACT_KIND_FALLTHROUGH and a.key.address.offset == call
    row = row_at(prog, call)
    assert row.fallthrough_override and row.fallthrough.offset == target and row.fallthrough_origin.HasField("asserted")
    assert prog.instruction(call).fall_through.offset == target
    assert any(x.kind == listing_pb2.XREF_KIND_FALLTHROUGH and x.to_address.offset == target
               for x in prog.xrefs_from(call))
    # (What only the skipped instruction reached leaves the body.)
    assert prog.function(main).size <= size

    nowhere = prog.set_fallthrough(call, None)
    row = row_at(prog, call)
    assert row.fallthrough_override and not row.HasField("fallthrough")
    assert not prog.instruction(call).HasField("fall_through")
    assert prog.function(main).size < size

    cleared = prog.clear_fallthrough(call)
    assert not row_at(prog, call).fallthrough_override
    assert prog.instruction(call).fall_through.offset == skipped
    assert prog.function(main).size == size
    for resp in (cleared, nowhere, moved):
        undo(prog, resp)
    assert not row_at(prog, call).fallthrough_override


def test_constant_and_volatile_ranges_in_the_decompiler(prog):
    threshold = sym(prog, "threshold")
    plain = decompiled(prog, "get_threshold")
    assert not any(t in plain for t in CONSTANT_TEXT), plain  # writable data: not folded

    const = prog.set_mutability(threshold, 4, "constant", reason="never written")
    a = edit_of(const)
    assert a.key.kind == common_pb2.FACT_KIND_MUTABILITY and a.key.sub == "4"
    row = row_at(prog, threshold)
    assert row.mutability == assertion_pb2.MUTABILITY_CONSTANT and row.mutability_origin.HasField("asserted")
    text = decompiled(prog, "get_threshold")
    assert any(t in text for t in CONSTANT_TEXT), text

    vol = prog.set_mutability(threshold, 4, "volatile")
    assert row_at(prog, threshold).mutability == assertion_pb2.MUTABILITY_VOLATILE
    text = decompiled(prog, "get_threshold")
    assert not any(t in text for t in CONSTANT_TEXT), text

    undo(prog, vol)
    assert any(t in decompiled(prog, "get_threshold") for t in CONSTANT_TEXT)
    undo(prog, const)
    assert decompiled(prog, "get_threshold") == plain
    assert row_at(prog, threshold).mutability == assertion_pb2.MUTABILITY_UNSPECIFIED


def test_bad_edits_are_refused(prog):
    with pytest.raises(InvalidArgument):
        prog.define_data(sym(prog, "threshold"), "struct no_such_type")
    with pytest.raises(ValueError):
        prog.set_mutability(sym(prog, "threshold"), 4, "readonly")
    with pytest.raises(ValueError):
        prog.clear_code(sym(prog, "helper"), 0)


SCRIPT = """\
# @category Tests
# @description Fixes the listing
from revkit.script import *
define_data("table", "uint32_t", count=4)
define_data("greeting", string="utf8")
clear("helper", ask_int("size", "helper's size"))
disassemble("helper", function=True)
set_mutability("threshold", 4, "constant")
assert pending_edits() == 5
"""


def test_script_edits_are_one_revision(rk, prog, tmp_path):
    s = tmp_path / "fix_listing.py"
    s.write_text(SCRIPT)
    table, helper = sym(prog, "table"), sym(prog, "helper")
    size = prog.function(helper).size
    host = HeadlessHost({"size": str(size)}, out=io.StringIO(), err=io.StringIO(), interactive=False)
    r = run_script(s, client=rk, program_id=prog.id, host=host)
    assert r.ok, r.traceback
    # (A type the server parsed for define_data adds its TYPE_DEF assertions.)
    assert len(r.revisions) == 1 and r.assertions >= 5
    mine = prog.assertions(session=r.run_id)
    assert all(m.provenance.kind == common_pb2.PROVENANCE_KIND_SCRIPT for m in mine)
    kinds = [m.key.kind for m in mine]
    assert kinds.count(common_pb2.FACT_KIND_CODE_UNIT) == 4 and kinds.count(common_pb2.FACT_KIND_MUTABILITY) == 1
    assert row_at(prog, table).data_type == "uint32_t[4]"
    assert helper in fn_entries(prog)
    assert any(t in decompiled(prog, "get_threshold") for t in CONSTANT_TEXT)

    prog.revert(session=r.run_id, actor="user:alice")
    assert row_at(prog, table).data_type != "uint32_t[4]"
    assert not any(t in decompiled(prog, "get_threshold") for t in CONSTANT_TEXT)

    bad = tmp_path / "bad_listing.py"
    bad.write_text('define_data("threshold", "uint32_t")\ndefine_data("threshold", "struct no_such_type")\n')
    before = len(prog.assertions(include_inactive=True))
    r = run_script(bad, client=rk, program_id=prog.id, host=HeadlessHost(out=io.StringIO(), err=io.StringIO(),
                                                                          interactive=False))
    assert r.status == "error" and "bad_listing.py:2" in r.error, r.error
    assert len(prog.assertions(include_inactive=True)) == before
