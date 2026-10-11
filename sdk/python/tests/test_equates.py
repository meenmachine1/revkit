"""Equates and user references (api_minor 39, features "equates" and
"user-references"; docs/api.md "Equates and user references") through the
SDK on the image backend, on a program compiled here: Convert (char, then
decimal, then cleared) in the listing and the decompiler, an equate and an
enum member, one name for one value, apply to the function and the
program, the equates table folded from the assertions with rename and
remove everywhere, undo; a user computed-call reference that makes a
function the decompiler calls, an analysis reference deleted, a primary
data reference shown in its operand; and the same edits from a script (one
revision, script provenance, revert)."""

import io
import platform
import shutil
import subprocess

import pytest

from revkit import Client, Daemon, InvalidArgument, fold_equates, operand_display_body, reference_body
from revkit.script import HeadlessHost, run_script
from revkit.v1 import assertion_pb2, common_pb2, decompile_pb2, listing_pb2

SOURCE = r"""
#include <stdint.h>
int table_g[4] = {1, 2, 3, 4};
__attribute__((noinline)) int is_a(int c) { return c == 'A' ? 3 : 5; }
__attribute__((noinline)) int weigh(int x) { return x * 0x1234 + table_g[x & 3]; }
__attribute__((noinline)) int sevens(int x) { return (x & 7) * 3 + (x ^ 7); }
__attribute__((noinline)) int add7(int x) { return x + 7; }
__attribute__((noinline)) int is_ncolors(int c) { return c == 10 ? 3 : 4; }
#if defined(__x86_64__)
__asm__(".text\n.p2align 4\n.globl anchor_fn\n.type anchor_fn,@function\nanchor_fn:\n  ret\n"
        ".p2align 4\n.Lhidden_target:\n  leal 3(%rdi,%rdi,4), %eax\n  ret\n");
extern int hidden_target(int) __asm__(".Lhidden_target");
#else
__attribute__((noinline)) int hidden_target(int x) { return x * 5 + 3; }
#endif
volatile long bias;
__attribute__((noinline)) int call_through(int x) {
  int (*f)(int) = (int (*)(int))((char *)hidden_target + bias);
  return f(x) + 1;
}
int main(int argc, char **argv) {
  (void)argv;
  return is_a(argc) + weigh(argc) + sevens(argc) + add7(argc) + is_ncolors(argc) + call_through(argc);
}
"""

COLOR = "enum color { RED, ORANGE, YELLOW, GREEN, BLUE, INDIGO, VIOLET, BLACK, WHITE, GREY, NCOLORS };"
SCALAR = listing_pb2.LISTING_TOKEN_KIND_SCALAR
X86_64 = platform.machine() in ("x86_64", "AMD64")


def compile_target(directory):
    """SOURCE compiled to ``directory``/equates_target (skips without a C compiler)."""
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    src = directory / "equates_target.c"
    src.write_text(SOURCE)
    out = directory / "equates_target"
    subprocess.run([cc, "-O1", "-fno-pie", "-no-pie", "-w", "-o", str(out), str(src)], check=True)
    return out


@pytest.fixture(scope="module")
def target(tmp_path_factory):
    return compile_target(tmp_path_factory.mktemp("equates"))


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
    """A fresh import per test, so edits never leak between tests."""
    return rk.program(rk.import_program("default", path=str(target)).program.program_id)


def sym(prog, name) -> int:
    hits = list(prog.symbols(name_equals=name))
    assert hits, f"no symbol {name}"
    return hits[0].address.offset


def rows(prog, entry):
    """The instruction rows of the function at ``entry``."""
    return [r for r in prog.listing(entry, max_rows=200).rows
            if r.kind == listing_pb2.LISTING_ROW_KIND_INSTRUCTION and r.function.offset == entry]


def row(prog, addr):
    return next(r for r in prog.listing(addr, max_rows=4).rows if r.address.offset == addr
                and r.kind == listing_pb2.LISTING_ROW_KIND_INSTRUCTION)


def scalar_in(prog, entry, value, mnemonic=""):
    """(address, operand) of the function's first instruction with a scalar of ``value``."""
    for r in rows(prog, entry):
        if mnemonic and (not r.tokens or r.tokens[0].text.upper() != mnemonic):
            continue
        for t in r.tokens:
            if t.kind == SCALAR and t.value == value:
                return r.address.offset, t.operand_index
    raise AssertionError(f"no scalar {value:#x} in the function at {entry:#x}")


def operand(prog, addr, op):
    """The operand's scalar, symbol or address token."""
    r = row(prog, addr)
    return next(t for t in r.tokens if t.HasField("operand_index") and t.operand_index == op and t.kind in (
        SCALAR, listing_pb2.LISTING_TOKEN_KIND_SYMBOL, listing_pb2.LISTING_TOKEN_KIND_ADDRESS))


def decompiled(prog, name) -> str:
    return prog.decompile(sym(prog, name)).text


def constants(prog, name, text):
    """The decompiler's CONSTANT tokens of the function that end in ``text``
    (a 32-bit character shows as L'A')."""
    f = prog.decompile(sym(prog, name))
    return [t for line in f.lines for t in line.tokens if t.kind == decompile_pb2.CODE_TOKEN_KIND_CONSTANT
            and t.text.endswith(text)]


def undo(prog, resp):
    prog.retract(*[a.seq for a in resp.assertions])


def entries(prog) -> set:
    return {f.entry.offset for f in prog.functions()}


def test_feature(image_daemon):
    with Client(image_daemon.grpc_target) as rk:
        info = rk.server_info()
        assert {"equates", "user-references"} <= set(info.features) and info.api_minor >= 39


def test_body_builders_check_their_arguments():
    with pytest.raises(ValueError):
        operand_display_body(0x10, 1, format="hex", equate="ONE")  # two displays
    with pytest.raises(ValueError):
        operand_display_body(0x10, 1, enum="abc")  # an enum without a member
    with pytest.raises(ValueError):
        operand_display_body(0x10, 1, format="roman")
    with pytest.raises(ValueError):
        operand_display_body(0x10, 1, equate="X", apply_to="module")
    with pytest.raises(ValueError):
        reference_body(0x10, 0x20)  # no type
    with pytest.raises(ValueError):
        reference_body(0x10, 0x20, "pointer")
    d = operand_display_body(0x10, -16, format="signed").operand_display
    assert d.value == 0xfffffffffffffff0 and d.format == assertion_pb2.SCALAR_FORMAT_SIGNED_DECIMAL
    assert not d.HasField("operand_index") and d.apply_to == assertion_pb2.EQUATE_SCOPE_UNSPECIFIED
    d = operand_display_body(0x10, "A", operand=1, equate="LETTER_A", apply_to="program").operand_display
    assert d.value == 0x41 and d.operand_index == 1 and d.equate.name == "LETTER_A"
    assert d.apply_to == assertion_pb2.EQUATE_SCOPE_PROGRAM
    d = operand_display_body(0x10, 10, enum="h", member="NCOLORS").operand_display
    assert d.equate.enum_type_hash == "h" and d.equate.member == "NCOLORS" and not d.equate.name
    assert operand_display_body(0x10, 7).operand_display.WhichOneof("display") is None  # clears
    r = reference_body(0x10, 0x20, "computed_call", primary=True).reference
    assert r.type == assertion_pb2.REFERENCE_TYPE_COMPUTED_CALL and r.primary and not r.HasField("operand_index")
    r = reference_body(0x10, 0x20, operand=0, remove=True).reference
    assert r.remove and r.operand_index == 0 and r.type == assertion_pb2.REFERENCE_TYPE_UNSPECIFIED
    assert reference_body(0x10, 0x20, "read", operand=-1).reference.type == assertion_pb2.REFERENCE_TYPE_DATA_READ


def test_convert_shows_in_the_listing_and_the_decompiler(prog):
    is_a = sym(prog, "is_a")
    cmp, op = scalar_in(prog, is_a, 0x41)
    assert "0x41" in decompiled(prog, "is_a")

    chr_ = prog.convert(cmp, 0x41, "char")
    a = chr_.assertions[0]
    assert a.key.kind == common_pb2.FACT_KIND_EQUATE and a.key.sub == f"{op}:41"
    assert a.body.operand_display.operand_index == op  # the server filled the operand
    t = operand(prog, cmp, op)
    assert t.text == "'A'" and t.value == 0x41 and t.display_origin.asserted.seq == a.seq
    assert "'A'" in decompiled(prog, "is_a")
    tok = constants(prog, "is_a", "'A'")
    assert tok and tok[0].display_set and tok[0].value == 0x41 and tok[0].address.offset == cmp
    assert tok[0].HasField("constant_hash")

    prog.convert(cmp, 0x41, "unsigned")
    assert operand(prog, cmp, op).text == "65"
    assert "65" in decompiled(prog, "is_a")
    prog.convert(cmp, 0x41, "binary")
    assert operand(prog, cmp, op).text == "1000001b"
    # Cleared: the disassembler's text, whoever set it.
    prog.clear_display(cmp, 0x41)
    t = operand(prog, cmp, op)
    assert t.text == "0x41" and not t.HasField("display_origin")
    prog.convert(cmp, 0x41, "octal", operand=op)
    assert operand(prog, cmp, op).text == "101o"
    with pytest.raises(InvalidArgument):
        prog.convert(cmp, 0x99, "char")  # no operand holds it
    # Undo every conversion: back to the start.
    for x in prog.assertions(kinds=("equate",)):
        prog.retract(x.seq)
    assert operand(prog, cmp, op).text == "0x41" and "0x41" in decompiled(prog, "is_a")


def test_equate_and_enum_member(prog):
    is_a = sym(prog, "is_a")
    cmp, op = scalar_in(prog, is_a, 0x41)
    eq = prog.set_equate(cmp, 0x41, "LETTER_A")
    assert operand(prog, cmp, op).text == "LETTER_A"
    assert "LETTER_A" in decompiled(prog, "is_a")
    # One name, one value.
    seven, _ = scalar_in(prog, sym(prog, "add7"), 7)
    with pytest.raises(InvalidArgument, match="already has the value"):
        prog.set_equate(seven, 7, "LETTER_A")

    # An enum member: the enum suggested by value, then shown by name.
    prog.import_header(COLOR, actor=None, categories="none")
    suggested = prog.enums_with_value(10, program_only=True)
    assert [t.name for t in suggested] == ["color"]
    assert prog.enums_with_value(11, program_only=True) == []
    ten, ten_op = scalar_in(prog, sym(prog, "is_ncolors"), 10)
    assert "10" in decompiled(prog, "is_ncolors")
    member = prog.set_enum_equate(ten, 10, "color", "NCOLORS")
    e = member.assertions[0].body.operand_display.equate
    assert e.name == "NCOLORS" and e.member == "NCOLORS" and e.enum_type_hash == suggested[0].hash
    assert operand(prog, ten, ten_op).text == "NCOLORS"
    assert "NCOLORS" in decompiled(prog, "is_ncolors")
    with pytest.raises(InvalidArgument):
        prog.set_enum_equate(ten, 10, "color", "GREY")  # GREY is 9

    table = prog.equates()
    assert sorted(table) == ["LETTER_A", "NCOLORS"]
    assert table["LETTER_A"].value == 0x41 and table["LETTER_A"].references[0].address == cmp
    assert table["LETTER_A"].references[0].seq == eq.assertions[0].seq
    assert table["NCOLORS"].enum_type_hash == suggested[0].hash and table["NCOLORS"].reference_count == 1

    undo(prog, member)
    assert operand(prog, ten, ten_op).text == "0xa"
    assert "NCOLORS" not in prog.equates()


def test_apply_to_function_and_program_then_rename_and_remove_everywhere(rk, prog):
    sevens, add7 = sym(prog, "sevens"), sym(prog, "add7")
    first, op = scalar_in(prog, sevens, 7)

    def shown(entry, text):
        return sum(t.text == text for r in rows(prog, entry) for t in r.tokens)

    in_function = prog.set_equate(first, 7, "SEVEN", apply_to="function")
    assert len(in_function.assertions) == 2 and in_function.assertions[0].key.address.offset == first
    assert shown(sevens, "SEVEN") == 2 and shown(add7, "SEVEN") == 0
    in_program = prog.set_equate(first, 7, "SEVEN", apply_to="program")
    assert shown(add7, "SEVEN") == 1
    assert "SEVEN" in decompiled(prog, "add7")
    table = prog.equates()
    assert table["SEVEN"].value == 7 and table["SEVEN"].reference_count >= 3

    # Rename everywhere: one edit, every operand.
    renamed = prog.rename_equate("SEVEN", "WEEK")
    assert len(renamed.assertions) == table["SEVEN"].reference_count
    assert len({a.revision for a in renamed.assertions}) == 1
    assert shown(sevens, "WEEK") == 2 and shown(add7, "WEEK") == 1 and shown(sevens, "SEVEN") == 0
    assert "SEVEN" not in prog.equates() and prog.equates()["WEEK"].reference_count == table["SEVEN"].reference_count
    undo(prog, renamed)
    assert shown(sevens, "SEVEN") == 2 and "WEEK" not in prog.equates()
    with pytest.raises(ValueError):
        prog.rename_equate("NO_SUCH", "X")

    # Remove everywhere: the disassembler's text again; undo brings the name back.
    removed = prog.remove_equate("SEVEN")
    assert shown(sevens, "SEVEN") == 0 and shown(add7, "SEVEN") == 0 and "SEVEN" not in prog.equates()
    assert "SEVEN" not in decompiled(prog, "add7")
    undo(prog, removed)
    assert shown(add7, "SEVEN") == 1
    # Undo of the sets themselves.
    undo(prog, in_program)
    undo(prog, in_function)
    assert prog.equates() == {}
    assert shown(sevens, "SEVEN") == 0


def test_fold_keeps_only_effective_equates():
    a = assertion_pb2.Assertion(seq=5, status=assertion_pb2.ASSERTION_STATUS_EFFECTIVE, op=assertion_pb2.ASSERTION_OP_ASSERT,
                                body=operand_display_body(0x10, 7, operand=1, equate="SEVEN"))
    b = assertion_pb2.Assertion(seq=6, status=assertion_pb2.ASSERTION_STATUS_SHADOWED, op=assertion_pb2.ASSERTION_OP_ASSERT,
                                body=operand_display_body(0x20, 7, operand=0, equate="SEVEN"))
    c = assertion_pb2.Assertion(seq=7, status=assertion_pb2.ASSERTION_STATUS_EFFECTIVE, op=assertion_pb2.ASSERTION_OP_ASSERT,
                                body=operand_display_body(0x30, 7, operand=0, format="char"))
    d = assertion_pb2.Assertion(seq=8, status=assertion_pb2.ASSERTION_STATUS_EFFECTIVE, op=assertion_pb2.ASSERTION_OP_ASSERT,
                                body=operand_display_body(0x08, 7, constant_hash=0xabc, equate="SEVEN"))
    t = fold_equates([a, b, c, d])
    assert list(t) == ["SEVEN"] and t["SEVEN"].seqs == [8, 5]
    assert t["SEVEN"].references[0].operand_index is None and t["SEVEN"].references[0].constant_hash == 0xabc
    # Two enums' members of one name (the server allows it) are two rows.
    def member(seq, at, value, enum):
        body = operand_display_body(at, value, operand=0, enum=enum, member="RED")
        body.operand_display.equate.name = "RED"  # as the server stores it
        return assertion_pb2.Assertion(seq=seq, status=assertion_pb2.ASSERTION_STATUS_EFFECTIVE,
                                       op=assertion_pb2.ASSERTION_OP_ASSERT, body=body)
    t = fold_equates([a, member(9, 0x40, 0, "aaaa1111bbbb2222"), member(10, 0x50, 5, "cccc3333dddd4444"),
                      member(11, 0x60, 0, "aaaa1111bbbb2222")])
    assert list(t) == ["RED#aaaa1111bbbb", "RED#cccc3333dddd", "SEVEN"]
    assert t["RED#aaaa1111bbbb"].name == "RED" and t["RED#aaaa1111bbbb"].seqs == [9, 11]
    assert t["RED#cccc3333dddd"].value == 5


@pytest.mark.skipif(not X86_64, reason="the hidden target is x86-64 code")
def test_computed_call_reference_makes_a_function_the_decompiler_calls(prog):
    hidden = sym(prog, "anchor_fn") + 16
    assert hidden not in entries(prog)
    ct = sym(prog, "call_through")
    call = next(r.address.offset for r in rows(prog, ct) if r.flow == listing_pb2.FLOW_KIND_INDIRECT_CALL)
    assert "(*" in decompiled(prog, "call_through")

    ref = prog.add_reference(call, hidden, "computed_call", primary=True)
    assert ref.assertions[0].key.kind == common_pb2.FACT_KIND_REFERENCE
    assert ref.assertions[0].key.sub == f"i:{hidden:x}"
    assert hidden in entries(prog)
    after = decompiled(prog, "call_through")
    assert f"FUN_{hidden:08x}(" in after and "(*" not in after, after
    x = next(x for x in prog.xrefs_to(hidden) if x.from_address.offset == call)
    assert x.kind == listing_pb2.XREF_KIND_INDIRECT_CALL and x.primary
    assert x.origin.asserted.seq == ref.assertions[0].seq and not x.HasField("operand_index")
    # Not primary any more: still a function, the call computed again.
    plain = prog.set_primary_reference(call, hidden, primary=False)
    assert plain.assertions[0].key.sub == f"i:{hidden:x}"
    assert not plain.assertions[0].body.reference.primary
    assert plain.assertions[0].body.reference.type == assertion_pb2.REFERENCE_TYPE_COMPUTED_CALL
    undo(prog, plain)
    undo(prog, ref)
    assert hidden not in entries(prog)
    assert "(*" in decompiled(prog, "call_through")


def test_remove_an_analysis_reference_and_a_primary_data_reference(prog):
    main, is_a = sym(prog, "main"), sym(prog, "is_a")
    frm = next(x.from_address.offset for x in prog.xrefs_to(is_a) if x.from_function.offset == main)
    removed = prog.remove_reference(frm, is_a)
    assert removed.assertions[0].body.reference.remove
    assert all(x.from_address.offset != frm for x in prog.xrefs_to(is_a))
    assert is_a in entries(prog)  # discovery keeps what it found
    undo(prog, removed)
    assert any(x.from_address.offset == frm for x in prog.xrefs_to(is_a))

    # A primary data reference on weigh's 0x1234 shows table_g in the operand.
    table = sym(prog, "table_g")
    imul, op = scalar_in(prog, sym(prog, "weigh"), 0x1234)
    data = prog.add_reference(imul, table, "read", operand=op, primary=True)
    assert data.assertions[0].key.sub == f"{op}:{table:x}"
    t = operand(prog, imul, op)
    assert t.text == "table_g" and t.target.offset == table
    assert t.reference_origin.asserted.seq == data.assertions[0].seq
    x = next(x for x in prog.xrefs_to(table) if x.from_address.offset == imul)
    assert x.kind == listing_pb2.XREF_KIND_DATA_READ and x.operand_index == op and x.primary
    # Not primary: the scalar again, the reference still listed.
    prog.set_primary_reference(imul, table, primary=False)
    t = operand(prog, imul, op)
    assert t.kind == SCALAR and not t.HasField("reference_origin")
    assert any(x.from_address.offset == imul for x in prog.xrefs_to(table))
    # Delete the user's own: found on its operand.
    gone = prog.remove_reference(imul, table)
    assert gone.assertions[0].key.sub == f"{op}:{table:x}"
    assert all(x.from_address.offset != imul for x in prog.xrefs_to(table))
    with pytest.raises(InvalidArgument):
        prog.add_reference(table, is_a, "call")  # no instruction there


SCRIPT = """\
# @category Tests
# @description Names constants and fixes a reference
from revkit.script import *
cmp = ask_address("cmp", "is_a's compare")
convert(cmp, 0x41, "char")
set_equate("add7", 7, "SEVEN", apply_to="function")
set_equate(ask_address("seven", "add7's 7"), 7, "SEVEN")
add_reference(cmp, "table_g", "read")
remove_reference(ask_address("call", "main's call of is_a"), "is_a")
assert pending_edits() == 5
assert "SEVEN" not in equates()
commit()
assert "SEVEN" in equates()
rename_equate("SEVEN", "WEEK")
assert pending_edits() == 1
"""


def test_script_edits_are_one_revision(rk, prog, tmp_path):
    s = tmp_path / "name_constants.py"
    s.write_text(SCRIPT)
    is_a, main = sym(prog, "is_a"), sym(prog, "main")
    cmp, op = scalar_in(prog, is_a, 0x41)
    seven, _ = scalar_in(prog, sym(prog, "add7"), 7)
    call = next(x.from_address.offset for x in prog.xrefs_to(is_a) if x.from_function.offset == main)
    host = HeadlessHost({"cmp": hex(cmp), "seven": hex(seven), "call": hex(call)}, out=io.StringIO(),
                        err=io.StringIO(), interactive=False)
    r = run_script(s, client=rk, program_id=prog.id, host=host)
    # set_equate("add7", ...) names the function's entry, which holds no 7: the commit refuses it.
    assert r.status == "error" and "name_constants.py:6" in r.error, r.error
    assert prog.assertions(kinds=("equate", "reference")) == []

    s.write_text(SCRIPT.replace('set_equate("add7", 7, "SEVEN", apply_to="function")\n', 'note(cmp, "x")\n'))
    r = run_script(s, client=rk, program_id=prog.id, host=host)
    assert r.ok, (r.error, r.traceback)
    assert len(r.revisions) == 2
    mine = prog.assertions(session=r.run_id)
    assert mine and all(m.provenance.kind == common_pb2.PROVENANCE_KIND_SCRIPT for m in mine)
    kinds = [m.key.kind for m in mine]
    assert kinds.count(common_pb2.FACT_KIND_REFERENCE) == 2 and kinds.count(common_pb2.FACT_KIND_EQUATE) >= 3
    assert operand(prog, cmp, op).text == "'A'"
    assert list(prog.equates()) == ["WEEK"]
    assert all(x.from_address.offset != call for x in prog.xrefs_to(is_a))

    prog.revert(session=r.run_id, actor="user:alice")
    assert operand(prog, cmp, op).text == "0x41" and prog.equates() == {}
    assert any(x.from_address.offset == call for x in prog.xrefs_to(is_a))
