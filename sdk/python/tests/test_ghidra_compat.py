"""revkit.ghidra.compat: Ghidra-style scripts on revkit (docs/scripting.md,
"Running Ghidra scripts").

The shim's API on the compiled fixture (tests/fixtures/script_target.c):
reads, buffered edits with script provenance, structural edits the script
sees, the decompiler, types, prompts, Unsupported and its table, detection,
Python 2 errors and rk-script. Then the corpus (tests/ghidra_corpus): the
30 ported Ghidra scripts, each run under the shim; with Ghidra's recorded
results for this very binary (expected/<sha12>.json) they are compared and
the gate checked; the live comparison through PyGhidra is the
ghidra_compat_corpus test."""

import hashlib
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from revkit import Client, Daemon
from revkit.ghidra.compat import UNSUPPORTED, Unsupported, is_ghidra_script, python2_hint
from revkit.script import HeadlessHost, parse_metadata, run_script

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "ghidra_corpus"
sys.path.insert(0, str(CORPUS))


@pytest.fixture(scope="module")
def daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture(scope="module")
def rk(daemon):
    with Client(daemon.grpc_target, actor="user:tester") as c:
        yield c


@pytest.fixture(scope="module")
def plain(rk, script_target):
    pid = rk.import_program("default", path=str(script_target["plain"]), name="script_target").program.program_id
    import time

    prog = rk.program(pid)
    deadline = time.monotonic() + 120
    while not prog.analysis_status().idle and time.monotonic() < deadline:
        time.sleep(0.2)
    return pid


def ghidra(rk, program, tmp_path, source, *, args=None, script_args=None, address=None, selection=None,
           name="g.py", compat="auto"):
    """Runs Ghidra-style source; returns (result, stdout, stderr)."""
    path = tmp_path / name
    path.write_text(source)
    host = HeadlessHost(args or {}, out=io.StringIO(), err=io.StringIO(), interactive=False)
    ctx = {}
    if script_args is not None:
        ctx["script_args"] = list(script_args)
    if address is not None:
        ctx["address"] = hex(address)
    if selection is not None:
        ctx["selection"] = [hex(selection[0]), hex(selection[1])]
    r = run_script(path, client=rk, program_id=program, args=args or {}, host=host, context=ctx, compat=compat)
    return r, host.out.getvalue(), host.err.getvalue()


def fn(rk, program, name):
    return next(f for f in rk.program(program).functions() if f.name == name)


def undo(rk, program, r):
    if r.revisions:
        rk.program(program).revert(session=r.run_id, actor="user:tester")


# ---------------------------------------------------------------------------
# Detection, metadata, Python 2
# ---------------------------------------------------------------------------


def test_detection():
    assert is_ghidra_script("from ghidra.program.model.listing import Function\n")
    assert is_ghidra_script("import ghidra.app.script.GhidraScript\n")
    assert is_ghidra_script("print(currentProgram.getName())\n")
    assert is_ghidra_script("# @runtime Jython\nprint 'x'\n")
    assert not is_ghidra_script("from revkit.script import *\nfor f in current_program.functions(): pass\n")
    assert not is_ghidra_script("x = 1  # no currentProgram here? yes: currentProgram\nimport revkit\n")
    assert not is_ghidra_script("import os\nprint(os.getcwd())\n")
    assert is_ghidra_script("a = toAddr(0x1000)\nprintln(str(a))\n")
    assert not is_ghidra_script("from revkit.script import *\nprintln = print\nprintln('x')\n")


def test_metadata_reads_ghidra_conventions():
    m = parse_metadata((CORPUS / "scripts" / "RecursiveStringFinder.py").read_bytes(), "RecursiveStringFinder.py")
    assert m.category == "Functions"
    assert m.description.startswith("Given a function, find all strings used within all called funtions. Handles only")
    m = parse_metadata((CORPUS / "scripts" / "IterateFunctionsScript.py").read_bytes(), "x.py")
    assert m.category == "Examples" and m.description == "Iterates over all functions in the current program."
    assert "Licensed" not in m.description and not m.errors


def test_python2_script_says_what_to_change(rk, plain, tmp_path):
    r, out, err = ghidra(rk, plain, tmp_path, "# @runtime Jython\nprint 'hello', currentProgram.name\n")
    assert r.status == "error" and r.error_type == "SyntaxError"
    assert "Jython (Python 2)" in r.error and "print(" in r.error
    assert python2_hint("print('x')\n", SyntaxError("x")) is None


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

READS = '''
from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import SourceType, RefType
from ghidra.program.model.listing import CodeUnit, CommentType
from ghidra.program.model.data import StringDataType
fm = currentProgram.getFunctionManager()
println("lang " + str(currentProgram.getLanguage().getLanguageID()) + " cspec " +
        str(currentProgram.getCompilerSpec().getCompilerSpecID()) + " ptr " +
        str(currentProgram.getDefaultPointerSize()))
println("min " + str(currentProgram.getMinAddress()) + " base " + str(currentProgram.getImageBase()))
main = getFunction("main")
println("main " + str(main.getEntryPoint()) + " " + str(main.getBody().getNumAddresses()))
println("count " + str(fm.getFunctionCount()) + " " + str(len(list(fm.getFunctions(True)))))
println("containing " + fm.getFunctionContaining(main.getEntryPoint().add(4)).getName())
println("first " + getFirstFunction().getName() + " last " + getLastFunction().getName())
a = main.getEntryPoint()
println("addr " + str(a.add(0x10)) + " " + str(a.add(0x10).subtract(a)) + " " + str(a.subtract(1)) + " " +
        str(a.getOffset() == a.add(0).getOffset()) + " " + str(toAddr("0x" + str(a)) == a))
s = AddressSet(a, a.add(0xf)); s.add(a.add(0x20), a.add(0x2f)); s.delete(a.add(0x8), a.add(0x27))
println("set " + str(s) + " n=" + str(s.getNumAddresses()) + " ranges=" + str(s.getNumAddressRanges()))
ins = getInstructionAt(a)
println("insn " + str(ins) + " len " + str(ins.getLength()) + " next " + str(ins.getNext().getAddress()))
calls = [i for i in currentProgram.getListing().getInstructions(main.getBody(), True) if i.getFlowType().isCall()]
println("calls " + str(len(calls)) + " " + calls[0].getDefaultOperandRepresentation(0))
d = getDataAt(getSymbol("unused_message", None).getAddress())
println("data " + d.getMnemonicString() + " " + repr(d.getValue()) + " " + str(isinstance(d.getDataType(), StringDataType)))
println("int " + hex(getInt(getSymbol("sha256_iv", None).getAddress()) & 0xffffffff))
mem = currentProgram.getMemory()
println("block " + mem.getBlock(main.getEntryPoint()).getName() + " exec " + str(mem.getExecuteSet().contains(a)))
hit = findBytes(toAddr(0), "\\\\x63\\\\x7c\\\\x77\\\\x7b")
println("find " + str(hit == getSymbol("aes_sbox", None).getAddress()))
hits = findBytes(None, "\\\\x63\\\\x7c.\\\\x7b", 5, 1)
println("hits " + str(len(hits)))
mf = mem.findBytes(a, bytes([0xf3, 0x0f, 0x1e, 0xfa]), None, True, monitor)
println("memfind " + str(mf == a))
refs = getReferencesTo(getFunction("decrypt").getEntryPoint())
println("refs " + str([(str(r.getReferenceType()), r.getFromAddress() in main.getBody()) for r in refs]))
sym = getSymbolAt(main.getEntryPoint())
println("sym " + sym.getName() + " " + str(sym.getSymbolType()) + " " + str(sym.getSource()))
println("callers " + str(sorted(f.getName() for f in getFunction("decrypt").getCallingFunctions(monitor))))
println("bean " + currentProgram.name + " " + ins.mnemonicString + " " + str(ins.address == a))
'''


def test_reads(rk, plain, tmp_path):
    r, out, err = ghidra(rk, plain, tmp_path, READS)
    assert r.ok and r.compat == "ghidra", (r.error, r.traceback, err)
    lines = dict(l.split(" ", 1) for l in out.splitlines())
    assert lines["lang"].startswith("x86:LE:64:default cspec gcc ptr 8")
    assert lines["min"].startswith("00100000")
    main = fn(rk, plain, "main")
    assert lines["main"].startswith(f"{main.entry.offset:08x} ")
    n = sum(1 for _ in rk.program(plain).functions())
    assert lines["count"] == f"{n} {n}"
    assert lines["containing"] == "main"
    assert lines["first"] == "_init last _fini"
    e = main.entry.offset
    assert lines["addr"] == f"{e + 0x10:08x} 16 {e - 1:08x} True True"
    assert lines["set"] == f"[[{e:08x}, {e + 7:08x}], [{e + 0x28:08x}, {e + 0x2f:08x}]] n=16 ranges=2"
    assert lines["insn"].startswith("ENDBR64 len 4 next ")
    assert lines["calls"].startswith("7 0x00")  # a call's target: Ghidra's "0x00101189"
    assert lines["data"] == "ds 'this string is never referenced' True"
    assert lines["int"] == "0x6a09e667"
    assert lines["block"] == ".text exec True"
    assert lines["find"] == "True" and lines["hits"] == "1" and lines["memfind"] == "True"
    assert lines["refs"] == "[('UNCONDITIONAL_CALL', True)]"
    assert lines["sym"] == "main FUNCTION IMPORTED"
    assert lines["callers"] == "['main']"
    assert lines["bean"] == "script_target ENDBR64 True"
    assert not r.revisions


RELOCS = '''
t = currentProgram.getRelocationTable()
rels = list(t.getRelocations())
println("size %d %d %s" % (t.getSize(), len(rels), t.isRelocatable()))
fp = [r for r in rels if r.getSymbolName() == "strlen"]
println("strlen %d %s" % (len(fp), fp[0].getAddress() if fp else None))
a = rels[0].getAddress()
println("at %s %s" % (t.hasRelocation(a), len(t.getRelocations(a))))
println("after %s" % t.getRelocationAddressAfter(a))
println("status %s len %d" % (rels[0].getStatus(), rels[0].getLength()))
'''


def test_relocation_table(rk, plain, tmp_path):
    """The relocation table (feature relocation-table): the SDK's relocations()
    and the shim's getRelocationTable() agree."""
    rels = list(rk.program(plain).relocations())
    assert rels and [r.address.offset for r in rels] == sorted(r.address.offset for r in rels)
    assert all(r.type_name.startswith("R_X86_64_") and len(r.original) == 8 for r in rels)
    [slot] = [r for r in rels if r.symbol == "strlen"]
    assert list(rk.program(plain).relocations("STRLEN")) == [slot]
    assert any(r.type_name == "R_X86_64_RELATIVE" and r.HasField("target") for r in rels)
    r, out, err = ghidra(rk, plain, tmp_path, RELOCS)
    assert r.ok, (r.error, r.traceback, err)
    lines = dict(l.split(" ", 1) for l in out.splitlines())
    assert lines["size"] == f"{len(rels)} {len(rels)} True"
    assert lines["strlen"] == f"1 {slot.address.offset:08x}"
    assert lines["at"] == "True 1"
    assert lines["after"] == f"{rels[1].address.offset:08x}"
    assert lines["status"] == "UNKNOWN len 8"


# ---------------------------------------------------------------------------
# Edits
# ---------------------------------------------------------------------------

EDITS = '''
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit, CommentType
main = getFunction("main")
a = main.getEntryPoint()
setEOLComment(a, "eol here")
setPlateComment(a, "plate here")
currentProgram.getListing().getCodeUnitAt(a.add(4)).setComment(CodeUnit.PRE_COMMENT, "pre here")
println("read back " + getEOLComment(a) + "|" + main.getComment() + "|" + str(getPostComment(a)))
createLabel(a.add(4), "after_endbr", True)
getFunction("mix").setName("mixer", SourceType.USER_DEFINED)
println("names " + getSymbolAt(a.add(4)).getName() + " " + getFunctionAt(getFunction("mixer").getEntryPoint()).getName())
'''


def test_edits_are_one_revision_with_script_provenance(rk, plain, tmp_path):
    prog = rk.program(plain)
    r, out, err = ghidra(rk, plain, tmp_path, EDITS, name="edits.py")
    assert r.ok, (r.error, r.traceback, err)
    assert "read back eol here|plate here|None" in out and "names after_endbr mixer" in out
    assert len(r.revisions) == 1 and r.assertions == 5
    asserted = prog.assertions(session=r.run_id)
    assert {a.provenance.tool for a in asserted} == {f"script:edits@{r.version}"}
    assert {a.provenance.kind for a in asserted} == {7}  # PROVENANCE_KIND_SCRIPT
    assert "mixer" in {f.name for f in prog.functions()}
    undo(rk, plain, r)
    assert "mixer" not in {f.name for f in prog.functions()}


STRUCTURAL = '''
mix = getFunction("mix")
entry = mix.getEntryPoint()
removeFunction(mix)
println("removed " + str(getFunctionAt(entry)))
f = createFunction(entry, "mix_again")
println("created " + str(f) + " " + str(f.getBody().getNumAddresses() > 8))
println("again " + str(createFunction(entry, None)))
from ghidra.program.model.data import IntegerDataType, StringDataType, ArrayDataType, ByteDataType, PointerDataType
iv = getSymbol("sha256_iv", None).getAddress()
d = createData(iv, IntegerDataType())
println("int " + d.getDataType().getName() + " " + str(d.getLength()) + " " + str(d.getValue()))
arr = createData(iv.add(4), ArrayDataType(ByteDataType.dataType, 4, 1))
println("array " + str(arr.getLength()))
s = createAsciiString(getSymbol("unused_message", None).getAddress())
println("string " + str(s.getValue()))
clearListing(iv, iv.add(7))
println("cleared " + str(getDataAt(iv).isDefined()))
'''


def test_structural_edits_are_seen_by_the_script(rk, plain, tmp_path):
    prog = rk.program(plain)
    r, out, err = ghidra(rk, plain, tmp_path, STRUCTURAL, name="structural.py")
    assert r.ok, (r.error, r.traceback, err)
    assert "removed None" in out and "created mix_again True" in out and "again None" in out
    assert "int int 4 0x6a09e667" in out and "array 4" in out
    assert "string this string is never referenced" in out and "cleared False" in out
    # Committed before each read that needed them: several revisions, one run.
    assert len(r.revisions) >= 3
    assert {a.provenance.session for a in prog.assertions(session=r.run_id)} == {r.run_id}
    undo(rk, plain, r)
    assert "mix" in {f.name for f in prog.functions()}


def test_memory_writes_are_patches_of_the_run(rk, plain, tmp_path):
    prog = rk.program(plain)
    secret = next(prog.symbols(name_equals="secret")).address.offset
    src = f'''
a = toAddr({secret})
for i in range(12):
    setByte(a.add(i), getByte(a.add(i)) ^ 0x5a)
println("now " + bytes(getBytes(a, 12)).decode())
'''
    r, out, err = ghidra(rk, plain, tmp_path, src, name="xor.py")
    assert r.ok, (r.error, r.traceback, err)
    assert "now hello secret" in out
    assert prog.read_memory(secret, 12) == b"hello secret" and r.revisions
    undo(rk, plain, r)
    assert prog.read_memory(secret, 12) != b"hello secret"


# ---------------------------------------------------------------------------
# Decompiler, types
# ---------------------------------------------------------------------------

DECOMPILE = '''
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.pcode import HighFunctionDBUtil, PcodeOp
from ghidra.program.model.symbol import SourceType
ifc = DecompInterface()
ifc.setOptions(DecompileOptions())
println("open " + str(ifc.openProgram(currentProgram)))
res = ifc.decompileFunction(getFunction("main"), 30, monitor)
println("done " + str(res.decompileCompleted()))
c = res.getDecompiledFunction().getC()
println("c " + str("main(" in c and "decrypt(" in c))
high = res.getHighFunction()
lsm = high.getLocalSymbolMap()
names = [s.getName() for s in lsm.getSymbols()]
println("params " + str(lsm.getNumParams()) + " " + lsm.getParamSymbol(0).getName())
ops = list(high.getPcodeOps())
println("ops " + str(len(ops) > 20) + " " + str(any(op.getOpcode() == PcodeOp.CALL for op in ops)))
println("mapped " + str(any(v.getHigh() is not None for op in ops for v in op.getInputs())))
HighFunctionDBUtil.updateDBVariable(lsm.getParamSymbol(0), "argc", None, SourceType.USER_DEFINED)
'''


def test_decompiler(rk, plain, tmp_path):
    r, out, err = ghidra(rk, plain, tmp_path, DECOMPILE, name="dec.py")
    assert r.ok, (r.error, r.traceback, err)
    assert "open True" in out and "done True" in out and "c True" in out
    assert "params 2 param_1" in out and "ops True True" in out and "mapped True" in out
    main = fn(rk, plain, "main").entry.offset
    d = rk.program(plain).decompile(main)
    assert any(v.name == "argc" for v in d.variables), [v.name for v in d.variables]
    undo(rk, plain, r)


EQUATES = '''
from ghidra.program.model.symbol import RefType, SourceType
listing = currentProgram.getListing()
f = getFunction("raw_getpid")
target = None
for ins in listing.getInstructions(f.getBody(), True):
    for i in range(ins.getNumOperands()):
        sc = ins.getScalar(i)
        if sc is not None and sc.getValue() == 39:
            target = (ins, i)
ins, op = target
eq = createEquate(ins, op, "SYS_getpid")
println("equate " + eq.getName() + " " + str(eq.getValue()) + " " + eq.getDisplayValue())
table = currentProgram.getEquateTable()
e = table.getEquate("SYS_getpid")
r0 = e.getReferences()[0]
println("table " + str(e.getReferenceCount()) + " " + str(r0.getAddress() == ins.getAddress()) + " " + str(r0.getOpIndex() == op))
println("at " + ",".join(x.getName() for x in table.getEquates(ins.getAddress(), op)) + " " + str(table.getEquate(ins.getAddress(), op, 39)))
println("default " + getInstructionAt(ins.getAddress()).getDefaultOperandRepresentation(op))
println("addresses " + str([a == ins.getAddress() for a in table.getEquateAddresses()]))
spare = table.createEquate("UNUSED", 1234)
println("spare " + str(table.getEquate("UNUSED").getReferenceCount()) + " " + str(len(list(table.getEquates()))))
try:
    table.createEquate("UNUSED", 5)
except Exception as x:
    println("duplicate " + type(x).__name__)
e.renameEquate("NR_getpid")
println("renamed " + str(table.getEquate("SYS_getpid")) + " " + str(table.getEquate("NR_getpid").getReferenceCount()))
main = getFunction("main").getEntryPoint()
mix = getFunction("mix").getEntryPoint()
call = [r for r in getReferencesTo(mix) if getFunctionContaining(r.getFromAddress()).getEntryPoint() == main][0]
removeReference(call)
println("removed " + str(len([r for r in getReferencesTo(mix) if r.getFromAddress() == call.getFromAddress()])))
iv = getSymbol("sha256_iv", None).getAddress()
ref = createMemoryReference(ins, op, iv, RefType.READ)
println("ref " + str(ref.getReferenceType()) + " " + str(ref.getOperandIndex() == op))
mine = [r for r in getReferencesTo(iv) if r.getFromAddress() == ins.getAddress()]
println("listed " + str(len(mine)) + " " + str(mine[0].getReferenceType()) + " " + str(mine[0].isPrimary()))
setReferencePrimary(mine[0], True)
println("primary " + str([r.isPrimary() for r in currentProgram.getReferenceManager().getReferencesFrom(ins.getAddress(), op)]))
'''


def test_equates_and_references(rk, plain, tmp_path):
    prog = rk.program(plain)
    r, out, err = ghidra(rk, plain, tmp_path, EQUATES, name="equates.py")
    assert r.ok, (r.error, r.traceback, err)
    assert "equate SYS_getpid 39 0x27" in out and "table 1 True True" in out, out
    assert "at SYS_getpid SYS_getpid" in out and "default 0x27" in out and "addresses [True]" in out, out
    assert "spare 0 2" in out and "duplicate DuplicateNameException" in out, out
    assert "renamed None 1" in out and "removed 0" in out, out
    assert "ref READ True" in out and "listed 1 READ True" in out and "primary [True]" in out, out
    # Committed with the run's provenance: the program has the equate; revert takes it all back.
    assert list(prog.equates()) == ["NR_getpid"]
    asserted = prog.assertions(session=r.run_id)
    assert {a.provenance.kind for a in asserted} == {7}  # PROVENANCE_KIND_SCRIPT
    undo(rk, plain, r)
    assert prog.equates() == {}
    mix = fn(rk, plain, "mix").entry.offset
    main = fn(rk, plain, "main")
    assert any(x.from_function.offset == main.entry.offset for x in prog.xrefs_to(mix))


TYPES = '''
from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import DataTypeConflictHandler
dtm = currentProgram.getDataTypeManager()
println("int " + dtm.getDataType("/int").getName() + " " + str(dtm.getDataType("/int").getLength()))
println("dword " + str(dtm.getDataType("/dword").getLength()))
dt = CParser(dtm).parse("struct sha_iv { unsigned int h[8]; };")
added = dtm.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER)
println("added " + added.getName() + " " + str(dtm.getDataType("/sha_iv") is not None))
d = createData(getSymbol("sha256_iv", None).getAddress(), added)
println("data " + str(d.getLength()))
'''


def test_types_and_cparser(rk, plain, tmp_path):
    r, out, err = ghidra(rk, plain, tmp_path, TYPES, name="types.py")
    assert r.ok, (r.error, r.traceback, err)
    assert "int int 4" in out and "dword 4" in out and "added sha_iv True" in out and "data 32" in out
    undo(rk, plain, r)


# ---------------------------------------------------------------------------
# Prompts, output, context
# ---------------------------------------------------------------------------

PROMPTS = '''
s = askString("Name", "Your name?")
n = askInt("Count", "How many?")
yes = askYesNo("Go", "Go on?")
pick = askChoice("Pick", "Which one?", ["red", "green", "blue"], "red")
a = askAddress("Where", "Address?")
println("got " + s + " " + str(n) + " " + str(yes) + " " + pick + " " + str(a) + " " + str(getScriptArgs()))
printf("%s=%05d|%-4s|%x\\n", "pad", 42, "ab", 255)
popup("look")
println("here " + str(currentAddress) + " sel " + str(currentSelection))
'''


def test_prompts_take_script_args_in_order_then_arg_names(rk, plain, tmp_path):
    main = fn(rk, plain, "main").entry.offset
    r, out, err = ghidra(rk, plain, tmp_path, PROMPTS, script_args=["ann", "3"],
                         args={"Go": "yes", "Pick": "blue", "Where": "main"}, address=main, selection=(main, main + 3))
    assert r.ok, (r.error, r.traceback, err)
    assert f"got ann 3 True blue {main:08x} ['ann', '3']" in out
    assert "pad=00042|ab  |ff" in out
    assert "INFO look" in err  # headless popup: Ghidra logs it (Msg.info)
    assert f"here {main:08x} sel [[{main:08x}, {main + 3:08x}]]" in out
    r, out, err = ghidra(rk, plain, tmp_path, PROMPTS, script_args=["ann"])
    assert r.status == "error" and "Count" in r.error


# ---------------------------------------------------------------------------
# Unsupported
# ---------------------------------------------------------------------------


def test_unsupported_names_the_api_and_the_replacement(rk, plain, tmp_path):
    cases = {
        "getFunction('main').setNoReturn(True)": "Function.setNoReturn: give the prototype as C",
        "createBookmark(toAddr(0x101000), 'c', 'x')": "createBookmark: revkit has notes",
        "currentProgram.getBookmarkManager()": "Program.getBookmarkManager: revkit has notes",
        "state.getTool()": "state.getTool: revkit scripts run without a Ghidra tool",
        "from ghidra.program.model.block import BasicBlockModel\nBasicBlockModel(currentProgram)":
            "ghidra.program.model.block.BasicBlockModel: the function's blocks",
        "from java.util import ArrayList\nArrayList()": "java.util.ArrayList: Java classes aren't available",
        "currentProgram.getListing().getInstructionAt(toAddr(0x101000)).getPrototype()": "Instruction.getPrototype",
        "currentProgram.getReferenceManager().addStackReference(toAddr(0x101000), 0, 8, None, None)":
            "ReferenceManager.addStackReference: revkit has no stack references",
    }
    for src, want in cases.items():
        r, out, err = ghidra(rk, plain, tmp_path, src + "\n", name="u.py", compat="ghidra")
        assert r.status == "error" and r.error_type == "Unsupported", (src, r.error)
        assert r.error.startswith("Unsupported: " + want), (src, r.error)
    # An import the script never uses costs nothing; hasattr probes say no.
    r, out, err = ghidra(rk, plain, tmp_path, "from java.util import Set\nfrom ghidra.app.services import GoToService\n"
                         "println(str(hasattr(getFunction('main'), 'setNoReturn')) + ' ' + str(hasattr(getFunction('main'), 'getName')))\n")
    assert r.ok and out.strip() == "False True", (r.error, out)


def test_every_unsupported_api_is_documented():
    doc = (HERE.parents[2] / "docs" / "scripting.md").read_text()
    missing = [k for k in UNSUPPORTED if f"`{k}`" not in doc]
    assert not missing, missing


def test_unsupported_is_both_kinds_of_error():
    e = Unsupported("createBookmark")
    assert isinstance(e, NotImplementedError) and isinstance(e, AttributeError)
    assert str(e).startswith("createBookmark: revkit has notes")


# ---------------------------------------------------------------------------
# rk-script
# ---------------------------------------------------------------------------


def test_rk_script_runs_a_ghidra_script(daemon, plain, tmp_path):
    script = CORPUS / "scripts" / "IterateFunctionsByAddressScript.py"
    env = dict(os.environ, PYTHONPATH=str(HERE.parent))
    cmd = [sys.executable, "-m", "revkit.script.cli", "run", str(script), "--daemon", daemon.grpc_target,
           "--program", plain, "--script-arg", "true", "--json"]
    p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    summary = json.loads(p.stdout.splitlines()[-1]) if p.stdout.strip().startswith("{") else json.loads(p.stdout)
    run = summary["runs"][0] if isinstance(summary, dict) else summary[0]["runs"][0]
    assert run["compat"] == "ghidra" and run["status"] == "ok"
    assert "main @ " in p.stderr and "found " in p.stderr
    p = subprocess.run(cmd[:-1] + ["--compat", "off"], env=env, capture_output=True, text=True, timeout=120)
    assert p.returncode == 1 and "No module named 'ghidra'" in p.stderr


# ---------------------------------------------------------------------------
# The corpus: 30 of Ghidra's scripts
# ---------------------------------------------------------------------------


def test_corpus(rk, plain, script_target, tmp_path):
    import observe
    import run as corpus

    binary = Path(script_target["plain"])
    specs = corpus.scenarios("fixture")
    assert len([s for s in specs if not s.get("extra")]) == 30
    side = corpus.RevkitSide(rk, plain)
    observations = {s["name"]: side.run(s, tmp_path) for s in specs}
    recorded = corpus.recorded(binary).get("observations", {})
    rows = corpus.evaluate(specs, observations, recorded, side.blocks)
    counted = [r for r in rows if not next(s for s in specs if s["name"] == r["name"]).get("extra")]
    # The scripts revkit doesn't support fail with Unsupported naming the API.
    wrong = [r for r in counted if r["result"] == "wrong"]
    assert not wrong, wrong
    unsupported = [r for r in counted if r["result"] == "unsupported"]
    assert len(unsupported) == 6
    # The others run.
    errors = [r for r in counted if r["result"] == "error"]
    assert not errors, errors
    if not recorded:
        pytest.skip(f"no Ghidra results recorded for this fixture build ({hashlib.sha256(binary.read_bytes()).hexdigest()[:12]}); "
                    "the ghidra_compat_corpus test compares live")
    agree = [r for r in counted if r["result"] == "agree"]
    other = [r for r in counted if r["result"] not in ("agree", "unsupported") and not corpus._model_difference(r, specs)]
    assert not other, other
    assert len(agree) >= corpus.GATE, [r["name"] for r in counted if r["result"] != "agree"]
