#!/usr/bin/env python3
"""The Ghidra half of roundtrip_test.py (runs in the PyGhidra virtualenv).

    roundtrip_ghidra.py setup  --work DIR --binary BIN
        Creates a Ghidra project in DIR, imports and analyzes BIN, makes a
        scripted set of user edits through Ghidra's API (renames, comments of
        every kind, a struct, an enum and a typedef, a data retype, a
        signature, a local, a new function, a flow override, a bookmark, an
        equate, a no-return flag, an AI-sourced name), saves, and writes
        DIR/ghidra.json (ghidra_dump.py's export), DIR/ghidra-rebased.json
        (the same program rebased by 0x100000, not saved) and
        DIR/ghidra-edits.json (what was edited, for the checks).

    roundtrip_ghidra.py apply  --work DIR --changes revkit.json
        Applies revkit-ghidra-export's JSON with ghidra_apply.py, saves, and
        writes DIR/ghidra-after.json (what Ghidra now shows at the changed
        places) and DIR/ghidra2.json (a fresh export).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ghidra_apply  # noqa: E402
import ghidra_common as gc  # noqa: E402
import ghidra_dump  # noqa: E402

PROJECT = "roundtrip"


def h(a) -> str:
    return gc.hexaddr(a)


def pick(program):
    """Deterministic edit targets in the analyzed program."""
    fm, listing = program.getFunctionManager(), program.getListing()
    funcs = [f for f in fm.getFunctions(True) if f.getName().startswith("FUN_") and not f.isThunk()]
    funcs.sort(key=lambda f: (-int(f.getBody().getNumAddresses()), int(f.getEntryPoint().getOffset())))
    with_locals = [f for f in funcs if any(v.isStackVariable() for v in f.getLocalVariables())]
    f1 = with_locals[0]
    others = [f for f in funcs if f != f1]
    f2 = next(f for f in others if any(i.getFlowType().isCall() for i in listing.getInstructions(f.getBody(), True)))
    rest = [f for f in others if f != f2]
    return f1, f2, rest


def jump_target_inside(program, f, skip=()):
    """A conditional jump's target in f's body: a block start that isn't f's entry."""
    for ins in program.getListing().getInstructions(f.getBody(), True):
        ft = ins.getFlowType()
        if ft.isJump() and ft.isConditional():
            for t in ins.getFlows():
                if f.getBody().contains(t) and t != f.getEntryPoint() and int(t.getOffset()) not in skip:
                    return t
    return None


def free_bss(program, size: int, skip=()):
    """An address in .bss (or .data) with ``size`` bytes of undefined data."""
    listing = program.getListing()
    mem = program.getMemory()
    block = mem.getBlock(".bss") or mem.getBlock(".data")
    a = block.getStart().add(0x40)
    while a.add(size) < block.getEnd():
        if int(a.getOffset()) not in skip and all(listing.getDefinedDataContaining(a.add(i)) is None for i in range(size)):
            return a
        a = a.add(8)
    raise RuntimeError("no free .bss space")


def setup(work: str, binary: str) -> None:
    import pyghidra
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd, CreateFunctionCmd
    from ghidra.program.model.data import (CategoryPath, CharDataType, DataTypeConflictHandler, DataUtilities,
                                           EnumDataType, FunctionDefinitionDataType, IntegerDataType,
                                           ParameterDefinitionImpl, PointerDataType, StructureDataType,
                                           TypedefDataType)
    from ghidra.program.model.listing import CommentType, FlowOverride
    from ghidra.program.model.scalar import Scalar
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import TaskMonitor

    project = pyghidra.open_project(os.path.abspath(work), PROJECT, create=True)
    path = gc.import_binary(project, binary)
    project.close()

    edits: dict = {}
    with gc.open_program(os.path.join(work, PROJECT + ".gpr"), path, writable=True) as (_, p):
        listing, st, dtm = p.getListing(), p.getSymbolTable(), p.getDataTypeManager()
        U = SourceType.USER_DEFINED
        tx = p.startTransaction("scripted user edits")
        ok = False
        try:
            f1, f2, rest = pick(p)
            f3, f5, f4 = rest[0], rest[1], rest[2]
            e1 = f1.getEntryPoint()
            # Types: a struct, an enum and a typedef in a user category.
            cat = CategoryPath("/rt")
            point = StructureDataType(cat, "rt_point", 0, dtm)
            point.add(IntegerDataType.dataType, "x", None)
            point.add(IntegerDataType.dataType, "y", None)
            point.add(PointerDataType(CharDataType.dataType, dtm), "label", "what it is")
            point = dtm.addDataType(point, DataTypeConflictHandler.DEFAULT_HANDLER)
            color = EnumDataType(cat, "rt_color", 4, dtm)
            for i, n in enumerate(("RT_RED", "RT_GREEN", "RT_BLUE")):
                color.add(n, i)
            dtm.addDataType(color, DataTypeConflictHandler.DEFAULT_HANDLER)
            handle = dtm.addDataType(TypedefDataType(cat, "rt_handle", PointerDataType(point, dtm), dtm),
                                     DataTypeConflictHandler.DEFAULT_HANDLER)
            # Names: a function, an AI-named function, a global.
            f1.setName("rt_parse_options", U)
            f5.setName("rt_ai_named", SourceType.AI)
            g = free_bss(p, 4)
            DataUtilities.createData(p, g, IntegerDataType.dataType, -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
            st.createLabel(g, "rt_global_flag", U).setPrimary()
            # Data retype with the struct, named.
            d = free_bss(p, 16, skip=range(int(g.getOffset()) - 16, int(g.getOffset()) + 8))
            DataUtilities.createData(p, d, point, -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
            st.createLabel(d, "rt_origin", U).setPrimary()
            # Signature: int rt_parse_options(rt_handle p, int count).
            sig = FunctionDefinitionDataType("rt_parse_options", dtm)
            sig.setReturnType(IntegerDataType.dataType)
            sig.setArguments([ParameterDefinitionImpl("p", handle, None),
                              ParameterDefinitionImpl("count", IntegerDataType.dataType, None)])
            assert ApplyFunctionSignatureCmd(e1, sig, U).applyTo(p, TaskMonitor.DUMMY)
            # A stack local renamed and retyped.
            local = sorted((v for v in f1.getLocalVariables() if v.isStackVariable()), key=lambda v: -v.getStackOffset())[0]
            local.setName("rt_counter", U)
            local.setDataType(IntegerDataType.dataType, U)
            # Comments of every kind in f1.
            ins = list(listing.getInstructions(f1.getBody(), True))[:6]
            comments = {"plate": (e1, "rt plate: parses options"), "pre": (ins[1].getAddress(), "rt pre"),
                        "post": (ins[2].getAddress(), "rt post"), "eol": (ins[3].getAddress(), "rt eol"),
                        "repeatable": (ins[4].getAddress(), "rt repeatable")}
            kinds = {"plate": CommentType.PLATE, "pre": CommentType.PRE, "post": CommentType.POST,
                     "eol": CommentType.EOL, "repeatable": CommentType.REPEATABLE}
            for k, (a, text) in comments.items():
                listing.setComment(a, kinds[k], text)
            # A new function at a block start inside f2 (left unnamed: only
            # the baseline tells it is the user's).
            call = next(i for i in listing.getInstructions(f2.getBody(), True) if i.getFlowType().isCall())
            nf = jump_target_inside(p, f2)
            assert CreateFunctionCmd(nf).applyTo(p, TaskMonitor.DUMMY)
            # A flow override on f2's first call.
            call.setFlowOverride(FlowOverride.CALL_RETURN)
            # A bookmark, an equate, a no-return flag.
            p.getBookmarkManager().setBookmark(e1, "Note", "rt", "check the option parsing")
            eq_ins, eq_op, eq_val = None, 0, 0
            for i in listing.getInstructions(f1.getBody(), True):
                for op in range(i.getNumOperands()):
                    s = i.getScalar(op)
                    if isinstance(s, Scalar) and s.getUnsignedValue() > 1:
                        eq_ins, eq_op, eq_val = i, op, int(s.getValue())
                        break
                if eq_ins:
                    break
            p.getEquateTable().createEquate("RT_MAGIC", eq_val).addReference(eq_ins.getAddress(), eq_op)
            f3.setNoReturn(True)
            # A function deleted.
            removed = f4.getEntryPoint()
            p.getFunctionManager().removeFunction(removed)
            edits = {
                "f1": h(e1), "f5": h(f5.getEntryPoint()), "f3": h(f3.getEntryPoint()), "f2": h(f2.getEntryPoint()),
                "global": h(g), "origin": h(d), "local": {"name": "rt_counter", "stack_offset": int(local.getStackOffset())},
                "comments": {k: [h(a), t] for k, (a, t) in comments.items()},
                "new_function": h(nf), "flow_override": h(call.getAddress()), "removed_function": h(removed),
                "equate": [h(eq_ins.getAddress()), eq_op, eq_val],
            }
            ok = True
        finally:
            p.endTransaction(tx, ok)
        p.save("scripted user edits", TaskMonitor.DUMMY)

        doc = ghidra_dump.export(p, project=work)
        write(os.path.join(work, "ghidra.json"), doc)

        # The same program rebased (not saved): addresses must map back.
        tx = p.startTransaction("rebase")
        try:
            base = p.getImageBase()
            p.setImageBase(base.add(0x100000), True)
            write(os.path.join(work, "ghidra-rebased.json"), ghidra_dump.export(p, project=work))
        finally:
            p.endTransaction(tx, False)
    write(os.path.join(work, "ghidra-edits.json"), edits)


def apply(work: str, changes: str) -> None:
    from ghidra.util.task import TaskMonitor

    with open(changes) as f:
        doc = json.load(f)
    with gc.open_program(os.path.join(work, PROJECT + ".gpr"), None, writable=True) as (_, p):
        report = ghidra_apply.apply_doc(p, doc)
        p.save("revkit-ghidra-export", TaskMonitor.DUMMY)
        write(os.path.join(work, "apply-report.json"), report)
        # What Ghidra shows now at each changed place.
        after = observe(p, doc)
        write(os.path.join(work, "ghidra-after.json"), after)
    with gc.open_program(os.path.join(work, PROJECT + ".gpr"), None) as (_, p):
        write(os.path.join(work, "ghidra2.json"), ghidra_dump.export(p, project=work))


def observe(p, doc: dict) -> dict:
    from ghidra.program.model.listing import CommentType

    fm, listing, st = p.getFunctionManager(), p.getListing(), p.getSymbolTable()
    space = p.getAddressFactory().getDefaultAddressSpace()
    delta = int(p.getImageBase().getOffset()) - int(doc["program"]["image_base"], 16)
    bm = p.getBookmarkManager()
    out = []
    for ch in doc["changes"]:
        at = ch.get("address") or ch.get("function") or ch.get("entry")
        if at is None:
            continue
        a = space.getAddress(int(at, 16) + delta)
        o = {"seq": ch["seq"], "op": ch["op"], "address": at}
        sym = st.getPrimarySymbol(a)
        o["name"] = str(sym.getName()) if sym else ""
        o["name_source"] = str(sym.getSource()) if sym else ""
        f = fm.getFunctionAt(a)
        o["function"] = f is not None
        if f is not None:
            o["prototype"] = str(f.getPrototypeString(False, False))
            o["variables"] = {str(v.getName()): str(v.getDataType().getName()) for v in f.getAllVariables()}
            o["no_return"] = bool(f.hasNoReturn())
        for k, ct in (("eol", CommentType.EOL), ("pre", CommentType.PRE), ("post", CommentType.POST),
                      ("plate", CommentType.PLATE), ("repeatable", CommentType.REPEATABLE)):
            c = listing.getComment(ct, a)
            if c is not None:
                o.setdefault("comments", {})[k] = str(c)
        d = listing.getDataAt(a)
        if d is not None:
            o["data_type"] = str(d.getDataType().getName())
        ins = listing.getInstructionAt(a)
        if ins is not None:
            o["flow_override"] = str(ins.getFlowOverride())
        b = bm.getBookmark(a, ghidra_apply.BOOKMARK_TYPE, "revkit")
        o["trace"] = str(b.getComment()) if b is not None else ""
        o["notes"] = {str(x.getCategory()): str(x.getComment()) for x in bm.getBookmarks(a, ghidra_apply.BOOKMARK_TYPE)}
        out.append(o)
    types = {}
    for dt in p.getDataTypeManager().getAllDataTypes():
        if str(dt.getCategoryPath()) == ghidra_apply.CATEGORY:
            types[str(dt.getName())] = {"description": str(dt.getDescription() or ""), "length": int(dt.getLength())}
    return {"changes": out, "revkit_types": types}


def write(path: str, doc) -> None:
    with open(path, "w") as f:
        json.dump(doc, f, indent=1)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["setup", "apply"])
    ap.add_argument("--work", required=True)
    ap.add_argument("--binary")
    ap.add_argument("--changes")
    args = ap.parse_args()
    gc.start()
    if args.command == "setup":
        setup(args.work, args.binary)
    else:
        apply(args.work, args.changes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
