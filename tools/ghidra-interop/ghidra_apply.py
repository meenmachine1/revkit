#!/usr/bin/env python3
"""Apply revkit-ghidra-export JSON to a Ghidra program, headless.

    ghidra_apply.py --project ~/work/proj.gpr [--program /prog] prog.revkit.json

Runs in the PyGhidra virtualenv. Every change is applied in one Ghidra
transaction and the program is saved. Each change leaves a trace:

* a bookmark of type ``revkit`` (category ``revkit``) at its address whose
  comment names the assertion: ``user:alice #12 rename -> parse_header``;
  defined types get the same text as their description;
* an entry in the ``revkit.applied`` string property map at the address,
  which ghidra_dump.py uses to tell revkit's edits from the user's.

A change that can't be applied is reported and skipped (``--strict`` rolls
the whole transaction back instead). The format is docs/ghidra-interop.md.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ghidra_common as gc  # noqa: E402

BOOKMARK_TYPE = "revkit"
CATEGORY = "/revkit"


class Unsupported(Exception):
    pass


class TypeBuilder:
    """revkit TypeDefinitions (GetTypes, as JSON) to Ghidra data types."""

    def __init__(self, program, types: dict):
        from ghidra.program.model.data import CategoryPath

        self.p = program
        self.dtm = program.getDataTypeManager()
        self.types = types
        self.built: dict = {}
        self.cat = CategoryPath(CATEGORY)

    def get(self, h: str):
        if h in self.built:
            return self.built[h]
        d = self.types.get(h)
        if d is None:
            raise Unsupported(f"type {h} is not in the export")
        dt = self._build(h, d)
        self.built[h] = dt
        return dt

    def _int(self, d: dict):
        from ghidra.program.model.data import (AbstractIntegerDataType, CharDataType, LongDataType, LongLongDataType,
                                               IntegerDataType, ShortDataType, SignedCharDataType,
                                               UnsignedCharDataType, UnsignedIntegerDataType, UnsignedLongDataType,
                                               UnsignedLongLongDataType, UnsignedShortDataType, WideChar16DataType,
                                               WideChar32DataType, WideCharDataType)

        size = int(d.get("size", 0))
        kind = d.get("kind")
        signed = kind == "TYPE_KIND_INT"
        rank = d.get("rank", "INTEGER_RANK_UNSPECIFIED")
        if kind == "TYPE_KIND_CHAR":
            return CharDataType.dataType
        named = {
            "INTEGER_RANK_CHAR": (SignedCharDataType.dataType, UnsignedCharDataType.dataType),
            "INTEGER_RANK_SHORT": (ShortDataType.dataType, UnsignedShortDataType.dataType),
            "INTEGER_RANK_INT": (IntegerDataType.dataType, UnsignedIntegerDataType.dataType),
            "INTEGER_RANK_LONG": (LongDataType.dataType, UnsignedLongDataType.dataType),
            "INTEGER_RANK_LONG_LONG": (LongLongDataType.dataType, UnsignedLongLongDataType.dataType),
            "INTEGER_RANK_WCHAR": (WideCharDataType.dataType, WideCharDataType.dataType),
            "INTEGER_RANK_CHAR16": (WideChar16DataType.dataType, WideChar16DataType.dataType),
            "INTEGER_RANK_CHAR32": (WideChar32DataType.dataType, WideChar32DataType.dataType),
        }.get(rank)
        if named is not None:
            dt = named[0 if signed else 1].clone(self.dtm)
            if dt.getLength() == size:
                return dt
        return (AbstractIntegerDataType.getSignedDataType(size, self.dtm) if signed
                else AbstractIntegerDataType.getUnsignedDataType(size, self.dtm))

    def _existing(self, name: str, kind: str, d: dict):
        """A program type of this name and shape (one revkit got from Ghidra)."""
        from java.util import ArrayList  # type: ignore
        from ghidra.program.model.data import Composite, Enum, TypeDef

        found = ArrayList()
        self.dtm.findDataTypes(name, found)
        for dt in found:
            if kind in ("TYPE_KIND_STRUCT", "TYPE_KIND_UNION") and isinstance(dt, Composite):
                if dt.getLength() == int(d.get("size", 0)) or dt.isNotYetDefined():
                    names = [str(c.getFieldName() or "") for c in dt.getDefinedComponents()]
                    want = [f.get("name", "") for f in d.get("composite", {}).get("fields", [])]
                    if names == want:
                        return dt
            elif kind == "TYPE_KIND_ENUM" and isinstance(dt, Enum) and dt.getLength() == int(d.get("size", 0)):
                return dt
            elif kind == "TYPE_KIND_TYPEDEF" and isinstance(dt, TypeDef):
                return dt
        return None

    def _build(self, h: str, d: dict):
        from ghidra.program.model.data import (AbstractFloatDataType, ArrayDataType, BooleanDataType,
                                               DataTypeConflictHandler, EnumDataType, FunctionDefinitionDataType,
                                               ParameterDefinitionImpl, PointerDataType, StructureDataType,
                                               TypedefDataType, Undefined, UnionDataType, VoidDataType)

        kind = d.get("kind", "TYPE_KIND_UNSPECIFIED")
        size = int(d.get("size", 0))
        name = d.get("name", "")
        H = DataTypeConflictHandler.DEFAULT_HANDLER
        if kind == "TYPE_KIND_VOID":
            return VoidDataType.dataType
        if kind == "TYPE_KIND_BOOL":
            return BooleanDataType.dataType
        if kind in ("TYPE_KIND_INT", "TYPE_KIND_UINT", "TYPE_KIND_CHAR"):
            return self._int(d)
        if kind == "TYPE_KIND_FLOAT":
            return AbstractFloatDataType.getFloatDataType(size, self.dtm)
        if kind == "TYPE_KIND_UNDEFINED":
            return Undefined.getUndefinedDataType(max(size, 1))
        if kind == "TYPE_KIND_POINTER":
            target = self.get(d["pointer"]["target_hash"])
            return PointerDataType(target, size if size else -1, self.dtm)
        if kind == "TYPE_KIND_ARRAY":
            elem = self.get(d["array"]["element_hash"])
            n = int(d["array"].get("count", 0))
            return ArrayDataType(elem, n, elem.getLength(), self.dtm) if n else PointerDataType(elem, self.dtm)
        if kind == "TYPE_KIND_QUALIFIED":
            return self.get(d["qualified"]["target_hash"])  # Ghidra has no qualifiers
        if kind in ("TYPE_KIND_STRUCT", "TYPE_KIND_UNION", "TYPE_KIND_ENUM", "TYPE_KIND_TYPEDEF") and name:
            old = self._existing(name, kind, d)
            if old is not None:
                return old
        if kind in ("TYPE_KIND_STRUCT", "TYPE_KIND_UNION"):
            fields = d.get("composite", {}).get("fields", [])
            nm = name or f"anon_{h[:8]}"
            if kind == "TYPE_KIND_UNION":
                shell = self.dtm.resolve(UnionDataType(self.cat, nm, self.dtm), H)
            else:
                shell = self.dtm.resolve(StructureDataType(self.cat, nm, 0, self.dtm), H)
            self.built[h] = shell  # self references find the shell
            if kind == "TYPE_KIND_UNION":
                for f in fields:
                    shell.add(self.get(f["type_hash"]), f.get("name") or None, None)
            else:
                if size:
                    shell.growStructure(size)
                for f in fields:
                    ft = self.get(f["type_hash"])
                    off = int(f.get("offset", 0))
                    if int(f.get("bit_size", 0)):
                        width = ft.getLength()
                        shell.insertBitFieldAt(off, width, int(f.get("bit_offset", 0)), ft, int(f["bit_size"]),
                                               f.get("name") or None, None)
                    elif ft.getLength() > 0:
                        shell.replaceAtOffset(off, ft, ft.getLength(), f.get("name") or None, None)
                    else:
                        shell.insertAtOffset(off, ft, 0, f.get("name") or None, None)
            return shell
        if kind == "TYPE_KIND_ENUM":
            e = EnumDataType(self.cat, name or f"anon_{h[:8]}", size or 4, self.dtm)
            for v in d.get("enumeration", {}).get("values", []):
                e.add(v["name"], int(v.get("value", 0)))
            return self.dtm.resolve(e, H)
        if kind == "TYPE_KIND_TYPEDEF":
            return self.dtm.resolve(TypedefDataType(self.cat, name, self.get(d["typedef_type"]["target_hash"]), self.dtm), H)
        if kind == "TYPE_KIND_FUNCTION":
            fd = FunctionDefinitionDataType(self.cat, f"revkit_fn_{h[:8]}", self.dtm)
            fn = d.get("function", {})
            fd.setReturnType(self.get(fn["return_hash"]) if fn.get("return_hash") else VoidDataType.dataType)
            fd.setArguments([ParameterDefinitionImpl(p.get("name") or None, self.get(p["type_hash"]), None)
                             for p in fn.get("params", [])])
            fd.setVarArgs(bool(fn.get("varargs")))
            cc = fn.get("calling_convention", "")
            if cc and cc != "other":
                try:
                    fd.setCallingConvention(cc)
                except Exception:  # noqa: BLE001 - not a convention of this language
                    pass
            return fd
        raise Unsupported(f"type kind {kind}")


class Applier:
    def __init__(self, program, doc: dict, delta: int):
        from ghidra.program.model.symbol import SourceType

        self.p = program
        self.doc = doc
        self.delta = delta
        self.listing = program.getListing()
        self.fm = program.getFunctionManager()
        self.st = program.getSymbolTable()
        self.types = TypeBuilder(program, doc.get("types", {}))
        self.SourceType = SourceType
        self.marks: dict = {}  # address -> [text]
        bm = program.getBookmarkManager()
        if bm.getBookmarkType(BOOKMARK_TYPE) is None:
            from java.awt import Color  # type: ignore
            from javax.swing import ImageIcon  # type: ignore

            bm.defineType(BOOKMARK_TYPE, ImageIcon(), Color(0x2a, 0x7a, 0xbf), 0)

    def addr(self, text: str):
        return self.p.getAddressFactory().getDefaultAddressSpace().getAddress(int(text, 16) + self.delta)

    def source(self, ch: dict):
        kind = ch["provenance"].split(":", 1)[0]
        S = self.SourceType
        return {"user": S.USER_DEFINED, "agent": S.AI, "import": S.IMPORTED}.get(kind, S.USER_DEFINED)

    def trace(self, ch: dict, addr, summary: str) -> None:
        self.marks.setdefault(addr, []).append(f"{ch['provenance']} #{ch['seq']} {ch['op']}{summary}")

    def function_at(self, text: str):
        f = self.fm.getFunctionAt(self.addr(text))
        if f is None:
            raise Unsupported(f"no Ghidra function at {text}")
        return f

    # -- one change ----------------------------------------------------------------

    def apply(self, ch: dict) -> str:
        return getattr(self, "op_" + ch["op"])(ch)

    def op_rename(self, ch):
        from ghidra.program.model.symbol import SymbolUtilities

        a = self.addr(ch["address"])
        name, src = ch["name"], self.source(ch)
        f = self.fm.getFunctionAt(a)
        if f is not None:
            if name:
                f.setName(name, src)
            else:
                f.setName(SymbolUtilities.getDefaultFunctionName(a), self.SourceType.DEFAULT)
        elif name:
            sym = self.st.getPrimarySymbol(a)
            if sym is not None and not sym.isDynamic() and sym.getSource() != self.SourceType.DEFAULT:
                sym.setName(name, src)
            else:
                sym = self.st.createLabel(a, name, src)
                sym.setPrimary()
        else:
            for sym in list(self.st.getSymbols(a)):
                if not sym.isDynamic():
                    sym.delete()
        gc.record_applied(self.p, a, "name", gc.fp_name(self.p, a))
        self.trace(ch, a, f" -> {name or '(default)'}")
        return "applied"

    def _variable(self, f, key: str, create_type=None):
        """The Ghidra parameter or local for a revkit storage key (created if missing)."""
        from ghidra.program.model.data import Undefined
        from ghidra.program.model.listing import LocalVariableImpl

        if key.startswith("param:"):
            n = int(key.split(":")[1].split("#")[0])
            if n >= f.getParameterCount():
                raise Unsupported(f"{f.getName()} has {f.getParameterCount()} parameters, not {n + 1}")
            return f.getParameter(n)
        base, _, pc = key.split("#")[0].partition("@")
        space, _, where = base.partition(":")
        first_use = int(pc, 16) - int(f.getEntryPoint().getOffset()) if pc else 0
        if space == "stack":
            off = int(where, 16) if not where.startswith("-") else -int(where[1:], 16)
            for v in f.getLocalVariables():
                if v.isStackVariable() and v.getStackOffset() == off:
                    return v
            dt = create_type or Undefined.getUndefinedDataType(4)
            v = LocalVariableImpl(None, dt, off, self.p)
            return f.addLocalVariable(v, self.SourceType.USER_DEFINED)
        if space == "register":
            reg = self.p.getRegister(where)
            if reg is None:
                raise Unsupported(f"no register {where}")
            for v in f.getLocalVariables():
                if v.isRegisterVariable() and v.getRegister() == reg and (not pc or v.getFirstUseOffset() == first_use):
                    return v
            dt = create_type or Undefined.getUndefinedDataType(reg.getMinimumByteSize())
            v = LocalVariableImpl(None, first_use, dt, reg, self.p)
            return f.addLocalVariable(v, self.SourceType.USER_DEFINED)
        raise Unsupported(f"storage {key} has no Ghidra variable")

    def op_rename_local(self, ch):
        f = self.function_at(ch["function"])
        v = self._variable(f, ch["storage_key"])
        v.setName(ch["name"], self.source(ch))
        key = f"param:{v.getOrdinal()}" if ch["storage_key"].startswith("param:") else gc.var_key(v)
        gc.record_applied(self.p, f.getEntryPoint(), key, gc.fp_variable(v))
        self.trace(ch, f.getEntryPoint(), f" {ch['storage_key']} -> {ch['name']}")
        return "applied"

    def _type(self, ch):
        """The change's type as a Ghidra data type (or a FunctionDefinition)."""
        from ghidra.util.data import DataTypeParser

        if "type_hash" in ch:
            return self.types.get(ch["type_hash"])
        text = " ".join(ch["c"].replace("*", " * ").split())
        for word in ("struct", "union", "enum", "const", "volatile", "restrict"):
            text = re.sub(rf"\b{word}\b ?", "", text)
        # C spellings to Ghidra's builtin names.
        for c, g in (("unsigned long long", "ulonglong"), ("long long", "longlong"), ("unsigned long", "ulong"),
                     ("unsigned int", "uint"), ("unsigned short", "ushort"), ("unsigned char", "uchar"),
                     ("signed char", "schar"), ("unsigned", "uint"), ("_Bool", "bool")):
            text = re.sub(rf"\b{c}\b", g, text)
        text = text.replace(" *", "*").strip()
        dtm = self.p.getDataTypeManager()
        parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
        return parser.parse(text)

    def op_retype(self, ch):
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
        from ghidra.app.util.cparser.C import CParserUtils
        from ghidra.program.model.data import DataUtilities, FunctionDefinition
        from ghidra.util.task import TaskMonitor

        a = self.addr(ch["address"])
        f = self.fm.getFunctionAt(a)
        src = self.source(ch)
        if f is not None:
            if "c" in ch:
                sig = CParserUtils.parseSignature(None, self.p, ch["c"], True)
                if sig is None:
                    raise Unsupported(f"Ghidra can't parse the prototype {ch['c']!r}")
            else:
                sig = self.types.get(ch["type_hash"])
                if not isinstance(sig, FunctionDefinition):
                    raise Unsupported("a function's type must be a function type")
            # The prototype doesn't rename the function: names are their own changes.
            sig = sig.clone(self.p.getDataTypeManager())
            sig.setName(f.getName())
            cmd = ApplyFunctionSignatureCmd(a, sig, src)
            if not cmd.applyTo(self.p, TaskMonitor.DUMMY):
                raise Unsupported(f"signature not applied: {cmd.getStatusMsg()}")
            gc.record_applied(self.p, a, "signature", gc.fp_signature(f))
            self.trace(ch, a, f" -> {f.getPrototypeString(False, False)}")
            return "applied"
        dt = self._type(ch)
        if self.listing.getInstructionContaining(a) is not None:
            raise Unsupported("an instruction is there; revkit retypes data, not code")
        DataUtilities.createData(self.p, a, dt, -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
        gc.record_applied(self.p, a, "data", gc.fp_data(self.listing.getDataAt(a)))
        self.trace(ch, a, f" -> {dt.getDisplayName()}")
        return "applied"

    def op_retype_local(self, ch):
        f = self.function_at(ch["function"])
        dt = self._type(ch)
        v = self._variable(f, ch["storage_key"], create_type=dt)
        v.setDataType(dt, self.source(ch))
        key = f"param:{v.getOrdinal()}" if ch["storage_key"].startswith("param:") else gc.var_key(v)
        gc.record_applied(self.p, f.getEntryPoint(), key, gc.fp_variable(v))
        self.trace(ch, f.getEntryPoint(), f" {ch['storage_key']} -> {dt.getDisplayName()}")
        return "applied"

    def op_comment(self, ch):
        from ghidra.program.model.listing import CommentType

        a = self.addr(ch["address"])
        kind = ch["kind"]
        ct = {"eol": CommentType.EOL, "pre": CommentType.PRE, "post": CommentType.POST, "plate": CommentType.PLATE,
              "repeatable": CommentType.REPEATABLE, "decompiler": CommentType.PRE}[kind]
        self.listing.setComment(a, ct, ch["text"] or None)
        gkind = "pre" if kind == "decompiler" else kind
        gc.record_applied(self.p, a, "comment:" + gkind, ch["text"])
        self.trace(ch, a, f" ({kind})")
        return "applied"

    def op_function(self, ch):
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.app.cmd.function import CreateFunctionCmd
        from ghidra.program.model.address import AddressSet
        from ghidra.util.task import TaskMonitor

        a = self.addr(ch["entry"])
        if ch.get("remove"):
            if self.fm.getFunctionAt(a) is not None:
                self.fm.removeFunction(a)
            self.trace(ch, a, " removed")
            return "applied"
        if self.listing.getInstructionAt(a) is None:
            DisassembleCommand(a, None, True).applyTo(self.p, TaskMonitor.DUMMY)
        body = None
        if ch.get("body"):
            body = AddressSet()
            for lo, hi in ch["body"]:
                body.add(self.addr(lo), self.addr(hi))
        f = self.fm.getFunctionAt(a)
        if f is None:
            cmd = CreateFunctionCmd(None, a, body, self.source(ch))
            if not cmd.applyTo(self.p, TaskMonitor.DUMMY):
                raise Unsupported(f"function not created: {cmd.getStatusMsg()}")
        elif body is not None:
            f.setBody(body)
        gc.record_applied(self.p, a, "function", "1")
        self.trace(ch, a, "")
        return "applied"

    def op_flow_override(self, ch):
        from ghidra.program.model.listing import FlowOverride

        a = self.addr(ch["address"])
        ins = self.listing.getInstructionAt(a)
        if ins is None:
            raise Unsupported("no instruction there in Ghidra")
        ins.setFlowOverride(FlowOverride.valueOf(ch["kind"].upper()))
        gc.record_applied(self.p, a, "flow", ch["kind"].lower())
        self.trace(ch, a, f" {ch['kind']}")
        return "applied"

    def op_note(self, ch):
        a = self.addr(ch["address"])
        if ch["tag"] == "ghidra:noreturn":
            f = self.function_at(ch["address"])
            f.setNoReturn(ch["text"].strip().lower() == "true")
        else:
            self.p.getBookmarkManager().setBookmark(a, BOOKMARK_TYPE, "note:" + (ch["tag"] or "-"), ch["text"])
        self.trace(ch, a, f" [{ch['tag']}]")
        return "applied"

    def op_define_type(self, ch):
        dt = self.types.get(ch["type_hash"])
        if dt.getDataTypeManager() != self.p.getDataTypeManager():
            from ghidra.program.model.data import DataTypeConflictHandler

            dt = self.p.getDataTypeManager().resolve(dt, DataTypeConflictHandler.DEFAULT_HANDLER)
        if dt.getCategoryPath().getPath() == CATEGORY:
            try:
                dt.setDescription(f"revkit: {ch['provenance']} #{ch['seq']}")
            except Exception:  # a function definition has no description to set
                pass
        return "applied"

    def finish(self) -> None:
        """Writes the traceability bookmarks."""
        bm = self.p.getBookmarkManager()
        for a, lines in self.marks.items():
            old = bm.getBookmark(a, BOOKMARK_TYPE, "revkit")
            text = "; ".join(([str(old.getComment())] if old is not None else []) + lines)
            bm.setBookmark(a, BOOKMARK_TYPE, "revkit", text[:4000])


def apply_doc(program, doc: dict, *, strict: bool = False, force: bool = False) -> dict:
    if doc.get("format") != gc.FORMAT or doc.get("direction") != "revkit-to-ghidra":
        raise SystemExit("not a revkit-ghidra-interop revkit-to-ghidra document")
    sha = str(program.getExecutableSHA256() or "")
    if sha.lower() != doc["program"]["sha256"].lower() and not force:
        raise SystemExit(f"sha256 mismatch: Ghidra's program is {sha}, the export is {doc['program']['sha256']} (--force)")
    delta = int(program.getImageBase().getOffset()) - int(doc["program"]["image_base"], 16)
    results = []
    tx = program.startTransaction("revkit-ghidra-export")
    ok = False
    try:
        ap = Applier(program, doc, delta)
        for ch in doc["changes"]:
            r = {"seq": ch["seq"], "op": ch["op"], "provenance": ch["provenance"]}
            try:
                r["status"] = ap.apply(ch)
            except Unsupported as e:
                r.update(status="skipped", reason=str(e))
            except Exception as e:  # noqa: BLE001 - a Ghidra exception for one change
                r.update(status="failed", reason=f"{type(e).__name__}: {e}")
                if os.environ.get("RK_DEBUG"):
                    traceback.print_exc()
            results.append(r)
        if strict and any(r["status"] != "applied" for r in results):
            raise SystemExit("--strict: some changes failed; rolled back")
        ap.finish()
        ok = True
    finally:
        program.endTransaction(tx, ok)
    return {"image_base_delta": delta, "applied": sum(r["status"] == "applied" for r in results),
            "skipped": sum(r["status"] == "skipped" for r in results),
            "failed": sum(r["status"] == "failed" for r in results), "changes": results}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("json", help="revkit-ghidra-export output")
    ap.add_argument("--project", required=True, help="Ghidra project (.gpr)")
    ap.add_argument("--program", help="program path in the project (default: its only program)")
    ap.add_argument("--strict", action="store_true", help="roll back if any change can't be applied")
    ap.add_argument("--force", action="store_true", help="apply even if the sha256 differs")
    ap.add_argument("--report", help="write the per-change report here")
    ap.add_argument("--ghidra", help="Ghidra install")
    args = ap.parse_args(argv)
    with open(args.json) as f:
        doc = json.load(f)
    gc.start(args.ghidra)
    from ghidra.util.task import TaskMonitor

    with gc.open_program(args.project, args.program, writable=True) as (_, program):
        report = apply_doc(program, doc, strict=args.strict, force=args.force)
        program.save("revkit-ghidra-export", TaskMonitor.DUMMY)
    if args.report:
        with open(args.report, "w") as f:
            json.dump(report, f, indent=1)
    gc.warn(f"ghidra_apply: {report['applied']} applied, {report['skipped']} skipped, {report['failed']} failed")
    for r in report["changes"]:
        if r["status"] != "applied":
            gc.warn(f"  #{r['seq']} {r['op']}: {r['status']}: {r.get('reason', '')}")
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
