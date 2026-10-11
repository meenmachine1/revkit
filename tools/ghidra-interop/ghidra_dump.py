#!/usr/bin/env python3
"""Export the user's work in a Ghidra program as revkit-ghidra-interop JSON.

Runs headless in the PyGhidra virtualenv (scripts/setup-pyghidra.sh) and
opens the program read-only; the format is docs/ghidra-interop.md.

    ghidra_dump.py --project ~/work/proj.gpr [--program /prog] -o prog.ghidra.json

Ghidra records a SourceType (DEFAULT, ANALYSIS, AI, IMPORTED, USER_DEFINED)
for symbols, function signatures and variables, but not for comments, data,
types, bookmarks, equates, flow overrides, function existence or no-return
flags. For those, the exporter re-imports the program's original bytes (kept
in the program) into memory, runs the same auto-analysis, and marks what
that fresh analysis also produces as ANALYSIS and the rest as USER_DEFINED
(`--no-baseline` marks them UNKNOWN instead).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ghidra_common as gc  # noqa: E402

AUTO_INT_RANKS = {
    "short": "short", "ushort": "short", "int": "int", "uint": "int", "long": "long", "ulong": "long",
    "longlong": "long_long", "ulonglong": "long_long", "int128": "int128", "uint128": "int128",
}
FLOAT_KINDS = {"float": "float", "double": "double", "longdouble": "long_double", "float2": "half"}


class Exporter:
    """Walks one program. ``baseline`` (another Exporter's index, optional)
    tells analysis output from the user's."""

    def __init__(self, program, baseline: "Baseline | None" = None):
        from ghidra.program.model.data import (AbstractFloatDataType, AbstractIntegerDataType,
                                               AbstractStringDataType, Array, BitFieldDataType,
                                               BooleanDataType, CharDataType, DefaultDataType, Enum,
                                               FunctionDefinition, Pointer, Structure, TypeDef, Undefined,
                                               Union, VoidDataType, WideChar16DataType, WideChar32DataType,
                                               WideCharDataType)

        self.J = dict(locals())
        self.p = program
        self.baseline = baseline
        self.types: dict[str, dict] = {}  # id -> definition
        self._defining: set[str] = set()
        dtm = program.getDataTypeManager()
        self.local_archive = dtm.getLocalSourceArchive().getSourceArchiveID() if dtm.getLocalSourceArchive() else None
        org = dtm.getDataOrganization()
        self.char_signed = bool(org.isSignedChar())
        self.applied = gc.read_applied(program)
        # Only the default space maps to revkit (not EXTERNAL, overlays or
        # Ghidra's _elfSectionHeaders-style OTHER spaces).
        self.space = program.getAddressFactory().getDefaultAddressSpace()

    def ours(self, a) -> bool:
        return a.getAddressSpace() == self.space

    def mark(self, item: dict, addr, key: str, fingerprint: str) -> dict:
        """Marks ``item`` from_revkit if ghidra_apply.py set this value."""
        rec = self.applied.get(int(addr.getOffset()) if not isinstance(addr, int) else addr)
        if rec is not None and rec.get(key) == fingerprint:
            item["from_revkit"] = True
        return item

    # -- types --------------------------------------------------------------

    def is_named(self, dt) -> bool:
        J = self.J
        return isinstance(dt, (J["Structure"], J["Union"], J["Enum"], J["TypeDef"], J["FunctionDefinition"]))

    def tref(self, dt, length: int | None = None) -> dict:
        """A type reference (docs/ghidra-interop.md, "Type references")."""
        J = self.J
        if dt is None:
            return {"kind": "undefined", "size": 1}
        if self.is_named(dt):
            tid = str(dt.getDataTypePath())
            self.define(dt, tid)
            return {"ref": tid}
        if isinstance(dt, J["Pointer"]):
            target = dt.getDataType()
            return {"kind": "pointer", "size": int(dt.getLength()) if dt.getLength() > 0 else 0,
                    "target": self.tref(target) if target is not None else {"kind": "undefined", "size": 1}}
        if isinstance(dt, J["Array"]):
            return {"kind": "array", "count": int(dt.getNumElements()), "element": self.tref(dt.getDataType())}
        return self.builtin(dt, length)

    def builtin(self, dt, length: int | None = None) -> dict:
        J = self.J
        name = str(dt.getName())
        size = int(dt.getLength())
        if isinstance(dt, J["VoidDataType"]):
            return {"kind": "void"}
        if isinstance(dt, (J["DefaultDataType"], J["Undefined"])):
            return {"kind": "undefined", "size": max(size, 1)}
        if isinstance(dt, J["BooleanDataType"]):
            return {"kind": "bool", "size": size}
        if isinstance(dt, J["AbstractStringDataType"]) or size <= 0:
            # Dynamic types (strings, unicode, ...) take their length from the data.
            n = length or 1
            if "unicode32" in name.lower() or "string32" in name.lower():
                return {"kind": "array", "count": max(n // 4, 1), "element": {"kind": "uint", "size": 4, "rank": "char32"}}
            if "unicode" in name.lower() or "16" in name:
                return {"kind": "array", "count": max(n // 2, 1), "element": {"kind": "uint", "size": 2, "rank": "char16"}}
            if isinstance(dt, J["AbstractStringDataType"]):
                return {"kind": "array", "count": n, "element": {"kind": "char", "size": 1, "signed": self.char_signed}}
            return {"kind": "undefined", "size": n, "ghidra": name}
        if isinstance(dt, J["WideChar16DataType"]):
            return {"kind": "uint", "size": size, "rank": "char16"}
        if isinstance(dt, J["WideChar32DataType"]):
            return {"kind": "uint", "size": size, "rank": "char32"}
        if isinstance(dt, J["WideCharDataType"]):
            # Windows' 2-byte wchar_t is unsigned, the 4-byte one of Unix signed.
            return {"kind": "int" if size == 4 else "uint", "size": size, "rank": "wchar"}
        if isinstance(dt, J["CharDataType"]):
            if name == "char":
                return {"kind": "char", "size": size, "signed": bool(dt.isSigned())}
            return {"kind": "int" if dt.isSigned() else "uint", "size": size, "rank": "char"}
        if isinstance(dt, J["AbstractIntegerDataType"]):
            out = {"kind": "int" if dt.isSigned() else "uint", "size": size}
            if name in AUTO_INT_RANKS:
                out["rank"] = AUTO_INT_RANKS[name]
            return out
        if isinstance(dt, J["AbstractFloatDataType"]):
            out = {"kind": "float", "size": size}
            if name in FLOAT_KINDS:
                out["float_kind"] = FLOAT_KINDS[name]
            return out
        return {"kind": "undefined", "size": max(size, 1), "ghidra": name}

    def define(self, dt, tid: str) -> None:
        if tid in self.types or tid in self._defining:
            return
        self._defining.add(tid)
        J = self.J
        d: dict = {"id": tid, "name": str(dt.getName()), "category": str(dt.getCategoryPath())}
        if isinstance(dt, (J["Structure"], J["Union"])):
            d["kind"] = "union" if isinstance(dt, J["Union"]) else "struct"
            d["size"] = int(dt.getLength()) if not dt.isNotYetDefined() else 0
            d["incomplete"] = bool(dt.isNotYetDefined())
            if dt.hasExplicitMinimumAlignment():
                d["alignment"] = int(dt.getExplicitMinimumAlignment())
            d["packed"] = bool(dt.hasExplicitPackingValue() and dt.getExplicitPackingValue() == 1)
            fields = []
            for c in dt.getDefinedComponents():
                f = {"name": str(c.getFieldName()) if c.getFieldName() is not None else "", "offset": int(c.getOffset())}
                cdt = c.getDataType()
                if isinstance(cdt, J["BitFieldDataType"]):
                    f["type"] = self.tref(cdt.getBaseDataType())
                    f["bit_offset"] = int(cdt.getBitOffset())
                    f["bit_size"] = int(cdt.getBitSize())
                else:
                    f["type"] = self.tref(cdt, int(c.getLength()))
                if c.getComment():
                    f["comment"] = str(c.getComment())
                fields.append(f)
            d["fields"] = fields
        elif isinstance(dt, J["Enum"]):
            d["kind"] = "enum"
            d["size"] = int(dt.getLength())
            d["signed"] = bool(dt.isSigned())
            d["values"] = sorted(([str(n), int(dt.getValue(n))] for n in dt.getNames()), key=lambda v: (v[1], v[0]))
        elif isinstance(dt, J["TypeDef"]):
            d["kind"] = "typedef"
            d["target"] = self.tref(dt.getDataType())
        elif isinstance(dt, J["FunctionDefinition"]):
            d["kind"] = "function"
            d["return"] = self.tref(dt.getReturnType())
            d["params"] = [{"name": str(a.getName() or ""), "type": self.tref(a.getDataType())} for a in dt.getArguments()]
            d["varargs"] = bool(dt.hasVarArgs())
            d["calling_convention"] = str(dt.getCallingConventionName())
            d["no_return"] = bool(dt.hasNoReturn())
        if dt.getDescription():
            d["description"] = str(dt.getDescription())
            if d["description"].startswith("revkit: ") and d["category"] == "/revkit":
                d["from_revkit"] = True  # defined by ghidra_apply.py
        arch = dt.getSourceArchive()
        d["archive"] = None if arch is None or arch.getSourceArchiveID() == self.local_archive else str(arch.getName())
        self.types[tid] = d
        self._defining.discard(tid)

    # -- items --------------------------------------------------------------

    def symbol_name(self, sym) -> str:
        """Plain name for globals and function-local labels, ns::name in a namespace."""
        from ghidra.program.model.listing import Function

        ns = sym.getParentNamespace()
        if ns is None or ns.isGlobal() or isinstance(ns.getSymbol().getObject(), Function):
            return str(sym.getName())
        return str(sym.getName(True))

    def walk(self, *, flow_overrides: bool = True) -> dict:
        from ghidra.program.model.listing import CommentType, FlowOverride
        from ghidra.program.model.symbol import SymbolType

        p = self.p
        listing = p.getListing()
        mem = p.getMemory()
        out: dict = {}

        symbols = []
        for s in p.getSymbolTable().getAllSymbols(False):
            a = s.getAddress()
            if not self.ours(a) or s.isExternal():
                continue
            st = s.getSymbolType()
            if st == SymbolType.FUNCTION:
                kind = "function"
            elif st == SymbolType.LABEL:
                kind = "data" if listing.getDefinedDataAt(a) is not None else "label"
            else:
                continue
            item = {"address": gc.hexaddr(a), "name": self.symbol_name(s), "kind": kind,
                    "source": str(s.getSource()), "primary": bool(s.isPrimary())}
            symbols.append(self.mark(item, a, "name", str(s.getName())) if s.isPrimary() else item)
        out["symbols"] = symbols

        functions = []
        for f in p.getFunctionManager().getFunctions(True):
            entry = f.getEntryPoint()
            if not self.ours(entry):
                continue
            fd = {"entry": gc.hexaddr(entry), "name": self.symbol_name(f.getSymbol()),
                  "name_source": str(f.getSymbol().getSource()),
                  "body": [[gc.hexaddr(r.getMinAddress()), gc.hexaddr(r.getMaxAddress())] for r in f.getBody()],
                  "signature": str(f.getPrototypeString(False, False)),
                  "signature_source": str(f.getSignatureSource()),
                  "calling_convention": str(f.getCallingConventionName()),
                  "return": self.tref(f.getReturnType()),
                  "params": [], "locals": [],
                  "varargs": bool(f.hasVarArgs()), "no_return": bool(f.hasNoReturn()),
                  "inline": bool(f.isInline()), "custom_storage": bool(f.hasCustomVariableStorage())}
            self.mark(fd, entry, "function", "1")
            if self.applied.get(int(entry.getOffset()), {}).get("signature") == gc.fp_signature(f):
                fd["signature_from_revkit"] = True
            if f.isThunk() and f.getThunkedFunction(False) is not None:
                fd["thunk_of"] = gc.hexaddr(f.getThunkedFunction(False).getEntryPoint())
            for v in f.getParameters():
                fd["params"].append(self.mark(
                    {"ordinal": int(v.getOrdinal()), "name": str(v.getName()), "type": self.tref(v.getDataType()),
                     "source": str(v.getSource()), "auto": bool(v.isAutoParameter()),
                     "storage": str(v.getVariableStorage())},
                    entry, f"param:{int(v.getOrdinal())}", gc.fp_variable(v)))
            for v in f.getLocalVariables():
                lv = {"name": str(v.getName()), "type": self.tref(v.getDataType()), "source": str(v.getSource()),
                      "first_use": gc.hexaddr(int(entry.getOffset()) + int(v.getFirstUseOffset())),
                      "storage": str(v.getVariableStorage())}
                if v.isStackVariable():
                    lv["stack_offset"] = int(v.getStackOffset())
                elif v.isRegisterVariable():
                    lv["register"] = str(v.getRegister().getName())
                fd["locals"].append(self.mark(lv, entry, gc.var_key(v), gc.fp_variable(v)))
            functions.append(fd)
        out["functions"] = functions

        comments = []
        for kind, ct in (("eol", CommentType.EOL), ("pre", CommentType.PRE), ("post", CommentType.POST),
                         ("plate", CommentType.PLATE), ("repeatable", CommentType.REPEATABLE)):
            for a in listing.getCommentAddressIterator(ct, mem, True):
                if not self.ours(a):
                    continue
                text = listing.getComment(ct, a)
                if text is not None:
                    comments.append(self.mark({"address": gc.hexaddr(a), "kind": kind, "text": str(text)},
                                              a, "comment:" + kind, str(text)))
        out["comments"] = comments

        data = []
        for d in listing.getDefinedData(True):
            if not self.ours(d.getAddress()):
                continue
            data.append(self.mark({"address": gc.hexaddr(d.getAddress()), "length": int(d.getLength()),
                                   "type": self.tref(d.getDataType(), int(d.getLength()))},
                                  d.getAddress(), "data", gc.fp_data(d)))
        out["data"] = data

        bookmarks = []
        for b in p.getBookmarkManager().getBookmarksIterator():
            if str(b.getTypeString()) == "revkit" or not self.ours(b.getAddress()):
                continue  # revkit's: traceability marks and notes ghidra_apply.py wrote
            bookmarks.append({"address": gc.hexaddr(b.getAddress()), "type": str(b.getTypeString()),
                              "category": str(b.getCategory() or ""), "comment": str(b.getComment() or "")})
        out["bookmarks"] = bookmarks

        fos = []
        if flow_overrides:
            for ins in listing.getInstructions(True):
                fo = ins.getFlowOverride()
                if fo != FlowOverride.NONE:
                    fos.append(self.mark({"address": gc.hexaddr(ins.getAddress()), "kind": str(fo).lower()},
                                         ins.getAddress(), "flow", str(fo).lower()))
        out["flow_overrides"] = fos

        equates = []
        for e in p.getEquateTable().getEquates():
            refs = [{"address": gc.hexaddr(r.getAddress()), "operand": int(r.getOpIndex())} for r in e.getReferences()
                    if self.ours(r.getAddress())]
            equates.append({"name": str(e.getName()), "value": int(e.getValue()),
                            "references": sorted(refs, key=lambda r: (int(r["address"], 16), r["operand"]))})
        out["equates"] = equates

        # Named types the program defines (beyond those the items reference).
        for dt in p.getDataTypeManager().getAllDataTypes():
            if self.is_named(dt):
                self.define(dt, str(dt.getDataTypePath()))
        out["types"] = [self.types[k] for k in sorted(self.types)]
        return out


class Baseline:
    """What a fresh auto-analysis of the same bytes produces, at the user's
    program's addresses (shifted by the difference in image base)."""

    def __init__(self, doc: dict, delta: int, seconds: float):
        self.delta, self.seconds = delta, seconds

        def a(x: str) -> int:
            return int(x, 16) + delta

        self.comments = {(a(c["address"]), c["kind"], c["text"]) for c in doc["comments"]}
        self.data = {(a(d["address"]), json.dumps(d["type"], sort_keys=True)) for d in doc["data"]}
        self.bookmarks = {(a(b["address"]), b["type"], b["category"], b["comment"]) for b in doc["bookmarks"]}
        self.flow_overrides = {(a(f["address"]), f["kind"]) for f in doc["flow_overrides"]}
        self.equates = {(e["name"], e["value"], a(r["address"]), r["operand"]) for e in doc["equates"] for r in e["references"]}
        self.functions = {a(f["entry"]): f for f in doc["functions"]}
        self.types = {t["id"]: _type_fingerprint(t) for t in doc["types"]}


def _type_fingerprint(t: dict) -> str:
    return json.dumps({k: v for k, v in t.items() if k not in ("description",)}, sort_keys=True)


def load_baseline(program) -> Baseline | None:
    """Re-imports the program's original file bytes in memory and analyzes them."""
    import jpype
    import pyghidra
    from ghidra.app.util.importer import MessageLog, ProgramLoader
    from ghidra.util.task import TaskMonitor
    from java.io import File  # type: ignore

    fbs = list(program.getMemory().getAllFileBytes())
    if not fbs:
        gc.warn("ghidra_dump: the program keeps no original file bytes; no baseline")
        return None
    fb = fbs[0]
    buf = jpype.JArray(jpype.JByte)(int(fb.getSize()))
    fb.getOriginalBytes(0, buf)
    t0 = time.monotonic()
    tmp = tempfile.mkdtemp(prefix="rk-baseline-")
    try:
        path = os.path.join(tmp, str(program.getName()))
        with open(path, "wb") as f:
            f.write(bytes(b & 0xFF for b in buf))
        results = (ProgramLoader.builder().source(File(path)).name(str(program.getName()))
                   .language(program.getLanguageID()).compiler(program.getCompilerSpec().getCompilerSpecID())
                   .log(MessageLog()).monitor(TaskMonitor.DUMMY).load())
        try:
            fresh = results.getPrimaryDomainObject()
            pyghidra.analyze(fresh)
            doc = Exporter(fresh).walk()
            delta = int(program.getImageBase().getOffset()) - int(fresh.getImageBase().getOffset())
            return Baseline(doc, delta, time.monotonic() - t0)
        finally:
            results.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def classify(doc: dict, baseline: Baseline | None) -> None:
    """Sets ``source`` on items Ghidra keeps no SourceType for."""

    def src(in_baseline: bool) -> str:
        if baseline is None:
            return "UNKNOWN"
        return "ANALYSIS" if in_baseline else "USER_DEFINED"

    b = baseline
    for c in doc["comments"]:
        c["source"] = src(b is not None and (int(c["address"], 16), c["kind"], c["text"]) in b.comments)
    for d in doc["data"]:
        d["source"] = src(b is not None and (int(d["address"], 16), json.dumps(d["type"], sort_keys=True)) in b.data)
    for k in doc["bookmarks"]:
        k["source"] = src(b is not None and (int(k["address"], 16), k["type"], k["category"], k["comment"]) in b.bookmarks)
    for f in doc["flow_overrides"]:
        f["source"] = src(b is not None and (int(f["address"], 16), f["kind"]) in b.flow_overrides)
    for e in doc["equates"]:
        e["source"] = src(b is not None and all((e["name"], e["value"], int(r["address"], 16), r["operand"]) in b.equates
                                                 for r in e["references"]))
    for f in doc["functions"]:
        old = b.functions.get(int(f["entry"], 16)) if b else None
        f["exists_source"] = src(old is not None)
        f["no_return_source"] = src(old is not None and old["no_return"] == f["no_return"])
    for t in doc["types"]:
        in_baseline = b is not None and b.types.get(t["id"]) == _type_fingerprint(t)
        # Types from a data type archive (generic_clib, a user's .gdt) that
        # analysis didn't apply came in through the user.
        t["source"] = "ANALYSIS" if in_baseline else "IMPORTED" if t.get("archive") else src(False)


def export(program, *, baseline: bool = True, flow_overrides: bool = True, project: str = "") -> dict:
    from ghidra.framework import Application

    t0 = time.monotonic()
    base = load_baseline(program) if baseline else None
    t1 = time.monotonic()
    ex = Exporter(program)
    items = ex.walk(flow_overrides=flow_overrides)
    cspec = program.getCompilerSpec()
    doc = {
        "format": gc.FORMAT,
        "version": gc.VERSION,
        "direction": "ghidra-to-revkit",
        "ghidra": {"version": str(Application.getApplicationVersion()), "project": project,
                   "program_path": str(program.getDomainFile().getPathname())},
        "program": {
            "name": str(program.getName()),
            "sha256": str(program.getExecutableSHA256() or ""),
            "md5": str(program.getExecutableMD5() or ""),
            "executable_path": str(program.getExecutablePath() or ""),
            "executable_format": str(program.getExecutableFormat() or ""),
            "language_id": str(program.getLanguageID()),
            "compiler_spec_id": str(cspec.getCompilerSpecID()),
            "image_base": gc.hexaddr(program.getImageBase()),
            "pointer_size": int(program.getDefaultPointerSize()),
            "big_endian": bool(program.getLanguage().isBigEndian()),
            "default_calling_convention": str(cspec.getDefaultCallingConvention().getName()),
            "char_signed": ex.char_signed,
        },
        "baseline": None if base is None else {"analysis_seconds": round(base.seconds, 2), "image_base_delta": base.delta},
    }
    doc.update(items)
    classify(doc, base)
    # Functions the fresh analysis finds that the program doesn't have: the
    # user deleted them.
    if base is not None:
        have = {int(f["entry"], 16) for f in doc["functions"]}
        doc["removed_functions"] = [{"entry": gc.hexaddr(e), "source": "USER_DEFINED"}
                                    for e in sorted(base.functions) if e not in have]
    doc["stats"] = {k: len(v) for k, v in items.items()}
    doc["stats"]["seconds"] = {"baseline": round(t1 - t0, 2), "export": round(time.monotonic() - t1, 2)}
    return doc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", required=True, help="Ghidra project (.gpr file, or its directory/name)")
    ap.add_argument("--program", help="program path in the project (default: its only program)")
    ap.add_argument("-o", "--out", default="-", help="output JSON (default stdout)")
    ap.add_argument("--no-baseline", action="store_true",
                    help="don't re-analyze the original bytes; unsourced items get source UNKNOWN")
    ap.add_argument("--no-flow-overrides", action="store_true", help="skip the per-instruction flow override scan")
    ap.add_argument("--ghidra", help="Ghidra install (default $GHIDRA_INSTALL_DIR or ~/ghidra/ghidra_12.1.4_PUBLIC)")
    ap.add_argument("--heap", default="2g")
    args = ap.parse_args(argv)

    gc.start(args.ghidra, args.heap)
    with gc.open_program(args.project, args.program) as (_, program):
        doc = export(program, baseline=not args.no_baseline, flow_overrides=not args.no_flow_overrides,
                     project=os.path.abspath(args.project))
    text = json.dumps(doc, indent=1, sort_keys=False) + "\n"
    if args.out == "-":
        sys.stdout.write(text)
    else:
        tmp = args.out + ".tmp"
        with open(tmp, "w") as f:
            f.write(text)
        os.replace(tmp, args.out)
    s = doc["stats"]
    gc.warn(f"ghidra_dump: {s['symbols']} symbols, {s['functions']} functions, {s['comments']} comments, "
            f"{s['data']} data, {s['types']} types, {s['bookmarks']} bookmarks, {s['flow_overrides']} flow overrides, "
            f"{s['equates']} equates; baseline {s['seconds']['baseline']} s, export {s['seconds']['export']} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
