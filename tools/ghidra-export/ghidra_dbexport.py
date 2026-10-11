#!/usr/bin/env python3
"""Export what Ghidra's decompiler is told about each corpus binary.

Ghidra's Java side answers the decompiler's queries (DecompileCallback) from
the program database that auto-analysis built: function signatures and
calling conventions, local variables, defined data with types, symbol names,
external references, comments, and the bytes as relocated by the loader.
This script writes those facts, after the same import and auto-analysis as
ghidra_export.py, as one JSON file per binary (docs/decompiler-inputs.md),
so revkit can decompile under the reference's conditions.

  ghidra_dbexport.py --corpus out/corpus --out out/ghidra-db
  ghidra_dbexport.py --corpus out/corpus --out out/ghidra-db --only 'elf-x86_64/*'

Data types are written in the decompiler's own type encoding (what
PcodeDataTypeManager.encodeTypeRef/encodeType send), transliterated from XML
to JSON elements; everything else is plain program facts, and revkit applies
the decompiler-facing rules itself (src/lift/decomp_inputs.cc).
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import shutil
import sys
import tempfile
import time
import traceback
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ghidra_export as ge  # noqa: E402

FORMAT = "revkit-decompiler-inputs"
VERSION = 1

# Attribute value types in the decompiler's encoding, so the JSON carries
# numbers and booleans rather than XML text.
_INT_ATTRS = {"size", "arraysize", "offset", "first", "last", "alignment", "wordsize",
              "value", "content", "logicalsize", "index", "cat", "extrapop"}
_UINT_ATTRS = {"id", "val"}
_BOOL_ATTRS = {"char", "utf", "opaquestring", "varlength", "incomplete", "typelock",
               "namelock", "readonly", "volatile", "merge", "modellock", "dotdotdot",
               "voidlock", "inline", "noreturn", "custom", "constructor", "destructor",
               "thisptr", "hiddenretparm", "lock"}


def _attr_value(name: str, text: str):
    if name in _BOOL_ATTRS:
        return text == "true"
    if name in _UINT_ATTRS or name in _INT_ATTRS:
        try:
            return int(text, 0)
        except ValueError:
            return text  # "unknown" extrapop and the like
    return text


def _element_json(el) -> list:
    """XML element -> [tag, {attrs}, [children]] (children omitted when empty)."""
    attrs = {k: _attr_value(k, v) for k, v in el.attrib.items()}
    if el.text is not None and el.text.strip():
        attrs["content"] = _attr_value("content", el.text.strip())
    kids = [_element_json(c) for c in el]
    return [el.tag, attrs, kids] if kids else [el.tag, attrs]


class Exporter:
    def __init__(self, program):
        from ghidra.app.decompiler import DecompileOptions
        from ghidra.program.model.pcode import PcodeDataTypeManager

        self.program = program
        opts = DecompileOptions()
        opts.grabFromProgram(program)
        self.dtm = PcodeDataTypeManager(program, opts.getNameTransformer())
        self.prog_dtm = program.getDataTypeManager()
        self.listing = program.getListing()
        self.memory = program.getMemory()
        self.symtab = program.getSymbolTable()
        self.refman = program.getReferenceManager()
        self.cspec = program.getCompilerSpec()
        self.types: dict = {}       # id -> encoded type element (named types)
        self.pending: list = []     # (name, id) to define
        self.default_space = program.getAddressFactory().getDefaultAddressSpace()

    # ---- helpers -------------------------------------------------------
    @staticmethod
    def addr(a) -> str:
        return "0x%x" % (int(a.getOffset()) & ((1 << 64) - 1))

    def where(self, a) -> dict:
        """{"addr": ...} plus "space" outside the default address space."""
        rec = {"addr": self.addr(a)}
        spc = a.getAddressSpace()
        if spc != self.default_space:
            rec["space"] = str(spc.getName())
        return rec

    def varnodes(self, storage):
        out = []
        for vn in storage.getVarnodes():
            a = vn.getAddress()
            out.append([str(a.getAddressSpace().getName()), "0x%x" % (int(a.getOffset()) & ((1 << 64) - 1)),
                        int(vn.getSize())])
        return out

    def _xml(self, fn) -> list:
        from ghidra.program.model.pcode import XmlEncode
        enc = XmlEncode()
        fn(enc)
        root = ET.fromstring(str(enc.toString()))
        return _element_json(root)

    def _collect_refs(self, node):
        tag, attrs = node[0], node[1]
        if tag in ("typeref", "def", "type") and attrs.get("name") and "id" in attrs:
            tid = attrs["id"]
            if tid not in self.types and (attrs["name"], tid) not in self.pending:
                self.pending.append((attrs["name"], tid))
        for kid in (node[2] if len(node) > 2 else []):
            self._collect_refs(kid)

    def type_ref(self, dt, size: int) -> list:
        node = self._xml(lambda e: self.dtm.encodeTypeRef(e, dt, size))
        self._collect_refs(node)
        return node

    def define_pending(self):
        """Full definitions of every named type referenced so far."""
        while self.pending:
            name, tid = self.pending.pop()
            if tid in self.types:
                continue
            dt = self.dtm.findBaseType(name, tid - (1 << 64) if tid >= (1 << 63) else tid)
            if dt is None:
                self.types[tid] = None
                continue
            node = self._xml(lambda e: self.dtm.encodeType(e, dt, 0))
            self.types[tid] = node
            self._collect_refs(node)

    # ---- program parts -------------------------------------------------
    def memory_blocks(self):
        out = []
        for b in self.memory.getBlocks():
            if b.isOverlay():
                continue
            out.append({
                "name": str(b.getName()), "start": self.addr(b.getStart()), "end": self.addr(b.getEnd()),
                "perms": ge._perms(b), "initialized": bool(b.isInitialized()), "loaded": bool(b.isLoaded()),
                "volatile": bool(b.isVolatile()), "external": bool(self.memory.isExternalBlockAddress(b.getStart())),
                **({"space": str(b.getStart().getAddressSpace().getName())}
                   if b.getStart().getAddressSpace() != self.default_space else {}),
            })
        return out

    def synthesized_memory(self, limit=1 << 20):
        """Bytes of initialized blocks that no file backs (e.g. a PE's
        thread data block, "tdb"), which a loader wouldn't have."""
        import jpype
        out = []
        for b in self.memory.getBlocks():
            if not b.isInitialized() or not b.isLoaded() or b.isOverlay():
                continue
            if b.getStart().getAddressSpace() != self.default_space:
                continue
            if any(info.getFileBytes().isPresent() for info in b.getSourceInfos()):
                continue
            n = int(b.getSize())
            if n > limit:
                continue
            buf = jpype.JArray(jpype.JByte)(n)
            got = b.getBytes(b.getStart(), buf)
            out.append({"addr": self.addr(b.getStart()), "bytes": bytes((x & 0xff) for x in buf[:got]).hex()})
        return out

    def patches(self):
        """Bytes the loader changed (relocations), as they now read."""
        import jpype
        out = []
        it = self.program.getRelocationTable().getRelocations()
        while it.hasNext():
            r = it.next()
            a = r.getAddress()
            n = int(r.getLength())
            if n <= 0 or not self.memory.getBlock(a) or not self.memory.getBlock(a).isInitialized():
                continue
            buf = jpype.JArray(jpype.JByte)(n)
            try:
                got = self.memory.getBytes(a, buf)
            except Exception:  # noqa: BLE001 - unreadable: skip
                continue
            out.append({"addr": self.addr(a), "bytes": bytes((x & 0xff) for x in buf[:got]).hex(),
                        "type": int(r.getType()), **({"symbol": str(r.getSymbolName())} if r.getSymbolName() else {})})
        out.sort(key=lambda p: int(p["addr"], 16))
        return out

    def function(self, f) -> dict:
        from ghidra.program.model.data import Undefined
        from ghidra.program.model.symbol import SourceType

        entry = f.getEntryPoint()
        rec = {
            "entry": self.addr(entry),
            "name": str(f.getName()),
            "body": [[self.addr(r.getMinAddress()), self.addr(r.getMaxAddress())] for r in f.getBody().getAddressRanges()],
            "signature_source": str(f.getSignatureSource()),
            "varargs": bool(f.hasVarArgs()),
            "inline": bool(f.isInline()),
            "noreturn": bool(f.hasNoReturn()),
            "custom_storage": bool(f.hasCustomVariableStorage()),
        }
        cc = f.getCallingConventionName()
        rec["convention"] = None if cc is None else str(cc)
        model = f.getCallingConvention() or self.cspec.getDefaultCallingConvention()
        rec["has_this"] = bool(model.hasThisPointer())
        purge = int(f.getStackPurgeSize())
        from ghidra.program.model.listing import Function
        if purge in (Function.INVALID_STACK_DEPTH_CHANGE, Function.UNKNOWN_STACK_DEPTH_CHANGE):
            ep = int(model.getExtrapop())
        else:
            ep = purge + int(model.getStackshift())
        from ghidra.program.model.lang import PrototypeModel
        rec["extrapop"] = "unknown" if ep == PrototypeModel.UNKNOWN_EXTRAPOP else ep
        fixup = f.getCallFixup()
        if fixup is not None:
            rec["call_fixup"] = str(fixup)
            from ghidra.program.model.lang import InjectPayload
            payload = self.cspec.getPcodeInjectLibrary().getPayload(InjectPayload.CALLFIXUP_TYPE, fixup)
            rec["call_fixup_noreturn"] = bool(payload is not None and not payload.isFallThru())
        if f.isThunk():
            t = f.getThunkedFunction(False)
            if t is not None:
                rec["thunk_of"] = str(t.getName()) if t.isExternal() else self.addr(t.getEntryPoint())
        path = _ns_path(_function_namespace(f))
        if path:
            rec["namespace"] = path
        rec["id"] = int(f.getID())
        label = _prefixed_name(f.getSymbol())
        if label != rec["name"]:
            rec["label"] = label

        ret = f.getReturn()
        rdt = ret.getDataType()
        rstore = ret.getVariableStorage()
        rsize = int(rdt.getLength())
        rec["return"] = {
            "type": self.type_ref(rdt, rsize if rsize > 0 else 1),
            "default": rdt == ge_default_type(),
            "storage": self.varnodes(rstore) if (rstore is not None and rstore.isValid()) else None,
            "void_storage": bool(rstore is not None and rstore.isVoidStorage()),
            "size": rsize,
        }
        params = []
        for p in f.getParameters():
            st = p.getVariableStorage()
            prm = {"name": str(p.getName()), "valid": bool(p.isValid())}
            if p.isValid():
                prm["storage"] = self.varnodes(st)
                prm["stack"] = bool(st.isStackStorage())
                prm["type"] = self.type_ref(p.getDataType(), int(st.size()))
                if st.isAutoStorage():
                    prm["auto"] = str(st.getAutoParameterType())
            sym = p.getSymbol()
            if sym is not None:
                prm["id"] = int(sym.getID())
            params.append(prm)
        rec["params"] = params
        locs = []
        for v in f.getLocalVariables():
            if not v.isValid():
                continue
            st = v.getVariableStorage()
            dt = v.getDataType()
            loc = {"name": str(v.getName()), "undefined": bool(Undefined.isUndefined(dt)),
                   "first_use": int(v.getFirstUseOffset())}
            if st.isHashStorage():
                loc["hash"] = "0x%x" % (int(st.getFirstVarnode().getOffset()) & ((1 << 64) - 1))
                loc["type"] = self.type_ref(dt, int(dt.getLength()))
                loc["size"] = int(dt.getLength())
            else:
                loc["storage"] = self.varnodes(st)
                loc["type"] = self.type_ref(dt, int(st.size()))
                loc["float"] = _is_float(dt)
                loc["type_size"] = int(dt.getLength())
            sym = v.getSymbol()
            if sym is not None:
                loc["id"] = int(sym.getID())
            locs.append(loc)
        rec["locals"] = locs
        if f.getSignatureSource() == SourceType.DEFAULT:
            pass
        return rec

    def mutability(self, a, data=None) -> str:
        from ghidra.program.model.pcode import MappedEntry
        from ghidra.program.model.data import MutabilitySettingsDefinition as M
        if data is not None:
            if data.isVolatile():
                return "volatile"
            if data.isConstant():
                return "constant"
            if data.isWritable():
                return "normal"
        m = MappedEntry.getMutabilityOfAddress(a, self.program)
        return {M.CONSTANT: "constant", M.VOLATILE: "volatile"}.get(m, "normal")

    def data_and_symbols(self, bodies):
        """Globals the decompiler can be told about: defined data (with its
        primary symbol or dynamic name), undefined bytes that carry a symbol,
        labels, and external references from pointer data."""
        from ghidra.program.model.symbol import SymbolUtilities, SymbolType
        from ghidra.program.model.data import DataType

        data_out, ext_out, label_out, code_labels = [], [], [], []
        seen = set()
        it = self.listing.getDefinedData(True)
        while it.hasNext():
            d = it.next()
            a = d.getMinAddress()
            if not d.getMinAddress().isMemoryAddress():
                continue
            seen.add((str(a.getAddressSpace().getName()), int(a.getOffset())))
            if d.isPointer():
                ref = d.getPrimaryReference(0)
                if ref is not None and ref.isExternalReference():
                    rec = {**self.where(a), "label": str(ref.getLabel())}
                    to = self.listing.getFunctionAt(ref.getToAddress())
                    if to is not None:
                        rec["function"] = self.function(to)
                    sym = ref.getExternalLocation().getSymbol()
                    if sym is not None:
                        rec["id"] = int(sym.getID())
                    ext_out.append(rec)
            sym = d.getPrimarySymbol()
            name = str(sym.getName()) if sym is not None else str(SymbolUtilities.getDynamicName(self.program, a))
            n = int(d.getLength())
            rec = {**self.where(a), "name": name, "length": n,
                   "type": self.type_ref(d.getDataType(), n),
                   "mutability": self.mutability(a, d)}
            text = _string_value(d)
            if text is not None:
                rec["string"] = text
            if sym is not None:
                rec["id"] = int(sym.getID())
                path = _ns_path(sym.getParentNamespace())
                if path:
                    rec["namespace"] = path
            else:
                rec["dynamic"] = True
            data_out.append(rec)

        sit = self.symtab.getAllSymbols(True)
        while sit.hasNext():
            s = sit.next()
            a = s.getAddress()
            if not a.isMemoryAddress() or s.isExternal() or not s.isPrimary():
                continue
            st = s.getSymbolType()
            if st not in (SymbolType.LABEL,):
                continue
            key = (str(a.getAddressSpace().getName()), int(a.getOffset()))
            in_body = bodies.contains(a)
            name = str(s.getName())
            ns = s.getParentNamespace()
            if in_body:
                # getCodeLabel: the primary name, namespace-prefixed. Default
                # (dynamic) names are included: only referenced addresses
                # have one, and the decompiler prints code_<addr> otherwise.
                code_labels.append({**self.where(a), "name": _prefixed_name(s)})
                continue
            if key in seen or self.listing.getDefinedDataContaining(a) is not None:
                continue
            if self.listing.getInstructionAt(a) is not None or self.listing.getInstructionContaining(a) is not None:
                if s.isGlobal():
                    label_out.append(self._label(s))
                continue
            d = self.listing.getDataAt(a)
            if d is None:
                if s.isGlobal():
                    label_out.append(self._label(s))
                continue
            rec = {**self.where(a), "name": name, "length": 1,
                   "type": self.type_ref(DataType.DEFAULT, 1), "mutability": self.mutability(a, d)}
            if not s.isDynamic():
                rec["id"] = int(s.getID())
            else:
                rec["dynamic"] = True
            path = _ns_path(ns)
            if path:
                rec["namespace"] = path
            data_out.append(rec)
        def key(r):
            return (r.get("space", ""), int(r["addr"], 16))
        data_out.sort(key=key)
        ext_out.sort(key=key)
        label_out.sort(key=key)
        code_labels.sort(key=key)
        return data_out, ext_out, label_out, code_labels

    def _label(self, s) -> dict:
        rec = {**self.where(s.getAddress()), "name": str(s.getName())}
        path = _ns_path(s.getParentNamespace())
        if path:
            rec["namespace"] = path
        return rec

    def comments(self, bodies):
        from ghidra.program.model.listing import CommentType
        out = []
        for kind, ct in (("eol", CommentType.EOL), ("pre", CommentType.PRE), ("post", CommentType.POST),
                         ("plate", CommentType.PLATE)):
            it = self.listing.getCommentAddressIterator(ct, bodies, True)
            while it.hasNext():
                a = it.next()
                text = self.listing.getComment(ct, a)
                if text is not None:
                    out.append({"addr": self.addr(a), "kind": kind, "text": str(text)})
        out.sort(key=lambda c: (int(c["addr"], 16), c["kind"]))
        return out

    def tracked(self, functions):
        """Register values the program context holds at function entries
        (getTrackedRegisters), keyed by entry."""
        ctx = self.program.getProgramContext()
        regs = [r for r in ctx.getRegistersWithValues() if not r.isProcessorContext()]
        out = {}
        for f in functions:
            a = f.getEntryPoint()
            sets = []
            for r in regs:
                v = ctx.getValue(r, a, False)
                if v is not None:
                    sets.append([str(r.getAddressSpace().getName()), "0x%x" % int(r.getOffset()),
                                 int(r.getMinimumByteSize()), "0x%x" % (int(v.longValue()) & ((1 << 64) - 1))])
            if sets:
                out[self.addr(a)] = sets
        return out

    def flow_overrides(self, bodies):
        from ghidra.program.model.listing import FlowOverride
        out = []
        it = self.listing.getInstructions(bodies, True)
        while it.hasNext():
            i = it.next()
            fo = i.getFlowOverride()
            if fo != FlowOverride.NONE:
                out.append({"addr": self.addr(i.getAddress()), "kind": str(fo)})
        return out

    def equates(self):
        n = 0
        it = self.program.getEquateTable().getEquates()
        while it.hasNext():
            it.next()
            n += 1
        return n


_DEFAULT = None


def ge_default_type():
    global _DEFAULT
    if _DEFAULT is None:
        from ghidra.program.model.data import DataType
        _DEFAULT = DataType.DEFAULT
    return _DEFAULT


def _is_float(dt) -> bool:
    from ghidra.program.model.data import AbstractFloatDataType
    return isinstance(dt, AbstractFloatDataType)


def _ns_path(ns):
    """HighFunction.encodeNamespace: [id, name] from below the root (global,
    or a library, which the decompiler treats as global) down to `ns`; empty
    for the global namespace."""
    from ghidra.program.model.listing import Library
    out = []
    while ns is not None and not ns.isGlobal() and not isinstance(ns, Library):
        out.append([int(ns.getID()), str(ns.getName())])
        ns = ns.getParentNamespace()
    out.reverse()
    return out


def _function_namespace(f):
    """HighFunctionSymbol.getNamespace: a thunk in the global namespace takes
    its thunked function's namespace."""
    ns = f.getParentNamespace()
    while f.isThunk() and ns.getID() == 0:
        t = f.getThunkedFunction(False)
        if t is None:
            break
        f = t
        ns = f.getParentNamespace()
    return ns


def _address_prefix(program) -> str:
    text = str(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000).toString())
    return text.split(":")[0] + "_" if ":" in text else ""


def _string_value(data):
    """The value Java's getStringData sends for defined string data."""
    from ghidra.program.model.data import StringDataInstance
    inst = StringDataInstance.getStringDataInstance(data)
    if inst == StringDataInstance.NULL_INSTANCE:
        return None
    if inst.isShowTranslation() and inst.getTranslatedValue() is not None:
        return str(inst.getTranslatedValue())
    v = inst.getStringValue()
    return None if v is None else str(v)


def _prefixed_name(sym) -> str:
    """DecompileCallback.getSymbolName: parent namespaces joined with '_'."""
    parts = []
    ns = sym.getParentNamespace()
    while ns is not None and not ns.isGlobal():
        from ghidra.program.model.listing import Function
        if isinstance(ns, Function):
            break  # the function being decompiled; a fair approximation
        parts.append(str(ns.getName()))
        ns = ns.getParentNamespace()
    parts.reverse()
    return "_".join(parts + [str(sym.getName())])


def decompile_all(program, timeout: int) -> dict:
    """Ghidra's own C for every function, from this same analysis run (as
    ghidra_export.py writes it), keyed by entry."""
    from ghidra.util.task import TaskMonitor
    ifc = ge._decompiler(program)
    out = {}
    try:
        for f in program.getListing().getFunctions(True):
            res = ifc.decompileFunction(f, timeout, TaskMonitor.DUMMY)
            df = res.getDecompiledFunction() if res is not None else None
            if df is not None:
                out["0x%x" % (int(f.getEntryPoint().getOffset()) & ((1 << 64) - 1))] = str(df.getC())
    finally:
        ifc.dispose()
    return out


def export_db(program, rel: str, sha: str, stats: dict) -> dict:
    from ghidra.program.model.address import AddressSet

    ex = Exporter(program)
    funcs = list(program.getListing().getFunctions(True))
    bodies = AddressSet()
    for f in funcs:
        bodies.add(f.getBody())
    fn_out = [ex.function(f) for f in funcs]
    data, ext, labels, code_labels = ex.data_and_symbols(bodies)
    doc = {
        "format": FORMAT,
        "format_version": VERSION,
        "producer": "ghidra-" + str(ge._ghidra_version()),
        "binary": {
            "path": rel, "sha256": sha,
            "language": str(program.getLanguageID().getIdAsString()),
            "compiler": str(program.getCompilerSpec().getCompilerSpecID().getIdAsString()),
            "image_base": ex.addr(program.getImageBase()),
            "default_convention": str(program.getCompilerSpec().getDefaultCallingConvention().getName()),
            # SymbolUtilities.getAddressString: "ram_" where Ghidra shows space names.
            "address_prefix": _address_prefix(program),
        },
        "synthesized_memory": ex.synthesized_memory(),
        "memory": ex.memory_blocks(),
        "patches": ex.patches(),
        "functions": fn_out,
        "data": data,
        "external_refs": ext,
        "labels": labels,
        "code_labels": code_labels,
        "comments": ex.comments(bodies),
        "tracked": ex.tracked(funcs),
        "flow_overrides": ex.flow_overrides(bodies),
    }
    ex.define_pending()
    doc["types"] = [ex.types[k] for k in sorted(ex.types) if ex.types[k] is not None]
    stats.update(functions=len(fn_out), data=len(data), types=len(doc["types"]),
                 external_refs=len(ext), equates=ex.equates(), flow_overrides=len(doc["flow_overrides"]))
    return doc


def write_json(path: str, doc: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write("{\n")
        keys = sorted(doc)
        for i, k in enumerate(keys):
            v = doc[k]
            f.write(json.dumps(k) + ": ")
            if isinstance(v, list) and v:
                f.write("[\n" + ",\n".join(json.dumps(x, sort_keys=True, separators=(",", ":")) for x in v) + "\n]")
            else:
                f.write(json.dumps(v, sort_keys=True, separators=(",", ":")))
            f.write(",\n" if i + 1 < len(keys) else "\n")
        f.write("}\n")
    os.replace(tmp, path)


def run_job(job: dict) -> dict:
    from java.io import File
    from ghidra.app.util.importer import ProgramLoader, MessageLog
    from ghidra.util.task import TaskMonitor

    stats = {"rel": job["rel"], "ok": False}
    t0 = time.monotonic()
    try:
        sha = ge.sha256_file(job["file"])
        results = (ProgramLoader.builder().source(File(job["file"])).name(os.path.basename(job["file"]))
                   .log(MessageLog()).monitor(TaskMonitor.DUMMY).load())
        try:
            program = results.getPrimaryDomainObject()
            if job.get("pdb"):
                from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
                tx = program.startTransaction("pdb option")
                try:
                    PdbUniversalAnalyzer.setPdbFileOption(program, File(job["pdb"]))
                finally:
                    program.endTransaction(tx, True)
            ge._analyze(program)
            t1 = time.monotonic()
            doc = export_db(program, job["rel"], sha, stats)
            if job.get("with_c"):
                c = decompile_all(program, 120)
                for f in doc["functions"]:
                    if f["entry"] in c:
                        f["decompiled_c"] = c[f["entry"]]
            write_json(job["out"], doc)
            stats.update(ok=True, analyze_s=round(t1 - t0, 2), export_s=round(time.monotonic() - t1, 2))
        finally:
            results.close()
    except Exception:  # noqa: BLE001 - report and continue
        stats["error"] = traceback.format_exc()
    stats["total_s"] = round(time.monotonic() - t0, 2)
    return stats


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--only", action="append", default=[], metavar="GLOB")
    ap.add_argument("--out", required=True)
    ap.add_argument("-j", "--jobs", type=int, default=0)
    ap.add_argument("--heap", default="3g")
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR", ge.DEFAULT_GHIDRA))
    ap.add_argument("--stats")
    ap.add_argument("--with-c", action="store_true",
                    help="also decompile every function in the same session (functions[].decompiled_c)")
    args = ap.parse_args(argv)

    jobs = ge.jobs_from_manifest(args.corpus, args.only)
    for job in jobs:
        job["out"] = os.path.join(args.out, job["rel"] + ".json")
        job["with_c"] = args.with_c
    jobs.sort(key=lambda j: (-os.path.getsize(j["file"]), j["rel"]))
    njobs = args.jobs or max(1, min(len(jobs), (os.cpu_count() or 4) // 3, ge._ram_gb() // 3))
    tmp_root = tempfile.mkdtemp(prefix="revkit-ghidra-dbexport-")
    print("exporting decompiler inputs for %d binaries with %d workers" % (len(jobs), njobs), flush=True)
    start = time.monotonic()
    results = []
    try:
        ctx = mp.get_context("spawn")
        with ctx.Pool(njobs, initializer=ge.worker_init, initargs=(args.ghidra, args.heap, tmp_root, 60),
                      maxtasksperchild=25) as pool:
            for st in pool.imap_unordered(run_job, jobs, chunksize=1):
                results.append(st)
                if st["ok"]:
                    print("[%d/%d] %-50s %6.1fs %5d funcs %6d data %5d types" % (
                        len(results), len(jobs), st["rel"], st["total_s"], st["functions"], st["data"],
                        st["types"]), flush=True)
                else:
                    print("[%d/%d] %s FAILED\n%s" % (len(results), len(jobs), st["rel"], st["error"]), flush=True)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)
    print("done in %.1fs" % (time.monotonic() - start))
    if args.stats:
        with open(args.stats, "w") as f:
            json.dump({"wall_s": round(time.monotonic() - start, 1), "workers": njobs,
                       "binaries": sorted(results, key=lambda s: s["rel"])}, f, indent=1, sort_keys=True)
    return 0 if all(s["ok"] for s in results) else 1


if __name__ == "__main__":
    sys.exit(main())
