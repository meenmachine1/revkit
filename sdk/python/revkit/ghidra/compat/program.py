"""``currentProgram`` for the compat shim: Ghidra's Program, Listing,
FunctionManager, SymbolTable, Memory and ReferenceManager over one revkit
program, with the run's buffered edits.

Reads go to the daemon through a per-run :class:`Session` that caches what
Ghidra scripts walk again and again (the functions, symbols, defined data,
and each memory block's instructions). Edits go into the run's buffer
(``revkit.script``): names and comments are visible to the script at once
through an overlay, and a structural edit (a function, disassembly, cleared
or defined data) is committed before the script's next read, so the script
sees what it did, as in Ghidra. A run without structural edits is one
revision; with them, one revision per batch, all with the run's session.
"""

from __future__ import annotations

import bisect
import re
import struct
from typing import Any, Iterable, Optional

from revkit.client import NotFound, RevkitError, _signed64, address, address_range, clear_code_body, \
    define_data_body, disassemble_body, fold_equates, masked_query, operand_display_body, reference_body, rename_equate_bodies
from revkit.ghidra.compat.errors import Unsupported
from revkit.ghidra.compat.model import (
    RAM,
    Address,
    AddressSet,
    AddressSetView,
    AddressSpace,
    ByteArray,
    CategoryPath,
    DataType,
    JavaIterator,
    JavaList,
    JavaObject,
    RefType,
    Register,
    Scalar,
    SourceType,
    SymbolType,
    addr_int,
    array_of,
    comment_kind,
    pointer_to,
    space_named,
    to_bytes,
)
from revkit.v1 import assertion_pb2, common_pb2, listing_pb2, query_pb2

_KIND_OF_VIEW = {1: "eol", 2: "pre", 3: "post", 4: "plate", 5: "repeatable", 6: "decompiler"}
# Names Ghidra makes up (dynamic, SourceType.DEFAULT): FUN_00101020,
# LAB_00101016, s_text_00102004, PTR_00103fb0, ...
_DEFAULT_NAME = re.compile(r"^(?:(?:FUN|LAB|DAT|PTR|SUB|EXT|UNK|OFF|BYTE|WORD|DWORD|QWORD|thunk_FUN|switchD|caseD)_"
                           r"[0-9a-fA-F]+|[su]_.*_[0-9a-fA-F]{8,})$")
_DEFAULT_PREFIXES = ("FUN_", "LAB_", "DAT_", "SUB_", "PTR_", "s_", "u_", "EXT_", "thunk_FUN_", "switchD_", "caseD_",
                     "BYTE_", "WORD_", "DWORD_", "QWORD_", "UNK_", "OFF_", "ZEXT_", "INT_", "CHAR_")


def source_of(origin: common_pb2.FactOrigin, name: str = "") -> SourceType:
    """Ghidra's SourceType for a revkit fact's origin."""
    which = origin.WhichOneof("source")
    if which == "asserted":
        kind = origin.asserted.provenance.kind
        return {
            common_pb2.PROVENANCE_KIND_USER: SourceType.USER_DEFINED,
            common_pb2.PROVENANCE_KIND_IMPORT: SourceType.IMPORTED,
            common_pb2.PROVENANCE_KIND_MIGRATION: SourceType.IMPORTED,
            common_pb2.PROVENANCE_KIND_AGENT: SourceType.AI,
        }.get(kind, SourceType.ANALYSIS)
    rule = origin.derived.rule if which == "derived" else ""
    if rule.startswith("names.default") or not name or _DEFAULT_NAME.match(name):
        return SourceType.DEFAULT
    if rule.startswith("names.loader") or rule == "analysis.functions" or rule.startswith("loader"):
        return SourceType.IMPORTED
    return SourceType.ANALYSIS


class Session:
    """One run's view of its program: caches, the edit overlay, and the
    revkit objects the shim's classes read."""

    def __init__(self, run):
        self.run = run
        self.prog = run.need_program()
        self.summary = self.prog.summary()
        lang = self.summary.language
        size = 64
        for s in self.summary.spaces:
            if s.is_default:
                size = s.size * 8 if s.size <= 16 else s.size
        self.space = AddressSpace(lang.default_space or "ram", size, 1, True, "memory") if lang.default_space else RAM
        self.little = lang.endianness != 2  # ENDIANNESS_BIG = 2
        self.pointer_size = lang.pointer_size or 8
        self.names: dict = {}  # addr -> name not committed yet
        self.local_names: dict = {}  # (entry, storage_key) -> name
        self.comments: dict = {}  # (addr, kind) -> text ("" deletes)
        self.patches: dict = {}  # addr -> byte
        self.pending_equates: dict = {}  # name -> value: equates with no reference (createEquate)
        self.structural = False
        try:
            self.token_scalars = "token-scalars" in run.features()
        except Exception:  # noqa: BLE001 - a daemon without GetServerInfo
            self.token_scalars = False
        self.program = Program(self)
        self.reset()

    # -- caches -------------------------------------------------------------

    def reset(self) -> None:
        self._functions = None
        self._symbols = None
        self._data = None
        self._blocks = None
        self._insns: dict = {}
        self._comment_cache: dict = {}
        self._comment_facts = None
        self._xrefs_from: dict = {}
        self._equates = None

    def addr(self, o) -> Address:
        return Address(o.offset if isinstance(o, common_pb2.Address) else int(o), self.space)

    def sync(self) -> None:
        """Before a daemon read: commit structural edits so the read sees them."""
        if self.structural:
            self.commit()

    def commit(self) -> None:
        self.flush_patches()
        if len(self.run.edits):
            self.run.edits.commit()
        self.structural = False
        self.names.clear()
        self.local_names.clear()
        self.comments.clear()
        self.reset()

    def flush_patches(self) -> None:
        if not self.patches:
            return
        offs = sorted(self.patches)
        runs, start, buf = [], offs[0], bytearray([self.patches[offs[0]]])
        for o in offs[1:]:
            if o == start + len(buf):
                buf.append(self.patches[o])
            else:
                runs.append((start, bytes(buf)))
                start, buf = o, bytearray([self.patches[o]])
        runs.append((start, bytes(buf)))
        self.patches.clear()
        from revkit.v1 import patch_pb2

        self.run.require_script_provenance()
        prov = self.run.provenance()
        for start, data in runs:
            resp = self.prog._p("PatchBytes", patch_pb2.PatchBytesRequest(
                program_id=self.prog.id, address=address(start), data=data, provenance=prov))
            # In the run's result like its other commits: one undo step, and
            # revert(session=run) takes the patch back too.
            self.run.edits.commits.append(_Committed(resp.revision, list(resp.seqs)))
        self.reset()

    # -- edits --------------------------------------------------------------

    def edit(self, what: str, body: assertion_pb2.AssertionBody, structural: bool = False) -> None:
        self.run.edits.add(what, body)
        if structural:
            self.structural = True

    def rename(self, a: int, name: str) -> None:
        cur = self.name_at(a)
        if cur == name:
            return
        self.edit(f"rename 0x{a:x} to {name!r}", assertion_pb2.AssertionBody(
            rename=assertion_pb2.Rename(target=assertion_pb2.Target(address=address(a)), name=name)))
        self.names[a] = name

    def rename_local(self, entry: int, key: str, name: str) -> None:
        self.edit(f"rename local {key} to {name!r}", assertion_pb2.AssertionBody(rename=assertion_pb2.Rename(
            target=assertion_pb2.Target(local=assertion_pb2.LocalVariableRef(function=address(entry), storage_key=key)),
            name=name)))
        self.local_names[(entry, key)] = name

    def retype_local(self, entry: int, key: str, c: str) -> None:
        self.edit(f"retype local {key} as {c!r}", assertion_pb2.AssertionBody(retype=assertion_pb2.Retype(
            target=assertion_pb2.Target(local=assertion_pb2.LocalVariableRef(function=address(entry), storage_key=key)),
            type=assertion_pb2.TypeSpec(c_declaration=c))), structural=True)

    def set_comment(self, a: int, kind: str, text: Optional[str]) -> None:
        text = text or ""
        if self.comment_at(a, kind) == (text or None):
            return
        from revkit.client import _COMMENT_KINDS

        self.edit(f"{kind} comment at 0x{a:x}", assertion_pb2.AssertionBody(
            comment=assertion_pb2.Comment(address=address(a), kind=_COMMENT_KINDS[kind], text=text)))
        self.comments[(a, kind)] = text

    # -- functions ------------------------------------------------------------

    def functions(self) -> list:
        self.sync()
        if self._functions is None:
            fs = [Function(self, f) for f in self.prog.functions()]
            fs.sort(key=lambda f: f._f.entry.offset)
            self._functions = fs
            self._fn_entries = [f._f.entry.offset for f in fs]
            ranges = []
            for f in fs:
                for r in f._f.body:
                    ranges.append((r.first.offset, r.last.offset, f))
            ranges.sort(key=lambda r: r[0])
            self._fn_ranges = ranges
            self._fn_starts = [r[0] for r in ranges]
        return self._functions

    def function_at(self, a: int) -> Optional["Function"]:
        fs = self.functions()
        i = bisect.bisect_left(self._fn_entries, a)
        return fs[i] if i < len(fs) and self._fn_entries[i] == a else None

    def function_containing(self, a: int) -> Optional["Function"]:
        self.functions()
        i = bisect.bisect_right(self._fn_starts, a) - 1
        best = None
        while i >= 0:
            lo, hi, f = self._fn_ranges[i]
            if lo <= a <= hi:
                best = f
                break
            if hi < a and lo < a - (1 << 24):
                break
            i -= 1
        return best

    def function_after(self, a: int) -> Optional["Function"]:
        fs = self.functions()
        i = bisect.bisect_right(self._fn_entries, a)
        return fs[i] if i < len(fs) else None

    def function_before(self, a: int) -> Optional["Function"]:
        fs = self.functions()
        i = bisect.bisect_left(self._fn_entries, a) - 1
        return fs[i] if i >= 0 else None

    # -- symbols --------------------------------------------------------------

    def symbols(self) -> list:
        self.sync()
        if self._symbols is None:
            syms = [Symbol(self, s.address.offset, s.name, s.kind, s.origin) for s in self.prog.symbols()]
            syms.sort(key=lambda s: s._a)
            self._symbols = syms
            self._sym_addrs = [s._a for s in syms]
        return self._symbols

    def symbol_at(self, a: int) -> Optional["Symbol"]:
        syms = self.symbols()
        i = bisect.bisect_left(self._sym_addrs, a)
        if i < len(syms) and syms[i]._a == a:
            return syms[i]
        if a in self.names:
            f = self.function_at(a)
            kind = listing_pb2.SYMBOL_KIND_FUNCTION if f else listing_pb2.SYMBOL_KIND_LABEL
            return Symbol(self, a, self.names[a], kind, None)
        return None

    def name_at(self, a: int) -> str:
        if a in self.names:
            return self.names[a]
        s = self.symbol_at(a)
        return s._name if s else ""

    # -- memory -----------------------------------------------------------------

    def blocks(self) -> list:
        self.sync()
        if self._blocks is None:
            self._blocks = [MemoryBlock(self, b) for b in self.prog.memory_map()]
        return self._blocks

    def block_of(self, a: int) -> Optional["MemoryBlock"]:
        for b in self.blocks():
            if b._lo <= a <= b._hi:
                return b
        return None

    def read(self, a: int, n: int) -> bytes:
        out, cur, left = bytearray(), a, n
        while left > 0:
            chunk = self.prog.read_memory(cur, min(left, 1 << 20))
            if not chunk:
                break
            out += chunk
            cur += len(chunk)
            left -= len(chunk)
        if self.patches:
            for i in range(len(out)):
                if a + i in self.patches:
                    out[i] = self.patches[a + i]
        return bytes(out)

    def patch(self, a: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self.patches[a + i] = b

    # -- instructions -------------------------------------------------------------

    def block_insns(self, b: "MemoryBlock") -> tuple:
        """(sorted offsets, {offset: Instruction}) of one block."""
        self.sync()
        got = self._insns.get(b._lo)
        if got is None:
            items = {}
            if b._b.initialized and b._b.execute or b._b.initialized:
                for d in self.prog.instructions(b._lo, b._hi, pcode=False):
                    items[d.address.offset] = Instruction(self, d)
            got = (sorted(items), items)
            self._insns[b._lo] = got
        return got

    def insn_at(self, a: int) -> Optional["Instruction"]:
        b = self.block_of(a)
        if b is None:
            return None
        return self.block_insns(b)[1].get(a)

    def insn_containing(self, a: int) -> Optional["Instruction"]:
        b = self.block_of(a)
        if b is None:
            return None
        offs, items = self.block_insns(b)
        i = bisect.bisect_right(offs, a) - 1
        if i >= 0:
            ins = items[offs[i]]
            if offs[i] <= a < offs[i] + ins._d.length:
                return ins
        return None

    def insns(self, lo: int = 0, hi: int = (1 << 64) - 1, forward: bool = True) -> Iterable["Instruction"]:
        blocks = [b for b in self.blocks() if b._hi >= lo and b._lo <= hi]
        if not forward:
            blocks.reverse()
        for b in blocks:
            offs, items = self.block_insns(b)
            sel = [o for o in offs if lo <= o <= hi]
            for o in (sel if forward else reversed(sel)):
                yield items[o]

    def insn_after(self, a: int) -> Optional["Instruction"]:
        for ins in self.insns(a + 1):
            return ins
        return None

    def insn_before(self, a: int) -> Optional["Instruction"]:
        if a == 0:
            return None
        for ins in self.insns(0, a - 1, forward=False):
            return ins
        return None

    def xrefs_from(self, a: int) -> list:
        self.sync()
        got = self._xrefs_from.get(a)
        if got is None:
            got = [Reference(self, x) for x in self.prog.xrefs(a, direction="from")]
            self._xrefs_from[a] = got
        return got

    # -- data -------------------------------------------------------------------

    def data(self) -> tuple:
        self.sync()
        if self._data is None:
            items = {d.address.offset: Data(self, d) for d in self.prog.data()}
            self._data = (sorted(items), items)
        return self._data

    def data_at(self, a: int) -> Optional["Data"]:
        return self.data()[1].get(a)

    def data_containing(self, a: int) -> Optional["Data"]:
        offs, items = self.data()
        i = bisect.bisect_right(offs, a) - 1
        if i >= 0 and offs[i] <= a < offs[i] + max(1, items[offs[i]]._d.length):
            return items[offs[i]]
        return None

    def defined_data(self, lo: int = 0, hi: int = (1 << 64) - 1, forward: bool = True):
        offs, items = self.data()
        sel = [o for o in offs if lo <= o <= hi]
        for o in (sel if forward else reversed(sel)):
            yield items[o]

    # -- code units -----------------------------------------------------------------

    def code_unit_at(self, a: int):
        return self.insn_at(a) or self.data_at(a) or self._undefined_at(a)

    def code_unit_containing(self, a: int):
        cu = self.insn_containing(a) or self.data_containing(a)
        if cu is not None:
            return cu
        return self._undefined_at(a)

    def _undefined_at(self, a: int):
        b = self.block_of(a)
        if b is None or self.insn_containing(a) is not None or self.data_containing(a) is not None:
            return None
        return UndefinedData(self, a)

    def code_units(self, lo: int = 0, hi: int = (1 << 64) - 1, forward: bool = True, kinds=("insn", "data", "undef")):
        """Instructions, defined data and undefined bytes in address order."""
        blocks = [b for b in self.blocks() if b._hi >= lo and b._lo <= hi]
        if not forward:
            blocks.reverse()
        for b in blocks:
            units = []
            offs, items = self.block_insns(b)
            for o in offs:
                units.append((o, items[o]._d.length, items[o]))
            doffs, ditems = self.data()
            for o in doffs[bisect.bisect_left(doffs, b._lo):bisect.bisect_right(doffs, b._hi)]:
                units.append((o, max(1, ditems[o]._d.length), ditems[o]))
            units.sort(key=lambda u: u[0])
            seq = []
            cur = b._lo
            for o, n, u in units:
                if o > cur and "undef" in kinds:
                    seq.append((cur, o - 1))
                if o >= cur:
                    seq.append(u)
                    cur = o + n
            if cur <= b._hi and "undef" in kinds:
                seq.append((cur, b._hi))
            if not forward:
                seq.reverse()
            for item in seq:
                if isinstance(item, tuple):
                    first, last = max(item[0], lo), min(item[1], hi)
                    rng = range(first, last + 1) if forward else range(last, first - 1, -1)
                    for o in rng:
                        yield UndefinedData(self, o)
                else:
                    o = item._a
                    if lo <= o <= hi and ((isinstance(item, Instruction) and "insn" in kinds) or
                                          (isinstance(item, Data) and "data" in kinds)):
                        yield item

    # -- comments -----------------------------------------------------------------

    def comment_facts(self) -> set:
        """Addresses with comment assertions: where a comment may be that the
        listing doesn't show (on a byte inside a folded row of undefined bytes)."""
        if self._comment_facts is None:
            self.sync()
            self._comment_facts = {x.key.address.offset for x in self.prog.assertions() if x.body.HasField("comment")}
        return self._comment_facts

    def _comments_by_fact(self, a: int) -> dict:
        from revkit.client import fact_key

        got = {}
        for kind in ("eol", "pre", "post", "plate", "repeatable"):
            text = self.prog.blame(fact_key(self.prog.id, "comment", a, kind)).value_text
            if text:
                got[kind] = text
        return got

    def comments_at(self, a: int) -> dict:
        """{kind: text} of the code unit at ``a``, overlay included."""
        if a not in self._comment_cache:
            self.sync()
            got = {}
            resp = self.prog.listing(a, max_rows=1, omit_bytes=True)
            at_row = False
            for row in resp.rows:
                if row.address.offset == a:
                    at_row = True
                    for cv in row.comments:
                        got[_KIND_OF_VIEW.get(cv.kind, "eol")] = cv.text
            if not at_row and a in self.comment_facts():
                got = self._comments_by_fact(a)
            self._comment_cache[a] = got
        out = dict(self._comment_cache[a])
        for (ca, kind), text in self.comments.items():
            if ca == a:
                if text:
                    out[kind] = text
                else:
                    out.pop(kind, None)
        return out

    def comment_at(self, a: int, kind: str) -> Optional[str]:
        return self.comments_at(a).get(kind)

    def comment_addresses(self, lo: int, hi: int, kind: Optional[str] = None) -> list:
        """Addresses with a comment (of ``kind``) in [lo, hi]."""
        if self.comments or self.names or self.structural:
            self.commit()
        out = []
        cur = lo
        while cur <= hi:
            resp = self.prog.listing(cur, hi, max_rows=4000, omit_bytes=True)
            if not resp.rows:
                break
            for row in resp.rows:
                kinds = {_KIND_OF_VIEW.get(cv.kind, "eol"): cv.text for cv in row.comments}
                if kinds and (kind is None or kind in kinds):
                    o = row.address.offset
                    if lo <= o <= hi and (not out or out[-1] != o):
                        out.append(o)
                        self._comment_cache.setdefault(o, kinds)
            last = resp.rows[-1]
            nxt = last.address.offset + max(1, last.length)
            if not resp.truncated or nxt <= cur:
                break
            cur = nxt
        # Comments on bytes the listing folds into a row of undefined bytes.
        for o in self.comment_facts():
            if lo <= o <= hi and o not in out and (kind is None and self.comments_at(o) or kind in self.comments_at(o)):
                out.append(o)
        return sorted(out)

    # -- equates ----------------------------------------------------------------

    def equates(self) -> dict:
        """The program's equates as committed: {name: revkit.Equate}."""
        self.sync()
        if self._equates is None:
            self._equates = fold_equates(self.prog.assertions(kinds=("equate",)))
        return self._equates

    # -- types ------------------------------------------------------------------

    def program_type(self, name: str) -> Optional[DataType]:
        """A program type (FindTypes) by its name ("point", "struct point")."""
        bare = name.split(" ", 1)[1] if name.startswith(("struct ", "union ", "enum ")) else name
        for t in self.prog.find_types(bare):
            if t.name == bare or t.display == name:
                return type_from_definition(t)
        return None


class _Committed:
    """A PatchBytes in the shape of an AppendAssertionsResponse (the run's commits)."""

    class _Snap:
        def __init__(self, revision):
            self.revision = revision

    class _A:
        def __init__(self, seq):
            self.seq = seq

    def __init__(self, revision: int, seqs: list):
        self.snapshot = self._Snap(revision)
        self.assertions = [self._A(q) for q in seqs]


def type_from_definition(t) -> DataType:
    from revkit.v1 import types_pb2

    kind = types_pb2.TypeKind.Name(t.kind).replace("TYPE_KIND_", "").lower()
    c = t.display or t.name
    if kind in ("struct", "union", "enum") and not c.startswith(kind + " "):
        c = f"{kind} {t.name}"
    return DataType(t.name, c, int(t.size) if t.size else -1, type_hash=t.hash, kind=kind, category="/")


# ---------------------------------------------------------------------------
# Program
# ---------------------------------------------------------------------------


class Program(JavaObject):
    """``currentProgram``."""

    _java_name = "Program"

    def __init__(self, s: Session):
        self._s = s
        self._listing = Listing(s)
        self._functions = FunctionManager(s)
        self._symbols = SymbolTable(s)
        self._memory = Memory(s)
        self._refs = ReferenceManager(s)
        self._factory = AddressFactory(s)
        self._dtm = DataTypeManager(s)
        self._equate_table = EquateTable(s)
        self._txn = 0

    def getName(self) -> str:
        return self._s.summary.info.name

    def getListing(self) -> "Listing":
        return self._listing

    def getFunctionManager(self) -> "FunctionManager":
        return self._functions

    def getSymbolTable(self) -> "SymbolTable":
        return self._symbols

    def getMemory(self) -> "Memory":
        return self._memory

    def getReferenceManager(self) -> "ReferenceManager":
        return self._refs

    def getEquateTable(self) -> "EquateTable":
        return self._equate_table

    def getAddressFactory(self) -> "AddressFactory":
        return self._factory

    def getDataTypeManager(self) -> "DataTypeManager":
        return self._dtm

    def getLanguage(self) -> "Language":
        return Language(self._s)

    def getLanguageID(self) -> "LanguageID":
        return LanguageID(self._s.summary.language.language_id)

    def getCompilerSpec(self) -> "CompilerSpec":
        return CompilerSpec(self._s)

    def getMinAddress(self) -> Optional[Address]:
        bs = self._s.blocks()
        return self._s.addr(min(b._lo for b in bs)) if bs else None

    def getMaxAddress(self) -> Optional[Address]:
        bs = self._s.blocks()
        return self._s.addr(max(b._hi for b in bs)) if bs else None

    def getImageBase(self) -> Address:
        return self._s.addr(self._s.summary.image_base.offset)

    def getExecutableFormat(self) -> str:
        return {"elf": "Executable and Linking Format (ELF)", "pe": "Portable Executable (PE)",
                "macho": "Mac OS X Mach-O", "raw": "Raw Binary"}.get(self._s.summary.info.format,
                                                                       self._s.summary.info.format)

    def getExecutableSHA256(self) -> str:
        return self._s.summary.info.sha256

    def getExecutablePath(self) -> str:
        return self._s.summary.info.name

    def getDefaultPointerSize(self) -> int:
        return self._s.pointer_size

    def getGlobalNamespace(self) -> "GlobalNamespace":
        return GlobalNamespace(self._s)

    def startTransaction(self, description: str = "") -> int:
        self._txn += 1
        return self._txn

    def endTransaction(self, txn: int, commit: bool = True) -> bool:
        if not commit:
            raise Unsupported("Program.endTransaction(rollback)")
        return True

    def withTransaction(self, description, fn):
        return fn()

    def flushEvents(self) -> None:
        pass

    def __str__(self):
        return self.getName()

    def __eq__(self, other):
        return isinstance(other, Program) and other._s is self._s

    def __hash__(self):
        return id(self._s)


class LanguageID(JavaObject):
    def __init__(self, id_: str):
        self.id = id_

    def getIdAsString(self) -> str:
        return self.id

    def __str__(self):
        return self.id

    def __eq__(self, other):
        return str(other) == self.id

    def __hash__(self):
        return hash(self.id)


class Processor(LanguageID):
    _java_name = "Processor"


class Language(JavaObject):
    def __init__(self, s: Session):
        self._s = s
        self._l = s.summary.language

    def getLanguageID(self) -> LanguageID:
        return LanguageID(self._l.language_id)

    def getProcessor(self) -> Processor:
        return Processor(self._l.processor)

    def isBigEndian(self) -> bool:
        return not self._s.little

    def getDefaultSpace(self) -> AddressSpace:
        return self._s.space

    def getAddressFactory(self) -> "AddressFactory":
        return self._s.program.getAddressFactory()

    def getDefaultDataSpace(self) -> AddressSpace:
        return self._s.space

    def getVersion(self) -> int:
        return 1

    def getMinorVersion(self) -> int:
        return 0

    def getInstructionAlignment(self) -> int:
        return 1

    def getLanguageDescription(self) -> "Language":
        return self

    def getSize(self) -> int:
        return int(self._l.language_id.split(":")[2]) if self._l.language_id.count(":") >= 2 else self._s.pointer_size * 8

    def getEndian(self) -> str:
        return "big" if not self._s.little else "little"

    def getRegister(self, name: str) -> Register:
        return Register(name)

    def __str__(self):
        return self._l.language_id


class CompilerSpecID(LanguageID):
    _java_name = "CompilerSpecID"


class DataOrganization(JavaObject):
    def __init__(self, s: Session):
        self._s = s

    def getPointerSize(self) -> int:
        return self._s.pointer_size

    def getIntegerSize(self) -> int:
        return 4

    def getLongSize(self) -> int:
        return 8 if self._s.pointer_size == 8 and "windows" not in self._s.summary.language.compiler_spec_id else 4

    def isBigEndian(self) -> bool:
        return not self._s.little


class CompilerSpec(JavaObject):
    def __init__(self, s: Session):
        self._s = s

    def getCompilerSpecID(self) -> CompilerSpecID:
        return CompilerSpecID(self._s.summary.language.compiler_spec_id)

    def getLanguage(self) -> Language:
        return Language(self._s)

    def getDataOrganization(self) -> DataOrganization:
        return DataOrganization(self._s)

    def getStackPointer(self) -> Register:
        return Register({"x86": "RSP" if self._s.pointer_size == 8 else "ESP"}.get(
            self._s.summary.language.processor, "SP"))

    def __str__(self):
        return self._s.summary.language.compiler_spec_id


class AddressFactory(JavaObject):
    def __init__(self, s: Session):
        self._s = s

    def getDefaultAddressSpace(self) -> AddressSpace:
        return self._s.space

    def getAddressSpace(self, name: str) -> Optional[AddressSpace]:
        if name == self._s.space.name:
            return self._s.space
        for sp in self._s.summary.spaces:
            if sp.name == name:
                return space_named(name, self._s.space)
        return None

    def getAddressSpaces(self) -> list:
        return [self._s.space]

    def getAllAddressSpaces(self) -> list:
        return [space_named(sp.name, self._s.space) for sp in self._s.summary.spaces]

    def getAddress(self, text) -> Optional[Address]:
        if isinstance(text, int):
            return self._s.addr(text)
        t = str(text).strip()
        space = self._s.space
        if "::" in t:
            name, t = t.split("::", 1)
            raise Unsupported(f"AddressFactory.getAddress({name}::...)", "overlay spaces aren't addressable by name in scripts; use the default space's offsets")
        if ":" in t:
            name, t = t.split(":", 1)
            space = self.getAddressSpace(name) or space
        try:
            return Address(int(t, 16) if not t.lower().startswith("0x") else int(t, 16), space)
        except ValueError:
            return None

    def getConstantSpace(self) -> AddressSpace:
        return space_named("const")

    def getRegisterSpace(self) -> AddressSpace:
        return space_named("register")

    def getStackSpace(self) -> AddressSpace:
        return space_named("stack")

    def getUniqueSpace(self) -> AddressSpace:
        return space_named("unique")

    def getConstantAddress(self, offset: int) -> Address:
        return Address(offset, space_named("const"))

    def isValidAddress(self, a) -> bool:
        return isinstance(a, Address)


class GlobalNamespace(JavaObject):
    _java_name = "Namespace"

    def __init__(self, s: Session):
        self._s = s

    def getName(self, full: bool = False) -> str:
        return "Global"

    def isGlobal(self) -> bool:
        return True

    def getParentNamespace(self):
        return None

    def getID(self) -> int:
        return 0

    def isExternal(self) -> bool:
        return False

    def getBody(self) -> AddressSetView:
        return self._s.program.getMemory()

    def __str__(self):
        return "Global"

    def __eq__(self, other):
        return isinstance(other, GlobalNamespace)

    def __hash__(self):
        return 0


# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------


class FunctionManager(JavaObject):
    def __init__(self, s: Session):
        self._s = s

    def getProgram(self) -> Program:
        return self._s.program

    def getFunctionCount(self) -> int:
        return len(self._s.functions())

    def getFunctions(self, a=True, forward: Optional[bool] = None):
        """``getFunctions(forward)``, ``getFunctions(start, forward)`` or ``getFunctions(set, forward)``."""
        fs = self._s.functions()
        if isinstance(a, bool):
            return JavaIterator(list(fs) if a else list(reversed(fs)))
        fwd = True if forward is None else forward
        if isinstance(a, AddressSetView):
            sel = [f for f in fs if a.contains(f.getEntryPoint())]
        else:
            start = addr_int(a)
            sel = [f for f in fs if (f._entry >= start if fwd else f._entry <= start)]
        return JavaIterator(sel if fwd else list(reversed(sel)))

    def getFunctionsNoStubs(self, a=True, forward: Optional[bool] = None):
        return JavaIterator([f for f in self.getFunctions(a, forward) if not f.isThunk() and not f.isExternal()])

    def getExternalFunctions(self):
        return JavaIterator([])

    def getFunctionAt(self, a) -> Optional["Function"]:
        return None if a is None else self._s.function_at(addr_int(a))

    def getFunctionContaining(self, a) -> Optional["Function"]:
        return None if a is None else self._s.function_containing(addr_int(a))

    getReferencedFunction = getFunctionAt

    def isInFunction(self, a) -> bool:
        return self.getFunctionContaining(a) is not None

    def getFunctionsOverlapping(self, view):
        return JavaIterator([f for f in self._s.functions() if f.getBody().intersects(view)])

    def removeFunction(self, a) -> bool:
        a = addr_int(a)
        if self._s.function_at(a) is None:
            return False
        self._s.edit(f"remove function 0x{a:x}", assertion_pb2.AssertionBody(
            function_bounds=assertion_pb2.SetFunctionBounds(entry=address(a), remove=True)), structural=True)
        return True

    def createFunction(self, name, entry, body=None, source=None):
        from revkit.ghidra.compat import flat

        return flat.create_function(self._s, entry, name, body)

    def getDefaultCallingConvention(self):
        return None

    def __iter__(self):
        return iter(self.getFunctions(True))


class Function(JavaObject):
    """``ghidra.program.model.listing.Function`` over a revkit function."""

    _java_name = "Function"

    def __init__(self, s: Session, f: listing_pb2.Function):
        self._s = s
        self._f = f
        self._entry = f.entry.offset
        self._dec = None

    # -- identity --
    def getName(self, include_namespace: bool = False) -> str:
        return self._s.names.get(self._entry, self._f.name)

    def setName(self, name: str, source=None) -> None:
        self._s.rename(self._entry, name)

    def getEntryPoint(self) -> Address:
        return self._s.addr(self._entry)

    def getBody(self) -> AddressSet:
        return _body(self._s, self._f.body)

    def getProgram(self) -> Program:
        return self._s.program

    def getID(self) -> int:
        return self._entry

    def getSymbol(self) -> "Symbol":
        return self._s.symbol_at(self._entry) or Symbol(self._s, self._entry, self.getName(),
                                                        listing_pb2.SYMBOL_KIND_FUNCTION, self._f.name_origin)

    def getParentNamespace(self) -> GlobalNamespace:
        return GlobalNamespace(self._s)

    def isGlobal(self) -> bool:
        return True

    def getSignatureSource(self) -> SourceType:
        return source_of(self._f.prototype_origin, "x")

    # -- properties --
    def isThunk(self) -> bool:
        return self._f.thunk

    def getThunkedFunction(self, recursive: bool = False) -> Optional["Function"]:
        if not self._f.thunk or not self._f.HasField("thunk_target"):
            return None
        t = self._s.function_at(self._f.thunk_target.offset)
        while recursive and t is not None and t.isThunk() and t is not self:
            nxt = t.getThunkedFunction(False)
            if nxt is None:
                break
            t = nxt
        return t

    def isExternal(self) -> bool:
        return self._f.external

    def hasNoReturn(self) -> bool:
        return self._f.no_return

    def isInline(self) -> bool:
        return False

    def hasVarArgs(self) -> bool:
        return self._decompiled().prototype.varargs if self._decompiled() else "..." in self._f.prototype

    def getCallingConventionName(self) -> str:
        return self._f.calling_convention or "unknown"

    def getCallingConvention(self):
        return None

    def getCallFixup(self):
        return None

    def getPrototypeString(self, formal: bool = False, include_cc: bool = False) -> str:
        p = self._f.prototype or (self._decompiled().prototype.c_declaration if self._decompiled() else "")
        if p and self.getName() != self._f.name:
            p = p.replace(self._f.name + "(", self.getName() + "(", 1)
        return p

    def getSignature(self, formal: bool = False) -> "FunctionSignature":
        return FunctionSignature(self)

    def getReturnType(self) -> DataType:
        d = self._decompiled()
        return type_named(self._s, d.prototype.return_type.display if d else "undefined")

    # -- comments --
    def getComment(self) -> Optional[str]:
        return self._s.comment_at(self._entry, "plate")

    def getCommentAsArray(self) -> list:
        c = self.getComment()
        return c.split("\n") if c else []

    def setComment(self, text: Optional[str]) -> None:
        self._s.set_comment(self._entry, "plate", text)

    def getRepeatableComment(self) -> Optional[str]:
        return self._s.comment_at(self._entry, "repeatable")

    def setRepeatableComment(self, text: Optional[str]) -> None:
        self._s.set_comment(self._entry, "repeatable", text)

    # -- calls --
    def getCallingFunctions(self, monitor=None) -> set:
        out = set()
        for x in self._s.prog.xrefs_to(self._entry):
            if x.kind in (listing_pb2.XREF_KIND_CALL, listing_pb2.XREF_KIND_JUMP, listing_pb2.XREF_KIND_CONDITIONAL_JUMP,
                          listing_pb2.XREF_KIND_THUNK, listing_pb2.XREF_KIND_INDIRECT_CALL):
                f = self._s.function_containing(x.from_address.offset)
                if f is not None and (x.kind != listing_pb2.XREF_KIND_JUMP or f is not self):
                    out.add(f)
        return out

    def getCalledFunctions(self, monitor=None) -> set:
        out = set()
        self._s.sync()
        for r in self._f.body:
            for x in self._s.prog.xrefs(range=(r.first.offset, r.last.offset), direction="from"):
                if x.kind in (listing_pb2.XREF_KIND_CALL, listing_pb2.XREF_KIND_THUNK, listing_pb2.XREF_KIND_INDIRECT_CALL,
                              listing_pb2.XREF_KIND_JUMP):
                    f = self._s.function_at(x.to_address.offset)
                    if f is not None and f is not self:
                        out.add(f)
        return out

    # -- variables (from the decompiler) --
    def _decompiled(self):
        if self._dec is None:
            try:
                self._dec = self._s.prog.decompile(self._entry, text=False)
            except RevkitError:
                self._dec = False
        return self._dec or None

    def _vars(self, kind) -> list:
        d = self._decompiled()
        if not d:
            return []
        vs = [Variable(self, v) for v in d.variables if v.kind == kind]
        if kind == 1:  # parameters, in order
            vs.sort(key=lambda v: v._v.parameter_index)
        return vs

    def getParameters(self) -> list:
        return [Parameter(self, v._v) for v in self._vars(1)]

    def getParameterCount(self) -> int:
        return len(self._vars(1))

    def getParameter(self, i: int):
        ps = self.getParameters()
        return ps[i] if 0 <= i < len(ps) else None

    def getLocalVariables(self, filter=None) -> list:
        return self._vars(2)

    def getAllVariables(self) -> list:
        return self.getParameters() + self._vars(2)

    def getVariables(self, filter=None) -> list:
        return self.getAllVariables()

    def getReturn(self):
        return None

    def getStackPurgeSize(self) -> int:
        return 0

    def __str__(self):
        return self.getName()

    def __repr__(self):
        return f"Function({self.getName()} @ {self.getEntryPoint()})"

    def __eq__(self, other):
        return isinstance(other, Function) and other._entry == self._entry

    def __hash__(self):
        return hash(self._entry)

    def __lt__(self, other):
        return self._entry < other._entry


def _body(s: Session, ranges) -> AddressSet:
    out = AddressSet(space=s.space)
    for r in ranges:
        out.add(s.addr(r.first.offset), s.addr(r.last.offset))
    return out


class FunctionSignature(JavaObject):
    def __init__(self, f: Function):
        self._fn = f

    def getName(self) -> str:
        return self._fn.getName()

    def getPrototypeString(self, include_cc: bool = False) -> str:
        return self._fn.getPrototypeString()

    def getReturnType(self) -> DataType:
        return self._fn.getReturnType()

    def getArguments(self) -> list:
        return self._fn.getParameters()

    def hasVarArgs(self) -> bool:
        return self._fn.hasVarArgs()

    def getCallingConventionName(self) -> str:
        return self._fn.getCallingConventionName()

    def __str__(self):
        return self.getPrototypeString()


def type_named(s: Session, display: str) -> DataType:
    display = (display or "undefined").strip()
    if display.endswith("*"):
        return pointer_to(type_named(s, display[:-1].strip()), s.pointer_size)
    builtin = DataType.builtin(display) or next((t for t in DataType._builtin.values() if t.c == display), None)
    if builtin is not None:
        return builtin
    return DataType(display, display, -1)


class VariableStorage(JavaObject):
    def __init__(self, varnodes):
        self._vns = list(varnodes)

    def getVarnodes(self) -> list:
        from revkit.ghidra.compat.decompiler import Varnode

        return [Varnode(v) for v in self._vns]

    def getFirstVarnode(self):
        vs = self.getVarnodes()
        return vs[0] if vs else None

    def isStackStorage(self) -> bool:
        return bool(self._vns) and self._vns[0].space == "stack"

    def isRegisterStorage(self) -> bool:
        return bool(self._vns) and self._vns[0].space == "register"

    def isMemoryStorage(self) -> bool:
        return bool(self._vns) and self._vns[0].space == "ram"

    def isUniqueStorage(self) -> bool:
        return bool(self._vns) and self._vns[0].space == "unique"

    def getRegister(self) -> Optional[Register]:
        if self.isRegisterStorage():
            v = self._vns[0]
            return Register(v.register_name or f"reg_{v.offset:x}", v.size, v.offset)
        return None

    def getStackOffset(self) -> int:
        v = self._vns[0]
        return v.offset - (1 << 64) if v.offset >= 1 << 63 else v.offset

    def size(self) -> int:
        return sum(v.size for v in self._vns)

    def getMinAddress(self) -> Optional[Address]:
        if not self._vns:
            return None
        v = self._vns[0]
        return Address(v.offset, space_named(v.space))

    def __str__(self):
        parts = []
        for v in self._vns:
            if v.space == "register":
                parts.append(f"{v.register_name or hex(v.offset)}:{v.size}")
            elif v.space == "stack":
                o = v.offset - (1 << 64) if v.offset >= 1 << 63 else v.offset
                parts.append(f"Stack[{'-' if o < 0 else ''}0x{abs(o):x}]:{v.size}")
            else:
                parts.append(f"{v.space}:{v.offset:x}:{v.size}")
        return ",".join(parts) or "<UNASSIGNED>"


class Variable(JavaObject):
    """A function's local variable or parameter, as the decompiler sees it."""

    _java_name = "Variable"

    def __init__(self, fn: Function, v):
        self._fn = fn
        self._v = v

    def getName(self) -> str:
        return self._fn._s.local_names.get((self._fn._entry, self._v.storage_key), self._v.name)

    def setName(self, name: str, source=None) -> None:
        self._fn._s.rename_local(self._fn._entry, self._v.storage_key, name)

    def getDataType(self) -> DataType:
        return type_named(self._fn._s, self._v.type.display)

    def setDataType(self, dt, *rest) -> None:
        self._fn._s.retype_local(self._fn._entry, self._v.storage_key, dt.c if isinstance(dt, DataType) else str(dt))

    def getLength(self) -> int:
        return sum(v.size for v in self._v.storage)

    def getStorage(self) -> VariableStorage:
        return VariableStorage(self._v.storage)

    def getFirstStorageVarnode(self):
        return self.getStorage().getFirstVarnode()

    def getVariableStorage(self) -> VariableStorage:
        return self.getStorage()

    def isStackVariable(self) -> bool:
        return self.getStorage().isStackStorage()

    def isRegisterVariable(self) -> bool:
        return self.getStorage().isRegisterStorage()

    def isMemoryVariable(self) -> bool:
        return self.getStorage().isMemoryStorage()

    def isUniqueVariable(self) -> bool:
        return self.getStorage().isUniqueStorage()

    def hasStackStorage(self) -> bool:
        return self.isStackVariable()

    def getStackOffset(self) -> int:
        if not self.isStackVariable():
            raise Unsupported("Variable.getStackOffset (not a stack variable)", "check isStackVariable() first")
        return self.getStorage().getStackOffset()

    def getRegister(self) -> Optional[Register]:
        return self.getStorage().getRegister()

    def getMinAddress(self) -> Optional[Address]:
        return self.getStorage().getMinAddress()

    def getFunction(self) -> Function:
        return self._fn

    def getProgram(self) -> Program:
        return self._fn._s.program

    def getSource(self) -> SourceType:
        o = self._v.name_origin
        return SourceType.DEFAULT if o.WhichOneof("source") != "asserted" else source_of(o, self.getName())

    def getComment(self) -> Optional[str]:
        return None

    def getSymbol(self):
        return None

    def getFirstUseOffset(self) -> int:
        return 0

    def isValid(self) -> bool:
        return True

    def getStorageKey(self) -> str:
        """revkit's storage key (rename_local / retype_local take it)."""
        return self._v.storage_key

    def __str__(self):
        return f"[{self.getDataType()} {self.getName()}@{self.getStorage()}]"

    def __eq__(self, other):
        return isinstance(other, Variable) and (other._fn, other._v.storage_key) == (self._fn, self._v.storage_key)

    def __hash__(self):
        return hash((self._fn._entry, self._v.storage_key))


class Parameter(Variable):
    _java_name = "Parameter"

    def getOrdinal(self) -> int:
        return self._v.parameter_index

    def isAutoParameter(self) -> bool:
        return False

    def getFormalDataType(self) -> DataType:
        return self.getDataType()


# ---------------------------------------------------------------------------
# Symbols
# ---------------------------------------------------------------------------


class SymbolTable(JavaObject):
    def __init__(self, s: Session):
        self._s = s

    def _all(self, include_dynamic: bool = True, primary_only: bool = False):
        return [x for x in self._s.symbols() if include_dynamic or not x.isDynamic()]

    def getNumSymbols(self) -> int:
        return len(self._s.symbols())

    def getSymbolAt(self, a, name: Optional[str] = None):
        return self.getPrimarySymbol(a) if name is None else next(
            (x for x in self.getSymbols(a) if x.getName() == name), None)

    def getPrimarySymbol(self, a) -> Optional["Symbol"]:
        return None if a is None else self._s.symbol_at(addr_int(a))

    def getSymbols(self, a, *rest):
        """``getSymbols(addr)`` (array), ``getSymbols(name)`` / ``getSymbols(name, ns)``
        (iterator), ``getSymbols(set, type, forward)``."""
        if isinstance(a, str):
            return JavaIterator(self._by_name(a))
        if isinstance(a, AddressSetView):
            kind = rest[0] if rest else None
            forward = rest[1] if len(rest) > 1 else True
            sel = [x for x in self._all(False) if a.contains(x.getAddress()) and (kind is None or x.getSymbolType() == kind)]
            return JavaIterator(sel if forward else list(reversed(sel)))
        if isinstance(a, GlobalNamespace):
            return JavaIterator(self._all(False))
        s = self.getPrimarySymbol(a)
        return [s] if s else []

    def getSymbolsAsIterator(self, a):
        return JavaIterator(self.getSymbols(a))

    def _by_name(self, name: str) -> list:
        if self._s.names:
            self._s.commit()
        return [x for x in self._s.symbols() if x.getName() == name]

    def getGlobalSymbols(self, name: str) -> list:
        return self._by_name(name)

    def getLabelOrFunctionSymbols(self, name: str, ns=None) -> list:
        return self._by_name(name)

    def getGlobalSymbol(self, name: str, a) -> Optional["Symbol"]:
        return next((x for x in self._by_name(name) if x._a == addr_int(a)), None)

    def getSymbol(self, name, a=None, ns=None):
        if isinstance(name, Reference):
            return self.getPrimarySymbol(name.getToAddress())
        if isinstance(name, str):
            matches = [x for x in self._by_name(name) if a is None or x._a == addr_int(a)]
            return matches[0] if matches else None
        raise Unsupported("SymbolTable.getSymbol(id)", "symbols have no ids in revkit; getSymbolAt(addr) or getSymbols(name)")

    def getAllSymbols(self, include_dynamic: bool = True):
        return JavaIterator(self._all(include_dynamic))

    def getSymbolIterator(self, a=True, forward: Optional[bool] = None):
        syms = self._all(False)
        if isinstance(a, bool):
            return JavaIterator(syms if a else list(reversed(syms)))
        if isinstance(a, str):
            pat = re.compile(".*".join(map(re.escape, a.split("*"))) + "$", 0 if forward in (None, True) else re.I)
            return JavaIterator([x for x in syms if pat.match(x.getName())])
        start, fwd = addr_int(a), (True if forward is None else forward)
        sel = [x for x in syms if (x._a >= start if fwd else x._a <= start)]
        return JavaIterator(sel if fwd else list(reversed(sel)))

    def getDefinedSymbols(self):
        return JavaIterator(self._all(False))

    def getPrimarySymbolIterator(self, a=True, forward: Optional[bool] = None):
        if isinstance(a, AddressSetView):
            sel = [x for x in self._all(False) if a.contains(x.getAddress())]
            return JavaIterator(sel if forward in (None, True) else list(reversed(sel)))
        return self.getSymbolIterator(a, forward)

    def getExternalSymbols(self, name: Optional[str] = None):
        return JavaIterator([])

    def getExternalEntryPointIterator(self):
        return JavaIterator(sorted({self._s.addr(e.address.offset) for e in self._s.summary.entry_points},
                                   key=lambda x: x.offset))

    def isExternalEntryPoint(self, a) -> bool:
        return any(e.address.offset == addr_int(a) for e in self._s.summary.entry_points)

    def hasSymbol(self, a) -> bool:
        return self.getPrimarySymbol(a) is not None

    def createLabel(self, a, name: str, *rest) -> "Symbol":
        o = addr_int(a)
        self._s.rename(o, name)
        f = self._s.function_at(o)
        return Symbol(self._s, o, name, listing_pb2.SYMBOL_KIND_FUNCTION if f else listing_pb2.SYMBOL_KIND_LABEL, None)

    def getNamespace(self, *a):
        return GlobalNamespace(self._s)


class Symbol(JavaObject):
    """A function or label name at an address (revkit has one per address)."""

    _java_name = "Symbol"

    def __init__(self, s: Session, a: int, name: str, kind: int, origin):
        self._s = s
        self._a = a
        self._name = name
        self._kind = kind
        self._origin = origin

    def getName(self, include_namespace: bool = False) -> str:
        return self._s.names.get(self._a, self._name)

    def setName(self, name: str, source=None) -> None:
        self._s.rename(self._a, name)

    def getAddress(self) -> Address:
        return self._s.addr(self._a)

    def getSource(self) -> SourceType:
        if self._a in self._s.names:
            return SourceType.ANALYSIS
        if self._origin is None:
            return SourceType.ANALYSIS
        if self._kind == listing_pb2.SYMBOL_KIND_FUNCTION and self._origin.WhichOneof("source") == "derived":
            f = self._s.function_at(self._a)
            if f is not None and f.isThunk():
                return SourceType.DEFAULT  # a thunk is named after its target (Ghidra: a dynamic name)
        return source_of(self._origin, self._name)

    def isDynamic(self) -> bool:
        """A made-up label (LAB_..., s_..._addr): Ghidra's iterators skip these."""
        return (self._kind == listing_pb2.SYMBOL_KIND_LABEL and self._origin is not None
                and self._origin.WhichOneof("source") == "derived"
                and source_of(self._origin, self._name) == SourceType.DEFAULT)

    def getSymbolType(self) -> SymbolType:
        return SymbolType.FUNCTION if self._kind == listing_pb2.SYMBOL_KIND_FUNCTION else SymbolType.LABEL

    def getObject(self):
        if self._kind == listing_pb2.SYMBOL_KIND_FUNCTION:
            return self._s.function_at(self._a)
        return self._s.code_unit_at(self._a)

    def isPrimary(self) -> bool:
        return True

    def setPrimary(self) -> bool:
        return True

    def isExternal(self) -> bool:
        return False

    def isExternalEntryPoint(self) -> bool:
        return any(e.address.offset == self._a for e in self._s.summary.entry_points)

    def isGlobal(self) -> bool:
        return True

    def isPinned(self) -> bool:
        return False

    def isDeleted(self) -> bool:
        return False

    def getID(self) -> int:
        return self._a

    def getProgram(self) -> Program:
        return self._s.program

    def getParentNamespace(self) -> GlobalNamespace:
        return GlobalNamespace(self._s)

    def getParentSymbol(self):
        return None

    def getPath(self) -> list:
        return [self.getName()]

    def getReferences(self, monitor=None) -> list:
        return [Reference(self._s, x) for x in self._s.prog.xrefs_to(self._a)]

    def getReferenceCount(self) -> int:
        return len(self.getReferences())

    def hasReferences(self) -> bool:
        return self.getReferenceCount() > 0

    def hasMultipleReferences(self) -> bool:
        return self.getReferenceCount() > 1

    def __str__(self):
        return self.getName()

    def __repr__(self):
        return f"Symbol({self.getName()} @ {self.getAddress()})"

    def __eq__(self, other):
        return isinstance(other, Symbol) and other._a == self._a and other.getName() == self.getName()

    def __hash__(self):
        return hash(self._a)


# ---------------------------------------------------------------------------
# Listing and code units
# ---------------------------------------------------------------------------


def _range_args(s: Session, a, forward):
    """(lo, hi, forward) from Ghidra's (forward) / (start, forward) / (set, forward)."""
    if isinstance(a, bool) or a is None:
        return [(0, (1 << 64) - 1)], (True if a is None else a)
    fwd = True if forward is None else forward
    if isinstance(a, AddressSetView):
        return list(a._r), fwd
    start = addr_int(a)
    return ([(start, (1 << 64) - 1)] if fwd else [(0, start)]), fwd


class Listing(JavaObject):
    def __init__(self, s: Session):
        self._s = s

    # -- instructions --
    def getInstructionAt(self, a) -> Optional["Instruction"]:
        return None if a is None else self._s.insn_at(addr_int(a))

    def getInstructionContaining(self, a) -> Optional["Instruction"]:
        return None if a is None else self._s.insn_containing(addr_int(a))

    def getInstructionAfter(self, a) -> Optional["Instruction"]:
        return self._s.insn_after(addr_int(a))

    def getInstructionBefore(self, a) -> Optional["Instruction"]:
        return self._s.insn_before(addr_int(a))

    def getInstructions(self, a=True, forward: Optional[bool] = None):
        if isinstance(a, (Function,)):
            a = a.getBody()
        ranges, fwd = _range_args(self._s, a, forward)

        def gen():
            for lo, hi in (ranges if fwd else reversed(ranges)):
                yield from self._s.insns(lo, hi, fwd)

        return JavaIterator(gen())

    def getNumInstructions(self) -> int:
        return sum(1 for _ in self._s.insns())

    # -- data --
    def getDataAt(self, a):
        if a is None:
            return None
        o = addr_int(a)
        if self._s.insn_containing(o) is not None:
            return None
        return self._s.data_at(o) or self._s._undefined_at(o)

    def getDefinedDataAt(self, a):
        return None if a is None else self._s.data_at(addr_int(a))

    def getDataContaining(self, a):
        if a is None:
            return None
        o = addr_int(a)
        if self._s.insn_containing(o) is not None:
            return None
        return self._s.data_containing(o) or self._s._undefined_at(o)

    def getDefinedDataContaining(self, a):
        return None if a is None else self._s.data_containing(addr_int(a))

    def getDataAfter(self, a):
        for d in self._s.defined_data(addr_int(a) + 1):
            return d
        return None

    getDefinedDataAfter = getDataAfter

    def getDataBefore(self, a):
        o = addr_int(a)
        if o == 0:
            return None
        for d in self._s.defined_data(0, o - 1, forward=False):
            return d
        return None

    getDefinedDataBefore = getDataBefore

    def getDefinedData(self, a=True, forward: Optional[bool] = None):
        ranges, fwd = _range_args(self._s, a, forward)

        def gen():
            for lo, hi in (ranges if fwd else reversed(ranges)):
                yield from self._s.defined_data(lo, hi, fwd)

        return JavaIterator(gen())

    def getData(self, a=True, forward: Optional[bool] = None):
        """Defined data and undefined bytes (Ghidra's ``getData``)."""
        ranges, fwd = _range_args(self._s, a, forward)

        def gen():
            for lo, hi in (ranges if fwd else reversed(ranges)):
                yield from self._s.code_units(lo, hi, fwd, kinds=("data", "undef"))

        return JavaIterator(gen())

    def getUndefinedDataAt(self, a):
        return self._s._undefined_at(addr_int(a))

    def getNumDefinedData(self) -> int:
        return len(self._s.data()[0])

    # -- code units --
    def getCodeUnitAt(self, a):
        return None if a is None else self._s.code_unit_at(addr_int(a))

    def getCodeUnitContaining(self, a):
        return None if a is None else self._s.code_unit_containing(addr_int(a))

    def getCodeUnitAfter(self, a):
        o = addr_int(a)
        cu = self._s.code_unit_containing(o)
        nxt = o + 1 if cu is None else cu._a + cu.getLength()
        for u in self._s.code_units(nxt):
            return u
        return None

    def getCodeUnitBefore(self, a):
        o = addr_int(a)
        if o == 0:
            return None
        for u in self._s.code_units(0, o - 1, forward=False):
            return u
        return None

    def getCodeUnits(self, a=True, forward: Optional[bool] = None):
        ranges, fwd = _range_args(self._s, a, forward)

        def gen():
            for lo, hi in (ranges if fwd else reversed(ranges)):
                yield from self._s.code_units(lo, hi, fwd)

        return JavaIterator(gen())

    # -- functions --
    def getFunctions(self, a=True, forward: Optional[bool] = None):
        return self._s.program.getFunctionManager().getFunctions(a, forward)

    def getFunctionAt(self, a):
        return self._s.program.getFunctionManager().getFunctionAt(a)

    def getFunctionContaining(self, a):
        return self._s.program.getFunctionManager().getFunctionContaining(a)

    def getGlobalFunctions(self, name: str) -> list:
        return [f for f in self._s.functions() if f.getName() == name]

    # -- comments --
    def getComment(self, kind, a) -> Optional[str]:
        return self._s.comment_at(addr_int(a), comment_kind(kind))

    def setComment(self, a, kind, text) -> None:
        self._s.set_comment(addr_int(a), comment_kind(kind), text)

    def getCommentAddressIterator(self, *args):
        """``(type, set, forward)`` or ``(set, forward)``."""
        if len(args) == 3:
            kind, view, forward = comment_kind(args[0]), args[1], args[2]
        else:
            kind, view, forward = None, args[0], args[1] if len(args) > 1 else True
        out = []
        for lo, hi in view._r:
            out.extend(self._s.comment_addresses(lo, hi, kind))
        addrs = [self._s.addr(o) for o in sorted(set(out))]
        return JavaIterator(addrs if forward else list(reversed(addrs)))

    # -- edits --
    def clearCodeUnits(self, start, end, clear_context: bool = False, monitor=None) -> None:
        lo, hi = addr_int(start), addr_int(end)
        self._s.edit(f"clear 0x{lo:x}..0x{hi + 1:x}", clear_code_body(lo, hi - lo + 1), structural=True)

    def clearAll(self, *a):
        raise Unsupported("Listing.clearAll", "clearListing(start, end) over the ranges to clear")

    def createData(self, a, dt, length: int = -1):
        from revkit.ghidra.compat import flat

        return flat.create_data(self._s, a, dt, length)

    def createInstruction(self, *a):
        raise Unsupported("Listing.createInstruction", "disassemble(addr)")


class CodeUnit(JavaObject):
    """What instructions and data share: address, bytes, comments, labels."""

    _java_name = "CodeUnit"
    EOL_COMMENT = 0
    PRE_COMMENT = 1
    POST_COMMENT = 2
    PLATE_COMMENT = 3
    REPEATABLE_COMMENT = 4
    MNEMONIC = -1

    _s: Session
    _a: int

    def getAddress(self, op_index: Optional[int] = None) -> Optional[Address]:
        if op_index is None:
            return self._s.addr(self._a)
        return self._operand_address(op_index)

    def _operand_address(self, i):
        return None

    def getMinAddress(self) -> Address:
        return self._s.addr(self._a)

    def getMaxAddress(self) -> Address:
        return self._s.addr(self._a + max(1, self.getLength()) - 1)

    def getLength(self) -> int:
        raise NotImplementedError

    def getBytes(self) -> ByteArray:
        return ByteArray.of(self._s.read(self._a, self.getLength()))

    def getByte(self, i: int) -> int:
        return self.getBytes()[i]

    def getProgram(self) -> Program:
        return self._s.program

    def getComment(self, kind) -> Optional[str]:
        return self._s.comment_at(self._a, comment_kind(kind))

    def getCommentAsArray(self, kind) -> list:
        c = self.getComment(kind)
        return c.split("\n") if c else []

    def setComment(self, kind, text) -> None:
        self._s.set_comment(self._a, comment_kind(kind), text)

    def setCommentAsArray(self, kind, lines) -> None:
        self.setComment(kind, "\n".join(lines) if lines else None)

    def getLabel(self) -> Optional[str]:
        s = self._s.symbol_at(self._a)
        return s.getName() if s else None

    def getPrimarySymbol(self):
        return self._s.symbol_at(self._a)

    def getSymbols(self) -> list:
        s = self._s.symbol_at(self._a)
        return [s] if s else []

    def contains(self, a) -> bool:
        return self._a <= addr_int(a) < self._a + max(1, self.getLength())

    def getReferencesFrom(self) -> list:
        return list(self._s.xrefs_from(self._a))

    def getReferenceIteratorTo(self):
        return JavaIterator(Reference(self._s, x) for x in self._s.prog.xrefs_to(self._a))

    def getOperandReferences(self, i: int) -> list:
        return [r for r in self._s.xrefs_from(self._a) if r.getOperandIndex() == i]

    def getNumOperands(self) -> int:
        return 0

    def compareTo(self, other) -> int:
        return (self._a > other._a) - (self._a < other._a)

    def __eq__(self, other):
        return isinstance(other, CodeUnit) and type(other) is type(self) and other._a == self._a

    def __hash__(self):
        return hash((type(self).__name__, self._a))


_FLOW = {
    listing_pb2.FLOW_KIND_FALL_THROUGH: RefType.FALL_THROUGH,
    listing_pb2.FLOW_KIND_UNCONDITIONAL_BRANCH: RefType.UNCONDITIONAL_JUMP,
    listing_pb2.FLOW_KIND_CONDITIONAL_BRANCH: RefType.CONDITIONAL_JUMP,
    listing_pb2.FLOW_KIND_CALL: RefType.UNCONDITIONAL_CALL,
    listing_pb2.FLOW_KIND_RETURN: RefType.TERMINATOR,
    listing_pb2.FLOW_KIND_INDIRECT_BRANCH: RefType.COMPUTED_JUMP,
    listing_pb2.FLOW_KIND_INDIRECT_CALL: RefType.COMPUTED_CALL,
    listing_pb2.FLOW_KIND_TERMINATOR: RefType.TERMINATOR,
}


class Instruction(CodeUnit):
    _java_name = "Instruction"

    def __init__(self, s: Session, d: listing_pb2.InstructionDetail):
        self._s = s
        self._d = d
        self._a = d.address.offset
        self._pcode = None

    def getLength(self) -> int:
        return self._d.length

    def getMnemonicString(self) -> str:
        return self._d.mnemonic

    def getNumOperands(self) -> int:
        return len(self._d.operands)

    def _op(self, i: int):
        if not 0 <= i < len(self._d.operands):
            return None
        return self._d.operands[i]

    def _operand_items(self, i: int) -> list:
        """(token, text, object) per token of operand ``i``, as Ghidra shows
        and lists them: a scalar is a Scalar ("0xc", LEA's "[0x101295]"),
        an address operand an Address (a branch target "0x00101016", a
        memory operand's "qword ptr [0x00103fb0]"). With the daemon's
        "token-scalars" (api_minor 34) a token that SLEIGH printed as a
        scalar keeps its value and width even when shown as a symbol;
        before that, a symbol inside brackets without "ptr" is taken as
        LEA's scalar."""
        op = self._op(i)
        if op is None:
            return []
        exact = self._s.token_scalars
        text = "".join(t.text for t in op.tokens)
        sized = " ptr" in text
        depth = 0
        out = []
        for t in op.tokens:
            obj = None
            shown = t.text
            if t.kind == listing_pb2.LISTING_TOKEN_KIND_SEPARATOR:
                depth += t.text.count("[") - t.text.count("]")
            elif t.kind == listing_pb2.LISTING_TOKEN_KIND_REGISTER:
                vn = t.register_varnode
                obj = Register(t.text, vn.size, vn.offset if vn.space else None)
            elif t.kind == listing_pb2.LISTING_TOKEN_KIND_SCALAR:
                v = t.value if t.HasField("value") else _parse_int(t.text)
                obj = Scalar(t.scalar_bits or 64, v, v < 0)
                if t.HasField("display_origin"):
                    shown = str(obj)  # the default representation, without the equate or conversion
            elif t.kind in (listing_pb2.LISTING_TOKEN_KIND_ADDRESS, listing_pb2.LISTING_TOKEN_KIND_SYMBOL):
                target = t.target.offset if t.HasField("target") else None
                if exact:
                    if t.HasField("value"):
                        obj = Scalar(t.scalar_bits or 64, t.value, t.value < 0)
                        shown = str(obj)
                    elif target is not None:
                        obj = self._s.addr(target)
                        shown = "0x" + str(obj)
                else:
                    if target is None and t.HasField("value"):
                        target = t.value
                    if target is not None:
                        branch = self._d.flow in (listing_pb2.FLOW_KIND_CALL, listing_pb2.FLOW_KIND_UNCONDITIONAL_BRANCH,
                                                  listing_pb2.FLOW_KIND_CONDITIONAL_BRANCH)
                        if (depth > 0 and not sized) or (depth == 0 and not branch):
                            obj = Scalar(64, target, False)
                            shown = f"0x{target:x}"
                        else:
                            obj = self._s.addr(target)
                            shown = "0x" + str(obj)
            out.append((t, shown, obj))
        return out

    def getDefaultOperandRepresentation(self, i: int) -> str:
        op = self._op(i)
        return "<UNSUPPORTED>" if op is None else "".join(shown for _, shown, _ in self._operand_items(i))

    def getDefaultOperandRepresentationList(self, i: int) -> list:
        return [x for x in self.getOpObjects(i)]

    def getOpObjects(self, i: int) -> list:
        """Registers, scalars and addresses in operand ``i``, as Ghidra lists them."""
        return [obj for _, _, obj in self._operand_items(i) if obj is not None]

    def getInputObjects(self) -> list:
        """The registers and scalars the instruction reads (from its p-code)."""
        out = []
        for op in self.getPcode():
            for v in op.getInputs():
                if v.isRegister() and v.getRegisterName():
                    r = Register(v.getRegisterName(), v.getSize(), v._v.offset)
                    if r not in out:
                        out.append(r)
        return out

    def getResultObjects(self) -> list:
        """The registers the instruction writes (from its p-code)."""
        out = []
        for op in self.getPcode():
            v = op.getOutput()
            if v is not None and v.isRegister() and v.getRegisterName():
                r = Register(v.getRegisterName(), v.getSize(), v._v.offset)
                if r not in out:
                    out.append(r)
        return out

    def getOperandType(self, i: int) -> int:
        from revkit.ghidra.compat.model import OperandType as T

        op = self._op(i)
        if op is None:
            return 0
        kinds = {t.kind for t in op.tokens}
        text = "".join(t.text for t in op.tokens)
        bits = 0
        if "[" in text:
            bits |= T.DYNAMIC
        if listing_pb2.LISTING_TOKEN_KIND_REGISTER in kinds:
            bits |= T.REGISTER
        if listing_pb2.LISTING_TOKEN_KIND_SCALAR in kinds:
            bits |= T.SCALAR
        if kinds & {listing_pb2.LISTING_TOKEN_KIND_ADDRESS, listing_pb2.LISTING_TOKEN_KIND_SYMBOL}:
            bits |= T.ADDRESS
            bits |= T.CODE if self._d.flow in (listing_pb2.FLOW_KIND_CALL, listing_pb2.FLOW_KIND_UNCONDITIONAL_BRANCH,
                                               listing_pb2.FLOW_KIND_CONDITIONAL_BRANCH) else T.DATA
        return bits

    def getRegister(self, i: int) -> Optional[Register]:
        objs = self.getOpObjects(i)
        return objs[0] if len(objs) == 1 and isinstance(objs[0], Register) else None

    def getScalar(self, i: int) -> Optional[Scalar]:
        objs = self.getOpObjects(i)
        return objs[0] if len(objs) == 1 and isinstance(objs[0], Scalar) else None

    def _operand_address(self, i):
        for o in self.getOpObjects(i):
            if isinstance(o, Address):
                return o
        op = self._op(i)
        if op is not None and op.references:
            return self._s.addr(op.references[0].offset)
        return None

    def getFlowType(self) -> RefType:
        if self._d.flow == listing_pb2.FLOW_KIND_INDIRECT_BRANCH:
            f = self._s.function_containing(self._a)
            if f is not None and f.isThunk():
                return RefType.COMPUTED_CALL_TERMINATOR  # a thunk's jump is a tail call, as Ghidra marks it
        return _FLOW.get(self._d.flow, RefType.FALL_THROUGH)

    def getFlows(self) -> list:
        return [self._s.addr(a.offset) for a in self._d.flow_targets]

    def getFallThrough(self) -> Optional[Address]:
        if self._d.HasField("fall_through") and self._d.flow in (
                listing_pb2.FLOW_KIND_FALL_THROUGH, listing_pb2.FLOW_KIND_CONDITIONAL_BRANCH, listing_pb2.FLOW_KIND_CALL,
                listing_pb2.FLOW_KIND_INDIRECT_CALL, listing_pb2.FLOW_KIND_UNSPECIFIED):
            return self._s.addr(self._d.fall_through.offset)
        return None

    def getDefaultFallThrough(self) -> Optional[Address]:
        return self._s.addr(self._a + self._d.length)

    def getFallThroughOffset(self) -> int:
        return self._d.length

    def hasFallthrough(self) -> bool:
        return self.getFallThrough() is not None

    def isFallthrough(self) -> bool:
        return self._d.flow == listing_pb2.FLOW_KIND_FALL_THROUGH

    def getFallFrom(self) -> Optional[Address]:
        prev = self._s.insn_before(self._a)
        if prev is not None and prev._a + prev._d.length == self._a and prev.getFallThrough() == self.getAddress():
            return prev.getAddress()
        return None

    def getNext(self) -> Optional["Instruction"]:
        return self._s.insn_after(self._a)

    def getPrevious(self) -> Optional["Instruction"]:
        return self._s.insn_before(self._a)

    def getDelaySlotDepth(self) -> int:
        return 0

    def isInDelaySlot(self) -> bool:
        return False

    def getPcode(self, include_overrides: bool = True) -> list:
        from revkit.ghidra.compat.decompiler import PcodeOp

        if self._pcode is None:
            d = self._s.prog.instruction(self._a)
            self._pcode = [PcodeOp(self._s, op, self._a, i) for i, op in enumerate(d.pcode)]
        return list(self._pcode)

    def getPcodeOps(self) -> list:
        return self.getPcode()

    def getFlowOverride(self):
        return None

    def isLengthOverridden(self) -> bool:
        return False

    def getParsedLength(self) -> int:
        return self._d.length

    def getRepresentation(self) -> str:
        return str(self)

    def __str__(self):
        ops = [self.getDefaultOperandRepresentation(i) for i in range(self.getNumOperands())]
        return self._d.mnemonic + (" " + ",".join(ops) if ops else "")

    def __repr__(self):
        return f"Instruction({self.getAddress()}: {self})"


def _parse_int(text: str) -> int:
    t = text.strip().lower()
    neg = t.startswith("-")
    t = t.lstrip("-")
    try:
        v = int(t[:-1], 16) if t.endswith("h") else int(t, 0)
    except ValueError:
        v = 0
    return -v if neg else v


_MNEMONIC_OF = {"string": "ds", "TerminatedCString": "ds", "unicode": "unicode", "pointer": "addr"}


class Data(CodeUnit):
    """Defined data (``ListData``)."""

    _java_name = "Data"

    def __init__(self, s: Session, d: query_pb2.DefinedData):
        self._s = s
        self._d = d
        self._a = d.address.offset
        self._repr = None

    def getLength(self) -> int:
        return max(1, self._d.length)

    def isDefined(self) -> bool:
        return True

    def getDataType(self) -> DataType:
        name = self._d.data_type
        if self._d.category == query_pb2.DATA_CATEGORY_STRING:
            return DataType.builtin("string") if "16" not in name else DataType.builtin("unicode")
        if self._d.category == query_pb2.DATA_CATEGORY_POINTER:
            return pointer_to(None, self._s.pointer_size)
        return type_named(self._s, name)

    def getBaseDataType(self) -> DataType:
        return self.getDataType()

    def getMnemonicString(self) -> str:
        dt = self.getDataType()
        return dt.getMnemonic() if dt.name in DataType._builtin else self._d.data_type

    def isPointer(self) -> bool:
        return self._d.category == query_pb2.DATA_CATEGORY_POINTER

    def hasStringValue(self) -> bool:
        return self._d.category == query_pb2.DATA_CATEGORY_STRING

    def isConstant(self) -> bool:
        return False

    def isVolatile(self) -> bool:
        return False

    def isArray(self) -> bool:
        return "[" in self._d.data_type

    def isStructure(self) -> bool:
        return self._d.data_type.startswith("struct ")

    def isUnion(self) -> bool:
        return self._d.data_type.startswith("union ")

    def getNumComponents(self) -> int:
        return 0

    def getParent(self):
        return None

    def getValue(self):
        cat = self._d.category
        if cat == query_pb2.DATA_CATEGORY_STRING:
            return self._d.value
        if cat == query_pb2.DATA_CATEGORY_POINTER:
            if self._d.HasField("target"):
                return self._s.addr(self._d.target.offset)
            raw = self._s.read(self._a, self.getLength())
            return self._s.addr(int.from_bytes(raw, "little" if self._s.little else "big"))
        n = self.getLength()
        if n in (1, 2, 4, 8) and not self._d.data_type.startswith(("float", "double", "struct", "union")):
            raw = self._s.read(self._a, n)
            v = int.from_bytes(raw, "little" if self._s.little else "big", signed=False)
            return Scalar(n * 8, v, not self._d.data_type.startswith(("u", "undefined", "byte", "word", "dword", "qword")))
        return None

    def getDefaultValueRepresentation(self) -> str:
        if self._repr is None:
            self._s.sync()
            text = ""
            for row in self._s.prog.listing(self._a, max_rows=1, omit_bytes=True).rows:
                if row.address.offset == self._a:
                    text = "".join(t.text for t in row.tokens if t.kind == listing_pb2.LISTING_TOKEN_KIND_DATA_VALUE)
            self._repr = text
        return self._repr

    def getPathName(self) -> str:
        return self.getLabel() or f"DAT_{self._s.addr(self._a)}"

    def getComponent(self, *a):
        raise Unsupported("Data.getComponent")

    def __str__(self):
        return f"{self.getMnemonicString()} {self.getDefaultValueRepresentation()}".rstrip()

    def __repr__(self):
        return f"Data({self.getAddress()}: {self})"


class UndefinedData(Data):
    """One undefined byte (Ghidra's ``??``)."""

    def __init__(self, s: Session, a: int):
        self._s = s
        self._a = a
        self._d = query_pb2.DefinedData(address=address(a), length=1, category=query_pb2.DATA_CATEGORY_UNDEFINED,
                                        data_type="undefined")
        self._repr = None

    def isDefined(self) -> bool:
        return False

    def getDataType(self) -> DataType:
        return DataType.builtin("undefined")

    def getMnemonicString(self) -> str:
        return "??"

    def getValue(self):
        raw = self._s.read(self._a, 1)
        return Scalar(8, raw[0], False) if raw else None

    def getDefaultValueRepresentation(self) -> str:
        raw = self._s.read(self._a, 1)
        return f"{raw[0]:02X}h" if raw else "??"


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------


class MemoryBlock(JavaObject):
    _java_name = "MemoryBlock"

    def __init__(self, s: Session, b):
        self._s = s
        self._b = b
        self._lo = b.range.first.offset
        self._hi = b.range.last.offset

    def getName(self) -> str:
        return self._b.name

    def getStart(self) -> Address:
        return self._s.addr(self._lo)

    def getEnd(self) -> Address:
        return self._s.addr(self._hi)

    def getSize(self) -> int:
        return self._hi - self._lo + 1

    def getSizeAsBigInteger(self) -> int:
        return self.getSize()

    def isRead(self) -> bool:
        return self._b.read

    def isWrite(self) -> bool:
        return self._b.write

    def isExecute(self) -> bool:
        return self._b.execute

    def isVolatile(self) -> bool:
        return self._b.is_volatile

    def isInitialized(self) -> bool:
        return self._b.initialized

    def isLoaded(self) -> bool:
        return True

    def isMapped(self) -> bool:
        return False

    def isOverlay(self) -> bool:
        return self._b.overlay

    def isExternalBlock(self) -> bool:
        return False

    def getComment(self) -> Optional[str]:
        return None

    def getSourceName(self) -> str:
        return self._b.source.file or "Elf Loader"

    def getPermissions(self) -> int:
        return (4 if self._b.read else 0) | (2 if self._b.write else 0) | (1 if self._b.execute else 0)

    def contains(self, a) -> bool:
        return self._lo <= addr_int(a) <= self._hi

    def getByte(self, a) -> int:
        b = self._s.read(addr_int(a), 1)
        if not b:
            raise Unsupported("MemoryBlock.getByte (uninitialized)", "read initialized memory only")
        return b[0] - 256 if b[0] > 127 else b[0]

    def getBytes(self, a, dest, off: int = 0, n: Optional[int] = None) -> int:
        return self._s.program.getMemory().getBytes(a, dest, off, n)

    def putByte(self, a, value) -> None:
        self._s.patch(addr_int(a), to_bytes(value))

    def putBytes(self, a, data, off: int = 0, n: Optional[int] = None) -> int:
        raw = to_bytes(data)
        raw = raw[off:off + n] if n is not None else raw[off:]
        self._s.patch(addr_int(a), raw)
        return len(raw)

    def getAddressRange(self):
        from revkit.ghidra.compat.model import AddressRange

        return AddressRange(self.getStart(), self.getEnd())

    def __str__(self):
        return self._b.name

    def __eq__(self, other):
        return isinstance(other, MemoryBlock) and other._lo == self._lo

    def __hash__(self):
        return hash(self._lo)


class Memory(AddressSetView):
    """``currentProgram.getMemory()``: blocks, bytes, search; and the address
    set of all blocks."""

    _java_name = "Memory"

    def __init__(self, s: Session):
        self._s = s
        self.space = s.space
        self._loaded = False
        self.__r: list = []

    @property
    def _r(self):
        if not self._loaded or self._s._blocks is None:
            ranges = AddressSetView([(b._lo, b._hi) for b in self._s.blocks()])
            self.__r = ranges._r
            self._loaded = True
        return self.__r

    @_r.setter
    def _r(self, value):
        self.__r = value

    def getProgram(self) -> Program:
        return self._s.program

    def getBlocks(self) -> list:
        return list(self._s.blocks())

    def getBlock(self, a) -> Optional[MemoryBlock]:
        if isinstance(a, str):
            return next((b for b in self._s.blocks() if b.getName() == a), None)
        return None if a is None else self._s.block_of(addr_int(a))

    def getNumAddressRanges(self) -> int:
        return len(self._r)

    def _set(self, pred) -> AddressSet:
        return AddressSet(space=self._s.space).add(AddressSetView([(b._lo, b._hi) for b in self._s.blocks() if pred(b)]))

    def getExecuteSet(self) -> AddressSet:
        return self._set(lambda b: b._b.execute)

    def getLoadedAndInitializedAddressSet(self) -> AddressSet:
        return self._set(lambda b: b._b.initialized)

    def getAllInitializedAddressSet(self) -> AddressSet:
        return self._set(lambda b: b._b.initialized)

    getInitializedAddressSet = getAllInitializedAddressSet

    def isBigEndian(self) -> bool:
        return not self._s.little

    def getSize(self) -> int:
        return self.getNumAddresses()

    # -- reads --
    def getByte(self, a) -> int:
        b = self._s.read(addr_int(a), 1)
        if not b:
            raise Unsupported("Memory.getByte (uninitialized memory)", "read initialized memory only")
        return b[0] - 256 if b[0] > 127 else b[0]

    def getBytes(self, a, dest, off: int = 0, n: Optional[int] = None) -> int:
        """Fills ``dest`` (a list or bytearray, or a length) from ``a``; returns the count."""
        if isinstance(dest, int):
            return ByteArray.of(self._s.read(addr_int(a), dest))
        count = len(dest) - off if n is None else n
        raw = self._s.read(addr_int(a), count)
        signed = not isinstance(dest, (bytearray, memoryview))
        for i, b in enumerate(raw):
            dest[off + i] = (b - 256 if b > 127 else b) if signed else b
        return len(raw)

    def _int(self, a, n: int, big: Optional[bool]) -> int:
        raw = self._s.read(addr_int(a), n)
        if len(raw) < n:
            raise Unsupported(f"Memory.get{n} (uninitialized memory)", "read initialized memory only")
        big = (not self._s.little) if big is None else big
        return int.from_bytes(raw, "big" if big else "little", signed=True)

    def getShort(self, a, big: Optional[bool] = None) -> int:
        return self._int(a, 2, big)

    def getInt(self, a, big: Optional[bool] = None) -> int:
        return self._int(a, 4, big)

    def getLong(self, a, big: Optional[bool] = None) -> int:
        return self._int(a, 8, big)

    # -- writes (patches, committed with the run) --
    def setByte(self, a, value) -> None:
        self._s.patch(addr_int(a), to_bytes(value))

    def setBytes(self, a, data, off: int = 0, n: Optional[int] = None) -> None:
        raw = to_bytes(data)
        raw = raw[off:off + n] if n is not None else raw[off:]
        self._s.patch(addr_int(a), raw)

    def _set_int(self, a, value: int, n: int, big: Optional[bool]) -> None:
        big = (not self._s.little) if big is None else big
        self._s.patch(addr_int(a), (int(value) & ((1 << (8 * n)) - 1)).to_bytes(n, "big" if big else "little"))

    def setShort(self, a, v, big: Optional[bool] = None) -> None:
        self._set_int(a, v, 2, big)

    def setInt(self, a, v, big: Optional[bool] = None) -> None:
        self._set_int(a, v, 4, big)

    def setLong(self, a, v, big: Optional[bool] = None) -> None:
        self._set_int(a, v, 8, big)

    # -- search --
    def findBytes(self, start, *args):
        """``findBytes(start, bytes, masks, forward, monitor)`` or
        ``findBytes(start, end, bytes, masks, forward, monitor)``."""
        if isinstance(args[0], Address) or args[0] is None and len(args) == 5:
            end, data, masks, forward = args[0], args[1], args[2], args[3]
        else:
            end, data, masks, forward = None, args[0], args[1], args[2]
        pattern = to_bytes(data)
        mask = to_bytes(masks) if masks is not None else None
        lo = addr_int(start) if start is not None else 0
        hi = addr_int(end) if end is not None else (1 << 64) - 1
        if not forward:
            # Backward from `start` (inclusive) toward the beginning, or
            # through [end, start] when both are given.
            lo, hi = (min(lo, hi), max(lo, hi)) if end is not None else (0, lo)
        found = self._s.prog.search_memory(
            masked_query(pattern, mask), format="binary", ranges=[(lo, hi)], backward=not forward,
            start=None if forward else (hi + 1 if hi < (1 << 64) - 1 else None), max_results=1, details=False)
        return self._s.addr(found[0].address.offset) if found else None

    def locateAddressesForFileOffset(self, offset: int) -> JavaList:
        out = JavaList()
        for b in self._s.blocks():
            bb = b._b
            if bb.has_file_offset and bb.initialized and bb.file_offset <= offset < bb.file_offset + b.getSize():
                out.append(self._s.addr(b._lo + offset - bb.file_offset))
        return out

    def getAddressSourceInfo(self, a):
        return AddressSourceInfo(self._s, addr_int(a))

    def __str__(self):
        return "Memory"


class AddressSourceInfo(JavaObject):
    def __init__(self, s: Session, a: int):
        self._s = s
        self._a = a
        self._b = s.block_of(a)

    def getFileOffset(self) -> int:
        if self._b is None or not self._b._b.has_file_offset:
            return -1
        return self._b._b.file_offset + self._a - self._b._lo

    def getMemoryBlock(self):
        return self._b

    def getAddress(self) -> Address:
        return self._s.addr(self._a)


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------

_XREF_TYPE = {
    listing_pb2.XREF_KIND_CALL: RefType.UNCONDITIONAL_CALL,
    listing_pb2.XREF_KIND_JUMP: RefType.UNCONDITIONAL_JUMP,
    listing_pb2.XREF_KIND_CONDITIONAL_JUMP: RefType.CONDITIONAL_JUMP,
    listing_pb2.XREF_KIND_INDIRECT_CALL: RefType.COMPUTED_CALL,
    listing_pb2.XREF_KIND_INDIRECT_JUMP: RefType.COMPUTED_JUMP,
    listing_pb2.XREF_KIND_DATA_READ: RefType.READ,
    listing_pb2.XREF_KIND_DATA_WRITE: RefType.WRITE,
    listing_pb2.XREF_KIND_DATA_POINTER: RefType.DATA,
    listing_pb2.XREF_KIND_THUNK: RefType.THUNK,
}


class Reference(JavaObject):
    _java_name = "Reference"
    MNEMONIC = -1

    def __init__(self, s: Session, x: listing_pb2.Xref):
        self._s = s
        self._x = x

    def getFromAddress(self) -> Address:
        return self._s.addr(self._x.from_address.offset)

    def getToAddress(self) -> Address:
        return self._s.addr(self._x.to_address.offset)

    def getReferenceType(self) -> RefType:
        return _XREF_TYPE.get(self._x.kind, RefType.DATA)

    def getOperandIndex(self) -> int:
        return self._x.operand_index if self._x.HasField("operand_index") else -1

    def isMnemonicReference(self) -> bool:
        return self.getOperandIndex() == -1

    def isOperandReference(self) -> bool:
        return self.getOperandIndex() >= 0

    def getSource(self) -> SourceType:
        return source_of(self._x.origin, "x") if self._x.origin.WhichOneof("source") == "asserted" else SourceType.ANALYSIS

    def isPrimary(self) -> bool:
        """The operand's primary reference: the one a user made primary, or
        (none made primary) every reference, as Ghidra's analysis makes them."""
        if self._x.primary:
            return True
        op = self.getOperandIndex()
        return not any(r._x.primary and r.getOperandIndex() == op
                       for r in self._s.xrefs_from(self._x.from_address.offset))

    def isMemoryReference(self) -> bool:
        return True

    def isExternalReference(self) -> bool:
        return False

    def isStackReference(self) -> bool:
        return False

    def isRegisterReference(self) -> bool:
        return False

    def isOffsetReference(self) -> bool:
        return False

    def isShiftedReference(self) -> bool:
        return False

    def isEntryPointReference(self) -> bool:
        return False

    def getSymbolID(self) -> int:
        return -1

    def __str__(self):
        return (f"From: {self.getFromAddress()} To: {self.getToAddress()} Type: {self.getReferenceType()} "
                f"Op: {self.getOperandIndex()} {self.getSource()}")

    def __eq__(self, other):
        return isinstance(other, Reference) and (other._x.from_address.offset, other._x.to_address.offset,
                                                 other._x.kind) == (self._x.from_address.offset,
                                                                    self._x.to_address.offset, self._x.kind)

    def __hash__(self):
        return hash((self._x.from_address.offset, self._x.to_address.offset, self._x.kind))


class ReferenceManager(JavaObject):
    def __init__(self, s: Session):
        self._s = s

    def getReferencesTo(self, a):
        self._s.sync()
        return JavaIterator([Reference(self._s, x) for x in self._s.prog.xrefs_to(addr_int(a))])

    def getReferenceCountTo(self, a) -> int:
        self._s.sync()
        return len(self._s.prog.xrefs_to(addr_int(a)))

    def hasReferencesTo(self, a) -> bool:
        return self.getReferenceCountTo(a) > 0

    def getReferencesFrom(self, a, op_index: Optional[int] = None) -> list:
        refs = self._s.xrefs_from(addr_int(a))
        return [r for r in refs if op_index is None or r.getOperandIndex() == op_index]

    def getFlowReferencesFrom(self, a) -> list:
        return [r for r in self.getReferencesFrom(a) if r.getReferenceType().isFlow()]

    def getReferenceCountFrom(self, a) -> int:
        return len(self.getReferencesFrom(a))

    def hasReferencesFrom(self, a, op_index: Optional[int] = None) -> bool:
        return bool(self.getReferencesFrom(a, op_index))

    def hasFlowReferencesFrom(self, a) -> bool:
        return bool(self.getFlowReferencesFrom(a))

    def getPrimaryReferenceFrom(self, a, op_index: int):
        refs = self.getReferencesFrom(a, op_index)
        return refs[0] if refs else None

    def getReference(self, frm, to, op_index: int):
        return next((r for r in self.getReferencesFrom(frm, op_index) if r.getToAddress() == to), None)

    def getReferenceSourceIterator(self, a, forward: bool = True):
        self._s.sync()
        if isinstance(a, AddressSetView):
            ranges = list(a._r)
        else:
            ranges = [(addr_int(a), (1 << 64) - 1)] if forward else [(0, addr_int(a))]
        addrs = set()
        for lo, hi in ranges:
            for x in self._s.prog.xrefs(range=(lo, hi), direction="from"):
                addrs.add(x.from_address.offset)
        out = [self._s.addr(o) for o in sorted(addrs)]
        return JavaIterator(out if forward else list(reversed(out)))

    def getReferenceDestinationIterator(self, a, forward: bool = True):
        self._s.sync()
        ranges = list(a._r) if isinstance(a, AddressSetView) else [(addr_int(a), (1 << 64) - 1)]
        addrs = set()
        for lo, hi in ranges:
            for x in self._s.prog.xrefs(range=(lo, hi), direction="to"):
                addrs.add(x.to_address.offset)
        out = [self._s.addr(o) for o in sorted(addrs)]
        return JavaIterator(out if forward else list(reversed(out)))

    def getExternalReferences(self):
        return JavaIterator([])

    def getReferenceIterator(self, start):
        self._s.sync()
        refs = [Reference(self._s, x) for x in self._s.prog.xrefs(range=(addr_int(start), (1 << 64) - 1), direction="from")]
        return JavaIterator(refs)

    # -- edits: user references (api_minor 39, feature "user-references") --

    def addMemoryReference(self, frm, to, ref_type, source=None, op_index: int = -1) -> Reference:
        """A reference from the instruction at ``frm`` (Ghidra's References >
        Add): ``op_index`` its operand (-1: the instruction). Committed
        before the script's next read."""
        return user_reference(self._s, addr_int(frm), addr_int(to), ref_type, int(op_index))

    def delete(self, ref: Reference) -> None:
        """Deletes a reference: the user's at its operand, and every one
        analysis made from its instruction to its target."""
        delete_reference(self._s, ref)

    def setPrimary(self, ref: Reference, primary: bool) -> None:
        f, t, op = ref._x.from_address.offset, ref._x.to_address.offset, ref.getOperandIndex()
        self._s.edit(f"{'' if primary else 'not '}primary reference 0x{f:x} -> 0x{t:x}", reference_body(
            f, t, reference_type(ref.getReferenceType()), operand=op, primary=bool(primary)), structural=True)

    def updateRefType(self, ref: Reference, ref_type) -> Reference:
        return user_reference(self._s, ref._x.from_address.offset, ref._x.to_address.offset, ref_type,
                              ref.getOperandIndex(), primary=ref._x.primary)

    def removeAllReferencesFrom(self, a, b=None) -> None:
        lo, hi = addr_int(a), addr_int(a if b is None else b)
        for ref in [Reference(self._s, x) for x in self._s.prog.xrefs(range=(lo, hi), direction="from")]:
            delete_reference(self._s, ref)

    def removeAllReferencesTo(self, a) -> None:
        for ref in [Reference(self._s, x) for x in self._s.prog.xrefs_to(addr_int(a))]:
            delete_reference(self._s, ref)


# What a RefType is as a user reference.
_REF_TYPE_NAMES = {
    "DATA": "data", "PARAM": "data", "DATA_IND": "data", "READ_WRITE": "data", "READ_WRITE_IND": "data",
    "READ": "read", "READ_IND": "read", "WRITE": "write", "WRITE_IND": "write",
    "UNCONDITIONAL_CALL": "call", "CONDITIONAL_CALL": "call", "CALL_TERMINATOR": "call",
    "CONDITIONAL_CALL_TERMINATOR": "call", "UNCONDITIONAL_JUMP": "jump", "CONDITIONAL_JUMP": "jump",
    "JUMP_TERMINATOR": "jump", "COMPUTED_CALL": "computed_call", "COMPUTED_CALL_TERMINATOR": "computed_call",
    "CONDITIONAL_COMPUTED_CALL": "computed_call", "COMPUTED_JUMP": "computed_jump",
    "CONDITIONAL_COMPUTED_JUMP": "computed_jump",
}

_REF_XREF_KIND = {
    "data": listing_pb2.XREF_KIND_DATA_POINTER, "read": listing_pb2.XREF_KIND_DATA_READ,
    "write": listing_pb2.XREF_KIND_DATA_WRITE, "call": listing_pb2.XREF_KIND_CALL, "jump": listing_pb2.XREF_KIND_JUMP,
    "computed_call": listing_pb2.XREF_KIND_INDIRECT_CALL, "computed_jump": listing_pb2.XREF_KIND_INDIRECT_JUMP,
}


def reference_type(ref_type) -> str:
    """A Ghidra RefType (or its name) as a revkit reference type ("read", "computed_call", ...)."""
    name = ref_type if isinstance(ref_type, str) else getattr(ref_type, "_name", str(ref_type))
    if name not in _REF_TYPE_NAMES:
        raise Unsupported(f"RefType.{name} as a reference", "revkit's user references are DATA, READ, WRITE, "
                          "UNCONDITIONAL_CALL, UNCONDITIONAL_JUMP, COMPUTED_CALL or COMPUTED_JUMP")
    return _REF_TYPE_NAMES[name]


def user_reference(s: Session, frm: int, to: int, ref_type, op_index: int, primary: bool = False) -> Reference:
    """Buffers a user reference and returns it as a Reference (the user's, not committed yet)."""
    kind = reference_type(ref_type)
    s.edit(f"{kind} reference 0x{frm:x} -> 0x{to:x}",
           reference_body(frm, to, kind, operand=op_index, primary=primary), structural=True)
    x = listing_pb2.Xref(from_address=address(frm), to_address=address(to), kind=_REF_XREF_KIND[kind], primary=primary,
                         direction=listing_pb2.XREF_DIRECTION_FROM)
    if op_index >= 0:
        x.operand_index = op_index
    x.origin.asserted.provenance.CopyFrom(s.run.provenance())
    return Reference(s, x)


def delete_reference(s: Session, ref: Reference) -> None:
    f, t = ref._x.from_address.offset, ref._x.to_address.offset
    s.edit(f"remove reference 0x{f:x} -> 0x{t:x}", reference_body(f, t, operand=ref.getOperandIndex(), remove=True),
           structural=True)


# ---------------------------------------------------------------------------
# Equates (api_minor 39, feature "equates")
# ---------------------------------------------------------------------------


def _check_equate_name(name) -> str:
    from revkit.ghidra.compat.modules import InvalidInputException

    name = str(name or "")
    if not name or any(c.isspace() or ord(c) < 0x20 for c in name):
        raise InvalidInputException(f"invalid equate name: {name!r}")
    return name


class EquateReference(JavaObject):
    """Where an equate is used: an instruction's operand (or a decompiler
    constant by its dynamic hash)."""

    _java_name = "EquateReference"

    def __init__(self, s: Session, ref):
        self._s = s
        self._r = ref

    def getAddress(self) -> Address:
        return self._s.addr(self._r.address)

    def getOpIndex(self) -> int:
        return -1 if self._r.operand_index is None else self._r.operand_index

    def getDynamicHashValue(self) -> int:
        return self._r.constant_hash

    def __str__(self):
        return f"{self.getAddress()}[{self.getOpIndex()}]"


class Equate(JavaObject):
    """``ghidra.program.model.symbol.Equate``: a name for a value, and the
    operands that show it. Edits go into the run's buffer and are committed
    before the script's next read."""

    _java_name = "Equate"

    def __init__(self, s: Session, name: str, value: int, enum_type_hash: str = "", member: str = ""):
        self._s = s
        self._name = name
        self._value = int(value) & ((1 << 64) - 1)
        self._enum = enum_type_hash
        self._member = member

    def _key(self) -> Optional[str]:
        # The table's key: the name, or for an enum member sharing its name
        # with another enum's, "NAME#<hash prefix>" (revkit.fold_equates).
        table = self._s.equates()
        if self._name in table and table[self._name].enum_type_hash == self._enum:
            return self._name
        return next((k for k, e in table.items() if e.name == self._name and e.enum_type_hash == self._enum
                     and (not self._enum or e.value == self._value)), None)

    def _info(self):
        k = self._key()
        return None if k is None else self._s.equates()[k]

    def getName(self) -> str:
        return self._name

    def getDisplayName(self) -> str:
        return self._name

    def getValue(self) -> int:
        return _signed64(self._value)

    def getDisplayValue(self) -> str:
        v = self.getValue()
        return f"-0x{-v:x}" if v < 0 else f"0x{v:x}"

    def getReferenceCount(self) -> int:
        e = self._info()
        return len(e.references) if e else 0

    def getReferences(self, a=None) -> list:
        e = self._info()
        refs = [EquateReference(self._s, r) for r in (e.references if e else [])]
        return refs if a is None else [r for r in refs if r._r.address == addr_int(a)]

    def _where(self, x, y) -> tuple:
        # (address, op index) or Ghidra's (dynamic hash, address).
        if isinstance(x, Address) or y is None or not isinstance(y, Address):
            return addr_int(x), (None if y is None else int(y)), 0
        return addr_int(y), None, int(x)

    def addReference(self, x, y=None) -> None:
        """``addReference(addr, opIndex)`` (or ``addReference(dynamicHash, addr)``):
        the operand shows this equate's name."""
        a, op, h = self._where(x, y)
        body = operand_display_body(a, self._value, operand=op, constant_hash=h, equate=None if self._enum else self._name,
                                    enum=self._enum or None, member=self._member or None)
        self._s.edit(f"equate {self._name} at 0x{a:x}", body, structural=True)
        self._s.pending_equates.pop(self._name, None)

    def removeReference(self, x, y=None) -> None:
        """The operand shows the disassembler's number again. The equate
        stays in the table with no reference, as in Ghidra."""
        a, op, h = self._where(x, y)
        e = self._info()
        for r in (e.references if e else []):
            if r.address == a and (h and r.constant_hash == h or not h and r.operand_index == op):
                self._s.edit(f"remove equate {self._name} at 0x{a:x}", operand_display_body(
                    a, r.value, operand=r.operand_index, constant_hash=r.constant_hash if r.operand_index is None else 0),
                    structural=True)
                if len(e.references) == 1:
                    self._s.pending_equates[self._name] = self._value

    def renameEquate(self, new_name) -> None:
        from revkit.ghidra.compat.modules import DuplicateNameException

        new_name = _check_equate_name(new_name)
        table = self._s.equates()
        if new_name in table or new_name in self._s.pending_equates:
            raise DuplicateNameException(f"{new_name} already exists")
        key = self._key()
        if key is not None:
            self._s.edit(f"rename equate {self._name} to {new_name}", *rename_equate_bodies(table, key, new_name),
                         structural=True)
        elif self._name in self._s.pending_equates:
            self._s.pending_equates[new_name] = self._s.pending_equates.pop(self._name)
        self._name = new_name
        self._enum = self._member = ""

    def isValidUUID(self) -> bool:
        return True

    def isEnumBased(self) -> bool:
        return bool(self._enum)

    def getEnumUUID(self) -> Optional[str]:
        return self._enum or None

    def __str__(self):
        return self._name

    def __eq__(self, other):
        return isinstance(other, Equate) and other._name == self._name and other._value == self._value

    def __hash__(self):
        return hash((self._name, self._value))


class EquateTable(JavaObject):
    """``currentProgram.getEquateTable()``: the equates folded from the
    program's EQUATE assertions, plus those the script created and hasn't
    used yet."""

    _java_name = "EquateTable"

    def __init__(self, s: Session):
        self._s = s

    def _all(self) -> list:
        table = self._s.equates()
        out = [Equate(self._s, e.name, e.value, e.enum_type_hash, e.member) for e in table.values()]
        out += [Equate(self._s, n, v) for n, v in self._s.pending_equates.items() if n not in table]
        return sorted(out, key=lambda e: e._name)

    def createEquate(self, name, value) -> Equate:
        from revkit.ghidra.compat.modules import DuplicateNameException

        name = _check_equate_name(name)
        if self.getEquate(name) is not None:
            raise DuplicateNameException(f"{name} already exists")
        self._s.pending_equates[name] = int(value) & ((1 << 64) - 1)
        return Equate(self._s, name, value)

    def removeEquate(self, name) -> bool:
        e = self.getEquate(name)
        if e is None:
            return False
        for r in list(e.getReferences()):
            e.removeReference(r.getAddress(), r.getOpIndex()) if r._r.operand_index is not None else \
                e.removeReference(r._r.constant_hash, r.getAddress())
        self._s.pending_equates.pop(str(name), None)
        return True

    def deleteAddressRange(self, start, end, monitor=None) -> None:
        lo, hi = addr_int(start), addr_int(end)
        for e in self._all():
            for r in e.getReferences():
                if lo <= r._r.address <= hi:
                    if r._r.operand_index is None:
                        e.removeReference(r._r.constant_hash, r.getAddress())
                    else:
                        e.removeReference(r.getAddress(), r.getOpIndex())

    def getEquate(self, x, op_index=None, value=None) -> Optional[Equate]:
        """``getEquate(name)`` or ``getEquate(addr, opIndex, value)``."""
        if op_index is None:
            return next((e for e in self._all() if e._name == str(x)), None)
        v = int(value) & ((1 << 64) - 1)
        return next((e for e in self.getEquates(x, op_index)
                     if e._value == v or _signed64(e._value) == int(value)), None)

    def getEquates(self, x=None, op_index=None):
        """``getEquates()`` (an iterator over every equate),
        ``getEquates(addr)``, ``getEquates(addr, opIndex)`` or
        ``getEquates(value)``."""
        if x is None:
            return JavaIterator(self._all())
        if not isinstance(x, Address):
            v = int(x) & ((1 << 64) - 1)
            return JavaList(e for e in self._all() if e._value == v)
        a = addr_int(x)
        return JavaList(e for e in self._all() if any(
            r._r.address == a and (op_index is None or r.getOpIndex() == int(op_index)) for r in e.getReferences()))

    def getEquateAddresses(self, where=None):
        addrs = sorted({r.address for e in self._s.equates().values() for r in e.references})
        if isinstance(where, AddressSetView):
            addrs = [a for a in addrs if where.contains(self._s.addr(a))]
        elif where is not None:
            addrs = [a for a in addrs if a >= addr_int(where)]
        return JavaIterator(self._s.addr(a) for a in addrs)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


class DataTypeManager(JavaObject):
    def __init__(self, s: Session):
        self._s = s

    def getName(self) -> str:
        return self._s.summary.info.name

    def getProgram(self) -> Program:
        return self._s.program

    def getDataType(self, path, name: Optional[str] = None) -> Optional[DataType]:
        """``getDataType("/int")``, ``getDataType("/struct_name")`` or
        ``getDataType(CategoryPath, name)``: builtins, then the program's types."""
        if name is not None:
            path = str(path).rstrip("/") + "/" + name
        p = str(path)
        leaf = p.rsplit("/", 1)[-1]
        builtin = DataType.builtin(leaf)
        if builtin is not None and p.count("/") <= 1:
            return builtin
        if leaf.endswith("*"):
            target = self.getDataType("/" + leaf[:-1].strip())
            return pointer_to(target, self._s.pointer_size) if target else None
        return self._s.program_type(leaf)

    def findDataTypes(self, name: str, out: list, case_sensitive: bool = True, monitor=None) -> None:
        dt = self.getDataType("/" + name)
        if dt is not None:
            out.append(dt)

    def getAllDataTypes(self, out: Optional[list] = None):
        types = list(DataType._builtin.values())
        types += [type_from_definition(t) for t in self._s.prog.find_types("")]
        if out is not None:
            out.extend(types)
            return None
        return JavaIterator(types)

    def getDataTypeCount(self, include_pointers: bool = False) -> int:
        return sum(1 for _ in self._s.prog.find_types(""))

    def getPointer(self, dt, size: int = -1) -> DataType:
        return pointer_to(dt, size if size > 0 else self._s.pointer_size)

    def getDataOrganization(self) -> DataOrganization:
        return DataOrganization(self._s)

    def addDataType(self, dt, handler=None) -> DataType:
        source = getattr(dt, "c_source", "")
        if not source:
            raise Unsupported("DataTypeManager.addDataType")
        from revkit.client import header_import_bodies

        parsed = self._s.prog.parse_c(source, name=f"{self._s.run.name}.h")
        if parsed.errors:
            raise ValueError("addDataType: " + "; ".join(parsed.errors))
        bodies = header_import_bodies(parsed, None)
        if bodies:
            self._s.run.edits.add(f"define {dt.name}", *bodies)
            self._s.commit()
        return self._s.program_type(dt.name) or dt

    def startTransaction(self, description: str = "") -> int:
        return 1

    def endTransaction(self, txn: int, commit: bool = True) -> None:
        pass
