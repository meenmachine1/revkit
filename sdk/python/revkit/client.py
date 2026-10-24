"""A thin, typed wrapper over the generated revkit.v1 gRPC stubs.

Everything returns the generated protobuf messages (see ``revkit.v1``); the
wrapper only removes boilerplate: addresses as ints, provenance as a string
(``"agent:claude@opus-5.5"``), automatic pagination, snapshot pinning, and
subscriptions you can wait on.

    from revkit import Client

    with Client("127.0.0.1:50051", actor="user:alice") as rk:
        prog = rk.program("demo/hello")
        for f in prog.functions():
            print(hex(f.entry.offset), f.name)
        prog.rename(0x401040, "checksum")
        print(prog.decompile(0x401040).text)

Against a daemon with authentication and TLS (docs/security.md), pass a token
and how to trust the daemon's certificate, or set RK_TOKEN and
RK_TLS_FINGERPRINT / RK_TLS_CA in the environment:

    rk = Client("host:50051", token="rkt_...", fingerprint="AB:CD:...")
    rk = Client.login("host:50051", "alice", password, ca_cert="cert.pem")

The server then stamps the caller's identity on every edit, so ``actor``
defaults to empty kind and id (the server fills them in).
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import queue
import re
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Iterator, List, Optional, Sequence, Union

import grpc

from revkit import __version__
from revkit.expr import ExprError, Resolver, evaluate_text, is_number, parse_number
from revkit.v1 import (
    analysis_pb2,
    analysis_pb2_grpc,
    apple_pb2,
    assertion_pb2,
    auth_pb2,
    auth_pb2_grpc,
    assertion_pb2_grpc,
    bsim_pb2,
    bsim_pb2_grpc,
    common_pb2,
    debugger_pb2,
    debugger_pb2_grpc,
    diff_pb2,
    diff_pb2_grpc,
    emulator_pb2,
    emulator_pb2_grpc,
    filesystem_pb2,
    filesystem_pb2_grpc,
    listing_pb2,
    meta_pb2,
    meta_pb2_grpc,
    patch_pb2,
    patch_pb2_grpc,
    plugin_pb2,
    plugin_pb2_grpc,
    presence_pb2_grpc,
    project_pb2,
    project_pb2_grpc,
    provider_pb2,
    provider_pb2_grpc,
    query_pb2,
    query_pb2_grpc,
    script_pb2,
    script_pb2_grpc,
    subscription_pb2,
    subscription_pb2_grpc,
    sync_pb2_grpc,
    types_pb2,
    types_pb2_grpc,
)

AddressLike = Union[int, common_pb2.Address]

_PROVENANCE_KINDS = {
    "user": common_pb2.PROVENANCE_KIND_USER,
    "import": common_pb2.PROVENANCE_KIND_IMPORT,
    "agent": common_pb2.PROVENANCE_KIND_AGENT,
    "analysis": common_pb2.PROVENANCE_KIND_ANALYSIS,
    "migration": common_pb2.PROVENANCE_KIND_MIGRATION,
    "plugin": common_pb2.PROVENANCE_KIND_PLUGIN,
    "script": common_pb2.PROVENANCE_KIND_SCRIPT,
}

_FACT_KINDS = {
    "name": common_pb2.FACT_KIND_NAME,
    "type": common_pb2.FACT_KIND_TYPE,
    "comment": common_pb2.FACT_KIND_COMMENT,
    "function": common_pb2.FACT_KIND_FUNCTION_BOUNDS,
    "function_bounds": common_pb2.FACT_KIND_FUNCTION_BOUNDS,
    "flow_override": common_pb2.FACT_KIND_FLOW_OVERRIDE,
    "note": common_pb2.FACT_KIND_NOTE,
    "type_def": common_pb2.FACT_KIND_TYPE_DEF,
    "memory_region": common_pb2.FACT_KIND_MEMORY_REGION,
    "code_unit": common_pb2.FACT_KIND_CODE_UNIT,
    "mutability": common_pb2.FACT_KIND_MUTABILITY,
    "equate": common_pb2.FACT_KIND_EQUATE,
    "reference": common_pb2.FACT_KIND_REFERENCE,
    "call_signature": common_pb2.FACT_KIND_CALL_SIGNATURE,
    "register_value": common_pb2.FACT_KIND_REGISTER_VALUE,
}

_COMMENT_KINDS = {
    "eol": assertion_pb2.COMMENT_KIND_EOL,
    "pre": assertion_pb2.COMMENT_KIND_PRE,
    "post": assertion_pb2.COMMENT_KIND_POST,
    "plate": assertion_pb2.COMMENT_KIND_PLATE,
    "repeatable": assertion_pb2.COMMENT_KIND_REPEATABLE,
    "decompiler": assertion_pb2.COMMENT_KIND_DECOMPILER,
}

_FLOW_OVERRIDES = {
    "none": assertion_pb2.FLOW_OVERRIDE_KIND_NONE,
    "branch": assertion_pb2.FLOW_OVERRIDE_KIND_BRANCH,
    "call": assertion_pb2.FLOW_OVERRIDE_KIND_CALL,
    "call_return": assertion_pb2.FLOW_OVERRIDE_KIND_CALL_RETURN,
    "return": assertion_pb2.FLOW_OVERRIDE_KIND_RETURN,
}


# Listing edits (api_minor 30, feature "listing-edit"; docs/listing-edit.md).
_INSTRUCTION_SETS = {
    "": assertion_pb2.INSTRUCTION_SET_UNSPECIFIED,
    "arm": assertion_pb2.INSTRUCTION_SET_ARM,
    "thumb": assertion_pb2.INSTRUCTION_SET_THUMB,
}

_NAME_CONFLICTS = {
    "": project_pb2.NAME_CONFLICT_UNSPECIFIED,
    "keepboth": project_pb2.NAME_CONFLICT_KEEP_BOTH,
    "keep_both": project_pb2.NAME_CONFLICT_KEEP_BOTH,
    "replace": project_pb2.NAME_CONFLICT_REPLACE,
    "refuse": project_pb2.NAME_CONFLICT_REFUSE,
}

_STRING_ENCODINGS = {
    "utf8": assertion_pb2.STRING_ENCODING_UTF8,
    "utf16": assertion_pb2.STRING_ENCODING_UTF16,
    "utf32": assertion_pb2.STRING_ENCODING_UTF32,
}

_STRING_LAYOUTS = {
    "terminated": assertion_pb2.STRING_LAYOUT_TERMINATED,
    "fixed": assertion_pb2.STRING_LAYOUT_FIXED,
    "pascal": assertion_pb2.STRING_LAYOUT_PASCAL,
    "pascal16": assertion_pb2.STRING_LAYOUT_PASCAL16,
}

_MUTABILITIES = {
    "default": assertion_pb2.MUTABILITY_DEFAULT,
    "normal": assertion_pb2.MUTABILITY_NORMAL,
    "constant": assertion_pb2.MUTABILITY_CONSTANT,
    "volatile": assertion_pb2.MUTABILITY_VOLATILE,
}


def _choice(table: dict, value: Optional[str], what: str) -> int:
    key = (value or "").strip().lower().replace("-", "")
    if key not in table:
        raise ValueError(f"{what} is one of {', '.join(repr(k) for k in table if k)}, not {value!r}")
    return table[key]


def clear_code_body(addr: AddressLike, length: int = 1) -> assertion_pb2.AssertionBody:
    """Clear (Ghidra's ``C``): bytes [addr, addr + length) back to undefined."""
    if int(length) < 1:
        raise ValueError("clear_code: length must be at least 1")
    return assertion_pb2.AssertionBody(listing_edit=assertion_pb2.ListingEdit(
        address=address(addr), clear=assertion_pb2.ClearCode(length=int(length))))


def disassemble_body(addr: AddressLike, isa: Optional[str] = None, function: bool = False) -> assertion_pb2.AssertionBody:
    """Disassemble here (Ghidra's ``D``): code starts at addr, in ``isa``
    (None: as the context says, "arm" or "thumb"); ``function`` also makes it
    a function."""
    d = assertion_pb2.Disassemble(instruction_set=_choice(_INSTRUCTION_SETS, isa, "isa"), function=bool(function))
    return assertion_pb2.AssertionBody(listing_edit=assertion_pb2.ListingEdit(address=address(addr), disassemble=d))


def define_data_body(
    addr: AddressLike,
    type: Optional[str] = None,
    *,
    count: int = 0,
    string: Optional[str] = None,
    layout: Optional[str] = None,
    collapsed: Optional[bool] = None,
    type_hash: Optional[str] = None,
) -> assertion_pb2.AssertionBody:
    """Define data: a typed item at addr (``type`` as C, "uint32_t", "struct
    foo", "char *", or a Ghidra builtin name such as "dword"; or ``type_hash``),
    an array of ``count`` of them, or a string (``string`` "utf8", "utf16" or
    "utf32"; ``layout`` "terminated" (the default), "fixed" (``count``
    characters), "pascal" or "pascal16"). ``collapsed`` shows it on one row or
    a row per field or element."""
    d = assertion_pb2.DefineData(count=int(count))
    if string is not None:
        d.string = _choice(_STRING_ENCODINGS, string, "string")
        d.layout = _choice(_STRING_LAYOUTS, layout or "terminated", "layout")
    elif layout is not None:
        raise ValueError("define_data: a layout is for strings (give string=\"utf8\", \"utf16\" or \"utf32\")")
    if type_hash:
        d.type.type_hash = type_hash
    elif type:
        d.type.c_declaration = type
    elif string is None:
        raise ValueError("define_data: give a type (C or a builtin name such as \"dword\"), type_hash or string")
    if collapsed is not None:
        d.collapsed = bool(collapsed)
    return assertion_pb2.AssertionBody(listing_edit=assertion_pb2.ListingEdit(address=address(addr), data=d))


def mutability_body(addr: AddressLike, length: int, mutability: str) -> assertion_pb2.AssertionBody:
    """[addr, addr + length) is "constant" (reads fold), "volatile" (never
    folded), "normal" (writable) or "default" (as the memory map says)."""
    if int(length) < 1:
        raise ValueError("set_mutability: length must be at least 1")
    m = assertion_pb2.SetMutability(address=address(addr), length=int(length),
                                    mutability=_choice(_MUTABILITIES, mutability, "mutability"))
    return assertion_pb2.AssertionBody(mutability=m)


# Data settings (api_minor 84, feature "data-settings"; docs/listing-edit.md#data-settings).
_DATA_FORMATS = {
    "": assertion_pb2.DATA_FORMAT_UNSPECIFIED,
    "hex": assertion_pb2.DATA_FORMAT_HEX,
    "decimal": assertion_pb2.DATA_FORMAT_DECIMAL,
    "dec": assertion_pb2.DATA_FORMAT_DECIMAL,
    "octal": assertion_pb2.DATA_FORMAT_OCTAL,
    "binary": assertion_pb2.DATA_FORMAT_BINARY,
    "char": assertion_pb2.DATA_FORMAT_CHAR,
}
_DATA_SIGNS = {"": assertion_pb2.DATA_SIGNEDNESS_UNSPECIFIED, "signed": assertion_pb2.DATA_SIGNEDNESS_SIGNED,
               "unsigned": assertion_pb2.DATA_SIGNEDNESS_UNSIGNED}
_DATA_ENDIANS = {"": assertion_pb2.DATA_ENDIAN_UNSPECIFIED, "little": assertion_pb2.DATA_ENDIAN_LITTLE,
                 "big": assertion_pb2.DATA_ENDIAN_BIG}
_DATA_PADDINGS = {"": assertion_pb2.DATA_PADDING_UNSPECIFIED, "padded": assertion_pb2.DATA_PADDING_PADDED,
                  "unpadded": assertion_pb2.DATA_PADDING_UNPADDED}
_STRING_TERMINATIONS = {"": assertion_pb2.STRING_TERMINATION_UNSPECIFIED, "nul": assertion_pb2.STRING_TERMINATION_NUL,
                        "all": assertion_pb2.STRING_TERMINATION_ALL}
_POINTER_KINDS = {"": assertion_pb2.POINTER_KIND_UNSPECIFIED, "absolute": assertion_pb2.POINTER_KIND_ABSOLUTE,
                  "imagebase": assertion_pb2.POINTER_KIND_IMAGE_BASE_OFFSET,
                  "imagebaseoffset": assertion_pb2.POINTER_KIND_IMAGE_BASE_OFFSET,
                  "ibo": assertion_pb2.POINTER_KIND_IMAGE_BASE_OFFSET,
                  "relative": assertion_pb2.POINTER_KIND_RELATIVE}


def data_settings(
    *,
    format: Optional[str] = None,
    signed: Optional[bool] = None,
    endian: Optional[str] = None,
    padding: Optional[str] = None,
    charset: Optional[str] = None,
    termination: Optional[str] = None,
    pointer: Optional[str] = None,
    mask: Optional[int] = None,
    shift: Optional[int] = None,
) -> assertion_pb2.DataSettings:
    """A ``DataSettings`` message; None (or "") leaves a setting to the type's
    default. ``format`` "hex", "decimal", "octal", "binary" or "char";
    ``signed`` True or False; ``endian`` "little" or "big"; ``padding``
    "padded" or "unpadded"; ``charset`` "US-ASCII", "ISO-8859-1",
    "windows-1252", "UTF-8", "UTF-16", "UTF-16LE", "UTF-16BE", "UTF-32",
    "UTF-32LE" or "UTF-32BE"; ``termination`` "nul" or "all"; ``pointer``
    "absolute", "image-base" (an RVA) or "relative" (to the pointer's
    address), after ``mask`` keeps the stored value's bits and ``shift``
    shifts it left (negative: right)."""
    s = assertion_pb2.DataSettings(
        format=_choice(_DATA_FORMATS, format, "format"),
        endian=_choice(_DATA_ENDIANS, endian, "endian"),
        padding=_choice(_DATA_PADDINGS, padding, "padding"),
        termination=_choice(_STRING_TERMINATIONS, termination, "termination"),
        pointer_kind=_choice(_POINTER_KINDS, pointer, "pointer"),
        charset=charset or "",
    )
    if signed is not None:
        s.signedness = assertion_pb2.DATA_SIGNEDNESS_SIGNED if signed else assertion_pb2.DATA_SIGNEDNESS_UNSIGNED
    if mask is not None:
        s.pointer_mask = int(mask)
    if shift is not None:
        s.pointer_shift = int(shift)
    return s


def data_settings_body(addr: Optional[AddressLike] = None, *, field: str = "", type_name: str = "",
                       settings: Optional[assertion_pb2.DataSettings] = None, **kw) -> assertion_pb2.AssertionBody:
    """How a data item displays (Ghidra's Data Settings): the item at ``addr``
    (``field``: a struct field's row, its ``data_field`` path "hdr.magic"), or
    with ``type_name`` instead the type's defaults (Ghidra's Default
    Settings; a row's ``data_settings_type``). Give ``settings`` or the
    ``data_settings`` keywords; none set removes them."""
    if settings is None:
        settings = data_settings(**kw)
    elif kw:
        raise ValueError("data_settings_body: give settings or setting keywords, not both")
    b = assertion_pb2.SetDataSettings(field=field, type_name=type_name, settings=settings)
    if addr is not None:
        b.address.CopyFrom(address(addr))
    elif not type_name:
        raise ValueError("data_settings_body: give an address (an item) or type_name (a type's defaults)")
    return assertion_pb2.AssertionBody(data_settings=b)


# Equates and user references (api_minor 39, features "equates" and
# "user-references"; docs/api.md "Equates and user references").
_SCALAR_FORMATS = {
    "": assertion_pb2.SCALAR_FORMAT_UNSPECIFIED,
    "default": assertion_pb2.SCALAR_FORMAT_UNSPECIFIED,
    "hex": assertion_pb2.SCALAR_FORMAT_HEX,
    "signed": assertion_pb2.SCALAR_FORMAT_SIGNED_DECIMAL,
    "decimal": assertion_pb2.SCALAR_FORMAT_SIGNED_DECIMAL,
    "unsigned": assertion_pb2.SCALAR_FORMAT_UNSIGNED_DECIMAL,
    "octal": assertion_pb2.SCALAR_FORMAT_OCTAL,
    "binary": assertion_pb2.SCALAR_FORMAT_BINARY,
    "char": assertion_pb2.SCALAR_FORMAT_CHAR,
    "float": assertion_pb2.SCALAR_FORMAT_FLOAT,
}

_EQUATE_SCOPES = {
    "": assertion_pb2.EQUATE_SCOPE_UNSPECIFIED,
    "operand": assertion_pb2.EQUATE_SCOPE_UNSPECIFIED,
    "function": assertion_pb2.EQUATE_SCOPE_FUNCTION,
    "program": assertion_pb2.EQUATE_SCOPE_PROGRAM,
}

_REFERENCE_TYPES = {
    "data": assertion_pb2.REFERENCE_TYPE_DATA,
    "read": assertion_pb2.REFERENCE_TYPE_DATA_READ,
    "data_read": assertion_pb2.REFERENCE_TYPE_DATA_READ,
    "write": assertion_pb2.REFERENCE_TYPE_DATA_WRITE,
    "data_write": assertion_pb2.REFERENCE_TYPE_DATA_WRITE,
    "call": assertion_pb2.REFERENCE_TYPE_CALL,
    "jump": assertion_pb2.REFERENCE_TYPE_JUMP,
    "computed_call": assertion_pb2.REFERENCE_TYPE_COMPUTED_CALL,
    "computed_jump": assertion_pb2.REFERENCE_TYPE_COMPUTED_JUMP,
}

# The reference type an xref of each kind was made as (for a user reference
# that restates one: set_primary_reference).
_XREF_REFERENCE_TYPES = {
    listing_pb2.XREF_KIND_CALL: assertion_pb2.REFERENCE_TYPE_CALL,
    listing_pb2.XREF_KIND_JUMP: assertion_pb2.REFERENCE_TYPE_JUMP,
    listing_pb2.XREF_KIND_CONDITIONAL_JUMP: assertion_pb2.REFERENCE_TYPE_JUMP,
    listing_pb2.XREF_KIND_INDIRECT_CALL: assertion_pb2.REFERENCE_TYPE_COMPUTED_CALL,
    listing_pb2.XREF_KIND_INDIRECT_JUMP: assertion_pb2.REFERENCE_TYPE_COMPUTED_JUMP,
    listing_pb2.XREF_KIND_DATA_READ: assertion_pb2.REFERENCE_TYPE_DATA_READ,
    listing_pb2.XREF_KIND_DATA_WRITE: assertion_pb2.REFERENCE_TYPE_DATA_WRITE,
    listing_pb2.XREF_KIND_DATA_POINTER: assertion_pb2.REFERENCE_TYPE_DATA,
    listing_pb2.XREF_KIND_THUNK: assertion_pb2.REFERENCE_TYPE_JUMP,
}

_U64 = (1 << 64) - 1


def _scalar_value(value) -> int:
    """A scalar as its 64-bit pattern: -16 is 0xfffffffffffffff0 (the
    server matches it against a narrower operand by sign extension); a
    one-character string is its code ("A" is 0x41)."""
    if isinstance(value, str):
        v = ord(value) if len(value) == 1 else int(value, 0)
    else:
        v = int(value)
    if not -(1 << 63) <= v <= _U64:
        raise ValueError(f"a scalar is at most 64 bits, not {value!r}")
    return v & _U64


def operand_display_body(
    addr: AddressLike,
    value: int,
    *,
    operand: Optional[int] = None,
    format: Optional[str] = None,
    equate: Optional[str] = None,
    enum: Optional[str] = None,
    member: Optional[str] = None,
    constant_hash: int = 0,
    apply_to: Optional[str] = None,
) -> assertion_pb2.AssertionBody:
    """How the scalar ``value`` at the instruction ``addr`` shows (Ghidra's
    Convert and Set Equate): ``format`` "hex", "signed", "unsigned",
    "octal", "binary", "char" or "float"; or an ``equate`` name; or an enum
    member (``enum``: the enum's type hash, and ``member``). None of them
    (or format "default") clears the display: the disassembler's text
    again. ``operand`` is the operand's index (default: the operand holding
    the value); a decompiler constant no operand holds needs its
    ``constant_hash`` (CodeToken.constant_hash). ``apply_to`` "function" or
    "program" also sets it on every other operand holding the value there."""
    if len([x for x in (format, equate, enum or member) if x]) > 1:
        raise ValueError("operand_display: give one of format, equate, or enum and member")
    if bool(enum) != bool(member):
        raise ValueError("operand_display: an enum member needs both enum (its type hash) and member")
    d = assertion_pb2.OperandDisplay(address=address(addr), value=_scalar_value(value),
                                     constant_hash=int(constant_hash or 0) & _U64,
                                     apply_to=_choice(_EQUATE_SCOPES, apply_to, "apply_to"))
    if operand is not None and int(operand) >= 0:
        d.operand_index = int(operand)
    if equate:
        d.equate.name = equate
    elif enum:
        d.equate.enum_type_hash = enum
        d.equate.member = member
    elif format:
        d.format = _choice(_SCALAR_FORMATS, format, "format")
    return assertion_pb2.AssertionBody(operand_display=d)


def reference_body(
    from_: AddressLike,
    to: AddressLike,
    type: Optional[str] = None,
    *,
    operand: Optional[int] = None,
    primary: bool = False,
    remove: bool = False,
) -> assertion_pb2.AssertionBody:
    """A reference from the instruction at ``from_`` to ``to`` (Ghidra's
    References > Add): ``type`` "data", "read", "write", "call", "jump",
    "computed_call" or "computed_jump", on operand ``operand`` (None: the
    instruction as a whole, Ghidra's mnemonic reference); ``primary`` shows
    the operand as ``to``'s symbol (on a computed call, the decompiler calls
    ``to``). ``remove`` deletes instead: the user's reference at this key and
    every reference analysis made from ``from_`` to ``to``."""
    r = assertion_pb2.UserReference(primary=bool(primary), remove=bool(remove))
    getattr(r, "from").CopyFrom(address(from_))
    r.to.CopyFrom(address(to))
    if operand is not None and int(operand) >= 0:
        r.operand_index = int(operand)
    if type is not None and not isinstance(type, str):
        r.type = int(type)
    elif type:
        r.type = _choice(_REFERENCE_TYPES, type.replace(" ", "_"), "type")
    elif not remove:
        raise ValueError("reference: give a type (" + ", ".join(repr(k) for k in _REFERENCE_TYPES) + ")")
    return assertion_pb2.AssertionBody(reference=r)


@dataclass
class ExportedC:
    """Ghidra's C/C++ export of a program (``Program.export_c``): the source
    (``<name>.c``) and, when asked for, a header of the program's types and
    the functions' prototypes (``<name>.h``); ``functions`` decompiled,
    ``failed`` the entries the decompiler failed on (a comment in the source
    says why), ``notes`` on types the header can't reproduce."""

    source_name: str
    source: str
    header_name: str = ""
    header: str = ""
    functions: int = 0
    failed: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    revision: int = 0
    # With per_function: each function's ``query_pb2.ExportedCFunction``
    # (entry, name, source, prototype, failure), in address order.
    function_sources: list = field(default_factory=list)


def _c_dialect(dialect: Union[str, int]) -> int:
    if isinstance(dialect, int):
        return dialect
    d = dialect.lower().replace("-", "").replace("_", "")
    if d in ("", "c11", "default"):
        return query_pb2.C_DIALECT_C11
    if d in ("c89", "c90", "ansi"):
        return query_pb2.C_DIALECT_C89
    raise ValueError("dialect: \"c11\" or \"c89\", not %r" % dialect)


@dataclass(frozen=True)
class EquateReference:
    """One operand an equate names: the instruction, its operand (None for a
    decompiler constant keyed by its hash), the scalar's 64-bit pattern
    there, and the assertion (``seq``) that names it."""

    address: int
    operand_index: Optional[int]
    value: int
    seq: int
    constant_hash: int = 0


@dataclass
class Equate:
    """An equate as Ghidra's Equates table shows it: a name, its value and
    every operand that shows the name. ``enum_type_hash`` and ``member``
    are set for an enum member's name."""

    name: str
    value: int
    references: list
    enum_type_hash: str = ""
    member: str = ""

    @property
    def reference_count(self) -> int:
        return len(self.references)

    @property
    def seqs(self) -> list:
        return [r.seq for r in self.references]


def fold_equates(assertions) -> dict:
    """The equates table, {name: Equate} by name, from assertions
    (``ListAssertions`` with kind EQUATE): each effective display that is an
    equate (a name, or an enum member's), with its references in address
    order. The server keeps one value per name, except that an enum's
    member may share its name with another enum's: such a member is keyed
    ``"NAME#<enum hash prefix>"`` (its ``name`` stays NAME)."""
    groups: dict = {}  # (name, enum hash, value) -> Equate
    for a in assertions:
        if a.status != assertion_pb2.ASSERTION_STATUS_EFFECTIVE or a.op != assertion_pb2.ASSERTION_OP_ASSERT:
            continue
        if not a.body.HasField("operand_display"):
            continue
        d = a.body.operand_display
        if d.WhichOneof("display") != "equate":
            continue
        name = d.equate.name or d.equate.member
        if not name:
            continue
        ident = (name, d.equate.enum_type_hash, d.value if d.equate.enum_type_hash else 0)
        e = groups.get(ident)
        if e is None:
            e = groups[ident] = Equate(name, d.value, [], d.equate.enum_type_hash, d.equate.member)
        e.references.append(EquateReference(
            d.address.offset, d.operand_index if d.HasField("operand_index") else None, d.value, a.seq,
            d.constant_hash))
    shared: dict = {}
    for name, *_ in groups:
        shared[name] = shared.get(name, 0) + 1
    out: dict = {}
    for (name, enum, value), e in groups.items():
        e.references.sort(key=lambda r: (r.address, -1 if r.operand_index is None else r.operand_index))
        key = name if shared[name] == 1 or not enum else f"{name}#{enum[:12]}"
        if key in out:
            key = f"{key}:{value:x}"
        out[key] = e
    return dict(sorted(out.items()))


def _restate(ref: EquateReference, **display) -> assertion_pb2.AssertionBody:
    return operand_display_body(ref.address, ref.value, operand=ref.operand_index,
                                constant_hash=ref.constant_hash if ref.operand_index is None else 0, **display)


def rename_equate_bodies(table: dict, old: str, new: str) -> list:
    """The bodies that rename equate ``old`` to ``new`` at every reference
    of it in ``table`` (fold_equates); one AppendAssertions, one undo step."""
    if old not in table:
        raise ValueError(f"no equate {old!r}")
    if not new or any(c.isspace() for c in new):
        raise ValueError(f"an equate name is not empty and has no whitespace: {new!r}")
    return [_restate(r, equate=new) for r in table[old].references]


def remove_equate_bodies(table: dict, name: str) -> list:
    """The bodies that clear equate ``name`` at every reference (its
    operands show the disassembler's text again)."""
    if name not in table:
        raise ValueError(f"no equate {name!r}")
    return [_restate(r) for r in table[name].references]


def _signed64(v: int) -> int:
    v = int(v) & _U64
    return v - (1 << 64) if v >> 63 else v


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


PREVIEW_LINES = 12

_CHAR_ESCAPES = {0: "\\0", 7: "\\a", 8: "\\b", 9: "\\t", 10: "\\n", 11: "\\v", 12: "\\f", 13: "\\r", 39: "\\'", 92: "\\\\"}


def plist_value(v: "apple_pb2.PlistValue"):
    """A property list value (``PlistValue``, api_minor 100, feature
    ``apple-bundles``; docs/apple-apps.md) as Python: str, int, float, bool,
    ``datetime`` (UTC), bytes (data, cut where the response cut it), list,
    dict, None (a binary plist's null), and a keyed archive's UID as
    ``{"CF$UID": n}`` (Foundation's own spelling)."""
    import datetime

    kind = v.WhichOneof("value")
    if kind is None or kind == "null_value":
        return None
    if kind == "array_value":
        return [plist_value(x) for x in v.array_value.items]
    if kind == "dict_value":
        return {e.key: plist_value(e.value) for e in v.dict_value.entries}
    if kind == "date_value":
        return datetime.datetime.fromtimestamp(v.date_value.seconds + v.date_value.nanos / 1e9, datetime.timezone.utc)
    if kind == "uid_value":
        return {"CF$UID": v.uid_value}
    return getattr(v, kind)


def scalar_text(value: int, bits: int = 64) -> dict:
    """A scalar's spellings in ``bits`` bits (8 to 64), as the UI's hover card
    shows them (api_minor 47, feature ``hover``; docs/ui.md "Hover cards"):
    ``hex``, ``unsigned`` and ``signed`` decimal, and ``chars``, a C character
    constant ("'A'", "'ELF'") when every byte prints, else None."""
    w = max(8, min(64, bits or 64))
    u = value & ((1 << w) - 1)
    s = u - (1 << w) if u >= 1 << (w - 1) else u
    chars = None
    if u:
        bs = u.to_bytes((u.bit_length() + 7) // 8, "big")
        if all(0x20 <= b < 0x7F or b in _CHAR_ESCAPES for b in bs):
            chars = "'" + "".join(_CHAR_ESCAPES.get(b, chr(b)) for b in bs) + "'"
    return {"hex": hex(u), "unsigned": str(u), "signed": str(s), "chars": chars}


def decompiled_lines(fn) -> list:
    """A DecompiledFunction's text, line by line, as the decompiler prints it."""
    return ["  " * line.indent + "".join(t.text for t in line.tokens) for line in fn.lines]


def preview_lines(fn, n: int = PREVIEW_LINES) -> list:
    """The first lines of a function's C, as a hover card shows them: its
    signature, the opening brace and the body's first statements (the local
    declarations, up to the first blank line, skipped), then "  …" when there
    is more."""
    all_lines = decompiled_lines(fn)
    opening = next((i for i, l in enumerate(all_lines) if l.strip() == "{"), -1)
    if opening < 0:
        return all_lines[:n]
    out = all_lines[: opening + 1]
    blank = next((j for j in range(opening + 1, len(all_lines)) if not all_lines[j].strip()), -1)
    i = blank + 1 if opening < blank < opening + 40 else opening + 1
    while i < len(all_lines) and len(out) < n:
        if all_lines[i].strip():
            out.append(all_lines[i])
        i += 1
    if i < len(all_lines):
        out.append("  …")
    return out


class RevkitError(Exception):
    """A failed call. ``code`` is the grpc.StatusCode, ``message`` the server's text."""

    def __init__(self, code: grpc.StatusCode, message: str):
        super().__init__(f"{code.name}: {message}")
        self.code = code
        self.message = message


class NotFound(RevkitError):
    pass


class InvalidArgument(RevkitError):
    pass


class FailedPrecondition(RevkitError):
    """Includes REVISION_EXPIRED for pinned reads older than the server retains."""


class Aborted(RevkitError):
    """Optimistic concurrency failure (expected_head_revision did not match)."""


class ResourceExhausted(RevkitError):
    """A budget ran out: a plugin's fuel, memory or time, a subscriber's queue, or login attempts."""


class Unauthenticated(RevkitError):
    """No valid credentials: log in, or pass a token (``token=`` or RK_TOKEN)."""


class PermissionDenied(RevkitError):
    """The caller's role or project list doesn't allow the call, or its provenance named someone else."""


class Unavailable(RevkitError):
    pass


_ERRORS = {
    grpc.StatusCode.NOT_FOUND: NotFound,
    grpc.StatusCode.INVALID_ARGUMENT: InvalidArgument,
    grpc.StatusCode.FAILED_PRECONDITION: FailedPrecondition,
    grpc.StatusCode.ABORTED: Aborted,
    grpc.StatusCode.UNAVAILABLE: Unavailable,
    grpc.StatusCode.RESOURCE_EXHAUSTED: ResourceExhausted,
    grpc.StatusCode.UNAUTHENTICATED: Unauthenticated,
    grpc.StatusCode.PERMISSION_DENIED: PermissionDenied,
}


def _error(e: grpc.RpcError) -> RevkitError:
    code = e.code() if hasattr(e, "code") else grpc.StatusCode.UNKNOWN
    details = e.details() if hasattr(e, "details") else str(e)
    return _ERRORS.get(code, RevkitError)(code, details or "")


# ---------------------------------------------------------------------------
# Small conversions
# ---------------------------------------------------------------------------


def address(a: AddressLike, space: str = "") -> common_pb2.Address:
    """An Address in the default space (or ``space``) from an int."""
    if isinstance(a, common_pb2.Address):
        return a
    return common_pb2.Address(space=space, offset=int(a))


def address_range(first: AddressLike, last: AddressLike) -> common_pb2.AddressRange:
    """Inclusive [first, last]."""
    return common_pb2.AddressRange(first=address(first), last=address(last))


def memory_region(spec: str) -> project_pb2.MemoryRegion:
    """A raw image's extra memory region from "name:start:size[:perms][:init|uninit|volatile]"
    (numbers in hex, as rk-lift --region and the UI spell it): read/write and
    uninitialized unless it says otherwise."""
    parts = spec.strip().split(":")
    if not 3 <= len(parts) <= 5 or not parts[0]:
        raise ValueError(f'region "{spec}": name:start:size[:perms][:init|uninit|volatile]')
    r = project_pb2.MemoryRegion(name=parts[0], start=int(parts[1], 16), size=int(parts[2], 16), read=True, write=True)
    for flag in parts[3:]:
        if flag == "init":
            r.initialized = True
        elif flag == "uninit":
            r.initialized = False
        elif flag == "volatile":
            r.is_volatile = True
        elif len(flag) == 3 and all(c in ok for c, ok in zip(flag, ("r-", "w-", "x-"))):
            r.read, r.write, r.execute = flag[0] == "r", flag[1] == "w", flag[2] == "x"
        else:
            raise ValueError(f'region "{spec}": unknown "{flag}"')
    if not r.size:
        raise ValueError(f'region "{spec}": empty')
    return r


def format_memory_region(r: project_pb2.MemoryRegion) -> str:
    """The inverse of ``memory_region``: "ram:20000000:40000:rw-"."""
    perms = ("r" if r.read else "-") + ("w" if r.write else "-") + ("x" if r.execute else "-")
    out = f"{r.name}:{r.start:x}:{r.size:x}:{perms}"
    if r.initialized:
        out += ":init"
    if r.is_volatile:
        out += ":volatile"
    return out


def detect_confidence(value: int) -> str:
    """A DetectConfidence as "high", "medium" or "low" ("" when unset)."""
    name = project_pb2.DetectConfidence.Name(value).removeprefix("DETECT_CONFIDENCE_").lower()
    return "" if name == "unspecified" else name


def provenance(actor: Union[str, common_pb2.Provenance, None], session: str = "", reason: str = "") -> common_pb2.Provenance:
    """Parses ``"kind:id[@version]"`` (e.g. ``"agent:claude@opus-5.5"``). Empty or None
    leaves kind and id unset, for a daemon that stamps the caller's identity;
    ``"@version"`` sets only the version (an agent token's model, say)."""
    if isinstance(actor, common_pb2.Provenance):
        return actor
    if not actor or actor.startswith("@"):
        return common_pb2.Provenance(
            version=(actor or "")[1:], session=session, reason=reason, tool=f"revkit-py/{__version__}"
        )
    kind, _, rest = actor.partition(":")
    if kind not in _PROVENANCE_KINDS:
        raise ValueError(f"provenance must look like 'user:alice' or 'agent:name@version', got {actor!r}")
    ident, _, version = rest.partition("@")
    return common_pb2.Provenance(
        kind=_PROVENANCE_KINDS[kind],
        id=ident,
        version=version,
        session=session,
        reason=reason,
        tool=f"revkit-py/{__version__}",
    )


def format_provenance(p: common_pb2.Provenance) -> str:
    """The canonical ``kind:id[@version]`` form."""
    names = {v: k for k, v in _PROVENANCE_KINDS.items()}
    text = f"{names.get(p.kind, 'unknown')}:{p.id}"
    return f"{text}@{p.version}" if p.version else text


def describe_provenance(p: common_pb2.Provenance) -> str:
    """Who said it, for people: ``user:alice``, or for a script run by
    someone (``Provenance.on_behalf_of``, api_minor 29) ``alice via
    script:fix-names``."""
    names = {v: k for k, v in _PROVENANCE_KINDS.items()}
    who = f"{names.get(p.kind, 'unknown')}:{p.id}"
    if not p.on_behalf_of:
        return format_provenance(p)
    person = p.on_behalf_of[len("user:"):] if p.on_behalf_of.startswith("user:") else p.on_behalf_of
    return f"{person} via {who}"


def byte_pattern(pattern: Union[str, bytes], mask: Optional[bytes] = None) -> tuple:
    """``(pattern, mask)`` bytes for FindBytes from bytes (and an optional
    mask), or from text such as ``"48 8b ?? 05"`` or ``"488b??05"``: hex
    digits, with ``?`` for a nibble that may be anything ("4?" matches
    0x40-0x4f). Spaces are ignored."""
    if isinstance(pattern, (bytes, bytearray)):
        data = bytes(pattern)
        if mask is not None and len(mask) != len(data):
            raise ValueError("mask must be as long as pattern")
        return data, bytes(mask) if mask is not None else b""
    text = "".join(pattern.split())
    if len(text) % 2:
        raise ValueError(f"byte pattern {pattern!r}: an odd number of hex digits")
    data, bits = bytearray(), bytearray()
    for i in range(0, len(text), 2):
        value = m = 0
        for c in text[i : i + 2]:
            value, m = value << 4, m << 4
            if c != "?":
                value |= int(c, 16)
                m |= 0xF
        data.append(value)
        bits.append(m)
    if not data:
        raise ValueError("empty byte pattern")
    return bytes(data), (b"" if all(b == 0xFF for b in bits) else bytes(bits))


def masked_query(pattern: bytes, mask: Optional[bytes] = None) -> str:
    """Bytes and an optional bit mask as a ``search_memory(format="binary")``
    query: eight digits a byte, ``x`` for a bit the mask leaves out."""
    if mask is not None and len(mask) != len(pattern):
        raise ValueError("mask must be as long as pattern")
    out = []
    for i, b in enumerate(pattern):
        m = 0xFF if mask is None else mask[i]
        out.append("".join(("1" if (b >> k) & 1 else "0") if (m >> k) & 1 else "x" for k in range(7, -1, -1)))
    return " ".join(out)


def latin1_regex(pattern: Union[str, bytes]) -> str:
    """A regular expression over bytes (a str of Latin-1 characters, as
    Ghidra's findBytes takes, or bytes) for ``search_memory(format="regex")``:
    characters above 0x7f become ``\\xHH``, since the query travels as
    UTF-8."""
    text = pattern.decode("latin-1") if isinstance(pattern, (bytes, bytearray)) else pattern
    return "".join(c if ord(c) < 0x80 else f"\\x{ord(c):02x}" for c in text)


def fact_key(program_id: str, kind: Union[str, int], addr: AddressLike, sub: str = "") -> common_pb2.FactKey:
    """A FactKey; ``kind`` is a FactKind value or one of name/type/comment/function/flow_override/note."""
    k = _FACT_KINDS[kind] if isinstance(kind, str) else kind
    return common_pb2.FactKey(program_id=program_id, kind=k, address=address(addr), sub=sub)


# ---------------------------------------------------------------------------
# Connections: TLS and tokens
# ---------------------------------------------------------------------------


def _split_target(target: str) -> tuple:
    host, _, port = target.rpartition(":")
    return host.strip("[]") or "localhost", int(port)


def certificate_fingerprint(pem: str) -> str:
    """SHA-256 of a PEM certificate, as ``AB:CD:...`` (what rk-daemon prints)."""
    der = ssl.PEM_cert_to_DER_cert(pem)
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i : i + 2] for i in range(0, len(h), 2))


def _normalize_fingerprint(f: str) -> str:
    f = f.strip()
    for prefix in ("sha256:", "SHA256:", "SHA256 Fingerprint="):
        if f.startswith(prefix):
            f = f[len(prefix):]
    return f.replace(":", "").replace(" ", "").upper()


def fetch_certificate(target: str, timeout: float = 5.0) -> str:
    """The PEM certificate the TLS server at ``host:port`` presents, unverified (for pinning)."""
    host, port = _split_target(target)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    return ssl.DER_cert_to_PEM_cert(der)


def pinned_certificate(target: str, fingerprint: str) -> str:
    """Fetches the server's certificate and checks it against ``fingerprint``.
    Raises ssl.SSLError on a mismatch."""
    pem = fetch_certificate(target)
    got = certificate_fingerprint(pem)
    if _normalize_fingerprint(got) != _normalize_fingerprint(fingerprint):
        raise ssl.SSLError(f"{target} presents certificate {got}, not the pinned {fingerprint}")
    return pem


class _BearerInterceptor(
    grpc.UnaryUnaryClientInterceptor,
    grpc.UnaryStreamClientInterceptor,
    grpc.StreamUnaryClientInterceptor,
    grpc.StreamStreamClientInterceptor,
):
    """Adds ``authorization: Bearer <token>`` to every call (also on plaintext loopback
    channels, where gRPC refuses call credentials)."""

    def __init__(self, token: str):
        self._md = ("authorization", f"Bearer {token}")

    def _details(self, d):
        md = list(d.metadata or []) + [self._md]
        return d._replace(metadata=md) if hasattr(d, "_replace") else _Details(d, md)

    def intercept_unary_unary(self, cont, d, req):
        return cont(self._details(d), req)

    def intercept_unary_stream(self, cont, d, req):
        return cont(self._details(d), req)

    def intercept_stream_unary(self, cont, d, it):
        return cont(self._details(d), it)

    def intercept_stream_stream(self, cont, d, it):
        return cont(self._details(d), it)


class _Details(grpc.ClientCallDetails):
    def __init__(self, d, metadata):
        self.method = d.method
        self.timeout = d.timeout
        self.metadata = metadata
        self.credentials = d.credentials
        self.wait_for_ready = getattr(d, "wait_for_ready", None)
        self.compression = getattr(d, "compression", None)


def make_channel(
    target: str,
    *,
    token: Optional[str] = None,
    tls: Optional[bool] = None,
    ca_cert: Optional[str] = None,
    fingerprint: Optional[str] = None,
    server_name: Optional[str] = None,
) -> grpc.Channel:
    """A gRPC channel to rk-daemon.

    TLS is used when ``tls`` is true or a ``ca_cert`` (PEM file) or ``fingerprint``
    is given. With ``fingerprint`` the daemon's certificate is fetched, checked
    and then trusted as the only root (a self-signed rk-daemon certificate), and
    its name is checked as ``localhost`` (which every rk-daemon self-signed
    certificate carries) unless ``server_name`` says otherwise. Without either,
    the system's CAs are trusted. ``token`` is sent as a bearer token.
    """
    options = [("grpc.max_receive_message_length", 64 << 20), ("grpc.max_send_message_length", 64 << 20)]
    if tls is None:
        tls = bool(ca_cert or fingerprint)
    if tls:
        root = None
        if fingerprint:
            root = pinned_certificate(target, fingerprint).encode()
            server_name = server_name or "localhost"
        elif ca_cert:
            with open(ca_cert, "rb") as f:
                root = f.read()
        if server_name:
            options.append(("grpc.ssl_target_name_override", server_name))
        channel = grpc.secure_channel(target, grpc.ssl_channel_credentials(root_certificates=root), options=options)
    else:
        channel = grpc.insecure_channel(target, options=options)
    if token:
        channel = grpc.intercept_channel(channel, _BearerInterceptor(token))
    return channel


def _env_token() -> Optional[str]:
    if tok := os.environ.get("RK_TOKEN"):
        return tok.strip()
    if path := os.environ.get("RK_TOKEN_FILE"):
        with open(path) as f:
            return f.readline().strip()
    return None


# ---------------------------------------------------------------------------
# Subscriptions
# ---------------------------------------------------------------------------


class Subscription:
    """A live SubscriptionService.Subscribe stream.

    Events are read on a background thread into a queue, so callers can wait
    with timeouts. Iterate it, or use :meth:`next` / :meth:`wait_for`.
    Use as a context manager (or call :meth:`close`) to cancel the stream.
    """

    _END = object()

    def __init__(self, call):
        self._call = call
        self._queue: "queue.Queue" = queue.Queue()
        self.error: Optional[RevkitError] = None
        self.hello: Optional[subscription_pb2.Hello] = None
        self.ended = False
        self._thread = threading.Thread(target=self._pump, name="revkit-subscription", daemon=True)
        self._thread.start()
        first = self.next(timeout=30)
        if first is None or not first.HasField("hello"):
            self.close()
            raise self.error or RevkitError(grpc.StatusCode.UNKNOWN, "subscription did not start")
        self.hello = first.hello

    def _pump(self):
        try:
            for event in self._call:
                self._queue.put(event)
        except grpc.RpcError as e:
            if e.code() != grpc.StatusCode.CANCELLED:
                self.error = _error(e)
        finally:
            self._queue.put(self._END)

    def next(self, timeout: Optional[float] = None) -> Optional[subscription_pb2.SubscribeResponse]:
        """The next event, or None when the stream ended or ``timeout`` passed (see :attr:`ended`)."""
        if self.ended:
            return None
        try:
            item = self._queue.get(timeout=timeout)
        except queue.Empty:
            return None
        if item is self._END:
            self.ended = True
            return None
        return item

    def wait_for(
        self,
        predicate: Callable[[subscription_pb2.SubscribeResponse], bool],
        timeout: float = 10.0,
    ) -> subscription_pb2.SubscribeResponse:
        """Skips events until one satisfies ``predicate``. Raises TimeoutError, or the
        stream's error if it ended."""
        deadline = time.monotonic() + timeout
        while (remaining := deadline - time.monotonic()) > 0:
            event = self.next(timeout=remaining)
            if event is not None and predicate(event):
                return event
            if self.ended:
                raise self.error or RevkitError(grpc.StatusCode.CANCELLED, "subscription ended")
        raise TimeoutError("no matching subscription event")

    def next_revision(self, timeout: float = 10.0) -> subscription_pb2.RevisionEvent:
        """Waits for the next RevisionEvent (skipping heartbeats and progress)."""
        return self.wait_for(lambda e: e.HasField("revision"), timeout).revision

    def __iter__(self) -> Iterator[subscription_pb2.SubscribeResponse]:
        while (event := self.next()) is not None:
            yield event
        if self.error:
            raise self.error

    def close(self):
        self._call.cancel()
        self._thread.join(timeout=5)

    def __enter__(self) -> "Subscription":
        return self

    def __exit__(self, *exc):
        self.close()


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


def header_import_bodies(
    parsed: "types_pb2.ParseCResponse",
    keys: Optional[Sequence[str]] = None,
    *,
    include_identical: bool = False,
    include_library: bool = False,
    categories: str = "chosen",
) -> list:
    """The assertions that import what ``Program.parse_c`` returned: a
    ``define_type`` for every type the chosen names need (references
    renumbered), then a ``bind_type_name`` for each chosen name, which makes
    it the program's definition of that name.

    ``keys`` chooses names ("struct cJSON"); by default every name that is new
    to the program or replaces its definition. A name whose definition is
    already the program's (the same hash) is left out unless
    ``include_identical``, or ``include_library`` and that definition is
    only the library archive's (a type archive's import). Constant enums
    (``defines_as_enum``) are named types too.

    ``categories`` (api_minor 35) files the types under
    ``ParseCNamedType.category``: the chosen ones (``"chosen"``: a header's
    types under its name), every parsed name whose category differs
    (``"all"``: a type archive's), or none (``"none"``).
    """
    if categories not in ("chosen", "all", "none"):
        raise ValueError("categories is 'chosen', 'all' or 'none'")
    named = list(parsed.named)
    if keys is not None:
        want = set(keys)
        unknown = want - {n.key for n in named}
        if unknown:
            raise ValueError(f"not in the parse: {sorted(unknown)}")
        chosen = [n for n in named if n.key in want]
    else:
        chosen = [n for n in named if not n.system]
    if not include_identical:
        chosen = [n for n in chosen if n.existing_hash != n.hash or (include_library and n.existing_library)]
    # Every node the chosen roots reach through assertion_index references.
    need, stack = set(), [n.index for n in chosen]

    def refs(node):
        out = []
        if node.HasField("target"):
            out.append(node.target)
        out.extend(f.type for f in node.fields)
        out.extend(p.type for p in node.params)
        return out

    while stack:
        i = stack.pop()
        if i in need:
            continue
        need.add(i)
        for r in refs(parsed.nodes[i]):
            if r.WhichOneof("kind") == "assertion_index":
                stack.append(r.assertion_index)
    order = sorted(need)
    new_index = {old: new for new, old in enumerate(order)}
    bodies = []
    for old in order:
        node = types_pb2.TypeNode()
        node.CopyFrom(parsed.nodes[old])
        for r in refs(node):
            if r.WhichOneof("kind") == "assertion_index":
                r.assertion_index = new_index[r.assertion_index]
        bodies.append(assertion_pb2.AssertionBody(define_type=assertion_pb2.DefineType(type=node)))
    for n in chosen:
        ref = types_pb2.TypeNodeRef(assertion_index=new_index[n.index])
        bodies.append(assertion_pb2.AssertionBody(bind_type_name=assertion_pb2.BindTypeName(type=ref)))
    if categories != "none":
        for n in named if categories == "all" else chosen:
            if n.category and n.category != n.existing_category:
                bodies.append(type_category_body(n.key, n.category))
    return bodies


def type_category_body(named_key: str, path: str) -> "assertion_pb2.AssertionBody":
    """Files a named type ("struct cJSON") under a category ("/net/http";
    "" or "/" the top) (api_minor 35, feature "type-archive")."""
    return assertion_pb2.AssertionBody(type_category=assertion_pb2.SetTypeCategory(named_key=named_key, path=path))


_ARCHIVE_SCOPES = {"selected": 1, "category": 2, "user": 3, "all": 4}


def auto_structure_bodies(
    made: "types_pb2.AutoStructureResponse",
    *,
    function: Optional[AddressLike] = None,
    storage_key: str = "",
    at: Optional[AddressLike] = None,
) -> list:
    """The assertions that apply what ``Program.auto_structure`` or
    ``Program.structure_from_range`` returned, as one request: a
    ``define_type`` per node, a ``bind_type_name`` of the structure's name,
    then a retype of the variable (``function`` and ``storage_key``) to a
    pointer to it, or a data definition of it ``at`` the range's start; for
    a field target, a ``bind_type_name`` of the outer structure's next
    version instead."""
    if made.unchanged and not made.nodes:
        raise ValueError("nothing to apply: " + ("; ".join(made.notes) or "the structure would not change"))
    bodies = [assertion_pb2.AssertionBody(define_type=assertion_pb2.DefineType(type=n)) for n in made.nodes]
    if made.named_key:
        ref = types_pb2.TypeNodeRef(assertion_index=made.struct_index)
        bodies.append(assertion_pb2.AssertionBody(bind_type_name=assertion_pb2.BindTypeName(type=ref)))
    # A field target (api_minor 56): the outer structure's next version, whose
    # field points to the new one, takes its name; nothing is retyped.
    if made.HasField("outer_index"):
        ref = types_pb2.TypeNodeRef(assertion_index=made.outer_index)
        bodies.append(assertion_pb2.AssertionBody(bind_type_name=assertion_pb2.BindTypeName(type=ref)))
        return bodies
    if function is not None:
        target = assertion_pb2.Target(local=assertion_pb2.LocalVariableRef(function=address(function), storage_key=storage_key))
        spec = assertion_pb2.TypeSpec(type_hash=made.pointer_hash)
        bodies.append(assertion_pb2.AssertionBody(retype=assertion_pb2.Retype(target=target, type=spec)))
    elif at is not None:
        bodies.append(define_data_body(at, type_hash=made.struct_hash))
    return bodies


@dataclass
class _Stubs:
    auth: auth_pb2_grpc.AuthServiceStub
    meta: meta_pb2_grpc.MetaServiceStub
    projects: project_pb2_grpc.ProjectServiceStub
    assertions: assertion_pb2_grpc.AssertionServiceStub
    queries: query_pb2_grpc.QueryServiceStub
    subscriptions: subscription_pb2_grpc.SubscriptionServiceStub
    analysis: analysis_pb2_grpc.AnalysisServiceStub
    plugins: plugin_pb2_grpc.PluginServiceStub
    presence: presence_pb2_grpc.PresenceServiceStub
    sync: sync_pb2_grpc.SyncServiceStub
    emulator: emulator_pb2_grpc.EmulatorServiceStub
    debugger: debugger_pb2_grpc.DebugServiceStub
    diff: diff_pb2_grpc.DiffServiceStub
    types: types_pb2_grpc.TypeServiceStub
    patch: patch_pb2_grpc.PatchServiceStub
    scripts: script_pb2_grpc.ScriptServiceStub
    filesystems: filesystem_pb2_grpc.FileSystemServiceStub
    bsim: bsim_pb2_grpc.BSimServiceStub
    providers: provider_pb2_grpc.ProviderServiceStub


class Client:
    """A connection to rk-daemon over gRPC.

    ``actor`` is the default provenance for writes (``"user:<name>"``,
    ``"agent:<name>@<version>"``); against a daemon with authentication the
    server stamps the caller's identity, so leave it unset (or give only
    ``"@<version>"``). ``session`` groups this client's edits so they can be
    reverted together. ``timeout`` (seconds) applies to unary calls.

    Credentials and TLS (docs/security.md): ``token`` (default $RK_TOKEN or
    the first line of $RK_TOKEN_FILE) is sent as a bearer token; ``tls``,
    ``ca_cert`` (default $RK_TLS_CA) and ``fingerprint`` (default
    $RK_TLS_FINGERPRINT) choose how to trust the daemon (see make_channel).
    """

    def __init__(
        self,
        target: str = "127.0.0.1:50051",
        *,
        actor: Optional[str] = None,
        session: str = "",
        timeout: Optional[float] = 30.0,
        channel: Optional[grpc.Channel] = None,
        token: Optional[str] = None,
        tls: Optional[bool] = None,
        ca_cert: Optional[str] = None,
        fingerprint: Optional[str] = None,
        server_name: Optional[str] = None,
    ):
        self.target = target
        self.token = token if token is not None else _env_token()
        self._tls = dict(
            tls=tls if tls is not None else (True if os.environ.get("RK_TLS") == "1" else None),
            ca_cert=ca_cert if ca_cert is not None else os.environ.get("RK_TLS_CA") or None,
            fingerprint=fingerprint if fingerprint is not None else os.environ.get("RK_TLS_FINGERPRINT") or None,
            server_name=server_name,
        )
        self._channel = channel or make_channel(target, token=self.token, **self._tls)
        self._stubs = _Stubs(
            auth=auth_pb2_grpc.AuthServiceStub(self._channel),
            meta=meta_pb2_grpc.MetaServiceStub(self._channel),
            projects=project_pb2_grpc.ProjectServiceStub(self._channel),
            assertions=assertion_pb2_grpc.AssertionServiceStub(self._channel),
            queries=query_pb2_grpc.QueryServiceStub(self._channel),
            subscriptions=subscription_pb2_grpc.SubscriptionServiceStub(self._channel),
            analysis=analysis_pb2_grpc.AnalysisServiceStub(self._channel),
            plugins=plugin_pb2_grpc.PluginServiceStub(self._channel),
            presence=presence_pb2_grpc.PresenceServiceStub(self._channel),
            sync=sync_pb2_grpc.SyncServiceStub(self._channel),
            emulator=emulator_pb2_grpc.EmulatorServiceStub(self._channel),
            debugger=debugger_pb2_grpc.DebugServiceStub(self._channel),
            diff=diff_pb2_grpc.DiffServiceStub(self._channel),
            types=types_pb2_grpc.TypeServiceStub(self._channel),
            patch=patch_pb2_grpc.PatchServiceStub(self._channel),
            scripts=script_pb2_grpc.ScriptServiceStub(self._channel),
            filesystems=filesystem_pb2_grpc.FileSystemServiceStub(self._channel),
            bsim=bsim_pb2_grpc.BSimServiceStub(self._channel),
            providers=provider_pb2_grpc.ProviderServiceStub(self._channel),
        )
        if actor is None:
            # With credentials the server knows who we are; without, keep the
            # old default for daemons running --no-auth.
            actor = "" if self.token else "user:unknown"
        self.provenance = provenance(actor, session=session)
        self.timeout = timeout

    @classmethod
    def login(cls, target: str, username: str, password: str, **kwargs) -> "Client":
        """Logs in (AuthService.Login) and returns a client using the session token.
        Takes Client's keyword arguments (TLS options, actor, ...)."""
        tls = {k: kwargs[k] for k in ("tls", "ca_cert", "fingerprint", "server_name") if k in kwargs}
        if "tls" not in tls and os.environ.get("RK_TLS") == "1":
            tls["tls"] = True
        tls.setdefault("ca_cert", os.environ.get("RK_TLS_CA") or None)
        tls.setdefault("fingerprint", os.environ.get("RK_TLS_FINGERPRINT") or None)
        channel = make_channel(target, **tls)
        try:
            stub = auth_pb2_grpc.AuthServiceStub(channel)
            resp = stub.Login(
                auth_pb2.LoginRequest(username=username, password=password, client=f"revkit-py/{__version__}"),
                timeout=kwargs.get("timeout", 30.0),
            )
        except grpc.RpcError as e:
            raise _error(e) from None
        finally:
            channel.close()
        return cls(target, token=resp.token, **kwargs)

    # -- plumbing --------------------------------------------------------------

    def _call(self, method, request, timeout: Union[float, None, str] = "default"):
        try:
            return method(request, timeout=self.timeout if timeout == "default" else timeout)
        except grpc.RpcError as e:
            raise _error(e) from None

    @property
    def stubs(self) -> _Stubs:
        """The raw generated stubs, for anything the wrapper does not cover."""
        return self._stubs

    def close(self):
        self._channel.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc):
        self.close()

    def _prov(self, actor, reason: str = "") -> common_pb2.Provenance:
        if actor is None:
            p = common_pb2.Provenance()
            p.CopyFrom(self.provenance)
        else:
            p = provenance(actor, session=self.provenance.session)
        if reason:
            p.reason = reason
        return p

    # -- meta and projects -------------------------------------------------------

    # -- scripts the daemon runs (api_minor 31, feature "scripts-host") ---------------

    def list_scripts(self, project_id: str = "") -> script_pb2.ListScriptsResponse:
        """The daemon's script libraries (shipped, per-user and, with
        ``project_id``, the project's) with their metadata; ``host_enabled``
        says whether it runs scripts for this caller."""
        return self._call(self._stubs.scripts.ListScripts, script_pb2.ListScriptsRequest(project_id=project_id))

    def script_source(self, script_id: str) -> script_pb2.GetScriptResponse:
        """A script's metadata and source (``.script``, ``.source``)."""
        return self._call(self._stubs.scripts.GetScript, script_pb2.GetScriptRequest(script_id=script_id))

    def save_script(self, file_name: str, source: str, *, project_id: str = "",
                    expected_sha256: str = "") -> script_pb2.ScriptInfo:
        """Writes a per-user script (or the project's, with ``project_id``);
        ``expected_sha256`` is the hash last read, to replace one."""
        lib = script_pb2.SCRIPT_LIBRARY_PROJECT if project_id else script_pb2.SCRIPT_LIBRARY_USER
        return self._call(self._stubs.scripts.SaveScript, script_pb2.SaveScriptRequest(
            library=lib, project_id=project_id, file_name=file_name, source=source,
            expected_sha256=expected_sha256)).script

    def setup_script_python(self, *, force: bool = False, output: Optional[Callable[[str], None]] = None,
                            timeout: Optional[float] = None) -> script_pb2.SetupScriptPythonResult:
        """Makes the Python environment the daemon runs scripts with
        (``~/.local/share/revkit/pyenv`` on the daemon's machine, as
        ``rk-script setup`` does) when ``list_scripts().python_problem`` says
        there is none (api_minor 33, feature "scripts-setup"). ``output`` gets
        what the steps print as it comes; the result has ``ok``, ``python``
        and ``error``."""
        try:
            for ev in self._stubs.scripts.SetupScriptPython(script_pb2.SetupScriptPythonRequest(force=force),
                                                            timeout=timeout):
                if ev.HasField("result"):
                    return ev.result
                if output is not None:
                    output(ev.output)
        except grpc.RpcError as e:
            raise _error(e) from None
        raise RevkitError(grpc.StatusCode.INTERNAL, "SetupScriptPython ended without a result")

    def script_runs(self, program_id: str = "", limit: int = 50) -> Sequence[script_pb2.ScriptRun]:
        """Recent runs (this caller's; an admin's: everyone's), newest first."""
        return self._call(self._stubs.scripts.ListScriptRuns,
                          script_pb2.ListScriptRunsRequest(program_id=program_id, limit=limit)).runs

    def run_script(
        self,
        script_id: str,
        program_id: str,
        *,
        args: Optional[dict] = None,
        address: Optional[AddressLike] = None,
        selection: Optional[tuple] = None,
        confirm_sha256: str = "",
        reason: str = "",
        timeout: Optional[float] = None,
    ) -> "ScriptRun":
        """Starts a script on the daemon (``"shipped/batch_decompile.py"``,
        ``"user/x.py"``, ``"project/default/x.py"``). Iterate the returned
        :class:`ScriptRun` for its events (output, progress, prompts) and
        answer prompts with ``run.answer``; or call ``run.wait()``. ``args``
        fill the script's ``args`` and answer prompts of those names."""
        ctx = script_pb2.ScriptContext()
        if address is not None:
            ctx.address.CopyFrom(globals()["address"](address))
        if selection is not None:
            ctx.selection.CopyFrom(address_range(*selection))
        req = script_pb2.RunScriptRequest(script_id=script_id, program_id=program_id,
                                          args={k: str(v) for k, v in (args or {}).items()}, context=ctx,
                                          confirm_sha256=confirm_sha256, reason=reason)
        return ScriptRun(self, self._stubs.scripts.RunScript(req, timeout=timeout))

    def console(self, program_id: str, *, ghidra_names: bool = False) -> "ScriptConsole":
        """The caller's Python console of a program on the daemon (api_minor
        43, feature "script-console"): ``console.run("x = 1")``,
        ``console.complete("current_program.fu")``, ``console.interrupt()``,
        ``console.close()``. The host lives on the daemon between calls (and
        between clients: the same caller and program share it)."""
        return ScriptConsole(self, program_id, ghidra_names=ghidra_names)

    # -- identity (api_minor 13, feature "auth") -----------------------------------

    def whoami(self) -> auth_pb2.WhoAmIResponse:
        """Who the daemon takes this client for (``auth_enabled`` false: --no-auth)."""
        return self._call(self._stubs.auth.WhoAmI, auth_pb2.WhoAmIRequest())

    def logout(self) -> None:
        """Ends this client's session (a Login token); API tokens are revoked by an admin."""
        self._call(self._stubs.auth.Logout, auth_pb2.LogoutRequest())

    def server_info(self) -> meta_pb2.GetServerInfoResponse:
        return self._call(self._stubs.meta.GetServerInfo, meta_pb2.GetServerInfoRequest(client=f"revkit-py/{__version__}"))

    def projects(self) -> Sequence[project_pb2.ProjectInfo]:
        return self._call(self._stubs.projects.ListProjects, project_pb2.ListProjectsRequest()).projects

    # -- Function ID databases (api_minor 49, feature "function-id"; docs/fid.md) -------

    _FID_SCOPES = {"user": 2, "project": 3}

    def fid_databases(self, project_id: str = "default") -> List[analysis_pb2.FidDatabase]:
        """Function ID's databases: Ghidra's shipped ones (``scope`` BUILTIN), the
        caller's (USER) and the project's (PROJECT), with ``attached``, their
        libraries and function counts."""
        req = analysis_pb2.ListFidDatabasesRequest(project_id=project_id)
        return list(self._call(self._stubs.analysis.ListFidDatabases, req).databases)

    def attach_fid_database(self, path: str, *, scope: str = "user", project_id: str = "default",
                            actor: Optional[str] = None, reason: str = "") -> analysis_pb2.FidDatabase:
        """Attaches a .fidbf (Ghidra's) or .rkfid file on the daemon's host for the caller
        (``scope="user"``) or the project (``"project"``); a ``builtin:<name>`` id attaches a
        detached builtin again. Needs the admin role (the daemon reads the file)."""
        req = analysis_pb2.AttachFidDatabaseRequest(project_id=project_id, path=path,
                                                    scope=self._FID_SCOPES[scope],
                                                    provenance=self._prov(actor, reason))
        return self._call(self._stubs.analysis.AttachFidDatabase, req).database

    def detach_fid_database(self, id: str, *, scope: str = "user", project_id: str = "default",
                            actor: Optional[str] = None, reason: str = "") -> None:
        """Detaches a database (its ``id``: a path, or ``builtin:<name>``) for the caller or
        the project."""
        req = analysis_pb2.DetachFidDatabaseRequest(project_id=project_id, id=id, scope=self._FID_SCOPES[scope],
                                                    provenance=self._prov(actor, reason))
        self._call(self._stubs.analysis.DetachFidDatabase, req)

    def create_fid_database(self, path: str, program_ids: Sequence[str], family: str, *, version: str = "",
                            variant: str = "", common_symbols: Sequence[str] = (), attach: Optional[str] = None,
                            project_id: str = "default", actor: Optional[str] = None,
                            reason: str = "") -> analysis_pb2.CreateFidDatabaseResponse:
        """Writes a .rkfid database at ``path`` (on the daemon's host) from programs of the
        project that have symbols: one library ``family``/``version``/``variant``. ``attach``
        ("user" or "project") attaches it too. Needs the admin role."""
        req = analysis_pb2.CreateFidDatabaseRequest(
            project_id=project_id, program_ids=list(program_ids), path=path, family=family, version=version,
            variant=variant, common_symbols=list(common_symbols), attach=self._FID_SCOPES.get(attach or "", 0),
            provenance=self._prov(actor, reason))
        return self._call(self._stubs.analysis.CreateFidDatabase, req)

    # -- External decompilers (api_minor 92, feature "external-decompilers"; docs/providers.md) --

    # A run waits for the tool (120 s by default, the daemon's timeout).
    _EXTERNAL_TIMEOUT = 900.0

    @staticmethod
    def _provider_input(program_id: Optional[str] = None, filesystem: Optional["FileSystem"] = None,
                        path: Optional[str] = None) -> provider_pb2.ProviderInput:
        if program_id:
            return provider_pb2.ProviderInput(program_id=program_id)
        if filesystem is not None and path:
            return provider_pb2.ProviderInput(file=provider_pb2.ProviderFileRef(
                session_id=filesystem.session_id, path=path))
        raise ValueError("a program_id, or a filesystem and a path")

    def providers(self, *, program_id: Optional[str] = None, filesystem: Optional["FileSystem"] = None,
                  path: Optional[str] = None, refresh: bool = False) -> provider_pb2.ListProvidersResponse:
        """The external decompilers (``ListProviders``): ``.providers`` (``.name``,
        ``.available``, ``.version``, ``.kinds``, ``.reason``; ``.path`` for admins),
        ``.sandbox`` (what the daemon enforces) and ``.limits``. With a program or a
        file of an open file system: ``.input_kind`` (``.kind`` "dotnet", "dex",
        "apk", "jar", "class", "pyc", "lua", "wasm", "js"), ``.applicable``,
        ``.default_provider`` and ``.cached``. ``refresh`` looks for the tools again."""
        req = provider_pb2.ListProvidersRequest(refresh=refresh)
        if program_id or filesystem is not None:
            req.input.CopyFrom(self._provider_input(program_id, filesystem, path))
        return self._call(self._stubs.providers.ListProviders, req, timeout=self._EXTERNAL_TIMEOUT)

    def decompile_external(self, *, program_id: Optional[str] = None, filesystem: Optional["FileSystem"] = None,
                           path: Optional[str] = None, provider: str = "", refresh: bool = False,
                           max_inline_bytes: int = 0) -> "ExternalDecompilation":
        """Runs an external decompiler (ILSpy, jadx, Vineflower, CFR, unluac, pycdc,
        webcrack, wasm-decompile) on a program's file or a file of an open file system
        (``DecompileExternal``), in the daemon's sandbox, or answers from its cache.
        ``provider`` empty: the default for the input's kind. Returns an
        :class:`ExternalDecompilation` (``.ok``, ``.files``, ``.text()``)."""
        inp = self._provider_input(program_id, filesystem, path)
        resp = self._call(self._stubs.providers.DecompileExternal, provider_pb2.DecompileExternalRequest(
            input=inp, provider=provider, refresh=refresh, max_inline_bytes=max_inline_bytes),
            timeout=self._EXTERNAL_TIMEOUT)
        return ExternalDecompilation(self, inp, resp)

    def provider_settings(self) -> provider_pb2.GetProviderSettingsResponse:
        """The external decompilers' settings (admin): ``.settings`` (``.enabled``,
        ``.providers`` with ``.name``, ``.path``, ``.disabled``; ``.java_path``,
        ``.node_path``, ``.dotnet_root``; the limits) and ``.cache_dir``."""
        return self._call(self._stubs.providers.GetProviderSettings, provider_pb2.GetProviderSettingsRequest())

    def set_provider_settings(self, settings: provider_pb2.ProviderSettings) -> provider_pb2.SetProviderSettingsResponse:
        """Replaces the settings (admin; start from :meth:`provider_settings`), keeps them
        beside the projects, and answers the providers as they now resolve."""
        return self._call(self._stubs.providers.SetProviderSettings,
                          provider_pb2.SetProviderSettingsRequest(settings=settings),
                          timeout=self._EXTERNAL_TIMEOUT)

    # -- BSim databases (api_minor 69, feature "bsim"; docs/bsim.md) -----------------------

    _BSIM_TEMPLATES = {"": 0, "64": 1, "32": 2, "nosize": 3}

    def bsim_databases(self, project_id: str = "default") -> List[bsim_pb2.BSimDatabase]:
        """The project's BSim databases (``id`` is the path the other calls take), with their
        executable and function counts; ``error`` says why one can't be opened."""
        req = bsim_pb2.ListBSimDatabasesRequest(project_id=project_id)
        return list(self._call(self._stubs.bsim.ListBSimDatabases, req).databases)

    def create_bsim_database(self, name: str = "", *, path: str = "", template: str = "", description: str = "",
                             lsh_k: int = 0, lsh_l: int = 0, project_id: str = "default",
                             actor: Optional[str] = None, reason: str = "") -> bsim_pb2.BSimDatabase:
        """Creates a database and attaches it to the project: ``path`` (a new directory on the
        daemon's host; admin) or, without one, ``bsim/<name>.rkbsim`` in the project's
        directory. ``template`` "64", "32" or "nosize" (programs of different pointer sizes)."""
        req = bsim_pb2.CreateBSimDatabaseRequest(
            project_id=project_id, path=path, name=name, description=description,
            template=self._BSIM_TEMPLATES[template], lsh_k=lsh_k, lsh_l=lsh_l, provenance=self._prov(actor, reason))
        return self._call(self._stubs.bsim.CreateBSimDatabase, req).database

    def attach_bsim_database(self, path: str, *, project_id: str = "default", actor: Optional[str] = None,
                             reason: str = "") -> bsim_pb2.BSimDatabase:
        """Attaches an existing database (a directory on the daemon's host; admin)."""
        req = bsim_pb2.AttachBSimDatabaseRequest(project_id=project_id, path=path, provenance=self._prov(actor, reason))
        return self._call(self._stubs.bsim.AttachBSimDatabase, req).database

    def detach_bsim_database(self, database: str, *, project_id: str = "default", actor: Optional[str] = None,
                             reason: str = "") -> None:
        """Detaches a database from the project; its files stay."""
        req = bsim_pb2.DetachBSimDatabaseRequest(project_id=project_id, database=database,
                                                 provenance=self._prov(actor, reason))
        self._call(self._stubs.bsim.DetachBSimDatabase, req)

    def bsim_ingest(self, database: str, program_ids: Sequence[str], *, categories: Optional[dict] = None,
                    threads: int = 0, project_id: str = "default") -> List[bsim_pb2.BSimIngested]:
        """Signs every function of each program and stores it in ``database``, replacing an
        earlier ingest of the same file; one ``BSimIngested`` per program (``functions``
        stored, ``excluded`` by reason, ``executable``)."""
        req = bsim_pb2.IngestBSimRequest(project_id=project_id, database=database, program_ids=list(program_ids),
                                         categories=dict(categories or {}), threads=threads)
        return list(self._call(self._stubs.bsim.IngestBSim, req).programs)

    def bsim_executables(self, database: str, *, filter: str = "", language: str = "",
                         project_id: str = "default") -> List[bsim_pb2.BSimExecutable]:
        req = bsim_pb2.ListBSimExecutablesRequest(project_id=project_id, database=database, filter=filter,
                                                  language=language)
        return list(self._call(self._stubs.bsim.ListBSimExecutables, req).executables)

    def bsim_functions(self, database: str, executable: str, *, name_contains: str = "", offset: int = 0,
                       limit: int = 0, project_id: str = "default") -> bsim_pb2.ListBSimFunctionsResponse:
        """An executable's functions (``executable``: its id, a unique id prefix or its name)."""
        req = bsim_pb2.ListBSimFunctionsRequest(project_id=project_id, database=database, executable=executable,
                                                name_contains=name_contains, offset=offset, limit=limit)
        return self._call(self._stubs.bsim.ListBSimFunctions, req)

    def update_bsim_executable(self, database: str, executable: str, *, name: str = "",
                               categories: Optional[dict] = None, project_id: str = "default") -> bsim_pb2.BSimExecutable:
        """Renames an executable or replaces its categories (when ``categories`` is given)."""
        req = bsim_pb2.UpdateBSimExecutableRequest(project_id=project_id, database=database, executable=executable,
                                                   name=name, categories=dict(categories or {}),
                                                   set_categories=categories is not None)
        return self._call(self._stubs.bsim.UpdateBSimExecutable, req).executable

    def bsim_search(self, database: str, program_id: str, functions: Sequence[AddressLike] = (), *,
                    all_functions: bool = False, min_similarity: Optional[float] = None,
                    min_confidence: Optional[float] = None, max_matches: int = 0, executables: Sequence[str] = (),
                    exclude_executables: Sequence[str] = (), include_self: bool = False, languages: Sequence[str] = (),
                    name_contains: str = "", categories: Optional[dict] = None, exclude_default_names: bool = False,
                    overview: bool = False, exhaustive: bool = False, index_only: bool = False, threads: int = 0,
                    project_id: str = "default") -> bsim_pb2.SearchBSimResponse:
        """Functions similar to the program's (``functions``: entries or addresses inside them;
        or ``all_functions``) in ``database`` (api_minor 72, feature "bsim-search"). Per
        function its matches, best first (similarity: cosine, default threshold 0.7; confidence:
        BSim's significance), at most ``max_matches`` (default 10), with ``hit_count`` and, for a
        match whose file is a program of the project, its ``program_id``. ``overview``: only the
        counts. The query's own file is left out unless ``include_self``."""
        req = bsim_pb2.SearchBSimRequest(
            project_id=project_id, database=database, program_id=program_id,
            functions=[address(f) for f in functions], all_functions=all_functions, max_matches=max_matches,
            executables=list(executables), exclude_executables=list(exclude_executables),
            include_self=include_self, languages=list(languages), name_contains=name_contains,
            categories=dict(categories or {}), exclude_default_names=exclude_default_names, overview=overview,
            exhaustive=exhaustive, index_only=index_only, threads=threads)
        if min_similarity is not None:
            req.min_similarity = min_similarity
        if min_confidence is not None:
            req.min_confidence = min_confidence
        return self._call(self._stubs.bsim.SearchBSim, req)

    _BSIM_APPLY_KINDS = {"name": bsim_pb2.BSIM_APPLY_KIND_NAME, "signature": bsim_pb2.BSIM_APPLY_KIND_SIGNATURE,
                         "signature_and_types": bsim_pb2.BSIM_APPLY_KIND_SIGNATURE_AND_TYPES,
                         "types": bsim_pb2.BSIM_APPLY_KIND_SIGNATURE_AND_TYPES}

    def bsim_apply(self, database: str, program_id: str, pairs: Sequence, kind: Union[str, int] = "name", *,
                   overwrite: bool = False, dry_run: bool = False, database_only: bool = False,
                   project_id: str = "default", actor: Optional[str] = None,
                   reason: str = "") -> bsim_pb2.ApplyBSimMatchesResponse:
        """Applies BSim matches to the program's functions (api_minor 76, feature "bsim-apply";
        docs/bsim.md, "Applying matches"), as Ghidra's BSim results do. ``pairs``: each a
        ``(function, match)`` with ``match`` a ``BSimMatch`` from ``bsim_search`` (its
        executable and function), or ``(function, executable, match_entry)``, or a
        ``BSimApplyPair``. ``kind``: ``"name"``, ``"signature"`` (the name and a skeleton
        signature: types the program lacks become empty placeholder structures) or
        ``"signature_and_types"`` (with the types themselves, when the match's file is a
        program of the project). Without ``overwrite`` a name goes only over a default one and
        a signature only over a guess. Every pair in one revision: retracting ``seqs`` undoes
        it. Per pair ``results`` say what happened (status, message, before and after)."""
        out = []
        for p in pairs:
            if isinstance(p, bsim_pb2.BSimApplyPair):
                out.append(p)
                continue
            p = tuple(p)
            if len(p) == 2:
                fn, m = p
                exe, entry = m.executable.id, m.function.entry.offset
            elif len(p) == 3:
                fn, exe, entry = p
            else:
                raise ValueError("a pair is (function, match) or (function, executable, match_entry)")
            out.append(bsim_pb2.BSimApplyPair(function=address(fn), executable=exe, match=address(entry)))
        k = self._BSIM_APPLY_KINDS.get(kind, kind) if isinstance(kind, str) else kind
        if isinstance(k, str):
            raise ValueError(f"kind: one of {sorted(self._BSIM_APPLY_KINDS)}")
        req = bsim_pb2.ApplyBSimMatchesRequest(
            project_id=project_id, database=database, program_id=program_id, pairs=out, kind=k,
            overwrite=overwrite, dry_run=dry_run, database_only=database_only, provenance=self._prov(actor, reason))
        return self._call(self._stubs.bsim.ApplyBSimMatches, req)

    def delete_bsim_executables(self, database: str, executables: Sequence[str], *,
                                project_id: str = "default") -> bsim_pb2.DeleteBSimExecutablesResponse:
        req = bsim_pb2.DeleteBSimExecutablesRequest(project_id=project_id, database=database,
                                                    executables=list(executables))
        return self._call(self._stubs.bsim.DeleteBSimExecutables, req)

    def open_project(
        self, project_id: str = "", *, path: str = "", create: bool = False, name: str = ""
    ) -> project_pb2.OpenProjectResponse:
        req = project_pb2.OpenProjectRequest(create_if_missing=create, name=name)
        if path:
            req.path = path
        else:
            req.project_id = project_id
        return self._call(self._stubs.projects.OpenProject, req)

    def close_project(self, project_id: str) -> None:
        self._call(self._stubs.projects.CloseProject, project_pb2.CloseProjectRequest(project_id=project_id))

    def compact_project(self, project_id: str, *, drop_caches: bool = False, cache_limit_mb: int = 0,
                        dry_run: bool = False) -> project_pb2.CompactProjectResponse:
        """Shrinks a closed project's store on disk (``CompactProject``, api_minor 104,
        feature "compact"; docs/backend.md, "Compaction"): stale memos dropped
        (every memo with ``drop_caches``, or those used longest ago beyond
        ``cache_limit_mb``), then the file rewritten without its free pages.
        The log is kept whole. Close the project first; reopen it after.
        Needs admin."""
        req = project_pb2.CompactProjectRequest(project_id=project_id, drop_caches=drop_caches,
                                                cache_limit_bytes=cache_limit_mb << 20, dry_run=dry_run)
        return self._call(self._stubs.projects.CompactProject, req, timeout=None)

    def programs(self, project_id: str, *, include_deleted: bool = False) -> Sequence[project_pb2.ProgramInfo]:
        req = project_pb2.ListProgramsRequest(project_id=project_id, include_deleted=include_deleted)
        return self._call(self._stubs.projects.ListPrograms, req).programs

    def rename_program(self, program_id: str, name: str) -> project_pb2.RenameProgramResponse:
        """Gives a program a new display name (feature ``program-management``);
        retract ``response.assertion.seq`` to undo it. An empty name restores the imported one."""
        req = project_pb2.RenameProgramRequest(program_id=program_id, name=name, provenance=self.provenance)
        return self._call(self._stubs.projects.RenameProgram, req)

    def libraries(self, program_id: str, *, include_imports: bool = False) -> project_pb2.ListProgramLibrariesResponse:
        """A program's shared libraries (api_minor 70, feature ``program-libraries``):
        each needed library (``name``, the ``program_id`` it resolves to, ``resolution``:
        LINKED, NAME, SONAME or NONE, ``imports_resolved``), its own first, then theirs;
        with ``include_imports``, every import and the library function it goes to."""
        req = project_pb2.ListProgramLibrariesRequest(program_id=program_id, include_imports=include_imports)
        return self._call(self._stubs.projects.ListProgramLibraries, req)

    def link_library(self, program_id: str, library: str, target_program_id: str = "") -> project_pb2.LinkProgramLibraryResponse:
        """Says which project program a library ``program_id`` needs is (an assertion:
        retract ``response.assertion.seq`` to undo); an empty target finds it by name again."""
        req = project_pb2.LinkProgramLibraryRequest(
            program_id=program_id, library=library, target_program_id=target_program_id, provenance=self.provenance
        )
        return self._call(self._stubs.projects.LinkProgramLibrary, req)

    def resolve_import(self, program_id: str, *, name: str = "", address: Optional[int] = None) -> project_pb2.ResolvedImport:
        """Where an import goes, by its name or its thunk's or slot's address: the library
        (``library``), its program (``program_id``), the function's ``address`` there and its
        ``function_name``; ``resolved`` is False when no library program exports it."""
        req = project_pb2.ResolveImportRequest(program_id=program_id)
        if address is not None:
            req.address.offset = address
        elif name:
            req.name = name
        else:
            raise ValueError("name or address is required")
        return self._call(self._stubs.projects.ResolveImport, req).resolved

    def library_importers(
        self,
        program_id: str,
        *,
        address: Optional[int] = None,
        name: str = "",
        include_references: bool = True,
        max_references: int = 0,
    ) -> query_pb2.ListLibraryImportersResponse:
        """References back from a library (api_minor 81, feature ``library-importers``):
        the project's programs whose imports resolve to ``program_id``, each import that does
        (``importers[].resolved``: its name, thunk and slot in the importer, the function's
        ``address`` here), and with ``include_references`` the importer's references to it
        (``importers[].references``, at most ``max_references`` each, default 50). One export
        by ``address`` (the function there) or ``name``; neither: every import of the library."""
        req = query_pb2.ListLibraryImportersRequest(
            program_id=program_id, include_references=include_references, max_references=max_references)
        if address is not None:
            req.address.offset = address
        elif name:
            req.name = name
        return self._call(self._stubs.queries.ListLibraryImporters, req)

    def delete_program(self, program_id: str) -> project_pb2.DeleteProgramResponse:
        """Deletes a program softly (feature ``program-management``): hidden from
        ``programs()``, its data kept; ``restore_program`` brings it back."""
        req = project_pb2.DeleteProgramRequest(program_id=program_id, provenance=self.provenance)
        return self._call(self._stubs.projects.DeleteProgram, req)

    def restore_program(self, program_id: str) -> None:
        """Undoes a DeleteProgram by retracting the deletion."""
        for p in self.programs(program_id.split("/")[0], include_deleted=True):
            if p.program_id == program_id and p.deleted:
                req = assertion_pb2.RetractAssertionsRequest(
                    program_id=program_id, seqs=[p.deleted_origin.asserted.seq], provenance=self.provenance
                )
                self._call(self._stubs.assertions.RetractAssertions, req)
                return
        raise RevkitError(grpc.StatusCode.FAILED_PRECONDITION, f"program {program_id} is not deleted")

    # -- folders (api_minor 37, feature "project-folders") ----------------------
    #
    # A folder is named by its id or by its path ("/libs/json"; "/" or "" is
    # the root). Every edit is one revision; ``undo_project_edit`` retracts
    # it (``response.assertion.seq``, or every seq of a move).

    def folders(self, project_id: str) -> Sequence[project_pb2.ProjectFolder]:
        """Every folder of a project, parents first (``path``, ``folder_id``, ``parent_id``)."""
        req = project_pb2.ListProgramsRequest(project_id=project_id)
        return self._call(self._stubs.projects.ListPrograms, req).folders

    def folder_id(self, project_id: str, folder: str, *, create: bool = False) -> str:
        """A folder's id from its path (or its id, returned as is); "" for the
        root. ``create`` makes the missing folders along the path."""
        if not folder or folder == "/":
            return ""
        if not folder.startswith("/"):
            return folder
        path = folder.rstrip("/")
        by_path = {f.path: f.folder_id for f in self.folders(project_id)}
        if path in by_path:
            return by_path[path]
        if not create:
            raise RevkitError(grpc.StatusCode.NOT_FOUND, f"no folder {path} in project {project_id}")
        parent, name = path.rsplit("/", 1)
        return self.create_folder(project_id, name, parent=self.folder_id(project_id, parent or "/", create=True)).folder.folder_id

    def create_folder(self, project_id: str, name: str, *, parent: str = "") -> project_pb2.CreateFolderResponse:
        """Creates a folder in ``parent`` (an id or a path; default the root).
        ``name`` may also be a whole path ("/a/b"): its parents must exist."""
        if name.startswith("/"):
            parent, name = name.rstrip("/").rsplit("/", 1)
            parent = parent or "/"
        req = project_pb2.CreateFolderRequest(project_id=project_id, parent_id=self.folder_id(project_id, parent),
                                              name=name, provenance=self.provenance)
        return self._call(self._stubs.projects.CreateFolder, req)

    def rename_folder(self, project_id: str, folder: str, name: str) -> project_pb2.RenameFolderResponse:
        req = project_pb2.RenameFolderRequest(project_id=project_id, folder_id=self.folder_id(project_id, folder),
                                              name=name, provenance=self.provenance)
        return self._call(self._stubs.projects.RenameFolder, req)

    def delete_folder(self, project_id: str, folder: str) -> project_pb2.DeleteFolderResponse:
        """Deletes an empty folder (no subfolders, no listed programs)."""
        req = project_pb2.DeleteFolderRequest(project_id=project_id, folder_id=self.folder_id(project_id, folder),
                                              provenance=self.provenance)
        return self._call(self._stubs.projects.DeleteFolder, req)

    def move_to_folder(
        self, project_id: str, folder: str, *, programs: Sequence[str] = (), folders: Sequence[str] = ()
    ) -> project_pb2.MoveToFolderResponse:
        """Moves programs (by id) and folders (ids or paths) into ``folder`` in
        one revision; ``undo_project_edit(project_id, [a.seq for a in resp.assertions])`` undoes it."""
        req = project_pb2.MoveToFolderRequest(
            project_id=project_id, folder_id=self.folder_id(project_id, folder), program_ids=list(programs),
            folder_ids=[self.folder_id(project_id, f) for f in folders], provenance=self.provenance)
        return self._call(self._stubs.projects.MoveToFolder, req)

    def undo_project_edit(self, project_id: str, seqs: Sequence[int]) -> assertion_pb2.RetractAssertionsResponse:
        """Retracts ops of a project by seq: folder edits, or any of its programs' (api_minor 37)."""
        req = assertion_pb2.RetractAssertionsRequest(project_id=project_id, seqs=list(seqs), provenance=self.provenance)
        return self._call(self._stubs.assertions.RetractAssertions, req)

    # -- project archives (api_minor 37, feature "project-archive") -------------

    def export_project(
        self,
        project_id: str,
        path: Union[str, os.PathLike, None] = None,
        *,
        programs: Sequence[str] = (),
        folders: Sequence[str] = (),
        annotations_only: bool = False,
        host_path: str = "",
        timeout: Optional[float] = None,
    ):
        """Exports a project (or ``programs`` and every program under
        ``folders``, ids or paths) as a .rkproj archive. With ``path`` the
        archive is written there and its ``ExportSummary`` returned; without,
        ``(summary, bytes)``. ``host_path`` makes the daemon write it on its
        own host instead (admin). ``annotations_only`` leaves the programs'
        files out (they are found again by sha256 on import)."""
        req = project_pb2.ExportProjectRequest(
            project_id=project_id, program_ids=list(programs),
            folder_ids=[self.folder_id(project_id, f) for f in folders], annotations_only=annotations_only,
            host_path=host_path)
        summary = None
        out = open(path, "wb") if path is not None else None
        data = bytearray()
        try:
            for msg in self._stubs.projects.ExportProject(req, timeout=timeout):
                if msg.HasField("summary"):
                    summary = msg.summary
                elif out is not None:
                    out.write(msg.data)
                else:
                    data += msg.data
        except grpc.RpcError as e:
            if out is not None:
                out.close()
                os.unlink(path)
            raise _error(e) from None
        if out is not None:
            out.close()
            return summary
        return summary, bytes(data)

    def symbol_settings(self) -> project_pb2.SymbolSettings:
        """Where Load PDB looks PDBs up (``GetSymbolSettings``; an admin's):
        ``symbol_path`` (_NT_SYMBOL_PATH syntax), ``downloads`` (symbol
        servers may be contacted), ``cache_dir``."""
        return self._call(self._stubs.projects.GetSymbolSettings, project_pb2.GetSymbolSettingsRequest()).settings

    def set_symbol_settings(self, symbol_path: str, *, downloads: bool = False, cache_dir: str = "") -> project_pb2.SymbolSettings:
        """Sets the daemon's symbol path (``SetSymbolSettings``; an admin's).
        ``downloads`` lets it contact the servers the path names: network
        access on the daemon's host (docs/security.md). The debug file
        settings (``set_debug_file_settings``) stay as they are."""
        settings = project_pb2.SymbolSettings()
        settings.CopyFrom(self.symbol_settings())
        settings.symbol_path, settings.downloads, settings.cache_dir = symbol_path, downloads, cache_dir
        req = project_pb2.SetSymbolSettingsRequest(settings=settings)
        return self._call(self._stubs.projects.SetSymbolSettings, req).settings

    def debuginfod_suggestions(self) -> list:
        """The servers the daemon's DEBUGINFOD_URLS names: a suggestion, never
        used unless set with ``set_debug_file_settings(urls=...)``."""
        r = self._call(self._stubs.projects.GetSymbolSettings, project_pb2.GetSymbolSettingsRequest())
        return list(r.suggested_debuginfod_urls)

    def set_debug_file_settings(
        self,
        *,
        dirs: Optional[Sequence[str]] = None,
        debuginfod: Optional[bool] = None,
        urls: Optional[Sequence[str]] = None,
        allow_http: Optional[bool] = None,
        max_bytes: Optional[int] = None,
        cache_max_bytes: Optional[int] = None,
    ) -> project_pb2.SymbolSettings:
        """Where ELF debug files are looked for and fetched (api_minor 86,
        feature ``debug-files``; ``SetSymbolSettings``, an admin's): ``dirs``
        searched as /usr/lib/debug is (build ID and debuglink), ``debuginfod``
        (contact the servers: network access, off by default), ``urls`` (https
        unless ``allow_http``), the largest file and the cache's size. What is
        left out (None) stays as it is; the symbol path too."""
        settings = project_pb2.SymbolSettings()
        settings.CopyFrom(self.symbol_settings())
        if dirs is not None:
            del settings.debug_dirs[:]
            settings.debug_dirs.extend(os.fspath(d) for d in dirs)
        if urls is not None:
            del settings.debuginfod_urls[:]
            settings.debuginfod_urls.extend(urls)
        if debuginfod is not None:
            settings.debuginfod = debuginfod
        if allow_http is not None:
            settings.debuginfod_allow_http = allow_http
        if max_bytes is not None:
            settings.debug_file_max_bytes = int(max_bytes)
        if cache_max_bytes is not None:
            settings.debug_cache_max_bytes = int(cache_max_bytes)
        req = project_pb2.SetSymbolSettingsRequest(settings=settings)
        return self._call(self._stubs.projects.SetSymbolSettings, req).settings

    def upload(self, source: Union[str, os.PathLike, bytes], *, file_name: str = "", chunk: int = 4 << 20) -> str:
        """Sends a local file (or bytes) to the daemon in pieces (UploadChunk);
        returns the upload id ImportProjectArchive takes (``archive`` or a
        binary). Uploads lapse an hour after their last piece."""
        if isinstance(source, (bytes, bytearray)):
            total, name, reader = len(source), file_name or "upload", None
            data = bytes(source)
        else:
            total, name = os.path.getsize(source), file_name or os.path.basename(str(source))
            reader, data = open(source, "rb"), b""
        upload_id, offset = "", 0
        try:
            while True:
                piece = reader.read(chunk) if reader else data[offset:offset + chunk]
                req = project_pb2.UploadChunkRequest(upload_id=upload_id, offset=offset, data=piece,
                                                     total_size=total if not upload_id else 0, file_name=name)
                resp = self._call(self._stubs.projects.UploadChunk, req)
                upload_id, offset = resp.upload_id, resp.received
                if resp.complete or not piece:
                    return upload_id
        finally:
            if reader:
                reader.close()

    def _archive_source(self, source, host: bool) -> project_pb2.ArchiveSource:
        if isinstance(source, project_pb2.ArchiveSource):
            return source
        if host:
            return project_pb2.ArchiveSource(path=str(source))
        if isinstance(source, (bytes, bytearray)) and len(source) <= (16 << 20):
            return project_pb2.ArchiveSource(content=bytes(source))
        return project_pb2.ArchiveSource(upload_id=self.upload(source))

    def import_project(
        self,
        archive: Union[str, os.PathLike, bytes],
        *,
        into: str = "",
        name: str = "",
        folder: str = "",
        binaries: Sequence[Union[str, os.PathLike, bytes]] = (),
        search_dir: str = "",
        skip_missing: bool = False,
        inspect: bool = False,
        on_host: bool = False,
        timeout: Optional[float] = None,
    ) -> project_pb2.ImportProjectArchiveResponse:
        """Imports a .rkproj: into a new project (``name``, default the
        archive's) or ``into`` an existing one as new programs, under
        ``folder`` (an id or path there). An annotations-only archive's
        binaries come from ``binaries`` (local files or bytes, uploaded and
        matched by sha256), programs already in ``into``, and ``search_dir``
        on the daemon's host. ``inspect`` only describes the archive and which
        binaries were found. Local files are uploaded; ``on_host`` names
        ``archive`` and ``binaries`` as paths on the daemon's host instead
        (admin)."""
        req = project_pb2.ImportProjectArchiveRequest(
            archive=self._archive_source(archive, on_host), project_id=into, new_project_name=name,
            folder_id=self.folder_id(into, folder) if into and folder else "",
            binaries=[self._archive_source(b, on_host) for b in binaries], search_dir=search_dir,
            skip_missing=skip_missing, inspect_only=inspect, provenance=self.provenance)
        return self._call(self._stubs.projects.ImportProjectArchive, req, timeout=timeout)

    def open_filesystem(
        self,
        project_id: str,
        *,
        host_path: str = "",
        program_id: str = "",
        file: Union[str, os.PathLike, bytes, None] = None,
        name: str = "",
        limits: Optional[dict] = None,
    ) -> "FileSystem":
        """Opens a container as a file system (api_minor 48, feature
        "filesystems"; docs/filesystems.md): an archive, a compressed file, a
        file system image or a firmware package, nested to any depth.

        The source is one of ``host_path`` (a file, or a directory for batch
        import, on the daemon's host: admin), ``program_id`` (a program's
        stored file: viewer) or ``file`` (a local path or bytes, sent to the
        daemon: admin). ``limits`` lowers the daemon's limits
        (``max_file_bytes``, ``max_total_bytes``, ``max_depth``,
        ``max_entries``, ``max_ratio``). Close it (or use ``with``) when done."""
        req = filesystem_pb2.OpenFileSystemRequest(project_id=project_id, name=name,
                                                   limits=filesystem_pb2.FileSystemLimits(**(limits or {})))
        if host_path:
            req.host_path = str(host_path)
        elif program_id:
            req.program_id = program_id
        elif isinstance(file, (bytes, bytearray)):
            if len(file) <= (16 << 20):
                req.content = bytes(file)
            else:
                req.upload_id = self.upload(file, file_name=name or "upload")
        elif file is not None:
            req.name = name or os.path.basename(str(file))
            if os.path.getsize(file) <= (16 << 20):
                with open(file, "rb") as f:
                    req.content = f.read()
            else:
                req.upload_id = self.upload(file)
        else:
            raise ValueError("open_filesystem needs host_path, program_id or file")
        return FileSystem(self, project_id, self._call(self._stubs.filesystems.OpenFileSystem, req))

    def filesystems(self) -> Sequence[filesystem_pb2.OpenFileSystemSession]:
        """The caller's open file system sessions (an admin's: everyone's)."""
        return self._call(self._stubs.filesystems.ListFileSystems, filesystem_pb2.ListFileSystemsRequest()).sessions

    def import_program(
        self,
        project_id: str,
        *,
        path: str = "",
        content: bytes = b"",
        name: str = "",
        analyze: bool = True,
        language_id: str = "",
        image_base: Optional[int] = None,
        format: str = "",
        progress: Optional[Callable[[project_pb2.GetImportProgressResponse], None]] = None,
        poll: float = 0.25,
        raw_offset: int = 0,
        regions: Sequence[Union[str, project_pb2.MemoryRegion]] = (),
        options: Optional[project_pb2.ImportOptions] = None,
        import_libraries: bool = False,
        library_search_paths: Sequence[str] = (),
        library_depth: int = 0,
        library_root: str = "",
        folder_id: str = "",
        macho_slice: str = "",
        program_file: str = "",
        memory_preset: str = "",
        on_conflict: str = "",
    ) -> project_pb2.ImportProgramResponse:
        """Imports a file. ``format`` forces "elf", "pe", "macho" or a loader plugin by
        name; by default the built-in loaders are tried, then loader plugins by magic.

        A universal (fat) Mach-O loads its arm64 slice by default, else its
        x86-64 one; ``macho_slice`` (api_minor 90, feature "macho") names
        another ("x86_64", "arm64e", "#1": the second). ``program_file`` imports
        the file of a program already in the project again, instead of
        ``path`` or ``content`` (another slice of it).

        A raw image (``format="raw"``) needs ``language_id`` and takes
        ``image_base``, ``raw_offset`` (a header to skip) and ``regions``
        (``MemoryRegion`` messages, or "name:start:size[:perms][:init|uninit|volatile]"
        with hex numbers). ``options`` gives the whole ``ImportOptions``
        instead, e.g. a suggestion of ``detect_raw_layout``
        (``suggestion.options``); the arguments above that are set override it.

        ``progress`` (api_minor 22, feature "import-progress") is called with
        a ``GetImportProgressResponse`` (``phase``, ``message``, ``progress``
        0..1 or -1, ``done``) every ``poll`` seconds while the import runs,
        from another thread, and once more when it has ended. Daemons
        without the feature import as before and never call it.

        ``import_libraries`` (api_minor 70, feature "program-libraries") also
        imports the shared libraries it needs that the project lacks, found in
        ``library_search_paths`` (directories on the daemon's host), beside the
        file and its runpath, then the host's library directories for a file
        imported by ``path``; ``library_depth`` levels deep (0: 2). They are in
        ``response.libraries``; those found nowhere in ``libraries_not_found``.
        ``library_root`` (api_minor 79, feature "library-roots") names the root
        file system they are in, a directory under the daemon's
        ``--browse-root`` (an extracted firmware root): ``/lib``, ``/usr/lib``,
        the runpath and ``/etc/ld.so.conf`` are read inside it instead of the
        host's. Without it, a file imported by ``path`` from such a tree under a
        ``--browse-root`` uses that tree (``response.library_root``).
        ``folder_id`` puts the program (and its libraries) in that folder.

        ``memory_preset`` (api_minor 104, feature "memory-preset") adds a
        platform's memory map to a raw image: "nds-arm9" or "nds-arm7" map the
        DS's I/O ports, shared WRAM and main memory's shared area as volatile
        memory. ``on_conflict`` (feature "import-conflict") says what a name
        already in the project does: "keep_both" (the default: ``name-2``,
        ``response.name_taken_by`` says which program had it), "replace" (that
        program is deleted, undoably, and the new one shows the name;
        ``response.replaced_program_id``) or "refuse" (``ALREADY_EXISTS``)."""
        opts = project_pb2.ImportOptions()
        if options is not None:
            opts.CopyFrom(options)
        opts.analyze = analyze
        if language_id:
            # "proc:endian:size:variant[:compiler]"
            fields = language_id.split(":")
            opts.language_id = ":".join(fields[:4])
            if len(fields) > 4:
                opts.compiler_spec_id = fields[4]
        if format:
            opts.format = format
        if image_base is not None:
            opts.has_image_base, opts.image_base = True, image_base
        if raw_offset:
            opts.raw_offset = raw_offset
        if regions:
            del opts.regions[:]
            opts.regions.extend(r if isinstance(r, project_pb2.MemoryRegion) else memory_region(r) for r in regions)
        if import_libraries:
            opts.import_libraries = True
        if library_search_paths:
            opts.library_search_paths.extend(library_search_paths)
        if library_depth:
            opts.library_depth = library_depth
        if library_root:
            opts.library_root = library_root
        if macho_slice:
            opts.macho_slice = macho_slice
        if memory_preset:
            opts.memory_preset = memory_preset
        req = project_pb2.ImportProgramRequest(project_id=project_id, name=name, options=opts, provenance=self.provenance,
                                               on_conflict=_choice(_NAME_CONFLICTS, on_conflict, "on_conflict"))
        if folder_id:
            req.folder_id = folder_id
        if program_file:
            req.program_file = program_file
        elif path:
            req.path = path
        else:
            req.content = content
        if progress is None:
            return self._call(self._stubs.projects.ImportProgram, req)
        req.import_id = os.urandom(12).hex()
        ask = project_pb2.GetImportProgressRequest(project_id=project_id, import_id=req.import_id)
        stop = threading.Event()

        def report() -> bool:
            try:
                progress(self._stubs.projects.GetImportProgress(ask, timeout=min(self.timeout or 10.0, 10.0)))
            except grpc.RpcError as e:
                # Not started yet (NOT_FOUND): ask again; an older daemon: stop.
                return e.code() != grpc.StatusCode.UNIMPLEMENTED
            return True

        def poller():
            while not stop.wait(poll) and report():
                pass

        thread = threading.Thread(target=poller, name="revkit-import-progress", daemon=True)
        thread.start()
        try:
            resp = self._call(self._stubs.projects.ImportProgram, req)
        finally:
            stop.set()
            thread.join()
        report()
        return resp

    def import_dsd_project(
        self,
        project_id: str,
        config_path: str,
        *,
        folder_id: str = "",
        folder_name: str = "",
        modules: Sequence[str] = (),
        skip_arm7: bool = False,
        analyze: bool = False,
        on_conflict: str = "",
    ) -> project_pb2.ImportDsdProjectResponse:
        """A Nintendo DS game's ds-decomp project as programs (``ImportDsdProject``,
        api_minor 103, feature "nds"; docs/nds.md): ``config_path`` is its
        ``config.yaml`` on the daemon's host, under a ``--browse-root``. Each
        module (main, the ITCM and DTCM autoloads, the overlays, and the ARM7
        from the extract unless ``skip_arm7``) becomes a raw program at its
        load address in a new folder (``folder_name``, else the project's
        name and version, inside ``folder_id``), with symbols.txt's names,
        sizes and Thumb modes, delinks.txt's sections as blocks and its
        translation units as plate comments, linked to the modules its
        relocs.txt refers to so calls into main are named and typed.
        ``modules`` limits it to those names. ``on_conflict`` ("keep_both",
        "replace", "refuse"; api_minor 104) says what a folder of the game's
        name already there does. Needs admin."""
        req = project_pb2.ImportDsdProjectRequest(
            project_id=project_id, config_path=config_path, folder_id=folder_id, folder_name=folder_name,
            modules=list(modules), skip_arm7=skip_arm7, analyze=analyze, provenance=self.provenance,
            on_conflict=_choice(_NAME_CONFLICTS, on_conflict, "on_conflict"))
        return self._call(self._stubs.projects.ImportDsdProject, req, timeout=None)

    def import_nds_rom(
        self,
        project_id: str,
        *,
        path: str = "",
        content: bytes = b"",
        program_file: str = "",
        folder_id: str = "",
        folder_name: str = "",
        modules: Sequence[str] = (),
        skip_arm7: bool = False,
        analyze: bool = False,
        on_conflict: str = "",
    ) -> project_pb2.ImportNdsRomResponse:
        """A .nds ROM image as the same programs ``import_dsd_project`` makes
        (``ImportNdsRom``, api_minor 103, feature "nds"): by ``path`` on the
        daemon's host (under a ``--browse-root``), ``content``, or a program's
        stored file (``program_file``). The ARM9 is decompressed (BLZ), the
        ITCM and DTCM autoloads split out, compressed overlays decompressed;
        the ROM carries no symbols. ``on_conflict`` as ``import_dsd_project``.
        Needs admin."""
        req = project_pb2.ImportNdsRomRequest(
            project_id=project_id, folder_id=folder_id, folder_name=folder_name, modules=list(modules),
            skip_arm7=skip_arm7, analyze=analyze, provenance=self.provenance,
            on_conflict=_choice(_NAME_CONFLICTS, on_conflict, "on_conflict"))
        if program_file:
            req.program_file = program_file
        elif path:
            req.path = path
        else:
            req.content = content
        return self._call(self._stubs.projects.ImportNdsRom, req, timeout=None)

    def export_dsd_symbols(
        self,
        project_id: str,
        *,
        program_ids: Sequence[str] = (),
        folder_id: str = "",
        write: bool = False,
        renames: bool = True,
        new_symbols: bool = True,
        include_text: bool = False,
    ) -> project_pb2.ExportDsdSymbolsResponse:
        """revkit's names as changes to a ds-decomp project's symbols.txt files
        (``ExportDsdSymbols``, api_minor 103, feature "nds"; docs/nds.md,
        "Writing names back"): for each module program (``program_ids``, else
        every one in ``folder_id``, else the project's), a unified diff
        (``modules[i].diff``, all of them in ``patch``) renaming each listed
        symbol whose name changed in place and adding named functions and
        data dsd doesn't list, in dsd's syntax. A name that is revkit's
        demangled form of the listed (mangled) one keeps the listed name; a
        new name is written as typed. With ``write`` the files are written,
        each copied to ``symbols.txt.bak-<UTC time>`` first (admin, under a
        ``--browse-root``)."""
        req = project_pb2.ExportDsdSymbolsRequest(
            project_id=project_id, program_ids=list(program_ids), folder_id=folder_id, write=write,
            no_renames=not renames, no_new_symbols=not new_symbols, include_text=include_text,
            provenance=self.provenance)
        return self._call(self._stubs.projects.ExportDsdSymbols, req)

    def build_decomp_kb(
        self,
        project_id: str,
        kb_path: str,
        *,
        program_ids: Sequence[str] = (),
        folder_id: str = "",
        game: str = "",
        source_root: str = "",
        manifest_path: str = "",
        compiler: str = "",
        flags: str = "",
        skip_near_index: bool = False,
        threads: int = 0,
    ) -> project_pb2.BuildDecompKbResponse:
        """A finished matching decomp into a decomp knowledge base (``BuildDecompKb``,
        api_minor 105, feature "decomp-kb"; docs/decomp-kb.md): each function of
        the module programs (``program_ids``, else those in ``folder_id``) with its
        Function ID hashes, its translation unit (delinks.txt), its own text in the
        unit's source (under ``source_root``, by default the dsd project's root;
        the unit files are copied into the KB), and the compiler and flags it
        matches with (the JSON-lines ``manifest_path``'s, a matching pipeline's
        fields, else ``compiler`` and ``flags``). Each function is also signed
        into the KB's BSim near index unless ``skip_near_index``. ``kb_path`` is a
        directory on the daemon's host under a ``--browse-root``; ingesting
        ``game`` again replaces its records. Admin."""
        req = project_pb2.BuildDecompKbRequest(
            project_id=project_id, kb_path=kb_path, program_ids=list(program_ids), folder_id=folder_id, game=game,
            source_root=source_root, manifest_path=manifest_path, compiler=compiler, flags=flags,
            skip_near_index=skip_near_index, threads=threads, provenance=self.provenance)
        return self._call(self._stubs.projects.BuildDecompKb, req, timeout=None)

    def apply_decomp_kb(
        self,
        project_id: str,
        kb_path: str,
        *,
        program_ids: Sequence[str] = (),
        folder_id: str = "",
        apply: bool = False,
        overwrite: bool = False,
        include_unit_source: bool = False,
        near: bool = False,
        min_similarity: Optional[float] = None,
        max_near: int = 0,
        export_dir: str = "",
        threads: int = 0,
    ) -> project_pb2.ApplyDecompKbResponse:
        """A decomp knowledge base matched against new programs (``ApplyDecompKb``,
        api_minor 105): each function whose Function ID hashes are a KB
        function's (``verdict`` "exact"; "candidate" when only the instructions
        match) with the KB function's symbol, unit, own source text, compiler and
        flags. With ``near``, the functions left get BSim's closest KB functions
        ("near", at least ``min_similarity``, default 0.7; ``max_near`` each,
        default 1) with the similarity and the instruction ``diff``: a starting
        scratch. With ``apply`` the exact matches with placeholder names (any,
        with ``overwrite``) are renamed, their linker spelling noted for
        ``export_dsd_symbols``, and a plate comment says where they came from.
        ``export_dir`` (on the daemon's host, under a ``--browse-root``) gets the
        changed symbols.txt files and symbols.patch, the exact matches' source
        in their units' paths and the near matches as ``scratch/`` files. Admin."""
        req = project_pb2.ApplyDecompKbRequest(
            project_id=project_id, kb_path=kb_path, program_ids=list(program_ids), folder_id=folder_id, apply=apply,
            overwrite=overwrite, include_unit_source=include_unit_source, near=near, max_near=max_near,
            export_dir=export_dir, threads=threads, provenance=self.provenance)
        if min_similarity is not None:
            req.min_similarity = min_similarity
        return self._call(self._stubs.projects.ApplyDecompKb, req, timeout=None)

    def detect_raw_layout(
        self,
        project_id: str,
        *,
        path: str = "",
        content: bytes = b"",
        language_id: str = "",
        processor: str = "",
        progress: Optional[Callable[[project_pb2.GetRawDetectProgressResponse], None]] = None,
        cancel: Optional[threading.Event] = None,
        poll: float = 0.25,
        timeout: Optional[float] = 600.0,
    ) -> project_pb2.DetectRawLayoutResponse:
        """For a file with no header (raw firmware, a dump): what a raw import
        of it needs, detected from its bytes (api_minor 23, feature
        "raw-detect"). Nothing is imported. Needs what importing needs.

        The response has up to three ``suggestions``, best first, each with
        ``options`` (``ImportOptions``: format "raw", language, compiler,
        load address, header offset, regions; pass them to
        ``import_program(options=...)``), a confidence per answer
        (``processor_confidence``, ``variant_confidence``,
        ``base_confidence``, ``offset_confidence``; ``detect_confidence``
        names one), the ``evidence`` sentences and the ``tie_group`` of
        languages the evidence can't tell apart, and (first suggestion)
        ``region_details``: each region with its ``kind``, ``spec``,
        ``confidence`` and ``evidence``; a ``refusal`` (``reason``,
        ``detail``) when nothing should be applied without a person
        deciding (the suggestions are then its closest guesses); and the
        file's ``segments``. Only a high confidence is meant to be relied on.

        ``language_id`` or ``processor`` say what is already known and narrow
        the search (``hints``). ``progress`` is called with a
        ``GetRawDetectProgressResponse`` (``phase``, ``message``, ``progress``
        0..1 or -1, ``done``) every ``poll`` seconds while it runs, from
        another thread, and once more when it has ended. Setting ``cancel``
        stops it: the call then raises ``RevkitError`` with code CANCELLED.
        ``timeout`` (seconds, None for none) bounds the call instead of the
        client's unary timeout: a detection takes seconds, and longer while
        it waits for others to end.
        """
        hints = project_pb2.RawDetectHints(language_id=language_id, processor=processor)
        req = project_pb2.DetectRawLayoutRequest(project_id=project_id, hints=hints)
        if path:
            req.path = path
        else:
            req.content = content
        if progress is None and cancel is None:
            return self._call(self._stubs.projects.DetectRawLayout, req, timeout)
        req.detect_id = os.urandom(12).hex()
        ask = project_pb2.GetRawDetectProgressRequest(project_id=project_id, detect_id=req.detect_id)
        stop = threading.Event()
        short = min(self.timeout or 10.0, 10.0)
        asked_to_stop = False

        def report() -> bool:
            if progress is None:
                return True
            try:
                progress(self._stubs.projects.GetRawDetectProgress(ask, timeout=short))
            except grpc.RpcError as e:
                # Not started yet (NOT_FOUND): ask again; an older daemon: stop.
                return e.code() != grpc.StatusCode.UNIMPLEMENTED
            return True

        def poller():
            nonlocal asked_to_stop
            while not stop.wait(poll):
                if cancel is not None and cancel.is_set() and not asked_to_stop:
                    try:
                        self._stubs.projects.CancelRawDetect(
                            project_pb2.CancelRawDetectRequest(project_id=project_id, detect_id=req.detect_id), timeout=short
                        )
                        asked_to_stop = True
                    except grpc.RpcError as e:
                        # Not started yet: ask again at the next poll.
                        asked_to_stop = e.code() != grpc.StatusCode.NOT_FOUND
                if not report():
                    break

        thread = threading.Thread(target=poller, name="revkit-detect-progress", daemon=True)
        thread.start()
        try:
            resp = self._call(self._stubs.projects.DetectRawLayout, req, timeout)
        finally:
            stop.set()
            thread.join()
            report()
        return resp

    def program(self, program_id: str) -> "Program":
        return Program(self, program_id)

    # -- plugins (api_minor 6, feature "plugins") ------------------------------------

    def plugins(self) -> Sequence[plugin_pb2.Plugin]:
        """Every plugin the daemon found: loaded ones, and rejected ones with their error."""
        return self._call(self._stubs.plugins.ListPlugins, plugin_pb2.ListPluginsRequest()).plugins

    # -- emulator (api_minor 12, feature "emulator") ----------------------------------

    def emulator_sessions(self, client: str = "") -> Sequence[emulator_pb2.EmulatorSessionInfo]:
        """The emulation sessions of ``client`` (default: this connection)."""
        req = emulator_pb2.ListEmulatorSessionsRequest(client=client)
        return self._call(self._stubs.emulator.ListEmulatorSessions, req).sessions

    def emulator_session(self, session_id: str) -> "EmulatorSession":
        """An existing session by id (from :meth:`emulator_sessions` or another client)."""
        return EmulatorSession(self, session_id)

    # -- debugger (api_minor 14, features "debugger", "debugger-live") -----------------

    def debug_sessions(self, client: str = "") -> Sequence[debugger_pb2.DebugSessionInfo]:
        """The debug sessions of ``client`` (default: this connection)."""
        return self._call(self._stubs.debugger.ListDebugSessions, debugger_pb2.ListDebugSessionsRequest(client=client)).sessions

    def debug_session(self, session_id: str) -> "DebugSession":
        """An existing debug session by id."""
        return DebugSession(self, session_id)

    # -- diffing (api_minor 16, feature "diff"; revkit.diff) ---------------------------

    def diff(self, project_id: str, program_a: str, program_b: str, *, name: str = "", run: bool = True,
             wait: bool = True, timeout: float = 600.0, similarity_tiers: Sequence[str] = (),
             actor=None) -> "DiffSession":
        """Creates a diff session of ``program_a`` (the analysed one) against
        ``program_b`` and, with ``run``, computes its matches (waiting with ``wait``)."""
        from revkit.diff import DiffSession

        resp = self._call(self._stubs.diff.CreateDiffSession, diff_pb2.CreateDiffSessionRequest(
            project_id=project_id, program_a=program_a, program_b=program_b, name=name, run=run,
            options=diff_pb2.DiffOptions(similarity_tiers=list(similarity_tiers)), provenance=self._prov(actor)))
        s = DiffSession(self, project_id, resp.session.session_id, resp.session)
        if run and wait:
            s.wait(timeout=timeout)
        return s

    def diff_sessions(self, project_id: str, program_id: str = "") -> Sequence[diff_pb2.DiffSessionInfo]:
        """The project's diff sessions, newest first (those with ``program_id`` on either side)."""
        return self._call(self._stubs.diff.ListDiffSessions,
                          diff_pb2.ListDiffSessionsRequest(project_id=project_id, program_id=program_id)).sessions

    def diff_session(self, project_id: str, session_id: str) -> "DiffSession":
        """An existing diff session by id."""
        from revkit.diff import DiffSession

        return DiffSession(self, project_id, session_id)

    def compare_functions(self, program_a: str, entry_a, program_b: str, entry_b, *, project_id: str = "",
                          session_id: str = "", markup: bool = True, revision: int = 0) -> diff_pb2.CompareFunctionsResponse:
        """Compares any two functions of a project, in one program or two
        (api_minor 54, feature "function-compare"): ``a``/``b`` summaries,
        ``detail`` (aligned listings, hunks, a summary line) and with
        ``markup`` what can be ported (``markup.variables`` paired across,
        ``markup.comments`` by aligned instruction, the signatures)."""
        from revkit.diff import compare_functions

        return compare_functions(self, program_a, entry_a, program_b, entry_b, project_id=project_id,
                                 session_id=session_id, markup=markup, revision=revision)

    def port_function_markup(self, from_program: str, from_entry, to_program: str, to_entry, *, items: Sequence = (),
                             overwrite: bool = False, dry_run: bool = False, project_id: str = "", session_id: str = "",
                             actor=None, reason: str = "") -> diff_pb2.PortFunctionMarkupResponse:
        """Ports the name, signature, variables' names and types and comments
        from one function to another (``items``: "name", "signature",
        "variable_names", "variable_types", "comments", or ("variable_name",
        storage_key) for one; empty: everything someone set). One revision;
        retracting ``seqs`` undoes it (api_minor 54)."""
        from revkit.diff import port_function_markup

        return port_function_markup(self, from_program, from_entry, to_program, to_entry, items=items,
                                    overwrite=overwrite, dry_run=dry_run, project_id=project_id,
                                    session_id=session_id, actor=actor, reason=reason)

    # -- subscriptions -------------------------------------------------------------

    def subscribe(
        self,
        project_id: str,
        *,
        programs: Sequence[str] = (),
        from_revision: int = 0,
        include_assertions: bool = False,
        heartbeat_seconds: int = 0,
    ) -> Subscription:
        """Opens a change stream; returns once the server's Hello arrived."""
        req = subscription_pb2.SubscribeRequest(
            project_id=project_id,
            program_ids=list(programs),
            from_revision=from_revision,
            include_assertions=include_assertions,
            heartbeat_seconds=heartbeat_seconds,
        )
        return Subscription(self._stubs.subscriptions.Subscribe(req))


@dataclass
class ConsoleStatement:
    """One statement's run in a console (:meth:`ScriptConsole.run`)."""

    run_id: str = ""
    # ok, error, interrupted, exit; "" with ``more``; "died" when the host
    # died during it (``error`` says how).
    status: str = ""
    more: bool = False
    stdout: str = ""
    stderr: str = ""
    revisions: list = field(default_factory=list)
    seqs: list = field(default_factory=list)
    discarded: int = 0
    seconds: float = 0.0
    error: str = ""
    started: Optional[script_pb2.ScriptStarted] = None

    @property
    def text(self) -> str:
        return self.stdout + self.stderr


class ScriptConsole:
    """The caller's console of one program (:meth:`Client.console`)."""

    def __init__(self, client: "Client", program_id: str, *, ghidra_names: bool = False):
        self._client = client
        self.program_id = program_id
        self.ghidra_names = ghidra_names
        self.run_id = ""
        self.started: Optional[script_pb2.ScriptStarted] = None

    def open(self) -> script_pb2.ScriptStarted:
        """Opens it (starting the host if needed); its ``started`` message
        (``console_started``, ``history``, ``read_only``, ...)."""
        self.run("")
        return self.started

    def run(self, source: str, *, address: Optional[AddressLike] = None, selection: Optional[tuple] = None,
            answers=None, on_output=None, timeout: Optional[float] = None) -> ConsoleStatement:
        """Runs ``source`` and waits for its end. ``answers`` answers
        ``ask_*`` prompts (a dict by name, or a function of the prompt)."""
        ctx = None
        if address is not None or selection is not None:
            ctx = script_pb2.ScriptContext()
            if address is not None:
                ctx.address.CopyFrom(globals()["address"](address))
            if selection is not None:
                ctx.selection.CopyFrom(address_range(*selection))
        req = script_pb2.RunScriptRequest(program_id=self.program_id, interactive=True, input=source,
                                          ghidra_names=self.ghidra_names, context=ctx)
        st = ConsoleStatement()
        try:
            for ev in self._client._stubs.scripts.RunScript(req, timeout=timeout):
                if ev.run_id:
                    self.run_id = st.run_id = ev.run_id
                kind = ev.WhichOneof("event")
                if kind == "started":
                    self.started = st.started = ev.started
                elif kind == "output":
                    if ev.output.stream == "stderr":
                        st.stderr += ev.output.text
                    else:
                        st.stdout += ev.output.text
                    if on_output:
                        on_output(ev.output.text, ev.output.stream)
                elif kind == "prompt":
                    p = ev.prompt
                    value = answers(p) if callable(answers) else (answers or {}).get(p.name)
                    areq = script_pb2.AnswerPromptRequest(run_id=self.run_id, prompt_id=p.prompt_id,
                                                          cancelled=value is None)
                    if isinstance(value, (list, tuple)):
                        areq.values.extend(str(v) for v in value)
                    elif value is not None:
                        areq.value = str(value)
                    self._client._call(self._client._stubs.scripts.AnswerPrompt, areq)
                elif kind == "console_result":
                    r = ev.console_result
                    st.status, st.more, st.error = r.status, r.more, r.error
                    st.revisions, st.seqs = list(r.revisions), list(r.seqs)
                    st.discarded, st.seconds = r.discarded, r.seconds
                elif kind == "error":
                    st.status, st.error = "died", ev.error.message
        except grpc.RpcError as e:
            raise _error(e) from None
        return st

    def complete(self, text: str, limit: int = 200) -> script_pb2.CompleteConsoleResponse:
        """Completions for ``text`` (the input up to the cursor) from the
        console's live namespace."""
        return self._client._call(self._client._stubs.scripts.CompleteConsole,
                                  script_pb2.CompleteConsoleRequest(program_id=self.program_id, text=text, limit=limit))

    def interrupt(self) -> bool:
        """Ctrl+C: KeyboardInterrupt in the running statement."""
        return self._client._call(self._client._stubs.scripts.CancelScript,
                                  script_pb2.CancelScriptRequest(run_id=self.run_id, interrupt=True)).was_running

    def update_context(self, address: Optional[AddressLike] = None, selection: Optional[tuple] = None) -> None:
        ctx = script_pb2.ScriptContext()
        if address is not None:
            ctx.address.CopyFrom(globals()["address"](address))
        if selection is not None:
            ctx.selection.CopyFrom(address_range(*selection))
        self._client._call(self._client._stubs.scripts.UpdateContext,
                           script_pb2.UpdateContextRequest(run_id=self.run_id, context=ctx))

    def close(self) -> bool:
        """Ends the console's host (the next statement starts a new one)."""
        if not self.run_id:
            return False
        return self._client._call(self._client._stubs.scripts.CancelScript,
                                  script_pb2.CancelScriptRequest(run_id=self.run_id)).was_running


class FileSystem:
    """An open container file system (``Client.open_filesystem``).

    Paths cross nested containers with ``!``: ``"/rootfs.sqfs!/bin/busybox"``
    is /bin/busybox in the squashfs at /rootfs.sqfs. Use the paths a listing
    returns (names are percent-encoded where they need to be)."""

    def __init__(self, client: "Client", project_id: str, opened: filesystem_pb2.OpenFileSystemResponse):
        self._client = client
        self.project_id = project_id
        self.session_id = opened.session_id
        self.name = opened.name
        self.root = opened.root
        self.limits = opened.limits

    @property
    def format(self) -> str:
        return self.root.format

    def __enter__(self) -> "FileSystem":
        return self

    def __exit__(self, *exc):
        self.close()

    def __repr__(self) -> str:
        return f"<FileSystem {self.name} ({self.root.format}) {self.session_id}>"

    def _call(self, method, req, timeout="default"):
        return self._client._call(getattr(self._client._stubs.filesystems, method), req, timeout=timeout)

    def list(self, path: str = "/", *, recursive: bool = False, detect: bool = True, offset: int = 0,
             limit: int = 0) -> filesystem_pb2.ListFileSystemResponse:
        """A directory's entries (a container file's: its root). ``detect``
        guesses each file's type from its first bytes (``detected``,
        ``detected_kind``, ``container_format``, ``processor``)."""
        return self._call("ListFileSystem", filesystem_pb2.ListFileSystemRequest(
            session_id=self.session_id, path=path, detect=detect, recursive=recursive, offset=offset, limit=limit))

    def entries(self, path: str = "/", *, recursive: bool = False, detect: bool = True) -> list:
        """Every entry of ``list`` across pages."""
        out, offset = [], 0
        while True:
            page = self.list(path, recursive=recursive, detect=detect, offset=offset, limit=5000)
            out.extend(page.entries)
            offset += len(page.entries)
            if not page.entries or offset >= page.total:
                return out

    def walk(self, path: str = "/", *, detect: bool = False) -> Iterator[filesystem_pb2.FileSystemEntry]:
        """Every entry below ``path``, not into nested containers."""
        yield from self.entries(path, recursive=True, detect=detect)

    def read(self, path: str, offset: int = 0, length: Optional[int] = None) -> bytes:
        """A file's bytes (all of them by default; links are followed inside
        the container)."""
        out, pos = bytearray(), offset
        while length is None or len(out) < length:
            want = 4 << 20 if length is None else min(4 << 20, length - len(out))
            r = self._call("ReadFileSystemFile", filesystem_pb2.ReadFileSystemFileRequest(
                session_id=self.session_id, path=path, offset=pos, length=want))
            out += r.data
            pos += len(r.data)
            if r.eof or not r.data:
                break
        return bytes(out)

    def info(self, path: str, *, hashes: bool = False) -> filesystem_pb2.GetFileSystemFileInfoResponse:
        """A file's entry, what it is, its first bytes, its container path,
        the container it holds, and (``hashes``) SHA-256, SHA-1 and MD5."""
        return self._call("GetFileSystemFileInfo", filesystem_pb2.GetFileSystemFileInfoRequest(
            session_id=self.session_id, path=path, hashes=hashes))

    def apple_bundle(self, path: str = "/", *, skip_info_plist: bool = False) -> filesystem_pb2.GetAppleBundleResponse:
        """An Apple bundle (api_minor 100, feature ``apple-bundles``; docs/apple-apps.md):
        ``path`` is an .app, a framework, an app extension, a file inside one, or an
        .ipa (its ``Payload/*.app``). ``.bundle`` has its ``layout``, ``platform``,
        ``info`` (Info.plist's keys: identifier, versions, minimum OS, URL schemes,
        document types, background modes, usage descriptions, exported and imported
        types), ``info_plist`` (all of it; ``plist_value`` makes it Python),
        ``executable_path``, ``code_signature`` (read, never verified), ``nested``
        bundles (frameworks, extensions, ...), ``interface_files`` and
        ``provisioning_profile``; ``.apps`` lists every app an .ipa holds. Import
        ``bundle.executable_path`` with ``import_libraries=True`` to bring its
        frameworks, found by ``@rpath``."""
        return self._call("GetAppleBundle", filesystem_pb2.GetAppleBundleRequest(
            session_id=self.session_id, path=path, skip_info_plist=skip_info_plist))

    def property_list(self, path: str, *, max_values: int = 0, max_data_bytes: int = 0,
                      resolve_keyed_archive: bool = False) -> filesystem_pb2.ReadPropertyListResponse:
        """A property list file as a tree (api_minor 100, feature ``apple-bundles``):
        XML or binary, or a provisioning profile's plist (``format``
        "mobileprovision"); ``plist_value(r.root)`` makes it Python. At most
        ``max_values`` values (default 20000; ``truncated`` says when entries were
        left out) and ``max_data_bytes`` of each data value (default 4096);
        ``keyed_archive`` says it is an NSKeyedArchiver archive, and
        ``resolve_keyed_archive`` (api_minor 101) returns one as a tree of its
        objects ({"$top": ...}, each object with "$class", later references as
        {"$ref": uid})."""
        return self._call("ReadPropertyList", filesystem_pb2.ReadPropertyListRequest(
            session_id=self.session_id, path=path, max_values=max_values, max_data_bytes=max_data_bytes,
            resolve_keyed_archive=resolve_keyed_archive))

    def ui_actions(self, path: str = "/", *, program_id: str = "",
                   include_documents: bool = False) -> filesystem_pb2.ListUiActionsResponse:
        """Interface Builder's UI wiring (api_minor 101, feature ``ui-actions``;
        docs/apple-apps.md): the compiled nibs and storyboards of a bundle, an .ipa,
        a .storyboardc or a nib, and ``.actions``: each control's action
        (``control_class``, ``control_label``, ``events`` such as "touchUpInside",
        ``selector``, ``target`` and ``target_class``) traced to the Objective-C
        method it runs (``resolution`` "resolved", "resolved-by-selector",
        "ambiguous", "external", "unresolved" or "no-program"; ``method``,
        ``implementation``, ``function_name``). The program is ``program_id``, else
        the project's program imported from the bundle's main executable.
        ``.outlets``; ``include_documents`` adds each nib's objects and
        connections."""
        return self._call("ListUiActions", filesystem_pb2.ListUiActionsRequest(
            session_id=self.session_id, path=path, program_id=program_id, include_documents=include_documents))

    def import_(
        self,
        paths: Union[str, Sequence[str]] = "/",
        *,
        project_id: str = "",
        folder: str = "",
        recursive: bool = False,
        descend: bool = False,
        programs_only: bool = False,
        detect_raw: bool = False,
        preview: bool = False,
        max_programs: int = 0,
        keep_folders: bool = False,
        analyze: bool = True,
        options: Optional[project_pb2.ImportOptions] = None,
        import_libraries: bool = False,
        library_search_paths: Sequence[str] = (),
        library_depth: int = 0,
        timeout: Optional[float] = None,
    ) -> filesystem_pb2.ImportFromFileSystemResponse:
        """Imports files as programs (editor of the project). One file named
        alone is imported whatever it is; directories (``recursive``: and
        below), and containers inside (``descend``), give their programs only:
        ELF, PE, and raw images whose header names the processor or
        (``detect_raw``) that raw detection identifies. ``preview`` imports
        nothing and says what would be; ``max_programs`` caps the count
        (default 100). ``folder`` is an id or a path in the project
        (``keep_folders`` recreates the container's directories under it).

        ``import_libraries`` (api_minor 79, feature "library-roots") also
        imports the shared libraries the programs need that the project lacks,
        from the same file system: beside each program, its runpath,
        ``library_search_paths`` (paths inside the container),
        ``/etc/ld.so.conf`` and the standard library directories of the
        container's root; ``library_depth`` levels deep (0: 2). They are items
        with ``library_of`` set; those found nowhere are in
        ``libraries_not_found``."""
        project = project_id or self.project_id
        opts = project_pb2.ImportOptions()
        if options is not None:
            opts.CopyFrom(options)
        opts.analyze = analyze
        if import_libraries:
            opts.import_libraries = True
        if library_search_paths:
            opts.library_search_paths.extend(library_search_paths)
        if library_depth:
            opts.library_depth = library_depth
        req = filesystem_pb2.ImportFromFileSystemRequest(
            session_id=self.session_id, project_id=project,
            folder_id=self._client.folder_id(project, folder) if folder else "",
            paths=[paths] if isinstance(paths, str) else list(paths), recursive=recursive, descend=descend,
            programs_only=programs_only, detect_raw=detect_raw, preview=preview, max_programs=max_programs,
            options=opts, keep_folders=keep_folders, provenance=self._client.provenance)
        return self._call("ImportFromFileSystem", req, timeout=timeout)

    # ``import`` is a keyword; both spellings work.
    import_files = import_

    def extract(self, paths: Union[str, Sequence[str]], host_dir: str, *,
                overwrite: bool = False) -> filesystem_pb2.ExtractFromFileSystemResponse:
        """Writes files (directories: everything below) to ``host_dir`` on
        the daemon's host, under --browse-root (admin). Names are sanitized;
        links, devices and pipes are skipped."""
        return self._call("ExtractFromFileSystem", filesystem_pb2.ExtractFromFileSystemRequest(
            session_id=self.session_id, paths=[paths] if isinstance(paths, str) else list(paths),
            host_dir=host_dir, overwrite=overwrite))

    def providers(self, path: str, *, refresh: bool = False) -> provider_pb2.ListProvidersResponse:
        """What a file is to the external decompilers, and which take it
        (:meth:`Client.providers`)."""
        return self._client.providers(filesystem=self, path=path, refresh=refresh)

    def decompile_external(self, path: str, *, provider: str = "", refresh: bool = False) -> "ExternalDecompilation":
        """An external decompiler on one file of this file system (:meth:`Client.decompile_external`):
        a jar, an APK, a .pyc, a Lua chunk, a .NET assembly, a wasm module."""
        return self._client.decompile_external(filesystem=self, path=path, provider=provider, refresh=refresh)

    def android_package(self, path: str = "", *, native: bool = True,
                        dex: bool = True) -> filesystem_pb2.AndroidPackage:
        """An APK's manifest, resources, native libraries, native methods and
        Flutter facts (api_minor 98, feature "android"; docs/android.md).
        ``path`` names the APK in this file system ("" or "/": the file
        system itself is one). ``native=False`` skips reading the native
        libraries (no JNI exports, no Flutter hash), ``dex=False`` the DEX
        files (no native methods).

        ``.manifest`` has the fields (``package``, ``version_code``,
        ``min_sdk``, ``target_sdk``, ``uses_permissions``, ``components``
        with ``exported`` and ``intent_filters``, ``debuggable``,
        ``allow_backup``, ``uses_cleartext_traffic``,
        ``network_security_config``, ...), ``.manifest_xml`` the XML text,
        ``.native_libraries`` each ``lib/<abi>/*.so`` (its ``path`` imports
        it: ``import_(lib.path)``), ``.native_methods`` the DEX's native
        methods with the ``libraries`` exporting their JNI names, and
        ``.flutter`` the Dart snapshot hash per ABI."""
        return self._call("GetAndroidPackage", filesystem_pb2.GetAndroidPackageRequest(
            session_id=self.session_id, path=path, skip_native=not native, skip_dex=not dex)).package

    def android_xml(self, path: str, *, resolve: bool = False) -> str:
        """A compiled XML file of an APK (``"/app.apk!/res/layout/main.xml"``)
        as XML text; ``resolve`` gives references' default-configuration
        values instead of their names."""
        return self._call("DecodeAndroidXml", filesystem_pb2.DecodeAndroidXmlRequest(
            session_id=self.session_id, path=path, resolve=resolve)).xml

    def android_resources(self, path: str = "", *, type: str = "", config: str = "", query: str = "",
                          offset: int = 0, limit: int = 0) -> filesystem_pb2.ListAndroidResourcesResponse:
        """The entries of an APK's ``resources.arsc``: one ``type``
        (``"string"`` for the strings table; "" every type), one ``config``
        ("" the default configuration, ``"fr"``, ``"night"``, ``"*"`` every
        one), names or values containing ``query``. ``.entries`` (``id``,
        ``name`` such as ``"@string/app_name"``, ``config``, ``value``,
        ``value_type``, a bag's ``items``), ``.total``, and the ``types``
        and ``configs`` there are."""
        return self._call("ListAndroidResources", filesystem_pb2.ListAndroidResourcesRequest(
            session_id=self.session_id, path=path, type=type, config=config, query=query, offset=offset,
            limit=limit))

    def android_strings(self, path: str = "", *, config: str = "") -> dict:
        """The strings table for one configuration as ``{name: value}``."""
        out, offset = {}, 0
        while True:
            r = self.android_resources(path, type="string", config=config, offset=offset, limit=5000)
            for e in r.entries:
                out[e.key] = e.value
            offset += len(r.entries)
            if not r.entries or offset >= r.total:
                return out

    def close(self) -> None:
        if self.session_id:
            try:
                self._call("CloseFileSystem", filesystem_pb2.CloseFileSystemRequest(session_id=self.session_id))
            except NotFound:
                pass
            self.session_id = ""


class ExternalDecompilation:
    """An external decompiler's result (:meth:`Client.decompile_external`).

    ``.response`` is the ``DecompileExternalResponse``. ``.ok`` (status OK),
    ``.status`` ("OK", "FAILED", "CRASHED", "TIMEOUT", "OUT_OF_MEMORY",
    "OUTPUT_LIMIT", "SANDBOX_ERROR"), ``.provider``, ``.version``, ``.cached``,
    ``.files`` (paths), ``.main_file``; ``.read(path)`` a file's bytes and
    ``.text(path)`` its text (the main file by default); ``.sources()`` every
    file in the output's language, as (path, text)."""

    def __init__(self, client: "Client", inp: provider_pb2.ProviderInput, resp: provider_pb2.DecompileExternalResponse):
        self._client = client
        self._input = inp
        self.response = resp

    @property
    def status(self) -> str:
        return provider_pb2.ProviderRunStatus.Name(self.response.status).replace("PROVIDER_RUN_STATUS_", "")

    @property
    def ok(self) -> bool:
        return self.response.status == provider_pb2.PROVIDER_RUN_STATUS_OK

    @property
    def provider(self) -> str:
        return self.response.provider

    @property
    def version(self) -> str:
        return self.response.provider_version

    @property
    def cached(self) -> bool:
        return self.response.cached

    @property
    def files(self) -> List[str]:
        return [f.path for f in self.response.files]

    @property
    def main_file(self) -> str:
        return self.response.main_file

    def read(self, path: str) -> bytes:
        out, offset = bytearray(), 0
        while True:
            r = self._client._call(self._client.stubs.providers.ReadProviderOutput, provider_pb2.ReadProviderOutputRequest(
                input=self._input, provider=self.response.provider, path=path, offset=offset, max_bytes=8 << 20))
            out += r.data
            offset += len(r.data)
            if not r.truncated or not r.data:
                return bytes(out)

    def text(self, path: Optional[str] = None) -> str:
        path = path or self.response.main_file
        if path == self.response.main_file and not self.response.main_truncated and self.response.main_text:
            return self.response.main_text
        return self.read(path).decode("utf-8", errors="replace")

    def sources(self) -> Iterator[tuple]:
        for f in self.response.files:
            if f.language == self.response.language:
                yield f.path, self.text(f.path)

    def __repr__(self) -> str:
        return (f"<ExternalDecompilation {self.provider} {self.version} {self.status} "
                f"{len(self.response.files)} files{' cached' if self.cached else ''}>")


class ScriptRun:
    """A script the daemon runs (:meth:`Client.run_script`).

    Iterating yields each ``RunScriptResponse`` (started, output, progress,
    prompt, then result or error; or only trust_required). ``wait()`` runs
    it to its end, answering prompts from a dict (by prompt name) or a
    function of the prompt, and returns the last message.
    """

    def __init__(self, client: "Client", call):
        self._client = client
        self._call = call
        self.run_id = ""
        self.started: Optional[script_pb2.ScriptStarted] = None
        self.result: Optional[script_pb2.ScriptResult] = None
        self.error: Optional[script_pb2.ScriptError] = None
        self.trust: Optional[script_pb2.ScriptTrustRequired] = None
        self.output: list = []

    def __iter__(self):
        try:
            for ev in self._call:
                if ev.run_id:
                    self.run_id = ev.run_id
                kind = ev.WhichOneof("event")
                if kind == "started":
                    self.started = ev.started
                elif kind == "output":
                    self.output.append(ev.output.text)
                elif kind == "result":
                    self.result = ev.result
                elif kind == "error":
                    self.error = ev.error
                    self.result = ev.error.result
                elif kind == "trust_required":
                    self.trust = ev.trust_required
                yield ev
        except grpc.RpcError as e:
            raise _error(e) from None

    @property
    def status(self) -> str:
        """"ok", "error", "cancelled", "untrusted", or "" while running."""
        if self.trust is not None:
            return "untrusted"
        return self.result.status if self.result is not None else ""

    @property
    def text(self) -> str:
        """Everything the script printed so far."""
        return "".join(self.output)

    def answer(self, prompt: script_pb2.ScriptPrompt, value=None, *, cancelled: bool = False) -> None:
        req = script_pb2.AnswerPromptRequest(run_id=self.run_id, prompt_id=prompt.prompt_id, cancelled=cancelled)
        if isinstance(value, (list, tuple)):
            req.values.extend(str(v) for v in value)
        elif value is not None:
            req.value = str(value)
        self._client._call(self._client.stubs.scripts.AnswerPrompt, req)

    def cancel(self) -> bool:
        """Cancels the run; False when it had already ended."""
        return self._client._call(self._client.stubs.scripts.CancelScript,
                                  script_pb2.CancelScriptRequest(run_id=self.run_id)).was_running

    def update_context(self, address: Optional[AddressLike] = None, selection: Optional[tuple] = None) -> None:
        ctx = script_pb2.ScriptContext()
        if address is not None:
            ctx.address.CopyFrom(globals()["address"](address))
        if selection is not None:
            ctx.selection.CopyFrom(address_range(*selection))
        self._client._call(self._client.stubs.scripts.UpdateContext,
                           script_pb2.UpdateContextRequest(run_id=self.run_id, context=ctx))

    def wait(self, answers=None, *, on_output=None, on_progress=None) -> script_pb2.RunScriptResponse:
        """Runs to the end. ``answers``: a dict by prompt name, or a function
        ``(prompt) -> value`` (None dismisses it, which cancels the run).
        Returns the last message (result, error or trust_required)."""
        last = None
        for ev in self:
            last = ev
            kind = ev.WhichOneof("event")
            if kind == "output" and on_output:
                on_output(ev.output.text, ev.output.stream)
            elif kind == "progress" and on_progress:
                on_progress(ev.progress)
            elif kind == "prompt":
                p = ev.prompt
                if callable(answers):
                    value = answers(p)
                elif isinstance(answers, dict) and p.name in answers:
                    value = answers[p.name]
                else:
                    value = None
                self.answer(p, value, cancelled=value is None)
        return last


class Program:
    """Reads and edits one program. ``revision`` pins every read (see :meth:`at`)."""

    def __init__(self, client: Client, program_id: str, revision: int = 0):
        self.client = client
        self.id = program_id
        self.revision = revision
        # The last message of the last search (search_memory and the others).
        self.last_search = None

    def __repr__(self):
        pin = f" @r{self.revision}" if self.revision else ""
        return f"<Program {self.id}{pin}>"

    def at(self, revision: int) -> "Program":
        """A view of this program frozen at ``revision`` (0 = follow head)."""
        return Program(self.client, self.id, revision)

    def _read(self) -> common_pb2.ReadOptions:
        return common_pb2.ReadOptions(revision=self.revision)

    def _q(self, name, request):
        return self.client._call(getattr(self.client.stubs.queries, name), request)

    def _paged(self, name, request, field: str, page_size: int):
        request.page.page_size = page_size
        while True:
            resp = self._q(name, request)
            yield from getattr(resp, field)
            if not resp.page.next_page_token:
                return
            request.page.page_token = resp.page.next_page_token

    # -- queries -----------------------------------------------------------------

    def summary(self) -> project_pb2.ProgramSummary:
        req = project_pb2.GetProgramSummaryRequest(program_id=self.id, read=self._read())
        return self.client._call(self.client.stubs.projects.GetProgramSummary, req).summary

    def macho(self) -> Optional[project_pb2.MachoSummary]:
        """A Mach-O's header and load commands (api_minor 90, feature "macho"): its arch,
        file type, UUID, platform and minimum OS, dylibs and rpaths, a universal file's
        slices, whether it is code-signed or encrypted; None for any other format."""
        s = self.summary()
        return s.macho if s.HasField("macho") else None

    def code_signature(self) -> Optional["apple_pb2.CodeSignature"]:
        """A Mach-O's code signature (api_minor 100, feature ``apple-bundles``;
        docs/apple-apps.md), read and NOT verified: ``.code_directories``
        (identifier, team_id, flag_names such as "runtime", hash_type, cdhash),
        ``.entitlements``, ``.requirements`` (their text), ``.certificates`` (the
        CMS signature's, by name), ``.adhoc``; None without one."""
        m = self.macho()
        return m.code_signature if m is not None and m.HasField("code_signature") else None

    def entitlements(self) -> dict:
        """A Mach-O's entitlements as a dict (its code signature's; {} without)."""
        sig = self.code_signature()
        return plist_value(sig.entitlements) or {} if sig is not None and sig.HasField("entitlements") else {}

    def dotnet(self) -> Optional[project_pb2.DotNetAssembly]:
        """A .NET assembly's CLR header (api_minor 94, feature "dotnet"): metadata and
        runtime versions, flags, IL-only or mixed-mode, ReadyToRun, whether code analysis
        was skipped (IL-only), the metadata streams; None for any other program."""
        s = self.summary()
        return s.info.dotnet if s.info.HasField("dotnet") else None

    def memory_map(self, *, rejected: bool = False) -> Sequence[project_pb2.MemoryBlock]:
        """The memory map in address order: the image's blocks (as edited) and the
        regions added since import. ``rejected``: the added regions the map can't
        place instead (``block.rejected`` says why; feature ``memory-map``)."""
        resp = self._q("GetMemoryMap", query_pb2.GetMemoryMapRequest(program_id=self.id, read=self._read()))
        return resp.rejected if rejected else resp.blocks

    # -- the memory map after import (api_minor 24, feature "memory-map") -------

    @staticmethod
    def _region(name: str, start: int, size: int, perms: str, initialized: bool, volatile: bool,
                space: str = "") -> project_pb2.MemoryRegion:
        if len(perms) != 3 or any(c not in ok for c, ok in zip(perms, ("r-", "w-", "x-"))):
            raise ValueError(f"perms {perms!r} is not like 'rw-'")
        return project_pb2.MemoryRegion(
            name=name, start=start, size=size, read=perms[0] == "r", write=perms[1] == "w", execute=perms[2] == "x",
            initialized=initialized, is_volatile=volatile, space=space,
        )

    def add_memory_region(
        self,
        name: str,
        start: int,
        size: int = 0,
        *,
        perms: str = "rw-",
        initialized: bool = False,
        volatile: bool = False,
        space: str = "",
        path: str = "",
        content: Optional[bytes] = None,
        file_name: str = "",
        file_offset: int = 0,
        length: int = 0,
        validate_only: bool = False,
        actor: Optional[str] = None,
        reason: str = "",
    ) -> project_pb2.AddMemoryRegionResponse:
        """Adds memory to the map after import: uninitialized RAM (the default),
        zero-filled (``initialized=True``), memory-mapped I/O (``volatile=True``), or
        bytes from another file at ``start`` (``path`` on the daemon's host, which
        needs admin, or ``content``; from ``file_offset``, ``length`` bytes, 0 = to
        the end; ``size`` 0 = their length), as Ghidra's "Add To Program" does.
        ``space`` names another memory space the program has ("EXTMEM").
        Overlaps and wrapping raise :class:`InvalidArgument`. Retract
        ``response.assertion.seq`` to undo it."""
        req = project_pb2.AddMemoryRegionRequest(
            program_id=self.id, region=self._region(name, start, size, perms, initialized, volatile, space),
            file_name=file_name, file_offset=file_offset, length=length,
            provenance=self.client._prov(actor, reason), validate_only=validate_only,
        )
        if path:
            req.path = path
        elif content is not None:
            req.content = content
        return self.client._call(self.client.stubs.projects.AddMemoryRegion, req)

    def _block(self, region: Union[str, int]) -> project_pb2.MemoryBlock:
        resp = self._q("GetMemoryMap", query_pb2.GetMemoryMapRequest(program_id=self.id, read=self._read()))
        for b in list(resp.blocks) + list(resp.rejected):
            if (isinstance(region, str) and b.region_id == region) or (
                not isinstance(region, str) and not b.region_id and b.range.first.offset == region
            ):
                return b
        raise NotFound(grpc.StatusCode.NOT_FOUND, f"no region {region!r} in the memory map")

    def update_memory_region(
        self,
        region: Union[str, int],
        *,
        name: Optional[str] = None,
        start: Optional[int] = None,
        size: Optional[int] = None,
        perms: Optional[str] = None,
        initialized: Optional[bool] = None,
        volatile: Optional[bool] = None,
        validate_only: bool = False,
        actor: Optional[str] = None,
        reason: str = "",
    ) -> project_pb2.UpdateMemoryRegionResponse:
        """Changes a region added after import (by its id) or one of the image's
        blocks (by its start address: name, ``perms`` and ``volatile`` only). Fields
        left None keep their current values. Retract ``response.assertion.seq`` to undo."""
        b = self._block(region)
        cur = "".join(c if on else "-" for c, on in zip("rwx", (b.read, b.write, b.execute)))
        r = self._region(
            b.name if name is None else name,
            b.range.first.offset if start is None else start,
            (b.range.last.offset - b.range.first.offset + 1) if size is None else size,
            cur if perms is None else perms,
            b.initialized if initialized is None else initialized,
            b.is_volatile if volatile is None else volatile,
        )
        req = project_pb2.UpdateMemoryRegionRequest(
            program_id=self.id, region=r, provenance=self.client._prov(actor, reason), validate_only=validate_only
        )
        if isinstance(region, str):
            req.region_id = region
        else:
            req.block_start.CopyFrom(address(region))
        return self.client._call(self.client.stubs.projects.UpdateMemoryRegion, req)

    def remove_memory_region(
        self, region: Union[str, int], *, actor: Optional[str] = None, reason: str = ""
    ) -> project_pb2.RemoveMemoryRegionResponse:
        """Removes a region added after import (by its id), or reverts the edits to
        one of the image's blocks (by its start address). Retract
        ``response.assertion.seq`` to undo."""
        req = project_pb2.RemoveMemoryRegionRequest(program_id=self.id, provenance=self.client._prov(actor, reason))
        if isinstance(region, str):
            req.region_id = region
        else:
            req.block_start.CopyFrom(address(region))
        return self.client._call(self.client.stubs.projects.RemoveMemoryRegion, req)

    def image_base(self) -> int:
        """Where the image is (its lowest loaded address, as ``summary().image_base``)."""
        return self.summary().image_base.offset

    def import_image_base(self) -> int:
        """Where the image was imported (api_minor 45, feature ``rebase``): every fact
        is kept relative to it, and ``image_base()`` differs after ``set_image_base``."""
        return self.summary().import_image_base.offset

    def set_image_base(
        self, base: int, *, validate_only: bool = False, actor: Optional[str] = None, reason: str = ""
    ) -> project_pb2.SetImageBaseResponse:
        """Moves the whole program to a new image base (api_minor 45, feature ``rebase``;
        docs/memory-map.md, "Rebase"), as Ghidra's Set Image Base: its blocks, functions,
        symbols and every fact recorded about it (names, comments, types, listing edits,
        patches, notes, memory regions, references) and their history. One assertion:
        retract ``response.assertion.seq`` to move it back. ``validate_only`` checks
        that the image fits there."""
        req = project_pb2.SetImageBaseRequest(
            program_id=self.id, image_base=base, provenance=self.client._prov(actor, reason), validate_only=validate_only
        )
        return self.client._call(self.client.stubs.projects.SetImageBase, req)

    def set_language(
        self,
        language_id: str,
        compiler_spec_id: str = "",
        *,
        validate_only: bool = False,
        actor: Optional[str] = None,
        reason: str = "",
    ) -> project_pb2.SetProgramLanguageResponse:
        """Changes the language the program is decoded and analyzed in (``SetProgramLanguage``,
        api_minor 73, feature ``set-language``; docs/api.md, "Changing a program's language"), as
        Ghidra's Set Language: same bytes, same addresses, every name, comment and type kept,
        analysis run again. ``language_id`` "" goes back to the language it was imported with; an
        empty ``compiler_spec_id`` takes the language's default. One assertion: retract
        ``response.assertion.seq`` to go back. Refused (FAILED_PRECONDITION) for a language that
        lays memory out differently: import the file again instead."""
        req = project_pb2.SetProgramLanguageRequest(
            program_id=self.id,
            language_id=language_id,
            compiler_spec_id=compiler_spec_id,
            provenance=self.client._prov(actor, reason),
            validate_only=validate_only,
        )
        return self.client._call(self.client.stubs.projects.SetProgramLanguage, req)

    def compare_languages(self, language_ids: Optional[Sequence[str]] = None) -> project_pb2.CompareLanguagesResponse:
        """How well each variant of the program's processor decodes its code (``CompareLanguages``,
        api_minor 73): per language and mode, the share of sampled bytes decoded, invalid and
        unimplemented instructions, and the code control flow reaches, with the variant
        auto-detection picks marked ``recommended``. Default: the variants in the program's byte
        order that it can change to; ``language_ids`` names others."""
        req = project_pb2.CompareLanguagesRequest(program_id=self.id, language_ids=list(language_ids or []))
        return self.client._call(self.client.stubs.projects.CompareLanguages, req)

    def load_pdb(
        self,
        path: Optional[Union[str, os.PathLike]] = None,
        *,
        local_file: Optional[Union[str, os.PathLike, bytes]] = None,
        symbol_path: bool = False,
        force: bool = False,
        actor: Optional[str] = None,
        reason: str = "",
    ) -> project_pb2.LoadPdbResponse:
        """Loads a PDB into the program (``LoadPdb``, api_minor 49, feature
        ``pdb-load``; docs/pdb.md): ``path`` on the daemon's host, a
        ``local_file`` sent with :meth:`Client.upload`, or with
        ``symbol_path`` the one the program's CodeView record names, looked up
        along the daemon's symbol path. Its names, prototypes and types become
        import:pdb assertions; another build's PDB needs ``force``. The
        response says the file, whether it is this build's (``exact``) and
        what it brought (``functions``, ``variables``, ``types``)."""
        req = project_pb2.LoadPdbRequest(program_id=self.id, force=force, provenance=self.client._prov(actor, reason))
        if symbol_path:
            req.symbol_path = True
        elif local_file is not None:
            req.upload_id = self.client.upload(local_file)
        elif path is not None:
            req.path = os.fspath(path)
        else:
            raise ValueError("load_pdb needs a path, a local_file or symbol_path=True")
        return self.client._call(self.client.stubs.projects.LoadPdb, req)

    def load_debug_file(
        self,
        path: Optional[Union[str, os.PathLike]] = None,
        *,
        local_file: Optional[Union[str, os.PathLike, bytes]] = None,
        search: bool = False,
        force: bool = False,
        actor: Optional[str] = None,
        reason: str = "",
    ) -> project_pb2.LoadDebugFileResponse:
        """Loads an ELF's separate debug file (``LoadDebugFile``, api_minor 86,
        feature ``debug-files``): ``path`` on the daemon's host, a
        ``local_file`` sent with :meth:`Client.upload`, or with ``search`` the
        one the program's build ID or .gnu_debuglink names, looked up beside
        the binary, in the settings' directories, /usr/lib/debug, the cache,
        then (only when an admin turned them on) debuginfod servers. Its DWARF
        becomes import:dwarf assertions; another build's file needs
        ``force``. ``search_log`` says where it looked."""
        req = project_pb2.LoadDebugFileRequest(program_id=self.id, force=force, provenance=self.client._prov(actor, reason))
        if search:
            req.search = True
        elif local_file is not None:
            req.upload_id = self.client.upload(local_file)
        elif path is not None:
            req.path = os.fspath(path)
        else:
            raise ValueError("load_debug_file needs a path, a local_file or search=True")
        return self.client._call(self.client.stubs.projects.LoadDebugFile, req)

    def read_memory(self, addr: AddressLike, length: int) -> bytes:
        req = query_pb2.ReadMemoryRequest(program_id=self.id, address=address(addr), length=length, read=self._read())
        return self._q("ReadMemory", req).data

    def byte_view(self, addr: AddressLike, length: int) -> query_pb2.GetByteViewResponse:
        """The byte viewer's read (api_minor 44, feature "byte-viewer"): up to
        64 KiB from ``addr`` as patched (zeros where there is no memory),
        ``runs`` saying what the listing makes of the bytes (a run per
        instruction or data item, undefined and uninitialized coalesced) and
        ``patched`` with the file's bytes where a patch changed them."""
        req = query_pb2.GetByteViewRequest(program_id=self.id, address=address(addr), length=length, read=self._read())
        return self._q("GetByteView", req)

    def overview(self, buckets: int = 0) -> query_pb2.GetOverviewResponse:
        """The memory blocks in about ``buckets`` slices (0: 512), each with
        its bytes by kind (code, data, undefined, external, uninitialized)
        and its entropy in bits per byte (api_minor 44, feature "overview")."""
        req = query_pb2.GetOverviewRequest(program_id=self.id, buckets=buckets, read=self._read())
        return self._q("GetOverview", req)

    def find_next(self, addr: AddressLike, kind: str, *, backward: bool = False) -> Optional[int]:
        """The next (``backward``: previous) place of a kind from ``addr``, or
        None: ``"instruction"``, ``"data"``, ``"undefined"`` (the next run of
        them, as Ghidra's Next Instruction), ``"label"``, ``"function"``,
        ``"different_byte"`` or ``"note"`` (api_minor 44, feature "find-next")."""
        k = query_pb2.NavigationKind.Value("NAVIGATION_KIND_" + kind.upper())
        req = query_pb2.FindNextRequest(program_id=self.id, read=self._read(), kind=k, backward=backward)
        getattr(req, "from").CopyFrom(address(addr))
        resp = self._q("FindNext", req)
        return resp.address.offset if resp.found else None

    def symbol_address(self, name: str) -> Optional[int]:
        """The address of the symbol with exactly this name (demangled or as the
        file spells it), a function's before a label's; None if there is none."""
        found = list(itertools.islice(self.symbols(name_equals=name, page_size=50), 50))
        if not found:
            return None
        funcs = [s for s in found if s.kind == listing_pb2.SYMBOL_KIND_FUNCTION]
        return (funcs or found)[0].address.offset

    def file_offset_address(self, offset: int) -> Optional[int]:
        """The address a file offset is loaded at (an initialized block's bytes), or None."""
        for b in self.memory_map():
            size = b.range.last.offset - b.range.first.offset
            if b.has_file_offset and b.initialized and b.file_offset <= offset <= b.file_offset + size:
                return b.range.first.offset + (offset - b.file_offset)
        return None

    def resolve(self, where: Union[int, str]) -> int:
        """An address from a Go To expression, as the UI's palette reads one
        (revkit.expr): a number (hex: ``401040``, ``0x401040``), a symbol
        (``main``, ``geo::Shape::scale``, a mangled name), arithmetic
        (``main+0x10``, ``(tbl - 8) / 2``), a file offset (``file:0x200``) or a
        space's address (``mem:0x100``). Raises ``revkit.expr.ExprError`` (a
        ValueError) for text that names nothing."""
        if isinstance(where, int):
            return where
        text = where.strip()
        if not text:
            raise ExprError("empty address")
        if is_number(text):
            return parse_number(text)
        # A whole name first: C++ names hold characters expressions don't
        # ("std::vector<int>::push_back", "operator new").
        whole = self.symbol_address(text)
        if whole is not None:
            return whole
        spaces: dict = {}

        def space_info() -> dict:
            if not spaces:
                for s in self.summary().spaces:
                    if not s.alias and (s.is_default or s.key_base):
                        spaces[s.name.lower()] = s
                spaces.setdefault("", None)
            return spaces

        def space_address(name: str, offset: int) -> Optional[int]:
            s = space_info().get(name.lower())
            return None if s is None else s.key_base + offset * max(1, s.word_size)

        r = Resolver(symbol=self.symbol_address, file_offset=self.file_offset_address,
                     is_space=lambda n: bool(n) and n.lower() in space_info(), space_address=space_address)
        return evaluate_text(text, r)

    def functions(self, name_contains: str = "", *, by_name: bool = False, page_size: int = 500) -> Iterator[listing_pb2.Function]:
        """All functions, paging transparently; all pages come from one snapshot."""
        req = query_pb2.ListFunctionsRequest(
            program_id=self.id,
            read=self._read(),
            name_contains=name_contains,
            sort=listing_pb2.FUNCTION_SORT_NAME if by_name else listing_pb2.FUNCTION_SORT_ADDRESS,
        )
        return self._paged("ListFunctions", req, "functions", page_size)

    def symbols(self, name_contains: str = "", *, name_equals: str = "", page_size: int = 5000) -> Iterator[listing_pb2.Symbol]:
        """Functions and labels by effective name, in address order (feature ``symbols``)."""
        req = query_pb2.ListSymbolsRequest(
            program_id=self.id, read=self._read(), name_contains=name_contains, name_equals=name_equals
        )
        return self._paged("ListSymbols", req, "symbols", page_size)

    def demangled(self, addr: AddressLike) -> Optional[common_pb2.DemangledName]:
        """The other spellings of the name at ``addr``, where it is the demangler
        analysis's name for a mangled symbol (api_minor 40, feature ``demangle``;
        docs/demangle.md): ``.mangled`` (as the file spells it) and ``.full``
        (the demangler's output, parameters included). None where the name
        isn't demangled (or a rename replaced it)."""
        a = address(addr)
        req = query_pb2.ListSymbolsRequest(program_id=self.id, read=self._read(),
                                           range=common_pb2.AddressRange(first=a, last=a))
        for s in self._paged("ListSymbols", req, "symbols", 10):
            return s.demangled if s.HasField("demangled") else None
        return None

    def mangled_name(self, addr: AddressLike) -> str:
        """The mangled symbol the name at ``addr`` was demangled from ("" if none)."""
        d = self.demangled(addr)
        return d.mangled if d is not None else ""

    def preview(self, addr: AddressLike, *, lines: int = PREVIEW_LINES, rows: int = 8, timeout_ms: int = 5000) -> dict:
        """What is at ``addr``, as the UI's hover card previews it (api_minor 47,
        feature ``hover``; docs/ui.md "Hover cards"): for a function's entry
        ``{"kind": "function", "address", "name", "signature", "lines"}`` with
        the first ``lines`` of its C (its listing rows when it doesn't
        decompile), else ``{"kind": "data", "address", "name", "lines"}`` with
        ``rows`` listing rows from there and the symbol's name ("" if none)."""
        a = address(addr)

        def listing_rows() -> list:
            out = []
            for r in self.listing(a, max_rows=rows, omit_bytes=True).rows:
                label = r.labels[0].name + ": " if r.labels else ""
                out.append(f"{r.address.offset:x}  {label}{''.join(t.text for t in r.tokens)}".rstrip())
            return out

        try:
            fn = self.function(a)
        except NotFound:
            fn = None
        if fn is not None:
            text = None
            try:
                req = query_pb2.DecompileRequest(program_id=self.id, function=a, read=self._read())
                req.options.timeout_ms = timeout_ms
                resp = self._q("Decompile", req)
                if resp.HasField("function") and not resp.HasField("failure"):
                    text = preview_lines(resp.function, lines)
            except RevkitError:
                text = None
            # No prototype recorded: the decompiler's signature line.
            signature = fn.prototype or (text[0] if text and len(text) > 1 else fn.name)
            return {"kind": "function", "address": a.offset, "name": fn.name, "signature": signature,
                    "lines": text if text is not None else listing_rows()}
        req = query_pb2.ListSymbolsRequest(program_id=self.id, read=self._read(), range=common_pb2.AddressRange(first=a, last=a))
        name = next((s.name for s in self._paged("ListSymbols", req, "symbols", 4) if s.address.offset == a.offset), "")
        return {"kind": "data", "address": a.offset, "name": name, "lines": listing_rows()}

    def describe_scalar(self, value: int, bits: int = 64) -> dict:
        """``scalar_text(value, bits)`` and, as the hover card adds, ``symbol``:
        the name of the symbol at that address ("" if none) and ``block``: the
        memory block it is in ("" if none)."""
        out = scalar_text(value, bits)
        u = int(out["unsigned"])
        req = query_pb2.ListSymbolsRequest(program_id=self.id, read=self._read(),
                                           range=common_pb2.AddressRange(first=address(u), last=address(u)))
        out["symbol"] = next((s.name for s in self._paged("ListSymbols", req, "symbols", 4) if s.address.offset == u), "")
        blocks = self._q("GetMemoryMap", query_pb2.GetMemoryMapRequest(program_id=self.id, read=self._read())).blocks
        out["block"] = next((b.name for b in blocks if b.range.first.offset <= u <= b.range.last.offset), "")
        return out

    def function(self, addr: AddressLike, *, containing: bool = False) -> listing_pb2.Function:
        req = query_pb2.GetFunctionRequest(program_id=self.id, address=address(addr), containing=containing, read=self._read())
        return self._q("GetFunction", req).function

    def listing(
        self,
        start: Optional[AddressLike] = None,
        end: Optional[AddressLike] = None,
        *,
        rows: Optional[tuple] = None,
        max_rows: int = 200,
        rows_before: int = 0,
        omit_bytes: bool = False,
    ) -> query_pb2.GetListingResponse:
        """A listing page by address window (``start``/``end``) or row window (``rows=(first, count)``)."""
        req = query_pb2.GetListingRequest(program_id=self.id, read=self._read(), omit_bytes=omit_bytes)
        if rows is not None:
            req.rows.first_row, req.rows.row_count = rows
        else:
            req.addresses.start.CopyFrom(address(start or 0))
            if end is not None:
                req.addresses.end.CopyFrom(address(end))
            req.addresses.max_rows = max_rows
            req.addresses.rows_before = rows_before
        return self._q("GetListing", req)

    def instruction(self, addr: AddressLike) -> listing_pb2.InstructionDetail:
        req = query_pb2.GetInstructionRequest(program_id=self.id, address=address(addr), read=self._read())
        return self._q("GetInstruction", req).instruction

    def xrefs(
        self,
        addr: Optional[AddressLike] = None,
        *,
        range: Optional[tuple] = None,
        direction: str = "to",
        page_size: int = 500,
    ) -> Iterator[listing_pb2.Xref]:
        """References ``to``, ``from`` or ``both`` an address or an inclusive (first, last) range."""
        dirs = {"to": listing_pb2.XREF_DIRECTION_TO, "from": listing_pb2.XREF_DIRECTION_FROM, "both": listing_pb2.XREF_DIRECTION_BOTH}
        req = query_pb2.GetXrefsRequest(program_id=self.id, direction=dirs[direction], read=self._read())
        if range is not None:
            req.range.CopyFrom(address_range(*range))
        else:
            req.address.CopyFrom(address(addr))
        return self._paged("GetXrefs", req, "xrefs", page_size)

    def xrefs_to(self, addr: AddressLike) -> list:
        return list(self.xrefs(addr, direction="to"))

    def xrefs_from(self, addr: AddressLike) -> list:
        return list(self.xrefs(addr, direction="from"))

    def decompile(self, entry: AddressLike, *, text: bool = True):
        """The decompiled function (token lines, variables, prototype; ``.text`` when ``text``).
        ``.unknowns`` (api_minor 97) lists what it couldn't determine: indirect calls with no
        known target, unrecovered switch tables, a failure; each origin's ``tier`` says how far
        to trust a name or type (revkit.evidence)."""
        return self.decompile_result(entry, text=text).function

    def decompile_result(self, entry: AddressLike, *, text: bool = True) -> query_pb2.DecompileResponse:
        """The whole Decompile response: ``.function``, ``.failure`` (set when the decompiler
        failed) and ``.snapshot`` (the revision it was read at)."""
        req = query_pb2.DecompileRequest(program_id=self.id, function=address(entry), read=self._read())
        req.options.include_text = text
        return self._q("Decompile", req)

    _SLICE_KINDS = {
        "def_use": query_pb2.SLICE_KIND_DEF_USE,
        "forward": query_pb2.SLICE_KIND_FORWARD,
        "backward": query_pb2.SLICE_KIND_BACKWARD,
        "forward_ops": query_pb2.SLICE_KIND_FORWARD_OPS,
        "backward_ops": query_pb2.SLICE_KIND_BACKWARD_OPS,
    }

    def slice(
        self,
        function: AddressLike,
        kind: str = "backward",
        *,
        variable: Union[str, int, None] = None,
        token: Optional[tuple] = None,
        varnode: Optional[int] = None,
    ) -> "query_pb2.SliceDecompiledResponse":
        """Def-use chains and data-flow slices in a function's decompilation
        (api_minor 57, feature "decompile-slices"; Ghidra's Highlight Def-use,
        Forward and Backward Slice, and the operator slices). ``kind``:
        "def_use" (the value's definition and uses), "forward" (every value
        computed from it), "backward" (every value it is computed from),
        "forward_ops" / "backward_ops" (the operations those run through).
        Start from ``variable`` (its name as the decompilation shows it, or
        its index), ``token`` (``(line, index)`` in ``decompile(function)``'s
        lines) or ``varnode`` (an index into its ``varnodes``). Returns a
        SliceDecompiledResponse: ``tokens`` (line, token), ``addresses`` (the
        instructions, ascending), ``varnode_indices`` and ``start``."""
        if kind not in self._SLICE_KINDS:
            raise ValueError(f"kind: one of {', '.join(self._SLICE_KINDS)}")
        req = query_pb2.SliceDecompiledRequest(program_id=self.id, function=address(function), read=self._read(),
                                              kind=self._SLICE_KINDS[kind])
        if [variable is not None, token is not None, varnode is not None].count(True) != 1:
            raise ValueError("give one of variable, token or varnode")
        if token is not None:
            req.token.line, req.token.token = token
        elif varnode is not None:
            req.varnode_index = varnode
        elif isinstance(variable, int):
            req.variable_index = variable
        else:
            req.variable_index = self._variable_index(function, variable)
        return self._q("SliceDecompiled", req)

    def _variable_index(self, function: AddressLike, name: str) -> int:
        """A decompiled variable's index by the name the decompilation shows."""
        fn = self.decompile(function, text=False)
        found = [v.index for v in fn.variables if v.name == name]
        if not found:
            raise ValueError(f"no variable {name!r} in {fn.name}: {', '.join(v.name for v in fn.variables)}")
        return found[0]

    _TRACE_DIRECTIONS = {"backward": query_pb2.TRACE_DIRECTION_BACKWARD, "forward": query_pb2.TRACE_DIRECTION_FORWARD}

    def trace(
        self,
        function: AddressLike,
        direction: str = "backward",
        *,
        variable: Union[str, int, None] = None,
        token: Optional[tuple] = None,
        varnode: Optional[int] = None,
        max_depth: int = 0,
        max_functions: int = 0,
        max_nodes: int = 0,
        max_edges: int = 0,
    ) -> "query_pb2.TraceValueResponse":
        """A value traced across calls (``TraceValue``, api_minor 89, feature
        "value-trace"): ``slice()``'s backward or forward walk carried through
        direct calls, a call's output to the callee's returned values and a
        parameter to the callers' arguments (backward), an argument to the
        callee's parameter and a returned value to the calls' outputs
        (forward); calls are matched, so a walk that entered a callee from one
        call leaves through that call. Start from ``variable``, ``token`` or
        ``varnode`` as for ``slice()``. Budgets (0: the daemon's defaults:
        3 calls deep, 12 functions, 2000 values, 4000 edges). Returns a
        TraceValueResponse: ``functions`` (each with ``name``, ``depth`` and
        the C ``lines`` it touches), ``nodes`` and ``edges`` (kind DATAFLOW,
        ARGUMENT or RETURN), ``unknowns`` (where it couldn't follow: indirect
        calls, imports, memory, functions nothing calls, budgets) and
        ``truncated``."""
        if direction not in self._TRACE_DIRECTIONS:
            raise ValueError("direction: 'backward' or 'forward'")
        req = query_pb2.TraceValueRequest(program_id=self.id, function=address(function), read=self._read(),
                                          direction=self._TRACE_DIRECTIONS[direction], max_depth=max_depth,
                                          max_functions=max_functions, max_nodes=max_nodes, max_edges=max_edges)
        if [variable is not None, token is not None, varnode is not None].count(True) != 1:
            raise ValueError("give one of variable, token or varnode")
        if token is not None:
            req.token.line, req.token.token = token
        elif varnode is not None:
            req.varnode_index = varnode
        elif isinstance(variable, int):
            req.variable_index = variable
        else:
            req.variable_index = self._variable_index(function, variable)
        return self._q("TraceValue", req)

    def decompile_many(
        self,
        entries: Optional[Sequence[AddressLike]] = None,
        *,
        text: bool = True,
        parallelism: int = 0,
        timeout_ms: int = 0,
        rerun_at_head: bool = True,
    ) -> Iterator[query_pb2.DecompileManyResponse]:
        """Decompiles ``entries`` (None: every function) in one streaming call
        (api_minor 29, feature "script-batch"): results come in completion
        order, each with its ``index`` into ``entries``, ``entry``,
        ``function`` (``.text`` with ``text``), ``failure`` or ``error``, and
        timings. Every result is at one revision (this view's pin, else the
        head when the call starts). A pinned revision the daemon no longer
        keeps is rerun at the head when ``rerun_at_head``. ``parallelism``
        bounds decompilations in flight (0: the daemon's workers plus one)."""
        req = query_pb2.DecompileManyRequest(program_id=self.id, read=self._read(), parallelism=parallelism)
        if entries is None:
            req.all = True
        else:
            req.functions.extend(address(e) for e in entries)
            if not req.functions:
                return iter(())
        req.options.include_text = text
        req.options.timeout_ms = timeout_ms

        def stream():
            call = self.client.stubs.queries.DecompileMany(req, timeout=None)
            try:
                yield from call
            except grpc.RpcError as e:
                err = _error(e)
                if rerun_at_head and isinstance(err, FailedPrecondition) and "REVISION_EXPIRED" in err.message and req.read.revision:
                    req.read.revision = 0
                    try:
                        yield from self.client.stubs.queries.DecompileMany(req, timeout=None)
                    except grpc.RpcError as e2:
                        raise _error(e2) from None
                    return
                raise err from None
            finally:
                call.cancel()

        return stream()

    def decomp_scratch(
        self, function: AddressLike, *, module: str = "", timeout_ms: int = 0, dialect: Union[str, int] = "c11"
    ) -> "query_pb2.ExportDecompScratchResponse":
        """One function as a matching decompilation's starting scratch
        (``ExportDecompScratch``, api_minor 103, feature "nds"; docs/nds.md):
        ``text`` is a ``// PROBE: <mangled> <module> <address>`` line, Ghidra's
        built-in type names, the named types it uses, its callees'
        prototypes (from linked DS modules too) and the globals it reads,
        then its decompiled C; ``context`` and ``source`` split it for a
        decomp.me scratch. ``module`` overrides the PROBE line's module.
        ``dialect`` ``"c89"`` writes the context for old compilers (api_minor
        112). The scratch is of one revision; ``program.at(revision)`` pins it
        to an ``export_c``'s."""
        req = query_pb2.ExportDecompScratchRequest(
            program_id=self.id, function=address(function), read=self._read(), module=module, timeout_ms=timeout_ms,
            dialect=_c_dialect(dialect))
        return self._q("ExportDecompScratch", req)

    def export_c(
        self,
        entries: Optional[Sequence[AddressLike]] = None,
        *,
        header: bool = True,
        name: str = "",
        directory: Optional[str] = None,
        timeout_ms: int = 0,
        parallelism: int = 0,
        progress: Optional[Callable[[int, int], None]] = None,
        dialect: Union[str, int] = "c11",
        per_function: bool = False,
        wait_for_analysis: bool = False,
    ) -> "ExportedC":
        """Ghidra's C/C++ exporter (``ExportC``, api_minor 80, feature
        "export-c"): ``entries`` (None: every function) decompiled into one
        ``<name>.c`` in address order and, with ``header``, a ``<name>.h`` of
        the program's types (as ``export_type_archive(scope="all")``),
        Ghidra's built-in type names and each function's prototype, which
        the source includes. ``name`` defaults to the program's.
        ``progress(done, total)`` is called while the functions decompile.
        With ``directory``, the files are written there too.

        api_minor 112 (feature "c-dialect"): the header's types are as the
        decompiler sees them (its field names, a byte member named
        ``field_0x10`` for each byte no field covers) with the function types
        the C names, so the C compiles with it. ``dialect="c89"`` writes it
        for old compilers (CodeWarrior's). ``per_function`` gives each
        function's C on its own (``function_sources``; with ``directory``,
        a ``<name>/<entry>.c`` each, including the header), of the header's
        revision. ``wait_for_analysis`` first waits for the program's
        background analysis (inference) to finish, so the export has its
        prototypes and structures."""
        if wait_for_analysis:
            self.wait_for_analysis()
        req = query_pb2.ExportCRequest(program_id=self.id, read=self._read(), header=header, name=name,
                                       timeout_ms=timeout_ms, parallelism=parallelism, dialect=_c_dialect(dialect),
                                       per_function=per_function)
        if entries is None:
            req.all = True
        else:
            req.functions.extend(address(e) for e in entries)
            if not req.functions:
                raise ValueError("export_c: no functions given (None exports every one)")
        out = ExportedC(source_name="", source="")
        parts = []
        call = self.client.stubs.queries.ExportC(req, timeout=None)
        try:
            for m in call:
                out.revision = m.snapshot.revision
                if m.source_name:
                    out.source_name = m.source_name
                if m.header_name:
                    out.header_name, out.header = m.header_name, m.header
                    out.notes = list(m.notes)
                if m.source_part:
                    parts.append(m.source_part)
                out.function_sources.extend(m.function_sources)
                if progress is not None and m.total and not m.source_part and not m.function_sources and not m.finished:
                    progress(m.done, m.total)
                if m.finished:
                    out.functions = m.functions
                    out.failed = [a.offset for a in m.failed]
        except grpc.RpcError as e:
            raise _error(e) from None
        finally:
            call.cancel()
        out.source = "".join(parts)
        if directory is not None:
            os.makedirs(directory, exist_ok=True)
            if per_function:
                stem = out.source_name[:-2] if out.source_name.endswith(".c") else out.source_name
                os.makedirs(os.path.join(directory, stem), exist_ok=True)
                for fn in out.function_sources:
                    if not fn.source:
                        continue
                    text = ('#include "../%s"\n\n' % out.header_name if out.header_name else "") + fn.source
                    with open(os.path.join(directory, stem, "%08x.c" % fn.entry.offset), "w", encoding="utf-8",
                              newline="") as f:
                        f.write(text)
            else:
                with open(os.path.join(directory, out.source_name), "w", encoding="utf-8", newline="") as f:
                    f.write(out.source)
            if out.header_name:
                with open(os.path.join(directory, out.header_name), "w", encoding="utf-8", newline="") as f:
                    f.write(out.header)
        return out

    def instructions(
        self,
        first: Optional[AddressLike] = None,
        last: Optional[AddressLike] = None,
        *,
        function: Optional[AddressLike] = None,
        pcode: bool = True,
        limit: int = 0,
    ) -> Iterator[listing_pb2.InstructionDetail]:
        """The instructions in ``[first, last]`` (default: the whole program)
        or in ``function``'s body, decoded in full with p-code (as
        :meth:`instruction`), in address order, streamed (api_minor 29,
        feature "script-batch")."""
        req = query_pb2.ListInstructionsRequest(program_id=self.id, read=self._read(), omit_pcode=not pcode, limit=limit)
        if function is not None:
            req.function.CopyFrom(address(function))
        else:
            req.range.CopyFrom(address_range(first if first is not None else 0, last if last is not None else (1 << 64) - 1))

        def stream():
            call = self.client.stubs.queries.ListInstructions(req, timeout=None)
            try:
                for batch in call:
                    yield from batch.instructions
            except grpc.RpcError as e:
                raise _error(e) from None
            finally:
                call.cancel()

        return stream()

    def find_bytes(
        self,
        pattern: Union[str, bytes],
        mask: Optional[bytes] = None,
        *,
        first: Optional[AddressLike] = None,
        last: Optional[AddressLike] = None,
        max_results: int = 0,
        alignment: int = 0,
        executable_only: bool = False,
    ) -> list:
        """Addresses where ``pattern`` occurs in initialized memory (as
        patched), in address order: bytes with an optional ``mask``, or
        text like ``"48 8b ?? 05"`` (see :func:`byte_pattern`). At most
        ``max_results`` (0: 1000); every match with ``max_results=-1``.
        Searched on the daemon (api_minor 29, feature "script-batch")."""
        data, bits = byte_pattern(pattern, mask)
        everything = max_results < 0
        req = query_pb2.FindBytesRequest(
            program_id=self.id, pattern=data, mask=bits, read=self._read(),
            max_results=100000 if everything else max_results, alignment=alignment, executable_only=executable_only,
        )
        lo = int(first) if first is not None else 0
        hi = int(last) if last is not None else (1 << 64) - 1
        out = []
        while True:
            req.range.CopyFrom(address_range(lo, hi))
            resp = self._q("FindBytes", req)
            out.extend(a.offset for a in resp.addresses)
            if not (everything and resp.truncated and resp.addresses):
                return out
            lo = resp.addresses[-1].offset + 1
            if req.read.revision == 0:
                req.read.revision = resp.snapshot.revision

    # -- searches (api_minor 41, feature "search") ---------------------------------

    def _search(self, name: str, req, progress: Optional[Callable] = None, cancel=None, field: str = "matches") -> list:
        """Runs a streaming search to its end: the matches of every message.
        ``progress(message)`` sees each message (``bytes_searched`` /
        ``rows_searched`` / ``functions_done`` against the totals); setting
        ``cancel`` (a threading.Event) stops the search on the daemon. The
        last message is kept in ``self.last_search`` (``truncated``,
        ``elapsed_ms``, a memory search's ``pattern``)."""
        call = getattr(self.client.stubs.queries, name)(req, timeout=None)
        out = []
        try:
            for m in call:
                out.extend(getattr(m, field))
                self.last_search = m
                if progress:
                    progress(m)
                if cancel is not None and cancel.is_set():
                    call.cancel()
                    break
        except grpc.RpcError as e:
            if cancel is not None and cancel.is_set() and e.code() == grpc.StatusCode.CANCELLED:
                return out
            raise _error(e) from None
        return out

    @staticmethod
    def _scope(ranges, code_units: Optional[Sequence[str]] = None, executable_only: bool = False) -> query_pb2.SearchScope:
        scope = query_pb2.SearchScope(executable_only=executable_only)
        for r in ranges or ():
            first, last = r
            scope.ranges.append(address_range(first, last))
        units = set(code_units or ())
        bad = units - {"instructions", "data", "undefined"}
        if bad:
            raise ValueError(f"code_units: {sorted(bad)} (instructions, data, undefined)")
        scope.instructions = "instructions" in units
        scope.defined_data = "data" in units
        scope.undefined = "undefined" in units
        return scope

    @staticmethod
    def _start(start: Optional[AddressLike], backward: bool, wrap: bool) -> query_pb2.SearchStart:
        s = query_pb2.SearchStart(backward=backward, wrap=wrap)
        if start is not None:
            getattr(s, "from").CopyFrom(address(start))
        return s

    _FORMATS = {"hex": 1, "string": 2, "decimal": 3, "float": 4, "double": 5, "binary": 6, "regex": 7}
    _ENCODINGS = {"ascii": 1, "utf8": 2, "utf-8": 2, "utf16": 3, "utf-16": 3}
    _ORDERS = {None: 0, "program": 0, "little": 1, "big": 2}
    _TEXT_FIELDS = {"comments": 1, "labels": 2, "functions": 3, "mnemonics": 4, "operands": 5, "data_mnemonics": 6, "data_values": 7}

    def search_memory(
        self,
        query: str,
        *,
        format: str = "hex",
        encoding: str = "ascii",
        case_sensitive: bool = False,
        escapes: bool = False,
        size: int = 4,
        unsigned: bool = False,
        byte_order: Optional[str] = None,
        ranges: Optional[Sequence[tuple]] = None,
        code_units: Optional[Sequence[str]] = None,
        executable_only: bool = False,
        alignment: int = 0,
        start: Optional[AddressLike] = None,
        backward: bool = False,
        wrap: bool = False,
        max_results: int = 1000,
        details: bool = True,
        progress: Optional[Callable] = None,
        cancel=None,
    ) -> list:
        """Ghidra's Search Memory on the daemon (api_minor 41, feature
        "search"): ``query`` read as ``format`` -- "hex" ("48 8b ?? e8",
        nibble wildcards "4?"), "string" (in ``encoding`` ascii, utf8 or
        utf16; ASCII letters in either case unless ``case_sensitive``;
        ``escapes`` reads \\n, \\xHH, \\uHHHH), "decimal" (values of
        ``size`` 1, 2, 4 or 8 bytes, ``unsigned``), "float", "double",
        "binary" ("10xx0101") or "regex" (RE2 over bytes) -- in
        ``byte_order`` (None: the program's; "little", "big"). Where:
        ``ranges`` [(first, last)], ``code_units`` (any of "instructions",
        "data", "undefined"), ``executable_only``, ``alignment``. From
        ``start`` (exclusive) forward or ``backward``, ``wrap``-ing at the
        end; at most ``max_results`` (``self.last_search.truncated`` says
        there were more). Returns MemoryMatch messages: ``address``,
        ``bytes``, and with ``details`` ``label``, ``preview`` (the code
        unit as the listing shows it) and the function."""
        if format not in self._FORMATS:
            raise ValueError(f"format {format!r}: one of {', '.join(self._FORMATS)}")
        if encoding.lower() not in self._ENCODINGS:
            raise ValueError(f"encoding {encoding!r}: ascii, utf8 or utf16")
        if byte_order not in self._ORDERS:
            raise ValueError(f"byte_order {byte_order!r}: None, 'little' or 'big'")
        req = query_pb2.SearchMemoryRequest(
            program_id=self.id, read=self._read(), format=self._FORMATS[format], query=query,
            encoding=self._ENCODINGS[encoding.lower()], case_sensitive=case_sensitive, escape_sequences=escapes,
            value_size=size, unsigned_values=unsigned, byte_order=self._ORDERS[byte_order],
            scope=self._scope(ranges, code_units, executable_only), alignment=alignment,
            start=self._start(start, backward, wrap), max_results=max_results, details=details,
        )
        return self._search("SearchMemory", req, progress, cancel)

    def search_text(
        self,
        query: str,
        *,
        regex: bool = False,
        case_sensitive: bool = False,
        whole_word: bool = False,
        fields: Optional[Sequence[str]] = None,
        ranges: Optional[Sequence[tuple]] = None,
        start: Optional[AddressLike] = None,
        backward: bool = False,
        wrap: bool = False,
        max_results: int = 1000,
        progress: Optional[Callable] = None,
        cancel=None,
    ) -> list:
        """Ghidra's Search Program Text on the daemon (feature "search"):
        what the listing shows -- ``fields`` of comments, labels, functions
        (signatures), mnemonics, operands, data_mnemonics, data_values (None:
        all) -- matched as plain text or a ``regex`` (RE2), so renames count.
        Returns TextMatch messages: ``address``, ``field``, ``text`` (the
        line) and the match's ``match_start`` / ``match_length`` (UTF-8
        bytes), ``comment_kind``, ``label``, the function."""
        bad = set(fields or ()) - set(self._TEXT_FIELDS)
        if bad:
            raise ValueError(f"fields: {sorted(bad)} (one of {', '.join(self._TEXT_FIELDS)})")
        req = query_pb2.SearchTextRequest(
            program_id=self.id, read=self._read(), query=query, regex=regex, case_sensitive=case_sensitive,
            whole_word=whole_word, fields=[self._TEXT_FIELDS[f] for f in fields or ()], scope=self._scope(ranges),
            start=self._start(start, backward, wrap), max_results=max_results,
        )
        return self._search("SearchText", req, progress, cancel)

    def search_scalars(
        self,
        min: Optional[int] = None,
        max: Optional[int] = None,
        *,
        value: Optional[int] = None,
        instructions: bool = True,
        data: bool = True,
        ranges: Optional[Sequence[tuple]] = None,
        start: Optional[AddressLike] = None,
        backward: bool = False,
        wrap: bool = False,
        max_results: int = 1000,
        progress: Optional[Callable] = None,
        cancel=None,
    ) -> list:
        """Ghidra's Search for Scalars (feature "search"): instructions'
        operands and defined data whose value (signed, or as unsigned) is
        ``value``, or in [``min``, ``max``] (None: open). Returns ScalarMatch
        messages: ``address``, ``value`` (signed), ``unsigned_value``,
        ``bits``, ``operand_index`` (-1 for data), ``data``, ``text`` (the
        instruction or data as shown), ``label``, the function."""
        if value is not None:
            min = max = value
        if not instructions and not data:
            raise ValueError("instructions, data or both")
        req = query_pb2.SearchScalarsRequest(
            program_id=self.id, read=self._read(),
            scope=self._scope(ranges, [u for u, on in (("instructions", instructions), ("data", data)) if on] if not (instructions and data) else None),
            start=self._start(start, backward, wrap), max_results=max_results,
        )
        if min is not None:
            req.min = min
        if max is not None:
            req.max = max
        return self._search("SearchScalars", req, progress, cancel)

    def search_decompiled(
        self,
        query: str,
        *,
        regex: bool = False,
        case_sensitive: bool = False,
        whole_word: bool = False,
        functions: Optional[Sequence[AddressLike]] = None,
        ranges: Optional[Sequence[tuple]] = None,
        parallelism: int = 0,
        timeout_ms: int = 0,
        max_results: int = 1000,
        progress: Optional[Callable] = None,
        cancel=None,
    ) -> list:
        """Searches decompiled C (feature "search"; Ghidra's Decompiler Text
        Finder) over DecompileMany's workers and cache: ``functions`` by
        entry, or those whose entry is in ``ranges``, else every function.
        Returns DecompiledMatch messages: ``function``, ``function_name``,
        ``line`` (index into DecompiledFunction.lines), ``text``,
        ``match_start`` / ``match_length``, ``address``. ``progress`` sees
        ``functions_done`` of ``functions_total``."""
        req = query_pb2.SearchDecompiledRequest(
            program_id=self.id, read=self._read(), query=query, regex=regex, case_sensitive=case_sensitive,
            whole_word=whole_word, parallelism=parallelism, timeout_ms=timeout_ms, max_results=max_results,
        )
        if functions is None and ranges is None:
            req.all = True
        for f in functions or ():
            req.functions.append(address(f))
        for first, last in ranges or ():
            req.ranges.append(address_range(first, last))
        if not req.all and not req.functions and not req.ranges:
            return []
        return self._search("SearchDecompiled", req, progress, cancel)

    # -- find uses of a type or field (api_minor 53, feature "type-uses") ----------

    def find_type_uses(
        self,
        struct: Union[str, "types_pb2.TypeDefinition"],
        field: Union[str, int, None] = None,
        *,
        functions: Optional[Sequence[AddressLike]] = None,
        ranges: Optional[Sequence[tuple]] = None,
        parallelism: int = 0,
        timeout_ms: int = 0,
        max_results: int = 1000,
        progress: Optional[Callable] = None,
        cancel=None,
    ) -> list:
        """Where a struct or union, or one of its fields, is used (Ghidra's Find
        Uses of; QueryService.FindTypeUses) in the decompiled C of every
        function (or ``functions`` by entry, or those in ``ranges``), over
        DecompileMany's workers and cache.

        ``struct`` is a type hash or a name ("struct node", "node");
        ``field`` a field's name or its offset (an int or "0x10"), or None
        for every use of the type: its fields and the type named in
        declarations and casts. Returns TypeUse messages: ``function``,
        ``function_name``, ``kind`` (TYPE_USE_KIND_FIELD or _TYPE),
        ``access`` (FIELD_ACCESS_READ, _WRITE, _READ_WRITE, _ADDRESS),
        ``address``, ``line``, ``text``, ``match_start`` /
        ``match_length``, ``field_name``, ``field_offset``. ``progress``
        sees ``functions_done`` of ``functions_total``; setting ``cancel``
        (a threading.Event) stops the work."""
        t = struct if isinstance(struct, types_pb2.TypeDefinition) else self.composite_type(struct)
        req = query_pb2.FindTypeUsesRequest(program_id=self.id, read=self._read(), type_hash=t.hash,
                                            parallelism=parallelism, timeout_ms=timeout_ms, max_results=max_results)
        if field is not None:
            if isinstance(field, str) and re.fullmatch(r"\s*(0x[0-9a-fA-F]+|\d+)\s*", field):
                field = int(field.strip(), 0)
            if isinstance(field, int):
                req.field_offset = field
            else:
                f = next((f for f in t.composite.fields if f.name == field), None)
                if f is None:
                    raise ValueError(f"{t.name} has no field {field}")
                req.field_offset = f.offset
                req.field_name = field
        if functions is None and ranges is None:
            req.all = True
        for f in functions or ():
            req.functions.append(address(f))
        for first, last in ranges or ():
            req.ranges.append(address_range(first, last))
        if not req.all and not req.functions and not req.ranges:
            return []
        return self._search("FindTypeUses", req, progress, cancel, field="uses")

    def data(
        self,
        *categories: str,
        text_contains: str = "",
        first: Optional[AddressLike] = None,
        last: Optional[AddressLike] = None,
        page_size: int = 1000,
    ) -> Iterator[query_pb2.DefinedData]:
        """Defined data in address order (``ListData``): every category, or
        those named ("string", "pointer", "undefined", "typed", "defined"), paging
        transparently from one snapshot."""
        cats = []
        for c in categories:
            name = "DATA_CATEGORY_" + c.upper()
            if name not in query_pb2.DataCategory.keys():
                raise ValueError(f"unknown data category {c!r}")
            cats.append(query_pb2.DataCategory.Value(name))
        req = query_pb2.ListDataRequest(program_id=self.id, read=self._read(), categories=cats, text_contains=text_contains)
        if first is not None or last is not None:
            req.range.CopyFrom(address_range(first if first is not None else 0, last if last is not None else (1 << 64) - 1))
        return self._paged("ListData", req, "data", page_size)

    def symbol_tree(self, *path: str, name_contains: str = "", page_size: int = 500) -> Iterator[query_pb2.SymbolTreeNode]:
        """Ghidra's symbol tree, one level (``ListSymbolTree``, api_minor 82,
        feature "symbol-tree"): no ``path`` lists the folders (Imports,
        Exports, Functions, Labels, Classes, Namespaces, each with
        ``.children``); ``symbol_tree("Imports")`` the libraries,
        ``symbol_tree("Imports", lib)`` their imports,
        ``symbol_tree("Classes", "geo::Circle")`` a class's members,
        ``symbol_tree("Namespaces", "geo", "util")`` a namespace's inner
        scopes and symbols. Each node has ``.name``, ``.kind``, ``.address``
        (symbols), ``.full_name`` and ``.children`` (scopes)."""
        req = query_pb2.ListSymbolTreeRequest(program_id=self.id, read=self._read(), path=list(path),
                                              name_contains=name_contains)
        return self._paged("ListSymbolTree", req, "nodes", page_size)

    def providers(self, *, refresh: bool = False) -> provider_pb2.ListProvidersResponse:
        """What this program's file is to the external decompilers (a .NET
        assembly, a DEX, ...), and which take it (:meth:`Client.providers`)."""
        return self.client.providers(program_id=self.id, refresh=refresh)

    def decompile_external(self, *, provider: str = "", refresh: bool = False) -> "ExternalDecompilation":
        """The program's file through an external decompiler: ILSpy's C# for a .NET
        assembly, jadx's Java for a DEX, ... (:meth:`Client.decompile_external`)."""
        return self.client.decompile_external(program_id=self.id, provider=provider, refresh=refresh)

    def build_info(self) -> query_pb2.GetBuildInfoResponse:
        """Build metadata the toolchain left in the file (``GetBuildInfo``,
        api_minor 88, feature "build-info"; docs/build-info.md). ``.go`` (when
        ``HasField("go")``): ``.go_version``, ``.path``, ``.main`` and ``.deps``
        (``GoModule``: ``.path``, ``.version``, ``.sum``, ``.replacement``),
        ``.settings`` (key/value: ``-ldflags``, ``GOOS``, ``GOARCH``,
        ``CGO_ENABLED``, ``vcs.revision``, ``vcs.time``, ...) and ``.format``
        ("inline" for Go 1.18 and later, "pointer" before). ``.rust`` (when
        ``HasField("rust")``): cargo-auditable's ``.packages`` (``.name``,
        ``.version``, ``.source``, ``.kind``, ``.dependencies`` as indexes,
        ``.root``). ``.rustc_version`` and ``.rustc_commits`` for Rust binaries,
        ``.warnings`` for metadata that didn't decode. ``.go_pclntab`` (when
        ``HasField("go_pclntab")``; api_minor 93, feature "go-pclntab";
        docs/go.md): a Go program's function table, which stripped binaries
        keep: ``.layout`` ("1.2", "1.16", "1.18", "1.20"), ``.address``,
        ``.function_count``, ``.functions_read``, ``.file_count``,
        ``.text_start``, ``.moduledata``, ``.found_by`` ("section", "symbol",
        "scan"). Its functions are named at import (provenance analysis:go)."""
        return self._q("GetBuildInfo", query_pb2.GetBuildInfoRequest(program_id=self.id, read=self._read()))

    def relocations(self, text_contains: str = "", *, first: Optional[AddressLike] = None,
                    last: Optional[AddressLike] = None, page_size: int = 1000) -> Iterator[query_pb2.ProgramRelocation]:
        """The relocations the file carries, in address order (``ListRelocations``,
        api_minor 78, feature "relocation-table"): ELF dynamic and object
        relocations, PE base relocations. Each has ``.address``, ``.type`` and
        ``.type_name`` ("R_X86_64_JUMP_SLOT"), ``.kind``, ``.symbol``,
        ``.addend``, ``.target`` (when ``HasField("target")``; ``.target_name``) and
        ``.original`` (the bytes there). ``text_contains`` matches the symbol
        or the type name, in any case."""
        req = query_pb2.ListRelocationsRequest(program_id=self.id, read=self._read(), text_contains=text_contains)
        if first is not None or last is not None:
            req.range.CopyFrom(address_range(first if first is not None else 0, last if last is not None else (1 << 64) - 1))
        return self._paged("ListRelocations", req, "relocations", page_size)

    def comments(self, *kinds: str, text_contains: str = "", first: Optional[AddressLike] = None,
                 last: Optional[AddressLike] = None, page_size: int = 1000) -> Iterator[query_pb2.ProgramComment]:
        """Every comment of the program in address order (``ListComments``,
        api_minor 77, feature "comment-table"): the kinds named ("eol",
        "pre", "post", "plate", "repeatable", "decompiler"; none: all), with
        ``.address``, ``.kind``, ``.text``, ``.function_name``, ``.label``,
        ``.origin``."""
        ks = []
        for k in kinds:
            name = "COMMENT_KIND_" + k.upper()
            if name not in assertion_pb2.CommentKind.keys():
                raise ValueError(f"unknown comment kind {k!r}")
            ks.append(assertion_pb2.CommentKind.Value(name))
        req = query_pb2.ListCommentsRequest(program_id=self.id, read=self._read(), kinds=ks, text_contains=text_contains)
        if first is not None or last is not None:
            req.range.CopyFrom(address_range(first if first is not None else 0, last if last is not None else (1 << 64) - 1))
        return self._paged("ListComments", req, "comments", page_size)

    def strings(self, text_contains: str = "", *, min_length: int = 0) -> Iterator[query_pb2.DefinedData]:
        """The strings data analysis found (``ListData``, category STRING), in
        address order: ``.address``, ``.value`` (the characters), ``.label``,
        ``.xref_to_count``."""
        for d in self.data("string", text_contains=text_contains):
            if len(d.value) >= min_length:
                yield d

    def classes(self, name_contains: str = "") -> List[query_pb2.RttiClass]:
        """C++ classes from MSVC RTTI (``GetClassHierarchy``, api_minor 45,
        feature ``msvc-rtti``; docs/pe.md), by name: ``.name``, ``.bases``
        (``.name``, ``.direct``, ``.is_virtual``, ``.offset``), ``.derived``,
        ``.vftables`` (``.name``, ``.functions`` with ``.slot``, ``.entry``,
        ``.name``) and ``.type_hash``, the struct ``this`` points to."""
        req = query_pb2.GetClassHierarchyRequest(program_id=self.id, read=self._read(), name_contains=name_contains)
        return list(self._q("GetClassHierarchy", req).classes)

    def objc_classes(self, name_contains: str = "") -> query_pb2.ListObjcClassesResponse:
        """A Mach-O's Objective-C classes, protocols and Swift types (``ListObjcClasses``,
        api_minor 91, feature ``objc``; docs/macho.md), from the runtime's metadata in the
        file: ``.classes`` (``.name``, ``.superclass``, ``.methods`` with ``.selector``,
        ``.types``, ``.implementation``, ``.category`` and ``.function_name``, ``.ivars``,
        ``.properties``, ``.protocols``, ``.categories``), ``.protocols`` and
        ``.swift_types``. ``name_contains`` filters by name, in any case."""
        req = query_pb2.ListObjcClassesRequest(program_id=self.id, read=self._read(), name_contains=name_contains)
        return self._q("ListObjcClasses", req)

    def calling_conventions(self) -> List[query_pb2.CallingConvention]:
        """The calling conventions a function of the program can have
        (``ListCallingConventions``, api_minor 58, feature
        ``calling-conventions``): the compiler spec's prototype models and
        aliases, the default first (``.is_default``), each with ``.c_spelling``,
        how a prototype's C declaration says it ("__stdcall",
        "__attribute__((ms_abi))"; empty when C can't). Set one with
        ``retype`` on the function and a declaration using that spelling."""
        req = query_pb2.ListCallingConventionsRequest(program_id=self.id)
        return list(self._q("ListCallingConventions", req).conventions)

    def types(self, *hashes: str, dependencies: bool = False):
        req = query_pb2.GetTypesRequest(program_id=self.id, hashes=list(hashes), include_dependencies=dependencies)
        return self._q("GetTypes", req)

    def parse_c(
        self,
        *texts: str,
        paths: Sequence[str] = (),
        name: str = "",
        include_dirs: Sequence[str] = (),
        system_include_dirs: Sequence[str] = (),
        defines: Sequence[str] = (),
        undefines: Sequence[str] = (),
        profile: str = "",
        prototypes: bool = False,
        defines_as_enum: bool = False,
        cplusplus: bool = False,
        include_system: bool = False,
    ) -> types_pb2.ParseCResponse:
        """Parses C (header text, or ``paths`` on the daemon's host under its
        --browse-root) for this program's target: types as DefineType-ready
        nodes, the named types with how each compares with the program's,
        constants, prototypes and line-numbered diagnostics. Asserts nothing
        (api_minor 25, feature "parse-c"); ``import_header`` imports the result.
        ``defines`` are ``"NAME"`` or ``"NAME=VALUE"``."""
        sources = [types_pb2.ParseCSource(text=t, name=name) for t in texts]
        sources += [types_pb2.ParseCSource(path=p) for p in paths]
        req = types_pb2.ParseCRequest(
            program_id=self.id,
            sources=sources,
            include_dirs=list(include_dirs),
            system_include_dirs=list(system_include_dirs),
            defines=list(defines),
            undefines=list(undefines),
            profile=profile,
            options=types_pb2.ParseCOptions(
                prototypes=prototypes, defines_as_enum=defines_as_enum, cplusplus=cplusplus, include_system=include_system
            ),
            read=self._read(),
        )
        return self.client._call(self.client.stubs.types.ParseC, req)

    def import_header(
        self,
        parsed: Union[str, types_pb2.ParseCResponse],
        keys: Optional[Sequence[str]] = None,
        *,
        file: str = "",
        include_identical: bool = False,
        actor: Optional[str] = "import:header",
        session: str = "",
        reason: str = "",
        categories: str = "chosen",
        **parse_kw,
    ) -> assertion_pb2.AppendAssertionsResponse:
        """Imports a header's types: defines them and binds their names
        (``header_import_bodies``) in one AppendAssertions, so the import is
        one revision and one undo. ``parsed`` is a ``parse_c`` result or the
        header's text (parsed with ``parse_kw``).

        Provenance is ``import:header`` (an admin's, against a daemon with
        accounts; pass ``actor=None`` for the client's own), with ``file`` as
        its version and a session of its own per import (a fresh one unless
        given): ``revert(session=resp.assertions[0].provenance.session)``
        undoes exactly this import. The imported types are filed under the
        header's name (``categories="none"``: not filed).
        """
        if isinstance(parsed, str):
            parsed = self.parse_c(parsed, name=file, **parse_kw)
        bodies = header_import_bodies(parsed, keys, include_identical=include_identical, categories=categories)
        if not bodies:
            raise ValueError("nothing to import: every chosen type is already the program's")
        prov = self.client._prov(actor, reason)
        if actor is not None and actor.startswith("import:"):
            prov.version = file or prov.version
        prov.session = session or f"import-{uuid.uuid4().hex[:12]}"
        req = assertion_pb2.AppendAssertionsRequest(
            program_id=self.id,
            assertions=[assertion_pb2.AssertionInput(body=b) for b in bodies],
            provenance=prov,
        )
        return self.client._call(self.client.stubs.assertions.AppendAssertions, req)

    # -- structures from pointer use and from data (api_minor 32, feature "auto-struct") --

    _MODES = {"create": 1, "fill": 2}

    def auto_structure(
        self,
        function: AddressLike,
        storage_key: str,
        *,
        fill: bool = False,
        call_depth: Optional[int] = None,
        name: str = "",
    ) -> types_pb2.AutoStructureResponse:
        """A structure from how a variable (``storage_key`` from the
        function's decompilation: ``"param:0"``, ``"stack:-0x28"``) is used as
        a pointer: Ghidra's Auto Create Structure, or with ``fill`` its Auto
        Fill in Structure (the variable must point to a structure). Follows
        the pointer ``call_depth`` calls deep (default 1). A preview: asserts
        nothing; ``apply_structure`` (or ``auto_create_structure``) applies it."""
        req = types_pb2.AutoStructureRequest(
            program_id=self.id,
            variable=types_pb2.AutoStructureVariable(function=address(function), storage_key=storage_key),
            mode=self._MODES["fill" if fill else "create"],
            name=name,
            read=self._read(),
        )
        if call_depth is not None:
            req.call_depth = call_depth
        return self.client._call(self.client.stubs.types.AutoStructure, req)

    def structure_from_range(self, first: AddressLike, last: AddressLike, *, name: str = "") -> types_pb2.AutoStructureResponse:
        """A structure of the data defined in [first, last] (a listing
        selection), undefined filler elsewhere. A preview: asserts nothing."""
        req = types_pb2.AutoStructureRequest(program_id=self.id, range=address_range(first, last), name=name, read=self._read())
        return self.client._call(self.client.stubs.types.AutoStructure, req)

    def apply_structure(
        self,
        made: types_pb2.AutoStructureResponse,
        *,
        function: Optional[AddressLike] = None,
        storage_key: str = "",
        at: Optional[AddressLike] = None,
        actor: Optional[str] = None,
        reason: str = "",
    ) -> assertion_pb2.AppendAssertionsResponse:
        """Applies a structure (``auto_structure_bodies``) in one revision:
        retract the returned seqs to undo it."""
        bodies = auto_structure_bodies(made, function=function, storage_key=storage_key, at=at)
        return self.append(*bodies, actor=actor, reason=reason)

    def auto_create_structure(self, function: AddressLike, storage_key: str, *, call_depth: Optional[int] = None,
                              name: str = "", **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Auto Create Structure: a new structure from the variable's use,
        bound by name, and the variable retyped to a pointer to it."""
        made = self.auto_structure(function, storage_key, call_depth=call_depth, name=name)
        return self.apply_structure(made, function=function, storage_key=storage_key, **kw)

    def auto_fill_structure(self, function: AddressLike, storage_key: str, *, call_depth: Optional[int] = None,
                            **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Auto Fill in Structure: the structure the variable points to, with
        fields added where its use shows some and it has none."""
        made = self.auto_structure(function, storage_key, fill=True, call_depth=call_depth)
        return self.apply_structure(made, function=function, storage_key=storage_key, **kw)

    def create_structure(self, first: AddressLike, last: AddressLike, *, name: str = "", **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Create Structure from a selection: a structure of the data defined
        in [first, last], defined there."""
        made = self.structure_from_range(first, last, name=name)
        return self.apply_structure(made, at=first, **kw)

    # -- a struct's or union's field renamed or retyped (Rename Field, Retype Field) --
    # As the UI's Types view does it (ui/src/ui/types.ts editField, ui/src/data/cgen.ts):
    # the struct's next version written as C (unchanged fields by hash, a struct's
    # fields at their offsets with undefined filler between), laid out by ParseC,
    # then defined and bound to the struct's name in one edit (one undo).

    _COMPOSITES = (types_pb2.TYPE_KIND_STRUCT, types_pb2.TYPE_KIND_UNION)

    def composite_type(self, struct: str) -> types_pb2.TypeDefinition:
        """A struct or union by its hash, or by name ("struct foo", "foo", or a
        typedef of one, followed to it): the program's definition of the name."""
        text = struct.strip()
        if re.fullmatch(r"[0-9a-f]{16,64}", text):
            found = list(self.types(text).types)
            if not found:
                raise ValueError(f"the program has no type {text}")
            t = found[0]
            if t.superseded and t.name and t.kind in self._COMPOSITES:  # an older version: edit the current one
                kw = "struct" if t.kind == types_pb2.TYPE_KIND_STRUCT else "union"
                return self.composite_type(f"{kw} {t.name}")
        else:
            m = re.fullmatch(r"(struct|union|typedef)\s+(\S+)", text)
            kw, name = (m.group(1), m.group(2)) if m else ("", text)
            kinds = {"struct": [types_pb2.TYPE_KIND_STRUCT], "union": [types_pb2.TYPE_KIND_UNION],
                     "typedef": [types_pb2.TYPE_KIND_TYPEDEF]}.get(kw)
            found = [t for t in self.find_types(name) if t.name == name and (kinds is None or t.kind in kinds)]
            if not found:
                raise ValueError(f"the program has no struct or union named {text} (find_types lists its types)")
            found.sort(key=lambda t: (not t.bound, t.kind not in self._COMPOSITES, not t.complete))
            t = found[0]
        for _ in range(16):  # through typedefs and qualifiers to the struct
            target = t.typedef_type.target_hash if t.HasField("typedef_type") else (
                t.qualified.target_hash if t.HasField("qualified") else "")
            if not target:
                break
            got = list(self.types(target).types)
            if not got:
                break
            t = got[0]
        if t.kind not in self._COMPOSITES or not t.HasField("composite"):
            raise ValueError(f"{t.display or t.name or struct} is not a struct or union")
        if not t.name:
            raise ValueError(f"{t.display} has no name of its own (an anonymous member's): edit the type that holds it")
        if not t.complete:
            raise ValueError(f"{t.display} is only declared, with no fields")
        return t

    def field_edit_bodies(self, struct: Union[str, types_pb2.TypeDefinition], field: Union[str, int], *,
                          name: Optional[str] = None, type: Optional[str] = None) -> tuple:
        """The assertions that rename (``name``) or retype (``type``, C such as
        ``"char *"`` or ``"struct node *"``) one field of a struct or union, and
        what they do: ``(bodies, info)`` with info's ``key`` ("struct foo"),
        ``field`` (its old name), ``offset``, ``old_type``, ``new_name``,
        ``new_type`` and ``c_definition`` (the struct as it will be).

        ``struct`` is a hash or a name (``composite_type``); ``field`` the
        field's name, or its offset (an int, or "0x10") where only one field
        starts there. A retyped struct field keeps its offset and the others
        theirs: a type that would overlap the next field, or end past the
        struct's size, is refused (redefine the struct with import_header)."""
        if (name is None) == (type is None):
            raise ValueError("give a new name or a new type")
        t = struct if isinstance(struct, types_pb2.TypeDefinition) else self.composite_type(struct)
        deps = {d.hash: d for d in self.types(t.hash, dependencies=True).types}
        is_struct = t.kind == types_pb2.TYPE_KIND_STRUCT
        kw = "struct" if is_struct else "union"
        key = f"{kw} {t.name}"
        self_ref = re.compile(rf"\b{kw}\s+{re.escape(t.name)}\b")

        drafts = []
        for f in t.composite.fields:
            ft = deps.get(f.type_hash)
            d = {"name": f.name, "offset": f.offset, "bit_offset": f.bit_offset, "bit_size": f.bit_size, "flex": False,
                 "hash": f.type_hash, "shown": ft.display if ft else f.type_hash[:8],
                 "size": ft.size if ft else -1, "align": (ft.alignment or -1) if ft else -1}
            if ft is not None and ft.HasField("array") and ft.array.count == 0:  # a flexible array member
                et = deps.get(ft.array.element_hash)
                d.update(flex=True, hash=ft.array.element_hash, shown=et.display if et else "",
                         size=et.size if et else 0, align=(et.alignment or 1) if et else 1)
            d["expr"] = f"__typeof__({d['shown']})" if self_ref.search(d["shown"]) else f"__revkit_type_{d['hash']}"
            drafts.append(d)

        # The field.
        if isinstance(field, str) and re.fullmatch(r"\s*(0x[0-9a-fA-F]+|\d+)\s*", field):
            field = int(field.strip(), 0)
        if isinstance(field, int):
            at = [d for d in drafts if d["offset"] == field and not d["bit_size"]]
            if len(at) != 1:
                names = ", ".join(d["name"] or "(unnamed)" for d in at)
                raise ValueError(f"{key} has no field at 0x{field:x}" if not at else
                                 f"{key} has several fields at 0x{field:x} ({names}): give the field's name")
            f = at[0]
        else:
            named = [d for d in drafts if d["name"] == field]
            if not named:
                have = ", ".join(d["name"] for d in drafts if d["name"])[:400]
                raise ValueError(f"{key} has no field {field!r} (it has: {have})")
            f = named[0]
        info = {"key": key, "field": f["name"], "offset": f["offset"], "old_type": f["shown"],
                "new_name": f["name"], "new_type": f["shown"]}

        if name is not None:
            to = name.strip()
            if not re.fullmatch(r"[A-Za-z_]\w*", to):
                raise ValueError("a field name is a C name: letters, digits, _")
            if to != f["name"] and any(d is not f and d["name"] == to for d in drafts):
                raise ValueError(f"{key} already has a field {to}")
            f["name"] = info["new_name"] = to
        else:
            to = type.strip().rstrip(";").strip()
            if not to:
                raise ValueError("the field's type is empty")
            # Its size and alignment where C puts it after a char.
            probe = self.parse_c(f"struct __rk_probe_0 {{ char c; __typeof__({to}) x; }};\n", name="edit.h")
            errs = [d.text for d in probe.diagnostics if d.severity == types_pb2.PARSE_C_SEVERITY_ERROR]
            pn = next((n for n in probe.named if n.key == "struct __rk_probe_0"), None)
            node = probe.nodes[pn.index] if pn is not None else None
            if errs or node is None or len(node.fields) < 2:
                raise ValueError(f"the type {to!r}: " + ("; ".join(errs[:3]) or "doesn't parse"))
            f["align"] = node.fields[1].offset
            f["size"] = node.size - f["align"]
            if f["flex"]:
                f["flex"] = False
            f["expr"] = f"__typeof__({to})"
            info["new_type"] = to

        def decl(d) -> str:
            anonymous = not d["name"] and d["expr"].startswith("__revkit_type_")
            nm = "" if anonymous else " " + (d["name"] or "field")
            return f"{d['expr']}{nm}{'[]' if d['flex'] else ''}{' : %d' % d['bit_size'] if d['bit_size'] else ''};"

        def gap(bits: int) -> str:
            return " ".join(["unsigned char : 8;"] * (bits // 8) + ([f"unsigned char : {bits % 8};"] if bits % 8 else []))

        natural = max([d["align"] for d in drafts if d["align"] > 0] or [1])
        attrs = ["packed"] if is_struct else []
        if not t.composite.packed and t.alignment > natural:
            attrs.append(f"aligned({t.alignment})")
        lines = [f"{kw} {t.name} {{"]
        order = sorted(drafts, key=lambda d: (d["offset"], d["bit_offset"])) if is_struct else drafts
        if is_struct:
            pos, before = 0, None
            for d in order:
                start = d["offset"] * 8 + d["bit_offset"]
                if start < pos:
                    raise ValueError(f"{key}: {before['name'] or 'a field'} would end at 0x{(pos + 7) // 8:x}, over "
                                     f"{d['name'] or 'the field'} at 0x{d['offset']:x} (retype that field too, or "
                                     "redefine the struct with import_header)")
                if start > pos:
                    lines.append(gap(start - pos))
                lines.append(decl(d))
                if d["size"] < 0 and not d["bit_size"]:
                    raise ValueError(f"{key}: the size of {d['name'] or 'a field'}'s type isn't known")
                pos = start + (d["bit_size"] if d["bit_size"] else 0 if d["flex"] else d["size"] * 8)
                before = d
            end = t.size * 8
            if end > pos:
                lines.append(gap(end - pos))
            elif end < pos:
                raise ValueError(f"{key}: {before['name'] or 'the last field'} would end at 0x{(pos + 7) // 8:x}, past the "
                                 f"struct's size 0x{t.size:x} (redefine the struct with import_header to grow it)")
        else:
            lines += [decl(d) for d in drafts]
        lines.append("}" + (f" __attribute__(({', '.join(attrs)}))" if attrs else "") + ";")
        parsed = self.parse_c("\n".join(lines) + "\n", name="edit.h")
        errs = [d.text for d in parsed.diagnostics if d.severity == types_pb2.PARSE_C_SEVERITY_ERROR]
        if errs:
            raise ValueError(f"{key}: " + "; ".join(errs[:3]))
        named = next((n for n in parsed.named if n.key == key), None)
        if named is None:
            raise ValueError(f"no {key} in the C")
        node = parsed.nodes[named.index]
        if len(node.fields) != len(order):
            raise ValueError(f"{key}: the C declares {len(node.fields)} fields, the struct has {len(order)}")
        if is_struct:
            for d, nf in zip(order, node.fields):
                if nf.offset != d["offset"] or nf.bit_offset != d["bit_offset"]:
                    raise ValueError(f"{key}: the target's layout rules put {d['name'] or 'a field'} at 0x{nf.offset:x}, "
                                     f"not 0x{d['offset']:x}")
        if named.existing_hash == named.hash:
            raise ValueError(f"no change to {key}")
        info["c_definition"] = named.c_definition
        info["hash"] = named.hash
        return header_import_bodies(parsed, [key], include_identical=True, categories="none"), info

    def rename_field(self, struct: str, field: Union[str, int], new_name: str, *, actor: Optional[str] = None,
                     reason: str = "") -> assertion_pb2.AppendAssertionsResponse:
        """Renames a field of a struct or union (by hash or name; the field by name
        or offset) as one edit: every use of the struct shows the new name."""
        bodies, _ = self.field_edit_bodies(struct, field, name=new_name)
        return self.append(*bodies, actor=actor, reason=reason)

    def retype_field(self, struct: str, field: Union[str, int], c_type: str, *, actor: Optional[str] = None,
                     reason: str = "") -> assertion_pb2.AppendAssertionsResponse:
        """Sets the type of a field of a struct or union from C ("char *",
        "struct node *", "uint8_t[16]") as one edit; the other fields keep their offsets."""
        bodies, _ = self.field_edit_bodies(struct, field, type=c_type)
        return self.append(*bodies, actor=actor, reason=reason)

    def find_types(self, name_contains: str = "", page_size: int = 500, *, category: str = "", exact: bool = False):
        """The program's named types (``FindTypes``), paging transparently;
        with ``category`` only those filed in it and below it (``exact``:
        only in it; ``"/"`` with ``exact``: the ones with no category)."""
        req = query_pb2.FindTypesRequest(program_id=self.id, name_contains=name_contains, read=self._read(),
                                         category=category, category_exact=exact)
        return self._paged("FindTypes", req, "types", page_size)

    def type_categories(self) -> dict:
        """Every category the program files a named type under, with how many
        types are directly in it (``"/"``: those with no category) (api_minor 35)."""
        req = query_pb2.FindTypesRequest(program_id=self.id, read=self._read(), include_categories=True,
                                         summary_only=True)
        req.page.page_size = 1
        resp = self._q("FindTypes", req)
        return {c.path: c.types for c in resp.categories}

    def set_type_category(self, keys: Union[str, Sequence[str]], path: str, *, actor: Optional[str] = None,
                          reason: str = "") -> assertion_pb2.AppendAssertionsResponse:
        """Files named types ("struct cJSON") under a category ("/net/http";
        "" or "/": the top), in one revision (api_minor 35)."""
        if isinstance(keys, str):
            keys = [keys]
        return self.append(*(type_category_body(k, path) for k in keys), actor=actor, reason=reason)

    # -- type archives (api_minor 35, feature "type-archive") --------------------------

    def export_type_archive(
        self,
        keys: Sequence[str] = (),
        *,
        scope: str = "",
        hashes: Sequence[str] = (),
        category: str = "",
        name: str = "",
        directory: Optional[str] = None,
    ) -> types_pb2.ExportTypeArchiveResponse:
        """The program's types as a type archive: a C header (``.header``,
        ``.header_name``) and a JSON sidecar of hashes, categories, provenance
        and the data model (``.sidecar``, ``.sidecar_name``). ``scope`` is
        ``"selected"`` (``keys`` and ``hashes``), ``"category"``
        (``category`` and below), ``"user"`` (the types made, edited or
        imported in revkit) or ``"all"``; by default whichever the arguments
        say, else ``"user"``. With ``directory``, both files are written
        there too. ``.notes`` says what the header doesn't reproduce."""
        if scope and scope not in _ARCHIVE_SCOPES:
            raise ValueError(f"scope is one of {sorted(_ARCHIVE_SCOPES)}")
        req = types_pb2.ExportTypeArchiveRequest(
            program_id=self.id, scope=_ARCHIVE_SCOPES.get(scope, 0), keys=list(keys), hashes=list(hashes),
            category=category, name=name, read=self._read(),
        )
        resp = self.client._call(self.client.stubs.types.ExportTypeArchive, req)
        if directory is not None:
            os.makedirs(directory, exist_ok=True)
            with open(os.path.join(directory, resp.header_name), "w", encoding="utf-8", newline="") as f:
                f.write(resp.header)
            with open(os.path.join(directory, resp.sidecar_name), "w", encoding="utf-8", newline="") as f:
                f.write(resp.sidecar)
        return resp

    def parse_type_archive(self, header: str, sidecar: str, *, name: str = "") -> types_pb2.ParseCResponse:
        """ParseC of a type archive's header with its sidecar: for the
        sidecar's data model, each type checked against its hash
        (``.archive``: ``verified``, ``mismatches``, ``header_changed``).
        The rest previews the import as a header's does."""
        if not name:
            try:
                name = json.loads(sidecar).get("header", "")
            except ValueError:
                name = ""
        req = types_pb2.ParseCRequest(
            program_id=self.id,
            sources=[types_pb2.ParseCSource(text=header, name=name or "archive.h")],
            archive_sidecar=sidecar,
            read=self._read(),
        )
        return self.client._call(self.client.stubs.types.ParseC, req)

    def import_type_archive(
        self,
        archive: Union[str, types_pb2.ParseCResponse, types_pb2.ExportTypeArchiveResponse],
        sidecar: Optional[str] = None,
        *,
        actor: Optional[str] = "import:archive",
        session: str = "",
        reason: str = "",
        allow_mismatches: bool = False,
    ) -> Optional[assertion_pb2.AppendAssertionsResponse]:
        """Imports a type archive in one revision (one undo): its types
        defined and their names bound where the program doesn't have them
        already (a library archive's definition counts as none), and filed
        under the archive's categories. ``archive`` is a header path (its
        sidecar beside it, ``<stem>.json``, unless ``sidecar`` names one),
        a ``parse_type_archive`` result, or another program's
        ``export_type_archive`` response. Refuses an archive whose types
        don't parse to the sidecar's hashes unless ``allow_mismatches``.

        Provenance is ``import:archive`` with the archive's origin as its
        version, so exporting these types again gives the same files.
        Returns None when there is nothing to do (importing it again)."""
        if isinstance(archive, types_pb2.ExportTypeArchiveResponse):
            archive = self.parse_type_archive(archive.header, archive.sidecar, name=archive.header_name)
        elif isinstance(archive, str):
            header_path = archive
            sidecar_path = sidecar or os.path.splitext(header_path)[0] + ".json"
            with open(header_path, encoding="utf-8", newline="") as f:
                header = f.read()
            with open(sidecar_path, encoding="utf-8") as f:
                side = f.read()
            archive = self.parse_type_archive(header, side, name=os.path.basename(header_path))
        parsed = archive
        if not parsed.HasField("archive"):
            raise ValueError("not a type archive's parse: parse it with its sidecar (parse_type_archive)")
        if parsed.archive.mismatches and not allow_mismatches:
            keys = ", ".join(m.key for m in list(parsed.archive.mismatches)[:5])
            raise ValueError(f"{len(parsed.archive.mismatches)} type(s) don't parse to the sidecar's hashes ({keys})")
        bodies = header_import_bodies(parsed, include_library=True, categories="all")
        if not bodies:
            return None
        prov = self.client._prov(actor, reason)
        if actor is not None and actor.startswith("import:"):
            prov.version = parsed.archive.origin
        prov.session = session or f"archive-{uuid.uuid4().hex[:12]}"
        req = assertion_pb2.AppendAssertionsRequest(
            program_id=self.id,
            assertions=[assertion_pb2.AssertionInput(body=b) for b in bodies],
            provenance=prov,
        )
        return self.client._call(self.client.stubs.assertions.AppendAssertions, req)

    # -- project-wide types and archives (api_minor 52, feature "project-types") -----

    def project_types(self, name_contains: str = "", page_size: int = 500):
        """The project's named types this program sees (``FindTypes`` with
        ``TYPE_SOURCE_PROJECT``): every program of the project sees them,
        after its own definition of a name."""
        req = query_pb2.FindTypesRequest(program_id=self.id, name_contains=name_contains, read=self._read(),
                                         sources=[query_pb2.TYPE_SOURCE_PROJECT])
        return self._paged("FindTypes", req, "types", page_size)

    def _copy_types(self, keys, mode, actor, reason) -> types_pb2.CopyTypesResponse:
        if isinstance(keys, str):
            keys = [keys]
        req = types_pb2.CopyTypesRequest(program_id=self.id, keys=list(keys), mode=mode,
                                         provenance=self.client._prov(actor, reason))
        return self.client._call(self.client.stubs.types.CopyTypes, req)

    def move_types_to_project(self, keys: Union[str, Sequence[str]], *, actor: Optional[str] = None,
                              reason: str = "") -> types_pb2.CopyTypesResponse:
        """Moves named types ("struct cJSON") to project scope with every
        type they reach, in one revision: every program of the project sees
        them, and an edit at project scope (``append_project``) reaches them
        all. The program's own definitions of the names are retracted."""
        return self._copy_types(keys, types_pb2.COPY_TYPES_MODE_MOVE_TO_PROJECT, actor, reason)

    def copy_types_to_program(self, keys: Union[str, Sequence[str]], *, actor: Optional[str] = None,
                              reason: str = "") -> types_pb2.CopyTypesResponse:
        """Copies project types into this program and binds their names
        here: the program's copy then wins, and the program can change it
        alone."""
        return self._copy_types(keys, types_pb2.COPY_TYPES_MODE_COPY_TO_PROGRAM, actor, reason)

    def append_project(self, *bodies: assertion_pb2.AssertionBody, actor: Optional[str] = None,
                       reason: str = "") -> assertion_pb2.AppendAssertionsResponse:
        """Appends define_type, bind_type_name and type_category bodies at
        project scope (one revision): types every program of the project
        sees, laid out for this program's data model."""
        req = assertion_pb2.AppendAssertionsRequest(
            program_id=self.id,
            assertions=[assertion_pb2.AssertionInput(body=b) for b in bodies],
            provenance=self.client._prov(actor, reason),
            project_scope=True,
        )
        return self.client._call(self.client.stubs.assertions.AppendAssertions, req)

    def type_archives(self) -> list:
        """The type archives for this program's project (``ListTypeArchives``):
        revkit's shipped library archives (``applies`` for this program's
        format and data model), Ghidra's ("ghidra") and those attached to the
        project, each ``enabled`` or not."""
        req = types_pb2.ListTypeArchivesRequest(program_id=self.id, read=self._read())
        return list(self.client._call(self.client.stubs.types.ListTypeArchives, req).archives)

    def _archive_setting(self, setting, actor, reason):
        body = assertion_pb2.AssertionBody(type_archive=setting)
        return self.append(body, actor=actor, reason=reason)

    def set_type_archive_enabled(self, name: str, enabled: bool, *, actor: Optional[str] = None,
                                 reason: str = "") -> assertion_pb2.AppendAssertionsResponse:
        """Turns a type archive on or off for every program of the project:
        a shipped one ("libc-lp64"), Ghidra's ("ghidra") or an attached one."""
        setting = assertion_pb2.TypeArchiveSetting(name=name, enabled=enabled)
        return self._archive_setting(setting, actor, reason)

    def attach_type_archive(self, archive: Union[str, types_pb2.ExportTypeArchiveResponse], sidecar: Optional[str] = None,
                            *, name: str = "", enabled: bool = True, actor: Optional[str] = None,
                            reason: str = "") -> assertion_pb2.AppendAssertionsResponse:
        """Attaches a type archive to the project: its prototypes apply by
        name to every program's functions (library rank) and its types are
        library types of every program. ``archive`` is a header path (its
        sidecar ``<stem>.json`` beside it, if any, unless ``sidecar`` names
        one), header text with ``name``, or an ``export_type_archive``
        response."""
        if isinstance(archive, types_pb2.ExportTypeArchiveResponse):
            header, side = archive.header, archive.sidecar
            name = name or os.path.splitext(archive.header_name)[0]
        elif os.path.exists(archive) and "\n" not in archive:
            with open(archive, encoding="utf-8", newline="") as f:
                header = f.read()
            side = ""
            side_path = sidecar or os.path.splitext(archive)[0] + ".json"
            if os.path.exists(side_path):
                with open(side_path, encoding="utf-8") as f:
                    side = f.read()
            name = name or os.path.splitext(os.path.basename(archive))[0]
        else:
            header, side = archive, sidecar or ""
        if not name:
            raise ValueError("name is required for an archive given as text")
        setting = assertion_pb2.TypeArchiveSetting(name=name, enabled=enabled, header=header, sidecar=side)
        return self._archive_setting(setting, actor, reason)

    def detach_type_archive(self, name: str, *, actor: Optional[str] = None,
                            reason: str = "") -> assertion_pb2.AppendAssertionsResponse:
        """Detaches an archive attached to the project (or clears a shipped
        archive's setting: back to on)."""
        return self._archive_setting(assertion_pb2.TypeArchiveSetting(name=name, detach=True), actor, reason)

    # -- assertions ----------------------------------------------------------------

    def key(self, kind: Union[str, int], addr: AddressLike, sub: str = "") -> common_pb2.FactKey:
        return fact_key(self.id, kind, addr, sub)

    def append(
        self,
        *bodies: assertion_pb2.AssertionBody,
        actor: Optional[str] = None,
        reason: str = "",
        expected_head_revision: int = 0,
        validate_only: bool = False,
        skip_invalid: bool = False,
    ) -> assertion_pb2.AppendAssertionsResponse:
        """Appends assertions atomically (one revision). Provenance defaults to the client's actor.

        A refused body refuses the batch (``RevkitError`` naming each index and
        why); with ``skip_invalid`` the others land and ``response.refused``
        lists the left-out ones (``index``, ``reason``; api_minor 104)."""
        req = assertion_pb2.AppendAssertionsRequest(
            program_id=self.id,
            assertions=[assertion_pb2.AssertionInput(body=b) for b in bodies],
            provenance=self.client._prov(actor, reason),
            expected_head_revision=expected_head_revision,
            validate_only=validate_only,
            skip_invalid=skip_invalid,
        )
        return self.client._call(self.client.stubs.assertions.AppendAssertions, req)

    # -- patching (api_minor 27, feature "patch"; revkit.patching, docs/patching.md) --

    def _p(self, name, request):
        return self.client._call(getattr(self.client.stubs.patch, name), request)

    def assemble(self, addr: AddressLike, text: str, *, context: Optional[dict] = None, complete: bool = False,
                 cursor: int = 0, max_candidates: int = 0) -> patch_pb2.AssembleResponse:
        """Encodings of one line at ``addr`` (ranked), or the error and what was
        expected; with ``complete``, the completions at ``cursor``."""
        return self._p("Assemble", patch_pb2.AssembleRequest(
            program_id=self.id, address=address(addr), text=text, complete=complete, cursor=cursor,
            max_candidates=max_candidates, context=context or {}, read=self._read()))

    def patch_instruction(self, addr: AddressLike, text: str, *, encoding: bytes = b"", pad: bool = False,
                          context: Optional[dict] = None, actor=None, reason: str = "",
                          expected_head_revision: int = 0) -> patch_pb2.PatchInstructionResponse:
        """Assembles ``text`` at ``addr`` and writes it (the first candidate, or
        ``encoding``); ``pad`` fills a shorter replacement with NOPs."""
        return self._p("PatchInstruction", patch_pb2.PatchInstructionRequest(
            program_id=self.id, address=address(addr), text=text, bytes=encoding, pad=pad, context=context or {},
            provenance=self.client._prov(actor, reason), expected_head_revision=expected_head_revision))

    def patch_bytes(self, addr: AddressLike, data: bytes, *, actor=None, reason: str = "",
                    expected_head_revision: int = 0) -> patch_pb2.PatchBytesResponse:
        return self._p("PatchBytes", patch_pb2.PatchBytesRequest(
            program_id=self.id, address=address(addr), data=data, provenance=self.client._prov(actor, reason),
            expected_head_revision=expected_head_revision))

    def patches(self, first: Optional[AddressLike] = None, last: Optional[AddressLike] = None):
        req = patch_pb2.ListPatchesRequest(program_id=self.id, read=self._read())
        if first is not None or last is not None:
            req.range.first.CopyFrom(address(first if first is not None else 0))
            req.range.last.CopyFrom(address(last if last is not None else (1 << 64) - 1))
        return self._p("ListPatches", req).patches

    def revert_patches(self, seqs: Sequence[int] = (), *, first: Optional[AddressLike] = None,
                       last: Optional[AddressLike] = None, actor=None, reason: str = "") -> patch_pb2.RevertPatchesResponse:
        req = patch_pb2.RevertPatchesRequest(program_id=self.id, seqs=list(seqs), provenance=self.client._prov(actor, reason))
        if first is not None:
            req.range.first.CopyFrom(address(first))
            req.range.last.CopyFrom(address(last if last is not None else first))
        return self._p("RevertPatches", req)

    def export(self, settings: Optional[patch_pb2.ExportSettings] = None, *, host_path: str = "",
               verify: bool = True) -> patch_pb2.ExportProgramResponse:
        """The file with its patches and fixups, verified by the daemon (stored
        settings when ``settings`` is None). ``.data`` holds the bytes unless
        ``host_path`` (admin) asks the daemon to write them."""
        req = patch_pb2.ExportProgramRequest(program_id=self.id, host_path=host_path, skip_verify=not verify,
                                             read=self._read())
        if settings is None:
            req.use_stored_settings = True
        else:
            req.settings.CopyFrom(settings)
        return self._p("ExportProgram", req)

    def detect_checksum(self, *, expected: str = "", file_name: str = "", patched: bool = False) -> patch_pb2.DetectChecksumResponse:
        """Which checksum rule the file obeys, against its header words and
        ``expected`` (hex) or the hex runs in ``file_name``."""
        return self._p("DetectChecksum", patch_pb2.DetectChecksumRequest(
            program_id=self.id, expected=expected, file_name=file_name, patched=patched, read=self._read()))

    def open_original(self, *, actor=None, reason: str = "") -> str:
        """The program as imported, without its patches, as another program of
        the project (made once): diff it against this one."""
        return self._p("OpenOriginal", patch_pb2.OpenOriginalRequest(
            program_id=self.id, provenance=self.client._prov(actor, reason))).program_id

    def export_settings(self) -> patch_pb2.GetExportSettingsResponse:
        return self._p("GetExportSettings", patch_pb2.GetExportSettingsRequest(program_id=self.id, read=self._read()))

    def set_export_settings(self, settings: patch_pb2.ExportSettings, *, actor=None, reason: str = ""):
        return self._p("SetExportSettings", patch_pb2.SetExportSettingsRequest(
            program_id=self.id, settings=settings, provenance=self.client._prov(actor, reason)))

    def rename(self, addr: AddressLike, name: str, **kw) -> assertion_pb2.AppendAssertionsResponse:
        body = assertion_pb2.AssertionBody(rename=assertion_pb2.Rename(target=assertion_pb2.Target(address=address(addr)), name=name))
        return self.append(body, **kw)

    def rename_local(self, function: AddressLike, storage_key: str, name: str, **kw):
        target = assertion_pb2.Target(local=assertion_pb2.LocalVariableRef(function=address(function), storage_key=storage_key))
        return self.append(assertion_pb2.AssertionBody(rename=assertion_pb2.Rename(target=target, name=name)), **kw)

    def retype(self, addr: AddressLike, c_declaration: str = "", *, type_hash: str = "", **kw):
        spec = assertion_pb2.TypeSpec(type_hash=type_hash) if type_hash else assertion_pb2.TypeSpec(c_declaration=c_declaration)
        body = assertion_pb2.AssertionBody(retype=assertion_pb2.Retype(target=assertion_pb2.Target(address=address(addr)), type=spec))
        return self.append(body, **kw)

    def retype_local(self, function: AddressLike, storage_key: str, c_declaration: str, **kw):
        target = assertion_pb2.Target(local=assertion_pb2.LocalVariableRef(function=address(function), storage_key=storage_key))
        spec = assertion_pb2.TypeSpec(c_declaration=c_declaration)
        return self.append(assertion_pb2.AssertionBody(retype=assertion_pb2.Retype(target=target, type=spec)), **kw)

    # -- call-site signature overrides (api_minor 53, feature "call-signature-override") --

    def override_call_signature(self, call: AddressLike, c_prototype: str = "", *, type_hash: str = "", **kw):
        """Overrides the prototype one call uses (Ghidra's Override Signature):
        ``c_prototype`` such as ``"int printf(char *fmt, int a, int b)"`` (the
        name is ignored) or a function type's ``type_hash``. The decompiler
        takes it for that call alone; one edit, undone by retracting it."""
        if not c_prototype and not type_hash:
            raise ValueError("give a C prototype or a type hash")
        spec = assertion_pb2.TypeSpec(type_hash=type_hash) if type_hash else assertion_pb2.TypeSpec(c_declaration=c_prototype)
        body = assertion_pb2.AssertionBody(call_signature=assertion_pb2.CallSignatureOverride(call=address(call), signature=spec))
        return self.append(body, **kw)

    def remove_call_signature(self, call: AddressLike, **kw):
        """Removes a call's signature override (Ghidra's Remove Signature
        Override): the call takes its callee's prototype again."""
        body = assertion_pb2.AssertionBody(call_signature=assertion_pb2.CallSignatureOverride(call=address(call)))
        return self.append(body, **kw)

    def call_signature(self, call: AddressLike) -> str:
        """The call's signature override as C ("" if none), as the listing shows it."""
        a = address(call).offset
        for r in self.listing(a, max_rows=4).rows:
            if r.address.offset == a and r.kind == listing_pb2.LISTING_ROW_KIND_INSTRUCTION:
                return r.call_signature
        return ""

    def comment(self, addr: AddressLike, text: str, kind: str = "eol", **kw):
        body = assertion_pb2.AssertionBody(comment=assertion_pb2.Comment(address=address(addr), kind=_COMMENT_KINDS[kind], text=text))
        return self.append(body, **kw)

    def set_function(self, entry: AddressLike, body: Sequence[tuple] = (), isa: Optional[str] = None, **kw):
        """Declares a function at ``entry``; ``body`` is inclusive (first, last) ranges (empty = discover).

        ARM: ``isa`` "arm" or "thumb"; None keeps the mode the entry's bit 0,
        the function already there or the code there has (api_minor 104)."""
        b = assertion_pb2.SetFunctionBounds(entry=address(entry), body=[address_range(*r) for r in body],
                                            instruction_set=_choice(_INSTRUCTION_SETS, isa, "isa"))
        return self.append(assertion_pb2.AssertionBody(function_bounds=b), **kw)

    def remove_function(self, entry: AddressLike, **kw):
        b = assertion_pb2.SetFunctionBounds(entry=address(entry), remove=True)
        return self.append(assertion_pb2.AssertionBody(function_bounds=b), **kw)

    def flow_override(self, addr: AddressLike, kind: str, **kw):
        b = assertion_pb2.FlowOverride(address=address(addr), kind=_FLOW_OVERRIDES[kind])
        return self.append(assertion_pb2.AssertionBody(flow_override=b), **kw)

    def set_no_return(self, function: AddressLike, no_return: bool = True, **kw):
        """Says whether the function at ``function`` (its entry) returns
        (``SetNoReturn``, api_minor 66, feature ``no-return``; Ghidra's
        Set No-Return): True, calls to it end their caller's flow there
        (bodies, the listing's flow and the decompiler stop after the call);
        False, it returns, even where analysis found it doesn't. Undo with
        ``retract(*[a.seq for a in resp.assertions])``; analysis then has
        its say again."""
        b = assertion_pb2.SetNoReturn(function=address(function), no_return=no_return)
        return self.append(assertion_pb2.AssertionBody(no_return=b), **kw)

    def set_decompiler_settings(self, *, comparison_form: str = "", load_types: str = "", compilable_c: bool = False,
                                ghidra_flag_tests: bool = False, **kw):
        """How the decompiler shapes this program's C (``SetDecompilerSettings``,
        api_minor 106, feature ``decompiler-settings``; docs/decompiler-inputs.md,
        "Source shape"). ``comparison_form``: ``"right"`` (revkit's default:
        ``x > 8``, ``x < 1``), ``"encoded"`` (also the constant the instruction
        compares against: ``x >= 9``, ``x <= 0``; for a compiler that keeps the
        source's, Metrowerks CodeWarrior) or ``"ghidra"`` (``8 < x``).
        ``compilable_c``: C a compiler accepts as it is (no ``x._2_2_``, no label
        ending a block, pointer/integer conversions cast). ``load_types``:
        ``"all"`` (revkit's default: the signedness the load's extension
        gives, ``ldrh`` and ``ldrb`` unsigned, ``ldrsh`` signed), ``"words"``
        (but for zero-extended bytes, which compilers also use for signed
        chars) or ``"ghidra"``. ``ghidra_flag_tests`` turns off the one-test form of
        ``subs; bgt``. Every decompilation of the program is redone; no
        arguments give revkit's defaults back."""
        forms = {"": assertion_pb2.COMPARISON_FORM_UNSPECIFIED, "ghidra": assertion_pb2.COMPARISON_FORM_GHIDRA,
                 "right": assertion_pb2.COMPARISON_FORM_RIGHT, "encoded": assertion_pb2.COMPARISON_FORM_ENCODED}
        loads = {"": assertion_pb2.LOAD_TYPES_UNSPECIFIED, "ghidra": assertion_pb2.LOAD_TYPES_GHIDRA,
                 "words": assertion_pb2.LOAD_TYPES_WORDS, "all": assertion_pb2.LOAD_TYPES_ALL}
        if comparison_form not in forms:
            raise ValueError("comparison_form is right, encoded or ghidra, not %r" % comparison_form)
        if load_types not in loads:
            raise ValueError("load_types is words, all or ghidra, not %r" % load_types)
        s = assertion_pb2.DecompilerSettings(comparison_form=forms[comparison_form], load_types=loads[load_types],
                                             compilable_c=compilable_c, ghidra_flag_tests=ghidra_flag_tests)
        body = assertion_pb2.AssertionBody(decompiler_settings=assertion_pb2.SetDecompilerSettings(settings=s))
        return self.append(body, **kw)

    def set_fallthrough(self, addr: AddressLike, target: Optional[AddressLike] = None, **kw):
        """Sets where control goes on after the instruction at ``addr``
        (``SetFallthrough``, api_minor 85, feature ``fallthrough-override``;
        Ghidra's Set Fallthrough): to ``target`` instead of the next
        instruction (inline data after a call, say), or with ``target`` None,
        nowhere: the instruction doesn't fall through. Function bodies, the
        listing's flow, the function graph and references follow it, and the
        decompiler sees a branch to ``target``. A ``target`` at the next
        instruction clears the override. Undo with
        ``retract(*[a.seq for a in resp.assertions])``."""
        b = assertion_pb2.SetFallthrough(address=address(addr))
        if target is None:
            b.no_fallthrough = True
        else:
            b.target.CopyFrom(address(target))
        return self.append(assertion_pb2.AssertionBody(fallthrough=b), **kw)

    def clear_fallthrough(self, addr: AddressLike, **kw):
        """Gives the instruction at ``addr`` its own fallthrough back (Ghidra's
        Clear Fallthrough), whoever set the override: one assertion, so one
        undo step."""
        b = assertion_pb2.SetFallthrough(address=address(addr))
        return self.append(assertion_pb2.AssertionBody(fallthrough=b), **kw)
    # -- register values (api_minor 87, feature "register-values"; docs/api.md "Register values") --

    def _register_ranges(self, first, last, function):
        if function is not None:
            if first is not None or last is not None:
                raise ValueError("give a range (first, last) or a function, not both")
            f = self.function(function, containing=True)
            if not f.body:
                raise ValueError(f"no function at {int(address(function).offset):#x}")
            return [address_range(r.first.offset, r.last.offset) for r in f.body]
        if first is None:
            raise ValueError("a range (first, last) or a function is required")
        return [address_range(first, first if last is None else last)]

    def set_register_value(self, register: str, value: int, first: Optional[AddressLike] = None,
                           last: Optional[AddressLike] = None, *, function: Optional[AddressLike] = None,
                           **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Says ``register`` holds ``value`` over [first, last] (inclusive;
        ``last`` defaults to ``first``), or over the body of the function at
        or containing ``function`` (``SetRegisterValue``, api_minor 87,
        feature ``register-values``; Ghidra's Set Register Values). Analysis's
        constants (MIPS ``gp``- and PowerPC ``r2``-relative references) and
        the decompiler (the value at a function's entry) take it as known
        there. One revision: undo with ``retract(*[a.seq for a in
        resp.assertions])``."""
        bodies = [assertion_pb2.AssertionBody(register_value=assertion_pb2.SetRegisterValue(
            register_name=register, range=r, value=int(value))) for r in self._register_ranges(first, last, function)]
        return self.append(*bodies, **kw)

    def clear_register_value(self, register: str, first: Optional[AddressLike] = None,
                             last: Optional[AddressLike] = None, *, function: Optional[AddressLike] = None,
                             **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Says ``register`` has no value over the range (or the function's
        body): what analysis assumed there (the loader's MIPS ``_gp``, the
        PowerPC TOC) or an older value goes. One revision, like
        ``set_register_value``."""
        bodies = [assertion_pb2.AssertionBody(register_value=assertion_pb2.SetRegisterValue(
            register_name=register, range=r, clear=True)) for r in self._register_ranges(first, last, function)]
        return self.append(*bodies, **kw)

    def register_values(self, register: str = "", *, first: Optional[AddressLike] = None,
                        last: Optional[AddressLike] = None, page_size: int = 1000) -> Iterator[query_pb2.RegisterValueRange]:
        """The register values over ranges (``ListRegisterValues``, api_minor
        87, feature ``register-values``; Ghidra's register manager), by
        register then address: ``.register_name``, ``.range``, ``.value``,
        ``.origin`` (the assertion, or analysis's rule
        "analysis.register_values:mips-gp"), ``.key`` (the assertion's)."""
        req = query_pb2.ListRegisterValuesRequest(program_id=self.id, read=self._read(), register_name=register)
        if first is not None or last is not None:
            req.range.CopyFrom(address_range(first if first is not None else 0, last if last is not None else (1 << 64) - 1))
        return self._paged("ListRegisterValues", req, "ranges", page_size)

    def register_value(self, register: str, addr: AddressLike) -> Optional[int]:
        """The value ``register`` holds at ``addr``, or None."""
        for r in self.register_values(register, first=addr, last=addr):
            return r.value
        return None

    def value_registers(self) -> List[query_pb2.RegisterDescription]:
        """The registers values may be set on (``.name``, ``.size`` in bytes)."""
        req = query_pb2.ListRegisterValuesRequest(program_id=self.id, read=self._read())
        req.page.page_size = 1
        return list(self._q("ListRegisterValues", req).registers)

    # -- listing edits (api_minor 30, feature "listing-edit"; docs/listing-edit.md) --
    # Each is one AppendAssertions; undo with retract(*[a.seq for a in resp.assertions])
    # (a define_data response also holds the TYPE_DEF assertions of a type it parsed).

    def define_data(self, addr: AddressLike, type: Optional[str] = None, *, count: int = 0,
                    string: Optional[str] = None, layout: Optional[str] = None, collapsed: Optional[bool] = None,
                    type_hash: Optional[str] = None, **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Defines a data item at ``addr`` (see ``define_data_body``):
        ``define_data(a, "dword")``, ``define_data(a, "struct hdr")``,
        ``define_data(a, "uint32_t", count=4)``, ``define_data(a, string="utf16")``.
        The stored body has ``size``, ``type_hash`` and ``type_name`` filled."""
        body = define_data_body(addr, type, count=count, string=string, layout=layout, collapsed=collapsed,
                                type_hash=type_hash)
        return self.append(body, **kw)

    def clear_code(self, addr: AddressLike, length: int = 1, **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Clears [addr, addr + length): instructions and data there go, and
        analysis starts nothing in them until a later edit."""
        return self.append(clear_code_body(addr, length), **kw)

    def plan_clear_flow(self, addr: AddressLike, *, follow_calls: bool = False) -> query_pb2.PlanClearFlowResponse:
        """Ghidra's Clear Flow and Repair, planned (``PlanClearFlow``,
        api_minor 83, feature "clear-flow"): the code the flow from ``addr``
        reaches that nothing else reaches (``.ranges``), how many
        instructions it reaches and how many stay because other code reaches
        them (``.instructions``, ``.kept``), and the functions whose entry
        goes (``.functions``). ``follow_calls`` also takes the callees only
        this flow calls. Writes nothing; ``clear_flow`` applies it."""
        req = query_pb2.PlanClearFlowRequest(program_id=self.id, read=self._read(), address=address(addr),
                                             follow_calls=follow_calls)
        return self._q("PlanClearFlow", req)

    def clear_flow(self, addr: AddressLike, *, follow_calls: bool = False,
                   **kw) -> tuple:
        """Clear Flow and Repair: ``plan_clear_flow``'s ranges cleared
        (``clear_code`` each) in one append, so one undo step reverts it.
        Returns ``(plan, response)``; the response is None when the plan
        clears nothing."""
        plan = self.plan_clear_flow(addr, follow_calls=follow_calls)
        if not plan.ranges:
            return plan, None
        return plan, self.append(*(clear_code_body(r.address.offset, r.length) for r in plan.ranges), **kw)

    def disassemble(self, addr: AddressLike, isa: Optional[str] = None, function: bool = False,
                    **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Disassembles from ``addr`` (``isa``: None, "arm" or "thumb");
        ``function=True`` also makes it a function."""
        return self.append(disassemble_body(addr, isa, function), **kw)

    def set_mutability(self, addr: AddressLike, length: int, mutability: str,
                       **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Marks [addr, addr + length) "constant", "volatile", "normal" or "default"."""
        return self.append(mutability_body(addr, length, mutability), **kw)

    # -- data settings (api_minor 84, feature "data-settings"; docs/listing-edit.md#data-settings) --

    _SETTING_KEYS = ("format", "signed", "endian", "padding", "charset", "termination", "pointer", "mask", "shift")

    def set_data_settings(self, addr: AddressLike, field: str = "", *,
                          settings: Optional[assertion_pb2.DataSettings] = None,
                          **kw) -> assertion_pb2.AppendAssertionsResponse:
        """How the data item at ``addr`` displays (Ghidra's Data Settings):
        ``set_data_settings(a, format="decimal", signed=True)``,
        ``set_data_settings(a, charset="ISO-8859-1")``,
        ``set_data_settings(a, pointer="image-base")``; ``field`` a struct
        field's row ("hdr.magic"). Settings left out fall back to the type's
        defaults; none at all removes the item's. Only the listing's display
        changes. Undo with ``retract``."""
        opts = {k: kw.pop(k) for k in list(kw) if k in self._SETTING_KEYS}
        return self.append(data_settings_body(addr, field=field, settings=settings, **opts), **kw)

    def set_type_data_settings(self, type_name: str, *, settings: Optional[assertion_pb2.DataSettings] = None,
                               **kw) -> assertion_pb2.AppendAssertionsResponse:
        """A type's default settings (Ghidra's Default Settings), for every data
        row of that type (``ListingRow.data_settings_type``: "uint32_t",
        "string", "pointer", "undefined4") its own settings leave unset."""
        opts = {k: kw.pop(k) for k in list(kw) if k in self._SETTING_KEYS}
        return self.append(data_settings_body(type_name=type_name, settings=settings, **opts), **kw)

    # -- equates (api_minor 39, feature "equates"; docs/api.md "Equates and user references") --
    # Each is one AppendAssertions; undo with retract(*[a.seq for a in resp.assertions])
    # (with apply_to, the response has one assertion per operand, the requested one first).

    def convert(self, addr: AddressLike, value, format: str, *, operand: Optional[int] = None,
                apply_to: Optional[str] = None, constant_hash: int = 0, **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Shows the scalar ``value`` at instruction ``addr`` as Ghidra's
        Convert does: ``format`` "hex", "signed", "unsigned", "octal",
        "binary", "char" or "float" ("default": as the disassembler prints
        it), in the listing and the decompiler."""
        return self.append(operand_display_body(addr, value, operand=operand, format=format or "default",
                                                constant_hash=constant_hash, apply_to=apply_to), **kw)

    def set_equate(self, addr: AddressLike, value, name: str, *, operand: Optional[int] = None,
                   apply_to: Optional[str] = None, constant_hash: int = 0,
                   **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Shows the scalar ``value`` at instruction ``addr`` as ``name``
        (Ghidra's Set Equate); ``apply_to`` "function" or "program" names
        every operand holding the value there too. A name has one value
        program-wide: naming another value with it is refused
        (InvalidArgument)."""
        return self.append(operand_display_body(addr, value, operand=operand, equate=name,
                                                constant_hash=constant_hash, apply_to=apply_to), **kw)

    def set_enum_equate(self, addr: AddressLike, value, enum: str, member: str, *, operand: Optional[int] = None,
                        apply_to: Optional[str] = None, constant_hash: int = 0,
                        **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Shows the scalar as an enum's member (``enum`` by name, "color"
        or "enum color", or by type hash); the member's value must be the
        scalar's. ``enums_with_value`` suggests enums."""
        return self.append(operand_display_body(addr, value, operand=operand, enum=self.enum_hash(enum),
                                                member=member, constant_hash=constant_hash, apply_to=apply_to), **kw)

    def clear_display(self, addr: AddressLike, value, *, operand: Optional[int] = None, constant_hash: int = 0,
                      **kw) -> assertion_pb2.AppendAssertionsResponse:
        """The scalar shows as the disassembler prints it again (a
        conversion or an equate cleared, whoever set it)."""
        return self.append(operand_display_body(addr, value, operand=operand, constant_hash=constant_hash), **kw)

    clear_equate = clear_display

    def equates(self) -> dict:
        """The equates table: {name: Equate(name, value, references,
        enum_type_hash, member)}, folded from the effective EQUATE
        assertions (an equate exists while an operand shows it)."""
        return fold_equates(self.assertions(kinds=("equate",)))

    def rename_equate(self, old: str, new: str, **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Renames an equate at every operand that shows it, as one edit."""
        return self.append(*rename_equate_bodies(self.equates(), old, new), **kw)

    def remove_equate(self, name: str, **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Removes an equate everywhere: each operand that showed it shows
        the disassembler's text again, as one edit."""
        return self.append(*remove_equate_bodies(self.equates(), name), **kw)

    def enums_with_value(self, value, *, program_only: bool = False) -> list:
        """Enums with a member of this value (Set Equate's suggestions), the
        program's first; ``program_only`` leaves out library archives'."""
        def find(*sources):
            req = query_pb2.FindTypesRequest(program_id=self.id, read=self._read(), sources=sources,
                                             enum_value=_signed64(_scalar_value(value)))
            return list(self._paged("FindTypes", req, "types", 500))

        found = find(query_pb2.TYPE_SOURCE_PROGRAM)
        if not program_only:
            mine = {t.hash for t in found}
            found += [t for t in find() if t.hash not in mine]
        return found

    def enum_hash(self, enum: str) -> str:
        """An enum's type hash, by name ("color", "enum color") or hash."""
        bare = enum.removeprefix("enum ").strip()
        for t in self.find_types(bare):
            if t.kind == types_pb2.TYPE_KIND_ENUM and (t.name == bare or t.display == enum):
                return t.hash
        try:
            if any(t.hash == enum and t.kind == types_pb2.TYPE_KIND_ENUM for t in self.types(enum).types):
                return enum
        except RevkitError:
            pass
        raise NotFound(grpc.StatusCode.NOT_FOUND, f"no enum {enum!r}")

    # -- user references (api_minor 39, feature "user-references") ---------------

    def add_reference(self, from_: AddressLike, to: AddressLike, type: str = "data", *,
                      operand: Optional[int] = None, primary: bool = False,
                      **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Adds a reference from the instruction at ``from_`` to ``to``
        (Ghidra's References > Add): ``type`` "data", "read", "write",
        "call", "jump", "computed_call" or "computed_jump"; ``operand`` its
        operand (None or -1: the instruction as a whole). A call makes ``to``
        a function; a primary computed call makes the decompiler call it."""
        return self.append(reference_body(from_, to, type, operand=operand, primary=primary), **kw)

    def _between(self, from_: AddressLike, to: AddressLike) -> list:
        f = from_.offset if isinstance(from_, common_pb2.Address) else int(from_)
        t = to.offset if isinstance(to, common_pb2.Address) else int(to)
        return [x for x in self.xrefs(f, direction="from") if x.from_address.offset == f and x.to_address.offset == t]

    def remove_reference_bodies(self, from_: AddressLike, to: AddressLike, operand: Optional[int] = None) -> list:
        """The bodies ``remove_reference`` appends: one per key the user's
        references from ``from_`` to ``to`` are at (``operand`` None), or at
        ``operand`` (-1: the instruction); the instruction's when there is
        none (analysis's references go whatever the key)."""
        if operand is not None:
            keys = [operand if operand >= 0 else None]
        else:
            keys = sorted({x.operand_index if x.HasField("operand_index") else None
                           for x in self._between(from_, to) if x.origin.HasField("asserted")},
                          key=lambda o: -1 if o is None else o) or [None]
        return [reference_body(from_, to, operand=o, remove=True) for o in keys]

    def remove_reference(self, from_: AddressLike, to: AddressLike, *, operand: Optional[int] = None,
                         **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Deletes the references from ``from_`` to ``to``: the user's own
        (on ``operand``; None: on whichever operand they are) and every one
        analysis made (they leave xrefs; discovery keeps what it found).
        Undo by retracting what it returns."""
        return self.append(*self.remove_reference_bodies(from_, to, operand), **kw)

    def primary_reference_body(self, from_: AddressLike, to: AddressLike, *, operand: Optional[int] = None,
                               type: Optional[str] = None, primary: bool = True) -> assertion_pb2.AssertionBody:
        """The body ``set_primary_reference`` appends: the existing
        reference (the user's, else analysis's) restated with ``primary``."""
        refs = self._between(from_, to)
        if operand is not None:
            refs = [x for x in refs if (x.operand_index if x.HasField("operand_index") else -1) == operand]
        ref = next((x for x in refs if x.origin.HasField("asserted")), refs[0] if refs else None)
        if ref is None and type is None:
            raise NotFound(grpc.StatusCode.NOT_FOUND, "no reference from the instruction to that address "
                           "(add_reference adds one; or give its type)")
        if operand is None and ref is not None and ref.HasField("operand_index"):
            operand = ref.operand_index
        kind = type if type is not None else _XREF_REFERENCE_TYPES.get(ref.kind, assertion_pb2.REFERENCE_TYPE_DATA)
        return reference_body(from_, to, kind, operand=operand, primary=primary)

    def set_primary_reference(self, from_: AddressLike, to: AddressLike, *, operand: Optional[int] = None,
                              type: Optional[str] = None, primary: bool = True,
                              **kw) -> assertion_pb2.AppendAssertionsResponse:
        """Makes the reference from ``from_`` to ``to`` its operand's primary
        one (the operand shows ``to``'s symbol; on a computed call the
        decompiler calls ``to``), or not (``primary=False``). The type and
        operand default to the existing reference's."""
        return self.append(self.primary_reference_body(from_, to, operand=operand, type=type, primary=primary), **kw)

    def note(self, addr: AddressLike, text: str, tag: str = "", **kw):
        b = assertion_pb2.Note(address=address(addr), tag=tag, text=text)
        return self.append(assertion_pb2.AssertionBody(note=b), **kw)

    def retract(self, *seqs: int, actor: Optional[str] = None, reason: str = ""):
        req = assertion_pb2.RetractAssertionsRequest(program_id=self.id, seqs=list(seqs), provenance=self.client._prov(actor, reason))
        return self.client._call(self.client.stubs.assertions.RetractAssertions, req)

    def history(self, key: common_pb2.FactKey) -> list:
        req = assertion_pb2.GetHistoryRequest(key=key, read=self._read())
        out, token = [], ""
        while True:
            req.page.page_token = token
            resp = self.client._call(self.client.stubs.assertions.GetHistory, req)
            out.extend(resp.entries)
            token = resp.page.next_page_token
            if not token:
                return out

    def blame(self, key: common_pb2.FactKey) -> assertion_pb2.BlameResponse:
        return self.client._call(self.client.stubs.assertions.Blame, assertion_pb2.BlameRequest(key=key, read=self._read()))

    def assertions(
        self,
        *,
        actor: Optional[str] = None,
        session: str = "",
        include_inactive: bool = False,
        on_behalf_of: str = "",
        kinds: Sequence[Union[str, int]] = (),
    ) -> list:
        """Assertions, optionally filtered by author (``"agent:claude"``,
        ``"script:fix-names"``), session, whom a script acted for
        (``on_behalf_of="user:alice"``, api_minor 29) and fact kind
        (``kinds=("equate",)``)."""
        f = assertion_pb2.AssertionFilter(include_inactive=include_inactive)
        f.kinds.extend(_FACT_KINDS[k] if isinstance(k, str) else int(k) for k in kinds)
        if actor:
            p = provenance(actor)
            f.provenance.kind, f.provenance.id, f.provenance.version = p.kind, p.id, p.version
        f.provenance.session = session
        f.provenance.on_behalf_of = on_behalf_of
        req = assertion_pb2.ListAssertionsRequest(program_id=self.id, filter=f, read=self._read())
        out = []
        while True:
            resp = self.client._call(self.client.stubs.assertions.ListAssertions, req)
            out.extend(resp.assertions)
            if not resp.page.next_page_token:
                return out
            req.page.page_token = resp.page.next_page_token

    def revert(
        self,
        *,
        kind: str = "",
        id: str = "",
        version: str = "",
        session: str = "",
        since_revision: int = 0,
        dry_run: bool = False,
        actor: Optional[str] = None,
        on_behalf_of: str = "",
    ) -> assertion_pb2.RevertByProvenanceResponse:
        """Reverts matching authors' work in one revision, as if they had never acted.

        Every matching assertion and retraction is retracted, live or not (the
        fact store's revert): what they retracted comes back, and undoing one
        of their retractions later cannot revive their work. The revert is
        itself an ordinary set of retractions, so it can be undone.
        """
        f = assertion_pb2.ProvenanceFilter(
            kind=_PROVENANCE_KINDS[kind] if kind else common_pb2.PROVENANCE_KIND_UNSPECIFIED,
            id=id,
            version=version,
            session=session,
            on_behalf_of=on_behalf_of,
        )
        req = assertion_pb2.RevertByProvenanceRequest(
            program_id=self.id, filter=f, since_revision=since_revision, dry_run=dry_run, provenance=self.client._prov(actor)
        )
        return self.client._call(self.client.stubs.assertions.RevertByProvenance, req)

    # -- plugins -------------------------------------------------------------------

    def run_command(
        self,
        plugin: str,
        args: Optional[dict] = None,
        *,
        dry_run: bool = False,
        expected_head_revision: int = 0,
        actor: Optional[str] = None,
        reason: str = "",
    ) -> plugin_pb2.RunCommandResponse:
        """Runs a command plugin; its edits land as one revision of assertions.

        They are recorded as ``plugin:<name>@<version>`` with this client's session
        and ``reason``, or, when the actor is an agent, as that agent (with the
        plugin as the tool), so ``revert(kind="plugin", id=name)`` or the agent's
        usual revert undoes them. ``dry_run`` returns the edits without committing.
        """
        req = plugin_pb2.RunCommandRequest(
            program_id=self.id,
            plugin=plugin,
            args={str(k): str(v) for k, v in (args or {}).items()},
            provenance=self.client._prov(actor, reason),
            dry_run=dry_run,
            expected_head_revision=expected_head_revision,
        )
        return self.client._call(self.client.stubs.plugins.RunCommand, req)

    def plugin_facts(
        self, *plugins: str, first: Optional[AddressLike] = None, last: Optional[AddressLike] = None
    ) -> plugin_pb2.GetPluginFactsResponse:
        """Facts analyzer plugins derive (all analyzers when none is named), optionally
        only at addresses in [first, last]. Each carries origin.derived.rule
        ``plugin:<name>@<version>``; failed runs are in ``errors``."""
        req = plugin_pb2.GetPluginFactsRequest(program_id=self.id, plugins=list(plugins), read=self._read())
        if first is not None or last is not None:
            req.range.CopyFrom(address_range(first or 0, last if last is not None else (1 << 64) - 1))
        return self.client._call(self.client.stubs.plugins.GetPluginFacts, req)

    # -- emulation (api_minor 12, feature "emulator") ----------------------------------

    def emulate(
        self,
        entry: Optional[AddressLike] = None,
        *,
        mode: str = "auto",
        args: Sequence[int] = (),
        registers: Optional[dict] = None,
        memory: Optional[dict] = None,
        breakpoints: Sequence[AddressLike] = (),
        stdin: bytes = b"",
        import_return: int = 0,
        library_stubs: bool = True,
        client: str = "",
        machine=None,
        machine_name: str = "",
        **limits,
    ) -> "EmulatorSession":
        """Starts an emulation session at ``entry`` (default: the entry point).

        ``mode`` is "auto" (a Linux process at an ELF's entry point, bare for raw
        images, else a call), "process", "call" (with ``args``; the function's
        return ends the run) or "bare". ``registers`` maps names to values and
        ``memory`` addresses to bytes, both applied after the start. ``limits``
        are EmulatorLimits fields (max_steps_per_call, max_total_steps,
        max_memory_bytes, trace_capacity, time_limit_ms). Use the session as a
        context manager, or close it.

        Firmware (api_minor 20): ``machine`` is a machine description (JSON
        text, or a dict) to run on, ``machine_name`` one saved with
        :meth:`save_machine` (docs/firmware-emulation.md); ``stdin`` then goes
        to the console UART.
        """
        modes = {
            "auto": emulator_pb2.EMULATOR_START_MODE_UNSPECIFIED,
            "process": emulator_pb2.EMULATOR_START_MODE_PROCESS,
            "call": emulator_pb2.EMULATOR_START_MODE_CALL,
            "bare": emulator_pb2.EMULATOR_START_MODE_BARE,
        }
        req = emulator_pb2.CreateEmulatorSessionRequest(
            program_id=self.id,
            mode=modes[mode],
            arguments=[int(a) for a in args],
            breakpoints=[address(b) for b in breakpoints],
            stdin=stdin,
            import_return=import_return,
            no_library_stubs=not library_stubs,
            client=client,
            limits=emulator_pb2.EmulatorLimits(**limits),
            machine=_machine_text(machine),
            machine_name=machine_name,
        )
        if entry is not None:
            req.entry.CopyFrom(address(entry))
        for name, value in (registers or {}).items():
            req.registers.append(_register_write(name, value))
        for at, data in (memory or {}).items():
            req.memory.append(emulator_pb2.EmulatorMemoryWrite(address=address(at), data=bytes(data)))
        created = self.client._call(self.client.stubs.emulator.CreateEmulatorSession, req)
        return EmulatorSession(self.client, created.session_id, created)

    # -- debugging (api_minor 14, feature "debugger") ------------------------------------

    def debug(
        self,
        target: str = "emulator",
        *,
        entry: Optional[AddressLike] = None,
        mode: str = "auto",
        args: Sequence = (),
        environment: Sequence[str] = (),
        attach: int = 0,
        qemu: str = "",
        breakpoints: Sequence[int] = (),
        slide: Optional[int] = None,
        stops_only: bool = False,
        max_snapshots: int = 0,
        client: str = "",
        machine=None,
        machine_name: str = "",
        stdin: bytes = b"",
        from_session=None,
        from_snapshot: Optional[int] = None,
        **emulator_limits,
    ) -> "DebugSession":
        """Starts a debug session (DebugService) over this program.

        ``target`` is "emulator" (``entry``, ``mode`` and integer ``args`` as
        :meth:`emulate`), "launch" (the program on the daemon's host under
        gdbserver or qemu-user, with string ``args`` and ``environment``; or
        ``attach`` to a pid), a GDB remote stub ("gdb://host:port",
        "host:port", "unix:/path"), or "trace:<name>" (a saved trace,
        replayed). Live targets need a daemon started with --debug-live.
        ``breakpoints`` are program (static) addresses. Use the session as a
        context manager, or close it.

        ``from_session`` (a DebugSession or its id; api_minor 67, feature
        "debugger-emulate-from"): the emulator starts from that session's
        stop (or ``from_snapshot``), its memory read from it when first
        touched; that session isn't changed. "What if" from a real process.
        """
        req = debugger_pb2.CreateDebugSessionRequest(program_id=self.id, client=client)
        if target == "emulator":
            modes = {
                "auto": emulator_pb2.EMULATOR_START_MODE_UNSPECIFIED,
                "process": emulator_pb2.EMULATOR_START_MODE_PROCESS,
                "call": emulator_pb2.EMULATOR_START_MODE_CALL,
                "bare": emulator_pb2.EMULATOR_START_MODE_BARE,
            }
            em = req.emulator
            em.mode = modes[mode]
            em.arguments.extend(int(a) for a in args)
            em.limits.CopyFrom(emulator_pb2.EmulatorLimits(**emulator_limits))
            em.machine = _machine_text(machine)
            em.machine_name = machine_name
            em.stdin = stdin
            if entry is not None:
                em.entry.CopyFrom(address(entry))
            if from_session is not None:
                em.from_session = from_session.id if isinstance(from_session, DebugSession) else str(from_session)
                if from_snapshot is not None:
                    em.from_snapshot = from_snapshot
        elif target == "launch":
            req.launch.arguments.extend(str(a) for a in args)
            req.launch.environment.extend(environment)
            req.launch.attach_pid = attach
            req.launch.qemu = qemu
        elif target.startswith("trace:"):
            req.trace.name = target[len("trace:"):]
        else:
            req.remote.address = target
            req.remote.attach_pid = attach
        for b in breakpoints:
            req.breakpoints.append(debugger_pb2.DebugBreakpointSpec(address=debugger_pb2.DebugAddress(offset=int(b), program=True)))
        if slide is not None:
            req.slide = slide
        req.timeline.stops_only = stops_only
        req.timeline.max_snapshots = max_snapshots
        created = self.client._call(self.client.stubs.debugger.CreateDebugSession, req)
        return DebugSession(self.client, created.session_id, created)

    def crash_dump(self, dump=None, *, host_path: str = "", file=None, client: str = "") -> "DebugSession":
        """Opens a crash dump as a stopped, read-only debug session over this
        program (api_minor 102, feature "crash-dumps"; docs/crash-dumps.md):
        an ELF core file or a Windows minidump. ``dump`` is a program of the
        project the dump was imported as (a Program or its id; ELF cores
        import), else ``host_path`` (a file on the daemon's host) or ``file``
        (a local path or bytes, uploaded); the last two need an admin.

        Open it on the crashed executable for its code and names: the
        dump's modules that are other project programs (its libraries) are
        mapped to them, and ``.crash()`` (also ``.created.crash``) says the
        signal or exception, the faulting address, module, function and
        instruction, the backtrace and threads; ``main_program_id`` names
        the executable's program when this one isn't it. Registers,
        memory, threads, the backtrace and disassembly read as in any
        session; running and writing are refused."""
        req = debugger_pb2.CreateDebugSessionRequest(program_id=self.id, client=client)
        if dump is not None:
            req.crash.dump_program_id = dump.id if isinstance(dump, Program) else str(dump)
        elif host_path:
            req.crash.host_path = str(host_path)
        elif file is not None:
            req.crash.upload_id = self.client.upload(file)
        else:
            raise ValueError("give the dump: a program, host_path or file")
        created = self.client._call(self.client.stubs.debugger.CreateDebugSession, req)
        return DebugSession(self.client, created.session_id, created)

    def debug_traces(self) -> Sequence[debugger_pb2.DebugTraceInfo]:
        """Traces saved with this program (DebugSession.save)."""
        req = debugger_pb2.ListDebugTracesRequest(program_id=self.id)
        return self.client._call(self.client.stubs.debugger.ListDebugTraces, req).traces

    def delete_debug_trace(self, name: str) -> None:
        req = debugger_pb2.DeleteDebugTraceRequest(program_id=self.id, name=name)
        self.client._call(self.client.stubs.debugger.DeleteDebugTrace, req)

    # -- machines (api_minor 20, feature "firmware-emulation") ---------------------------

    def machines(self) -> Sequence[emulator_pb2.MachineInfo]:
        """Machine descriptions saved with this program."""
        req = emulator_pb2.ListMachinesRequest(program_id=self.id)
        return self.client._call(self.client.stubs.emulator.ListMachines, req).machines

    def machine(self, name: str) -> str:
        """A saved machine description (JSON text)."""
        req = emulator_pb2.GetMachineRequest(program_id=self.id, name=name)
        return self.client._call(self.client.stubs.emulator.GetMachine, req).machine

    def save_machine(self, name: str, machine) -> emulator_pb2.MachineInfo:
        """Saves a machine description (JSON text or a dict) with the program."""
        req = emulator_pb2.SaveMachineRequest(program_id=self.id, name=name, machine=_machine_text(machine))
        return self.client._call(self.client.stubs.emulator.SaveMachine, req).info

    def delete_machine(self, name: str) -> None:
        req = emulator_pb2.DeleteMachineRequest(program_id=self.id, name=name)
        self.client._call(self.client.stubs.emulator.DeleteMachine, req)

    def derive_machine(self, trial_steps: int = 0, trial: bool = True) -> emulator_pb2.DeriveMachineResponse:
        """A starter machine for this program: its memory, the MMIO its code
        reaches, and auto-ack registers for polling loops a trial run finds
        (``.machine`` is the JSON, ``.notes`` say what was guessed)."""
        req = emulator_pb2.DeriveMachineRequest(program_id=self.id, trial_steps=trial_steps, no_trial=not trial)
        return self.client._call(self.client.stubs.emulator.DeriveMachine, req)

    # -- analysis ------------------------------------------------------------------

    def analyze(self, *analyzers: str) -> analysis_pb2.AnalysisJob:
        req = analysis_pb2.StartAnalysisRequest(program_id=self.id, analyzers=list(analyzers), provenance=self.client.provenance)
        return self.client._call(self.client.stubs.analysis.StartAnalysis, req).job

    def analysis_status(self) -> analysis_pb2.GetAnalysisStatusResponse:
        req = analysis_pb2.GetAnalysisStatusRequest(program_id=self.id)
        return self.client._call(self.client.stubs.analysis.GetAnalysisStatus, req)

    def wait_for_analysis(self, timeout: float = 3600.0, poll: float = 0.25) -> analysis_pb2.GetAnalysisStatusResponse:
        """Waits until the program's analysis is idle (the import's, and the
        background inference that publishes prototypes and structures in a
        revision of its own), so what is read next has them. Raises
        TimeoutError after ``timeout`` seconds."""
        deadline = time.monotonic() + timeout
        while True:
            status = self.analysis_status()
            if status.idle:
                return status
            if time.monotonic() >= deadline:
                raise TimeoutError("analysis of %s still running after %.0f s" % (self.id, timeout))
            time.sleep(poll)

    # -- Function ID (api_minor 49, feature "function-id"; docs/fid.md) ---------------

    def bsim_search(self, database: str, functions: Sequence[AddressLike] = (), **kw) -> bsim_pb2.SearchBSimResponse:
        """Functions similar to this program's in a BSim database (``Client.bsim_search``);
        no ``functions`` searches them all."""
        if not functions:
            kw.setdefault("all_functions", True)
        return self.client.bsim_search(database, self.id, functions, **kw)

    def bsim_apply(self, database: str, pairs: Sequence, kind: Union[str, int] = "name",
                   **kw) -> bsim_pb2.ApplyBSimMatchesResponse:
        """Applies BSim matches to this program's functions (``Client.bsim_apply``):
        ``pairs`` of ``(function, match)``, ``kind`` ``"name"``, ``"signature"`` or
        ``"signature_and_types"``."""
        return self.client.bsim_apply(database, self.id, pairs, kind, **kw)

    def fid_matches(self) -> analysis_pb2.ListFidMatchesResponse:
        """Function ID's last run on this program: every function with a match, its
        candidates (name, library, database, score), the name it proposes and what
        became of it (``status``: APPLIED, KEPT, UNAPPLIED, REJECTED, ACCEPTED).
        ``revision`` is 0 when it hasn't run; ``run_fid()`` runs it."""
        req = analysis_pb2.ListFidMatchesRequest(program_id=self.id)
        return self.client._call(self.client.stubs.analysis.ListFidMatches, req)

    def run_fid(self, *, wait: bool = True, timeout: float = 300.0) -> analysis_pb2.ListFidMatchesResponse:
        """Runs Function ID (the analyzer ``function-id``) in the background and, with
        ``wait``, returns its results when it is done."""
        self.analyze("function-id")
        if not wait:
            return self.fid_matches()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.analysis_status().idle:
                break
            time.sleep(0.2)
        return self.fid_matches()

    def fid_databases(self) -> List[analysis_pb2.FidDatabase]:
        """The Function ID databases for this program (``applies``: a library for its
        language), as ``Client.fid_databases`` lists them."""
        req = analysis_pb2.ListFidDatabasesRequest(program_id=self.id)
        return list(self.client._call(self.client.stubs.analysis.ListFidDatabases, req).databases)

    def apply_fid(self, entry: AddressLike, name: str = "", *, actor: Optional[str] = None,
                  reason: str = "") -> int:
        """Names a function as one of its Function ID matches (``name``: a candidate's,
        default the proposed one), as the caller. Returns the revision."""
        req = analysis_pb2.ApplyFidMatchRequest(program_id=self.id, entry=address(entry).offset, name=name,
                                                provenance=self.client._prov(actor, reason))
        return self.client._call(self.client.stubs.analysis.ApplyFidMatch, req).revision

    def reject_fid(self, entry: AddressLike, *, actor: Optional[str] = None, reason: str = "") -> int:
        """Rejects a function's Function ID match: its FID name and plate comment are
        retracted and later runs leave it alone. Returns the revision."""
        req = analysis_pb2.RejectFidMatchRequest(program_id=self.id, entry=address(entry).offset,
                                                 provenance=self.client._prov(actor, reason))
        return self.client._call(self.client.stubs.analysis.RejectFidMatch, req).revision


# ---------------------------------------------------------------------------
# Emulation sessions
# ---------------------------------------------------------------------------


def _register_write(name: str, value) -> emulator_pb2.EmulatorRegisterWrite:
    if isinstance(value, (bytes, bytearray)):
        return emulator_pb2.EmulatorRegisterWrite(name=name, bytes=bytes(value))
    value = int(value)
    if value < 0 or value >= 1 << 64:
        size = max(8, (value.bit_length() + 8) // 8)
        return emulator_pb2.EmulatorRegisterWrite(name=name, bytes=value.to_bytes(size, "little", signed=value < 0))
    return emulator_pb2.EmulatorRegisterWrite(name=name, value=value)


_RUN_MODES = {
    "run": emulator_pb2.EMULATOR_RUN_MODE_RUN,
    "into": emulator_pb2.EMULATOR_RUN_MODE_STEP_INTO,
    "over": emulator_pb2.EMULATOR_RUN_MODE_STEP_OVER,
    "out": emulator_pb2.EMULATOR_RUN_MODE_STEP_OUT,
}


def _machine_text(machine) -> str:
    if machine is None:
        return ""
    if isinstance(machine, (dict, list)):
        import json

        return json.dumps(machine)
    return str(machine)


def stop_kind(stop: emulator_pb2.EmulatorStop) -> str:
    """A stop's kind as a short name: "breakpoint", "exited", "unmapped", ..."""
    return emulator_pb2.EmulatorStopKind.Name(stop.kind).removeprefix("EMULATOR_STOP_KIND_").lower()


class EmulatorSession:
    """One emulation session (EmulatorService). Its state is this client's, not
    a fact: nothing it does is asserted or seen by other clients.

        with prog.emulate(0x401000, mode="call", args=[10]) as emu:
            emu.breakpoint(0x401020)
            print(emu.run().stop.kind, emu.registers()["RAX"])
            emu.step()
            print(emu.read(emu.register("RSP"), 16))
    """

    def __init__(self, client: Client, session_id: str, created: Optional[emulator_pb2.CreateEmulatorSessionResponse] = None):
        self.client = client
        self.id = session_id
        self.created = created
        self.state: Optional[emulator_pb2.EmulatorState] = created.state if created else None

    def __repr__(self):
        return f"<EmulatorSession {self.id}>"

    def _call(self, name, request):
        return self.client._call(getattr(self.client.stubs.emulator, name), request)

    @staticmethod
    def _state_options(registers: Sequence[str] = (), all_registers: bool = False) -> emulator_pb2.EmulatorStateOptions:
        return emulator_pb2.EmulatorStateOptions(registers=list(registers), all_registers=all_registers)

    # -- running -------------------------------------------------------------------

    def run(
        self,
        *,
        mode: str = "run",
        max_steps: int = 0,
        until: Optional[AddressLike] = None,
        time_limit_ms: int = 0,
        registers: Sequence[str] = (),
    ) -> emulator_pb2.RunEmulatorResponse:
        """Runs (or steps: ``mode`` "into", "over", "out") until a stop; the
        response's ``stop`` says why (:func:`stop_kind`) and ``state`` where."""
        req = emulator_pb2.RunEmulatorRequest(
            session_id=self.id,
            mode=_RUN_MODES[mode],
            max_steps=max_steps,
            time_limit_ms=time_limit_ms,
            state=self._state_options(registers),
        )
        if until is not None:
            req.until.CopyFrom(address(until))
        resp = self._call("RunEmulator", req)
        self.state = resp.state
        return resp

    def step(self, **kw) -> emulator_pb2.RunEmulatorResponse:
        """One instruction."""
        return self.run(mode="into", **kw)

    def step_over(self, **kw) -> emulator_pb2.RunEmulatorResponse:
        """One instruction, or a whole call."""
        return self.run(mode="over", **kw)

    def step_out(self, **kw) -> emulator_pb2.RunEmulatorResponse:
        """Until the current function returns."""
        return self.run(mode="out", **kw)

    # -- state -----------------------------------------------------------------------

    def get_state(self, *registers: str, all_registers: bool = False, regions: bool = False,
                  stdout_offset: int = 0) -> emulator_pb2.EmulatorState:
        opts = self._state_options(registers, all_registers)
        opts.include_regions = regions
        opts.stdout_offset = stdout_offset
        self.state = self._call("GetEmulatorState", emulator_pb2.GetEmulatorStateRequest(session_id=self.id, state=opts)).state
        return self.state

    @property
    def pc(self) -> int:
        return self.get_state().pc.offset

    def registers(self, *names: str, all_registers: bool = False) -> dict:
        """Register values by name (the display set by default)."""
        return {r.name: int.from_bytes(r.bytes, "little") for r in self.get_state(*names, all_registers=all_registers).registers}

    def register(self, name: str) -> int:
        return next(iter(self.registers(name).values()))

    def set_registers(self, values: Optional[dict] = None, **named) -> emulator_pb2.EmulatorState:
        writes = [_register_write(k, v) for k, v in {**(values or {}), **named}.items()]
        req = emulator_pb2.WriteEmulatorRegistersRequest(session_id=self.id, registers=writes)
        self.state = self._call("WriteEmulatorRegisters", req).state
        return self.state

    def read(self, addr: AddressLike, length: int) -> bytes:
        """Memory as the program sees it now (unmapped bytes read as 0; see :meth:`read_detailed`)."""
        return self.read_detailed(addr, length).data

    def read_detailed(self, addr: AddressLike, length: int) -> emulator_pb2.ReadEmulatorMemoryResponse:
        req = emulator_pb2.ReadEmulatorMemoryRequest(session_id=self.id, address=address(addr), length=length)
        return self._call("ReadEmulatorMemory", req)

    def write(self, addr: AddressLike, data: bytes) -> None:
        req = emulator_pb2.WriteEmulatorMemoryRequest(session_id=self.id, address=address(addr), data=bytes(data))
        self._call("WriteEmulatorMemory", req)

    @property
    def stdout(self) -> bytes:
        return self.get_state(stdout_offset=0).stdout

    # -- breakpoints and the trace ---------------------------------------------------------

    def breakpoint(self, *addrs: AddressLike) -> list:
        """Adds breakpoints; returns every breakpoint now set."""
        return self._breakpoints(add=addrs)

    def clear_breakpoint(self, *addrs: AddressLike) -> list:
        return self._breakpoints(remove=addrs)

    def clear_breakpoints(self) -> list:
        return self._breakpoints(clear=True)

    def _breakpoints(self, add=(), remove=(), clear=False) -> list:
        req = emulator_pb2.SetEmulatorBreakpointsRequest(
            session_id=self.id, add=[address(a) for a in add], remove=[address(a) for a in remove], clear=clear
        )
        return [a.offset for a in self._call("SetEmulatorBreakpoints", req).breakpoints]

    def trace(self, from_index: int = 0, limit: int = 0) -> emulator_pb2.GetEmulatorTraceResponse:
        """Trace entries (pc, instruction, registers written, memory read and
        written) and the summary."""
        req = emulator_pb2.GetEmulatorTraceRequest(session_id=self.id, from_index=from_index, limit=limit)
        return self._call("GetEmulatorTrace", req)

    # -- firmware (api_minor 20) ----------------------------------------------

    def input(self, data: bytes, peripheral: str = "") -> None:
        """Bytes for a UART of the session's machine (default: the console)."""
        req = emulator_pb2.WriteEmulatorInputRequest(session_id=self.id, data=bytes(data), peripheral=peripheral)
        self._call("WriteEmulatorInput", req)

    def machine(self, from_event: int = 0, limit: int = 0) -> emulator_pb2.GetEmulatorMachineResponse:
        """The machine's state (CPU mode, banked registers, devices, pending
        interrupts) and the exceptions taken from ``from_event`` on."""
        req = emulator_pb2.GetEmulatorMachineRequest(session_id=self.id, from_event=from_event, limit=limit)
        return self._call("GetEmulatorMachine", req)

    def break_on(self, *kinds: str) -> list:
        """Stops when the CPU takes these exceptions ("irq", "fiq", "swi",
        "svc", "systick", "irq:4", "any", "return"); none clears them."""
        req = emulator_pb2.SetEmulatorBreakpointsRequest(session_id=self.id, exception_breaks=list(kinds), set_exception_breaks=True)
        return list(self._call("SetEmulatorBreakpoints", req).exception_breaks)

    def trace_json(self) -> dict:
        """The whole trace as rk-emu --trace writes it."""
        import json

        req = emulator_pb2.GetEmulatorTraceRequest(session_id=self.id, json=True)
        return json.loads(self._call("GetEmulatorTrace", req).json)

    def close(self) -> None:
        self._call("CloseEmulatorSession", emulator_pb2.CloseEmulatorSessionRequest(session_id=self.id))

    def __enter__(self) -> "EmulatorSession":
        return self

    def __exit__(self, *exc):
        try:
            self.close()
        except NotFound:
            pass


# ---------------------------------------------------------------------------
# Debug sessions
# ---------------------------------------------------------------------------


_DEBUG_RUN_MODES = {
    "run": debugger_pb2.DEBUG_RUN_MODE_RUN,
    "into": debugger_pb2.DEBUG_RUN_MODE_STEP_INTO,
    "over": debugger_pb2.DEBUG_RUN_MODE_STEP_OVER,
    "out": debugger_pb2.DEBUG_RUN_MODE_STEP_OUT,
}

_BREAK_KINDS = {
    "software": debugger_pb2.DEBUG_BREAKPOINT_KIND_SOFTWARE,
    "hardware": debugger_pb2.DEBUG_BREAKPOINT_KIND_HARDWARE,
    "write": debugger_pb2.DEBUG_BREAKPOINT_KIND_WATCH_WRITE,
    "read": debugger_pb2.DEBUG_BREAKPOINT_KIND_WATCH_READ,
    "access": debugger_pb2.DEBUG_BREAKPOINT_KIND_WATCH_ACCESS,
}


def debug_stop_kind(stop) -> str:
    """A debug stop's (or snapshot's) kind as a short name: "breakpoint", "exited", "signal", ..."""
    kind = stop.kind if isinstance(stop, debugger_pb2.DebugStop) else stop
    return debugger_pb2.DebugStopKind.Name(kind).removeprefix("DEBUG_STOP_KIND_").lower()


def _daddr(addr: int, program: bool) -> debugger_pb2.DebugAddress:
    return debugger_pb2.DebugAddress(offset=int(addr), program=program)


class HookEvent:
    """What stopped a run at a hook (DebugSession.hook_function and the
    like): the event, and the session to read and change state through.
    Addresses here are runtime ones."""

    KINDS = {1: "function", 2: "syscall", 3: "mmio", 4: "userop"}

    def __init__(self, session: "DebugSession", event):
        self.session = session
        self.event = event
        self.id = event.hook_id
        self.kind = self.KINDS.get(event.kind, "unknown")
        self.pc = event.pc
        self.name = event.name
        self.number = event.number
        self.args = list(event.args)
        self.address = event.address
        self.size = event.size
        self.write = event.write
        self.value = event.value

    def arg(self, index: int) -> int:
        return self.args[index] if index < len(self.args) else 0

    def read(self, addr: int, length: int) -> bytes:
        return self.session.read(addr, length, runtime=True)

    def read_string(self, addr: int, max_length: int = 4096) -> bytes:
        """A NUL-terminated string at a runtime address."""
        out = b""
        while len(out) < max_length:
            chunk = self.session.read(addr + len(out), min(256, max_length - len(out)), runtime=True)
            end = chunk.find(b"\0")
            if end >= 0:
                return out + chunk[:end]
            out += chunk
        return out

    def write_memory(self, addr: int, data: bytes) -> None:
        self.session.write(addr, data, runtime=True)

    def register(self, name: str) -> int:
        return self.session.register(name)

    def __repr__(self):
        return f"<HookEvent {self.kind} {self.name or self.number} at {self.pc:#x}>"


class DebugSession:
    """One debug session (DebugService): the emulator, a live process or board,
    or a saved trace, all the same way. Addresses you give are the program's
    (as the listing shows them) unless ``runtime=True``. Every stop is
    recorded; ``snapshot=`` reads the recording (time travel).

        with prog.debug("launch", breakpoints=[main]) as dbg:
            dbg.run()                      # to main
            dbg.step_over(); dbg.step_out()
            print(dbg.registers()["RAX"], dbg.read(message, 16))
            first = dbg.timeline().first
            print(dbg.registers(snapshot=first))   # as it was
    """

    def __init__(self, client: Client, session_id: str, created: Optional[debugger_pb2.CreateDebugSessionResponse] = None):
        self.client = client
        self.id = session_id
        self.created = created
        self.state: Optional[debugger_pb2.DebugState] = created.state if created else None
        self._hook_fns: dict = {}

    def __repr__(self):
        return f"<DebugSession {self.id}>"

    def _call(self, name, request):
        return self.client._call(getattr(self.client.stubs.debugger, name), request)

    # -- running ---------------------------------------------------------------

    def run(self, *, mode: str = "run", until: Optional[int] = None, runtime: bool = False, max_steps: int = 0,
            time_limit_ms: int = 0, registers: Sequence[str] = ()) -> debugger_pb2.ResumeDebugSessionResponse:
        """Runs (or steps: ``mode`` "into", "over", "out"). A live target still
        running at the time limit answers RUNNING: :meth:`wait` or :meth:`interrupt`."""
        req = debugger_pb2.ResumeDebugSessionRequest(
            session_id=self.id, mode=_DEBUG_RUN_MODES[mode], max_steps=max_steps, time_limit_ms=time_limit_ms,
            state=debugger_pb2.DebugStateOptions(registers=list(registers)))
        if until is not None:
            req.until.CopyFrom(_daddr(until, not runtime))
        resp = self._call("ResumeDebugSession", req)
        # Hooks this session's Python answers: answer, and go on (api_minor 68).
        resp = self._handle_hooks(resp, lambda: self._call("ResumeDebugSession", req))
        self.state = resp.state
        return resp

    def step(self, **kw):
        return self.run(mode="into", **kw)

    def step_over(self, **kw):
        return self.run(mode="over", **kw)

    def step_out(self, **kw):
        return self.run(mode="out", **kw)

    def wait(self, wait_ms: int = 1000) -> debugger_pb2.WaitDebugSessionResponse:
        resp = self._call("WaitDebugSession", debugger_pb2.WaitDebugSessionRequest(session_id=self.id, wait_ms=wait_ms))
        self.state = resp.state
        return resp

    def interrupt(self) -> None:
        self._call("InterruptDebugSession", debugger_pb2.InterruptDebugSessionRequest(session_id=self.id))

    # -- state -----------------------------------------------------------------

    def get_state(self, *registers: str, snapshot: Optional[int] = None, all_registers: bool = False,
                  threads: bool = False, output_offset: int = 0) -> debugger_pb2.DebugState:
        req = debugger_pb2.GetDebugStateRequest(session_id=self.id, state=debugger_pb2.DebugStateOptions(
            registers=list(registers), all_registers=all_registers, include_threads=threads, output_offset=output_offset))
        if snapshot is not None:
            req.snapshot = snapshot
        state = self._call("GetDebugState", req).state
        if snapshot is None:
            self.state = state
        return state

    @property
    def pc(self) -> int:
        """The program (static) address of the pc, else the runtime one."""
        loc = self.get_state().pc
        return loc.program_address.offset if loc.HasField("program_address") else loc.address.offset

    def registers(self, *names: str, snapshot: Optional[int] = None) -> dict:
        return {r.name: int.from_bytes(r.bytes, "little") for r in self.get_state(*names, snapshot=snapshot).registers}

    def register(self, name: str, snapshot: Optional[int] = None) -> int:
        return next(iter(self.registers(name, snapshot=snapshot).values()))

    def set_registers(self, values: Optional[dict] = None, **named) -> debugger_pb2.DebugState:
        writes = []
        for k, v in {**(values or {}), **named}.items():
            w = _register_write(k, v)
            writes.append(debugger_pb2.DebugRegisterWrite(name=w.name, value=w.value, bytes=w.bytes))
        self.state = self._call("WriteDebugRegisters", debugger_pb2.WriteDebugRegistersRequest(session_id=self.id, registers=writes)).state
        return self.state

    def read(self, addr: int, length: int, *, runtime: bool = False, snapshot: Optional[int] = None) -> bytes:
        return self.read_detailed(addr, length, runtime=runtime, snapshot=snapshot).data

    def read_detailed(self, addr: int, length: int, *, runtime: bool = False,
                      snapshot: Optional[int] = None) -> debugger_pb2.ReadDebugMemoryResponse:
        req = debugger_pb2.ReadDebugMemoryRequest(session_id=self.id, address=_daddr(addr, not runtime), length=length)
        if snapshot is not None:
            req.snapshot = snapshot
        return self._call("ReadDebugMemory", req)

    def write(self, addr: int, data: bytes, *, runtime: bool = False) -> None:
        self._call("WriteDebugMemory", debugger_pb2.WriteDebugMemoryRequest(
            session_id=self.id, address=_daddr(addr, not runtime), data=bytes(data)))

    @property
    def output(self) -> bytes:
        return self.get_state(output_offset=0).output

    # -- breakpoints, threads, modules -------------------------------------------

    def breakpoint(self, *addrs: int, kind: str = "software", size: int = 0, runtime: bool = False,
                   condition: str = "", ignore_count: int = 0) -> list:
        """Adds breakpoints (``kind`` "software", "hardware", or watchpoints
        "write", "read", "access" of ``size`` bytes); returns them all.
        ``condition`` (an expression, as :meth:`evaluate` takes) and
        ``ignore_count`` (api_minor 64, feature "debugger-conditions"): a run
        stops there only after that many hits and when the condition holds."""
        req = debugger_pb2.SetDebugBreakpointsRequest(session_id=self.id, add=[
            debugger_pb2.DebugBreakpointSpec(address=_daddr(a, not runtime), kind=_BREAK_KINDS[kind], size=size,
                                             condition=condition, ignore_count=ignore_count) for a in addrs])
        return list(self._call("SetDebugBreakpoints", req).breakpoints)

    def update_breakpoint(self, breakpoint_id: int, *, condition: Optional[str] = None, ignore_count: Optional[int] = None,
                          enabled: Optional[bool] = None) -> list:
        """Changes a breakpoint's condition ("" removes it), ignore count or
        enabled state (api_minor 64); returns every breakpoint."""
        u = debugger_pb2.DebugBreakpointUpdate(id=breakpoint_id)
        if condition is not None:
            u.condition = condition
        if ignore_count is not None:
            u.ignore_count = ignore_count
        if enabled is not None:
            u.disabled = not enabled
        req = debugger_pb2.SetDebugBreakpointsRequest(session_id=self.id, update=[u])
        return list(self._call("SetDebugBreakpoints", req).breakpoints)

    def watch(self, addr: int, size: int = 4, kind: str = "write", runtime: bool = False) -> list:
        return self.breakpoint(addr, kind=kind, size=size, runtime=runtime)

    def clear_breakpoint(self, *addrs: int, runtime: bool = False) -> list:
        req = debugger_pb2.SetDebugBreakpointsRequest(session_id=self.id, remove=[_daddr(a, not runtime) for a in addrs])
        return list(self._call("SetDebugBreakpoints", req).breakpoints)

    def clear_breakpoints(self) -> list:
        return list(self._call("SetDebugBreakpoints", debugger_pb2.SetDebugBreakpointsRequest(session_id=self.id, clear=True)).breakpoints)

    def threads(self) -> list:
        return list(self.get_state(threads=True).threads)

    def select_thread(self, thread_id: str) -> debugger_pb2.DebugState:
        self.state = self._call("SelectDebugThread", debugger_pb2.SelectDebugThreadRequest(session_id=self.id, thread_id=thread_id)).state
        return self.state

    def modules(self) -> debugger_pb2.ListDebugModulesResponse:
        """Loaded modules, the memory map and the address mapping (slide)."""
        return self._call("ListDebugModules", debugger_pb2.ListDebugModulesRequest(session_id=self.id))

    # -- the recording ---------------------------------------------------------

    def crash(self, max_frames: int = 0) -> debugger_pb2.DebugCrash:
        """A crash dump session's summary (api_minor 102): ``reason``
        ("SIGSEGV (SEGV_MAPERR) at 0x0"), ``fault_address``, ``pc`` with the
        ``module`` and ``module_offset``, ``function``, ``instruction``,
        ``backtrace`` (DebugFrame), ``threads``, ``modules`` (with the project
        programs they are), the process and system, and ``summary`` as text."""
        return self._call("GetDebugCrash", debugger_pb2.GetDebugCrashRequest(session_id=self.id, max_frames=max_frames)).crash

    def backtrace(self, snapshot: Optional[int] = None, max_frames: int = 0) -> list:
        """The call stack now, or at a recorded snapshot (api_minor 59, feature
        "debugger-stack"): DebugFrame messages, innermost first, each with
        ``level``, ``pc`` (a DebugLocation: runtime and program address,
        module), ``sp``, ``cfa``, ``how`` ("registers", "cfi", "entry",
        "frame pointer", "link register", "stack scan"), ``function``,
        ``function_entry`` and ``function_offset`` (when the analysis knows
        it), and the frame's ``registers``. Raises when the architecture has
        no unwinder."""
        req = debugger_pb2.GetDebugBacktraceRequest(session_id=self.id, max_frames=max_frames)
        if snapshot is not None:
            req.snapshot = snapshot
        r = self._call("GetDebugBacktrace", req)
        if r.unsupported:
            raise RevkitError(r.unsupported)
        return list(r.frames)

    def evaluate(self, *expressions: str, snapshot: Optional[int] = None, frame: Optional[int] = None,
                 compare_snapshot: Optional[int] = None, depth: int = 0, function: Optional[AddressLike] = None) -> list:
        """Values of C expressions now, or at a recorded snapshot, in a
        call-stack frame (api_minor 60, feature "debugger-values";
        docs/debugger.md "Expressions"): registers (``$RAX`` or ``RAX``),
        symbols, the frame's variables by their decompiler names, memory
        and casts to the program's types (``*(struct ctx *)$RDI``,
        ``buf[i] == 'x'``). DebugValue messages, one per expression:
        ``text`` (typed), ``type``, ``hex``, ``address`` or
        ``register_name``, ``children`` (a struct's fields), and ``error``
        when there is no value. ``compare_snapshot`` marks ``changed``
        against an earlier stop, as a watch does. ``function`` (a program
        address; api_minor 61): evaluate in the innermost frame of the
        function there, for its variables."""
        fn = address(function) if function is not None else None
        req = debugger_pb2.EvaluateDebugRequest(session_id=self.id, depth=depth,
                                                items=[debugger_pb2.DebugEvalItem(expression=e, frame_function=fn) for e in expressions])
        if snapshot is not None:
            req.snapshot = snapshot
        if frame is not None:
            req.frame = frame
        if compare_snapshot is not None:
            req.compare_snapshot = compare_snapshot
        return list(self._call("EvaluateDebug", req).values)

    def disassemble(self, addr: Optional[int] = None, count: int = 32, *, before: int = 0, runtime: bool = False,
                    snapshot: Optional[int] = None) -> debugger_pb2.DisassembleDebugMemoryResponse:
        """Instructions in target memory (api_minor 62, feature
        "debugger-disassembly"), in the program or not: at ``addr`` (a
        program address, or runtime with ``runtime=True``; the pc when
        omitted), ``before`` instructions earlier for context. Each
        DebugInstruction has ``location``, ``bytes``, ``mnemonic``,
        ``operands``, ``symbol``, a direct ``target`` with
        ``target_symbol``, and ``pc``/``breakpoint`` marks; ``next`` is where
        to continue."""
        req = debugger_pb2.DisassembleDebugMemoryRequest(session_id=self.id, count=count, before=before)
        if addr is not None:
            req.address.CopyFrom(_daddr(addr, not runtime))
        if snapshot is not None:
            req.snapshot = snapshot
        return self._call("DisassembleDebugMemory", req)

    # -- hooks (api_minor 68, feature "debugger-hooks"; docs/debugger.md "Hooks") --

    def hook_function(self, target, fn) -> int:
        """Calls ``fn(hook)`` instead of a function: ``target`` is its entry
        (a program address) or an import's or symbol's name ("malloc").
        ``fn`` returns the value the function returns (it isn't run), or
        None to let it run. ``hook.args`` are its integer arguments by the
        calling convention; ``hook.read``/``write``/``register`` reach the
        state. Runs (:meth:`run`) answer hooks until another stop. Returns
        the hook's id."""
        spec = debugger_pb2.DebugHookSpec(kind=debugger_pb2.DEBUG_HOOK_KIND_FUNCTION)
        if isinstance(target, str):
            spec.name = target
        else:
            spec.address.CopyFrom(_daddr(target, True))
        return self._add_hook(spec, fn)

    def hook_syscall(self, number: Optional[int], fn) -> int:
        """Calls ``fn(hook)`` for a system call (``number``, None: every
        call): it returns the call's result, or None for the emulator's own
        handling. ``hook.number`` and ``hook.args``."""
        spec = debugger_pb2.DebugHookSpec(kind=debugger_pb2.DEBUG_HOOK_KIND_SYSCALL, number=-1 if number is None else number)
        return self._add_hook(spec, fn)

    def hook_mmio(self, start: int, end: int, *, read=None, write=None, runtime: bool = False) -> int:
        """Hooks reads and writes of [start, end) (firmware registers; the
        range becomes MMIO). ``read(hook)`` returns the value read (None:
        what memory holds); ``write(hook)`` sees ``hook.value``.
        ``hook.address``, ``hook.size``."""
        if end <= start:
            raise ValueError("end must be past start")
        spec = debugger_pb2.DebugHookSpec(kind=debugger_pb2.DEBUG_HOOK_KIND_MMIO, size=end - start,
                                          read=read is not None, write=write is not None)
        spec.address.CopyFrom(_daddr(start, not runtime))

        def dispatch(h):
            fn = write if h.write else read
            return fn(h) if fn is not None else None
        return self._add_hook(spec, dispatch)

    def hook_userop(self, name: str, fn) -> int:
        """Calls ``fn(hook)`` for a CALLOTHER by name (a p-code user op the
        spec leaves to the emulator): it returns the op's output.
        ``hook.args`` are its inputs."""
        spec = debugger_pb2.DebugHookSpec(kind=debugger_pb2.DEBUG_HOOK_KIND_USEROP, name=name)
        return self._add_hook(spec, fn)

    def unhook(self, *hook_ids: int) -> None:
        req = debugger_pb2.SetDebugHooksRequest(session_id=self.id, remove=list(hook_ids))
        self._call("SetDebugHooks", req)
        for i in hook_ids:
            self._hook_fns.pop(i, None)

    def clear_hooks(self) -> None:
        self._call("SetDebugHooks", debugger_pb2.SetDebugHooksRequest(session_id=self.id, clear=True))
        self._hook_fns.clear()

    def hooks(self) -> list:
        """The hooks set, with their ids and hits."""
        return list(self._call("SetDebugHooks", debugger_pb2.SetDebugHooksRequest(session_id=self.id)).hooks)

    def _add_hook(self, spec, fn) -> int:
        r = self._call("SetDebugHooks", debugger_pb2.SetDebugHooksRequest(session_id=self.id, add=[spec]))
        hid = r.hooks[-1].id
        self._hook_fns[hid] = fn
        return hid

    def answer_hook(self, hook_id: int, value: Optional[int] = None) -> debugger_pb2.DebugState:
        """Answers the hook a run stopped at (DebugStop.hook): its value
        (a function's return, a call's result, a read's value, a user op's
        output), or None to go on as if not hooked. Then resume."""
        req = debugger_pb2.AnswerDebugHookRequest(session_id=self.id, hook_id=hook_id)
        if value is not None:
            req.value = int(value) & 0xFFFFFFFFFFFFFFFF
        self.state = self._call("AnswerDebugHook", req).state
        return self.state

    def _handle_hooks(self, r, again):
        """While the run stopped at a hook this session's Python handles: answer it and go on."""
        while r.stop.kind == debugger_pb2.DEBUG_STOP_KIND_HOOK and r.stop.hook.hook_id in self._hook_fns:
            fn = self._hook_fns[r.stop.hook.hook_id]
            value = fn(HookEvent(self, r.stop.hook))
            if value is not None and not isinstance(value, (int, bool)):
                raise TypeError(f"a hook returns an int or None, not {type(value).__name__}")
            self.answer_hook(r.stop.hook.hook_id, None if value is None else int(value))
            r = again()
        return r

    def rewind(self, snapshot: Optional[int] = None, *, save_branch_as: str = "") -> debugger_pb2.RewindDebugSessionResponse:
        """Back to a recorded snapshot, to continue from there (api_minor 65,
        feature "debugger-rewind"): the emulator's state as it was then; the
        later snapshots are dropped, first saved as the trace
        ``save_branch_as`` when given. Only the emulator (without a machine)
        can go back; ``state.rewindable`` says so."""
        req = debugger_pb2.RewindDebugSessionRequest(session_id=self.id, save_branch_as=save_branch_as)
        if snapshot is None:
            req.step_back = True
        else:
            req.snapshot = snapshot
        r = self._call("RewindDebugSession", req)
        self.state = r.state
        return r

    def step_back(self) -> debugger_pb2.RewindDebugSessionResponse:
        """One instruction back (the emulator's recording)."""
        return self.rewind()

    def copy_memory(self, addr: int, length: int = 0, *, mode: str = "block", region: bool = False, runtime: bool = False,
                    name: str = "", snapshot: Optional[int] = None, permissions: str = "", analyze: bool = False,
                    actor=None, reason: str = "") -> debugger_pb2.CopyDebugMemoryResponse:
        """Target memory into the program (api_minor 63, feature
        "debugger-copy"; docs/debugger.md "Copying runtime memory"): ``mode``
        "block" (a new memory block at the runtime address: a library, the
        heap, unpacked code outside the program), "patch" (patches over the
        program's own bytes, only those that differ) or "program" (a new raw
        program in the project, based at the runtime address). ``addr`` is a
        program address (runtime with ``runtime=True``); ``region`` copies
        the whole region of the target's memory map holding it. One revision:
        retract ``seqs`` to undo."""
        modes = {"block": debugger_pb2.DEBUG_COPY_MODE_BLOCK, "patch": debugger_pb2.DEBUG_COPY_MODE_PATCH,
                 "patches": debugger_pb2.DEBUG_COPY_MODE_PATCH, "program": debugger_pb2.DEBUG_COPY_MODE_NEW_PROGRAM}
        if mode not in modes:
            raise ValueError(f"mode is block, patch or program, not {mode!r}")
        req = debugger_pb2.CopyDebugMemoryRequest(
            session_id=self.id, address=_daddr(addr, not runtime), length=length, region=region, mode=modes[mode],
            name=name, permissions=permissions, analyze=analyze, provenance=self.client._prov(actor, reason))
        if snapshot is not None:
            req.snapshot = snapshot
        return self._call("CopyDebugMemory", req)

    def value(self, expression: str, snapshot: Optional[int] = None, frame: Optional[int] = None) -> str:
        """One expression's typed text (``evaluate``); raises when it has no value."""
        v = self.evaluate(expression, snapshot=snapshot, frame=frame)[0]
        if v.error:
            raise RevkitError(f"{expression}: {v.error}")
        return v.text

    def timeline(self, from_snapshot: int = 0, limit: int = 0, stops_only: bool = False,
                 events_only: bool = False) -> debugger_pb2.GetDebugTimelineResponse:
        """Recorded snapshots; ``events_only``: those that entered or returned
        from an exception (firmware), each with ``event``."""
        return self._call("GetDebugTimeline", debugger_pb2.GetDebugTimelineRequest(
            session_id=self.id, from_snapshot=from_snapshot, limit=limit, stops_only=stops_only, events_only=events_only))

    # -- firmware (api_minor 20) ----------------------------------------------

    def input(self, data: bytes, peripheral: str = "") -> None:
        """Bytes for a UART of the emulator's machine (default: the console)."""
        self._call("WriteDebugInput", debugger_pb2.WriteDebugInputRequest(session_id=self.id, data=bytes(data), peripheral=peripheral))

    def machine(self, from_event: int = 0, limit: int = 0) -> debugger_pb2.GetDebugMachineResponse:
        """The machine's state and the exceptions taken from ``from_event`` on."""
        return self._call("GetDebugMachine", debugger_pb2.GetDebugMachineRequest(session_id=self.id, from_event=from_event, limit=limit))

    def break_on(self, *kinds: str) -> list:
        """Stops when the CPU takes these exceptions ("irq", "svc", "irq:4", "any"); none clears them."""
        req = debugger_pb2.SetDebugBreakpointsRequest(session_id=self.id, exception_breaks=list(kinds), set_exception_breaks=True)
        return list(self._call("SetDebugBreakpoints", req).exception_breaks)

    def save(self, name: str) -> debugger_pb2.DebugTraceInfo:
        """Saves the timeline with the program's project (see Program.debug_traces)."""
        return self._call("SaveDebugTrace", debugger_pb2.SaveDebugTraceRequest(session_id=self.id, name=name)).trace

    def close(self, kill: bool = False) -> None:
        self._call("CloseDebugSession", debugger_pb2.CloseDebugSessionRequest(session_id=self.id, kill=kill))

    def __enter__(self) -> "DebugSession":
        return self

    def __exit__(self, *exc):
        try:
            self.close()
        except NotFound:
            pass
