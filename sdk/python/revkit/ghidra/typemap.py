"""Ghidra types (as ghidra_dump.py writes them) to revkit's type model.

Two targets:

* ``TypeBatch`` turns type references into ``TypeNode``s for ``DefineType``
  assertions (api_minor 4, feature ``define-types``), deduplicated, with
  references between them as ``assertion_index`` (recursive structs work).
* ``c_type`` / ``c_prototype`` print C declarations, the text a ``Retype``
  takes as ``c_declaration`` from daemons without ``define-types``.

A type reference (docs/ghidra-interop.md) is ``{"ref": id}`` for a named
type in the document's ``types`` table, or a structural one:
``{"kind": "pointer", "size": 8, "target": T}``, ``{"kind": "array",
"count": N, "element": T}``, or a builtin (``void``, ``undefined``,
``bool``, ``char``, ``int``, ``uint``, ``float``) with ``size`` and, for
integers, ``rank``.
"""

from __future__ import annotations

import json
from typing import Optional

from revkit.v1 import assertion_pb2, types_pb2

RANKS = {
    "char": types_pb2.INTEGER_RANK_CHAR,
    "short": types_pb2.INTEGER_RANK_SHORT,
    "int": types_pb2.INTEGER_RANK_INT,
    "long": types_pb2.INTEGER_RANK_LONG,
    "long_long": types_pb2.INTEGER_RANK_LONG_LONG,
    "int128": types_pb2.INTEGER_RANK_INT128,
    "wchar": types_pb2.INTEGER_RANK_WCHAR,
    "char8": types_pb2.INTEGER_RANK_CHAR8,
    "char16": types_pb2.INTEGER_RANK_CHAR16,
    "char32": types_pb2.INTEGER_RANK_CHAR32,
}
FLOATS = {
    "half": types_pb2.FLOAT_KIND_HALF,
    "float": types_pb2.FLOAT_KIND_FLOAT,
    "double": types_pb2.FLOAT_KIND_DOUBLE,
    "long_double": types_pb2.FLOAT_KIND_LONG_DOUBLE,
    "float128": types_pb2.FLOAT_KIND_FLOAT128,
}
# Ghidra calling-convention names revkit's type model spells the same way;
# the program's default convention (and "unknown") become revkit's default.
CONVENTIONS = {"__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall", "__pascal"}


def convention(name: str, default: str) -> str:
    if not name or name in ("unknown", "default", default):
        return ""
    return name if name in CONVENTIONS else "other"


class TypeError_(ValueError):
    pass


class TypeBatch:
    """Collects the TypeNodes that a set of type references needs.

    ``node_for(tref)`` returns the batch index of the node for ``tref``
    (adding it and what it references); ``nodes`` are in index order, and
    their ``TypeNodeRef.assertion_index`` values are batch indexes, which the
    caller offsets by the position of the batch in its request.
    """

    def __init__(self, types: dict[str, dict], default_cc: str = "", pointer_size: int = 8):
        self.types = types
        self.default_cc = default_cc
        self.pointer_size = pointer_size
        self.nodes: list[types_pb2.TypeNode] = []
        self.what: list[str] = []  # a label per node, for reports
        self._index: dict[str, int] = {}

    def node_for(self, tref: dict) -> int:
        key = _key(tref)
        if key in self._index:
            return self._index[key]
        i = len(self.nodes)
        self._index[key] = i
        self.nodes.append(types_pb2.TypeNode())  # filled below; a cycle back here finds the index
        self.what.append(tref.get("ref") or c_type(tref, self.types))
        self.nodes[i] = self._build(tref)
        return i

    def function_node(self, ret: dict, params: list[tuple[str, dict]], varargs: bool, cc: str) -> int:
        """A FUNCTION node for a function's own signature (not a named type)."""
        return self.node_for({"kind": "function", "return": ret, "params": [{"name": n, "type": t} for n, t in params],
                              "varargs": varargs, "calling_convention": cc})

    def _ref(self, tref: dict) -> types_pb2.TypeNodeRef:
        return types_pb2.TypeNodeRef(assertion_index=self.node_for(tref))

    def _build(self, t: dict) -> types_pb2.TypeNode:
        N = types_pb2.TypeNode
        if "ref" in t:
            d = self.types.get(t["ref"])
            if d is None:
                raise TypeError_(f"type {t['ref']!r} is not in the document's types")
            return self._named(d)
        kind = t.get("kind")
        size = int(t.get("size", 0))
        if kind == "void":
            return N(kind=types_pb2.TYPE_KIND_VOID)
        if kind == "undefined":
            return N(kind=types_pb2.TYPE_KIND_UNDEFINED, size=max(size, 1))
        if kind == "bool":
            return N(kind=types_pb2.TYPE_KIND_BOOL, size=size or 1)
        if kind == "char":
            return N(kind=types_pb2.TYPE_KIND_CHAR, size=size or 1, is_signed=bool(t.get("signed", True)))
        if kind in ("int", "uint"):
            return N(kind=types_pb2.TYPE_KIND_INT if kind == "int" else types_pb2.TYPE_KIND_UINT, size=size,
                     rank=RANKS.get(t.get("rank", ""), types_pb2.INTEGER_RANK_UNSPECIFIED))
        if kind == "float":
            return N(kind=types_pb2.TYPE_KIND_FLOAT, size=size,
                     float_kind=FLOATS.get(t.get("float_kind", ""), types_pb2.FLOAT_KIND_UNSPECIFIED))
        if kind == "pointer":
            return N(kind=types_pb2.TYPE_KIND_POINTER, size=size or self.pointer_size, target=self._ref(t["target"]))
        if kind == "array":
            return N(kind=types_pb2.TYPE_KIND_ARRAY, count=int(t.get("count", 0)), target=self._ref(t["element"]))
        if kind == "function":
            return self._function(t)
        raise TypeError_(f"unknown type reference {t!r}")

    def _function(self, d: dict) -> types_pb2.TypeNode:
        n = types_pb2.TypeNode(kind=types_pb2.TYPE_KIND_FUNCTION, varargs=bool(d.get("varargs")),
                               calling_convention=convention(d.get("calling_convention", ""), self.default_cc))
        ret = d.get("return") or {"kind": "void"}
        if ret.get("kind") != "void":
            n.target.CopyFrom(self._ref(ret))
        for p in d.get("params", []):
            n.params.add(name=p.get("name") or "", type=self._ref(p["type"]))
        return n

    def _named(self, d: dict) -> types_pb2.TypeNode:
        kind = d["kind"]
        if kind in ("struct", "union"):
            n = types_pb2.TypeNode(
                kind=types_pb2.TYPE_KIND_UNION if kind == "union" else types_pb2.TYPE_KIND_STRUCT,
                name=d["name"], size=int(d.get("size", 0)), alignment=int(d.get("alignment", 0)),
                packed=bool(d.get("packed")), incomplete=bool(d.get("incomplete")))
            for f in d.get("fields", []):
                bits = int(f["offset"]) * 8 + int(f.get("bit_offset", 0))
                n.fields.add(name=f.get("name", ""), type=self._ref(f["type"]), offset=bits // 8,
                             bit_offset=bits % 8 if f.get("bit_size") else 0, bit_size=int(f.get("bit_size", 0)))
            return n
        if kind == "enum":
            n = types_pb2.TypeNode(kind=types_pb2.TYPE_KIND_ENUM, name=d["name"], size=int(d.get("size", 4)),
                                   is_signed=bool(d.get("signed")))
            for name, value in d.get("values", []):
                n.enumerators.add(name=name, value=int(value))
            return n
        if kind == "typedef":
            return types_pb2.TypeNode(kind=types_pb2.TYPE_KIND_TYPEDEF, name=d["name"], target=self._ref(d["target"]))
        if kind == "function":
            # A named function definition: revkit's function types are
            # structural, so it is a typedef of the function type.
            return types_pb2.TypeNode(kind=types_pb2.TYPE_KIND_TYPEDEF, name=d["name"],
                                      target=self._ref({**{k: d[k] for k in ("return", "params", "varargs", "calling_convention") if k in d},
                                                        "kind": "function"}))
        raise TypeError_(f"unknown named type kind {kind!r}")

    def bodies(self, offset: int) -> list[assertion_pb2.AssertionBody]:
        """The nodes as define_type bodies placed at ``offset`` in a request."""
        out = []
        for node in self.nodes:
            n = types_pb2.TypeNode()
            n.CopyFrom(node)
            _shift(n, offset)
            out.append(assertion_pb2.AssertionBody(define_type=assertion_pb2.DefineType(type=n)))
        return out


def _shift(n: types_pb2.TypeNode, offset: int) -> None:
    refs = ([n.target] if n.HasField("target") else []) + [f.type for f in n.fields] + [p.type for p in n.params]
    for r in refs:
        if r.WhichOneof("kind") == "assertion_index":
            r.assertion_index += offset


def _key(tref: dict) -> str:
    return json.dumps(tref, sort_keys=True)


def is_undefined(tref: Optional[dict]) -> bool:
    """True for types that say nothing (undefined, undefinedN)."""
    return tref is None or tref.get("kind") == "undefined"


# ---------------------------------------------------------------------------
# C text
# ---------------------------------------------------------------------------

_INT_NAMES = {"char": "char", "short": "short", "int": "int", "long": "long", "long_long": "long long",
              "int128": "__int128", "wchar": "wchar_t", "char8": "char8_t", "char16": "char16_t", "char32": "char32_t"}


def _base(t: dict, types: dict) -> str:
    if "ref" in t:
        d = types.get(t["ref"], {})
        k = d.get("kind")
        name = d.get("name", t["ref"].rsplit("/", 1)[-1])
        return f"{k} {name}" if k in ("struct", "union", "enum") else name
    kind = t.get("kind")
    size = int(t.get("size", 0))
    if kind == "void":
        return "void"
    if kind == "undefined":
        return "undefined" if size <= 1 else f"undefined{size}"
    if kind == "bool":
        return "bool"
    if kind == "char":
        return "char"
    if kind in ("int", "uint"):
        rank = t.get("rank")
        if rank in ("wchar", "char8", "char16", "char32"):
            return _INT_NAMES[rank]
        if rank in _INT_NAMES:
            name = _INT_NAMES[rank]
            if kind == "uint":
                return "unsigned " + name
            return "signed char" if rank == "char" else name
        return f"{'' if kind == 'int' else 'u'}int{size * 8}_t"
    if kind == "float":
        fk = t.get("float_kind") or {2: "half", 4: "float", 8: "double"}.get(size, "long_double")
        return {"half": "_Float16", "float": "float", "double": "double", "long_double": "long double",
                "float128": "__float128"}[fk]
    return f"undefined{max(size, 1)}"


def c_type(t: dict, types: dict, name: str = "") -> str:
    """A C declaration of ``name`` with type ``t`` (just the type when unnamed)."""
    inner = name
    while True:
        kind = t.get("kind") if "ref" not in t else None
        if kind == "pointer":
            target = t["target"]
            inner = "*" + inner
            if target.get("kind") in ("array", "function"):
                inner = "(" + inner + ")"
            t = target
        elif kind == "array":
            inner = f"{inner}[{int(t.get('count', 0)) or ''}]"
            t = t["element"]
        elif kind == "function":
            params = ", ".join(c_type(p["type"], types, p.get("name", "")) for p in t.get("params", []))
            if t.get("varargs"):
                params = params + ", ..." if params else "..."
            inner = f"{inner}({params or 'void'})"
            t = t.get("return") or {"kind": "void"}
        else:
            base = _base(t, types)
            if not inner:
                return base
            return base + ("" if inner.startswith("*") and base.endswith("*") else " ") + inner


def c_prototype(name: str, ret: dict, params: list[tuple[str, dict]], varargs: bool, types: dict, cc: str = "") -> str:
    """``int name(char *s, ...)``, with a calling convention when not the default."""
    args = ", ".join(c_type(t, types, n) for n, t in params)
    if varargs:
        args = args + ", ..." if args else "..."
    head = c_type(ret, types)
    if cc:
        head += " " + cc
    return f"{head} {name}({args or 'void'})"
