"""Ghidra's value types for the compat shim: addresses and address sets,
Java-style iterators and lists, the enums scripts compare against
(SourceType, RefType, SymbolType, CommentType, OperandType), registers,
scalars and data types.

Every class derives from :class:`JavaObject`, which gives JPype/Jython bean
properties (``instruction.address`` calls ``getAddress()``) and turns a
method the shim lacks into :class:`Unsupported` naming it, never an
``AttributeError`` a script could mistake for absence.
"""

from __future__ import annotations

import bisect
from typing import Any, Iterable, Iterator, Optional

from revkit.ghidra.compat.errors import Unsupported


class JavaObject:
    """Bean properties and honest failures for the shim's Ghidra classes."""

    _java_name = ""

    @classmethod
    def java_name(cls) -> str:
        return cls._java_name or cls.__name__

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        cls = type(self)
        if name[:1].islower():
            cap = name[:1].upper() + name[1:]
            for prefix in ("get", "is", "has"):
                getter = getattr(cls, prefix + cap, None)
                if callable(getter):
                    return getter(self)
        raise Unsupported(f"{cls.java_name()}.{name}")

    def getClass(self):
        return type(self)

    def equals(self, other) -> bool:
        return self == other

    def hashCode(self) -> int:
        return hash(self)

    def toString(self) -> str:
        return str(self)


def unsupported(api: str):
    """A function that raises Unsupported(api) when called."""

    def fail(*_a, **_k):
        raise Unsupported(api)

    fail.__name__ = api.rsplit(".", 1)[-1]
    fail.__qualname__ = api
    return fail


# ---------------------------------------------------------------------------
# Java-style collections
# ---------------------------------------------------------------------------


class JavaIterator(JavaObject):
    """``hasNext()``/``next()`` over a Python iterator, and a Python iterator too."""

    _java_name = "Iterator"

    def __init__(self, items: Iterable):
        self._it = iter(items)
        self._peek: list = []

    def hasNext(self) -> bool:
        if not self._peek:
            try:
                self._peek.append(next(self._it))
            except StopIteration:
                return False
        return True

    def next(self):
        if self._peek:
            return self._peek.pop()
        try:
            return next(self._it)
        except StopIteration:
            raise Unsupported("Iterator.next past the end", "check hasNext() first") from None

    def __iter__(self):
        return self

    def __next__(self):
        if self._peek:
            return self._peek.pop()
        return next(self._it)

    def iterator(self):
        return self


class JavaList(list):
    """A Python list with ``java.util.List``'s common methods."""

    def size(self) -> int:
        return len(self)

    def isEmpty(self) -> bool:
        return not self

    def get(self, i: int):
        return self[i]

    def add(self, item) -> bool:
        self.append(item)
        return True

    def contains(self, item) -> bool:
        return item in self

    def iterator(self):
        return JavaIterator(list(self))

    def toArray(self):
        return list(self)


class ByteArray(list):
    """A Java ``byte[]``: signed values -128..127; ``bytes(b)`` gives the raw bytes."""

    @classmethod
    def of(cls, data: bytes) -> "ByteArray":
        return cls(b - 256 if b > 127 else b for b in data)

    def __bytes__(self) -> bytes:
        return bytes(b & 0xFF for b in self)

    @property
    def length(self) -> int:
        return len(self)


def to_bytes(value) -> bytes:
    """Raw bytes from a ByteArray, bytes, a list of (signed) ints or one int."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, int):
        return bytes([value & 0xFF])
    return bytes(int(b) & 0xFF for b in value)


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------


class AddressSpace(JavaObject):
    _java_name = "AddressSpace"

    def __init__(self, name: str = "ram", size: int = 64, word_size: int = 1, is_default: bool = True,
                 kind: str = "memory"):
        self.name = name
        self.size = size
        self.word_size = word_size
        self.is_default = is_default
        self.kind = kind

    def getName(self) -> str:
        return self.name

    def getSize(self) -> int:
        return self.size

    def getAddressableUnitSize(self) -> int:
        return self.word_size

    def getPointerSize(self) -> int:
        return max(1, self.size // 8)

    def getAddress(self, offset) -> "Address":
        if isinstance(offset, str):
            return Address(int(offset.split(":")[-1], 16), self)
        return Address(int(offset), self)

    def getMinAddress(self) -> "Address":
        return Address(0, self)

    def getMaxAddress(self) -> "Address":
        return Address((1 << self.size) - 1, self)

    def isMemorySpace(self) -> bool:
        return self.kind in ("memory", "overlay")

    def isLoadedMemorySpace(self) -> bool:
        return self.kind in ("memory", "overlay")

    def isStackSpace(self) -> bool:
        return self.kind == "stack"

    def isRegisterSpace(self) -> bool:
        return self.kind == "register"

    def isConstantSpace(self) -> bool:
        return self.kind == "const"

    def isUniqueSpace(self) -> bool:
        return self.kind == "unique"

    def isExternalSpace(self) -> bool:
        return self.kind == "external"

    def isOverlaySpace(self) -> bool:
        return self.kind == "overlay"

    def showSpaceName(self) -> bool:
        return not self.is_default and self.kind != "const"

    def __eq__(self, other):
        return isinstance(other, AddressSpace) and other.name == self.name

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return self.name + ":"

    __repr__ = __str__


RAM = AddressSpace()
_SPACE_KINDS = {"register": "register", "const": "const", "unique": "unique", "stack": "stack"}


def space_named(name: str, default: AddressSpace = RAM) -> AddressSpace:
    if not name or name == default.name:
        return default
    return AddressSpace(name, 64, 1, False, _SPACE_KINDS.get(name, "memory"))


class Address(JavaObject):
    """``ghidra.program.model.address.Address``: an offset in a space. Prints
    as Ghidra does: lowercase hex, at least 8 digits ("00101139")."""

    _java_name = "Address"
    __slots__ = ("offset", "space")

    def __init__(self, offset: int, space: AddressSpace = RAM):
        self.offset = int(offset) & ((1 << 64) - 1)
        self.space = space

    def __getattr__(self, name):
        return JavaObject.__getattr__(self, name)

    # -- reads --
    def getOffset(self) -> int:
        """Signed, as Java's long."""
        return self.offset - (1 << 64) if self.offset >= 1 << 63 else self.offset

    def getUnsignedOffset(self) -> int:
        return self.offset

    def getAddressableWordOffset(self) -> int:
        return self.offset // max(1, self.space.word_size)

    def getAddressSpace(self) -> AddressSpace:
        return self.space

    def getPhysicalAddress(self) -> "Address":
        return self

    def getSize(self) -> int:
        return self.space.size

    def getPointerSize(self) -> int:
        return self.space.getPointerSize()

    def isMemoryAddress(self) -> bool:
        return self.space.isMemorySpace()

    def isLoadedMemoryAddress(self) -> bool:
        return self.space.isLoadedMemorySpace()

    def isStackAddress(self) -> bool:
        return self.space.isStackSpace()

    def isRegisterAddress(self) -> bool:
        return self.space.isRegisterSpace()

    def isConstantAddress(self) -> bool:
        return self.space.isConstantSpace()

    def isUniqueAddress(self) -> bool:
        return self.space.isUniqueSpace()

    def isExternalAddress(self) -> bool:
        return self.space.isExternalSpace()

    def isVariableAddress(self) -> bool:
        return False

    def isNonLoadedMemoryAddress(self) -> bool:
        return False

    # -- arithmetic --
    def add(self, n: int) -> "Address":
        return Address(self.offset + int(n), self.space)

    addNoWrap = add
    addWrap = add

    def subtract(self, other):
        """``Address - long`` is an Address; ``Address - Address`` is a long."""
        if isinstance(other, Address):
            return self.offset - other.offset
        return Address(self.offset - int(other), self.space)

    subtractNoWrap = subtract
    subtractWrap = subtract

    def next(self) -> Optional["Address"]:
        return None if self.offset == (1 << self.space.size) - 1 else Address(self.offset + 1, self.space)

    def previous(self) -> Optional["Address"]:
        return None if self.offset == 0 else Address(self.offset - 1, self.space)

    def isSuccessor(self, other: "Address") -> bool:
        return other.offset == self.offset + 1

    def compareTo(self, other: "Address") -> int:
        return (self.offset > other.offset) - (self.offset < other.offset)

    def hasSameAddressSpace(self, other: "Address") -> bool:
        return self.space == other.space

    def getNewAddress(self, offset: int) -> "Address":
        return Address(offset, self.space)

    # -- text --
    def toString(self, arg=None, pad=None) -> str:
        if isinstance(arg, str):
            return arg + self._digits(8)
        show = self.space.showSpaceName() if arg is None else bool(arg)
        digits = 16 if pad is True else (int(pad) if isinstance(pad, int) and not isinstance(pad, bool) else 8)
        if self.space.isStackSpace():
            return f"Stack[{'-' if self.getOffset() < 0 else ''}0x{abs(self.getOffset()):x}]"
        return (self.space.name + ":" if show else "") + self._digits(digits)

    def _digits(self, minimum: int) -> str:
        width = min(minimum, (self.space.size - 1) // 4 + 1)
        return f"{self.offset:0{width}x}"

    def __str__(self):
        return self.toString()

    def __repr__(self):
        return f"Address({self})"

    def __format__(self, spec):
        return format(str(self), spec)

    # -- Python --
    def __eq__(self, other):
        return isinstance(other, Address) and other.offset == self.offset and other.space == self.space

    def __hash__(self):
        return hash((self.offset, self.space.name))

    def __lt__(self, other):
        return self.offset < other.offset

    def __le__(self, other):
        return self.offset <= other.offset

    def __gt__(self, other):
        return self.offset > other.offset

    def __ge__(self, other):
        return self.offset >= other.offset

    def __int__(self):
        return self.offset

    __index__ = __int__


def addr_int(a) -> int:
    """An int offset from an Address, an int, or something with an Address."""
    if isinstance(a, Address):
        return a.offset
    if isinstance(a, int):
        return a
    for getter in ("getEntryPoint", "getMinAddress", "getAddress"):
        f = getattr(type(a), getter, None)
        if f is not None:
            return f(a).offset
    raise TypeError(f"not an address: {a!r}")


class AddressRange(JavaObject):
    _java_name = "AddressRange"

    def __init__(self, first: Address, last: Address):
        self.first = first
        self.last = last

    def getMinAddress(self) -> Address:
        return self.first

    def getMaxAddress(self) -> Address:
        return self.last

    def getLength(self) -> int:
        return self.last.offset - self.first.offset + 1

    def getAddressSpace(self) -> AddressSpace:
        return self.first.space

    def contains(self, a: Address) -> bool:
        return self.first.offset <= addr_int(a) <= self.last.offset

    def intersects(self, other) -> bool:
        return not (other.getMaxAddress().offset < self.first.offset or other.getMinAddress().offset > self.last.offset)

    def __iter__(self):
        return (Address(o, self.first.space) for o in range(self.first.offset, self.last.offset + 1))

    def __eq__(self, other):
        return isinstance(other, AddressRange) and (self.first, self.last) == (other.first, other.last)

    def __hash__(self):
        return hash((self.first, self.last))

    def __str__(self):
        return f"[{self.first}, {self.last}]"


class AddressSetView(JavaObject):
    """A sorted set of disjoint inclusive ranges (``AddressSet``)."""

    _java_name = "AddressSetView"

    def __init__(self, ranges: Iterable[tuple] = (), space: AddressSpace = RAM):
        self.space = space
        self._r: list = []  # [(lo, hi)] sorted, disjoint, non-adjacent
        for lo, hi in ranges:
            self._add(int(lo), int(hi))

    # -- internals --
    def _add(self, lo: int, hi: int) -> None:
        if hi < lo:
            lo, hi = hi, lo
        out, i = [], 0
        r = self._r
        while i < len(r) and r[i][1] < lo - 1:
            out.append(r[i])
            i += 1
        while i < len(r) and r[i][0] <= hi + 1:
            lo, hi = min(lo, r[i][0]), max(hi, r[i][1])
            i += 1
        out.append((lo, hi))
        out.extend(r[i:])
        self._r = out

    def _delete(self, lo: int, hi: int) -> None:
        out = []
        for a, b in self._r:
            if b < lo or a > hi:
                out.append((a, b))
                continue
            if a < lo:
                out.append((a, lo - 1))
            if b > hi:
                out.append((hi + 1, b))
        self._r = out

    def _addr(self, o: int) -> Address:
        return Address(o, self.space)

    @staticmethod
    def _ranges_of(x) -> list:
        if isinstance(x, AddressSetView):
            return list(x._r)
        if isinstance(x, AddressRange):
            return [(x.first.offset, x.last.offset)]
        if isinstance(x, Address):
            return [(x.offset, x.offset)]
        if isinstance(x, (tuple, list)) and len(x) == 2:
            return [(addr_int(x[0]), addr_int(x[1]))]
        body = getattr(type(x), "getBody", None)
        if body is not None:
            return list(body(x)._r)
        raise TypeError(f"not an address set: {x!r}")

    # -- reads --
    def isEmpty(self) -> bool:
        return not self._r

    def getMinAddress(self) -> Optional[Address]:
        return self._addr(self._r[0][0]) if self._r else None

    def getMaxAddress(self) -> Optional[Address]:
        return self._addr(self._r[-1][1]) if self._r else None

    def getNumAddresses(self) -> int:
        return sum(b - a + 1 for a, b in self._r)

    def getNumAddressRanges(self) -> int:
        return len(self._r)

    def contains(self, a, b=None) -> bool:
        if b is not None:
            lo, hi = addr_int(a), addr_int(b)
            return any(x <= lo and hi <= y for x, y in self._r)
        if isinstance(a, (AddressSetView, AddressRange)):
            return all(self.contains(self._addr(lo), self._addr(hi)) for lo, hi in self._ranges_of(a))
        o = addr_int(a)
        i = bisect.bisect_right(self._r, (o, float("inf"))) - 1
        return i >= 0 and self._r[i][0] <= o <= self._r[i][1]

    def intersects(self, a, b=None) -> bool:
        other = [(addr_int(a), addr_int(b))] if b is not None else self._ranges_of(a)
        return any(not (y < lo or x > hi) for x, y in self._r for lo, hi in other)

    def getAddressRanges(self, arg=True):
        forward = arg if isinstance(arg, bool) else True
        rs = [AddressRange(self._addr(a), self._addr(b)) for a, b in self._r]
        if not isinstance(arg, bool) and arg is not None:
            start = addr_int(arg)
            rs = [r for r in rs if r.last.offset >= start]
        return JavaIterator(rs if forward else reversed(rs))

    def iterator(self, forward: bool = True):
        return self.getAddressRanges(forward)

    def getFirstRange(self) -> Optional[AddressRange]:
        return AddressRange(self._addr(self._r[0][0]), self._addr(self._r[0][1])) if self._r else None

    def getLastRange(self) -> Optional[AddressRange]:
        return AddressRange(self._addr(self._r[-1][0]), self._addr(self._r[-1][1])) if self._r else None

    def getRangeContaining(self, a) -> Optional[AddressRange]:
        o = addr_int(a)
        for lo, hi in self._r:
            if lo <= o <= hi:
                return AddressRange(self._addr(lo), self._addr(hi))
        return None

    def getAddresses(self, arg=True, forward: Optional[bool] = None):
        """Every address, low to high (or high to low), optionally from a start."""
        start = None
        if isinstance(arg, bool):
            fwd = arg
        else:
            start, fwd = addr_int(arg), (True if forward is None else forward)

        def gen():
            rs = self._r if fwd else list(reversed(self._r))
            for lo, hi in rs:
                if fwd:
                    for o in range(lo if start is None else max(lo, start), hi + 1):
                        yield self._addr(o)
                else:
                    for o in range(hi if start is None else min(hi, start), lo - 1, -1):
                        yield self._addr(o)

        return JavaIterator(gen())

    def __iter__(self):
        return iter(self.getAddressRanges(True))

    def __contains__(self, a) -> bool:
        return self.contains(a)

    def __len__(self):
        return len(self._r)

    def __bool__(self):
        return True

    def hasSameAddresses(self, other) -> bool:
        return self._r == self._ranges_of(other)

    def intersect(self, other) -> "AddressSet":
        out = AddressSet(space=self.space)
        for a, b in self._r:
            for c, d in self._ranges_of(other):
                lo, hi = max(a, c), min(b, d)
                if lo <= hi:
                    out._add(lo, hi)
        return out

    def intersectRange(self, a, b) -> "AddressSet":
        return self.intersect(AddressSet(a, b))

    def union(self, other) -> "AddressSet":
        out = AddressSet(self, space=self.space)
        for lo, hi in self._ranges_of(other):
            out._add(lo, hi)
        return out

    def subtract(self, other) -> "AddressSet":
        out = AddressSet(self, space=self.space)
        for lo, hi in self._ranges_of(other):
            out._delete(lo, hi)
        return out

    def xor(self, other) -> "AddressSet":
        return self.union(other).subtract(self.intersect(other))

    def findFirstAddressInCommon(self, other) -> Optional[Address]:
        common = self.intersect(other)
        return common.getMinAddress()

    def __eq__(self, other):
        return isinstance(other, AddressSetView) and self._r == other._r

    def __hash__(self):
        return hash(tuple(self._r))

    def __str__(self):
        return "[" + ", ".join(f"[{self._addr(a)}, {self._addr(b)}]" for a, b in self._r) + "]"

    __repr__ = __str__


class AddressSet(AddressSetView):
    """``new AddressSet()``, ``AddressSet(addr)``, ``AddressSet(start, end)``,
    ``AddressSet(set)``, ``AddressSet(range)``."""

    _java_name = "AddressSet"

    def __init__(self, *args, space: AddressSpace = RAM):
        super().__init__((), space)
        if len(args) == 1 and args[0] is not None and not hasattr(args[0], "getFunctionManager"):
            for lo, hi in self._ranges_of(args[0]):
                self._add(lo, hi)
        elif len(args) == 2:
            a, b = args
            if hasattr(a, "getFunctionManager"):  # AddressSet(program, start, end) style
                a, b = b, b
            self._add(addr_int(a), addr_int(b))
        elif len(args) == 3:
            self._add(addr_int(args[1]), addr_int(args[2]))

    def add(self, a, b=None) -> "AddressSet":
        if b is not None:
            self._add(addr_int(a), addr_int(b))
        else:
            for lo, hi in self._ranges_of(a):
                self._add(lo, hi)
        return self

    addRange = add

    def delete(self, a, b=None) -> "AddressSet":
        if b is not None:
            self._delete(addr_int(a), addr_int(b))
        else:
            for lo, hi in self._ranges_of(a):
                self._delete(lo, hi)
        return self

    deleteRange = delete

    def clear(self) -> None:
        self._r = []


# ---------------------------------------------------------------------------
# Enums scripts compare against
# ---------------------------------------------------------------------------


class _Enum(JavaObject):
    _members: dict = {}

    def __init__(self, name: str, *extra):
        self._name = name
        self._extra = extra

    def name(self) -> str:
        return self._name

    def ordinal(self) -> int:
        return list(type(self)._members).index(self._name)

    def __str__(self):
        return self._name

    __repr__ = __str__

    def __eq__(self, other):
        return type(other) is type(self) and other._name == self._name

    def __hash__(self):
        return hash((type(self).__name__, self._name))

    @classmethod
    def values(cls) -> list:
        return list(cls._members.values())

    @classmethod
    def valueOf(cls, name: str):
        return cls._members[name]


def _enum(cls, names):
    cls._members = {}
    for n in names:
        m = cls(n) if isinstance(n, str) else cls(*n)
        cls._members[m._name] = m
        setattr(cls, m._name, m)
    return cls


class SourceType(_Enum):
    """``ghidra.program.model.symbol.SourceType`` (priority as Ghidra's)."""

    _PRIORITY = {"DEFAULT": 1, "ANALYSIS": 2, "AI": 2, "IMPORTED": 3, "USER_DEFINED": 4}
    _DISPLAY = {"DEFAULT": "Default", "ANALYSIS": "Analysis", "AI": "AI", "IMPORTED": "Imported",
                "USER_DEFINED": "User Defined"}

    def getPriority(self) -> int:
        return self._PRIORITY[self._name]

    def getDisplayString(self) -> str:
        return self._DISPLAY[self._name]

    def isHigherPriorityThan(self, o) -> bool:
        return self.getPriority() > o.getPriority()

    def isLowerPriorityThan(self, o) -> bool:
        return self.getPriority() < o.getPriority()

    def isHigherOrEqualPriorityThan(self, o) -> bool:
        return self.getPriority() >= o.getPriority()

    def isLowerOrEqualPriorityThan(self, o) -> bool:
        return self.getPriority() <= o.getPriority()


_enum(SourceType, ["DEFAULT", "ANALYSIS", "AI", "IMPORTED", "USER_DEFINED"])


class SymbolType(_Enum):
    def isNamespace(self) -> bool:
        return self._name in ("NAMESPACE", "CLASS", "LIBRARY")


_enum(SymbolType, ["LABEL", "LIBRARY", "NAMESPACE", "CLASS", "FUNCTION", "PARAMETER", "LOCAL_VAR", "GLOBAL_VAR",
                   "GLOBAL"])
SymbolType.CODE = SymbolType.LABEL


class CommentType(_Enum):
    """``ghidra.program.model.listing.CommentType`` (Ghidra 11.4+); the int
    constants of ``CodeUnit`` (EOL_COMMENT = 0, ...) mean the same."""


_enum(CommentType, ["EOL", "PRE", "POST", "PLATE", "REPEATABLE"])
COMMENT_KINDS = {"EOL": "eol", "PRE": "pre", "POST": "post", "PLATE": "plate", "REPEATABLE": "repeatable"}
_COMMENT_BY_INT = ["EOL", "PRE", "POST", "PLATE", "REPEATABLE"]


def comment_kind(t) -> str:
    """revkit's comment kind ("eol") from a CommentType or CodeUnit's int."""
    if isinstance(t, CommentType):
        return COMMENT_KINDS[t._name]
    if isinstance(t, int) and 0 <= t < 5:
        return COMMENT_KINDS[_COMMENT_BY_INT[t]]
    if isinstance(t, str) and t.upper() in COMMENT_KINDS:
        return COMMENT_KINDS[t.upper()]
    raise ValueError(f"not a comment type: {t!r}")


class RefType(_Enum):
    """``RefType``/``FlowType``: what a reference or an instruction's flow is."""

    _java_name = "RefType"

    def __init__(self, name, *flags):
        super().__init__(name)
        self._flags = set(flags)

    def _is(self, f):
        return f in self._flags

    def isCall(self):
        return self._is("call")

    def isJump(self):
        return self._is("jump")

    def isFlow(self):
        return self._is("flow")

    def isData(self):
        return self._is("data")

    def isRead(self):
        return self._is("read")

    def isWrite(self):
        return self._is("write")

    def isIndirect(self):
        return self._is("indirect")

    def isComputed(self):
        return self._is("computed")

    def isConditional(self):
        return self._is("conditional")

    def isUnConditional(self):
        return self.isFlow() and not self.isConditional()

    def isTerminal(self):
        return self._is("terminal")

    def isFallthrough(self):
        return self._is("fallthrough")

    def hasFallthrough(self):
        return self._is("fallthrough") or (self.isCall() and not self.isTerminal()) or self.isConditional()

    def isOverride(self):
        return False

    def isStackReference(self):
        return False

    def getName(self):
        return self._name

    def getDisplayString(self):
        return self._name


_enum(RefType, [
    ("INVALID",), ("FLOW", "flow"), ("FALL_THROUGH", "flow", "fallthrough"),
    ("UNCONDITIONAL_JUMP", "flow", "jump"), ("CONDITIONAL_JUMP", "flow", "jump", "conditional"),
    ("UNCONDITIONAL_CALL", "flow", "call"), ("CONDITIONAL_CALL", "flow", "call", "conditional"),
    ("TERMINATOR", "flow", "terminal"), ("COMPUTED_JUMP", "flow", "jump", "computed"),
    ("CONDITIONAL_TERMINATOR", "flow", "terminal", "conditional"), ("COMPUTED_CALL", "flow", "call", "computed"),
    ("CALL_TERMINATOR", "flow", "call", "terminal"), ("COMPUTED_CALL_TERMINATOR", "flow", "call", "computed", "terminal"),
    ("CONDITIONAL_CALL_TERMINATOR", "flow", "call", "terminal", "conditional"),
    ("CONDITIONAL_COMPUTED_CALL", "flow", "call", "computed", "conditional"),
    ("CONDITIONAL_COMPUTED_JUMP", "flow", "jump", "computed", "conditional"),
    ("JUMP_TERMINATOR", "flow", "jump", "terminal"), ("INDIRECTION", "flow", "indirect"),
    ("THUNK", "flow", "call"), ("DATA", "data"), ("PARAM", "data"), ("DATA_IND", "data", "indirect"),
    ("READ", "data", "read"), ("WRITE", "data", "write"), ("READ_WRITE", "data", "read", "write"),
    ("READ_IND", "data", "read", "indirect"), ("WRITE_IND", "data", "write", "indirect"),
    ("READ_WRITE_IND", "data", "read", "write", "indirect"), ("EXTERNAL_REF", "data"),
])
FlowType = RefType


class OperandType(JavaObject):
    """``ghidra.program.model.lang.OperandType`` bit flags."""

    READ = 0x1
    WRITE = 0x2
    INDIRECT = 0x4
    IMMEDIATE = 0x8
    RELATIVE = 0x10
    IMPLICIT = 0x20
    CODE = 0x40
    DATA = 0x80
    PORT = 0x100
    REGISTER = 0x200
    LIST = 0x400
    FLAG = 0x800
    TEXT = 0x1000
    ADDRESS = 0x2000
    SCALAR = 0x4000
    BIT = 0x8000
    BYTE = 0x10000
    WORD = 0x20000
    QUADWORD = 0x40000
    SIGNED = 0x80000
    FLOAT = 0x100000
    COP = 0x200000
    DYNAMIC = 0x400000

    @staticmethod
    def isRegister(t):
        return bool(t & OperandType.REGISTER)

    @staticmethod
    def isScalar(t):
        return bool(t & OperandType.SCALAR)

    @staticmethod
    def isAddress(t):
        return bool(t & OperandType.ADDRESS)

    @staticmethod
    def isDynamic(t):
        return bool(t & OperandType.DYNAMIC)

    @staticmethod
    def isIndirect(t):
        return bool(t & OperandType.INDIRECT)

    @staticmethod
    def isCodeReference(t):
        return bool(t & OperandType.CODE)

    @staticmethod
    def isDataReference(t):
        return bool(t & OperandType.DATA)

    @staticmethod
    def isImmediate(t):
        return bool(t & OperandType.IMMEDIATE)


# ---------------------------------------------------------------------------
# Operand objects
# ---------------------------------------------------------------------------


class Register(JavaObject):
    """A register by name (from the disassembler's tokens and varnodes)."""

    _java_name = "Register"

    def __init__(self, name: str, size: int = 0, offset: Optional[int] = None):
        self.name = name
        self.size = size
        self.offset = offset

    def getName(self) -> str:
        return self.name

    def getBitLength(self) -> int:
        return self.size * 8

    def getMinimumByteSize(self) -> int:
        return self.size

    def getNumBytes(self) -> int:
        return self.size

    def getOffset(self) -> int:
        if self.offset is None:
            raise Unsupported("Register.getOffset", "register offsets are in varnodes (Varnode.offset)")
        return self.offset

    def getBaseRegister(self) -> "Register":
        return Register(_BASE.get(self.name.upper(), self.name), 0)

    def getAddress(self) -> Address:
        return Address(self.getOffset(), space_named("register"))

    def isProgramCounter(self) -> bool:
        return self.name.upper() in ("RIP", "EIP", "PC", "IP")

    def __eq__(self, other):
        return isinstance(other, Register) and other.name.upper() == self.name.upper()

    def __hash__(self):
        return hash(self.name.upper())

    def __str__(self):
        return self.name


def _x86_bases() -> dict:
    out = {}
    for r in ("AX", "BX", "CX", "DX", "SI", "DI", "SP", "BP"):
        base = "R" + r
        for alias in ("E" + r, r):
            out[alias] = base
        out[base] = base
    for low, base in (("AL", "RAX"), ("AH", "RAX"), ("BL", "RBX"), ("BH", "RBX"), ("CL", "RCX"), ("CH", "RCX"),
                      ("DL", "RDX"), ("DH", "RDX"), ("SIL", "RSI"), ("DIL", "RDI"), ("SPL", "RSP"), ("BPL", "RBP")):
        out[low] = base
    for n in range(8, 16):
        for suffix in ("", "D", "W", "B"):
            out[f"R{n}{suffix}"] = f"R{n}"
    return out


_BASE = _x86_bases()


class Scalar(JavaObject):
    """``ghidra.program.model.scalar.Scalar``."""

    _java_name = "Scalar"

    def __init__(self, bits: int, value: int, signed: bool = True):
        self.bits = bits or 64
        mask = (1 << self.bits) - 1
        self.raw = int(value) & mask
        self.signed = signed

    def getValue(self) -> int:
        return self.getSignedValue() if self.signed else self.raw

    def getUnsignedValue(self) -> int:
        return self.raw

    def getSignedValue(self) -> int:
        return self.raw - (1 << self.bits) if self.raw >> (self.bits - 1) else self.raw

    def bitLength(self) -> int:
        return self.bits

    def isSigned(self) -> bool:
        return self.signed

    def toString(self, radix: int = 16, zero_pad: bool = False, show_sign: bool = True, prefix: str = "0x",
                 suffix: str = "") -> str:
        v = self.getSignedValue() if (show_sign and self.signed) else self.raw
        neg = v < 0
        v = abs(v)
        digits = {16: f"{v:x}", 10: f"{v:d}", 8: f"{v:o}", 2: f"{v:b}"}.get(radix, f"{v:x}")
        if zero_pad:
            width = {16: (self.bits + 3) // 4, 8: (self.bits + 2) // 3, 2: self.bits}.get(radix, 0)
            digits = digits.rjust(width, "0")
        return ("-" if neg else "") + prefix + digits + suffix

    def __str__(self):
        return self.toString(16, False, True, "0x", "")

    def __eq__(self, other):
        return isinstance(other, Scalar) and other.raw == self.raw and other.bits == self.bits

    def __hash__(self):
        return hash((self.raw, self.bits))

    def __int__(self):
        return self.getValue()

    __index__ = __int__


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


class DataType(JavaObject):
    """A Ghidra data type as revkit spells it: a C declaration (or a builtin
    listing name such as "dword", or a program type's hash)."""

    _java_name = "DataType"
    _builtin: dict = {}

    def __init__(self, name: str = "", c: str = "", length: int = -1, *, mnemonic: str = "", type_hash: str = "",
                 category: str = "/", string: str = "", base: Optional["DataType"] = None, kind: str = ""):
        self.name = name
        self.c = c or name
        self.length = length
        self.mnemonic = mnemonic or name
        self.type_hash = type_hash
        self.category = category
        self.string = string  # utf8 / utf16 / utf32 for string types
        self.base = base
        self.kind = kind

    @classmethod
    def builtin(cls, name: str) -> Optional["DataType"]:
        return cls._builtin.get(name)

    def getName(self) -> str:
        return self.name

    def getDisplayName(self) -> str:
        return self.name

    def getPathName(self) -> str:
        return self.category.rstrip("/") + "/" + self.name

    def getCategoryPath(self):
        return CategoryPath(self.category)

    def getLength(self) -> int:
        return self.length

    def getAlignedLength(self) -> int:
        return self.length

    def getMnemonic(self, settings=None) -> str:
        return self.mnemonic

    def getDescription(self) -> str:
        return self.c

    def isZeroLength(self) -> bool:
        return self.length == 0

    def hasLanguageDependantLength(self) -> bool:
        return self.length < 0

    def getDataTypeManager(self):
        return None

    def isEquivalent(self, other) -> bool:
        return isinstance(other, DataType) and other.c == self.c

    def clone(self, dtm=None) -> "DataType":
        return self

    copy = clone

    # Type-family helpers several scripts use instead of instanceof.
    def isPointer(self) -> bool:
        return self.kind == "pointer"

    def __eq__(self, other):
        return isinstance(other, DataType) and (other.c, other.type_hash) == (self.c, self.type_hash)

    def __hash__(self):
        return hash((self.c, self.type_hash))

    def __str__(self):
        return self.name

    __repr__ = __str__


class CategoryPath(JavaObject):
    ROOT = None

    def __init__(self, path: str = "/"):
        self.path = path or "/"

    def getPath(self) -> str:
        return self.path

    def getName(self) -> str:
        return self.path.rstrip("/").rsplit("/", 1)[-1]

    def isRoot(self) -> bool:
        return self.path == "/"

    def __str__(self):
        return self.path

    def __eq__(self, other):
        return isinstance(other, CategoryPath) and other.path == self.path

    def __hash__(self):
        return hash(self.path)


CategoryPath.ROOT = CategoryPath("/")


# The builtin data type classes (IntegerDataType, StringDataType, ...): each
# is a DataType subclass whose instances are that builtin, with the static
# ``dataType`` instance Ghidra has. Filled by _builtin_types().
BUILTIN_CLASSES: dict = {}


def _builtin_types() -> dict:
    """Ghidra's builtin data types (their root-category names), each with the
    C type (or listing builtin) revkit takes for it."""
    t = {}

    def add(name, c, length, mnemonic="", kind="", string="", cls_name=""):
        fields = dict(name=name, c=c, length=length, mnemonic=mnemonic or name, kind=kind, string=string)

        def init(self, *_dtm, _f=fields):
            DataType.__init__(self, _f["name"], _f["c"], _f["length"], mnemonic=_f["mnemonic"], kind=_f["kind"],
                              string=_f["string"])

        cls = type(cls_name or (name.capitalize() + "DataType"), (DataType,), {"__init__": init})
        cls._java_name = cls.__name__
        dt = cls()
        cls.dataType = dt
        t[name] = dt
        if cls_name:
            BUILTIN_CLASSES[cls_name] = cls

    add("undefined", "undefined", 1, "undefined", cls_name="Undefined1DataType")
    for n in (2, 4, 8):
        add(f"undefined{n}", f"undefined{n}", n, cls_name=f"Undefined{n}DataType")
    t["undefined1"] = t["undefined"]
    add("byte", "byte", 1, "db", cls_name="ByteDataType")
    add("sbyte", "sbyte", 1, "sdb", cls_name="SignedByteDataType")
    add("word", "word", 2, "dw", cls_name="WordDataType")
    add("sword", "sword", 2, "sdw", cls_name="SignedWordDataType")
    add("dword", "dword", 4, "ddw", cls_name="DWordDataType")
    add("sdword", "sdword", 4, "sddw", cls_name="SignedDWordDataType")
    add("qword", "qword", 8, "dq", cls_name="QWordDataType")
    add("sqword", "sqword", 8, "sdq", cls_name="SignedQWordDataType")
    add("char", "char", 1, cls_name="CharDataType")
    add("uchar", "unsigned char", 1, cls_name="UnsignedCharDataType")
    add("short", "short", 2, cls_name="ShortDataType")
    add("ushort", "unsigned short", 2, cls_name="UnsignedShortDataType")
    add("int", "int", 4, cls_name="IntegerDataType")
    add("uint", "unsigned int", 4, cls_name="UnsignedIntegerDataType")
    add("long", "long", 8, cls_name="LongDataType")
    add("ulong", "unsigned long", 8, cls_name="UnsignedLongDataType")
    add("longlong", "long long", 8, cls_name="LongLongDataType")
    add("ulonglong", "unsigned long long", 8, cls_name="UnsignedLongLongDataType")
    add("bool", "bool", 1, cls_name="BooleanDataType")
    add("float", "float", 4, cls_name="FloatDataType")
    add("double", "double", 8, cls_name="DoubleDataType")
    add("longdouble", "long double", 16, cls_name="LongDoubleDataType")
    add("wchar_t", "wchar_t", 4, cls_name="WideCharDataType")
    add("void", "void", 0, cls_name="VoidDataType")
    add("string", "", -1, "ds", kind="string", string="utf8", cls_name="StringDataType")
    add("TerminatedCString", "", -1, "ds", kind="string", string="utf8", cls_name="TerminatedStringDataType")
    add("unicode", "", -1, "unicode", kind="string", string="utf16", cls_name="UnicodeDataType")
    add("TerminatedUnicode", "", -1, "unicode", kind="string", string="utf16",
        cls_name="TerminatedUnicodeDataType")
    add("unicode32", "", -1, "unicode32", kind="string", string="utf32", cls_name="Unicode32DataType")
    add("PascalString", "", -1, "p_string", kind="string", string="utf8", cls_name="PascalStringDataType")
    t["pointer"] = PointerDataType()
    PointerDataType.dataType = t["pointer"]
    BUILTIN_CLASSES["PointerDataType"] = PointerDataType
    BUILTIN_CLASSES["ArrayDataType"] = ArrayDataType
    return t


class PointerDataType(DataType):
    """``new PointerDataType()`` (void *) or ``PointerDataType(target[, length])``."""

    _java_name = "PointerDataType"

    def __init__(self, target: Optional[DataType] = None, length: int = -1, *_dtm):
        if isinstance(length, (int,)) is False:
            length = -1
        if target is None or getattr(target, "name", "") == "void":
            super().__init__("pointer", "void *", length, mnemonic="addr", kind="pointer")
        else:
            super().__init__(target.name + " *", target.c + " *", length, mnemonic="addr", kind="pointer",
                             base=target)

    def getDataType(self) -> Optional[DataType]:
        return self.base


class ArrayDataType(DataType):
    """``new ArrayDataType(element, count, elementLength)``."""

    _java_name = "ArrayDataType"

    def __init__(self, element: DataType, count: int, element_length: int = -1, *_dtm):
        length = element.length * count if element.length > 0 else -1
        super().__init__(f"{element.name}[{count}]", element.c, length, kind="array", base=element)
        self.count = int(count)

    def getNumElements(self) -> int:
        return self.count

    def getDataType(self) -> DataType:
        return self.base

    def getElementLength(self) -> int:
        return self.base.length


DataType._builtin = _builtin_types()


def pointer_to(target: Optional[DataType], length: int = -1) -> DataType:
    return PointerDataType(target, length)


def array_of(element: DataType, count: int, element_length: int = -1) -> DataType:
    return ArrayDataType(element, count, element_length)
