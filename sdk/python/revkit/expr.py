"""Go To expressions (Ghidra's address expressions), as the UI's palette reads
them (ui/src/data/expr.ts): ``main+0x10``, ``0x1000 + 4*3``, ``(sym - 8) / 2``,
a file offset ``file:0x200``, a space's address ``mem:0x100``.

Numbers are hex, as Ghidra's and as the listing shows addresses (``10`` is
0x10; ``0x`` and an ``h`` suffix are optional). Names are looked up through a
resolver, so this module talks to no daemon; ``Program.resolve`` evaluates
an expression against a program (names exactly as ``ListSymbols`` matches
them, demangled or mangled). A name that is also hex (``add``, ``face``) is
the symbol when there is one, else the number.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional, Union

__all__ = ["ExprError", "Resolver", "parse_expr", "evaluate", "evaluate_text", "is_number", "parse_number"]


class ExprError(ValueError):
    """An expression that doesn't parse or evaluate; ``at`` is the character offset where it went wrong."""

    def __init__(self, message: str, at: int = 0):
        super().__init__(message)
        self.at = at


@dataclass
class Resolver:
    """Looks names up for :func:`evaluate`: each returns an address or None."""

    symbol: Callable[[str], Optional[int]]
    file_offset: Callable[[int], Optional[int]] = lambda _offset: None
    is_space: Callable[[str], bool] = lambda _name: False
    space_address: Callable[[str, int], Optional[int]] = lambda _name, _offset: None


_NAME_START = re.compile(r"[A-Za-z_.$@?]")
_NAME_PART = re.compile(r"[A-Za-z0-9_.$@?]")
_HEX = re.compile(r"^(0x)?[0-9a-f]+$", re.I)
_NUMBER = re.compile(r"^(0x[0-9a-f]+|[0-9][0-9a-f]*h?)$", re.I)
_MASK = (1 << 64) - 1


def is_number(text: str) -> bool:
    """A plain address: hex digits starting with a digit, or 0x-prefixed (``401040``, ``0x401040``, ``1000h``)."""
    return bool(_NUMBER.match(text.strip()))


def parse_number(text: str, at: int = 0) -> int:
    h = text.strip()
    if h[-1:] in "hH" and not h.lower().startswith("0x"):
        h = h[:-1]
    if h.lower().startswith("0x"):
        h = h[2:]
    if not re.fullmatch(r"[0-9a-fA-F]{1,16}", h):
        raise ExprError(f"not a number: {text}", at)
    return int(h, 16)


def _tokenize(text: str) -> list:
    out, i = [], 0
    while i < len(text):
        c = text[i]
        if c.isspace():
            i += 1
        elif c in "+-*/()":
            out.append(("op", c, i))
            i += 1
        elif c == ":":
            out.append(("colon", c, i))
            i += 1
        elif _NAME_PART.match(c):
            at = i
            # A name may hold C++'s "::" (ns::f); a single ':' ends it (file:, mem:).
            while i < len(text) and (_NAME_PART.match(text[i]) or (
                    text[i] == ":" and text[i + 1:i + 2] == ":" and i + 2 < len(text) and _NAME_PART.match(text[i + 2]))):
                i += 2 if text[i] == ":" else 1
            s = text[at:i]
            num = s[0].isdigit() and _HEX.match(re.sub(r"h$", "", s, flags=re.I))
            out.append(("num" if num else "id", s, at))
        else:
            raise ExprError(f'unexpected "{c}"', i)
    return out


def parse_expr(text: str, is_space: Callable[[str], bool] = lambda _n: False):
    """Parses an expression into a tuple tree; raises ExprError."""
    toks = _tokenize(text)
    if not toks:
        raise ExprError("empty", 0)
    p = 0

    def peek():
        return toks[p] if p < len(toks) else None

    def end():
        t = toks[-1]
        return t[2] + len(t[1])

    def total():
        nonlocal p
        a = product()
        while (t := peek()) and t[0] == "op" and t[1] in "+-":
            p += 1
            a = ("bin", t[1], a, product())
        return a

    def product():
        nonlocal p
        a = unary()
        while (t := peek()) and t[0] == "op" and t[1] in "*/":
            p += 1
            a = ("bin", t[1], a, unary())
        return a

    def unary():
        nonlocal p
        t = peek()
        if t and t[0] == "op" and t[1] == "-":
            p += 1
            return ("neg", unary())
        if t and t[0] == "op" and t[1] == "+":
            p += 1
            return unary()
        return primary()

    def primary():
        nonlocal p
        t = peek()
        if t is None:
            raise ExprError("expected a number or a name", end())
        kind, s, at = t
        if kind == "op" and s == "(":
            p += 1
            e = total()
            if not (peek() and peek()[1] == ")"):
                raise ExprError('expected ")"', peek()[2] if peek() else end())
            p += 1
            return e
        # file:<offset>, <space>:<offset>
        if kind in ("id", "num") and p + 1 < len(toks) and toks[p + 1][0] == "colon":
            if s.lower() == "file":
                p += 2
                return ("file", unary())
            if is_space(s):
                p += 2
                return ("space", s, unary())
            raise ExprError(f'no address space "{s}"', at)
        if kind == "num":
            p += 1
            return ("num", parse_number(s, at))
        if kind == "id":
            p += 1
            if not _NAME_START.match(s[0]):
                raise ExprError(f"not a number or a name: {s}", at)
            return ("sym", s, int(s, 16) if re.fullmatch(r"[a-fA-F]{1,16}", s) else None)
        raise ExprError(f'unexpected "{s}"', at)

    e = total()
    if p < len(toks):
        raise ExprError(f'unexpected "{toks[p][1]}"', toks[p][2])
    return e


def evaluate(e, r: Resolver) -> int:
    """A parsed expression's value (64-bit); raises ExprError for unknown names and bad arithmetic."""
    k = e[0]
    if k == "num":
        return e[1]
    if k == "sym":
        a = r.symbol(e[1])
        if a is not None:
            return a
        if e[2] is not None:
            return e[2]
        raise ExprError(f'no symbol "{e[1]}"')
    if k == "file":
        off = evaluate(e[1], r)
        a = r.file_offset(off)
        if a is None:
            raise ExprError(f"file offset 0x{off:x} isn't loaded")
        return a
    if k == "space":
        off = evaluate(e[2], r)
        a = r.space_address(e[1], off)
        if a is None:
            raise ExprError(f"no address {e[1]}:{off:x}")
        return a
    if k == "neg":
        return -evaluate(e[1], r) & _MASK
    a, b = evaluate(e[2], r), evaluate(e[3], r)
    if e[1] == "+":
        return (a + b) & _MASK
    if e[1] == "-":
        return (a - b) & _MASK
    if e[1] == "*":
        return (a * b) & _MASK
    if b == 0:
        raise ExprError("division by zero")
    return a // b


def evaluate_text(text: Union[str, int], r: Resolver) -> int:
    """Parses and evaluates (an int is its own value)."""
    if isinstance(text, int):
        return text
    return evaluate(parse_expr(text, r.is_space), r)
