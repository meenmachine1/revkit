"""Ready-made hook handlers for DebugSession.hook_function and the like
(docs/debugger.md "Hooks"): constants, sequences, a call log, and a few C
library stand-ins written over the emulated program's memory.

    from revkit import hooklib
    dbg.hook_function("rand", hooklib.sequence([4, 2, 7]))
    dbg.hook_function("time", hooklib.returns(1700000000))
    calls = []
    dbg.hook_function("check_license", hooklib.record(calls, returns=1))
    out = []
    dbg.hook_function("printf", hooklib.printf(out))

The emulator's own stubs already cover what a small C program imports
(docs/emulator.md "Hooks"); these replace or add to them per call.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable, List, Optional

__all__ = ["returns", "sequence", "record", "skip", "printf", "strlen", "memset"]


def returns(value: int) -> Callable:
    """Every call returns ``value`` (the function doesn't run)."""
    return lambda hook: value


def sequence(values: Iterable[int], then: Optional[int] = None) -> Callable:
    """Successive calls return the values in turn, then ``then`` (None: the
    function runs)."""
    it = iter(values)

    def handler(hook):
        return next(it, then)
    return handler


def record(log: List, returns: Optional[int] = None, args: int = 4) -> Callable:
    """Appends each call's first ``args`` arguments to ``log``; returns
    ``returns`` (None: the function runs)."""
    def handler(hook):
        log.append(tuple(hook.args[:args]))
        return returns
    return handler


def skip(hook) -> int:
    """The function doesn't run and returns 0."""
    return 0


_CONVERSION = re.compile(rb"%([-+ #0]*)(\d*)(?:\.(\d+))?(hh|h|ll|l|z|j|t)?([diouxXcsp%])")


def _format(hook, fmt: bytes, first_arg: int) -> bytes:
    """printf's integer, character, string and pointer conversions over the
    hook's integer arguments (no floating point: they are in other registers)."""
    out = bytearray()
    arg = first_arg
    pos = 0
    for m in _CONVERSION.finditer(fmt):
        out += fmt[pos:m.start()]
        pos = m.end()
        flags, width, precision, length, conv = m.groups()
        if conv == b"%":
            out += b"%"
            continue
        value = hook.arg(arg)
        arg += 1
        bits = {b"hh": 8, b"h": 16, b"l": 64, b"ll": 64, b"z": 64, b"j": 64, b"t": 64}.get(length, 32)
        value &= (1 << bits) - 1
        if conv == b"s":
            text = hook.read_string(value) if value else b"(null)"
            if precision:
                text = text[: int(precision)]
        elif conv == b"c":
            text = bytes([value & 0xFF])
        elif conv in (b"d", b"i"):
            signed = value - (1 << bits) if value >> (bits - 1) else value
            text = str(signed).encode()
        elif conv == b"u":
            text = str(value).encode()
        elif conv in (b"x", b"X"):
            text = format(value, "x" if conv == b"x" else "X").encode()
        elif conv == b"o":
            text = format(value, "o").encode()
        else:  # p
            text = b"0x" + format(value, "x").encode()
        if width:
            pad = b"0" if b"0" in flags and b"-" not in flags and conv != b"s" else b" "
            text = text.ljust(int(width), b" ") if b"-" in flags else text.rjust(int(width), pad)
        out += text
    out += fmt[pos:]
    return bytes(out)


def printf(out: List[bytes]) -> Callable:
    """printf: formats from the program's arguments (integer, character,
    string and pointer conversions), appends the text to ``out`` and
    returns its length."""
    def handler(hook):
        text = _format(hook, hook.read_string(hook.arg(0)), 1)
        out.append(text)
        return len(text)
    return handler


def strlen(hook) -> int:
    """strlen over the emulated memory."""
    return len(hook.read_string(hook.arg(0), 1 << 20))


def memset(hook) -> int:
    """memset over the emulated memory; returns the destination."""
    dest, byte, n = hook.arg(0), hook.arg(1) & 0xFF, hook.arg(2)
    if n:
        hook.write_memory(dest, bytes([byte]) * min(n, 1 << 24))
    return dest
