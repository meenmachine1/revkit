#!/usr/bin/env python3
"""Which truth prototypes a stripped-binary analysis could match.

The rule (docs/heldout.md, "Matchable functions"): a function is matchable
when its truth prototype, as `rk-debuginfo --resolve-typedefs` prints it
(the reference notation), names only

  - C primitive types (void, bool, the integer and floating types in
    Ghidra's spelling, wchar_t/char16_t/char32_t, __int128, complex);
  - types the target's libc or OS headers declare
    (`system_types.txt`, from gen_system_types.py: glibc's names for ELF,
    mingw-w64's for PE, and the compilers' va_list types);
  - pointers to and arrays of those, and anonymous function types
    (`_func_<ret>_<params>`) whose return and parameter types are
    themselves matchable.

A struct, union or enum the program declares, an anonymous aggregate
(`anon_struct_<hash>`), or an `undefinedN` makes the function unmatchable:
no analysis without the program's debug info can name it. Parameter and
function names never matter (the gate's level is the signature).

    matchable.py TRUTH.json [--platform elf|pe]   # prints counts and the unmatchable names
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "rk-debuginfo"))
import protonorm as pn  # noqa: E402

SYSTEM_TYPES = os.path.join(HERE, "system_types.txt")

# Words of primitive types after protonorm's normalization (Ghidra spellings).
PRIMITIVES = frozenset("""
    void bool char uchar short ushort int uint long ulong longlong ulonglong
    float double longdouble __int128 int128 uint128 complex _Float16 _Float128
    wchar_t char8_t char16_t char32_t wchar16 wchar32
""".split())
# Fixed-width integers rk-debuginfo prints for base types without a C rank.
_FIXED = re.compile(r"u?int\d+_t")
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_:$.~]*")


@functools.lru_cache(maxsize=None)
def system_types(platform: str, path: str = SYSTEM_TYPES) -> frozenset:
    names = set()
    with open(path) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            plat, name = line.split()
            if plat == platform:
                names.add(name)
    return frozenset(names)


def platform_of(rel: str) -> str:
    """'pe-x86_64/...' -> 'pe'; every other corpus path is an ELF."""
    return "pe" if rel.startswith("pe-") else "elf"


def _word_ok(word: str, known: frozenset) -> bool:
    if word in PRIMITIVES or word in known or _FIXED.fullmatch(word):
        return True
    if word.startswith("_func_"):
        return _func_ok(word[len("_func_"):], known)
    return False


@functools.lru_cache(maxsize=4096)
def _func_ok_cached(rest: str, known: frozenset) -> bool:
    # Ghidra's mangled signature: the return and parameter type names joined
    # by '_', with ' ' -> '_' and '*' -> 'ptr' (types/print.cc g_func_name).
    # Names contain '_' themselves, so segment: each piece is a primitive or
    # known name (or a nested '_func_...'), 'ptr', 'varargs', or an array
    # suffix, and some split of the whole string must work.
    vocab = PRIMITIVES | known | {"ptr", "varargs"}
    n = len(rest)

    @functools.lru_cache(maxsize=None)
    def ok_from(i: int) -> bool:
        if i == n:
            return True
        if rest.startswith("_func_", i):
            # A nested function type runs to the end of the name (its own
            # parameters follow), as far as a flat mangling can say.
            return _func_ok_cached(rest[i + len("_func_"):], known)
        for j in range(i + 1, n + 1):
            if j < n and rest[j] != "_":
                continue
            piece = re.sub(r"(\[\d*\])+$", "", rest[i:j])
            if piece in vocab or _FIXED.fullmatch(piece):
                if j == n or ok_from(j + 1):
                    return True
        return False

    return ok_from(0)


def _func_ok(rest: str, known: frozenset) -> bool:
    return bool(rest) and _func_ok_cached(rest, known)


def type_words(proto: str):
    """The identifiers naming types in a prototype's signature (return and
    parameter types; function and parameter names dropped), or None if it
    doesn't parse."""
    parts = pn._parts(proto)
    if parts is None:
        return None
    ret, _name, params, _varargs = parts
    words = [t for t in ret if _WORD.fullmatch(t)]
    for p in params:
        # "<type> <name>": the last identifier is the name (as pn.signature).
        toks = p[:-1] if len(p) > 1 and _WORD.fullmatch(p[-1]) else p
        words += [t for t in toks if _WORD.fullmatch(t)]
    return words


def unmatchable_words(proto: str, platform: str) -> list[str]:
    """Type names in `proto` a stripped analysis can't name ([] if matchable)."""
    words = type_words(proto)
    if words is None:
        return [proto]
    known = system_types(platform)
    return [w for w in words if not _word_ok(w, known)]


def is_matchable(proto: str, platform: str) -> bool:
    return not unmatchable_words(proto, platform)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("truth")
    ap.add_argument("--platform", choices=("elf", "pe"), help="default: from the file name (.exe: pe)")
    args = ap.parse_args(argv)
    plat = args.platform or ("pe" if args.truth.endswith((".exe.json", ".dll.json")) else "elf")
    with open(args.truth) as f:
        fns = [fn for fn in json.load(f).get("functions", []) if "prototype" in fn]
    bad: dict[str, int] = {}
    n = 0
    for fn in fns:
        miss = unmatchable_words(fn["prototype"], plat)
        n += not miss
        for w in set(miss):
            bad[w] = bad.get(w, 0) + 1
    print("%d of %d prototypes matchable (%s)" % (n, len(fns), plat))
    for w, c in sorted(bad.items(), key=lambda kv: (-kv[1], kv[0]))[:40]:
        print("  %5d %s" % (c, w))
    return 0


if __name__ == "__main__":
    sys.exit(main())
