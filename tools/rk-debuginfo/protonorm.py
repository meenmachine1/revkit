#!/usr/bin/env python3
"""Prototype normalization for comparing against DWARF ground truth.

Implements the rules in docs/reference-format.md ("Comparing prototypes"),
so refdiff and other consumers can import it:

  normalize(p)   notation-only differences removed (spacing, C vs Ghidra
                 type spellings, qualifiers, tag keywords, hidden struct
                 return pointer, (void) vs ())
  signature(p)   normalize(p) without the function and parameter names
  arity(p)       (returns a value, parameter count, varargs): the coarsest
                 shape of a prototype

As a script, compares debug-info truth (rk-debuginfo output: DWARF, or a
PE's PDB) with another export:

  protonorm.py TRUTH CAND [--examples N] [--decompiled]

TRUTH and CAND are reference files or directories of them (paired by
relative path). Only functions with a truth prototype are scored; a
function missing from CAND counts as a mismatch. With --decompiled the
candidate prototype is the signature line of its `decompiled_c` (what the
decompiler recovered) instead of its `prototype` field, which for Ghidra on a
stripped binary is just `undefined FUN_...()`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

_TOKEN = re.compile(r"\.\.\.|[A-Za-z_][A-Za-z0-9_:$.~]*|\d+|[*&()\[\],<>]")

# Multi-word C spellings -> Ghidra's built-in names (longest first).
_SPELLINGS = [
    ("long long unsigned int", "ulonglong"),
    ("unsigned long long int", "ulonglong"),
    ("unsigned long long", "ulonglong"),
    ("long long int", "longlong"),
    ("signed long long int", "longlong"),
    ("long long", "longlong"),
    ("long unsigned int", "ulong"),
    ("unsigned long int", "ulong"),
    ("unsigned long", "ulong"),
    ("signed long int", "long"),
    ("long int", "long"),
    ("short unsigned int", "ushort"),
    ("unsigned short int", "ushort"),
    ("unsigned short", "ushort"),
    ("signed short int", "short"),
    ("short int", "short"),
    ("unsigned char", "uchar"),
    ("signed char", "char"),
    ("unsigned int", "uint"),
    ("signed int", "int"),
    ("long double", "longdouble"),
    ("unsigned", "uint"),
    ("signed", "int"),
    ("_Bool", "bool"),
    # Ghidra's names for types it imports from a PDB, or for long double on
    # Windows, where its data organization has no 16-byte long double.
    ("long64", "longlong"),
    ("ulong64", "ulonglong"),
    ("schar", "char"),
    ("float10", "longdouble"),
    ("float16", "longdouble"),
]
# Ghidra names an anonymous function type from a PDB with its calling
# convention: _func___cdecl_int_int.
_FUNC_CC = re.compile(r"_func___(?:cdecl|stdcall|fastcall|thiscall|vectorcall)_")
_DROP = {"const", "volatile", "restrict", "__restrict", "_Atomic", "struct", "union", "enum", "class"}
_RETURN_STORAGE = "__return_storage_ptr__"


def _tokens(text: str) -> list[str]:
    toks = [_FUNC_CC.sub("_func_", t) for t in _TOKEN.findall(text) if t not in _DROP]
    out: list[str] = []
    i = 0
    while i < len(toks):
        for words, name in _SPELLINGS:
            w = words.split()
            if toks[i:i + len(w)] == w:
                out.append(name)
                i += len(w)
                break
        else:
            out.append(toks[i])
            i += 1
    return out


def _join(toks: list[str]) -> str:
    s = ""
    for t in toks:
        if not s or s.endswith((" ", "(", "[")) or t in (")", "]", ",", "["):
            s += t
        else:
            s += " " + t
        if t == ",":
            s += " "
    return s.strip()


def _split(proto: str):
    """-> (return+name tokens, [param token lists], varargs) or None."""
    toks = _tokens(proto)
    if "(" not in toks or toks[-1:] != [")"]:
        return None
    open_at = toks.index("(")
    head, inner = toks[:open_at], toks[open_at + 1:-1]
    params: list[list[str]] = []
    depth, cur = 0, []
    for t in inner:
        if t in "([":
            depth += 1
        elif t in ")]":
            depth -= 1
        if t == "," and depth == 0:
            params.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        params.append(cur)
    if params == [["void"]]:
        params = []
    varargs = bool(params) and params[-1] == ["..."]
    if varargs:
        params = params[:-1]
    return head, params, varargs


def _parts(proto: str):
    sp = _split(proto)
    if sp is None:
        return None
    head, params, varargs = sp
    ret, name = head[:-1], head[-1:]
    # Ghidra shows a struct returned in memory as a hidden first parameter.
    if params and params[0][-1:] == [_RETURN_STORAGE]:
        ptype = params[0][:-1]
        if ptype[-1:] == ["*"] and (ret == ptype or ret == ["void"]):
            ret = ptype[:-1]
        params = params[1:]
    return ret, name, params, varargs


def _render(ret, name, params, varargs) -> str:
    plist = [_join(p) for p in params] + (["..."] if varargs else [])
    return _join(ret + name) + "(" + (", ".join(plist) if plist else "void") + ")"


def normalize(proto: str) -> str:
    p = _parts(proto)
    return proto.strip() if p is None else _render(*p)


def signature(proto: str) -> str:
    p = _parts(proto)
    if p is None:
        return proto.strip()
    ret, _, params, varargs = p
    # In the reference notation a parameter is "<type> <name>": drop the name.
    types = [q[:-1] if len(q) > 1 and re.match(r"[A-Za-z_]", q[-1]) else q for q in params]
    return _render(ret, [], types, varargs)


def arity(proto: str):
    p = _parts(proto)
    if p is None:
        return None
    ret, _, params, varargs = p
    return (ret != ["void"], len(params), varargs)


# --- comparison --------------------------------------------------------------

def _load(path: str) -> dict:
    import gzip
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def _pairs(truth: str, cand: str):
    if os.path.isfile(truth):
        yield os.path.basename(truth), truth, cand
        return
    for dirpath, dirnames, filenames in os.walk(truth):
        dirnames.sort()
        for n in sorted(filenames):
            if not n.endswith((".json", ".json.gz")):
                continue
            t = os.path.join(dirpath, n)
            rel = os.path.relpath(t, truth)
            for c in (os.path.join(cand, rel), os.path.join(cand, rel + ".gz"),
                      os.path.join(cand, rel[:-3]) if rel.endswith(".gz") else None):
                if c and os.path.exists(c):
                    yield rel, t, c
                    break


def decompiled_prototype(c: str | None) -> str | None:
    """The function declaration at the top of decompiled C."""
    if not c or "{" not in c:
        return None
    head = c[:c.index("{")]
    lines = [ln.strip() for ln in head.splitlines() if ln.strip() and not ln.strip().startswith("/*")]
    return " ".join(lines) or None


def compare(truth: str, cand: str, examples: int = 0, out=sys.stdout,
            decompiled: bool = False) -> dict:
    total = {"truth": 0, "found": 0, "exact": 0, "normalized": 0, "signature": 0, "arity": 0}
    misses: list[tuple] = []
    for rel, t, c in _pairs(truth, cand):
        tf = {f["entry"]: f for f in _load(t).get("functions", []) if "prototype" in f}
        cf = {f["entry"]: f for f in _load(c).get("functions", [])}
        row = dict.fromkeys(total, 0)
        for entry, f in sorted(tf.items(), key=lambda kv: int(kv[0], 16)):
            row["truth"] += 1
            g = cf.get(entry)
            b = g and (decompiled_prototype(g.get("decompiled_c")) if decompiled else g.get("prototype"))
            if not b:
                continue
            row["found"] += 1
            a = f["prototype"]
            row["exact"] += a == b
            row["normalized"] += normalize(a) == normalize(b)
            ok = signature(a) == signature(b)
            row["signature"] += ok
            row["arity"] += arity(a) == arity(b)
            if not ok and len(misses) < examples:
                misses.append((rel, entry, a, b))
        for k in total:
            total[k] += row[k]
        print("%-48s %s" % (rel, _rates(row)), file=out)
    print("%-48s %s" % ("TOTAL", _rates(total)), file=out)
    for m in misses:
        print("  %s %s\n    truth: %s\n    cand:  %s" % m, file=out)
    return total


def _rates(row: dict) -> str:
    n = row["truth"] or 1
    return "truth=%d found=%d exact=%.1f%% normalized=%.1f%% signature=%.1f%% arity=%.1f%%" % (
        row["truth"], row["found"], 100 * row["exact"] / n, 100 * row["normalized"] / n,
        100 * row["signature"] / n, 100 * row["arity"] / n)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("truth")
    ap.add_argument("cand")
    ap.add_argument("--examples", type=int, default=0, help="print up to N signature mismatches")
    ap.add_argument("--decompiled", action="store_true",
                    help="take the candidate prototype from decompiled_c")
    args = ap.parse_args(argv)
    compare(args.truth, args.cand, args.examples, decompiled=args.decompiled)
    return 0


if __name__ == "__main__":
    sys.exit(main())
