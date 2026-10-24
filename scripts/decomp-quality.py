#!/usr/bin/env python3
"""Decompiler quality against the original source: revkit vs Ghidra.

Both tools decompile the same stripped binaries from their own analysis
(revkit: rk-lift --analyze --decompile, its own inputs; Ghidra: its default
auto-analysis, the reference exports out/ref and out/firmware-ref), and
each function's C is scored against the truth the debug twin and the
source give (scripts/source_truth.py): DWARF (or PDB) prototypes, locals
and globals, and the function's source text. Functions are paired (the
same function, by entry, decompiled by both), and every metric reports
paired wins, ties and losses with a two-sided sign test. docs/decomp-quality.md
explains each metric and what it can't show.

  decomp-quality.py [--families tuning,firmware] [--revkit DIR] [--revkit-firmware DIR]
                    [--json OUT] [--markdown OUT] [--judge DIR [--judge-n 40]]

revkit's outputs are read from --revkit (default
build/corpus-out/revkit-decomp-own: scripts/decompile-corpus.sh --inputs own)
and --revkit-firmware (build/corpus-out/firmware: scripts/firmware_score.py);
run those first. With --judge, also writes a blinded sample for human
judges (README.md there).
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import json
import math
import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "tools", "refdiff"))
sys.path.insert(0, os.path.join(ROOT, "tools", "rk-debuginfo"))
import bench_firmware  # noqa: E402
import cnorm  # noqa: E402
import protonorm as pn  # noqa: E402
import refformat  # noqa: E402
import source_truth as st  # noqa: E402

# metric -> (group, higher is better, description)
METRICS = {
    "proto_arity": ("prototype", True, "parameter count equals the truth's (named parameters for varargs)"),
    "proto_return": ("prototype", True, "returns a value exactly when the truth does"),
    "proto_ret_class": ("prototype", True, "return type class (void/int/char/bool/float/ptr/struct) equals the truth's"),
    "proto_param_class": ("prototype", True, "share of parameter positions whose type class equals the truth's"),
    "proto_exact": ("prototype", True, "the signature equals the truth's after notation normalization (protonorm)"),
    "call_args": ("calls", True, "share of calls to the program's functions passing the callee's true argument count"),
    "lib_call_args": ("calls", True, "share of calls to named (library) functions the source calls passing an argument "
                      "count the source's calls of that function pass (printf's from its format)"),
    "noise": ("types", False, "in_/unaff_/extraout_ variables (prototype and convention errors)"),
    "undefined": ("types", False, "undefinedN types in declarations and casts"),
    "locals_class": ("types", True, "overlap of declared locals' type classes with the source's locals (multiset)"),
    "members": ("types", True, "member accesses (p->f, s.f) closeness to the source's count (minus |difference|)"),
    "globals_named": ("types", True, "share of the source's global variables accessed by symbol, not raw address"),
    "noreturn": ("calls", True, "minus calls whose returning or not the C gets wrong (DWARF DW_AT_noreturn)"),
    "gotos": ("control", True, "minus |gotos - the source's gotos|"),
    "switch": ("control", True, "a switch where the source has one"),
    "loops": ("control", True, "minus |loops - the source's loops|"),
    "strings": ("data", True, "share of the source's string literals shown as string literals"),
    "constants": ("data", True, "share of the source's numeric literals (>= 10) shown with that value"),
    "failed": ("robustness", False, "decompilation failed (no C)"),
    "warnings": ("robustness", False, "WARNING comments, but 'Subroutine does not return' (see noreturn)"),
    "casts": ("readability", False, "casts per statement line"),
    "temporaries": ("readability", False, "|declared locals - the source's locals|"),
    "length": ("readability", False, "|log(lines / the source's lines)|"),
}

FAMILIES_TUNING = [
    ("ELF gcc -O0", lambda g: g.startswith("elf-") and "/gcc-O0" in g),
    ("ELF gcc -O2", lambda g: g.startswith("elf-") and "/gcc-O2" in g),
    ("ELF clang -O0", lambda g: g.startswith("elf-") and "/clang-O0" in g),
    ("ELF clang -O2", lambda g: g.startswith("elf-") and "/clang-O2" in g),
    ("PE clang -O0", lambda g: g.startswith("pe-") and "-O0" in g),
    ("PE clang -O2", lambda g: g.startswith("pe-") and "-O2" in g),
]

_NOISE = re.compile(r"\b(?:in_|unaff_|extraout_)\w+")
_UNDEF = re.compile(r"\bundefined\d*\b")
_FUN = re.compile(r"^(?:thunk_)?FUN_([0-9a-f]{6,16})$")
_ADDR_NAME = re.compile(r"\b(?:_?DAT|PTR_\w*?|s_\w*?|u_\w*?|UNK|BYTE|WORD|DWORD|QWORD|INT|UINT|ULONG|LONG)_([0-9a-f]{6,16})\b")


# --------------------------------------------------------------------------
# Decompiled C


def split_c(c: str):
    """(signature, declaration lines, body text) of decompiled C."""
    i = c.find("\n{")
    if i < 0:
        return None, [], c
    sig = pn.decompiled_prototype(c)
    rest = c[i + 2:].split("\n")
    decls, j = [], 0
    while j < len(rest) and not rest[j].strip():
        j += 1
    while j < len(rest) and rest[j].strip() and rest[j].rstrip().endswith(";") and "(" not in rest[j] \
            and "=" not in rest[j]:
        decls.append(rest[j].strip())
        j += 1
    return sig, decls, "\n".join(rest[j:])


def decl_type(decl: str) -> str:
    d = re.sub(r"\[[^\]]*\]", "", decl.rstrip(";")).strip()
    m = re.match(r"^(.*?)(\w+)$", d)
    return m.group(1).strip() if m else d


_PTR_FUN = re.compile(r"^PTR_(?:thunk_)?FUN_([0-9a-f]{6,16})$")

# Reads the pointer at a slot address (firmware images), set per unit.
_SLOT_READER = None


def calls(body: str):
    """(callee address, argument count) of every call to a known function:
    FUN_x(...), or through a pointer slot named after what it holds,
    (*(code *)PTR_FUN_<slot>)(...) (literal pools on SuperH), whose target
    is read from the image."""
    toks = st.tokens(body)
    out = []
    for i, (k, t) in enumerate(toks):
        if k != "ident":
            continue
        if (m := _FUN.match(t)) is not None:
            if i > 0 and toks[i - 1][1] == "&":
                continue
            callee, open_at = int(m.group(1), 16), i + 1
        elif (m := _PTR_FUN.match(t)) is not None and _SLOT_READER is not None and i + 1 < len(toks) and \
                toks[i + 1][1] == ")":
            callee, open_at = _SLOT_READER(int(m.group(1), 16)), i + 2
            if callee is None:
                continue
        else:
            continue
        if open_at >= len(toks) or toks[open_at][1] != "(":
            continue
        depth, n, j, empty = 0, 0, open_at, True
        while j < len(toks):
            tt = toks[j][1]
            if tt in ("(", "[", "{"):
                depth += 1
            elif tt in (")", "]", "}"):
                depth -= 1
                if depth == 0:
                    break
            elif tt == "," and depth == 1:
                n += 1
            if depth >= 1 and j > open_at:
                empty = False
            j += 1
        out.append((callee, 0 if empty else n + 1))
    return out


def count_casts(body: str) -> int:
    toks = [(k, t) for k, t in cnorm.tokenize(body) if k != "comment"]
    return sum(1 for i in range(len(toks)) if bench_firmware._cast_end(toks, i) is not None)


def proto_parts(sig: str | None):
    p = pn._parts(sig) if sig else None
    if p is None:
        return None
    ret, _, params, varargs = p
    types = [" ".join(q[:-1]) if len(q) > 1 and re.match(r"[A-Za-z_]", q[-1]) else " ".join(q) for q in params]
    return " ".join(ret), types, varargs


def overlap(a: list[str], b: list[str]) -> float:
    if not a and not b:
        return 1.0
    ca, cb = collections.Counter(a), collections.Counter(b)
    return sum((ca & cb).values()) / max(len(a), len(b))


# --------------------------------------------------------------------------
# Scoring one function


_NORET = re.compile(r"does not return \*/\s*\n\s*(?:\w+ = )?\(?\*?(\w+)\)?\s*\(")


def score_side(c: str | None, t: dict, src: dict | None, truth_arity: dict, globals_: list,
               noreturn: set | None = None) -> dict:
    """Metric values for one tool's C of one function (None: not applicable)."""
    v: dict = {k: None for k in METRICS}
    v["failed"] = int(not c)
    if not c:
        return v
    sig, decls, body = split_c(c)
    v["warnings"] = c.count("WARNING") - c.count("WARNING: Subroutine does not return")
    v["noise"] = len(_NOISE.findall(c))
    v["undefined"] = len(_UNDEF.findall("\n".join(decls) + body + (sig or "")))
    lines = [l for l in body.split("\n") if l.strip() and l.strip() not in ("{", "}")]
    v["casts"] = count_casts(body) / max(1, len(lines))
    # Prototype
    pp = proto_parts(sig)
    tproto = t.get("prototype")
    tparts = proto_parts(tproto) if tproto else None
    if pp and tparts:
        ret, params, varargs = pp
        tret, tparams, tvarargs = tparts
        v["proto_arity"] = int(len(params) == len(tparams))
        v["proto_return"] = int((ret != "void") == (tret != "void"))
        tclasses = t.get("param_classes") or [st.c_type_class(x) for x in tparams]
        rclass = t.get("ret_class") or st.c_type_class(tret)
        v["proto_ret_class"] = int(st.c_type_class(ret) == rclass)
        mine = [st.c_type_class(x) for x in params]
        n = max(len(mine), len(tclasses))
        v["proto_param_class"] = 1.0 if n == 0 else sum(a == b for a, b in zip(mine, tclasses)) / n
        v["proto_exact"] = int(pn.signature(sig) == pn.signature(tproto))
    # Calls
    cs = [(a, n) for a, n in calls(body) if a in truth_arity]
    if cs:
        ok = 0
        for a, n in cs:
            want, va = truth_arity[a]
            ok += (n >= want) if va else (n == want)
        v["call_args"] = ok / len(cs)
    # Callees that never return: marked where the truth says so, and only there
    if noreturn is not None:
        called = {a for a, _ in calls(body)}
        marked = set()
        for name in _NORET.findall(c):
            m = _FUN.match(name)
            if m:
                marked.add(int(m.group(1), 16))
        if called & noreturn or marked:
            v["noreturn"] = -(len(marked - noreturn) + len((called & noreturn) - marked))
    # Locals
    if src is not None:
        v["locals_class"] = overlap([st.c_type_class(decl_type(d)) for d in decls], t.get("local_classes", []))
        v["temporaries"] = abs(len(decls) - len(t.get("local_classes", [])))
    # Globals: by symbol (DAT_x, PTR_x, s_..._x) or by raw address
    if globals_:
        named, raw = set(), set()
        for m in _ADDR_NAME.finditer(body):
            g = find_global(globals_, int(m.group(1), 16))
            if g is not None:
                named.add(g)
        for k, tok in st.tokens(body):
            if k == "number":
                n = st.number_value(tok)
                if n is not None and n > 0x1000:
                    g = find_global(globals_, n)
                    if g is not None:
                        raw.add(g)
        if named or raw:
            v["globals_named"] = len(named) / len(named | raw)
    if src is not None:
        f = st.c_facts("{" + body)
        v["gotos"] = -abs(f["gotos"] - src["gotos"])
        v["loops"] = -abs(f["loops"] - src["loops"])
        if src["switches"]:
            v["switch"] = int(f["switches"] > 0)
        if src["members"]:
            v["members"] = -abs(f["members"] - src["members"])
        if src["strings"]:
            shown = set(f["strings"])
            v["strings"] = sum(s in shown for s in src["strings"]) / len(src["strings"])
        if src["calls"]:
            want_calls = collections.Counter(tuple(c) for c in src["calls"])
            names = {name for name, _ in want_calls}
            mine = [c for c in f["calls"] if c[0] in names and not _FUN.match(c[0])]
            if mine:
                v["lib_call_args"] = sum((collections.Counter(mine) & want_calls).values()) / len(mine)
        want = {n for n in src["numbers"] if n >= 10}
        if want:
            v["constants"] = len(want & f["numbers"]) / len(want)
        v["length"] = abs(math.log(max(1, f["lines"]) / max(1, src["lines"])))
    return v


def find_global(globals_: list, a: int):
    import bisect
    i = bisect.bisect_right(globals_, (a, float("inf"), "")) - 1
    if i >= 0:
        start, end, name = globals_[i]
        if start <= a < end:
            return name
    return None


def compare(a, b, higher: bool):
    if a is None or b is None:
        return None
    if abs(a - b) < 1e-9:
        return 0
    return 1 if (a > b) == higher else -1


# --------------------------------------------------------------------------
# Units: one stripped binary or raw image with both tools' C and its truth


def cached_json(path: str, make):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = make()
    with open(path + ".tmp", "w") as f:
        json.dump(data, f)
    os.replace(path + ".tmp", path)
    return data


def debuginfo(args, path: str, pe: bool):
    def make():
        cmd = [args.rk_debuginfo, "--resolve-typedefs"] + (["--no-dwarf"] if pe else []) + [path]
        r = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return json.loads(r.stdout)
    rel = os.path.relpath(path, ROOT).replace("/", "__")
    return cached_json(os.path.join(args.work, "truth", rel + ".json"), make)


def dwarf(args, path: str):
    rel = os.path.relpath(os.path.realpath(path), os.path.realpath(ROOT)).replace("/", "__")
    return cached_json(os.path.join(args.work, "dwarf", rel + ".json"), lambda: st.read_dwarf(path))


def load_funcs(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    doc = refformat.load(path) if path.endswith((".json", ".gz")) else json.load(open(path))
    return {int(f["entry"], 16): f for f in doc["functions"]}


def tuning_units(args, roots) -> list[dict]:
    manifest = json.load(open(os.path.join(args.corpus, "manifest.json")))
    by_program_elf = {}
    for b in manifest["binaries"]:
        if b["format"] == "elf" and not b["stripped"]:
            by_program_elf.setdefault(b["program"], b["path"])
    units = []
    for b in manifest["binaries"]:
        if not b["stripped"]:
            continue
        rel = b["path"]
        debug_rel = rel.replace("/stripped/", "/debug/")
        units.append({
            "kind": "tuning", "id": rel, "group": b["config"], "program": b["program"],
            "ghidra": os.path.join(args.ref, rel + ".json"), "revkit": os.path.join(args.revkit, rel + ".json"),
            "truth_bin": os.path.join(args.corpus, debug_rel), "pe": b["format"] == "pe",
            "dwarf_bin": os.path.join(args.corpus, debug_rel if b["format"] == "elf" else
                                      by_program_elf[b["program"]]),
            "src_root": roots[b["program"]], "src_exclude": (),
        })
    return units


def firmware_units(args, roots) -> list[dict]:
    manifest = json.load(open(os.path.join(args.firmware_corpus, "manifest.json")))
    units = []
    for im in manifest["images"]:
        elf = os.path.join(args.firmware_corpus, im["path"][:-len(".bin")] + ".elf")
        uboot = "uboot" in im["name"]
        units.append({
            "kind": "firmware", "id": im["name"], "group": "fw " + im["arch"], "program": im["name"],
            "ghidra": os.path.join(args.firmware_ref, im["path"] + ".json"),
            "revkit": os.path.join(args.revkit_firmware, im["name"] + ".json"),
            "truth_bin": elf, "pe": False, "dwarf_bin": elf,
            "image": os.path.join(args.firmware_corpus, im["path"]), "base": int(im["base"], 16),
            "big_endian": ":BE:" in im["language"],
            # A fixture's manifest names its sources (tests/data/arm32).
            "src_root": (os.path.join(ROOT, im["src_root"]) if im.get("src_root") else
                         os.path.join(roots["firmware"], "u-boot") if uboot else roots["firmware"]),
            "src_exclude": () if uboot or im.get("src_root") else ("u-boot",),
        })
    return units


def slot_reader(u: dict):
    """The pointer a firmware image holds at an address, or None."""
    if not u.get("image"):
        return None
    data = open(u["image"], "rb").read()
    base, big = u["base"], u["big_endian"]

    def read(a: int):
        off = a - base
        if off < 0 or off + 4 > len(data):
            return None
        return int.from_bytes(data[off:off + 4], "big" if big else "little") & ~1
    return read


def score_unit(args, u: dict) -> dict:
    global _SLOT_READER
    _SLOT_READER = slot_reader(u)
    G, R = load_funcs(u["ghidra"]), load_funcs(u["revkit"])
    truth = {int(f["entry"], 16): f for f in debuginfo(args, u["truth_bin"], u["pe"])["functions"]}
    dw = dwarf(args, u["dwarf_bin"])
    index = st.SourceIndex(u["src_root"], u["src_exclude"])
    by_entry = {f["entry"]: f for f in dw["functions"]}
    by_name = {}
    for f in dw["functions"]:
        by_name.setdefault(f["name"], f)
    globals_ = [] if u["pe"] else sorted((g["addr"], g["addr"] + max(1, g["size"]), g["name"] or "")
                                         for g in dw["globals"])
    noreturn = {f["entry"] for f in dw["functions"] if f.get("noreturn")} if not u["pe"] else None
    truth_arity = {}
    for e, f in truth.items():
        p = proto_parts(f.get("prototype"))
        if p:
            truth_arity[e] = (len(p[1]), p[2])
    rows = []
    for e in sorted(set(G) & set(R) & set(truth)):
        t = dict(truth[e])
        d = by_name.get(t.get("name")) if u["pe"] else by_entry.get(e)
        src_text = st.function_source(index, d["file"], d["line"], d["name"]) if d else None
        if d:
            if not u["pe"]:
                t["param_classes"], t["ret_class"] = d["params"], d["ret"]
            t["local_classes"] = d["locals"]
        src = st.c_facts(src_text) if src_text else None
        if src is not None:
            src["locals"] = len(t.get("local_classes", []))
        gc, rc = G[e].get("decompiled_c"), R[e].get("decompiled_c")
        sg = score_side(gc, t, src, truth_arity, globals_, noreturn)
        sr = score_side(rc, t, src, truth_arity, globals_, noreturn)
        # Content metrics only where both decompiled.
        if not gc or not rc:
            for k in METRICS:
                if k != "failed":
                    sg[k] = sr[k] = None
        rows.append({"entry": e, "name": t.get("name"), "ghidra": sg, "revkit": sr,
                     "same": bool(gc and rc and cnorm.normalize(gc, "ast") == cnorm.normalize(rc, "ast")),
                     "src_lines": src["lines"] if src else None,
                     "src": (d["file"], d["line"]) if d and src_text else None})
    T = set(truth)
    return {
        "id": u["id"], "group": u["group"], "rows": rows,
        "functions": {"truth": len(T), "ghidra": len(T & set(G)), "revkit": len(T & set(R)),
                      "both": len(T & set(G) & set(R))},
    }


# --------------------------------------------------------------------------
# Aggregation


# The composite: per function, the metrics revkit wins minus those it loses,
# the prototype counted once (its parameter types) so its five views don't
# outweigh the body.
COMPOSITE_SKIP = {"proto_arity", "proto_return", "proto_ret_class", "proto_exact"}


def composite(row: dict):
    s, any_ = 0, False
    for m, (_, higher, _) in METRICS.items():
        if m in COMPOSITE_SKIP:
            continue
        c = compare(row["revkit"][m], row["ghidra"][m], higher)
        if c is not None:
            any_ = True
            s += c
    return (s > 0) - (s < 0) if any_ else None


def sign_test(w: int, l: int) -> float:
    n = w + l
    if n == 0:
        return 1.0
    k = min(w, l)
    c, s = 1, 0
    for i in range(k + 1):
        s += c
        c = c * (n - i) // (i + 1)
    return min(1.0, 2 * s / (1 << n))


def aggregate(results: list[dict], families: list[tuple[str, callable]]) -> dict:
    out = {}
    for fam, pick in families:
        rs = [r for r in results if pick(r["group"])]
        if not rs:
            continue
        agg = {"binaries": len(rs), "functions": {k: sum(r["functions"][k] for r in rs)
                                                   for k in ("truth", "ghidra", "revkit", "both")},
               "pairs": sum(len(r["rows"]) for r in rs), "identical": sum(x["same"] for r in rs for x in r["rows"]),
               "metrics": {}}
        for m, (_, higher, _) in METRICS.items():
            w = t = l = 0
            sr = sg = 0.0
            n = 0
            for r in rs:
                for row in r["rows"]:
                    a, b = row["revkit"][m], row["ghidra"][m]
                    c = compare(a, b, higher)
                    if c is None:
                        continue
                    n += 1
                    sr += a
                    sg += b
                    w += c == 1
                    t += c == 0
                    l += c == -1
            agg["metrics"][m] = {"n": n, "win": w, "tie": t, "loss": l, "p": sign_test(w, l),
                                 "revkit": sr / n if n else None, "ghidra": sg / n if n else None}
        cs = [composite(row) for r in rs for row in r["rows"]]
        w, t, l = cs.count(1), cs.count(0), cs.count(-1)
        agg["composite"] = {"n": w + t + l, "win": w, "tie": t, "loss": l, "p": sign_test(w, l)}
        out[fam] = agg
    return out


def verdict(m: dict, alpha: float = 0.01) -> str:
    if m["n"] == 0:
        return "n/a"
    if m["p"] < alpha:
        return "WIN" if m["win"] > m["loss"] else "LOSS"
    return "tie"


def markdown(agg: dict) -> str:
    fams = list(agg)
    lines = ["# Decompiler quality vs source: revkit vs Ghidra", "",
             "Paired per function (both tools' C of the same function). W/T/L: revkit wins, ties, loses; "
             "p: two-sided sign test on W vs L; verdict at p < 0.01. Means are revkit / Ghidra.", ""]
    lines.append("| family | binaries | truth fns | Ghidra has | revkit has | paired | identical C |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for f in fams:
        a = agg[f]
        fn = a["functions"]
        lines.append("| %s | %d | %d | %d | %d | %d | %d |" % (f, a["binaries"], fn["truth"], fn["ghidra"], fn["revkit"],
                                                            a["pairs"], a["identical"]))
    lines.append("")
    lines.append("### Per function, all metrics (the composite)")
    lines.append("")
    lines.append("Per function: the metrics revkit wins minus those it loses (the prototype counted once, by its "
                 "parameter types); W/T/L are functions where that is positive, zero, negative.")
    lines.append("")
    lines.append("| family | n | W | T | L | p | verdict |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | --- |")
    for f in fams:
        x = agg[f]["composite"]
        lines.append("| %s | %d | %d | %d | %d | %.2g | %s |" % (f, x["n"], x["win"], x["tie"], x["loss"], x["p"],
                                                               verdict(x)))
    lines.append("")
    for m, (grp, higher, desc) in METRICS.items():
        lines.append("### %s (%s; %s is better)" % (m, grp, "higher" if higher else "lower"))
        lines.append("")
        lines.append(desc)
        lines.append("")
        lines.append("| family | n | revkit | Ghidra | W | T | L | p | verdict |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
        for f in fams:
            x = agg[f]["metrics"][m]
            if not x["n"]:
                continue
            lines.append("| %s | %d | %.3f | %.3f | %d | %d | %d | %.2g | %s |" % (
                f, x["n"], x["revkit"], x["ghidra"], x["win"], x["tie"], x["loss"], x["p"], verdict(x)))
        lines.append("")
    return "\n".join(lines)


def summary(agg: dict) -> str:
    """One line per family: the metrics won and lost (p < 0.01)."""
    out = []
    for f, a in agg.items():
        wins = [m for m, x in a["metrics"].items() if verdict(x) == "WIN"]
        losses = [m for m, x in a["metrics"].items() if verdict(x) == "LOSS"]
        c = a["composite"]
        out.append("%-16s composite %d/%d/%d (%s)\n%-16s won: %s\n%-16s lost: %s" % (
            f, c["win"], c["tie"], c["loss"], verdict(c), "", ", ".join(wins) or "-", "", ", ".join(losses) or "-"))
    return "\n".join(out)


# --------------------------------------------------------------------------
# The blinded judge packet


def judge_packet(args, results: list[dict], families, units_by_id: dict) -> None:
    rng = random.Random(args.seed)
    root = args.judge
    os.makedirs(root, exist_ok=True)
    key, manifest = {}, []
    indexes: dict = {}
    for fam, pick in families:
        if fam.startswith("ALL"):
            continue
        pool = []
        for r in results:
            if not pick(r["group"]):
                continue
            u = units_by_id[r["id"]]
            for row in r["rows"]:
                if row["src"] and not row["same"] and not row["ghidra"]["failed"] and not row["revkit"]["failed"]:
                    pool.append((r["id"], row))
        if not pool:
            continue
        pool.sort(key=lambda x: (x[1]["src_lines"], x[0], x[1]["entry"]))
        quart = [pool[i * len(pool) // 4:(i + 1) * len(pool) // 4] for i in range(4)]
        picked = []
        for qi, q in enumerate(quart):
            want = args.judge_n // 4 + (1 if qi < args.judge_n % 4 else 0)
            picked += rng.sample(q, min(want, len(q)))
        slug = re.sub(r"[^a-z0-9]+", "-", fam.lower()).strip("-")
        os.makedirs(os.path.join(root, slug), exist_ok=True)
        for i, (uid, row) in enumerate(picked):
            u = units_by_id[uid]
            ix = indexes.setdefault(uid, st.SourceIndex(u["src_root"], u["src_exclude"]))
            src = st.function_source(ix, row["src"][0], row["src"][1], row["name"])
            G, R = load_funcs(u["ghidra"]), load_funcs(u["revkit"])
            gc, rc = G[row["entry"]]["decompiled_c"], R[row["entry"]]["decompiled_c"]
            x_is = rng.choice(["revkit", "ghidra"])
            X, Y = (rc, gc) if x_is == "revkit" else (gc, rc)
            item = "%s-%02d" % (slug, i + 1)
            with open(os.path.join(root, slug, item + ".md"), "w") as f:
                f.write("# %s\n\nFamily: %s. Function: `%s` (%s).\n\n" % (item, fam, row["name"],
                                                                         os.path.basename(row["src"][0])))
                f.write("## Original source\n\n```c\n%s\n```\n\n" % src.strip("\n"))
                f.write("## X\n\n```c\n%s\n```\n\n## Y\n\n```c\n%s\n```\n" % (X.strip("\n"), Y.strip("\n")))
            key[item] = {"X": x_is, "Y": "ghidra" if x_is == "revkit" else "revkit", "binary": uid,
                         "entry": "0x%x" % row["entry"]}
            manifest.append({"item": item, "family": fam, "file": os.path.join(slug, item + ".md")})
        pairs = sum(1 for r in results if pick(r["group"]) for _ in r["rows"])
        same = sum(1 for r in results if pick(r["group"]) for row in r["rows"] if row["same"])
        manifest.append({"family": fam, "pairs": pairs, "identical": same, "eligible": len(pool),
                         "sampled": len(picked)})
    with open(os.path.join(root, "items.json"), "w") as f:
        json.dump(manifest, f, indent=1)
    with open(os.path.join(root, "answers-template.csv"), "w") as f:
        f.write("item,correctness (X|Y|same),readability (X|Y|same),notes\n")
        for m in manifest:
            if "item" in m:
                f.write("%s,,,\n" % m["item"])
    os.makedirs(os.path.join(os.path.dirname(root.rstrip("/")), "judge-key"), exist_ok=True)
    with open(os.path.join(os.path.dirname(root.rstrip("/")), "judge-key", "key.json"), "w") as f:
        json.dump(key, f, indent=1, sort_keys=True)
    with open(os.path.join(root, "README.md"), "w") as f:
        f.write(JUDGE_README % {"n": args.judge_n, "seed": args.seed})


JUDGE_README = """# Blinded decompiler comparison

Each item is one function from a program built from source: the original
source, and two decompilations of the stripped binary (no symbols, no debug
information) labelled X and Y in random order. One comes from revkit, the
other from Ghidra 12.1.4; which is which is not in this directory.

Per family, up to %(n)d functions were drawn (seed %(seed)d), stratified by
the source function's length (quartiles), among the functions whose two
decompilations differ (`items.json` gives, per family, how many paired
functions there were and how many were identical, which count as ties).

For each item, compare X and Y against the source:

1. **Correctness** first: which one says what the source does (the same
   computation, conditions, calls with the right arguments, return values,
   memory accessed). Names don't matter: neither tool has the source's
   names, functions are `FUN_<address>` and globals `DAT_<address>`.
2. **Readability** second: which one would let you understand the source
   faster (types, structure, loops and switches, fewer casts and gotos).

Answer `X`, `Y` or `same` for each in `answers-template.csv` (one row per
item), with a note where useful. Files:

- `<family>/<item>.md`: the source, X and Y;
- `items.json`: the items, and per family the counts above;
- `answers-template.csv`: the answer sheet.

The key is kept apart, in `../judge-key/key.json`; don't open it before
answering.
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--families", default="tuning,firmware")
    ap.add_argument("--corpus", default=os.path.join(ROOT, "out", "corpus"))
    ap.add_argument("--ref", default=os.path.join(ROOT, "out", "ref"))
    ap.add_argument("--revkit", default=os.path.join(ROOT, "build", "corpus-out", "revkit-decomp-own"))
    ap.add_argument("--firmware-corpus", default=os.path.join(ROOT, "out", "firmware-corpus"))
    ap.add_argument("--firmware-ref", default=os.path.join(ROOT, "out", "firmware-ref"))
    ap.add_argument("--revkit-firmware", default=os.path.join(ROOT, "build", "corpus-out", "firmware"))
    ap.add_argument("--work", default=os.path.join(ROOT, "build", "quality"))
    ap.add_argument("--rk-debuginfo", default=os.path.join(ROOT, "build", "tools", "rk-debuginfo", "rk-debuginfo"))
    ap.add_argument("--only", action="append", default=[], help="units (binary paths, image names) matching GLOB")
    ap.add_argument("-j", "--jobs", type=int, default=8)
    ap.add_argument("--json", help="write the aggregate (and per-function rows with --rows) here")
    ap.add_argument("--rows", help="write every paired function's metrics here (JSON)")
    ap.add_argument("--markdown", help="write the tables here")
    ap.add_argument("--judge", help="write the blinded judge packet into this directory")
    ap.add_argument("--judge-n", type=int, default=40)
    ap.add_argument("--heldout", action="store_true",
                    help="the held-out set (docs/heldout.md: run once, read the summary only): out/corpus-heldout, "
                         "out/ref-heldout, build/corpus-out/heldout/revkit-decomp-own; no firmware")
    ap.add_argument("--seed", type=int, default=20261005)
    args = ap.parse_args()

    import fnmatch
    if args.heldout:
        args.corpus = os.path.join(ROOT, "out", "corpus-heldout")
        args.ref = os.path.join(ROOT, "out", "ref-heldout")
        args.revkit = os.path.join(ROOT, "build", "corpus-out", "heldout", "revkit-decomp-own")
        args.families = "tuning"
    roots = st.prepare_sources(os.path.join(args.work, "src"), args.heldout)
    fams = args.families.split(",")
    units = (tuning_units(args, roots) if "tuning" in fams else []) + \
        (firmware_units(args, roots) if "firmware" in fams else [])
    if args.only:
        units = [u for u in units if any(fnmatch.fnmatch(u["id"], p) for p in args.only)]
    missing = [u["revkit"] for u in units if not os.path.exists(u["revkit"])]
    if missing:
        print("missing revkit outputs (run decompile-corpus.sh --inputs own / firmware_score.py): %s" %
              ", ".join(missing[:5]), file=sys.stderr)
        return 2
    with cf.ProcessPoolExecutor(args.jobs) as ex:
        results = list(ex.map(score_unit, [args] * len(units), units))
    families = list(FAMILIES_TUNING) + [("fw " + a, (lambda a: lambda g: g == "fw " + a)(a))
                                        for a in ("arm", "cortexm", "m68k", "mips", "ppc", "sh4", "xtensa")]
    families += [("ALL tuning", lambda g: not g.startswith("fw ")), ("ALL firmware", lambda g: g.startswith("fw "))]
    agg = aggregate(results, families)
    md = markdown(agg)
    print(summary(agg))
    if args.markdown:
        with open(args.markdown, "w") as f:
            f.write(md + "\n")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(agg, f, indent=1, sort_keys=True)
    if args.rows:
        with open(args.rows, "w") as f:
            json.dump(results, f)
    if args.judge:
        judge_packet(args, results, families, {u["id"]: u for u in units})
    return 0


if __name__ == "__main__":
    sys.exit(main())
