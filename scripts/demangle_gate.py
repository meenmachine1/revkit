#!/usr/bin/env python3
"""The demangler gate (docs/demangle.md): decompiled C++ with and without
the demangler analysis, against DWARF truth.

Builds corpus/cxx (a C++ shared library and an executable calling it) with
the host's compilers, debug and stripped, then decompiles each stripped
build with `rk-lift --analyze --decompile` twice: as is ("after") and with
`--no-own demangle` ("before"). Per build it reports:

  mangled     functions named by a mangled symbol (the stripped library's
              exports, both builds' imports)
  demangled   of those, how many the decompiled C names by their
              demangled name (no mangled name left in the signature line)
  arity       functions of the library's DWARF (the debug build) whose
              decompiled parameter count (`this` included) is the truth's
  calls_mangled  mangled names left anywhere in the decompiled C

and fails unless, for every build, after names every mangled function
demangled and gets at least as many parameter counts right as before. The
compilers it can't find are skipped (with a message). Outputs under
build/corpus-out/demangle.

    scripts/demangle_gate.py [-j N] [--keep] [--json out.json]
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SRC = os.path.join(ROOT, "corpus", "cxx")

# (config, compiler, flags, library name, executable name, extra link flags)
CONFIGS = [
    ("elf-x86_64/gcc-O2", "g++", ["-O2"], "libshapes.so", "shapes"),
    ("elf-x86_64/gcc-O0", "g++", ["-O0"], "libshapes.so", "shapes"),
    ("elf-x86_64/clang-O2", "clang++", ["-O2"], "libshapes.so", "shapes"),
    ("elf-aarch64/gcc-O2", "aarch64-linux-gnu-g++", ["-O2"], "libshapes.so", "shapes"),
    ("pe-x86_64/mingw-O2", "x86_64-w64-mingw32-g++", ["-O2", "-static-libgcc", "-static-libstdc++"], "shapes.dll", "shapes.exe"),
]

MANGLED = re.compile(r"\b(_Z[A-Za-z0-9_]+|\?[A-Za-z0-9_?@$]+)")


def build(cfg, out: str) -> str | None:
    name, cxx, flags, lib, exe = cfg
    if shutil.which(cxx) is None:
        return f"{cxx} not found"
    d = os.path.join(out, name)
    for kind in ("debug", "stripped"):
        os.makedirs(os.path.join(d, kind), exist_ok=True)
    dbg = os.path.join(d, "debug")
    common = ["-std=c++17", "-g", "-fno-omit-frame-pointer"] + flags
    shared = ["-shared"] + ([] if name.startswith("pe-") else ["-fPIC"])
    subprocess.run([cxx, *common, *shared, "-o", os.path.join(dbg, lib), os.path.join(SRC, "shapes.cc")],
                   check=True, capture_output=True)
    subprocess.run([cxx, *common, "-o", os.path.join(dbg, exe), os.path.join(SRC, "main.cc"),
                    os.path.join(dbg, lib)], check=True, capture_output=True)
    strip = cxx.replace("g++", "strip").replace("clang++", "strip")
    if shutil.which(strip) is None:
        strip = "strip"
    for f in (lib, exe):
        dst = os.path.join(d, "stripped", f)
        shutil.copyfile(os.path.join(dbg, f), dst)
        subprocess.run([strip, "--strip-debug", "--strip-unneeded", dst], check=True, capture_output=True)
    return None


def params_of(sig: str) -> int | None:
    """Parameter count of a decompiled signature line, `this` included."""
    if "(" not in sig or not sig.rstrip().endswith(")"):
        return None
    # The parameter list: from the '(' that closes the name (the first at
    # template depth 0 after the name).
    depth = 0
    start = None
    for i, c in enumerate(sig):
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
        elif c == "(" and depth <= 0:
            start = i
            break
    if start is None:
        return None
    inner = sig[start + 1:sig.rstrip().rindex(")")].strip()
    if inner in ("", "void"):
        return 0
    n, depth = 1, 0
    for c in inner:
        if c in "(<[":
            depth += 1
        elif c in ")>]":
            depth -= 1
        elif c == "," and depth == 0:
            n += 1
    if inner.endswith("..."):
        n -= 1
    return n


def truth_arity(proto: str) -> int | None:
    return params_of(proto)


def signature_line(c: str | None) -> str | None:
    if not c or "{" not in c:
        return None
    head = c[:c.index("{")]
    lines = [ln.strip() for ln in head.splitlines() if ln.strip() and not ln.strip().startswith("/*")]
    return " ".join(lines) or None


def decompile(rk_lift: str, binary: str, out: str, extra: list[str]) -> dict:
    if not os.path.exists(out):
        subprocess.run([rk_lift, "--analyze", "--decompile", "--no-instructions", "-j", "2", *extra, "-o", out, binary],
                       check=True, capture_output=True)
    with open(out) as f:
        return json.load(f)


def score(cand: dict, truth: dict | None) -> dict:
    fns = cand.get("functions", [])
    mangled = demangled = 0
    left = 0
    by_entry = {}
    for f in fns:
        c = f.get("decompiled_c") or ""
        left += len(MANGLED.findall(c))
        sig = signature_line(c)
        by_entry[int(f["entry"], 16)] = sig
        name = f.get("name", "")
        if MANGLED.fullmatch(name.split("@")[0]):
            mangled += 1
            if sig and not MANGLED.search(sig):
                demangled += 1
    row = {"functions": len(fns), "mangled": mangled, "demangled": demangled, "mangled_left": left}
    if truth is not None:
        total = right = 0
        for t in truth.get("functions", []):
            want = truth_arity(t.get("prototype") or "")
            if want is None:
                continue
            total += 1
            sig = by_entry.get(int(t["entry"], 16))
            if sig is not None and params_of(sig) == want:
                right += 1
        row["arity_total"] = total
        row["arity_right"] = right
    return row


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-j", type=int, default=4)
    ap.add_argument("--out", default=os.path.join(ROOT, "build", "corpus-out", "demangle"))
    ap.add_argument("--rk-lift", default=os.path.join(ROOT, "build", "tools", "rk-lift", "rk-lift"))
    ap.add_argument("--rk-debuginfo", default=os.path.join(ROOT, "build", "tools", "rk-debuginfo", "rk-debuginfo"))
    ap.add_argument("--keep", action="store_true", help="reuse earlier builds and decompilations")
    ap.add_argument("--json", help="write the table here")
    args = ap.parse_args(argv)
    if not args.keep and os.path.isdir(args.out):
        shutil.rmtree(args.out)
    os.makedirs(args.out, exist_ok=True)

    built = []
    for cfg in CONFIGS:
        why = build(cfg, args.out)
        if why:
            print(f"{cfg[0]}: skipped ({why})")
        else:
            built.append(cfg)

    jobs = []
    for cfg in built:
        name, _, _, lib, exe = cfg
        d = os.path.join(args.out, name)
        for f in (lib, exe):
            binary = os.path.join(d, "stripped", f)
            for side, extra in (("before", ["--no-own", "demangle"]), ("after", [])):
                jobs.append((name, f, side, binary, os.path.join(d, f"{f}.{side}.json"), extra))
    results: dict = {}
    with cf.ThreadPoolExecutor(max_workers=max(1, args.j // 2)) as ex:
        futs = {ex.submit(decompile, args.rk_lift, b, o, e): (n, f, s) for n, f, s, b, o, e in jobs}
        for fut in cf.as_completed(futs):
            results[futs[fut]] = fut.result()

    table = {}
    status = 0
    for cfg in built:
        name, _, _, lib, exe = cfg
        d = os.path.join(args.out, name)
        tpath = os.path.join(d, f"{lib}.truth.json")
        if not os.path.exists(tpath):
            with open(tpath, "w") as f:
                subprocess.run([args.rk_debuginfo, "--resolve-typedefs", os.path.join(d, "debug", lib)],
                               check=True, stdout=f, stderr=subprocess.DEVNULL)
        with open(tpath) as f:
            truth = json.load(f)
        for binary in (lib, exe):
            row = {}
            for side in ("before", "after"):
                row[side] = score(results[(name, binary, side)], truth if binary == lib else None)
            table[f"{name}/{binary}"] = row
            b, a = row["before"], row["after"]
            ok = a["demangled"] == a["mangled"] and a.get("arity_right", 0) >= b.get("arity_right", 0)
            if not ok:
                status = 1
            arity = ""
            if "arity_total" in a:
                arity = f"  arity {b['arity_right']}/{b['arity_total']} -> {a['arity_right']}/{a['arity_total']}"
            print(f"{name}/{binary}: mangled functions {a['mangled']}, named demangled {b['demangled']} -> "
                  f"{a['demangled']}; mangled names left in the C {b['mangled_left']} -> {a['mangled_left']}"
                  f"{arity}{'' if ok else '  FAIL'}")
    tot = {s: {"arity_right": 0, "arity_total": 0, "mangled": 0, "demangled": 0} for s in ("before", "after")}
    for row in table.values():
        for s in tot:
            for k in tot[s]:
                tot[s][k] += row[s].get(k, 0)
    print(f"total: named demangled {tot['before']['demangled']}/{tot['before']['mangled']} -> "
          f"{tot['after']['demangled']}/{tot['after']['mangled']}; parameter counts right "
          f"{tot['before']['arity_right']}/{tot['before']['arity_total']} -> "
          f"{tot['after']['arity_right']}/{tot['after']['arity_total']}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"builds": table, "total": tot}, f, indent=1, sort_keys=True)
    return status


if __name__ == "__main__":
    sys.exit(main())
