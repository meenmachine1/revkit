#!/usr/bin/env python3
"""What inferred prototypes do to decompiled C, on the stripped corpus.

Decompiles every stripped binary twice with `rk-infer --decompile`: with
every function's inferred prototype locked (feedback) and with only the
library prototypes of imports (--no-feedback, what the decompiler gets
without inference). Then, per function that has debug-info truth:

  signature   the C's signature line matches the truth (protonorm rules);
  noise       tokens the decompiler emits when prototypes are missing or
              wrong: in_* (a register read that isn't a parameter),
              extraout_* (a register a call leaves that isn't its return),
              unaff_* and undefinedN types, per function;
  similarity  token similarity (difflib ratio) to Ghidra's decompilation of
              the debug build, which has DWARF prototypes, after renaming
              every identifier that isn't a C keyword or basic type.

    c_quality.py [-P procs] [-j threads] [--out DIR] [--json FILE]
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import difflib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "rk-debuginfo"))
sys.path.insert(0, HERE)
import protonorm as pn  # noqa: E402
import score  # noqa: E402

_TOK = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|\d+|\"(?:[^\"\\\\]|\\\\.)*\"|'.'|->|<<|>>|[<>=!]=|&&|\|\||\+\+|--|\S")
_KEEP = {"if", "else", "while", "do", "for", "return", "break", "continue", "goto", "switch", "case", "default",
         "void", "char", "uchar", "short", "ushort", "int", "uint", "long", "ulong", "longlong", "ulonglong",
         "float", "double", "longdouble", "bool", "true", "false", "code", "sizeof"}
_NOISE = re.compile(r"\b(in_\w+|extraout_\w+|unaff_\w+|undefined\d*)\b")


def tokens(c: str) -> list[str]:
    body = c[c.find("{"):] if "{" in c else c
    body = re.sub(r"/\*.*?\*/", " ", body, flags=re.S)
    out = []
    for t in _TOK.findall(body):
        if re.match(r"[A-Za-z_]", t) and t not in _KEEP:
            out.append("ID")
        elif t.startswith("0x") or t.isdigit():
            out.append("NUM")
        else:
            out.append(t)
    return out


def run(args, rel: str, feedback: bool) -> str:
    name = "feedback" if feedback else "plain"
    path = os.path.join(args.out, name, rel + ".json")
    if args.reuse and os.path.exists(path):
        return path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    cmd = [os.path.join(args.build, "tools", "rk-infer", "rk-infer"), "-j", str(args.jobs), "--decompile", "-o", path,
           "--stats", path[:-5] + ".stats.json"]
    if not feedback:
        cmd.append("--no-feedback")
    subprocess.run(cmd + [os.path.join(args.corpus, rel)], check=True, capture_output=True)
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=os.path.join(ROOT, "out", "corpus"))
    ap.add_argument("--ref", default=os.path.join(ROOT, "out", "ref"))
    ap.add_argument("--truth", default=os.path.join(ROOT, "build", "corpus-out", "infer-truth"))
    ap.add_argument("--out", default=os.path.join(ROOT, "build", "corpus-out", "infer-c"))
    ap.add_argument("--build", default=os.path.join(ROOT, "build"))
    ap.add_argument("-P", "--procs", type=int, default=4)
    ap.add_argument("-j", "--jobs", type=int, default=8)
    ap.add_argument("--reuse", action="store_true")
    ap.add_argument("--json")
    args = ap.parse_args()
    args.rk_debuginfo = os.path.join(args.build, "tools", "rk-debuginfo", "rk-debuginfo")

    bins = score.stripped_binaries(args.corpus)
    with cf.ThreadPoolExecutor(max_workers=args.procs) as ex:
        truths = dict(zip(bins, ex.map(lambda b: score.make_truth(args, b), bins)))
        plain = dict(zip(bins, ex.map(lambda b: run(args, b, False), bins)))
        fed = dict(zip(bins, ex.map(lambda b: run(args, b, True), bins)))

    groups: dict[str, dict] = {}
    for b in bins:
        truth = {e: f for e, f in score.load_functions(truths[b]).items() if "prototype" in f}
        debug_ref = os.path.join(args.ref, b.replace("/stripped/", "/debug/") + ".json")
        ref = score.load_functions(debug_ref) if os.path.exists(debug_ref) else {}
        sides = {"plain": score.load_functions(plain[b]), "feedback": score.load_functions(fed[b])}
        arch = b.split("/")[0]
        for key in ("TOTAL", arch):
            g = groups.setdefault(key, {})
            for side, funcs in sides.items():
                row = g.setdefault(side, {"n": 0, "signature": 0, "noise": 0, "sim": 0.0, "sim_n": 0})
                for entry, t in truth.items():
                    f = funcs.get(entry)
                    c = f.get("decompiled_c", "") if f else ""
                    row["n"] += 1
                    proto = pn.decompiled_prototype(c)
                    row["signature"] += bool(proto) and pn.signature(proto) == pn.signature(t["prototype"])
                    row["noise"] += len(_NOISE.findall(c[c.find("{"):] if "{" in c else ""))
                    r = ref.get(entry, {}).get("decompiled_c")
                    if r and c:
                        row["sim"] += difflib.SequenceMatcher(None, tokens(r), tokens(c), autojunk=False).ratio()
                        row["sim_n"] += 1

    print("%-14s %6s  %-24s %-24s %-24s" % ("group", "n", "signature plain/fed", "noise/fn plain/fed",
                                             "similarity plain/fed"))
    result = {}
    for key in sorted(groups, key=lambda k: (k != "TOTAL", k)):
        p, f = groups[key]["plain"], groups[key]["feedback"]
        n = p["n"] or 1
        entry = {
            "functions": p["n"],
            "signature": [round(100 * p["signature"] / n, 2), round(100 * f["signature"] / n, 2)],
            "noise_per_function": [round(p["noise"] / n, 3), round(f["noise"] / n, 3)],
            "similarity": [round(p["sim"] / max(1, p["sim_n"]), 4), round(f["sim"] / max(1, f["sim_n"]), 4)],
        }
        result[key] = entry
        print("%-14s %6d  %5.1f%% -> %5.1f%%      %5.2f -> %5.2f          %.3f -> %.3f" % (
            key, p["n"], *entry["signature"], *entry["noise_per_function"], *entry["similarity"]))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(result, fh, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
