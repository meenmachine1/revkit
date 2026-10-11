#!/usr/bin/env python3
"""Side by side: every gate's summary rates on the tuning corpus and on the
held-out set (docs/heldout.md), per arch and in total.

    scripts/heldout-report.py [--tuning build/corpus-out] [--heldout build/corpus-out/heldout]

Reads the outputs `scripts/ci.sh --heldout` leaves (rk-lift, rk-lift
--analyze, decompiled C under Ghidra's and revkit's own inputs, score.py
JSON) and compares them with the references. Prints summary rates only,
never per-function differences: held-out results must not drive tuning.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "refdiff"))
import refdiff  # noqa: E402

GATES = [
    # label, output subdir, refdiff categories, --common-functions
    ("rk-lift", "revkit", ["functions", "instructions", "pcode", "pcode_shared"], False),
    ("rk-lift --analyze", "revkit-analyze", ["functions", "names", "bodies", "instructions", "pcode_shared"], False),
    ("C under Ghidra's inputs", "revkit-decomp", ["c_ast", "c_tokens"], False),
    ("C from own inputs", "revkit-decomp-own", ["functions", "c_ast", "c_tokens", "c_alpha"], True),
]


def by_arch(ref: str, cand: str, cats: list[str], common: bool) -> dict:
    total, per, _ = refdiff.compare_paths(ref, cand, only=set(cats) | {"binaries"}, common=common, jobs=16)
    groups: dict[str, refdiff.Tally] = {"all": total}
    for rel, t in per.items():
        groups.setdefault(rel.split("/")[0], refdiff.Tally()).merge(t)
    return {g: {c: t.counts[c] for c in cats} for g, t in groups.items()}


def fmt(cell) -> str:
    a, n = cell
    return "%6.2f%% (%d)" % (100.0 * a / n, n) if n else "n/a"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tuning", default=os.path.join(ROOT, "build", "corpus-out"))
    ap.add_argument("--heldout", default=os.path.join(ROOT, "build", "corpus-out", "heldout"))
    ap.add_argument("--tuning-ref", default=os.path.join(ROOT, "out", "ref"))
    ap.add_argument("--heldout-ref", default=os.path.join(ROOT, "out", "ref-heldout"))
    ap.add_argument("--tuning-infer", default=None, help="score.py --json for the tuning corpus (with --matchable)")
    ap.add_argument("--heldout-infer", default=None, help="score.py --json for the held-out set")
    args = ap.parse_args()

    for label, sub, cats, common in GATES:
        sides = {}
        for name, out, ref in (("tuning", args.tuning, args.tuning_ref), ("held-out", args.heldout, args.heldout_ref)):
            d = os.path.join(out, sub)
            sides[name] = by_arch(ref, d, cats, common) if os.path.isdir(d) else {}
        print("## %s\n" % label)
        print("| arch | " + " | ".join("%s tuning | %s held-out" % (c, c) for c in cats) + " |")
        print("| --- |" + " ---: |" * (2 * len(cats)))
        archs = sorted(set(sides["tuning"]) | set(sides["held-out"]), key=lambda a: (a == "all", a))
        for a in archs:
            cells = []
            for c in cats:
                for s in ("tuning", "held-out"):
                    cells.append(fmt(sides[s].get(a, {}).get(c, (0, 0))))
            print("| %s | %s |" % (a, " | ".join(cells)))
        print()

    infer = {"tuning": args.tuning_infer, "held-out": args.heldout_infer}
    if any(infer.values()):
        print("## Phase 4 inference (revkit / Ghidra / gain, %)\n")
        print("| arch | subset | n tuning | signature tuning | n held-out | signature held-out | arity tuning | arity held-out |")
        print("| --- | --- |" + " ---: |" * 6)
        docs = {k: json.load(open(v)) if v and os.path.exists(v) else {} for k, v in infer.items()}
        for sub in ("matchable:", ""):
            for a in ("TOTAL", "elf-x86_64", "elf-aarch64", "elf-riscv64", "pe-x86_64"):
                row = ["%s" % a, "matchable" if sub else "all"]
                for lv in ("signature", "arity"):
                    for s in ("tuning", "held-out"):
                        e = docs[s].get(sub + a)
                        if lv == "signature":
                            row.append(str(e["functions"]) if e else "-")
                        row.append("%.1f / %.1f / %+.1f" % (e[lv]["revkit"], e[lv]["ghidra"], e[lv]["gain"]) if e else "-")
                # reorder: n t, sig t, n h, sig h, ar t, ar h
                n_t, sig_t, n_h, sig_h, ar_t, ar_h = row[2:]
                print("| " + " | ".join(row[:2] + [n_t, sig_t, n_h, sig_h, ar_t, ar_h]) + " |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
