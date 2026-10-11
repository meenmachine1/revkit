#!/usr/bin/env python3
"""Score revkit's inferred prototypes against debug-info truth, beside Ghidra.

For every stripped corpus binary whose debug twin has a DWARF or PDB truth:

  1. truth: `rk-debuginfo --resolve-typedefs` on the debug build (a PE's
     PDB only, `--no-dwarf`), cached in --truth;
  2. revkit: `rk-infer` on the stripped build, into --out;
  3. Ghidra: the signature line of its decompiled C on the stripped build
     (`out/ref`, as `protonorm.py --decompiled`).

Both are compared with the truth at protonorm's four levels (exact,
normalized, signature, arity), per arch, per arch/compiler-opt group and in
total. The gate is revkit minus Ghidra in percentage points:

    score.py [--baseline B.json | --save-baseline B.json] [--min-gain PP] ...

fails if any level of any arch falls below its baseline (0.2 pp slack), or
if the total gain at --gate-level is below --min-gain. --target-gain reports
the Phase 4 gate (revkit minus Ghidra at exact and signature) without
failing.

With --matchable, every row is also computed on the matchable subset
(matchable.py, docs/heldout.md: truth prototypes naming only primitives and
libc/OS types), as "matchable:<group>"; --gate-subset matchable makes
--min-gain and --target-gain apply to that subset (the held-out Phase 4 gate).
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "rk-debuginfo"))
import protonorm as pn  # noqa: E402
import matchable  # noqa: E402

LEVELS = ("exact", "normalized", "signature", "arity")


def stripped_binaries(corpus: str) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(corpus):
        dirnames.sort()
        if os.path.basename(dirpath) != "stripped":
            continue
        for n in sorted(filenames):
            rel = os.path.relpath(os.path.join(dirpath, n), corpus)
            debug = os.path.join(corpus, rel.replace("/stripped/", "/debug/"))
            if os.path.exists(debug):
                out.append(rel)
    return out


def make_truth(args, rel: str) -> str:
    path = os.path.join(args.truth, rel + ".json")
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    debug = os.path.join(args.corpus, rel.replace("/stripped/", "/debug/"))
    cmd = [args.rk_debuginfo, "--resolve-typedefs"]
    if rel.startswith("pe-"):
        cmd.append("--no-dwarf")
    cmd.append(debug)
    with open(path + ".tmp", "w") as f:
        subprocess.run(cmd, check=True, stdout=f, stderr=subprocess.DEVNULL)
    os.replace(path + ".tmp", path)
    return path


def run_infer(args, rel: str) -> str:
    path = os.path.join(args.out, rel + ".json")
    if args.reuse and os.path.exists(path):
        return path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    cmd = [args.rk_infer, "-j", str(args.jobs), "-o", path, "--stats", path[:-5] + ".stats.json", *args.infer_arg,
           os.path.join(args.corpus, rel)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        r = subprocess.CompletedProcess(cmd, "timeout", "", "timed out after %s s" % args.timeout)
    if r.returncode != 0:
        if not args.keep_going:
            raise RuntimeError(f"rk-infer failed on {rel}: {r.stderr[-2000:]}")
        # Scored as no prototypes at all (every truth function a miss).
        print(f"warning: rk-infer failed on {rel} (exit {r.returncode}): scored as no prototypes",
              file=sys.stderr, flush=True)
        args.failed.append(rel)
        if os.path.exists(path):
            os.remove(path)
        return None
    return path


def load_functions(path: str) -> dict:
    with open(path) as f:
        return {fn["entry"]: fn for fn in json.load(f).get("functions", [])}


def score(truth_path: str, cand_path: str | None, decompiled: bool, misses: list | None = None, rel: str = "",
          only_matchable: bool = False) -> dict:
    row = dict.fromkeys(("truth", "found", *LEVELS), 0)
    truth = {e: f for e, f in load_functions(truth_path).items() if "prototype" in f}
    if only_matchable:
        plat = matchable.platform_of(rel)
        truth = {e: f for e, f in truth.items() if matchable.is_matchable(f["prototype"], plat)}
    cand = load_functions(cand_path) if cand_path and os.path.exists(cand_path) else {}
    for entry, f in truth.items():
        row["truth"] += 1
        g = cand.get(entry)
        b = g and (pn.decompiled_prototype(g.get("decompiled_c")) if decompiled else g.get("prototype"))
        if not b:
            continue
        row["found"] += 1
        a = f["prototype"]
        row["exact"] += a == b
        row["normalized"] += pn.normalize(a) == pn.normalize(b)
        ok = pn.signature(a) == pn.signature(b)
        row["signature"] += ok
        row["arity"] += pn.arity(a) == pn.arity(b)
        if misses is not None and not ok:
            misses.append((rel, entry, a, b))
    return row


def add(into: dict, row: dict) -> None:
    for k, v in row.items():
        into[k] = into.get(k, 0) + v


def pct(row: dict, k: str) -> float:
    return 100.0 * row.get(k, 0) / row["truth"] if row.get("truth") else 0.0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=os.path.join(ROOT, "out", "corpus"))
    ap.add_argument("--ref", default=os.path.join(ROOT, "out", "ref"))
    # Outputs go under build/ (out/ holds the shared inputs only).
    ap.add_argument("--truth", default=os.path.join(ROOT, "build", "corpus-out", "infer-truth"))
    ap.add_argument("--out", default=os.path.join(ROOT, "build", "corpus-out", "infer"))
    ap.add_argument("--build", default=os.path.join(ROOT, "build"))
    ap.add_argument("-P", "--procs", type=int, default=4, help="binaries at once")
    ap.add_argument("-j", "--jobs", type=int, default=8, help="threads per rk-infer")
    ap.add_argument("--infer-arg", action="append", default=[], help="extra rk-infer argument (repeatable)")
    ap.add_argument("--reuse", action="store_true", help="keep existing rk-infer outputs")
    ap.add_argument("--timeout", type=float, default=None, help="seconds per rk-infer run (a failure if exceeded)")
    ap.add_argument("--keep-going", action="store_true",
                    help="score a binary rk-infer fails on as no prototypes (reported) instead of stopping")
    ap.add_argument("--only", default="", help="substring filter on binary paths")
    ap.add_argument("--examples", type=int, default=0, help="print N signature mismatches of revkit")
    ap.add_argument("--json", help="write the scores here")
    ap.add_argument("--baseline", help="fail if any arch/level falls below this baseline")
    ap.add_argument("--save-baseline", help="write the scores as the new baseline")
    ap.add_argument("--gate-level", default="signature", choices=LEVELS)
    ap.add_argument("--min-gain", type=float, default=None, help="required total gain over Ghidra (pp); fails below")
    ap.add_argument("--target-gain", type=float, default=None,
                    help="the Phase 4 gate's gain over Ghidra (pp): reported, never fails")
    ap.add_argument("--matchable", action="store_true",
                    help="also score the matchable subset (rows 'matchable:<group>'; docs/heldout.md)")
    ap.add_argument("--gate-subset", choices=("all", "matchable"), default="all",
                    help="which rows --min-gain and --target-gain judge (matchable implies --matchable)")
    args = ap.parse_args()
    if args.gate_subset == "matchable":
        args.matchable = True
    args.rk_infer = os.path.join(args.build, "tools", "rk-infer", "rk-infer")
    args.rk_debuginfo = os.path.join(args.build, "tools", "rk-debuginfo", "rk-debuginfo")
    args.failed = []

    bins = [b for b in stripped_binaries(args.corpus) if args.only in b]
    with cf.ThreadPoolExecutor(max_workers=args.procs) as ex:
        truths = dict(zip(bins, ex.map(lambda b: make_truth(args, b), bins)))
        cands = dict(zip(bins, ex.map(lambda b: run_infer(args, b), bins)))

    groups: dict[str, dict] = {}
    misses: list = []
    for b in bins:
        arch = b.split("/")[0]
        group = "/".join(b.split("/")[:2])
        ref = os.path.join(args.ref, b + ".json")
        rk = score(truths[b], cands[b], False, misses, b)
        gh = score(truths[b], ref, True, rel=b)
        for key in ("TOTAL", arch, group):
            g = groups.setdefault(key, {"revkit": {}, "ghidra": {}})
            add(g["revkit"], rk)
            add(g["ghidra"], gh)
        if args.matchable:
            rk = score(truths[b], cands[b], False, None, b, only_matchable=True)
            gh = score(truths[b], ref, True, rel=b, only_matchable=True)
            for key in ("TOTAL", arch, group):
                g = groups.setdefault("matchable:" + key, {"revkit": {}, "ghidra": {}})
                add(g["revkit"], rk)
                add(g["ghidra"], gh)

    def order(k: str):
        sub, _, base = k.rpartition(":")
        return (sub, 0 if base == "TOTAL" else 1 if "/" not in base else 2, base)

    result = {}
    hdr = "%-34s %5s  " % ("group", "n") + "  ".join("%-20s" % ("%s rk/gh/+" % lv[:4]) for lv in LEVELS)
    print(hdr)
    for key in sorted(groups, key=order):
        g = groups[key]
        n = g["revkit"]["truth"]
        cells = []
        entry = {"functions": n}
        for lv in LEVELS:
            r, h = pct(g["revkit"], lv), pct(g["ghidra"], lv)
            cells.append("%5.1f %5.1f %+6.1f   " % (r, h, r - h))
            entry[lv] = {"revkit": round(r, 2), "ghidra": round(h, 2), "gain": round(r - h, 2)}
        result[key] = entry
        print("%-34s %5d  %s" % (key, n, " ".join(cells)))

    # Convergence and time from rk-infer's stats.
    stats = []
    for b in bins:
        p = os.path.join(args.out, b + ".stats.json")
        if os.path.exists(p):
            with open(p) as f:
                stats.append(json.load(f))
    if stats:
        conv = sum(s["converged"] for s in stats)
        print("rk-infer: %d binaries, %d converged, max rounds %d, infer %.1f s total, widened %d" % (
            len(stats), conv, max(s["rounds"] for s in stats), sum(s["infer_s"] for s in stats),
            sum(s["widened"] for s in stats)))
        result["_convergence"] = {"binaries": len(stats), "converged": conv,
                                  "max_rounds": max(s["rounds"] for s in stats)}

    for m in misses[: args.examples]:
        print("  %s %s\n    truth:  %s\n    revkit: %s" % m)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(result, f, indent=1, sort_keys=True)
    status = 0
    if args.failed:
        print("rk-infer failed on %d binaries, scored as no prototypes: %s" % (len(args.failed), " ".join(args.failed)))
        result["_failed"] = args.failed
    if args.save_baseline:
        base = {k: v for k, v in result.items() if not k.startswith("_") and "/" not in k}
        with open(args.save_baseline, "w") as f:
            json.dump(base, f, indent=1, sort_keys=True)
            f.write("\n")
    if args.baseline:
        with open(args.baseline) as f:
            base = json.load(f)
        for key, levels in base.items():
            for lv in LEVELS:
                want = levels[lv]["revkit"]
                have = result.get(key, {}).get(lv, {}).get("revkit", 0.0)
                if have + 0.2 < want:
                    print("REGRESSION %s %s: %.1f%% < baseline %.1f%%" % (key, lv, have, want))
                    status = 1
    total = "matchable:TOTAL" if args.gate_subset == "matchable" else "TOTAL"
    subset = " (matchable subset, %d functions)" % result[total]["functions"] if args.gate_subset == "matchable" else ""
    if args.target_gain is not None:
        for lv in ("exact", "signature"):
            gain = result[total][lv]["gain"]
            print("phase 4 gate at %s%s: revkit %.1f%% - Ghidra %.1f%% = %+.1f pp (target %+.1f): %s" % (
                lv, subset, result[total][lv]["revkit"], result[total][lv]["ghidra"], gain, args.target_gain,
                "met" if gain >= args.target_gain else "not met"))
    if args.min_gain is not None:
        gain = result[total][args.gate_level]["gain"]
        verdict = "PASS" if gain >= args.min_gain else "FAIL"
        print("gate: revkit - Ghidra at %s%s = %+.1f pp (need %+.1f): %s" % (
            args.gate_level, subset, gain, args.min_gain, verdict))
        if gain < args.min_gain:
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
