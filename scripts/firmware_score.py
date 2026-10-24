#!/usr/bin/env python3
"""Scores revkit's firmware analysis against Ghidra's, per processor, on the
firmware corpus (corpus/firmware; docs/firmware.md).

  firmware_score.py [--corpus out/firmware-corpus] [--ref out/firmware-ref]
                    [--out build/corpus-out/firmware] [--only GLOB]
                    [--baseline-dir corpus/baselines | --save-baseline]

For every raw image, revkit runs from scratch with the layout the manifest
gives (rk-lift --raw --lang --base --raw-entry --region ... --analyze
--decompile), and is compared with Ghidra's analysis of the same image
under the same layout (tools/ghidra-export/ghidra_export.py
--firmware-corpus):

  functions    recall and precision of Ghidra's function entries
  dwarf        recall of the ELF's DWARF functions, for revkit and for Ghidra
               (ground truth independent of either tool), and the share of
               revkit's functions that the DWARF or the symbol table has
               (truth precision)
  listing      instructions both decode, revkit only, Ghidra only (Ghidra's:
               the instructions in its functions; revkit's: its listing)
  C            on every function both have and both decompile: identical
               tokens without comments (ast), with locals renamed (alpha),
               and structure: shape (identifiers and casts abstracted) and
               flow (control-flow skeleton), as scripts/bench_firmware.py
               defines them; c_shape_dwarf also counts as the same a
               function whose C differs because the two disagree about
               whether a callee returns, where DWARF (DW_AT_noreturn) says
               revkit is right

Rates are pooled over each processor's images (counts summed). With
--baseline-dir, exits 1 if a processor's rate drops more than 0.1 point
below corpus/baselines/firmware-<arch>.json; --save-baseline writes them.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools", "refdiff"))
sys.path.insert(0, HERE)
import bench_firmware  # noqa: E402
import cnorm  # noqa: E402
import refformat  # noqa: E402

RATES = ["recall", "precision", "dwarf_recall", "ghidra_dwarf_recall", "truth_precision", "listing_both", "c_ast", "c_alpha", "c_shape",
         "c_flow", "c_shape_dwarf"]
NO_RETURN_CALL = re.compile(r"does not return \*/\s*\n\s*(?:\w+ = )?\(?\*?(\w+)\)?\s*\(")


def no_return_callees(c: str) -> set[int]:
    """Addresses of the default-named callees the C says never return."""
    out = set()
    for name in NO_RETURN_CALL.findall(c):
        m = re.fullmatch(r"FUN_(?:\w+_)?([0-9a-f]{8,16})", name)
        if m:
            out.add(int(m.group(1), 16))
    return out
TOLERANCE = 0.001


def raw_args(image: dict) -> list[str]:
    args = ["--raw", "--lang", image["language"], "--base", image["base"], "--raw-entry", image["entry"]]
    for r in image.get("regions", []):
        args += ["--region", r]
    return args


def run_revkit(rk_lift: str, corpus: str, out: str, image: dict, threads: int, extra: list = ()) -> dict:
    path = os.path.join(out, image["name"] + ".json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    cmd = [rk_lift, *raw_args(image), "--analyze", "--decompile", "-j", str(threads), *extra, "--name", image["path"],
           "-o", path, os.path.join(corpus, image["path"])]
    t = time.monotonic()
    r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        raise RuntimeError("rk-lift failed on %s:\n%s" % (image["name"], r.stderr[-2000:]))
    return {"path": path, "seconds": round(time.monotonic() - t, 2)}


def score_image(corpus: str, ref_dir: str, image: dict, rk_path: str) -> dict:
    ref = refformat.load(os.path.join(ref_dir, image["path"] + ".json"))
    rk = json.load(open(rk_path))
    truth = json.load(open(os.path.join(corpus, image["truth"])))
    G = {int(f["entry"], 16): f for f in ref["functions"]}
    R = {int(f["entry"], 16): f for f in rk["functions"]}
    T = {int(f["address"], 16) for f in truth["dwarf_functions"]}
    NR = {int(a, 16) for a in truth.get("dwarf_noreturn", [])}
    S = T | {int(f["address"], 16) for f in truth.get("symbol_functions", [])}
    common = set(G) & set(R)
    gi = {int(i["addr"], 16) for i in ref["instructions"]}
    ri = {int(i["addr"], 16) for i in rk["instructions"]}
    s = {
        "ghidra": len(G), "revkit": len(R), "common": len(common),
        "dwarf": len(T), "dwarf_revkit": len(T & set(R)), "dwarf_ghidra": len(T & set(G)),
        "truth_revkit": len(S & set(R)), "truth_ghidra": len(S & set(G)),
        "insn_ghidra": len(gi), "insn_revkit": len(ri), "insn_both": len(gi & ri),
        "c_both": 0, "c_ast": 0, "c_alpha": 0, "c_shape": 0, "c_flow": 0, "c_ghidra_only": 0, "c_revkit_only": 0,
        "c_shape_dwarf": 0,
    }
    for a in sorted(common):
        g, r = G[a].get("decompiled_c"), R[a].get("decompiled_c")
        if g is None or r is None:
            s["c_ghidra_only" if r is None and g is not None else "c_revkit_only"] += g is not None or r is not None
            continue
        s["c_both"] += 1
        s["c_ast"] += cnorm.normalize(g, "ast") == cnorm.normalize(r, "ast")
        s["c_alpha"] += cnorm.normalize(g, "alpha") == cnorm.normalize(r, "alpha")
        same = bench_firmware.shape(g) == bench_firmware.shape(r)
        s["c_shape"] += same
        s["c_flow"] += bench_firmware.flow(g) == bench_firmware.flow(r)
        if not same:
            ours, theirs = no_return_callees(r), no_return_callees(g)
            same = bool(ours - theirs) and not (theirs - ours) and (ours - theirs) <= NR
        s["c_shape_dwarf"] += same
    return s


def rates(s: dict) -> dict:
    div = lambda a, b: round(a / b, 6) if b else None
    return {
        "recall": div(s["common"], s["ghidra"]),
        "precision": div(s["common"], s["revkit"]),
        "dwarf_recall": div(s["dwarf_revkit"], s["dwarf"]),
        "ghidra_dwarf_recall": div(s["dwarf_ghidra"], s["dwarf"]),
        "truth_precision": div(s["truth_revkit"], s["revkit"]),
        "ghidra_truth_precision": div(s["truth_ghidra"], s["ghidra"]),
        "listing_both": div(s["insn_both"], s["insn_ghidra"]),
        "c_ast": div(s["c_ast"], s["c_both"]),
        "c_alpha": div(s["c_alpha"], s["c_both"]),
        "c_shape": div(s["c_shape"], s["c_both"]),
        "c_flow": div(s["c_flow"], s["c_both"]),
        "c_shape_dwarf": div(s["c_shape_dwarf"], s["c_both"]),
    }


def pct(v):
    return "   -  " if v is None else "%5.1f%%" % (100 * v)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=os.path.join(ROOT, "out", "firmware-corpus"))
    ap.add_argument("--ref", default=os.path.join(ROOT, "out", "firmware-ref"))
    ap.add_argument("--out", default=os.path.join(ROOT, "build", "corpus-out", "firmware"))
    ap.add_argument("--rk-lift", default=os.path.join(ROOT, "build", "tools", "rk-lift", "rk-lift"))
    ap.add_argument("--only", action="append", default=[], metavar="GLOB", help="images (names) matching GLOB")
    ap.add_argument("-j", "--jobs", type=int, default=int(os.environ.get("RK_CI_JOBS", 16)))
    ap.add_argument("--baseline-dir", help="fail on a drop below <dir>/firmware-<arch>.json")
    ap.add_argument("--save-baseline", metavar="DIR", help="write <dir>/firmware-<arch>.json")
    ap.add_argument("--reuse", action="store_true", help="score revkit outputs already in --out")
    ap.add_argument("--rk-args", default="", help="more rk-lift options (--no-source-shape, say)")
    args = ap.parse_args(argv)

    manifest = json.load(open(os.path.join(args.corpus, "manifest.json")))
    images = [im for im in manifest["images"] if not args.only or any(fnmatch.fnmatch(im["name"], p) for p in args.only)]
    missing = [im["name"] for im in images if not os.path.exists(os.path.join(args.ref, im["path"] + ".json"))]
    if missing:
        print("no Ghidra reference for %s: run ghidra_export.py --firmware-corpus (docs/firmware.md)" %
              ", ".join(missing), file=sys.stderr)
        return 2
    threads = 4
    workers = max(1, args.jobs // threads)
    results = {}

    def one(im):
        path = os.path.join(args.out, im["name"] + ".json")
        secs = None
        if not (args.reuse and os.path.exists(path)):
            secs = run_revkit(args.rk_lift, args.corpus, args.out, im, threads, shlex.split(args.rk_args))["seconds"]
        s = score_image(args.corpus, args.ref, im, path)
        s["seconds"] = secs
        return im, s

    with concurrent.futures.ThreadPoolExecutor(workers) as pool:
        for im, s in pool.map(one, images):
            results[im["name"]] = s

    by_arch: dict[str, dict] = {}
    for im in images:
        s = results[im["name"]]
        agg = by_arch.setdefault(im["arch"], {"images": 0})
        agg["images"] += 1
        for k, v in s.items():
            if k != "seconds":
                agg[k] = agg.get(k, 0) + v

    print("%-38s %6s %6s %7s %7s %7s %7s %7s %7s %7s %7s" % ("image", "ghidra", "revkit", "recall", "prec",
                                                         "dwarf", "g-dwarf", "listing", "c_ast", "c_shape",
                                                         "c_flow"))
    for im in images:
        s = results[im["name"]]
        r = rates(s)
        print("%-38s %6d %6d %s %s %s %s %s %s %s %s" % (
            im["name"], s["ghidra"], s["revkit"], pct(r["recall"]), pct(r["precision"]), pct(r["dwarf_recall"]),
            pct(r["ghidra_dwarf_recall"]), pct(r["listing_both"]), pct(r["c_ast"]), pct(r["c_shape"]),
            pct(r["c_flow"])))
    print()
    print("%-10s %3s %6s %6s %7s %7s %7s %7s %7s %7s %7s %7s %7s %7s %7s %7s" % (
        "arch", "img", "ghidra", "revkit", "recall", "prec", "dwarf", "g-dwarf", "t-prec", "g-tprec", "listing",
        "c_ast", "c_alpha", "c_shape", "shape*", "c_flow"))
    for arch, agg in sorted(by_arch.items()):
        r = rates(agg)
        print("%-10s %3d %6d %6d %s %s %s %s %s %s %s %s" % (
            arch, agg["images"], agg["ghidra"], agg["revkit"], pct(r["recall"]), pct(r["precision"]),
            pct(r["dwarf_recall"]), pct(r["ghidra_dwarf_recall"]), pct(r["truth_precision"]),
            pct(r["ghidra_truth_precision"]), pct(r["listing_both"]), pct(r["c_ast"])) + " %s %s %s %s" % (
            pct(r["c_alpha"]), pct(r["c_shape"]), pct(r["c_shape_dwarf"]), pct(r["c_flow"])))
    print("(shape*: c_shape, counting as the same C that differs only where DWARF says revkit is right that a "
          "callee never returns)")

    os.makedirs(args.out, exist_ok=True)
    report = {"images": results, "arches": {a: {"counts": agg, "rates": rates(agg)} for a, agg in by_arch.items()}}
    with open(os.path.join(args.out, "report.json"), "w") as f:
        json.dump(report, f, indent=1, sort_keys=True)

    status = 0
    for arch, agg in sorted(by_arch.items()):
        r = rates(agg)
        doc = {"arch": arch, "images": sorted(im["name"] for im in images if im["arch"] == arch),
               "counts": {k: v for k, v in agg.items() if k != "images"}, "rates": r}
        if args.save_baseline:
            os.makedirs(args.save_baseline, exist_ok=True)
            with open(os.path.join(args.save_baseline, "firmware-%s.json" % arch), "w") as f:
                json.dump(doc, f, indent=1, sort_keys=True)
                f.write("\n")
        elif args.baseline_dir:
            path = os.path.join(args.baseline_dir, "firmware-%s.json" % arch)
            if not os.path.exists(path):
                print("%s: no baseline %s" % (arch, path), file=sys.stderr)
                status = 1
                continue
            base = json.load(open(path))
            for k in RATES:
                b, v = base["rates"].get(k), r.get(k)
                if b is None or k.startswith("ghidra_"):
                    continue
                if v is None or v < b - TOLERANCE:
                    print("REGRESSION %s %s: %s -> %s" % (arch, k, pct(b), pct(v)), file=sys.stderr)
                    status = 1
                elif v > b + TOLERANCE:
                    print("improved %s %s: %s -> %s (save the baseline)" % (arch, k, pct(b), pct(v)))
    if args.save_baseline:
        print("baselines written to %s" % args.save_baseline)
    return status


if __name__ == "__main__":
    sys.exit(main())
