#!/usr/bin/env python3
"""Binary-diffing evaluation (docs/diff.md, design docs/diff/design.md section 5).

Matches pairs of stripped binaries with rk-diff and scores the matches
against debug-info truth: a function's identity is its DWARF name (names
that occur more than once on a side are left out), taken from the debug
twin of each stripped binary (rk-debuginfo) or, for firmware, from the
image's truth file.

Families:
  a   adjacent source versions (out/corpus-diff: zlib, Lua, cJSON, 3 versions
      each), per config: x86-64 gcc -O2, x86-64 clang -O2, AArch64 gcc -O2
  b   -O0 against -O2 (x86-64 gcc, each program's newest version)       [information]
  c   gcc against clang (x86-64 -O2, newest versions)                   [information]
  e   the firmware corpus, same processor: fwkit -O2 against -Os, and
      U-Boot built for two boards (out/firmware-corpus)                 [baseline]
  d   x86-64 against AArch64 (gcc -O2, newest versions)                 [information]
  f   the firmware corpus across processors: fwkit at -O2, every pair
      of the seven processors                                           [information]

--similarity bsim runs rk-diff with the BSim tier over the residue (F5).

Metrics per family (summed over its pairs): precision and recall of all
matches and of the auto-applied ones (confidence >= 0.95), by tier, by
size bucket (the A function's instructions), by change kind (unchanged:
equal masked bytes; modified; and for functions only one side has, how
many were matched anyway), and ported-name accuracy (a name ported from A
over a default name in B is right iff B's truth has that name).

A pair counts toward precision when either function has a truth name
(PLT stubs and CRT code have none: unscored); it is correct when both
have the same one. Recall's denominator is the names both sides have,
among the functions discovery found on both.

  scripts/diff_eval.py [--families a,b,c,e] [-j N] [--out build/corpus-out/diff]
                       [--baseline corpus/baselines/diff.json | --save-baseline corpus/baselines/diff.json]
                       [--gate] [--heldout]

--gate fails unless family (a)'s auto-applied matches have precision >= 0.99
and recall >= 0.9. --baseline fails when a family's figures drop more than
0.5 points below the saved ones. --heldout scores the held-out families
(docs/heldout.md) instead: out/corpus-diff-heldout, summary rates only.
"""

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUTO = 0.95
BUCKETS = [(0, 9, "<10"), (10, 29, "10-29"), (30, 99, "30-99"), (100, 1 << 60, ">=100")]
PROGRAMS = {"zlib": ["1.2.13", "1.3", "1.3.1"], "lua": ["5.4.5", "5.4.6", "5.4.7"], "cjson": ["1.7.16", "1.7.17", "1.7.18"]}
HELDOUT_PROGRAMS = {"bzip2": ["1.0.6", "1.0.7", "1.0.8"], "mujs": ["1.3.4", "1.3.5"], "sqlite": ["3.46.0", "3.46.1"],
                    "mbedtls": ["3.6.1", "3.6.2"]}
RENAMES = json.load(open(os.path.join(ROOT, "corpus/diff-renames.json")))
A_CONFIGS = ["elf-x86_64/gcc-O2", "elf-x86_64/clang-O2", "elf-aarch64/gcc-O2"]
FW_PAIRS = [
    ("cortexm", "fwkit-cortexm3-O2", "fwkit-cortexm4-Os"),
    ("m68k", "fwkit-m68k-O2", "fwkit-m68k-Os"),
    ("mips", "fwkit-mips-O2", "fwkit-mipsel-Os"),
    ("ppc", "fwkit-ppc-O2", "fwkit-ppc-Os"),
    ("sh4", "fwkit-sh4-O2", "fwkit-sh4-Os"),
    ("xtensa", "fwkit-esp32-O2", "fwkit-esp32-Os"),
    ("xtensa", "fwkit-lx106-O2", "fwkit-lx106-Os"),
    ("cortexm", "uboot-stm32f429-discovery", "uboot-stm32f746-disco"),
    ("m68k", "uboot-M5208EVBE", "uboot-M5373EVB"),
    ("mips", "uboot-malta", "uboot-maltael"),
    ("ppc", "uboot-MPC837XERDB", "uboot-MCR3000"),
]


def pairs_for(families, args):
    out = []
    progs = HELDOUT_PROGRAMS if args.heldout else PROGRAMS
    corpus = args.corpus_diff
    for fam in families:
        if fam == "a":
            for cfg in A_CONFIGS:
                for prog, versions in sorted(progs.items()):
                    for v1, v2 in zip(versions, versions[1:]):
                        out.append({"family": "a", "group": cfg, "name": "%s %s %s->%s" % (cfg, prog, v1, v2),
                                    "a": "%s/%s/stripped/%s-%s" % (corpus, cfg, prog, v1),
                                    "b": "%s/%s/stripped/%s-%s" % (corpus, cfg, prog, v2),
                                    "truth_a": "%s/%s/debug/%s-%s" % (corpus, cfg, prog, v1),
                                    "truth_b": "%s/%s/debug/%s-%s" % (corpus, cfg, prog, v2),
                                    "renames": RENAMES.get(prog, {}).get("%s->%s" % (v1, v2), {})})
        elif fam in ("b", "c"):
            for prog, versions in sorted(progs.items()):
                v = versions[-1]
                ca, cb = ("elf-x86_64/gcc-O0", "elf-x86_64/gcc-O2") if fam == "b" else ("elf-x86_64/gcc-O2", "elf-x86_64/clang-O2")
                out.append({"family": fam, "group": "%s vs %s" % (ca, cb), "name": "%s %s-%s %s vs %s" % (fam, prog, v, ca, cb),
                            "a": "%s/%s/stripped/%s-%s" % (corpus, ca, prog, v),
                            "b": "%s/%s/stripped/%s-%s" % (corpus, cb, prog, v),
                            "truth_a": "%s/%s/debug/%s-%s" % (corpus, ca, prog, v),
                            "truth_b": "%s/%s/debug/%s-%s" % (corpus, cb, prog, v)})
        elif fam == "d":
            for prog, versions in sorted(progs.items()):
                v = versions[-1]
                ca, cb = "elf-x86_64/gcc-O2", "elf-aarch64/gcc-O2"
                out.append({"family": fam, "group": "%s vs %s" % (ca, cb), "name": "%s %s-%s %s vs %s" % (fam, prog, v, ca, cb),
                            "a": "%s/%s/stripped/%s-%s" % (corpus, ca, prog, v),
                            "b": "%s/%s/stripped/%s-%s" % (corpus, cb, prog, v),
                            "truth_a": "%s/%s/debug/%s-%s" % (corpus, ca, prog, v),
                            "truth_b": "%s/%s/debug/%s-%s" % (corpus, cb, prog, v)})
        elif fam == "f" and not args.heldout:
            manifest = json.load(open(os.path.join(args.firmware, "manifest.json")))
            fw = sorted((img for img in manifest["images"] if img.get("project") == "fwkit" and img.get("opt") == "O2"),
                        key=lambda i: i["name"])
            for x in range(len(fw)):
                for y in range(x + 1, len(fw)):
                    ia, ib = fw[x], fw[y]
                    out.append({"family": "f", "group": "fwkit-O2", "name": "f %s vs %s" % (ia["name"], ib["name"]),
                                "a": os.path.join(args.firmware, ia["path"]), "b": os.path.join(args.firmware, ib["path"]),
                                "raw_a": raw_spec(ia), "raw_b": raw_spec(ib),
                                "fw_truth_a": os.path.join(args.firmware, ia["truth"]),
                                "fw_truth_b": os.path.join(args.firmware, ib["truth"])})
        elif fam == "e" and not args.heldout:
            manifest = json.load(open(os.path.join(args.firmware, "manifest.json")))
            images = {img["name"]: img for img in manifest["images"]}
            for arch, na, nb in FW_PAIRS:
                ia, ib = images.get(arch + "/" + na), images.get(arch + "/" + nb)
                if not ia or not ib:
                    continue
                out.append({"family": "e", "group": arch, "name": "e %s %s vs %s" % (arch, na, nb),
                            "a": os.path.join(args.firmware, ia["path"]), "b": os.path.join(args.firmware, ib["path"]),
                            "raw_a": raw_spec(ia), "raw_b": raw_spec(ib),
                            "fw_truth_a": os.path.join(args.firmware, ia["truth"]),
                            "fw_truth_b": os.path.join(args.firmware, ib["truth"])})
    return out


def raw_spec(img):
    parts = ["lang=" + img["language"], "base=" + img["base"].removeprefix("0x"), "entry=" + img["entry"].removeprefix("0x")]
    parts += ["region=" + r for r in img.get("regions", [])]
    return ",".join(parts)


def truth_of(binary, args):
    """entry -> name from rk-debuginfo on a debug binary (cached under --out)."""
    cache = truth_file(binary, args)
    if not os.path.exists(cache) or os.path.getmtime(cache) < os.path.getmtime(binary):
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        text = subprocess.run([args.rk_debuginfo, binary], check=True, capture_output=True, text=True).stdout
        with open(cache, "w") as f:
            f.write(text)
    funcs = json.load(open(cache))["functions"]
    return {int(f["entry"], 16): f["name"] for f in funcs}


def fw_truth(path):
    t = json.load(open(path))
    return {int(f["address"], 16) & ~1: f["name"] for f in t["dwarf_functions"]}


def truth_file(binary, args):
    return os.path.join(args.out, "truth", os.path.relpath(binary, ROOT).replace("/", "_") + ".json")


def run_pair(p, args):
    out = os.path.join(args.out, "pairs", p["name"].replace("/", "_").replace(" ", "_").replace(">", "") + ".json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    cmd = [args.rk_diff, "-j", str(args.threads), "--json", out]
    if args.similarity:
        cmd += ["--similarity", args.similarity]
    if args.direct:
        cmd.append("--direct")
    else:
        # A's truth names, then a port of names over the auto-applicable matches.
        cmd += ["--names-a", p["fw_truth_a"] if p.get("fw_truth_a") else truth_file(p["truth_a"], args)]
    if p.get("raw_a"):
        cmd += ["--raw-a", p["raw_a"], "--raw-b", p["raw_b"]]
    cmd += [p["a"], p["b"]]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("%s: %s" % (p["name"], r.stderr.strip()))
    return out


def unique(names):
    count = Counter(names.values())
    return {a: n for a, n in names.items() if count[n] == 1}, {n for n, c in count.items() if c > 1}


def new_stats():
    return {"pairs": 0, "scored": 0, "correct": 0, "common": 0, "auto_scored": 0, "auto_correct": 0,
            "by_tier": defaultdict(lambda: [0, 0, 0]),  # tier -> [scored, correct, auto_correct]
            "by_bucket": defaultdict(lambda: [0, 0, 0, 0]),  # bucket -> [common, correct, scored, wrong]
            "by_change": defaultdict(lambda: [0, 0]),  # kind -> [functions, matched correctly (or matched at all for added/removed)]
            "ported": 0, "ported_right": 0, "functions_a": 0, "functions_b": 0, "ms": 0.0}


def bucket(n):
    for lo, hi, label in BUCKETS:
        if lo <= n <= hi:
            return label
    return BUCKETS[-1][2]


def score(p, result, args, s):
    if p.get("fw_truth_a"):
        ta, tb = fw_truth(p["fw_truth_a"]), fw_truth(p["fw_truth_b"])
    else:
        ta, tb = truth_of(p["truth_a"], args), truth_of(p["truth_b"], args)
    tb_raw = dict(tb)
    # Source-level renames between versions: the old function goes by its new name.
    renames = p.get("renames", {})
    ta = {a: renames.get(n, n) for a, n in ta.items()}
    if renames:
        renamed = set(renames.values())
        # A new function now has the old name (lua_resetthread's wrapper): it is new.
        tb = {b: (n + "@new" if n in renames and n not in renamed else n) for b, n in tb.items()}
    ta, dup_a = unique(ta)
    tb, dup_b = unique(tb)
    dup = dup_a | dup_b
    ta = {a: n for a, n in ta.items() if n not in dup}
    tb = {b: n for b, n in tb.items() if n not in dup}
    funcs_a = {int(k, 16) for k in result["instructions_a"]}
    sizes = {int(k, 16): v for k, v in result["instructions_a"].items()}
    matched_b = {int(m["b"], 16) for m in result["matches"]}
    funcs_b = matched_b | {int(x, 16) for x in result["unmatched_b"]}
    names_a = {n: a for a, n in ta.items() if a in funcs_a}
    names_b = {n: b for b, n in tb.items() if b in funcs_b}
    common = set(names_a) & set(names_b)
    s["pairs"] += 1
    s["common"] += len(common)
    s["functions_a"] += result["functions_a"]
    s["functions_b"] += result["functions_b"]
    s["ms"] += result["timing_ms"]["features_and_match"]
    matched_by_name = {}
    unchanged_of = {}
    for m in result["matches"]:
        a, b = int(m["a"], 16), int(m["b"], 16)
        na, nb = ta.get(a), tb.get(b)
        if na is None and nb is None:
            continue
        ok = na is not None and na == nb
        auto = m["confidence"] >= AUTO
        s["scored"] += 1
        s["correct"] += ok
        t = s["by_tier"][m["tier"] + "/" + m["relation"]]
        t[0] += 1
        t[1] += ok
        if auto:
            s["auto_scored"] += 1
            s["auto_correct"] += ok
            t[2] += ok
            # Porting (--direct: as ApplyMarkup would): A's name over B's default name.
            if na is not None and "ported" not in result:
                s["ported"] += 1
                s["ported_right"] += ok
        if na is not None:
            bk = s["by_bucket"][bucket(sizes.get(a, 0))]
            bk[2] += 1
            bk[3] += not ok
        if ok:
            matched_by_name[na] = auto
            unchanged_of[na] = m["unchanged"]
    # Names ApplyMarkup ported (the backend path): right iff B's truth has that name.
    known_a = set(ta.values())
    for b, name in result.get("ported", {}).items():
        if name not in known_a:
            continue
        s["ported"] += 1
        s["ported_right"] += tb_raw.get(int(b, 16)) == name
    for n in common:
        bk = s["by_bucket"][bucket(sizes.get(names_a[n], 0))]
        bk[0] += 1
        bk[1] += n in matched_by_name
    # Change kinds: the truth pairs' masked-byte equality is known where they
    # were matched; an unmatched common function counts as modified.
    for n in common:
        kind = "unchanged" if unchanged_of.get(n) else "modified"
        c = s["by_change"][kind]
        c[0] += 1
        c[1] += n in matched_by_name
    matched_a = {int(m["a"], 16) for m in result["matches"]}
    for n, a in names_a.items():
        if n not in names_b and n not in dup:
            c = s["by_change"]["removed"]
            c[0] += 1
            c[1] += a in matched_a
    for n, b in names_b.items():
        if n not in names_a and n not in dup:
            c = s["by_change"]["added"]
            c[0] += 1
            c[1] += b in matched_b


def pct(x, y):
    return 100.0 * x / y if y else float("nan")


def summarize(s):
    return {
        "pairs": s["pairs"], "common": s["common"], "matches_scored": s["scored"],
        "precision": round(pct(s["correct"], s["scored"]), 2), "recall": round(pct(s["correct"], s["common"]), 2),
        "auto_precision": round(pct(s["auto_correct"], s["auto_scored"]), 2),
        "auto_recall": round(pct(s["auto_correct"], s["common"]), 2),
        "ported_name_accuracy": round(pct(s["ported_right"], s["ported"]), 2), "ported_names": s["ported"],
        "f1": round(2 * pct(s["correct"], s["scored"]) * pct(s["correct"], s["common"]) /
                    (pct(s["correct"], s["scored"]) + pct(s["correct"], s["common"])), 2) if s["correct"] else 0.0,
        "by_tier": {k: {"scored": v[0], "precision": round(pct(v[1], v[0]), 2), "correct": v[1], "auto_correct": v[2]}
                    for k, v in sorted(s["by_tier"].items())},
        "by_bucket": {k: {"common": v[0], "recall": round(pct(v[1], v[0]), 2), "scored": v[2],
                          "precision": round(pct(v[2] - v[3], v[2]), 2)} for k, v in sorted(s["by_bucket"].items())},
        "by_change": {k: {"functions": v[0], ("matched" if k in ("added", "removed") else "recall"):
                          (v[1] if k in ("added", "removed") else round(pct(v[1], v[0]), 2))}
                      for k, v in sorted(s["by_change"].items())},
        "functions": [s["functions_a"], s["functions_b"]],
        "features_and_match_ms": round(s["ms"], 1),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--families", default="a,b,c,e")
    ap.add_argument("--similarity", default="", help="rk-diff --similarity (bsim: the F5 residue tier)")
    ap.add_argument("-j", "--jobs", type=int, default=4)
    ap.add_argument("--threads", type=int, default=2, help="rk-diff threads per pair")
    ap.add_argument("--out", default=os.path.join(ROOT, "build/corpus-out/diff"))
    ap.add_argument("--corpus-diff", default=os.path.join(ROOT, "out/corpus-diff"))
    ap.add_argument("--firmware", default=os.path.join(ROOT, "out/firmware-corpus"))
    ap.add_argument("--rk-diff", default=os.path.join(ROOT, "build/tools/rk-diff/rk-diff"))
    ap.add_argument("--rk-debuginfo", default=os.path.join(ROOT, "build/tools/rk-debuginfo/rk-debuginfo"))
    ap.add_argument("--baseline")
    ap.add_argument("--save-baseline")
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--heldout", action="store_true")
    ap.add_argument("--per-pair", action="store_true", help="also print each pair's figures (tuning corpus only)")
    ap.add_argument("--direct", action="store_true", help="rk-diff --direct: no backend (no real port of names)")
    args = ap.parse_args()
    if args.heldout:
        args.corpus_diff = args.corpus_diff.replace("corpus-diff", "corpus-diff-heldout")
        args.out = os.path.join(args.out, "heldout")
        if args.per_pair:
            sys.exit("--per-pair is not allowed on the held-out set (docs/heldout.md)")
    families = [f for f in args.families.split(",") if f]
    pairs = pairs_for(families, args)
    missing = [p for p in pairs if not os.path.exists(p["a"]) or not os.path.exists(p["b"])]
    if missing:
        sys.exit("missing inputs (scripts/build-corpus.sh --diff; scripts/build-firmware-corpus.sh): " + missing[0]["a"])
    # Truth first: --names-a reads A's.
    for p in pairs:
        if not p.get("fw_truth_a"):
            truth_of(p["truth_a"], args)
            truth_of(p["truth_b"], args)
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(run_pair, p, args): p["name"] for p in pairs}
        for fut in concurrent.futures.as_completed(futs):
            results[futs[fut]] = fut.result()
    stats = defaultdict(new_stats)
    per_pair = {}
    for p in pairs:
        result = json.load(open(results[p["name"]]))
        score(p, result, args, stats[p["family"]])
        score(p, result, args, stats[p["family"] + " " + p["group"]])
        if args.per_pair:
            one = new_stats()
            score(p, result, args, one)
            per_pair[p["name"]] = summarize(one)
    summary = {k: summarize(v) for k, v in sorted(stats.items())}
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "summary.json"), "w") as f:
        json.dump({"families": summary, "pairs": per_pair}, f, indent=1)

    print("%-34s %5s %6s | %6s %6s %6s | %6s %6s | %6s" % ("family", "pairs", "common", "prec", "recall", "F1",
                                                           "auto-P", "auto-R", "names"))
    for k, v in summary.items():
        print("%-34s %5d %6d | %6.2f %6.2f %6.2f | %6.2f %6.2f | %6.2f" % (
            k, v["pairs"], v["common"], v["precision"], v["recall"], v["f1"], v["auto_precision"], v["auto_recall"],
            v["ported_name_accuracy"]))
    for fam in families:
        if fam not in summary:
            continue
        v = summary[fam]
        print("\nfamily %s by tier (scored, precision, auto-correct):" % fam)
        for t, x in v["by_tier"].items():
            print("  %-22s %6d %7.2f %6d" % (t, x["scored"], x["precision"], x["auto_correct"]))
        print("family %s by size (common, recall; scored, precision):" % fam)
        for b, x in v["by_bucket"].items():
            print("  %-8s %6d %7.2f %6d %7.2f" % (b, x["common"], x["recall"], x["scored"], x["precision"]))
        print("family %s by change kind:" % fam, json.dumps(v["by_change"]))
    if args.per_pair:
        print()
        for name, v in per_pair.items():
            print("%-60s P %6.2f R %6.2f autoP %6.2f autoR %6.2f" % (name, v["precision"], v["recall"],
                                                                      v["auto_precision"], v["auto_recall"]))

    status = 0
    if args.gate and "a" in summary:
        a = summary["a"]
        if not (a["auto_precision"] >= 99.0 and a["auto_recall"] >= 90.0):
            print("GATE FAILED: family (a) auto-applied precision %.2f (>= 99), recall %.2f (>= 90)" %
                  (a["auto_precision"], a["auto_recall"]), file=sys.stderr)
            status = 1
        else:
            print("gate: family (a) auto-applied precision %.2f >= 99, recall %.2f >= 90" %
                  (a["auto_precision"], a["auto_recall"]))
    keys = ["precision", "recall", "auto_precision", "auto_recall", "ported_name_accuracy"]
    if args.save_baseline:
        base = {k: {m: v[m] for m in keys} for k, v in summary.items() if " " not in k}
        with open(args.save_baseline, "w") as f:
            json.dump(base, f, indent=1, sort_keys=True)
            f.write("\n")
        print("saved", args.save_baseline)
    elif args.baseline:
        base = json.load(open(args.baseline))
        for fam, want in sorted(base.items()):
            if fam not in summary:
                continue
            for m in keys:
                got = summary[fam][m]
                if want[m] == want[m] and got == got and got < want[m] - 0.5:
                    print("BASELINE: family %s %s %.2f < %.2f" % (fam, m, got, want[m]), file=sys.stderr)
                    status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
