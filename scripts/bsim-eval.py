#!/usr/bin/env python3
"""BSim database evaluation (docs/bsim.md, "Evaluation").

A reference database holds one build of each program (gcc -O2 with debug
info, x86-64, from out/corpus-diff); each query is a *stripped* build that
differs by compiler, optimization level, architecture or version. Every
function of the query is searched against the whole database (the other
programs are distractors) and its top-1 match is compared with the truth:
the name its debug twin gives the function at the same entry.

  bsim-eval.py [--work DIR] [--rk-bsim PATH] [-j N] [--lsh] [--only REGEX]

Counted: query functions with a non-default true name that the reference
build also has (once). A function's top-1 is correct when its name is the
true name; strictly correct when, besides, no other name ties it (equal
similarity: tiny functions often have identical vectors). At a similarity
threshold t (and, for "conf", BSim's confidence >= 10 too):
  recall@t    = correct with similarity >= t / counted
  precision@t = correct with similarity >= t / counted with a top-1 >= t
(precision over the functions that have a counterpart: those without one
are reported apart, as false hits above t). Prints a table and writes
DIR/eval.json.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.environ.get("RK_CORPUS_DIFF", os.path.join(ROOT, "out", "corpus-diff"))

REFERENCE = [("elf-x86_64", "gcc-O2", "zlib-1.3.1"), ("elf-x86_64", "gcc-O2", "lua-5.4.6"),
             ("elf-x86_64", "gcc-O2", "cjson-1.7.18")]
QUERIES = [
    # (label, arch, config, program, reference program)
    ("clang -O2", "elf-x86_64", "clang-O2", "zlib-1.3.1", "zlib-1.3.1"),
    ("clang -O2", "elf-x86_64", "clang-O2", "lua-5.4.6", "lua-5.4.6"),
    ("clang -O2", "elf-x86_64", "clang-O2", "cjson-1.7.18", "cjson-1.7.18"),
    ("gcc -O0", "elf-x86_64", "gcc-O0", "zlib-1.3.1", "zlib-1.3.1"),
    ("gcc -O0", "elf-x86_64", "gcc-O0", "lua-5.4.6", "lua-5.4.6"),
    ("gcc -O0", "elf-x86_64", "gcc-O0", "cjson-1.7.18", "cjson-1.7.18"),
    ("aarch64 gcc -O2", "elf-aarch64", "gcc-O2", "zlib-1.3.1", "zlib-1.3.1"),
    ("aarch64 gcc -O2", "elf-aarch64", "gcc-O2", "lua-5.4.6", "lua-5.4.6"),
    ("aarch64 gcc -O2", "elf-aarch64", "gcc-O2", "cjson-1.7.18", "cjson-1.7.18"),
    ("older version", "elf-x86_64", "gcc-O2", "zlib-1.3", "zlib-1.3.1"),
    ("older version", "elf-x86_64", "gcc-O2", "lua-5.4.5", "lua-5.4.6"),
    ("older version", "elf-x86_64", "gcc-O2", "cjson-1.7.17", "cjson-1.7.18"),
]
THRESHOLDS = [0.0, 0.5, 0.7, 0.9]
DEFAULT = re.compile(r"^(FUN_|thunk_FUN_|LAB_|sub_)[0-9a-fA-F]+$")


def run(cmd, **kw):
    t = time.monotonic()
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        sys.exit("failed (%d): %s\n%s" % (r.returncode, " ".join(cmd), r.stderr[-2000:]))
    return r.stdout, time.monotonic() - t


def path(arch, config, kind, prog):
    return os.path.join(CORPUS, arch, config, kind, prog)


def names_by_entry(rk, db):
    out, _ = run([rk, "list", db, "--json"])
    exes = json.loads(out)
    assert len(exes) == 1, exes
    fns, _ = run([rk, "functions", db, exes[0]["id"], "--json"])
    return {int(f["entry"], 16): f["name"] for f in json.loads(fns)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work", default=os.path.join(ROOT, "build", "bsim-eval"))
    ap.add_argument("--rk-bsim", default=os.path.join(ROOT, "build", "tools", "rk-bsim", "rk-bsim"))
    ap.add_argument("-j", type=int, default=2)
    ap.add_argument("--lsh", action="store_true", help="only the LSH index's candidates (default: score every function)")
    ap.add_argument("--only", default="", help="queries whose label or program match")
    args = ap.parse_args()
    rk = args.rk_bsim
    os.makedirs(args.work, exist_ok=True)
    j = ["-j", str(args.j)]

    # The reference database, and every reference function's name by program.
    ref = os.path.join(args.work, "reference.rkbsim")
    if not os.path.isdir(ref):
        run([rk, "create", ref, "--template", "64", "--description", "gcc -O2 debug builds"])
        for arch, config, prog in REFERENCE:
            out, secs = run([rk, "ingest", ref, path(arch, config, "debug", prog), "--category", "program=" + prog] + j)
            print("ingested %-16s %s (%.0f s)" % (prog, out.strip(), secs), file=sys.stderr)
    exes = {e["categories"].get("program"): e for e in json.loads(run([rk, "list", ref, "--json"])[0])}
    ref_names = {}
    for prog, e in exes.items():
        fns = json.loads(run([rk, "functions", ref, e["id"], "--json"])[0])
        counts = {}
        for f in fns:
            counts[f["name"]] = counts.get(f["name"], 0) + 1
        ref_names[prog] = {n for n, c in counts.items() if c == 1 and not DEFAULT.match(n)}

    rows = []
    for label, arch, config, prog, ref_prog in QUERIES:
        if args.only and not re.search(args.only, label + " " + prog):
            continue
        stripped, debug = path(arch, config, "stripped", prog), path(arch, config, "debug", prog)
        if not (os.path.exists(stripped) and os.path.exists(debug)):
            print("skipped %s %s: not in the corpus" % (label, prog), file=sys.stderr)
            continue
        # The truth: the debug twin's names by entry.
        truth_db = os.path.join(args.work, "truth-%s-%s-%s.rkbsim" % (arch, config, prog))
        if not os.path.isdir(truth_db):
            run([rk, "create", truth_db, "--template", "64"])
            run([rk, "ingest", truth_db, debug] + j)
        truth = names_by_entry(rk, truth_db)
        query = [rk, "query", ref, stripped, "--json", "--max", "2", "--min-similarity", "0"] + j
        query.append("--index-only" if args.lsh else "--exhaustive")
        out, secs = run(query)
        res = json.loads(out)
        counted = correct = strict = 0
        at = {t: [0, 0, 0] for t in THRESHOLDS}  # correct, counted with top-1 >= t, no-counterpart with top-1 >= t
        conf = [0, 0]  # similarity >= 0.7 and confidence >= 10: correct, with such a top-1
        searched = 0
        for q in res["results"]:
            if q.get("skipped"):
                continue
            searched += 1
            name = truth.get(int(q["entry"], 16))
            top = q["matches"][0] if q["matches"] else None
            sim = top["similarity"] if top else -1
            if not name or DEFAULT.match(name):
                continue
            if name not in ref_names[ref_prog]:
                for t in THRESHOLDS:
                    if sim >= t:
                        at[t][2] += 1
                continue
            counted += 1
            ok = top is not None and top["name"] == name
            correct += ok
            tied = len(q["matches"]) > 1 and q["matches"][1]["similarity"] == sim and q["matches"][1]["name"] != name
            strict += ok and not tied
            if top is not None and sim >= 0.7 and top["confidence"] >= 10:
                conf[1] += 1
                conf[0] += ok
            for t in THRESHOLDS:
                if sim >= t:
                    at[t][1] += 1
                    at[t][0] += ok
        row = {"label": label, "program": prog, "reference": ref_prog, "searched": searched, "counted": counted,
               "seconds": round(secs, 1), "database_functions": res["total"], "scored": res["scored"],
               "strict_top1": round(100.0 * strict / counted, 1) if counted else None,
               "strict": strict, "conf_correct": conf[0], "conf_hits": conf[1]}
        for t in THRESHOLDS:
            c, n, extra = at[t]
            row["recall@%.1f" % t] = round(100.0 * c / counted, 1) if counted else None
            row["precision@%.1f" % t] = round(100.0 * c / n, 1) if n else None
            row["no_counterpart_hits@%.1f" % t] = extra
        rows.append(row)
        print("%-16s %-13s top-1 %5.1f%% of %4d | @0.7 precision %5s recall %5s | %.0f s" % (
            label, prog, row["recall@0.0"] or 0, counted, row["precision@0.7"], row["recall@0.7"], secs),
            file=sys.stderr)

    # Per label, function-weighted.
    summary = {}
    for r in rows:
        s = summary.setdefault(r["label"], {"counted": 0, **{"c%.1f" % t: 0 for t in THRESHOLDS},
                                            **{"n%.1f" % t: 0 for t in THRESHOLDS}})
        s["counted"] += r["counted"]
        for t in THRESHOLDS:
            if r["recall@%.1f" % t] is not None:
                c = round(r["recall@%.1f" % t] * r["counted"] / 100.0)
                s["c%.1f" % t] += c
                p = r["precision@%.1f" % t]
                s["n%.1f" % t] += round(c * 100.0 / p) if p else 0
    for r in rows:
        s = summary[r["label"]]
        s["strict"] = s.get("strict", 0) + r["strict"]
        s["conf_correct"] = s.get("conf_correct", 0) + r["conf_correct"]
        s["conf_hits"] = s.get("conf_hits", 0) + r["conf_hits"]
    print("| query builds | functions | top-1 (strict) | precision / recall @0.5 | @0.7 | @0.9 | @0.7, confidence >= 10 |")
    print("| --- | ---: | ---: | --- | --- | --- | --- |")
    for label, s in summary.items():
        def pr(t):
            c, n = s["c%.1f" % t], s["n%.1f" % t]
            return "%.1f%% / %.1f%%" % (100.0 * c / n if n else 0, 100.0 * c / s["counted"] if s["counted"] else 0)
        n = s["counted"] or 1
        print("| %s | %d | %.1f%% (%.1f%%) | %s | %s | %s | %.1f%% / %.1f%% |" % (
            label, s["counted"], 100.0 * s["c0.0"] / n, 100.0 * s["strict"] / n, pr(0.5), pr(0.7), pr(0.9),
            100.0 * s["conf_correct"] / s["conf_hits"] if s["conf_hits"] else 0, 100.0 * s["conf_correct"] / n))
    with open(os.path.join(args.work, "eval%s.json" % ("-lsh" if args.lsh else "")), "w") as f:
        json.dump({"rows": rows, "summary": summary}, f, indent=1)


if __name__ == "__main__":
    main()
