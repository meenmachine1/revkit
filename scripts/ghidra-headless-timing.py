#!/usr/bin/env python3
"""Time Ghidra's analyzeHeadless on the corpus: import, auto-analysis and
decompiling every function, as the reference export does it.

Binaries are split into P groups of similar total size; each group runs in
one analyzeHeadless process (one JVM, binaries one after another), and the P
processes run at once. The post-script decompiles every function with
DecompileOptions.grabFromProgram and the "decompile" style and records how
long that took (tools/ghidra-export/ghidra_scripts).

  scripts/ghidra-headless-timing.py [-P 10] [--stats out/ghidra-headless-timing.json]

Prints the wall-clock time of the whole run and, from the scripts' records,
the time each binary spent in analysis and in decompilation.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "tools", "ghidra-export", "ghidra_scripts")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=os.path.join(ROOT, "out", "corpus"))
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR",
                                                       os.path.expanduser("~/ghidra/ghidra_12.1.4_PUBLIC")))
    ap.add_argument("-P", "--procs", type=int, default=10, help="analyzeHeadless processes at once (default 10)")
    ap.add_argument("--heap", default="3G", help="MAXMEM per process (default 3G, as the reference export)")
    ap.add_argument("--stats", help="write timings here as JSON")
    ap.add_argument("--only", action="append", default=[], metavar="GLOB", help="time only these corpus paths")
    args = ap.parse_args()

    with open(os.path.join(args.corpus, "manifest.json")) as f:
        rels = [b["path"] for b in json.load(f)["binaries"]]
    if args.only:
        import fnmatch
        rels = [r for r in rels if any(fnmatch.fnmatch(r, g) for g in args.only)]
    # Largest first, each to the least loaded group.
    rels.sort(key=lambda r: -os.path.getsize(os.path.join(args.corpus, r)))
    groups = [[] for _ in range(min(args.procs, len(rels)))]
    load = [0] * len(groups)
    for rel in rels:
        i = load.index(min(load))
        groups[i].append(rel)
        load[i] += os.path.getsize(os.path.join(args.corpus, rel))

    tmp = tempfile.mkdtemp(prefix="revkit-headless-")
    procs = []
    env = dict(os.environ, MAXMEM=args.heap)
    start = time.monotonic()
    try:
        for i, group in enumerate(groups):
            # One import directory per group, mirroring the corpus tree so
            # same-named binaries stay apart (-recursive keeps folders).
            src = os.path.join(tmp, "import%d" % i)
            for rel in group:
                os.makedirs(os.path.dirname(os.path.join(src, rel)), exist_ok=True)
                os.symlink(os.path.realpath(os.path.join(args.corpus, rel)), os.path.join(src, rel))
            stats = os.path.join(tmp, "stats%d.jsonl" % i)
            cmd = [os.path.join(args.ghidra, "support", "analyzeHeadless"), os.path.join(tmp, "proj%d" % i),
                   "timing", "-import", src, "-recursive", "-scriptPath", SCRIPTS,
                   "-preScript", "RevkitTimingPre.java", stats,
                   "-postScript", "RevkitTimingPost.java", stats, "-deleteProject"]
            os.makedirs(os.path.join(tmp, "proj%d" % i))
            log = open(os.path.join(tmp, "log%d.txt" % i), "w")
            procs.append((subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env), log, stats))
        failed = 0
        for p, log, _ in procs:
            failed += p.wait() != 0
            log.close()
        wall = time.monotonic() - start

        records: dict[str, dict] = {}
        for _, _, stats in procs:
            if not os.path.exists(stats):
                continue
            with open(stats) as f:
                for line in f:
                    rec = json.loads(line)
                    records.setdefault(os.path.realpath(rec["program"]), {}).update(rec)
        binaries = []
        for path, rec in sorted(records.items()):
            if "decompile_start_ms" not in rec or "analysis_start_ms" not in rec:
                continue
            binaries.append({
                "binary": os.path.relpath(path, os.path.realpath(args.corpus)),
                "analysis_s": round((rec["decompile_start_ms"] - rec["analysis_start_ms"]) / 1000, 2),
                "decompile_s": round((rec["decompile_end_ms"] - rec["decompile_start_ms"]) / 1000, 2),
                "functions": rec["functions"],
                "decompiled": rec["decompiled"],
            })
    finally:
        if failed or len(binaries) != len(rels):
            print("logs kept in %s" % tmp, file=sys.stderr)
        else:
            shutil.rmtree(tmp, ignore_errors=True)

    doc = {
        "ghidra": args.ghidra,
        "processes": len(groups),
        "heap": args.heap,
        "wall_s": round(wall, 1),
        "binaries": binaries,
        "analysis_s_total": round(sum(b["analysis_s"] for b in binaries), 1),
        "decompile_s_total": round(sum(b["decompile_s"] for b in binaries), 1),
        "functions": sum(b["functions"] for b in binaries),
        "decompiled": sum(b["decompiled"] for b in binaries),
    }
    print("analyzeHeadless: %d binaries, %d functions (%d decompiled) in %.1f s wall with %d processes" % (
        len(binaries), doc["functions"], doc["decompiled"], wall, len(groups)))
    print("  per-binary sums: analysis %.1f s, decompilation %.1f s" % (doc["analysis_s_total"],
                                                                         doc["decompile_s_total"]))
    if args.stats:
        with open(args.stats, "w") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
            f.write("\n")
    return 1 if failed or len(binaries) != len(rels) else 0


if __name__ == "__main__":
    sys.exit(main())
