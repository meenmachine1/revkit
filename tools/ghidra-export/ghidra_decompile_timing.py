#!/usr/bin/env python3
"""Time Ghidra's decompilation of the corpus alone, without import and
analysis, at a given parallelism.

W worker processes (one JVM each, through PyGhidra) split the binaries by
size, import and auto-analyze theirs, and keep them open. When every worker
is ready they start together and decompile every function of their programs
(one DecompInterface per program, DecompileOptions.grabFromProgram, style
"decompile", as the reference export). The decompilation wall-clock time is
from that common start until the last worker finishes.

  ghidra_decompile_timing.py --corpus out/corpus -j 10 [--stats out.json]
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ghidra_export as ge  # noqa: E402


def worker(jobs, ghidra, heap, tmp, ready, go, results):
    ge.worker_init(ghidra, heap, tmp, 120)
    from java.io import File
    from ghidra.app.util.importer import MessageLog, ProgramLoader
    from ghidra.util.task import TaskMonitor

    programs = []
    for job in jobs:
        res = (ProgramLoader.builder().source(File(job["file"])).name(os.path.basename(job["file"]))
               .log(MessageLog()).monitor(TaskMonitor.DUMMY).load())
        program = res.getPrimaryDomainObject()
        if job.get("pdb"):
            from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
            tx = program.startTransaction("pdb option")
            try:
                PdbUniversalAnalyzer.setPdbFileOption(program, File(job["pdb"]))
            finally:
                program.endTransaction(tx, True)
        ge._analyze(program)
        programs.append((job["rel"], program, res))
    ready.wait()  # everyone analyzed
    go.wait()     # common start
    start = time.time()
    per = []
    for rel, program, _ in programs:
        t0 = time.time()
        ifc = ge._decompiler(program)
        n = ok = 0
        try:
            for f in program.getListing().getFunctions(True):
                n += 1
                r = ifc.decompileFunction(f, 120, TaskMonitor.DUMMY)
                ok += r is not None and r.getDecompiledFunction() is not None
        finally:
            ifc.dispose()
        per.append({"binary": rel, "decompile_s": round(time.time() - t0, 3), "functions": n, "decompiled": ok})
    results.put({"start": start, "end": time.time(), "binaries": per})
    for _, _, res in programs:
        res.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("-j", "--jobs", type=int, default=10)
    ap.add_argument("--heap", default="3g")
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR", ge.DEFAULT_GHIDRA))
    ap.add_argument("--stats")
    args = ap.parse_args()

    jobs = ge.jobs_from_manifest(args.corpus, [])
    jobs.sort(key=lambda j: -os.path.getsize(j["file"]))
    groups = [[] for _ in range(min(args.jobs, len(jobs)))]
    load = [0] * len(groups)
    for job in jobs:
        i = load.index(min(load))
        groups[i].append(job)
        load[i] += os.path.getsize(job["file"])

    ctx = mp.get_context("spawn")
    ready = ctx.Barrier(len(groups) + 1)
    go = ctx.Barrier(len(groups) + 1)
    results = ctx.Queue()
    tmp = tempfile.mkdtemp(prefix="revkit-ghidra-decompile-timing-")
    procs = [ctx.Process(target=worker, args=(g, args.ghidra, args.heap, tmp, ready, go, results)) for g in groups]
    for p in procs:
        p.start()
    t_ready = time.time()
    ready.wait()
    print("all %d workers imported and analyzed in %.1f s; decompiling" % (len(groups), time.time() - t_ready),
          flush=True)
    go.wait()
    start = time.time()
    outs = [results.get() for _ in procs]
    for p in procs:
        p.join()
    end = max(o["end"] for o in outs)
    binaries = sorted((b for o in outs for b in o["binaries"]), key=lambda b: b["binary"])
    doc = {
        "workers": len(groups),
        "decompile_wall_s": round(end - start, 2),
        "decompile_s_total": round(sum(b["decompile_s"] for b in binaries), 2),
        "functions": sum(b["functions"] for b in binaries),
        "decompiled": sum(b["decompiled"] for b in binaries),
        "binaries": binaries,
    }
    print("Ghidra decompiled %d functions (%d with C) in %.2f s wall with %d workers (per-binary sum %.1f s)" % (
        doc["functions"], doc["decompiled"], doc["decompile_wall_s"], len(groups), doc["decompile_s_total"]))
    if args.stats:
        with open(args.stats, "w") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
