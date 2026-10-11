#!/usr/bin/env python3
"""Peak memory of a process and its descendants (a parent and its
decompiler workers), sampled.

    scripts/tree-memory.py [--interval S] [--json FILE] -- command args...
    scripts/tree-memory.py [--interval S] [--json FILE] --pid PID   (watch a running one)

Runs the command, and every --interval seconds (default 0.25) sums over the
process tree the proportional set size (PSS: shared pages divided among the
processes sharing them, so the workers' common binary counts once) and the
resident set size (RSS, which counts shared pages in every process). Prints
the peaks on stderr and writes them with the samples' process counts to
--json. Exits with the command's status.
"""
import argparse
import json
import os
import subprocess
import sys
import time


def children(pid):
    # Each thread lists the children it started: workers come from pool
    # threads, not the main one.
    out = []
    try:
        tasks = os.listdir(f"/proc/{pid}/task")
    except OSError:
        return out
    for t in tasks:
        try:
            with open(f"/proc/{pid}/task/{t}/children") as f:
                out.extend(int(x) for x in f.read().split())
        except OSError:
            pass
    return out


def tree(pid):
    todo, seen = [pid], []
    while todo:
        p = todo.pop()
        seen.append(p)
        todo.extend(children(p))
    return seen


def memory(pid):
    """(pss, rss) in bytes, or None if the process is gone."""
    try:
        with open(f"/proc/{pid}/smaps_rollup") as f:
            pss = rss = 0
            for line in f:
                if line.startswith("Pss:"):
                    pss = int(line.split()[1]) * 1024
                elif line.startswith("Rss:"):
                    rss = int(line.split()[1]) * 1024
            return pss, rss
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=0.25)
    ap.add_argument("--json")
    ap.add_argument("--pid", type=int)
    ap.add_argument("command", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.command[1:] if a.command and a.command[0] == "--" else a.command
    if a.pid:
        class Running:
            pid = a.pid
            returncode = 0
            def poll(self):
                return None if os.path.exists(f"/proc/{a.pid}") else 0
        proc = Running()
        cmd = [f"pid {a.pid}"]
    elif not cmd:
        ap.error("no command")
    else:
        proc = subprocess.Popen(cmd)
    peak_pss = peak_rss = 0
    peak_procs = 0
    at_peak = {}
    start = time.monotonic()
    while proc.poll() is None:
        pss = rss = 0
        n = 0
        per = {}
        for p in tree(proc.pid):
            m = memory(p)
            if m is None:
                continue
            n += 1
            pss += m[0]
            rss += m[1]
            per[p] = m[0]
        if pss > peak_pss:
            peak_pss, at_peak = pss, {"t_s": round(time.monotonic() - start, 1), "processes": n,
                                      "parent_pss": per.get(proc.pid, 0), "workers_pss": pss - per.get(proc.pid, 0)}
        peak_rss = max(peak_rss, rss)
        peak_procs = max(peak_procs, n)
        time.sleep(a.interval)
    result = {"command": cmd, "status": proc.returncode, "wall_s": round(time.monotonic() - start, 1),
              "peak_pss_bytes": peak_pss, "peak_rss_sum_bytes": peak_rss, "max_processes": peak_procs,
              "at_peak": at_peak}
    print(f"tree-memory: peak PSS {peak_pss / 2**30:.2f} GiB (parent {at_peak.get('parent_pss', 0) / 2**30:.2f}, "
          f"workers {at_peak.get('workers_pss', 0) / 2**30:.2f}, {at_peak.get('processes', 0)} processes), "
          f"peak RSS sum {peak_rss / 2**30:.2f} GiB, {result['wall_s']} s", file=sys.stderr)
    if a.json:
        with open(a.json, "w") as f:
            json.dump(result, f)
    sys.exit(proc.returncode if proc.returncode >= 0 else 128 - proc.returncode)


if __name__ == "__main__":
    main()
