# @category Decompiler
# @description Decompiles every function (or those named) on the daemon's decompiler workers
# @description and reports the timing: rate, percentiles, the slowest, the failures.
# @context program
# @arg parallelism:int=0 Decompilations in flight (0: the daemon's workers plus one)
# @arg functions= Comma-separated names or addresses (empty: every function)
# @arg out:file= Also write the report as JSON here
# @arg text:bool=false Fetch the C text too (slower over the wire)
"""Batch decompile with a timing report (QueryService.DecompileMany)."""
import json
import time

from revkit.script import *

names = [s.strip() for s in args["functions"].split(",") if s.strip()]
entries = [to_addr(n) for n in names] or None
total = len(entries) if entries else sum(1 for _ in functions())
monitor.set_max(total)
monitor.message("Decompiling")
start = time.monotonic()
times, failures, errors, slow, served = [], {}, [], [], 0
first_result = None
for r in decompile_many(entries, text=args["text"], parallelism=args["parallelism"]):
    monitor.increment()
    first_result = first_result or time.monotonic() - start
    if r.error:
        errors.append({"entry": f"0x{r.entry.offset:x}", "error": r.error})
        continue
    if r.HasField("failure"):
        kind = {1: "segv", 2: "fpe", 3: "abort", 4: "timeout", 5: "oom"}.get(r.failure.kind, str(r.failure.kind))
        failures.setdefault(kind, []).append(f"0x{r.entry.offset:x}")
    served += r.served_before
    times.append(r.function_ms)
    slow.append((r.function_ms, r.function.name or f"0x{r.entry.offset:x}"))
wall = time.monotonic() - start
times.sort()


def pct(p):
    return round(times[min(len(times) - 1, int(p / 100 * len(times)))], 1) if times else 0.0


report = {
    "program": current_program.id,
    "functions": total,
    "decompiled": len(times),
    "failed": {k: len(v) for k, v in failures.items()},
    "errors": len(errors),
    "served_before": served,
    "wall_seconds": round(wall, 2),
    "first_result_seconds": round(first_result or 0, 3),
    "functions_per_second": round(len(times) / wall, 1) if wall else 0,
    "function_ms": {"p50": pct(50), "p90": pct(90), "p99": pct(99), "max": round(times[-1], 1) if times else 0,
                    "sum": round(sum(times), 1)},
    "slowest": [{"ms": round(ms, 1), "function": name} for ms, name in sorted(slow, reverse=True)[:10]],
    "failures": failures,
}
print(f"{report['decompiled']}/{total} decompiled in {wall:.1f} s ({report['functions_per_second']}/s); "
      f"per function p50 {pct(50)} ms, p90 {pct(90)} ms, p99 {pct(99)} ms, max {report['function_ms']['max']} ms")
if failures or errors:
    print("failures:", ", ".join(f"{k} {len(v)}" for k, v in failures.items()) or "none", f"; errors: {len(errors)}")
for row in report["slowest"][:5]:
    print(f"  {row['ms']:9.1f} ms  {row['function']}")
if args["out"]:
    with open(args["out"], "w") as fh:
        json.dump(report, fh, indent=1)
