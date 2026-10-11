#!/usr/bin/env python3
"""Cold start through the real daemon and the Python SDK: from launching
rk-daemon to the first listing page and the first decompiled function.

    scripts/bench-coldstart.py <binary> [--daemon build/tools/rk-daemon/rk-daemon]
                               [--function main] [--json out.json]

Timeline, all from the moment rk-daemon is launched (wall clock):
  ready      the daemon listens (port file written)
  import     ImportProgram returned
  listing    the first 100-row listing page arrived
  functions  the first page of ListFunctions arrived
  decompile  the first function decompiled: --function (by name) if given
             and present, else `main`, else the entry point's function,
             else the first function
Also reports the daemon's peak RSS (VmHWM) and CPU time once done.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "sdk" / "python"))

from revkit.client import Client  # noqa: E402
from revkit.daemon import Daemon  # noqa: E402


def proc_status(pid: int) -> dict:
    out = {}
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            k, _, v = line.partition(":")
            out[k] = v.strip()
    except OSError:
        pass
    return out


def cpu_seconds(pid: int) -> float:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    except OSError:
        return 0.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--daemon", default=str(root / "build" / "tools" / "rk-daemon" / "rk-daemon"))
    ap.add_argument("--function", default="")
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    t0 = time.monotonic()
    marks = {}
    d = Daemon(args.daemon, "--backend", "image", startup_timeout=3600)
    d.start()
    try:
        marks["ready"] = time.monotonic() - t0
        with Client(d.grpc_target, timeout=3600) as rk:
            imported = rk.import_program("default", path=os.path.abspath(args.binary))
            marks["import"] = time.monotonic() - t0
            prog = rk.program(imported.program.program_id)
            page = prog.listing(rows=(0, 100))
            marks["listing"] = time.monotonic() - t0
            first = []
            req_iter = prog.functions(page_size=100)
            for f in req_iter:
                first.append(f)
                if len(first) == 100:
                    break
            marks["functions"] = time.monotonic() - t0

            # Pick the function to decompile without listing every function
            # first (that would not be a cold start any more).
            target = None
            how = ""
            for name in [n for n in (args.function, "main") if n]:
                found = list(prog.functions(name_contains=name, page_size=50))
                exact = [f for f in found if f.name == name]
                if exact:
                    target, how = exact[0], name
                    break
            if target is None:
                summary = prog.summary()
                for e in summary.entry_points:
                    try:
                        target = prog.function(e.address.offset, containing=True)
                        how = "entry point"
                        break
                    except Exception:  # no function there
                        continue
            if target is None and first:
                target, how = first[0], "first function"
            t_pick = time.monotonic() - t0
            result = prog.decompile(target.entry.offset)
            marks["decompile"] = time.monotonic() - t0
            decompile_ms = (marks["decompile"] - t_pick) * 1000
            st = proc_status(d.process.pid)
            out = {
                "binary": args.binary,
                "rows": page.total_rows,
                "function": target.name,
                "function_choice": how,
                "decompile_lines": len(result.text.splitlines()) if result.text else 0,
                "decompile_ms": round(decompile_ms, 1),
                **{k + "_s": round(v, 3) for k, v in marks.items()},
                "peak_rss_mb": int(st.get("VmHWM", "0 kB").split()[0]) // 1024,
                "rss_mb": int(st.get("VmRSS", "0 kB").split()[0]) // 1024,
                "cpu_s": round(cpu_seconds(d.process.pid), 2),
                "load": os.getloadavg()[0],
            }
    finally:
        d.stop()
    print(json.dumps(out, indent=1))
    if args.json:
        Path(args.json).write_text(json.dumps(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
