"""The script host process: runs one program's scripts (pre, script, post).

``rk-script`` starts one per program (``-j`` at a time) so each run has its
own interpreter: a script's globals, ``sys.exit`` or crash cost that run
only, and the flat API's state is the process's. The daemon's script
service starts the same process with ``--stream`` for a UI's run
(JSON lines on stdin and stdout: :class:`revkit.script.host.StreamHost`).

    python -m revkit.script.worker --daemon 127.0.0.1:50051 --program default/bash \\
        --script S.py [--pre P.py] [--post Q.py] [--arg k=v ...] [--result-file F]

Credentials and TLS come from the environment (RK_TOKEN, RK_TLS_FINGERPRINT,
RK_TLS_CA, RK_TLS), as for every SDK client. Exit status 0 when every phase
succeeded, 1 when one failed, 3 when cancelled.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path

from revkit.client import Client, RevkitError
from revkit.script.host import HeadlessHost, StreamHost
from revkit.script.runtime import run_script


def parse_args_list(pairs) -> dict:
    out = {}
    for kv in pairs or ():
        k, sep, v = kv.partition("=")
        if not sep or not k:
            raise SystemExit(f"--arg {kv!r}: expected NAME=VALUE")
        out[k] = v
    return out


def wait_for_analysis(client: Client, program_id: str, timeout: float, host) -> bool:
    prog = client.program(program_id)
    deadline = time.monotonic() + timeout
    while True:
        try:
            if prog.analysis_status().idle:
                return True
        except RevkitError:
            return True  # a daemon without analysis jobs
        if time.monotonic() > deadline:
            host.output(f"analysis still running after {timeout:.0f} s; running the script anyway\n", "stderr")
            return False
        time.sleep(0.25)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m revkit.script.worker", description=__doc__.split("\n\n")[0])
    ap.add_argument("--daemon", required=True)
    ap.add_argument("--program", default="")
    ap.add_argument("--script", required=True)
    ap.add_argument("--pre", action="append", default=[])
    ap.add_argument("--post", action="append", default=[])
    ap.add_argument("--arg", action="append", default=[])
    ap.add_argument("--context", default="", help="JSON: {address, selection}")
    ap.add_argument("--result-file", default="")
    ap.add_argument("--prefix", default="")
    ap.add_argument("--stream", action="store_true", help="JSON lines on stdin/stdout (the daemon's host protocol)")
    ap.add_argument("--output-to-stderr", action="store_true")
    ap.add_argument("--progress", action="store_true")
    ap.add_argument("--stdin", action="store_true", help="answer prompts from stdin")
    ap.add_argument("--analysis-timeout", type=float, default=600.0)
    ap.add_argument("--no-analysis-wait", action="store_true", help="run at once, even while analysis runs")
    ap.add_argument("--run-id", default="")
    ap.add_argument("--reason", default="")
    ap.add_argument("--actor", default=None, help="no-auth daemons: who runs it (user:NAME)")
    ap.add_argument("--compat", choices=("auto", "ghidra", "off"), default="auto",
                    help="run Ghidra-style scripts under revkit.ghidra.compat (auto: when the script looks like one)")
    ap.add_argument("--lib", action="append", default=None,
                    help="a script library directory imports look in, in order (default: the per-user library); "
                         "the script's own directory comes after them")
    ap.add_argument("--read-only", action="store_true", help="edits fail at once (a viewer's run)")
    a = ap.parse_args(argv)
    from revkit.script.runtime import install_library_paths, library_dirs

    libs = a.lib if a.lib is not None else []
    install_library_paths(library_dirs(a.script, user_dir=libs[0] if libs else None, extra=libs[1:]))
    answers = parse_args_list(a.arg)
    context = json.loads(a.context) if a.context else {}

    if a.stream:
        host = StreamHost.stdio()
    else:
        out = sys.stderr if a.output_to_stderr else sys.stdout
        host = HeadlessHost(answers, out=out, err=sys.stderr, prefix=a.prefix, show_progress=a.progress,
                            interactive=True if a.stdin else None)

    def on_term(signum, frame):
        from revkit.script import runtime

        if host.cancelled():
            raise KeyboardInterrupt
        host.cancel()
        # The daemon's cancel: end the script now (a sleep or a blocking
        # call is interrupted), unless a commit is in flight, which then
        # finishes and the run ends at its next monitor check.
        if a.stream and not runtime.committing:
            raise runtime.Cancelled("cancelled")

    signal.signal(signal.SIGTERM, on_term)

    results: list = []
    client = Client(a.daemon, actor=a.actor, timeout=300.0)
    phases = [("pre", p) for p in a.pre] + [("script", a.script)] + [("post", p) for p in a.post]
    waited = False
    status = 0
    try:
        for phase, path in phases:
            if phase != "pre" and not waited and a.program and not a.no_analysis_wait:
                waited = True
                wait_for_analysis(client, a.program, a.analysis_timeout, host)
            r = run_script(path, client=client, program_id=a.program, args=answers, host=host, context=context,
                           run_id=(a.run_id + ("" if phase == "script" else f"-{phase}")) if a.run_id else "",
                           reason=a.reason, phase=phase, compat=a.compat, read_only=a.read_only)
            results.append(r)
            if not r.ok:
                if not a.stream and r.traceback:
                    host.output(r.traceback, "stderr")
                elif not a.stream:
                    host.output(f"{Path(path).name}: {r.error}\n", "stderr")
                status = 3 if r.status == "cancelled" else 1
                break
    finally:
        client.close()
        if a.result_file:
            Path(a.result_file).write_text(json.dumps([r.to_dict() for r in results]))
    return status


if __name__ == "__main__":
    sys.exit(main())
