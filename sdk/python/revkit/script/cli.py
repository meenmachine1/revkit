"""rk-script: run revkit scripts headless, against a daemon or a throwaway one.

    rk-script run S.py [--daemon host:port | --throwaway] [--project-dir D] [--import FILE... | --program ID...]
                       [--pre P.py] [--post Q.py] [-j N] [--arg k=v] [--json]
    rk-script info S.py          its metadata (category, description, args) as JSON
    rk-script list [DIR...]      scripts and what they do (default: the shipped starters)
    rk-script setup              a Python environment for the daemon's scripts
                                 (~/.local/share/revkit/pyenv, which rk-daemon finds)

Per program: the --pre scripts, then waiting for analysis, then the script,
then the --post scripts, each in a fresh host process; -j programs at a
time. Each script run is one revision of edits with script provenance, so
``revert(session=<run id>)`` (or the UI) undoes it. A script is ordinary
Python with your rights: it can read files and use the network
(docs/scripting.md).

Exit status: 0 when every run succeeded, 1 when one failed, 2 for a usage
error, 3 when cancelled. With --json, one JSON object per program goes to
stdout (scripts' output to stderr).
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

from revkit.client import Client, RevkitError
from revkit.daemon import Daemon
from revkit.script.meta import find_script, list_scripts, read_metadata


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _connect(a) -> tuple:
    """(client, daemon or None, target)."""
    tls = {k: v for k, v in (("fingerprint", a.fingerprint), ("ca_cert", a.ca)) if v}
    if a.throwaway or (not a.daemon and not os.environ.get("RK_GRPC") and a.imports):
        extra = ["--decompilers", str(a.decompilers or max(2, a.jobs))]
        if a.project_dir:
            extra += ["--project-dir", str(Path(a.project_dir).resolve())]
        listen = {}
        if a.listen_port:
            listen = dict(grpc=f"127.0.0.1:{a.listen_port}", http=f"127.0.0.1:{a.listen_port + 1}")
        d = Daemon(None, *extra, startup_timeout=60, **listen).start()
        return Client(d.grpc_target, timeout=600.0), d, d.grpc_target
    target = a.daemon or os.environ.get("RK_GRPC")
    if not target:
        raise SystemExit("rk-script: say where the daemon is (--daemon host:port, $RK_GRPC) or use --throwaway")
    return Client(target, token=a.token, timeout=600.0, **tls), None, target


def _import(client: Client, project: str, path: Path, lock: threading.Lock) -> str:
    """The program id of ``path`` in ``project``: imported, or the one already there."""
    sha = _sha256(path)
    with lock:
        try:
            existing = {p.sha256: p.program_id for p in client.programs(project)}
        except RevkitError:
            existing = {}
    if sha in existing:
        return existing[sha]
    resp = client.import_program(project, path=str(path.resolve()))
    return resp.program.program_id


def _run_program(a, target: str, program_id: str, label: str, script: Path, multi: bool, env: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="rk-script-") as tmp:
        result_file = Path(tmp) / "result.json"
        cmd = [sys.executable, "-m", "revkit.script.worker", "--daemon", target, "--program", program_id,
               "--script", str(script), "--result-file", str(result_file),
               "--analysis-timeout", str(a.analysis_timeout)]
        for p in a.pre:
            cmd += ["--pre", str(find_script(p))]
        for p in a.post:
            cmd += ["--post", str(find_script(p))]
        for kv in a.arg:
            cmd += ["--arg", kv]
        # Libraries: the per-user one, the project's (with --project-dir),
        # then --lib; the script's own directory comes after them.
        from revkit.script.runtime import user_scripts_dir

        libs = [str(user_scripts_dir())]
        if a.project_dir:
            libs.append(str(Path(a.project_dir).resolve() / program_id.split("/")[0] / "scripts"))
        for d in libs + [str(Path(x).resolve()) for x in a.lib]:
            cmd += ["--lib", d]
        ctx = json.loads(a.context) if a.context else {}
        if a.address:
            ctx["address"] = a.address
        if a.selection:
            first, _, last = a.selection.partition(":")
            ctx["selection"] = [first, last or first]
        if a.script_args:
            ctx["script_args"] = list(a.script_args)
        if ctx:
            cmd += ["--context", json.dumps(ctx)]
        if multi:
            cmd += ["--prefix", f"[{label}] "]
        if a.json:
            cmd += ["--output-to-stderr"]
        if a.progress:
            cmd += ["--progress"]
        if a.stdin:
            cmd += ["--stdin"]
        if a.actor:
            cmd += ["--actor", a.actor]
        if a.reason:
            cmd += ["--reason", a.reason]
        if a.compat != "auto":
            cmd += ["--compat", a.compat]
        started = time.monotonic()
        proc = subprocess.run(cmd, env=env, stdin=None if (a.jobs == 1 and not multi) else subprocess.DEVNULL)
        runs = json.loads(result_file.read_text()) if result_file.exists() else []
    status = "ok" if proc.returncode == 0 else ("cancelled" if proc.returncode == 3 else "error")
    if proc.returncode not in (0, 1, 3) and not runs:
        status = "error"
    return {
        "program_id": program_id,
        "input": label,
        "status": status,
        "exit_code": proc.returncode,
        "seconds": round(time.monotonic() - started, 3),
        "runs": runs,
        "revisions": [rev for r in runs for rev in r.get("revisions", [])],
        "assertions": sum(r.get("assertions", 0) for r in runs),
        "error": next((r.get("error") for r in runs if r.get("status") != "ok"), "" if proc.returncode == 0 else f"host exited with {proc.returncode}"),
    }


def cmd_run(a) -> int:
    try:
        script = find_script(a.script)
        for p in [*a.pre, *a.post]:
            find_script(p)
    except FileNotFoundError as e:
        print(f"rk-script: {e}", file=sys.stderr)
        return 2
    meta = read_metadata(script)
    for err in meta.errors:
        print(f"rk-script: {script.name}: {err}", file=sys.stderr)
    if not a.programs and not a.imports:
        print("rk-script: name the programs (--program ID) or files to import (--import FILE)", file=sys.stderr)
        return 2
    try:
        client, daemon, target = _connect(a)
    except (RuntimeError, TimeoutError, FileNotFoundError) as e:
        print(f"rk-script: {e}", file=sys.stderr)
        return 2
    env = dict(os.environ)
    if a.token:
        env["RK_TOKEN"] = a.token
    if a.fingerprint:
        env["RK_TLS_FINGERPRINT"] = a.fingerprint
    if a.ca:
        env["RK_TLS_CA"] = a.ca
    sdk_root = str(Path(__file__).resolve().parents[2])
    env["PYTHONPATH"] = sdk_root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    lock = threading.Lock()
    work = [(p, p) for p in a.programs] + [(None, f) for f in a.imports]
    multi = len(work) > 1
    summaries: list = [None] * len(work)

    def one(i: int, program_id: Optional[str], label: str) -> None:
        try:
            if program_id is None:
                path = Path(label)
                label = path.name
                program_id = _import(client, a.project, path, lock)
            summaries[i] = _run_program(a, target, program_id, label, script, multi, env)
        except (RevkitError, OSError) as e:
            summaries[i] = {"program_id": program_id or "", "input": label, "status": "error", "exit_code": 1,
                            "seconds": 0, "runs": [], "revisions": [], "assertions": 0, "error": str(e)}
        if a.json:
            with lock:
                print(json.dumps(summaries[i]), flush=True)

    interrupted = False
    try:
        with cf.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as pool:
            futures = [pool.submit(one, i, p, label) for i, (p, label) in enumerate(work)]
            for f in futures:
                f.result()
    except KeyboardInterrupt:
        interrupted = True
    finally:
        client.close()
        if daemon:
            daemon.stop()
    done = [s for s in summaries if s]
    if not a.json:
        for s in done:
            what = f"{len(s['revisions'])} revision(s), {s['assertions']} assertion(s)" if s["status"] == "ok" else s["error"]
            print(f"rk-script: {s['input']} ({s['program_id']}): {s['status']} in {s['seconds']:.1f} s: {what}",
                  file=sys.stderr)
    if interrupted or any(s["status"] == "cancelled" for s in done):
        return 3
    return 0 if len(done) == len(work) and all(s["status"] == "ok" for s in done) else 1


def cmd_info(a) -> int:
    try:
        meta = read_metadata(find_script(a.script))
    except FileNotFoundError as e:
        print(f"rk-script: {e}", file=sys.stderr)
        return 2
    print(json.dumps(meta.to_dict(), indent=2))
    return 1 if meta.errors else 0


def cmd_list(a) -> int:
    scripts = list_scripts(*a.dirs)
    if a.json:
        print(json.dumps([m.to_dict() for m in scripts], indent=2))
        return 0
    for m in scripts:
        print(f"{m.category or '-':28} {m.name:34} {m.description}")
    return 0


def default_pyenv() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "revkit" / "pyenv"


def sdk_source() -> Optional[Path]:
    """What to install: a wheel shipped beside rk-daemon (share/revkit/python,
    or share/revkit/sdk in older bundles), else the SDK source tree this
    revkit runs from."""
    import shutil

    daemon = os.environ.get("RK_DAEMON") or shutil.which("rk-daemon")
    if daemon:
        share = Path(daemon).resolve().parent.parent / "share" / "revkit"
        for d in ("python", "sdk"):
            wheels = sorted((share / d).glob("revkit-*.whl"))
            if wheels:
                return wheels[-1]
    here = Path(__file__).resolve().parents[2]
    if (here / "pyproject.toml").is_file():
        return here
    return None


def cmd_setup(a) -> int:
    """Creates the environment rk-daemon runs scripts with: a venv with the
    revkit SDK (and whatever the scripts need: --with)."""
    target = Path(a.dir) if a.dir else default_pyenv()
    src = Path(a.wheel) if a.wheel else sdk_source()
    if src is None:
        print("rk-script setup: no revkit wheel or SDK source found; give --wheel share/revkit/python/revkit-*.whl",
              file=sys.stderr)
        return 2
    python = a.python or sys.executable
    py = str(target / "bin" / "python")
    steps = [[python, "-m", "venv", str(target)],
             [py, "-m", "pip", "install", "-q", "--upgrade", str(src), *a.with_],
             # pip keeps an installed SDK with the same version string even
             # when it is an older build: reinstall the SDK itself, not its
             # dependencies.
             [py, "-m", "pip", "install", "-q", "--force-reinstall", "--no-deps", str(src)],
             [py, "-c", "import revkit.script.worker, revkit.script.console"]]
    if a.dry_run:
        for s in steps:
            print(" ".join(s))
        return 0
    if (target / "bin" / "python").exists() and not a.force:
        steps = steps[1:]  # update the SDK in the existing environment
    for s in steps:
        print("rk-script setup:", " ".join(s), file=sys.stderr)
        if subprocess.run(s).returncode != 0:
            print(f"rk-script setup: failed: {' '.join(s)}", file=sys.stderr)
            return 1
    print(f"{target / 'bin' / 'python'} runs scripts; rk-daemon finds it (or pass --script-python)")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="rk-script", description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("\n\n", 1)[1])
    sub = ap.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="run a script over programs")
    r.add_argument("script", help="a script file, or a shipped script's name (rk-script list)")
    where = r.add_mutually_exclusive_group()
    where.add_argument("--daemon", help="host:port of rk-daemon's gRPC listener (default $RK_GRPC)")
    where.add_argument("--throwaway", action="store_true", help="start a daemon for this run (the default with --import)")
    r.add_argument("--project-dir", help="the throwaway daemon's project directory (kept: imports and decompilations are reused)")
    r.add_argument("--project", default="default", help="project to import into (default: default)")
    r.add_argument("--lib", action="append", default=[], metavar="DIR",
                   help="another script library to import from, after the per-user and the project's")
    r.add_argument("--import", dest="imports", nargs="+", default=[], metavar="FILE")
    r.add_argument("--program", dest="programs", nargs="+", default=[], metavar="ID")
    r.add_argument("--pre", action="append", default=[], metavar="P.py")
    r.add_argument("--post", action="append", default=[], metavar="Q.py")
    r.add_argument("-j", "--jobs", type=int, default=1, help="programs in flight (default 1)")
    r.add_argument("--decompilers", type=int, default=0, help="the throwaway daemon's decompiler workers (default max(2, -j))")
    r.add_argument("--arg", action="append", default=[], metavar="NAME=VALUE", help="answers a prompt or sets an @arg")
    r.add_argument("--script-arg", dest="script_args", action="append", default=[], metavar="VALUE",
                   help="a Ghidra script's argument (getScriptArgs()); they answer its ask* calls in order, "
                        "as in Ghidra's headless mode")
    r.add_argument("--compat", choices=("auto", "ghidra", "off"), default="auto",
                   help="Ghidra compatibility (revkit.ghidra.compat): auto when the script looks like a Ghidra "
                        "script (ghidra.* imports, currentProgram), ghidra always, off never")
    r.add_argument("--address", help="current_address (hex, decimal or a symbol)")
    r.add_argument("--selection", help="current_selection, FIRST:LAST")
    r.add_argument("--context", help="context JSON ({\"address\": ..., \"selection\": [...]}), as the UI passes it")
    r.add_argument("--json", action="store_true", help="a JSON summary per program on stdout")
    r.add_argument("--progress", action="store_true", help="show the monitor's progress on stderr")
    r.add_argument("--stdin", action="store_true", help="answer prompts from stdin even when it is not a terminal")
    r.add_argument("--analysis-timeout", type=float, default=600.0)
    r.add_argument("--token", default=None, help="API or session token (default $RK_TOKEN)")
    r.add_argument("--fingerprint", default=None, help="the daemon's certificate SHA-256 to pin")
    r.add_argument("--ca", default=None, help="CA certificate (PEM) to trust")
    r.add_argument("--actor", default=None, help="who runs it on a daemon without accounts (user:NAME)")
    r.add_argument("--reason", default="", help="provenance reason (default: the script's @description)")
    r.add_argument("--listen-port", type=int, default=0, help="the throwaway daemon's gRPC port (HTTP: the next one)")
    r.set_defaults(fn=cmd_run)
    i = sub.add_parser("info", help="a script's metadata as JSON")
    i.add_argument("script")
    i.set_defaults(fn=cmd_info)
    ls = sub.add_parser("list", help="scripts with their metadata")
    ls.add_argument("dirs", nargs="*")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(fn=cmd_list)
    su = sub.add_parser("setup", help="a Python environment for the daemon's scripts")
    su.add_argument("--dir", help="where (default ~/.local/share/revkit/pyenv)")
    su.add_argument("--python", help="the Python to make it from (default: this one)")
    su.add_argument("--wheel", help="the SDK to install (default: share/revkit/python's wheel, or this source tree)")
    su.add_argument("--with", dest="with_", action="append", default=[], metavar="PACKAGE",
                    help="also install this (repeatable): what your scripts import")
    su.add_argument("--force", action="store_true", help="make the environment again")
    su.add_argument("--dry-run", action="store_true", help="print the commands")
    su.set_defaults(fn=cmd_setup)
    a = ap.parse_args(argv)
    if getattr(a, "jobs", 1) < 1:
        ap.error("-j must be at least 1")
    def on_term(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_term)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
