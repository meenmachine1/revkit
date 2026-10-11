"""The Ghidra compatibility corpus: Ghidra's own scripts, ported to Python 3
(scripts/, API calls unchanged), run under revkit.ghidra.compat and
compared with what Ghidra does with them.

    run.py [--programs fixture,features] [--binary FIXTURE] [--ghidra live|recorded|none]
           [--record] [--only NAME ...] [--report out.json] [--grpc 127.0.0.1:PORT --http 127.0.0.1:PORT]

The programs: the SDK fixture, tests/fixtures/script_target.c compiled here
with cc -O1 (or --binary), and the corpus program features
(elf-x86_64/gcc-O0/debug/features from scripts/build-corpus.sh, pinned by
corpus/manifest.json; $RK_CORPUS_DIR or out/corpus; skipped when it isn't
built). ``--ghidra live`` runs the same scripts in Ghidra through
PyGhidra ($REVKIT_PYGHIDRA, else scripts/setup-pyghidra.sh's venv);
``recorded`` uses expected/<sha12 of the binary>.json, written by
``--record`` (a live run kept as test data). Each scenario (corpus.json)
names what is compared: the output, the comments, functions and names the
script changed, bytes, a file it wrote. ``expect`` says what should happen:
"agree", or {"unsupported": "<API>"}: the script must fail with
Unsupported naming that API.

Exit status: 0 when, for each program, every scenario met its expectation
(or differs for the program-model reason corpus.json gives) and at least 20
of the 30 scripts ran and agreed with Ghidra (the gate); 1 otherwise; 77
when there was no Ghidra result to compare with.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))  # sdk/python

import observe  # noqa: E402

GATE = 20


def scenarios(program: str = "fixture", only=()) -> list:
    return observe.scenarios(HERE / "corpus.json", program, only)


def compile_fixture(dest: Path) -> Path:
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        raise SystemExit("no C compiler for the fixture")
    out = dest / "script_target"
    subprocess.run([cc, "-O1", "-w", "-o", str(out), str(HERE.parent / "fixtures" / "script_target.c")], check=True)
    return out


# ---------------------------------------------------------------------------
# revkit's side
# ---------------------------------------------------------------------------


class RevkitSide:
    """One daemon with the program imported; each scenario's edits are
    reverted after it runs."""

    def __init__(self, client, program_id: str):
        self.client = client
        self.pid = program_id
        self.prog = client.program(program_id)
        self.blocks = [(b.range.first.offset, b.range.last.offset) for b in self.prog.memory_map()]

    def resolve(self, text: str) -> int:
        if text.startswith("block:"):
            return next(b.range.first.offset for b in self.prog.memory_map() if b.name == text[6:])
        if text.startswith("end:"):
            f = next(f for f in self.prog.functions() if f.name == text[4:])
            return max(r.last.offset for r in f.body)
        base, plus, off = text.partition("+")
        if base.startswith("0x"):
            a = int(base, 16)
        else:
            f = next((f for f in self.prog.functions() if f.name == base), None)
            if f is not None:
                a = f.entry.offset
            else:
                s = next(iter(self.prog.symbols(name_equals=base)), None)
                if s is None:
                    raise KeyError(f"no symbol {base!r} in revkit's program")
                a = s.address.offset
        return a + (int(off, 0) if plus else 0)

    def snapshot(self) -> dict:
        from revkit.ghidra.compat.program import _DEFAULT_NAME, _KIND_OF_VIEW

        functions = {hex(f.entry.offset): f.name for f in self.prog.functions()}
        names = {}
        for s in self.prog.symbols():
            if s.origin.WhichOneof("source") == "derived" and _DEFAULT_NAME.match(s.name) and s.kind == 2:
                continue  # Ghidra's iterators skip dynamic labels
            names[hex(s.address.offset)] = s.name
        comments = {}
        for lo, hi in self.blocks:
            cur = lo
            while cur <= hi:
                resp = self.prog.listing(cur, hi, max_rows=4000, omit_bytes=True)
                if not resp.rows:
                    break
                for row in resp.rows:
                    for cv in row.comments:
                        kind = _KIND_OF_VIEW.get(cv.kind, "eol")
                        if kind != "decompiler":
                            comments[f"{hex(row.address.offset)}/{kind}"] = cv.text
                last = resp.rows[-1]
                nxt = last.address.offset + max(1, last.length)
                if not resp.truncated or nxt <= cur:
                    break
                cur = nxt
        # Comments on bytes the listing folds into a row of undefined bytes.
        from revkit.client import fact_key

        shown = {k.split("/")[0] for k in comments}
        for a in {x.key.address.offset for x in self.prog.assertions() if x.body.HasField("comment")}:
            if hex(a) in shown:
                continue
            for kind in ("eol", "pre", "post", "plate", "repeatable"):
                text = self.prog.blame(fact_key(self.pid, "comment", a, kind)).value_text
                if text:
                    comments[f"{hex(a)}/{kind}"] = text
        return {"functions": functions, "comments": comments, "names": names}

    def setup(self, step: dict, session: str) -> None:
        from revkit.v1 import assertion_pb2

        from revkit.client import address

        a = self.resolve(step["at"])
        op = step["op"]
        # Setup edits rank with the script's (agent = script), so the script
        # may change them, as a Ghidra script may change anything; a person's
        # edit (user:) would outrank any script's in revkit. A Ghidra label
        # source of ANALYSIS is revkit's analysis provenance, USER_DEFINED a
        # person's.
        actor = {"ANALYSIS": "analysis:corpus", "USER_DEFINED": "user:corpus"}.get(step.get("source", ""), "agent:corpus")
        if op == "comment":
            body = assertion_pb2.AssertionBody(comment=assertion_pb2.Comment(
                address=address(a), kind={"eol": 1, "pre": 2, "post": 3, "plate": 4, "repeatable": 5}[step["kind"]],
                text=step["text"]))
        elif op == "remove_function":
            body = assertion_pb2.AssertionBody(function_bounds=assertion_pb2.SetFunctionBounds(entry=address(a), remove=True))
        elif op == "label":
            body = assertion_pb2.AssertionBody(rename=assertion_pb2.Rename(
                target=assertion_pb2.Target(address=address(a)), name=step["name"]))
        else:
            raise ValueError(f"unknown setup op {op!r}")
        from revkit.client import provenance

        prov = provenance(actor, session=session)
        req = assertion_pb2.AppendAssertionsRequest(program_id=self.pid, provenance=prov,
                                                    assertions=[assertion_pb2.AssertionInput(body=body)])
        self.client._call(self.client.stubs.assertions.AppendAssertions, req)

    def run(self, spec: dict, tmp: Path) -> dict:
        obs = {"status": "ok", "error": "", "output": [], "messages": []}
        session = f"corpus-setup-{spec['name']}-{time.monotonic_ns()}"
        # Addresses are resolved before the setup (which may remove a name).
        where = {x: self.resolve(x) for x in _addresses(spec)}
        self.resolve = lambda text, _w=where, _r=self.resolve: _w[text] if text in _w else _r(text)
        try:
            return self._run(spec, tmp, obs, session)
        finally:
            del self.resolve

    def _run(self, spec, tmp, obs, session):
        from revkit.script import HeadlessHost, run_script

        for step in spec.get("setup", []):
            self.setup(step, session)
        before = self.snapshot()
        out_file = tmp / f"{spec['name']}.out"
        if out_file.exists():
            out_file.unlink()
        ctx = {"script_args": [str(x).replace("{out}", str(out_file)) for x in spec.get("args", [])]}
        if spec.get("address"):
            ctx["address"] = hex(self.resolve(spec["address"]))
        if spec.get("selection"):
            ctx["selection"] = [hex(self.resolve(x)) for x in spec["selection"]]
        host = HeadlessHost({}, out=io.StringIO(), err=io.StringIO(), interactive=False)
        r = run_script(HERE / "scripts" / spec["script"], client=self.client, program_id=self.pid, host=host,
                       context=ctx, run_id=f"corpus-{spec['name']}-{time.monotonic_ns()}")
        obs["output"] = host.out.getvalue().split("\n")
        obs["messages"] = [l for l in host.err.getvalue().split("\n") if l.startswith(("INFO ", "WARN ", "ERROR "))]
        obs["compat"] = r.compat
        if not r.ok:
            obs["status"] = "error"
            obs["error"] = r.error
            obs["traceback"] = r.traceback
            if r.error_type == "Unsupported":
                obs["unsupported"] = r.error.split(": ", 1)[1]
        after = self.snapshot()
        obs["functions"] = after["functions"]
        obs["changes"] = {k: observe.diff(before[k], after[k]) for k in ("functions", "comments", "names")}
        obs["bytes"] = {}
        for rng in spec.get("bytes", []):
            obs["bytes"][rng[0]] = self.prog.read_memory(self.resolve(rng[0]), int(rng[1])).hex()
        obs["file"] = out_file.read_text() if out_file.exists() else None
        obs["revisions"] = len(r.revisions)
        if r.revisions:
            self.prog.revert(session=r.run_id, actor="user:corpus")
        if spec.get("setup"):
            self.prog.revert(session=session, actor="user:corpus")
        return obs


def _addresses(spec: dict) -> list:
    out = [s["at"] for s in spec.get("setup", [])]
    out += [spec["address"]] if spec.get("address") else []
    out += list(spec.get("selection") or [])
    out += [b[0] for b in spec.get("bytes", [])]
    return out


def revkit_observations(binary: Path, specs: list, grpc: str = "127.0.0.1:0", http: str = "127.0.0.1:0") -> tuple:
    from revkit import Client, Daemon

    out = {}
    with Daemon(None, "--backend", "image", startup_timeout=60, grpc=grpc, http=http) as d, \
            Client(d.grpc_target, actor="user:corpus", timeout=300.0) as c, \
            tempfile.TemporaryDirectory(prefix="rk-corpus-") as tmp:
        pid = c.import_program("default", path=str(binary), name=binary.name).program.program_id
        prog = c.program(pid)
        deadline = time.monotonic() + 300
        while not prog.analysis_status().idle and time.monotonic() < deadline:
            time.sleep(0.2)
        side = RevkitSide(c, pid)
        for spec in specs:
            out[spec["name"]] = side.run(spec, Path(tmp))
        return out, side.blocks


# ---------------------------------------------------------------------------
# Ghidra's side
# ---------------------------------------------------------------------------


def pyghidra_python() -> str:
    env = os.environ.get("REVKIT_PYGHIDRA")
    if env and Path(env).exists():
        return env
    default = Path.home() / ".local" / "share" / "revkit-pyghidra" / "bin" / "python"
    return str(default) if default.exists() else ""


def ghidra_live(binary: Path, program: str, only=()) -> dict:
    py = pyghidra_python()
    if not py:
        raise FileNotFoundError("no PyGhidra venv: scripts/setup-pyghidra.sh, or set REVKIT_PYGHIDRA")
    with tempfile.TemporaryDirectory(prefix="rk-corpus-ghidra-") as tmp:
        out = Path(tmp) / "ghidra.json"
        cmd = [py, str(HERE / "ghidra_reference.py"), "--binary", str(binary), "--out", str(out), "--program", program]
        if only:
            cmd += ["--only", *only]
        subprocess.run(cmd, check=True, stdout=sys.stderr)
        return json.loads(out.read_text())


def recorded(binary: Path) -> dict:
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    path = HERE / "expected" / f"{sha[:12]}.json"
    return json.loads(path.read_text()) if path.exists() else {}


# ---------------------------------------------------------------------------


def evaluate(specs: list, rk: dict, gh: dict, blocks: list) -> list:
    rows = []
    for spec in specs:
        r = rk[spec["name"]]
        expect = spec.get("expect", "agree")
        row = {"name": spec["name"], "script": spec["script"], "source": spec.get("source", ""), "expect": expect}
        if isinstance(expect, dict) and "unsupported" in expect:
            api = expect["unsupported"]
            got = r.get("unsupported", "")
            row["result"] = "unsupported" if got.startswith(api) else "wrong"
            row["detail"] = got or r.get("error", "") or "ran without Unsupported"
        else:
            g = gh.get(spec["name"])
            if r["status"] != "ok":
                row["result"] = "error"
                row["detail"] = r.get("error", "")
            elif g is None:
                row["result"] = "ran"
                row["detail"] = "no Ghidra result to compare with"
            else:
                agree, rp, gp, diffs = observe.compare(spec, r, g, blocks)
                row["result"] = "agree" if agree else "disagree"
                row["detail"] = "; ".join(diffs)
                row["compared"] = spec.get("compare", ["output"])
        rows.append(row)
    return rows


def _model_difference(row: dict, specs: list) -> bool:
    """A scenario corpus.json says differs because of revkit's program model."""
    spec = next(s for s in specs if s["name"] == row["name"])
    return bool(spec.get("model_difference")) and row["result"] == "disagree"


def corpus_binary(name: str) -> Path:
    """A corpus program (corpus/manifest.json), built into out/corpus by
    scripts/build-corpus.sh: $RK_CORPUS_DIR, else the repository's out/corpus."""
    root = Path(os.environ.get("RK_CORPUS_DIR") or HERE.parents[3] / "out" / "corpus")
    return root / CORPUS_PROGRAMS[name]


# The corpus programs the scenarios also run on (their "on" overrides).
CORPUS_PROGRAMS = {"features": "elf-x86_64/gcc-O0/debug/features"}


def run_program(a, program: str, binary: Path) -> tuple:
    specs = scenarios(program, a.only)
    rk, blocks = revkit_observations(binary, specs, a.grpc, a.http)
    gh: dict = {}
    if a.record or a.ghidra == "live":
        result = ghidra_live(binary, program, a.only)
        gh = result["observations"]
        if a.record:
            (HERE / "expected").mkdir(exist_ok=True)
            path = HERE / "expected" / f"{result['binary_sha256'][:12]}.json"
            old = json.loads(path.read_text()) if path.exists() else {"observations": {}}
            old.update({k: v for k, v in result.items() if k != "observations"})
            for o in gh.values():  # what the comparison doesn't use
                o.pop("functions", None)
                o.pop("traceback", None)
            old["observations"].update(gh)
            old["program"] = program
            path.write_text(json.dumps(old, indent=1, sort_keys=True) + "\n")
    elif a.ghidra == "recorded":
        gh = recorded(binary).get("observations", {})
    return specs, evaluate(specs, rk, gh, blocks), rk, gh


def summarize(program: str, specs: list, rows: list, rk: dict, gh: dict, verbose: bool) -> tuple:
    print(f"== {program}")
    for row in rows:
        detail = "" if row["result"] == "agree" else row["detail"][:300]
        print(f"{row['result']:12} {row['name']:44} {detail}")
        if verbose and row["result"] in ("disagree", "error", "wrong"):
            print("   revkit:", json.dumps(rk[row["name"]].get("output"))[:2000])
            if row["name"] in gh:
                print("   ghidra:", json.dumps(gh[row["name"]].get("output"))[:2000])
            print("   ", rk[row["name"]].get("traceback", "")[-1500:])
    extra = {s["name"] for s in specs if s.get("extra")}
    counted = [r for r in rows if r["name"] not in extra]
    agree = sum(r["result"] == "agree" for r in counted)
    unsupported = sum(r["result"] == "unsupported" for r in counted)
    model = sum(_model_difference(r, specs) for r in counted)
    print(f"{program}: {agree} agree, {unsupported} unsupported as expected, {model} differ by revkit's program model, "
          f"{len(counted) - agree - unsupported - model} other, of {len(counted)} (and {len(rows) - len(counted)} extra: "
          f"{', '.join(r['name'] + ' ' + r['result'] for r in rows if r['name'] in extra)})")
    ok = all(r["result"] in ("agree", "unsupported") or _model_difference(r, specs) for r in counted)
    return ok, agree


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--binary", help="the fixture's binary (default: compile it)")
    ap.add_argument("--programs", default="fixture", help="fixture and/or corpus programs: fixture,features")
    ap.add_argument("--ghidra", choices=("live", "recorded", "none"), default="recorded")
    ap.add_argument("--record", action="store_true", help="run Ghidra live and keep its results in expected/")
    ap.add_argument("--only", nargs="*", default=[])
    ap.add_argument("--report")
    ap.add_argument("--grpc", default="127.0.0.1:0")
    ap.add_argument("--http", default="127.0.0.1:0")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    report, status, compared = {}, 0, False
    if (a.record or a.ghidra == "live") and not pyghidra_python():
        print("skip: no PyGhidra venv (scripts/setup-pyghidra.sh, or set REVKIT_PYGHIDRA)", file=sys.stderr)
        return 77
    with tempfile.TemporaryDirectory(prefix="rk-corpus-bin-") as tmp:
        for program in [p for p in a.programs.split(",") if p]:
            if program == "fixture":
                binary = Path(a.binary).resolve() if a.binary else compile_fixture(Path(tmp))
            else:
                binary = corpus_binary(program)
                if not binary.exists():
                    print(f"skip {program}: no {binary} (scripts/build-corpus.sh, or set RK_CORPUS_DIR)", file=sys.stderr)
                    continue
            specs, rows, rk, gh = run_program(a, program, binary)
            compared = compared or bool(gh)
            ok, agree = summarize(program, specs, rows, rk, gh, a.verbose)
            if not ok or (gh and not a.only and agree < GATE):
                status = 1
            report[program] = {"binary": str(binary), "rows": rows, "revkit": rk, "ghidra": gh}
    if a.report:
        Path(a.report).write_text(json.dumps(report, indent=1, default=str))
    if not compared and not a.only and status == 0:
        return 77
    return status


if __name__ == "__main__":
    sys.exit(main())
