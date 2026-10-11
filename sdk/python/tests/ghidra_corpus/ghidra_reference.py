"""Runs the Ghidra compatibility corpus in Ghidra itself (through PyGhidra)
and writes what each script did, for run.py to compare with revkit.

    $(scripts/setup-pyghidra.sh) ghidra_reference.py --binary PROG --out ghidra.json [--only NAME ...]

The program is imported and analyzed once; each scenario runs in a
transaction that is rolled back afterwards, so scenarios don't see each
other.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import observe  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--program", default="fixture", help="which scenarios: those listing this program")
    ap.add_argument("--only", nargs="*", default=[])
    a = ap.parse_args(argv)
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(Path.home() / "ghidra" / "ghidra_12.1.4_PUBLIC"))
    import pyghidra

    pyghidra.start()
    scenarios = observe.scenarios(HERE / "corpus.json", a.program, a.only)
    binary = Path(a.binary).resolve()
    result = {"binary": binary.name, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "ghidra": "12.1.4", "observations": {}}
    with tempfile.TemporaryDirectory(prefix="rk-ghidra-corpus-") as tmp:
        with pyghidra.open_program(str(binary), project_location=tmp, project_name="corpus", analyze=True) as flat:
            program = flat.getCurrentProgram()
            for spec in scenarios:
                result["observations"][spec["name"]] = run_one(program, spec, Path(tmp))
                print(f"{spec['name']}: {result['observations'][spec['name']]['status']}", file=sys.stderr)
    Path(a.out).write_text(json.dumps(result, indent=1, sort_keys=True))
    return 0


# ---------------------------------------------------------------------------


_WHERE: dict = {}  # the scenario's addresses, resolved before its setup


def resolve(program, text: str):
    """An address from "main", "main+0x4", "0x104010", "block:.data" or "end:mix"."""
    if text in _WHERE:
        return _WHERE[text]

    af = program.getAddressFactory()
    if text.startswith("block:"):
        return program.getMemory().getBlock(text[6:]).getStart()
    if text.startswith("end:"):
        f = function_named(program, text[4:])
        return f.getBody().getMaxAddress()
    base, plus, off = text.partition("+")
    if base.startswith("0x"):
        a = af.getDefaultAddressSpace().getAddress(int(base, 16))
    else:
        f = function_named(program, base)
        if f is not None:
            a = f.getEntryPoint()
        else:
            syms = [s for s in program.getSymbolTable().getSymbols(base)]
            if not syms:
                raise KeyError(f"no symbol {base!r} in Ghidra's program")
            a = syms[0].getAddress()
    return a.add(int(off, 0)) if plus else a


def function_named(program, name: str):
    for f in program.getFunctionManager().getFunctions(True):
        if f.getName() == name:
            return f
    return None


def snapshot(program, spec) -> dict:
    from ghidra.program.model.listing import CommentType

    kinds = [("eol", CommentType.EOL), ("pre", CommentType.PRE), ("post", CommentType.POST),
             ("plate", CommentType.PLATE), ("repeatable", CommentType.REPEATABLE)]
    listing = program.getListing()
    mem = program.getMemory()
    functions = {}
    for f in program.getFunctionManager().getFunctions(True):
        if mem.contains(f.getEntryPoint()):
            functions[hex(f.getEntryPoint().getOffset())] = str(f.getName())
    comments = {}
    it = listing.getCommentAddressIterator(mem, True)
    while it.hasNext():
        a = it.next()
        for name, kind in kinds:
            c = listing.getComment(kind, a)
            if c is not None:
                comments[f"{hex(a.getOffset())}/{name}"] = str(c)
    names = {}
    for s in program.getSymbolTable().getPrimarySymbolIterator(True):
        if mem.contains(s.getAddress()):
            names[hex(s.getAddress().getOffset())] = str(s.getName())
    return {"functions": functions, "comments": comments, "names": names}


def setup(program, step: dict) -> None:
    from ghidra.program.model.listing import CommentType
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import TaskMonitor

    op = step["op"]
    a = resolve(program, step["at"])
    if op == "comment":
        kind = {"eol": CommentType.EOL, "pre": CommentType.PRE, "post": CommentType.POST,
                "plate": CommentType.PLATE, "repeatable": CommentType.REPEATABLE}[step["kind"]]
        program.getListing().setComment(a, kind, step["text"])
    elif op == "remove_function":
        program.getFunctionManager().removeFunction(a)
    elif op == "label":
        source = getattr(SourceType, step.get("source", "USER_DEFINED"))
        st = program.getSymbolTable()
        prim = st.getPrimarySymbol(a)
        if prim is not None and not prim.isDynamic():
            prim.setName(step["name"], source)
        else:
            st.createLabel(a, step["name"], source).setPrimary()
    else:
        raise ValueError(f"unknown setup op {op!r}")


def run_one(program, spec: dict, tmp: Path) -> dict:
    from ghidra.app.script import GhidraState
    from ghidra.program.util import ProgramLocation, ProgramSelection
    from ghidra.util import Msg
    from ghidra.util.task import TaskMonitor
    from java.io import PrintWriter, StringWriter
    from pyghidra.script import PyGhidraScript

    obs = {"status": "ok", "error": "", "output": [], "messages": []}
    tx = program.startTransaction("corpus " + spec["name"])
    try:
        # Addresses are resolved before the setup (which may remove a name).
        _WHERE.clear()
        _WHERE.update({x: resolve(program, x) for x in addresses(spec)})
        for step in spec.get("setup", []):
            setup(program, step)
        before = snapshot(program, spec)
        out_file = tmp / f"{spec['name']}.out"
        args = [str(x).replace("{out}", str(out_file)) for x in spec.get("args", [])]
        loc = ProgramLocation(program, resolve(program, spec["address"])) if spec.get("address") else None
        sel = None
        if spec.get("selection"):
            first, last = spec["selection"]
            sel = ProgramSelection(resolve(program, first), resolve(program, last))
        state = GhidraState(None, None, program, loc, sel, None)
        sw, ew = StringWriter(), StringWriter()
        script = PyGhidraScript()
        script.set(state, TaskMonitor.DUMMY, PrintWriter(sw, True), PrintWriter(ew, True))
        # PyGhidraScript binds print() to the writer it had when made (none
        # yet), and getScriptName() to its source file: point both at ours.
        from generic.jar import ResourceFile
        from java.io import File
        from pyghidra.script import _build_script_print

        dict.__setitem__(script, "print", _build_script_print(script._script.writer))
        script._script.setSourceFile(ResourceFile(File(str(HERE / "scripts" / spec["script"]))))
        messages = []
        logger = _MessageLogger(messages)
        Msg.setErrorLogger(logger)
        try:
            script.run(str(HERE / "scripts" / spec["script"]), args)
        finally:
            Msg.setErrorLogger(None)
        obs["output"] = str(sw.toString()).split("\n")
        err = str(ew.toString())
        if "Traceback" in err or "Exception" in err:
            obs["status"] = "error"
            obs["error"] = err.strip().splitlines()[-1] if err.strip() else "error"
            obs["traceback"] = err
        obs["messages"] = messages
        after = snapshot(program, spec)
        obs["functions"] = after["functions"]
        obs["changes"] = {k: observe.diff(before[k], after[k]) for k in ("functions", "comments", "names")}
        obs["bytes"] = {}
        for rng in spec.get("bytes", []):
            start = resolve(program, rng[0])
            buf = bytearray(int(rng[1]))
            import jpype

            arr = jpype.JArray(jpype.JByte)(int(rng[1]))
            program.getMemory().getBytes(start, arr)
            obs["bytes"][rng[0]] = bytes((b + 256) % 256 for b in arr).hex()
        obs["file"] = out_file.read_text() if out_file.exists() else None
    except Exception as e:  # noqa: BLE001 - the observation records it
        obs["status"] = "error"
        obs["error"] = f"{type(e).__name__}: {e}"
    finally:
        program.endTransaction(tx, False)
        _WHERE.clear()
    return obs


def addresses(spec: dict) -> list:
    out = [s["at"] for s in spec.get("setup", [])]
    out += [spec["address"]] if spec.get("address") else []
    out += list(spec.get("selection") or [])
    out += [b[0] for b in spec.get("bytes", [])]
    return out


def _MessageLogger(messages: list):
    """A ghidra.util.ErrorLogger that keeps Msg.info/warn/error lines (not
    println's ScriptMessage echoes)."""
    from jpype import JImplements, JOverride

    @JImplements("ghidra.util.ErrorLogger")
    class Logger:
        def _keep(self, level, message):
            if message is None or type(message).__name__.endswith("ScriptMessage"):
                return
            messages.append(f"{level} {message}")

        @JOverride
        def debug(self, originator, message, throwable=None):
            pass

        @JOverride
        def trace(self, originator, message, throwable=None):
            pass

        @JOverride
        def info(self, originator, message, throwable=None):
            self._keep("INFO", message)

        @JOverride
        def warn(self, originator, message, throwable=None):
            self._keep("WARN", message)

        @JOverride
        def error(self, originator, message, throwable=None):
            self._keep("ERROR", message)

    return Logger()


if __name__ == "__main__":
    sys.exit(main())
