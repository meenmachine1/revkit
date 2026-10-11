"""The static completion index of the script API, for editors.

The Script Manager's editor completes ``revkit.script`` names, the members of
what they return (``current_program.``, ``monitor.``, ``client.``) and
Ghidra's names (``currentProgram``, ``getFunctionAt``, ...; revkit's compat
layer), and shows a function's signature when ``(`` is typed, without asking
the daemon. This module builds that index from the SDK's own signatures and
docstrings:

    python -m revkit.script.completion_index --out ui/src/scripts/script-api.json

``sdk/python/generate.sh`` runs it with the protobuf stubs; the committed
file is checked against a fresh build by tests/test_completion_index.py.
"""

from __future__ import annotations

import argparse
import inspect
import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

FORMAT = "revkit-script-api/1"

# The context names: what they are (they have no docstrings of their own).
CONTEXT = {
    "current_program": ("instance", "Program", "The program the script runs on (revkit.Program: every SDK read and write)."),
    "current_address": ("instance", "", "The cursor's address (int), or None."),
    "current_function": ("instance", "Function", "The function containing current_address (listing_pb2.Function), or None."),
    "current_selection": ("instance", "", "The selection as (first, last), or None."),
    "current_project": ("instance", "", "The program's project id."),
    "args": ("instance", "", "The script's arguments (--arg NAME=VALUE), typed by its @arg lines."),
    "script": ("instance", "", "The script's metadata (ScriptMeta: name, description, args, sha12)."),
    "run_id": ("instance", "", "The run's id: its provenance session."),
    "client": ("instance", "Client", "The revkit.Client the run talks to the daemon with."),
    "monitor": ("instance", "Monitor", "Progress and cancellation: set_max, increment, message, check_cancelled."),
}

GHIDRA_CONTEXT = {
    "currentProgram": ("instance", "GhidraProgram", "The program, as Ghidra's Program (revkit.ghidra.compat)."),
    "currentAddress": ("instance", "GhidraAddress", "The cursor, as Ghidra's Address, or None."),
    "currentLocation": ("instance", "", "The cursor as a ProgramLocation, or None."),
    "currentSelection": ("instance", "", "The selection as a ProgramSelection, or None."),
    "currentHighlight": ("instance", "", "Always None: revkit has no highlights."),
    "state": ("instance", "", "GhidraState: getCurrentProgram, getCurrentAddress, getCurrentSelection."),
}


def _doc(obj: Any, limit: int = 400) -> str:
    """The docstring's first paragraph, on one line."""
    doc = inspect.getdoc(obj) or ""
    para = doc.split("\n\n")[0]
    text = re.sub(r"\s+", " ", para).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _default(v: Any) -> str:
    if isinstance(v, (int, float, bool, str, bytes, type(None))):
        return repr(v)
    if isinstance(v, (tuple, list)) and not v:
        return repr(v)
    return "…"


def signature(name: str, fn: Any, *, drop_self: bool = False) -> str:
    """``name(a, b=2, *, c=True)``: without annotations, which differ between
    Python versions and crowd an editor's tooltip."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return f"{name}(…)"
    params = list(sig.parameters.values())
    if drop_self and params and params[0].name in ("self", "cls"):
        params = params[1:]
    out, star_done = [], False
    for p in params:
        if p.name.startswith("_") and p.default is not inspect.Parameter.empty:
            continue  # private keyword hooks
        if p.kind is p.VAR_POSITIONAL:
            out.append(f"*{p.name}")
            star_done = True
            continue
        if p.kind is p.VAR_KEYWORD:
            out.append(f"**{p.name}")
            continue
        if p.kind is p.KEYWORD_ONLY and not star_done:
            out.append("*")
            star_done = True
        out.append(p.name if p.default is inspect.Parameter.empty else f"{p.name}={_default(p.default)}")
    return f"{name}({', '.join(out)})"


def _entry(name: str, obj: Any, group: str, *, drop_self: bool = False, returns: str = "") -> dict:
    if isinstance(obj, property):
        return {"name": name, "kind": "property", "signature": "", "doc": _doc(obj.fget) if obj.fget else "", "group": group}
    if inspect.isclass(obj):
        init = obj.__init__ if obj.__init__ is not object.__init__ else None
        sig = signature(name, init, drop_self=True) if init else f"{name}()"
        return {"name": name, "kind": "class", "signature": sig, "doc": _doc(obj), "group": group}
    if callable(obj):
        e = {"name": name, "kind": "function", "signature": signature(name, obj, drop_self=drop_self), "doc": _doc(obj),
             "group": group}
        if returns:
            e["returns"] = returns
        return e
    return {"name": name, "kind": "instance", "signature": "", "doc": "", "group": group}


def _members(cls: type, group: str) -> list:
    out = []
    for name in sorted(dir(cls)):
        if name.startswith("_"):
            continue
        try:
            obj = inspect.getattr_static(cls, name)
        except AttributeError:
            continue
        if isinstance(obj, (staticmethod, classmethod)):
            obj = obj.__func__
            out.append(_entry(name, obj, group, drop_self=isinstance(inspect.getattr_static(cls, name), classmethod)))
            continue
        out.append(_entry(name, obj, group, drop_self=True))
    return out


def build() -> dict:
    """The index: ``globals`` (names a script starts with) and ``members``
    (by type: what ``.`` after a name of that type offers), each entry
    ``{name, kind, signature, doc, group}`` (group "revkit" or "ghidra");
    a global's ``type`` names its ``members`` key."""
    from revkit import script as api
    from revkit.client import Client, Program
    from revkit.script.runtime import Monitor

    globals_: list = []
    for name in api.__all__:
        if name in CONTEXT:
            kind, typ, doc = CONTEXT[name]
            e = {"name": name, "kind": kind, "signature": "", "doc": doc, "group": "revkit"}
            if typ:
                e["type"] = typ
            globals_.append(e)
        else:
            globals_.append(_entry(name, getattr(api, name), "revkit"))
    globals_.append({"name": "print", "kind": "function", "signature": "print(*values, sep=' ', end='\\n', file=None, flush=False)",
                     "doc": "Prints to the run's console.", "group": "revkit"})

    members = {
        "Program": _members(Program, "revkit"),
        "Client": _members(Client, "revkit"),
        "Monitor": _members(Monitor, "revkit"),
        "Function": [{"name": n, "kind": "instance", "signature": "", "doc": d, "group": "revkit"} for n, d in (
            ("entry", "The entry Address (.offset)."), ("name", "Its effective name."), ("body", "Its address ranges."),
            ("prototype", "Its C prototype."), ("size", "Bytes in its body."), ("instruction_count", "Instructions."),
            ("caller_count", "Functions that call it."), ("thunk", "A thunk (a jump to another function)."),
            ("external", "Imported."), ("no_return", "Never returns."), ("calling_convention", "Its convention."))],
    }

    try:
        from revkit.ghidra.compat import flat as gflat
        from revkit.ghidra.compat import model as gmodel
        from revkit.ghidra.compat import program as gprogram
    except ImportError:  # pragma: no cover - the compat layer ships with the SDK
        gflat = None
    if gflat is not None:
        for name in gflat.GHIDRA_FLAT_METHODS:
            impl = getattr(gflat.Flat, name, None)
            if impl is None:
                globals_.append({"name": name, "kind": "function", "signature": f"{name}(…)",
                                 "doc": "Not in revkit: raises Unsupported naming what to use instead.", "group": "ghidra"})
            else:
                e = _entry(name, impl, "ghidra", drop_self=True)
                e["doc"] = e["doc"] or f"Ghidra's FlatProgramAPI.{name} (revkit.ghidra.compat)."
                globals_.append(e)
        for name in ("parseBytes", "parseInt", "parseLong", "parseDouble", "parseBoolean", "parseAddress"):
            if hasattr(gflat.Flat, name):
                globals_.append(_entry(name, getattr(gflat.Flat, name), "ghidra", drop_self=True))
        for name, (kind, typ, doc) in GHIDRA_CONTEXT.items():
            e = {"name": name, "kind": kind, "signature": "", "doc": doc, "group": "ghidra"}
            if typ:
                e["type"] = typ
            globals_.append(e)
        members["GhidraProgram"] = _members(gprogram.Program, "ghidra")
        if hasattr(gmodel, "Address"):
            members["GhidraAddress"] = _members(gmodel.Address, "ghidra")
    seen, unique = set(), []
    for e in globals_:
        if e["name"] not in seen:
            seen.add(e["name"])
            unique.append(e)
    return {"format": FORMAT, "globals": unique, "members": members}


def render(index: dict) -> str:
    return json.dumps(index, indent=None, separators=(",", ":"), ensure_ascii=False, sort_keys=False) + "\n"


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m revkit.script.completion_index", description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", help="where to write (default: stdout)")
    a = ap.parse_args(argv)
    text = render(build())
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
