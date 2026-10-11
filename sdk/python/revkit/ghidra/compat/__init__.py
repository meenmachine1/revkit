"""Ghidra script compatibility: run Ghidra-style Python 3 scripts on revkit.

``rk-script`` and the daemon's script service detect a Ghidra-style script
(:func:`is_ghidra_script`: ``ghidra.*`` imports, ``currentProgram``, a
``@runtime Jython``/``PyGhidra`` tag) and run it with GhidraScript's names
defined (``currentProgram``, ``currentAddress``, ``currentLocation``,
``currentSelection``, ``monitor``, ``state``, ``println``, ``toAddr``,
``askString``, ``createLabel``, ...) and ``ghidra.*`` imports answered by
this shim. It is a bounded subset of GhidraScript and FlatProgramAPI over
``revkit.script``: edits are buffered with the run's provenance, and
everything outside the subset raises :class:`Unsupported` naming the Ghidra
API and what to use in revkit instead (the table is in docs/scripting.md and
:data:`UNSUPPORTED`). Python 3 only: a Jython 2 script needs its ``print``
statements made calls.

It is labelled "compat" on purpose: revkit's own API (``revkit.script``) is
what new scripts should use, and it gets features first.
"""

from __future__ import annotations

import re
from typing import Optional

from revkit.ghidra.compat.errors import UNSUPPORTED, Unsupported, replacement_for

__all__ = ["Unsupported", "UNSUPPORTED", "replacement_for", "is_ghidra_script", "setup", "python2_hint"]

_GHIDRA_IMPORT = re.compile(r"^\s*(?:from\s+ghidra[.\s]|import\s+ghidra\b)", re.M)
_CURRENT_PROGRAM = re.compile(r"\b(?:currentProgram|currentAddress|getCurrentProgram)\b")
_RUNTIME = re.compile(r"^\s*#\s*@runtime\s+(?:Jython|PyGhidra)\b", re.M | re.I)
_REVKIT_IMPORT = re.compile(r"^\s*(?:from\s+revkit[.\s]|import\s+revkit\b)", re.M)
# Calls only Ghidra's flat API has (revkit.script spells its own differently).
_FLAT_CALL = re.compile(r"\b(?:println|printf|printerr|popup|toAddr|getFunctionAt|getFunctionContaining|getFirstFunction|"
                        r"getFunctionAfter|getInstructionAt|getFirstInstruction|getInstructionAfter|getFirstData|"
                        r"getDataAt|getDataAfter|getSymbolAt|getReferencesTo|getReferencesFrom|createLabel|"
                        r"setEOLComment|setPlateComment|setPreComment|setPostComment|createFunction|clearListing|"
                        r"createData|askString|askInt|askYesNo|askChoice|askAddress|askBytes|askFile|getScriptArgs|"
                        r"findBytes|getMemoryBlock|getBytes|getByte|setByte|setBytes|getInt|isRunningHeadless)\s*\(")


def is_ghidra_script(source: str) -> bool:
    """A script written for Ghidra: it imports ``ghidra.*``, says
    ``@runtime Jython`` or ``@runtime PyGhidra``, or (without importing
    revkit) uses ``currentProgram``/``currentAddress`` or calls Ghidra's flat
    API (``println(``, ``toAddr(``, ``getFunctionAt(``, ``askString(``, ...)."""
    if _GHIDRA_IMPORT.search(source) or _RUNTIME.search(source):
        return True
    if _REVKIT_IMPORT.search(source):
        return False
    return bool(_CURRENT_PROGRAM.search(source) or _FLAT_CALL.search(source))


_PY2_PRINT = re.compile(r"^\s*print\s+[^(\s=]", re.M)


def python2_hint(source: str, error: SyntaxError) -> Optional[str]:
    """For a SyntaxError in a Jython 2 script: what to change."""
    if _PY2_PRINT.search(source) or "print " in (error.text or ""):
        return ("this looks like a Jython (Python 2) script: revkit runs Python 3, so make each print statement a call "
                "(print \"x\", y -> print(\"x\", y)), long(...) -> int(...), and except E, e -> except E as e")
    return None


def setup(run, namespace: dict, script_args: Optional[list] = None):
    """Defines the Ghidra names in ``namespace`` for ``run`` and aliases
    ``ghidra.*`` imports to the shim; returns the function that undoes the
    aliasing (call it when the script ends)."""
    from revkit.ghidra.compat import flat, modules

    names, f = flat.namespace(run, script_args if script_args is not None else run.context.get("script_args"))
    namespace.update(names)
    f.namespace = namespace
    run.finalizers.append(f.s.flush_patches)
    run.context_listeners.append(f.refresh_context)
    modules.install(f)
    return modules.uninstall
