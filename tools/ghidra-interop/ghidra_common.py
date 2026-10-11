"""Shared PyGhidra helpers for ghidra_dump.py and ghidra_apply.py.

Runs in the PyGhidra virtualenv (scripts/setup-pyghidra.sh), never in the
revkit SDK's: nothing here imports grpc or revkit.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import sys
import tempfile
from pathlib import Path

DEFAULT_GHIDRA = os.path.expanduser("~/ghidra/ghidra_12.1.4_PUBLIC")
FORMAT = "revkit-ghidra-interop"
VERSION = 1


def start(ghidra: str | None = None, heap: str = "2g") -> str:
    """Starts a headless JVM (once) and returns Ghidra's version."""
    ghidra = ghidra or os.environ.get("GHIDRA_INSTALL_DIR") or DEFAULT_GHIDRA
    os.environ["GHIDRA_INSTALL_DIR"] = ghidra
    import pyghidra

    if not pyghidra.started():
        from pyghidra.launcher import HeadlessPyGhidraLauncher

        launcher = HeadlessPyGhidraLauncher(install_dir=ghidra)
        launcher.add_vmargs("-Xmx" + heap)
        launcher.start()
    from ghidra.framework import Application

    return str(Application.getApplicationVersion())


def split_project(gpr: str) -> tuple[str, str]:
    """``/dir/name.gpr`` (or ``/dir/name``) -> (``/dir``, ``name``)."""
    p = Path(gpr)
    if p.suffix == ".gpr" or p.suffix == ".rep":
        p = p.with_suffix("")
    return str(p.parent.resolve()), p.name


def program_paths(project) -> list[str]:
    """Every program's path in a project, sorted."""
    out = []

    def walk(folder):
        for f in folder.getFiles():
            if f.getContentType() == "Program":
                out.append(str(f.getPathname()))
        for sub in folder.getFolders():
            walk(sub)

    walk(project.getProjectData().getRootFolder())
    return sorted(out)


@contextlib.contextmanager
def open_program(gpr: str, program: str | None, *, writable: bool = False, create: bool = False):
    """Opens ``program`` (a project path like ``/prog``; default: the only one)
    in the Ghidra project ``gpr``. Yields (project, program)."""
    import pyghidra
    from java.lang import Object  # type: ignore

    parent, name = split_project(gpr)
    project = pyghidra.open_project(parent, name, create=create)
    try:
        if program is None:
            paths = program_paths(project)
            if len(paths) != 1:
                raise SystemExit(f"{gpr}: pick a program with --program (it has {paths or 'none'})")
            program = paths[0]
        if not program.startswith("/"):
            program = "/" + program
        df = project.getProjectData().getFile(program)
        if df is None:
            raise SystemExit(f"{gpr}: no program {program} (it has {program_paths(project)})")
        consumer = Object()
        from ghidra.util.task import TaskMonitor

        # A read-only open never changes the user's project files.
        if writable:
            prog = df.getDomainObject(consumer, False, False, TaskMonitor.DUMMY)
        else:
            from ghidra.framework.model import DomainFile

            prog = df.getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY)
        try:
            yield project, prog
        finally:
            prog.release(consumer)
    finally:
        project.close()


def import_binary(project, binary: str, *, analyze: bool = True, folder: str = "/"):
    """Imports ``binary`` into ``project`` (saved), optionally auto-analyzed;
    returns the program's project path."""
    import pyghidra
    from java.io import File  # type: ignore
    from ghidra.app.util.importer import MessageLog, ProgramLoader
    from ghidra.util.task import TaskMonitor

    results = (ProgramLoader.builder().source(File(binary)).project(project).projectFolderPath(folder)
               .name(os.path.basename(binary)).log(MessageLog()).monitor(TaskMonitor.DUMMY).load())
    try:
        program = results.getPrimaryDomainObject()
        if analyze:
            pyghidra.analyze(program)
        results.save(TaskMonitor.DUMMY)
        return str(program.getDomainFile().getPathname())
    finally:
        results.close()


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hexaddr(a) -> str:
    """A Ghidra Address (or int) as ``0x...``."""
    return "0x%x" % (a if isinstance(a, int) else int(a.getOffset()))


def scratch_tmpdir() -> str:
    """A temp dir for Java's temp files, removed by the caller."""
    return tempfile.mkdtemp(prefix="rk-ghidra-")


def warn(msg: str) -> None:
    print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# What ghidra_apply.py applied: a string property map at each address it
# changed, holding {item key: fingerprint} as JSON. ghidra_dump.py marks an
# item "from_revkit" while its fingerprint is still the one recorded, so a
# later import doesn't bring revkit's own edits back as Ghidra's.
# ---------------------------------------------------------------------------

APPLIED_MAP = "revkit.applied"


def applied_map(program, create: bool = False):
    pm = program.getUsrPropertyManager()
    m = pm.getStringPropertyMap(APPLIED_MAP)
    if m is None and create:
        m = pm.createStringPropertyMap(APPLIED_MAP)
    return m


def read_applied(program) -> dict:
    """{address offset: {key: fingerprint}}."""
    import json

    m = applied_map(program)
    out = {}
    if m is None:
        return out
    it = m.getPropertyIterator()
    while it.hasNext():
        a = it.next()
        try:
            out[int(a.getOffset())] = json.loads(str(m.getString(a)))
        except ValueError:
            pass
    return out


def record_applied(program, addr, key: str, fingerprint: str) -> None:
    import json

    m = applied_map(program, create=True)
    cur = m.getString(addr)
    d = json.loads(str(cur)) if cur is not None else {}
    d[key] = fingerprint
    m.add(addr, json.dumps(d, sort_keys=True))


def fp_name(program, addr) -> str:
    s = program.getSymbolTable().getPrimarySymbol(addr)
    return "" if s is None else str(s.getName())


def fp_signature(func) -> str:
    return f"{func.getPrototypeString(False, False)}|{func.getCallingConventionName()}"


def fp_variable(var) -> str:
    return f"{var.getName()}|{var.getDataType().getPathName()}"


def var_key(var) -> str:
    """A Ghidra local variable's identity within its function."""
    if var.isStackVariable():
        return f"var:stack:{int(var.getStackOffset())}"
    return f"var:{var.getVariableStorage()}@{int(var.getFirstUseOffset())}"


def fp_data(data) -> str:
    return "" if data is None else f"{data.getDataType().getPathName()}|{data.getLength()}"
