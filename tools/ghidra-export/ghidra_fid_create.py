#!/usr/bin/env python3
"""Build a Function ID database with Ghidra's own populate (FidService.
createNewLibraryFromPrograms, what Tools > Function ID > Populate does), for
cross-checking revkit's FID against Ghidra's on the same database
(docs/fid.md, "Gates").

  ghidra_fid_create.py --library zlib:1.3.1:gcc-O2 --out lib.fidb [--raw lib.fidbf] prog...

Writes the packed .fidb Ghidra attaches (ghidra_fid.py --fidb) and, with
--raw, the same database as a raw .fidbf (FidDB.saveRawDatabaseFile), the
form revkit reads. Programs are imported and auto-analyzed in a temporary
project. Ghidra's preferences go to a private settings directory, so the
user's Ghidra never sees these databases.

Run with the PyGhidra venv: $(scripts/setup-pyghidra.sh) tools/ghidra-export/ghidra_fid_create.py ...
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile


def isolate_settings(root: str) -> None:
    """Ghidra's FidFileManager saves its file list to the user's settings."""
    os.makedirs(root, exist_ok=True)
    os.environ["XDG_CONFIG_HOME"] = os.path.join(root, "config")
    os.environ["XDG_CACHE_HOME"] = os.path.join(root, "cache")


def start(ghidra_dir: str, settings: str) -> None:
    os.environ["GHIDRA_INSTALL_DIR"] = ghidra_dir
    from pyghidra.launcher import HeadlessPyGhidraLauncher

    launcher = HeadlessPyGhidraLauncher(install_dir=ghidra_dir)
    launcher.add_vmargs("-Xmx4g", "-Djava.io.tmpdir=" + tempfile.gettempdir(), "-Duser.home=" + settings)
    launcher.start()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("programs", nargs="+")
    ap.add_argument("--library", required=True, help="family:version:variant")
    ap.add_argument("--out", required=True, help="the packed .fidb to write")
    ap.add_argument("--raw", help="also write a raw .fidbf")
    ap.add_argument("--settings", default=None, help="Ghidra settings directory (default: a temporary one)")
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR",
                                                       os.path.expanduser("~/ghidra/ghidra_12.1.4_PUBLIC")))
    args = ap.parse_args(argv)
    family, version, variant = (args.library.split(":") + ["", ""])[:3]
    settings = args.settings or tempfile.mkdtemp(prefix="rk-ghidra-settings-")
    isolate_settings(settings)
    start(args.ghidra, settings)

    from java.io import File
    from java.util import ArrayList
    from ghidra.base.project import GhidraProject
    from ghidra.feature.fid.db import FidFileManager
    from ghidra.feature.fid.service import FidService
    from ghidra.util.task import TaskMonitor
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.program.util import GhidraProgramUtilities

    projdir = tempfile.mkdtemp(prefix="rk-fid-project-")
    out = os.path.abspath(args.out)
    if os.path.exists(out):
        os.remove(out)
    try:
        project = GhidraProject.createProject(projdir, "fid", True)
        files = ArrayList()
        language = None
        for p in args.programs:
            program = project.importProgram(File(p))
            tx = program.startTransaction("analyze")
            try:
                opts = program.getOptions("Analyzers")
                opts.setBoolean("Function ID", False)
                mgr = AutoAnalysisManager.getAnalysisManager(program)
                mgr.initializeOptions()
                mgr.reAnalyzeAll(None)
                mgr.startAnalysis(TaskMonitor.DUMMY, True)
                GhidraProgramUtilities.markProgramAnalyzed(program)
            finally:
                program.endTransaction(tx, True)
            project.saveAs(program, "/", os.path.basename(p), True)
            language = program.getLanguageID()
            files.add(program.getDomainFile())
            project.close(program)
        fm = FidFileManager.getInstance()
        fm.createNewFidDatabase(File(out))
        fid_file = next(f for f in fm.getFidFiles() if os.path.abspath(str(f.getPath())) == out)
        service = FidService()
        db = fid_file.getFidDB(True)
        try:
            result = service.createNewLibraryFromPrograms(db, family, version, variant, files, None, language, None,
                                                          None, TaskMonitor.DUMMY)
            db.saveDatabase("revkit gate", TaskMonitor.DUMMY)
            print("ghidra populate: %d functions" % result.getTotalAttempted(), file=sys.stderr)
        finally:
            db.close()
        if args.raw:
            raw = os.path.abspath(args.raw)
            if os.path.exists(raw):
                os.remove(raw)
            db = fid_file.getFidDB(False)  # outside a transaction
            try:
                db.saveRawDatabaseFile(File(raw), TaskMonitor.DUMMY)
            finally:
                db.close()
        fm.removeUserFile(fid_file)
        project.close()
    finally:
        shutil.rmtree(projdir, ignore_errors=True)
        if args.settings is None:
            shutil.rmtree(settings, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
