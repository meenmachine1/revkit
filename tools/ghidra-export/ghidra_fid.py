#!/usr/bin/env python3
"""Ghidra's Function ID, as a yardstick for revkit's (docs/fid.md).

For each binary: import and auto-analyze it in Ghidra (headless, PyGhidra),
then write one JSON file with, per function, its entry, name, body and
Ghidra's FID hash quad (FidService.hashFunction). With --fidb, also run
Ghidra's FID search (FidProgramSeeker, the analyzer's own scoring) against
the given databases and record each function's matches.

  ghidra_fid.py --out out.json prog [--pdb prog.pdb] [--fidb a.fidbf ...]
               [--detail 0x401000 ...]   # per-instruction masks and operands
               [--no-fid-analyzer]       # keep Ghidra's FID analyzer from renaming

Run it with the PyGhidra venv: $(scripts/setup-pyghidra.sh) tools/ghidra-export/ghidra_fid.py ...
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile


def _start(ghidra_dir: str) -> None:
    os.environ["GHIDRA_INSTALL_DIR"] = ghidra_dir
    # Attaching databases saves Ghidra's FID file list to its settings: keep
    # them in a private directory, away from the user's Ghidra.
    settings = tempfile.mkdtemp(prefix="rk-ghidra-settings-")
    os.environ["XDG_CONFIG_HOME"] = os.path.join(settings, "config")
    os.environ["XDG_CACHE_HOME"] = os.path.join(settings, "cache")
    from pyghidra.launcher import HeadlessPyGhidraLauncher

    launcher = HeadlessPyGhidraLauncher(install_dir=ghidra_dir)
    launcher.add_vmargs("-Xmx4g", "-Djava.io.tmpdir=" + tempfile.gettempdir(), "-Duser.home=" + settings)
    launcher.start()


def _analyze(program, fid_analyzer: bool) -> None:
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.app.script import GhidraScriptUtil
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.util.task import TaskMonitor

    tx = program.startTransaction("revkit analyze")
    GhidraScriptUtil.acquireBundleHostReference()
    try:
        if not fid_analyzer:
            opts = program.getOptions("Analyzers")
            opts.setBoolean("Function ID", False)
        mgr = AutoAnalysisManager.getAnalysisManager(program)
        mgr.initializeOptions()
        mgr.reAnalyzeAll(None)
        mgr.startAnalysis(TaskMonitor.DUMMY, True)
        GhidraProgramUtilities.markProgramAnalyzed(program)
    finally:
        GhidraScriptUtil.releaseBundleHostReference()
        program.endTransaction(tx, True)


def _u64(v: int) -> str:
    return "%016x" % (int(v) & 0xFFFFFFFFFFFFFFFF)


def _detail(program, func) -> list:
    """Per instruction: bytes, instruction and operand masks, operand objects and types."""
    from ghidra.program.model.lang import OperandType
    from ghidra.program.model.scalar import Scalar
    from ghidra.program.model.lang import Register
    from ghidra.program.model.address import Address

    out = []
    listing = program.getListing()
    for ins in listing.getInstructions(func.getBody(), True):
        proto = ins.getPrototype()
        m = proto.getInstructionMask()
        ops = []
        for i in range(ins.getNumOperands()):
            om = proto.getOperandValueMask(i)
            objs = []
            for o in ins.getOpObjects(i):
                if isinstance(o, Scalar):
                    objs.append(["s", int(o.getSignedValue()), int(o.bitLength())])
                elif isinstance(o, Register):
                    objs.append(["r", o.getName(), int(o.getOffset())])
                elif isinstance(o, Address):
                    objs.append(["a", str(o)])
                else:
                    objs.append(["?", str(o)])
            t = int(ins.getOperandType(i))
            ops.append({"mask": None if om is None else bytes(om.getBytes()).hex(),
                        "objs": objs, "scalar": OperandType.isScalar(t),
                        "address": OperandType.isAddress(t)})
        out.append({"addr": "%x" % ins.getAddress().getOffset(),
                    "bytes": bytes(ins.getBytes()).hex(),
                    "text": str(ins),
                    "mask": None if m is None else bytes(m.getBytes()).hex(),
                    "call": bool(ins.getFlowType().isCall()),
                    "ops": ops})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--out", required=True)
    ap.add_argument("--pdb")
    ap.add_argument("--fidb", action="append", default=[], help="FID database to search (repeatable)")
    ap.add_argument("--detail", action="append", default=[], help="function entry (hex) to dump per instruction")
    ap.add_argument("--no-fid-analyzer", action="store_true")
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR",
                                                       os.path.expanduser("~/ghidra/ghidra_12.1.4_PUBLIC")))
    args = ap.parse_args(argv)
    _start(args.ghidra)

    from java.io import File
    from ghidra.app.util.importer import MessageLog, ProgramLoader
    from ghidra.util.task import TaskMonitor
    from ghidra.feature.fid.service import FidService

    log = MessageLog()
    results = (ProgramLoader.builder().source(File(args.binary)).name(os.path.basename(args.binary))
               .log(log).monitor(TaskMonitor.DUMMY).load())
    try:
        program = results.getPrimaryDomainObject()
        if args.pdb:
            from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
            tx = program.startTransaction("pdb option")
            try:
                PdbUniversalAnalyzer.setPdbFileOption(program, File(args.pdb))
            finally:
                program.endTransaction(tx, True)
        _analyze(program, not args.no_fid_analyzer)
        service = FidService()
        hasher = service.getHasher(program)
        details = {int(d, 16) for d in args.detail}
        funcs = []
        for f in program.getFunctionManager().getFunctions(True):
            entry = int(f.getEntryPoint().getOffset())
            rec = {"entry": "%x" % entry, "name": f.getName(), "thunk": bool(f.isThunk()),
                   "ranges": [["%x" % r.getMinAddress().getOffset(), "%x" % r.getMaxAddress().getOffset()]
                              for r in f.getBody().getAddressRanges()]}
            try:
                q = hasher.hash(f)
            except Exception as e:  # MemoryAccessException
                q = None
                rec["error"] = str(e)
            if q is not None:
                rec["hash"] = {"units": int(q.getCodeUnitSize()), "full": _u64(q.getFullHash()),
                               "specific_extra": int(q.getSpecificHashAdditionalSize()),
                               "specific": _u64(q.getSpecificHash())}
            if entry in details:
                rec["detail"] = _detail(program, f)
            funcs.append(rec)
        doc = {"binary": os.path.basename(args.binary), "language": str(program.getLanguageID()),
               "image_base": "%x" % program.getImageBase().getOffset(), "functions": funcs}
        if args.fidb:
            doc["matches"] = _search(program, service, args.fidb)
        with open(args.out, "w") as fh:
            json.dump(doc, fh, indent=1)
    finally:
        results.close()
    return 0


def _applied(program, matches) -> str:
    """The name ApplyFidEntriesCommand gives (its processMatches): "" when it
    names nothing, FID_conflict:<first> for several base names."""
    from ghidra.feature.fid.service import MatchNameAnalysis, FidService
    from ghidra.util.task import TaskMonitor

    if matches is None or matches.size() == 0:
        return ""
    a = MatchNameAnalysis()
    a.analyzeNames(matches, program, TaskMonitor.DUMMY)
    if a.getMostOptimisticCount() > 1 and a.getOverallScore() < FidService.MULTINAME_SCORE_THRESHOLD:
        return ""
    if a.numNames() == 1:
        return str(a.getNameIterator().next())
    if a.getMostOptimisticCount() == 1:
        return str(a.getMostOptimisticName())
    return "FID_conflict:" + sorted(str(n) for n in a.getNameIterator())[0]


def _search(program, service, paths: list) -> list:
    """Ghidra's FID search over the given databases, with the analyzer's threshold."""
    from java.io import File
    from ghidra.feature.fid.db import FidFileManager
    from ghidra.util.task import TaskMonitor

    mgr = FidFileManager.getInstance()
    for f in mgr.getFidFiles():
        f.setActive(False)
    for p in paths:
        ff = mgr.addUserFidFile(File(p))
        if ff is None:
            ff = next(x for x in mgr.getFidFiles() if os.path.abspath(str(x.getPath())) == os.path.abspath(p))
        ff.setActive(True)
    out = []
    with service.openFidQueryService(program.getLanguage(), False) as q:
        for r in service.processProgram(program, q, service.getDefaultScoreThreshold(), TaskMonitor.DUMMY):
            ms = []
            for m in r.matches or []:
                fr = m.getFunctionRecord()
                lib = m.getLibraryRecord()
                ms.append({"name": fr.getName(), "score": float(m.getOverallScore()),
                           "primary": float(m.getPrimaryFunctionCodeUnitScore()),
                           "child": float(m.getChildFunctionCodeUnitScore()),
                           "parent": float(m.getParentFunctionCodeUnitScore()),
                           "mode": str(m.getPrimaryFunctionMatchMode()),
                           "library": "%s %s %s" % (lib.getLibraryFamilyName(), lib.getLibraryVersion(),
                                                    lib.getLibraryVariant())})
            out.append({"entry": "%x" % r.function.getEntryPoint().getOffset(), "matches": ms,
                        "applied": _applied(program, r.matches)})
    return out


if __name__ == "__main__":
    sys.exit(main())
