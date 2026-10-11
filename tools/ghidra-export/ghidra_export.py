#!/usr/bin/env python3
"""Export Ghidra reference JSON for corpus binaries (docs/reference-format.md).

Each worker process starts one headless Ghidra JVM via PyGhidra and handles
binaries from a shared queue: import, auto-analyze, export, discard. Nothing is
saved to a Ghidra project; programs live in memory only (any scratch project
goes under a temp dir).

Usage:
  ghidra_export.py --corpus out/corpus --out out/ref -j 8
  ghidra_export.py --out out/ref path/to/binary [more binaries...]
  ghidra_export.py --firmware-corpus out/firmware-corpus --out out/firmware-ref

Raw images (--firmware-corpus, corpus/firmware) are imported as Ghidra's
Raw Binary loader does, with the layout revkit is given from the manifest:
language, load address, entry point, and RAM/MMIO regions (uninitialized
blocks; volatile for MMIO).
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import multiprocessing as mp
import os
import shutil
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "refdiff"))
import refformat  # noqa: E402

DEFAULT_GHIDRA = os.path.expanduser("~/ghidra/ghidra_12.1.4_PUBLIC")


# --------------------------------------------------------------------------
# Job discovery (runs in the parent, no JVM needed)

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def jobs_from_manifest(corpus: str, patterns: list[str]) -> list[dict]:
    """One job per manifest entry. `path` is relative to the corpus dir."""
    manifest_path = os.path.join(corpus, "manifest.json")
    with open(manifest_path) as f:
        manifest = json.load(f)
    jobs = []
    for entry in manifest["binaries"]:
        rel = entry["path"]
        if patterns and not any(fnmatch.fnmatch(rel, p) for p in patterns):
            continue
        job = {"rel": rel, "file": os.path.join(corpus, rel)}
        if entry.get("pdb"):
            job["pdb"] = os.path.join(corpus, entry["pdb"])
        jobs.append(job)
    return jobs


def jobs_from_firmware_manifest(corpus: str, patterns: list[str]) -> list[dict]:
    """One job per raw image in a firmware corpus manifest (corpus/firmware)."""
    with open(os.path.join(corpus, "manifest.json")) as f:
        manifest = json.load(f)
    jobs = []
    for entry in manifest["images"]:
        rel = entry["path"]
        if patterns and not any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(entry["name"], p) for p in patterns):
            continue
        jobs.append({"rel": rel, "file": os.path.join(corpus, rel),
                     "raw": {"language": entry["language"], "base": entry["base"], "entry": entry["entry"],
                             "regions": entry.get("regions", [])}})
    return jobs


def jobs_from_files(files: list[str]) -> list[dict]:
    jobs = []
    for path in files:
        job = {"rel": os.path.basename(path), "file": path}
        pdb = os.path.splitext(path)[0] + ".pdb"
        if os.path.exists(pdb):
            job["pdb"] = pdb
        jobs.append(job)
    return jobs


# --------------------------------------------------------------------------
# Worker side (runs inside a process with a JVM)

_state: dict = {}


def worker_init(ghidra_dir: str, heap: str, tmp_root: str, decompile_timeout: int) -> None:
    os.environ["GHIDRA_INSTALL_DIR"] = ghidra_dir
    # Nothing is saved to a project; Java's temp files go under tmp_root.
    from pyghidra.launcher import HeadlessPyGhidraLauncher

    launcher = HeadlessPyGhidraLauncher(install_dir=ghidra_dir)
    launcher.add_vmargs("-Xmx" + heap, "-Djava.io.tmpdir=" + tmp_root)
    launcher.start()
    _state["tmp_root"] = tmp_root
    _state["decompile_timeout"] = decompile_timeout


def _perms(block) -> str:
    return ("r" if block.isRead() else "-") + ("w" if block.isWrite() else "-") + (
        "x" if block.isExecute() else "-")


def _varnode(vn, op_code: int, index: int):
    from ghidra.program.model.pcode import PcodeOp

    space = vn.getAddress().getAddressSpace()
    size = int(vn.getSize())
    # LOAD/STORE input 0 names an address space. Its numeric value is an
    # implementation detail (Java space ID vs C++ AddrSpace pointer), so the
    # format writes the space's name instead.
    if index == 0 and op_code in (PcodeOp.LOAD, PcodeOp.STORE) and vn.isConstant():
        spc = _state["program"].getAddressFactory().getAddressSpace(int(vn.getOffset()))
        name = spc.getName() if spc is not None else "0x%x" % (int(vn.getOffset()) & ((1 << 64) - 1))
        return ["space", name, size]
    offset = int(vn.getOffset())
    if vn.isConstant() and size < 8:
        offset &= (1 << (8 * size)) - 1
    else:
        offset &= (1 << 64) - 1
    return [space.getName(), "0x%x" % offset, size]


def _pcode(instr) -> list:
    ops = []
    for op in instr.getPcode(False):
        code = int(op.getOpcode())
        out = op.getOutput()
        ops.append({
            "op": op.getMnemonic(),
            "out": None if out is None else _varnode(out, code, -1),
            "in": [_varnode(op.getInput(i), code, i) for i in range(op.getNumInputs())],
        })
    return ops


def _analyze(program) -> str:
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.app.script import GhidraScriptUtil
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.util.task import TaskMonitor

    tx = program.startTransaction("revkit analyze")
    GhidraScriptUtil.acquireBundleHostReference()
    try:
        mgr = AutoAnalysisManager.getAnalysisManager(program)
        mgr.initializeOptions()
        mgr.reAnalyzeAll(None)
        mgr.startAnalysis(TaskMonitor.DUMMY, True)
        GhidraProgramUtilities.markProgramAnalyzed(program)
        return str(mgr.getMessageLog().toString())
    finally:
        GhidraScriptUtil.releaseBundleHostReference()
        program.endTransaction(tx, True)


def _decompiler(program):
    from ghidra.app.decompiler import DecompInterface, DecompileOptions

    opts = DecompileOptions()
    opts.grabFromProgram(program)
    ifc = DecompInterface()
    ifc.setOptions(opts)
    ifc.toggleCCode(True)
    ifc.toggleSyntaxTree(True)
    ifc.setSimplificationStyle("decompile")
    if not ifc.openProgram(program):
        raise RuntimeError("decompiler failed to open program: " + str(ifc.getLastMessage()))
    return ifc


def export_program(program, rel: str, sha: str, stats: dict) -> dict:
    from ghidra.program.model.address import AddressSet
    from ghidra.util.task import TaskMonitor

    _state["program"] = program
    default_space = program.getAddressFactory().getDefaultAddressSpace()
    listing = program.getListing()

    def addr(a) -> str:
        return "0x%x" % (int(a.getOffset()) & ((1 << 64) - 1))

    memory = []
    for block in program.getMemory().getBlocks():
        if not block.isLoaded() or block.isOverlay():
            continue
        entry = {
            "name": str(block.getName()),
            "start": addr(block.getStart()),
            "end": addr(block.getEnd()),
            "perms": _perms(block),
        }
        if block.getStart().getAddressSpace() != default_space:
            entry["space"] = str(block.getStart().getAddressSpace().getName())
        memory.append(entry)

    functions = []
    covered = AddressSet()
    ifc = _decompiler(program)
    timeout = _state["decompile_timeout"]
    decompile_failures = []
    try:
        for func in listing.getFunctions(True):
            body = func.getBody()
            covered.add(body)
            entry = {
                "entry": addr(func.getEntryPoint()),
                "name": str(func.getName()),
                "body": [[addr(r.getMinAddress()), addr(r.getMaxAddress())]
                         for r in body.getAddressRanges()],
                "prototype": str(func.getPrototypeString(False, False)),
            }
            res = ifc.decompileFunction(func, timeout, TaskMonitor.DUMMY)
            df = res.getDecompiledFunction() if res is not None else None
            if df is not None:
                entry["decompiled_c"] = str(df.getC())
            else:
                msg = str(res.getErrorMessage()) if res is not None else "no result"
                decompile_failures.append({"entry": entry["entry"], "error": msg.strip()})
            functions.append(entry)
    finally:
        ifc.dispose()

    instructions = []
    pcode_ops = 0
    for instr in listing.getInstructions(covered, True):
        pcode = _pcode(instr)
        pcode_ops += len(pcode)
        instructions.append({
            "addr": addr(instr.getAddress()),
            "len": int(instr.getLength()),
            "mnemonic": str(instr.getMnemonicString()),
            "text": str(instr.toString()),
            "pcode": pcode,
        })

    stats.update(functions=len(functions), instructions=len(instructions),
                 pcode_ops=pcode_ops, decompile_failures=decompile_failures)
    return {
        "format_version": refformat.FORMAT_VERSION,
        "producer": "ghidra-" + str(_ghidra_version()),
        "binary": {
            "path": rel,
            "sha256": sha,
            "language": str(program.getLanguageID().getIdAsString()),
            "compiler": str(program.getCompilerSpec().getCompilerSpecID().getIdAsString()),
            "image_base": addr(program.getImageBase()),
        },
        "memory": memory,
        "functions": functions,
        "instructions": instructions,
    }


def _ghidra_version() -> str:
    from ghidra.framework import Application
    return Application.getApplicationVersion()


def load_raw(path: str, raw: dict, log):
    """Ghidra's Raw Binary loader with revkit's layout (`raw`: language
    "proc:endian:size:variant[:compiler]", base and entry as hex strings,
    regions as rk-lift's name:start:size[:perms][:init|uninit|volatile])."""
    from java.io import File
    from ghidra.app.util.importer import ProgramLoader
    from ghidra.util.task import TaskMonitor

    parts = raw["language"].split(":")
    return (ProgramLoader.builder().source(File(path)).name(os.path.basename(path))
            .loaders("BinaryLoader").language(":".join(parts[:4]))
            .compiler(parts[4] if len(parts) > 4 else "default")
            .addLoaderArg("-loader-baseAddr", raw.get("base", "0x0"))
            .log(log).monitor(TaskMonitor.DUMMY).load())


def apply_raw_layout(program, raw: dict) -> None:
    """The regions and the entry point, as a user would add them before
    analysis."""
    from ghidra.program.model.symbol import SourceType

    factory = program.getAddressFactory()
    space = factory.getDefaultAddressSpace()
    tx = program.startTransaction("raw layout")
    try:
        for spec in raw.get("regions", []):
            name, start, size, *flags = spec.split(":")
            perms = next((f for f in flags if len(f) == 3 and f[0] in "r-"), "rw-")
            # "space=EXTMEM": a block in another memory space (the 8051's
            # external RAM); start is a byte offset there.
            named = next((f[6:] for f in flags if f.startswith("space=")), None)
            in_space = factory.getAddressSpace(named) if named else space
            if in_space is None:
                raise RuntimeError("the language has no address space %s" % named)
            block = program.getMemory().createUninitializedBlock(name, in_space.getAddress(int(start, 16)),
                                                                 int(size, 16), False)
            block.setRead(perms[0] == "r")
            block.setWrite(perms[1] == "w")
            block.setExecute(perms[2] == "x")
            block.setVolatile("volatile" in flags)
        if raw.get("entry"):
            entry = space.getAddress(int(raw["entry"], 16))
            program.getSymbolTable().addExternalEntryPoint(entry)
            program.getSymbolTable().createLabel(entry, "entry", SourceType.IMPORTED)
    finally:
        program.endTransaction(tx, True)


def run_job(job: dict) -> dict:
    """Import, analyze and export one binary. Returns a stats dict."""
    from java.io import File
    from ghidra.app.util.importer import ProgramLoader
    from ghidra.app.util.importer import MessageLog
    from ghidra.util.task import TaskMonitor

    stats = {"rel": job["rel"], "ok": False}
    t0 = time.monotonic()
    try:
        sha = sha256_file(job["file"])
        log = MessageLog()
        if job.get("raw"):
            results = load_raw(job["file"], job["raw"], log)
        else:
            results = (ProgramLoader.builder()
                       .source(File(job["file"]))
                       .name(os.path.basename(job["file"]))
                       .log(log)
                       .monitor(TaskMonitor.DUMMY)
                       .load())
        try:
            program = results.getPrimaryDomainObject()
            if job.get("raw"):
                apply_raw_layout(program, job["raw"])
            t1 = time.monotonic()
            if job.get("pdb"):
                from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
                tx = program.startTransaction("pdb option")
                try:
                    PdbUniversalAnalyzer.setPdbFileOption(program, File(job["pdb"]))
                finally:
                    program.endTransaction(tx, True)
            _analyze(program)
            t2 = time.monotonic()
            doc = export_program(program, job["rel"], sha, stats)
            refformat.write(job["out"], doc)
            if job.get("inputs_out"):
                # Decompiler inputs from the same analysis (ghidra_dbexport.py),
                # so they can't differ from what this reference was made with.
                import ghidra_dbexport
                ghidra_dbexport.write_json(job["inputs_out"],
                                           ghidra_dbexport.export_db(program, job["rel"], sha, {}))
            t3 = time.monotonic()
            stats.update(ok=True, import_s=round(t1 - t0, 2), analyze_s=round(t2 - t1, 2),
                         export_s=round(t3 - t2, 2))
        finally:
            _state.pop("program", None)
            results.close()
    except Exception:  # report and move on to the next binary
        stats["error"] = traceback.format_exc()
    stats["total_s"] = round(time.monotonic() - t0, 2)
    return stats


# --------------------------------------------------------------------------
# Parent

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="binaries to export (instead of --corpus)")
    ap.add_argument("--corpus", help="corpus output dir containing manifest.json")
    ap.add_argument("--firmware-corpus", help="firmware corpus dir (corpus/firmware's manifest.json): raw images")
    ap.add_argument("--only", action="append", default=[], metavar="GLOB",
                    help="export only manifest paths matching GLOB (repeatable)")
    ap.add_argument("--out", required=True, help="output dir; writes <path>.json per binary")
    ap.add_argument("--gzip", action="store_true", help="write .json.gz instead of .json")
    ap.add_argument("-j", "--jobs", type=int, default=0,
                    help="worker processes (default: min(binaries, cores/3, RAM/3GB))")
    ap.add_argument("--heap", default="3g", help="max Java heap per worker (default 3g)")
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR", DEFAULT_GHIDRA))
    ap.add_argument("--decompile-timeout", type=int, default=120, help="seconds per function")
    ap.add_argument("--skip-existing", action="store_true",
                    help="skip binaries whose output exists and matches the binary's sha256")
    ap.add_argument("--stats", help="write per-binary timing stats JSON here")
    ap.add_argument("--inputs-out", metavar="DIR",
                    help="also write Ghidra's decompiler inputs (ghidra_dbexport.py) from the same analysis")
    args = ap.parse_args(argv)

    if args.firmware_corpus:
        jobs = jobs_from_firmware_manifest(args.firmware_corpus, args.only)
    elif args.corpus:
        jobs = jobs_from_manifest(args.corpus, args.only)
    elif args.files:
        jobs = jobs_from_files(args.files)
    else:
        ap.error("give --corpus or binaries")
    suffix = ".json.gz" if args.gzip else ".json"
    for job in jobs:
        job["out"] = os.path.join(args.out, job["rel"] + suffix)
        if args.inputs_out:
            job["inputs_out"] = os.path.join(args.inputs_out, job["rel"] + ".json")
    if args.skip_existing:
        jobs = [j for j in jobs if not _up_to_date(j)]
    if not jobs:
        print("nothing to export")
        return 0
    # Largest first so the long ones don't straggle at the end.
    jobs.sort(key=lambda j: (-os.path.getsize(j["file"]), j["rel"]))

    njobs = args.jobs or max(1, min(len(jobs), (os.cpu_count() or 4) // 3, _ram_gb() // 3))
    tmp_root = tempfile.mkdtemp(prefix="revkit-ghidra-export-")
    print("exporting %d binaries with %d workers (heap %s each)" % (len(jobs), njobs, args.heap),
          flush=True)
    start = time.monotonic()
    results = []
    try:
        ctx = mp.get_context("spawn")
        with ctx.Pool(njobs, initializer=worker_init,
                      initargs=(args.ghidra, args.heap, tmp_root, args.decompile_timeout),
                      maxtasksperchild=25) as pool:
            for stats in pool.imap_unordered(run_job, jobs, chunksize=1):
                results.append(stats)
                if stats["ok"]:
                    print("[%d/%d] %-50s %6.1fs  %5d funcs %7d insns" % (
                        len(results), len(jobs), stats["rel"], stats["total_s"],
                        stats["functions"], stats["instructions"]), flush=True)
                else:
                    print("[%d/%d] %s FAILED\n%s" % (len(results), len(jobs), stats["rel"],
                                                    stats["error"]), flush=True)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)
    wall = time.monotonic() - start
    failed = [s for s in results if not s["ok"]]
    print("exported %d/%d binaries in %.1fs wall (%d workers)" % (
        len(results) - len(failed), len(jobs), wall, njobs))
    if args.stats:
        with open(args.stats, "w") as f:
            json.dump({"wall_s": round(wall, 1), "workers": njobs,
                       "binaries": sorted(results, key=lambda s: s["rel"])}, f, indent=1, sort_keys=True)
            f.write("\n")
    return 1 if failed else 0


def _ram_gb() -> int:
    try:
        return int(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / (1 << 30))
    except (ValueError, OSError):
        return 16


def _up_to_date(job: dict) -> bool:
    if not os.path.exists(job["out"]):
        return False
    try:
        doc = refformat.load(job["out"])
    except Exception:
        return False
    return doc.get("binary", {}).get("sha256") == sha256_file(job["file"])


if __name__ == "__main__":
    sys.exit(main())
