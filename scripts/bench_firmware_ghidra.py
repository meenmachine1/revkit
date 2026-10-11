#!/usr/bin/env python3
"""Ghidra's side of the firmware benchmark, headless (PyGhidra): import a raw
firmware image as Ghidra's Raw Binary loader does, with the same memory map
revkit is given, run Ghidra's default auto-analysis, and write its function
list, its listing and its decompiled C for chosen functions (or all).

Used by scripts/bench-firmware.sh --headless: a second reference beside the
user's own Ghidra, or the only one when there is none. It works on a
throwaway in-memory program: nothing is saved and no existing Ghidra project
is opened.

  bench_firmware_ghidra.py --lang ARM:LE:32:v4t[:compiler] [--offset HEX] [--base HEX]
                           [--region name:start:size[:perms]]... [--all-c] --out OUT.json <file> [<entry hex>...]
  bench_firmware_ghidra.py --elf [--all-c] --out OUT.json <file> [<entry hex>...]

With --elf the file is loaded as Ghidra's loaders take it (ELF: its own
language, image base and relocations), not as a raw image.

OUT.json:
  "functions":    [{"address": "0001a2b0", "name": ..., "thumb": bool, "size": instructions in the body}]
  "instructions": [address, ...]                   every instruction in the listing
  "listing":      [[address, length, thumb, in a function, text], ...]   the
                  same, with the instruction set (ARM's TMode), whether a
                  function's body has it, and Ghidra's text
  "bad":          [[address, category, comment], ...]     Ghidra's Error bookmarks
                  (Bad Instruction, conflicting code, failed disassembly)
  "c":            {"0x1a2b0": "C text" | null}     C for the given entries, or
                  for every function with --all-c (null: Ghidra couldn't)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools", "ghidra-export"))
import ghidra_export  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("entries", nargs="*")
    ap.add_argument("--lang")
    ap.add_argument("--elf", action="store_true", help="load with Ghidra's own loaders (an ELF), not as raw bytes")
    ap.add_argument("--offset", default="0", help="header bytes to skip (hex)")
    ap.add_argument("--base", default="0", help="the image's address (hex)")
    ap.add_argument("--region", action="append", default=[], help="name:start:size[:perms] (hex), uninitialized")
    ap.add_argument("--all-c", action="store_true", help="decompile every function")
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR", ghidra_export.DEFAULT_GHIDRA))
    ap.add_argument("--heap", default="4g")
    args = ap.parse_args(argv)
    if not args.elf and not args.lang:
        ap.error("--lang is required for a raw image")

    tmp = tempfile.mkdtemp(prefix="rk-benchfw-")
    # The image without its header, as the raw loader sees it.
    with open(args.file, "rb") as f:
        data = f.read()[int(args.offset, 16):]
    image = os.path.join(tmp, os.path.basename(args.file))
    with open(image, "wb") as f:
        f.write(data)

    ghidra_export.worker_init(args.ghidra, args.heap, tmp, args.timeout)
    from java.io import File
    from ghidra.app.util.importer import MessageLog, ProgramLoader
    from ghidra.util.task import TaskMonitor

    if args.elf:
        results = (ProgramLoader.builder().source(File(args.file)).name(os.path.basename(args.file))
                   .log(MessageLog()).monitor(TaskMonitor.DUMMY).load())
    else:
        parts = args.lang.split(":")
        results = (ProgramLoader.builder().source(File(image)).name(os.path.basename(args.file))
                   .loaders("BinaryLoader").language(":".join(parts[:4]))
                   .compiler(parts[4] if len(parts) > 4 else "default")
                   .log(MessageLog()).monitor(TaskMonitor.DUMMY).load())
    try:
        program = results.getPrimaryDomainObject()
        space = program.getAddressFactory().getDefaultAddressSpace()
        tx = program.startTransaction("regions")
        try:
            base = 0 if args.elf else int(args.base, 16)
            if base:
                program.setImageBase(space.getAddress(base), True)
            for spec in args.region:
                name, start, size, *rest = spec.split(":")
                block = program.getMemory().createUninitializedBlock(name, space.getAddress(int(start, 16)),
                                                                     int(size, 16), False)
                perms = rest[0] if rest else "rw-"
                block.setRead(perms[0] == "r")
                block.setWrite(perms[1] == "w")
                block.setExecute(perms[2] == "x")
        finally:
            program.endTransaction(tx, True)
        ghidra_export._analyze(program)

        tmode = program.getRegister("TMode")

        def thumb(insn) -> bool:
            if tmode is None:
                return False
            v = insn.getValue(tmode, False)
            return v is not None and int(v.intValue()) == 1

        listing = program.getListing()
        fm = program.getFunctionManager()

        def real(func) -> bool:
            # Not an import: external, or a thunk in the loader's EXTERNAL block.
            if func.isExternal() or not func.getEntryPoint().isMemoryAddress():
                return False
            block = program.getMemory().getBlock(func.getEntryPoint())
            return block is None or block.getName() != "EXTERNAL"
        out = {"functions": [], "c": {}, "instructions": [], "listing": [], "bad": [],
               "image_base": "%x" % program.getImageBase().getOffset(), "language": str(program.getLanguageID())}
        for func in fm.getFunctions(True):
            if not real(func):
                continue
            first = listing.getInstructionAt(func.getEntryPoint())
            size = sum(1 for _ in listing.getInstructions(func.getBody(), True))
            out["functions"].append({"address": "%08x" % func.getEntryPoint().getOffset(), "name": func.getName(),
                                     "thumb": first is not None and thumb(first), "size": size})
        for insn in listing.getInstructions(True):
            a = int(insn.getAddress().getOffset())
            out["instructions"].append(a)
            inside = fm.getFunctionContaining(insn.getAddress()) is not None
            out["listing"].append([a, int(insn.getLength()), thumb(insn), inside, str(insn.toString())])
        it = program.getBookmarkManager().getBookmarksIterator("Error")
        while it.hasNext():
            b = it.next()
            out["bad"].append([int(b.getAddress().getOffset()), str(b.getCategory()), str(b.getComment())])
        ifc = ghidra_export._decompiler(program)
        try:
            if args.all_c:
                funcs = [f for f in fm.getFunctions(True) if real(f)]
            else:
                funcs = [fm.getFunctionAt(space.getAddress(int(t, 16))) for t in args.entries]
            for func in funcs:
                if func is None:
                    continue
                res = ifc.decompileFunction(func, args.timeout, TaskMonitor.DUMMY)
                key = "0x%x" % func.getEntryPoint().getOffset()
                out["c"][key] = str(res.getDecompiledFunction().getC()) if res.decompileCompleted() else None
        finally:
            ifc.dispose()
        with open(args.out, "w") as f:
            json.dump(out, f)
    finally:
        results.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
