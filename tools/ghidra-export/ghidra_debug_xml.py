#!/usr/bin/env python3
"""Capture Ghidra's decompiler debug XML for chosen functions of a binary.

Imports and auto-analyzes the binary headlessly (as ghidra_export.py does),
then decompiles each function with DecompInterface.enableDebug: the file
written is what the GUI's "Debug Function Decompilation" action saves (an
<xml_savefile> with the bytes, symbols, types and prototypes the decompiler
asked for). The vendored console replays it (third_party/ghidra/README.md,
"Reproducing a decompiler bug"), as does upstream's decomp_dbg:

    restore <file.xml>
    load function <name>
    decompile

Usage:
  ghidra_debug_xml.py [--pdb F] [--timeout S] --out DIR <binary> <entry hex>...
  ghidra_debug_xml.py --raw ARM:LE:32:v4t[:compiler] [--read-only] [--function HEX]... --out DIR <file> <entry hex>...

With --raw the file is loaded as a flat binary at 0 (Ghidra's Raw Binary
loader) in that language; --read-only clears the block's write permission
before analysis, so the decompiler folds reads of it; --function makes a
function at an address analysis doesn't reach.

Writes DIR/<name>_<entry>.xml per function and prints the decompiler's
result (ok, error message, or timeout) for each.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ghidra_export  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("entries", nargs="+", help="function entry points (hex)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--pdb")
    ap.add_argument("--timeout", type=int, default=60, help="decompiler timeout per function (s)")
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR", ghidra_export.DEFAULT_GHIDRA))
    ap.add_argument("--heap", default="4g")
    ap.add_argument("--raw", metavar="LANG", help="load as a raw binary in this language (proc:endian:size:variant[:compiler])")
    ap.add_argument("--read-only", action="store_true", help="with --raw: the image is not writable")
    ap.add_argument("--function", action="append", default=[], metavar="HEX", help="with --raw: create a function here")
    args = ap.parse_args(argv)

    os.makedirs(args.out, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="rk-debugxml-")
    ghidra_export.worker_init(args.ghidra, args.heap, tmp, args.timeout)

    from java.io import File
    from ghidra.app.util.importer import MessageLog, ProgramLoader
    from ghidra.util.task import TaskMonitor

    builder = (ProgramLoader.builder().source(File(args.binary)).name(os.path.basename(args.binary))
               .log(MessageLog()).monitor(TaskMonitor.DUMMY))
    if args.raw:
        parts = args.raw.split(":")
        builder = builder.loaders("BinaryLoader").language(":".join(parts[:4]))
        builder = builder.compiler(parts[4] if len(parts) > 4 else "default")
    results = builder.load()
    try:
        program = results.getPrimaryDomainObject()
        if args.raw and (args.read_only or args.function):
            tx = program.startTransaction("raw setup")
            try:
                if args.read_only:
                    for block in program.getMemory().getBlocks():
                        block.setWrite(False)
                space0 = program.getAddressFactory().getDefaultAddressSpace()
                from ghidra.app.cmd.function import CreateFunctionCmd
                from ghidra.app.cmd.disassemble import DisassembleCommand
                for text in args.function:
                    a = space0.getAddress(int(text, 16))
                    DisassembleCommand(a, None, True).applyTo(program, TaskMonitor.DUMMY)
                    CreateFunctionCmd(a).applyTo(program, TaskMonitor.DUMMY)
            finally:
                program.endTransaction(tx, True)
        if args.pdb:
            from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
            tx = program.startTransaction("pdb option")
            try:
                PdbUniversalAnalyzer.setPdbFileOption(program, File(args.pdb))
            finally:
                program.endTransaction(tx, True)
        ghidra_export._analyze(program)
        space = program.getAddressFactory().getDefaultAddressSpace()
        status = 0
        for text in args.entries:
            entry = int(text, 16)
            func = program.getFunctionManager().getFunctionAt(space.getAddress(entry))
            if func is None:
                print(f"{text}: no function", flush=True)
                status = 1
                continue
            path = os.path.join(args.out, f"{func.getName()}_{entry:x}.xml")
            ifc = ghidra_export._decompiler(program)
            try:
                ifc.enableDebug(File(path))
                res = ifc.decompileFunction(func, args.timeout, TaskMonitor.DUMMY)
                if res.decompileCompleted():
                    what = "ok"
                elif res.isTimedOut():
                    what = "timeout"
                else:
                    what = "failed: " + str(res.getErrorMessage()).strip()
            finally:
                ifc.dispose()
            print(f"{text} {func.getName()}: {what} -> {path}", flush=True)
    finally:
        results.close()
    return status


if __name__ == "__main__":
    sys.exit(main())
