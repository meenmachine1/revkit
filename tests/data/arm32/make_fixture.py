#!/usr/bin/env python3
"""Builds the 32-bit ARM fixture (docs/infer.md, "32-bit ARM").

From the C, C++ and assembly in this directory, compiled with clang for
ARMv5TE (ARM and Thumb code, interworking, soft float) and linked with
ld.lld at 0x02000000, it writes, for each optimization level, what the
firmware corpus holds for an image (corpus/firmware/build.py):

  OUT/arm/arm32-<opt>.elf         the ELF, with DWARF and symbols
  OUT/arm/arm32-<opt>.bin         the raw image: its loaded bytes from 0x02000000
  OUT/arm/arm32-<opt>.truth.json  functions from the DWARF and symbols
  OUT/manifest.json               the images, as the firmware corpus's manifest

so scripts/firmware_score.py, scripts/decomp-quality.py and
tools/ghidra-export/ghidra_export.py --firmware-corpus take OUT as a corpus.

usage: make_fixture.py --clang CLANG --lld LD_LLD --out DIR [--opt O2 --opt Os]
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, os.path.join(ROOT, "corpus", "firmware"))

BASE = 0x02000000
LANGUAGE = "ARM:LE:32:v5t:default"
REGIONS = ["ram:2200000:10000", "stack:23e0000:20000"]
SOURCES = [("veneers.S", []), ("libc.c", ["-marm"]), ("dev.c", ["-marm"]), ("bd.c", ["-marm"]), ("mix.c", ["-marm"]),
           ("main.c", ["-marm"]), ("thumb.c", ["-mthumb"]), ("softfloat.c", ["-mthumb"]),
           ("rt.c", ["-marm"]), ("shapes.cpp", ["-mthumb"]), ("scene.cpp", ["-marm"]),
           ("cxx_main.cpp", ["-mthumb"])]
# clang interworks on ARMv5TE without -mthumb-interwork (which it refuses).
CFLAGS = ["--target=armv5te-none-eabi", "-mfloat-abi=soft", "-g", "-ffreestanding",
          "-nostdlib", "-fno-builtin", "-ffunction-sections", "-fdata-sections", "-fno-unwind-tables",
          "-fno-asynchronous-unwind-tables", "-mno-unaligned-access", "-fno-exceptions"]
CXXFLAGS = ["-fno-rtti", "-fno-threadsafe-statics", "-fno-use-cxa-atexit", "-std=c++17"]


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(" ".join(cmd) + "\n" + r.stdout + r.stderr)
        raise SystemExit(1)
    return r.stdout


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def build(clang, lld, out, opt):
    objdir = os.path.join(out, "obj", opt)
    os.makedirs(objdir, exist_ok=True)
    objs = []
    for src, flags in SOURCES:
        obj = os.path.join(objdir, src + ".o")
        cmd = [clang] + CFLAGS + ["-" + opt] + flags
        if src.endswith(".cpp"):
            cmd += CXXFLAGS
        run(cmd + ["-c", os.path.join(HERE, src), "-o", obj])
        objs.append(obj)
    arch_dir = os.path.join(out, "arm")
    os.makedirs(arch_dir, exist_ok=True)
    name = "arm/arm32-" + opt
    elf = os.path.join(out, name + ".elf")
    run([lld, "-T", os.path.join(HERE, "fixture.ld"), "--gc-sections", "-o", elf] + objs)
    from build import raw_and_truth  # corpus/firmware/build.py (needs pyelftools)

    info = raw_and_truth(elf, os.path.join(out, name + ".bin"), os.path.join(out, name + ".truth.json"))
    assert info["base"] == BASE, hex(info["base"])
    return {
        "name": name, "arch": "arm", "path": name + ".bin", "elf": name + ".elf", "truth": name + ".truth.json",
        "language": LANGUAGE, "base": "0x%x" % info["base"], "entry": "0x%x" % info["entry"], "regions": REGIONS,
        "size": info["size"], "sha256": sha256_file(os.path.join(out, name + ".bin")),
        "elf_sha256": sha256_file(elf), "dwarf_functions": info["dwarf_functions"],
        "symbol_functions": info["symbol_functions"], "project": "arm32-fixture", "opt": opt,
        "target": "armv5te", "src_root": os.path.relpath(HERE, ROOT),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--clang", default="clang")
    ap.add_argument("--lld", default="ld.lld")
    ap.add_argument("--out", required=True)
    ap.add_argument("--opt", action="append", default=[])
    args = ap.parse_args()
    images = [build(args.clang, args.lld, args.out, opt) for opt in (args.opt or ["O2", "Os"])]
    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump({"images": images}, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
