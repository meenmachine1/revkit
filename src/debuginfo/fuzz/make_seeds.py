#!/usr/bin/env python3
"""Write dwarf_fuzzer seed inputs from ELF files: make_seeds.py OUTDIR ELF..."""

import os
import struct
import sys
import zlib

SECTIONS = [".debug_info", ".debug_abbrev", ".debug_str", ".debug_line_str",
            ".debug_str_offsets", ".debug_addr", ".debug_rnglists", ".debug_ranges"]


def elf_sections(data: bytes):
    is64, big = data[4] == 2, data[5] == 2
    e = ">" if big else "<"
    if is64:
        shoff, = struct.unpack_from(e + "Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x3a)
        fmt = e + "IIQQQQIIQQ"
    else:
        shoff, = struct.unpack_from(e + "I", data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x2e)
        fmt = e + "IIIIIIIIII"
    hdrs = [struct.unpack_from(fmt, data, shoff + i * shentsize) for i in range(shnum)]
    stroff = hdrs[shstrndx][4]
    out = {}
    for h in hdrs:
        name_off, typ, flags, off, size = h[0], h[1], h[2], h[4], h[5]
        name = data[stroff + name_off:data.index(b"\0", stroff + name_off)].decode()
        body = data[off:off + size]
        if flags & 0x800:  # SHF_COMPRESSED, zlib
            body = zlib.decompress(body[24 if is64 else 12:])
        out[name] = body
    return out, big, is64


def main():
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    for path in sys.argv[2:]:
        secs, big, is64 = elf_sections(open(path, "rb").read())
        blob = bytes([(1 if big else 0) | (0 if is64 else 2)])
        for i, name in enumerate(SECTIONS):
            if name in secs:
                blob += struct.pack("<BI", i, len(secs[name])) + secs[name]
        name = path.strip("/").replace("/", "_")
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(blob)


if __name__ == "__main__":
    main()
