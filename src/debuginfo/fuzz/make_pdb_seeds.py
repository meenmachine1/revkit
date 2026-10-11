#!/usr/bin/env python3
"""Write pdb_fuzzer seeds from PDB files: make_pdb_seeds.py OUTDIR PDB...

For each PDB, two seeds: the file itself (truncated to --max-raw bytes if
larger), and its streams as [u32 length][bytes] records, which the fuzzer
packs into a fresh MSF container.
"""

import argparse
import os
import struct


def streams(data: bytes):
    bs, _, nblocks, dir_bytes, _, map_addr = struct.unpack_from("<6I", data, 32)
    ndir = (dir_bytes + bs - 1) // bs
    dir_blocks = struct.unpack_from("<%dI" % ndir, data, map_addr * bs)
    d = b"".join(data[b * bs:(b + 1) * bs] for b in dir_blocks)[:dir_bytes]
    n, = struct.unpack_from("<I", d, 0)
    sizes = struct.unpack_from("<%dI" % n, d, 4)
    pos = 4 + 4 * n
    out = []
    for size in sizes:
        if size == 0xffffffff:
            out.append(b"")
            continue
        count = (size + bs - 1) // bs
        blocks = struct.unpack_from("<%dI" % count, d, pos)
        pos += 4 * count
        out.append(b"".join(data[b * bs:(b + 1) * bs] for b in blocks)[:size])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("outdir")
    ap.add_argument("pdbs", nargs="+")
    ap.add_argument("--max-raw", type=int, default=1 << 20)
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    for path in args.pdbs:
        data = open(path, "rb").read()
        base = os.path.basename(path).replace(".", "_")
        with open(os.path.join(args.outdir, base + ".raw"), "wb") as f:
            f.write(data[:args.max_raw])
        with open(os.path.join(args.outdir, base + ".streams"), "wb") as f:
            for s in streams(data):
                f.write(struct.pack("<I", len(s)) + s)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
