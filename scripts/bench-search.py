#!/usr/bin/env python3
"""Search speed (docs/api.md "Search", docs/scale.md) through the real
daemon and the Python SDK, on cmake (corpus/large) and a 16 MiB firmware
image made from the firmware corpus.

    scripts/bench-search.py [--daemon build/tools/rk-daemon/rk-daemon]
                            [--cmake /usr/bin/cmake] [--only cmake,firmware]
                            [--decompile-functions 500] [--json out.jsonl]

The firmware image is deterministic: the firmware corpus's PowerPC U-Boot
(out/firmware-corpus/ppc/uboot-MCR3000.bin) at its load address, then
pseudo-random bytes (SHA-256 in counter mode, standing in for a compressed
kernel and root file system) to 15 MiB, then 0xff (erased flash) to 16 MiB,
imported raw as PowerPC:BE:32:default.

Each search is timed in wall-clock milliseconds from the call to its last
message, plus the daemon's own `elapsed_ms`. "cold" is the first row search
after import (it decodes the listing); the rest are warm.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "sdk" / "python"))

from revkit.client import Client  # noqa: E402
from revkit.daemon import Daemon  # noqa: E402

FIRMWARE = root / "out" / "firmware-corpus" / "ppc" / "uboot-MCR3000.bin"
FIRMWARE_BASE = 0x3FF0000  # out/firmware-corpus/ppc/uboot-MCR3000.truth.json
SIZE = 16 << 20


def make_firmware(path: Path) -> None:
    code = FIRMWARE.read_bytes()
    out = bytearray(code)
    counter = 0
    while len(out) < 15 << 20:
        out += hashlib.sha256(counter.to_bytes(8, "little")).digest()
        counter += 1
    del out[15 << 20 :]
    out += b"\xff" * (SIZE - len(out))
    path.write_bytes(bytes(out))


def timed(fn):
    t = time.monotonic()
    result = fn()
    return result, (time.monotonic() - t) * 1000


def bench(rk: Client, program_id: str, which: str, decompile_functions: int) -> list:
    prog = rk.program(program_id)
    rows = []

    def row(kind: str, what: str, fn):
        hits, ms = timed(fn)
        last = prog.last_search
        rows.append({
            "program": which, "search": kind, "query": what, "matches": len(hits),
            "truncated": bool(last.truncated), "wall_ms": round(ms, 1), "daemon_ms": round(last.elapsed_ms, 1),
        })
        print(json.dumps(rows[-1]), flush=True)
        return hits

    big = 100000
    if which == "cmake":
        hexq, insn, word = "48 8b ?? e8", "xor eax,eax", "usage"
    else:
        hexq, insn, word = "7c 08 02 a6", "mfspr r0,LR", "error"
    # Memory: every format over all of memory.
    row("memory", f"hex {hexq}", lambda: prog.search_memory(hexq, max_results=big, details=False))
    row("memory", f"hex {hexq}, with details", lambda: prog.search_memory(hexq, max_results=big))
    row("memory", f"string {word!r}, any case", lambda: prog.search_memory(word, format="string", max_results=big))
    row("memory", f"string {word!r}, UTF-16", lambda: prog.search_memory(word, format="string", encoding="utf16", max_results=big))
    row("memory", "decimal 1000000 (4 bytes)", lambda: prog.search_memory("1000000", format="decimal", max_results=big))
    row("memory", "double 0.5", lambda: prog.search_memory("0.5", format="double", max_results=big))
    row("memory", "regex [\\x20-\\x7e]{64}", lambda: prog.search_memory(r"[\x20-\x7e]{64}", format="regex", max_results=big, details=False))
    row("memory", "binary 1x0x1x0x 11110000 (not found: a full pass)", lambda: prog.search_memory("1x0x1x0x 11111111 00000000 10101010", format="binary"))
    blocks = sorted((b for b in prog.memory_map() if b.initialized), key=lambda b: b.range.last.offset - b.range.first.offset)
    mid = (blocks[-1].range.first.offset + blocks[-1].range.last.offset) // 2
    row("memory", f"hex {hexq}, next from the middle", lambda: prog.search_memory(hexq, start=mid, max_results=1))
    row("memory", f"hex {hexq}, previous from the middle", lambda: prog.search_memory(hexq, start=mid, backward=True, max_results=1))
    # Program text and scalars: the first decodes the listing.
    row("text (cold)", insn, lambda: prog.search_text(insn, max_results=big))
    row("text", insn, lambda: prog.search_text(insn, max_results=big))
    row("text", "regex ^CALL|^BL", lambda: prog.search_text(r"^(CALL|BL) ", regex=True, max_results=big))
    row("text", f"{word!r}, labels and comments", lambda: prog.search_text(word, fields=["labels", "comments"], max_results=big))
    row("text", f"{insn}, next from the middle", lambda: prog.search_text(insn, start=mid, max_results=1))
    row("scalars", "0x1000", lambda: prog.search_scalars(value=0x1000, max_results=big))
    row("scalars", "0..0xff", lambda: prog.search_scalars(0, 0xFF, max_results=big))
    # Decompiled C: N functions spread evenly over the program (cold:
    # decompiled now; then from the memo).
    every = [f.entry.offset for f in prog.functions(page_size=5000)]
    step = max(1, len(every) // max(1, decompile_functions))
    fns = every[::step][:decompile_functions]
    row("decompiled (cold)", f"'if', {len(fns)} functions", lambda: prog.search_decompiled("if", functions=fns, max_results=big))
    row("decompiled (memoized)", f"'if', {len(fns)} functions", lambda: prog.search_decompiled("if", functions=fns, max_results=big))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--daemon", default=str(root / "build" / "tools" / "rk-daemon" / "rk-daemon"))
    ap.add_argument("--cmake", default="/usr/bin/cmake")
    ap.add_argument("--only", default="cmake,firmware")
    ap.add_argument("--decompile-functions", type=int, default=500)
    ap.add_argument("--grpc", default="127.0.0.1:54121")
    ap.add_argument("--http", default="127.0.0.1:54122")
    ap.add_argument("--json", default="")
    args = ap.parse_args()
    only = set(args.only.split(","))
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        d = Daemon(args.daemon, "--backend", "image", "--no-web-root", startup_timeout=600, grpc=args.grpc, http=args.http)
        d.start()
        try:
            with Client(d.grpc_target, timeout=3600) as rk:
                if "cmake" in only:
                    imported, ms = timed(lambda: rk.import_program("default", path=os.path.abspath(args.cmake)))
                    print(f"cmake imported in {ms / 1000:.1f} s", flush=True)
                    results += bench(rk, imported.program.program_id, "cmake", args.decompile_functions)
                if "firmware" in only:
                    if not FIRMWARE.exists():
                        print(f"skipping the firmware image: {FIRMWARE} not built (scripts/build-firmware-corpus.sh)")
                    else:
                        fw = Path(tmp) / "fw16.bin"
                        make_firmware(fw)
                        imported, ms = timed(lambda: rk.import_program(
                            "default", path=str(fw), format="raw", language_id="PowerPC:BE:32:default", image_base=FIRMWARE_BASE))
                        print(f"firmware imported in {ms / 1000:.1f} s", flush=True)
                        results += bench(rk, imported.program.program_id, "firmware-16MiB", args.decompile_functions)
        finally:
            d.stop()
    print()
    print("| program | search | query | matches | wall ms | daemon ms |")
    print("| --- | --- | --- | ---: | ---: | ---: |")
    for r in results:
        trunc = "+" if r["truncated"] else ""
        print(f"| {r['program']} | {r['search']} | {r['query']} | {r['matches']:,}{trunc} | {r['wall_ms']:,} | {r['daemon_ms']:,} |")
    if args.json:
        Path(args.json).write_text("".join(json.dumps(r) + "\n" for r in results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
