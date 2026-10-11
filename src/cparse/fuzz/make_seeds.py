#!/usr/bin/env python3
"""Seeds for cparse_fuzzer from C headers: one file per header and target
flag, the header as the source (and, for a pair, the next one as a.h).

  make_seeds.py OUT_DIR HEADER...
"""
import os
import sys


def main():
    out, headers = sys.argv[1], sys.argv[2:]
    os.makedirs(out, exist_ok=True)
    texts = []
    for h in headers:
        with open(h, "rb") as f:
            texts.append(f.read()[:200_000])
    n = 0
    for i, t in enumerate(texts):
        for flags in (0, 1, 3, 0x40, 0x80, 0x20):
            body = bytes([flags + i % 16]) + t.replace(b"\0", b"")
            if flags == 0x20 and i + 1 < len(texts):
                body += b"\0" + texts[i + 1].replace(b"\0", b"")
            with open(os.path.join(out, f"seed-{n:05d}"), "wb") as f:
                f.write(body)
            n += 1
    print(f"{n} seeds in {out}")


if __name__ == "__main__":
    main()
