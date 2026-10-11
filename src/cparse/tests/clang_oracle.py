#!/usr/bin/env python3
"""Checks rk-cparse's struct layouts against clang's, on every target.

A test oracle only (CMake -DREVKIT_WITH_CLANG=ON registers it with CTest):
revkit never links or ships clang. For each target, rk-cparse lays out the
header's structs and unions; clang lays out the same header for the same
triple (-Xclang -fdump-record-layouts, forced by a sizeof of each record);
sizes and every named field's bit offset and width must agree.

  clang_oracle.py --rk-cparse build/tools/rk-cparse/rk-cparse [--clang clang] [HEADER...]
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# rk-cparse target -> clang triple
TARGETS = {
    "x86_64-linux-gnu": "x86_64-linux-gnu",
    "aarch64-linux-gnu": "aarch64-linux-gnu",
    "riscv64-linux-gnu": "riscv64-linux-gnu",
    "x86_64-w64-mingw32": "x86_64-w64-mingw32",
    "x86_64-pc-windows-msvc": "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc": "aarch64-pc-windows-msvc",
    "i386-linux-gnu": "i386-pc-linux-gnu",
    "i686-w64-mingw32": "i686-w64-mingw32",
    "i386-pc-windows-msvc": "i386-pc-windows-msvc",
    "arm-linux-gnueabihf": "arm-linux-gnueabihf",
    "arm-none-eabi": "arm-none-eabi",
    "riscv32-linux-gnu": "riscv32-linux-gnu",
    "powerpc-linux-gnu": "powerpc-linux-gnu",
    "mips-linux-gnu": "mips-linux-gnu",
    "mipsel-linux-gnu": "mipsel-linux-gnu",
}

# Where clang's own headers differ from GCC's, which revkit follows.
SKIP = {
    # GCC's stddef.h gives i386's max_align_t a __float128 member; clang's doesn't.
    ("i386-linux-gnu", "struct s_max_align"), ("i686-w64-mingw32", "struct s_max_align"),
    # GCC's MIPS o32 __BIGGEST_ALIGNMENT__ is 8 (its long double); clang's is 16.
    ("mips-linux-gnu", "struct s_aligned_noarg"), ("mipsel-linux-gnu", "struct s_aligned_noarg"),
}

FIELD = re.compile(r"^\s*(\d+)(?::(\d+)-(\d+)|:-)?\s\|(\s+)(.*)$")


def clang_layouts(clang, triple, probe, flags):
    p = subprocess.run([clang, "-target", triple, "-fsyntax-only", "-nostdlibinc", "-w"] + flags +
                       ["-Xclang", "-fdump-record-layouts", probe], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"clang {triple}: {p.stderr.strip()[:2000]}")
    out = {}
    for block in p.stdout.split("*** Dumping AST Record Layout")[1:]:
        lines = [l for l in block.splitlines() if l.strip()]
        head = FIELD.match(lines[0])
        if not head:
            continue
        name = head.group(5).strip()
        fields = []
        size = None
        for l in lines[1:]:
            m = re.search(r"\[sizeof=(\d+)", l)
            if m:
                size = int(m.group(1))
                break
            f = FIELD.match(l)
            if not f or len(f.group(4)) != 3:  # direct members only: "|" + 3 spaces
                continue
            text = f.group(5)
            byte = int(f.group(1))
            if f.group(2) is not None:
                first, last = int(f.group(2)), int(f.group(3))
                bit, width = byte * 8 + first, last - first + 1
            elif ":-" in l.split("|")[0]:
                continue  # an unnamed zero-width bitfield
            else:
                bit, width = byte * 8, 0
            # "type name"; an unnamed member ends with a space or with
            # "(anonymous at file:line:col)".
            text = text.rstrip("\n")
            fname = "" if text.endswith(" ") or text.endswith(")") else text.rsplit(" ", 1)[-1].lstrip("*")
            if width and not fname:
                continue  # unnamed bitfields are padding; compilers record none
            fields.append((fname, bit, width))
        out[name] = (size, fields)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rk-cparse", required=True)
    ap.add_argument("--clang", default=shutil.which("clang") or "clang")
    ap.add_argument("--targets", default=",".join(TARGETS))
    ap.add_argument("--isystem", action="append", default=[], help="system include directory (both sides)")
    ap.add_argument("--define", "-D", action="append", default=[])
    ap.add_argument("--system", action="store_true", help="also compare records from system headers")
    ap.add_argument("headers", nargs="*", default=[os.path.join(HERE, "data", "layouts.h")])
    args = ap.parse_args()
    failures = 0
    checked = 0
    with tempfile.TemporaryDirectory() as tmp:
        for header in args.headers:
            for target in args.targets.split(","):
                triple = TARGETS[target]
                flags = [x for d in args.isystem for x in ("-isystem", d)] + ["-D" + d for d in args.define]
                p = subprocess.run([args.rk_cparse, "--json", "--target", target] + (["--system"] if args.system else []) +
                                   flags + [header],
                                   capture_output=True, text=True)
                r = json.loads(p.stdout)
                if r["errors"]:
                    print(f"FAIL {target} {header}: rk-cparse errors: {r['diagnostics'][:3]}")
                    failures += 1
                    continue
                # Built-in records (the va_list tags) aren't declarable.
                records = [n for n in r["named"] if n["kind"] in ("struct", "union") and
                           not n["key"].startswith("typedef ") and n.get("complete") and not n.get("file", "<").startswith("<")]
                probe = os.path.join(tmp, "probe.c")
                with open(probe, "w") as f:
                    f.write(f'#include "{os.path.abspath(header)}"\n')
                    for i, n in enumerate(records):
                        f.write(f"char rk_probe_{i}[sizeof({n['key']})];\n")
                theirs = clang_layouts(args.clang, triple, probe, flags)
                for n in records:
                    if (target, n["key"]) in SKIP:
                        continue
                    t = theirs.get(n["key"])
                    if not t:
                        print(f"FAIL {target}: clang has no layout for {n['key']}")
                        failures += 1
                        continue
                    ours = (n["size"], [(f["name"], f["bit_offset"], f["bit_size"]) for f in n["fields"]])
                    checked += 1
                    if ours != t:
                        failures += 1
                        print(f"FAIL {target} {n['key']}:\n  revkit {ours}\n  clang  {t}")
    print(f"{checked} layouts compared, {failures} differ")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
