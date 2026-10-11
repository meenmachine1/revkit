#!/usr/bin/env python3
"""List the type names libc and the OS headers declare: the named types
a stripped-binary analysis can know without the program's own sources.

`score.py --matchable` (docs/heldout.md, "Matchable functions") counts a
truth prototype as matchable when every type it names is a C primitive or
one of these (or pointers, arrays and function types over them).

The headers are the ones the library signature databases are generated
from (tools/rk-sigdb/gen_sigdb.py's glibc and mingw profiles: libc, POSIX
and GNU headers; windows.h and the msvcrt C headers), parsed with clang;
every struct, union and enum tag and every typedef name they declare is
listed, plus the compilers' built-in va_list types. glibc's names apply to
ELF binaries and mingw-w64's to PE ones.

    gen_system_types.py -o tools/rk-infer/system_types.txt
"""

from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "rk-sigdb"))
import gen_sigdb  # noqa: E402

# Types the compilers declare themselves (the ABI's va_list): x86-64 System V
# `__va_list_tag *`, AAPCS64 `__va_list`, and their C names.
BUILTINS = ["__builtin_va_list", "__gnuc_va_list", "__va_list", "__va_list_tag", "va_list"]

KINDS = {"RecordDecl", "EnumDecl", "TypedefDecl"}
# Which binaries a profile's names apply to (the binary's format).
PLATFORM = {"glibc": "elf", "mingw": "pe"}


def names(node, out: set[str]) -> None:
    if node.get("kind") in KINDS and node.get("name"):
        out.add(node["name"])
    for child in node.get("inner", []) or []:
        names(child, out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", required=True)
    args = ap.parse_args()
    rows = []
    for name in sorted(gen_sigdb.PROFILES):
        profile = gen_sigdb.PROFILES[name]
        headers = gen_sigdb.usable_headers(profile)
        found: set[str] = set(BUILTINS)
        for decl in gen_sigdb.clang_ast(profile, headers):
            names(decl, found)
        print("%s: %d headers, %d names" % (name, len(headers), len(found)), file=sys.stderr)
        rows += [(PLATFORM[name], n) for n in found]
    with open(args.output, "w") as f:
        f.write("# Type names declared by libc and OS headers (tools/rk-infer/gen_system_types.py):\n")
        f.write("# <platform> <name>, platform elf (glibc) or pe (mingw-w64); docs/heldout.md.\n")
        for row in sorted(rows):
            f.write("%s %s\n" % row)
    print("%s: %d names" % (args.output, len(rows)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
