#!/usr/bin/env python3
"""What the C of tests/data/shape must look like (tools/rk-lift/shape_smoke.sh).

  check.py <workdir>

<workdir> holds rk-lift's JSON for each build: <arch>.json (the source-shape
options, rk-lift's default), <arch>-ghidra.json (--no-source-shape: Ghidra's
forms), <arch>-g.json (a -g build with --compilable-c), arm-encoded.json
(--source-shape words,encoded,flag), and arm-noinfer.json and
arm-encoded-noinfer.json (the ARM default and encoded runs with
--no-infer-prototypes)."""

import json
import os
import re
import sys

work = sys.argv[1]
failures = []


def functions(name):
    d = json.load(open(os.path.join(work, name + ".json")))
    return {f.get("name", ""): f.get("decompiled_c", "") for f in d["functions"]}


def expect(build, fn, pattern, present=True):
    c = functions(build).get(fn)
    if c is None:
        failures.append("%s: no function %s" % (build, fn))
        return
    found = re.search(pattern, c) is not None
    if found != present:
        failures.append("%s %s: %s %r\n%s" % (build, fn, "expected" if present else "unexpected", pattern, c))


# ARMv5TE: loads follow ldrh/ldrsh/ldrb/ldrsb.
expect("arm", "inc_fields", r"void inc_fields\(ushort \*param_1\)")
expect("arm", "get_id", r"ushort get_id\(ushort \*param_1\)")
expect("arm", "get_x", r"\*\(short \*\)")
expect("arm", "get_dir", r"\*\(char \*\)")
expect("arm", "get_kind", r"\*\(byte \*\)")
expect("arm-encoded", "get_kind", r"\*\(byte \*\)", present=False)  # words: not zero-extended bytes
# The same loads without inference's prototypes: the decompiler's own load
# types, words leaving the zero-extended byte untyped.
expect("arm-noinfer", "get_x", r"\*\(short \*\)")
expect("arm-noinfer", "get_dir", r"\*\(char \*\)")
expect("arm-noinfer", "get_kind", r"\*\(byte \*\)")
expect("arm-noinfer", "inc_fields", r"void inc_fields\(ushort \*param_1\)")
expect("arm-encoded-noinfer", "get_kind", r"\*\(byte \*\)", present=False)
expect("arm", "half_cw", r"void half_cw\(ushort \*param_1\)")
expect("arm", "half_cw", r"\(short\)param_1\[1\] >> 1")
expect("arm-ghidra", "inc_fields", r"void inc_fields\(short \*param_1\)")
# Comparisons: the constant on the right; encoded, the constant the
# instruction compares against.
for arch in ("arm", "x64", "a64"):
    expect(arch, "cmp_le0", r"0 < param_1", present=False)
    expect(arch, "cmp_ge9", r"param_1 > 8")
    expect(arch + "-ghidra", "cmp_ge9", r"8 < param_1")
expect("arm-encoded", "cmp_le0", r"param_1 <= 0")
expect("arm-encoded", "cmp_ge9", r"param_1 >= 9")
expect("arm-encoded", "memset_cw", r"param_3 <= 0")
# subs; bgt: one test of the result, n > 0.
expect("arm", "memset_cw", r"while \(param_3 > 0\)")
expect("arm", "memset_cw", r"bVar|&&", present=False)
expect("arm-ghidra", "memset_cw", r"!= 0 && ")
# -g with --compilable-c: bitfields as fields, no artificial pieces, no
# label ending a block, DWARF's base type names as C spells them.
for arch in ("arm", "x64", "a64"):
    b = arch + "-g"
    expect(b, "bf_on", r"return f->on;")
    expect(b, "bf_clear", r"f->on = 0;")
    expect(b, "bf_level", r"return f->level;")
    expect(b, "copy_mixed", r"\._[0-9]+_[0-9]+_", present=False)
    expect(b, "copy_mixed", r"\(char \*\)&gobj \+ 2")
    for fn, c in functions(b).items():
        if re.search(r":\n\s*\}", c):
            failures.append("%s %s: a label ends a block\n%s" % (b, fn, c))
        if "unsigned_" in c:
            failures.append("%s %s: unsigned_ is no C type\n%s" % (b, fn, c))

if failures:
    print("\n\n".join(failures))
    sys.exit(1)
print("ok: source shape on ARMv5TE, x86-64 and AArch64")
