#!/bin/sh
# rk-lift on a raw image: the synthetic ARM firmware
# (src/analysis/tests/fixtures/armfw) behind a header, with an MMIO region,
# discovered, decompiled and listed (its Thumb functions make the listing
# take its second, in-order pass after the decompiler's inputs are freed).
# The output must be valid JSON with every function decompiled, and the
# same on 1 and 4 threads. Exits 77 (skip) without clang, ld.lld,
# llvm-objcopy or python3.
#   raw_smoke.sh <rk-lift> <ghidra root> <workdir> <fixture dir> <clang> <ld.lld> <llvm-objcopy>
set -eu
rk_lift=$1 ghidra=$2 work=$3 fixture=$4 cc=$5 ld=$6 objcopy=$7
for t in "$cc" "$ld" "$objcopy" python3; do command -v "$t" >/dev/null 2>&1 || exit 77; done
mkdir -p "$work"
sh "$fixture/build.sh" "$cc" "$ld" "$objcopy" "$work" >/dev/null 2>&1 || exit 77
{ head -c 64 /dev/zero | tr '\0' 'H'; cat "$work/fw.bin"; } > "$work/fw-header.bin"
args="--ghidra $ghidra --raw --lang ARM:LE:32:v4t:default --raw-offset 0x40 --region sysctrl:d0000000:1000:rw-:volatile
      --analyze --decompile"
"$rk_lift" $args -j 1 -o "$work/a.json" "$work/fw-header.bin"
"$rk_lift" $args -j 4 -o "$work/b.json" "$work/fw-header.bin"
python3 - "$work/a.json" "$work/b.json" <<'PY'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
fns = a["functions"]
assert len(fns) >= 20, len(fns)
missing = [f["entry"] for f in fns if not f.get("decompiled_c")]
assert not missing, "not decompiled: %s" % missing
assert a["instructions"], "no instructions"
# Thumb listed as Thumb: some 2-byte instructions.
assert any(i["len"] == 2 for i in a["instructions"]), "no Thumb instructions"
assert [f["entry"] for f in fns] == [f["entry"] for f in b["functions"]], "differs across thread counts"
print("ok: %d functions, %d instructions" % (len(fns), len(a["instructions"])))
PY
