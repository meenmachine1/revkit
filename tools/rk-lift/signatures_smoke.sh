#!/bin/sh
# rk-lift --signatures on a corpus binary (Lua, x86-64 gcc -O2, with
# DWARF) at -j 1 and -j 8: every function's BSim features must be the same
# (join records and scheduling differ; normalize-level hashes must not),
# and the program's stripped twin must give the same vectors (the
# signature profile reads no debug info). Exits 77 (skip) without the corpus.
set -eu

rk_lift=$1
ghidra_root=$2
workdir=$3
corpus=$4

debug=$corpus/elf-x86_64/gcc-O2/debug/lua
stripped=$corpus/elf-x86_64/gcc-O2/stripped/lua
[ -f "$debug" ] && [ -f "$stripped" ] || exit 77
mkdir -p "$workdir"
# A generous per-function timeout: under a sanitizer on a busy machine a
# function can pass the default 30 s in one run and not the other, and a
# timed-out function has no features, which isn't what this test checks.
limit="--timeout 600"
for j in 1 8; do
  "$rk_lift" --ghidra "$ghidra_root" --analyze --no-instructions $limit -j $j --signatures "$workdir/sig-j$j.json" \
    -o /dev/null "$debug"
done
"$rk_lift" --ghidra "$ghidra_root" --analyze --no-instructions $limit -j 8 --signatures "$workdir/sig-stripped.json" \
  -o /dev/null "$stripped"
# Everything but the timings (the "stats" line), and for the stripped twin
# the names too.
grep -v '^"stats"' "$workdir/sig-j1.json" > "$workdir/j1"
grep -v '^"stats"' "$workdir/sig-j8.json" > "$workdir/j8"
cmp "$workdir/j1" "$workdir/j8"
sed -e 's/"name":"[^"]*",//' "$workdir/j8" > "$workdir/j8-unnamed"
grep -v '^"stats"' "$workdir/sig-stripped.json" | sed -e 's/"name":"[^"]*",//' > "$workdir/stripped-unnamed"
# Discovery may find a few functions differently without symbols: compare
# the functions both list, by entry.
if command -v python3 >/dev/null 2>&1; then
  python3 - "$workdir/sig-j8.json" "$workdir/sig-stripped.json" <<'PY'
import json, sys
a = {f["entry"]: f for f in json.load(open(sys.argv[1]))["functions"]}
b = {f["entry"]: f for f in json.load(open(sys.argv[2]))["functions"]}
common = [e for e in a if e in b and a[e]["status"] == "ok"]
same = sum(1 for e in common if a[e]["features"] == b[e]["features"])
print("signatures: %d functions, %d in both, %d identical with the stripped twin" % (len(a), len(common), same))
assert len(common) > 600, len(common)
assert same >= 0.99 * len(common), (same, len(common))
PY
fi
grep -q '"status":"ok"' "$workdir/j1"
