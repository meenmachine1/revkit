#!/bin/sh
# Replay a decompiler repro in the console built from the patched fork
# (ghidra_decomp_dbg, upstream's decomp_dbg) and check the outcome.
#
#   replay.sh <ghidra_decomp_dbg> <ghidra root> <repro.xml>
#   replay.sh <rk-decompd> <ghidra root> <repro.bundle>
#
# <repro.xml> is an <xml_savefile> (Ghidra's "Debug Function Decompilation"
# output, or one written by the console's `save`) whose name attribute is
# the function to decompile. It is restored, decompiled and printed; the
# console must exit normally (no crash, within the time limit) and its
# output must match every extended regex in <repro>.expect, one per line.
# A <repro.bundle> is a revkit decompiler input bundle (docs/decompd.md:
# what a failed decompilation's Export repro or rk-lift --failure-bundles
# writes); rk-decompd decompiles it alone and must exit normally (0, or 1
# when the decompiler reports an error) with output matching the .expect.
set -u

dbg=$1 root=$2 xml=$3
case $xml in
  *.bundle)
    expect=${xml%.bundle}.expect
    limit=${RK_REPRO_TIMEOUT:-300}
    out=
    [ -f "$expect" ] || { echo "FAIL $(basename "$xml"): no $(basename "$expect")" >&2; exit 1; }
    out=$(timeout "$limit" "$dbg" --ghidra "$root" --bundle "$xml" 2>&1)
    rc=$?
    if [ $rc -gt 1 ]; then
      echo "FAIL $(basename "$xml"): rk-decompd exited with status $rc (124: timeout, >128: signal $((rc - 128)))" >&2
      printf '%s\n' "$out" | tail -20 >&2
      exit 1
    fi
    while IFS= read -r re; do
      [ -n "$re" ] || continue
      printf '%s\n' "$out" | grep -Eq -- "$re" || { echo "FAIL $(basename "$xml"): no output line matches: $re" >&2; exit 1; }
    done < "$expect"
    echo "ok $(basename "$xml")"
    exit 0 ;;
esac
expect=${xml%.xml}.expect
limit=${RK_REPRO_TIMEOUT:-300}

fail() { echo "FAIL $(basename "$xml"): $*" >&2; printf '%s\n' "$out" | tail -20 >&2; exit 1; }

out=
[ -f "$expect" ] || fail "no $(basename "$expect")"
name=$(sed -n 's/.*<xml_savefile name="\([^"]*\)".*/\1/p' "$xml" | head -n 1)
[ -n "$name" ] || fail "no <xml_savefile name=...>"
out=$(printf 'restore %s\nload function %s\ndecompile\nprint C\nquit\n' "$xml" "$name" |
      SLEIGHHOME=$root timeout "$limit" "$dbg" 2>&1)
rc=$?
[ $rc = 0 ] || fail "console exited with status $rc (124: timeout, >128: signal $((rc - 128)))"
printf '%s\n' "$out" | grep -q "successfully loaded" || fail "restore failed"
while IFS= read -r re; do
  [ -n "$re" ] || continue
  printf '%s\n' "$out" | grep -Eq -- "$re" || fail "no output line matches: $re"
done < "$expect"
echo "ok $(basename "$xml"): $name"
