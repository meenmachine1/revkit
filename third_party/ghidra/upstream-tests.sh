#!/bin/sh
# Run upstream's own decompiler tests (unittests/ or the datatests/ XML
# suite) against the patched fork, with ghidra_test (upstream's
# decomp_test_dbg).
#
#   upstream-tests.sh <ghidra_test> <ghidra root> <datatests dir> unittests|datatests
#
# A Ghidra release ships no Toy processor, which some upstream tests are
# written for; those (and only those) may fail, and every other test must
# pass. Exits non-zero otherwise.
set -u

exe=$1 root=$2 dir=$3 kind=$4

out=$("$exe" -sleighpath "$root" -path "$dir" "$kind" 2>&1)
case $kind in
  unittests)
    # "testing : name ..." then "  passed." or "  fail: message"
    bad=$(printf '%s\n' "$out" | awk '
      /^testing : / { name = $3 }
      /^  fail/ {
        if (!(name ~ /^funcproto_/ && ($0 ~ /Toy/ || $0 ~ /Architecture did not load/)))
          print name ": " $0
      }')
    summary=$(printf '%s\n' "$out" | grep 'tests passed\.$')
    ;;
  datatests)
    # After "Failures:", one line per failed test or file.
    bad=$(printf '%s\n' "$out" | sed -n '/^Failures:/,$p' | sed 1d | grep -v 'No sleigh specification for Toy:' | grep .)
    applied=$(printf '%s\n' "$out" | sed -n 's/^Total tests applied = //p')
    passing=$(printf '%s\n' "$out" | sed -n 's/^Total passing tests = //p')
    summary="$passing/$applied datatests passed"
    [ -n "$applied" ] && [ "$applied" -gt 0 ] && [ "$applied" = "$passing" ] || bad="$bad
$summary"
    ;;
  *) echo "usage: $0 <ghidra_test> <ghidra root> <datatests dir> unittests|datatests" >&2; exit 2 ;;
esac

echo "$summary (tests that need the Toy processor, absent from a release, excluded)"
if [ -n "$bad" ]; then
  echo "failures:" >&2
  printf '%s\n' "$bad" >&2
  exit 1
fi
