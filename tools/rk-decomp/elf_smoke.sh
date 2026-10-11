#!/bin/sh
# Build a shared object with the system (or a cross) compiler, decompile a
# function by symbol name, and check the FNV-1a constants come through.
# Exits 77 (skip) when the compiler is missing.
set -eu

rk_decomp=$1
ghidra_root=$2
source=$3
workdir=$4
cc=${5:-cc}

command -v "$cc" >/dev/null 2>&1 || exit 77
mkdir -p "$workdir"
"$cc" -O1 -shared -fPIC "$source" -o "$workdir/libchecksum.so"

"$rk_decomp" --ghidra "$ghidra_root" --file "$workdir/libchecksum.so" --symbol checksum \
  > "$workdir/checksum.c.out"
cat "$workdir/checksum.c.out"
grep -q "checksum(" "$workdir/checksum.c.out"
grep -q "0x1000193" "$workdir/checksum.c.out"
grep -q "0x811c9dc5" "$workdir/checksum.c.out"
