#!/bin/sh
# Compile a known function, dump its .text as a raw image, decompile it,
# and check the output carries the function's FNV-1a constants.
set -eu

rk_decomp=$1
ghidra_root=$2
source=$3
workdir=$4

mkdir -p "$workdir"
cc -O1 -fno-asynchronous-unwind-tables -fcf-protection=none -c "$source" -o "$workdir/checksum.o"
objcopy -O binary --only-section=.text "$workdir/checksum.o" "$workdir/checksum.bin"

"$rk_decomp" --ghidra "$ghidra_root" --file "$workdir/checksum.bin" --addr 0 \
  > "$workdir/checksum.c.out"
cat "$workdir/checksum.c.out"

grep -q "0x1000193" "$workdir/checksum.c.out"   # 16777619, the FNV prime
grep -q "0x811c9dc5" "$workdir/checksum.c.out"  # 2166136261, the offset basis
