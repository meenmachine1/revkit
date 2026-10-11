#!/bin/sh
# Builds the synthetic ARM firmware: build.sh <clang> <ld.lld> <llvm-objcopy> <out dir> [-O level] [bulk functions]
# Writes fw.elf (with symbols: the ground truth) and fw.bin (the raw image
# a boot ROM would load at 0). With a bulk function count, main also calls
# that many generated functions (bulk.py; about 160 bytes each at -O2), to
# scale the image up to a real firmware's size.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cc=$1 ld=$2 objcopy=$3 out=$4 opt=${5:--O2} bulk=${6:-0}
flags="--target=armv4t-none-eabi -mfloat-abi=soft -ffreestanding -fno-builtin -nostdlib $opt -fno-unwind-tables -fno-asynchronous-unwind-tables -Wno-unused-command-line-argument"
mkdir -p "$out"
objs="$out/vectors.o $out/main.o $out/thumb.o $out/rodata.o"
$cc $flags -c "$here/vectors.s" -o "$out/vectors.o"
if [ "$bulk" -gt 0 ]; then
  python3 "$here/bulk.py" "$bulk" > "$out/bulk.c"
  $cc $flags -marm -c "$out/bulk.c" -o "$out/bulk.o"
  $cc $flags -marm -DARMFW_BULK -c "$here/main.c" -o "$out/main.o"
  objs="$objs $out/bulk.o"
else
  $cc $flags -marm -c "$here/main.c" -o "$out/main.o"
fi
$cc $flags -mthumb -c "$here/thumb.c" -o "$out/thumb.o"
$cc $flags -c "$here/rodata.c" -o "$out/rodata.o"
$ld -T "$here/link.ld" $objs -o "$out/fw.elf"
$objcopy -O binary "$out/fw.elf" "$out/fw.bin"
