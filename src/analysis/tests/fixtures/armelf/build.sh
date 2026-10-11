#!/bin/sh
# Builds a stripped dynamic ARM program: build.sh <clang> <ld.lld> <out dir>
# Writes prog (stripped: what is analyzed) and prog.sym (the same link with
# its symbols: the ground truth), linked against libext.so with a lazy PLT.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cc=$1 ld=$2 out=$3
flags="--target=armv7a-linux-gnueabihf -mthumb -O2 -nostdlib -ffreestanding -fno-unwind-tables -fno-asynchronous-unwind-tables"
mkdir -p "$out"
$cc $flags -fPIC -c "$here/lib.c" -o "$out/lib.o"
$ld -shared "$out/lib.o" -o "$out/libext.so"
$cc $flags -fno-PIC -c "$here/main.c" -o "$out/main.o"
$ld -z lazy -e _start "$out/main.o" "$out/libext.so" -o "$out/prog.sym"
$ld -z lazy -e _start --strip-all "$out/main.o" "$out/libext.so" -o "$out/prog"
