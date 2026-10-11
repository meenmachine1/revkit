#!/bin/sh
# Builds the firmware-emulation fixtures: build.sh <clang> <ld.lld> <llvm-objcopy> <out dir>
# ARMv4T programs for qemu's versatilepb (arm_*.elf/.bin) and Cortex-M3
# programs for its lm3s6965evb (cm_*.elf/.bin), raw images at 0; a MIPS32
# program (mips.elf/.bin) at 0x80000000.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cc=$1 ld=$2 objcopy=$3 out=$4
mkdir -p "$out"
common="-ffreestanding -fno-builtin -nostdlib -O2 -fno-unwind-tables -fno-asynchronous-unwind-tables -Wall -Werror -Wno-unused-command-line-argument"
arm="--target=armv4t-none-eabi -marm -mfloat-abi=soft $common"
cm="--target=thumbv7m-none-eabi -mcpu=cortex-m3 -mthumb -mfloat-abi=soft $common"
$cc $arm -c "$here/arm_start.s" -o "$out/arm_start.o"
$cc $arm -c "$here/arm_svc.c" -o "$out/arm_svc.o"
for p in arm_timer arm_uart arm_swi custom arm_plugin; do
  $cc $arm -c "$here/$p.c" -o "$out/$p.o"
  $ld -T "$here/arm.ld" "$out/arm_start.o" "$out/arm_svc.o" "$out/$p.o" -o "$out/$p.elf"
  $objcopy -O binary "$out/$p.elf" "$out/$p.bin"
done
$cc $cm -c "$here/cm_start.c" -o "$out/cm_start.o"
for p in cm_timer cm_uart cm_svc; do
  $cc $cm -c "$here/$p.c" -o "$out/$p.o"
  $ld -T "$here/cm.ld" "$out/cm_start.o" "$out/$p.o" -o "$out/$p.elf"
  $objcopy -O binary "$out/$p.elf" "$out/$p.bin"
done
# MIPS32 big endian (mips_*): when clang has the MIPS target.
mips="--target=mips-unknown-none-elf -march=mips32r2 -mabi=32 -EB -mno-abicalls -fno-pic -G0 $common"
if $cc $mips -c "$here/mips_start.s" -o "$out/mips_start.o" 2>/dev/null; then
  $cc $mips -c "$here/mips.c" -o "$out/mips.o"
  $ld -T "$here/mips.ld" "$out/mips_start.o" "$out/mips.o" -o "$out/mips.elf"
  $objcopy -O binary "$out/mips.elf" "$out/mips.bin"
fi
