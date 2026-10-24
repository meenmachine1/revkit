#!/bin/sh
# Source shape (docs/decompiler-inputs.md, "Source shape"): the program in
# tests/data/shape, built with clang for ARMv5TE (with CodeWarrior-style
# loops in assembly), x86-64 and AArch64, decompiled by rk-lift --analyze
# --decompile with the source-shape options (the default), without them,
# with --compilable-c on a -g build, and (ARM) with encoded comparisons and
# zero-extended bytes left untyped, each of those ARM runs also without
# inference's prototypes (the decompiler's load types alone, which a
# prototype inference locks would otherwise decide); tests/data/shape/check.py says what
# each C must look like. Exits 77 (skip) without clang, ld.lld or python3.
#   shape_smoke.sh <rk-lift> <ghidra root> <workdir> <source dir> <clang> <ld.lld>
set -eu
rk_lift=$1 ghidra=$2 work=$3 src=$4 cc=$5 ld=$6
for t in "$cc" "$ld" python3; do command -v "$t" >/dev/null 2>&1 || exit 77; done
mkdir -p "$work"
flags="-O2 -ffreestanding -nostdlib -fno-builtin -fno-stack-protector -fno-pic -fno-asynchronous-unwind-tables"
build() {  # build <name> <triple> <extra flags>
  name=$1 triple=$2; shift 2
  objs="$work/$name.o"
  "$cc" --target="$triple" $flags "$@" -c "$src/shape.c" -o "$work/$name.o" || exit 77
  if [ "$triple" = armv5te-none-eabi ]; then
    "$cc" --target="$triple" -c "$src/loops_arm.s" -o "$work/$name-loops.o" || exit 77
    objs="$objs $work/$name-loops.o"
  fi
  "$ld" -e _start -static $objs -o "$work/$name" || exit 77
}
for arch in arm x64 a64; do
  case $arch in
    arm) triple=armv5te-none-eabi; extra="-marm -mfloat-abi=soft" ;;
    x64) triple=x86_64-linux-gnu; extra= ;;
    a64) triple=aarch64-linux-gnu; extra= ;;
  esac
  build "$arch" "$triple" $extra
  build "$arch-g" "$triple" $extra -g
  "$rk_lift" --ghidra "$ghidra" --analyze --decompile --no-instructions -j 2 -o "$work/$arch.json" "$work/$arch"
  "$rk_lift" --ghidra "$ghidra" --analyze --decompile --no-instructions -j 2 --no-source-shape \
    -o "$work/$arch-ghidra.json" "$work/$arch"
  "$rk_lift" --ghidra "$ghidra" --analyze --decompile --no-instructions -j 2 --compilable-c \
    -o "$work/$arch-g.json" "$work/$arch-g"
done
# Encoded comparisons (COMPARISON_FORM_ENCODED, as a matching
# decompilation of CodeWarrior's code sets them) with LOAD_TYPES_WORDS.
"$rk_lift" --ghidra "$ghidra" --analyze --decompile --no-instructions -j 2 --source-shape words,encoded,flag \
  -o "$work/arm-encoded.json" "$work/arm"
"$rk_lift" --ghidra "$ghidra" --analyze --decompile --no-instructions -j 2 --no-infer-prototypes \
  -o "$work/arm-noinfer.json" "$work/arm"
"$rk_lift" --ghidra "$ghidra" --analyze --decompile --no-instructions -j 2 --source-shape words,encoded,flag \
  --no-infer-prototypes -o "$work/arm-encoded-noinfer.json" "$work/arm"
[ -n "${SHAPE_NO_CHECK:-}" ] || python3 "$src/check.py" "$work"
