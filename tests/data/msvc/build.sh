#!/bin/sh
# Builds classes.cc (with runtime.cc, the CRT's stand-ins) for an MSVC target without a Windows SDK or CRT:
#   build.sh CLANG LLD_LINK OUTDIR ARCH
# ARCH is x86_64 or i686. Writes OUTDIR/classes-ARCH.exe with its PDB
# (classes-ARCH.pdb, recorded by file name only) and linker map, and
# OUTDIR/classes-ARCH-stripped.exe, the same objects linked without debug
# info.
set -eu
clang=$1
lld=$2
out=$3
arch=$4
dir=$(dirname "$0")
obj="$out/classes-$arch.obj"
rt="$out/runtime-$arch.obj"
"$clang" --driver-mode=cl --target="$arch-pc-windows-msvc" /nologo /GR /EHsc /GS /O1 /Zi \
  /guard:cf,nochecks /c "$dir/classes.cc" "/Fo$obj"
"$clang" --driver-mode=cl --target="$arch-pc-windows-msvc" /nologo /GR- /O1 /Zi /c "$dir/runtime.cc" "/Fo$rt"
common="/nologo /nodefaultlib /entry:start /subsystem:console /guard:cf,nolongjmp /opt:ref /opt:noicf"
# shellcheck disable=SC2086
"$lld" $common /debug "/pdb:$out/classes-$arch.pdb" "/pdbaltpath:classes-$arch.pdb" \
  "/map:$out/classes-$arch.map" "/out:$out/classes-$arch.exe" "$obj" "$rt"
# shellcheck disable=SC2086
"$lld" $common "/out:$out/classes-$arch-stripped.exe" "$obj" "$rt"
