#!/bin/sh
# Builds the Mach-O loader's fixtures without an Apple SDK: clang for the
# Apple targets, ld64.lld against the hand-written libSystem.tbd and
# libobjc.tbd, llvm-lipo for a universal file; llvm-nm and llvm-objdump
# write what the tests check the loader against.
#   build.sh CLANG LD64_LLD LIPO NM OBJDUMP OUTDIR
# Writes to OUTDIR (and for each linked file F, F.nm: llvm-nm's symbols,
# and F.fixups: llvm-objdump's binds, lazy binds and rebases, or its
# chained fixups):
#   hello-{x86_64,arm64}          dyld info opcodes (LC_DYLD_INFO_ONLY)
#   hello-{x86_64,arm64}-chained  chained fixups (LC_DYLD_CHAINED_FIXUPS)
#   hello-arm64_32                arm64_32 (a 32-bit header)
#   hello-fat                     universal: x86_64 and arm64
#   hello-{armv7,i386}.o          object files (lld links neither)
#   libgreet.dylib, uses-greet    a dylib, and a program linking it by @rpath
#   objc-arm64, objc-x86_64       Objective-C classes, a protocol, a category
#   objc-arm64-chained            the same with chained fixups
#   objc-stripped                 objc-arm64 without its local symbols (llvm-strip
#                                 beside NM, when there is one)
set -eu
clang=$1
ld=$2
lipo=$3
nm=$4
objdump=$5
out=$6
dir=$(dirname "$0")
mkdir -p "$out"
cc() { "$clang" --target="$1" -O1 -c "$2" -o "$3"; }
link() {  # arch platform version out objs...
  arch=$1 platform=$2 version=$3 o=$4
  shift 4
  "$ld" -arch "$arch" -platform_version "$platform" "$version" "$version" -o "$o" "$@"
}
cc x86_64-apple-macos11 "$dir/hello.c" "$out/hello-x86_64.o"
cc arm64-apple-macos11 "$dir/hello.c" "$out/hello-arm64.o"
cc arm64_32-apple-watchos5 "$dir/hello.c" "$out/hello-arm64_32.o"
cc armv7-apple-ios9 "$dir/hello.c" "$out/hello-armv7.o"
cc i386-apple-macos10.10 "$dir/hello.c" "$out/hello-i386.o"
sys="$dir/libSystem.tbd"
link x86_64 macos 11.0 "$out/hello-x86_64" "$out/hello-x86_64.o" "$sys"
link arm64 macos 11.0 "$out/hello-arm64" "$out/hello-arm64.o" "$sys"
link x86_64 macos 13.0 "$out/hello-x86_64-chained" -fixup_chains "$out/hello-x86_64.o" "$sys"
link arm64 macos 13.0 "$out/hello-arm64-chained" -fixup_chains "$out/hello-arm64.o" "$sys"
link arm64_32 watchos 5.0 "$out/hello-arm64_32" "$out/hello-arm64_32.o" "$sys"
"$lipo" -create "$out/hello-x86_64" "$out/hello-arm64" -output "$out/hello-fat"
cc arm64-apple-macos11 "$dir/greet.c" "$out/greet.o"
cc arm64-apple-macos11 "$dir/uses_greet.c" "$out/uses_greet.o"
link arm64 macos 13.0 "$out/libgreet.dylib" -dylib -install_name @rpath/libgreet.dylib -fixup_chains \
  "$out/greet.o" "$sys"
link arm64 macos 13.0 "$out/uses-greet" -fixup_chains -rpath @loader_path "$out/uses_greet.o" \
  "$out/libgreet.dylib" "$sys"
"$clang" --target=arm64-apple-macos11 -fobjc-runtime=macosx-11.0 -O1 -c "$dir/objc.m" -o "$out/objc.o"
link arm64 macos 11.0 "$out/objc-arm64" "$out/objc.o" "$dir/libobjc.tbd" "$sys"
link arm64 macos 13.0 "$out/objc-arm64-chained" -fixup_chains "$out/objc.o" "$dir/libobjc.tbd" "$sys"
"$clang" --target=x86_64-apple-macos11 -fobjc-runtime=macosx-11.0 -O1 -c "$dir/objc.m" -o "$out/objc-x86_64.o"
link x86_64 macos 11.0 "$out/objc-x86_64" "$out/objc-x86_64.o" "$dir/libobjc.tbd" "$sys"
strip=$(printf '%s' "$nm" | sed 's/llvm-nm/llvm-strip/')
if [ "$strip" != "$nm" ] && [ -x "$strip" ]; then
  "$strip" -x -o "$out/objc-stripped" "$out/objc-arm64"
fi
for f in hello-x86_64 hello-arm64 hello-x86_64-chained hello-arm64-chained hello-arm64_32 \
  libgreet.dylib uses-greet objc-arm64 objc-arm64-chained objc-x86_64; do
  "$nm" -n "$out/$f" >"$out/$f.nm"
  "$objdump" --macho --bind --lazy-bind --weak-bind --rebase --dyld-info "$out/$f" >"$out/$f.fixups"
done
