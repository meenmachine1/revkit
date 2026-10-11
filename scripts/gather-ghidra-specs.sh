#!/bin/sh
# Copies the parts of a Ghidra install that revkit reads at run time into a
# self-contained tree that any revkit tool accepts as its Ghidra root
# (--ghidra DIR, or a bundle's share/revkit/ghidra):
#
#   Ghidra/Processors/<proc>/data/languages/  .sla .ldefs .pspec .cspec .opinion .dwarf
#   Ghidra/Processors/<proc>/data/patterns/   function-start patterns
#   Ghidra/Processors/<proc>/LICENSE.txt      the module's license statement
#   Ghidra/Features/Base/data/typeinfo/       the four C library archives the
#                                             decompiler inputs use (.gdt)
#   Ghidra/Features/Base/data/stringngrams/StringModel.sng
#   Ghidra/application.properties             the Ghidra version
#   LICENSE, NOTICE, SHA256SUMS
#
# Nothing is modified. Ghidra is Apache-2.0 (NOTICE below says what this is
# and where it came from). SLEIGH sources (.slaspec, .sinc) and processor
# manuals are left out; a Ghidra release ships the compiled .sla files.
#
#   scripts/gather-ghidra-specs.sh [--ghidra DIR] [--processors x86,AARCH64,...] OUT
#
# --ghidra defaults to $GHIDRA_INSTALL_DIR, else ~/ghidra/ghidra_12.1.4_PUBLIC.
# OUT is replaced. Prints OUT's size.
set -eu

ghidra=${GHIDRA_INSTALL_DIR:-$HOME/ghidra/ghidra_12.1.4_PUBLIC}
procs=
out=
while [ $# -gt 0 ]; do
  case $1 in
    --ghidra) ghidra=$2; shift 2 ;;
    --processors) procs=$2; shift 2 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    -*) echo "gather-ghidra-specs: unknown option $1" >&2; exit 2 ;;
    *) out=$1; shift ;;
  esac
done
[ -n "$out" ] || { echo "usage: $0 [--ghidra DIR] [--processors a,b] OUT" >&2; exit 2; }
if [ ! -d "$ghidra/Ghidra/Processors" ]; then
  echo "gather-ghidra-specs: $ghidra is not a Ghidra install (no Ghidra/Processors)" >&2
  exit 1
fi
if ! find "$ghidra/Ghidra/Processors" -name '*.sla' -print -quit | grep -q .; then
  echo "gather-ghidra-specs: $ghidra has no compiled .sla files (a source checkout?); use a Ghidra release" >&2
  exit 1
fi

version=$(sed -n 's/^application.version=//p' "$ghidra/Ghidra/application.properties" 2>/dev/null || true)
rm -rf "$out"
mkdir -p "$out"
out=$(cd "$out" && pwd)

copy() {  # copy <path relative to the Ghidra root>
  mkdir -p "$out/$(dirname "$1")"
  cp -p "$ghidra/$1" "$out/$1"
}

cd "$ghidra"
for dir in Ghidra/Processors/*/; do
  dir=${dir%/}
  proc=$(basename "$dir")
  if [ -n "$procs" ]; then
    case ",$procs," in *",$proc,"*) ;; *) continue ;; esac
  fi
  [ -d "$dir/data/languages" ] || continue
  find "$dir/data/languages" -type f \( -name '*.sla' -o -name '*.ldefs' -o -name '*.pspec' -o -name '*.cspec' \
       -o -name '*.opinion' -o -name '*.dwarf' \) | sort | while read -r f; do copy "${f#./}"; done
  if [ -d "$dir/data/patterns" ]; then
    find "$dir/data/patterns" -type f | sort | while read -r f; do copy "${f#./}"; done
  fi
  if [ -f "$dir/LICENSE.txt" ]; then copy "$dir/LICENSE.txt"; fi
done
for f in Ghidra/Features/Base/data/typeinfo/generic/generic_clib.gdt \
         Ghidra/Features/Base/data/typeinfo/generic/generic_clib_64.gdt \
         Ghidra/Features/Base/data/typeinfo/win32/windows_vs12_32.gdt \
         Ghidra/Features/Base/data/typeinfo/win32/windows_vs12_64.gdt \
         Ghidra/Features/Base/data/stringngrams/StringModel.sng \
         Ghidra/Features/Base/LICENSE.txt \
         Ghidra/application.properties; do
  if [ -f "$f" ]; then copy "$f"; else echo "gather-ghidra-specs: warning: $f missing from $ghidra" >&2; fi
done
cp -p LICENSE "$out/LICENSE"

cat > "$out/NOTICE" <<EOF
Ghidra ${version:-(unknown version)} processor specifications and data
=====================================================================

This directory holds unmodified files from a Ghidra ${version} release
(https://github.com/NationalSecurityAgency/ghidra), developed by the
National Security Agency and released under the Apache License, Version 2.0
(LICENSE in this directory). Each Ghidra/<module>/LICENSE.txt is that
module's own license statement; none of the files copied here are listed
in them as third-party components.

What is included: the compiled SLEIGH specifications (.sla), language,
processor and compiler specifications (.ldefs, .pspec, .cspec), loader
opinions (.opinion), DWARF register mappings (.dwarf) and function-start
patterns of each processor; the generic C and Windows data type archives
(.gdt) and the string n-gram model from the Base module; and
application.properties (the version). revkit reads them at run time; they
were selected by revkit's scripts/gather-ghidra-specs.sh. SHA256SUMS lists
every file.
EOF

(cd "$out" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)
n=$(grep -c '\.sla$' "$out/SHA256SUMS" || true)
echo "gather-ghidra-specs: Ghidra ${version:-?} -> $out ($n .sla files, $(du -sh "$out" | cut -f1))"
