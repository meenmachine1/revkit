#!/bin/sh
# Lift every corpus binary with rk-lift into reference-format JSON.
#
#   scripts/lift-corpus.sh [corpus-dir] [out-dir] [rk-lift] [rk-lift options...]
#
# Options after the third argument go to every rk-lift run (e.g. --analyze).
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
corpus=$(realpath "${1:-$root/out/corpus}")
out=$(realpath -m "${2:-$root/out/revkit}")
rk_lift=$(realpath "${3:-$root/build/tools/rk-lift/rk-lift}")
[ $# -gt 3 ] && shift 3 || set --
flags="$*"

rm -rf "$out"
mkdir -p "$out"
cd "$corpus"
# Every file in the corpus tree except PDBs and metadata is a binary to lift.
find . -type f ! -name '*.pdb' ! -name '*.json' | sed 's|^\./||' | sort |
  xargs -P "${JOBS:-$(nproc)}" -I{} sh -c '
    mkdir -p "$(dirname "$2/$1")"
    "$3" $4 --name "$1" -o "$2/$1.json" "$1" 2>"$2/$1.log" || { echo "rk-lift failed: $1" >&2; exit 255; }
  ' _ {} "$out" "$rk_lift" "$flags"
echo "lifted $(find "$out" -name '*.json' | wc -l) binaries into $out"
