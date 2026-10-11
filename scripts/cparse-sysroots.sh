#!/bin/sh
# Copies the C library headers the corpus was compiled against out of the
# corpus toolchain image (corpus/docker/Dockerfile: Debian trixie glibc for
# x86-64, AArch64 and RISC-V, mingw-w64 for PE) into
# out/cache/cparse-sysroots/<target>/include, for the C parser's round-trip
# gate (scripts/cparse_roundtrip.py). The host's own headers are another
# glibc, whose FILE differs.
#
#   scripts/cparse-sysroots.sh [--force]
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
dest=$root/out/cache/cparse-sysroots
[ "${1:-}" = "--force" ] && rm -rf "$dest"
if [ -f "$dest/.complete" ]; then
  exit 0
fi
tag=revkit-corpus:$(sha256sum "$root/corpus/docker/Dockerfile" | cut -c1-12)
if ! docker image inspect "$tag" >/dev/null 2>&1; then
  echo "cparse-sysroots: the corpus image $tag is missing; run scripts/build-corpus.sh first" >&2
  exit 1
fi
rm -rf "$dest.tmp"
mkdir -p "$dest.tmp"
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$dest.tmp:/out" "$tag" sh -c '
  set -e
  copy() { mkdir -p "/out/$1/include"; tar -C "$2" -chf - . | tar -C "/out/$1/include" -xf -; }
  copy x86_64-linux-gnu /usr/include
  copy aarch64-linux-gnu /usr/aarch64-linux-gnu/include
  copy riscv64-linux-gnu /usr/riscv64-linux-gnu/include
  copy x86_64-w64-mingw32 /usr/x86_64-w64-mingw32/include
'
touch "$dest.tmp/.complete"
rm -rf "$dest"
mv "$dest.tmp" "$dest"
echo "cparse-sysroots: headers in $dest"
