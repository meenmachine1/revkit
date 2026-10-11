#!/bin/sh
# revkit's fork of Ghidra's decompiler: a pristine vendored release plus an
# ordered patch series (README.md here explains the scheme).
#
#   fork.sh apply <dir>     verify the pristine copy, apply patches/series into
#                           <dir> (upstream layout: <dir>/cpp, <dir>/datatests,
#                           <dir>/unittests); files that don't change keep their
#                           timestamps. CMake runs this at configure time.
#   fork.sh check [<dir>]   verify the pristine copy against PRISTINE.sha256 and
#                           that the series applies to it exactly (no fuzz, no
#                           offsets); with <dir>, also that <dir> is what it
#                           produces (the build tree is current).
#   fork.sh unpack <dir>    a git repository for working on the series: the
#                           pristine release in Ghidra's own layout as one
#                           commit tagged ghidra-<version>, then one commit per
#                           patch (git am).
#   fork.sh export <dir>    write that repository's commits after the tag back
#                           to patches/ (git format-patch) and rewrite the series.
#   fork.sh import <root>   replace the pristine copy with the release at <root>
#                           (a Ghidra install or source tree) and rewrite
#                           PRISTINE.sha256; set UPSTREAM_VERSION by hand.
#
# Patch paths are Ghidra repository paths (a/Ghidra/Features/Decompiler/src/
# decompile/cpp/merge.cc), so each patch applies to upstream as it is.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
version=$(cat "$here/UPSTREAM_VERSION")
upstream=Ghidra/Features/Decompiler/src/decompile
strip=6   # a/Ghidra/Features/Decompiler/src/decompile/
# pristine dir in this tree -> dir in Ghidra's src/decompile
map="decompiler:cpp datatests:datatests unittests:unittests"

die() { echo "fork.sh: $*" >&2; exit 1; }

verify_pristine() {
  (cd "$here" && sha256sum --quiet --strict -c PRISTINE.sha256) ||
    die "the pristine Ghidra $version sources differ from PRISTINE.sha256; never edit them, add a patch"
  (cd "$here" && awk '{print $2}' PRISTINE.sha256 | LC_ALL=C sort) > "$tmp/listed"
  (cd "$here" && find decompiler datatests unittests -type f | LC_ALL=C sort) > "$tmp/present"
  extra=$(LC_ALL=C comm -13 "$tmp/listed" "$tmp/present")
  [ -z "$extra" ] || die "files in the pristine tree that PRISTINE.sha256 doesn't list: $extra"
}

patches() {
  grep -v '^[[:space:]]*\(#\|$\)' "$here/patches/series" || true
}

# stage <dir>: pristine copy plus the series, in Ghidra's layout.
stage() {
  for m in $map; do
    mkdir -p "$1/${m#*:}"
    cp -pR "$here/${m%%:*}/." "$1/${m#*:}/"
  done
  for p in $(patches); do
    [ -f "$here/patches/$p" ] || die "patches/series names $p, which doesn't exist"
    if ! out=$(patch -d "$1" -p$strip --forward --batch --fuzz=0 --no-backup-if-mismatch \
                 -i "$here/patches/$p" 2>&1); then
      printf '%s\n' "$out" >&2
      die "patch $p does not apply to Ghidra $version"
    fi
    # GNU patch applies hunks at an offset without failing; the series must be exact.
    if printf '%s\n' "$out" | grep -q 'offset\|fuzz'; then
      printf '%s\n' "$out" >&2
      die "patch $p applies only with an offset; refresh it (fork.sh unpack, then export)"
    fi
  done
  for p in $(cd "$here/patches" && ls -- *.patch 2>/dev/null); do
    patches | grep -qx "$p" || die "patches/$p is not in patches/series"
  done
}

# sync <from> <to>: make <to> match <from>, touching only files that differ.
sync_tree() {
  (cd "$1" && find . -type f) | while read -r f; do
    if ! cmp -s "$1/$f" "$2/$f"; then
      mkdir -p "$(dirname "$2/$f")"
      cp "$1/$f" "$2/$f"
    fi
  done
  (cd "$2" && find . -type f ! -name .series) | while read -r f; do
    [ -e "$1/$f" ] || rm -f "$2/$f"
  done
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cmd=${1:-}
case $cmd in
  apply)
    [ $# = 2 ] || die "usage: fork.sh apply <dir>"
    verify_pristine
    stage "$tmp/stage"
    mkdir -p "$2"
    sync_tree "$tmp/stage" "$2"
    patches > "$tmp/series"
    cmp -s "$tmp/series" "$2/.series" || cp "$tmp/series" "$2/.series"
    ;;
  check)
    verify_pristine
    stage "$tmp/stage"
    n=$(patches | wc -l)
    if [ $# -ge 2 ]; then
      diff -r -x .series "$tmp/stage" "$2" >/dev/null ||
        die "$2 is not the pristine sources plus the current series; re-run cmake"
    fi
    echo "Ghidra $version pristine sources verified; $n patches apply exactly"
    ;;
  unpack)
    [ $# = 2 ] || die "usage: fork.sh unpack <dir>"
    [ ! -e "$2" ] || die "$2 exists"
    mkdir -p "$2/$upstream"
    for m in $map; do cp -pR "$here/${m%%:*}" "$2/$upstream/${m#*:}"; done
    cd "$2"
    git init -q
    git add -A
    git -c user.name=revkit -c user.email=revkit@localhost commit -qm "Ghidra $version decompiler (pristine)"
    git tag "ghidra-$version"
    for p in $(patches); do
      git -c user.name=revkit -c user.email=revkit@localhost am -q --keep-cr "$here/patches/$p" || die "git am stopped at $p: resolve, git am --continue, then fork.sh export $2"
    done
    echo "$2: ghidra-$version plus $(patches | wc -l) patches; edit, commit, then fork.sh export $2"
    ;;
  export)
    [ $# = 2 ] || die "usage: fork.sh export <dir>"
    dir=$(cd "$2" && pwd)
    rm -f "$here"/patches/*.patch
    git -C "$dir" format-patch -q --zero-commit --no-signature --no-stat -N \
      -o "$here/patches" "ghidra-$version..HEAD"
    {
      echo "# Applied in order on the pristine Ghidra $version sources (fork.sh)."
      (cd "$here/patches" && ls -- *.patch)
    } > "$here/patches/series"
    echo "exported $(patches | wc -l) patches"
    ;;
  import)
    [ $# = 2 ] || die "usage: fork.sh import <ghidra root>"
    src=$2/$upstream
    [ -d "$src/cpp" ] || die "no $src/cpp"
    rm -rf "$here/decompiler" "$here/datatests" "$here/unittests"
    mkdir -p "$here/decompiler"
    # The C++ sources only: not the Makefile, bison/flex grammars or Doxyfile.
    cp -p "$src"/cpp/*.cc "$src"/cpp/*.hh "$src"/cpp/*.h "$here/decompiler/"
    cp -pR "$src/datatests" "$here/datatests"
    cp -pR "$src/unittests" "$here/unittests"
    (cd "$here" && find decompiler datatests unittests -type f | LC_ALL=C sort | xargs sha256sum > PRISTINE.sha256)
    echo "imported; now set UPSTREAM_VERSION, update CMakeLists.txt's file lists, and rebase the series"
    ;;
  *)
    sed -n '2,25p' "$0" >&2
    exit 2
    ;;
esac
