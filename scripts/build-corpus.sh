#!/usr/bin/env bash
# Build the benchmark corpus in Docker.
#
#   scripts/build-corpus.sh [--heldout | --diff | --diff-heldout] [--out DIR] [--update-manifest] [-- build.py args...]
#
# Binaries land in $OUT (default out/corpus), with out/corpus/manifest.json.
# The committed corpus/manifest.json pins every binary's sha256; the build
# fails if the fresh manifest differs unless --update-manifest is given.
# --heldout builds the held-out set instead (docs/heldout.md):
# corpus/heldout.json -> out/corpus-heldout, pinned by
# corpus/heldout-manifest.json, tarballs cached in out/cache-heldout.
# --diff builds the binary-diffing corpus (docs/diff.md: adjacent source
# versions of the tuning programs): corpus/diff.json -> out/corpus-diff,
# pinned by corpus/diff-manifest.json, tarballs cached in out/cache-diff.
# --diff-heldout: the held-out programs' adjacent versions (docs/heldout.md):
# corpus/diff-heldout.json -> out/corpus-diff-heldout, pinned by
# corpus/diff-heldout-manifest.json, tarballs in out/cache-diff-heldout.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
out=$repo/out/corpus
cache=$repo/out/cache
update=0
defn=corpus.json
manifest=$repo/corpus/manifest.json
extra=()
out_arg=
while [ $# -gt 0 ]; do
  case $1 in
    --out) out_arg=$(realpath -m "$2"); shift 2 ;;
    --heldout) defn=heldout.json; manifest=$repo/corpus/heldout-manifest.json
               out=$repo/out/corpus-heldout; cache=$repo/out/cache-heldout; shift ;;
    --diff) defn=diff.json; manifest=$repo/corpus/diff-manifest.json
            out=$repo/out/corpus-diff; cache=$repo/out/cache-diff; shift ;;
    --diff-heldout) defn=diff-heldout.json; manifest=$repo/corpus/diff-heldout-manifest.json
                    out=$repo/out/corpus-diff-heldout; cache=$repo/out/cache-diff-heldout; shift ;;
    --update-manifest) update=1; shift ;;
    --) shift; extra=("$@"); break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -z "$out_arg" ] || out=$out_arg
# The cache may sit behind a symlinked out/ (shared between worktrees);
# Docker mounts the real path.
mkdir -p "$cache"
cache=$(realpath "$cache")

python3 "$repo/corpus/fetch.py" --cache "$cache" --corpus-json "$repo/corpus/$defn"

# Tag the image by the Dockerfile's content so edits rebuild it.
tag=revkit-corpus:$(sha256sum "$repo/corpus/docker/Dockerfile" | cut -c1-12)
if ! docker image inspect "$tag" >/dev/null 2>&1; then
  echo "building toolchain image $tag"
  docker build -t "$tag" "$repo/corpus/docker"
fi

rm -rf "$out"
mkdir -p "$out"
start=$(date +%s)
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -e RK_CORPUS_IMAGE="$tag" -e HOME=/tmp \
  --tmpfs /build:exec,size=8g \
  -v "$repo/corpus:/src:ro" -v "$cache:/cache:ro" -v "$out:/out" \
  "$tag" python3 /src/build.py --corpus /src --defn "$defn" --cache /cache --out /out "${extra[@]}"
echo "corpus built in $(( $(date +%s) - start ))s: $out"

if [ ${#extra[@]} -gt 0 ]; then
  echo "partial build (extra args given): not checking ${manifest#$repo/}"
elif [ $update = 1 ]; then
  cp "$out/manifest.json" "$manifest"
  echo "updated ${manifest#$repo/}"
elif ! cmp -s "$out/manifest.json" "$manifest"; then
  echo "error: built manifest differs from ${manifest#$repo/}" >&2
  diff <(python3 -m json.tool "$manifest" 2>/dev/null || true) \
       <(python3 -m json.tool "$out/manifest.json") | head -40 >&2 || true
  echo "(rerun with --update-manifest if the change is intended)" >&2
  exit 1
fi
