#!/usr/bin/env bash
# Build the firmware corpus (corpus/firmware) in Docker.
#
#   scripts/build-firmware-corpus.sh [--out DIR] [--update-manifest] [-- build.py args...]
#
# Images land in $OUT (default out/firmware-corpus) with manifest.json;
# corpus/firmware/manifest.json (committed) pins every image's sha256 and
# the build fails if the fresh manifest differs, unless --update-manifest.
# Sources and Espressif's Xtensa toolchain are pinned downloads cached in
# out/cache-firmware.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
out=$repo/out/firmware-corpus
cache=$repo/out/cache-firmware
manifest=$repo/corpus/firmware/manifest.json
update=0
extra=()
while [ $# -gt 0 ]; do
  case $1 in
    --out) out=$(realpath -m "$2"); shift 2 ;;
    --update-manifest) update=1; shift ;;
    --) shift; extra=("$@"); break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$cache"
cache=$(realpath "$cache")
python3 "$repo/corpus/fetch.py" --cache "$cache" --corpus-json "$repo/corpus/firmware/firmware.json"

tag=revkit-fwcorpus:$(sha256sum "$repo/corpus/firmware/docker/Dockerfile" | cut -c1-12)
if ! docker image inspect "$tag" >/dev/null 2>&1; then
  echo "building toolchain image $tag"
  docker build -t "$tag" "$repo/corpus/firmware/docker"
fi

rm -rf "$out"
mkdir -p "$out"
start=$(date +%s)
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -e RK_CORPUS_IMAGE="$tag" -e HOME=/tmp \
  --tmpfs /build:exec,size=12g \
  -v "$repo/corpus/firmware:/src:ro" -v "$cache:/cache:ro" -v "$out:/out" \
  "$tag" python3 /src/build.py --corpus /src --cache /cache --out /out -j "${RK_CI_JOBS:-16}" "${extra[@]}"
echo "firmware corpus built in $(( $(date +%s) - start ))s: $out"

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
