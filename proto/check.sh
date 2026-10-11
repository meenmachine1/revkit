#!/bin/sh
# Lint the schema and check it for breaking changes against a git ref
# (default: master), using the bufbuild/buf Docker image.
#
#   proto/check.sh [ref]
#
# A ref that has no proto/ directory yet (the first commit of the schema) is
# skipped for the breaking check.
set -eu

ref=${1:-master}
root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
buf_image=${BUF_IMAGE:-bufbuild/buf:1.73.0}
buf() { docker run --rm --user "$(id -u):$(id -g)" -e BUF_CACHE_DIR=/tmp/buf-cache -v "$root:/repo" -w /repo/proto "$buf_image" "$@"; }

buf lint
echo "proto/check.sh: lint ok"

against=$(mktemp -d "$root/.cache-buf-against.XXXXXX")
trap 'rm -rf "$against"' EXIT
if git -C "$root" archive "$ref" proto 2>/dev/null | tar -x -C "$against" 2>/dev/null; then
  buf breaking --against "/repo/$(basename "$against")/proto"
  echo "proto/check.sh: no breaking changes against $ref"
else
  echo "proto/check.sh: $ref has no proto/; skipping breaking check"
fi
