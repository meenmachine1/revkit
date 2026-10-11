#!/bin/sh
# Regenerates src/gen from proto/ using Node in Docker, so no local Node or
# protoc is needed. With Node installed: npm ci && npm run generate.
#
#   sdk/ts/generate.sh            # install deps (from package-lock) and generate
#   sdk/ts/generate.sh smoke URL  # run test/smoke.ts against a daemon's HTTP URL
#   sdk/ts/generate.sh typecheck
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
image=${NODE_IMAGE:-node:22-bookworm-slim}
cmd=${1:-generate}
run() {
  docker run --rm --network host -u "$(id -u):$(id -g)" -e HOME=/tmp -e NPM_CONFIG_UPDATE_NOTIFIER=false -e RK_HTTP_URL="${RK_HTTP_URL:-}" \
    -e RK_GRPC_URL="${RK_GRPC_URL:-}" -v "$root:/repo" -w /repo/sdk/ts "$image" sh -c "$1"
}
[ -d "$here/node_modules" ] || run "npm ci --no-audit --no-fund"
case "$cmd" in
  generate) run "npm run generate" ;;
  typecheck) run "npm run typecheck" ;;
  smoke) RK_HTTP_URL=${2:?usage: generate.sh smoke http://127.0.0.1:PORT [grpc-url]} RK_GRPC_URL=${3:-} run "npm run smoke" ;;
  *) echo "usage: $0 [generate|typecheck|smoke URL [GRPC_URL]]" >&2; exit 2 ;;
esac
