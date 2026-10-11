#!/usr/bin/env bash
# The full benchmark used for bench/RESULTS.md, repeated: host Chrome
# (software and GPU), Playwright engines in Docker, and the Tauri shell
# under Xvfb (as shipped and with dpr=native). Each run waits for the
# machine to be quiet (1-minute load below $MAX_LOAD, default 6), since the
# host is shared. Needs rk-daemon on :50052 serving the program with
# --allow-origin tauri://localhost, and fresh dist/ and shell builds.
# START=n resumes at round n.
set -euo pipefail
cd "$(dirname "$0")/.."
RUNS=${RUNS:-3}
START=${START:-1}
MAX_LOAD=${MAX_LOAD:-6}
quiet() {
  for _ in $(seq 1 360); do
    awk -v max="$MAX_LOAD" '{ exit !($1 < max) }' /proc/loadavg && return 0
    sleep 10
  done
  echo "machine never got quiet; running anyway (load $(cut -d' ' -f1 /proc/loadavg))"
}
for r in $(seq "$START" "$RUNS"); do
  sfx=$([ "$r" = 1 ] && echo "" || echo "-r$r")
  quiet
  npx tsx bench/run.ts --engines chrome,chrome-uncapped,chrome-gpu,chrome-gpu-uncapped --dpr 1,2 \
    --out "bench/raw/daemon-host-chrome$sfx.json" --host host
  quiet
  docker run --rm --network host --ipc host --user "$(id -u):$(id -g)" -e HOME=/tmp -e IN_DOCKER=1 \
    -v "$PWD/..:/repo" -w /repo/ui mcr.microsoft.com/playwright:v1.63.0-noble \
    node_modules/.bin/tsx bench/run.ts --engines chromium,chromium-uncapped,webkit,firefox --dpr 1,2 \
    --out "bench/raw/daemon-docker$sfx.json" --host docker
  quiet
  REP="$sfx" bench/tauri-all.sh
done
bench/report-all.sh
