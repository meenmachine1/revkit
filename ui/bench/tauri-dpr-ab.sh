#!/usr/bin/env bash
# Does the DPR 1 fallback help WebKitGTK at device scale 2? Alternates the
# Tauri shell at dpr=native and dpr=1 (canvas upscaled, nearest-neighbour)
# N times each, waiting for a quiet machine before each run, then one run
# as shipped (auto). Same prerequisites as bench/tauri.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
N=${N:-4}
MAX_LOAD=${MAX_LOAD:-6}
ONLY=${ONLY:-steady-3000,fling,scrollbar-drag,fill-baseline}
quiet() {
  for _ in $(seq 1 360); do
    awk -v max="$MAX_LOAD" '{ exit !($1 < max) }' /proc/loadavg && return 0
    sleep 10
  done
}
for i in $(seq 1 "$N"); do
  for mode in native 1; do
    quiet
    SCALES=2 SUFFIX="-ab-$mode-$i" QUERY_EXTRA="&dpr=$mode&only=$ONLY" bench/tauri.sh
  done
done
quiet
SCALES=2 SUFFIX="-ab-auto" QUERY_EXTRA="&only=$ONLY" bench/tauri.sh
