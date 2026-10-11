#!/usr/bin/env bash
# Regenerate bench/results.json and the markdown tables used in RESULTS.md
# (bench/raw/tables-main.md) from the runs against rk-daemon.
set -euo pipefail
cd "$(dirname "$0")/.."
R=bench/raw
shopt -s nullglob
MAIN=($R/daemon-*.json $R/autobench-tauri-webkitgtk-dpr?.json $R/autobench-tauri-webkitgtk-r?-dpr?.json
      $R/autobench-tauri-webkitgtk-native-dpr?.json $R/autobench-tauri-webkitgtk-native-r?-dpr?.json)
npx tsx bench/report.ts --json bench/results.json "${MAIN[@]}" > $R/tables-main.md
echo "wrote bench/results.json and $R/tables-main.md"
