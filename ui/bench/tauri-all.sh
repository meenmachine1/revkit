#!/usr/bin/env bash
# The Tauri shell's WebKitGTK under Xvfb, twice: as shipped (the DPR 1
# fallback may engage) and with it disabled (dpr=native), which is what the
# spike measured. REP=-r2 appends a suffix to the labels for repeated runs.
set -euo pipefail
cd "$(dirname "$0")/.."
SUFFIX="${REP:-}" bench/tauri.sh
SUFFIX="-native${REP:-}" QUERY_EXTRA="&dpr=native" bench/tauri.sh
