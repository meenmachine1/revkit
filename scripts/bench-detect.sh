#!/bin/sh
# Scores auto-detection (docs/autodetect.md) on files outside the
# repository: real firmware and labelled code whose answers are known. Not
# part of CI: it runs only when the benchmark's manifest exists, and skips
# (exit 0) otherwise.
#
#   scripts/bench-detect.sh [--heldout] [detect_score.py options]
#
# $RK_DETECT_BENCH (default ~/revkit-bench/detect) holds
# manifest.json (scripts/detect_external.py describes it). Cases are built
# under build/detect-ext and reports go to build/detect-ext-out; nothing is
# written to the repository. Without --heldout only the dev split runs: the
# held-out split is for a final run, not for tuning (docs/heldout.md).
set -eu
cd "$(dirname "$0")/.."
bench=${RK_DETECT_BENCH:-$HOME/revkit-bench/detect}
split=dev
if [ "${1:-}" = --heldout ]; then split=heldout; shift; fi
if [ ! -f "$bench/manifest.json" ]; then
  echo "bench-detect: no $bench/manifest.json: skipped"
  exit 0
fi
python3 scripts/detect_external.py "$bench/manifest.json" --out build/detect-ext
python3 scripts/detect_score.py --cases build/detect-ext --out "build/detect-ext-out/$split" --split "$split" "$@"
cp "build/detect-ext-out/$split/report.json" "$bench/report-$split.json"
