#!/usr/bin/env bash
# Phase 0 harness, end to end: build the corpus, export Ghidra references,
# run refdiff. This is the entry point CI calls.
#
#   scripts/phase0.sh [options]
#
#   --skip-build          reuse out/corpus
#   --skip-export         reuse out/ref and out/ghidra-db
#   --only GLOB           export only manifest paths matching GLOB (repeatable)
#   --jobs N              exporter worker processes (default: auto)
#   --check-determinism   export a second time to out/ref.2 and require identical bytes
#   --candidate DIR       also diff DIR (e.g. revkit's output) against out/ref
#   --baseline FILE       with --candidate: fail on any regression vs FILE
#   --save-baseline FILE  with --candidate: write the run's rates to FILE
#
# Always runs refdiff's unit tests and the self-check (out/ref vs itself must
# agree 100%). Exits non-zero if any step fails.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
out=$repo/out
build=1 export=1 determinism=0
only=() jobs=() candidate="" baseline="" save_baseline=""
while [ $# -gt 0 ]; do
  case $1 in
    --skip-build) build=0; shift ;;
    --skip-export) export=0; shift ;;
    --only) only+=(--only "$2"); shift 2 ;;
    --jobs) jobs=(-j "$2"); shift 2 ;;
    --check-determinism) determinism=1; shift ;;
    --candidate) candidate=$(realpath "$2"); shift 2 ;;
    --baseline) baseline=$(realpath "$2"); shift 2 ;;
    --save-baseline) save_baseline=$(realpath -m "$2"); shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

step() { printf '\n=== %s ===\n' "$*"; }
py=$("$repo/scripts/setup-pyghidra.sh")

step "refdiff unit tests"
"$py" -m pytest -q "$repo/tools/refdiff/tests" -k "not RealExport"

if [ $build = 1 ]; then
  step "build corpus"
  "$repo/scripts/build-corpus.sh"
fi

export_to() {
  local dest=$1
  shift
  rm -rf "$dest"
  "$py" "$repo/tools/ghidra-export/ghidra_export.py" --corpus "$out/corpus" --out "$dest" \
    --stats "$dest.stats.json" "${only[@]}" "${jobs[@]}" "$@"
}

if [ $export = 1 ]; then
  step "export Ghidra references and decompiler inputs"
  # One analysis for both: Ghidra's auto-analysis isn't fully deterministic.
  rm -rf "$out/ghidra-db"
  export_to "$out/ref" --inputs-out "$out/ghidra-db"
fi

if [ $determinism = 1 ]; then
  step "determinism: export again and compare bytes"
  export_to "$out/ref.2"
  diff -rq "$out/ref" "$out/ref.2"
  echo "byte-identical"
fi

step "refdiff self-check"
selfcheck_args=()
for c in binaries memory functions names bodies prototypes decompiled_c c_tokens c_ast c_alpha instructions pcode; do
  selfcheck_args+=(--require "$c=1.0")
done
python3 "$repo/tools/refdiff/refdiff.py" "$out/ref" "$out/ref" "${selfcheck_args[@]}"

if [ -n "$candidate" ]; then
  step "refdiff: candidate vs reference"
  args=(--by-group --json "$out/refdiff-result.json")
  [ -n "$baseline" ] && args+=(--baseline "$baseline")
  [ -n "$save_baseline" ] && args+=(--save-baseline "$save_baseline")
  python3 "$repo/tools/refdiff/refdiff.py" "$out/ref" "$candidate" "${args[@]}"
fi
step "phase0 harness: OK"
