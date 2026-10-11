#!/bin/sh
# Fast scale regression checks (scripts/ci.sh):
#   - rk-lift on the smallest large-binary benchmark (corpus/large/manifest.json,
#     bash) must stay under peak-RSS limits, a few times today's numbers
#     (docs/scale.md), so only a return of whole-program buffering trips them;
#   - the first decompilation of cmake's main (rk-backend-bench --cold-start,
#     prototype inference off: it runs in the background after the import,
#     best of three runs) within budgets, docs/scale.md:
#       CPU time: 16 s of the process's user and system time, at any load
#       (about 8.6 s on a quiet machine, 11 s at load 10, 13 s at load 15,
#       on 32 threads): what fails on a busy machine too;
#       wall time: 2 s from starting the backend (the design's scale gate;
#       about 1.45 s on a quiet machine), judged only while the load average
#       is under a quarter of the cores, else reported: on a shared machine
#       it measures the other jobs as much as revkit.
# Each is skipped when its binary is missing or differs from the manifest.
#
#   scripts/scale-check.sh [build dir]
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
build=${1:-$root/build}
rk_lift=$build/tools/rk-lift/rk-lift
manifest=$root/corpus/large/manifest.json

# manifest_path <id>: the binary's path if it is the manifest's build, else empty.
manifest_path() {
  entry=$(python3 -c '
import json, sys
b = [b for b in json.load(open(sys.argv[1]))["binaries"] if b["id"] == sys.argv[2]][0]
print(b["path"], b["sha256"])' "$manifest" "$1")
  p=${entry% *}
  s=${entry#* }
  if [ -f "$p" ] && [ "$(sha256sum "$p" | cut -c1-64)" = "$s" ]; then echo "$p"; fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
status=0

# First decompilation on cmake: best of three.
cmake_bin=$(manifest_path cmake)
bench=$build/tools/rk-backend-bench/rk-backend-bench
if [ -z "$cmake_bin" ] || [ ! -x "$bench" ]; then
  echo "scale check: cold start: cmake (manifest build) or rk-backend-bench missing: skipped"
else
  best=
  best_cpu=
  cpu_limit=16000
  for run in 1 2 3; do
    "$bench" "$cmake_bin" --cold-start FUN_001f2130 --infer-prototypes off >"$tmp/cold" 2>"$tmp/err" || {
      echo "scale check: cold start: rk-backend-bench failed" >&2
      cat "$tmp/err" >&2
      status=1
      break
    }
    ms=$(sed -n 's/.*; \([0-9.]*\) ms in all.*/\1/p' "$tmp/cold" | cut -d. -f1)
    cpu=$(sed -n 's/.* ms in all, \([0-9.]*\) ms CPU.*/\1/p' "$tmp/cold" | cut -d. -f1)
    if [ -z "$ms" ] || [ -z "$cpu" ]; then
      echo "scale check: cold start: rk-backend-bench printed no times" >&2
      cat "$tmp/cold" >&2
      status=1
      break
    fi
    if [ -z "$best" ] || [ "$ms" -lt "$best" ]; then best=$ms; fi
    if [ -z "$best_cpu" ] || [ "$cpu" -lt "$best_cpu" ]; then best_cpu=$cpu; fi
    [ "$best" -le 2000 ] && [ "$best_cpu" -le "$cpu_limit" ] && break
  done
  if [ -n "$best" ] && [ -n "$best_cpu" ]; then
    load=$(cut -d' ' -f1 /proc/loadavg)
    quiet=$(awk -v l="$load" -v n="$(nproc)" 'BEGIN { print (l < n / 4) ? 1 : 0 }')
    what="first decompilation of cmake's main after $best ms, $best_cpu ms CPU (load $load"
    if [ "$best_cpu" -gt "$cpu_limit" ]; then
      echo "scale check: cold start: $what): CPU over $cpu_limit ms" >&2
      status=1
    elif [ "$best" -gt 2000 ] && [ "$quiet" = 1 ]; then
      echo "scale check: cold start: $what): over 2000 ms" >&2
      status=1
    elif [ "$best" -gt 2000 ]; then
      echo "scale check: cold start: $what, over a quarter of the $(nproc) cores): CPU within $cpu_limit ms; wall time over 2000 ms, not judged at this load"
    elif [ "$quiet" = 1 ]; then
      echo "scale check: cold start: $what): within 2000 ms and $cpu_limit ms CPU"
    else
      echo "scale check: cold start: $what, over a quarter of the $(nproc) cores): within $cpu_limit ms CPU; wall time not judged at this load"
    fi
  fi
fi

path=$(manifest_path bash)
if [ -z "$path" ]; then
  echo "scale check: bash missing or not the manifest's build: skipped"
  exit $status
fi
# check <label> <limit MB> rk-lift args...
check() {
  label=$1 limit=$2
  shift 2
  /usr/bin/time -o "$tmp/time" -f '%M %e' "$rk_lift" "$@" -o "$tmp/out.json" "$path" 2>"$tmp/err" || {
    echo "scale check: $label: rk-lift failed" >&2
    cat "$tmp/err" >&2
    status=1
    return
  }
  read -r kb secs <"$tmp/time"
  mb=$((kb / 1024))
  if [ "$mb" -gt "$limit" ]; then
    echo "scale check: $label: peak RSS $mb MB > $limit MB" >&2
    status=1
  else
    echo "scale check: $label: peak RSS $mb MB (limit $limit MB), ${secs} s"
  fi
}
check "rk-lift bash" 150
check "rk-lift --analyze bash" 400 --analyze
exit $status
