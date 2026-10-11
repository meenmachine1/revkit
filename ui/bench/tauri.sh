#!/usr/bin/env bash
# Run the autobench inside the Tauri shell (WebKitGTK) under Xvfb, at device
# scale 1 and 2. Needs:
#   - rk-daemon serving the program on :50052 and allowing the shell's
#     origin:  rk-daemon --no-auth --open <binary> --allow-origin tauri://localhost
#   - a release build of the shell (it embeds dist/, so rebuild after
#     every npm run build):  (cd tauri/src-tauri && cargo build --release)
# Results land in bench/raw/autobench-<label>.json (bench/sink.ts is
# started here). Extra env is passed through, e.g.
# WEBKIT_DISABLE_DMABUF_RENDERER=1. QUERY_EXTRA adds URL parameters
# (&dpr=native measures without the DPR 1 fallback). NO_XVFB=1 DISP=:0 runs
# on an existing display instead.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=tauri/src-tauri/target/release/revkit-shell
SUFFIX=${SUFFIX:-}
QUERY_EXTRA=${QUERY_EXTRA:-}
DISP=${DISP:-:99}
SINK_PORT=${SINK_PORT:-8790}
node_modules/.bin/tsx bench/sink.ts --port "$SINK_PORT" >/dev/null 2>&1 &
sink=$!
# tsx runs the script in a child node process: stop both.
trap 'pkill -P $sink 2>/dev/null; kill $sink 2>/dev/null || true' EXIT
sleep 1
for scale in ${SCALES:-1 2}; do
  label="tauri-webkitgtk${SUFFIX}-dpr${scale}"
  out="bench/raw/autobench-${label}.json"
  rm -f "$out"
  xpid=""
  if [[ -z "${NO_XVFB:-}" ]]; then
    Xvfb "$DISP" -screen 0 $((1920 * scale))x$((1080 * scale))x24 -nolisten tcp >/dev/null 2>&1 &
    xpid=$!
    sleep 1
  fi
  DISPLAY=$DISP GDK_SCALE=$scale REVKIT_DAEMON=${REVKIT_DAEMON:-http://127.0.0.1:50052} REVKIT_UNDECORATED=1 REVKIT_WIDTH=1920 REVKIT_HEIGHT=1080 \
    REVKIT_UI_QUERY="theme=dark&autobench=${label}&sink=http://127.0.0.1:${SINK_PORT}${QUERY_EXTRA}" \
    "$BIN" >"bench/raw/${label}.log" 2>&1 &
  apid=$!
  for _ in $(seq 1 600); do
    [[ -s "$out" ]] && break
    sleep 1
  done
  kill "$apid" $xpid 2>/dev/null || true
  wait "$apid" $xpid 2>/dev/null || true
  if [[ -s "$out" ]]; then echo "ok: $out"; else echo "no result for $label (see bench/raw/${label}.log)"; fi
done
