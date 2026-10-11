#!/bin/sh
# Scores revkit's own analysis of a raw firmware image against Ghidra
# (scripts/bench_firmware.py): function recall and precision, listing
# coverage and instruction sets (ARM/Thumb), what the differences are,
# decompile failures (halt_baddata, bad instructions) on both sides, and
# decompiled C on a stratified sample. Not part of CI: it runs only when the
# benchmark's files exist, and skips (exit 0) otherwise.
#
#   scripts/bench-firmware.sh [--fetch] [--headless] [name]
#
# Everything lives outside the repository, in $RK_FW_BENCH (default
# ~/revkit-bench), named after the benchmark (default firmware):
#
#   <name>-firmware.path          the firmware file's path (one line)
#   <name>-raw-args               rk-lift's raw layout flags (one line: --raw --lang ... --region ...);
#                                 empty for an ELF, which both tools load as they do
#   <name>-ghidra-functions.json  the user's Ghidra function list (--fetch)
#   <name>-ghidra-disasm.json     every function's disassembly there (listing coverage; optional)
#   <name>-ghidra-c.json          Ghidra's C for the sample there (optional)
#   <name>-ghidra-headless.json   Ghidra's default analysis of the same image (--headless):
#                                 functions, listing with instruction sets, bad-instruction
#                                 bookmarks, C for every function
#
# One of the function lists is needed: the user's Ghidra is the reference
# when it is there, else Ghidra's default analysis (headless) is.
# --fetch reads the Ghidra files from the user's running Ghidra through the
# ghidra-mcp plugin's HTTP server, read-only (bench_firmware_fetch.py).
# --headless runs Ghidra's default analysis headless (PyGhidra,
# bench_firmware_ghidra.py) on a throwaway in-memory program.
# Ghidra is only the yardstick: nothing from it reaches revkit.
# The report: <name>-report.json.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
fetch=0 headless=0 name=firmware
for a in "$@"; do
  case $a in
    --fetch) fetch=1 ;;
    --headless) headless=1 ;;
    -*) echo "usage: $0 [--fetch] [--headless] [name]" >&2; exit 2 ;;
    *) name=$a ;;
  esac
done
bench=${RK_FW_BENCH:-$HOME/revkit-bench}
b() { echo "$bench/$name-$1"; }
if [ ! -f "$(b firmware.path)" ] || [ ! -f "$(b raw-args)" ]; then
  echo "bench-firmware: no $(b firmware.path) or $(b raw-args): skipped"
  exit 0
fi
fw=$(cat "$(b firmware.path)")
raw=$(cat "$(b raw-args)")
if [ ! -f "$fw" ]; then
  echo "bench-firmware: $fw missing: skipped"
  exit 0
fi
if [ "$fetch" = 1 ]; then
  python3 "$root/scripts/bench_firmware_fetch.py" functions "$(b ghidra-functions.json)"
  python3 "$root/scripts/bench_firmware_fetch.py" disasm "$(b ghidra-disasm.json)"
fi
lang=$(echo "$raw" | sed -n 's/.*--lang \([^ ]*\).*/\1/p')
offset=$(echo "$raw" | sed -n 's/.*--raw-offset \([^ ]*\).*/\1/p')
base=$(echo "$raw" | sed -n 's/.*--base \([^ ]*\).*/\1/p')
regions=$(echo "$raw" | grep -o -- '--region [^ ]*' | tr '\n' ' ' || true)
if [ "$headless" = 1 ]; then
  py=$("$root/scripts/setup-pyghidra.sh")
  if [ -z "$lang" ]; then
    "$py" "$root/scripts/bench_firmware_ghidra.py" --elf --all-c --out "$(b ghidra-headless.json)" "$fw"
  else
    "$py" "$root/scripts/bench_firmware_ghidra.py" --lang "$lang" --offset "${offset:-0}" --base "${base:-0}" $regions \
      --all-c --out "$(b ghidra-headless.json)" "$fw"
  fi
fi
if [ ! -f "$(b ghidra-functions.json)" ] && [ ! -f "$(b ghidra-headless.json)" ]; then
  echo "bench-firmware: no $(b ghidra-functions.json) or $(b ghidra-headless.json) (run with --fetch or --headless): skipped"
  exit 0
fi
# The sample, then Ghidra's C for it from the user's Ghidra (--fetch), then
# the scores again with it.
python3 "$root/scripts/bench_firmware.py" --firmware "$fw" --name "$name" --bench "$bench" --raw-args "$raw" \
  --report "$(b report.json)"
if [ "$fetch" = 1 ]; then
  python3 "$root/scripts/bench_firmware_fetch.py" decompile "$(b ghidra-c.json)" "$(b decompile-sample.txt)"
  python3 "$root/scripts/bench_firmware.py" --firmware "$fw" --name "$name" --bench "$bench" --raw-args "$raw" \
    --report "$(b report.json)"
fi
