#!/bin/bash
# rawdec.sh <ghidra root> <lang> <file> <offset hex> <length hex> <out.json> [rk-lift options]
# Decompiles a flat image with rk-lift (RKLIFT, default ~/dev/revkit/build) under a 4G scope
# and prints each function's C.
set -o pipefail
root=$1 lang=$2 file=$3 off=$4 len=$5 out=$6; shift 6
systemd-run --user --slice=revkit-work.slice --scope -p MemoryMax=4G -p MemorySwapMax=0 --quiet \
  ${RKLIFT:-$HOME/dev/revkit/build/tools/rk-lift/rk-lift} --ghidra "$root" --raw --lang "$lang" --raw-offset "$off" --raw-length "$len" \
  --raw-entry 0 --analyze --decompile -j 1 "$@" "$file" -o "$out" 2>&1 | tail -4
python3 -I -c "
import json,sys; d=json.load(open(sys.argv[1]))
for f in d['functions']: print(f.get('decompiled_c') or {k:v for k,v in f.items() if k!='body'})" "$out"
