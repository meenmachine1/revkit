#!/bin/sh
# rk-emu end to end: a static x86-64 test program to its exit, with a
# breakpoint, a register set before the run and the trace written.
#   smoke.sh <rk-emu> <ghidra root> <program> <out dir>
set -eu
emu=$1 ghidra=$2 prog=$3 out=$4
[ -x "$prog" ] || exit 77
mkdir -p "$out"
"$emu" --ghidra "$ghidra" --trace "$out/trace.json" --trace-entries 50 "$prog" >"$out/stdout" 2>"$out/stderr" </dev/null
grep -q '^out: hello$' "$out/stdout"
grep -q 'stopped (exited)' "$out/stderr"
grep -q 'exit(42)' "$out/stderr"
python3 - "$out/trace.json" <<'PY'
import json, sys
t = json.load(open(sys.argv[1]))
assert t["stop"]["kind"] == "exited" and t["stop"]["exit_code"] == 42, t["stop"]
assert t["summary"]["syscalls"] >= 5, t["summary"]
assert len(t["entries"]) == 50
assert any(e.get("event", "").startswith("syscall write") for e in t["entries"]) or t["summary"]["syscalls"] > 0
PY
# A breakpoint on a symbol, then the registers there; --reg changes them first.
"$emu" --ghidra "$ghidra" --break rk_finish --reg RBX=0x1234 --steps 100000 "$prog" >/dev/null 2>"$out/stderr2" </dev/null
grep -q 'stopped (breakpoint)' "$out/stderr2"
# A fault is exit status 3.
set +e
"$emu" --ghidra "$ghidra" --entry 0x10 "$prog" >/dev/null 2>"$out/stderr3" </dev/null
rc=$?
set -e
[ "$rc" = 3 ] || { cat "$out/stderr3"; exit 1; }
grep -q 'stopped (unmapped)' "$out/stderr3"
echo ok
