#!/bin/sh
# rk-dbg end to end: the debugger tests' program in the emulator (time
# travel) and, when gdbserver is installed, live (a PIE: breakpoints at
# program addresses, step over and out, a watchpoint, the exit).
#   smoke.sh <rk-dbg> <ghidra root> <debuggee.c> <out dir>
set -eu
dbg=$1 ghidra=$2 src=$3 out=$4
mkdir -p "$out"
cc -O0 -g0 -fno-inline -pie -fPIE -pthread -o "$out/debuggee" "$src" 2>/dev/null || exit 77
cd "$out"

# The emulator: a call to middle(4), its every instruction recorded.
"$dbg" --ghidra "$ghidra" --entry middle --mode call --arg 4 \
  -c 'break leaf' -c c -c 'regs RDI' -c finish -c 'regs RAX' -c c -c 'timeline 0 3' -c 'snap 0 RDI' \
  -c 'xs 0 counter 4' -c 'save emu.rktrace' -c 'json emu.json' debuggee >emu.out 2>&1
grep -q 'stopped: breakpoint at 0x[0-9a-f]* (leaf)' emu.out
grep -q '^RDI = 0x5$' emu.out
grep -q '^RAX = 0xf$' emu.out
grep -q 'stopped: returned' emu.out
grep -q '^snapshot 0 stop' emu.out
grep -q '^RDI = 0x4$' emu.out
grep -q ': 00 00 00 00$' emu.out
python3 - emu.json <<'PY'
import json, sys
t = json.load(open(sys.argv[1]))
assert t["target"] == "emulator" and t["complete"], t["target"]
kinds = [s["kind"] for s in t["snapshots"]]
assert kinds[0] == "stop" and "step" in kinds, kinds[:5]
assert t["snapshots"][-1]["stop"] == "returned"
PY

# A conditional breakpoint: fact(5)'s recursion, stopping where n is 2.
"$dbg" --ghidra "$ghidra" --entry fact --mode call --arg 5 \
  -c 'break fact if $RDI == 2' -c c -c 'regs RDI' -c 'info breakpoints' debuggee >cond.out 2>&1
grep -q '^RDI = 0x2$' cond.out
# Rewinding the emulator: back one instruction, and to the start.
"$dbg" --ghidra "$ghidra" --entry fact --mode call --arg 3 \
  -c 'break fact' -c c -c back -c 'rewind 0' -c 'regs RDI' -c c -c 'regs RDI' debuggee >back.out 2>&1
grep -q '^back at snapshot 0: ' back.out
grep -q '^RDI = 0x3$' back.out
grep -q '^RDI = 0x2$' back.out
grep -q '^1 software 0x[0-9a-f]* (fact) hits 3 if \$RDI == 2$' cond.out

command -v gdbserver >/dev/null 2>&1 || { echo "ok (no gdbserver: live part skipped)"; exit 0; }
# Live: under gdbserver, as a PIE that slides.
cat >live.cmds <<'C'
mapping
break main
continue
regs RDI
break middle
continue
bt
print $RDI * 2 + 1
p *(char *)message
display $RAX & 0xff
disas
finish
undisplay
regs RAX
delete 1
delete 2
break fact
continue
delete 3
finish
regs RAX
watch message
info breakpoints
modules
x message 15
continue
delete
continue
output
quit
C
"$dbg" --ghidra "$ghidra" --launch --echo -x live.cmds debuggee >live.out 2>&1 || { cat live.out; exit 1; }
grep -q 'mapping: known slide 0x[0-9a-f]* (auxv AT_ENTRY)' live.out
grep -q 'stopped: breakpoint at 0x[0-9a-f]* (main) \[program 0x1[0-9a-f]*\]' live.out
grep -q '^RDI = 0x1$' live.out
grep -q '^\$RDI \* 2 + 1 = 3 (0x3)$' live.out
grep -q "^\*(char \*)message = 104 'h'" live.out
grep -q '^1: \$RAX & 0xff = 7 (0x7)$' live.out
grep -q '^=> 0x[0-9a-f]* (middle) \[program 0x1[0-9a-f]*\]:  ' live.out
grep -q '^#0  0x[0-9a-f]* (middle) \[program 0x1[0-9a-f]*\]  sp 0x[0-9a-f]*  (registers)$' live.out
grep -q '^#1  0x[0-9a-f]* (main+0x[0-9a-f]*) \[program 0x1[0-9a-f]*\]  sp 0x[0-9a-f]*  (cfi)$' live.out
grep -q '^RAX = 0x7$' live.out
grep -q '^RAX = 0x78$' live.out
grep -q ' debuggee .*main$' live.out
grep -q ': 68 65 6c 6c 6f' live.out
grep -q 'stopped: watchpoint' live.out
grep -q 'Hello, debugger 7 120' live.out
echo ok
