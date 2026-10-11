# @category Search
# @description Finds instructions whose text matches a regular expression ("syscall", "^call .*rax",
# @description "xor (\w+), \1"), in the selection or in every executable block.
# @context program
# @arg pattern Regular expression over "mnemonic operands" (as the listing shows them)
# @arg ignore_case:bool=true Match without regard to case
# @arg max_results:int=1000 Stop after this many
# @arg note:bool=false Put a "search" note on each match
"""Instruction search by regular expression (Ghidra's Search → For Instruction
Patterns, by text)."""
import re

from revkit.script import *

rx = re.compile(ask_string("pattern", "Instruction text to match (a regular expression)"),
                re.IGNORECASE if args["ignore_case"] else 0)
if current_selection:
    ranges = [current_selection]
else:
    ranges = [(b.range.first.offset, b.range.last.offset) for b in current_program.memory_map()
              if b.execute and b.initialized]


def text(ins):
    ops = ", ".join("".join(t.text for t in op.tokens) for op in ins.operands)
    return f"{ins.mnemonic} {ops}".strip()


hits = []
for first, last in ranges:
    monitor.message(f"Searching 0x{first:x}..0x{last:x}")
    for ins in instructions(first, last, pcode=False):
        monitor.check_cancelled()
        t = text(ins)
        if rx.search(t):
            hits.append((ins.address.offset, t, ins.function.offset if ins.HasField("function") else None))
            if len(hits) >= args["max_results"]:
                break
    if len(hits) >= args["max_results"]:
        break

names = {}
for at, t, fn in hits:
    if fn is not None and fn not in names:
        f = function_at(fn)
        names[fn] = f.name if f else f"0x{fn:x}"
    where = f"  in {names[fn]}" if fn is not None else ""
    print(f"0x{at:x}  {t}{where}")
    if args["note"]:
        note(at, f"matches /{rx.pattern}/: {t}", tag="search")
more = " (stopped at max_results)" if len(hits) >= args["max_results"] else ""
print(f"{len(hits)} match(es){more}")
