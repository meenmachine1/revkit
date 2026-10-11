# @category Analysis/Functions
# @description Tags the program's most complex functions with a plate comment, by size,
# @description instruction count or number of callers.
# @context program
# @arg threshold:int=0 Tag functions measuring at least this (0: the top tenth)
# @arg dry_run:bool=false Report without commenting
"""Tag complex functions.

Asks which measure to use (``ask_choice``; ``--arg measure=...``
answers it headless), measures every function with progress, and puts a
``complexity: <measure> N`` plate comment on each function at or over the
threshold. Every comment is one revision: one undo.
"""
from revkit.script import *

MEASURES = {
    "size": lambda f: f.size,
    "instructions": lambda f: f.instruction_count,
    "callers": lambda f: f.caller_count,
}

measure = ask_choice("measure", "Measure complexity by", list(MEASURES), default="size")
value = MEASURES[measure]

funcs = [f for f in current_program.functions() if not f.external and not f.thunk]
monitor.set_max(len(funcs))
monitor.message(f"Measuring {len(funcs)} functions by {measure}")
scores = []
for f in funcs:
    monitor.increment()
    scores.append((value(f), f))

threshold = args["threshold"]
if threshold <= 0 and scores:
    ranked = sorted(s for s, _ in scores)
    threshold = max(1, ranked[min(len(ranked) - 1, (len(ranked) * 9) // 10)])

tagged = 0
for score, f in sorted(scores, key=lambda s: (-s[0], s[1].entry.offset)):
    if score < threshold:
        break
    print(f"0x{f.entry.offset:x} {f.name}: {measure} {score}")
    if not args["dry_run"]:
        comment(f.entry.offset, f"complexity: {measure} {score}", kind="plate")
    tagged += 1
print(f"{tagged} function(s) at or over {measure} {threshold}")
