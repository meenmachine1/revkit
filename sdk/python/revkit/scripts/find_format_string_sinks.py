# @category Vulnerability
# @description Finds calls to printf-family functions whose format argument is not a constant
# @description string (format-string bugs), from the decompiler's view of each caller.
# @context program
# @arg annotate:bool=true Add a "format-sink" note at each call
"""Find format-string sinks.

The sinks are the C library's formatting functions (and their _chk
variants), found by name. Each caller is decompiled (DecompileMany) and
every call to a sink is read from the C tokens: when the argument in the
format's position isn't a string literal, the call is reported.
"""
from collections import defaultdict

from revkit.script import *

# The format argument's index for each function.
SINKS = {
    "printf": 0, "vprintf": 0, "fprintf": 1, "vfprintf": 1, "dprintf": 1, "vdprintf": 1, "sprintf": 1,
    "vsprintf": 1, "snprintf": 2, "vsnprintf": 2, "asprintf": 1, "vasprintf": 1, "syslog": 1, "vsyslog": 1,
    "warn": 0, "warnx": 0, "err": 1, "errx": 1, "__printf_chk": 1, "__vprintf_chk": 1, "__fprintf_chk": 2,
    "__vfprintf_chk": 2, "__dprintf_chk": 2, "__sprintf_chk": 3, "__vsprintf_chk": 3, "__snprintf_chk": 4,
    "__vsnprintf_chk": 4, "__asprintf_chk": 2, "__syslog_chk": 2, "__vsyslog_chk": 2,
}

sinks = {}  # entry -> (name, format index)
for f in functions():
    base = f.name if f.name in SINKS else f.name.lstrip("_")
    if base in SINKS:
        sinks[f.entry.offset] = (f.name, SINKS[base])
callers = defaultdict(set)
for entry in sinks:
    for x in xrefs_to(entry):
        if x.HasField("from_function"):
            callers[x.from_function.offset].add(entry)
print(f"{len(sinks)} formatting function(s), called from {len(callers)} function(s)")


def arguments(tokens, start):
    """The argument token lists of the call whose name is tokens[start]."""
    args_, depth, cur = [], 0, []
    for t in tokens[start + 1:]:
        if t.text == "(":
            depth += 1
            if depth == 1:
                continue
        elif t.text == ")":
            depth -= 1
            if depth == 0:
                args_.append(cur)
                return args_
        elif t.text == "," and depth == 1:
            args_.append(cur)
            cur = []
            continue
        if depth >= 1 and t.kind != 14:  # not whitespace
            cur.append(t)
    return args_


found = 0
monitor.set_max(len(callers))
for r in decompile_many(sorted(callers), text=False):
    monitor.increment()
    if r.error or r.HasField("failure"):
        continue
    for line in r.function.lines:
        toks = list(line.tokens)
        for i, t in enumerate(toks):
            target = t.target.offset if t.HasField("target") else None
            if t.kind != 3 or target not in sinks:  # FUNCTION_NAME
                continue
            name, index = sinks[target]
            got = arguments(toks, i)
            if index >= len(got) or not got[index]:
                continue
            if any(a.kind == 8 for a in got[index]):  # STRING literal
                continue
            site = t.address.offset if t.HasField("address") else r.entry.offset
            text = "".join(a.text for a in got[index])
            print(f"0x{site:x} in {r.function.name}: {name}(... {text} ...) has a non-constant format")
            if args["annotate"]:
                note(site, f"{name} with a non-constant format: {text}", tag="format-sink")
            found += 1
print(f"{found} format-string sink(s)")
