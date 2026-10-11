# @category Analysis/Naming
# @description Names unnamed functions after the identifier a string they use starts with
# @description ("parse_config: missing value" names its function parse_config).
# @context program
# @arg min_length:int=4 Shortest identifier to take from a string
# @arg dry_run:bool=false Report the renames without making them
"""Rename FUN_ functions by their strings.

Error and log messages often start with the function's own name
("parse_config: missing value", "open_database(): ..."). For every string
that starts so, the functions referring to it get that identifier as a
candidate; an unnamed function with exactly one candidate that no other
function claims, and that isn't already a name, is renamed.
"""
import re
from collections import defaultdict

from revkit.script import *

min_len = args["min_length"]
ident = re.compile(r"^\s*\[?([A-Za-z_][A-Za-z0-9_]{%d,63})\]?\s*(?::|\(\))" % max(0, min_len - 1))

candidates = defaultdict(set)  # function entry -> identifiers
claims = defaultdict(set)  # identifier -> function entries
strs = [s for s in strings() if s.xref_to_count and ident.match(s.value)]
monitor.set_max(len(strs))
monitor.message("Reading the strings' references")
for s in strs:
    monitor.increment()
    name = ident.match(s.value).group(1)
    for x in xrefs_to(s.address):
        if x.HasField("from_function"):
            candidates[x.from_function.offset].add(name)
            claims[name].add(x.from_function.offset)

taken = {f.name for f in functions()}
renamed = 0
for f in functions():
    if not f.name.startswith("FUN_"):
        continue
    names = candidates.get(f.entry.offset, set())
    if len(names) != 1:
        continue
    name = next(iter(names))
    if len(claims[name]) != 1 or name in taken:
        continue
    print(f"0x{f.entry.offset:x} {f.name} -> {name}")
    if not args["dry_run"]:
        rename(f.entry, name)
    taken.add(name)
    renamed += 1
print(f"{renamed} function(s) {'would be ' if args['dry_run'] else ''}renamed")
