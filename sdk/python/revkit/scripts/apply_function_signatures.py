# @category Signatures
# @description Names unnamed functions after the signatures export_function_signatures wrote from
# @description another program: a function whose signature names one function there gets its name.
# @context program
# @arg signatures:file The JSON file export_function_signatures wrote
# @arg prototypes:bool=false Also give each named function the prototype recorded with it
# @arg dry_run:bool=false Report the names without renaming
"""Apply function signatures (a small Function ID): match by the hash of the
instructions with addresses masked; only unique matches, both ways, are
named."""
import json
from collections import defaultdict

from revkit.script import *
from revkit.scripts._signatures import is_default_name, signature

with open(ask_file("signatures", "The signatures file")) as fh:
    data = json.load(fh)
if data.get("format") != "revkit-function-signatures/1":
    raise SystemExit("not a revkit function-signatures file (export_function_signatures writes them)")
known = defaultdict(list)
for row in data["functions"]:
    known[row["hash"]].append(row)

taken = {f.name for f in functions()}
mine = defaultdict(list)
fs = [f for f in functions() if not f.thunk and not f.external and is_default_name(f.name)]
monitor.set_max(len(fs))
for f in fs:
    monitor.increment()
    sig, _ = signature(current_program, f)
    if sig in known:
        mine[sig].append(f)

named = ambiguous = 0
for sig, here in sorted(mine.items(), key=lambda kv: kv[1][0].entry.offset):
    there = known[sig]
    names = sorted({r["name"] for r in there})
    if len(here) != 1 or len(names) != 1:
        ambiguous += 1
        print(f"ambiguous: {', '.join(f.name for f in here)} ~ {', '.join(names)}")
        continue
    f, row = here[0], there[0]
    if row["name"] in taken:
        print(f"skipped 0x{f.entry.offset:x} {f.name}: {row['name']} is taken")
        continue
    taken.add(row["name"])
    named += 1
    print(f"0x{f.entry.offset:x} {f.name} -> {row['name']}")
    if not args["dry_run"]:
        rename(f.entry.offset, row["name"])
        if args["prototypes"] and row.get("prototype"):
            retype(f.entry.offset, row["prototype"])
print(f"{named} function(s) {'would be ' if args['dry_run'] else ''}named, {ambiguous} ambiguous, "
      f"from {data.get('program', 'another program')}")
