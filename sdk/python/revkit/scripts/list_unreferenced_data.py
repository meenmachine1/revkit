# @category Analysis/Data
# @description Lists defined data nothing refers to (strings, pointers, typed globals): dead
# @description data, tables reached only through computed addresses, or leftovers worth a look.
# @context program
# @arg categories=string,pointer,typed Which kinds of data (string, pointer, undefined, typed)
# @arg annotate:bool=false Add an "unreferenced" note at each one
# @arg out:file= Also write the list as JSON here
"""List unreferenced data (ListData with no references to it)."""
import json

from revkit.script import *

cats = [c.strip() for c in args["categories"].split(",") if c.strip()]
rows = []
for d in current_program.data(*cats):
    monitor.check_cancelled()
    if d.xref_to_count:
        continue
    value = d.value if len(d.value) <= 60 else d.value[:57] + "..."
    rows.append({"address": f"0x{d.address.offset:x}", "size": d.length, "type": d.data_type, "label": d.label,
                 "value": d.value})
    print(f"0x{d.address.offset:x} {d.data_type:<14} {d.label or '':<28} {value!r}")
    if args["annotate"]:
        note(d.address, f"unreferenced {d.data_type}", tag="unreferenced")
print(f"{len(rows)} unreferenced data item(s)")
if args["out"]:
    with open(args["out"], "w") as fh:
        json.dump({"program": current_program.id, "unreferenced": rows}, fh, indent=1)
