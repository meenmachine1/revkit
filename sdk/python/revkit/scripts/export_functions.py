# @category Export
# @description Exports every function (entry, name, size, prototype, callers and references and,
# @description optionally, its decompiled C) to a JSON or CSV file.
# @context program
# @arg out:file Where to write
# @arg format[json|csv]=json File format
# @arg decompile:bool=false Include each function's decompiled C (DecompileMany)
"""Export functions to JSON or CSV (with decompilation, through DecompileMany)."""
import csv
import json

from revkit.script import *

out = ask_file("out", "Write the functions to")
rows = []
for f in functions():
    rows.append({
        "entry": f"0x{f.entry.offset:x}",
        "name": f.name,
        "size": f.size,
        "prototype": f.prototype,
        "thunk": f.thunk,
        "instructions": f.instruction_count,
        "callers": f.caller_count,
        "xrefs": f.xref_count,
    })
if args["decompile"]:
    by_entry = {r["entry"]: r for r in rows}
    monitor.set_max(len(rows))
    monitor.message("Decompiling")
    for r in decompile_many():
        monitor.increment()
        row = by_entry[f"0x{r.entry.offset:x}"]
        row["c"] = r.function.text if not r.error else ""
        row["decompile_failed"] = r.HasField("failure") or bool(r.error)

with open(out, "w", newline="") as fh:
    if args["format"] == "csv":
        w = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else ["entry"])
        w.writeheader()
        w.writerows(rows)
    else:
        json.dump({"program": current_program.id, "functions": rows}, fh, indent=1)
print(f"{len(rows)} function(s) written to {out}")
