# @category Export
# @description Exports the program's strings with their addresses and the functions that use them,
# @description to JSON or CSV.
# @context program
# @arg out:file Where to write
# @arg format[json|csv]=json File format
# @arg min_length:int=4 Shortest string to include
# @arg contains= Only strings containing this text
"""Export strings and where they are used."""
import csv
import json

from revkit.script import *

rows = []
all_strings = list(strings(args.get("contains") or "", min_length=args["min_length"]))
monitor.set_max(len(all_strings))
for s in all_strings:
    monitor.increment()
    users = []
    if s.xref_to_count:
        users = sorted({x.from_function_name or f"0x{x.from_address.offset:x}" for x in xrefs_to(s.address.offset)})
    rows.append({"address": f"0x{s.address.offset:x}", "length": len(s.value), "value": s.value,
                 "references": s.xref_to_count, "functions": users})

out = ask_file("out", "Write the strings to")
with open(out, "w", newline="") as fh:
    if args["format"] == "csv":
        w = csv.DictWriter(fh, fieldnames=["address", "length", "value", "references", "functions"])
        w.writeheader()
        for r in rows:
            w.writerow({**r, "functions": " ".join(r["functions"])})
    else:
        json.dump({"program": current_program.id, "strings": rows}, fh, indent=1, ensure_ascii=False)
print(f"{len(rows)} string(s) written to {out}")
