# @category Analysis/Notes
# @description Lists the program's notes (what scripts and people marked: crypto constants, dangerous
# @description calls, search hits, ...) by tag, with where they are; Ghidra's Bookmarks window as a report.
# @context program
# @arg tag= Only notes with this tag
# @arg out:file= Also write them to this JSON file
"""Notes by tag (revkit's bookmarks)."""
import json
from collections import defaultdict

from revkit.script import *

by_tag = defaultdict(list)
for a in current_program.assertions(kinds=("note",)):
    n = a.body.note
    if args.get("tag") and n.tag != args["tag"]:
        continue
    at = n.address.offset
    f = function_containing(at)
    by_tag[n.tag or "(no tag)"].append({"address": f"0x{at:x}", "function": f.name if f else "", "text": n.text,
                                         "by": a.provenance.id, "seq": a.seq})
total = 0
for tag in sorted(by_tag):
    rows = sorted(by_tag[tag], key=lambda r: int(r["address"], 16))
    print(f"{tag} ({len(rows)}):")
    for r in rows:
        total += 1
        where = f" in {r['function']}" if r["function"] else ""
        print(f"  {r['address']}{where}: {r['text']}")
if args.get("out"):
    with open(args["out"], "w") as fh:
        json.dump({"program": current_program.id, "notes": by_tag}, fh, indent=1)
print(f"{total} note(s)")
