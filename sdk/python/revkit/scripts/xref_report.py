# @category Analysis/References
# @description Lists every reference to a symbol or address, grouped by the function it comes
# @description from, with the referring instruction.
# @context address
# @arg target:address= What to report on (default: the current address)
# @arg out:file= Also write the report as JSON here
"""Cross-reference report for one symbol or address."""
import json
from collections import defaultdict

from revkit.script import *

KINDS = {1: "call", 2: "jump", 3: "cond-jump", 4: "indirect-call", 5: "indirect-jump", 6: "read", 7: "write",
         8: "pointer", 9: "thunk"}

if args.get("target"):
    target = to_addr(args["target"])
elif current_address is not None:
    target = current_address
else:
    target = ask_address("target", "Report references to")
label = symbol_at(target) or f"0x{target:x}"
by_function = defaultdict(list)
for x in xrefs_to(target):
    insn = next(iter(instructions(x.from_address.offset, x.from_address.offset, pcode=False)), None)
    text = "".join(t.text for t in insn.tokens) if insn else ""
    by_function[x.from_function_name or "(no function)"].append(
        {"from": f"0x{x.from_address.offset:x}", "kind": KINDS.get(x.kind, str(x.kind)), "instruction": text})
count = sum(len(v) for v in by_function.values())
print(f"{count} reference(s) to {label} (0x{target:x}) from {len(by_function)} function(s)")
for fname in sorted(by_function):
    print(f"  {fname}")
    for r in by_function[fname]:
        print(f"    {r['from']}  {r['kind']:<13} {r['instruction']}")
if args.get("out"):
    with open(args["out"], "w") as fh:
        json.dump({"target": f"0x{target:x}", "name": label, "references": by_function}, fh, indent=1)
