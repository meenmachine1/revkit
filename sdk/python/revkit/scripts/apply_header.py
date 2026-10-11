# @category Data Types
# @description Applies a C header to the program: defines its types, then gives every function
# @description (imports included) whose name a prototype declares that prototype.
# @context program
# @arg header:file The C header (.h) to apply
# @arg types:bool=true Also define the header's structs, unions, enums and typedefs
# @arg dry_run:bool=false Report what would change without changing it
"""Bulk-apply a header's prototypes to matching functions ("apply a C header
to matching imports"). The types are committed first, so the prototypes can
use them: two revisions, one session (one undo in the UI)."""
from pathlib import Path

from revkit.script import *

path = Path(ask_file("header", "The C header to apply"))
text = path.read_text(errors="replace")
monitor.message(f"Parsing {path.name}")
parsed = current_program.parse_c(text, name=path.name, prototypes=True)
if parsed.errors:
    raise SystemExit(f"{path.name} doesn't parse: " + "; ".join(parsed.errors[:5]))

prototypes = {p.name: p for p in parsed.prototypes}
by_name = {}
for f in functions():
    by_name.setdefault(f.name, []).append(f)

matches = []
for name, proto in sorted(prototypes.items()):
    for f in by_name.get(name, []):
        if f.prototype.replace(" ", "") != proto.declaration.replace(" ", ""):
            matches.append((f, proto))

new_types = [n.key for n in parsed.named if not n.system and n.existing_hash != n.hash]
print(f"{path.name}: {len(prototypes)} prototype(s), {len(parsed.named)} named type(s)")
if args["types"] and new_types:
    print(f"types: {', '.join(new_types)}")
for f, proto in matches:
    print(f"0x{f.entry.offset:x} {f.name}: {f.prototype or '(none)'} -> {proto.declaration}")
unmatched = sorted(set(prototypes) - set(by_name))
if unmatched:
    print(f"{len(unmatched)} prototype(s) name no function here: {', '.join(unmatched[:20])}"
          + (" ..." if len(unmatched) > 20 else ""))

if args["dry_run"]:
    print(f"dry run: {len(matches)} function(s) would be retyped")
else:
    if args["types"] and new_types:
        define_type(text, new_types)
        commit(reason=f"types from {path.name}")
    for f, proto in matches:
        retype(f.entry.offset, proto.declaration)
    print(f"{len(matches)} function(s) retyped")
