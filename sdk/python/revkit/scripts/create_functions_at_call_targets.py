# @category Analysis/Functions
# @description Creates a function at every call target in executable memory that isn't the
# @description entry of one yet (code discovery missed, or a function someone removed).
# @context program
# @arg dry_run:bool=false Report the targets without creating functions
"""Create functions at unexplored call targets.

Every direct call the listing decodes is a reference of kind CALL; a target
that no function starts at, inside an initialized executable block, gets a
function (its body discovered by the daemon, as for any asserted entry).
"""
from revkit.script import *

entries = {f.entry.offset for f in functions()}
blocks = [(b.range.first.offset, b.range.last.offset) for b in current_program.memory_map() if b.execute and b.initialized]


def executable(a):
    return any(lo <= a <= hi for lo, hi in blocks)


targets = {}
for x in current_program.xrefs(range=(0, (1 << 64) - 1), direction="from", page_size=5000):
    if x.kind != 1:  # XREF_KIND_CALL
        continue
    t = x.to_address.offset
    if t not in entries and executable(t):
        targets.setdefault(t, x.from_address.offset)
for t, site in sorted(targets.items()):
    print(f"0x{t:x} (called from 0x{site:x})")
    if not args["dry_run"]:
        set_function(t)
print(f"{len(targets)} function(s) {'would be ' if args['dry_run'] else ''}created")
