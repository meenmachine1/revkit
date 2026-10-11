# @category Analysis/Naming
# @description Names small unnamed functions that only call one named function after it
# @description (FUN_00401230 that only calls malloc becomes malloc_wrapper).
# @context program
# @arg max_instructions:int=40 Largest function to consider, in instructions
# @arg suffix=_wrapper What to append to the callee's name
# @arg dry_run:bool=false Report the names without renaming
"""Rename FUN_ functions by their one callee (a wrapper, a tail call)."""
from revkit.script import *
from revkit.v1 import listing_pb2

CALLS = (listing_pb2.XREF_KIND_CALL, listing_pb2.XREF_KIND_JUMP)

funcs = {f.entry.offset: f for f in functions()}
taken = {f.name for f in funcs.values()}
renames = []
candidates = [f for f in funcs.values()
              if f.name.startswith("FUN_") and not f.thunk and not f.external
              and 0 < f.instruction_count <= args["max_instructions"]]
monitor.set_max(len(candidates))
for f in candidates:
    monitor.increment()
    callees = set()
    for r in f.body:
        for x in current_program.xrefs(range=(r.first.offset, r.last.offset), direction="from"):
            target = funcs.get(x.to_address.offset)
            # Calls, and jumps to another function's entry (tail calls).
            if x.kind in CALLS and target is not None and target.entry.offset != f.entry.offset:
                callees.add(target.entry.offset)
    if len(callees) != 1:
        continue
    callee = funcs[callees.pop()]
    if callee.name.startswith("FUN_"):
        continue
    # __printf_chk (a fortified printf) and printf@GLIBC name printf.
    plain = callee.name.split("@")[0]
    if plain.startswith("__") and plain.endswith("_chk"):
        plain = plain[2:-4]
    base = plain + args["suffix"]
    name, n = base, 2
    while name in taken:
        name, n = f"{base}_{n}", n + 1
    taken.add(name)
    renames.append((f, name))

for f, name in renames:
    print(f"0x{f.entry.offset:x} {f.name} -> {name}")
    if not args["dry_run"]:
        rename(f.entry.offset, name)
print(f"{len(renames)} function(s) {'would be ' if args['dry_run'] else ''}named")
