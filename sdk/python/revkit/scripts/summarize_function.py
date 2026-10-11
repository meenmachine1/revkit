# @category Analysis/Functions
# @description Puts a summary of the current function in its plate comment: size, instructions,
# @description callers and the functions it calls.
# @context function
"""Summarize the function at the cursor (``@context function``: the UI
offers it in the listing's and decompiler's right-click menus)."""
from revkit.script import *
from revkit.v1 import listing_pb2

f = current_function
if f is None:
    raise SystemExit("no function at the cursor: give rk-script --address")

calls = set()
for r in f.body:
    for x in current_program.xrefs(range=(r.first.offset, r.last.offset), direction="from"):
        if x.kind in (listing_pb2.XREF_KIND_CALL, listing_pb2.XREF_KIND_INDIRECT_CALL):
            calls.add(x.to_name or f"0x{x.to_address.offset:x}")

text = (f"{f.name}: {f.size} bytes, {f.instruction_count} instructions, "
        f"{f.caller_count} caller(s); calls {', '.join(sorted(calls)) if calls else 'nothing'}")
print(text)
comment(f.entry.offset, text, kind="plate")
