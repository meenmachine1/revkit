# @category Signatures
# @description Writes a signature of every named function (a hash of its instructions with
# @description addresses masked) to a JSON file that apply_function_signatures uses on another program.
# @context program
# @arg out:file Where to write
# @arg min_instructions:int=5 Skip functions shorter than this
"""Function signatures, for naming the same functions in another build (a
small Function ID): each function's mnemonics and operands in order, with
every operand that refers to an address masked, hashed with SHA-256."""
import json

from revkit.script import *
from revkit.scripts._signatures import is_default_name, signature

rows = []
fs = [f for f in functions() if not f.thunk and not f.external and not is_default_name(f.name)
      and f.instruction_count >= args["min_instructions"]]
monitor.set_max(len(fs))
for f in fs:
    monitor.increment()
    sig, n = signature(current_program, f)
    if n >= args["min_instructions"]:
        rows.append({"name": f.name, "hash": sig, "instructions": n, "size": f.size, "prototype": f.prototype})

out = ask_file("out", "Write the signatures to")
with open(out, "w") as fh:
    json.dump({"format": "revkit-function-signatures/1", "program": current_program.id, "functions": rows}, fh, indent=1)
print(f"{len(rows)} signature(s) written to {out}")
