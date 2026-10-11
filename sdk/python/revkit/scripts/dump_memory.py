# @category Export
# @description Writes the bytes of the selection (or of a range you give) to a file, as patched:
# @description raw, hex, or a C array.
# @context selection
# @arg out:file Where to write
# @arg start:address= First address (default: the selection's)
# @arg length:int=0 How many bytes (default: to the selection's end)
# @arg format[raw|hex|c]=raw File format
"""Dump memory to a file (Ghidra's Export → Binary of a selection)."""
from revkit.script import *

if args.get("start") not in (None, ""):
    first = to_addr(args["start"])
    length = args["length"] or ask_int("length", "How many bytes")
elif current_selection:
    first, last = current_selection
    length = args["length"] or (last - first + 1)
else:
    first = ask_address("start", "First address")
    length = args["length"] or ask_int("length", "How many bytes")
if length <= 0:
    raise SystemExit("nothing to dump: give a positive length")

data = read_bytes(first, length)
out = ask_file("out", "Write the bytes to")
if args["format"] == "raw":
    with open(out, "wb") as fh:
        fh.write(data)
elif args["format"] == "hex":
    with open(out, "w") as fh:
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            fh.write(f"{first + i:08x}  {chunk.hex(' ')}\n")
else:
    name = (symbol_at(first) or f"data_{first:x}").replace(".", "_")
    with open(out, "w") as fh:
        fh.write(f"/* 0x{first:x}, {len(data)} bytes, from {current_program.id} */\n")
        fh.write(f"const unsigned char {name}[{len(data)}] = {{\n")
        for i in range(0, len(data), 12):
            fh.write("    " + ", ".join(f"0x{b:02x}" for b in data[i:i + 12]) + ",\n")
        fh.write("};\n")
short = f" (only {len(data)} initialized)" if len(data) < length else ""
print(f"0x{first:x}..0x{first + len(data) - 1:x}: {len(data)} byte(s){short} written to {out}")
