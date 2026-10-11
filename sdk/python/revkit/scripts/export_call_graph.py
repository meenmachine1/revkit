# @category Export
# @description Writes the call graph as Graphviz DOT (or JSON): every function and the functions it
# @description calls, or only what a root function reaches, to a depth.
# @context program
# @arg out:file Where to write (a .dot file renders with dot -Tsvg)
# @arg root:address= Start from this function (empty: the whole program)
# @arg depth:int=0 How many calls deep from the root (0: no limit)
# @arg externals:bool=true Include imported functions (thunks and externals)
# @arg format[dot|json]=dot File format
"""Export the call graph to DOT or JSON (Ghidra users' "Export call graph")."""
import json

from revkit.script import *
from revkit.v1 import listing_pb2

CALLS = (listing_pb2.XREF_KIND_CALL, listing_pb2.XREF_KIND_INDIRECT_CALL)

funcs = {f.entry.offset: f for f in functions()}
monitor.message("Reading calls")
edges = {}  # caller entry -> {callee entry: call count}
# One query for every reference from the whole address space.
for x in current_program.xrefs(range=(0, (1 << 64) - 1), direction="from"):
    monitor.check_cancelled()
    if x.kind not in CALLS or not x.HasField("from_function"):
        continue
    to = x.to_address.offset
    target = funcs.get(to)
    if target is None:
        continue
    caller = x.from_function.offset
    edges.setdefault(caller, {})
    edges[caller][to] = edges[caller].get(to, 0) + 1


def imported(f):
    return f.thunk or f.external


keep = set(funcs)
if not args["externals"]:
    keep = {e for e in keep if not imported(funcs[e])}
root = args.get("root")
if root not in (None, ""):
    start = function_containing(to_addr(root))
    if start is None:
        raise SystemExit(f"no function at {root}")
    seen, frontier, level = {start.entry.offset}, [start.entry.offset], 0
    while frontier and (args["depth"] <= 0 or level < args["depth"]):
        level += 1
        nxt = []
        for e in frontier:
            for callee in edges.get(e, {}):
                if callee in keep and callee not in seen:
                    seen.add(callee)
                    nxt.append(callee)
        frontier = nxt
    keep &= seen

nodes = sorted(keep)
links = [(a, b, n) for a in nodes for b, n in sorted(edges.get(a, {}).items()) if b in keep]
out = ask_file("out", "Write the call graph to")
with open(out, "w") as fh:
    if args["format"] == "json":
        json.dump({
            "program": current_program.id,
            "functions": [{"entry": f"0x{e:x}", "name": funcs[e].name, "imported": imported(funcs[e])} for e in nodes],
            "calls": [{"from": f"0x{a:x}", "to": f"0x{b:x}", "count": n} for a, b, n in links],
        }, fh, indent=1)
    else:
        def q(s):
            return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

        fh.write(f"digraph {q(current_program.id)} {{\n  node [shape=box, fontname=monospace];\n")
        for e in nodes:
            style = ", style=dashed" if imported(funcs[e]) else ""
            fh.write(f"  {q(f'0x{e:x}')} [label={q(funcs[e].name)}{style}];\n")
        for a, b, n in links:
            label = f" [label={n}]" if n > 1 else ""
            fh.write(f"  {q(f'0x{a:x}')} -> {q(f'0x{b:x}')}{label};\n")
        fh.write("}\n")
print(f"{len(nodes)} function(s), {len(links)} call edge(s) written to {out}")
