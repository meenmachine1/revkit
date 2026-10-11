# @category Vulnerability
# @description Lists the calls to functions that are easy to misuse (gets, strcpy, sprintf, system,
# @description ...), grouped by caller, and marks each call with a note.
# @context program
# @arg functions= Comma-separated names to look for instead of the built-in list
# @arg note:bool=true Put a "dangerous-call" note on each call site
"""Find calls to risky C library functions (Ghidra users' "find dangerous
functions"): unbounded copies, format functions, shell commands, temporary
names."""
from revkit.script import *
from revkit.v1 import listing_pb2

RISKY = {
    "gets": "unbounded read", "strcpy": "unbounded copy", "strcat": "unbounded copy", "wcscpy": "unbounded copy",
    "wcscat": "unbounded copy", "stpcpy": "unbounded copy", "sprintf": "unbounded format",
    "vsprintf": "unbounded format", "scanf": "unbounded %s", "sscanf": "unbounded %s", "fscanf": "unbounded %s",
    "system": "shell command", "popen": "shell command", "execl": "runs a program", "execlp": "runs a program",
    "execv": "runs a program", "execvp": "runs a program", "alloca": "stack allocation", "mktemp": "racy temporary name",
    "tmpnam": "racy temporary name", "tempnam": "racy temporary name", "strtok": "not reentrant",
    "realpath": "unbounded output", "getwd": "unbounded output",
}
CALLS = (listing_pb2.XREF_KIND_CALL, listing_pb2.XREF_KIND_JUMP, listing_pb2.XREF_KIND_INDIRECT_CALL)

if args.get("functions"):
    wanted = {n.strip(): "listed" for n in args["functions"].split(",") if n.strip()}
else:
    wanted = RISKY


def base(name):
    n = name.split("@")[0]
    for prefix in ("__", "_"):
        if n.startswith(prefix) and n[len(prefix):] in wanted:
            return n[len(prefix):]
    return n[:-4] if n.endswith("_chk") and n[:-4].lstrip("_") in wanted else n


targets = [f for f in functions() if base(f.name).lstrip("_") in wanted or base(f.name) in wanted]
found = {}
for t in targets:
    name = base(t.name).lstrip("_") if base(t.name).lstrip("_") in wanted else base(t.name)
    for x in xrefs_to(t.entry.offset):
        if x.kind not in CALLS:
            continue
        caller = x.from_function_name or "(no function)"
        found.setdefault(caller, []).append((x.from_address.offset, name))

total = 0
for caller in sorted(found):
    calls = sorted(set(found[caller]))
    print(f"{caller}:")
    for at, name in calls:
        total += 1
        why = wanted.get(name, "")
        print(f"  0x{at:x} {name}" + (f" ({why})" if why and why != "listed" else ""))
        if args["note"]:
            note(at, f"call to {name}" + (f": {why}" if why and why != "listed" else ""), tag="dangerous-call")
print(f"{total} call(s) in {len(found)} function(s)")
