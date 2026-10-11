#!/usr/bin/env python3
"""The auto-struct gate (docs/types.md, "Structures from pointer use").

On a stripped corpus binary with a debug twin: for every function whose
DWARF prototype has a parameter of type `<struct> *` (default
`lua_State *`), TypeService.AutoStructure creates a structure from that
parameter's use in the stripped build (the daemon's decompilation, the
pointer followed --depth calls deep), and each field it makes from
accesses is scored against the true layout: does it start where some field
of the struct starts (at any depth: nested structs, unions and arrays of
structs flattened)? Field names and types are reported, not gated.

    auto_struct.py [--binary elf-x86_64/gcc-O2/lua] [--struct lua_State] [--depth 1] [--min 95]

Exit status 1 if the share of fields on true field starts is below --min.
Needs rk-debuginfo and rk-daemon from the build tree, and the corpus
(out/corpus) in the main checkout or this one.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "sdk", "python"))

INT_REGS = {
    "x86:LE:64": ["RDI", "RSI", "RDX", "RCX", "R8", "R9"],
    "AARCH64": [f"x{i}" for i in range(8)],
    "RISCV": [f"a{i}" for i in range(8)],
}
FLOATS = {"float", "double", "long double", "float10", "float16"}


def layouts(debuginfo: str, binary: str) -> dict:
    out = subprocess.run([debuginfo, "--types-json", binary], check=True, capture_output=True, text=True).stdout
    return {t["key"]: t for t in (json.loads(line) for line in out.splitlines() if line.strip())}


def lookup(types: dict, spelled: str):
    s = spelled.replace("volatile ", "").replace("const ", "").strip()
    if s.endswith("*") or s.endswith("]"):
        return None, s
    for key in (s, "typedef " + s, "struct " + s, "union " + s):
        if key in types:
            return types[key], s
    return None, s


def field_starts(types: dict, entry: dict, base: int = 0, depth: int = 0, out=None) -> set:
    """Every byte offset a field starts at, nested aggregates flattened."""
    out = set() if out is None else out
    if depth > 8:
        return out
    for f in entry.get("fields", []):
        off = base + f["bit_offset"] // 8
        out.add(off)
        t = f["type"]
        m = re.match(r"^(.*)\[(\d+)\]$", t)
        if m:
            inner, _ = lookup(types, m.group(1))
            if inner and inner.get("fields") and inner.get("size"):
                for i in range(int(m.group(2))):
                    field_starts(types, inner, off + i * inner["size"], depth + 1, out)
            continue
        inner, _ = lookup(types, t)
        if inner and inner.get("fields"):
            field_starts(types, inner, off, depth + 1, out)
    return out


def leaf_names(types: dict, entry: dict, base: int = 0, prefix: str = "", depth: int = 0, out=None) -> dict:
    out = {} if out is None else out
    if depth > 8:
        return out
    for f in entry.get("fields", []):
        off = base + f["bit_offset"] // 8
        out.setdefault(off, prefix + f["name"])
        inner, _ = lookup(types, f["type"])
        if inner and inner.get("fields"):
            leaf_names(types, inner, off, prefix + f["name"] + ".", depth + 1, out)
    return out


def split_params(proto: str) -> list:
    inside = proto[proto.index("(") + 1: proto.rindex(")")]
    if inside.strip() in ("", "void"):
        return []
    parts, level, cur = [], 0, ""
    for ch in inside:
        if ch == "," and level == 0:
            parts.append(cur.strip())
            cur = ""
            continue
        level += ch in "(["
        level -= ch in ")]"
        cur += ch
    parts.append(cur.strip())
    return parts


def param_type(p: str) -> str:
    # "lua_State * L" -> "lua_State *"; "int idx" -> "int"
    m = re.match(r"^(.*?)(\w+)$", p)
    return (m.group(1) if m and m.group(1).strip() else p).strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", default="elf-x86_64/gcc-O2/lua", help="<arch>/<compiler-opt>/<name> under out/corpus")
    ap.add_argument("--corpus", default="")
    ap.add_argument("--struct", default="lua_State")
    ap.add_argument("--depth", type=int, default=1)
    ap.add_argument("--build", default=os.path.join(ROOT, "build"))
    ap.add_argument("--grpc", default="127.0.0.1:0")
    ap.add_argument("--http", default="127.0.0.1:0")
    ap.add_argument("--min", type=float, default=95.0)
    ap.add_argument("--limit", type=int, default=0, help="score at most this many functions")
    ap.add_argument("--json", default="", help="write the per-function results here")
    args = ap.parse_args()

    from revkit import Client, Daemon

    corpus = args.corpus
    if not corpus:
        for c in (os.path.join(ROOT, "out", "corpus"), os.path.expanduser("~/dev/revkit/out/corpus")):
            if os.path.isdir(c):
                corpus = c
                break
    arch, group, name = args.binary.split("/")
    debug = os.path.join(corpus, arch, group, "debug", name)
    stripped = os.path.join(corpus, arch, group, "stripped", name)
    debuginfo = os.path.join(args.build, "tools", "rk-debuginfo", "rk-debuginfo")
    truth = json.loads(subprocess.run([debuginfo, debug], check=True, capture_output=True, text=True).stdout)
    types = layouts(debuginfo, debug)
    target = types.get("struct " + args.struct) or types.get("typedef " + args.struct)
    if not target:
        print(f"no struct {args.struct} in {debug}", file=sys.stderr)
        return 2
    starts = field_starts(types, target)
    names = leaf_names(types, target)
    top = {f["bit_offset"] // 8 for f in target["fields"]}
    wanted = args.struct + " *"
    regs = next(v for k, v in INT_REGS.items() if truth["binary"]["language"].startswith(k))

    cases = []
    for f in truth["functions"]:
        if "prototype" not in f:
            continue
        params = split_params(f["prototype"])
        ints = 0
        for i, p in enumerate(params):
            t = param_type(p)
            if t == wanted and ints < len(regs):
                cases.append((int(f["entry"], 16), f["name"], i, regs[ints]))
            if t not in FLOATS:
                ints += 1
    if args.limit:
        cases = cases[: args.limit]

    results = []
    daemon = Daemon(os.path.join(args.build, "tools", "rk-daemon", "rk-daemon"), "--backend", "image",
                    startup_timeout=60, grpc=args.grpc, http=args.http)
    with daemon, Client(daemon.grpc_target) as rk:
        prog = rk.program(rk.import_program("default", path=stripped).program.program_id)
        t0 = time.monotonic()
        while not prog.analysis_status().idle and time.monotonic() - t0 < 900:
            time.sleep(1)
        entries = {f.entry.offset for f in prog.functions()}
        started = time.monotonic()
        for entry, fname, index, reg in cases:
            row = {"function": fname, "entry": hex(entry), "parameter": index}
            results.append(row)
            if entry not in entries:
                row["skipped"] = "no function there in the stripped build"
                continue
            fn = prog.decompile(entry, text=False)
            fn = getattr(fn, "function", fn)
            var = next((v for v in fn.variables if v.kind == 1 and v.storage and v.storage[0].register_name == reg), None)
            if var is None:
                row["skipped"] = f"no parameter in {reg}"
                continue
            try:
                made = prog.auto_structure(entry, var.storage_key, call_depth=args.depth)
            except Exception as e:  # noqa: BLE001 - reported per function
                row["skipped"] = str(e)
                continue
            fields = [f for f in made.fields if f.source == 1]
            row["fields"] = [{"offset": f.offset, "size": f.size, "type": f.type_display, "hit": f.offset in starts,
                              "truth": names.get(f.offset, "")} for f in fields]
            row["functions"] = len(made.functions)
        elapsed = time.monotonic() - started

    scored = [r for r in results if "fields" in r]
    fields = [f for r in scored for f in r["fields"]]
    hits = sum(f["hit"] for f in fields)
    covered = {f["offset"] for f in fields if f["hit"]}
    with_fields = [r for r in scored if r["fields"]]
    exact = sum(all(f["hit"] for f in r["fields"]) for r in with_fields)
    pct = 100.0 * hits / len(fields) if fields else 0.0
    print(f"{args.binary}: struct {args.struct} ({target['size']} bytes, {len(target['fields'])} fields, "
          f"{len(starts)} field starts at any depth)")
    print(f"  functions with a {wanted} parameter: {len(cases)}; scored {len(scored)} "
          f"({len(with_fields)} with fields), skipped {len(results) - len(scored)}; depth {args.depth}; {elapsed:.1f} s")
    print(f"  fields made: {len(fields)}; on a true field start: {hits} = {pct:.1f}%")
    print(f"  functions whose fields all land: {exact}/{len(with_fields)}")
    print(f"  distinct true starts found: {len(covered)}/{len(starts)} (top-level fields: {len(covered & top)}/{len(top)})")
    misses = {}
    for f in fields:
        if not f["hit"]:
            misses[f["offset"]] = misses.get(f["offset"], 0) + 1
    if misses:
        print("  misses by offset: " + ", ".join(f"{hex(o)}x{n}" for o, n in sorted(misses.items())))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"binary": args.binary, "struct": args.struct, "depth": args.depth, "percent": pct,
                       "results": results}, fh, indent=1)
    return 0 if pct >= args.min else 1


if __name__ == "__main__":
    sys.exit(main())
