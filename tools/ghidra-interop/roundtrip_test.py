#!/usr/bin/env python3
"""Ghidra <-> revkit round trip, headless (runs with the revkit SDK's Python).

    roundtrip_test.py [--binary out/corpus/elf-x86_64/gcc-O0/stripped/features] [--work DIR] [--keep]

1. Ghidra (PyGhidra, roundtrip_ghidra.py setup): import and analyze the
   binary in a new project, make scripted user edits, export them.
2. revkit: start rk-daemon (persistent project dir), revkit-ghidra-import
   the export, and check every edit is there with import:ghidra provenance
   (agent:ghidra-ai for the AI-named function). Import again, and import an
   export of the program rebased in Ghidra: nothing new may be appended.
3. revkit: edits as user:alice and agent:claude; revkit-ghidra-export.
4. Ghidra (roundtrip_ghidra.py apply): apply the export, check each change
   shows in Ghidra with its revkit provenance, export again.
5. revkit: import that export: revkit's own edits must not come back.

Needs RK_DAEMON (or a build tree), the PyGhidra venv ($REVKIT_PYGHIDRA, default
~/.local/share/revkit-pyghidra/bin/python) and Ghidra ($GHIDRA_INSTALL_DIR).
Exits 0 when every check passes, 77 when a prerequisite is missing (CTest's
skip code).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from revkit import Client, Daemon  # noqa: E402
from revkit.ghidra import exporter, importer  # noqa: E402
from revkit.v1 import assertion_pb2, common_pb2, types_pb2  # noqa: E402

DEFAULT_BINARY = ROOT / "out" / "corpus" / "elf-x86_64" / "gcc-O0" / "stripped" / "features"
SKIP = 77


class Checks:
    def __init__(self):
        self.failed: list[str] = []
        self.passed = 0

    def check(self, ok: bool, what: str) -> bool:
        if ok:
            self.passed += 1
        else:
            self.failed.append(what)
            print(f"  FAIL {what}", file=sys.stderr)
        return ok


def pyghidra(args, *cmd: str) -> None:
    t = time.monotonic()
    r = subprocess.run([args.pyghidra, str(HERE / "roundtrip_ghidra.py"), *cmd], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout)
        raise SystemExit(f"roundtrip_ghidra.py {cmd[0]} failed")
    print(f"ghidra {cmd[0]}: {time.monotonic() - t:.1f} s", file=sys.stderr)


_runs = iter(range(1, 100))


def import_json(target: str, path: Path, work: Path, *extra: str) -> dict:
    report = work / f"import-{next(_runs)}-{path.stem}.report.json"
    importer.main([str(path), "--daemon", target, "--report", str(report), *extra])
    return json.loads(report.read_text())


def winner(prog, kind: str, addr: int, sub: str = ""):
    """The effective assertion on a key, or None."""
    b = prog.blame(prog.key(kind, addr, sub))
    for c in b.candidates:
        if c.status == assertion_pb2.ASSERTION_STATUS_EFFECTIVE:
            return c
    return None


def prov(a) -> str:
    from revkit import format_provenance

    return format_provenance(a.provenance) if a is not None else "(none)"


def check_import(c: Checks, prog, edits: dict, actor: str) -> None:
    """Every scripted Ghidra edit is in revkit with Ghidra's provenance."""
    x = lambda s: int(s, 16)  # noqa: E731
    f1, f5, f3 = x(edits["f1"]), x(edits["f5"]), x(edits["f3"])
    for addr, name, who in ((f1, "rt_parse_options", actor), (f5, "rt_ai_named", "agent:ghidra-ai"),
                            (x(edits["global"]), "rt_global_flag", actor), (x(edits["origin"]), "rt_origin", actor)):
        w = winner(prog, "name", addr)
        c.check(w is not None and w.body.rename.name == name and prov(w) == who,
                f"name {name} at {addr:#x} by {who} (got {w.body.rename.name if w else None} by {prov(w)})")
    for kind, (addr, text) in edits["comments"].items():
        w = winner(prog, "comment", x(addr), kind)
        c.check(w is not None and w.body.comment.text == text and prov(w) == actor, f"{kind} comment at {addr}")
    # Types: the struct, enum and typedef, defined field by field.
    hashes = [a.key.sub for a in prog.assertions(actor="import:ghidra")
              if a.key.kind == common_pb2.FACT_KIND_TYPE_DEF]
    types = {t.name: t for t in prog.types(*hashes).types if t.name}
    for n in ("rt_point", "rt_color", "rt_handle"):
        c.check(n in types, f"type {n} defined by import:ghidra")
    if "rt_point" in types:
        t = types["rt_point"]
        c.check([f.name for f in t.composite.fields] == ["x", "y", "label"] and t.size == 16, "rt_point's fields")
    if "rt_color" in types:
        c.check([v.name for v in types["rt_color"].enumeration.values] == ["RT_RED", "RT_GREEN", "RT_BLUE"], "rt_color's values")
    # Data retypes and the signature, by hash.
    for addr, want in ((x(edits["origin"]), "rt_point"), (x(edits["global"]), "int")):
        w = winner(prog, "type", addr)
        h = w.body.retype.type.type_hash if w else ""
        got = prog.types(h).types[0] if h else None
        c.check(got is not None and (got.name or got.display) == want and prov(w) == actor,
                f"data at {addr:#x} retyped {want} (got {got.display if got else None})")
    w = winner(prog, "type", f1)
    sig = prog.types(w.body.retype.type.type_hash).types[0] if w and w.body.retype.type.type_hash else None
    c.check(sig is not None and sig.kind == types_pb2.TYPE_KIND_FUNCTION and prov(w) == actor, "rt_parse_options' signature")
    d = prog.decompile(f1)
    c.check("rt_handle" in d.prototype.c_declaration and "count" in d.prototype.c_declaration,
            f"the decompiler uses the signature: {d.prototype.c_declaration}")
    local = next((v for v in d.variables if v.name == edits["local"]["name"]), None)
    c.check(local is not None and local.name_origin.asserted.provenance.id == "ghidra",
            f"local {edits['local']['name']} ({[v.storage_key + '=' + v.name for v in d.variables][:8]})")
    # The new function, the flow override, and the notes.
    nf = x(edits["new_function"])
    w = winner(prog, "function", nf)
    c.check(w is not None and prov(w) == actor, f"new function at {nf:#x} asserted")
    c.check(any(f.entry.offset == nf for f in prog.functions()), "new function listed")
    gone = x(edits["removed_function"])
    w = winner(prog, "function", gone)
    c.check(w is not None and w.body.function_bounds.remove and prov(w) == actor, f"deleted function at {gone:#x} removed")
    c.check(not any(f.entry.offset == gone for f in prog.functions()), "deleted function not listed")
    w = winner(prog, "flow_override", x(edits["flow_override"]))
    c.check(w is not None and w.body.flow_override.kind == assertion_pb2.FLOW_OVERRIDE_KIND_CALL_RETURN and prov(w) == actor,
            "flow override CALL_RETURN")
    w = winner(prog, "note", f1, "ghidra:bookmark:Note:rt")
    c.check(w is not None and w.body.note.text == "check the option parsing", "bookmark as a note")
    ea, op, val = edits["equate"]
    w = winner(prog, "note", x(ea), f"ghidra:equate:{op}")
    c.check(w is not None and w.body.note.text == f"RT_MAGIC={val:#x}", "equate as a note")
    w = winner(prog, "note", f3, "ghidra:noreturn")
    known = prog.function(f3).no_return
    c.check(known or (w is not None and prov(w) == actor), "no-return flag (a note, unless revkit infers it)")


def revkit_edits(prog, alice: Client, claude: Client, edits: dict) -> dict:
    """User and agent edits in revkit; returns what to look for in Ghidra."""
    x = lambda s: int(s, 16)  # noqa: E731
    taken = {x(edits[k]) for k in ("f1", "f2", "f3", "f5", "new_function", "removed_function")}
    funcs = [f for f in prog.functions() if f.name.startswith("FUN_") and f.entry.offset not in taken and not f.thunk]
    funcs.sort(key=lambda f: (-f.instruction_count, f.entry.offset))
    f6, f7, f8 = funcs[0], funcs[1], funcs[2]
    a = alice.program(prog.id)
    a.rename(f6.entry.offset, "alice_func", reason="round trip")
    a.comment(f6.entry.offset, "alice was here", "eol")
    a.retype(f6.entry.offset, "int alice_func(char *s)")
    d = a.decompile(f6.entry.offset)
    local = next(v for v in d.variables if v.storage_key.startswith("stack:"))
    a.rename_local(f6.entry.offset, local.storage_key, "alice_tmp")
    calls = [r for r in a.xrefs(range=(f6.body[0].first.offset, f6.body[-1].last.offset), direction="from")
             if r.kind == 1]  # XREF_KIND_CALL
    a.flow_override(calls[0].from_address.offset, "branch")
    a.note(f6.entry.offset, "verify the bounds", tag="todo")
    blocks = {b.name: b for b in a.memory_map()}
    bss = blocks.get(".bss") or blocks[".data"]
    g1, g2 = bss.range.last.offset - 0x3f & ~0xf, bss.range.last.offset - 0x1f & ~0xf
    a.retype(g1, "unsigned int")
    long_ = types_pb2.TypeNode(kind=types_pb2.TYPE_KIND_INT, size=8, rank=types_pb2.INTEGER_RANK_LONG)
    pair = types_pb2.TypeNode(kind=types_pb2.TYPE_KIND_STRUCT, name="alice_pair", size=16)
    pair.fields.add(name="a", type=types_pb2.TypeNodeRef(assertion_index=0), offset=0)
    pair.fields.add(name="b", type=types_pb2.TypeNodeRef(assertion_index=0), offset=8)
    defs = [assertion_pb2.AssertionBody(define_type=assertion_pb2.DefineType(type=n)) for n in (long_, pair)]
    hashes = [x.key.sub for x in a.append(*defs, validate_only=True).assertions]
    retype = assertion_pb2.AssertionBody(retype=assertion_pb2.Retype(
        target=assertion_pb2.Target(address=common_pb2.Address(offset=g2)), type=assertion_pb2.TypeSpec(type_hash=hashes[1])))
    a.append(*defs, retype)
    jumps = [r for r in a.xrefs(range=(f8.body[0].first.offset, f8.body[-1].last.offset), direction="from")
             if r.kind == 3 and r.to_address.offset != f8.entry.offset]  # XREF_KIND_CONDITIONAL_JUMP
    nf2 = jumps[0].to_address.offset
    a.set_function(nf2)
    claude.program(prog.id).rename(f7.entry.offset, "claude_helper", reason="it formats the help text")
    return {"f6": f6.entry.offset, "f7": f7.entry.offset, "local": "alice_tmp", "call": calls[0].from_address.offset,
            "g1": g1, "g2": g2, "nf2": nf2}


def check_export(c: Checks, after: dict, report: dict, mine: dict) -> None:
    c.check(report["failed"] == 0 and report["skipped"] == 0,
            f"every change applied ({[r for r in report['changes'] if r['status'] != 'applied']})")
    by = {}
    for o in after["changes"]:
        by.setdefault((o["op"], int(o["address"], 16)), o)

    def at(op, addr):
        return by.get((op, addr), {})

    o = at("rename", mine["f6"])
    c.check(o.get("name") == "alice_func" and o.get("name_source") == "USER_DEFINED", f"alice_func in Ghidra ({o.get('name')})")
    c.check("user:alice #" in o.get("trace", ""), f"rename traced to user:alice ({o.get('trace')})")
    o = at("rename", mine["f7"])
    c.check(o.get("name") == "claude_helper" and o.get("name_source") == "AI", "claude_helper in Ghidra, source AI")
    c.check("agent:claude" in o.get("trace", ""), "rename traced to agent:claude")
    o = at("comment", mine["f6"])
    c.check(o.get("comments", {}).get("eol") == "alice was here", "comment in Ghidra")
    o = at("retype", mine["f6"])
    c.check("char" in o.get("prototype", "") and "alice_func" in o.get("prototype", ""), f"prototype in Ghidra ({o.get('prototype')})")
    o = at("rename_local", mine["f6"])
    c.check("alice_tmp" in o.get("variables", {}), f"local in Ghidra ({o.get('variables')})")
    o = at("retype", mine["g1"])
    c.check(o.get("data_type") == "uint", f"data uint in Ghidra ({o.get('data_type')})")
    o = at("retype", mine["g2"])
    c.check(o.get("data_type") == "alice_pair", f"data alice_pair in Ghidra ({o.get('data_type')})")
    c.check("alice_pair" in after["revkit_types"] and after["revkit_types"]["alice_pair"]["length"] == 16
            and "user:alice" in after["revkit_types"]["alice_pair"]["description"], "struct alice_pair in /revkit")
    o = at("flow_override", mine["call"])
    c.check(o.get("flow_override") == "BRANCH", f"flow override in Ghidra ({o.get('flow_override')})")
    o = at("note", mine["f6"])
    c.check(o.get("notes", {}).get("note:todo") == "verify the bounds", "note as a revkit bookmark")
    o = at("function", mine["nf2"])
    c.check(o.get("function") is True and "user:alice" in o.get("trace", ""), "new function in Ghidra")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", default=str(DEFAULT_BINARY))
    ap.add_argument("--work", help="work directory (default: a temp dir, removed unless --keep)")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--pyghidra", default=os.environ.get("REVKIT_PYGHIDRA",
                                                          os.path.expanduser("~/.local/share/revkit-pyghidra/bin/python")))
    args = ap.parse_args(argv)
    if not os.path.exists(args.binary):
        print(f"skip: no {args.binary} (build the corpus)", file=sys.stderr)
        return SKIP
    if not os.path.exists(args.pyghidra):
        print(f"skip: no PyGhidra venv at {args.pyghidra} (scripts/setup-pyghidra.sh)", file=sys.stderr)
        return SKIP
    work = Path(args.work or tempfile.mkdtemp(prefix="rk-ghidra-roundtrip-"))
    work.mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()
    c = Checks()
    try:
        pyghidra(args, "setup", "--work", str(work), "--binary", args.binary)
        edits = json.loads((work / "ghidra-edits.json").read_text())
        doc = json.loads((work / "ghidra.json").read_text())
        actor = importer.ghidra_actor(doc)
        with Daemon(None, "--backend", "image", "--project-dir", str(work / "rk"), startup_timeout=60) as d:
            print("== import", file=sys.stderr)
            rep = import_json(d.grpc_target, work / "ghidra.json", work, "--binary", args.binary)
            print(f"  appended {rep['appended']}", file=sys.stderr)
            want = {"name": 4, "signature": 1, "local_type": 1, "comment": 5, "data_type": 2, "flow_override": 1,
                    "bookmark": 1, "equate": 1, "function": 1, "function_removed": 1}
            c.check(all(rep["appended"].get(k, 0) >= n for k, n in want.items()), f"first import appended {want}")
            c.check(len(rep["revisions"]) <= 3, f"the import is a few revisions ({rep['revisions']})")
            with Client(d.grpc_target, actor="user:alice") as alice, \
                    Client(d.grpc_target, actor="agent:claude@test", session="rt") as claude:
                prog = alice.program(rep["program_id"])
                check_import(c, prog, edits, actor)
                print("== import again, and the rebased program", file=sys.stderr)
                again = import_json(d.grpc_target, work / "ghidra.json", work)
                c.check(not again["appended"] and not again["revisions"], f"re-import appends nothing ({again['appended']})")
                rebased = import_json(d.grpc_target, work / "ghidra-rebased.json", work)
                c.check(rebased["image_base_delta"] == -0x100000, "rebased program's delta")
                c.check(not rebased["appended"], f"rebased re-import appends nothing ({rebased['appended']})")
                print("== revkit edits, export", file=sys.stderr)
                mine = revkit_edits(prog, alice, claude, edits)
                exported = exporter.export_program(alice, prog.id)
                (work / "revkit.json").write_text(json.dumps(exported, indent=1))
                c.check(all(ch["provenance"].startswith(("user:", "agent:claude")) for ch in exported["changes"]),
                        "only user and agent changes exported, none that came from Ghidra")
            pyghidra(args, "apply", "--work", str(work), "--changes", str(work / "revkit.json"))
            check_export(c, json.loads((work / "ghidra-after.json").read_text()),
                         json.loads((work / "apply-report.json").read_text()), mine)
            print("== import Ghidra's export after the apply", file=sys.stderr)
            echo = import_json(d.grpc_target, work / "ghidra2.json", work)
            c.check(not echo["appended"], f"revkit's edits don't come back from Ghidra ({echo['appended']})")
    finally:
        if not args.keep and not args.work:
            shutil.rmtree(work, ignore_errors=True)
    print(f"roundtrip: {c.passed} checks passed, {len(c.failed)} failed, {time.monotonic() - t0:.1f} s"
          + (f" (kept {work})" if args.keep or args.work else ""), file=sys.stderr)
    return 1 if c.failed else 0


if __name__ == "__main__":
    sys.exit(main())
