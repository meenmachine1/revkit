"""revkit-ghidra-export: revkit's assertions for a Ghidra program.

Reads a program's live assertions through the API and writes the effective
ones by the selected provenance kinds (default: ``user`` and ``agent``) as
revkit-ghidra-interop JSON (docs/ghidra-interop.md) for
``tools/ghidra-interop/ghidra_apply.py``, which applies them to a Ghidra
program in one transaction and records each change's provenance there.

    revkit-ghidra-export --program-id default/prog -o prog.revkit.json
    revkit-ghidra-export --binary prog --ghidra-project ~/work/proj.gpr --program /prog

Why only user and agent by default: ``import:dwarf``/``import:pdb`` facts are
what Ghidra's own DWARF and PDB analyzers produce; ``import:ghidra`` facts
came from Ghidra in the first place; and loader names and analysis are what
Ghidra derives itself. Only people's and agents' edits are new to Ghidra,
and of those not ``agent:ghidra-ai``'s, which came from Ghidra.
``--provenance user,agent,import`` widens it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from google.protobuf.json_format import MessageToDict

from revkit import Client, format_provenance
from revkit.client import _COMMENT_KINDS, _FLOW_OVERRIDES, _PROVENANCE_KINDS
from revkit.ghidra.importer import FORMAT, TOOLS_DIR, VERSION
from revkit.v1 import assertion_pb2, common_pb2

COMMENTS = {v: k for k, v in _COMMENT_KINDS.items()}
FLOWS = {v: k for k, v in _FLOW_OVERRIDES.items()}
DEFAULT_PROVENANCE = ("user", "agent")
GHIDRA_ORIGIN = {(common_pb2.PROVENANCE_KIND_IMPORT, "ghidra"), (common_pb2.PROVENANCE_KIND_AGENT, "ghidra-ai")}


def change_of(a: assertion_pb2.Assertion) -> dict | None:
    """One assertion as an export change (addresses in revkit's image)."""
    b = a.body
    which = b.WhichOneof("kind")
    p = a.provenance
    ch: dict = {"seq": a.seq, "revision": a.revision, "provenance": format_provenance(p)}
    if p.session:
        ch["session"] = p.session
    if p.reason:
        ch["reason"] = p.reason

    def target(t: assertion_pb2.Target):
        if t.WhichOneof("kind") == "local":
            ch["function"] = hex(t.local.function.offset)
            ch["storage_key"] = t.local.storage_key
            return "_local"
        ch["address"] = hex(t.address.offset)
        return ""

    if which == "rename":
        ch["op"] = "rename" + target(b.rename.target)
        ch["name"] = b.rename.name
    elif which == "retype":
        ch["op"] = "retype" + target(b.retype.target)
        if b.retype.type.WhichOneof("kind") == "type_hash":
            ch["type_hash"] = b.retype.type.type_hash
        else:
            ch["c"] = b.retype.type.c_declaration
    elif which == "comment":
        ch.update(op="comment", address=hex(b.comment.address.offset), kind=COMMENTS.get(b.comment.kind, "eol"),
                  text=b.comment.text)
    elif which == "function_bounds":
        fb = b.function_bounds
        ch.update(op="function", entry=hex(fb.entry.offset), remove=fb.remove,
                  body=[[hex(r.first.offset), hex(r.last.offset)] for r in fb.body])
    elif which == "flow_override":
        ch.update(op="flow_override", address=hex(b.flow_override.address.offset),
                  kind=FLOWS.get(b.flow_override.kind, "none"))
    elif which == "note":
        ch.update(op="note", address=hex(b.note.address.offset), tag=b.note.tag, text=b.note.text)
    elif which == "define_type":
        ch.update(op="define_type", type_hash=a.key.sub)
    elif a.key.kind == common_pb2.FACT_KIND_TYPE_DEF:
        ch.update(op="define_type", type_hash=a.key.sub)  # stored without a body (debug-info imports)
    else:
        return None
    return ch


def export_program(client: Client, program_id: str, kinds=DEFAULT_PROVENANCE, include_ghidra: bool = False) -> dict:
    """The effective assertions by ``kinds``, except those revkit-ghidra-import
    made (``import:ghidra``, ``agent:ghidra-ai``) unless ``include_ghidra``."""
    prog = client.program(program_id)
    summary = prog.summary()
    wanted = {_PROVENANCE_KINDS[k] for k in kinds}
    live = prog.assertions()
    revision = max((a.revision for a in live), default=0)
    changes, hashes = [], set()
    for a in live:
        if a.op != assertion_pb2.ASSERTION_OP_ASSERT or a.status != assertion_pb2.ASSERTION_STATUS_EFFECTIVE:
            continue
        if a.provenance.kind not in wanted:
            continue
        if (a.provenance.kind, a.provenance.id) in GHIDRA_ORIGIN and not include_ghidra:
            continue  # it came from Ghidra (revkit-ghidra-import)
        ch = change_of(a)
        if ch is None:
            continue
        if "type_hash" in ch:
            hashes.add(ch["type_hash"])
        changes.append(ch)
    types = {}
    if hashes:
        resp = prog.types(*sorted(hashes), dependencies=True)
        for t in resp.types:
            d = MessageToDict(t, preserving_proto_field_name=True)
            d.pop("origin", None)
            types[t.hash] = d
    info = summary.info
    return {
        "format": FORMAT,
        "version": VERSION,
        "direction": "revkit-to-ghidra",
        "revkit": {"program_id": program_id, "server": client.server_info().server_version,
                   "revision": revision, "provenance_kinds": list(kinds)},
        "program": {"name": info.name, "sha256": info.sha256, "language_id": info.language_id,
                    "image_base": hex(summary.image_base.offset), "pointer_size": summary.language.pointer_size},
        "types": types,
        "changes": sorted(changes, key=lambda c: c["seq"]),
    }


def find_program_id(client: Client, sha: str) -> str:
    for proj in client.projects():
        for p in client.programs(proj.project_id):
            if p.sha256.lower() == sha.lower():
                return p.program_id
    raise SystemExit(f"no program with sha256 {sha} in the daemon")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="revkit-ghidra-export", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--daemon", default="127.0.0.1:50051", help="rk-daemon gRPC address")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--program-id", help="revkit program id")
    g.add_argument("--binary", help="find the program by this file's sha256")
    g.add_argument("--sha256", help="find the program by sha256")
    ap.add_argument("--provenance", default=",".join(DEFAULT_PROVENANCE),
                    help="provenance kinds to export (default %(default)s; also import, migration, analysis)")
    ap.add_argument("-o", "--out", help="output JSON (default stdout, or a temp file with --ghidra-project)")
    a = ap.add_argument_group("applying to Ghidra (runs ghidra_apply.py)")
    a.add_argument("--ghidra-project", help="Ghidra project (.gpr) to apply the changes to")
    a.add_argument("--program", help="program path in the Ghidra project")
    a.add_argument("--strict", action="store_true", help="roll back if any change fails")
    a.add_argument("--pyghidra", help="PyGhidra venv python (default $REVKIT_PYGHIDRA or ~/.local/share/revkit-pyghidra)")
    a.add_argument("--tools", help="tools/ghidra-interop directory (default: beside this SDK checkout)")
    args = ap.parse_args(argv)

    kinds = [k.strip() for k in args.provenance.split(",") if k.strip()]
    for k in kinds:
        if k not in _PROVENANCE_KINDS:
            ap.error(f"unknown provenance kind {k!r}")
    with Client(args.daemon, timeout=600) as client:
        pid = args.program_id
        if not pid:
            sha = args.sha256
            if args.binary:
                sha = hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()
            pid = find_program_id(client, sha)
        doc = export_program(client, pid, kinds)
    text = json.dumps(doc, indent=1) + "\n"
    out = args.out
    if args.ghidra_project and not out:
        out = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"revkit-export-{os.getpid()}.json")
    if out:
        Path(out).write_text(text)
    else:
        sys.stdout.write(text)
    print(f"revkit-ghidra-export: {len(doc['changes'])} changes, {len(doc['types'])} types from {pid}", file=sys.stderr)
    if args.ghidra_project:
        py = args.pyghidra or os.environ.get("REVKIT_PYGHIDRA") or os.path.expanduser("~/.local/share/revkit-pyghidra/bin/python")
        script = Path(args.tools or os.environ.get("REVKIT_GHIDRA_INTEROP") or TOOLS_DIR) / "ghidra_apply.py"
        cmd = [py, str(script), "--project", args.ghidra_project, out]
        if args.program:
            cmd += ["--program", args.program]
        if args.strict:
            cmd.append("--strict")
        return subprocess.run(cmd, stdout=sys.stderr).returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
