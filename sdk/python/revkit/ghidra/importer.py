"""revkit-ghidra-import: a Ghidra program's user work as revkit assertions.

Reads the JSON ``tools/ghidra-interop/ghidra_dump.py`` writes (or runs it on
a Ghidra project), finds the same binary in a running rk-daemon by SHA-256
(importing it if asked), and appends what the user did in Ghidra as
assertions with provenance ``import:ghidra@<ghidra version>``; work Ghidra
attributes to its AI source is appended as ``agent:ghidra-ai``. The format
and the mapping are documented in docs/ghidra-interop.md.

    revkit-ghidra-import prog.ghidra.json --daemon 127.0.0.1:50051
    revkit-ghidra-import --ghidra-project ~/work/proj.gpr --program /prog --binary prog

Re-running is idempotent: an item whose identical assertion (same key and
body, by this importer) is live is skipped; one Ghidra changed since is
appended and the importer's older assertion on that key retracted.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from revkit import Client, InvalidArgument, format_provenance
from revkit.client import _COMMENT_KINDS, _FLOW_OVERRIDES, address, address_range
from revkit.ghidra import typemap
from revkit.v1 import assertion_pb2, common_pb2, decompile_pb2

FORMAT = "revkit-ghidra-interop"
VERSION = 1
# Ghidra SourceTypes, plus UNKNOWN for items Ghidra keeps no source for when
# the export ran without a baseline (ghidra_dump.py --no-baseline).
ALL_SOURCES = ("USER_DEFINED", "IMPORTED", "AI", "ANALYSIS", "DEFAULT", "UNKNOWN")
DEFAULT_SOURCES = ("USER_DEFINED", "IMPORTED", "AI", "UNKNOWN")
AI_ACTOR = "agent:ghidra-ai"
# tools/ghidra-interop in the checkout this SDK is installed from (editable).
TOOLS_DIR = Path(__file__).resolve().parents[4] / "tools" / "ghidra-interop"


def ghidra_actor(doc: dict) -> str:
    return f"import:ghidra@{doc['ghidra']['version']}"


def signed_hex(v: int) -> str:
    return f"-0x{-v:x}" if v < 0 else f"0x{v:x}"


def key_of(body: assertion_pb2.AssertionBody, type_hash: str = "") -> tuple:
    """The fact key a body sets, as (FactKind, address, sub); mirrors the server."""
    which = body.WhichOneof("kind")
    if which in ("rename", "retype"):
        b = getattr(body, which)
        kind = common_pb2.FACT_KIND_NAME if which == "rename" else common_pb2.FACT_KIND_TYPE
        if b.target.WhichOneof("kind") == "local":
            return (kind, b.target.local.function.offset, "local:" + b.target.local.storage_key)
        return (kind, b.target.address.offset, "")
    if which == "comment":
        sub = {v: k for k, v in _COMMENT_KINDS.items()}[body.comment.kind]
        return (common_pb2.FACT_KIND_COMMENT, body.comment.address.offset, sub)
    if which == "function_bounds":
        return (common_pb2.FACT_KIND_FUNCTION_BOUNDS, body.function_bounds.entry.offset, "")
    if which == "flow_override":
        return (common_pb2.FACT_KIND_FLOW_OVERRIDE, body.flow_override.address.offset, "")
    if which == "note":
        return (common_pb2.FACT_KIND_NOTE, body.note.address.offset, body.note.tag)
    if which == "define_type":
        return (common_pb2.FACT_KIND_TYPE_DEF, 0, type_hash)
    raise ValueError(f"no key for {which}")


def stored_key(a: assertion_pb2.Assertion) -> tuple:
    return (a.key.kind, 0 if a.key.kind == common_pb2.FACT_KIND_TYPE_DEF else a.key.address.offset, a.key.sub)


def same_body(a: assertion_pb2.AssertionBody, b: assertion_pb2.AssertionBody) -> bool:
    return a.SerializeToString(deterministic=True) == b.SerializeToString(deterministic=True)


@dataclass
class Item:
    """One planned assertion."""

    body: assertion_pb2.AssertionBody
    what: str  # "name", "comment", ... (report category)
    actor: str
    source: str
    # Type references whose hash the body needs (a retype by hash): the body's
    # type_hash is filled in once the batch's hashes are known.
    tref: Optional[dict] = None
    function: Optional[dict] = None  # a signature retype: the function's JSON
    key: tuple = ()
    tref_index: Optional[int] = None  # TypeBatch index of the type it names
    echo: bool = False  # Ghidra shows what revkit-ghidra-export applied here
    superseded: list = field(default_factory=list)  # this importer's older assertions on the key


@dataclass
class Report:
    planned: Counter = field(default_factory=Counter)
    appended: Counter = field(default_factory=Counter)
    unchanged: Counter = field(default_factory=Counter)  # identical live assertion by this importer
    known: Counter = field(default_factory=Counter)  # revkit already has this value
    from_revkit: Counter = field(default_factory=Counter)  # applied to Ghidra by revkit-ghidra-export
    rejected: Counter = field(default_factory=Counter)  # someone in revkit retracted this importer's identical assertion
    filtered: Counter = field(default_factory=Counter)  # source not selected
    skipped: list = field(default_factory=list)  # (what, address, reason)
    retracted: int = 0
    revisions: list = field(default_factory=list)

    def skip(self, what: str, addr, reason: str):
        self.skipped.append({"what": what, "address": addr if isinstance(addr, str) else hex(addr), "reason": reason})

    def as_dict(self) -> dict:
        return {
            "appended": dict(self.appended), "unchanged": dict(self.unchanged), "already_in_revkit": dict(self.known),
            "from_revkit": dict(self.from_revkit), "rejected_in_revkit": dict(self.rejected),
            "filtered_by_source": dict(self.filtered),
            "skipped": self.skipped, "retracted_superseded": self.retracted, "revisions": self.revisions,
        }


class RevkitState:
    """What revkit already says about the program (one snapshot)."""

    def __init__(self, prog, our_actors: Iterable[str]):
        self.prog = prog
        self.functions = {f.entry.offset: f for f in prog.functions(page_size=5000)}
        self.names = {s.address.offset: s.name for s in prog.symbols()}
        for e, f in self.functions.items():
            self.names[e] = f.name
        self.memory = [(b.range.first.offset, b.range.last.offset) for b in prog.memory_map()]
        log = prog.assertions(include_inactive=True)
        ours = {(p.kind, p.id) for p in (_parse_actor(x) for x in our_actors)}
        mine = lambda a: (a.provenance.kind, a.provenance.id) in ours  # noqa: E731
        retractor = {a.seq: a for a in log if a.op == assertion_pb2.ASSERTION_OP_RETRACT}
        self.effective: dict[tuple, assertion_pb2.Assertion] = {}
        self.live_by_key: dict[tuple, list] = defaultdict(list)
        self.ours: dict[tuple, list] = defaultdict(list)
        # This importer's assertions someone else retracted (or reverted):
        # the same value isn't imported again.
        self.rejected: dict[tuple, list] = defaultdict(list)
        for a in log:
            if a.op != assertion_pb2.ASSERTION_OP_ASSERT:
                continue
            k = stored_key(a)
            if a.status == assertion_pb2.ASSERTION_STATUS_RETRACTED:
                if mine(a) and any(r in retractor and not mine(retractor[r]) for r in a.retracted_by):
                    self.rejected[k].append(a)
                continue
            if a.status not in (assertion_pb2.ASSERTION_STATUS_EFFECTIVE, assertion_pb2.ASSERTION_STATUS_SHADOWED):
                continue
            self.live_by_key[k].append(a)
            if a.status == assertion_pb2.ASSERTION_STATUS_EFFECTIVE:
                self.effective[k] = a
            if mine(a):
                self.ours[k].append(a)
        self._decompiled: dict[int, object] = {}

    def mapped(self, addr: int) -> bool:
        return any(lo <= addr <= hi for lo, hi in self.memory)

    def variables(self, entry: int):
        if entry not in self._decompiled:
            try:
                self._decompiled[entry] = list(self.prog.decompile(entry, text=False).variables)
            except Exception:  # noqa: BLE001 - a function revkit can't decompile has no variables to match
                self._decompiled[entry] = []
        return self._decompiled[entry]

    def other_import(self, key: tuple) -> bool:
        """A live assertion on ``key`` from revkit's own importers (DWARF, PDB)."""
        return any(a.provenance.kind == common_pb2.PROVENANCE_KIND_IMPORT and a.provenance.id != "ghidra"
                   for a in self.live_by_key.get(key, []))


def _parse_actor(actor: str) -> common_pb2.Provenance:
    from revkit.client import provenance

    return provenance(actor)


def match_local(lv: dict, variables, delta: int) -> Optional[str]:
    """The revkit storage key of a Ghidra local (stack or register variable)."""
    keys = [v.storage_key for v in variables if v.kind != decompile_pb2.VARIABLE_KIND_GLOBAL]

    def base(k: str) -> str:
        return k.split("#")[0].split("@")[0]

    if "stack_offset" in lv:
        want = "stack:" + signed_hex(int(lv["stack_offset"]))
        cands = [k for k in keys if base(k) == want]
    elif "register" in lv:
        want = "register:" + lv["register"]
        cands = [k for k in keys if base(k) == want]
        pc = int(lv["first_use"], 16) + delta
        at_pc = [k for k in cands if "@" in k and int(k.split("#")[0].split("@")[1], 16) == pc]
        if at_pc:
            cands = at_pc
    else:
        return None
    return cands[0] if len(cands) == 1 else None


class Planner:
    def __init__(self, doc: dict, state: RevkitState, args, delta: int, define_types: bool):
        self.doc, self.state, self.args, self.delta = doc, state, args, delta
        self.define_types = define_types
        self.sources = set(args.sources)
        self.actor = ghidra_actor(doc)
        self.types = {t["id"]: t for t in doc.get("types", [])}
        p = doc["program"]
        self.default_cc = p.get("default_calling_convention", "")
        self.report = Report()
        self.signatures_imported: set[int] = set()
        self.new_functions: set[int] = set()

    # -- helpers ------------------------------------------------------------

    def a(self, x: str) -> int:
        return int(x, 16) + self.delta

    def take(self, what: str, source: str) -> Optional[str]:
        """The actor for an item of ``source``, or None if it is filtered out."""
        if source not in self.sources:
            self.report.filtered[what] += 1
            return None
        return AI_ACTOR if source == "AI" else self.actor

    def item(self, body, what, actor, source, **kw) -> Item:
        self.report.planned[what] += 1
        return Item(body=body, what=what, actor=actor, source=source, **kw)

    def echo(self, obj: dict, flag: str = "from_revkit") -> bool:
        """Ghidra shows what revkit-ghidra-export applied (see Committer._needed)."""
        return bool(obj.get(flag)) and not self.args.include_from_revkit

    def retype_body(self, target: assertion_pb2.Target, tref: dict) -> assertion_pb2.AssertionBody:
        spec = assertion_pb2.TypeSpec(c_declaration=typemap.c_type(tref, self.types))
        return assertion_pb2.AssertionBody(retype=assertion_pb2.Retype(target=target, type=spec))

    # -- phase 1: functions ---------------------------------------------------

    def functions(self) -> list[Item]:
        out = []
        mode = self.args.functions
        if mode == "none":
            return out
        for f in self.doc.get("functions", []):
            entry = self.a(f["entry"])
            if entry in self.state.functions or not self.state.mapped(entry):
                continue
            # A function revkit's discovery doesn't find. Whether the user made
            # it can only be told with a baseline (exists_source); with the
            # default mode, one the user named or typed counts too.
            sources = {f.get("exists_source", "UNKNOWN")}
            if mode == "user":
                sources |= {f.get("name_source"), f.get("signature_source")}
                sources |= {v.get("source") for v in f.get("params", []) + f.get("locals", [])}
            source = next((s for s in ("USER_DEFINED", "AI", "IMPORTED", "UNKNOWN", "ANALYSIS", "DEFAULT")
                           if s in sources and s in self.sources), None)
            if mode == "all":
                source = source or f.get("exists_source", "ANALYSIS")
            if source is None:
                self.report.filtered["function"] += 1
                continue
            body = assertion_pb2.SetFunctionBounds(entry=address(entry))
            if self.args.function_bodies:
                body.body.extend(address_range(self.a(lo), self.a(hi)) for lo, hi in f["body"])
            actor = AI_ACTOR if source == "AI" else self.actor
            out.append(self.item(assertion_pb2.AssertionBody(function_bounds=body), "function", actor, source,
                                 echo=self.echo(f)))
        # Functions the user deleted in Ghidra (known only with a baseline).
        for r in self.doc.get("removed_functions", []):
            entry = self.a(r["entry"])
            if entry not in self.state.functions:
                continue
            actor = self.take("function_removed", r.get("source", "USER_DEFINED"))
            if actor is None:
                continue
            body = assertion_pb2.SetFunctionBounds(entry=address(entry), remove=True)
            out.append(self.item(assertion_pb2.AssertionBody(function_bounds=body), "function_removed", actor, r.get("source")))
        return out

    # -- phase 2: everything else -------------------------------------------------

    def rest(self) -> list[Item]:
        out: list[Item] = []
        out += self.names()
        out += self.signatures()
        out += self.variables()
        out += self.comments()
        out += self.data()
        out += self.flow_overrides()
        out += self.notes()
        return out

    def names(self) -> list[Item]:
        out = []
        for s in self.doc.get("symbols", []):
            actor = self.take("name", s["source"])
            if actor is None:
                continue
            addr = self.a(s["address"])
            if not s.get("primary", True):
                self.report.skip("name", addr, f"{s['name']}: not the primary label (revkit keeps one name per address)")
                continue
            if not self.state.mapped(addr):
                self.report.skip("name", addr, f"{s['name']}: not in revkit's memory map")
                continue
            if re.search(r"\s", s["name"]):
                self.report.skip("name", addr, f"{s['name']!r}: names can't contain whitespace")
                continue
            key = (common_pb2.FACT_KIND_NAME, addr, "")
            body = assertion_pb2.AssertionBody(rename=assertion_pb2.Rename(
                target=assertion_pb2.Target(address=address(addr)), name=s["name"]))
            if not any(same_body(a.body, body) for a in self.state.ours.get(key, [])):
                if self.state.names.get(addr) == s["name"] or (s["source"] == "IMPORTED" and self.state.other_import(key)):
                    self.report.known["name"] += 1
                    continue
            out.append(self.item(body, "name", actor, s["source"], echo=self.echo(s)))
        return out

    def signatures(self) -> list[Item]:
        out = []
        for f in self.doc.get("functions", []):
            if f.get("thunk_of"):
                continue
            actor = self.take("signature", f.get("signature_source", "DEFAULT"))
            if actor is None:
                continue
            entry = self.a(f["entry"])
            key = (common_pb2.FACT_KIND_TYPE, entry, "")
            if f["signature_source"] == "IMPORTED" and self.state.other_import(key):
                self.report.known["signature"] += 1
                continue
            params = [(p["name"], p["type"]) for p in f.get("params", []) if not p.get("auto")]
            target = assertion_pb2.Target(address=address(entry))
            if self.define_types:
                body = assertion_pb2.AssertionBody(retype=assertion_pb2.Retype(target=target, type=assertion_pb2.TypeSpec()))
                it = self.item(body, "signature", actor, f["signature_source"], function=f,
                               echo=self.echo(f, "signature_from_revkit"))
            else:
                cc = typemap.convention(f.get("calling_convention", ""), self.default_cc)
                decl = typemap.c_prototype(f["name"], f["return"], params, f.get("varargs", False), self.types,
                                           "" if cc in ("", "other") else cc)
                body = assertion_pb2.AssertionBody(retype=assertion_pb2.Retype(
                    target=target, type=assertion_pb2.TypeSpec(c_declaration=decl)))
                it = self.item(body, "signature", actor, f["signature_source"], echo=self.echo(f, "signature_from_revkit"))
            self.signatures_imported.add(entry)
            out.append(it)
        return out

    def variables(self) -> list[Item]:
        """Parameters (unless the signature was imported, which names them) and locals."""
        out = []
        for f in self.doc.get("functions", []):
            entry = self.a(f["entry"])
            if f.get("thunk_of") or not self.state.mapped(entry):
                continue  # a thunk's variables are its target's
            todo = []
            # Parameters belong to the signature: one imported (or applied
            # from revkit) names them already.
            if entry not in self.signatures_imported and not f.get("signature_from_revkit"):
                todo += [("param", p) for p in f.get("params", []) if not p.get("auto")]
            todo += [("local", v) for v in f.get("locals", [])]
            for kind, v in todo:
                actor = self.take(kind, v.get("source", "DEFAULT"))
                if actor is None:
                    continue
                if entry not in self.state.functions and entry not in self.new_functions:
                    self.report.skip(kind, entry, f"{v['name']}: revkit has no function at the entry")
                    continue
                variables = self.state.variables(entry)
                if kind == "param":
                    sk = f"param:{v['ordinal']}"
                    if not any(x.storage_key == sk for x in variables):
                        self.report.skip(kind, entry, f"{v['name']}: revkit's decompilation has no {sk}")
                        continue
                else:
                    sk = match_local(v, variables, self.delta)
                    if sk is None:
                        self.report.skip(kind, entry, f"{v['name']} ({v.get('storage')}): no unique matching revkit variable")
                        continue
                current = next((x for x in variables if x.storage_key == sk), None)
                target = assertion_pb2.Target(local=assertion_pb2.LocalVariableRef(function=address(entry), storage_key=sk))
                body = assertion_pb2.AssertionBody(rename=assertion_pb2.Rename(target=target, name=v["name"]))
                mine = any(same_body(a.body, body) for a in self.state.ours.get(key_of(body), []))
                if mine or current is None or current.name != v["name"]:
                    out.append(self.item(body, kind, actor, v["source"], echo=self.echo(v)))
                else:
                    self.report.known[kind] += 1
                if not typemap.is_undefined(v.get("type")):
                    if self.define_types:
                        body = assertion_pb2.AssertionBody(retype=assertion_pb2.Retype(target=target, type=assertion_pb2.TypeSpec()))
                        out.append(self.item(body, kind + "_type", actor, v["source"], tref=v["type"], echo=self.echo(v)))
                    else:
                        out.append(self.item(self.retype_body(target, v["type"]), kind + "_type", actor, v["source"],
                                             echo=self.echo(v)))
        return out

    def comments(self) -> list[Item]:
        out = []
        for c in self.doc.get("comments", []):
            actor = self.take("comment", c.get("source", "UNKNOWN"))
            if actor is None:
                continue
            addr = self.a(c["address"])
            if not self.state.mapped(addr):
                self.report.skip("comment", addr, "not in revkit's memory map")
                continue
            body = assertion_pb2.AssertionBody(comment=assertion_pb2.Comment(
                address=address(addr), kind=_COMMENT_KINDS[c["kind"]], text=c["text"]))
            out.append(self.item(body, "comment", actor, c.get("source", "UNKNOWN"), echo=self.echo(c)))
        return out

    def data(self) -> list[Item]:
        out = []
        for d in self.doc.get("data", []):
            actor = self.take("data_type", d.get("source", "UNKNOWN"))
            if actor is None:
                continue
            addr = self.a(d["address"])
            if typemap.is_undefined(d["type"]):
                continue
            if not self.state.mapped(addr):
                self.report.skip("data_type", addr, "not in revkit's memory map")
                continue
            target = assertion_pb2.Target(address=address(addr))
            if self.define_types:
                body = assertion_pb2.AssertionBody(retype=assertion_pb2.Retype(target=target, type=assertion_pb2.TypeSpec()))
                out.append(self.item(body, "data_type", actor, d.get("source", "UNKNOWN"), tref=d["type"], echo=self.echo(d)))
            else:
                out.append(self.item(self.retype_body(target, d["type"]), "data_type", actor, d.get("source", "UNKNOWN"),
                                     echo=self.echo(d)))
        return out

    def flow_overrides(self) -> list[Item]:
        out = []
        for f in self.doc.get("flow_overrides", []):
            actor = self.take("flow_override", f.get("source", "UNKNOWN"))
            if actor is None:
                continue
            if f["kind"] not in _FLOW_OVERRIDES:
                self.report.skip("flow_override", f["address"], f"unknown kind {f['kind']}")
                continue
            body = assertion_pb2.AssertionBody(flow_override=assertion_pb2.FlowOverride(
                address=address(self.a(f["address"])), kind=_FLOW_OVERRIDES[f["kind"]]))
            out.append(self.item(body, "flow_override", actor, f.get("source", "UNKNOWN"), echo=self.echo(f)))
        return out

    def notes(self) -> list[Item]:
        """Bookmarks, equates and no-return flags, which revkit has no assertion for, as notes."""
        out = []

        def note(addr: int, tag: str, text: str, what: str, actor: str, source: str):
            if not self.state.mapped(addr):
                self.report.skip(what, addr, "not in revkit's memory map")
                return
            body = assertion_pb2.AssertionBody(note=assertion_pb2.Note(address=address(addr), tag=tag, text=text))
            out.append(self.item(body, what, actor, source))

        for b in self.doc.get("bookmarks", []):
            actor = self.take("bookmark", b.get("source", "UNKNOWN"))
            if actor is not None:
                tag = "ghidra:bookmark:" + b["type"] + (":" + b["category"] if b["category"] else "")
                note(self.a(b["address"]), tag, b["comment"], "bookmark", actor, b.get("source", "UNKNOWN"))
        for e in self.doc.get("equates", []):
            actor = self.take("equate", e.get("source", "UNKNOWN"))
            if actor is None:
                continue
            for r in e["references"]:
                note(self.a(r["address"]), f"ghidra:equate:{r['operand']}", f"{e['name']}={e['value']:#x}", "equate",
                     actor, e.get("source", "UNKNOWN"))
        for f in self.doc.get("functions", []):
            if not f.get("no_return"):
                continue
            actor = self.take("no_return", f.get("no_return_source", "UNKNOWN"))
            if actor is None:
                continue
            entry = self.a(f["entry"])
            if entry in self.state.functions and self.state.functions[entry].no_return:
                self.report.known["no_return"] += 1
                continue
            note(entry, "ghidra:noreturn", "true", "no_return", actor, f.get("no_return_source", "UNKNOWN"))
        return out

    def user_types(self) -> list[dict]:
        """Named types the user defined (by source), whether or not anything uses them."""
        out = []
        for t in self.doc.get("types", []):
            src = t.get("source", "UNKNOWN")
            if self.echo(t):
                continue  # ghidra_apply.py's /revkit copy of a revkit type
            if src == "IMPORTED":  # archive types: only when something imported uses them
                continue
            if self.take("type", src) is not None:
                out.append(t)
        return out


# ---------------------------------------------------------------------------
# Committing
# ---------------------------------------------------------------------------


class Committer:
    def __init__(self, client: Client, prog, state: RevkitState, report: Report, dry_run: bool,
                 reimport_rejected: bool = False):
        self.client, self.prog, self.state, self.report, self.dry_run = client, prog, state, report, dry_run
        self.reimport_rejected = reimport_rejected

    def commit(self, items: list[Item], *, types: Optional[typemap.TypeBatch] = None,
               type_actor: str = "", user_types: Iterable[dict] = ()) -> None:
        """Appends ``items`` (and the types they need) idempotently, one request per actor."""
        for it in items:
            it.key = key_of(it.body)
        items = [it for it in items if not self._echo(it)]
        if types is not None:
            for t in user_types:
                types.node_for({"ref": t["id"]})
            for it in items:
                if it.tref is not None:
                    it.tref_index = types.node_for(it.tref)
                if it.function is not None:
                    f = it.function
                    params = [(p["name"], p["type"]) for p in f.get("params", []) if not p.get("auto")]
                    it.tref_index = types.function_node(f["return"], params, f.get("varargs", False),
                                                        f.get("calling_convention", ""))
            hashes = self._type_hashes(types, type_actor) if types.nodes else []
        by_actor: dict[str, list[Item]] = defaultdict(list)
        for it in items:
            if it.tref_index is not None:
                it.body.retype.type.type_hash = hashes[it.tref_index]
            it.key = key_of(it.body)
            by_actor[it.actor].append(it)
        # Type definitions go first, with the import actor's batch: the
        # others' retypes may name them.
        actors = list(by_actor)
        if types is not None and types.nodes:
            actors = [type_actor] + [a for a in actors if a != type_actor]
        for actor in actors:
            batch = [it for it in by_actor.get(actor, []) if self._needed(it)]
            type_bodies: list = []
            if types is not None and actor == type_actor and types.nodes:
                type_bodies = self._type_bodies(types, hashes, type_actor)
            self._append(actor, type_bodies, batch)

    # -- types --------------------------------------------------------------

    def _type_hashes(self, types: typemap.TypeBatch, actor: str) -> list[str]:
        resp = self.prog.append(*types.bodies(0), actor=actor, validate_only=True)
        return [a.key.sub for a in resp.assertions]

    def _type_bodies(self, types: typemap.TypeBatch, hashes: list[str], actor: str) -> list:
        """define_type bodies for the types this importer hasn't defined yet;
        references to the ones it has become hashes."""
        # A type is content-addressed: defined by anyone, it is defined.
        keep = [i for i, h in enumerate(hashes) if not self.state.live_by_key.get((common_pb2.FACT_KIND_TYPE_DEF, 0, h))]
        self.report.unchanged["type"] += len(hashes) - len(keep)
        pos = {old: new for new, old in enumerate(keep)}
        all_bodies = types.bodies(0)
        bodies = []
        for i in keep:
            body = all_bodies[i]
            node = body.define_type.type
            refs = ([node.target] if node.HasField("target") else []) + [f.type for f in node.fields] + [p.type for p in node.params]
            for r in refs:
                if r.WhichOneof("kind") == "assertion_index":
                    j = r.assertion_index
                    if j in pos:
                        r.assertion_index = pos[j]
                    else:
                        r.hash = hashes[j]
            bodies.append((body, hashes[i]))
        return bodies

    # -- idempotency ---------------------------------------------------------------

    def _echo(self, it: Item) -> bool:
        """What revkit-ghidra-export put into Ghidra comes back only if revkit
        lost it (a fresh project): while another author's assertion holds the
        key, it is that author's edit, not Ghidra's."""
        ours = self.state.ours.get(it.key, [])
        if it.echo and any(a not in ours for a in self.state.live_by_key.get(it.key, [])):
            self.report.from_revkit[it.what] += 1
            return True
        return False

    def _needed(self, it: Item) -> bool:
        ours = self.state.ours.get(it.key, [])
        if any(same_body(a.body, it.body) for a in ours):
            self.report.unchanged[it.what] += 1
            return False
        if not self.reimport_rejected and any(same_body(a.body, it.body) for a in self.state.rejected.get(it.key, [])):
            self.report.rejected[it.what] += 1
            return False

        eff = self.state.effective.get(it.key)
        if eff is not None and same_body(eff.body, it.body):
            self.report.known[it.what] += 1
            return False
        it.superseded = [a.seq for a in ours]
        return True

    def _append(self, actor: str, type_bodies: list, items: list[Item]) -> None:
        """One atomic request; an item the server rejects is reported and dropped."""
        items = list(items)
        while type_bodies or items:
            bodies = [b for b, _ in type_bodies] + [it.body for it in items]
            if self.dry_run:
                break
            try:
                resp = self.prog.append(*bodies, actor=actor, reason="revkit-ghidra-import")
            except InvalidArgument as e:
                m = re.match(r"assertions\[(\d+)\]: (.*)", e.message)
                if not m or int(m.group(1)) < len(type_bodies):
                    raise
                bad = items.pop(int(m.group(1)) - len(type_bodies))
                self.report.skip(bad.what, bad.key[1], m.group(2))
                continue
            self.report.revisions.append(resp.snapshot.revision)
            if type_bodies:
                self.report.appended["type"] += len(type_bodies)
            for it in items:
                self.report.appended[it.what] += 1
            stale = [s for it in items for s in it.superseded]
            if stale:
                self.prog.retract(*stale, actor=actor, reason="revkit-ghidra-import: superseded by a newer import")
                self.report.retracted += len(stale)
            break
        if self.dry_run:
            self.report.appended["type"] += len(type_bodies)
            for it in items:
                self.report.appended[it.what] += 1


# ---------------------------------------------------------------------------
# Program lookup
# ---------------------------------------------------------------------------


def find_program(client: Client, doc: dict, args):
    sha = doc["program"]["sha256"].lower()
    if args.program_id:
        prog = client.program(args.program_id)
        info = prog.summary().info
    else:
        info = None
        for proj in client.projects():
            for p in client.programs(proj.project_id):
                if p.sha256.lower() == sha:
                    info = p
                    break
            if info:
                break
        if info is None:
            binary = args.binary or doc["program"].get("executable_path")
            if not binary or not os.path.exists(binary):
                raise SystemExit(f"no program with sha256 {sha} in the daemon; pass --binary to import it")
            resp = client.import_program(args.project, path=os.path.abspath(binary))
            info = resp.program
            print(f"imported {binary} as {info.program_id}", file=sys.stderr)
        prog = client.program(info.program_id)
    if info.sha256.lower() != sha and not args.force:
        raise SystemExit(f"sha256 mismatch: Ghidra's program is {sha}, revkit's {info.program_id} is {info.sha256} "
                         "(--force to import anyway)")
    return prog, info


def run_dump(args) -> dict:
    """Runs ghidra_dump.py in the PyGhidra venv and returns its document."""
    py = args.pyghidra or os.environ.get("REVKIT_PYGHIDRA") or os.path.expanduser("~/.local/share/revkit-pyghidra/bin/python")
    script = Path(args.tools or os.environ.get("REVKIT_GHIDRA_INTEROP") or TOOLS_DIR) / "ghidra_dump.py"
    with tempfile.TemporaryDirectory(prefix="rk-ghidra-dump-") as tmp:
        out = os.path.join(tmp, "dump.json")
        cmd = [py, str(script), "--project", args.ghidra_project, "-o", out]
        if args.program:
            cmd += ["--program", args.program]
        if args.no_baseline:
            cmd.append("--no-baseline")
        subprocess.run(cmd, check=True, stdout=sys.stderr)  # the JVM logs to stdout
        with open(out) as f:
            return json.load(f)


def load_doc(path: str) -> dict:
    with open(path) as f:
        doc = json.load(f)
    check_doc(doc, "ghidra-to-revkit")
    return doc


def check_doc(doc: dict, direction: str) -> None:
    if doc.get("format") != FORMAT or doc.get("direction") != direction:
        raise SystemExit(f"not a {FORMAT} {direction} document")
    if int(doc.get("version", 0)) > VERSION:
        raise SystemExit(f"document version {doc['version']} is newer than this tool's ({VERSION})")


def import_doc(client: Client, doc: dict, args) -> Report:
    check_doc(doc, "ghidra-to-revkit")
    define_types = "define-types" in client.server_info().features and not args.c_types
    prog, info = find_program(client, doc, args)
    summary = prog.summary()
    delta = summary.image_base.offset - int(doc["program"]["image_base"], 16)
    actor = ghidra_actor(doc)
    state = RevkitState(prog, [actor, AI_ACTOR])
    planner = Planner(doc, state, args, delta, define_types)
    committer = Committer(client, prog, state, planner.report, args.dry_run, getattr(args, "reimport_rejected", False))

    funcs = planner.functions()
    committer.commit(funcs)
    planner.new_functions = {it.body.function_bounds.entry.offset for it in funcs}
    if funcs and not args.dry_run:
        state = RevkitState(prog, [actor, AI_ACTOR])  # discovery ran again; new functions have variables
        planner.state = committer.state = state

    items = planner.rest()
    types = typemap.TypeBatch(planner.types, planner.default_cc, summary.language.pointer_size or 8) if define_types else None
    committer.commit(items, types=types, type_actor=actor, user_types=planner.user_types() if define_types else ())

    if args.prune and not args.dry_run:
        prune(prog, state, planner, funcs + items, [actor, AI_ACTOR])
    report = planner.report
    report.program_id = info.program_id
    report.delta = delta
    return report


def prune(prog, state: RevkitState, planner: Planner, items: list[Item], actors: list[str]) -> None:
    """Retracts this importer's live assertions on keys this run didn't produce
    (what the user removed in Ghidra since the last import)."""
    keep = {it.key for it in items}
    stale = []
    for k, lst in state.ours.items():
        if k[0] == common_pb2.FACT_KIND_TYPE_DEF or k in keep:
            continue
        stale += [a.seq for a in lst]
    if stale:
        prog.retract(*stale, actor=actors[0], reason="revkit-ghidra-import --prune: gone from Ghidra")
        planner.report.retracted += len(stale)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="revkit-ghidra-import", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("json", nargs="?", help="ghidra_dump.py output (omit with --ghidra-project)")
    ap.add_argument("--daemon", default="127.0.0.1:50051", help="rk-daemon gRPC address")
    ap.add_argument("--project", default="default", help="revkit project to import the binary into, if needed")
    ap.add_argument("--program-id", help="revkit program (default: the one whose sha256 matches)")
    ap.add_argument("--binary", help="the binary, to import it into revkit when the daemon doesn't have it")
    ap.add_argument("--force", action="store_true", help="import even if the sha256 differs")
    ap.add_argument("--sources", default=",".join(DEFAULT_SOURCES),
                    help="Ghidra SourceTypes to import (default %(default)s; add ANALYSIS,DEFAULT for everything)")
    ap.add_argument("--all-sources", action="store_true", help="import every source, ANALYSIS and DEFAULT included")
    ap.add_argument("--functions", choices=["user", "all", "none"], default="user",
                    help="functions revkit lacks: those the user made or named (default), all of Ghidra's, or none")
    ap.add_argument("--function-bodies", action="store_true", help="pin Ghidra's bodies, not just the entries")
    ap.add_argument("--c-types", action="store_true", help="retype with C text even if the daemon can define types")
    ap.add_argument("--include-from-revkit", action="store_true",
                    help="also import items revkit-ghidra-export applied to Ghidra (echoes of revkit's own edits)")
    ap.add_argument("--reimport-rejected", action="store_true",
                    help="import items even if someone in revkit retracted this importer's identical assertion")
    ap.add_argument("--prune", action="store_true",
                    help="retract this importer's assertions that are no longer in Ghidra")
    ap.add_argument("--session", default="", help="provenance session (default: a fresh id)")
    ap.add_argument("--dry-run", action="store_true", help="report what would be appended")
    g = ap.add_argument_group("running Ghidra (instead of a JSON file)")
    g.add_argument("--ghidra-project", help="Ghidra project (.gpr) to export with ghidra_dump.py")
    g.add_argument("--program", help="program path in the Ghidra project")
    g.add_argument("--no-baseline", action="store_true", help="passed to ghidra_dump.py")
    g.add_argument("--pyghidra", help="PyGhidra venv python (default $REVKIT_PYGHIDRA or ~/.local/share/revkit-pyghidra)")
    g.add_argument("--tools", help="tools/ghidra-interop directory (default: beside this SDK checkout)")
    ap.add_argument("--report", help="write the report as JSON here")
    args = ap.parse_args(argv)
    args.sources = list(ALL_SOURCES) if args.all_sources else [s.strip().upper() for s in args.sources.split(",") if s.strip()]
    if not args.json and not args.ghidra_project:
        ap.error("give a JSON file or --ghidra-project")

    doc = run_dump(args) if args.ghidra_project else load_doc(args.json)
    session = args.session or f"ghidra-import-{uuid.uuid4().hex[:12]}"
    with Client(args.daemon, actor=ghidra_actor(doc), session=session, timeout=600) as client:
        report = import_doc(client, doc, args)
    out = {"program_id": report.program_id, "provenance": ghidra_actor(doc), "session": session,
           "image_base_delta": report.delta, **report.as_dict()}
    text = json.dumps(out, indent=1)
    if args.report:
        Path(args.report).write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
