"""Unit tests of the Ghidra <-> revkit JSON mapping (revkit.ghidra), plus a
fast import of a hand-written export into rk-daemon when one is available
(RK_DAEMON or a build tree). No Ghidra needed: roundtrip_test.py covers that.

    PYTHONPATH=sdk/python python -m pytest tools/ghidra-interop/tests
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path

import pytest

from revkit.ghidra import exporter, importer, typemap
from revkit.v1 import assertion_pb2, common_pb2, decompile_pb2, types_pb2

TYPES = {
    "/node": {"id": "/node", "kind": "struct", "name": "node", "size": 16, "fields": [
        {"name": "value", "offset": 0, "type": {"kind": "int", "size": 4, "rank": "int"}},
        {"name": "flags", "offset": 4, "type": {"kind": "uint", "size": 4, "rank": "int"}, "bit_offset": 3, "bit_size": 5},
        {"name": "next", "offset": 8, "type": {"kind": "pointer", "size": 8, "target": {"ref": "/node"}}}]},
    "/color": {"id": "/color", "kind": "enum", "name": "color", "size": 4, "values": [["RED", 0], ["BLUE", 2]]},
    "/handle": {"id": "/handle", "kind": "typedef", "name": "handle", "target": {"kind": "pointer", "size": 8, "target": {"ref": "/node"}}},
    "/cb": {"id": "/cb", "kind": "function", "name": "cb", "return": {"kind": "void"},
            "params": [{"name": "n", "type": {"ref": "/node"}}], "varargs": True, "calling_convention": "__stdcall"},
}


# ---------------------------------------------------------------------------
# typemap
# ---------------------------------------------------------------------------


def test_recursive_struct_is_one_batch():
    b = typemap.TypeBatch(TYPES, default_cc="__stdcall")
    i = b.node_for({"ref": "/node"})
    node = b.nodes[i]
    assert node.kind == types_pb2.TYPE_KIND_STRUCT and node.name == "node" and node.size == 16
    assert [f.name for f in node.fields] == ["value", "flags", "next"]
    ptr = b.nodes[node.fields[2].type.assertion_index]
    assert ptr.kind == types_pb2.TYPE_KIND_POINTER and ptr.target.assertion_index == i
    flags = node.fields[1]
    assert (flags.offset, flags.bit_offset, flags.bit_size) == (4, 3, 5)
    assert b.nodes[node.fields[0].type.assertion_index].rank == types_pb2.INTEGER_RANK_INT
    # The same reference again is the same node; the typedef reuses the pointer.
    assert b.node_for({"ref": "/node"}) == i
    n = len(b.nodes)
    h = b.nodes[b.node_for({"ref": "/handle"})]
    assert h.kind == types_pb2.TYPE_KIND_TYPEDEF and h.target.assertion_index == node.fields[2].type.assertion_index
    assert len(b.nodes) == n + 1
    # Bodies placed later in a request shift their indexes.
    bodies = b.bodies(10)
    assert bodies[i].define_type.type.fields[2].type.assertion_index == node.fields[2].type.assertion_index + 10


def test_named_function_definition_is_a_typedef_of_a_function_type():
    b = typemap.TypeBatch(TYPES, default_cc="__fastcall")
    t = b.nodes[b.node_for({"ref": "/cb"})]
    assert t.kind == types_pb2.TYPE_KIND_TYPEDEF and t.name == "cb"
    fn = b.nodes[t.target.assertion_index]
    assert fn.kind == types_pb2.TYPE_KIND_FUNCTION and fn.varargs and fn.calling_convention == "__stdcall"
    assert not fn.HasField("target")  # void return
    assert typemap.convention("__stdcall", "__stdcall") == "" and typemap.convention("unknown", "x") == ""
    assert typemap.convention("__weird", "__stdcall") == "other"


def test_c_text():
    T = TYPES
    p = lambda t: {"kind": "pointer", "size": 8, "target": t}  # noqa: E731
    char = {"kind": "char", "size": 1}
    assert typemap.c_type(p(char), T, "s") == "char *s"
    assert typemap.c_type(p(p(char)), T, "argv") == "char **argv"
    assert typemap.c_type({"kind": "array", "count": 4, "element": p(char)}, T, "v") == "char *v[4]"
    assert typemap.c_type(p({"kind": "array", "count": 4, "element": char}), T, "v") == "char (*v)[4]"
    assert typemap.c_type({"kind": "uint", "size": 8, "rank": "long"}, T) == "unsigned long"
    assert typemap.c_type({"kind": "int", "size": 1, "rank": "char"}, T) == "signed char"
    assert typemap.c_type({"kind": "uint", "size": 2}, T) == "uint16_t"
    assert typemap.c_type({"kind": "undefined", "size": 4}, T) == "undefined4"
    assert typemap.c_type(p({"ref": "/node"}), T, "n") == "struct node *n"
    assert typemap.c_type({"ref": "/handle"}, T, "h") == "handle h"
    fp = p({"kind": "function", "return": {"kind": "int", "size": 4, "rank": "int"}, "params": [{"name": "x", "type": char}]})
    assert typemap.c_type(fp, T, "f") == "int (*f)(char x)"
    assert typemap.c_prototype("f", {"kind": "void"}, [("fmt", p(char))], True, T) == "void f(char *fmt, ...)"
    assert typemap.c_prototype("g", {"kind": "void"}, [], False, T) == "void g(void)"


# ---------------------------------------------------------------------------
# keys and locals
# ---------------------------------------------------------------------------


def test_keys_mirror_the_server():
    A = lambda o: common_pb2.Address(offset=o)  # noqa: E731
    tgt = assertion_pb2.Target(local=assertion_pb2.LocalVariableRef(function=A(0x10), storage_key="stack:-0x14"))
    cases = [
        (assertion_pb2.AssertionBody(rename=assertion_pb2.Rename(target=assertion_pb2.Target(address=A(5)), name="x")),
         (common_pb2.FACT_KIND_NAME, 5, "")),
        (assertion_pb2.AssertionBody(retype=assertion_pb2.Retype(target=tgt)), (common_pb2.FACT_KIND_TYPE, 0x10, "local:stack:-0x14")),
        (assertion_pb2.AssertionBody(comment=assertion_pb2.Comment(address=A(7), kind=assertion_pb2.COMMENT_KIND_PLATE)),
         (common_pb2.FACT_KIND_COMMENT, 7, "plate")),
        (assertion_pb2.AssertionBody(function_bounds=assertion_pb2.SetFunctionBounds(entry=A(9))), (common_pb2.FACT_KIND_FUNCTION_BOUNDS, 9, "")),
        (assertion_pb2.AssertionBody(flow_override=assertion_pb2.FlowOverride(address=A(3))), (common_pb2.FACT_KIND_FLOW_OVERRIDE, 3, "")),
        (assertion_pb2.AssertionBody(note=assertion_pb2.Note(address=A(4), tag="t")), (common_pb2.FACT_KIND_NOTE, 4, "t")),
    ]
    for body, key in cases:
        assert importer.key_of(body) == key
    assert importer.key_of(assertion_pb2.AssertionBody(define_type=assertion_pb2.DefineType()), "ab") == (common_pb2.FACT_KIND_TYPE_DEF, 0, "ab")


def test_match_local():
    V = lambda k: decompile_pb2.Variable(storage_key=k, kind=decompile_pb2.VARIABLE_KIND_LOCAL)  # noqa: E731
    vs = [V("param:0"), V("stack:-0x14"), V("register:EAX@0x101010"), V("register:EAX@0x101020"), V("stack:-0x20@0x101005")]
    assert importer.match_local({"stack_offset": -0x14}, vs, 0) == "stack:-0x14"
    assert importer.match_local({"stack_offset": -0x20}, vs, 0) == "stack:-0x20@0x101005"
    assert importer.match_local({"register": "EAX", "first_use": "0x1020"}, vs, 0x100000) == "register:EAX@0x101020"
    assert importer.match_local({"register": "EAX", "first_use": "0x1030"}, vs, 0x100000) is None  # ambiguous
    assert importer.match_local({"stack_offset": 8}, vs, 0) is None


# ---------------------------------------------------------------------------
# planning, against a stand-in for revkit's state
# ---------------------------------------------------------------------------


class FakeFunction:
    def __init__(self, name, no_return=False):
        self.name, self.no_return = name, no_return


class FakeState:
    def __init__(self):
        self.functions = {0x101000: FakeFunction("FUN_00101000"), 0x101100: FakeFunction("exit", True)}
        self.names = {0x101000: "FUN_00101000", 0x101100: "exit", 0x104000: "loader_name"}
        self.memory = [(0x100000, 0x10ffff)]
        self.effective, self.live_by_key, self.ours = {}, defaultdict(list), defaultdict(list)

    def mapped(self, a):
        return any(lo <= a <= hi for lo, hi in self.memory)

    def variables(self, entry):
        return [decompile_pb2.Variable(storage_key="param:0", name="param_1")]

    def other_import(self, key):
        return False


def doc(base=0x100000) -> dict:
    h = lambda o: hex(o + base)  # noqa: E731
    return {
        "format": importer.FORMAT, "version": 1, "direction": "ghidra-to-revkit",
        "ghidra": {"version": "12.1.4"},
        "program": {"sha256": "00", "image_base": hex(base), "default_calling_convention": "__stdcall", "pointer_size": 8},
        "types": list(TYPES.values()),
        "symbols": [
            {"address": h(0x1000), "name": "parse", "kind": "function", "source": "USER_DEFINED", "primary": True},
            {"address": h(0x1100), "name": "exit", "kind": "function", "source": "IMPORTED", "primary": True},
            {"address": h(0x2000), "name": "LAB_00102000", "kind": "label", "source": "ANALYSIS", "primary": True},
            {"address": h(0x3000), "name": "ai_name", "kind": "label", "source": "AI", "primary": True},
            {"address": h(0x3008), "name": "has space", "kind": "label", "source": "USER_DEFINED", "primary": True},
            {"address": h(0x3010), "name": "second", "kind": "label", "source": "USER_DEFINED", "primary": False},
            {"address": h(0x3020), "name": "echo", "kind": "label", "source": "USER_DEFINED", "primary": True, "from_revkit": True},
        ],
        "functions": [
            {"entry": h(0x1000), "name": "parse", "name_source": "USER_DEFINED", "signature_source": "USER_DEFINED",
             "calling_convention": "__stdcall", "return": {"kind": "int", "size": 4, "rank": "int"},
             "params": [{"ordinal": 0, "name": "n", "type": {"ref": "/node"}, "source": "USER_DEFINED"}],
             "locals": [], "varargs": False, "no_return": True, "no_return_source": "USER_DEFINED",
             "exists_source": "ANALYSIS", "body": [[h(0x1000), h(0x10ff)]]},
            {"entry": h(0x1200), "name": "FUN_00101200", "name_source": "DEFAULT", "signature_source": "DEFAULT",
             "return": {"kind": "undefined", "size": 1}, "params": [], "locals": [], "no_return": False,
             "exists_source": "USER_DEFINED", "body": [[h(0x1200), h(0x120f)]]},
            {"entry": h(0x1300), "name": "FUN_00101300", "name_source": "DEFAULT", "signature_source": "DEFAULT",
             "return": {"kind": "undefined", "size": 1}, "params": [], "locals": [], "no_return": False,
             "exists_source": "ANALYSIS", "body": [[h(0x1300), h(0x130f)]]},
        ],
        "comments": [{"address": h(0x1004), "kind": "eol", "text": "mine", "source": "USER_DEFINED"},
                     {"address": h(0x1008), "kind": "plate", "text": "analysis", "source": "ANALYSIS"}],
        "data": [{"address": h(0x9000), "length": 16, "type": {"ref": "/node"}, "source": "USER_DEFINED"}],
        "bookmarks": [{"address": h(0x1000), "type": "Note", "category": "rt", "comment": "look", "source": "USER_DEFINED"}],
        "flow_overrides": [{"address": h(0x1010), "kind": "call_return", "source": "USER_DEFINED"}],
        "equates": [{"name": "MAGIC", "value": 23, "source": "USER_DEFINED", "references": [{"address": h(0x1014), "operand": 1}]}],
    }


def planner(d: dict, **kw) -> importer.Planner:
    args = argparse.Namespace(sources=list(importer.DEFAULT_SOURCES), functions="user", function_bodies=False,
                              include_from_revkit=False, **kw)
    return importer.Planner(d, FakeState(), args, 0x100000 - int(d["program"]["image_base"], 16), define_types=True)


@pytest.mark.parametrize("base", [0x100000, 0x400000])
def test_plan(base):
    p = planner(doc(base))
    funcs = p.functions()
    assert [f.body.function_bounds.entry.offset for f in funcs] == [0x101200]  # the user's; not analysis's
    items = p.rest()
    by = defaultdict(list)
    for it in items:
        by[it.what].append(it)
    names = {it.body.rename.target.address.offset: (it.body.rename.name, it.actor, it.echo) for it in by["name"]}
    assert names == {0x101000: ("parse", "import:ghidra@12.1.4", False), 0x103000: ("ai_name", "agent:ghidra-ai", False),
                     0x103020: ("echo", "import:ghidra@12.1.4", True)}  # dropped later if revkit still has its edit
    assert p.report.known["name"] == 1  # exit: revkit has it
    assert p.report.filtered["name"] == 1
    assert {s["reason"].split(":")[-1].strip() for s in p.report.skipped} >= {
        "names can't contain whitespace", "not the primary label (revkit keeps one name per address)"}
    (sig,) = by["signature"]
    assert sig.function["entry"] == hex(0x1000 + base) and sig.body.retype.target.address.offset == 0x101000
    assert not by["param"]  # the signature names its parameters
    assert [c.body.comment.text for c in by["comment"]] == ["mine"]
    (data,) = by["data_type"]
    assert data.tref == {"ref": "/node"} and data.body.retype.target.address.offset == 0x109000
    (fo,) = by["flow_override"]
    assert fo.body.flow_override.kind == assertion_pb2.FLOW_OVERRIDE_KIND_CALL_RETURN
    notes = {(it.body.note.address.offset, it.body.note.tag): it.body.note.text
             for it in by["bookmark"] + by["equate"] + by["no_return"]}
    assert notes == {(0x101000, "ghidra:bookmark:Note:rt"): "look", (0x101014, "ghidra:equate:1"): "MAGIC=0x17",
                     (0x101000, "ghidra:noreturn"): "true"}
    assert {t["id"] for t in p.user_types()} == set(TYPES)


def test_plan_sources_and_c_text():
    d = doc()
    p = planner(d)
    p.sources = set(importer.ALL_SOURCES)
    p.define_types = False
    assert {f.body.function_bounds.entry.offset for f in p.functions()} == {0x101200, 0x101300}
    items = p.rest()
    sig = next(it for it in items if it.what == "signature")
    assert sig.body.retype.type.c_declaration == "int parse(struct node n)"
    data = next(it for it in items if it.what == "data_type")
    assert data.body.retype.type.c_declaration == "struct node"
    assert any(it.body.rename.name == "LAB_00102000" for it in items if it.what == "name")


def test_export_change_of():
    A = lambda o: common_pb2.Address(offset=o)  # noqa: E731
    a = assertion_pb2.Assertion(
        seq=7, revision=3, provenance=common_pb2.Provenance(kind=common_pb2.PROVENANCE_KIND_USER, id="alice", reason="why"),
        op=assertion_pb2.ASSERTION_OP_ASSERT,
        body=assertion_pb2.AssertionBody(retype=assertion_pb2.Retype(
            target=assertion_pb2.Target(local=assertion_pb2.LocalVariableRef(function=A(0x10), storage_key="param:0")),
            type=assertion_pb2.TypeSpec(c_declaration="char *"))))
    assert exporter.change_of(a) == {"seq": 7, "revision": 3, "provenance": "user:alice", "reason": "why",
                                     "op": "retype_local", "function": "0x10", "storage_key": "param:0", "c": "char *"}


# ---------------------------------------------------------------------------
# a real daemon: import, idempotence, a rebased export
# ---------------------------------------------------------------------------

SOURCE = r"""
#include <stdio.h>
struct node { int value; struct node *next; };
struct node head;
__attribute__((noinline)) int walk(struct node *n) { int k = 0; while (n) { k += n->value; n = n->next; } return k; }
int main(int argc, char **argv) { head.value = argc; printf("%d\n", walk(&head)); return 0; }
"""


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("prog")
    (d / "prog.c").write_text(SOURCE)
    subprocess.run([cc, "-O1", "-o", str(d / "prog"), str(d / "prog.c")], check=True)
    return d / "prog"


@pytest.fixture(scope="module")
def daemon():
    from revkit import Daemon

    try:
        with Daemon(None, "--backend", "image", startup_timeout=60) as d:
            yield d
    except FileNotFoundError:
        pytest.skip("no rk-daemon (set RK_DAEMON)")


def test_import_into_daemon(daemon, binary, tmp_path):
    from revkit import Client

    with Client(daemon.grpc_target, actor="user:test") as rk:
        if "define-types" not in rk.server_info().features:
            pytest.skip("daemon without define-types")
        prog = rk.program(rk.import_program("default", path=str(binary)).program.program_id)
        base = prog.summary().image_base.offset
        walk = next(f.entry.offset for f in prog.functions() if f.name == "walk")
        head = next(s.address.offset for s in prog.symbols(name_equals="head"))
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    node = {"id": "/node", "kind": "struct", "name": "node", "size": 16, "fields": [
        {"name": "value", "offset": 0, "type": {"kind": "int", "size": 4, "rank": "int"}},
        {"name": "next", "offset": 8, "type": {"kind": "pointer", "size": 8, "target": {"ref": "/node"}}}],
        "source": "USER_DEFINED"}

    def make(gbase: int) -> dict:
        g = lambda a: hex(a - base + gbase)  # noqa: E731
        return {
            "format": importer.FORMAT, "version": 1, "direction": "ghidra-to-revkit", "ghidra": {"version": "12.1.4"},
            "program": {"sha256": sha, "image_base": hex(gbase), "default_calling_convention": "__stdcall"},
            "types": [node],
            "symbols": [{"address": g(walk), "name": "sum_list", "kind": "function", "source": "USER_DEFINED", "primary": True}],
            "functions": [{"entry": g(walk), "name": "sum_list", "name_source": "USER_DEFINED",
                           "signature_source": "USER_DEFINED", "calling_convention": "__stdcall",
                           "return": {"kind": "int", "size": 4, "rank": "int"},
                           "params": [{"ordinal": 0, "name": "list", "source": "USER_DEFINED",
                                       "type": {"kind": "pointer", "size": 8, "target": {"ref": "/node"}}}],
                           "locals": [], "no_return": False, "exists_source": "ANALYSIS", "body": [[g(walk), g(walk)]]}],
            "comments": [{"address": g(walk), "kind": "plate", "text": "sums a list", "source": "USER_DEFINED"}],
            "data": [{"address": g(head), "length": 16, "type": {"ref": "/node"}, "source": "USER_DEFINED"}],
            "bookmarks": [], "flow_overrides": [], "equates": [],
        }

    def run(d: dict) -> dict:
        path, report = tmp_path / "doc.json", tmp_path / "report.json"
        path.write_text(json.dumps(d))
        assert importer.main([str(path), "--daemon", daemon.grpc_target, "--report", str(report)]) == 0
        return json.loads(report.read_text())

    first = run(make(base))
    assert first["appended"] == {"name": 1, "signature": 1, "comment": 1, "data_type": 1, "type": 4}
    assert len(first["revisions"]) == 1  # one atomic revision
    with Client(daemon.grpc_target) as rk:
        prog = rk.program(first["program_id"])
        d = prog.decompile(walk)
        assert d.name == "sum_list" and "node *list" in d.prototype.c_declaration, d.prototype.c_declaration
        b = prog.blame(prog.key("comment", walk, "plate"))
        assert b.value_text == "sums a list" and b.origin.asserted.provenance.id == "ghidra"
        assert b.origin.asserted.provenance.version == "12.1.4"
    again = run(make(base))
    assert again["appended"] == {} and again["unchanged"]["comment"] == 1 and again["unchanged"]["type"] == 4
    rebased = run(make(base + 0x10000000))
    assert rebased["image_base_delta"] == -0x10000000 and rebased["appended"] == {}
    # A comment changed in Ghidra replaces the importer's older one.
    changed = make(base)
    changed["comments"][0]["text"] = "sums a linked list"
    rep = run(changed)
    assert rep["appended"] == {"comment": 1} and rep["retracted_superseded"] == 1
    # A user retracts the imported name: the next import respects that.
    with Client(daemon.grpc_target, actor="user:bob") as rk:
        prog = rk.program(first["program_id"])
        seq = next(a.seq for a in prog.assertions(actor="import:ghidra") if a.body.WhichOneof("kind") == "rename")
        prog.retract(seq)
    rep = run(changed)
    assert rep["appended"] == {} and rep["rejected_in_revkit"] == {"name": 1}
    # The export side sees only user and agent work: none of this.
    with Client(daemon.grpc_target) as rk:
        assert exporter.export_program(rk, first["program_id"])["changes"] == []
        e = exporter.export_program(rk, first["program_id"], ("user", "agent", "import"), include_ghidra=True)
        assert {c["op"] for c in e["changes"]} >= {"retype", "comment", "define_type"}  # bob retracted the rename
        assert any(t.get("name") == "node" for t in e["types"].values())
