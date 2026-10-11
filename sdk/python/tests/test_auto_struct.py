"""Structures from pointer use and from data (TypeService.AutoStructure,
api_minor 32, feature "auto-struct"): Program.auto_structure, apply and
undo, auto_fill_structure, create_structure from a range, the MCP tools,
and the buffered script helpers."""

import io
import json
import shutil
import subprocess

import pytest

from revkit import Client, Daemon, auto_structure_bodies
from revkit.script import HeadlessHost, run_script

SOURCE = r"""
struct item { struct item *next; int count; short kind; signed char tag; double weight; long total; };
struct conf { int magic; short port; short flags; const char *name; };
struct conf config = {0x1234, 80, 3, "server"};
__attribute__((noinline)) void bump(struct item *it) { it->count++; it->weight *= 2.0; }
__attribute__((noinline)) void mark(long *p) { *p += 1; }
__attribute__((noinline)) long walk(struct item *it) {
  long t = it->kind + it->tag;
  if (it->next != 0) t += it->next->kind;
  it->total = t;
  bump(it);
  mark(&it->total);
  return t;
}
int main(int argc, char **argv) {
  (void)argv;
  static struct item a, b;
  a.next = argc > 2 ? &b : 0;
  a.kind = (short)argc;
  return (int)walk(&a) + config.port;
}
"""


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("auto_struct")
    (d / "prog.c").write_text(SOURCE)
    subprocess.run([cc, "-O1", "-fno-inline", "-fno-pie", "-no-pie", "-o", str(d / "prog"), str(d / "prog.c")], check=True)
    return d / "prog"


@pytest.fixture(scope="module")
def daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def entry(prog, name):
    return next(f.entry.offset for f in prog.functions() if f.name == name)


def param0(prog, fn):
    f = prog.decompile(fn, text=False)
    return next(v for v in f.variables if v.kind == 1 and v.parameter_index == 0)


def test_create_apply_fill_and_undo(daemon, binary):
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        info = rk.server_info()
        assert "auto-struct" in info.features and info.api_minor >= 32
        prog = rk.program(rk.import_program("default", path=str(binary)).program.program_id)
        walk, bump = entry(prog, "walk"), entry(prog, "bump")
        it = param0(prog, walk)

        made = prog.auto_structure(walk, it.storage_key)
        offsets = {f.offset: f for f in made.fields}
        assert {0, 8, 0xc, 0xe, 0x10, 0x18} <= set(offsets), made.c_definition
        assert made.name == "astruct" and made.size == 0x20
        assert offsets[0x10].type_display == "double"
        assert offsets[0].type_display == "undefined1 *"
        assert any(a.kind == 3 for a in made.accesses)  # passed to bump
        bodies = auto_structure_bodies(made, function=walk, storage_key=it.storage_key)
        assert [b.WhichOneof("kind") for b in bodies][-2:] == ["bind_type_name", "retype"]

        # Only this function: no count or weight.
        here = prog.auto_structure(walk, it.storage_key, call_depth=0)
        assert 8 not in {f.offset for f in here.fields}

        done = prog.auto_create_structure(walk, it.storage_key, call_depth=0, reason="from walk")
        assert len({a.revision for a in done.assertions}) == 1
        assert param0(prog, walk).type.display == "struct astruct *"

        # Fill in from bump, once its parameter points to the struct.
        prog.retype_local(bump, "param:0", "struct astruct *")
        filled = prog.auto_fill_structure(bump, "param:0")
        assert filled.assertions
        astruct = next(t for t in prog.find_types("astruct") if t.name == "astruct")
        assert {f.name for f in astruct.composite.fields} >= {"field_0x8", "field_0x10"}
        assert prog.auto_structure(bump, "param:0", fill=True).unchanged

        prog.retract(*[a.seq for a in filled.assertions])
        prog.retract(*[a.seq for a in done.assertions])
        assert param0(prog, walk).type.display == it.type.display


def test_structure_from_range(daemon, binary):
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        prog = rk.program(rk.import_program("default", path=str(binary), name="range").program.program_id)
        config = next(s.address.offset for s in prog.symbols(name_equals="config"))
        prog.define_data(config, "int")
        prog.define_data(config + 4, "short")
        prog.define_data(config + 8, "char *")
        made = prog.structure_from_range(config, config + 15, name="conf_t")
        assert [(f.offset, f.type_display) for f in made.fields] == [(0, "int"), (4, "short"), (8, "char *")]
        done = prog.create_structure(config, config + 15, name="conf_t")
        row = prog.listing(config, max_rows=1).rows[0]
        assert row.data_type == "struct conf_t"
        prog.retract(*[a.seq for a in done.assertions])


def test_mcp_tools(daemon, binary):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    with Client(daemon.grpc_target, actor="user:alice") as rk:
        prog = rk.program(rk.import_program("default", path=str(binary), name="for-mcp").program.program_id)
        walk = entry(prog, "walk")
        key = param0(prog, walk).storage_key
    server = create_server(daemon.grpc_target, agent="claude", agent_version="test", session="mcp-auto-struct")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(name, **kw):
                return json.loads((await mcp.call_tool(name, kw)).content[0].text)

            preview = await call("auto_structure", program_id=prog.id, function_address=hex(walk), storage_key=key,
                                 reason="the item walk() reads")
            assert preview["name"] == "astruct" and "seqs" not in preview
            assert {f["offset"] for f in preview["fields"]} >= {"0x0", "0x8", "0x18"}
            applied = await call("auto_structure", program_id=prog.id, function_address=hex(walk), storage_key=key,
                                 reason="the item walk() reads", apply=True)
            assert applied["ok"] and applied["seqs"], applied
            await call("undo_changes", program_id=prog.id, seqs=applied["seqs"], reason="test")

    anyio.run(run)


SCRIPT = """\
# @category Tests
from revkit.script import *
walk = function_at(ask_address("walk", "walk"))
key = next(v.storage_key for v in decompile(walk).variables if v.kind == 1)
a = auto_create_structure(walk, key, call_depth=0)
b = auto_create_structure(walk, key, call_depth=1)
print(a, b)
"""


def test_script_helpers(daemon, binary, tmp_path):
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        prog = rk.program(rk.import_program("default", path=str(binary), name="script").program.program_id)
        s = tmp_path / "structs.py"
        s.write_text(SCRIPT)
        host = HeadlessHost(None, out=io.StringIO(), err=io.StringIO(), interactive=False)
        r = run_script(s, client=rk, program_id=prog.id, args={"walk": hex(entry(prog, "walk"))}, host=host)
        assert r.ok, r.traceback
        assert len(r.revisions) == 1
        # Two structures in one run: two names, though neither was committed when the second was made.
        assert "astruct astruct_1" in host.out.getvalue()
        assert {t.name for t in prog.find_types("astruct")} >= {"astruct", "astruct_1"}
