"""Project-wide types and type archives (api_minor 52, feature
"project-types"; docs/types.md#project-types) through the SDK, the MCP tools
and revkit.script: two programs share a struct moved to project scope, an
edit there reaches both decompilations, a copy to one program stops it, and
archives switch off and attach."""

import io
import json
import shutil
import subprocess

import pytest

from revkit import Client, Daemon
from revkit.script import HeadlessHost, run_script
from revkit.v1 import assertion_pb2, types_pb2

FIRST = r"""
struct point { int x; int y; };
struct point origin = {1, 2};
__attribute__((noinline)) int gety(struct point *p) { return p->y; }
int main(void) { return gety(&origin); }
"""

SECOND = r"""
struct point { int x; int y; };
struct point corner = {3, 4};
__attribute__((noinline)) int sumxy(struct point *p) { return p->x + p->y * 3; }
int main(void) { return sumxy(&corner); }
"""


@pytest.fixture(scope="module")
def binaries(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("project-types")
    for name, src in (("first", FIRST), ("second", SECOND)):
        (d / f"{name}.c").write_text(src)
        subprocess.run([cc, "-g", "-O1", "-fno-inline", "-o", str(d / name), str(d / f"{name}.c")], check=True)
    return d


@pytest.fixture(scope="module")
def image_daemon(binaries):
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def decompiled(prog, fn):
    return prog.decompile(next(f.entry.offset for f in prog.functions() if f.name == fn)).text


def point(prog):
    return [t for t in prog.find_types("point") if t.name == "point" and t.kind == types_pb2.TYPE_KIND_STRUCT][0]


def edited_point(prog, x, y):
    """struct point with new field names, bound to its name at project scope."""
    old = point(prog)
    body = assertion_pb2.AssertionBody()
    t = body.define_type.type
    t.kind = types_pb2.TYPE_KIND_STRUCT
    t.name = "point"
    t.size = 8
    for i, n in enumerate((x, y)):
        f = t.fields.add()
        f.name = n
        f.offset = 4 * i
        f.type.hash = old.composite.fields[0].type_hash
    bind = assertion_pb2.AssertionBody()
    bind.bind_type_name.type.assertion_index = 0
    return prog.append_project(body, bind, reason="rename the fields")


def test_project_types_and_archives(image_daemon, binaries):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        info = rk.server_info()
        assert "project-types" in info.features and "library-types" in info.features and info.api_minor >= 52
        a = rk.program(rk.import_program("default", path=str(binaries / "first")).program.program_id)
        b = rk.program(rk.import_program("default", path=str(binaries / "second")).program.program_id)

        moved = a.move_types_to_project("struct point")
        assert [t.key for t in moved.types] == ["struct point"] and moved.retracted >= 1
        assert [t.name for t in a.project_types("point")] == ["point"]
        resp = edited_point(a, "px", "py")
        assert resp.assertions[0].key.project
        assert "->py" in decompiled(a, "gety")
        assert "->px" in decompiled(b, "sumxy")

        b.copy_types_to_program("struct point")
        edited_point(a, "qx", "qy")
        assert "->qy" in decompiled(a, "gety")
        assert "->py" in decompiled(b, "sumxy") and "->qy" not in decompiled(b, "sumxy")

        names = {x.name: x for x in a.type_archives()}
        assert "ghidra" in names
        if "libc-lp64" in names:
            assert names["libc-lp64"].applies and names["libc-lp64"].enabled
            a.set_type_archive_enabled("libc-lp64", False)
            assert not {x.name: x for x in a.type_archives()}["libc-lp64"].enabled
            a.detach_type_archive("libc-lp64")  # back to the default: on
            assert {x.name: x for x in b.type_archives()}["libc-lp64"].enabled
        a.attach_type_archive("int gety(struct widget *w);\nstruct widget { int a; };\n", name="mylib")
        mine = {x.name: x for x in b.type_archives()}["mylib"]
        assert mine.kind == types_pb2.TYPE_ARCHIVE_KIND_ATTACHED and mine.functions == 1 and mine.types == 1


def test_mcp_tools(image_daemon, binaries):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        a = rk.import_program("default", path=str(binaries / "first"), name="mcp-first").program.program_id
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-project-types")

    async def run():
        async with mcp_client.Client(server) as mcp:
            call = lambda tool, args: mcp.call_tool(tool, args)  # noqa: E731
            archives = json.loads((await call("list_type_archives", {"program_id": a})).content[0].text)
            assert any(x["name"] == "ghidra" for x in archives["archives"]), archives
            off = json.loads((await call("set_type_archive", {"program_id": a, "name": "ghidra", "enabled": False,
                                                               "reason": "revkit's archives only"})).content[0].text)
            assert off["ok"], off
            moved = json.loads((await call("move_types_to_project", {"program_id": a, "names": ["struct point"],
                                                                      "reason": "shared"})).content[0].text)
            assert moved["ok"] and moved["types"][0]["key"] == "struct point", moved
            found = json.loads((await call("find_types", {"program_id": a, "name_contains": "point"})).content[0].text)
            assert any(t["name"] == "point" and t.get("project") for t in found["types"]), found
            copied = json.loads((await call("copy_types_to_program", {"program_id": a, "names": ["struct point"],
                                                                       "reason": "mine"})).content[0].text)
            assert copied["ok"], copied

    anyio.run(run)


SCRIPT = """\
# @category Tests
# @description Shares a struct with the project
from revkit.script import *
print(move_types_to_project("struct point"))
set_type_archive_enabled("ghidra", True)
print(len(type_archives()), "archives")
"""


def test_script_helpers(image_daemon, binaries, tmp_path):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        pid = rk.import_program("default", path=str(binaries / "first"), name="s-first").program.program_id
        s = tmp_path / "share.py"
        s.write_text(SCRIPT)
        out = io.StringIO()
        host = HeadlessHost({}, out=out, err=io.StringIO(), interactive=False)
        r = run_script(s, client=rk, program_id=pid, host=host)
        assert r.ok, r.traceback
        assert "['struct point']" in out.getvalue()
        assert [t.name for t in rk.program(pid).project_types("point")] == ["point"]
