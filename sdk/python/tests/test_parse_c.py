"""Parsing C and importing a header (TypeService.ParseC, api_minor 25):
parse_c, header_import_bodies and import_header against the image backend,
then the MCP server's parse_c and import_header tools."""

import json
import shutil
import subprocess

import pytest

from revkit import Client, Daemon, header_import_bodies

SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
struct point { int x; int y; long weight; };
__attribute__((noinline)) long weigh(void *p) {
  struct point *pt = p;
  return pt->weight * 3 + pt->y;
}
int main(int argc, char **argv) {
  struct point *p = calloc(1, sizeof *p);
  p->weight = argc;
  printf("%ld\n", weigh(p));
  return 0;
}
"""

HEADER = r"""
#include <stddef.h>
#define POINT_MAGIC 0x50
struct point { int x; int y; long weight; };
typedef struct point point_t;
long weigh(struct point *p);
"""


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("parse_c")
    (d / "prog.c").write_text(SOURCE)
    subprocess.run([cc, "-O1", "-s", "-o", str(d / "prog"), str(d / "prog.c")], check=True)
    return d / "prog"


@pytest.fixture(scope="module")
def image_daemon(binary):
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def weigh_entry(prog):
    # The only function computing *3 of a field at +8: find it by its code.
    for f in prog.functions():
        text = prog.decompile(f.entry.offset).text
        if "* 3" in text and "+ 8" in text:
            return f.entry.offset, text
    raise AssertionError("weigh not found")


def test_parse_import_retype_and_undo(image_daemon, binary):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        assert "parse-c" in rk.server_info().features and rk.server_info().api_minor >= 25
        pid = rk.import_program("default", path=str(binary)).program.program_id
        prog = rk.program(pid)
        entry, before = weigh_entry(prog)
        assert "->weight" not in before

        parsed = prog.parse_c(HEADER, name="point.h", prototypes=True, defines_as_enum=True)
        assert parsed.errors == 0, list(parsed.diagnostics)
        keys = {n.key for n in parsed.named}
        assert {"struct point", "typedef point_t", "enum point_h_constants"} <= keys
        assert [p.declaration for p in parsed.prototypes] == ["long weigh(struct point *p)"]
        assert [(c.name, c.value) for c in parsed.constants] == [("POINT_MAGIC", 0x50)]
        # Each node's spelling and each named type's definition, for previews.
        assert len(parsed.displays) == len(parsed.nodes)
        point = next(n for n in parsed.named if n.key == "struct point")
        assert parsed.displays[point.index] == "struct point"
        assert "long weight;" in point.c_definition
        # A diagnostic carries its line's text.
        bad = prog.parse_c("struct ok { int a; };\nstruct bad { mystery_t m; };\n", name="bad.h")
        assert bad.diagnostics[0].line == 2 and bad.diagnostics[0].source_line == "struct bad { mystery_t m; };"
        # Only what the chosen names need, renumbered.
        bodies = header_import_bodies(parsed, ["struct point"])
        # ... then the binding, and the type filed under the header's name.
        assert [b.WhichOneof("kind") for b in bodies][-2:] == ["bind_type_name", "type_category"]
        assert bodies[-1].type_category.path == "/point.h"
        assert header_import_bodies(parsed, ["struct point"], categories="none")[-1].WhichOneof("kind") == "bind_type_name"
        assert sum(b.WhichOneof("kind") == "bind_type_name" for b in bodies) == 1

        resp = prog.import_header(parsed, file="point.h")
        session = resp.assertions[0].provenance.session
        assert session.startswith("import-")
        assert len({a.revision for a in resp.assertions}) == 1  # one revision, one undo
        point = next(n for n in parsed.named if n.key == "struct point")
        # Parsed again, it's the program's own now.
        again = prog.parse_c(HEADER, name="point.h")
        assert next(n for n in again.named if n.key == "struct point").existing_hash == point.hash
        assert not again.conflicts

        prog.retype(entry, "long weigh(struct point *p)", actor="user:alice", reason="from point.h")
        after = prog.decompile(entry).text
        assert "->weight" in after, after

        prog.revert(kind="user", id="alice")
        prog.revert(kind="import", id="header", session=session)
        assert "->weight" not in prog.decompile(entry).text


def test_mcp_parse_and_import(image_daemon, binary):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        pid = rk.import_program("default", path=str(binary), name="for-mcp").program.program_id
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-parse")

    async def run():
        async with mcp_client.Client(server) as mcp:
            parsed = json.loads((await mcp.call_tool("parse_c", {"program_id": pid, "c_text": HEADER})).content[0].text)
            assert parsed["errors"] == 0, parsed
            assert {t["key"] for t in parsed["types"]} >= {"struct point", "typedef point_t"}
            assert parsed["types"][0]["status"] == "new"
            imported = json.loads((await mcp.call_tool("import_header", {
                "program_id": pid, "c_text": HEADER, "reason": "the program's struct", "names": ["struct point"]})).content[0].text)
            assert imported["ok"] and imported["bound"] == ["struct point"], imported
            again = json.loads((await mcp.call_tool("parse_c", {"program_id": pid, "c_text": HEADER})).content[0].text)
            assert next(t for t in again["types"] if t["key"] == "struct point")["status"] == "identical"

    anyio.run(run)
