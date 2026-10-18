"""Type archives and categories (api_minor 35, feature "type-archive";
docs/types.md#type-archives) on the image backend: a debug build's types
exported, imported into its stripped twin from the files, exported again
byte for byte, imported again (nothing to do); categories from the debug
info and set by hand; the MCP tools; and revkit.script's helpers."""

import io
import json
import shutil
import subprocess

import pytest

from revkit import Client, Daemon, type_category_body
from revkit.script import HeadlessHost, run_script

SOURCE = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
struct __attribute__((packed)) wire { uint8_t tag; uint32_t len; uint16_t crc; };
struct flags { unsigned a : 1, b : 3; int c : 5; };
typedef struct node {
  struct node *next;
  struct wire w;
  struct flags f;
  union { int i; float x; } u;
} node_t;
__attribute__((noinline)) int walk(node_t *n) {
  int s = 0;
  for (; n; n = n->next) s += n->w.len + n->f.c + n->u.i;
  return s;
}
int main(int argc, char **argv) {
  node_t *n = calloc(1, sizeof *n);
  n->w.len = argc;
  printf("%d\n", walk(n));
  return 0;
}
"""


@pytest.fixture(scope="module")
def binaries(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc or not shutil.which("strip"):
        pytest.skip("no C compiler or strip")
    d = tmp_path_factory.mktemp("archive")
    (d / "prog.c").write_text(SOURCE)
    subprocess.run([cc, "-g", "-O1", "-o", str(d / "prog-debug"), str(d / "prog.c")], check=True)
    subprocess.run(["strip", "-o", str(d / "prog"), str(d / "prog-debug")], check=True)
    return d


@pytest.fixture(scope="module")
def image_daemon(binaries):
    # Without inference: its structures (astruct_<n>) would be the stripped
    # program's types too, and the round trip compares every type.
    with Daemon(None, "--backend", "image", "--infer-prototypes", "off", startup_timeout=60) as d:
        yield d


def test_round_trip_through_files(image_daemon, binaries, tmp_path):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        info = rk.server_info()
        assert "type-archive" in info.features and info.api_minor >= 35
        dbg = rk.program(rk.import_program("default", path=str(binaries / "prog-debug")).program.program_id)
        prog = rk.program(rk.import_program("default", path=str(binaries / "prog")).program.program_id)

        a = dbg.export_type_archive(scope="all", directory=str(tmp_path))
        assert a.header_name == "prog-debug.h" and a.sidecar_name == "prog-debug.json"
        assert a.mismatches == 0, list(a.notes)
        keys = {t.key for t in a.archive.types}
        assert {"struct wire", "struct flags", "struct node", "typedef node_t"} <= keys
        assert "#pragma pack(push, 1)\nstruct wire {" in a.header
        assert "_Static_assert(sizeof(struct wire) == 7" in a.header
        sidecar = json.loads((tmp_path / a.sidecar_name).read_text())
        assert sidecar["provenance"]["origin"] == "prog-debug"
        assert {t["key"]: t.get("category") for t in sidecar["types"]}["struct wire"] == "/prog.c"
        cc = shutil.which("cc") or shutil.which("gcc")
        subprocess.run([cc, "-fsyntax-only", "-x", "c", str(tmp_path / a.header_name)], check=True)

        resp = prog.import_type_archive(str(tmp_path / a.header_name))
        assert resp is not None and len({x.revision for x in resp.assertions}) == 1
        assert resp.assertions[0].provenance.id == "archive"
        assert resp.assertions[0].provenance.version == "prog-debug"
        b = prog.export_type_archive(scope="all")
        assert b.header == a.header and b.sidecar == a.sidecar
        # Again: nothing to do; the hashes checked.
        assert prog.import_type_archive(a) is None
        bad = prog.parse_type_archive(a.header.replace("uint32_t len;", "uint16_t len;"), a.sidecar)
        assert bad.archive.header_changed and any(m.key == "struct wire" for m in bad.archive.mismatches)
        with pytest.raises(ValueError, match="sidecar's hashes"):
            prog.import_type_archive(bad)

        # Categories: the debug info's, then moved by hand.
        assert dbg.type_categories().get("/prog.c", 0) >= 3
        prog.set_type_category(["struct wire", "struct flags"], "/net/")
        assert sorted(t.name for t in prog.find_types(category="/net")) == ["flags", "wire"]
        assert "/net" in prog.type_categories()
        sel = prog.export_type_archive(["struct node"])
        assert {t.key: t.category for t in sel.archive.types}["struct wire"] == "/net"
        assert type_category_body("struct x", "/y").type_category.path == "/y"


def test_mcp_tools(image_daemon, binaries):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        dbg = rk.import_program("default", path=str(binaries / "prog-debug"), name="mcp-debug").program.program_id
        prog = rk.import_program("default", path=str(binaries / "prog"), name="mcp-stripped").program.program_id
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-archive")

    async def run():
        async with mcp_client.Client(server) as mcp:
            call = lambda tool, args: mcp.call_tool(tool, args)  # noqa: E731
            a = json.loads((await call("export_type_archive", {"program_id": dbg, "scope": "all"})).content[0].text)
            assert a["mismatches"] == 0 and "struct wire" in a["types"], a
            imported = json.loads((await call("import_type_archive", {
                "program_id": prog, "header": a["header"], "sidecar": a["sidecar"],
                "reason": "the debug build's types"})).content[0].text)
            assert imported["ok"] and "struct wire" in imported["imported"], imported
            assert imported["provenance"].startswith("agent:claude")
            again = json.loads((await call("import_type_archive", {
                "program_id": prog, "header": a["header"], "sidecar": a["sidecar"], "reason": "again"})).content[0].text)
            assert again["ok"] and again["imported"] == [], again
            moved = json.loads((await call("set_type_category", {
                "program_id": prog, "names": ["struct wire"], "category": "/net", "reason": "a wire format"})).content[0].text)
            assert moved["ok"], moved
            found = json.loads((await call("find_types", {"program_id": prog, "category": "/net"})).content[0].text)
            assert [t["name"] for t in found["types"]] == ["wire"] and found["types"][0]["category"] == "/net"

    anyio.run(run)


SCRIPT = """\
# @category Tests
# @description Imports an archive and files a type
from revkit.script import *
names = import_type_archive(ask_file("archive", "The archive's header"))
set_type_category("struct flags", "/bits")
print(len(names), "types")
"""


def test_script_helpers(image_daemon, binaries, tmp_path):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        dbg = rk.program(rk.import_program("default", path=str(binaries / "prog-debug"), name="s-debug").program.program_id)
        pid = rk.import_program("default", path=str(binaries / "prog"), name="s-stripped").program.program_id
        a = dbg.export_type_archive(scope="all", directory=str(tmp_path), name="from-debug")
        s = tmp_path / "import_archive.py"
        s.write_text(SCRIPT)
        host = HeadlessHost({"archive": str(tmp_path / a.header_name)}, out=io.StringIO(), err=io.StringIO(),
                            interactive=False)
        r = run_script(s, client=rk, program_id=pid, host=host)
        assert r.ok, r.traceback
        assert len(r.revisions) == 1
        prog = rk.program(pid)
        assert [t.name for t in prog.find_types(category="/bits")] == ["flags"]
        assert "struct wire" in {f"struct {t.name}" for t in prog.find_types("wire")}
