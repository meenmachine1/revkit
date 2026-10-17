"""End to end against the image backend on a real binary compiled here:
open -> list functions -> decompile main -> rename -> subscription event ->
re-decompile -> blame -> revert, plus a listing page and a Connect call."""

import json
import shutil
import subprocess
import urllib.request

import pytest

from revkit import Client, Daemon, format_provenance
from revkit.v1 import listing_pb2, subscription_pb2

# Generous: the call takes milliseconds, but a sanitizer build on a busy
# machine can be many times slower.
HTTP_TIMEOUT = 120

SOURCE = r"""
#include <stdio.h>
int counter;
__attribute__((noinline)) unsigned checksum(const unsigned char *p, int n) {
  unsigned h = 0x811c9dc5;
  for (int i = 0; i < n; i++) h = (h ^ p[i]) * 0x1000193;
  counter++;
  return h;
}
int main(int argc, char **argv) {
  unsigned r = checksum((const unsigned char *)argv[0], argc);
  printf("%u\n", r);
  return (int)r;
}
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
def image_daemon(binary):
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_real_binary_rename_subscribe_blame_revert(image_daemon, binary):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        assert "image-backend" in rk.server_info().features
        imported = rk.import_program("default", path=str(binary))
        prog = rk.program(imported.program.program_id)
        assert imported.program.format == "elf"
        assert prog.summary().language.language_id.startswith("x86:LE:64")

        functions = {f.name: f for f in prog.functions(page_size=5)}  # forces pagination
        assert {"main", "checksum"} <= functions.keys()
        main, checksum = functions["main"].entry.offset, functions["checksum"].entry.offset

        before = prog.decompile(main)
        assert "checksum(" in before.text
        assert before.prototype.c_declaration.startswith(("int main(", "undefined4 main(", "uint main("))
        call = [t for line in before.lines for t in line.tokens if t.text == "checksum"]
        assert call and call[0].target.offset == checksum and call[0].HasField("address")

        with rk.subscribe(imported.program.project_id, include_assertions=True) as sub:
            start = sub.hello.head_revision
            with Client(image_daemon.grpc_target, actor="agent:claude@test", session="run-1") as agent:
                appended = agent.program(prog.id).rename(checksum, "fnv1a", reason="FNV-1a constants")
            seq = appended.assertions[0].seq

            event = sub.next_revision()
            assert event.revision == start + 1
            assert event.cause == subscription_pb2.CHANGE_CAUSE_ASSERTION
            assert [a.seq for a in event.assertions] == [seq]
            assert any(k.address.offset == checksum for k in event.changed_keys)
            assert any(
                q.kind == subscription_pb2.QUERY_KIND_DECOMPILE and q.address.offset == main for q in event.invalidated
            ), "the caller's decompilation must be invalidated"

            after = prog.decompile(main)
            assert "fnv1a(" in after.text and "checksum(" not in after.text
            assert prog.function(checksum).name == "fnv1a"
            assert prog.at(start).function(checksum).name == "checksum"  # pinned read
            assert "checksum(" in prog.at(start).decompile(main).text

            blame = prog.blame(prog.key("name", checksum))
            assert blame.value_text == "fnv1a"
            assert format_provenance(blame.origin.asserted.provenance) == "agent:claude@test"

            reverted = prog.revert(kind="agent", session="run-1")
            assert list(reverted.retracted_seqs) == [seq]
            event = sub.next_revision()
            assert event.cause == subscription_pb2.CHANGE_CAUSE_RETRACTION

        assert prog.function(checksum).name == "checksum"
        assert "checksum(" in prog.decompile(main).text
        assert prog.blame(prog.key("name", checksum)).origin.HasField("derived")


def test_listing_instruction_xrefs_and_locals(image_daemon, binary, tmp_path):
    with Client(image_daemon.grpc_target, actor="user:bob") as rk:
        prog = rk.program(rk.import_program("default", path=str(binary), name="prog2").program.program_id)
        functions = {f.name: f for f in prog.functions()}
        main, checksum = functions["main"].entry.offset, functions["checksum"].entry.offset

        page = prog.listing(main, max_rows=40)
        assert page.rows[0].address.offset == main and page.rows[0].function_entry
        assert page.rows[0].labels[0].name == "main"
        calls = [r for r in page.rows if r.tokens and r.tokens[0].text == "CALL"]
        sym = [t for r in calls for t in r.tokens if t.kind == listing_pb2.LISTING_TOKEN_KIND_SYMBOL and t.text == "checksum"]
        assert sym and sym[0].target.offset == checksum
        regs = [t for r in page.rows for t in r.tokens if t.kind == listing_pb2.LISTING_TOKEN_KIND_REGISTER]
        assert regs and all(t.register_varnode.space == "register" for t in regs)

        insn = prog.instruction(calls[0].address.offset)
        assert insn.flow == listing_pb2.FLOW_KIND_CALL
        assert any(p.mnemonic == "CALL" for p in insn.pcode)
        callers = prog.xrefs_to(checksum)
        assert any(x.from_function_name == "main" and x.kind == listing_pb2.XREF_KIND_CALL for x in callers)

        # A local rename and a comment show up in the next decompile.
        fn = prog.decompile(checksum)
        param = fn.variables[fn.prototype.parameter_indices[0]]
        prog.rename_local(checksum, param.storage_key, "buf")
        prog.comment(checksum, "FNV-1a over a buffer", kind="plate")
        text = prog.decompile(checksum).text
        assert "/* FNV-1a over a buffer */" in text and "(buf" in text.replace(" ", "")
        [row] = prog.listing(checksum, max_rows=1).rows
        assert row.comments[0].text == "FNV-1a over a buffer"
        # The symbol tree (api_minor 82): the folders; checksum among the functions.
        assert [n.name for n in prog.symbol_tree()] == ["Imports", "Exports", "Functions", "Labels", "Classes", "Namespaces"]
        assert [n.address.offset for n in prog.symbol_tree("Functions", name_contains="CHECKSUM") if n.name == "checksum"] == [checksum]
        # Export C (api_minor 80): the function's C, in a file with a header.
        ex = prog.export_c([checksum], directory=str(tmp_path / "c"), name="one")
        assert ex.functions == 1 and ex.failed == [] and ex.source_name == "one.c" and ex.header_name == "one.h"
        assert (tmp_path / "c" / "one.c").read_text() == ex.source and '#include "one.h"' in ex.source
        assert "checksum(" in ex.header and "/* checksum @ 0x" in ex.source
        # The comment table (api_minor 77).
        [c] = [c for c in prog.comments("plate") if c.address.offset == checksum]
        assert c.text == "FNV-1a over a buffer" and c.function_name == "checksum"
        assert not list(prog.comments("eol", text_contains="FNV"))
        prog.revert(kind="user", id="bob")
        assert "buf" not in prog.decompile(checksum).text


def test_browser_protocol(image_daemon, binary):
    with Client(image_daemon.grpc_target) as rk:
        program_id = rk.import_program("default", path=str(binary), name="prog3").program.program_id
    req = urllib.request.Request(
        image_daemon.http_url + "/revkit.v1.QueryService/ListFunctions",
        data=json.dumps({"programId": program_id, "nameContains": "main"}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        body = json.loads(resp.read())
    assert [f["name"] for f in body["functions"]] == ["main"]


def test_mcp_tools_on_a_real_binary(image_daemon, binary):
    """The MCP server's read and write tools work against real programs."""
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    with Client(image_daemon.grpc_target) as rk:
        program = rk.import_program("default", path=str(binary), name="prog-mcp").program.program_id
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-image")

    def data(result):
        assert not result.is_error, result
        return json.loads(result.content[0].text)

    async def run():
        async with mcp_client.Client(server) as mcp:
            fns = {f["name"]: f["address"] for f in data(await mcp.call_tool("list_functions", {"program_id": program}))["functions"]}
            dec = data(await mcp.call_tool("decompile", {"program_id": program, "function_address": fns["main"]}))
            assert "checksum(" in dec["c"]
            listing = data(await mcp.call_tool("disassemble", {"program_id": program, "address": fns["main"], "max_rows": 20}))
            assert "CALL checksum" in listing["listing"]
            data(await mcp.call_tool("rename", {"program_id": program, "address": fns["checksum"], "new_name": "fnv1a", "reason": "constants"}))
            xrefs = data(await mcp.call_tool("xrefs", {"program_id": program, "address": fns["checksum"]}))
            assert all(x["to_name"] == "fnv1a" for x in xrefs["xrefs"]) and xrefs["xrefs"]
            assert "fnv1a(" in data(await mcp.call_tool("decompile", {"program_id": program, "function_address": fns["main"]}))["c"]
            assert data(await mcp.call_tool("revert_my_changes", {"program_id": program}))["retracted"] == 1

    try:
        anyio.run(run)
    finally:
        server.revkit_client.close()


def test_rename_delete_and_restore_a_program(image_daemon, binary):
    """Program management (feature program-management): rename, soft delete, restore."""
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        if "program-management" not in rk.server_info().features:
            pytest.skip("daemon predates api_minor 19")
        pid = rk.import_program("default", path=str(binary), name="leftover").program.program_id
        renamed = rk.rename_program(pid, "scratch copy")
        assert renamed.program.name == "scratch copy"
        assert renamed.program.program_id == pid
        rk.delete_program(pid)
        assert pid not in [p.program_id for p in rk.programs("default")]
        trash = [p for p in rk.programs("default", include_deleted=True) if p.program_id == pid]
        assert trash and trash[0].deleted and trash[0].name == "scratch copy"
        rk.restore_program(pid)
        assert pid in [p.program_id for p in rk.programs("default")]


def test_import_progress_callback(image_daemon, binary):
    """import_program(progress=...) (feature import-progress): reports while
    the import runs and once at the end; the fraction never goes back."""
    from revkit.v1 import project_pb2

    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        if "import-progress" not in rk.server_info().features:
            pytest.skip("daemon predates api_minor 22")
        seen = []
        imported = rk.import_program("default", path=str(binary), name="with-progress", progress=seen.append, poll=0.005)
        assert seen, "no progress reported"
        last = seen[-1]
        assert last.done and not last.error
        assert last.phase == project_pb2.IMPORT_PHASE_DONE
        assert last.progress == 1.0
        assert last.program_id == imported.program.program_id
        assert last.functions_found > 0
        fractions = [p.progress for p in seen if p.progress >= 0]
        assert fractions == sorted(fractions)
        phases = [p.phase for p in seen]
        assert phases == sorted(phases)
