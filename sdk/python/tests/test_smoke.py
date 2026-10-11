"""End-to-end against a real rk-daemon over gRPC: open -> list functions ->
rename -> subscription event -> blame -> bulk revert."""

import json
import urllib.request

import pytest

from revkit import Client, FailedPrecondition, InvalidArgument, NotFound, format_provenance
from revkit.v1 import subscription_pb2

CHECKSUM, MAIN = 0x401040, 0x401010
# Generous: the call takes milliseconds, but a sanitizer build on a busy
# machine can be many times slower.
HTTP_TIMEOUT = 120


def test_open_list_rename_subscribe_blame_revert(daemon):
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        assert rk.server_info().api_major == "v1"

        opened = rk.open_project("demo")
        prog = rk.program(opened.programs[0].program_id)
        functions = list(prog.functions(page_size=2))  # forces pagination
        assert [f.name for f in functions] == ["entry", "main", "FUN_00401040", "FUN_00401070"]

        with rk.subscribe(opened.project.project_id, include_assertions=True) as sub:
            start = sub.hello.head_revision

            # An agent renames the checksum function.
            with Client(daemon.grpc_target, actor="agent:claude@test", session="run-1") as agent:
                appended = agent.program(prog.id).rename(CHECKSUM, "fnv1a", reason="FNV-1a constants")
            seq = appended.assertions[0].seq

            event = sub.next_revision()
            assert event.revision == start + 1
            assert event.cause == subscription_pb2.CHANGE_CAUSE_ASSERTION
            assert [a.seq for a in event.assertions] == [seq]
            assert any(k.address.offset == CHECKSUM for k in event.changed_keys)
            assert any(
                q.kind == subscription_pb2.QUERY_KIND_DECOMPILE and q.address.offset == MAIN for q in event.invalidated
            ), "callers' decompilation must be invalidated"

            assert prog.function(CHECKSUM).name == "fnv1a"
            assert "uVar1 = fnv1a(s_hello_00402000,5);" in prog.decompile(MAIN).text
            # A pinned read still sees the old name.
            assert prog.at(start).function(CHECKSUM).name == "FUN_00401040"

            blame = prog.blame(prog.key("name", CHECKSUM))
            assert blame.value_text == "fnv1a"
            assert format_provenance(blame.origin.asserted.provenance) == "agent:claude@test"
            assert blame.origin.asserted.provenance.reason == "FNV-1a constants"

            # Bulk revert everything that agent session did.
            reverted = prog.revert(kind="agent", session="run-1")
            assert list(reverted.retracted_seqs) == [seq]
            event = sub.next_revision()
            assert event.cause == subscription_pb2.CHANGE_CAUSE_RETRACTION
            assert event.revision == start + 2

        assert prog.function(CHECKSUM).name == "FUN_00401040"
        history = prog.history(prog.key("name", CHECKSUM))
        assert [h.op for h in history] == [1, 2]  # ASSERT, then RETRACT
        assert prog.blame(prog.key("name", CHECKSUM)).origin.HasField("derived")


def test_reads_and_errors(daemon):
    with Client(daemon.grpc_target, actor="user:bob") as rk:
        prog = rk.program("demo/hello")
        summary = prog.summary()
        assert summary.language.language_id == "x86:LE:64:default"
        assert [b.name for b in prog.memory_map()] == [".text", ".rodata", ".data", ".bss"]
        assert prog.read_memory(0x402000, 6) == b"hello\x00"

        page = prog.listing(0x401040, max_rows=3)
        assert [r.address.offset for r in page.rows] == [0x401040, 0x401043, 0x401045]
        assert "".join(t.text for t in page.rows[1].tokens) == "JZ LAB_00401065"

        insn = prog.instruction(0x401055)
        assert insn.mnemonic == "IMUL" and insn.pcode[0].mnemonic == "INT_MULT"
        [xref] = prog.xrefs_to(CHECKSUM)
        assert xref.from_address.offset == 0x401020 and xref.from_function_name == "main"

        fn = prog.decompile(CHECKSUM)
        assert fn.prototype.c_declaration.startswith("uint ")
        # Statement tokens map to varnodes and to the instruction they came
        # from (the signature's parameters are inputs, so they have no address).
        body = [t for line in fn.lines[1:] for t in line.tokens if t.varnode_indices]
        assert body and all(t.HasField("address") for t in body)

        with pytest.raises(NotFound):
            rk.program("nope").summary()
        with pytest.raises(InvalidArgument):
            prog.rename(0x900000, "nowhere")
        with pytest.raises(Exception):
            prog.at(10_000).summary()


def test_comment_and_local_edits_show_up(daemon):
    with Client(daemon.grpc_target, actor="user:carol") as rk:
        prog = rk.program("demo/hello")
        prog.comment(0x401055, "FNV prime", kind="pre")
        prog.rename_local(CHECKSUM, "register:EAX@0x40104b", "hash")
        text = prog.decompile(CHECKSUM).text
        assert "/* FNV prime */" in text and "hash = (hash ^ *pbVar1) * 0x1000193;" in text
        [row] = prog.listing(0x401055, max_rows=1).rows
        assert row.comments[0].text == "FNV prime"
        mine = prog.assertions(actor="user:carol")
        assert len(mine) == 2
        prog.revert(kind="user", id="carol")
        assert "uVar2" in prog.decompile(CHECKSUM).text


def test_browser_protocol_from_python(daemon):
    """The Connect endpoint answers plain JSON POSTs, as a browser fetch() would."""
    req = urllib.request.Request(
        daemon.http_url + "/revkit.v1.QueryService/GetFunction",
        data=json.dumps({"programId": "demo/hello", "address": {"offset": str(MAIN)}}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        body = json.loads(resp.read())
    assert body["function"]["name"] == "main"
    assert int(body["snapshot"]["revision"]) >= 1
