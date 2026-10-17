"""Data settings (api_minor 84, feature "data-settings";
docs/listing-edit.md#data-settings) through the SDK and MCP on the image
backend: an item, a struct field and a type's defaults, strings in another
charset, pointers as image-base offsets, undo; and compatibility: a project
written before data settings (fixtures/pre_data_settings.rkproj, made by
master at api_minor 83) loads with its listing unchanged, and, with
RK_OLD_DAEMON set to such a daemon, a project with settings exported here
imports there and shows as before."""

import json
import os
from pathlib import Path

import pytest

from revkit import Client, Daemon, InvalidArgument, data_settings, data_settings_body
from revkit.v1 import assertion_pb2, common_pb2, listing_pb2

from fixtures.make_pre_data_settings import BASE, LANGUAGE, listing, program

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture()
def rk(image_daemon):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as c:
        yield c


@pytest.fixture()
def prog(rk):
    pid = rk.import_program("default", content=program(), name="settings.bin", format="raw", language_id=LANGUAGE,
                            image_base=BASE).program.program_id
    p = rk.program(pid)
    p.define_data(BASE + 0x100, "int")
    p.define_data(BASE + 0x110, string="utf8")
    p.define_data(BASE + 0x120, "struct pair { int a; short b; short c; }")
    p.define_data(BASE + 0x130, "uint32_t", count=4)
    p.define_data(BASE + 0x140, "char *")
    p.define_data(BASE + 0x158, string="utf8")
    return p


def row(prog, addr, field=""):
    for r in prog.listing(addr, max_rows=12).rows:
        if (r.data_field == field and (field or (r.address.offset == addr and not r.HasField("data_parent")))
                and r.kind != listing_pb2.LISTING_ROW_KIND_HEADER):
            return r
    raise AssertionError(f"no row at {addr:#x} {field!r}")


def value(r) -> str:
    return "".join(t.text for t in r.tokens if t.kind == listing_pb2.LISTING_TOKEN_KIND_DATA_VALUE)


def target(r) -> int:
    return next(t.target.offset for t in r.tokens if t.HasField("target"))


def test_pre_change_project_loads_unchanged(rk):
    """A project written before data settings shows the same listing, keeps its notes, and carries no settings."""
    resp = rk.import_project(FIXTURES / "pre_data_settings.rkproj", name="pre-data-settings")
    assert len(resp.programs) == 1
    prog = rk.program(resp.programs[0].program.program_id)
    expected = json.loads((FIXTURES / "pre_data_settings.listing.json").read_text())
    assert listing(prog) == expected
    rows = prog.listing(BASE + 0x100, max_rows=40).rows
    assert not any(r.HasField("data_settings") or r.HasField("data_type_settings") for r in rows)
    assert {r.data_settings_type for r in rows if r.kind == listing_pb2.LISTING_ROW_KIND_DATA} >= {"int", "string", "uint32_t"}
    notes = [a for a in prog.assertions(kinds=["note"]) if a.body.WhichOneof("kind") == "note"]
    assert [(n.body.note.tag, n.body.note.text) for n in notes] == [("todo", "check these")]


def test_an_item_a_field_and_a_type(prog):
    threshold = BASE + 0x100
    assert value(row(prog, threshold)) == "12345678h"
    dec = prog.set_data_settings(threshold, format="decimal", reason="it is a count")
    a = dec.assertions[0]
    assert a.key.kind == common_pb2.FACT_KIND_NOTE and a.key.sub == "revkit:data-settings"
    assert a.body.data_settings.settings.format == assertion_pb2.DATA_FORMAT_DECIMAL
    r = row(prog, threshold)
    assert value(r) == "305419896"
    assert r.data_settings.format == assertion_pb2.DATA_FORMAT_DECIMAL
    assert r.data_settings_origin.asserted.provenance.id == "alice"
    big = prog.set_data_settings(threshold, endian="big", padding="padded")
    assert value(row(prog, threshold)) == "78563412h"
    prog.retract(*[x.seq for x in big.assertions])
    prog.retract(*[x.seq for x in dec.assertions])
    assert value(row(prog, threshold)) == "12345678h"
    assert not row(prog, threshold).HasField("data_settings")

    # A struct field's own, and every int (the struct's int field too).
    pair = BASE + 0x120
    prog.set_data_settings(pair, "b", format="binary")
    assert value(row(prog, pair, "b")) == "10b"
    assert value(row(prog, pair, "c")) == "3h"
    ints = prog.set_type_data_settings("int", format="octal", padding="padded")
    assert value(row(prog, pair, "a")) == "00000000001o"
    assert value(row(prog, threshold)) == "02215053170o"
    assert row(prog, threshold).data_type_settings.format == assertion_pb2.DATA_FORMAT_OCTAL
    prog.retract(*[x.seq for x in ints.assertions])
    assert value(row(prog, pair, "a")) == "1h"

    # An array's elements, by the item's.
    prog.set_data_settings(BASE + 0x130, format="decimal")
    assert value(row(prog, BASE + 0x130)) == "{10, 20, 30, 40}"


def test_strings_and_pointers(prog):
    cafe = BASE + 0x158
    plain = value(row(prog, cafe))
    assert plain == '"caf\\xe9"'  # not UTF-8: escaped
    prog.set_data_settings(cafe, charset="latin1")
    assert value(row(prog, cafe)) == '"café"'
    prog.set_data_settings(cafe, charset="US-ASCII")
    assert value(row(prog, cafe)) == '"caf\\xe9"'
    prog.set_data_settings(cafe)  # none: removed
    assert value(row(prog, cafe)) == plain

    ptr = BASE + 0x140
    assert target(row(prog, ptr)) == BASE + 0x110
    prog.set_data_settings(ptr, pointer="image-base", mask=0xff)
    assert target(row(prog, ptr)) == BASE + 0x10
    prog.set_type_data_settings("string", termination="all")
    assert value(row(prog, BASE + 0x110)) == '"hello fixture\\0"'  # every character: its terminator too


def test_refusals(prog):
    with pytest.raises(ValueError, match="format is one of"):
        data_settings(format="roman")
    with pytest.raises(ValueError, match="give an address"):
        data_settings_body()
    with pytest.raises(InvalidArgument, match="charset"):
        prog.set_data_settings(BASE + 0x100, charset="EBCDIC")
    with pytest.raises(InvalidArgument, match="reserved"):
        prog.note(BASE + 0x100, "format=decimal", tag="revkit:data-settings")


def test_mcp_set_data_settings(image_daemon, prog):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-settings")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                r = await mcp.call_tool(tool, args)
                assert not r.is_error, r
                return json.loads(r.content[0].text)

            out = await call("set_data_settings", program_id=prog.id, address=hex(BASE + 0x100), format="decimal",
                             signed=True, reason="a signed count")
            assert "error" not in out and out["provenance"] == "agent:claude@test", out
            assert value(row(prog, BASE + 0x100)) == "305419896"
            types = await call("set_data_settings", program_id=prog.id, type_name="uint32_t", format="decimal",
                               reason="counts")
            assert "error" not in types, types
            assert value(row(prog, BASE + 0x130)) == "{10, 20, 30, 40}"
            both = await call("set_data_settings", program_id=prog.id, address=hex(BASE + 0x100), type_name="int",
                              reason="x")
            assert "error" in both, both
            await call("undo_changes", program_id=prog.id, seqs=out["seqs"] + types["seqs"], reason="back")
            assert value(row(prog, BASE + 0x100)) == "12345678h"

    anyio.run(run)


@pytest.mark.skipif(not os.environ.get("RK_OLD_DAEMON"), reason="RK_OLD_DAEMON: a daemon from before data settings")
def test_an_older_daemon_imports_a_project_with_settings(prog, rk, tmp_path):
    """Settings are NOTE keys: an older daemon imports the archive and shows the rows as it always did."""
    # (Not the Latin-1 string: an older daemon sends it as invalid UTF-8, which the client refuses.)
    prog.clear_code(BASE + 0x158, 5)
    expected_rows = listing(prog)
    prog.set_data_settings(BASE + 0x100, format="decimal")
    prog.set_type_data_settings("uint32_t", format="binary")
    prog.set_data_settings(BASE + 0x120, "b", format="octal")
    assert listing(prog) != expected_rows
    archive = tmp_path / "with-settings.rkproj"
    rk.export_project("default", archive, programs=[prog.id])
    old_bin = os.environ["RK_OLD_DAEMON"]
    with Daemon(old_bin, "--backend", "image", startup_timeout=60) as old, Client(old.grpc_target, actor="user:bob") as o:
        assert "data-settings" not in o.server_info().features
        resp = o.import_project(archive, name="from-newer")
        old_prog = o.program(resp.programs[0].program.program_id)
        assert listing(old_prog) == expected_rows
