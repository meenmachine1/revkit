"""The MCP server's equate and reference tools (api_minor 39, features
"equates" and "user-references"): convert_operand, set_equate (a name and an
enum member), list_equates, rename_equate, remove_equate, add_reference,
set_primary_reference and remove_reference as an agent, with provenance and
undo_changes, on test_equates.py's program."""

import json

import pytest

mcp_client = pytest.importorskip("mcp.client.client")
anyio = pytest.importorskip("anyio")

from revkit import Client, Daemon  # noqa: E402
from revkit.mcp_server import create_server  # noqa: E402

from test_equates import COLOR, compile_target, scalar_in, sym  # noqa: E402


def _json(result):
    assert not result.is_error, result
    return json.loads(result.content[0].text)


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_equate_and_reference_tools(image_daemon, tmp_path):
    target = compile_target(tmp_path)
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        pid = rk.import_program("default", path=str(target)).program.program_id
        prog = rk.program(pid)
        prog.import_header(COLOR, actor=None, categories="none")
        is_a, add7, weigh = (sym(prog, n) for n in ("is_a", "add7", "weigh"))
        cmp, op = scalar_in(prog, is_a, 0x41)
        ten, _ = scalar_in(prog, sym(prog, "is_ncolors"), 10)
        seven, _ = scalar_in(prog, add7, 7)
        imul, imul_op = scalar_in(prog, weigh, 0x1234)
        table = sym(prog, "table_g")
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-equates")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                r = _json(await mcp.call_tool(tool, args))
                assert "error" not in r, (tool, r)
                return r

            async def listing(addr):
                return (await call("disassemble", program_id=pid, address=hex(addr), max_rows=1))["listing"]

            async def decompiled(entry):
                return (await call("decompile", program_id=pid, function_address=hex(entry)))["c"]

            tools = {t.name for t in (await mcp.list_tools()).tools}
            assert {"convert_operand", "set_equate", "list_equates", "rename_equate", "remove_equate",
                    "add_reference", "remove_reference", "set_primary_reference"} <= tools

            # Convert to char, in both views; undo.
            c = await call("convert_operand", program_id=pid, address=hex(cmp), value="0x41", format="char",
                           reason="compares with a letter")
            assert c["provenance"] == "agent:claude@test" and c["seq"] in c["seqs"]
            assert c["operands"] == [{"address": hex(cmp), "operand": op}]
            assert "'A'" in await listing(cmp) and "'A'" in await decompiled(is_a)
            await call("undo_changes", program_id=pid, seqs=c["seqs"], reason="back")
            assert "0x41" in await listing(cmp)

            # Equates: a name (refused for a second value), an enum member found by value.
            await call("set_equate", program_id=pid, address=hex(seven), value=7, name="SEVEN", reason="a week")
            bad = _json(await mcp.call_tool("set_equate", {"program_id": pid, "address": hex(cmp), "value": "0x41",
                                                           "name": "SEVEN", "reason": "x"}))
            assert bad["error"] == "INVALID_ARGUMENT" and "already has the value" in bad["message"]
            enums = await call("find_types", program_id=pid, enum_value="0xa")
            assert "color" in [t["name"] for t in enums["types"]]
            await call("set_equate", program_id=pid, address=hex(ten), value=10, enum="color", member="NCOLORS",
                       reason="the number of colors")
            assert "NCOLORS" in await listing(ten)
            eqs = {e["name"]: e for e in (await call("list_equates", program_id=pid))["equates"]}
            assert set(eqs) == {"SEVEN", "NCOLORS"} and eqs["SEVEN"]["value"] == "0x7"
            assert eqs["NCOLORS"]["member"] == "NCOLORS" and eqs["SEVEN"]["references"][0]["address"] == hex(seven)
            renamed = await call("rename_equate", program_id=pid, name="SEVEN", new_name="WEEK", reason="clearer")
            assert "WEEK" in await listing(seven) and "WEEK" in await decompiled(add7)
            await call("undo_changes", program_id=pid, seqs=renamed["seqs"], reason="back")
            assert "SEVEN" in await listing(seven)
            gone = await call("remove_equate", program_id=pid, name="NCOLORS", reason="not colors after all")
            assert "0xa" in await listing(ten)
            assert {e["name"] for e in (await call("list_equates", program_id=pid))["equates"]} == {"SEVEN"}
            await call("undo_changes", program_id=pid, seqs=gone["seqs"], reason="back")
            assert "NCOLORS" in await listing(ten)

            # References: a primary data reference shows its target; an analysis call deleted, then undone.
            ref = await call("add_reference", program_id=pid, from_address=hex(imul), to_address=hex(table),
                             type="read", operand=imul_op, primary=True, reason="indexes table_g")
            assert "table_g" in await listing(imul)
            xs = (await call("xrefs", program_id=pid, address=hex(table)))["xrefs"]
            x = next(x for x in xs if x["from"] == hex(imul))
            assert x["primary"] and x["added_by"] == "agent:claude@test" and x["seq"] == ref["seq"]
            await call("set_primary_reference", program_id=pid, from_address=hex(imul), to_address=hex(table),
                       primary=False, reason="show the number")
            assert "table_g" not in await listing(imul)
            frm = next(x["from"] for x in (await call("xrefs", program_id=pid, address=hex(is_a)))["xrefs"]
                       if x["from_function"] == "main")
            cut = await call("remove_reference", program_id=pid, from_address=frm, to_address=hex(is_a),
                             reason="testing")
            assert all(x["from"] != frm for x in (await call("xrefs", program_id=pid, address=hex(is_a)))["xrefs"])
            await call("undo_changes", program_id=pid, seqs=cut["seqs"], reason="back")
            assert any(x["from"] == frm for x in (await call("xrefs", program_id=pid, address=hex(is_a)))["xrefs"])

            mine = await call("list_my_changes", program_id=pid)
            kinds = [c["key"]["kind"] for c in mine["changes"]]
            assert "FACT_KIND_EQUATE" in kinds and "FACT_KIND_REFERENCE" in kinds, kinds

    anyio.run(run)
