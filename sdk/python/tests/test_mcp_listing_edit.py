"""The MCP server's listing tools (api_minor 30, feature "listing-edit"):
define_data, clear_code, disassemble_here and set_mutability as an agent,
with provenance and undo_changes, on test_listing_edit.py's program."""

import json

import pytest

mcp_client = pytest.importorskip("mcp.client.client")
anyio = pytest.importorskip("anyio")

from revkit import Client, Daemon  # noqa: E402
from revkit.mcp_server import create_server  # noqa: E402

from test_listing_edit import CONSTANT_TEXT, compile_target  # noqa: E402


def _json(result):
    assert not result.is_error, result
    return json.loads(result.content[0].text)


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_listing_tools(image_daemon, tmp_path):
    target = compile_target(tmp_path)
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        pid = rk.import_program("default", path=str(target)).program.program_id
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-listing")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                r = _json(await mcp.call_tool(tool, args))
                assert "error" not in r, (tool, r)
                return r

            async def addr(name):
                return (await call("search_symbols", program_id=pid, name_equals=name))["symbols"][0]["address"]

            async def entries():
                return {f["address"] for f in (await call("list_functions", program_id=pid, limit=1000))["functions"]}

            async def decompiled(name):
                return (await call("decompile", program_id=pid, function_address=await addr(name)))["c"]

            tools = {t.name for t in (await mcp.list_tools()).tools}
            assert {"define_data", "clear_code", "disassemble_here", "set_mutability", "disassemble"} <= tools

            # Define data: an array, shown in list_data's "defined" category.
            table = await addr("table")
            arr = await call("define_data", program_id=pid, address=table, type="uint32_t", count=4,
                             reason="main indexes a table of four words")
            assert arr["provenance"] == "agent:claude@test" and arr["seq"] in arr["seqs"]
            assert arr["size"] == 16 and arr["type_name"] == "uint32_t"
            listed = await call("list_data", program_id=pid, category="defined")
            assert any(d["address"] == table for d in listed["data"]), listed
            s = await call("define_data", program_id=pid, address=await addr("greeting"), string="utf8",
                           reason="printed with %s")
            assert s["size"] == 6
            bad = _json(await mcp.call_tool("define_data", {"program_id": pid, "address": table, "string": "utf7",
                                                            "reason": "x"}))
            assert bad["error"] == "INVALID_ARGUMENT"

            # Clear a function, then disassemble it back as a function.
            helper = await addr("helper")
            size = (await call("get_function", program_id=pid, address=helper))["size"]
            cleared = await call("clear_code", program_id=pid, address=helper, length=int(size), reason="test clear")
            assert helper not in await entries()
            code = await call("disassemble_here", program_id=pid, address=helper, function=True,
                              reason="it is code after all")
            assert helper in await entries()
            await call("undo_changes", program_id=pid, seqs=[code["seq"], cleared["seq"]], reason="back as it was")
            assert helper in await entries()

            # Constant memory folds in the decompiler; undo restores it.
            plain = await decompiled("get_threshold")
            const = await call("set_mutability", program_id=pid, address=await addr("threshold"), length=4,
                               mutability="constant", reason="never written")
            assert const["status"] == "ASSERTION_STATUS_EFFECTIVE", const
            folded = await decompiled("get_threshold")
            assert any(t in folded for t in CONSTANT_TEXT), folded
            await call("undo_changes", program_id=pid, seqs=const["seqs"], reason="it is written after all")
            assert await decompiled("get_threshold") == plain

            # Everything the agent did is listed as its own.
            mine = await call("list_my_changes", program_id=pid, include_inactive=True)
            kinds = [c["key"]["kind"] for c in mine["changes"]]
            assert kinds.count("FACT_KIND_CODE_UNIT") >= 4 and kinds.count("FACT_KIND_MUTABILITY") >= 1, kinds  # with their undos

    anyio.run(run)
