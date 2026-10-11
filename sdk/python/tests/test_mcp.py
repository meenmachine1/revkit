"""The MCP server over an in-memory MCP session against a real rk-daemon."""

import json

import pytest

mcp_client = pytest.importorskip("mcp.client.client")
anyio = pytest.importorskip("anyio")

from revkit import Client, format_provenance  # noqa: E402
from revkit.mcp_server import create_server  # noqa: E402


def _json(result):
    assert not result.is_error, result
    return json.loads(result.content[0].text)


def test_agent_reads_renames_and_reverts(daemon):
    server = create_server(daemon.grpc_target, agent="claude", agent_version="test", session="mcp-test")

    async def run():
        async with mcp_client.Client(server) as mcp:
            tools = {t.name for t in (await mcp.list_tools()).tools}
            assert {"decompile", "rename", "set_comment", "list_functions", "blame"} <= tools

            programs = _json(await mcp.call_tool("list_programs", {}))
            program = programs["projects"][0]["programs"][0]["program_id"]
            fns = _json(await mcp.call_tool("list_functions", {"program_id": program}))
            assert {"address": "0x401040", "name": "FUN_00401040"}.items() <= fns["functions"][2].items()

            dec = _json(await mcp.call_tool("decompile", {"program_id": program, "function_address": "0x401040"}))
            assert "0x1000193" in dec["c"]
            local = next(v for v in dec["variables"] if v["name"] == "uVar2")

            done = _json(await mcp.call_tool(
                "rename", {"program_id": program, "address": "0x401040", "new_name": "fnv1a_32", "reason": "FNV-1a constants"}))
            assert done["provenance"] == "agent:claude@test"
            _json(await mcp.call_tool("rename_variable", {
                "program_id": program, "function_address": "0x401040", "storage_key": local["storage_key"],
                "new_name": "hash", "reason": "accumulator"}))
            _json(await mcp.call_tool("set_comment", {
                "program_id": program, "address": "0x401055", "text": "FNV prime", "reason": "constant 0x1000193"}))

            listing = _json(await mcp.call_tool("disassemble", {"program_id": program, "address": "0x401050", "max_rows": 3}))
            assert "FNV prime" in listing["listing"]

            # Errors come back as data the model can read.
            bad = _json(await mcp.call_tool("rename", {"program_id": program, "address": "0x900000", "new_name": "x", "reason": "r"}))
            assert bad["error"] == "INVALID_ARGUMENT"

            blame = _json(await mcp.call_tool("blame", {"program_id": program, "address": "0x401040"}))
            assert blame["set_by"] == "agent:claude@test" and blame["candidates"][0]["reason"] == "FNV-1a constants"

            # A human sees the agent's edits with agent provenance, then the agent reverts its run.
            with Client(daemon.grpc_target, actor="user:reviewer") as rk:
                prog = rk.program(program)
                edits = prog.assertions(actor="agent:claude", session="mcp-test")
                assert len(edits) == 3
                assert all(format_provenance(a.provenance) == "agent:claude@test" for a in edits)
                assert prog.function(0x401040).name == "fnv1a_32"

            reverted = _json(await mcp.call_tool("revert_my_changes", {"program_id": program}))
            assert reverted["retracted"] == 3
            with Client(daemon.grpc_target) as rk:
                assert rk.program(program).function(0x401040).name == "FUN_00401040"

    try:
        anyio.run(run)
    finally:
        server.revkit_client.close()
