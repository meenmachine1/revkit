"""The MCP server's memory-map tools (api_minor 24, feature "memory-map"):
memory_map, add_memory_region (RAM, and a file's bytes by path),
update_memory_region, remove_memory_region, and undo, on the hand-assembled
ARM firmware of test_memory_map.py."""

import json

import pytest

mcp_client = pytest.importorskip("mcp.client.client")
anyio = pytest.importorskip("anyio")

from revkit import Client, Daemon  # noqa: E402
from revkit.mcp_server import create_server  # noqa: E402
from revkit.v1 import project_pb2  # noqa: E402

from test_memory_map import BOOT, FIRMWARE  # noqa: E402


def _json(result):
    assert not result.is_error, result
    return json.loads(result.content[0].text)


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_memory_map_tools(image_daemon, tmp_path):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        opts = project_pb2.ImportOptions(format="raw", language_id="ARM:LE:32:v4t", raw_permissions="r-x")
        req = project_pb2.ImportProgramRequest(project_id="default", name="fw.bin", content=FIRMWARE, options=opts)
        pid = rk.stubs.projects.ImportProgram(req).program.program_id
    boot = tmp_path / "boot.bin"
    boot.write_bytes(b"\xff" * 0x20 + BOOT)
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-memory")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                r = _json(await mcp.call_tool(tool, args))
                assert "error" not in r, (tool, r)
                return r

            tools = {t.name for t in (await mcp.list_tools()).tools}
            assert {"memory_map", "add_memory_region", "update_memory_region", "remove_memory_region"} <= tools

            m = await call("memory_map", program_id=pid)
            assert [b["name"] for b in m["blocks"]] == ["ram"] and m["blocks"][0]["source"] == "image"

            ram = await call("add_memory_region", program_id=pid, name="sram", start="0x20000000", size="0x1000",
                             reason="read_ram loads from 0x20000000")
            assert ram["region_id"] and ram["seq"] and ram["provenance"] == "agent:claude@test"
            assert ram["block"]["source"] == "none" and ram["block"]["perms"] == "rw-"

            code = await call("add_memory_region", program_id=pid, name="boot", start="0x100000", perms="r-x",
                              path=str(boot), file_offset="0x20", reason="main calls 0x100000")
            assert code["block"]["file"] == {"name": "boot.bin", "offset": "0x20", "length": 8, "missing": False}
            dec = _json(await mcp.call_tool("decompile", {"program_id": pid, "function_address": "0x100000"}))
            assert "return 7;" in dec["c"], dec

            up = await call("update_memory_region", program_id=pid, region=ram["region_id"], volatile=True,
                            reason="it is MMIO")
            assert up["block"]["volatile"]
            img = await call("update_memory_region", program_id=pid, region="0x0", name="flash", reason="it is flash")
            assert img["block"]["edited"] and img["block"]["name"] == "flash"

            bad = _json(await mcp.call_tool("add_memory_region", {"program_id": pid, "name": "x", "start": "0x80",
                                                                  "size": "0x10", "reason": "overlap"}))
            assert bad["error"] == "INVALID_ARGUMENT" and "overlaps block flash" in bad["message"]

            gone = await call("remove_memory_region", program_id=pid, region=code["region_id"], reason="wrong file")
            assert [b["name"] for b in (await call("memory_map", program_id=pid))["blocks"]] == ["flash", "sram"]
            await call("undo_changes", program_id=pid, seqs=[gone["seq"]], reason="it was the right file")
            m = await call("memory_map", program_id=pid)
            assert [b["name"] for b in m["blocks"]] == ["flash", "boot", "sram"]
            assert all(b["origin"] == "agent:claude@test" for b in m["blocks"])

    anyio.run(run)
