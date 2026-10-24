"""EVM contracts (api_minor 99, feature "evm"; docs/evm.md) through the SDK and
MCP: OpenZeppelin's compiled ERC-20 and ERC-721 (tests/data/evm, MIT), imported
as hex text, their functions named by selector, decompiled with revkit's EVM
processor; and the table of well-known signatures checked against keccak256."""

import json
import re
from pathlib import Path

import pytest

from revkit import Client, Daemon, unknown_dict
from revkit.v1 import common_pb2

DATA = Path(__file__).resolve().parents[3] / "tests" / "data" / "evm"
EVM_CC = Path(__file__).resolve().parents[3] / "src" / "evm" / "evm.cc"

# Keccak-256 as Ethereum uses it (the original padding, not SHA3-256's).
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(x, n):
    return ((x << n) | (x >> (64 - n))) & _M if n else x


def keccak256(data: bytes) -> bytes:
    rate = 136
    p = bytearray(data) + b"\x01"
    while len(p) % rate:
        p += b"\x00"
    p[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for i in range(0, len(p), rate):
        for j in range(rate // 8):
            a[j % 5][j // 5] ^= int.from_bytes(p[i + 8 * j:i + 8 * j + 8], "little")
        for rc in _RC:
            c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
            d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
            a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
            a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
            a[0][0] ^= rc
    return b"".join(a[j % 5][j // 5].to_bytes(8, "little") for j in range(4))


def test_keccak_and_the_signature_table():
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    table = re.findall(r'\{0x([0-9a-f]{8}), "([^"]+)", "[^"]+"\}', EVM_CC.read_text())
    assert len(table) >= 30
    for selector, signature in table:
        assert keccak256(signature.encode())[:4].hex() == selector, signature


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_contracts_import_name_and_decompile(image_daemon):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        info = rk.server_info()
        assert "evm" in info.features and info.api_minor >= 99
        pid = rk.import_program("default", path=str(DATA / "erc20.creation.hex")).program.program_id
        prog = rk.program(pid)
        s = prog.summary()
        assert s.info.format == "evm" and s.language.language_id == "EVM:BE:32:default"
        assert s.evm.creation and s.evm.runtime_size == 2140
        sigs = {f.name: f.signature for f in s.evm.functions}
        assert sigs["transfer"] == "transfer(address,uint256)" and len(sigs) == 11
        assert s.evm.resolved_jumps == s.evm.jumps and s.evm.unresolved_jumps == 0
        names = {f.name: f.entry.offset for f in prog.functions()}
        assert {"dispatcher", "constructor", "transfer", "balanceOf"} <= set(names)
        fn = prog.decompile(names["transfer"])
        jumps = (common_pb2.UNKNOWN_KIND_INDIRECT_JUMP, common_pb2.UNKNOWN_KIND_INDIRECT_CALL)
        assert not [unknown_dict(u) for u in fn.unknowns if u.kind in jumps]  # every jump's target is known
        # transfer's body: the balance mapping (keccak256 of the key), sstore, the Transfer event's topic.
        assert "keccak256" in fn.text and "sstore" in fn.text and "0xddf252ad" in fn.text, fn.text
        assert "0xa9059cbb" in prog.decompile(0).text
        # Runtime code as a binary file works the same; a JUMPDEST is labelled tag_<offset>.
        raw = bytes.fromhex((DATA / "erc721.runtime.hex").read_text().strip()[2:])
        pid2 = rk.import_program("default", content=raw, name="erc721.bin").program.program_id
        s2 = rk.program(pid2).summary()
        assert s2.info.format == "evm" and not s2.evm.creation
        assert any(sym.name.startswith("tag_") for sym in rk.program(pid2).symbols("tag_"))


mcp_client = pytest.importorskip("mcp.client.client")
anyio = pytest.importorskip("anyio")


def test_mcp_program_summary_and_functions(image_daemon):
    from revkit.mcp_server import create_server

    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-evm")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                r = json.loads((await mcp.call_tool(tool, args)).content[0].text)
                assert "error" not in r, (tool, r)
                return r

            imp = await call("import_program", project_id="default", path=str(DATA / "erc721.creation.hex"),
                             name="erc721")
            pid = imp["program"]["program_id"]
            s = await call("program_summary", program_id=pid)
            evm = s["evm"]
            assert evm["creation"] and {"ownerOf", "safeTransferFrom", "supportsInterface"} <= {
                f["name"] for f in evm["functions"]}
            assert evm["jumps"]["resolved"] >= evm["jumps"]["total"] - 1
            assert s["evidence"]["provenance"]["evm.functions[].signature"]["tier"] == "guessed"
            fns = await call("list_functions", program_id=pid, name_contains="ownerOf")
            assert fns["functions"][0]["named_by"] == "analysis:evm"
            dec = await call("decompile", program_id=pid, function_address="ownerOf")
            assert "sload" in dec["c"], dec["c"]

    try:
        anyio.run(run)
    finally:
        server.revkit_client.close()
