"""The memory map after import through the SDK (api_minor 24, feature
"memory-map"): regions added, changed and removed, undo, and their effect on
references and the decompiler. The firmware is hand-assembled ARM (as in
src/backend/tests/memory_map_test.cc):

  0x00  b main; the other vectors b .
  0x20  main:       push {lr}; bl read_ram; bl read_const; bl 0x100000; pop {pc}
  0x40  read_ram:   ldr r0, =0x20000000; ldr r0, [r0]; bx lr
  0x50  read_const: ldr r0, =0x80000; ldr r0, [r0]; bx lr
"""

import struct

import pytest

from revkit import Client, Daemon, InvalidArgument, NotFound
from revkit.v1 import project_pb2


def words(*ws):
    return b"".join(struct.pack("<I", w) for w in ws)


FIRMWARE = (
    words(0xEA000006, *[0xEAFFFFFE] * 7)
    + words(0xE52DE004, 0xEB000005, 0xEB000008, 0xEB03FFF3, 0xE49DF004, 0, 0, 0)
    + words(0xE59F0004, 0xE5900000, 0xE12FFF1E, 0x20000000)
    + words(0xE59F0004, 0xE5900000, 0xE12FFF1E, 0x00080000)
).ljust(0x100, b"\0")
CONSTANTS = b"C" * 0x10 + words(0x12345678)
BOOT = words(0xE3A00007, 0xE12FFF1E)  # mov r0, #7; bx lr


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture()
def prog(image_daemon):
    # Generous: the first decompilation starts a worker (slow under sanitizers).
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as rk:
        # Read-only flash, so its literal pools are constants.
        opts = project_pb2.ImportOptions(format="raw", language_id="ARM:LE:32:v4t", raw_permissions="r-x")
        req = project_pb2.ImportProgramRequest(project_id="default", name="fw.bin", content=FIRMWARE, options=opts)
        resp = rk.stubs.projects.ImportProgram(req)
        yield rk.program(resp.program.program_id)


def test_feature(image_daemon):
    with Client(image_daemon.grpc_target) as rk:
        info = rk.server_info()
        assert "memory-map" in info.features and info.api_minor >= 24


def test_regions_change_analysis_and_undo(prog):
    assert [b.name for b in prog.memory_map()] == ["ram"]
    assert prog.xrefs_to(0x20000000) == []
    assert "0x12345678" not in prog.decompile(0x50).text

    ram = prog.add_memory_region("sram", 0x20000000, 0x1000)
    assert ram.region_id and ram.assertion.seq
    assert prog.xrefs_to(0x20000000)
    assert "DAT_20000000" in prog.decompile(0x40).text

    rom = prog.add_memory_region("consts", 0x80000, perms="r--", content=CONSTANTS, file_name="consts.bin",
                                 file_offset=0x10, length=4)
    assert rom.block.source.file == "consts.bin" and rom.block.range.last.offset == 0x80003
    assert prog.read_memory(0x80000, 4) == words(0x12345678)
    assert "return 0x12345678;" in prog.decompile(0x50).text
    prog.update_memory_region(rom.region_id, volatile=True)
    assert "0x12345678" not in prog.decompile(0x50).text

    boot = prog.add_memory_region("boot", 0x100000, perms="r-x", content=BOOT)
    assert any(f.entry.offset == 0x100000 for f in prog.functions())
    prog.retract(boot.assertion.seq)  # undo
    assert not any(f.entry.offset == 0x100000 for f in prog.functions())

    gone = prog.remove_memory_region(ram.region_id)
    assert prog.xrefs_to(0x20000000) == []
    prog.retract(gone.assertion.seq)
    assert prog.xrefs_to(0x20000000)

    names = [b.name for b in prog.memory_map()]
    assert names == ["ram", "consts", "sram"]
    blame = prog.blame(prog.key("memory_region", 0, "region:" + ram.region_id))
    assert blame.value_text.startswith("sram 0x20000000-0x20000fff rw-")


def test_image_blocks_and_validation(prog):
    with pytest.raises(InvalidArgument, match=r"overlaps block ram \[0x0, 0xff\]"):
        prog.add_memory_region("low", 0x80, 0x100)
    with pytest.raises(InvalidArgument, match="past the top of the 32-bit address space"):
        prog.add_memory_region("top", 0xFFFFF000, 0x2000)
    prog.add_memory_region("check", 0x30000, 0x10, validate_only=True)
    assert [b.name for b in prog.memory_map()] == ["ram"]

    edited = prog.update_memory_region(0, name="flash", perms="r-x")
    assert edited.block.edited and edited.block.name == "flash"
    with pytest.raises(InvalidArgument):
        prog.update_memory_region(0, start=0x10)
    prog.remove_memory_region(0)  # reverts the edits
    assert prog.memory_map()[0].name == "ram"
    with pytest.raises(NotFound):
        prog.remove_memory_region("no-such-region")
