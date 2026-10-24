"""Decompiler output shaped like the source (docs/decompiler-inputs.md,
"Source shape"), through the SDK: load signedness and comparisons as the
instructions encode them, and the tokens of a volatile register and a string
literal carrying their addresses. The firmware is hand-assembled ARM:

  0x00  b main; the other vectors b .
  0x20  main: ldr r1, =0x04000006
  0x24        ldrh r0, [r1]      @ polls a volatile I/O register
  0x28        tst r0, #1
  0x2c        bne 0x24
  0x30        cmp r2, #0
  0x34        ldrgt r0, =msg     @ "shape-string" at 0x48
  0x38        movle r0, #0
  0x3c        bx lr
"""

import struct

import pytest

from revkit import Client, Daemon
from revkit.v1 import decompile_pb2, project_pb2


def words(*ws):
    return b"".join(struct.pack("<I", w) for w in ws)


FIRMWARE = (
    words(0xEA000006, *[0xEAFFFFFE] * 7)
    + words(0xE59F1018, 0xE1D100B0, 0xE3100001, 0x1AFFFFFC, 0xE3520000, 0xC59F0008, 0xD3A00000, 0xE12FFF1E)
    + words(0x04000006, 0x00000048)
    + b"shape-string\0"
).ljust(0x100, b"\0")


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture()
def prog(image_daemon):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as rk:
        opts = project_pb2.ImportOptions(format="raw", language_id="ARM:LE:32:v5t", raw_permissions="r-x")
        req = project_pb2.ImportProgramRequest(project_id="default", name="shape.bin", content=FIRMWARE, options=opts)
        resp = rk.stubs.projects.ImportProgram(req)
        p = rk.program(resp.program.program_id)
        p.add_memory_region("io", 0x04000000, 0x1000, volatile=True)
        # Returns the string (or null): typed, the decompiler prints it.
        p.retype(0x20, "char *poll_name(int a, int b, int n)")
        yield p


def tokens(fn):
    return [t for line in fn.lines for t in line.tokens]


def test_volatile_and_string_tokens_have_targets(prog):
    fn = prog.decompile(0x20)
    toks = tokens(fn)
    reg = [t for t in toks if t.HasField("target") and t.target.offset == 0x04000006]
    assert reg, fn.text
    assert all(t.kind == decompile_pb2.CODE_TOKEN_KIND_GLOBAL_VARIABLE for t in reg), [(t.kind, t.text) for t in reg]
    strings = [t for t in toks if t.kind == decompile_pb2.CODE_TOKEN_KIND_STRING]
    assert strings and all(t.target.offset == 0x48 for t in strings), [(t.text, t.target) for t in strings]


def test_shape_follows_the_instructions(prog):
    text = prog.decompile(0x20).text
    # ldrh: the register is unsigned; the constant on the right (revkit's
    # default comparison form, COMPARISON_FORM_RIGHT).
    assert "ushort" in text or "uint" in text, text
    assert "0 < n" not in text and "1 > n" not in text, text


def test_settings_change_the_shape(prog, image_daemon):
    with Client(image_daemon.grpc_target) as rk:
        info = rk.server_info()
        assert "decompiler-settings" in info.features and info.api_minor >= 106
    prog.set_decompiler_settings(comparison_form="encoded", compilable_c=True)
    text = prog.decompile(0x20).text
    assert "n <= 0" in text or "n > 0" in text, text
    prog.set_decompiler_settings(comparison_form="ghidra", load_types="ghidra")
    text = prog.decompile(0x20).text
    assert "n < 1" in text or "0 < n" in text, text
    with pytest.raises(ValueError):
        prog.set_decompiler_settings(comparison_form="sideways")
    prog.set_decompiler_settings()  # revkit's defaults again
    assert "0 < n" not in prog.decompile(0x20).text
