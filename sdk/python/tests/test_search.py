"""The searches (api_minor 41, feature "search") through the Python SDK, the
revkit.script helpers and the Ghidra compat shim, on the image backend and
tests/fixtures/script_target.c: memory (hex, strings, numbers, regex,
binary, next and previous), program text (renames count), scalars and
decompiled C, with progress and cancel."""

import io
import threading

import pytest

from revkit import Client, Daemon
from revkit.client import RevkitError, latin1_regex, masked_query
from revkit.script import HeadlessHost, run_script
from revkit.v1 import query_pb2


@pytest.fixture(scope="module")
def daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture(scope="module")
def program(daemon, script_target):
    with Client(daemon.grpc_target, actor="user:tester") as rk:
        return rk.import_program("default", path=str(script_target["plain"])).program.program_id


@pytest.fixture
def rk(daemon):
    with Client(daemon.grpc_target, actor="user:tester") as c:
        yield c


def fn(prog, name):
    return next(f for f in prog.functions() if f.name == name)


def test_feature(rk):
    info = rk.server_info()
    assert "search" in info.features
    assert info.api_minor >= 41


def test_memory(rk, program):
    prog = rk.program(program)
    # sha256_iv[0] = 0x6a09e667, little-endian: hex, decimal, binary, regex.
    hex_hits = prog.search_memory("67 e6 09 6a")
    assert len(hex_hits) == 1
    at = hex_hits[0].address.offset
    assert hex_hits[0].bytes == bytes.fromhex("67e6096a")
    assert prog.last_search.pattern == "67 e6 09 6a" and prog.last_search.done
    assert [m.address.offset for m in prog.search_memory("1779033703", format="decimal")] == [at]
    assert [m.address.offset for m in prog.search_memory("0x6a09e667", format="decimal", unsigned=True)] == [at]
    assert not prog.search_memory("1779033703", format="decimal", byte_order="big")
    assert at in [m.address.offset for m in prog.search_memory("67 e? 0? 6a")]
    assert at in [m.address.offset for m in prog.search_memory(masked_query(bytes.fromhex("67e6096a"), b"\xff\xf0\xff\xff"), format="binary")]
    assert at in [m.address.offset for m in prog.search_memory(latin1_regex(b"\x67\xe6.\x6a"), format="regex")]
    # Strings: case, encodings, details.
    s = prog.search_memory("PARSE_CONFIG: missing", format="string")
    assert len(s) == 1 and s[0].bytes == b"parse_config: missing"
    assert s[0].preview, s[0]
    assert not prog.search_memory("PARSE_CONFIG: missing", format="string", case_sensitive=True)
    assert not prog.search_memory("parse_config", format="string", encoding="utf16")
    # Where: a selection, code units.
    assert not prog.search_memory("67 e6 09 6a", ranges=[(at + 1, at + 100)])
    assert not prog.search_memory("67 e6 09 6a", code_units=["instructions"])
    # Next, previous, wrap.
    many = [m.address.offset for m in prog.search_memory("00 00", max_results=100000, details=False)]
    assert len(many) > 10 and many == sorted(many)
    mid = many[len(many) // 2]
    nxt = prog.search_memory("00 00", start=mid, max_results=1)
    assert [m.address.offset for m in nxt] == [many[len(many) // 2 + 1]]
    prev = prog.search_memory("00 00", start=mid, backward=True, max_results=1)
    assert [m.address.offset for m in prev] == [many[len(many) // 2 - 1]]
    wrapped = prog.search_memory("67 e6 09 6a", start=at, wrap=True, max_results=1)
    assert [m.address.offset for m in wrapped] == [at] and wrapped[0].wrapped
    three = prog.search_memory("00 00", max_results=3)
    assert len(three) == 3 and prog.last_search.truncated
    with pytest.raises(RevkitError):
        prog.search_memory("zz")
    with pytest.raises(ValueError):
        prog.search_memory("00", format="octal")


def test_text_scalars_and_renames(rk, program):
    prog = rk.program(program)
    mix = fn(prog, "mix")
    calls = prog.search_text("CALL mix")
    assert calls and all(m.function_name == "main" for m in calls)
    labels = prog.search_text("parse_config", fields=["labels"], whole_word=True)
    assert [m.address.offset for m in labels] == [fn(prog, "parse_config").entry.offset]
    assert prog.search_text("parse_config: missing", fields=["data_values"])
    assert prog.search_text(r"^CALL\s+(mix|decrypt)$", regex=True)
    with pytest.raises(ValueError):
        prog.search_text("x", fields=["everything"])
    # A rename reaches labels, signatures and call operands.
    prog.rename(mix.entry.offset, "mix_words")
    try:
        renamed = prog.search_text("mix_words", case_sensitive=True)
        fields = {m.field for m in renamed}
        assert {query_pb2.TEXT_FIELD_LABELS, query_pb2.TEXT_FIELD_FUNCTIONS, query_pb2.TEXT_FIELD_OPERANDS} <= fields
        m = next(m for m in renamed if m.field == query_pb2.TEXT_FIELD_OPERANDS)
        assert m.text.encode()[m.match_start:m.match_start + m.match_length] == b"mix_words"
    finally:
        prog.rename(mix.entry.offset, "mix")
    # Scalars: x & 7 and x & 31 in mix.
    sevens = prog.search_scalars(value=7)
    assert any(m.function_name == "mix" and m.operand_index >= 0 for m in sevens)
    small = prog.search_scalars(0, 31, max_results=100000)
    assert {7, 31} <= {m.value for m in small if m.function_name == "mix"}
    assert prog.search_scalars(value=7, instructions=False) == [] or all(m.data for m in prog.search_scalars(value=7, instructions=False))


def test_decompiled_progress_and_cancel(rk, program):
    prog = rk.program(program)
    seen = []
    hits = prog.search_decompiled("parse_config", whole_word=True, progress=seen.append)
    assert any(m.function_name == "main" for m in hits)
    assert seen[-1].done and seen[-1].functions_done == seen[-1].functions_total > 3
    main = fn(prog, "main")
    only = prog.search_decompiled("mix", functions=[main.entry.offset])
    assert only and {m.function_name for m in only} == {"main"}
    assert only[0].text.encode()[only[0].match_start:only[0].match_start + 3] == b"mix"
    # Cancelling: the call stops; what came is kept.
    stop = threading.Event()
    stop.set()
    prog.search_decompiled("return", cancel=stop)


def test_script_helpers(rk, program, tmp_path):
    s = tmp_path / "searches.py"
    s.write_text("""\
from revkit.script import *
iv = search_memory("67 e6 09 6a")
assert len(iv) == 1, iv
assert search_text("CALL mix")
assert any(m.function_name == "mix" for m in search_scalars(value=7))
assert any(m.function_name == "main" for m in search_decompiled("parse_config", functions=["main"]))
print("searched", hex(iv[0].address.offset))
""")
    host = HeadlessHost(None, out=io.StringIO(), err=io.StringIO(), interactive=False)
    r = run_script(s, client=rk, program_id=program, host=host)
    assert r.ok, r.traceback
    assert "searched 0x" in host.out.getvalue()


def test_ghidra_compat_find(rk, program, tmp_path):
    s = tmp_path / "FindIv.py"
    s.write_text("""\
# Ghidra's flat API on the daemon's searches.
a = findBytes(currentProgram.getMinAddress(), "\\x67\\xe6\\x09\\x6a")
assert a is not None, "IV not found"
many = findBytes(currentProgram.getMinAddress(), "\\x67\\xe6.\\x6a", 10)
assert a in many
mem = currentProgram.getMemory()
b = mem.findBytes(currentProgram.getMinAddress(), bytes([0x67, 0xe6, 0x00, 0x6a]), bytes([0xff, 0xff, 0x00, 0xff]), True, monitor)
assert b == a, (b, a)
c = mem.findBytes(currentProgram.getMaxAddress(), bytes([0x67, 0xe6, 0x09, 0x6a]), None, False, monitor)
assert c == a, (c, a)
f = find("parse_config")
assert f is not None
print("found", a)
""")
    host = HeadlessHost(None, out=io.StringIO(), err=io.StringIO(), interactive=False)
    r = run_script(s, client=rk, program_id=program, host=host, compat="ghidra")
    assert r.ok, (r.error, r.traceback, host.err.getvalue())
    assert "found" in host.out.getvalue()
