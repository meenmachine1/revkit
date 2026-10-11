"""The byte viewer's read, the overview and next/previous by kind
(api_minor 44, features "byte-viewer", "overview", "find-next") through
the SDK helpers, on the image backend with tests/fixtures/script_target.c."""

import pytest

from revkit import Client, Daemon
from revkit.v1 import query_pb2


@pytest.fixture(scope="module")
def daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_byte_view_overview_find_next(daemon, script_target):
    with Client(daemon.grpc_target, actor="user:tester") as rk:
        assert {"byte-viewer", "overview", "find-next"} <= set(rk.server_info().features)
        prog = rk.program(rk.import_program("default", path=str(script_target["plain"])).program.program_id)
        fns = {f.name: f.entry.offset for f in prog.functions()}
        main = fns["main"]

        view = prog.byte_view(main, 32)
        assert view.data == prog.read_memory(main, 32)
        assert not view.patched
        first = view.runs[0]
        assert first.start.offset == main and first.kind == query_pb2.BYTE_KIND_CODE
        assert first.length == prog.listing(main, max_rows=1).rows[0].length

        overview = prog.overview(64)
        assert overview.total_bytes == sum(b.length for b in overview.buckets)
        text = [b for b in overview.buckets if b.block == ".text"]
        assert text and any(b.code for b in text)
        bss = [b for b in overview.buckets if b.block == ".bss"]
        assert bss and all(b.entropy == 0 and b.code == 0 for b in bss) and any(b.uninitialized for b in bss)

        entries = sorted(fns.values())
        i = entries.index(main)
        if i + 1 < len(entries):
            assert prog.find_next(main, "function") == entries[i + 1]
        if i > 0:
            assert prog.find_next(main, "function", backward=True) == entries[i - 1]
        nxt = prog.find_next(main, "different_byte")
        assert nxt is not None and prog.read_memory(nxt, 1) != prog.read_memory(main, 1)
        assert prog.find_next(0, "note") is None
