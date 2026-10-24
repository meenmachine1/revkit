"""Function discovery through the daemon, on a stripped binary compiled here:
the functions, names and bodies are the ones `rk-lift --analyze` finds, and
an entry point a user asserts is discovered with what it calls, its listing
rows turn from data into instructions, and the subscription reports the
rows it rebuilt."""

import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from revkit import Client, Daemon
from revkit.v1 import listing_pb2, subscription_pb2

SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>

#if defined(__x86_64__)
/* No symbol once stripped, no unwind entry (no CFI), and only a pointer
   reaches it: discovery can't find hidden() or what it calls. */
__asm__(".text\n.p2align 8\n.globl hidden\n.type hidden, @function\nhidden:\n"
        "  call hidden_inner\n  add $1, %eax\n  ret\n"
        ".p2align 4\nhidden_inner:\n  lea 7(%rdi), %eax\n  ret\n.p2align 8\n");
int hidden(int);
#define HIDDEN hidden
#else
static int hidden_c(int x) { return x + 8; }
#define HIDDEN hidden_c
#endif

int (*volatile hook)(int);
__attribute__((noinline)) static void die(const char *m) { puts(m); exit(2); }
__attribute__((noinline)) static int check(int x) { if (x < 0) die("negative"); return x * 2; }
__attribute__((noinline)) static int op(int k, int v) {
  switch (k) {
    case 0: return v + 1;
    case 1: return v * 3;
    case 2: return v - 7;
    case 3: return v << 2;
    case 4: return v ^ 0x55;
    case 5: return v / 3;
    case 6: return -v;
    default: return 0;
  }
}
int main(int argc, char **argv) {
  hook = HIDDEN;
  int r = check(argc);
  for (int i = 0; argv[0][i]; i++) r = op(argv[0][i] & 7, r);
  printf("%d %d\n", r, hook(r));
  return 0;
}
"""


def _rk_lift():
    if os.environ.get("RK_LIFT"):
        return Path(os.environ["RK_LIFT"])
    daemon = os.environ.get("RK_DAEMON")
    return Path(daemon).parents[1] / "rk-lift" / "rk-lift" if daemon else None


@pytest.fixture(scope="module")
def stripped(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("discovery")
    (d / "prog.c").write_text(SOURCE)
    subprocess.run([cc, "-O2", "-o", str(d / "named"), str(d / "prog.c")], check=True)
    subprocess.run([cc, "-O2", "-s", "-o", str(d / "prog"), str(d / "prog.c")], check=True)
    return d


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_functions_match_rk_lift_analyze(image_daemon, stripped):
    rk_lift = _rk_lift()
    if not rk_lift or not rk_lift.exists():
        pytest.skip("rk-lift not built (set RK_LIFT)")
    out = stripped / "prog.json"
    subprocess.run([str(rk_lift), "--analyze", "--name", "prog", "-o", str(out), str(stripped / "prog")], check=True)
    ref = {
        int(f["entry"], 16): (f["name"], [(int(a, 16), int(b, 16)) for a, b in f["body"]])
        for f in json.loads(out.read_text())["functions"]
    }

    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        assert "function-discovery" in rk.server_info().features
        imported = rk.import_program("default", path=str(stripped / "prog"))
        prog = rk.program(imported.program.program_id)
        got = {f.entry.offset: (f.name, [(r.first.offset, r.last.offset) for r in f.body]) for f in prog.functions()}
        assert got == ref
        # Discovery named the PLT stubs after their imports, and found the
        # switch's jump table: references from its jump to every case.
        names = {name for name, _ in got.values()}
        assert {"puts", "exit"} <= names and any("printf" in n for n in names)  # __printf_chk when fortified
        assert any(
            x.kind == listing_pb2.XREF_KIND_INDIRECT_JUMP
            for entry, (name, body) in got.items()
            for x in prog.xrefs(range=(body[0][0], body[-1][1]), direction="from")
        )
        no_return = [f for f in prog.functions() if f.no_return]
        assert any(f.name == "exit" for f in no_return)


@pytest.mark.skipif(platform.machine() not in ("x86_64", "AMD64"), reason="the hidden function is x86-64 assembly")
def test_asserted_entry_is_discovered_and_rebuilds_rows(image_daemon, stripped):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        # Stripping moves nothing: the unstripped twin says where hidden() is.
        named = rk.program(rk.import_program("default", path=str(stripped / "named"), name="named").program.program_id)
        hidden = {f.name: f.entry.offset for f in named.functions()}["hidden"]

        prog = rk.program(rk.import_program("default", path=str(stripped / "prog"), name="asserted").program.program_id)
        before = {f.entry.offset for f in prog.functions()}
        assert hidden not in before
        page = prog.listing(hidden, max_rows=1)
        assert page.rows[0].kind == listing_pb2.LISTING_ROW_KIND_UNDEFINED

        with rk.subscribe("default", programs=[prog.id]) as sub:
            done = prog.set_function(hidden, reason="only a pointer reaches it")
            # This edit's event: inference publishes its own revision after
            # an import (analysis:infer.prototypes), which may come first.
            event = sub.wait_for(lambda e: e.HasField("revision") and e.revision.revision == done.snapshot.revision).revision

        after = {f.entry.offset: f for f in prog.functions()}
        assert hidden in after
        assert len(after) == len(before) + 2  # hidden() and the function it calls
        assert after[hidden].bounds_origin.HasField("asserted")
        now = prog.listing(hidden, max_rows=1)
        assert now.rows[0].kind == listing_pb2.LISTING_ROW_KIND_INSTRUCTION
        assert now.rows[0].function_entry

        # The event names the rows rebuilt, with their windows on both sides;
        # the row count moved by exactly what they say.
        windows = [q for q in event.invalidated if q.kind == subscription_pb2.QUERY_KIND_LISTING and q.HasField("rows")]
        assert any(q.range.first.offset <= hidden <= q.range.last.offset for q in windows)
        assert now.total_rows - page.total_rows == sum(q.rows.row_count - q.previous_rows.row_count for q in windows)
        assert any(q.kind == subscription_pb2.QUERY_KIND_FUNCTION and q.address.offset == hidden for q in event.invalidated)
        assert "FUN_" in prog.decompile(hidden).text
