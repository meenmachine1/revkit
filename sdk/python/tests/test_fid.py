"""Function ID through the SDK (api_minor 51, feature "function-id";
docs/fid.md): a database made from one program that links a small static
library names that library's functions in another, stripped program;
reject, apply, detach; the builtin (Ghidra's) databases are listed."""

import shutil
import subprocess

import pytest

from revkit import Client, Daemon
from revkit.v1 import analysis_pb2

LIB = r"""
#include <string.h>
struct acc { unsigned long sum, count, max; };
__attribute__((noinline)) void acc_add(struct acc *a, unsigned long v) {
  a->sum += v; a->count += 1; if (v > a->max) a->max = v;
}
__attribute__((noinline)) unsigned long acc_mean(const struct acc *a) {
  return a->count ? a->sum / a->count : 0;
}
__attribute__((noinline)) unsigned long checksum(const unsigned char *p, unsigned long n) {
  unsigned long h = 5381;
  for (unsigned long i = 0; i < n; i++) h = ((h << 5) + h) ^ p[i];
  return h;
}
__attribute__((noinline)) int rle_encode(const unsigned char *in, int n, unsigned char *out) {
  int o = 0;
  for (int i = 0; i < n;) {
    int j = i;
    while (j < n && in[j] == in[i] && j - i < 255) j++;
    out[o++] = (unsigned char)(j - i); out[o++] = in[i];
    i = j;
  }
  return o;
}
__attribute__((noinline)) unsigned long summarize(const unsigned char *p, int n, unsigned char *scratch) {
  struct acc a; memset(&a, 0, sizeof a);
  for (int i = 0; i < n; i++) acc_add(&a, p[i]);
  int r = rle_encode(p, n, scratch);
  return acc_mean(&a) * 31 + checksum(scratch, (unsigned long)r) + a.max;
}
"""

PROG_A = r"""
#include <stdio.h>
unsigned long summarize(const unsigned char *p, int n, unsigned char *scratch);
unsigned long checksum(const unsigned char *p, unsigned long n);
int main(int argc, char **argv) {
  static unsigned char buf[4096];
  unsigned long s = summarize((const unsigned char *)argv[0], argc * 3, buf);
  printf("%lu %lu\n", s, checksum(buf, 16));
  return 0;
}
"""

PROG_B = r"""
#include <stdlib.h>
unsigned long summarize(const unsigned char *p, int n, unsigned char *scratch);
int rle_encode(const unsigned char *in, int n, unsigned char *out);
int main(int argc, char **argv) {
  unsigned char *scratch = malloc(8192);
  int n = rle_encode((const unsigned char *)argv[0], argc, scratch);
  return (int)(summarize(scratch, n, scratch + 4096) & 0x7f);
}
"""

LIBRARY = {"acc_add", "acc_mean", "checksum", "rle_encode", "summarize"}


@pytest.fixture(scope="module")
def programs(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("fid")
    (d / "lib.c").write_text(LIB)
    (d / "a.c").write_text(PROG_A)
    (d / "b.c").write_text(PROG_B)
    subprocess.run([cc, "-O2", "-g", "-c", str(d / "lib.c"), "-o", str(d / "lib.o")], check=True)
    subprocess.run(["ar", "rcs", str(d / "libacc.a"), str(d / "lib.o")], check=True)
    for name in ("a", "b"):
        subprocess.run([cc, "-O2", "-g", str(d / f"{name}.c"), str(d / "libacc.a"), "-o", str(d / name)], check=True)
    shutil.copy(d / "b", d / "b-stripped")
    subprocess.run(["strip", "--strip-all", str(d / "b-stripped")], check=True)
    return d


@pytest.fixture(scope="module")
def daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture()
def rk(daemon):
    with Client(daemon.grpc_target, actor="user:alice", timeout=300) as c:
        yield c


def wait_idle(prog, timeout=120):
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if prog.analysis_status().idle:
            return
        time.sleep(0.2)
    raise AssertionError("analysis didn't finish")


def names(prog):
    return {f.entry.offset: f.name for f in prog.functions()}


def test_feature(daemon):
    with Client(daemon.grpc_target) as c:
        info = c.server_info()
        assert "function-id" in info.features and info.api_minor >= 51


def test_create_match_reject_apply_detach(rk, programs, tmp_path):
    a = rk.program(rk.import_program("default", path=str(programs / "a"), name="a").program.program_id)
    b = rk.program(rk.import_program("default", path=str(programs / "b-stripped"), name="b").program.program_id)
    truth = rk.program(rk.import_program("default", path=str(programs / "b"), name="b-debug").program.program_id)
    wait_idle(a)
    wait_idle(b)
    wait_idle(truth)
    true_names = names(truth)

    db = tmp_path / "acc.rkfid"
    r = rk.create_fid_database(str(db), [a.id], "acc", version="1", variant="gcc-O2", attach="project")
    assert r.functions_added >= len(LIBRARY) and db.exists()
    assert r.database.scope == analysis_pb2.FID_SCOPE_PROJECT and r.database.attached
    assert r.database.libraries[0].family == "acc"
    dbs = {d.id: d for d in b.fid_databases()}
    assert dbs[str(db)].applies

    res = b.run_fid()
    assert res.revision > 0 and str(db) in res.databases and res.functions_hashed > 0
    by_entry = {m.entry: m for m in res.matches}
    named = {m.entry: m.name for m in res.matches if m.name}
    # Every library function named, and named right.
    lib_entries = {e for e, n in true_names.items() if n in LIBRARY}
    assert lib_entries <= set(named), (lib_entries, named)
    for e in lib_entries:
        assert named[e] == true_names[e]
        assert by_entry[e].status == analysis_pb2.FID_MATCH_STATUS_APPLIED
        assert by_entry[e].candidates[0].database == "acc"
        assert by_entry[e].comment.startswith("Library Function - Single Match")
    now = names(b)
    for e in lib_entries:
        assert now[e] == true_names[e]
    # The name is analysis's, under "fid:acc".
    e0 = sorted(lib_entries)[0]
    fn = next(f for f in b.functions() if f.entry.offset == e0)
    assert fn.name_origin.asserted.provenance.id == "fid:acc"
    assert fn.name_origin.asserted.provenance.kind == 4  # ANALYSIS

    # Reject: the name goes, and stays gone after another run.
    b.reject_fid(e0, reason="not this one")
    assert names(b)[e0].startswith("FUN_")
    res = b.run_fid()
    assert {m.entry: m for m in res.matches}[e0].status == analysis_pb2.FID_MATCH_STATUS_REJECTED
    assert names(b)[e0].startswith("FUN_")

    # Apply: the caller's name, accepted.
    b.apply_fid(e0)
    assert names(b)[e0] == true_names[e0]
    assert {m.entry: m for m in b.fid_matches().matches}[e0].status == analysis_pb2.FID_MATCH_STATUS_ACCEPTED

    # A user's rename stays over Function ID's.
    e1 = sorted(lib_entries)[1]
    b.rename(e1, "mine")
    b.run_fid()
    assert names(b)[e1] == "mine"
    assert {m.entry: m for m in b.fid_matches().matches}[e1].status == analysis_pb2.FID_MATCH_STATUS_KEPT

    # revkit.script: the matches, and a reject from a script.
    from revkit.script import HeadlessHost, run_script

    e2 = sorted(lib_entries)[2]
    script = tmp_path / "fid_script.py"
    script.write_text(
        "from revkit.script import *\n"
        "ms = {m.entry: m for m in fid_matches()}\n"
        f"assert ms[{e2}].name == {true_names[e2]!r}\n"
        f"reject_fid({e2})\n"
        "print('rejected')\n")
    r = run_script(script, client=rk, program_id=b.id, host=HeadlessHost())
    assert r.ok, r.traceback
    assert names(b)[e2].startswith("FUN_")
    b.apply_fid(e2)

    # Detach: the next run names nothing, and its earlier names go.
    rk.detach_fid_database(str(db), scope="project")
    assert not {d.id: d for d in rk.fid_databases()}.get(str(db))
    b.run_fid()
    left = names(b)
    for e in lib_entries - {e0, e1, e2}:
        assert left[e].startswith("FUN_"), (e, left[e])
    assert left[e0] == true_names[e0] and left[e1] == "mine" and left[e2] == true_names[e2]


def test_builtin_databases(rk):
    dbs = rk.fid_databases()
    builtin = [d for d in dbs if d.scope == analysis_pb2.FID_SCOPE_BUILTIN]
    if not builtin:
        pytest.skip("no Ghidra FunctionID data under the daemon's Ghidra root")
    vs = next((d for d in builtin if d.name == "vs2019_x64"), None)
    assert vs is not None and vs.attached and vs.format == "fidbf" and not vs.error
    assert vs.functions > 50000 and vs.libraries[0].family == "Visual Studio"
    # Detached for alice, attached again.
    rk.detach_fid_database(vs.id)
    assert not {d.id: d for d in rk.fid_databases()}[vs.id].attached
    rk.attach_fid_database(vs.id)
    assert {d.id: d for d in rk.fid_databases()}[vs.id].attached
