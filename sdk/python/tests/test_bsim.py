"""BSim databases through the SDK (api_minor 69, feature "bsim"; docs/bsim.md):
a database created at a path and attached, two builds of one program
ingested (names, prototypes from debug info, sizes), listed, renamed and
categorized, ingested again (replaced), deleted, detached; rk-bsim reads
the same files."""

import json
import os
import shutil
import subprocess

import pytest

from revkit import Client, Daemon

SOURCE = r"""
volatile int sink;
__attribute__((noinline)) unsigned checksum(const unsigned char *p, unsigned long n) {
  unsigned h = 2166136261u;
  for (unsigned long i = 0; i < n; ++i) h = (h ^ p[i]) * 16777619u;
  return h;
}
__attribute__((noinline)) int classify(int c) {
  switch (c) {
    case 0: return 10; case 1: return 22; case 2: return 37; case 3: return 41;
    case 4: return 58; case 5: return 63; case 6: return 79; default: return -1;
  }
}
int main(int argc, char **argv) {
  sink = (int)checksum((const unsigned char *)argv[0], 4) + classify(argc);
  return 0;
}
"""

RK_BSIM = os.path.join(os.path.dirname(__file__), "..", "..", "..", "build", "tools", "rk-bsim", "rk-bsim")


@pytest.fixture(scope="module")
def builds(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("bsim")
    (d / "p.c").write_text(SOURCE)
    subprocess.run([cc, "-O1", "-g", str(d / "p.c"), "-o", str(d / "p-O1")], check=True)
    subprocess.run([cc, "-O2", str(d / "p.c"), "-o", str(d / "p-O2")], check=True)
    return d


@pytest.fixture(scope="module")
def daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture()
def rk(daemon):
    with Client(daemon.grpc_target, actor="user:alice", timeout=300) as c:
        yield c


def test_bsim_database_lifecycle(rk, builds, tmp_path):
    if "bsim" not in rk.server_info().features:
        pytest.skip("daemon without feature bsim")
    path = str(tmp_path / "test.rkbsim")
    db = rk.create_bsim_database("test", path=path, description="sdk test")
    assert db.id == path and db.settings == 0x49 and db.executables == 0
    assert [d.id for d in rk.bsim_databases()] == [path]

    a = rk.import_program("default", path=str(builds / "p-O1"), name="p-O1").program.program_id
    b = rk.import_program("default", path=str(builds / "p-O2"), name="p-O2").program.program_id
    done = rk.bsim_ingest(path, [a, b], categories={"suite": "sdk"})
    assert [r.executable.name for r in done] == ["p-O1", "p-O2"]
    assert all(r.functions >= 3 and not r.replaced for r in done)
    exes = rk.bsim_executables(path)
    assert sorted(e.name for e in exes) == ["p-O1", "p-O2"]
    assert all(e.categories["suite"] == "sdk" for e in exes)
    fns = rk.bsim_functions(path, "p-O1", name_contains="checksum")
    assert [f.name for f in fns.functions] == ["checksum"]
    assert "checksum(" in fns.functions[0].prototype  # debug info's
    assert fns.functions[0].size > 0 and fns.functions[0].feature_count > 5

    # Search (api_minor 72): p-O2's functions find p-O1's counterparts; the query's own file is left out.
    hits = rk.program(b).bsim_search(path, min_similarity=0.0, max_matches=3)
    by_name = {q.name: q for q in hits.results if not q.skipped}
    for name in ("checksum", "classify"):
        q = by_name.get(name)
        if q is None:  # stripped of its name? p-O2 has symbols
            continue
        assert q.matches and q.matches[0].function.name == name, (name, q)
        assert q.matches[0].program_id == a and q.matches[0].executable.name == "p-O1"
        assert all(m.executable.name != "p-O2" for m in q.matches)
    entry = by_name["checksum"].function.offset
    one = rk.bsim_search(path, b, [entry], min_similarity=0.0)
    assert [q.name for q in one.results] == ["checksum"]
    ov = rk.program(b).bsim_search(path, overview=True, min_similarity=0.0)
    assert all(not q.matches for q in ov.results) and any(q.hit_count for q in ov.results)

    again = rk.bsim_ingest(path, [a])
    assert again[0].replaced
    assert len(rk.bsim_executables(path)) == 2
    e = rk.update_bsim_executable(path, "p-O1", name="first", categories={"vendor": "me"})
    assert e.name == "first" and dict(e.categories) == {"vendor": "me"}

    # rk-bsim reads the same files.
    if os.path.exists(RK_BSIM):
        out = subprocess.run([RK_BSIM, "list", path, "--json"], check=True, capture_output=True, text=True).stdout
        assert sorted(x["name"] for x in json.loads(out)) == ["first", "p-O2"]

    gone = rk.delete_bsim_executables(path, ["first", "nonesuch"])
    assert gone.deleted == 1 and list(gone.missing) == ["nonesuch"]
    assert [x.name for x in rk.bsim_executables(path)] == ["p-O2"]
    rk.detach_bsim_database(path)
    assert rk.bsim_databases() == []
    rk.attach_bsim_database(path)
    assert rk.bsim_databases()[0].executables == 1
