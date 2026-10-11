"""DiffService through the SDK (revkit.diff) on two versions of a program
compiled here: A with debug info, B stripped. Match, port names, revert."""

import shutil
import subprocess

import pytest

from revkit import Client, Daemon, DiffSession, tier_name

V1 = r"""
#include <stdio.h>
__attribute__((noinline)) unsigned hash_str(const char *s) {
  unsigned h = 5381;
  while (*s) h = h * 33 + (unsigned char)*s++;
  return h;
}
__attribute__((noinline)) int twice(int x) { return x * 2 + 1; }
int main(int argc, char **argv) {
  printf("%u %d\n", hash_str(argv[0]), twice(argc));
  return 0;
}
"""

V2 = r"""
#include <stdio.h>
__attribute__((noinline)) int added(int x) { return x - 3; }
__attribute__((noinline)) unsigned hash_str(const char *s) {
  unsigned h = 5381;
  while (*s) h = h * 33 + (unsigned char)*s++;
  return h;
}
__attribute__((noinline)) int twice(int x) { return x * 2 + 1; }
int main(int argc, char **argv) {
  printf("%u %d %d\n", hash_str(argv[0]), twice(argc), added(argc));
  return 0;
}
"""


@pytest.fixture(scope="module")
def binaries(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc or not shutil.which("strip"):
        pytest.skip("no C compiler or strip")
    d = tmp_path_factory.mktemp("diff")
    out = {}
    for name, src in (("v1", V1), ("v2", V2)):
        (d / f"{name}.c").write_text(src)
        subprocess.run([cc, "-g", "-O2", "-fno-inline", "-o", str(d / name), str(d / f"{name}.c")], check=True)
    subprocess.run(["strip", "-o", str(d / "v2-stripped"), str(d / "v2")], check=True)
    return d / "v1", d / "v2-stripped"


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_diff_match_apply_revert(image_daemon, binaries):
    v1, v2 = binaries
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        assert "diff" in rk.server_info().features
        a = rk.import_program("default", path=str(v1), name="v1").program.program_id
        b = rk.import_program("default", path=str(v2), name="v2").program.program_id
        s = rk.diff("default", a, b)
        assert isinstance(s, DiffSession)
        assert s.status().session.run.state == 3  # SUCCEEDED
        assert [x.session_id for x in rk.diff_sessions("default", program_id=b)] == [s.id]

        matches = {m.a.name: m for m in s.matches()}
        assert {"hash_str", "twice", "main"} <= matches.keys()
        h = matches["hash_str"]
        assert h.b.default_name and h.confidence >= 0.95
        assert tier_name(h.tier) in ("bytes", "pcode", "name")
        assert all(m.confidence >= 0.95 for m in s.matches(min_confidence=0.95))
        assert [m.a.name for m in s.matches(name_contains="HASH")] == ["hash_str"]
        unmatched_b = {u.function.entry.offset for u in s.unmatched("b")}
        assert unmatched_b, "added() has no counterpart"

        dry = s.apply(dry_run=True)
        assert dry.names >= 2 and not dry.run_id
        run = s.apply()
        assert run.run_id and run.names == dry.names
        prog_b = rk.program(b)
        assert prog_b.function(h.b.entry.offset).name == "hash_str"
        blame = prog_b.blame(prog_b.key("name", h.b.entry.offset))
        assert blame.candidates[0].provenance.id == "diff"
        assert blame.candidates[0].ported_from.program_id == a
        assert next(s.matches(name_contains="hash_str")).status == 3  # APPLIED

        s.revert_apply(run.run_id)
        assert prog_b.function(h.b.entry.offset).name.startswith("FUN_")

        # Decisions: reject the real pair, then set it by hand.
        s.reject((h.a.entry.offset, h.b.entry.offset))
        assert "hash_str" not in {m.a.name for m in s.matches()}
        s.set_match(h.a.entry.offset, h.b.entry.offset)
        again = next(s.matches(name_contains="hash_str"))
        assert again.status == 2 and tier_name(again.tier) == "accepted"  # ACCEPTED
        fd = s.function_diff(entry_a=h.a.entry.offset)
        assert fd.match.b.entry.offset == h.b.entry.offset and fd.a.bytes_hash == fd.b.bytes_hash
        # Inside the pair (api_minor 17): the same code, aligned line by line.
        d = s.function_diff(entry_a=h.a.entry.offset, detail=True).detail
        assert len(d.rows_a) == len(d.rows_b) == len(d.lines) > 3
        assert not d.hunks and d.summary.text == "no instruction changed"
        assert all(r.status == 1 and r.text for r in d.rows_a)  # EQUAL
        (summary,) = s.summaries((h.a.entry.offset, h.b.entry.offset))
        assert summary.equal == len(d.rows_a) and summary.text == d.summary.text


def test_compare_functions_port_and_unmatch(image_daemon, binaries):
    """Any two functions (api_minor 54, feature "function-compare"): compare
    across programs and within one, port markup either way as one undo step,
    and unmatch a decision."""
    v1, v2 = binaries
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        assert "function-compare" in rk.server_info().features
        a = rk.import_program("default", path=str(v1), name="cv1").program.program_id
        b = rk.import_program("default", path=str(v2), name="cv2").program.program_id
        s = rk.diff("default", a, b)
        twice = next(s.matches(name_contains="twice"))
        ta, tb = twice.a.entry.offset, twice.b.entry.offset

        # Across programs, no session: the same code, aligned; x paired with param_1.
        c = rk.compare_functions(a, ta, b, tb)
        assert c.a.function.name == "twice" and c.b.function.default_name
        assert not c.detail.hunks and c.detail.summary.text == "no instruction changed"
        params = [v for v in c.markup.variables if v.HasField("a") and v.HasField("b") and v.evidence == "parameter 1"]
        assert params and params[0].a.name == "x" and params[0].a.named and not params[0].b.named
        assert "twice" in c.markup.signature_a and c.markup.signature_set_a

        # Within one program: two different functions.
        h = next(s.matches(name_contains="hash_str"))
        two = rk.compare_functions(a, ta, a, h.a.entry.offset, markup=False)
        assert two.detail.hunks and not two.HasField("markup")
        # Through the session: its match comes with it.
        assert s.compare(ta, tb, markup=False).match.b.entry.offset == tb

        # Port everything A has to B: name, signature, the parameter's name.
        dry = rk.port_function_markup(a, ta, b, tb, dry_run=True)
        assert dry.names == 1 and dry.variable_names >= 1 and not dry.seqs
        r = s.port(ta, tb, reason="same function")
        assert r.names == 1 and r.signatures == 1 and r.variable_names >= 1 and r.seqs
        prog_b = rk.program(b)
        assert prog_b.function(tb).name == "twice"
        dec = prog_b.decompile(tb)
        assert any(v.name == "x" for v in dec.variables), [v.name for v in dec.variables]
        blame = prog_b.blame(prog_b.key("name", tb))
        assert blame.candidates[0].ported_from.program_id == a
        assert blame.candidates[0].ported_from.session_id == s.id
        # One undo step: retracting its seqs.
        prog_b.retract(*r.seqs, reason="undo the port")
        assert prog_b.function(tb).name.startswith("FUN_")

        # Single items, the other way: B's own name for its function, onto A's (only with overwrite).
        prog_b.rename(tb, "doubled_plus_one", reason="mine")
        back = s.port(ta, tb, items=["name"], reverse=True)
        assert back.names == 0 and back.skipped == 1
        back = s.port(ta, tb, items=["name"], reverse=True, overwrite=True)
        assert back.names == 1 and rk.program(a).function(ta).name == "doubled_plus_one"
        one = rk.port_function_markup(a, ta, b, tb, items=[("variable_name", params[0].a.storage_key)], overwrite=True)
        assert one.variable_names == 1 and len(one.ported) == 1 and one.ported[0].after == "x"

        # Manual matching: accept, unmatch (undo the decision), and undo the unmatch.
        acc = s.accept((ta, tb))
        assert acc.seqs
        assert next(s.matches(name_contains="doubled")).status == 2  # ACCEPTED
        un = s.unmatch((ta, tb))
        assert un.retracted_seqs and un.seqs
        assert next(s.matches(name_contains="doubled")).status == 1  # PROPOSED
        prog_b.retract(*un.seqs)
        assert next(s.matches(name_contains="doubled")).status == 2
