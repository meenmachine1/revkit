"""PatchService through the SDK (revkit.patching, docs/patching.md): a
program compiled here, an immediate patched and undone, a byte patch, the
patches list, and an export whose name carries the file's 32-bit sum."""

import shutil
import subprocess

import pytest

from revkit import Client, Daemon, patching

SRC = r"""
__attribute__((noinline)) int scale(int x) { return x * 3 + 0x41; }
int main(int argc, char **argv) { (void)argv; return scale(argc); }
"""


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("patch")
    (d / "prog.c").write_text(SRC)
    subprocess.run([cc, "-O1", "-o", str(d / "prog"), str(d / "prog.c")], check=True)
    return d / "prog"


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_patch_list_undo_export(image_daemon, binary):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        assert "patch" in rk.server_info().features
        pid = rk.import_program("default", path=str(binary), name="prog").program.program_id
        prog = rk.program(pid)
        scale = next(f for f in prog.functions() if f.name == "scale").entry.offset
        rows = prog.listing(start=scale, max_rows=8).rows
        row = next(r for r in rows if "0x41" in "".join(t.text for t in r.tokens))
        text = "".join(t.text for t in row.tokens).replace("0x41", "0x42")

        a = prog.assemble(row.address.offset, text)
        assert a.candidates and not a.error, a.error
        assert a.current_text and a.current_bytes == row.bytes
        bad = prog.assemble(row.address.offset, "MOV EAX,")
        assert not bad.candidates and bad.error and bad.expected

        done = prog.patch_instruction(row.address.offset, text)
        assert done.seqs and done.bytes != row.bytes
        [p] = prog.patches()
        assert p.original == row.bytes and p.typed_text == text and p.provenance.id == "alice"
        now = prog.listing(start=row.address.offset, max_rows=1).rows[0]
        assert now.patched and now.original_bytes == row.bytes

        # A byte patch elsewhere, then undo of the instruction.
        prog.patch_bytes(scale - 1, b"\xcc")
        prog.retract(done.seqs[0])
        assert prog.listing(start=row.address.offset, max_rows=1).rows[0].bytes == row.bytes
        assert len(prog.patches()) == 1

        out = prog.export(patching.name_sum("sum32", template="prog_{SUM:08X}"))
        assert out.verification.ok, out.verification.detail
        assert out.file_name == "prog_%08X" % (sum(out.data) & 0xFFFFFFFF)
        original = binary.read_bytes()
        assert len(out.data) == len(original)
        assert sum(x != y for x, y in zip(out.data, original)) == 1

        hits = prog.detect_checksum(patched=True, file_name=out.file_name).hits
        assert hits and hits[0].spec.name and patching.describe(hits[0].spec).startswith("sum32 over 0x0..EOF")
        assert hits[0].file_name_template == "prog_{SUM:08X}"
