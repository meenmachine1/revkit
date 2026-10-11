"""Folders in a project and project archives (api_minor 35) through the SDK,
rk-daemon's project commands, MCP and the roles that may use them."""

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from revkit import Client, Daemon, FailedPrecondition, PermissionDenied
from revkit.daemon import find_daemon
from revkit.v1 import common_pb2

SOURCE = r"""
#include <stdio.h>
int counter;
__attribute__((noinline)) int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
__attribute__((noinline)) int twice(int x) { return x * 2 + %d; }
int main(int argc, char **argv) {
  counter = fib(argc + 9);
  printf("fib is %%d and twice %%d\n", counter, twice(argc));
  return counter & 0x7f;
}
"""


@pytest.fixture(scope="module")
def binaries(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("org")
    out = []
    for i in range(2):
        (d / f"v{i}.c").write_text(SOURCE % (i + 1))
        subprocess.run([cc, "-O1", "-fno-inline", "-o", str(d / f"v{i}"), str(d / f"v{i}.c")], check=True)
        out.append(d / f"v{i}")
    return out


@pytest.fixture(scope="module")
def daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def _answers(rk, program_id):
    """Its functions (with prototypes) and main's C, once background analysis
    (inferred prototypes, derived again after an import) has settled."""
    prog = rk.program(program_id)
    deadline = time.monotonic() + 180
    while not prog.analysis_status().idle:
        assert time.monotonic() < deadline, "analysis did not settle"
        time.sleep(0.2)
    funcs = sorted((f.entry.offset, f.name, f.prototype) for f in prog.functions())
    main = next(f for f in prog.functions() if f.name in ("main", "entry_point"))
    return funcs, prog.decompile(main.entry.offset).text


def test_folders_and_archives_through_the_sdk(daemon, binaries, tmp_path):
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        assert {"project-folders", "project-archive"} <= set(rk.server_info().features)
        a = rk.import_program("default", path=str(binaries[0]), name="v0").program.program_id
        b = rk.import_program("default", path=str(binaries[1]), name="v1").program.program_id
        assert all(p.folder_path == "/" for p in rk.programs("default"))

        json_id = rk.folder_id("default", "/libs/json", create=True)
        assert [f.path for f in rk.folders("default")] == ["/libs", "/libs/json"]
        moved = rk.move_to_folder("default", "/libs/json", programs=[a])
        assert {p.name: p.folder_path for p in rk.programs("default")} == {"v0": "/libs/json", "v1": "/"}
        rk.undo_project_edit("default", [x.seq for x in moved.assertions])
        assert {p.name: p.folder_path for p in rk.programs("default")}["v0"] == "/"
        rk.move_to_folder("default", json_id, programs=[a])
        rk.move_to_folder("default", "/libs", programs=[b])
        rk.rename_folder("default", "/libs", "third_party")
        assert {p.name: p.folder_path for p in rk.programs("default")} == {"v0": "/third_party/json", "v1": "/third_party"}
        rk.create_folder("default", "/empty")
        with pytest.raises(FailedPrecondition):
            rk.delete_folder("default", "/third_party")
        rk.delete_folder("default", "/empty")

        prog = rk.program(a)
        fib = next(f for f in prog.functions() if f.name == "fib")
        prog.rename(fib.entry.offset, "fibonacci")
        prog.comment(fib.entry.offset, "the slow one", kind="plate")
        before = {"v0": _answers(rk, a), "v1": _answers(rk, b)}

        full = tmp_path / "full.rkproj"
        summary = rk.export_project("default", full)
        assert summary.file_name == "default.rkproj" and full.stat().st_size > 1000
        assert {p.name: p.folder for p in summary.manifest.programs} == {"v0": "/third_party/json", "v1": "/third_party"}
        copy = rk.import_project(full, name="copy")
        assert copy.project.project_id == "copy"
        got = {p.program.name: p.program for p in copy.programs}
        assert got["v0"].folder_path == "/third_party/json"
        for name in ("v0", "v1"):
            assert _answers(rk, got[name].program_id) == before[name]

        # Annotations only: the binaries are found by sha256 among files we send.
        ann = tmp_path / "ann.rkproj"
        rk.export_project("default", ann, annotations_only=True)
        assert ann.stat().st_size < full.stat().st_size
        seen = rk.import_project(ann, inspect=True)
        assert {p.binary_source for p in seen.programs} == {""}
        with pytest.raises(FailedPrecondition, match="not found"):
            rk.import_project(ann, name="nope")
        back = rk.import_project(ann, name="ann-copy", binaries=[str(binaries[0]), binaries[1].read_bytes()])
        got = {p.program.name: p for p in back.programs}
        assert got["v0"].binary_source == "upload"
        assert _answers(rk, got["v0"].program.program_id) == before["v0"]

        # Merged into the project it came from: new programs, renamed beside the originals.
        rk.create_folder("default", "/incoming")
        merged = rk.import_project(full, into="default", folder="/incoming")
        names = {p.program.name: p.program.folder_path for p in merged.programs}
        assert names == {"v0": "/incoming/third_party/json", "v1": "/incoming/third_party"}
        again = rk.import_project(full, into="default", folder="/incoming")
        assert {p.program.name for p in again.programs} == {"v0 (2)", "v1 (2)"}
        assert again.warnings


def test_project_commands(binaries, tmp_path):
    rk_daemon = find_daemon()
    src = tmp_path / "src"
    with Daemon(None, "--backend", "image", "--project-dir", str(src), startup_timeout=60) as d:
        with d.client(actor="user:alice") as rk:
            p = rk.import_program("default", path=str(binaries[0]), name="v0").program.program_id
            rk.move_to_folder("default", rk.folder_id("default", "/fw", create=True), programs=[p])
            before = _answers(rk, p)
        # A second daemon on the same directory is refused while the first runs.
        r = subprocess.run([rk_daemon, "project", "export", "--project-dir", str(src), "-o", str(tmp_path / "x")],
                           capture_output=True, text=True)
        assert r.returncode == 1 and "another rk-daemon" in r.stderr
    out = tmp_path / "x.rkproj"
    r = subprocess.run([rk_daemon, "project", "export", "--project-dir", str(src), "--folder", "/fw", "-o", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "1 program" in r.stdout and "/fw/v0" in r.stdout
    dst = tmp_path / "dst"
    r = subprocess.run([rk_daemon, "project", "import", "--project-dir", str(dst), str(out), "--name", "imported fw"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "into project imported_fw" in r.stdout
    with Daemon(None, "--backend", "image", "--project-dir", str(dst), startup_timeout=60) as d:
        with d.client() as rk:
            progs = rk.programs("imported_fw")
            assert [(x.name, x.folder_path) for x in progs] == [("v0", "/fw")]
            assert _answers(rk, progs[0].program_id) == before
    # A newer format is refused with a clear message.
    bad = tmp_path / "bad.rkproj"
    import gzip
    import io
    import tarfile

    manifest = json.dumps({"format": "revkit-project-archive", "format_version": 99, "op_format": 1}).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        t.addfile(info, io.BytesIO(manifest))
    bad.write_bytes(gzip.compress(buf.getvalue()))
    r = subprocess.run([rk_daemon, "project", "import", "--project-dir", str(dst), str(bad), "--inspect"],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "format version 99 is newer" in r.stderr, r.stderr


def test_roles(binaries, tmp_path):
    """Exporting is a viewer's (a read); folders an editor's; importing an admin's."""
    with Daemon(None, "--backend", "image", auth=True, startup_timeout=60) as d:
        admin = d.create_token("root", "admin")
        viewer = d.create_token("vic", "viewer")
        editor = d.create_token("ed", "editor")
        with d.client(token=admin) as rk:
            rk.import_program("default", path=str(binaries[0]), name="v0")
        with d.client(token=editor) as rk:
            prog = rk.program("default/v0")
            prog.rename(next(f for f in prog.functions() if f.name == "fib").entry.offset, "fibonacci")
        out = tmp_path / "v.rkproj"
        with d.client(token=viewer) as rk:
            rk.export_project("default", out)
            with pytest.raises(PermissionDenied):
                rk.create_folder("default", "x")
            with pytest.raises(PermissionDenied):
                rk.export_project("default", host_path=str(tmp_path / "host.rkproj"))
        with d.client(token=editor) as rk:
            rk.create_folder("default", "x")
            with pytest.raises(PermissionDenied):
                rk.import_project(out, name="copy")
        with d.client(token=admin) as rk:
            r = rk.import_project(out, name="copy")
            assert r.programs[0].program.program_id == "copy/v0"
            # Imported ops keep their authors.
            prov = {(a.provenance.kind, a.provenance.id) for a in rk.program("copy/v0").assertions(include_inactive=True)}
            assert prov == {(common_pb2.PROVENANCE_KIND_AGENT, "ed")}, prov  # a token with no account is an agent


def test_mcp_tools(daemon, binaries, tmp_path):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    with Client(daemon.grpc_target, actor="user:alice") as rk:
        rk.open_project(path=str(tmp_path / "mcp-project"), create=True, name="mcp")
        p = rk.import_program("mcp", path=str(binaries[0]), name="m0").program.program_id
    server = create_server(daemon.grpc_target, agent="claude", session="mcp-org")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                r = await mcp.call_tool(tool, args)
                assert not r.is_error, r
                out = json.loads(r.content[0].text)
                assert "error" not in out, (tool, out)
                return out

            await call("create_folder", project_id="mcp", path="/a/b", reason="organize")
            await call("move_to_folder", project_id="mcp", folder="/a/b", program_ids=[p], reason="file it")
            await call("rename_folder", project_id="mcp", folder="/a", name="top", reason="clearer")
            listed = await call("list_programs")
            proj = next(x for x in listed["projects"] if x["project_id"] == "mcp")
            assert proj["programs"][0]["folder"] == "/top/b" and proj["folders"] == ["/top", "/top/b"]
            path = str(tmp_path / "mcp.rkproj")
            ex = await call("export_project", project_id="mcp", path=path)
            assert ex["programs"][0]["folder"] == "/top/b"
            im = await call("import_project", path=path, new_project_name="mcp-copy", reason="a copy")
            assert im["programs"][0]["folder"] == "/top/b"
            await call("create_folder", project_id="mcp", path="/gone", reason="temp")
            await call("delete_folder", project_id="mcp", folder="/gone", reason="temp")

    try:
        anyio.run(run)
    finally:
        server.revkit_client.close()


ORGANIZE = """\
# @category Tests
# @description Files the program under /scripted/<format>
from revkit.script import *
folder = create_folder("/scripted/elf")
move_to_folder(folder, programs=[current_program.id])
print(current_project, [f.path for f in folders()])
export_project(args["out"], programs=[current_program.id])
"""


def test_script_api(daemon, binaries, tmp_path):
    import io

    from revkit.script import HeadlessHost, run_script

    with Client(daemon.grpc_target, actor="user:tester") as rk:
        rk.open_project(path=str(tmp_path / "script-project"), create=True, name="scripted")
        p = rk.import_program("scripted", path=str(binaries[1]), name="s1").program.program_id
        script = tmp_path / "organize.py"
        script.write_text(ORGANIZE)
        host = HeadlessHost(None, out=io.StringIO(), err=io.StringIO(), interactive=False)
        out = tmp_path / "s.rkproj"
        r = run_script(script, client=rk, program_id=p, args={"out": str(out)}, host=host)
        assert r.ok, r.traceback
        assert "scripted ['/scripted', '/scripted/elf']" in host.out.getvalue()
        listed = rk.programs("scripted")
        assert listed[0].folder_path == "/scripted/elf"
        assert listed[0].folder_origin.asserted.provenance.kind == common_pb2.PROVENANCE_KIND_SCRIPT
        assert out.stat().st_size > 1000
