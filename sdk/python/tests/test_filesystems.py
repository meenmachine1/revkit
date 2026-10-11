"""Container file systems (api_minor 48, feature "filesystems";
docs/filesystems.md) through the SDK: open, list, read, info, import (one
and batch), extract, nesting, hostile names, and who may do what."""

import gzip
import io
import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

from revkit import Client, Daemon, InvalidArgument, NotFound, PermissionDenied, ResourceExhausted

SOURCE = r"""
#include <stdio.h>
__attribute__((noinline)) int twice(int x) { return x * 2 + 1; }
int main(int argc, char **argv) { printf("%d\n", twice(argc)); return 0; }
"""


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    """root/fw.zip holding bin/hello (an ELF), etc/motd, a symlink, and
    pkg/data.tar.gz holding usr/bin/tool (an ELF) and inner.zip holding
    deep/x (an ELF): three containers deep."""
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("fs")
    (d / "hello.c").write_text(SOURCE)
    elf = d / "hello"
    subprocess.run([cc, "-O1", "-o", str(elf), str(d / "hello.c")], check=True)
    exe = elf.read_bytes()
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("deep/x", exe)
    tgz = io.BytesIO()
    with tarfile.open(fileobj=tgz, mode="w:gz") as t:
        for name, data in (("usr/bin/tool", exe), ("usr/share/readme.txt", b"just text\n"),
                           ("inner.bin", inner.getvalue())):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755
            t.addfile(info, io.BytesIO(data))
    root = d / "root"
    root.mkdir()
    with zipfile.ZipFile(root / "fw.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("bin/hello", exe)
        z.writestr("etc/motd", "welcome\n")
        z.writestr("pkg/data.tar.gz", tgz.getvalue())
        link = zipfile.ZipInfo("bin/hi")
        link.create_system = 3
        link.external_attr = (0o120777 << 16)
        z.writestr(link, "hello")
    # Hostile names.
    evil = io.BytesIO()
    with tarfile.open(fileobj=evil, mode="w") as t:
        for name in ("../../escape.txt", "/abs/root.txt", "dir/../../../up.txt"):
            info = tarfile.TarInfo(name)
            info.size = 3
            t.addfile(info, io.BytesIO(b"bad"))
        loop = tarfile.TarInfo("loop")
        loop.type, loop.linkname = tarfile.SYMTYPE, "loop"
        t.addfile(loop)
    (root / "evil.tar").write_bytes(evil.getvalue())
    with zipfile.ZipFile(root / "bomb.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("zeros", bytes(32 << 20))
    (root / "plain.txt").write_text("not a container\n")
    return {"root": root, "elf": exe, "dir": d}


@pytest.fixture(scope="module")
def daemon(fixtures):
    out = fixtures["dir"] / "out"
    out.mkdir()
    with Daemon(None, "--backend", "image", "--browse-root", str(out), startup_timeout=60) as d:
        yield d


def by_name(entries):
    return {e.name: e for e in entries}


def test_browse_read_info(daemon, fixtures):
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        assert "filesystems" in rk.server_info().features and rk.server_info().api_minor >= 48
        with rk.open_filesystem("default", host_path=str(fixtures["root"] / "fw.zip")) as fs:
            assert fs.format == "zip" and "zip archive" in fs.root.description
            top = by_name(fs.list("/").entries)
            assert set(top) == {"bin", "etc", "pkg"}
            assert top["bin"].kind == 2 and top["bin"].child_count == 2
            bins = by_name(fs.list("/bin").entries)
            assert bins["hello"].detected_kind == "elf" and "ELF 64-bit LE x86-64" in bins["hello"].detected
            assert bins["hello"].processor == "x86:LE:64"
            assert bins["hi"].kind == 3 and bins["hi"].link_target == "hello" and bins["hi"].link_path == "/bin/hello"
            assert fs.read("/bin/hello") == fixtures["elf"]
            assert fs.read("/bin/hi") == fixtures["elf"]  # links are followed inside
            assert fs.read("/bin/hello", 1, 3) == fixtures["elf"][1:4]
            pkg = by_name(fs.list("/pkg").entries)
            assert pkg["data.tar.gz"].container_format == "gzip"
            info = fs.info("/bin/hello", hashes=True)
            import hashlib
            assert info.sha256 == hashlib.sha256(fixtures["elf"]).hexdigest()
            assert info.md5 == hashlib.md5(fixtures["elf"]).hexdigest()
            assert info.magic[:4] == b"\x7fELF"
            assert info.container_path == "zip://fw.zip!/bin/hello"
            # Nesting, three deep, by magic: inner.bin is a zip.
            deep = "/pkg/data.tar.gz!/data.tar!/inner.bin!/deep/x"
            assert fs.read(deep) == fixtures["elf"]
            layer = fs.list("/pkg/data.tar.gz!/data.tar!/inner.bin")
            assert layer.layer.format == "zip" and layer.layer.depth == 4
            assert fs.info(deep).container_path == "zip://fw.zip!/pkg/data.tar.gz!/data.tar!/inner.bin!/deep/x"
            walked = [e.path for e in fs.walk("/pkg/data.tar.gz!/data.tar!/")]
            assert "/pkg/data.tar.gz!/data.tar!/usr/bin/tool" in walked
            with pytest.raises(NotFound):
                fs.read("/nope")
        with pytest.raises(InvalidArgument):
            rk.open_filesystem("default", host_path=str(fixtures["root"] / "plain.txt"))


def test_hostile(daemon, fixtures):
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        with rk.open_filesystem("default", host_path=str(fixtures["root"] / "evil.tar")) as fs:
            names = {e.path: e for e in fs.walk("/")}
            assert {"/escape.txt", "/abs/root.txt", "/up.txt", "/loop"} <= set(names)
            assert names["/escape.txt"].renamed and "../../escape.txt" in names["/escape.txt"].note
            assert names["/loop"].link_path == ""  # a loop resolves to nothing
            with pytest.raises(ResourceExhausted):
                fs.read("/loop")
        with rk.open_filesystem("default", host_path=str(fixtures["root"] / "bomb.zip"),
                                limits={"max_file_bytes": 8 << 20}) as fs:
            assert fs.limits.max_file_bytes == 8 << 20
            with pytest.raises(ResourceExhausted):
                fs.read("/zeros")
        # A request can lower the limits, never raise them.
        with rk.open_filesystem("default", host_path=str(fixtures["root"] / "bomb.zip"),
                                limits={"max_file_bytes": 1 << 40}) as fs:
            assert fs.limits.max_file_bytes == 1 << 30


def test_extract(daemon, fixtures):
    out = fixtures["dir"] / "out"
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        with rk.open_filesystem("default", host_path=str(fixtures["root"] / "evil.tar")) as fs:
            r = fs.extract(["/"], str(out / "evil"))
            written = sorted(os.path.relpath(p, out) for p in r.written)
            assert written == ["evil/abs/root.txt", "evil/escape.txt", "evil/up.txt"]
            assert any("loop" in s for s in r.skipped)
            assert not (fixtures["dir"] / "escape.txt").exists() and not Path("/abs/root.txt").exists()
            # Again: exists, unless overwrite.
            again = fs.extract(["/escape.txt"], str(out / "evil"))
            assert again.files == 0 and "exists" in again.skipped[0]
            assert fs.extract(["/escape.txt"], str(out / "evil"), overwrite=True).files == 1
            # Outside the browse root.
            with pytest.raises(PermissionDenied):
                fs.extract(["/escape.txt"], str(fixtures["dir"] / "elsewhere"))
        with rk.open_filesystem("default", host_path=str(fixtures["root"] / "fw.zip")) as fs:
            r = fs.extract(["/bin"], str(out / "fw"))
            assert (out / "fw" / "bin" / "hello").read_bytes() == fixtures["elf"]
            assert not (out / "fw" / "bin" / "hi").exists()  # links aren't written


def test_import_one_and_batch(daemon, fixtures):
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        rk.open_project(path=str(fixtures["dir"] / "proj"), create=True, name="fsproj")
        with rk.open_filesystem("fsproj", host_path=str(fixtures["root"] / "fw.zip")) as fs:
            one = fs.import_("/bin/hello", analyze=False)
            assert one.imported == 1, one
            prog = one.items[0].program
            assert prog.container_path == "zip://fw.zip!/bin/hello"
            listed = {p.program_id: p for p in rk.programs("fsproj")}
            assert listed[prog.program_id].container_path == "zip://fw.zip!/bin/hello"
            # Batch: preview, then everything below the root, into containers, capped.
            rk.create_folder("fsproj", "/batch")
            preview = fs.import_("/", recursive=True, descend=True, preview=True, folder="/batch", project_id="fsproj")
            actions = {i.path: i.action for i in preview.items}
            assert actions["/pkg/data.tar.gz!/data.tar!/usr/bin/tool"] == "import"
            assert actions["/pkg/data.tar.gz!/data.tar!/inner.bin!/deep/x"] == "import"
            assert actions["/etc/motd"] == "skipped"
            assert actions["/pkg/data.tar.gz!/data.tar!/usr/share/readme.txt"] == "skipped"
            assert len(rk.programs("fsproj")) == 1  # a preview imports nothing
            capped = fs.import_("/", recursive=True, descend=True, max_programs=2, folder="/batch",
                                keep_folders=True, analyze=False)
            assert capped.capped and capped.imported == 2
            imported = [i for i in capped.items if i.action == "imported"]
            assert {i.program.folder_path for i in imported} == {"/batch/bin", "/batch/pkg/data.tar.gz/data.tar/inner.bin/deep"}
            assert any(i.reason.startswith("over the cap") for i in capped.items)


def test_program_source_and_roles(fixtures, tmp_path):
    """Browsing a program's stored file is a viewer's; a host path is an
    admin's; importing an editor's; extracting an admin's."""
    out = tmp_path / "out"
    out.mkdir()
    with Daemon(None, "--backend", "image", "--browse-root", str(out), auth=True, startup_timeout=60) as d:
        admin = d.create_token("root", "admin")
        viewer = d.create_token("vic", "viewer")
        editor = d.create_token("ed", "editor")
        zip_bytes = (fixtures["root"] / "fw.zip").read_bytes()
        with d.client(token=admin) as rk:
            # A container stored as a (raw) program, as a firmware dump would be.
            prog = rk.import_program("default", content=zip_bytes, name="fw.bin", format="raw",
                                     language_id="ARM:LE:32:v4t", analyze=False).program.program_id
        with d.client(token=viewer) as rk:
            with pytest.raises(PermissionDenied):
                rk.open_filesystem("default", host_path=str(fixtures["root"] / "fw.zip"))
            with pytest.raises(PermissionDenied):
                rk.open_filesystem("default", file=zip_bytes)
            with rk.open_filesystem("default", program_id=prog) as fs:
                assert fs.read("/bin/hello") == fixtures["elf"]
                with pytest.raises(PermissionDenied):
                    fs.import_("/bin/hello", analyze=False)
        with d.client(token=editor) as rk:
            with rk.open_filesystem("default", program_id=prog) as fs:
                r = fs.import_("/bin/hello", analyze=False)
                assert r.imported == 1 and r.items[0].program.container_path == "zip://fw.bin!/bin/hello"
                with pytest.raises(PermissionDenied):
                    fs.extract(["/bin/hello"], str(out / "x"))
                sid = fs.session_id
        # Sessions are their opener's.
        with d.client(token=viewer) as rk:
            assert all(s.session_id != sid for s in rk.filesystems())
        with d.client(token=admin) as rk:
            with rk.open_filesystem("default", host_path=str(fixtures["root"] / "fw.zip")) as fs:
                assert fs.extract(["/etc/motd"], str(out / "x")).files == 1


def test_mcp_tools(daemon, fixtures, tmp_path):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    import json

    from revkit.mcp_server import create_server

    server = create_server(daemon.grpc_target, agent="claude", session="mcp-fs")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                r = await mcp.call_tool(tool, args)
                assert not r.is_error, r
                out = json.loads(r.content[0].text)
                assert "error" not in out, (tool, out)
                return out

            opened = await call("open_filesystem", project_id="default", file=str(fixtures["root"] / "fw.zip"))
            sid = opened["session_id"]
            assert opened["format"] == "zip"
            listed = await call("list_filesystem", session_id=sid, path="/bin")
            hello = next(e for e in listed["entries"] if e["name"] == "hello")
            assert hello["processor"] == "x86:LE:64" and hello["kind"] == "file"
            motd = await call("read_filesystem_file", session_id=sid, path="/etc/motd")
            assert motd["text"] == "welcome\n"
            info = await call("filesystem_file_info", session_id=sid, path="/pkg/data.tar.gz")
            assert info["container"]["format"] == "gzip" and len(info["sha256"]) == 64
            preview = await call("import_from_filesystem", session_id=sid, paths=["/"], reason="look",
                                 recursive=True, descend=True, preview=True)
            assert {i["path"] for i in preview["items"] if i["action"] == "import"} >= {
                "/bin/hello", "/pkg/data.tar.gz!/data.tar!/usr/bin/tool"}
            done = await call("import_from_filesystem", session_id=sid, paths=["/bin/hello"], reason="analyze it",
                              analyze=False)
            assert done["imported"] == 1 and done["items"][0]["program_id"].startswith("default/hello")
            await call("close_filesystem", session_id=sid)

    try:
        anyio.run(run)
    finally:
        server.revkit_client.close()


SCRIPT = """\
# @category Tests
from revkit.script import *
with open_filesystem(host_path=args["zip"]) as fs:
    print(sorted(e.name for e in fs.list("/bin").entries))
    r = import_from_filesystem(fs, "/pkg/data.tar.gz!/data.tar!/usr/bin/tool", analyze=False)
    print(r.imported, r.items[0].program.container_path)
"""


def test_script_api(daemon, fixtures, tmp_path):
    from revkit.script import HeadlessHost, run_script

    with Client(daemon.grpc_target, actor="user:tester") as rk:
        rk.open_project(path=str(tmp_path / "script-fs"), create=True, name="scriptfs")
        with rk.open_filesystem("scriptfs", host_path=str(fixtures["root"] / "fw.zip")) as fs:
            p = fs.import_("/bin/hello", analyze=False).items[0].program.program_id
        script = tmp_path / "fs.py"
        script.write_text(SCRIPT)
        host = HeadlessHost(None, out=io.StringIO(), err=io.StringIO(), interactive=False)
        r = run_script(script, client=rk, program_id=p, args={"zip": str(fixtures["root"] / "fw.zip")}, host=host)
        assert r.ok, r.traceback
        out = host.out.getvalue()
        assert "['hello', 'hi']" in out and "1 zip://fw.zip!/pkg/data.tar.gz!/data.tar!/usr/bin/tool" in out
        tool = next(x for x in rk.programs("scriptfs") if x.name.startswith("tool"))
        assert tool.container_path == "zip://fw.zip!/pkg/data.tar.gz!/data.tar!/usr/bin/tool"


def test_file_system_images_and_firmware(daemon, fixtures, tmp_path):
    """A squashfs inside a zip, batch-imported by descending into it, and a
    UF2 image imported as a raw program from the language and load address
    its family names."""
    mksquashfs = shutil.which("mksquashfs") or ("/usr/sbin/mksquashfs" if os.path.exists("/usr/sbin/mksquashfs") else None)
    if not mksquashfs:
        pytest.skip("mksquashfs is not installed")
    import struct
    root = tmp_path / "rootfs"
    (root / "usr/bin").mkdir(parents=True)
    (root / "usr/bin/app").write_bytes(fixtures["elf"])
    (root / "etc").mkdir()
    (root / "etc/hostname").write_text("box\n")
    subprocess.run([mksquashfs, str(root), str(tmp_path / "rootfs.sqfs"), "-noappend", "-comp", "xz"],
                   check=True, capture_output=True)
    code = bytes(range(256)) * 16
    blocks = []
    for i in range(len(code) // 256):
        data = code[256 * i:256 * i + 256]
        blocks.append(struct.pack("<IIIIIIII", 0x0A324655, 0x9E5D5157, 0x2000, 0x10000000 + 256 * i, 256, i,
                                  len(code) // 256, 0xe48bff56) + data + bytes(476 - 256) + struct.pack("<I", 0x0AB16F30))
    with zipfile.ZipFile(tmp_path / "update.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.write(tmp_path / "rootfs.sqfs", "rootfs.sqfs")
        z.writestr("mcu/fw.uf2", b"".join(blocks))
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        rk.open_project(path=str(tmp_path / "proj"), create=True, name="images")
        with rk.open_filesystem("images", host_path=str(tmp_path / "update.zip")) as fs:
            top = by_name(fs.list("/").entries)
            assert top["rootfs.sqfs"].container_format == "squashfs"
            sq = fs.list("/rootfs.sqfs")
            assert sq.layer.format == "squashfs" and "xz" in sq.layer.description
            uf2 = by_name(fs.list("/mcu/fw.uf2").entries)
            img = uf2["rp2040@0x10000000.bin"]
            assert img.language_id == "ARM:LE:32:Cortex" and img.has_load_address and img.load_address == 0x10000000
            r = fs.import_("/", recursive=True, descend=True, analyze=False)
            done = {i.path: i for i in r.items if i.action == "imported"}
            assert set(done) == {"/rootfs.sqfs!/usr/bin/app", "/mcu/fw.uf2!/rp2040@0x10000000.bin"}, r
            raw = done["/mcu/fw.uf2!/rp2040@0x10000000.bin"]
            assert raw.language_id == "ARM:LE:32:Cortex" and raw.program.format == "raw"
            assert raw.program.container_path == "zip://update.zip!/mcu/fw.uf2!/rp2040@0x10000000.bin"
            summary = rk.program(raw.program.program_id).summary()
            assert any(b.range.first.offset == 0x10000000 for b in summary.memory), summary


def test_cli_import_batch(fixtures, tmp_path):
    """rk-daemon project import-batch: a host directory and the containers in
    it, recursively, with a preview, a cap and folders kept."""
    from revkit.daemon import find_daemon

    tree = tmp_path / "drop"
    (tree / "bin").mkdir(parents=True)
    (tree / "bin/hello").write_bytes(fixtures["elf"])
    (tree / "notes.txt").write_text("not a program\n")
    shutil.copy(fixtures["root"] / "fw.zip", tree / "fw.zip")
    project_dir = tmp_path / "projects"
    run = lambda *args: subprocess.run([find_daemon(), "project", "import-batch", "--project-dir", str(project_dir),
                                        str(tree), *args], capture_output=True, text=True)
    preview = run("--recursive", "--preview")
    assert preview.returncode == 0, preview.stderr
    assert "4 programs would be imported, " in preview.stdout, preview.stdout
    assert "skipped  file://" + str(tree / "notes.txt") in preview.stdout
    capped = run("--recursive", "--max", "2", "--folder", "/drop", "--keep-folders", "--into", "fw")
    assert capped.returncode == 0, capped.stderr
    assert "2 imported" in capped.stdout and "(capped: --max)" in capped.stdout, capped.stdout
    with Daemon(None, "--backend", "image", "--project-dir", str(project_dir), startup_timeout=60) as d:
        with Client(d.grpc_target) as rk:
            progs = {p.name: p for p in rk.programs("fw")}
            assert len(progs) == 2, progs
            assert {p.folder_path for p in progs.values()} <= {"/drop/bin", "/drop/fw.zip/bin", "/drop/fw.zip/pkg/data.tar.gz/data.tar/inner.bin/deep",
                                                             "/drop/fw.zip/pkg/data.tar.gz/data.tar/usr/bin"}
            assert all(p.container_path.startswith("file://" + str(tree)) for p in progs.values())
