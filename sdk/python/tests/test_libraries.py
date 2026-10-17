"""Shared libraries (api_minor 70, feature "program-libraries") through the
SDK and MCP: a program built against a tiny shared library, imported with
its library; the libraries, their resolution, an import resolved to the
library's function, and a link."""

import io
import json
import os
import shutil
import subprocess
import tarfile

import pytest

from revkit import Client, Daemon
from revkit.v1 import project_pb2

LIB = r"""
__attribute__((noinline)) int lib_add(int a, int b) { return a + b + 1000; }
"""

PROG = r"""
int lib_add(int a, int b);
int main(int argc, char **argv) { (void)argv; return lib_add(argc, 2) & 0x7f; }
"""


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("libs")
    (d / "mylib.c").write_text(LIB)
    (d / "prog.c").write_text(PROG)
    subprocess.run([cc, "-O1", "-shared", "-fPIC", "-Wl,-soname,libmylib.so", "-o", str(d / "libmylib.so"),
                    str(d / "mylib.c")], check=True)
    subprocess.run([cc, "-O1", "-o", str(d / "prog"), str(d / "prog.c"), "-Wl,--no-as-needed", f"-L{d}", "-lmylib",
                    f"-Wl,-rpath,{d}"], check=True)
    return d


@pytest.fixture(scope="module")
def daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_import_with_libraries_and_resolve(daemon, built):
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        # Uploaded: only the given search path is looked in (not the host's libc).
        r = rk.import_program("default", content=(built / "prog").read_bytes(), name="prog",
                              import_libraries=True, library_search_paths=[str(built)], library_depth=1)
        prog = r.program.program_id
        assert [p.name for p in r.libraries] == ["libmylib.so"]
        lib = r.libraries[0].program_id
        assert "libc.so.6" in [m.name for m in r.libraries_not_found]

        libs = rk.libraries(prog, include_imports=True)
        by_name = {l.name: l for l in libs.libraries}
        assert by_name["libmylib.so"].resolution == project_pb2.LIBRARY_RESOLUTION_NAME
        assert by_name["libmylib.so"].program_id == lib
        assert by_name["libc.so.6"].resolution == project_pb2.LIBRARY_RESOLUTION_NONE
        add = next(i for i in libs.imports if i.name == "lib_add")
        assert add.resolved and add.program_id == lib and add.function_name == "lib_add"
        assert rk.libraries(lib).soname == "libmylib.so"

        one = rk.resolve_import(prog, name="lib_add")
        assert one.address.offset == add.address.offset
        assert rk.resolve_import(prog, address=add.thunk.offset).name == "lib_add"

        # References back from the library (api_minor 80, feature "library-importers").
        assert "library-importers" in rk.server_info().features
        back = rk.library_importers(lib, name="lib_add")
        assert [i.program_id for i in back.importers] == [prog]
        use = back.importers[0]
        assert use.library == "libmylib.so" and use.resolved.thunk.offset == add.thunk.offset
        assert any(x.from_function_name == "main" for x in use.references), use.references
        by_address = rk.library_importers(lib, address=add.address.offset)
        assert [i.resolved.name for i in by_address.importers] == ["lib_add"]
        assert len(rk.library_importers(prog).importers) == 0

        linked = rk.link_library(prog, "libc.so.6", lib)
        assert linked.library.resolution == project_pb2.LIBRARY_RESOLUTION_LINKED
        rk.link_library(prog, "libc.so.6", "")
        again = {l.name: l for l in rk.libraries(prog).libraries}
        assert again["libc.so.6"].resolution == project_pb2.LIBRARY_RESOLUTION_NONE


def _rootfs(built, root):
    """An extracted root file system: the program in /usr/bin, the library in
    /opt/vendor/lib (named by /etc/ld.so.conf) through an absolute symlink."""
    (root / "usr/bin").mkdir(parents=True)
    (root / "opt/vendor/lib").mkdir(parents=True)
    (root / "etc").mkdir()
    (root / "lib").mkdir()
    shutil.copy(built / "prog", root / "usr/bin/prog")
    shutil.copy(built / "libmylib.so", root / "opt/vendor/lib/libmylib.so.1")
    os.symlink("/opt/vendor/lib/libmylib.so.1", root / "opt/vendor/lib/libmylib.so")
    (root / "etc/ld.so.conf").write_text("/opt/vendor/lib\n")
    return root


def test_libraries_from_the_programs_root_file_system(built, tmp_path):
    """api_minor 79, feature "library-roots": a program in an extracted root
    under --browse-root finds its library there (not on the host), and one
    imported from a tar of that root finds it in the tar."""
    fw = tmp_path / "fw"
    root = _rootfs(built, fw / "rootfs")
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w") as t:
        t.add(root, arcname=".")
    with Daemon(None, "--backend", "image", "--browse-root", str(fw), startup_timeout=60) as d, \
            Client(d.grpc_target, actor="user:alice") as rk:
        assert "library-roots" in rk.server_info().features
        r = rk.import_program("default", path=str(root / "usr/bin/prog"), import_libraries=True, library_depth=1)
        assert r.library_root == str(root.resolve())
        assert [p.name for p in r.libraries] == ["libmylib.so"]
        assert "libc.so.6" in [m.name for m in r.libraries_not_found]

        rk.open_project(path=str(tmp_path / "proj"), create=True, name="tarred")
        with rk.open_filesystem("tarred", file=tar.getvalue(), name="rootfs.tar") as fs:
            got = fs.import_("/usr/bin/prog", import_libraries=True, library_depth=1)
        assert got.imported == 2
        lib = next(i for i in got.items if i.library_of)
        assert lib.library_of == "prog" and lib.program.name == "libmylib.so"
        assert lib.container_path == "tar://rootfs.tar!/opt/vendor/lib/libmylib.so.1"
        prog = next(i for i in got.items if not i.library_of).program.program_id
        by_name = {l.name: l for l in rk.libraries(prog).libraries}
        assert by_name["libmylib.so"].program_id == lib.program.program_id


def test_mcp_lists_and_resolves(daemon, built):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    with Client(daemon.grpc_target, actor="user:alice") as rk:
        progs = {p.name: p.program_id for p in rk.programs("default")}
        if "prog" not in progs:
            rk.import_program("default", content=(built / "prog").read_bytes(), name="prog",
                              import_libraries=True, library_search_paths=[str(built)], library_depth=1)
            progs = {p.name: p.program_id for p in rk.programs("default")}
    server = create_server(daemon.grpc_target, agent="claude", agent_version="test", session="mcp-libs")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                res = await mcp.call_tool(tool, args)
                assert not res.is_error, res
                return json.loads(res.content[0].text)

            libs = await call("list_libraries", program_id=progs["prog"], include_imports=True)
            mine = next(l for l in libs["libraries"] if l["name"] == "libmylib.so")
            assert mine["resolution"] == "name" and mine["program_id"] == progs["libmylib.so"]
            add = await call("resolve_import", program_id=progs["prog"], name="lib_add")
            assert add["resolved"] and add["function"] == "lib_add" and add["program_id"] == progs["libmylib.so"]
            back = await call("list_library_importers", program_id=progs["libmylib.so"], name="lib_add")
            assert [i["program_id"] for i in back["importers"]] == [progs["prog"]]
            assert any(r.get("from_function") == "main" and r["kind"] == "call" for r in back["importers"][0]["references"])

    anyio.run(run)
