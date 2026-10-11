"""Shared libraries (api_minor 70, feature "program-libraries") through the
SDK and MCP: a program built against a tiny shared library, imported with
its library; the libraries, their resolution, an import resolved to the
library's function, and a link."""

import json
import shutil
import subprocess

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

        linked = rk.link_library(prog, "libc.so.6", lib)
        assert linked.library.resolution == project_pb2.LIBRARY_RESOLUTION_LINKED
        rk.link_library(prog, "libc.so.6", "")
        again = {l.name: l for l in rk.libraries(prog).libraries}
        assert again["libc.so.6"].resolution == project_pb2.LIBRARY_RESOLUTION_NONE


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

    anyio.run(run)
