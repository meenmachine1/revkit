"""MSVC RTTI classes through the Python SDK and MCP (api_minor 45, feature
"msvc-rtti"; docs/pe.md), on tests/data/msvc/classes.cc built for
x86_64-pc-windows-msvc with clang in cl mode and lld-link (skipped without
them)."""

import json
import pathlib
import shutil
import subprocess

import pytest

from revkit import Client, Daemon

FIXTURE = pathlib.Path(__file__).resolve().parents[3] / "tests" / "data" / "msvc"


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    clang, lld = shutil.which("clang"), shutil.which("lld-link") or shutil.which("lld-link-18")
    if not clang or not lld:
        pytest.skip("no clang or lld-link")
    d = tmp_path_factory.mktemp("msvc")
    subprocess.run(["sh", str(FIXTURE / "build.sh"), clang, lld, str(d), "x86_64"], check=True, capture_output=True)
    return d / "classes-x86_64-stripped.exe"


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture()
def prog(image_daemon, binary):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as rk:
        resp = rk.import_program("default", path=str(binary), name=binary.name)
        yield rk.program(resp.program.program_id)


def test_feature(image_daemon):
    with Client(image_daemon.grpc_target) as rk:
        info = rk.server_info()
        assert "msvc-rtti" in info.features and info.api_minor >= 45


def test_classes(prog):
    classes = {c.name: c for c in prog.classes()}
    sq = classes["geo::Square"]
    assert [b.name for b in sq.bases] == ["geo::Rect", "geo::Shape", "geo::Named"]
    assert sq.bases[0].direct and not sq.bases[1].direct
    assert list(classes["geo::Rect"].derived) == ["geo::Square"]
    assert sq.vftables[0].name == "geo::Square::vftable"
    assert sq.vftables[0].functions[1].name == "geo::Square::vfunc1"
    assert classes["geo::Left"].bases[0].is_virtual
    assert [c.name for c in prog.classes("box")] == ["geo::Box<int>"]
    # Its virtual methods are functions with `this` typed.
    f = next(f for f in prog.functions() if f.name == "geo::Square::vfunc1")
    assert "struct geo::Square *this" in f.prototype
    assert "Square *this" in prog.decompile(f.entry.offset).text


def test_load_pdb_and_symbol_settings(image_daemon, binary):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as rk:
        prog = rk.program(rk.import_program("default", path=str(binary), name="pdb-" + binary.name).program.program_id)
        pdb = binary.parent / "classes-x86_64.pdb"
        # The stripped build names no PDB: another build's only with force.
        with pytest.raises(Exception, match="force"):
            prog.load_pdb(pdb)
        r = prog.load_pdb(pdb, force=True)
        assert not r.exact and r.functions > 10 and r.assertion_seqs
        assert "geo::Rect::area" in {f.name for f in prog.functions()}
        # Undo: retract what it asserted.
        prog.retract(*r.assertion_seqs)
        assert "geo::Rect::area" not in {f.name for f in prog.functions()}
        # The symbol settings: downloads are off by default.
        s = rk.symbol_settings()
        assert not s.downloads
        s = rk.set_symbol_settings("srv*" + str(binary.parent / "store"), downloads=False)
        assert s.symbol_path.endswith("store") and not s.downloads
        assert rk.server_info().api_minor >= 49 and "pdb-load" in rk.server_info().features


mcp_client = pytest.importorskip("mcp.client.client")
anyio = pytest.importorskip("anyio")


def test_mcp_list_classes(image_daemon, prog, binary):
    prog_pdb = binary.parent / "classes-x86_64.pdb"
    from revkit.mcp_server import create_server

    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-msvc")

    async def run():
        async with mcp_client.Client(server) as mcp:
            r = await mcp.call_tool("list_classes", {"program_id": prog.id, "name_contains": "rect"})
            assert not r.is_error, r
            out = json.loads(r.content[0].text)
            names = [c["name"] for c in out["classes"]]
            assert names == ["geo::Rect"]
            rect = out["classes"][0]
            assert [b["name"] for b in rect["bases"]] == ["geo::Shape", "geo::Named"]
            assert rect["vftables"][0]["functions"][1]["name"] == "geo::Rect::vfunc1"
            r = await mcp.call_tool("load_pdb", {"program_id": prog.id, "path": str(prog_pdb), "force": True})
            assert not r.is_error, r
            out = json.loads(r.content[0].text)
            assert out["functions"] > 10 and not out["exact"], out

    anyio.run(run)
