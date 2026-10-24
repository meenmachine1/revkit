"""Nintendo DS games (api_minor 103, feature "nds"; docs/nds.md) through the SDK and MCP, on the
synthetic fixtures tests/data/nds/make_fixture.py builds with clang and ld.lld: a ds-decomp
project imported as module programs, names across modules in the decompiler and the listing,
the names written back to symbols.txt, a decomp scratch, and the same game from its .nds ROM."""

import json
import os
import shutil
import subprocess
import sys

import pytest

from revkit import Client, Daemon

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "..", "..", "..", "tests", "data", "nds", "make_fixture.py")


@pytest.fixture(scope="module")
def game(tmp_path_factory):
    clang, lld = shutil.which("clang"), shutil.which("ld.lld")
    if not clang or not lld:
        pytest.skip("no clang or ld.lld for the DS fixture")
    out = tmp_path_factory.mktemp("nds")
    subprocess.run([sys.executable, "-I", FIXTURE, "--clang", clang, "--lld", lld, "--out", str(out)], check=True,
                   capture_output=True)
    return out


@pytest.fixture(scope="module")
def image_daemon(game):
    with Daemon(None, "--backend", "image", "--browse-root", str(game), startup_timeout=60) as d:
        yield d


def lines(fn):
    return fn.text


def test_dsd_import_names_links_export_and_scratch(image_daemon, game):
    expect = json.loads((game / "expect.json").read_text())
    config = game / "dsd" / "config" / "arm9" / "config.yaml"
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as rk:
        assert "nds" in rk.server_info().features
        r = rk.import_dsd_project("default", str(config))
        assert r.imported == 6 and r.failed == 0, r
        assert r.folder.name == "dsd"
        mods = {m.module: m for m in r.modules}
        assert set(mods) == {"main", "itcm", "dtcm", "ov000", "ov001", "arm7"}
        assert mods["main"].language_id == "ARM:LE:32:v5t" and mods["arm7"].language_id == "ARM:LE:32:v4t"
        assert mods["main"].address == 0x02000000 and mods["itcm"].address == 0x01FF8000
        assert mods["ov000"].address == mods["ov001"].address == 0x02100000
        assert mods["main"].thumb_functions == 1 and mods["main"].sections == 4 and mods["main"].units == 1
        assert set(mods["ov000"].links) == {"main", "itcm", "dtcm"}
        assert mods["ov000"].cross_module_relocations > 10
        assert all(m.program.folder_id == r.folder.folder_id for m in r.modules)

        main = rk.program(mods["main"].program.program_id)
        fns = {f.entry.offset: f for f in main.functions()}
        syms = {s["name"]: s for s in expect["modules"]["main"]["symbols"]}
        # Names from symbols.txt, demangled; the Thumb function found as Thumb.
        assert fns[syms["_ZN9SceneBase6UpdateEv"]["addr"]].name == "SceneBase::Update"
        assert fns[syms["_ZN9SceneBase6UpdateEv"]["addr"]].demangled.mangled == "_ZN9SceneBase6UpdateEv"
        thumb = syms["_Z13ThumbChecksumPKhi"]["addr"]
        assert fns[thumb].name == "ThumbChecksum"
        assert "ThumbChecksum" in lines(main.decompile(thumb))
        blocks = {b.name for b in main.memory_map()}
        assert {".text", ".rodata", ".data", ".bss"} <= blocks

        # An overlay's calls into main: main's names and prototypes.
        ov0 = rk.program(mods["ov000"].program.program_id)
        update = next(s for s in expect["modules"]["ov000"]["symbols"] if s["name"] == "_ZN13GameOverScene6UpdateEv")
        text = lines(ov0.decompile(update["addr"]))
        assert "SceneBase::Update((SceneBase *)this)" in text, text
        assert "Lerp(" in text and expect["placeholder"] in text and "_s32_div_f(" in text, text
        assert "func_0x" not in text, text
        # Not C23's fdiv(double, double): the raw image's _fdiv takes no library prototype.
        assert "CONCAT44" not in text, text
        # The listing names them too, with the program they are in.
        rows = ov0.listing(update["addr"], update["addr"] + 0x40).rows
        linked = [t for row in rows for t in row.tokens if t.target_program_id]
        assert any(t.text == "SceneBase::Update" and t.target_program_id == main.id for t in linked), linked

        # A rename in main shows in the overlay's decompilation.
        clamp = syms[expect["placeholder"]]["addr"]
        main.rename(clamp, "Clamp")
        assert "Clamp(" in lines(ov0.decompile(update["addr"]))

        # The scratch.
        s = ov0.decomp_scratch(update["addr"])
        assert s.probe == "// PROBE: _ZN13GameOverScene6UpdateEv ov000 0x%08x" % update["addr"], s.probe
        assert s.text.startswith(s.probe + "\n") and "void GameOverScene::Update(GameOverScene *this)" in s.source
        assert "SceneBase::Update(SceneBase *this);" in s.context and s.callees >= 3, s.context
        assert "typedef unsigned int undefined4;" in s.context
        assert "extern" in s.context and "kRetryItems" in s.context, s.context
        # For an old compiler (api_minor 112, feature "c-dialect"): the scratch's
        # declarations and a module's whole header in C89, as clang -std=c89
        # -pedantic-errors for the DS's ARM9 takes them (C++ names left out).
        assert "c-dialect" in rk.server_info().features
        s89 = ov0.decomp_scratch(update["addr"], dialect="c89")
        assert "_Static_assert" not in s89.context and "stdbool" not in s89.context, s89.context
        assert "typedef unsigned char bool;" in s89.context
        hdr = ov0.export_c(None, header=True, dialect="c89", per_function=True)
        assert hdr.function_sources and not hdr.source
        assert {f.entry.offset for f in hdr.function_sources} >= {update["addr"]}
        for what, text in (("scratch", s89.context), ("header", hdr.header)):
            path = game / ("c89-%s.c" % what)
            path.write_text(text + "\nint revkit_check;\n")
            cc = subprocess.run([shutil.which("clang"), "-std=c89", "-pedantic-errors", "--target=armv5te-none-eabi",
                                 "-c", "-o", os.devnull, str(path)], capture_output=True, text=True)
            assert cc.returncode == 0, what + ":\n" + cc.stderr[-3000:] + "\n" + text

        # Back to symbols.txt: the rename in place, a new name added, the demangled form kept.
        main.rename(syms["_ZN9SceneBase4DrawEi"]["addr"], "SceneBase::Draw")
        main.rename(syms["gSeed"]["addr"] + 8, "gUnlisted")
        ex = rk.export_dsd_symbols("default", folder_id=r.folder.folder_id)
        assert ex.renamed == 1 and ex.added == 1, ex
        m = next(m for m in ex.modules if m.module == "main")
        assert "-%s kind:function" % expect["placeholder"] in m.diff and "+Clamp kind:function(arm," in m.diff
        assert "+gUnlisted kind:data(any) addr:0x%08x" % (syms["gSeed"]["addr"] + 8) in m.diff
        assert "-_ZN9SceneBase4DrawEi" not in m.diff
        assert {x.module for x in ex.modules} == {"main", "itcm", "dtcm", "ov000", "ov001"}
        symbols = game / "dsd" / "config" / "arm9" / "symbols.txt"
        before = symbols.read_text()
        w = rk.export_dsd_symbols("default", program_ids=[main.id], write=True)
        assert w.written == 1 and w.modules[0].backup_path
        assert open(w.modules[0].backup_path).read() == before
        after = symbols.read_text()
        assert "Clamp kind:function(arm," in after and expect["placeholder"] not in after
        # Written: nothing left to change.
        assert rk.export_dsd_symbols("default", program_ids=[main.id]).modules[0].diff == ""
        # Outside a --browse-root nothing is read.
        with pytest.raises(Exception):
            rk.import_dsd_project("default", "/etc/passwd")

    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-nds")

    async def run():
        async with mcp_client.Client(server) as mcp:
            sc = await mcp.call_tool("decomp_scratch", {"program_id": ov0.id, "function_address": hex(update["addr"])})
            ex = await mcp.call_tool("export_dsd_symbols", {"project_id": "default"})
            return json.loads(sc.content[0].text), json.loads(ex.content[0].text)

    sc, ex = anyio.run(run)
    assert sc["probe"].startswith("// PROBE: _ZN13GameOverScene6UpdateEv ov000"), sc
    assert sc["evidence"]["target_content"] == ["text", "context", "source"]
    assert ex["renamed"] == 0 and "modules" in ex, ex


def test_nds_rom_import(image_daemon, game):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as rk:
        r = rk.import_nds_rom("default", path=str(game / "game.nds"))
        assert r.failed == 0 and r.folder.name == "REVKITTEST (RKTE)", r
        mods = {m.module: m for m in r.modules}
        assert set(mods) == {"main", "itcm", "dtcm", "ov000", "ov001", "arm7"}
        assert mods["main"].compressed and mods["ov000"].compressed and not mods["ov001"].compressed
        main = rk.program(mods["main"].program.program_id)
        assert main.summary().language.language_id.startswith("ARM:LE:32:v5t")
        # The same bytes as the dsd extract's.
        data = main.read_memory(0x02000000, mods["main"].size)
        assert data == (game / "dsd" / "extract" / "arm9" / "arm9.bin").read_bytes()
        assert mods["ov000"].program.container_path == "nds://game.nds!/ov000"
        with pytest.raises(Exception):
            rk.import_nds_rom("default", content=b"not a rom" * 100)


def test_ds_run_fixes(game, tmp_path):
    """What a matching run needed (api_minor 104): the DS's I/O volatile, Thumb bounds kept, batches that
    name what they refuse, name conflicts, and compaction."""
    config = game / "dsd" / "config" / "arm9" / "config.yaml"
    projects = tmp_path / "projects"
    with Daemon(None, "--backend", "image", "--browse-root", str(game), "--project-dir", str(projects),
                startup_timeout=60) as d, Client(d.grpc_target, actor="user:alice", timeout=300) as rk:
        features = set(rk.server_info().features)
        assert {"assertion-refusals", "bounds-isa", "memory-preset", "import-conflict", "compact"} <= features
        r = rk.import_dsd_project("default", str(config), modules=["main", "ov000"])
        mods = {m.module: rk.program(m.program.program_id) for m in r.modules}
        io = [b for b in mods["ov000"].memory_map() if b.name == "io"]
        assert io and io[0].is_volatile, mods["ov000"].memory_map()

        main = mods["main"]
        fns = {f.name: f.entry.offset for f in main.functions()}
        thumb = fns["ThumbChecksum"]
        count = {f.name: f.instruction_count for f in main.functions()}["ThumbChecksum"]
        resp = main.set_function(thumb)
        # symbols.txt marks it Thumb, so its key is the plain entry (only Thumb code nothing marks is
        # keyed tagged), and it stays Thumb: as many instructions as before, not half as many ARM ones.
        assert resp.assertions[0].key.address.offset == thumb
        assert {f.name: f.instruction_count for f in main.functions()}["ThumbChecksum"] == count
        with pytest.raises(Exception):
            main.set_function(thumb | 1, isa="arm")

        from revkit.client import address
        from revkit.v1 import assertion_pb2

        def rename(at, name):
            return assertion_pb2.AssertionBody(rename=assertion_pb2.Rename(
                target=assertion_pb2.Target(address=address(at)), name=name))
        bodies = [rename(fns["SceneBase::Update"], "Tick"), rename(fns["SceneBase::Draw"], "bad name")]
        with pytest.raises(Exception) as e:
            main.append(*bodies)
        assert "assertions[1]" in str(e.value)
        resp = main.append(*bodies, skip_invalid=True)
        assert [x.index for x in resp.refused] == [1] and len(resp.assertions) == 1

        with pytest.raises(Exception):
            rk.import_dsd_project("default", str(config), modules=["main"], on_conflict="refuse")
        again = rk.import_dsd_project("default", str(config), modules=["main", "ov000"], on_conflict="replace")
        assert again.folder.folder_id == r.folder.folder_id and len(again.replaced_program_ids) == 2

        rk.close_project("default")
        c = rk.compact_project("default", drop_caches=True)
        assert c.memo_records > 0 and c.file_bytes_after < c.file_bytes_before, c
        rk.open_project("default")


def test_function_id_from_objects_names_a_rom(image_daemon, game, tmp_path):
    """Reusing a finished decomp (docs/nds.md, docs/decomp-kb.md "Why Function ID alone named
    almost nothing"): Function ID built from the objects a decomp's build has (here clang's,
    standing in for mwcc's) names functions of the same code in a ROM that has no symbols. The
    objects are imported as ARM:LE:32:v5t, the DS modules' language: Function ID matches within
    one language. Only what is long enough (4 instructions), whole in the objects (an object's
    body ends at its first unrelocated call) and found in the ROM (main's functions only overlays
    call are found at import) is named; the decomp knowledge base names most of the rest."""
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as rk:
        ids = []
        for o in ("main.o", "itcm.o", "ov000.o", "ov001.o"):
            r = rk.import_program("default", path=str(game / "objs" / o), name="obj-" + o,
                                  language_id="ARM:LE:32:v5t:default")
            ids.append(r.program.program_id)
            # The relocatable object's symbols, Thumb included.
            names = {f.name for f in rk.program(r.program.program_id).functions()}
            if o == "main.o":
                assert {"SceneBase::Update", "ThumbChecksum", "Lerp"} <= names, names
        db = tmp_path / "game1.rkfid"
        made = rk.create_fid_database(str(db), ids, "fixture-game", version="1", attach="project")
        assert made.functions_added >= 8, made
        rom = rk.import_nds_rom("default", path=str(game / "game.nds"), folder_name="fid-rom")
        main = rk.program(next(m.program.program_id for m in rom.modules if m.module == "main"))
        matches = main.run_fid()
        named = {m.name for m in matches.matches if m.name}
        assert {"ThumbChecksum", "_s32_div_f"} <= named, matches
