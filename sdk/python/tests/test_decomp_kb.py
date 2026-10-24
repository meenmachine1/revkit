"""The decomp knowledge base (api_minor 105, feature "decomp-kb"; docs/decomp-kb.md) through
the SDK and MCP: the synthetic DS game (tests/data/nds/make_fixture.py) as a finished decomp,
ingested with its source and a matching pipeline's manifest, then applied to the same project
with dsd's placeholder names (dsd3/: exact matches, names through callers, the export as files)
and to "game 3" (the same source and flags built again, every address moved, one function
changed; as a dsd project with placeholder names and as a ROM with none): exact matches, names
through callers, and a BSim near match with its source and instruction diff."""

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
    out = tmp_path_factory.mktemp("kb")
    subprocess.run([sys.executable, "-I", FIXTURE, "--clang", clang, "--lld", lld, "--out", str(out)], check=True,
                   capture_output=True)
    return out


@pytest.fixture(scope="module")
def image_daemon(game):
    with Daemon(None, "--backend", "image", "--browse-root", str(game), startup_timeout=60) as d:
        yield d


def test_ingest_apply_export(image_daemon, game):
    expect = json.loads((game / "expect.json").read_text())
    kb = game / "kb"
    manifest = game / "manifest.jsonl"
    syms = {s["name"]: s for s in expect["modules"]["main"]["symbols"]}
    lerp = syms["_Z4Lerpfff"]
    # A line as the matching pipeline writes it (its field names), one with the older names, one that
    # doesn't parse.
    manifest.write_text("\n".join([
        json.dumps({"address": f"0x{lerp['addr']:08x}", "compiler": "mwcc-ds/2.0/sp2p2", "flags": "-O4,p -ipa file",
                    "fuzzy": 100.0, "isa": "arm", "library": "", "masked_sha256": "deadbeef", "module": "main",
                    "name": "_Z4Lerpfff", "object": "build/src/main.o", "relocations": [{"offset": 4}, {"offset": 8}],
                    "size": lerp["size"], "source": "src/main.cpp", "status": "exact", "variant": "base"}),
        json.dumps({"module": "main", "address": syms["_Z13ThumbChecksumPKhi"]["addr"], "symbol": "_Z13ThumbChecksumPKhi",
                    "mode": "thumb", "status": "fuzzy", "fuzzy": 87.5, "masked_hash": "cafe"}),
        "{not json"]) + "\n")
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=600) as rk:
        assert "decomp-kb" in rk.server_info().features
        g1 = rk.import_dsd_project("default", str(game / "dsd" / "config" / "arm9" / "config.yaml"), folder_name="game1")
        b = rk.build_decomp_kb("default", str(kb), folder_id=g1.folder.folder_id, compiler="clang-18", flags="-O2",
                               manifest_path=str(manifest))
        assert b.game == "game1" and b.functions >= 15 and b.units >= 3 and b.from_manifest == 2, b
        assert b.with_source >= 10 and b.near_indexed >= 8, b
        assert any("manifest" in w for w in b.warnings), b.warnings
        records = [json.loads(line) for line in (kb / "functions.jsonl").read_text().splitlines()]
        rec = {r["symbol"]: r for r in records}
        lr = rec["_Z4Lerpfff"]
        assert lr["compiler"] == "mwcc-ds/2.0/sp2p2" and lr["manifest_hash"] == "deadbeef" and lr["status"] == "matching"
        assert lr["object"] == "build/src/main.o" and lr["variant"] == "base" and lr["relocations"] == 2 and lr["fuzzy"] == 100
        tc = rec["_Z13ThumbChecksumPKhi"]
        assert tc["status"] == "nonmatching" and tc["manifest_hash"] == "cafe" and tc["mode"] == "thumb", tc
        assert rec["_ZN9SceneBase6UpdateEv"]["compiler"] == "clang-18"
        assert rec["_ZN9SceneBase6UpdateEv"]["text"].startswith("void SceneBase::Update()"), rec["_ZN9SceneBase6UpdateEv"]
        assert "GameOverScene::GameOverScene() : cursor{0, 0}, fade(1.0f) {}" in rec["_ZN13GameOverSceneC1Ev"]["text"]
        # Functions under Function ID's 4 instructions are kept, matched only through their callers.
        assert rec["_fadd"].get("small") and rec["_fadd"]["text"].startswith('extern "C" __attribute__((noinline)) float _fadd'), rec["_fadd"]
        assert any(c["symbol"] == "_fadd" for c in lr["calls"]), lr["calls"]
        assert (kb / "sources" / "game1" / "src" / "main.cpp").read_text() == (game / "dsd" / "src" / "main.cpp").read_text()
        assert json.loads((kb / "kb.json").read_text())["format"] == "revkit-decomp-kb/1"
        assert (kb / "near.rkbsim" / "database.json").exists()
        # Again: the game's records replaced, not doubled.
        again = rk.build_decomp_kb("default", str(kb), folder_id=g1.folder.folder_id, compiler="clang-18",
                                   manifest_path=str(manifest))
        assert again.total == b.total and again.near_indexed == b.near_indexed

        # The same project under dsd's placeholder names.
        g3 = rk.import_dsd_project("default", str(game / "dsd3" / "config" / "arm9" / "config.yaml"), folder_name="dsd3")
        dry = rk.apply_decomp_kb("default", str(kb), folder_id=g3.folder.folder_id)
        assert dry.exact >= 8 and dry.by_call >= 3 and dry.applied == 0, dry
        out = game / "export"
        r = rk.apply_decomp_kb("default", str(kb), folder_id=g3.folder.folder_id, apply=True, include_unit_source=True,
                               export_dir=str(out))
        assert r.applied >= 12, r
        main3 = rk.program(next(m.program.program_id for m in g3.modules if m.module == "main"))
        names = {f.name for f in main3.functions()}
        assert {"SceneBase::Update", "Lerp", "ThumbChecksum", "_fadd", "_fmul", "_fsub"} <= names, names
        m = next(x for x in r.matches if x.functions[0].symbol == "_Z4Lerpfff")
        assert m.applied and m.verdict == "exact" and "_fmul" in m.functions[0].text and "int gSeed" in m.unit_source
        c = next(x for x in r.matches if x.functions[0].symbol == "_fadd")
        assert c.verdict == "call" and c.applied and "Lerp" in c.reason, c
        plates = [c.text for c in main3.comments() if "decomp KB" in c.text]
        assert any("matches with mwcc-ds/2.0/sp2p2, -O4,p -ipa file" in t for t in plates), plates
        # The export: symbols.txt with the linker's spelling, the matched source in its unit, the patch.
        ex = r.exported
        assert ex.dir == str(out) and ex.sources >= 2 and ex.symbols_files >= 1, ex
        sym = (out / "config" / "arm9" / "symbols.txt").read_text()
        assert "_ZN9SceneBase6UpdateEv kind:function(arm," in sym and "_Z4Lerpfff kind:function(arm," in sym, sym
        assert "+_Z4Lerpfff kind:function(arm," in (out / "symbols.patch").read_text()
        unit = (out / "src" / "main.cpp").read_text()
        assert '#include "game.h"' in unit and "float Lerp(float a, float b, float t)" in unit, unit
        assert "SceneBase::Update" in unit and "int gSeed" not in unit, unit

        # Game 3: built again from the same source and flags, every address moved, one function
        # changed, as dsd init leaves it (placeholder names only).
        g3b = rk.import_dsd_project("default", str(game / "game3" / "config" / "arm9" / "config.yaml"), folder_name="game3")
        rr = rk.apply_decomp_kb("default", str(kb), folder_id=g3b.folder.folder_id, apply=True, near=True,
                                export_dir=str(game / "export3"))
        assert rr.exact >= 15 and rr.by_call >= 3 and rr.ambiguous == 0, rr
        by_module = {m.module: m.program.program_id for m in g3b.modules}
        skip = set(expect["game3"]["own"] + expect["game3"]["changed"])
        named, total, missed = 0, 0, []
        for mod, fns in expect["game3"]["modules"].items():
            got = {f.entry.offset: f.name for f in rk.program(by_module[mod]).functions()}
            want = {}  # address -> the names the KB may give it (C1/C2 aliases share one)
            for f in fns:
                if f["name"] in skip or f["name"] not in rec or rec[f["name"]].get("anonymous"):
                    continue
                want.setdefault(f["addr"], set()).add(rec[f["name"]]["name"])
            for addr, names in want.items():
                total += 1
                if got.get(addr) in names:
                    named += 1
                else:
                    missed.append((mod, sorted(names), got.get(addr)))
        # Most are named; the misses are dead code no caller reaches (operator delete).
        assert total >= 18 and named >= 0.85 * total, (named, total, missed)
        near = [x for x in rr.matches if x.verdict == "near"]
        upd = next((x for x in near if x.functions[0].symbol == "_ZN13GameOverScene6UpdateEv"), None)
        assert upd is not None and 0.7 <= upd.similarity < 1.0, near
        assert "void GameOverScene::Update()" in upd.functions[0].text and "\n+" in upd.diff, upd
        assert not upd.applied
        assert rr.exported.scratches >= 1 and rr.exported.sources >= 3, rr.exported
        scratch = list((game / "export3" / "scratch").rglob("*.c"))
        assert any("void GameOverScene::Update()" in p.read_text() and "similarity" in p.read_text() for p in scratch), scratch

        # Game 3's ROM: no symbols at all. Functions only other modules call are found at import.
        rom = rk.import_nds_rom("default", path=str(game / "game3.nds"), folder_name="game3-rom")
        rm = rk.apply_decomp_kb("default", str(kb), folder_id=rom.folder.folder_id, apply=True)
        assert rm.exact >= 10, rm
        rom_names = {f.name for m in rom.modules if m.module in ("main", "itcm", "ov000")
                     for f in rk.program(m.program.program_id).functions()}
        assert {"_s32_div_f", "ItcmMix", "GameOverScene::Draw", "ThumbChecksum"} <= rom_names, rom_names
        # Outside the roots: refused.
        with pytest.raises(Exception):
            rk.build_decomp_kb("default", "/tmp/elsewhere-kb", folder_id=g1.folder.folder_id)
        with pytest.raises(Exception):
            rk.apply_decomp_kb("default", str(kb), folder_id=g3b.folder.folder_id, export_dir="/tmp/elsewhere-export")

    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-kb")

    async def run():
        async with mcp_client.Client(server) as mcp:
            res = await mcp.call_tool("apply_decomp_kb", {"project_id": "default", "kb_path": str(kb),
                                                          "folder_id": g3b.folder.folder_id, "near": True})
            return json.loads(res.content[0].text)

    out = anyio.run(run)
    assert out["exact"] + out.get("by_call", 0) >= 8 and out["matches"], out
    assert any(m["verdict"] == "near" and "diff" in m and m["similarity"] >= 0.7 for m in out["matches"]), out
