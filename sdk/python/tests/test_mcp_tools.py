"""Every MCP tool beyond the first twelve, against the image backend: reads
(symbols, strings, memory, graph, callers, types, plugins), edits (types,
notes, functions), comparing two versions, the emulator, the debugger,
firmware on a machine (a description, a saved one, a derived one), and
patching (assemble, patch, list, export with a checksum, revert), and
detecting a raw image's layout."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

mcp_client = pytest.importorskip("mcp.client.client")
anyio = pytest.importorskip("anyio")

from revkit import Client, Daemon  # noqa: E402
from revkit.mcp_server import create_server  # noqa: E402

V1 = r"""
#include <stdio.h>
int counter;
__attribute__((noinline)) int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
__attribute__((noinline)) int twice(int x) { return x * 2 + 1; }
int main(int argc, char **argv) {
  counter = fib(argc + 9);
  printf("fib is %d and twice %d\n", counter, twice(argc));
  return counter & 0x7f;
}
"""
V2 = V1.replace("x * 2 + 1", "x * 2 + 5")


def _json(result):
    assert not result.is_error, result
    return json.loads(result.content[0].text)


@pytest.fixture(scope="module")
def binaries(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("mcp")
    out = []
    for i, src in enumerate((V1, V2)):
        (d / f"v{i}.c").write_text(src)
        subprocess.run([cc, "-O1", "-fno-inline", "-o", str(d / f"v{i}"), str(d / f"v{i}.c")], check=True)
        out.append(d / f"v{i}")
    return out


@pytest.fixture(scope="module")
def image_daemon(binaries):
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_every_tool_group(image_daemon, binaries, tmp_path):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        a = rk.import_program("default", path=str(binaries[0])).program.program_id
        b = rk.import_program("default", path=str(binaries[1])).program.program_id
        bsim_db = rk.create_bsim_database("mcp", path=str(tmp_path / "mcp.rkbsim")).id
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-tools")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(name, **args):
                r = _json(await mcp.call_tool(name, args))
                assert "error" not in r, (name, r)
                return r

            tools = {t.name for t in (await mcp.list_tools()).tools}
            assert len(tools) == 188, sorted(tools)

            # The workflow guide: a resource, and the investigate prompt built on it.
            resources = (await mcp.list_resources()).resources
            assert [str(r.uri) for r in resources] == ["revkit://guide"], resources
            guide = (await mcp.read_resource("revkit://guide")).contents[0].text
            assert guide.startswith("# Investigating a binary with revkit") and "undo_changes" in guide
            prompts = {p.name: p for p in (await mcp.list_prompts()).prompts}
            assert set(prompts) == {"investigate"} and {a.name for a in prompts["investigate"].arguments} == {"goal", "program_id"}
            msg = (await mcp.get_prompt("investigate", {"goal": "find the parser", "program_id": a})).messages[0].content.text
            assert msg.startswith("# Investigating") and "find the parser" in msg and a in msg
            assert "revkit://guide" in (await call("about"))["guide"]

            # Function ID: the databases and a program's matches (none here).
            dbs = await call("fid_databases", program_id=a)
            assert isinstance(dbs["databases"], list)
            fm = await call("fid_matches", program_id=a)
            assert fm["total"] == len(fm["matches"])

            # Reads.
            syms = await call("search_symbols", program_id=a, name_equals="fib")
            fib = syms["symbols"][0]["address"]
            twice = (await call("search_symbols", program_id=a, name_equals="twice"))["symbols"][0]["address"]
            main = (await call("search_symbols", program_id=a, name_equals="main"))["symbols"][0]["address"]
            fn = await call("get_function", program_id=a, address=fib)
            assert fn["name"] == "fib"
            strings = await call("list_strings", program_id=a, text_contains="fib is")
            assert strings["data"], strings
            # search_strings: a substring in any case, a regular expression, case-sensitive, a length floor.
            hit = strings["data"][0]["address"]
            assert [d["address"] for d in (await call("search_strings", program_id=a, query="FIB IS"))["data"]] == [hit]
            assert hit in [d["address"] for d in (await call("search_strings", program_id=a, query=r"fib\s+is", regex=True))["data"]]
            assert (await call("search_strings", program_id=a, query="FIB IS", case_sensitive=True))["data"] == []
            assert (await call("search_strings", program_id=a, query="fib is", min_length=10_000))["data"] == []
            bad = _json(await mcp.call_tool("search_strings", {"program_id": a, "query": "(", "regex": True}))
            assert "invalid regular expression" in bad.get("error", ""), bad
            assert (await call("list_data", program_id=a, limit=5))["data"]
            # The relocation table (feature relocation-table): a PLT slot by its symbol, its type named.
            relocs = await call("list_relocations", program_id=a, limit=3)
            assert relocs["format"] == "elf" and relocs["total"] >= len(relocs["relocations"]) > 0, relocs
            assert all(r["type"].startswith("R_") and len(r["bytes"]) == 16 for r in relocs["relocations"]), relocs
            if relocs["total"] > 3:
                assert relocs["truncated"] and relocs["next_offset"] == 3, relocs
            slots = (await call("list_relocations", program_id=a, contains="R_X86_64_JUMP_SLOT"))["relocations"]
            assert slots and all(r["kind"] == "jump_slot" and r.get("symbol") for r in slots), slots
            # External decompilers (feature external-decompilers): a C program isn't bytecode.
            ext = await call("list_providers", program_id=a)
            assert ext["input_kind"] is None and "ilspy" in {p["name"] for p in ext["providers"]}, ext
            # Build info (feature build-info): a C program has none, and says so.
            bi = await call("build_info", program_id=a)
            assert "go" not in bi and "rust" not in bi and bi["note"], bi
            # Export C (feature export-c): one function's C and the header's prototype; into a directory.
            ex = await call("export_c", program_id=a, function_addresses=[fib])
            assert ex["functions"] == 1 and "/* fib @ " in ex["source"] and '#include "' in ex["source"], ex
            assert "fib(" in ex["header"] and "typedef unsigned int uint;" in ex["header"], ex["header"][-500:]
            ex_dir = tmp_path / "export-c"
            written = await call("export_c", program_id=a, directory=str(ex_dir), header=False, file_name="all")
            assert written["source_path"] == str(ex_dir / "all.c") and "source" not in written, written
            assert written["functions"] >= 3 and "/* main @ " in (ex_dir / "all.c").read_text(), written
            # The symbol tree (feature symbol-tree): the folders, then fib among the functions.
            tree = await call("symbol_tree", program_id=a)
            assert [n["name"] for n in tree["nodes"]] == ["Imports", "Exports", "Functions", "Labels", "Classes", "Namespaces"], tree
            fns = await call("symbol_tree", program_id=a, path=["Functions"], contains="fib")
            assert [n["address"] for n in fns["nodes"] if n["name"] == "fib"] == [fib], fns
            imports = await call("symbol_tree", program_id=a, path=["Imports"])
            assert imports["nodes"] and all(n["kind"] == "library" for n in imports["nodes"]), imports
            # Clear Flow and Repair (feature clear-flow): twice's flow planned, cleared, undone.
            dry = await call("clear_flow", program_id=a, address=twice, reason="mcp test", dry_run=True)
            assert dry["dry_run"] and dry["ranges"][0]["address"] == twice and dry["functions"] == [twice], dry
            cf = await call("clear_flow", program_id=a, address=twice, reason="mcp test")
            assert cf["ok"] and len(cf["seqs"]) == len(dry["ranges"]), cf
            await call("undo_changes", program_id=a, seqs=cf["seqs"], reason="mcp test")
            assert (await call("get_function", program_id=a, address=twice))["name"] == "twice"
            # The comment table (feature comment-table): a comment listed by kind and text; undone, gone.
            cm = await call("set_comment", program_id=a, address=fib, text="MCP comment table", reason="mcp test", kind="pre")
            listed = (await call("list_comments", program_id=a, kinds=["pre"], contains="COMMENT TABLE"))["comments"]
            assert [(c["address"], c["kind"], c.get("function")) for c in listed] == [(fib, "pre", "fib")], listed
            assert (await call("list_comments", program_id=a, kinds=["eol"], contains="comment table"))["comments"] == []
            await call("undo_changes", program_id=a, seqs=[cm["seq"]], reason="mcp test")
            assert (await call("list_comments", program_id=a, contains="comment table"))["comments"] == []
            # Languages (feature set-language): the variants compared; the imported one asked for changes nothing.
            fits = await call("compare_languages", program_id=a)
            assert any(f["current"] for f in fits["fits"]), fits
            assert sum(f["recommended"] for f in fits["fits"]) <= 1, fits
            same = await call("set_language", program_id=a, language_id="", reason="test")
            assert same["ok"] and "seq" not in same, same
            assert (await call("list_classes", program_id=a))["classes"] == []  # an ELF: no MSVC RTTI
            assert (await call("list_objc_classes", program_id=a))["classes"] == []  # nor Objective-C
            # The calling conventions (feature calling-conventions): x86-64-gcc.cspec's models, the
            # default first, MSABI spelled as GCC's ms_abi attribute.
            cc = await call("list_calling_conventions", program_id=a)
            assert cc["default"] and cc["conventions"][0]["name"] == cc["default"] and cc["conventions"][0]["default"], cc
            assert {"name": "MSABI", "default": False, "c_spelling": "__attribute__((ms_abi))"} in cc["conventions"], cc
            # BSim (feature bsim): a program ingested, the database listed with it.
            ing = await call("bsim_ingest", database=bsim_db, program_ids=[a], categories={"t": "mcp"})
            assert ing["programs"][0]["functions"] > 0, ing
            dbs = (await call("bsim_databases"))["databases"]
            assert dbs[0]["id"] == bsim_db and dbs[0]["executables"] == 1, dbs
            assert dbs[0]["executable_list"][0]["categories"] == {"t": "mcp"}, dbs
            # Search (feature bsim-search): v1's functions against v0's.
            found = await call("bsim_search", program_id=b, all_functions=True, min_similarity=0.5)
            assert found["total"] > 0 and found["results"][0]["matches"][0]["program_id"] == a, found
            one = found["results"][0]
            again = await call("bsim_search", program_id=b, address=one["entry"], min_similarity=0.5)
            assert again["results"][0]["matches"][0]["entry"] == one["matches"][0]["entry"], again
            ov = await call("bsim_overview", program_id=b, min_similarity=0.5)
            assert ov["with_hits"] >= 1 and ov["results"][0]["hits"] >= 1, ov
            # Apply (feature bsim-apply): v1 has v0's names already; a dry run of the signature says what it would do.
            m = one["matches"][0]
            pair = {"address": one["entry"], "executable_id": m["executable_id"], "entry": m["entry"]}
            ap = await call("bsim_apply", program_id=b, matches=[pair], reason="mcp test")
            assert ap["results"][0]["status"] in ("unchanged", "skipped") and ap["seqs"] == [], ap
            dry = await call("bsim_apply", program_id=b, matches=[pair], kind="signature", overwrite=True, dry_run=True,
                             reason="mcp test")
            assert dry["dry_run"] and dry["seqs"] == [] and dry["results"][0]["status"] != "failed", dry
            # No return (feature no-return): twice marked, its record says so; undone, as analysis has it.
            nr = await call("set_no_return", program_id=a, function_address=twice, no_return=True, reason="mcp test")
            assert nr["ok"], nr
            assert (await call("get_function", program_id=a, address=twice)).get("no_return") is True
            await call("undo_changes", program_id=a, seqs=[nr["seq"]], reason="mcp test")
            assert not (await call("get_function", program_id=a, address=twice)).get("no_return")
            # Fallthrough (feature fallthrough-override): twice's first instruction goes on at fib, a reference
            # there; cleared, and both undone.
            ft = await call("set_fallthrough", program_id=a, address=twice, target=fib, reason="mcp test")
            assert ft["ok"], ft
            refs = await call("xrefs", program_id=a, address=fib, kind="fallthrough")
            assert refs["xrefs"] and refs["xrefs"][0]["from"] == twice, refs
            cl = await call("set_fallthrough", program_id=a, address=twice, clear=True, reason="mcp test")
            assert not (await call("xrefs", program_id=a, address=fib, kind="fallthrough"))["xrefs"]
            await call("undo_changes", program_id=a, seqs=[cl["seq"], ft["seq"]], reason="mcp test")
            mem = await call("read_memory", program_id=a, address=fib, length=16)
            assert len(mem["hex"]) == 32 and mem["dump"]
            graph = await call("function_graph", program_id=a, function_address=fib)
            assert len(graph["blocks"]) >= 2 and graph["edges"] and graph["blocks"][0]["instructions"]
            assert any(c["name"] == "main" for c in (await call("callers", program_id=a, function_address=fib))["callers"])
            assert {"fib", "twice"} <= {c["name"] for c in (await call("callees", program_id=a, function_address=main))["callees"]}
            types = await call("find_types", program_id=a, name_contains="size_t", limit=5)
            if types["types"]:
                got = await call("get_type", program_id=a, type_hash=types["types"][0]["hash"])
                assert got["types"]
            await call("list_plugins")
            await call("plugin_facts", program_id=a)
            await call("analysis_status", program_id=a)

            # Searches (feature "search").
            found = await call("search_memory", program_id=a, query="fib is", format="string")
            assert found["matches"] and found["matches"][0]["bytes"] == b"fib is".hex(), found
            text = await call("search_text", program_id=a, query="fib", whole_word=True, fields=["labels"])
            assert any(m["address"] == fib for m in text["matches"]), text
            calls = await call("search_text", program_id=a, query="CALL fib")
            assert any(m.get("function_name") == "main" for m in calls["matches"]), calls
            scal = await call("search_scalars", program_id=a, value="0x7f")
            assert any(m.get("function_name") == "main" for m in scal["matches"]), scal
            c = await call("search_decompiled", program_id=a, query="fib(", functions=[main])
            assert c["matches"] and c["matches"][0]["function_name"] == "main", c
            assert any(l["language_id"] == "ARM:LE:32:v4t" for l in (await call("list_languages", name_contains="ARM:LE:32:v4"))["languages"])

            # Edits, all the agent's, then listed and undone.
            proto = await call("retype", program_id=a, address=twice, c_declaration="int twice(int value)", reason="one int in, one out")
            assert proto["provenance"] == "agent:claude@test"
            dec = _json(await mcp.call_tool("decompile", {"program_id": a, "function_address": twice}))
            assert "value" in dec["c"] or "int twice(int" in dec["prototype"], dec
            assert isinstance(dec["fields"], list), dec
            var = next((v for v in dec["variables"] if v["storage_key"]), None)
            if var:
                await call("retype_variable", program_id=a, function_address=twice, storage_key=var["storage_key"],
                           c_declaration="unsigned int v", reason="unsigned arithmetic")
            note = await call("add_note", program_id=a, address=fib, text="recursive Fibonacci", reason="recognised", tag="finding")
            mine = await call("list_my_changes", program_id=a)
            assert len(mine["changes"]) >= 2
            await call("undo_changes", program_id=a, seqs=[note["seq"]], reason="testing undo")
            assert (await call("revert_my_changes", program_id=a))["retracted"] >= 1

            # Comparing the two versions: twice changed, nothing else.
            cmp = await call("compare_programs", project_id="default", program_a=a, program_b=b, similarity=False)
            sid = cmp["session_id"]
            assert (await call("list_diff_sessions", project_id="default"))["sessions"]
            modified = await call("diff_matches", project_id="default", session_id=sid, change="modified")
            names = {m["a"]["name"] for m in modified["matches"]}
            assert "twice" in names, modified
            pair = next(m for m in modified["matches"] if m["a"]["name"] == "twice")
            detail = await call("diff_function", project_id="default", session_id=sid, address_a=pair["a"]["entry"])
            assert detail["changes"], detail
            await call("diff_unmatched", project_id="default", session_id=sid, side="b")
            await call("diff_accept", project_id="default", session_id=sid, pairs=[[pair["a"]["entry"], pair["b"]["entry"]]], reason="same function")
            await call("diff_apply_markup", project_id="default", session_id=sid, reason="port names", min_confidence=0.95)
            # Any two functions (feature function-compare): compare, port, match by hand, unmatch.
            cf = await call("compare_functions", program_a=a, address_a=pair["a"]["entry"], program_b=b, address_b=pair["b"]["entry"])
            assert cf["changes"] and cf["variables"] and cf["signature_a"], cf
            same = await call("compare_functions", program_a=a, address_a=fib, program_b=a, address_b=fib)
            assert not same["changes"] and same["summary"] == "no instruction changed", same
            dry = await call("port_function_markup", from_program=a, from_address=pair["a"]["entry"], to_program=b,
                             to_address=pair["b"]["entry"], reason="same function", dry_run=True, overwrite=True)
            assert not dry["seqs"] and "ported" in dry, dry
            ported = await call("diff_port_function", project_id="default", session_id=sid, address_a=pair["a"]["entry"],
                                address_b=pair["b"]["entry"], reason="same function", items=["signature", "variable_names"])
            assert "warnings" in ported, ported
            sm = await call("diff_set_match", project_id="default", session_id=sid, address_a=pair["a"]["entry"],
                            address_b=pair["b"]["entry"], reason="by hand")
            assert sm["seqs"], sm
            un = await call("diff_unmatch", project_id="default", session_id=sid, pairs=[[pair["a"]["entry"], pair["b"]["entry"]]], reason="undo")
            assert un["retracted"], un

            # The emulator: fib(10) = 55.
            emu = await call("emu_start", program_id=a, entry=fib, mode="call", args=["10"])
            eid = emu["session_id"]
            await call("emu_breakpoints", session_id=eid, set=[fib])
            stopped = await call("emu_run", session_id=eid, mode="into")
            assert stopped
            await call("emu_breakpoints", session_id=eid, clear=[fib])
            done = await call("emu_run", session_id=eid, mode="run", registers=["RAX"])
            state = await call("emu_state", session_id=eid, registers=["RAX", "RSP"])
            assert "55" in json.dumps(done) or "0x37" in json.dumps(state) or "55" in json.dumps(state), (done, state)
            regs = json.dumps(state)
            assert "RSP" in regs
            await call("emu_read_memory", session_id=eid, address=fib, length=8)
            await call("emu_write", session_id=eid, registers={"RAX": "0x10"})
            await call("emu_close", session_id=eid)

            # The debugger over the emulator: a breakpoint, a step, the timeline.
            dbg = await call("debug_start", program_id=a, target="emulator", entry=fib, mode="call", args=["6"], breakpoints=[twice])
            did = dbg["session_id"]
            await call("debug_run", session_id=did, mode="into")
            await call("debug_state", session_id=did, registers=["RIP"])
            await call("debug_read_memory", session_id=did, address=fib, length=8)
            await call("debug_breakpoints", session_id=did, set=[fib])
            assert (await call("debug_timeline", session_id=did, limit=10))
            await call("debug_modules", session_id=did)
            await call("debug_close", session_id=did)

    try:
        anyio.run(run)
    finally:
        server.revkit_client.close()


def test_patching_tools(image_daemon, binaries, tmp_path):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        pid = rk.import_program("default", path=str(binaries[0]), name="patchme").program.program_id
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-patch")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def raw(name, **args):
                return _json(await mcp.call_tool(name, args))

            async def call(name, **args):
                r = await raw(name, **args)
                assert "error" not in r, (name, r)
                return r

            tools = {t.name for t in (await mcp.list_tools()).tools}
            assert {"assemble", "patch_instruction", "patch_bytes", "list_patches", "revert_patch", "detect_checksum",
                    "export_patched"} <= tools

            # main returns counter & 0x7f: the mask is the instruction to change.
            main = (await call("search_symbols", program_id=pid, name_equals="main"))["symbols"][0]["address"]
            graph = await call("function_graph", program_id=pid, function_address=main)
            line = next(i for b in graph["blocks"] for i in b["instructions"] if "0x7f" in i)
            at, old = line.split(None, 1)
            new = old.replace("0x7f", "0x3f")

            # assemble writes nothing: the candidates, or what is wrong and where.
            asm = await call("assemble", program_id=pid, address=at, text=new)
            assert asm["candidates"] and "assembly_error" not in asm, asm
            assert asm["current_text"] and asm["current_bytes"]
            best = asm["candidates"][0]
            assert best["length"] == len(asm["current_bytes"]) // 2 and best["bits_changed"] >= 1
            same = await call("assemble", program_id=pid, address=at, text=old)
            assert any(c["current"] and c["bytes"] == asm["current_bytes"] for c in same["candidates"]), same
            bad = await call("assemble", program_id=pid, address=at, text="MOV EAX,")
            assert not bad["candidates"] and bad["assembly_error"]["message"] and bad["assembly_error"]["expected"], bad
            assert (await call("list_patches", program_id=pid))["patches"] == []

            # Patch the instruction (the agent's edit), then a byte of a string.
            done = await call("patch_instruction", program_id=pid, address=at, text=new, reason="narrow the exit status mask")
            assert done["seqs"] and done["bytes"] == best["bytes"] and done["provenance"] == "agent:claude@test"
            assert "0x3f" in done["text"]
            text_at = (await call("list_strings", program_id=pid, text_contains="fib is"))["data"][0]["address"]
            assert (await call("read_memory", program_id=pid, address=text_at, length=3))["hex"] == b"fib".hex()
            wrote = await call("patch_bytes", program_id=pid, address=text_at, hex_bytes="46 49", reason="capitalise the message")
            assert wrote["length"] == 2 and len(wrote["seqs"]) == 1
            assert (await call("read_memory", program_id=pid, address=text_at, length=3))["hex"] == b"FIb".hex()

            # Listed in address order, with what was there, who and why; every view reads the patched bytes.
            listed = (await call("list_patches", program_id=pid))["patches"]
            assert [p["address"] for p in listed] == sorted([at, text_at], key=lambda a: int(a, 16))
            insn = next(p for p in listed if p["address"] == at)
            assert insn["seq"] == done["seqs"][0] and insn["bytes"] == best["bytes"] and insn["original"] == asm["current_bytes"]
            assert "0x7f" in insn["original_text"] and "0x3f" in insn["text"] and insn["typed"] == new
            assert insn["by"] == "agent:claude@test" and insn["reason"] == "narrow the exit status mask"
            assert insn["function_name"] == "main"
            assert [p["address"] for p in (await call("list_patches", program_id=pid, first=at, last=at))["patches"]] == [at]
            assert "0x3f" in (await call("disassemble", program_id=pid, address=at, max_rows=1))["listing"]
            assert "0x3f" in (await call("decompile", program_id=pid, function_address=main))["c"]
            mine = await call("list_my_changes", program_id=pid)
            assert len(mine["changes"]) == 2

            # Export: nothing written without a destination; then the file, its 32-bit sum in its name.
            original = binaries[0].read_bytes()
            name_rule = {"algorithm": "sum32", "name": True}
            dry = await call("export_patched", program_id=pid, fixups=[name_rule], file_name_template="{NAME}_{SUM:08X}.bin")
            assert dry["verified"] and dry["size"] == len(original) and "saved" not in dry, dry
            assert [c["what"] for c in dry["changes"]].count("patch") == 2 and dry["fixups"], dry
            saved = await call("export_patched", program_id=pid, save_to=str(tmp_path), fixups=[name_rule],
                               file_name_template="{NAME}_{SUM:08X}.bin")
            assert saved["saved"] and saved["file_name"] == dry["file_name"] and saved["sha256"] == dry["sha256"]
            data = (tmp_path / saved["file_name"]).read_bytes()
            assert saved["path"] == str(tmp_path / saved["file_name"])
            assert saved["file_name"] == "patchme_%08X.bin" % (sum(data) & 0xFFFFFFFF)
            assert len(data) == len(original) and sum(x != y for x, y in zip(data, original)) == 3
            again = await call("export_patched", program_id=pid, save_to=str(tmp_path), fixups=[name_rule],
                               file_name_template="{NAME}_{SUM:08X}.bin")
            assert again["saved"] is False and "exists" in again["note"]

            # The detector finds that rule from the name, and its hit goes back into an export as it is.
            found = await call("detect_checksum", program_id=pid, file_name=saved["file_name"], patched=True)
            hit = found["hits"][0]
            assert hit["rule"] == {"algorithm": "sum32", "start": "0x0", "end": 0, "name": True}, found
            assert hit["file_name_template"] == "patchme_{SUM:08X}.bin" and "sum32" in hit["evidence"]
            back = await call("export_patched", program_id=pid, fixups=[hit["rule"]], file_name_template=hit["file_name_template"])
            assert back["file_name"] == saved["file_name"]

            # Bad arguments are data the model can read, and write nothing.
            for name, args in (("patch_bytes", {"address": text_at, "hex_bytes": "zz", "reason": "r"}),
                               ("patch_instruction", {"address": at, "text": "MOV EAX,", "reason": "r"}),
                               ("revert_patch", {"reason": "r"}),
                               ("export_patched", {"fixups": [{"algorithm": "sum32"}]}),
                               ("export_patched", {"fixups": [{"algorithm": "md5", "name": True}]})):
                r = await raw(name, program_id=pid, **args)
                assert r.get("error") in ("INVALID_ARGUMENT", "FAILED_PRECONDITION"), (name, r)
            assert len((await call("list_patches", program_id=pid))["patches"]) == 2

            # Revert: one by address, the other by seq; the original bytes show again.
            r1 = await call("revert_patch", program_id=pid, address=text_at, reason="keep the message")
            assert r1["reverted"] == 1
            assert [p["address"] for p in (await call("list_patches", program_id=pid))["patches"]] == [at]
            assert (await call("read_memory", program_id=pid, address=text_at, length=3))["hex"] == b"fib".hex()
            r2 = await call("revert_patch", program_id=pid, seqs=done["seqs"], reason="the mask was right")
            assert r2["reverted"] == 1
            assert (await call("list_patches", program_id=pid))["patches"] == []
            assert "0x7f" in (await call("disassemble", program_id=pid, address=at, max_rows=1))["listing"]
            clean = await call("export_patched", program_id=pid, save_to=str(tmp_path / "clean.bin"))
            assert clean["saved"] and (tmp_path / "clean.bin").read_bytes() == original
            # Undoing a revert brings the patch back; reverting the session's edits removes it for good.
            await call("undo_changes", program_id=pid, seqs=r2["seqs"], reason="testing redo")
            assert [p["address"] for p in (await call("list_patches", program_id=pid))["patches"]] == [at]
            assert (await call("revert_my_changes", program_id=pid))["retracted"] >= 1
            assert (await call("list_patches", program_id=pid))["patches"] == []

    try:
        anyio.run(run)
    finally:
        server.revkit_client.close()
    # A human sees whose patches they were.
    with Client(image_daemon.grpc_target, actor="user:reviewer") as rk:
        edits = rk.program(pid).assertions(actor="agent:claude", session="mcp-patch", include_inactive=True)
        assert len(edits) >= 2 and all(a.provenance.kind == edits[0].provenance.kind for a in edits)


FWEMU = Path(__file__).resolve().parents[3] / "src" / "emu" / "tests" / "fixtures" / "fwemu"


@pytest.fixture(scope="module")
def firmware(tmp_path_factory):
    tools = [shutil.which(t) for t in ("clang", "ld.lld", "llvm-objcopy")]
    if not all(tools):
        pytest.skip("needs clang, ld.lld and llvm-objcopy")
    out = tmp_path_factory.mktemp("mcp-fwemu")
    subprocess.run(["sh", str(FWEMU / "build.sh"), *tools, str(out)], check=True, capture_output=True)
    return out


def test_firmware_on_a_machine(image_daemon, firmware):
    """emu_start's machine (a description, a saved machine's name, a derived starter), emu_input and
    emu_machine, and debug_start on a machine: the UART echo and timer fixtures on versatilepb."""
    board = (FWEMU / "versatilepb.json").read_text()
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        def raw(name):
            return rk.import_program("default", path=str(firmware / f"{name}.bin"), name=f"mcp_{name}", format="raw",
                                     language_id="ARM:LE:32:v4t").program.program_id
        uart, timer = raw("arm_uart"), raw("arm_timer")
        rk.program(timer).save_machine("versatilepb", board)
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-firmware")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(name, **args):
                r = _json(await mcp.call_tool(name, args))
                assert "error" not in r, (name, r)
                return r

            tools = {t.name for t in (await mcp.list_tools()).tools}
            assert {"emu_machine", "emu_input"} <= tools, sorted(tools)

            # A description: the program waits for the UART, echoes what it gets, and exits.
            emu = await call("emu_start", program_id=uart, machine=board)
            eid = emu["session_id"]
            assert emu["machine"]["cpu"] == "arm", emu
            assert "IDLE" in json.dumps(await call("emu_run", session_id=eid)).upper()
            assert (await call("emu_input", session_id=eid, text="hi\nquit\n"))["sent"] == 8
            assert "EXITED" in json.dumps(await call("emu_run", session_id=eid)).upper()
            assert "echo: HI" in (await call("emu_state", session_id=eid))["stdout"]
            machine = await call("emu_machine", session_id=eid)
            assert machine["state"]["cpu"] == "arm"
            assert any(e["kind"] == "irq" and e.get("source") == "vic" for e in machine["events"]), machine
            await call("emu_close", session_id=eid)

            # A saved machine by name, stopping on the first FIQ (at its vector, 0x1c).
            emu = await call("emu_start", program_id=timer, machine="versatilepb")
            eid = emu["session_id"]
            assert (await call("emu_input", session_id=eid, break_on=["fiq"]))["break_on"] == ["fiq"]
            hit = await call("emu_run", session_id=eid)
            assert "EXCEPTION" in json.dumps(hit).upper(), hit
            assert (await call("emu_state", session_id=eid))["state"]["pc"] == "0x1c"
            await call("emu_close", session_id=eid)

            # A derived starter: the description comes back, with notes, and the session runs on it.
            emu = await call("emu_start", program_id=timer, derive_machine=True)
            derived = emu["derived_machine"]
            assert '"memory"' in derived and emu["notes"], emu
            assert emu["machine"]["cpu"] == "arm"
            await call("emu_run", session_id=emu["session_id"], max_steps=1000)
            await call("emu_close", session_id=emu["session_id"])

            # The debugger on a machine: the timeline marks the exceptions.
            dbg = await call("debug_start", program_id=timer, machine=board)
            did = dbg["session_id"]
            assert "EXITED" in json.dumps(await call("debug_run", session_id=did)).upper()
            await call("debug_close", session_id=did)

    anyio.run(run)


ARMFW = Path(__file__).resolve().parents[3] / "src" / "analysis" / "tests" / "fixtures" / "armfw"


@pytest.fixture(scope="module")
def armfw(tmp_path_factory):
    """The synthetic ARM firmware: scaled up with generated functions (about 250 KB), and as built (1 KB)."""
    tools = [shutil.which(t) for t in ("clang", "ld.lld", "llvm-objcopy")]
    if not all(tools):
        pytest.skip("needs clang, ld.lld and llvm-objcopy")
    out = tmp_path_factory.mktemp("mcp-armfw")
    subprocess.run(["sh", str(ARMFW / "build.sh"), *tools, str(out / "bulk"), "-O2", "1500"], check=True, capture_output=True)
    subprocess.run(["sh", str(ARMFW / "build.sh"), *tools, str(out / "small")], check=True, capture_output=True)
    return out


def test_detect_raw_layout(image_daemon, armfw, tmp_path):
    """detect_raw_layout: a suggestion with its confidence, evidence and tie group, a language hint, a
    refusal, the daemon's error, and import_program taking what it suggested (raw_offset, regions)."""
    (tmp_path / "noise.bin").write_bytes(os.urandom(1 << 15))
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-detect")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                result = await mcp.call_tool(tool, args)
                assert not result.is_error, result
                return json.loads(result.content[0].text)

            tools = {t.name: t for t in (await mcp.list_tools()).tools}
            assert "detect_raw_layout" in tools
            assert tools["detect_raw_layout"].annotations.read_only_hint

            r = await call("detect_raw_layout", project_id="default", path=str(armfw / "bulk" / "fw.bin"), processor="ARM")
            assert r["refusal"] is None, r
            top = r["suggestions"][0]
            assert top["language_id"].startswith("ARM:LE:32:") and top["compiler_spec_id"] == "default"
            assert top["raw_offset"] == "0x0"
            # Each region with its kind, confidence and evidence; the classified ones are `regions`.
            assert top["regions"] == [d["region"] for d in top["region_details"] if d["kind"] != "unknown"]
            assert all(d["kind"] in ("ram", "mmio", "unknown") and d["confidence"] in ("low", "medium", "high")
                       and d["evidence"] and d["start"].startswith("0x") for d in top["region_details"])
            assert top["image_base"] is None or top["image_base"].startswith("0x")
            assert set(top["confidence"]) == {"processor", "variant", "base", "offset"}
            assert top["confidence"]["processor"] in ("medium", "high")
            assert top["evidence"] and top["evidence"][0]["about"] == "processor"
            assert any(t.startswith("ARM:LE:32:v4t") for t in [top["language_id"], *top["tie_group"]])
            assert r["segments"] and r["segments"][0]["kind"] == "code" and r["segments"][0]["offset"] == "0x0"
            assert r["file_size"] == (armfw / "bulk" / "fw.bin").stat().st_size

            pinned = await call("detect_raw_layout", project_id="default", path=str(armfw / "bulk" / "fw.bin"),
                                language_id="ARM:LE:32:v4t")
            assert pinned["suggestions"][0]["language_pinned"] and pinned["suggestions"][0]["language_id"] == "ARM:LE:32:v4t"

            refused = await call("detect_raw_layout", project_id="default", path=str(tmp_path / "noise.bin"))
            assert refused["refusal"]["reason"] == "high-entropy" and refused["suggestions"] == []
            assert refused["segments"][0]["kind"] == "high_entropy"

            # The daemon's errors come back as the tool's.
            missing = await call("detect_raw_layout", project_id="default", path=str(tmp_path / "missing"))
            assert "error" in missing, missing

            # What it suggests is what import_program takes.
            s = pinned["suggestions"][0]
            imported = await call("import_program", project_id="default", path=str(armfw / "small" / "fw.bin"),
                                  name="mcp-detected", format="raw", language_id=s["language_id"],
                                  image_base=s["image_base"] or "", raw_offset=s["raw_offset"], regions=s["regions"])
            assert imported["program"]["language_id"] == "ARM:LE:32:v4t", imported

    try:
        anyio.run(run)
    finally:
        server.revkit_client.close()
