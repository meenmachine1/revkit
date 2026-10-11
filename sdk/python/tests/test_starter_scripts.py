"""The starter scripts (revkit/scripts, rk-script list) on the compiled
fixture (tests/fixtures/script_target.c): each finds what the fixture
plants, and its edits are one revision that revert(session) undoes."""

import csv
import io
import json

import pytest

from revkit import Client, Daemon
from revkit.script import HeadlessHost, find_script, run_script


@pytest.fixture(scope="module")
def daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture(scope="module")
def rk(daemon):
    with Client(daemon.grpc_target, actor="user:tester") as c:
        yield c


@pytest.fixture(scope="module")
def plain(rk, script_target):
    return rk.import_program("default", path=str(script_target["plain"]), name="plain").program.program_id


@pytest.fixture(scope="module")
def stripped(rk, script_target):
    return rk.import_program("default", path=str(script_target["stripped"]), name="stripped").program.program_id


def run(rk, program, name, **args):
    host = HeadlessHost({}, out=io.StringIO(), err=io.StringIO(), interactive=False)
    r = run_script(find_script(name), client=rk, program_id=program, args={k: str(v) for k, v in args.items()}, host=host)
    assert r.ok, (r.error, r.traceback, host.err.getvalue())
    return r, host.out.getvalue()


def fn(rk, program, name):
    return next(f for f in rk.program(program).functions() if f.name == name)


def undo(rk, program, r):
    if r.revisions:
        rk.program(program).revert(session=r.run_id, actor="user:tester")


def test_rename_by_strings(rk, stripped):
    prog = rk.program(stripped)
    assert not {"parse_config", "open_database"} & {f.name for f in prog.functions()}
    r, out = run(rk, stripped, "rename_by_strings", dry_run="true")
    assert not r.revisions and "would be renamed" in out
    r, out = run(rk, stripped, "rename_by_strings")
    assert len(r.revisions) == 1
    names = {f.name for f in prog.functions()}
    assert {"parse_config", "open_database"} <= names, out
    undo(rk, stripped, r)
    assert "parse_config" not in {f.name for f in prog.functions()}


def test_find_crypto_constants(rk, plain):
    r, out = run(rk, plain, "find_crypto_constants")
    assert "AES S-box" in out and "SHA-256 initial hash values" in out, out
    notes = [a for a in rk.program(plain).assertions(session=r.run_id) if a.body.HasField("note")]
    assert {n.body.note.tag for n in notes} == {"crypto"} and len(notes) >= 2
    assert any("used by mix" in n.body.note.text for n in notes), [n.body.note.text for n in notes]
    undo(rk, plain, r)


def test_decrypt_strings(rk, plain):
    r, out = run(rk, plain, "decrypt_strings", decryptor="decrypt")
    assert '"hello secret"' in out, out
    comments = [a.body.comment.text for a in rk.program(plain).assertions(session=r.run_id)]
    assert comments == ['decrypted: "hello secret"']
    undo(rk, plain, r)


def test_export_functions(rk, plain, tmp_path):
    out_json = tmp_path / "f.json"
    run(rk, plain, "export_functions", out=out_json, decompile="true")
    data = json.loads(out_json.read_text())
    mix = next(f for f in data["functions"] if f["name"] == "mix")
    assert "mix" in mix["c"] and mix["size"] > 0 and not mix["decompile_failed"]
    out_csv = tmp_path / "f.csv"
    run(rk, plain, "export_functions", out=out_csv, format="csv")
    rows = list(csv.DictReader(out_csv.open()))
    assert any(r["name"] == "decrypt" for r in rows) and "c" not in rows[0]


def test_batch_decompile(rk, plain, tmp_path):
    report = tmp_path / "report.json"
    r, out = run(rk, plain, "batch_decompile", out=report)
    data = json.loads(report.read_text())
    n = sum(1 for _ in rk.program(plain).functions())
    assert data["functions"] == n and data["decompiled"] + data["errors"] + sum(data["failed"].values()) >= n
    assert data["decompiled"] > 0 and data["function_ms"]["p50"] >= 0 and "decompiled in" in out
    r, out = run(rk, plain, "batch_decompile", functions="mix,decrypt", text="true")
    assert "2/2 decompiled" in out


def test_xref_report(rk, plain, tmp_path):
    out_file = tmp_path / "x.json"
    r, out = run(rk, plain, "xref_report", target="decrypt", out=out_file)
    assert "reference(s) to decrypt" in out and "main" in out and "CALL" in out, out
    data = json.loads(out_file.read_text())
    assert data["name"] == "decrypt" and data["references"]["main"][0]["kind"] == "call"


def test_create_functions_at_call_targets(rk, plain):
    prog = rk.program(plain)
    mix = fn(rk, plain, "mix").entry.offset
    # Someone (an agent) removed a called function; the script puts it back.
    prog.remove_function(mix, actor="agent:test")
    assert mix not in {f.entry.offset for f in prog.functions()}
    r, out = run(rk, plain, "create_functions_at_call_targets")
    assert f"0x{mix:x}" in out and len(r.revisions) == 1
    assert mix in {f.entry.offset for f in prog.functions()}
    undo(rk, plain, r)
    prog.revert(kind="agent", id="test", actor="user:tester")
    assert mix in {f.entry.offset for f in prog.functions()}
    r, out = run(rk, plain, "create_functions_at_call_targets")
    assert "0 function(s) created" in out


def test_find_format_string_sinks(rk, plain):
    r, out = run(rk, plain, "find_format_string_sinks")
    lines = [line for line in out.splitlines() if "non-constant format" in line]
    assert len(lines) == 1 and "in log_user" in lines[0], out
    notes = rk.program(plain).assertions(session=r.run_id)
    assert len(notes) == 1 and notes[0].body.note.tag == "format-sink"
    undo(rk, plain, r)


def test_comment_syscalls(rk, plain):
    r, out = run(rk, plain, "comment_syscalls")
    assert "syscall getpid (39)" in out, out
    getpid = fn(rk, plain, "raw_getpid")
    comments = rk.program(plain).assertions(session=r.run_id)
    assert any(c.body.comment.text == "syscall getpid (39)" for c in comments)
    body = getpid.body[0]
    assert all(body.first.offset <= c.body.comment.address.offset <= body.last.offset for c in comments
               if "getpid" in c.body.comment.text)
    undo(rk, plain, r)


def test_list_unreferenced_data(rk, plain, tmp_path):
    out_file = tmp_path / "u.json"
    r, out = run(rk, plain, "list_unreferenced_data", out=out_file)
    rows = json.loads(out_file.read_text())["unreferenced"]
    values = [row["value"] for row in rows]
    assert "this string is never referenced" in values, out
    assert "parse_config: missing value\n" not in values
    assert not r.revisions


def test_tag_functions_by_complexity(rk, plain):
    r, out = run(rk, plain, "tag_functions_by_complexity", measure="instructions", dry_run="true")
    assert not r.revisions and "function(s) at or over instructions" in out, out
    r, out = run(rk, plain, "tag_functions_by_complexity", measure="size", threshold=1)
    assert len(r.revisions) == 1
    comments = [a.body.comment.text for a in rk.program(plain).assertions(session=r.run_id)]
    assert comments and all(c.startswith("complexity: size ") for c in comments)
    assert len(comments) == len([f for f in rk.program(plain).functions() if not f.external and not f.thunk])
    undo(rk, plain, r)


def test_summarize_function(rk, plain):
    main = fn(rk, plain, "main")
    host = HeadlessHost({}, out=io.StringIO(), err=io.StringIO(), interactive=False)
    r = run_script(find_script("summarize_function"), client=rk, program_id=plain, host=host,
                   context={"address": hex(main.entry.offset + 1)})
    assert r.ok, (r.error, r.traceback)
    text = rk.program(plain).assertions(session=r.run_id)[0].body.comment.text
    assert text.startswith("main: ") and "instructions" in text and "calls " in text and "parse_config" in text, text
    undo(rk, plain, r)
    host = HeadlessHost({}, out=io.StringIO(), err=io.StringIO(), interactive=False)
    assert not run_script(find_script("summarize_function"), client=rk, program_id=plain, host=host).ok


def test_export_call_graph(rk, plain, tmp_path):
    dot = tmp_path / "g.dot"
    r, out = run(rk, plain, "export_call_graph", out=dot)
    text = dot.read_text()
    funcs = {f.name: f"0x{f.entry.offset:x}" for f in rk.program(plain).functions()}
    assert text.startswith("digraph ") and f'"{funcs["main"]}" -> "{funcs["decrypt"]}"' in text, text
    assert f'"{funcs["main"]}" [label="main"]' in text and "call edge(s)" in out
    # From a root, to a depth, as JSON, without imports.
    js = tmp_path / "g.json"
    run(rk, plain, "export_call_graph", out=js, root="main", depth=1, externals="false", format="json")
    data = json.loads(js.read_text())
    names = {f["name"] for f in data["functions"]}
    assert {"main", "decrypt", "parse_config", "mix", "log_user"} <= names and "printf" not in names, names
    assert all(c["from"] == funcs["main"] for c in data["calls"])


def test_apply_header(rk, plain, tmp_path):
    header = tmp_path / "target.h"
    header.write_text(
        "struct db_handle { int fd; const char *path; };\n"
        "int parse_config(const char *text);\n"
        "int open_database(const char *db_path);\n"
        "void decrypt(unsigned char *buf, int len);\n"
        "int not_in_the_program(void);\n"
    )
    r, out = run(rk, plain, "apply_header", header=header, dry_run="true")
    assert "3 function(s) would be retyped" in out and "not_in_the_program" in out and not r.revisions, out
    r, out = run(rk, plain, "apply_header", header=header)
    assert len(r.revisions) == 2 and "3 function(s) retyped" in out, out  # the types, then the prototypes
    assert "buf" in fn(rk, plain, "decrypt").prototype and "db_path" in fn(rk, plain, "open_database").prototype
    assert rk.program(plain).find_types("db_handle")
    undo(rk, plain, r)
    assert "buf" not in fn(rk, plain, "decrypt").prototype


def test_name_wrappers(rk, stripped):
    r, out = run(rk, stripped, "name_wrappers", dry_run="true")
    assert "printf_wrapper" in out and not r.revisions, out
    r, out = run(rk, stripped, "name_wrappers")
    names = {f.name for f in rk.program(stripped).functions()}
    assert "printf_wrapper" in names and len(r.revisions) == 1, out
    undo(rk, stripped, r)
    assert "printf_wrapper" not in {f.name for f in rk.program(stripped).functions()}


def test_find_dangerous_calls(rk, plain):
    r, out = run(rk, plain, "find_dangerous_calls")
    assert "0 call(s)" in out and not r.revisions  # the fixture calls nothing on the list
    # Compilers make fprintf of a constant fwrite, and printf the fortified
    # __printf_chk, which counts as printf.
    r, out = run(rk, plain, "find_dangerous_calls", functions="strlen,fwrite,fprintf,printf")
    assert "parse_config:" in out and "open_database:" in out and "log_user:" in out, out
    assert "strlen" in out and " printf" in out, out
    notes = [a.body.note for a in rk.program(plain).assertions(session=r.run_id)]
    assert len(notes) >= 4 and {n.tag for n in notes} == {"dangerous-call"}
    undo(rk, plain, r)


def test_export_strings(rk, plain, tmp_path):
    out_json = tmp_path / "s.json"
    run(rk, plain, "export_strings", out=out_json)
    rows = json.loads(out_json.read_text())["strings"]
    row = next(r for r in rows if r["value"].startswith("parse_config: missing value"))
    assert row["functions"] == ["parse_config"] and row["references"] >= 1
    out_csv = tmp_path / "s.csv"
    run(rk, plain, "export_strings", out=out_csv, format="csv", contains="open_database")
    rows = list(csv.DictReader(out_csv.open()))
    assert len(rows) == 1 and rows[0]["functions"] == "open_database"


def test_search_instructions(rk, plain):
    r, out = run(rk, plain, "search_instructions", pattern=r"^syscall", note="true")
    assert "1 match(es)" in out and "in raw_getpid" in out, out
    notes = [a.body.note for a in rk.program(plain).assertions(session=r.run_id)]
    assert len(notes) == 1 and notes[0].tag == "search"
    undo(rk, plain, r)
    r, out = run(rk, plain, "search_instructions", pattern=r"xor .*0x5a")
    assert "in decrypt" in out, out


def test_dump_memory(rk, plain, tmp_path):
    iv = next(s for s in rk.program(plain).symbols(name_equals="sha256_iv")).address.offset
    raw = tmp_path / "iv.bin"
    run(rk, plain, "dump_memory", out=raw, start=hex(iv), length=32)
    assert raw.read_bytes()[:8] == bytes.fromhex("67e6096a85ae67bb")
    c_file = tmp_path / "iv.c"
    host = HeadlessHost({}, out=io.StringIO(), err=io.StringIO(), interactive=False)
    r = run_script(find_script("dump_memory"), client=rk, program_id=plain, host=host,
                   args={"out": str(c_file), "format": "c"}, context={"selection": [hex(iv), hex(iv + 7)]})
    assert r.ok, r.error
    assert "const unsigned char sha256_iv[8]" in c_file.read_text() and "0x67, 0xe6" in c_file.read_text()


def test_function_signatures_name_the_stripped_build(rk, plain, stripped, tmp_path):
    sigs = tmp_path / "sigs.json"
    r, out = run(rk, plain, "export_function_signatures", out=sigs)
    data = json.loads(sigs.read_text())
    assert {"decrypt", "mix", "parse_config"} <= {f["name"] for f in data["functions"]}, out
    r, out = run(rk, stripped, "apply_function_signatures", signatures=sigs, dry_run="true")
    assert "-> decrypt" in out and not r.revisions, out
    r, out = run(rk, stripped, "apply_function_signatures", signatures=sigs)
    names = {f.name for f in rk.program(stripped).functions()}
    assert {"decrypt", "mix", "parse_config", "open_database"} <= names, out
    undo(rk, stripped, r)


def test_list_notes(rk, plain, tmp_path):
    r1, _ = run(rk, plain, "find_crypto_constants")
    out_file = tmp_path / "notes.json"
    r, out = run(rk, plain, "list_notes", tag="crypto", out=out_file)
    assert "crypto (" in out and "AES S-box" in out, out
    assert json.loads(out_file.read_text())["notes"]["crypto"]
    undo(rk, plain, r1)
