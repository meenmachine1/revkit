"""revkit.script and rk-script (docs/scripting.md) on the image backend: a
run's edits are one revision with script provenance, revert(session)
restores the head, a person's later edit survives a re-run, bad edits and
failures commit nothing and name the script's line, prompts are answered by
--arg or fail fast, the stream host speaks JSON lines, and the CLI runs
programs in host processes with a JSON summary."""

import io
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from revkit import Client, Daemon, describe_provenance, format_provenance
from revkit.script import (HeadlessHost, PromptUnanswered, StreamHost, list_scripts, parse_metadata, read_metadata,
                           run_script)
from revkit.v1 import common_pb2

SDK = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture(scope="module")
def program(daemon, script_target):
    with Client(daemon.grpc_target, actor="user:tester") as rk:
        return rk.import_program("default", path=str(script_target["plain"])).program.program_id


@pytest.fixture
def rk(daemon):
    with Client(daemon.grpc_target, actor="user:tester") as c:
        yield c


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


def fn(prog, name):
    return next(f for f in prog.functions() if f.name == name)


def quiet(answers=None):
    return HeadlessHost(answers, out=io.StringIO(), err=io.StringIO(), interactive=False)


RENAMES = """\
# @category Tests
# @description Renames two functions
from revkit.script import *
a = function_at(ask_address("first", "First function"))
rename(a, "first_" + a.name)
rename(ask_address("second", "Second function", "open_database"), "db_open")
print("renamed", a.name)
"""


def test_one_revision_provenance_revert_and_precedence(rk, program, tmp_path):
    prog = rk.program(program)
    s = write(tmp_path, "fix_names.py", RENAMES)
    head = prog.summary().snapshot.revision if hasattr(prog.summary(), "snapshot") else None
    host = quiet()
    r = run_script(s, client=rk, program_id=program, args={"first": "parse_config"}, host=host)
    assert r.ok, r.traceback
    assert len(r.revisions) == 1 and r.assertions == 2
    assert "renamed parse_config" in host.out.getvalue()
    names = {f.name for f in prog.functions()}
    assert {"first_parse_config", "db_open"} <= names
    # Provenance: script:<name>@<sha12>, the run as session, who ran it.
    mine = prog.assertions(session=r.run_id)
    assert len(mine) == 2
    p = mine[0].provenance
    assert p.kind == common_pb2.PROVENANCE_KIND_SCRIPT
    assert format_provenance(p) == f"script:fix_names@{r.version}"
    assert p.tool == f"script:fix_names@{r.version}" and p.session == r.run_id
    assert p.reason == "Renames two functions" and p.on_behalf_of == "user:tester"
    assert describe_provenance(p) == "tester via script:fix_names"
    assert len(prog.assertions(actor="script:fix_names", on_behalf_of="user:tester")) == 2
    assert prog.assertions(on_behalf_of="user:nobody") == []
    blame = prog.blame(prog.key("name", fn(prog, "db_open").entry.offset))
    assert blame.origin.asserted.provenance.on_behalf_of == "user:tester"

    # revert(session) restores what was there.
    reverted = prog.revert(session=r.run_id, actor="user:tester")
    assert len(reverted.retracted_seqs) == 2
    names = {f.name for f in prog.functions()}
    assert "parse_config" in names and "open_database" in names and "db_open" not in names

    # A person's edit after a run survives running the script again.
    r2 = run_script(s, client=rk, program_id=program, args={"first": "parse_config"}, host=quiet())
    assert r2.ok
    prog.rename(fn(prog, "db_open").entry.offset, "database_open")
    r3 = run_script(s, client=rk, program_id=program, args={"first": "log_safe", "second": "database_open"}, host=quiet())
    assert r3.ok
    names = {f.name for f in prog.functions()}
    assert "database_open" in names and "db_open" not in names
    prog.revert(session=r2.run_id, actor="user:tester")
    prog.revert(session=r3.run_id, actor="user:tester")
    assert {"log_safe", "parse_config", "database_open"} <= {f.name for f in prog.functions()}


def test_failures_commit_nothing_and_name_the_line(rk, program, tmp_path):
    prog = rk.program(program)
    before = len(prog.assertions(include_inactive=True))
    bad = write(tmp_path, "bad_edit.py", "rename(to_addr('log_safe'), 'ok_name')\ncomment(to_addr('log_safe'), 'x', kind='eol')\n"
                "rename_local(0x10, 'param:0', 'nothing_here')\n")
    r = run_script(bad, client=rk, program_id=program, host=quiet())
    assert r.status == "error" and "bad_edit.py:3" in r.error, r.error
    assert len(prog.assertions(include_inactive=True)) == before

    boom = write(tmp_path, "boom.py", "rename(to_addr('log_safe'), 'never')\n\ndef f():\n    raise ValueError('no')\nf()\n")
    r = run_script(boom, client=rk, program_id=program, host=quiet())
    assert r.status == "error" and r.error == "ValueError: no"
    assert r.error_file == str(boom.resolve()) and r.error_line == 4
    assert 'boom.py", line 5' in r.traceback and "runtime.py" not in r.traceback
    assert r.discarded == 1
    assert len(prog.assertions(include_inactive=True)) == before

    exits = write(tmp_path, "exits.py", "import sys\nrename(to_addr('log_safe'), 'never')\nsys.exit(2)\n")
    r = run_script(exits, client=rk, program_id=program, host=quiet())
    assert r.status == "error" and r.exit_code == 2

    cancels = write(tmp_path, "cancels.py", "monitor.set_max(3)\nmonitor.cancel()\nmonitor.increment()\n")
    r = run_script(cancels, client=rk, program_id=program, host=quiet())
    assert r.status == "cancelled"

    syntax = write(tmp_path, "syntax.py", "x = (\n")
    r = run_script(syntax, client=rk, program_id=program, host=quiet())
    assert r.status == "error" and r.error_type == "SyntaxError"


def test_commit_early_and_reads(rk, program, tmp_path):
    prog = rk.program(program)
    s = write(tmp_path, "staged.py", """\
from revkit.script import *
note(to_addr("mix"), "first stage", tag="test")
first = commit("stage one")
note(to_addr("mix"), "second stage", tag="test2")
assert pending_edits() == 1
hits = find_bytes("67 e6 09 6a")
assert hits, "sha256 IV not found"
n = sum(1 for _ in instructions(function="mix"))
assert n > 2
assert any(s.value == "parse_config: missing value\\n" for s in strings("parse_config"))
done = list(decompile_many(["mix", "decrypt"]))
assert sorted(r.function.name for r in done) == ["decrypt", "mix"], [r.function.name for r in done]
print(current_address, current_function.name if current_function else None, current_selection)
""")
    host = quiet()
    r = run_script(s, client=rk, program_id=program, host=host,
                   context={"address": hex(fn(prog, "mix").entry.offset + 1), "selection": ["0x10", "0x20"]})
    assert r.ok, r.traceback
    assert len(r.revisions) == 2 and r.revisions[0] < r.revisions[1]
    assert f"{fn(prog, 'mix').entry.offset + 1} mix (16, 32)" in host.out.getvalue()
    prog.revert(session=r.run_id, actor="user:tester")


def test_prompts(rk, program, tmp_path):
    s = write(tmp_path, "asks.py", """\
n = ask_int("count", "How many", 3)
yes = ask_yes_no("really", "Sure?")
pick = ask_choice("mode", "Mode", ["fast", "slow"])
many = ask_choices("which", "Which", ["a", "b", "c"])
where = ask_address("where", "Where")
vals = ask_values({"prefix": "sub_", "limit": 5})
print(n, yes, pick, many, hex(where), vals, args)
""")
    host = quiet()
    r = run_script(s, client=rk, program_id=program, host=host,
                   args={"really": "yes", "mode": "slow", "which": "a,c", "where": "main", "limit": "7"})
    assert r.ok, r.traceback
    assert "3 True slow ['a', 'c'] 0x" in host.out.getvalue()
    assert "{'prefix': 'sub_', 'limit': 7}" in host.out.getvalue()
    # Headless with no answer: fails at once, naming the --arg.
    r = run_script(s, client=rk, program_id=program, host=quiet(), args={})
    assert r.status == "error" and r.error_type == "PromptUnanswered" and "--arg really=" in r.error
    r = run_script(s, client=rk, program_id=program, host=quiet(), args={"really": "yes", "mode": "medium"})
    assert r.status == "error" and "not one of" in r.error
    # Answers from stdin, one per line.
    stdin = io.StringIO("4\nno\nfast\nb\n0x10\n\n\n")
    host = HeadlessHost({}, stdin=stdin, interactive=True, out=io.StringIO(), err=io.StringIO())
    r = run_script(s, client=rk, program_id=program, host=host)
    assert r.ok, r.traceback
    assert "4 False fast ['b'] 0x10" in host.out.getvalue()


def test_stream_host_round_trip(rk, program, tmp_path):
    """The JSON-lines protocol phase 2's daemon host speaks: events out, answers in."""
    s = write(tmp_path, "stream.py", "monitor.set_max(2)\nmonitor.increment()\nname = ask_string('who', 'Name?')\nprint('hi', name)\nlog('logged')\n")
    out_r, out_w = os.pipe()
    in_r, in_w = os.pipe()
    reader, writer = os.fdopen(out_r), os.fdopen(out_w, "w")
    answers_in, answers_out = os.fdopen(in_r), os.fdopen(in_w, "w")
    events = []

    def answer():
        for line in reader:
            e = json.loads(line)
            events.append(e)
            if e["type"] == "prompt":
                answers_out.write(json.dumps({"type": "answer", "id": e["id"], "value": "ada"}) + "\n")
                answers_out.flush()
            if e["type"] in ("result", "error"):
                return

    t = threading.Thread(target=answer)
    t.start()

    def w(line):
        writer.write(line)
        writer.flush()

    r = run_script(s, client=rk, program_id=program, host=StreamHost(w, answers_in.readline))
    t.join(10)
    assert r.ok, r.traceback
    kinds = [e["type"] for e in events]
    assert kinds[0] == "start" and kinds[-1] == "result" and "progress" in kinds
    prompt = next(e for e in events if e["type"] == "prompt")
    assert prompt["name"] == "who" and prompt["kind"] == "string" and prompt["message"] == "Name?"
    text = "".join(e["text"] for e in events if e["type"] == "output" and e["stream"] == "stdout")
    assert text == "hi ada\n"
    assert any(e["type"] == "output" and e["stream"] == "stderr" and e["text"] == "logged\n" for e in events)
    for f in (reader, writer, answers_in, answers_out):
        f.close()


def test_metadata():
    m = parse_metadata("""#!/usr/bin/env python3
# @category Analysis/Strings
# @description Names functions
# @description   after their strings
# @menupath Analysis.Rename by strings
# @keybinding ctrl shift R
# @context function
# @arg min_len:int=4 Shortest name
# @arg mode[fast|slow]=fast How
# @arg out:file Where to write
# @author someone
import os
# @category Not this
""", "x/rename_by_strings.py")
    assert m.name == "rename_by_strings" and m.category == "Analysis/Strings"
    assert m.description == "Names functions after their strings"
    assert (m.menupath, m.keybinding, m.context) == ("Analysis.Rename by strings", "ctrl shift R", "function")
    assert [(a.name, a.type, a.default) for a in m.args] == [("min_len", "int", "4"), ("mode", "choice", "fast"), ("out", "file", None)]
    assert m.arg("mode").choices == ["fast", "slow"] and m.arg("min_len").convert("0x10") == 16
    assert m.extra == {"author": "someone"} and not m.errors and len(m.sha12) == 12
    assert parse_metadata("# @context everywhere\n# @arg x:widget\n").errors
    shipped = list_scripts()
    assert len(shipped) >= 10
    for meta in shipped:
        assert meta.category and meta.description and not meta.errors, meta


def rk_script(*args, timeout=600, **kw):
    env = dict(os.environ, PYTHONPATH=str(SDK))
    return subprocess.run([sys.executable, "-m", "revkit.script.cli", *args], capture_output=True, text=True,
                          timeout=timeout, env=env, **kw)


def test_cli_runs_programs_with_json_summaries(daemon, program, script_target, tmp_path, rk):
    s = write(tmp_path, "count.py", """\
# @category Tests
# @description Counts functions and notes the count
# @arg tag=count Note tag
n = sum(1 for _ in current_program.functions())
note(next(iter(current_program.functions())).entry, str(n), tag=args["tag"])
print("functions:", n)
""")
    pre = write(tmp_path, "pre.py", "print('pre ran')\n")
    other = rk.import_program("default", path=str(script_target["stripped"])).program.program_id
    r = rk_script("run", str(s), "--daemon", daemon.grpc_target, "--program", program, other, "-j", "2",
                  "--pre", str(pre), "--arg", "tag=cli", "--json", "--actor", "user:cli")
    assert r.returncode == 0, r.stderr
    rows = [json.loads(line) for line in r.stdout.splitlines()]
    assert {row["program_id"] for row in rows} == {program, other}
    for row in rows:
        assert row["status"] == "ok" and len(row["revisions"]) == 1 and row["assertions"] == 1
        assert [x["phase"] for x in row["runs"]] == ["pre", "script"]
    assert "pre ran" in r.stderr and "functions:" in r.stderr
    run_id = rows[0]["runs"][1]["run_id"]
    notes = rk.program(rows[0]["program_id"]).assertions(session=run_id)
    assert notes[0].provenance.on_behalf_of == "user:cli" and notes[0].body.note.tag == "cli"

    # A failing script: exit status 1, the error in the summary.
    bad = write(tmp_path, "bad.py", "raise RuntimeError('broken')\n")
    r = rk_script("run", str(bad), "--daemon", daemon.grpc_target, "--program", program, "--json")
    assert r.returncode == 1
    assert json.loads(r.stdout)["error"] == "RuntimeError: broken"
    assert 'bad.py", line 1' in r.stderr
    # Unanswered prompt: fails fast with the --arg to pass.
    ask = write(tmp_path, "ask.py", "ask_int('limit', 'Limit')\n")
    r = rk_script("run", str(ask), "--daemon", daemon.grpc_target, "--program", program, stdin=subprocess.DEVNULL)
    assert r.returncode == 1 and "--arg limit=" in r.stderr
    # Usage errors.
    assert rk_script("run", "no-such-script", "--daemon", daemon.grpc_target, "--program", program).returncode == 2
    assert rk_script("run", str(s), "--daemon", daemon.grpc_target).returncode == 2
    # info and list.
    info = json.loads(rk_script("info", str(s)).stdout)
    assert info["description"] == "Counts functions and notes the count" and info["args"][0]["name"] == "tag"
    assert "batch_decompile" in rk_script("list").stdout


def test_cli_throwaway_imports(script_target, tmp_path):
    s = write(tmp_path, "names.py", "print(sorted(f.name for f in current_program.functions() if f.name in ('main', 'mix')))\n")
    r = rk_script("run", str(s), "--throwaway", "--import", str(script_target["plain"]), "--project-dir", str(tmp_path / "proj"))
    assert r.returncode == 0, r.stderr
    assert "['main', 'mix']" in r.stdout
    # The project directory keeps the import: a second run reuses it.
    r = rk_script("run", str(s), "--throwaway", "--import", str(script_target["plain"]), "--project-dir", str(tmp_path / "proj"),
                  "--json")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["program_id"] == "default/script_target"


def test_server_stamps_who_ran_it(script_target, tmp_path):
    with Daemon(None, "--backend", "image", auth=True, startup_timeout=60) as d:
        d.add_user("alice", "editor", "alice-password-1")
        d.add_user("root", "admin", "root-password-12")
        admin = d.client(token=d.create_token("root-tok", "admin", user="root"))
        pid = admin.import_program("default", path=str(script_target["plain"])).program.program_id
        alice = d.client(token=d.create_token("alice-tok", "editor", user="alice"))
        s = write(tmp_path, "auth_names.py", "rename(to_addr('mix'), 'mixer')\n")
        r = run_script(s, client=alice, program_id=pid, host=quiet())
        assert r.ok, r.error
        a = alice.program(pid).assertions(session=r.run_id)[0]
        assert a.provenance.kind == common_pb2.PROVENANCE_KIND_SCRIPT and a.provenance.id == "auth_names"
        assert a.provenance.on_behalf_of == "user:alice"
        assert describe_provenance(a.provenance) == "alice via script:auth_names"
        # Claiming to run it for someone else is refused, and nothing lands.
        s2 = write(tmp_path, "auth_names2.py", "rename(to_addr('decrypt'), 'unxor')\n")
        r = run_script(s2, client=alice, program_id=pid, host=quiet(), on_behalf_of="user:root")
        assert r.status == "error" and r.error_type == "PermissionDenied", r.error
        assert "decrypt" in {f.name for f in alice.program(pid).functions()}
        admin.close()
        alice.close()


def test_stream_host_background_context_and_cancel(tmp_path):
    """The daemon's protocol with a reader thread: a context message moves
    current_address while the script runs, and a cancel ends a script that
    is waiting for nothing in particular."""
    r_fd, w_fd = os.pipe()
    reader = os.fdopen(r_fd, "r")
    writer = os.fdopen(w_fd, "w")
    events = []
    host = StreamHost(lambda line: events.append(json.loads(line)), reader.readline, background=True)
    script = write(tmp_path, "follow.py", """\
import time
seen = [current_address]
deadline = time.monotonic() + 10
while current_address == seen[0] and time.monotonic() < deadline:
    time.sleep(0.02)
print("moved to", hex(current_address), current_selection)
while True:
    monitor.check_cancelled()
    time.sleep(0.02)
""")

    def drive():
        while not any(e.get("type") == "start" for e in events):
            time.sleep(0.01)
        writer.write(json.dumps({"type": "context", "address": "0x1234", "selection": ["0x1230", "0x123f"]}) + "\n")
        writer.flush()
        while not any(e.get("type") == "output" for e in events):
            time.sleep(0.01)
        writer.write(json.dumps({"type": "cancel"}) + "\n")
        writer.flush()

    import time
    t = threading.Thread(target=drive)
    t.start()
    r = run_script(script, host=host, context={"address": "0x1000"})
    t.join()
    writer.close()
    assert r.status == "cancelled", r.error
    out = "".join(e["text"] for e in events if e.get("type") == "output")
    assert "moved to 0x1234 (4656, 4671)" in out, out
