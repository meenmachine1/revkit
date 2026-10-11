"""The daemon's Python console (RunScript{interactive}, CompleteConsole,
CancelScript{interrupt}; docs/scripting.md, "The console") on an
authenticated daemon whose --scripts-host-role is viewer: one live host per
caller and program that keeps its namespace, each statement's edits one
revision with script provenance "console" on behalf of the caller, the
history kept per caller, completion from the live namespace, Ctrl+C,
prompts, the cursor following UpdateContext, a busy console, a host that
dies started again, Close, the idle timeout, Ghidra's names, and a viewer's
console that reads but can't write."""

import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

from revkit import Daemon, FailedPrecondition, PermissionDenied
from revkit.v1 import common_pb2

IDLE = 4


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    xdg = tmp_path_factory.mktemp("xdg-console")
    (xdg / "revkit" / "scripts").mkdir(parents=True)
    (xdg / "revkit" / "scripts" / "conlib.py").write_text("def triple(x):\n    return 3 * x\n")
    return {"XDG_CONFIG_HOME": str(xdg), "REVKIT_PYTHON": sys.executable,
            "PYTHONPATH": os.environ.get("PYTHONPATH", str(Path(__file__).resolve().parents[1]))}


@pytest.fixture(scope="module")
def daemon(env, tmp_path_factory):
    with Daemon(None, "--backend", "image", "--project-dir", str(tmp_path_factory.mktemp("projects-console")),
                "--scripts-host-role", "viewer", "--console-idle-timeout", str(IDLE), auth=True, env=env,
                startup_timeout=60) as d:
        d.add_user("alice", "editor", "alice-password-1")
        d.add_user("bob", "editor", "bob-password-12")
        d.add_user("victor", "viewer", "victor-password")
        yield d


def client_for(d, user, role="editor"):
    return d.client(token=d.create_token(f"t-{user}-{time.monotonic_ns()}", role, user=user))


@pytest.fixture(scope="module")
def alice(daemon):
    with client_for(daemon, "alice") as c:
        yield c


@pytest.fixture(scope="module")
def program(daemon, script_target):
    with daemon.client(token=daemon.create_token("importer", "admin")) as admin:
        return admin.import_program("default", path=str(script_target["plain"])).program.program_id


def test_statements_share_a_namespace_and_history(daemon, alice, program, env):
    con = alice.console(program)
    con.close()  # whatever an earlier test left
    started = con.open()
    assert started.console_started and con.run_id.startswith("console-")
    assert started.python_version and started.completion_engine in ("jedi", "rlcompleter") and not started.read_only
    r = con.run("x = 41")
    assert r.status == "ok" and not r.started.console_started and r.run_id == con.run_id
    r = con.run("x + 1")
    assert r.stdout == "42\n"
    r = con.run("for i in range(2):")
    assert r.more and r.status == ""
    r = con.run("for i in range(2):\n    print('i', i)\n")
    assert r.stdout == "i 0\ni 1\n"
    # Libraries import from the per-user one.
    assert con.run("import conlib; conlib.triple(x)").stdout == "123\n"
    # The history, kept on the daemon per caller, newest last.
    hist = list(con.open().history)
    assert hist[-3:] == ["x + 1", "for i in range(2):\n    print('i', i)", "import conlib; conlib.triple(x)"], hist
    assert "for i in range(2):" not in hist  # an open block isn't a statement yet
    files = list((Path(env["XDG_CONFIG_HOME"]) / "revkit" / "console-history").iterdir())
    assert files and all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in files)
    # Another user has their own console and history.
    with client_for(daemon, "bob") as bob:
        b = bob.console(program)
        assert b.run("'x' in globals()").stdout == "False\n"
        assert "x = 41" not in b.open().history
        b.close()


def test_a_statement_is_one_revision_and_one_undo(alice, program):
    con = alice.console(program)
    prog = alice.program(program)
    main = next(f for f in prog.functions() if f.name == "main").entry.offset
    r = con.run(f"rename({main}, 'console_main'); comment({main}, 'typed at the console')")
    assert r.status == "ok" and len(r.revisions) == 1 and len(r.seqs) == 2, r
    a = [x for x in prog.assertions(session=con.run_id) if x.seq in r.seqs]
    assert len(a) == 2 and len({x.revision for x in a}) == 1
    p = a[0].provenance
    assert p.kind == common_pb2.PROVENANCE_KIND_SCRIPT and p.id == "console" and p.on_behalf_of == "user:alice"
    assert p.tool.startswith("script:console@") and p.session == con.run_id
    assert next(f for f in prog.functions() if f.entry.offset == main).name == "console_main"
    # Undo is the statement's seqs.
    prog.retract(*r.seqs)
    assert next(f for f in prog.functions() if f.entry.offset == main).name == "main"
    # A failing statement commits nothing.
    r = con.run(f"rename({main}, 'never')\nraise ValueError('nope')")
    assert r.status == "error" and r.error == "ValueError: nope" and r.discarded == 1 and not r.seqs
    assert 'File "<console' in r.stderr and "raise ValueError('nope')" in r.stderr


def test_completion_from_the_live_namespace(alice, program):
    con = alice.console(program)
    con.run("console_answer = 42")
    c = alice.console(program).complete("console_ans")
    assert [x.text for x in c.completions] == ["console_answer"] and c.prefix_length == len("console_ans")
    assert c.engine in ("jedi", "rlcompleter")
    c = con.complete("decompile_m")
    (d,) = [x for x in c.completions if x.text == "decompile_many"]
    assert d.signature.startswith("decompile_many(") and d.kind == "function"
    c = con.complete("current_program.functi")
    assert "functions" in [x.text for x in c.completions]
    # Another program: no console there yet.
    with pytest.raises(FailedPrecondition):
        alice.console("default/none").complete("x")


def test_interrupt_ends_the_statement_and_keeps_the_console(alice, program):
    con = alice.console(program)
    con.run("kept = 'still here'")
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", con.run("import time\nwhile True:\n    time.sleep(0.05)\n")))
    t.start()
    time.sleep(1.0)
    # Busy: another statement waits its turn.
    with pytest.raises(FailedPrecondition):
        alice.console(program).run("1")
    t0 = time.monotonic()
    assert con.interrupt()
    t.join(10)
    assert out["r"].status == "interrupted" and "KeyboardInterrupt" in out["r"].stderr
    assert time.monotonic() - t0 < 3
    assert con.run("kept").stdout == "'still here'\n"


def test_prompts_and_input(alice, program):
    con = alice.console(program)
    r = con.run("n = ask_int('count', 'How many?'); s = input('Name? '); print(n + 1, s)",
                answers=lambda p: {"count": "41", "input": "ann"}[p.name])
    assert r.status == "ok" and r.stdout == "42 ann\n"
    r = con.run("ask_string('dismissed', 'Anything?')", answers={})
    assert r.status == "interrupted"


def test_context_follows_the_cursor(alice, program):
    con = alice.console(program)
    prog = alice.program(program)
    mix = next(f for f in prog.functions() if f.name == "mix").entry.offset
    main = next(f for f in prog.functions() if f.name == "main").entry.offset
    assert con.run("current_function.name", address=mix).stdout == "'mix'\n"
    con.update_context(address=main, selection=(main, main + 3))
    deadline = time.monotonic() + 5
    while con.run("current_function.name").stdout != "'main'\n" and time.monotonic() < deadline:
        time.sleep(0.1)
    assert con.run("current_function.name, current_selection == (current_address, current_address + 3)").stdout == \
        "('main', True)\n"


def test_a_dead_console_starts_again(alice, program):
    con = alice.console(program)
    con.run("marker = 1")
    r = con.run("import os; os._exit(3)")
    assert r.status == "died" and "exited with status 3" in r.error
    r = con.run("'marker' in globals()")
    assert r.started.console_started and r.stdout == "False\n"
    r = con.run("exit()")
    assert r.status == "exit"
    assert con.run("1").started.console_started
    # Close: the next statement starts a new one.
    con.run("marker = 2")
    assert con.close()
    assert con.run("'marker' in globals()").stdout == "False\n"


def test_idle_consoles_close(daemon, program):
    with client_for(daemon, "bob") as bob:
        con = bob.console(program)
        con.run("idle_marker = 1")
        time.sleep(IDLE + 2.5)
        r = con.run("'idle_marker' in globals()")
        assert r.started.console_started and r.stdout == "False\n"
        con.close()


def test_ghidra_names(alice, program):
    con = alice.console(program, ghidra_names=True)
    r = con.run("currentProgram.getFunctionManager().getFunctionAt(toAddr(function_at('mix').entry.offset)).getName()")
    assert r.stdout == "'mix'\n", r
    con.ghidra_names = False
    assert con.run("'currentProgram' in globals()").stdout == "False\n"


def test_viewer_console_reads_but_cannot_write(daemon, program):
    with client_for(daemon, "victor", "viewer") as v:
        con = v.console(program)
        started = con.open()
        assert started.read_only
        assert con.run("sum(1 for _ in current_program.functions()) > 3").stdout == "True\n"
        r = con.run("rename(function_at('main').entry.offset, 'viewer_was_here')")
        assert r.status == "error" and "read-only" in r.stderr and not r.seqs
        # The run token is a viewer's: going around the buffer, the daemon refuses.
        r = con.run("current_program.rename(function_at('main').entry.offset, 'viewer_was_here')")
        assert r.status == "error" and "PermissionDenied" in r.error, r
        assert "viewer_was_here" not in {f.name for f in v.program(program).functions()}
        con.close()


def test_viewer_has_no_console_by_default(script_target, tmp_path, env):
    with Daemon(None, "--backend", "image", auth=True, env=env, startup_timeout=60) as d:
        d.add_user("victor", "viewer", "victor-password")
        with d.client(token=d.create_token("importer", "admin")) as admin:
            pid = admin.import_program("default", path=str(script_target["plain"])).program.program_id
        with client_for(d, "victor", "viewer") as v:
            with pytest.raises(PermissionDenied):
                v.console(pid).open()
