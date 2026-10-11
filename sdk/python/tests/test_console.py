"""The Python console's host (revkit/script/console.py; docs/scripting.md,
"The console"): statements and blocks as Python's REPL takes them,
expression echo, tracebacks from the console's own lines, KeyboardInterrupt,
input() as a prompt, completion from the live namespace (rlcompleter, and
jedi when it is installed), Ghidra's names on and off; then the host
process over its JSON-lines protocol against a daemon: each statement's
edits one revision with script provenance "console", a read-only host
refusing edits, Ctrl+C (SIGINT) ending a statement but not the console.
And script libraries: `import mylib` from the per-user library, then the
project's."""

import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from revkit import Client, Daemon
from revkit.script import console as console_mod
from revkit.script.console import Completer, Console, ConsoleHost
from revkit.script.runtime import install_library_paths, library_dirs

SDK = Path(__file__).resolve().parents[1]


class Lines:
    """A host's two ends in memory: what it sent, and answers to read."""

    def __init__(self, answers=()):
        self.sent = []
        self.answers = list(answers)

    def write(self, line):
        self.sent.append(json.loads(line))

    def read(self):
        return self.answers.pop(0) if self.answers else ""


def make(answers=(), **kw):
    lines = Lines(answers)
    host = ConsoleHost(lines.write, lines.read, background=False)
    return Console(None, "", host, **kw), lines


def run(c, src, **kw):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        r = c.execute(src, **kw)
    return r, out.getvalue(), err.getvalue()


@pytest.fixture(autouse=True)
def _restore_runtime():
    from revkit.script import runtime

    yield
    runtime._current = None


def test_statements_echo_and_namespace():
    c, _ = make()
    r, out, _ = run(c, "x = 6 * 7")
    assert r["status"] == "ok" and not r["more"] and out == ""
    r, out, _ = run(c, "x")
    assert out == "42\n"
    r, out, _ = run(c, "print('a'); x + 1")
    assert out == "a\n43\n"
    # The flat API is there, and current_program without a program is None.
    r, out, _ = run(c, "callable(rename), current_program")
    assert out == "(True, None)\n"


def test_blocks_need_their_end_as_in_the_repl():
    c, _ = make()
    r, _, _ = run(c, "for i in range(3):")
    assert r["more"] and r["status"] == ""
    r, _, _ = run(c, "for i in range(3):\n    print(i)")
    assert r["more"]
    r, out, _ = run(c, "for i in range(3):\n    print(i)\n")
    assert r["status"] == "ok" and out == "0\n1\n2\n"
    # A paste of several statements runs at once, echoing expressions.
    r, out, _ = run(c, "def f(a):\n    return a * 2\ny = f(4)\ny")
    assert r["status"] == "ok" and out == "8\n"
    # An unfinished expression continues; a real error doesn't.
    r, _, _ = run(c, "z = (1 +")
    assert r["more"]
    r, _, err = run(c, "1 +* 2")
    assert r["status"] == "error" and "SyntaxError" in err and r["error"].startswith("SyntaxError")


def test_traceback_names_console_lines():
    c, _ = make()
    run(c, "def boom():\n    raise ValueError('bad thing')\n")
    r, _, err = run(c, "boom()")
    assert r["status"] == "error" and r["error"] == "ValueError: bad thing"
    assert err.startswith("Traceback (most recent call last):\n"), err
    assert 'File "<console 2>", line 1' in err and 'File "<console 1>", line 2, in boom' in err
    assert "raise ValueError('bad thing')" in err  # the console's own source line
    assert "revkit/script/console.py" not in err


def test_keyboard_interrupt_ends_the_statement_not_the_console():
    c, _ = make()
    threading.Timer(0.3, lambda: os.kill(os.getpid(), signal.SIGINT)).start()
    t0 = time.monotonic()
    r, _, err = run(c, "import time\nfor _ in range(100):\n    time.sleep(0.1)\n")
    assert r["status"] == "interrupted" and time.monotonic() - t0 < 5
    assert "KeyboardInterrupt" in err
    r, out, _ = run(c, "'still here'")
    assert out == "'still here'\n"


def test_input_asks_the_ui():
    c, lines = make(answers=[json.dumps({"type": "answer", "id": 1, "value": "typed"}) + "\n"])
    r, out, _ = run(c, "input('Name? ')")
    assert r["status"] == "ok" and out == "'typed'\n"
    prompt = next(m for m in lines.sent if m["type"] == "prompt")
    assert prompt["kind"] == "string" and prompt["message"] == "Name? "


def test_exit_ends_the_console():
    c, _ = make()
    r, _, _ = run(c, "exit()")
    assert r["status"] == "exit"


def test_a_refused_commit_is_the_statements_error():
    c, _ = make()
    r, _, err = run(c, "rename(0x1000, 'x')")
    # No daemon here: the commit fails, and the error is all it shows.
    assert r["status"] == "error" and r["discarded"] == 1 and not r["seqs"]
    assert "Traceback" not in err and "console.py" not in err


def test_read_only_console_refuses_edits_at_once():
    c, _ = make(read_only=True)
    c.run.program = object()  # as if it had one: the edit fails before any call
    r, _, err = run(c, "comment(0x1000, 'hi')")
    assert r["status"] == "error" and "read-only" in err and "viewer" in err


def test_rlcompleter_completion_with_signatures():
    c, _ = make(completion="rlcompleter")
    run(c, "import os\nclass K:\n    def method(self, a, b=2):\n        'Does a thing.'\n\nk = K()\n")
    r = c.completer("decompile_m")
    assert r["engine"] == "rlcompleter" and r["prefix_length"] == len("decompile_m")
    (d,) = [x for x in r["completions"] if x["text"] == "decompile_many"]
    assert d["kind"] == "function" and d["signature"].startswith("decompile_many(funcs") and d["doc"]
    r = c.completer("k.me")
    assert [x["text"] for x in r["completions"]] == ["method"] and r["prefix_length"] == 2
    assert r["completions"][0]["signature"] == "method(a, b=2)" and r["completions"][0]["doc"] == "Does a thing."
    r = c.completer("os.pa")
    assert "path" in [x["text"] for x in r["completions"]]
    # Private names only when asked for.
    assert not [x for x in c.completer("k.")["completions"] if x["text"].startswith("_")]
    assert [x for x in c.completer("k._")["completions"] if x["text"] == "__init__"]
    # A property is never evaluated to complete.
    run(c, "class P:\n    @property\n    def boom(self):\n        raise RuntimeError('evaluated')\n\np = P()\n")
    assert [x["text"] for x in c.completer("p.bo")["completions"]] == ["boom"]
    assert c.completer("ask_str")["completions"][0]["signature"].startswith("ask_string(")


def test_jedi_completion_when_installed():
    pytest.importorskip("jedi")
    c, _ = make(completion="jedi")
    run(c, "class K:\n    def method(self, a, b=2):\n        pass\n\nk = K()\n")
    r = c.completer("k.me")
    assert r["engine"] == "jedi" and r["prefix_length"] == 2
    assert [x["text"] for x in r["completions"]] == ["method"]


def test_ghidra_names_on_and_off(rk, program):
    lines = Lines()
    c = Console(rk, program, ConsoleHost(lines.write, lines.read, background=False))
    assert "currentProgram" not in c.ns
    c.set_ghidra(True)
    assert "currentProgram" in c.ns and "getFunctionAt" in c.ns and "rename" in c.ns
    assert [x for x in c.completer("getFunctionA")["completions"] if x["text"] == "getFunctionAt"]
    c.set_ghidra(False)
    assert "currentProgram" not in c.ns and "getFunctionAt" not in c.ns and "rename" in c.ns


def test_completion_message_answers_from_the_reader():
    c, lines = make()
    c.host._dispatch(json.dumps({"type": "complete", "id": 7, "text": "print(functi"}))
    m = lines.sent[-1]
    assert m["type"] == "completions" and m["id"] == 7 and "functions" in [x["text"] for x in m["completions"]]
    c.host.completer = lambda t, n: 1 / 0
    c.host._dispatch(json.dumps({"type": "complete", "id": 8, "text": "x"}))
    assert lines.sent[-1]["id"] == 8 and "ZeroDivisionError" in lines.sent[-1]["error"]


# ---------------------------------------------------------------------------
# Libraries
# ---------------------------------------------------------------------------


def test_library_order_and_placement(tmp_path, monkeypatch):
    user, project, other = tmp_path / "user", tmp_path / "proj", tmp_path / "elsewhere"
    for d in (user, project, other):
        d.mkdir()
    script = other / "s.py"
    script.write_text("")
    dirs = library_dirs(script, user_dir=user, project_dir=project)
    assert dirs == [str(user), str(project), str(other)]
    # A script in a library adds nothing more.
    assert library_dirs(project / "x.py", user_dir=user, project_dir=project) == [str(user), str(project)]
    monkeypatch.setattr(sys, "path", ["/x/lib/python3.12", "/x/lib/python3.12/site-packages", "/y"])
    install_library_paths(dirs)
    assert sys.path == ["/x/lib/python3.12", str(user), str(project), str(other), "/x/lib/python3.12/site-packages", "/y"]
    install_library_paths(dirs)  # idempotent
    assert len(sys.path) == 6


@pytest.fixture(scope="module")
def daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture(scope="module")
def rk(daemon):
    with Client(daemon.grpc_target, actor="user:tester") as c:
        yield c


@pytest.fixture(scope="module")
def program(rk, script_target):
    return rk.import_program("default", path=str(script_target["plain"]), name="console-plain").program.program_id


def test_rk_script_imports_user_then_project_libraries(daemon, program, tmp_path):
    xdg, projects = tmp_path / "xdg", tmp_path / "projects"
    user_lib = xdg / "revkit" / "scripts"
    project_lib = projects / program.split("/")[0] / "scripts"
    for d in (user_lib, project_lib):
        d.mkdir(parents=True)
    (user_lib / "mylib.py").write_text("WHERE = 'user'\n")
    (project_lib / "mylib.py").write_text("WHERE = 'project'\n")
    (project_lib / "projlib.py").write_text("def hello():\n    return 'from the project'\n")
    (tmp_path / "helper.py").write_text("NAME = 'beside the script'\n")
    script = tmp_path / "uses_libs.py"
    script.write_text("import mylib, projlib, helper\nprint(mylib.WHERE, projlib.hello(), helper.NAME, sep='|')\n")
    env = {**os.environ, "XDG_CONFIG_HOME": str(xdg), "PYTHONPATH": str(SDK)}
    out = subprocess.run(
        [sys.executable, "-m", "revkit.script.cli", "run", str(script), "--daemon", daemon.grpc_target, "--program", program,
         "--project-dir", str(projects), "--actor", "user:tester"],
        env=env, capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr
    assert "user|from the project|beside the script" in out.stdout


# ---------------------------------------------------------------------------
# The host process
# ---------------------------------------------------------------------------


class Proc:
    def __init__(self, daemon, program, *extra):
        env = {**os.environ, "PYTHONPATH": str(SDK), "PYTHONUNBUFFERED": "1"}
        self.p = subprocess.Popen(
            [sys.executable, "-m", "revkit.script.console", "--daemon", daemon.grpc_target, "--program", program,
             "--run-id", "console-test", "--actor", "user:tester", *extra],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
            start_new_session=True,
        )
        self.next = 0
        self.ready = self.until(lambda m: m["type"] == "ready")

    def send(self, msg):
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()

    def until(self, pred, timeout=60):
        got = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            line = self.p.stdout.readline()
            if not line:
                raise AssertionError(f"the host ended: {self.p.stderr.read()}")
            m = json.loads(line)
            got.append(m)
            if pred(m):
                m["_before"] = got
                return m
        raise AssertionError(f"timed out; got {got}")

    def exec(self, source, **kw):
        self.next += 1
        self.send({"type": "exec", "id": self.next, "source": source, **kw})
        done = self.until(lambda m: m["type"] == "done" and m["id"] == self.next)
        done["out"] = "".join(m["text"] for m in done["_before"] if m["type"] == "output" and m["stream"] == "stdout")
        done["err"] = "".join(m["text"] for m in done["_before"] if m["type"] == "output" and m["stream"] == "stderr")
        return done

    def close(self):
        if self.p.poll() is None:
            self.send({"type": "quit"})
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()


def test_host_process_statements_edits_and_interrupt(daemon, rk, program):
    h = Proc(daemon, program, "--context", json.dumps({"address": "0x0"}))
    try:
        assert h.ready["engine"] in ("jedi", "rlcompleter") and not h.ready["read_only"]
        main = next(f for f in rk.program(program).functions() if f.name == "main").entry.offset
        r = h.exec("current_function.name if current_function else None", context={"address": hex(main), "selection": None})
        assert r["out"] == "'main'\n", r
        # One statement, two edits: one revision with script provenance "console".
        r = h.exec(f"rename({main}, 'console_main'); comment({main}, 'from the console')")
        assert r["status"] == "ok" and len(r["revisions"]) == 1 and len(r["seqs"]) == 2, r
        a = rk.program(program).assertions(session="console-test")
        assert {x.provenance.id for x in a} == {"console"} and {x.provenance.tool.split("@")[0] for x in a} == {"script:console"}
        assert next(f for f in rk.program(program).functions() if f.entry.offset == main).name == "console_main"
        # A failing statement commits nothing.
        r = h.exec(f"rename({main}, 'never'); 1/0")
        assert r["status"] == "error" and r["discarded"] == 1 and not r["seqs"] and "ZeroDivisionError" in r["err"]
        # Completion over the protocol sees the statements' names.
        h.exec("my_value = 1")
        h.send({"type": "complete", "id": 1, "text": "my_va"})
        c = h.until(lambda m: m["type"] == "completions")
        assert [x["text"] for x in c["completions"]] == ["my_value"]
        # SIGINT interrupts a long statement; the console carries on.
        h.next += 1
        h.send({"type": "exec", "id": h.next, "source": "import time\nwhile True:\n    time.sleep(0.05)\n"})
        time.sleep(0.5)
        os.killpg(h.p.pid, signal.SIGINT)
        r = h.until(lambda m: m["type"] == "done")
        assert r["status"] == "interrupted"
        assert h.exec("my_value + 1")["out"] == "2\n"
        rk.program(program).revert(session="console-test", actor="user:tester")
    finally:
        h.close()
    assert h.p.returncode == 0


def test_host_process_read_only_and_ghidra(daemon, program):
    h = Proc(daemon, program, "--read-only", "--ghidra")
    try:
        assert h.ready["read_only"]
        r = h.exec("currentProgram.getFunctionManager().getFunctionCount() > 0")
        assert r["out"] == "True\n", r
        r = h.exec("rename(current_program.functions().__next__(), 'nope')")
        assert r["status"] == "error" and "read-only" in r["err"]
        r = h.exec("1", ghidra=False)
        assert h.exec("'currentProgram' in globals()")["out"] == "False\n"
    finally:
        h.close()


def test_console_module_documents_its_protocol():
    assert "exec" in console_mod.__doc__ and "complete" in console_mod.__doc__ and "quit" in console_mod.__doc__
