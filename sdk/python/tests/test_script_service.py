"""ScriptService (docs/scripting.md, "The daemon's script service") on an
authenticated image-backend daemon: the libraries and their metadata, a run
streaming output and progress, a prompt answered over the API, cancel ending
a run within 2 s (also one that ignores SIGTERM), a run's edits as one
revision with script provenance on behalf of the caller, the run token
revoked at exit, tracebacks naming the script and line, roles (a viewer
can't run), trust confirmation for unseen and changed text, SaveScript, the
recent runs, a daemon with scripts off, and the MCP tools."""

import os
import sys
import time
from pathlib import Path

import pytest

from revkit import Client, Daemon, PermissionDenied, Unauthenticated
from revkit.v1 import common_pb2

PROGRESS = """\
# @category Tests
# @description Prints and reports progress
import time
monitor.set_max(5)
for i in range(5):
    print("line", i)
    monitor.increment()
    monitor.message(f"step {i}")
    time.sleep(0.12)
print("done")
"""

PROMPTS = """\
# @category Tests
measure = ask_choice("measure", "Measure by", ["size", "instructions"], default="size")
n = ask_int("count", "How many")
names = ask_choices("which", "Which ones", ["a", "b", "c"])
print(f"measure={measure} count={n + 1} which={'+'.join(names)}")
"""

SLEEPER = """\
# @category Tests
import time
print("sleeping", flush=True)
time.sleep(60)
"""

STUBBORN = """\
# @category Tests
import signal, time
signal.signal(signal.SIGTERM, lambda *a: None)   # ignores the polite cancel
print("stubborn", flush=True)
while True:
    try:
        time.sleep(60)
    except BaseException:
        pass
"""

RENAMES = """\
# @category Tests
# @description Renames the first two functions
import os
print("token", os.environ.get("RK_TOKEN", ""))
fs = [f for f in current_program.functions() if not f.external][:2]
for i, f in enumerate(fs):
    rename(f, f"scripted_{i}")
"""

BROKEN = """\
# @category Tests
x = 1
raise ValueError("broken on purpose")
"""

FOLLOW = """\
# @category Tests
import time
first = current_address
print("at", hex(first), flush=True)
deadline = time.monotonic() + 20
while current_address == first and time.monotonic() < deadline:
    time.sleep(0.02)
print("moved to", hex(current_address), current_function.name if current_function else None)
"""

USER_SCRIPTS = {"follow.py": FOLLOW, "progress.py": PROGRESS, "prompts.py": PROMPTS, "sleeper.py": SLEEPER, "stubborn.py": STUBBORN,
                "renames.py": RENAMES, "broken.py": BROKEN}


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    xdg = tmp_path_factory.mktemp("xdg")
    scripts = xdg / "revkit" / "scripts"
    scripts.mkdir(parents=True)
    for name, text in USER_SCRIPTS.items():
        (scripts / name).write_text(text)
    return {"XDG_CONFIG_HOME": str(xdg), "REVKIT_PYTHON": sys.executable,
            "PYTHONPATH": os.environ.get("PYTHONPATH", str(Path(__file__).resolve().parents[1]))}


@pytest.fixture(scope="module")
def daemon(env, tmp_path_factory):
    project_dir = tmp_path_factory.mktemp("projects")
    with Daemon(None, "--backend", "image", "--project-dir", str(project_dir), auth=True, env=env,
                startup_timeout=60) as d:
        d.add_user("alice", "editor", "alice-password-1")
        d.add_user("bob", "editor", "bob-password-12")
        d.add_user("victor", "viewer", "victor-password")
        d.project_dir = project_dir
        yield d


def client_for(d, user):
    return d.client(token=d.create_token(f"t-{user}-{time.monotonic_ns()}", "editor" if user != "victor" else "viewer",
                                         user=user))


@pytest.fixture(scope="module")
def alice(daemon):
    with client_for(daemon, "alice") as c:
        yield c


@pytest.fixture(scope="module")
def program(daemon, script_target):
    with daemon.client(token=daemon.create_token("importer", "admin")) as admin:
        return admin.import_program("default", path=str(script_target["plain"])).program.program_id


def confirmed(rk, script_id, program, **kw):
    """Runs a user script, confirming its text first when asked."""
    run = rk.run_script(script_id, program, **kw)
    run.wait()
    if run.trust is not None:
        run = rk.run_script(script_id, program, confirm_sha256=run.trust.script.sha256, **kw)
        run.wait()
    return run


def test_list_scripts(alice, daemon, program):
    r = alice.list_scripts("default")
    assert r.host_enabled and r.python, r
    ids = {s.script_id: s for s in r.scripts}
    tag = ids["shipped/tag_functions_by_complexity.py"]
    assert tag.category == "Analysis/Functions" and tag.context == "program" and tag.trusted and not tag.writable
    assert [a.name for a in tag.args] == ["threshold", "dry_run"] and tag.args[0].type == "int"
    assert ids["shipped/summarize_function.py"].context == "function"
    mine = ids["user/progress.py"]
    assert mine.library == 2 and mine.writable and not mine.trusted and len(mine.sha256) == 64
    with client_for(daemon, "victor") as v:
        rv = v.list_scripts("default")
        assert not rv.host_enabled and "viewer" in rv.host_disabled_reason
        assert any(s.script_id == "shipped/batch_decompile.py" for s in rv.scripts)


def test_run_streams_output_and_progress(alice, program):
    run = confirmed(alice, "user/progress.py", program)
    assert run.status == "ok", run.error
    assert "line 0" in run.text and "done" in run.text
    # Ask again and look at the stream itself.
    events = list(alice.run_script("user/progress.py", program))
    kinds = [e.WhichOneof("event") for e in events]
    assert kinds[0] == "started" and kinds[-1] == "result"
    assert "output" in kinds and "progress" in kinds
    prog = [e.progress for e in events if e.HasField("progress")]
    assert prog[0].maximum == 5 and any(p.message.startswith("step") for p in prog)
    assert events[0].started.script.script_id == "user/progress.py"


def test_prompt_round_trip(alice, program):
    seen = []

    def answer(p):
        seen.append((p.kind, p.name, list(p.choices), p.default_value))
        return {"measure": "instructions", "count": "41", "which": ["a", "c"]}[p.name]

    run = alice.run_script("user/prompts.py", program, confirm_sha256=alice.script_source("user/prompts.py").script.sha256)
    run.wait(answer)
    assert run.status == "ok", run.error
    assert "measure=instructions count=42 which=a+c" in run.text
    assert seen[0] == ("choice", "measure", ["size", "instructions"], "size")
    assert [s[0] for s in seen] == ["choice", "int", "choices"]
    # --arg answers it without a prompt; a dismissed prompt cancels the run.
    run = alice.run_script("user/prompts.py", program, args={"measure": "size", "count": "1", "which": "b"})
    run.wait()
    assert run.status == "ok" and "measure=size count=2 which=b" in run.text
    run = alice.run_script("user/prompts.py", program)
    run.wait(lambda p: None)
    assert run.status == "cancelled", run.error


@pytest.mark.parametrize("script", ["user/sleeper.py", "user/stubborn.py"])
def test_cancel_within_2s(alice, program, script):
    run = alice.run_script(script, program, confirm_sha256=alice.script_source(script).script.sha256)
    it = iter(run)
    for ev in it:
        if ev.HasField("output"):
            break
    t0 = time.monotonic()
    assert run.cancel()
    for ev in it:
        pass
    took = time.monotonic() - t0
    assert run.status == "cancelled", run.error
    # SIGTERM ends a cooperative script at once; one that ignores it is
    # killed 2 s later.
    limit = 1.0 if script.endswith("sleeper.py") else 2.6
    assert took < limit, took
    assert not run.cancel()  # already ended


def test_one_revision_with_script_provenance(alice, program, daemon):
    run = confirmed(alice, "user/renames.py", program)
    assert run.status == "ok", run.error
    assert len(run.result.revisions) == 1 and len(run.result.seqs) == 2
    prog = alice.program(program)
    entries = list(prog.assertions(session=run.run_id))
    assert sorted(a.seq for a in entries) == sorted(run.result.seqs)
    assert {a.revision for a in entries} == set(run.result.revisions)
    for a in entries:
        p = a.provenance
        assert p.kind == common_pb2.PROVENANCE_KIND_SCRIPT and p.id == "renames" and p.on_behalf_of == "user:alice"
        assert p.session == run.run_id and p.tool.startswith("script:renames@")
    # The run token died with the run.
    token = next(line.split(" ", 1)[1] for line in run.text.splitlines() if line.startswith("token "))
    assert token.startswith("rkr_")
    with daemon.client(token=token) as stale:
        with pytest.raises(Unauthenticated):
            stale.list_scripts()
    # One revert takes the run back.
    prog.revert(session=run.run_id)
    assert not any(f.name.startswith("scripted_") for f in prog.functions())
    runs = alice.script_runs(program)
    mine = next(r for r in runs if r.run_id == run.run_id)
    assert mine.status == "ok" and mine.caller == "user:alice" and mine.assertions == 2


def test_context_follows_the_cursor(alice, program):
    prog = alice.program(program)
    main = next(f for f in prog.functions() if f.name == "main")
    other = next(f for f in prog.functions() if f.name == "parse_config")
    run = alice.run_script("user/follow.py", program, address=main.entry.offset,
                           confirm_sha256=alice.script_source("user/follow.py").script.sha256)
    sent = False
    for ev in run:
        if not sent and "\n" in run.text:  # "at ..." printed (perhaps in pieces)
            run.update_context(address=other.entry.offset + 2)
            sent = True
    assert run.status == "ok", run.error
    assert f"at {hex(main.entry.offset)}" in run.text
    assert f"moved to {hex(other.entry.offset + 2)} parse_config" in run.text, run.text


def test_traceback_names_script_and_line(alice, program):
    run = confirmed(alice, "user/broken.py", program)
    assert run.status == "error"
    e = run.error
    assert e.script_id == "user/broken.py" and e.line == 3, e
    assert "ValueError: broken on purpose" in e.message and "user/broken.py" in e.traceback
    assert "/scripts/broken.py" not in e.traceback


def test_viewer_cannot_run(daemon, program):
    with client_for(daemon, "victor") as v:
        with pytest.raises(PermissionDenied):
            v.run_script("shipped/tag_functions_by_complexity.py", program).wait()
        with pytest.raises(PermissionDenied):
            v.save_script("mine.py", "print(1)\n")


def test_trust_unseen_changed_and_saved(daemon, alice, program, env):
    path = Path(env["XDG_CONFIG_HOME"]) / "revkit" / "scripts" / "trusty.py"
    path.write_text("# @category Tests\nprint('first')\n")
    run = alice.run_script("user/trusty.py", program)
    run.wait()
    assert run.status == "untrusted" and run.trust.reason == "unseen"
    assert "print('first')" in run.trust.source and len(run.trust.script.sha256) == 64
    first = run.trust.script.sha256
    run = alice.run_script("user/trusty.py", program, confirm_sha256=first)
    run.wait()
    assert run.status == "ok" and "first" in run.text
    run = alice.run_script("user/trusty.py", program)  # pinned now
    run.wait()
    assert run.status == "ok"
    # Someone changes it: confirm again, shown what was pinned.
    path.write_text("# @category Tests\nprint('second')\n")
    run = alice.run_script("user/trusty.py", program)
    run.wait()
    assert run.status == "untrusted" and run.trust.reason == "changed" and run.trust.previous_sha256 == first
    # A confirmation of other text doesn't count.
    run = alice.run_script("user/trusty.py", program, confirm_sha256=first)
    run.wait()
    assert run.status == "untrusted"
    # Saving it pins the saver's trust, not anyone else's.
    info = alice.script_source("user/trusty.py").script
    saved = alice.save_script("trusty.py", "# @category Tests\nprint('third')\n", expected_sha256=info.sha256)
    assert saved.trusted and saved.script_id == "user/trusty.py"
    run = alice.run_script("user/trusty.py", program)
    run.wait()
    assert run.status == "ok" and "third" in run.text
    with client_for(daemon, "bob") as bob:
        run = bob.run_script("user/trusty.py", program)
        run.wait()
        assert run.status == "untrusted" and run.trust.reason == "unseen"
    pins = (Path(env["XDG_CONFIG_HOME"]) / "revkit" / "trusted-scripts").read_text()
    assert "user/trusty.py user:alice" in pins


def test_save_script(alice, program):
    from revkit import Aborted

    info = alice.save_script("fresh.py", "# @category Tests/Saved\n# @context function\nprint('saved')\n",
                             project_id="default")
    assert info.script_id == "project/default/fresh.py" and info.context == "function" and info.trusted
    assert any(s.script_id == info.script_id for s in alice.list_scripts("default").scripts)
    with pytest.raises(Exception):  # exists: needs the hash it replaces
        alice.save_script("fresh.py", "print(1)\n", project_id="default")
    with pytest.raises(Aborted):
        alice.save_script("fresh.py", "print(1)\n", project_id="default", expected_sha256="0" * 64)
    with pytest.raises(Exception):
        alice.save_script("../escape.py", "print(1)\n")
    for bad in ("..", "a/b", ".hidden"):
        with pytest.raises(Exception):
            alice.save_script("x.py", "print(1)\n", project_id=bad)
    run = alice.run_script(info.script_id, program)
    run.wait()
    assert run.status == "ok" and "saved" in run.text


def test_scripts_off(env, script_target):
    with Daemon(None, "--backend", "image", "--scripts-host-role", "off", env=env, startup_timeout=60) as d:
        with Client(d.grpc_target, actor="user:tester") as rk:
            r = rk.list_scripts()
            assert not r.host_enabled and "--scripts-host-role off" in r.host_disabled_reason
            pid = rk.import_program("default", path=str(script_target["plain"])).program.program_id
            with pytest.raises(PermissionDenied):
                rk.run_script("shipped/tag_functions_by_complexity.py", pid).wait()


def test_no_python(env, script_target, tmp_path):
    with Daemon(None, "--backend", "image", "--script-python", str(tmp_path / "no-python"), env=env,
                startup_timeout=60) as d:
        with Client(d.grpc_target, actor="user:tester") as rk:
            r = rk.list_scripts()
            assert r.host_enabled and not r.python and "rk-script setup" in r.python_problem
            pid = rk.import_program("default", path=str(script_target["plain"])).program.program_id
            from revkit import FailedPrecondition

            with pytest.raises(FailedPrecondition, match="no Python"):
                rk.run_script("shipped/tag_functions_by_complexity.py", pid).wait()


# Stand-ins for python3 and the venv it makes, so SetupScriptPython runs its
# real steps without a network: "-m venv DIR" makes DIR/bin/python, which
# "installs" anything pip is given; the daemon's SDK probe (-c) then finds
# the SDK current only once pip reinstalled it (--force-reinstall), as for a
# stale SDK with the same version string, and older (exit 3) before.
FAKE_PYTHON3 = """#!/bin/sh
PATH=/usr/bin:/bin
if [ "$1" = -m ] && [ "$2" = venv ]; then
  mkdir -p "$3/bin" && cp "$(dirname "$0")/venv-python" "$3/bin/python" && echo "made $3"
  exit 0
fi
exit 1
"""
FAKE_VENV_PYTHON = """#!/bin/sh
PATH=/usr/bin:/bin
here=$(dirname "$0")
case "$1 $2" in
  "-m pip") echo "Processing $*"; echo "Successfully installed revkit"; touch "$here/../installed"
    case "$*" in *--force-reinstall*--no-deps*) touch "$here/../current" ;; esac; exit 0 ;;
  "-c "*) [ -f "$here/../installed" ] || exit 1; [ -f "$here/../current" ] && exit 0; exit 3 ;;
esac
exit 1
"""


def fake_pythons(tmp_path, base=FAKE_PYTHON3):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, text in (("python3", base), ("venv-python", FAKE_VENV_PYTHON)):
        (bin_dir / name).write_text(text)
        (bin_dir / name).chmod(0o755)
    return bin_dir


def test_setup_python_in_one_call(env, tmp_path):
    # No Python that imports revkit on this daemon's PATH, and no environment:
    # SetupScriptPython makes ~/.local/share/revkit/pyenv ($XDG_DATA_HOME's),
    # streaming its steps, and scripts then run with it.
    bin_dir = fake_pythons(tmp_path)
    data = tmp_path / "data"
    denv = {k: v for k, v in env.items() if k != "REVKIT_PYTHON"}
    denv.update({"PATH": str(bin_dir), "XDG_DATA_HOME": str(data), "REVKIT_PYTHON": ""})
    with Daemon(None, "--backend", "image", env=denv, startup_timeout=60) as d:
        with Client(d.grpc_target, actor="user:tester") as rk:
            assert "scripts-setup" in rk.server_info().features
            before = rk.list_scripts()
            assert before.host_enabled and not before.python and "Set up Python" in before.python_problem
            lines = []
            r = rk.setup_script_python(output=lines.append)
            out = "".join(lines)
            pyenv = data / "revkit" / "pyenv"
            assert r.ok, (r.error, out)
            assert r.python == str(pyenv / "bin" / "python") and r.directory == str(pyenv)
            assert f"$ python3 -m venv {pyenv}" in out and "-m pip install --upgrade" in out
            assert "-m pip install --force-reinstall --no-deps" in out
            assert "Successfully installed revkit" in out and "import revkit.script.worker" in out
            assert rk.list_scripts().python == r.python
            # Again: the environment is there, so only the SDK is updated.
            lines.clear()
            assert rk.setup_script_python(output=lines.append).ok
            assert "-m venv" not in "".join(lines)


def test_stale_sdk_says_to_update_it(env, script_target, tmp_path):
    # ~/.local/share/revkit/pyenv holds an SDK older than the daemon (the
    # same version string, no console): scripts and consoles say so, and
    # Set up Python reinstalls it although pip sees the same version.
    bin_dir = fake_pythons(tmp_path)
    data = tmp_path / "data"
    pyenv = data / "revkit" / "pyenv"
    (pyenv / "bin").mkdir(parents=True)
    (pyenv / "bin" / "python").write_text(FAKE_VENV_PYTHON)
    (pyenv / "bin" / "python").chmod(0o755)
    (pyenv / "installed").touch()
    denv = {k: v for k, v in env.items() if k != "REVKIT_PYTHON"}
    denv.update({"PATH": str(bin_dir), "XDG_DATA_HOME": str(data), "REVKIT_PYTHON": ""})
    with Daemon(None, "--backend", "image", env=denv, startup_timeout=60) as d:
        with Client(d.grpc_target, actor="user:tester") as rk:
            before = rk.list_scripts()
            want = f"the revkit SDK in {pyenv / 'bin' / 'python'} is older than this daemon"
            assert not before.python and want in before.python_problem, before.python_problem
            assert "Set up Python (or run `rk-script setup`)" in before.python_problem
            pid = rk.import_program("default", path=str(script_target["plain"])).program.program_id
            from revkit import FailedPrecondition

            with pytest.raises(FailedPrecondition, match="older than this daemon"):
                rk.run_script("shipped/tag_functions_by_complexity.py", pid).wait()
            lines = []
            r = rk.setup_script_python(output=lines.append)
            assert r.ok, (r.error, "".join(lines))
            assert "--force-reinstall --no-deps" in "".join(lines)
            assert rk.list_scripts().python == str(pyenv / "bin" / "python")


def test_setup_python_says_what_failed(env, tmp_path):
    bin_dir = fake_pythons(tmp_path, base="#!/bin/sh\necho 'ensurepip is not available' >&2\nexit 1\n")
    denv = {k: v for k, v in env.items() if k != "REVKIT_PYTHON"}
    denv.update({"PATH": str(bin_dir), "XDG_DATA_HOME": str(tmp_path / "data"), "REVKIT_PYTHON": ""})
    with Daemon(None, "--backend", "image", env=denv, startup_timeout=60) as d:
        with Client(d.grpc_target, actor="user:tester") as rk:
            lines = []
            r = rk.setup_script_python(output=lines.append)
            assert not r.ok and "python3-venv" in r.error and "ensurepip is not available" in "".join(lines)
            assert rk.list_scripts().python_problem
    # A daemon told which Python to run scripts with has nothing to set up.
    with Daemon(None, "--backend", "image", "--script-python", str(tmp_path / "no-python"), env=env,
                startup_timeout=60) as d:
        with Client(d.grpc_target, actor="user:tester") as rk:
            from revkit import FailedPrecondition

            with pytest.raises(FailedPrecondition, match="--script-python"):
                rk.setup_script_python()


def test_mcp_tools(env, script_target):
    mcp_client = pytest.importorskip("mcp.client.client")
    import json

    import anyio

    from revkit.mcp_server import create_server

    with Daemon(None, "--backend", "image", env=env, startup_timeout=60) as d:
        with Client(d.grpc_target, actor="user:tester") as rk:
            pid = rk.import_program("default", path=str(script_target["plain"])).program.program_id
        server = create_server(d.grpc_target, agent="claude", session="mcp-scripts")

        async def run():
            async with mcp_client.Client(server) as mcp:
                async def call(name, **args):
                    r = await mcp.call_tool(name, args)
                    assert not r.is_error, r
                    return json.loads(r.content[0].text)

                listed = await call("list_scripts", project_id="default")
                assert listed["host_enabled"]
                assert any(s["script_id"] == "shipped/tag_functions_by_complexity.py" for s in listed["scripts"])
                r = await call("run_script", program_id=pid, script_id="shipped/tag_functions_by_complexity.py",
                               args={"measure": "instructions"})
                assert r["status"] == "ok" and r["seqs"] and "function(s) at or over" in r["output"], r
                r = await call("run_script", program_id=pid, script_id="shipped/tag_functions_by_complexity.py")
                assert r["status"] == "cancelled" and r["unanswered_prompts"] == ["measure"], r
                r = await call("run_script", program_id=pid, script_id="user/progress.py")
                assert r["trust_required"] and r["sha256"], r
                r = await call("run_script", program_id=pid, script_id="user/progress.py", confirm_sha256=r["sha256"])
                assert r["status"] == "ok" and "done" in r["output"], r

        anyio.run(run)
        server.revkit_client.close()


def test_rk_script_setup_plan(tmp_path):
    import subprocess

    r = subprocess.run([sys.executable, "-m", "revkit.script.cli", "setup", "--dry-run", "--dir", str(tmp_path / "env"),
                        "--with", "capstone"], capture_output=True, text=True, env={**os.environ, "RK_DAEMON": ""})
    assert r.returncode == 0, r.stderr
    lines = r.stdout.splitlines()
    assert lines[0].endswith(f"-m venv {tmp_path / 'env'}")
    assert "pip install" in lines[1] and lines[1].endswith("capstone") and "sdk/python" in lines[1]
    assert "--force-reinstall --no-deps" in lines[2] and "capstone" not in lines[2]
    assert lines[3].endswith("import revkit.script.worker, revkit.script.console")


def test_script_api_stamp_matches_the_daemon():
    # The SDK's stamp is the daemon's number (src/api/script_service.cc): an
    # SDK below it is "older than this daemon".
    import re
    from pathlib import Path

    from revkit.script import SCRIPT_API

    src = Path(__file__).resolve().parents[3] / "src" / "api" / "script_service.cc"
    if not src.is_file():
        pytest.skip("not in a source tree")
    m = re.search(r"constexpr int kScriptSdkApi = (\d+);", src.read_text())
    assert m and int(m.group(1)) == SCRIPT_API
