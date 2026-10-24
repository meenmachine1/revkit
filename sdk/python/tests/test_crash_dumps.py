"""Crash dumps as debug sessions (api_minor 102, feature "crash-dumps";
docs/crash-dumps.md) through the SDK and MCP: a real core of
tests/data/crash/crash.c crashing in libcrash.so (made by the kernel when
core_pattern writes files, else by gcore on the program stopped), imported
and opened over the program with its library in the project; the same core
from the host with the C library read under --browse-root; a minidump of
the mingw build of tests/data/crash/win.c; who may open what."""

import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from revkit import Client, Daemon, FailedPrecondition, PermissionDenied

DATA = Path(__file__).resolve().parents[3] / "tests" / "data" / "crash"
LIBC_DIR = "/usr/lib/x86_64-linux-gnu"


def _idle(*progs):
    import time
    deadline = time.monotonic() + 120
    for p in progs:
        while not p.analysis_status().idle and time.monotonic() < deadline:
            time.sleep(0.2)


def _import(rk, project, d: Path):
    """The program and its library (not the C library: that comes from the host)."""
    exe = rk.import_program(project, path=str(d / "crash")).program
    rk.import_program(project, path=str(d / "libcrash.so"))
    return exe


def _core(d: Path):
    """The core and whether the kernel wrote it (else gcore did, at a SIGSTOP)."""
    pattern = Path("/proc/sys/kernel/core_pattern").read_text().strip()
    if pattern and not pattern.startswith("|"):
        subprocess.run(["sh", "-c", "ulimit -c unlimited; exec ./crash"], cwd=d, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        cores = [p for p in d.iterdir() if p.name.startswith("core")]
        if cores:
            return cores[0], True
    if not shutil.which("gcore"):
        pytest.skip("no core: core_pattern pipes to a helper and gcore is missing")
    p = subprocess.Popen(["./crash", "stop"], cwd=d)
    try:
        for _ in range(500):
            if Path(f"/proc/{p.pid}/stat").read_text().split(")")[1].split()[0] == "T":
                break
            import time
            time.sleep(0.01)
        subprocess.run(["gcore", "-o", str(d / "gcore"), str(p.pid)], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    finally:
        p.send_signal(signal.SIGKILL)
        p.wait()
    return d / f"gcore.{p.pid}", False


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc or sys.platform != "linux" or os.uname().machine != "x86_64":
        pytest.skip("needs cc on x86-64 Linux")
    d = tmp_path_factory.mktemp("crash")
    subprocess.run([cc, "-O1", "-g", "-shared", "-fPIC", "-o", str(d / "libcrash.so"), str(DATA / "libcrash.c")], check=True)
    subprocess.run([cc, "-O1", "-g", "-o", str(d / "crash"), str(DATA / "crash.c"), f"-L{d}", "-lcrash",
                    "-Wl,-rpath,$ORIGIN", "-pthread"], check=True)
    core, kernel = _core(d)
    out = {"dir": d, "core": core, "kernel": kernel, "dump": None}
    mingw = shutil.which("x86_64-w64-mingw32-gcc")
    if mingw:
        subprocess.run([mingw, "-O1", "-o", str(d / "win64.exe"), str(DATA / "win.c")], check=True)
        subprocess.run([sys.executable, "-I", str(DATA / "make_minidump.py"), str(d / "win64.dmp"), "--arch", "amd64",
                        "--pe", str(d / "win64.exe")], check=True)
        out["dump"] = d / "win64.dmp"
    return out


@pytest.fixture(scope="module")
def daemon(fixtures):
    with Daemon(None, "--backend", "image", "--browse-root", str(fixtures["dir"]), "--browse-root", LIBC_DIR,
                startup_timeout=60) as d:
        yield d


def test_core_over_the_program(daemon, fixtures):
    d = fixtures["dir"]
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        info = rk.server_info()
        assert "crash-dumps" in info.features and info.api_minor >= 102
        rk.open_project(path=str(d / "proj"), create=True, name="crash")
        exe = _import(rk, "crash", d)
        progs = {p.name: p for p in rk.programs("crash")}
        assert "libcrash.so" in progs
        core = rk.import_program("crash", path=str(fixtures["core"]), analyze=False).program
        assert core.crash_dump == "elf-core"
        prog = rk.program(exe.program_id)
        _idle(prog, rk.program(progs["libcrash.so"].program_id))
        with prog.crash_dump(core.program_id) as s:
            c = s.created.crash
            assert s.created.target_kind == "crash-dump"
            assert c.format == "elf-core" and c.arch == "x86-64"
            assert len(c.threads) == 2
            mods = {m.name: m for m in c.modules}
            assert mods["libcrash.so"].program_id == progs["libcrash.so"].program_id
            assert mods["crash"].main and mods["crash"].program_id == exe.program_id
            if fixtures["kernel"]:
                assert c.reason == "SIGSEGV (SEGV_MAPERR) at 0x0" and c.fault_address == 0
                assert c.signal_name == "SIGSEGV" and c.code_name == "SEGV_MAPERR"
                assert c.module == "libcrash.so"
                assert c.function.startswith("lib_store"), c.function
                print(c.summary)
                # The faulting store, decoded from the library program's bytes.
                assert c.instruction.startswith("MOV dword ptr [RDI]"), c.instruction
                names = [f.function for f in c.backtrace]
                assert names[:4] == ["lib_store", "lib_compute", "run_crash", "main"], names
                assert [f.how for f in c.backtrace[1:4]] == ["cfi", "cfi", "cfi"], [f.how for f in c.backtrace]
                assert c.backtrace[2].pc.HasField("program_address")
                assert "lib_store" in c.summary and "SIGSEGV" in c.summary
                st = s.get_state()
                assert st.last_stop.signal == 11 and st.target_state == 1
            # Read-only: running and writing are refused.
            with pytest.raises(FailedPrecondition):
                s.run()
            # Threads: the other one waits in libc.
            other = next(t for t in c.threads if not t.crashed)
            assert other.pc.module == "libc.so.6"
            s.select_thread(other.id)
            assert s.backtrace()[0].pc.module == "libc.so.6"
            # Memory as dumped: the stack.
            regs = s.registers()
            assert len(s.read(regs.get("RSP", 0), 64, runtime=True)) == 64
            assert s.crash().crashed_thread == c.crashed_thread


def test_core_from_the_host_reads_libc(daemon, fixtures):
    """An admin's session over the program reads libc from its file under
    --browse-root: the waiting thread's stack unwinds through it by CFI."""
    d = fixtures["dir"]
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        rk.open_project(path=str(d / "proj2"), create=True, name="crash2")
        exe = _import(rk, "crash2", d)
        _idle(*[rk.program(p.program_id) for p in rk.programs("crash2")])
        with rk.program(exe.program_id).crash_dump(host_path=str(fixtures["core"])) as s:
            c = s.created.crash
            other = next(t for t in c.threads if not t.crashed)
            assert other.where.startswith("libc.so.6+"), other.where  # an internal libc function: no symbol covers it
            s.select_thread(other.id)
            frames = s.backtrace()
            # libc's exported pthread_cond_wait names its frame, from the file's symbols.
            assert any(f.function == "pthread_cond_wait" for f in frames), [(f.function, f.how) for f in frames]
            assert any(f.how == "cfi" for f in frames[1:]), [f.how for f in frames]
            # Through libc's condition wait, by its CFI, to the thread's function in the program.
            assert "waiter" in [f.function for f in frames], [(f.function, f.how) for f in frames]


def test_minidump(daemon, fixtures):
    if not fixtures["dump"]:
        pytest.skip("needs x86_64-w64-mingw32-gcc")
    d = fixtures["dir"]
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        rk.open_project(path=str(d / "proj3"), create=True, name="win")
        exe = rk.import_program("win", path=str(d / "win64.exe")).program
        _idle(rk.program(exe.program_id))
        with rk.program(exe.program_id).crash_dump(host_path=str(fixtures["dump"])) as s:
            c = s.created.crash
            assert c.format == "minidump" and c.os == "Windows 10.0.19045" and c.pid == 4242
            assert c.exception_name == "EXCEPTION_ACCESS_VIOLATION" and c.access == "write" and c.fault_address == 0
            assert c.reason.startswith("EXCEPTION_ACCESS_VIOLATION (write of 0x0) at 0x")
            # The module at another base: mapped, and the store decoded from the program.
            assert c.pc.HasField("program_address")
            assert c.instruction.startswith("MOV dword ptr [RCX],EDX"), c.instruction
            assert c.function.startswith("crash_here"), c.function
            assert [t.name for t in c.threads] == ["main thread", "worker"]
            mods = {m.name: m for m in c.modules}
            assert mods["win64.exe"].version == "1.2.3.4" and mods["win64.exe"].pdb_name == "win.pdb"
            assert len(c.backtrace) >= 2 and c.backtrace[1].function.startswith("caller"), [f.function for f in c.backtrace]


def test_roles(fixtures, tmp_path):
    """A dump that is a program of the project is an editor's to open; a
    host file is an admin's."""
    with Daemon(None, "--backend", "image", auth=True, startup_timeout=60) as dmn:
        admin = dmn.create_token("root", "admin")
        editor = dmn.create_token("eve", "editor")
        with dmn.client(token=admin) as rk:
            exe = rk.import_program("default", content=(fixtures["dir"] / "crash").read_bytes(), name="crash").program
            core = rk.import_program("default", content=fixtures["core"].read_bytes(), name="core", analyze=False).program
        with dmn.client(token=editor) as rk:
            prog = rk.program(exe.program_id)
            with pytest.raises(PermissionDenied):
                prog.crash_dump(host_path=str(fixtures["core"]))
            with prog.crash_dump(core.program_id) as s:
                assert s.crash().threads


def test_mcp(daemon, fixtures):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    with Client(daemon.grpc_target, actor="user:alice") as rk:
        rk.open_project(path=str(fixtures["dir"] / "proj4"), create=True, name="mcpcrash")
        exe = _import(rk, "mcpcrash", fixtures["dir"])
        _idle(*[rk.program(p.program_id) for p in rk.programs("mcpcrash")])

    def _json(result):
        assert not result.is_error, result
        return json.loads(result.content[0].text)

    async def run():
        server = create_server(daemon.grpc_target, agent="claude", agent_version="test", session="mcp-crash")
        async with mcp_client.Client(server) as c:
            async def call(name, **args):
                return _json(await c.call_tool(name, args))
            opened = await call("debug_crash_dump", program_id=exe.program_id, host_path=str(fixtures["core"]))
            crash = opened["crash"]
            assert len(crash["threads"]) == 2 and crash["backtrace"]
            if fixtures["kernel"]:
                assert crash["reason"] == "SIGSEGV (SEGV_MAPERR) at 0x0"
                assert crash["where"].startswith("lib_store") and crash["module"] == "libcrash.so"
            again = await call("debug_crash", session_id=opened["session_id"])
            assert "summary" in again and again["crashed_thread"] == crash["crashed_thread"]
            await call("debug_close", session_id=opened["session_id"])
    anyio.run(run)
