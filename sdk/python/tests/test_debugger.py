"""DebugService through the SDK against the image backend: the emulator with
time travel and a saved trace replayed, and (with gdbserver) the program
launched as a sliding PIE, broken into at its static addresses."""

import shutil
import subprocess

import pytest

from revkit import Client, Daemon, FailedPrecondition, debug_stop_kind

SOURCE = r"""
#include <stdio.h>
int counter;
char message[16] = "hello";
__attribute__((noinline)) int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
int main(int argc, char **argv) {
  counter = fib(argc + 9);
  message[0] = 'H';
  printf("%s fib=%d\n", message, counter);
  return 0;
}
"""


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("dbg")
    (d / "prog.c").write_text(SOURCE)
    subprocess.run([cc, "-O1", "-fno-inline", "-pie", "-fPIE", "-o", str(d / "prog"), str(d / "prog.c")], check=True)
    return d / "prog"


@pytest.fixture(scope="module")
def live_daemon(binary):
    with Daemon(None, "--backend", "image", "--debug-live", startup_timeout=60) as d:
        yield d


def symbols(prog):
    return {f.name: f.entry.offset for f in prog.functions()}


def test_emulator_time_travel_and_traces(live_daemon, binary):
    with Client(live_daemon.grpc_target, actor="user:alice") as rk:
        info = rk.server_info()
        assert "debugger" in info.features and "debugger-live" in info.features and info.api_minor >= 14
        prog = rk.program(rk.import_program("default", path=str(binary)).program.program_id)
        fn = symbols(prog)
        with prog.debug("emulator", entry=fn["fib"], mode="call", args=["5"]) as dbg:
            assert dbg.created.target_kind == "emulator"
            assert dbg.pc == fn["fib"]
            dbg.breakpoint(fn["fib"])
            r = dbg.run()
            assert debug_stop_kind(r.stop) == "breakpoint"
            assert dbg.register("RDI") == 4
            t = dbg.timeline()
            assert t.complete and t.count > 2
            assert dbg.register("RDI", snapshot=t.first) == 5
            stops = dbg.timeline(stops_only=True)
            assert [debug_stop_kind(s.stop) for s in stops.snapshots] == ["none", "breakpoint"]
            # The call stack (api_minor 59): fib(4) inside fib(5).
            frames = dbg.backtrace()
            assert [f.function for f in frames[:2]] == ["fib", "fib"], frames
            assert frames[0].level == 0 and frames[1].function_offset > 0
            # Values (api_minor 60): registers, expressions, a snapshot, changed marks.
            assert dbg.value("$RDI") == "0x4" and dbg.value("RDI * 2") == "8"
            assert dbg.value("$RDI", snapshot=t.first) == "0x5"
            v = dbg.evaluate("$RDI", "nosuch", compare_snapshot=t.first)
            assert v[0].changed and "nosuch" in v[1].error
            # A watch in a function's frame (api_minor 61).
            assert dbg.evaluate("$RDI", function=fn["fib"], frame=0)[0].text == "0x4"
            first = dbg.backtrace(snapshot=t.first)
            assert first[0].function == "fib" and first[0].function_offset == 0 and len(first) <= len(frames)
            saved = dbg.save("fib5")
            assert saved.snapshots == t.count
            # Rewinding (api_minor 65): one instruction back, then on to the same stop.
            assert dbg.get_state().rewindable
            back = dbg.step_back()
            assert back.discarded == 1 and back.state.last_snapshot == t.last - 1
            r = dbg.run()
            assert debug_stop_kind(r.stop) == "breakpoint" and dbg.register("RDI") == 4
        assert [x.name for x in prog.debug_traces()] == ["fib5"]
        with prog.debug("trace:fib5") as replay:
            assert replay.register("RDI") == 4
            assert replay.register("RDI", snapshot=0) == 5
            with pytest.raises(FailedPrecondition):
                replay.run()
        # A conditional breakpoint (api_minor 64): on to where n is 1, then the next call.
        with prog.debug("emulator", entry=fn["fib"], mode="call", args=["5"]) as dbg:
            bp = dbg.breakpoint(fn["fib"], condition="$RDI == 1")[0]
            r = dbg.run()
            assert debug_stop_kind(r.stop) == "breakpoint" and dbg.register("RDI") == 1
            bps = dbg.update_breakpoint(bp.id, condition="")
            assert bps[0].condition == "" and bps[0].hits == 4
            dbg.run()
            assert dbg.register("RDI") == 0
        # Hooks (api_minor 68): fib(10) answered in Python, the rest of the program as it is.
        with prog.debug("emulator") as dbg:
            seen = []

            def fib_hook(h):
                seen.append(h.arg(0) & 0xFFFFFFFF)
                return 89 if h.arg(0) == 10 else None
            hid = dbg.hook_function("fib", fib_hook)
            r = dbg.run()
            assert debug_stop_kind(r.stop) == "exited", r.stop
            assert b"fib=89" in dbg.output and seen == [10]
            assert dbg.hooks()[0].id == hid and dbg.hooks()[0].hits == 1
        prog.delete_debug_trace("fib5")
        assert list(prog.debug_traces()) == []


def test_launch_a_pie(live_daemon, binary):
    if not shutil.which("gdbserver"):
        pytest.skip("gdbserver is not installed")
    with Client(live_daemon.grpc_target, actor="user:alice") as rk:
        prog = rk.program(rk.import_program("default", path=str(binary), name="prog2").program.program_id)
        fn = symbols(prog)
        with prog.debug("launch", breakpoints=[fn["main"]]) as dbg:
            assert dbg.created.target_kind == "gdb-remote"
            mapping = dbg.state.mapping
            assert mapping.known and mapping.slide != 0
            r = dbg.run()
            assert debug_stop_kind(r.stop) == "breakpoint", r.stop.detail
            assert dbg.pc == fn["main"]
            assert r.stop.pc.address.offset == fn["main"] + mapping.slide
            assert dbg.register("RDI") == 1
            # The stack into the program as a block (api_minor 63).
            rsp = dbg.register("RSP")
            c = dbg.copy_memory(rsp, region=True, runtime=True)
            assert c.region_id and c.address <= rsp < c.address + c.length and len(c.seqs) == 1
            message = next(s.address.offset for s in prog.symbols(name_equals="message"))
            assert dbg.read(message, 5) == b"hello"
            at_main = dbg.timeline().last
            dbg.watch(message, 1)
            r = dbg.run()
            assert debug_stop_kind(r.stop) == "watchpoint"
            dbg.clear_breakpoints()
            assert dbg.read(message, 5) == b"Hello"
            assert dbg.read(message, 5, snapshot=at_main) == b"hello"
            # Runtime disassembly (api_minor 62): main by its static address names its call to fib.
            d = dbg.disassemble(fn["main"], 40)
            assert any(i.call and i.target_symbol == "fib" for i in d.instructions), d
            assert d.next > d.instructions[-1].location.address.offset
            # An emulator from this stop (api_minor 66): the process's state, the process untouched.
            with prog.debug("emulator", from_session=dbg) as em:
                assert em.created.target_kind == "emulator"
                assert em.register("RDI") == dbg.register("RDI") and em.pc == dbg.pc
                em.step()
                assert em.pc != dbg.pc
            mods = dbg.modules()
            assert any(m.program for m in mods.modules)
            r = dbg.run()
            assert debug_stop_kind(r.stop) == "exited" and r.stop.exit_code == 0
            assert b"Hello fib=55" in dbg.output


def test_mcp_backtrace(live_daemon, binary):
    mcp_client = pytest.importorskip("mcp.client.client")
    import json

    import anyio

    from revkit.mcp_server import create_server

    with Client(live_daemon.grpc_target, actor="user:alice") as rk:
        prog = rk.program(rk.import_program("default", path=str(binary), name="prog-bt").program.program_id)
        fn = symbols(prog)
    server = create_server(live_daemon.grpc_target, agent="claude", session="mcp-bt")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                r = await mcp.call_tool(tool, args)
                assert not r.is_error, r
                return json.loads(r.content[0].text)

            started = await call("debug_start", program_id=prog.id, entry=hex(fn["fib"]), mode="call", args=["5"])
            sid = started["session_id"]
            await call("debug_breakpoints", session_id=sid, set=[hex(fn["fib"])])
            await call("debug_run", session_id=sid)
            # emu_call (api_minor 68): fib(6) with the recursive calls stubbed to 1.
            ec = await call("emu_call", program_id=prog.id, function=hex(fn["fib"]), args=["6"], returns={"fib": "1"})
            assert ec["stop"] == "returned" and ec["return_value"] == 2 and len(ec["stubbed_calls"]["fib"]) == 2, ec
            dis = await call("debug_disassemble", session_id=sid, count=3)
            assert dis["lines"][0].startswith("=> ") and "fib" in dis["lines"][0], dis
            vals = await call("debug_evaluate", session_id=sid, expressions=["$RDI", "RDI + 1"])
            assert [x["text"] for x in vals["values"]] == ["0x4", "5"], vals
            bt = await call("debug_backtrace", session_id=sid)
            assert [f.get("function", "").split("+")[0] for f in bt["frames"][:2]] == ["fib", "fib"], bt
            await call("debug_close", session_id=sid)

    anyio.run(run)
    server.revkit_client.close()
