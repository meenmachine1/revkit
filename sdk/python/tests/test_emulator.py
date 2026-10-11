"""EmulatorService through the SDK against the image backend: a call with
arguments, a breakpoint, stepping with changed registers, memory, the trace,
and the program run as a process to its exit."""

import shutil
import subprocess

import pytest

from revkit import Client, Daemon, InvalidArgument, stop_kind

SOURCE = r"""
#include <stdio.h>
int counter;
__attribute__((noinline)) int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
int main(int argc, char **argv) {
  counter = fib(argc + 9);
  printf("fib=%d\n", counter);
  return counter & 0x7f;
}
"""


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("emu")
    (d / "prog.c").write_text(SOURCE)
    subprocess.run([cc, "-O1", "-fno-inline", "-o", str(d / "prog"), str(d / "prog.c")], check=True)
    return d / "prog"


@pytest.fixture(scope="module")
def image_daemon(binary):
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_emulate_a_function_and_the_program(image_daemon, binary):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        info = rk.server_info()
        assert "emulator" in info.features and info.api_minor >= 12
        prog = rk.program(rk.import_program("default", path=str(binary)).program.program_id)
        fib = next(f.entry.offset for f in prog.functions() if f.name == "fib")

        with prog.emulate(fib, mode="call", args=[10]) as emu:
            assert emu.created.pc_register == "RIP"
            assert emu.pc == fib
            stepped = emu.step()
            assert stop_kind(stepped.stop) == "stepped"
            assert any(r.changed for r in stepped.state.registers if r.name == "RIP")
            assert emu.breakpoint(fib) == [fib]
            hit = emu.run()
            assert stop_kind(hit.stop) == "breakpoint" and hit.state.pc.offset == fib
            emu.clear_breakpoints()
            done = emu.run()
            assert stop_kind(done.stop) == "returned" and done.stop.exit_code == 55
            assert emu.registers("RAX") == {"RAX": 55}
            emu.set_registers(RBX=0x1234)
            assert emu.register("rbx") == 0x1234
            with pytest.raises(InvalidArgument):
                emu.set_registers(NOPE=1)
            sp = emu.register("RSP")
            emu.write(sp, b"\x01\x02\x03")
            assert emu.read(sp, 3) == b"\x01\x02\x03"
            trace = emu.trace(limit=3)
            assert len(trace.entries) == 3 and trace.entries[0].pc.offset == fib
            assert trace.summary.steps > 100
            assert emu.trace_json()["stop"]["kind"] == "returned"
            assert any(s.session_id == emu.id for s in rk.emulator_sessions())
        assert not any(s.session_id == emu.id for s in rk.emulator_sessions())

        with prog.emulate() as process:
            ran = process.run()
            assert stop_kind(ran.stop) == "exited" and ran.stop.exit_code == 55
            assert process.stdout == b"fib=55\n"
