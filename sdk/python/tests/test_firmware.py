"""Firmware emulation through the SDK (api_minor 20, feature
"firmware-emulation"): a raw ARMv4T program on a machine description, UART
input, the machine's interrupts, exception breakpoints in the debugger, the
timeline's events, and machines saved with the program."""

import shutil
import subprocess
from pathlib import Path

import pytest

from revkit import Client, Daemon, debug_stop_kind, stop_kind

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "src" / "emu" / "tests" / "fixtures" / "fwemu"


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    tools = [shutil.which(t) for t in ("clang", "ld.lld", "llvm-objcopy")]
    if not all(tools):
        pytest.skip("needs clang, ld.lld and llvm-objcopy")
    out = tmp_path_factory.mktemp("fwemu")
    subprocess.run(["sh", str(FIXTURES / "build.sh"), *tools, str(out)], check=True, capture_output=True)
    return out


@pytest.fixture(scope="module")
def image_daemon(fixtures):
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def import_raw(rk, path, name):
    return rk.program(rk.import_program("default", path=str(path), name=name, format="raw",
                                        language_id="ARM:LE:32:v4t").program.program_id)


def test_uart_and_interrupts_on_a_machine(image_daemon, fixtures):
    board = (FIXTURES / "versatilepb.json").read_text()
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        info = rk.server_info()
        assert "firmware-emulation" in info.features and info.api_minor >= 20
        prog = import_raw(rk, fixtures / "arm_uart.bin", "arm_uart")
        with prog.emulate(machine=board) as emu:
            assert emu.created.machine.cpu == "arm"
            assert stop_kind(emu.run().stop) == "idle"
            emu.input(b"hi\nquit\n")
            done = emu.run()
            assert stop_kind(done.stop) == "exited"
            assert emu.stdout == b"uart echo test\necho: HI\necho: QUIT\nlines 2\ndone\n"
            m = emu.machine()
            assert m.state.cpu == "arm" and any(e.kind == "irq" and e.source == "vic" for e in m.events)

        timer = import_raw(rk, fixtures / "arm_timer.bin", "arm_timer")
        timer.save_machine("versatilepb", board)
        assert [m.name for m in timer.machines()] == ["versatilepb"]
        with timer.debug(machine_name="versatilepb") as dbg:
            assert dbg.break_on("fiq") == ["fiq"]
            hit = dbg.run()
            assert debug_stop_kind(hit.stop) == "exception" and hit.state.pc.address.offset == 0x1C
            dbg.break_on()
            assert debug_stop_kind(dbg.run().stop) == "exited"
            events = [s.event for s in dbg.timeline(events_only=True, limit=10000).snapshots]
            assert events.count("irq") == 10 and events.count("fiq") == 2
        timer.delete_machine("versatilepb")
        assert list(timer.machines()) == []
