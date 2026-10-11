"""WebAssembly plugins through the daemon: listing them, analyzer facts,
a command's edits with plugin provenance and their revert, and a loader
plugin importing a custom format. Needs the example plugins
(build/plugins, or $RK_PLUGIN_DIR) and a C compiler."""

import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from revkit import Client, Daemon, FailedPrecondition, InvalidArgument, format_provenance
from revkit.v1 import common_pb2, plugin_pb2

SOURCE = r"""
const char greeting[] = "hello, plugin";
__attribute__((noinline)) int sum(const char *s) { int t = 0; while (*s) t += *s++; return t; }
__attribute__((noinline)) int uses_greeting(void) { return sum(greeting); }
void _start(void) { volatile int r = uses_greeting(); (void)r; for (;;) {} }
"""

FLAGS = ["-O1", "-nostdlib", "-static", "-ffreestanding", "-fno-pie", "-no-pie", "-fno-asynchronous-unwind-tables"]


def plugin_dir():
    d = os.environ.get("RK_PLUGIN_DIR") or str(Path(__file__).resolve().parents[3] / "build" / "plugins")
    return d if Path(d, "rename-regex.wasm").exists() else None


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("prog")
    (d / "prog.c").write_text(SOURCE)
    subprocess.run([cc, *FLAGS, "-s", "-o", str(d / "prog"), str(d / "prog.c")], check=True)
    return d / "prog"


@pytest.fixture(scope="module")
def plugin_daemon():
    plugins = plugin_dir()
    if not plugins:
        pytest.skip("example plugins not built (no wasm32 clang)")
    with Daemon(None, "--backend", "image", "--plugin-dir", plugins, startup_timeout=60) as d:
        yield d


def test_plugins_are_listed(plugin_daemon):
    with Client(plugin_daemon.grpc_target) as rk:
        info = rk.server_info()
        assert "plugins" in info.features and info.api_minor >= 6
        plugins = {p.name: p for p in rk.plugins()}
        assert {"crc32-tables", "string-refs", "rkraw-loader", "rename-regex"} <= plugins.keys()
        assert plugins["rename-regex"].kind == plugin_pb2.PLUGIN_KIND_COMMAND
        assert all(p.loaded for p in plugins.values())


def test_analyzer_facts(plugin_daemon, binary):
    with Client(plugin_daemon.grpc_target, actor="user:alice") as rk:
        prog = rk.program(rk.import_program("default", path=str(binary), name="facts").program.program_id)
        facts = prog.plugin_facts("string-refs")
        assert not facts.errors
        comments = [f for f in facts.facts if f.kind == plugin_pb2.PLUGIN_FACT_KIND_COMMENT]
        assert [f.text for f in comments] == ['"hello, plugin"']
        assert comments[0].origin.derived.rule == "plugin:string-refs@1.0.0"
        labels = [f for f in facts.facts if f.kind == plugin_pb2.PLUGIN_FACT_KIND_LABEL]
        assert [f.text for f in labels] == ["str_hello_plugin"]
        # Renaming the function: its analyzer runs again and drops the suggestion.
        prog.rename(labels[0].address.offset, "greet")
        assert not [f for f in prog.plugin_facts("string-refs").facts if f.kind == plugin_pb2.PLUGIN_FACT_KIND_LABEL]


def test_command_provenance_and_revert(plugin_daemon, binary):
    with Client(plugin_daemon.grpc_target, actor="user:alice", session="py") as rk:
        prog = rk.program(rk.import_program("default", path=str(binary), name="cmd").program.program_id)
        before = {f.entry.offset: f.name for f in prog.functions()}
        defaults = [a for a, n in before.items() if n.startswith("FUN_")]
        assert defaults

        dry = prog.run_command("rename-regex", {"pattern": "^FUN_0*", "replace": "fn_"}, dry_run=True)
        assert len(dry.assertions) == len(defaults)
        assert {f.entry.offset: f.name for f in prog.functions()} == before

        ran = prog.run_command("rename-regex", {"pattern": "^FUN_0*", "replace": "fn_"}, reason="tidy names")
        assert len(ran.assertions) == len(defaults)
        p = ran.assertions[0].provenance
        assert format_provenance(p) == "plugin:rename-regex@1.0.0"
        assert p.session == "py" and p.reason == "tidy names"
        after = {f.entry.offset: f.name for f in prog.functions()}
        assert all(after[a].startswith("fn_") for a in defaults)

        blame = prog.blame(prog.key("name", defaults[0]))
        assert format_provenance(blame.origin.asserted.provenance) == "plugin:rename-regex@1.0.0"

        prog.revert(kind="plugin", id="rename-regex")
        assert {f.entry.offset: f.name for f in prog.functions()} == before

        with pytest.raises(InvalidArgument):
            prog.run_command("rename-regex", {"pattern": "x"})
        with pytest.raises(FailedPrecondition, match="bad pattern"):
            prog.run_command("rename-regex", {"pattern": "[", "replace": "x"})


def test_agent_runs_a_command_as_itself(plugin_daemon, binary):
    with Client(plugin_daemon.grpc_target, actor="agent:claude@opus-5.5", session="run-7") as rk:
        prog = rk.program(rk.import_program("default", path=str(binary), name="agent").program.program_id)
        ran = prog.run_command("rename-regex", {"pattern": "^FUN_", "replace": "auto_", "limit": 1})
        assert len(ran.assertions) == 1
        p = ran.assertions[0].provenance
        assert format_provenance(p) == "agent:claude@opus-5.5"
        assert p.tool == "plugin:rename-regex@1.0.0"
        prog.revert(kind="agent", session="run-7")


def test_loader_plugin_imports_a_custom_format(plugin_daemon):
    # x86-64: f: mov eax, 42; ret / entry: call f; jmp $
    code = bytes([0xB8, 0x2A, 0, 0, 0, 0xC3, 0xE8, 0xF5, 0xFF, 0xFF, 0xFF, 0xEB, 0xFE])
    base, header = 0x10000, 80
    lang = b"x86:LE:64:default".ljust(40, b"\0")
    blocks = struct.pack("<16sQQIIII", b".text", base, len(code), header + 48 + 32, len(code), 5, 0)
    symbols = struct.pack("<20sQI", b"answer", base, 1)
    raw = b"RKRAW\x01" + struct.pack("<HQ", 1, base + 6) + lang + b"gcc".ljust(16, b"\0") + struct.pack("<II", 1, 0)
    raw += blocks + symbols + code
    with Client(plugin_daemon.grpc_target, actor="user:alice") as rk:
        imported = rk.import_program("default", content=raw, name="tiny.rkr")
        assert imported.program.format == "plugin:rkraw-loader@1.0.0"
        prog = rk.program(imported.program.program_id)
        names = {f.entry.offset: f.name for f in prog.functions()}
        assert names[base] == "answer" and names[base + 6] == "entry"
        assert "42" in prog.decompile(base).text or "0x2a" in prog.decompile(base).text
