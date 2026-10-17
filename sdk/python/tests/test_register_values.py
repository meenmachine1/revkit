"""Register values over address ranges (api_minor 87, feature
\"register-values\"; docs/api.md "Register values") through the SDK and the
MCP tools on the image backend, on a MIPS program built here with small
data (clang and ld.lld; skipped without them): analysis takes gp from the
loader's _gp, so the decompiler names the globals bump reaches through it;
a clear over the function takes that away, a value gives it back, each one
undo step; what is refused."""

import json
import shutil
import subprocess

import pytest

from revkit import Client, Daemon, InvalidArgument
from revkit.v1 import common_pb2

SOURCE = r"""
int counter;
int limit = 7;
__attribute__((noinline)) int bump(int x) { counter += x; return counter < limit; }
void __start(void) { for (;;) if (!bump(3)) limit = 0; }
"""


@pytest.fixture(scope="module")
def target(tmp_path_factory):
    clang, lld = shutil.which("clang"), shutil.which("ld.lld")
    if not clang or not lld:
        pytest.skip("no clang and ld.lld")
    d = tmp_path_factory.mktemp("regvalues")
    (d / "g.c").write_text(SOURCE)
    try:
        subprocess.run([clang, "--target=mipsel-linux-gnu", "-O1", "-fno-pic", "-mno-abicalls", "-G", "8", "-c",
                        str(d / "g.c"), "-o", str(d / "g.o")], check=True, capture_output=True)
        subprocess.run([lld, "-e", "__start", "-o", str(d / "g.elf"), str(d / "g.o")], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        pytest.skip("clang can't build a MIPS program")
    return d / "g.elf"


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture()
def rk(image_daemon):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as c:
        yield c


@pytest.fixture()
def prog(rk, target):
    return rk.program(rk.import_program("default", path=str(target)).program.program_id)


def sym(prog, name) -> int:
    return list(prog.symbols(name_equals=name))[0].address.offset


def named(text):
    return "counter" in text and "limit" in text and "unaff_gp" not in text


def test_register_values(rk, prog):
    assert "register-values" in rk.server_info().features
    bump = sym(prog, "bump")
    # Analysis's gp, from the loader's _gp.
    ranges = list(prog.register_values("gp"))
    assert ranges and all(r.register_name == "gp" for r in ranges)
    gp = ranges[0].value
    assert ranges[0].origin.derived.rule == "analysis.register_values:mips-gp"
    assert prog.register_value("gp", bump) == gp
    assert "gp" in {r.name for r in prog.value_registers()}
    assert named(prog.decompile(bump).text)

    # Cleared over bump's body: one revision; gp is unknown there.
    cleared = prog.clear_register_value("gp", function=bump)
    assert [a.key.kind for a in cleared.assertions] == [common_pb2.FACT_KIND_REGISTER_VALUE]
    assert prog.register_value("gp", bump) is None
    assert "unaff_gp" in prog.decompile(bump).text
    prog.retract(*[a.seq for a in cleared.assertions])
    assert named(prog.decompile(bump).text)

    # The user's value over a range: alice's, and a different value shows.
    r = prog.set_register_value("gp", gp + 0x10, bump, bump + 0x17, reason="test")
    assert prog.register_value("gp", bump) == gp + 0x10
    mine = [x for x in prog.register_values("GP", first=bump, last=bump)]
    assert len(mine) == 1 and mine[0].origin.asserted.provenance.id == "alice" and mine[0].key.sub.startswith("gp:")
    assert not named(prog.decompile(bump).text)
    blame = prog.blame(prog.key("register_value", bump, mine[0].key.sub))
    assert blame.value_text == f"gp = {gp + 0x10:#x}" and blame.origin.asserted.provenance.id == "alice"
    prog.retract(*[a.seq for a in r.assertions])
    assert prog.register_value("gp", bump) == gp

    # Refused: not a register; a value too wide; a range backwards.
    with pytest.raises(InvalidArgument, match="not a register"):
        prog.set_register_value("nosuch", 1, bump)
    with pytest.raises(InvalidArgument, match="doesn't fit"):
        prog.set_register_value("gp", 1 << 40, bump)
    with pytest.raises(InvalidArgument, match="after"):
        prog.set_register_value("gp", 1, bump + 4, bump)


mcp_client = pytest.importorskip("mcp.client.client")
anyio = pytest.importorskip("anyio")


def test_mcp_register_values(image_daemon, rk, prog):
    from revkit.mcp_server import create_server

    bump = f"{sym(prog, 'bump'):#x}"
    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="regvalues")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(name, **args):
                r = await mcp.call_tool(name, args)
                assert not r.is_error, r
                out = json.loads(r.content[0].text)
                assert "error" not in out, (name, out)
                return out

            listed = await call("list_register_values", program_id=prog.id, register="gp")
            assert listed["ranges"] and listed["ranges"][0]["set_by"] == "analysis:mips-gp" and "gp" in listed["registers"]
            done = await call("set_register_value", program_id=prog.id, register="gp", clear=True,
                              function_address=bump, reason="mcp test")
            assert done["ok"], done
            after = await call("list_register_values", program_id=prog.id, register="gp", first=bump, last=bump)
            assert after["ranges"] == [], after
            await call("undo_changes", program_id=prog.id, seqs=[done["seq"]], reason="mcp test")
            back = await call("list_register_values", program_id=prog.id, register="gp", first=bump, last=bump)
            assert len(back["ranges"]) == 1

    anyio.run(run)
