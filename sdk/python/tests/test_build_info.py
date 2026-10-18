"""Build metadata (api_minor 88, feature "build-info"; docs/build-info.md)
through the SDK and MCP: a Go binary's build info and function table
(api_minor 93, feature "go-pclntab"; docs/go.md) and a Rust binary's
cargo-auditable dependency list, each built here when its toolchain is
installed ($RK_GO or go; $RK_CARGO or cargo with cargo-auditable), with a
dependency replaced by a local directory so nothing reaches the network."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from revkit import Client, Daemon


def _tool(env: str, name: str, *extra: str) -> str:
    for c in (os.environ.get(env), shutil.which(name), *extra):
        if c and Path(c).exists():
            return c
    return ""


GO = _tool("RK_GO", "go", str(Path.home() / ".local/go/bin/go"), "/usr/local/go/bin/go")
CARGO = _tool("RK_CARGO", "cargo", str(Path.home() / ".cargo/bin/cargo"))


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.fixture(scope="module")
def go_binary(tmp_path_factory):
    if not GO:
        pytest.skip("no Go toolchain (set RK_GO)")
    d = tmp_path_factory.mktemp("go-build-info")
    _write(d / "go.mod", "module example.com/hello\n\ngo 1.21\n\nrequire example.com/dep v0.1.0\n\n"
                         "replace example.com/dep => ./dep\n")
    _write(d / "dep/go.mod", "module example.com/dep\n\ngo 1.21\n")
    _write(d / "dep/dep.go", 'package dep\n\n//go:noinline\nfunc Greeting() string { return "hi" }\n')
    _write(d / "main.go", 'package main\n\nimport (\n\t"fmt"\n\n\t"example.com/dep"\n)\n\nfunc main() { fmt.Println(dep.Greeting()) }\n')
    env = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOFLAGS="-p=2", CGO_ENABLED="0", GOWORK="off")
    subprocess.run([GO, "build", "-ldflags=-s -w", "-o", str(d / "hello"), "."], cwd=d, env=env, check=True,
                   capture_output=True)
    return d / "hello"


@pytest.fixture(scope="module")
def rust_binary(tmp_path_factory):
    if not CARGO or not (Path(CARGO).parent / "cargo-auditable").exists():
        pytest.skip("no cargo with cargo-auditable (set RK_CARGO)")
    d = tmp_path_factory.mktemp("rust-build-info")
    _write(d / "Cargo.toml", '[package]\nname = "hello"\nversion = "0.3.1"\nedition = "2021"\n\n'
                             '[dependencies]\ndep = { path = "dep" }\n')
    _write(d / "dep/Cargo.toml", '[package]\nname = "dep"\nversion = "1.2.3"\nedition = "2021"\n')
    _write(d / "dep/src/lib.rs", 'pub fn greeting() -> &\'static str { "hi" }\n')
    _write(d / "src/main.rs", 'fn main() { println!("{}", dep::greeting()); }\n')
    env = dict(os.environ, PATH=f"{Path(CARGO).parent}:{os.environ.get('PATH', '')}", CARGO_TARGET_DIR=str(d / "target"))
    subprocess.run([CARGO, "auditable", "build", "--offline", "-j2"], cwd=d, env=env, check=True, capture_output=True)
    return d / "target/debug/hello"


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def _mcp(target, program_id, **args):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server
    server = create_server(target, agent="claude", agent_version="test", session="mcp-build-info")

    async def run():
        async with mcp_client.Client(server) as mcp:
            res = await mcp.call_tool("build_info", {"program_id": program_id, **args})
            return json.loads(res.content[0].text)

    return anyio.run(run)


def test_go(image_daemon, go_binary):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        assert "build-info" in rk.server_info().features
        prog = rk.program(rk.import_program("default", path=str(go_binary), name="go-hello").program.program_id)
        bi = prog.build_info()
        assert bi.HasField("go") and not bi.HasField("rust") and not bi.warnings
        g = bi.go
        assert g.go_version.startswith("go1.") and g.format == "inline" and g.pointer_size == 8
        assert g.path == "example.com/hello" and g.main.path == "example.com/hello"
        assert [(d.path, d.version, d.replacement.path) for d in g.deps] == [("example.com/dep", "v0.1.0", "./dep")]
        settings = {s.key: s.value for s in g.settings}
        assert settings["-ldflags"] == "-s -w" and settings["CGO_ENABLED"] == "0"
        assert settings["GOOS"] == "linux" and settings["GOARCH"] == "amd64"
        assert "dep\texample.com/dep\tv0.1.0" in g.module_text
        # The header is in .go.buildinfo.
        sec = next(b for b in prog.summary().memory if b.name == ".go.buildinfo")
        assert sec.range.first.offset <= g.address.offset <= sec.range.last.offset

        out = _mcp(image_daemon.grpc_target, prog.id)
        assert out["go"]["go_version"] == g.go_version and out["go"]["dep_count"] == 1
        assert out["go"]["deps"][0]["replacement"]["path"] == "./dep", out
        assert out["go"]["settings"]["-ldflags"] == "-s -w"
        short = _mcp(image_daemon.grpc_target, prog.id, deps=False, settings=False)
        assert "deps" not in short["go"] and "settings" not in short["go"] and short["go"]["dep_count"] == 1


def test_go_pclntab(image_daemon, go_binary):
    """The stripped binary's function table (api_minor 92, feature
    "go-pclntab"; docs/go.md): its summary, and the functions it named."""
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        assert "go-pclntab" in rk.server_info().features
        imp = rk.import_program("default", path=str(go_binary), name="go-pclntab")
        assert any(w.startswith("analysis:go: ") and "pclntab 1.20 layout" in w for w in imp.warnings), imp.warnings
        prog = rk.program(imp.program.program_id)
        t = prog.build_info().go_pclntab
        assert prog.build_info().HasField("go_pclntab")
        assert t.layout == "1.20" and t.found_by == "section" and t.pointer_size == 8 and t.quantum == 1
        assert not t.big_endian and t.HasField("text_start") and t.HasField("moduledata")
        assert t.functions_read == t.function_count > 1000 and t.file_count > 50
        names = {f.name for f in prog.functions()}
        assert {"main.main", "example.com/dep.Greeting", "fmt.Fprintln", "runtime.throw"} <= names
        assert sum(n.startswith("FUN_") for n in names) * 50 < len(names)
        plates = [c for c in prog.comments("plate", text_contains="main.go:") if c.function_name == "main.main"]
        assert plates and plates[0].text.startswith("Go source: ")

        out = _mcp(image_daemon.grpc_target, prog.id)
        assert out["go_pclntab"]["layout"] == "1.20" and out["go_pclntab"]["functions"] == t.functions_read
        assert out["go_pclntab"]["found_by"] == "section"


def test_rust(image_daemon, rust_binary):
    with Client(image_daemon.grpc_target, actor="user:alice") as rk:
        prog = rk.program(rk.import_program("default", path=str(rust_binary), name="rust-hello").program.program_id)
        bi = prog.build_info()
        assert bi.HasField("rust") and not bi.HasField("go") and not bi.warnings
        r = bi.rust
        assert r.HasField("root")
        root = r.packages[r.root]
        assert (root.name, root.version, root.source) == ("hello", "0.3.1", "local")
        assert [r.packages[i].name for i in root.dependencies] == ["dep"]
        assert bi.rustc_version.startswith("rustc version 1.") and bi.rustc_commits

        out = _mcp(image_daemon.grpc_target, prog.id)
        assert out["rust"]["root"] == {"name": "hello", "version": "0.3.1"}
        assert {p["name"]: p.get("dependencies", []) for p in out["rust"]["packages"]} == {"dep": [], "hello": ["dep"]}
        assert out["rustc_version"] == bi.rustc_version
