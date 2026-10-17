"""Separate debug files for ELF (api_minor 86, feature "debug-files";
docs/backend.md "External debug files") through the SDK and MCP: a stripped
binary's debug file loaded by path, the settings (DEBUGINFOD_URLS only
suggested), and debuginfod from a fake server on a loopback port, never
contacted while off. No test reaches the internet."""

import http.server
import json
import shutil
import subprocess
import threading

import pytest

from revkit import Client, Daemon, NotFound
from revkit.v1 import project_pb2

SOURCE = r"""
struct point { int x; int y; };
struct point grid[4] = {{1, 2}, {3, 4}, {5, 6}, {7, 8}};
__attribute__((noinline)) int sum_points(struct point *pts, int n) {
  int total_sum = 0;
  for (int i = 0; i < n; i++) total_sum += pts[i].x * pts[i].y;
  return total_sum;
}
int main(int argc, char **argv) { (void)argv; return sum_points(grid, argc & 3); }
"""


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    """{"prog": stripped, "debug": its debug file, "build_id": hex}."""
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc or not shutil.which("objcopy"):
        pytest.skip("no C compiler or objcopy")
    d = tmp_path_factory.mktemp("debug-files")
    (d / "prog.c").write_text(SOURCE)
    subprocess.run([cc, "-g", "-O0", "-fno-pie", "-no-pie", "-Wl,--build-id=sha1", "-o", str(d / "prog.full"),
                    str(d / "prog.c")], check=True)
    subprocess.run(["objcopy", "--only-keep-debug", str(d / "prog.full"), str(d / "prog.debug")], check=True)
    alone = d / "alone"
    alone.mkdir()
    subprocess.run(["objcopy", "--strip-all", str(d / "prog.full"), str(alone / "prog")], check=True)
    out = subprocess.run(["readelf", "-n", str(alone / "prog")], capture_output=True, text=True).stdout
    build_id = next((line.split(":")[1].strip() for line in out.splitlines() if "Build ID" in line), "")
    if not build_id:
        pytest.skip("no build ID")
    return {"prog": alone / "prog", "debug": d / "prog.debug", "build_id": build_id}


@pytest.fixture(scope="module")
def fake_server(built):
    """A debuginfod on a loopback port: GET /buildid/<id>/debuginfo, and what it was asked."""
    debug = built["debug"].read_bytes()
    asked = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            asked.append(self.path)
            if self.path == f"/buildid/{built['build_id']}/debuginfo":
                self.send_response(200)
                self.send_header("Content-Length", str(len(debug)))
                self.end_headers()
                self.wfile.write(debug)
            else:
                self.send_error(404)

        def log_message(self, *a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield {"url": f"http://127.0.0.1:{server.server_address[1]}", "asked": asked}
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def daemon(tmp_path_factory, fake_server):
    projects = tmp_path_factory.mktemp("projects")
    with Daemon(None, "--backend", "image", "--project-dir", str(projects), startup_timeout=60,
                env={"DEBUGINFOD_URLS": fake_server["url"]}) as d:
        yield d


def symbol(prog, name):
    hits = list(prog.symbols(name_equals=name))
    return hits[0].address.offset if hits else 0


def test_by_path_and_undo(daemon, built):
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        prog = rk.program(rk.import_program("default", path=str(built["prog"]), name="by-path").program.program_id)
        assert symbol(prog, "sum_points") == 0
        summary = prog.summary()
        assert summary.build_id == built["build_id"] and summary.debug_file == ""
        with pytest.raises(ValueError):
            prog.load_debug_file()
        r = prog.load_debug_file(built["debug"], reason="the distro's debug package")
        assert r.exact and r.cached and r.build_id == built["build_id"] and r.functions >= 2
        assert symbol(prog, "sum_points") != 0
        prog.retract(*r.assertion_seqs)
        assert symbol(prog, "sum_points") == 0


def test_debuginfod_only_when_on(daemon, built, fake_server):
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        prog = rk.program(rk.import_program("default", path=str(built["prog"]), name="fetched").program.program_id)
        # DEBUGINFOD_URLS is a suggestion: nothing is set or asked.
        assert rk.debuginfod_suggestions() == [fake_server["url"]]
        s = rk.symbol_settings()
        assert not s.debuginfod and list(s.debuginfod_urls) == [] and s.debug_cache_dir.endswith("debuginfod")
        # (The cache may hold the file test_by_path kept: clear it for this test.)
        shutil.rmtree(s.debug_cache_dir, ignore_errors=True)
        with pytest.raises(NotFound):
            prog.load_debug_file(search=True)
        assert fake_server["asked"] == []
        # http needs allow_http; then on, it is fetched and kept.
        with pytest.raises(Exception, match="http"):
            rk.set_debug_file_settings(debuginfod=True, urls=[fake_server["url"]])
        s = rk.set_debug_file_settings(debuginfod=True, urls=[fake_server["url"]], allow_http=True)
        assert s.debuginfod and list(s.debuginfod_urls) == [fake_server["url"]]
        rk.set_symbol_settings("")  # the symbol path; the debug file settings stay
        assert rk.symbol_settings().debuginfod
        r = prog.load_debug_file(search=True)
        assert r.exact and r.source == f"debuginfod {fake_server['url']}", r
        assert fake_server["asked"] == [f"/buildid/{built['build_id']}/debuginfo"]
        assert any("not in /usr/lib/debug" in line for line in r.search_log)
        assert symbol(prog, "sum_points") != 0

        # MCP: from the cache now, without asking.
        mcp_client = pytest.importorskip("mcp.client.client")
        anyio = pytest.importorskip("anyio")
        from revkit.mcp_server import create_server
        server = create_server(daemon.grpc_target, agent="claude", agent_version="test", session="mcp-debug")

        async def run():
            async with mcp_client.Client(server) as mcp:
                res = await mcp.call_tool("load_debug_file", {"program_id": prog.id, "search": True})
                out = json.loads(res.content[0].text)
                assert "error" not in out and out["source"] == "cache" and out["exact"], out

        anyio.run(run)
        assert len(fake_server["asked"]) == 1
        rk.set_debug_file_settings(debuginfod=False, urls=[])
