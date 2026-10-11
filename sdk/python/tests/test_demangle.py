"""Demangled names through the SDK, revkit.script and MCP (api_minor 40,
feature "demangle"; docs/demangle.md): a stripped C++ library's exports by
their demangled names, a search by either spelling, the mangled
signature's prototype, and the mangled spelling back."""

import json
import shutil
import subprocess

import pytest

from revkit import Client, Daemon

LIBRARY = r"""
namespace geo {
class Shape {
 public:
  explicit Shape(int id);
  virtual ~Shape();
  virtual double area() const;
  void scale(double factor);
  int id_;
  double size_;
};
Shape::Shape(int id) : id_(id), size_(1) {}
Shape::~Shape() {}
double Shape::area() const { return size_ * size_; }
__attribute__((noinline)) void Shape::scale(double factor) { size_ *= factor; }
__attribute__((noinline)) double distance(const Shape &a, const Shape &b) { return a.size_ - b.size_; }
}  // namespace geo
"""


@pytest.fixture(scope="module")
def library(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("demangle")
    src, out = d / "libgeo.cc", d / "libgeo.so"
    src.write_text(LIBRARY)
    subprocess.run([cc, "-x", "c++", "-O1", "-fPIC", "-shared", "-fno-exceptions", "-fno-rtti", "-s", "-o", str(out), str(src)],
                   check=True)
    return out


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


@pytest.fixture()
def rk(image_daemon):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as c:
        yield c


@pytest.fixture()
def prog(rk, library):
    resp = rk.import_program("default", path=str(library), name="libgeo.so")
    return rk.program(resp.program.program_id)


def scale_of(prog):
    return next(f for f in prog.functions() if f.name == "geo::Shape::scale" and not f.thunk)


def test_feature(image_daemon):
    with Client(image_daemon.grpc_target) as rk:
        info = rk.server_info()
        assert "demangle" in info.features and info.api_minor >= 40


def test_names_search_and_prototype(prog):
    names = {f.name for f in prog.functions()}
    assert {"geo::Shape::scale", "geo::Shape::area", "geo::Shape::Shape", "geo::distance"} <= names
    assert not any(n.startswith("_Z") for n in names)
    f = scale_of(prog)
    assert f.demangled.mangled == "_ZN3geo5Shape5scaleEd"
    assert f.demangled.full == "geo::Shape::scale(double)"
    assert f.prototype == "undefined geo::Shape::scale(geo::Shape *this, double param_2)"
    assert f.prototype_origin.derived.rule == "analysis.demangler"
    # Either spelling finds it.
    assert {x.name for x in prog.functions("_ZN3geo5Shape5scale")} == {"geo::Shape::scale"}
    assert [s.name for s in prog.symbols(name_equals="_ZN3geo8distanceERKNS_5ShapeES2_")] == ["geo::distance"]
    # The mangled spelling back.
    assert prog.mangled_name(f.entry.offset) == "_ZN3geo5Shape5scaleEd"
    assert prog.demangled(f.entry.offset).full == "geo::Shape::scale(double)"
    # The decompiler prints it in its namespaces, with `this`.
    assert "geo::Shape::scale(Shape *this,double param_2)" in prog.decompile(f.entry.offset).text
    # A rename replaces the demangled name: no other spellings then.
    prog.rename(f.entry.offset, "resize")
    assert prog.mangled_name(f.entry.offset) == ""


SCRIPT = """\
from revkit.script import *
f = next(x for x in functions("geo::Shape::scale") if not x.thunk)
print(symbol_at(f.entry.offset), mangled_name(f.entry.offset), demangled_signature(f.entry.offset))
"""


def test_script_names(rk, prog, tmp_path):
    import io

    from revkit.script import HeadlessHost, run_script

    s = tmp_path / "names.py"
    s.write_text(SCRIPT)
    host = HeadlessHost(None, out=io.StringIO(), err=io.StringIO(), interactive=False)
    r = run_script(s, client=rk, program_id=prog.id, host=host)
    assert r.ok, r.traceback
    assert host.out.getvalue().split() == ["geo::Shape::scale", "_ZN3geo5Shape5scaleEd", "geo::Shape::scale(double)"]


mcp_client = pytest.importorskip("mcp.client.client")
anyio = pytest.importorskip("anyio")


def test_mcp_names(image_daemon, prog):
    from revkit.mcp_server import create_server

    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-demangle")
    entry = hex(scale_of(prog).entry.offset)

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                r = await mcp.call_tool(tool, args)
                assert not r.is_error, r
                out = json.loads(r.content[0].text)
                assert "error" not in out, (tool, out)
                return out

            fns = await call("list_functions", program_id=prog.id, name_contains="_ZN3geo5Shape5scale")
            assert {f["name"] for f in fns["functions"]} == {"geo::Shape::scale"}
            assert all(f["mangled"] == "_ZN3geo5Shape5scaleEd" for f in fns["functions"])
            syms = await call("search_symbols", program_id=prog.id, name_equals="_ZN3geo5Shape5scaleEd")
            assert syms["symbols"] and syms["symbols"][0]["name"] == "geo::Shape::scale"
            d = await call("decompile", program_id=prog.id, function_address=entry)
            assert "geo::Shape::scale(Shape *this,double param_2)" in d["c"]

    anyio.run(run)
