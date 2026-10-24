"""Android packages (api_minor 98, feature "android"; docs/android.md)
through the SDK and MCP: an APK written by tests/data/android/make_apk.py
(binary XML, resources.arsc, a DEX, JNI libraries compiled here, Flutter's
libraries) opened as a file system; the manifest's fields and XML, the
strings table, a compiled layout, native methods linked to their exports,
the Flutter snapshot hash, and a native library imported with the library
beside it linked and its JNI exports in the symbols."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from revkit import Client, Daemon, InvalidArgument

GEN = Path(__file__).resolve().parents[3] / "tests" / "data" / "android" / "make_apk.py"


@pytest.fixture(scope="module")
def apks(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("android")
    out = {}
    for name, flags in (("app", []), ("flutter", ["--flutter"])):
        p = d / f"{name}.apk"
        subprocess.run([sys.executable, "-I", str(GEN), str(p), "--cc", f"{cc}:x86_64", *flags], check=True)
        out[name] = p
    # An APK inside another container: found by its path there.
    import zipfile
    with zipfile.ZipFile(d / "bundle.zip", "w") as z:
        z.write(out["app"], "release/app.apk")
    out["bundle"] = d / "bundle.zip"
    out["dir"] = d
    return out


@pytest.fixture(scope="module")
def daemon(apks):
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_package(daemon, apks):
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        info = rk.server_info()
        assert "android" in info.features and info.api_minor >= 98
        with rk.open_filesystem("default", host_path=str(apks["app"])) as fs:
            pkg = fs.android_package()
            m = pkg.manifest
            assert pkg.manifest_present and pkg.path == ""
            assert m.package == "com.example.droid" and m.version_code == 7 and m.version_name == "1.2.3"
            assert (m.min_sdk, m.target_sdk, m.compile_sdk) == (24, 34, 34)
            assert [p.name for p in m.uses_permissions] == ["android.permission.INTERNET",
                                                             "android.permission.READ_EXTERNAL_STORAGE"]
            assert m.permissions[0].protection_level == "signature"
            assert m.application_class == "com.example.droid.DroidApp" and m.label == "Droid Test"
            assert m.debuggable and m.HasField("allow_backup") and not m.allow_backup and m.uses_cleartext_traffic
            assert m.network_security_config == "@xml/network_security_config"
            assert m.network_security_config_file == "res/xml/network_security_config.xml"
            comps = {c.name: c for c in m.components}
            assert comps["com.example.droid.MainActivity"].launcher
            deep = comps["com.example.droid.DeepLinkActivity"]
            assert deep.exported and not deep.exported_explicit
            assert deep.intent_filters[0].data[0].host == "example.com"
            assert not comps["com.example.droid.DataProvider"].exported
            assert comps["com.example.droid.SyncService"].permission == "com.example.droid.permission.SYNC"
            assert dict(m.meta_data) == {"io.example.API_KEY": "k-123"}
            assert 'android:label="@string/app_name"' in pkg.manifest_xml
            assert 'android:label="Droid Test"' in pkg.manifest_xml_resolved
            # Resources.
            assert pkg.resources.present and pkg.resources.packages[0].name == "com.example.droid"
            types = {t.name: t for t in pkg.resources.packages[0].types}
            assert types["string"].entries == 4 and sorted(types["string"].configs) == ["", "en-rGB", "fr"]
            # Native libraries and methods.
            assert list(pkg.abis) == ["x86_64"]
            libs = {l.name: l for l in pkg.native_libraries}
            native = libs["libnative.so"]
            assert native.path == "/lib/x86_64/libnative.so" and native.machine == "x86-64"
            assert native.jni_onload and "Java_com_example_droid_NativeLib_add__II" in native.jni_exports
            assert list(native.needed) == ["libhelper.so"]
            methods = {f"{n.class_name}.{n.method}{n.signature}": n for n in pkg.native_methods}
            assert list(methods["com.example.droid.NativeLib.add(JJ)J"].libraries) == ["/lib/x86_64/libnative.so"]
            assert methods["com.example.droid.NativeLib.add(JJ)J"].jni_long_name == "Java_com_example_droid_NativeLib_add__JJ"
            assert not methods["com.example.droid.NativeLib.registered()V"].libraries
            assert pkg.dex_files[0].path == "/classes.dex" and pkg.dex_files[0].native_methods == 6
            assert not pkg.flutter.detected
            assert not pkg.warnings, pkg.warnings
            # Skipping the libraries and the DEX.
            light = fs.android_package(native=False, dex=False)
            assert not light.native_methods and not light.native_libraries[0].jni_exports
            # The strings table, configurations, a query, every type.
            assert fs.android_strings() == {"app_name": "Droid Test", "hello": "Hello, world!",
                                            "net_host": "api.example.com", "unused_label": "日本語 \U0001F600"}
            assert fs.android_strings(config="fr")["app_name"] == "Droïde d'essai"
            r = fs.android_resources(type="", config="*", query="example")
            assert {e.name for e in r.entries} == {"@string/net_host"} and r.total == 1
            assert "string" in r.types and "night" in fs.android_resources(type="color").configs
            styles = fs.android_resources(type="style")
            assert styles.entries[0].value_type == "bag" and styles.entries[0].items[0].endswith("= @color/primary")
            colors = {e.config: e.value for e in fs.android_resources(type="color", config="*").entries}
            assert colors == {"": "#ff336699", "night": "#ff112233"}
            page = fs.android_resources(type="string", config="*", limit=2)
            assert len(page.entries) == 2 and page.total == 7
            # A compiled layout.
            xml = fs.android_xml("/res/layout/main.xml")
            assert 'android:text="@string/hello"' in xml and "<LinearLayout" in xml
            assert 'android:text="Hello, world!"' in fs.android_xml("/res/layout/main.xml", resolve=True)
            with pytest.raises(InvalidArgument):
                fs.android_xml("/classes.dex")


def test_nested_and_not_an_apk(daemon, apks):
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        with rk.open_filesystem("default", host_path=str(apks["bundle"])) as fs:
            pkg = fs.android_package("/release/app.apk")
            assert pkg.path == "/release/app.apk!" and pkg.manifest.package == "com.example.droid"
            assert pkg.container_path == "zip://bundle.zip!/release/app.apk!"
            assert pkg.native_libraries[0].path.startswith("/release/app.apk!/lib/x86_64/")
            assert fs.android_strings("/release/app.apk!/res")["hello"] == "Hello, world!"
            with pytest.raises(InvalidArgument):
                fs.android_package("/")


def test_flutter(daemon, apks):
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        with rk.open_filesystem("default", host_path=str(apks["flutter"])) as fs:
            f = fs.android_package().flutter
            assert f.detected and f.snapshot_hash == "90b56a561f70cd55e972cb49b79b3d8b"
            abi = f.abis[0]
            assert abi.abi == "x86_64" and abi.libapp == "/lib/x86_64/libapp.so"
            assert len(abi.engine_build_id) == 40 and abi.dart_version.startswith("3.4.0 (stable)")
            data = [s for s in abi.snapshots if s.symbol.endswith("Data")]
            assert len(data) == 2 and all(s.header and s.kind_name == "full-aot" for s in data)
            assert "compressed-pointers" in abi.features


def test_import_native_library(daemon, apks):
    """A JNI library imported from the APK, its DT_NEEDED neighbour imported
    and linked from the same lib/<abi>/ directory, its JNI exports named."""
    with Client(daemon.grpc_target, actor="user:alice") as rk:
        rk.open_project(path=str(apks["dir"] / "proj"), create=True, name="droid")
        with rk.open_filesystem("droid", host_path=str(apks["app"])) as fs:
            lib = next(l for l in fs.android_package().native_libraries if l.name == "libnative.so")
            r = fs.import_(lib.path, import_libraries=True, analyze=False)
            assert r.imported == 2, r
            items = {i.path: i for i in r.items}
            assert items["/lib/x86_64/libhelper.so"].library_of == "libnative.so"
            prog = items[lib.path].program
            assert prog.container_path == "zip://app.apk!/lib/x86_64/libnative.so"
            libs = {l.name: l for l in rk.libraries(prog.program_id).libraries}
            assert libs["libhelper.so"].program_id == items["/lib/x86_64/libhelper.so"].program.program_id
            names = {s.name for s in rk.program(prog.program_id).symbols("Java_")}
            assert "Java_com_example_droid_NativeLib_do_1it" in names and "Java_com_example_droid_NativeLib_hello" in names


def test_mcp(daemon, apks):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    def _json(result):
        assert not result.is_error, result
        return json.loads(result.content[0].text)

    async def run():
        server = create_server(daemon.grpc_target, agent="claude", agent_version="test", session="mcp-android")
        if True:
            async with mcp_client.Client(server) as c:
                async def call(name, **args):
                    return _json(await c.call_tool(name, args))
                opened = await call("open_filesystem", project_id="default", host_path=str(apks["app"]))
                sid = opened["session_id"]
                pkg = await call("android_package", session_id=sid)
                assert pkg["manifest"]["package"] == "com.example.droid"
                assert pkg["manifest"]["debuggable"] is True
                assert any(m["jni_name"] == "Java_com_example_droid_NativeLib_do_1it" for m in pkg["native_methods"])
                reg = next(m for m in pkg["native_methods"] if m["method"].endswith("registered()V"))
                assert reg["libraries"].startswith("none")
                res = await call("android_resources", session_id=sid, config="fr")
                assert {e["name"]: e["value"] for e in res["entries"]}["@string/hello"] == "Bonjour, le monde !"
                xml = await call("android_xml", session_id=sid, path="/AndroidManifest.xml")
                assert "<manifest" in xml["xml"]
                await call("close_filesystem", session_id=sid)
    anyio.run(run)
