"""Apple applications through the Python SDK and MCP (api_minor 100, feature
"apple-bundles"; docs/apple-apps.md), on tests/data/apple's fixtures built
with clang and ld64.lld (skipped without them): an .ipa's bundle, a property
list, the main executable imported with its framework, and its code
signature in the program's summary."""

import datetime
import json
import pathlib
import shutil
import subprocess

import pytest

from revkit import Client, Daemon, plist_value

FIXTURE = pathlib.Path(__file__).resolve().parents[3] / "tests" / "data" / "apple"


def _tool(*names):
    for n in names:
        if shutil.which(n):
            return shutil.which(n)
    return None


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    tools = [_tool("clang"), _tool("ld64.lld", "ld64.lld-18")]
    if not all(tools):
        pytest.skip("no clang or ld64.lld")
    d = tmp_path_factory.mktemp("apple")
    subprocess.run(["sh", str(FIXTURE / "build.sh"), *tools, str(d)], check=True, capture_output=True)
    return d


@pytest.fixture(scope="module")
def image_daemon():
    with Daemon(None, "--backend", "image", startup_timeout=60) as d:
        yield d


def test_feature(image_daemon):
    with Client(image_daemon.grpc_target) as rk:
        info = rk.server_info()
        assert "apple-bundles" in info.features and info.api_minor >= 100


def test_bundle_plist_and_signature(image_daemon, fixtures):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as rk:
        with rk.open_filesystem("default", file=str(fixtures / "Demo.ipa")) as fs:
            entries = {e.name: e for e in fs.list("/Payload").entries}
            assert entries["Demo.app"].bundle_kind == "app"
            r = fs.apple_bundle("/")
            b = r.bundle
            assert b.path == "/Payload/Demo.app" and b.layout == "shallow" and b.platform == "ios"
            assert b.info.identifier == "com.example.demo" and list(b.info.url_schemes) == ["demo", "demo-auth"]
            assert [u.key for u in b.info.usage_descriptions] == ["NSCameraUsageDescription",
                                                                  "NSLocationWhenInUseUsageDescription"]
            info = plist_value(b.info_plist)
            assert info["UIDeviceFamily"] == [1, 2] and info["LSRequiresIPhoneOS"] is True
            assert b.executable_path == "/Payload/Demo.app/Demo"
            assert b.code_signature.code_directories[0].team_id == "ABCDE12345"
            assert plist_value(b.code_signature.entitlements)["get-task-allow"] is True
            assert {n.role for n in b.nested} == {"framework", "app-extension"}
            assert b.provisioning_profile.kind == "development"

            p = fs.property_list("/Payload/Demo.app/embedded.mobileprovision")
            assert p.format == "mobileprovision"
            profile = plist_value(p.root)
            assert profile["Name"] == "Demo Development"
            assert profile["ExpirationDate"] == datetime.datetime(2027, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
            assert isinstance(profile["DeveloperCertificates"][0], bytes)

            imported = fs.import_([b.executable_path], import_libraries=True)
            names = [i.program.name for i in imported.items if i.action == "imported"]
            assert names == ["Demo", "Greeter"], imported
        prog = rk.program(imported.items[0].program.program_id)
        sig = prog.code_signature()
        assert sig is not None and not sig.adhoc
        assert sig.code_directories[0].identifier == "com.example.demo"
        assert "runtime" in sig.code_directories[0].flag_names
        assert sig.requirements[0].text.startswith('identifier "com.example.demo" and anchor apple generic')
        assert prog.entitlements()["aps-environment"] == "development"


def test_ui_actions(image_daemon, fixtures):
    with Client(image_daemon.grpc_target, actor="user:alice", timeout=300) as rk:
        with rk.open_filesystem("default", file=str(fixtures / "Demo.ipa")) as fs:
            # A nib by itself names no program.
            before = {a.selector: a for a in fs.ui_actions("/Payload/Demo.app/SettingsController.nib").actions}
            assert before["save:"].resolution == "no-program"
            imported = fs.import_(["/Payload/Demo.app/Demo"])
            pid = imported.items[0].program.program_id
            r = fs.ui_actions("/", program_id=pid, include_documents=True)
            assert r.program_id == pid
            actions = {a.selector: a for a in r.actions}
            tap = actions["buttonTapped:"]
            assert tap.resolution == "resolved" and tap.method == "-[ViewController buttonTapped:]"
            assert list(tap.events) == ["touchUpInside"] and tap.target == "files-owner"
            assert actions["copyAll:"].resolution == "resolved-by-selector"
            assert {d.format for d in r.documents} == {"nib:archive"} and r.documents[0].objects
            fn = rk.program(r.program_id).functions()
            assert any(f.entry.offset == tap.implementation.offset and f.name == tap.method for f in fn)
            keyed = fs.property_list("/Payload/Demo.app/Info.plist", resolve_keyed_archive=True)
            assert not keyed.keyed_archive


def test_mcp_bundle(image_daemon, fixtures):
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    from revkit.mcp_server import create_server

    server = create_server(image_daemon.grpc_target, agent="claude", agent_version="test", session="mcp-apple")

    async def run():
        async with mcp_client.Client(server) as mcp:
            async def call(tool, **args):
                res = await mcp.call_tool(tool, args)
                assert not res.is_error, res
                return json.loads(res.content[0].text)

            fs = await call("open_filesystem", project_id="default", file=str(fixtures / "Demo.ipa"))
            sid = fs["session_id"]
            listed = await call("list_filesystem", session_id=sid, path="/Payload")
            assert listed["entries"][0]["bundle_kind"] == "app"
            b = await call("apple_bundle", session_id=sid, path="/")
            assert b["info"]["identifier"] == "com.example.demo" and b["platform"] == "ios"
            assert b["code_signature"]["team_id"] == "ABCDE12345" and b["code_signature"]["verified"] is False
            assert b["code_signature"]["entitlements"]["application-identifier"] == "ABCDE12345.com.example.demo"
            assert b["provisioning_profile"]["kind"] == "development"
            assert {n["role"] for n in b["nested"]} == {"framework", "app-extension"}
            p = await call("read_property_list", session_id=sid, path="/Payload/Demo.app/Info.plist")
            assert p["format"] == "binary" and p["root"]["CFBundleExecutable"] == "Demo"
            imp = await call("import_from_filesystem", session_id=sid, paths=[b["executable_path"]],
                             reason="test", import_libraries=True)
            pid = imp["items"][0]["program_id"]
            s = await call("program_summary", program_id=pid)
            assert s["macho"]["code_signature"]["identifier"] == "com.example.demo"
            assert s["macho"]["code_signature"]["requirements"]["designated"].startswith("identifier")
            ui = await call("list_ui_actions", session_id=sid, path="/")
            acts = {a["selector"]: a for a in ui["actions"]}
            assert acts["buttonTapped:"]["method"] == "-[ViewController buttonTapped:]"
            assert acts["buttonTapped:"]["address"].startswith("0x") and acts["save:"]["target_class"] == "SettingsController"

    anyio.run(run)
