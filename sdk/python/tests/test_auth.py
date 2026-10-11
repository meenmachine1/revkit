"""Authentication, authorization and TLS against real rk-daemon processes
(docs/security.md): API tokens and logins over TLS with the self-signed
certificate pinned, server-stamped provenance, roles, and replication
between authenticated daemons."""

import shutil
import ssl
import subprocess
import time

import pytest

from revkit import (
    Client,
    Daemon,
    PermissionDenied,
    RevkitError,
    Unauthenticated,
    certificate_fingerprint,
    fetch_certificate,
    format_provenance,
)
from revkit.v1 import auth_pb2

PROGRAM = "demo/hello"
FN = 0x401040


@pytest.fixture(scope="module")
def secure():
    """A fake-backend daemon with accounts and a self-signed certificate."""
    with Daemon(None, "--backend", "fake", auth=True) as d:
        d.add_user("alice", "editor", "alice-password")
        d.add_user("vic", "viewer", "vic-password")
        yield d


def test_token_over_pinned_tls_and_stamped_provenance(secure):
    token = secure.create_token("pybot", "editor")
    assert token.startswith("rkt_")
    assert certificate_fingerprint(fetch_certificate(secure.grpc_target)) == secure.fingerprint
    with secure.client(token=token) as rk:
        info = rk.server_info()
        assert {"auth", "auth-required", "provenance-stamping"} <= set(info.features)
        who = rk.whoami()
        assert who.auth_enabled and who.identity.name == "pybot"
        assert who.identity.kind == auth_pb2.PRINCIPAL_KIND_AGENT
        prog = rk.program(PROGRAM)
        assert any(f.name == "main" for f in prog.functions())
        r = prog.rename(FN, "py_checksum", reason="test")
        assert format_provenance(r.assertions[0].provenance) == "agent:pybot"
    # Only a version: the server supplies kind and id.
    with secure.client(token=token, actor="@opus-5.5") as rk:
        r = rk.program(PROGRAM).comment(FN, "hi", reason="test")
        assert format_provenance(r.assertions[0].provenance) == "agent:pybot@opus-5.5"
    # Claiming to be someone else is refused, not silently rewritten.
    with secure.client(token=token, actor="user:alice") as rk:
        with pytest.raises(PermissionDenied, match="does not match"):
            rk.program(PROGRAM).rename(FN, "evil")


def test_no_credentials_wrong_pin_or_plaintext(secure):
    with secure.client(token="") as rk:
        who = rk.whoami()
        assert who.auth_enabled and not who.HasField("identity")
        with pytest.raises(Unauthenticated):
            list(rk.program(PROGRAM).functions())
    with pytest.raises(ssl.SSLError, match="not the pinned"):
        Client(secure.grpc_target, fingerprint="00" * 32)
    with Client(secure.grpc_target, token="x", tls=False, timeout=3) as rk:
        with pytest.raises(RevkitError):
            rk.server_info()
    # The certificate as a CA file works too.
    with Client(secure.grpc_target, ca_cert=str(secure.ca_cert), server_name="localhost") as rk:
        assert rk.whoami().auth_enabled


def test_login_roles_and_logout(secure):
    rk = Client.login(secure.grpc_target, "vic", "vic-password", fingerprint=secure.fingerprint)
    try:
        who = rk.whoami().identity
        assert (who.name, who.role, who.method) == ("vic", auth_pb2.ROLE_VIEWER, auth_pb2.AUTH_METHOD_SESSION)
        assert rk.token.startswith("rks_")
        prog = rk.program(PROGRAM)
        assert prog.decompile(FN).text
        with pytest.raises(PermissionDenied, match="needs editor"):
            prog.rename(FN, "x")
        rk.logout()
        with pytest.raises(Unauthenticated):
            list(prog.functions())
    finally:
        rk.close()
    with pytest.raises(Unauthenticated):
        Client.login(secure.grpc_target, "vic", "wrong password", fingerprint=secure.fingerprint)

    alice = Client.login(secure.grpc_target, "alice", "alice-password", fingerprint=secure.fingerprint)
    with alice:
        r = alice.program(PROGRAM).rename(FN, "by_alice")
        assert format_provenance(r.assertions[0].provenance) == "user:alice"


def test_environment_configuration(secure, monkeypatch):
    token = secure.create_token("envbot", "viewer")
    monkeypatch.setenv("RK_TOKEN", token)
    monkeypatch.setenv("RK_TLS_FINGERPRINT", secure.fingerprint)
    with Client(secure.grpc_target) as rk:
        assert rk.whoami().identity.name == "envbot"


def test_tokens_are_revocable(secure):
    token = secure.create_token("shortlived", "viewer")
    with secure.client(token=token) as rk:
        assert list(rk.program(PROGRAM).functions())
        secure.admin("token", "revoke", "shortlived")
        deadline = time.monotonic() + 5  # the daemon re-reads its file within a second
        while time.monotonic() < deadline:
            try:
                list(rk.program(PROGRAM).functions())
            except Unauthenticated:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("a revoked token still works")


SOURCE = r"""
#include <stdio.h>
__attribute__((noinline)) unsigned checksum(const unsigned char *p, int n) {
  unsigned h = 0x811c9dc5;
  for (int i = 0; i < n; i++) h = (h ^ p[i]) * 0x1000193;
  return h;
}
int main(int argc, char **argv) {
  printf("%u\n", checksum((const unsigned char *)argv[0], argc));
  return 0;
}
"""


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("prog")
    (d / "prog.c").write_text(SOURCE)
    subprocess.run([cc, "-O1", "-o", str(d / "prog"), str(d / "prog.c")], check=True)
    return d / "prog"


def wait_for(fn, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if fn():
                return
        except RevkitError:
            pass
        time.sleep(0.1)
    raise AssertionError("timed out")


def test_peers_replicate_with_tokens_over_tls(binary, tmp_path):
    """b links to a with a peer token a issued and a's certificate pinned;
    a link with a viewer's token replicates nothing."""
    with Daemon(None, "--open", str(binary), auth=True, startup_timeout=60) as a:
        a.add_user("alice", "editor", "alice-password")
        (tmp_path / "peer.token").write_text(a.create_token("daemon-b", "peer") + "\n")
        (tmp_path / "viewer.token").write_text(a.create_token("dash", "viewer") + "\n")
        time.sleep(1.2)  # a re-reads its credential file at most once a second
        link = f"{a.grpc_target},token-file={tmp_path / 'peer.token'},fingerprint={a.fingerprint}"
        bad = f"{a.grpc_target},token-file={tmp_path / 'viewer.token'},fingerprint={a.fingerprint}"
        with Daemon(None, "--peer", link, auth=True, startup_timeout=60) as b, Daemon(
            None, "--peer", bad, auth=True, startup_timeout=60
        ) as c:
            b.add_user("bob", "editor", "bob-password")
            c.add_user("carol", "viewer", "carol-password")
            ra = Client.login(a.grpc_target, "alice", "alice-password", fingerprint=a.fingerprint)
            rb = Client.login(b.grpc_target, "bob", "bob-password", fingerprint=b.fingerprint)
            rc = Client.login(c.grpc_target, "carol", "carol-password", fingerprint=c.fingerprint)
            with ra, rb, rc:
                wait_for(lambda: len(rb.programs("default")) == 1)
                pa, pb = ra.program("default/prog"), rb.program("default/prog")
                wait_for(lambda: "checksum" in {f.name for f in pb.functions()})
                checksum = {f.name: f.entry.offset for f in pa.functions()}["checksum"]
                pb.rename(checksum, "fnv1a", reason="FNV-1a")
                wait_for(lambda: pa.blame(pa.key("name", checksum)).value_text == "fnv1a")
                blame = pa.blame(pa.key("name", checksum))
                assert format_provenance(blame.origin.asserted.provenance) == "user:bob"
                pa.comment(checksum, "seen on a", reason="test")
                wait_for(lambda: any("seen on a" in r.body.comment.text for r in pb.assertions(actor="user:alice")))
                # c's link was refused all along.
                assert rc.programs("default") == [] or len(rc.programs("default")) == 0
                assert "refused" in c.log()


def test_mcp_server_with_an_agent_token(secure):
    """The MCP server takes a token and a pinned certificate; the daemon stamps
    the token's name on the agent's edits, and its revert finds them."""
    mcp_client = pytest.importorskip("mcp.client.client")
    anyio = pytest.importorskip("anyio")
    import json

    from revkit.mcp_server import create_server

    token = secure.create_token("claude-mcp", "editor")
    with pytest.raises(ValueError, match="agent:claude-mcp"):
        create_server(secure.grpc_target, agent="someone-else", token=token, fingerprint=secure.fingerprint)
    server = create_server(secure.grpc_target, agent_version="test", session="mcp-auth", token=token,
                           fingerprint=secure.fingerprint)

    def body(result):
        assert not result.is_error, result
        return json.loads(result.content[0].text)

    async def run():
        async with mcp_client.Client(server) as mcp:
            done = body(await mcp.call_tool(
                "rename", {"program_id": PROGRAM, "address": "0x401070", "new_name": "twice", "reason": "LEA x+x"}))
            assert done["provenance"] == "agent:claude-mcp@test"
            reverted = body(await mcp.call_tool("revert_my_changes", {"program_id": PROGRAM}))
            assert reverted["retracted"] == 1

    anyio.run(run)
    server.revkit_client.close()
