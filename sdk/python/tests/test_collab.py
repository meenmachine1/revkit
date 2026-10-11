"""rk-daemon --peer end to end (docs/collab.md): three daemon processes in a
chain (c -> b -> a). Only a opens the binary; b and c receive its record and
file over the sync service. Edits on any daemon reach every other one, and
all three serve the same blame, presence and decompiled C."""

import shutil
import subprocess
import time

import pytest

from revkit import Client, Daemon
from revkit.v1 import presence_pb2, sync_pb2

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


def state(rk):
    return rk.stubs.sync.GetSyncState(sync_pb2.GetSyncStateRequest(project_id="default"), timeout=10).projects[0]


def wait_converged(clients, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        states = [state(rk) for rk in clients]
        vectors = [{e.replica: e.counter for e in s.version_vector.entries} for s in states]
        if all(v == vectors[0] for v in vectors) and not any(s.waiting or s.missing_programs for s in states):
            if all(len(rk.programs("default")) == 1 for rk in clients):
                return
        time.sleep(0.05)
    raise AssertionError("daemons did not converge")


def test_three_daemons_replicate(binary):
    with Daemon(None, "--open", str(binary), startup_timeout=60) as a:
        with Daemon(None, "--peer", a.grpc_target, startup_timeout=60) as b:
            with Daemon(None, "--peer", b.grpc_target, startup_timeout=60) as c:
                with Client(a.grpc_target, actor="user:alice") as ra, Client(
                    b.grpc_target, actor="user:bob"
                ) as rb, Client(c.grpc_target, actor="user:carol") as rc:
                    info = rc.server_info()
                    assert {"sync", "presence", "op-ids"} <= set(info.features)
                    wait_converged([ra, rb, rc])
                    pa, pc = ra.program("default/prog"), rc.program("default/prog")
                    checksum = {f.name: f.entry.offset for f in pa.functions()}["checksum"]

                    pc.rename(checksum, "fnv1a", reason="FNV-1a")
                    wait_converged([ra, rb, rc])
                    blames = [rk.program("default/prog").blame(pa.key("name", checksum)) for rk in (ra, rb, rc)]
                    assert {b.value_text for b in blames} == {"fnv1a"}
                    ids = {(b.origin.asserted.id.replica, b.origin.asserted.id.counter) for b in blames}
                    assert len(ids) == 1  # the same op everywhere, whatever its local seq
                    # A project-level setting (docs/types.md#project-types): a library
                    # archive switched off on c is off on a.
                    pc.set_type_archive_enabled("ghidra", False, reason="revkit's archives only")
                    wait_converged([ra, rb, rc])
                    assert not {x.name: x for x in pa.type_archives()}["ghidra"].enabled
                    # Each daemon infers prototypes in the background (not
                    # replicated: derived): the same C once all three are done.
                    deadline = time.monotonic() + 120
                    while time.monotonic() < deadline and not all(
                        rk.program("default/prog").analysis_status().idle for rk in (ra, rb, rc)
                    ):
                        time.sleep(0.1)
                    texts = {rk.program("default/prog").decompile(checksum).text for rk in (ra, rb, rc)}
                    assert len(texts) == 1 and "fnv1a" in texts.pop()

                    rc.stubs.presence.UpdatePresence(
                        presence_pb2.UpdatePresenceRequest(
                            project_id="default",
                            presence=presence_pb2.Presence(
                                client_id="tab", program_id="default/prog", view="listing"
                            ),
                        ),
                        timeout=10,
                    )
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        listed = ra.stubs.presence.ListPresence(
                            presence_pb2.ListPresenceRequest(project_id="default"), timeout=10
                        ).presence
                        if listed:
                            break
                        time.sleep(0.05)
                    assert [p.client_id for p in listed] == ["tab"]
