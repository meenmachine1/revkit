"""The committed stubs must match what generate.sh produces from proto/."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]


def test_stubs_are_current():
    pytest.importorskip("grpc_tools")
    with tempfile.TemporaryDirectory() as out:
        subprocess.run(
            ["sh", str(HERE / "generate.sh"), sys.executable], check=True, env={**os.environ, "OUT": out}
        )
        fresh = {p.name: p.read_bytes() for p in (Path(out) / "revkit" / "v1").glob("*_pb2*")}
        committed = {p.name: p.read_bytes() for p in (HERE / "revkit" / "v1").glob("*_pb2*")}
        assert fresh.keys() == committed.keys()
        stale = sorted(name for name in fresh if fresh[name] != committed[name])
        assert not stale, f"stale stubs (run sdk/python/generate.sh): {stale}"
