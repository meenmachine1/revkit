import pytest

from revkit import Daemon


@pytest.fixture(scope="module")
def daemon():
    """A fresh rk-daemon on the fake backend (the synthetic demo program) per
    test module; set RK_DAEMON to pick the binary."""
    with Daemon(None, "--backend", "fake") as d:
        yield d


@pytest.fixture(scope="session")
def script_target(tmp_path_factory):
    """tests/fixtures/script_target.c compiled here: {"plain": path, "stripped": path}."""
    import shutil
    import subprocess
    from pathlib import Path

    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no C compiler")
    src = Path(__file__).parent / "fixtures" / "script_target.c"
    d = tmp_path_factory.mktemp("script-target")
    out = {"plain": d / "script_target", "stripped": d / "script_target_stripped"}
    subprocess.run([cc, "-O1", "-w", "-o", str(out["plain"]), str(src)], check=True)
    subprocess.run([cc, "-O1", "-w", "-s", "-o", str(out["stripped"]), str(src)], check=True)
    return out
