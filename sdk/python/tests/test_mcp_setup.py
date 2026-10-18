"""revkit-mcp setup (docs/getting-started.md "MCP for AI agents"): each
agent's config written as its docs describe, shown first, asked, backed
up, idempotent, and nothing written by --dry-run; other servers and
settings in the files kept. Runs against a scratch home directory; the
claude command is a stub that records how it was called."""

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from revkit import mcp_setup


def run(tmp_path, *args, answers=(), env_extra=None, capsys=None):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    cwd = tmp_path / "proj"
    cwd.mkdir(exist_ok=True)
    env = {"HOME": str(home), "PATH": str(tmp_path / "bin")}
    env.update(env_extra or {})
    replies = list(answers)
    asked = []

    def ask(prompt):
        asked.append(prompt)
        return replies.pop(0) if replies else "n"

    code = mcp_setup.main(["--command", "/opt/revkit/bin/revkit-mcp", *args], input_fn=ask, env=env, home=home, cwd=cwd)
    return code, home, cwd, asked


def backups(path: Path):
    return sorted(path.parent.glob(path.name + ".revkit-backup-*"))


def test_every_client_written_once(tmp_path, capsys):
    code, home, cwd, asked = run(tmp_path, "--client", "all", "--daemon", "10.0.0.5:50051", answers=["y"] * 4)
    assert code == 0 and len(asked) == 4
    out = capsys.readouterr().out
    assert "+++ " in out and "Restart the agent" in out

    claude = json.loads((home / ".claude.json").read_text())["mcpServers"]["revkit"]
    assert claude == {"type": "stdio", "command": "/opt/revkit/bin/revkit-mcp",
                      "args": ["--daemon", "10.0.0.5:50051", "--agent", "claude"]}
    cursor = json.loads((home / ".cursor/mcp.json").read_text())["mcpServers"]["revkit"]
    assert cursor["type"] == "stdio" and cursor["args"][-1] == "cursor"
    gemini = json.loads((home / ".gemini/settings.json").read_text())["mcpServers"]["revkit"]
    assert "type" not in gemini and gemini["args"][-1] == "gemini"
    toml = (home / ".codex/config.toml").read_text()
    assert toml.startswith("[mcp_servers.revkit]\ncommand = \"/opt/revkit/bin/revkit-mcp\"\n")
    assert 'args = ["--daemon", "10.0.0.5:50051", "--agent", "codex"]' in toml

    # Again: nothing to change, nothing asked, no backups.
    code, home, cwd, asked = run(tmp_path, "--client", "all", "--daemon", "10.0.0.5:50051")
    assert code == 0 and asked == []
    assert capsys.readouterr().out.count("already set up") == 4
    for p in (home / ".claude.json", home / ".cursor/mcp.json", home / ".gemini/settings.json", home / ".codex/config.toml"):
        assert backups(p) == [], p


def test_dry_run_and_no_writes_the_answer_no(tmp_path, capsys):
    code, home, _, asked = run(tmp_path, "--client", "cursor", "--dry-run")
    assert code == 0 and asked == [] and not (home / ".cursor/mcp.json").exists()
    assert "dry run" in capsys.readouterr().out
    code, home, _, asked = run(tmp_path, "--client", "cursor", answers=["n"])
    assert code == 0 and len(asked) == 1 and not (home / ".cursor/mcp.json").exists()


def test_existing_files_kept_and_backed_up(tmp_path):
    home = tmp_path / "home"
    (home / ".gemini").mkdir(parents=True)
    settings = home / ".gemini/settings.json"
    settings.write_text(json.dumps({"theme": "dark", "mcpServers": {"other": {"command": "x"},
                                                                    "revkit": {"command": "old"}}}))
    settings.chmod(0o600)
    codex = home / ".codex/config.toml"
    codex.parent.mkdir()
    codex.write_text('model = "o4"\n\n[mcp_servers.revkit]\ncommand = "old"\nargs = []\n\n[mcp_servers.revkit.env]\n'
                     'X = "1"\n\n[mcp_servers.other]\ncommand = "y"\n\n[profiles.fast]\nmodel = "mini"\n')
    token = tmp_path / "token"
    token.write_text("rkt_secret\n")
    code, home, _, _ = run(tmp_path, "--client", "gemini", "--client", "codex", "--token-file", str(token), "--yes")
    assert code == 0
    g = json.loads(settings.read_text())
    assert g["theme"] == "dark" and g["mcpServers"]["other"] == {"command": "x"}
    assert g["mcpServers"]["revkit"]["env"] == {"RK_TOKEN_FILE": str(token.resolve())}
    assert "rkt_secret" not in settings.read_text()
    assert stat.S_IMODE(settings.stat().st_mode) == 0o600
    (saved,) = backups(settings)
    assert json.loads(saved.read_text())["mcpServers"]["revkit"] == {"command": "old"}
    text = codex.read_text()
    assert text.startswith('model = "o4"\n\n[mcp_servers.revkit]\n')
    assert 'command = "old"' not in text and 'X = "1"' not in text
    assert f'RK_TOKEN_FILE = "{token.resolve()}"' in text
    assert '[mcp_servers.other]\ncommand = "y"' in text and '[profiles.fast]\nmodel = "mini"' in text
    if sys.version_info >= (3, 11):
        import tomllib
        t = tomllib.loads(text)
        assert t["profiles"]["fast"]["model"] == "mini" and t["mcp_servers"]["other"]["command"] == "y"
    assert len(backups(codex)) == 1
    # Idempotent with the token file too.
    code, *_ = run(tmp_path, "--client", "gemini", "--client", "codex", "--token-file", str(token), "--yes")
    assert code == 0 and len(backups(settings)) == 1 and len(backups(codex)) == 1


def test_claude_code_through_its_command(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "claude.log"
    stub = bin_dir / "claude"
    stub.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\n")
    stub.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    (home / ".claude.json").write_text(json.dumps({"numStartups": 3, "mcpServers": {"revkit": {"command": "old"}}}))
    code, *_ = run(tmp_path, "--client", "claude", "--yes")
    assert code == 0
    calls = log.read_text().splitlines()
    assert calls[0] == "mcp remove --scope user revkit"
    assert calls[1].startswith("mcp add-json --scope user revkit {")
    entry = json.loads(calls[1].split("revkit ", 1)[1])
    assert entry == {"type": "stdio", "command": "/opt/revkit/bin/revkit-mcp", "args": ["--daemon", "127.0.0.1:50051", "--agent", "claude"]}
    assert len(backups(home / ".claude.json")) == 1
    # The file itself is left to claude (the stub didn't change it).
    assert json.loads((home / ".claude.json").read_text())["numStartups"] == 3


def test_project_scope_and_refusals(tmp_path, capsys):
    code, home, cwd, _ = run(tmp_path, "--client", "claude", "--client", "cursor", "--scope", "project", "--yes")
    assert code == 0
    assert json.loads((cwd / ".mcp.json").read_text())["mcpServers"]["revkit"]["type"] == "stdio"
    assert (cwd / ".cursor/mcp.json").exists() and not (home / ".cursor").exists()
    # A config that isn't JSON is left alone, and said.
    bad = home / ".cursor/mcp.json"
    bad.parent.mkdir(parents=True)
    bad.write_text("{ not json")
    code, *_ = run(tmp_path, "--client", "cursor", "--yes")
    assert code == 1 and bad.read_text() == "{ not json" and "not valid JSON" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        run(tmp_path, "--client", "cursor", "--name", "bad name")
    # Nothing found and nothing named.
    empty = tmp_path / "empty"
    empty.mkdir()
    code, *_ = run(empty)
    assert code == 1 and "No coding agent found" in capsys.readouterr().err


def test_found_by_config_directory(tmp_path, capsys):
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    code, home, *_ = run(tmp_path, "--dry-run")
    assert code == 0 and "Found: Codex" in capsys.readouterr().out


def test_the_commands(tmp_path):
    """revkit-mcp setup (revkit.mcp_cli), and the revkit launcher's `revkit mcp setup`."""
    import subprocess

    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "PATH": "/usr/bin:/bin"}
    r = subprocess.run([sys.executable, "-m", "revkit.mcp_cli", "setup", "--client", "cursor", "--dry-run"],
                       env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "Cursor: " in r.stdout and '"--agent",' in r.stdout and "dry run" in r.stdout
    assert not (home / ".cursor").exists()
    launcher = Path(__file__).resolve().parents[3] / "packaging" / "revkit"
    fake = tmp_path / "revkit-mcp"
    fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    fake.chmod(0o755)
    r = subprocess.run(["sh", str(launcher), "mcp", "setup", "--dry-run"], capture_output=True, text=True,
                       env={**env, "REVKIT_MCP": str(fake), "REVKIT_PORT": "6000"})
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["setup", "--daemon", "127.0.0.1:5999", "--dry-run"]
    r = subprocess.run(["sh", str(launcher), "mcp", "bogus"], capture_output=True, text=True,
                       env={**env, "REVKIT_MCP": str(fake)})
    assert r.returncode != 0 and "usage: revkit mcp setup" in r.stderr
