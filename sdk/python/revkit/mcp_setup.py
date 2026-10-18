"""Register revkit's MCP server with coding agents: ``revkit-mcp setup``.

Claude Code, Codex, Cursor and Gemini CLI each keep their MCP servers in a
config file. This command works out the entry for revkit (``revkit-mcp``
with the daemon's address and the agent's name), shows the change it would
make to each one, asks before writing, backs the file up first, and does
nothing when the entry is already there as it would write it.

    revkit-mcp setup                     # the agents found on this computer
    revkit-mcp setup --client codex --client cursor
    revkit-mcp setup --dry-run           # show, write nothing
    revkit-mcp setup --scope project     # this directory's project config

The formats, from each tool's documentation (2026-10):

- Claude Code (https://code.claude.com/docs/en/mcp): ``claude mcp add-json
  --scope user <name> '<json>'`` writes a user-scope server into
  ``~/.claude.json``; a project's servers are ``mcpServers`` in ``.mcp.json``
  at its root. A stdio entry is ``{"type": "stdio", "command", "args",
  "env"}``. With the ``claude`` command on PATH this uses it for the user
  scope (``~/.claude.json`` holds Claude Code's other state too); without
  it, it edits ``mcpServers`` in ``~/.claude.json`` itself.
- Codex (https://developers.openai.com/codex/mcp, now
  https://learn.chatgpt.com/docs/extend/mcp?surface=cli): a
  ``[mcp_servers.<name>]`` table in ``~/.codex/config.toml``, or
  ``.codex/config.toml`` in a trusted project, with ``command``, ``args`` and
  an ``[mcp_servers.<name>.env]`` table. ``$CODEX_HOME`` moves ``~/.codex``
  (Codex's configuration docs).
- Cursor (https://cursor.com/docs/context/mcp): ``mcpServers`` in
  ``~/.cursor/mcp.json``, or ``.cursor/mcp.json`` in a project; a stdio entry
  is ``{"type": "stdio", "command", "args", "env"}``.
- Gemini CLI (https://geminicli.com/docs/tools/mcp-server/): ``mcpServers``
  in ``~/.gemini/settings.json``, or ``.gemini/settings.json`` in a project;
  an entry is ``{"command", "args", "env", "cwd", "timeout", "trust"}``.

A token is never written into a config file: ``--token-file`` puts its path
in ``RK_TOKEN_FILE`` for the server to read. Python's standard library
only (no ``mcp`` needed to run it).
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

CLIENTS = ("claude", "codex", "cursor", "gemini")
LABELS = {"claude": "Claude Code", "codex": "Codex", "cursor": "Cursor", "gemini": "Gemini CLI"}
NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclass
class Server:
    """What every client runs: a command, its arguments, its environment."""

    command: str
    args: list[str]
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class Plan:
    """One client's change: the file, its text now and after, or a command to run."""

    client: str
    path: Path
    before: Optional[str]  # None: the file doesn't exist
    after: Optional[str]  # None: nothing to write (already set up, or a command instead)
    command: Optional[list[str]] = None  # run instead of writing (Claude Code's own CLI)
    note: str = ""

    @property
    def unchanged(self) -> bool:
        return self.after is None and self.command is None


def default_server(daemon: str, agent: str, token_file: Optional[str], executable: Optional[str]) -> Server:
    """revkit-mcp as this installation runs it: the script beside this Python, else on PATH, else
    ``python -m revkit.mcp_server``."""
    env = {"RK_TOKEN_FILE": str(Path(token_file).expanduser().resolve())} if token_file else {}
    args = ["--daemon", daemon, "--agent", agent]
    if executable:
        return Server(executable, args, env)
    beside = Path(sys.executable).with_name("revkit-mcp")
    found = str(beside) if beside.exists() else shutil.which("revkit-mcp")
    if found:
        return Server(str(Path(found).absolute()), args, env)
    return Server(sys.executable, ["-m", "revkit.mcp_server", *args], env)


def _json_entry(server: Server, typed: bool) -> dict:
    out: dict = {"type": "stdio"} if typed else {}
    out.update({"command": server.command, "args": list(server.args)})
    if server.env:
        out["env"] = dict(server.env)
    return out


def _load_json(path: Path, text: Optional[str]) -> dict:
    if text is None or not text.strip():
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise SetupError(f"{path} is not valid JSON ({e}); fix or move it, then run setup again") from None
    if not isinstance(data, dict):
        raise SetupError(f"{path} does not hold a JSON object")
    return data


def _json_plan(client: str, path: Path, name: str, entry: dict, key_path: tuple[str, ...] = ("mcpServers",)) -> Plan:
    before = path.read_text() if path.exists() else None
    data = _load_json(path, before)
    node = data
    for k in key_path:
        if not isinstance(node.get(k, {}), dict):
            raise SetupError(f"{path}: {'.'.join(key_path)} is not an object")
        node = node.setdefault(k, {})
    if node.get(name) == entry:
        return Plan(client, path, before, None)
    node[name] = entry
    return Plan(client, path, before, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def _toml_string(s: str) -> str:
    # A TOML basic string: JSON's escapes are TOML's (\", \\, \n, \uXXXX).
    return json.dumps(s, ensure_ascii=False)


def _toml_key(k: str) -> str:
    return k if re.fullmatch(r"[A-Za-z0-9_-]+", k) else _toml_string(k)


def _codex_block(name: str, server: Server) -> str:
    lines = [f"[mcp_servers.{_toml_key(name)}]", f"command = {_toml_string(server.command)}",
             "args = [" + ", ".join(_toml_string(a) for a in server.args) + "]"]
    if server.env:
        lines += ["", f"[mcp_servers.{_toml_key(name)}.env]"]
        lines += [f"{_toml_key(k)} = {_toml_string(v)}" for k, v in sorted(server.env.items())]
    return "\n".join(lines) + "\n"


_HEADER = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(#.*)?$")


def _toml_header_path(line: str) -> Optional[list[str]]:
    """The dotted key path of a table header line, or None."""
    m = _HEADER.match(line)
    if not m:
        return None
    parts, cur, quote = [], "", None
    for ch in m.group(1):
        if quote:
            if ch == quote:
                quote = None
            else:
                cur += ch
        elif ch in "\"'":
            quote = ch
        elif ch == ".":
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    parts.append(cur.strip())
    return parts


def _codex_plan(path: Path, name: str, server: Server) -> Plan:
    before = path.read_text() if path.exists() else None
    text = before or ""
    lines = text.splitlines(keepends=True)
    # The lines of [mcp_servers.<name>] and its sub-tables ([mcp_servers.<name>.env]).
    start = end = None
    for i, line in enumerate(lines):
        p = _toml_header_path(line)
        if p is None:
            continue
        ours = p[:2] == ["mcp_servers", name]
        if ours and start is None:
            start = i
        elif start is not None and end is None and not ours:
            end = i
    block = _codex_block(name, server)
    if start is None:
        sep = "" if not text or text.endswith("\n\n") else ("\n" if text.endswith("\n") else "\n\n")
        after = text + sep + block
    else:
        end = len(lines) if end is None else end
        current = "".join(lines[start:end])
        if current.strip() == block.strip():
            return Plan("codex", path, before, None)
        trailing = "\n" if end < len(lines) else ""
        after = "".join(lines[:start]) + block + trailing + "".join(lines[end:])
    try:
        import tomllib  # Python 3.11+: check what we'd write parses and says what we mean

        parsed = tomllib.loads(after).get("mcp_servers", {}).get(name, {})
        if parsed.get("command") != server.command or parsed.get("args") != server.args or parsed.get("env", {}) != server.env:
            raise SetupError(f"{path}: the edited file doesn't read back as the entry (left unchanged)")
    except ModuleNotFoundError:
        pass
    except ValueError as e:  # tomllib.TOMLDecodeError
        raise SetupError(f"{path} would not be valid TOML after the edit ({e}); is it valid now?") from None
    return Plan("codex", path, before, after)


def _normal(entry) -> Optional[dict]:
    """An entry as Claude Code may store it: no type is stdio, no env is an empty one."""
    if not isinstance(entry, dict):
        return None
    return {"type": "stdio", "env": {}, "args": [], **entry}


def _claude_plan(scope: str, name: str, server: Server, home: Path, cwd: Path, claude: Optional[str]) -> Plan:
    entry = _json_entry(server, typed=True)
    if scope == "project":
        return _json_plan("claude", cwd / ".mcp.json", name, entry)
    path = home / ".claude.json"
    before = path.read_text() if path.exists() else None
    current = _load_json(path, before).get("mcpServers", {})
    if isinstance(current, dict) and _normal(current.get(name)) == _normal(entry):
        return Plan("claude", path, before, None)
    if claude:
        cmd = [claude, "mcp", "add-json", "--scope", "user", name, json.dumps(entry)]
        note = ""
        if isinstance(current, dict) and name in current:
            note = f"replaces the existing user-scope {name!r} (claude mcp remove first)"
        return Plan("claude", path, before, None, command=cmd, note=note)
    plan = _json_plan("claude", path, name, entry)
    plan.note = "the claude command isn't on PATH: editing ~/.claude.json directly"
    return plan


def client_paths(scope: str, home: Path, cwd: Path, env: dict) -> dict[str, Path]:
    codex_home = Path(env["CODEX_HOME"]) if env.get("CODEX_HOME") else home / ".codex"
    if scope == "project":
        return {"claude": cwd / ".mcp.json", "codex": cwd / ".codex" / "config.toml",
                "cursor": cwd / ".cursor" / "mcp.json", "gemini": cwd / ".gemini" / "settings.json"}
    return {"claude": home / ".claude.json", "codex": codex_home / "config.toml",
            "cursor": home / ".cursor" / "mcp.json", "gemini": home / ".gemini" / "settings.json"}


def detect_clients(home: Path, env: dict) -> list[str]:
    """The agents that look installed: their command on PATH or their config directory."""
    codex_home = Path(env["CODEX_HOME"]) if env.get("CODEX_HOME") else home / ".codex"
    marks = {"claude": [home / ".claude.json", home / ".claude"], "codex": [codex_home],
             "cursor": [home / ".cursor"], "gemini": [home / ".gemini"]}
    path = env.get("PATH", "")
    return [c for c in CLIENTS
            if shutil.which(c if c != "cursor" else "cursor-agent", path=path) or shutil.which(c, path=path)
            or any(m.exists() for m in marks[c])]


class SetupError(Exception):
    pass


def plan_for(client: str, scope: str, name: str, server: Server, home: Path, cwd: Path, env: dict) -> Plan:
    paths = client_paths(scope, home, cwd, env)
    if client == "claude":
        return _claude_plan(scope, name, server, home, cwd, shutil.which("claude", path=env.get("PATH", "")))
    if client == "codex":
        return _codex_plan(paths["codex"], name, server)
    if client == "cursor":
        return _json_plan("cursor", paths["cursor"], name, _json_entry(server, typed=True))
    if client == "gemini":
        return _json_plan("gemini", paths["gemini"], name, _json_entry(server, typed=False))
    raise SetupError(f"unknown client {client!r} (one of {', '.join(CLIENTS)})")


def describe(plan: Plan) -> str:
    """What the plan would do, for the person to read: a diff, or the command."""
    head = f"{LABELS[plan.client]}: {plan.path}"
    if plan.unchanged:
        return f"{head}\n  already set up; nothing to change"
    out = [head]
    if plan.note:
        out.append(f"  ({plan.note})")
    if plan.command:
        out.append("  would run: " + " ".join(_shell_quote(a) for a in plan.command))
        return "\n".join(out)
    diff = difflib.unified_diff((plan.before or "").splitlines(keepends=True), plan.after.splitlines(keepends=True),
                                fromfile=str(plan.path) if plan.before is not None else "/dev/null",
                                tofile=str(plan.path))
    out.append("".join(diff).rstrip("\n"))
    return "\n".join(out)


def _shell_quote(s: str) -> str:
    return s if re.fullmatch(r"[A-Za-z0-9_./:=@+-]+", s) else "'" + s.replace("'", "'\\''") + "'"


def backup(path: Path, now: Optional[float] = None) -> Optional[Path]:
    """A copy beside the file (<name>.revkit-backup-<time>), keeping its mode; None when there is no file."""
    if not path.exists():
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now))
    dest = path.with_name(f"{path.name}.revkit-backup-{stamp}")
    n = 1
    while dest.exists():
        dest = path.with_name(f"{path.name}.revkit-backup-{stamp}-{n}")
        n += 1
    shutil.copy2(path, dest)
    return dest


def apply(plan: Plan, run: Callable = subprocess.run) -> Optional[Path]:
    """Writes (or runs) the plan after backing the file up; returns the backup."""
    if plan.unchanged:
        return None
    saved = backup(plan.path)
    if plan.command:
        name = plan.command[5]
        if plan.note:  # an entry of that name is there: claude mcp add-json won't replace it
            run([plan.command[0], "mcp", "remove", "--scope", "user", name], check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        r = run(plan.command, capture_output=True, text=True)
        if r.returncode != 0:
            raise SetupError(f"{' '.join(plan.command[:3])} failed: {(r.stderr or r.stdout).strip()}")
        return saved
    plan.path.parent.mkdir(parents=True, exist_ok=True)
    tmp = plan.path.with_name(plan.path.name + ".revkit-tmp")
    tmp.write_text(plan.after)
    if saved is not None:
        shutil.copymode(saved, tmp)
    os.replace(tmp, plan.path)
    return saved


def main(argv: Optional[list[str]] = None, *, input_fn: Callable[[str], str] = input,
         env: Optional[dict] = None, home: Optional[Path] = None, cwd: Optional[Path] = None) -> int:
    env = dict(os.environ) if env is None else env
    home = Path(env.get("HOME") or Path.home()) if home is None else home
    cwd = Path.cwd() if cwd is None else cwd
    p = argparse.ArgumentParser(
        prog="revkit-mcp setup",
        description="Register revkit's MCP server with Claude Code, Codex, Cursor and Gemini CLI: shows each "
                    "change, asks, backs the file up, writes. Running it again changes nothing.")
    p.add_argument("--client", action="append", choices=[*CLIENTS, "all"],
                   help="an agent to set up (repeatable; default: the ones found on this computer)")
    p.add_argument("--scope", choices=["user", "project"], default="user",
                   help="user (every project; default) or project (config files in the current directory)")
    p.add_argument("--daemon", default=env.get("RK_GRPC", "127.0.0.1:50051"), help="rk-daemon's gRPC address")
    p.add_argument("--token-file", help="a file holding the API token (its path goes in RK_TOKEN_FILE; the token "
                                        "itself is never written into a config)")
    p.add_argument("--name", default="revkit", help="the server's name in each config (default revkit)")
    p.add_argument("--command", dest="executable", help="the revkit-mcp to run (default: this installation's)")
    p.add_argument("--dry-run", action="store_true", help="show the changes, write nothing")
    p.add_argument("-y", "--yes", action="store_true", help="write without asking")
    a = p.parse_args(argv)
    if not NAME_RE.match(a.name):
        p.error("--name: letters, digits, '-' and '_' only")
    if a.token_file and not Path(a.token_file).expanduser().is_file():
        p.error(f"--token-file: no such file: {a.token_file}")
    clients = list(CLIENTS) if a.client and "all" in a.client else list(dict.fromkeys(a.client or []))
    if not clients:
        clients = detect_clients(home, env)
        if not clients:
            print("No coding agent found (claude, codex, cursor, gemini). Name one with --client.", file=sys.stderr)
            return 1
        print(f"Found: {', '.join(LABELS[c] for c in clients)}")
    interactive = sys.stdin.isatty() or input_fn is not input
    failed = 0
    for client in clients:
        server = default_server(a.daemon, client, a.token_file, a.executable)
        try:
            plan = plan_for(client, a.scope, a.name, server, home, cwd, env)
        except SetupError as e:
            print(f"{LABELS[client]}: {e}", file=sys.stderr)
            failed += 1
            continue
        print()
        print(describe(plan))
        if plan.unchanged or a.dry_run:
            continue
        if not a.yes:
            if not interactive:
                print("  not written: no terminal to ask on (pass --yes)", file=sys.stderr)
                failed += 1
                continue
            if input_fn(f"Write this for {LABELS[client]}? [y/N] ").strip().lower() not in ("y", "yes"):
                print("  skipped")
                continue
        try:
            saved = apply(plan)
        except (SetupError, OSError) as e:
            print(f"  {e}", file=sys.stderr)
            failed += 1
            continue
        print(f"  done{f' (backup: {saved})' if saved else ''}")
    if a.dry_run:
        print("\n(dry run: nothing written)")
    elif not failed:
        print("\nRestart the agent (or reload its MCP servers) to pick revkit up; its first call should be `about`.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
