"""Starts a local rk-daemon for scripts and tests."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional, Sequence


def find_daemon() -> str:
    """$RK_DAEMON, then rk-daemon on PATH, then the repo's build tree."""
    if env := os.environ.get("RK_DAEMON"):
        return env
    if found := shutil.which("rk-daemon"):
        return found
    repo = Path(__file__).resolve().parents[3]
    candidate = repo / "build" / "tools" / "rk-daemon" / "rk-daemon"
    if candidate.exists():
        return str(candidate)
    raise FileNotFoundError("rk-daemon not found: set RK_DAEMON or build it (cmake --build --preset default)")


class Daemon:
    """An rk-daemon child process on free loopback ports.

        with Daemon() as d:
            client = Client(d.grpc_target)
            ...  # d.http_url serves Connect / gRPC-web

    It listens on free loopback ports unless ``grpc``/``http`` name others.
    By default it runs with ``--no-auth`` (local development). With
    ``auth=True`` it keeps its own credential file and, with ``tls=True``
    (the default then), a self-signed certificate, both in its temporary
    directory; ``env`` adds to the environment it inherits (scripts' Python,
    ``XDG_CONFIG_HOME``); :meth:`add_user` and :meth:`create_token` manage accounts
    through ``rk-daemon user`` / ``rk-daemon token``, and :meth:`client`
    connects with the certificate pinned.
    """

    def __init__(
        self,
        binary: Optional[str] = None,
        *args: str,
        startup_timeout: float = 15.0,
        auth: bool = False,
        tls: Optional[bool] = None,
        grpc: str = "127.0.0.1:0",
        http: str = "127.0.0.1:0",
        env: Optional[dict] = None,
    ):
        self.binary = binary or find_daemon()
        self.listen = (grpc, http)
        self.args = list(args)
        self.startup_timeout = startup_timeout
        self.auth = auth
        self.tls = auth if tls is None else tls
        # Added to (or replacing) the environment it inherits.
        self.env = dict(env or {})
        self.process: Optional[subprocess.Popen] = None
        self.grpc_port = 0
        self.http_port = 0
        self.fingerprint = ""
        self._dir = None

    @property
    def dir(self) -> Path:
        return Path(self._dir.name)

    @property
    def auth_file(self) -> Path:
        return self.dir / "auth.db"

    @property
    def ca_cert(self) -> Path:
        """The daemon's self-signed certificate (tls=True)."""
        return self.dir / "tls" / "cert.pem"

    @property
    def grpc_target(self) -> str:
        return f"127.0.0.1:{self.grpc_port}"

    @property
    def http_url(self) -> str:
        return f"{'https' if self.tls else 'http'}://127.0.0.1:{self.http_port}"

    def _security_args(self) -> list:
        out = ["--auth-file", str(self.auth_file)] if self.auth else ["--no-auth"]
        if self.tls:
            out += ["--tls-self-signed", "--tls-dir", str(self.dir / "tls")]
        return out

    def start(self) -> "Daemon":
        self._dir = tempfile.TemporaryDirectory(prefix="rk-daemon-")
        port_file = self.dir / "ports.json"
        # The log goes to a file: a pipe nobody reads would fill and stall the daemon.
        self._log = open(self.dir / "daemon.log", "w")
        self.process = subprocess.Popen(
            [self.binary, "--grpc", self.listen[0], "--http", self.listen[1], "--port-file", str(port_file),
             *self._security_args(), *self.args],
            stdout=subprocess.DEVNULL,
            stderr=self._log,
            text=True,
            env={**os.environ, **self.env} if self.env else None,
        )
        deadline = time.monotonic() + self.startup_timeout
        while not port_file.exists():
            if self.process.poll() is not None:
                raise RuntimeError(f"rk-daemon exited with {self.process.returncode}: {self.log()}")
            if time.monotonic() > deadline:
                self.stop()
                raise TimeoutError("rk-daemon did not start")
            time.sleep(0.02)
        ports = json.loads(port_file.read_text())
        self.grpc_port, self.http_port = ports["grpc"], ports["http"]
        if self.tls:
            from revkit.client import certificate_fingerprint

            self.fingerprint = certificate_fingerprint(self.ca_cert.read_text())
        return self

    def log(self) -> str:
        """What the daemon has written to stderr so far."""
        try:
            return (self.dir / "daemon.log").read_text()
        except OSError:
            return ""

    def admin(self, *args: str, input: Optional[str] = None) -> str:
        """Runs ``rk-daemon <args>`` against this daemon's credential file; returns stdout."""
        r = subprocess.run([self.binary, *args, "--auth-file", str(self.auth_file)], input=input,
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"rk-daemon {' '.join(args)}: {r.stderr.strip()}")
        return r.stdout

    def add_user(self, name: str, role: str, password: str, projects: Sequence[str] = ()) -> None:
        extra = ["--projects", ",".join(projects)] if projects else []
        self.admin("user", "add", name, "--role", role, "--password-stdin", *extra, input=password + "\n")

    def create_token(self, name: str, role: str, *, user: str = "", projects: Sequence[str] = ()) -> str:
        """Issues an API token and returns its secret."""
        extra = (["--user", user] if user else []) + (["--projects", ",".join(projects)] if projects else [])
        return self.admin("token", "create", "--name", name, "--role", role, *extra).strip()

    def client(self, **kwargs):
        """A Client for this daemon, trusting its pinned certificate when it has TLS."""
        from revkit.client import Client

        if self.tls:
            kwargs.setdefault("fingerprint", self.fingerprint)
        return Client(self.grpc_target, **kwargs)

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if getattr(self, "_log", None):
            self._log.close()
            self._log = None
        if self._dir:
            self._dir.cleanup()
            self._dir = None

    def __enter__(self) -> "Daemon":
        return self.start()

    def __exit__(self, *exc):
        self.stop()
