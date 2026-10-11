#!/usr/bin/env python3
"""rk-daemon under socket activation, as systemd starts it
(packaging/linux/revkit-daemon.socket; docs/packaging.md).

The test plays the service manager: it opens the listening socket, connects
a client to it before the daemon exists (the connection that would start
the daemon), then starts rk-daemon with the socket as descriptor 3 and
LISTEN_PID/LISTEN_FDS/LISTEN_FDNAMES set, and checks that

  - the waiting request is answered, by a daemon that says it was socket
    activated (GetServerInfo.socket_activated);
  - accounts are on, as on any start without --no-auth: the API refuses an
    anonymous caller, and GetServerInfo hides the command line from it;
  - --no-auth on a loopback socket stays possible, as an explicit flag;
  - a socket off loopback is refused without accounts, and in plaintext
    with them, as a bound one would be.

    socket_activation_test.py path/to/rk-daemon

Ports come from 53900-53999. Only the daemons this test starts are stopped,
by PID. No systemd is involved.
"""
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time

DAEMON = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("RK_DAEMON", "")
failures = 0


def check(cond, what):
    global failures
    if cond:
        print(f"ok   {what}")
    else:
        failures += 1
        print(f"FAIL {what}")


def listener(host="127.0.0.1"):
    """A listening socket on the first free port in 53900-53999."""
    for port in range(53900, 54000):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((host, port))
            s.listen(16)
            return s
        except OSError:
            s.close()
    raise SystemExit("no free port in 53900-53999")


def spawn(sock, args, tmp, log):
    """rk-daemon with `sock` as descriptor 3, the way systemd passes it:
    the shell's PID is the daemon's after exec, so LISTEN_PID names it."""
    fd = sock.fileno()
    move = "" if fd == 3 else f"exec 3<&{fd} {fd}<&-; "
    script = move + 'export LISTEN_PID=$$ LISTEN_FDS=1 LISTEN_FDNAMES=http; exec "$0" "$@"'
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        # The default credential file (and anything else per user) in here.
        "HOME": tmp,
        "XDG_DATA_HOME": os.path.join(tmp, "data"),
        "XDG_CONFIG_HOME": os.path.join(tmp, "config"),
    }
    return subprocess.Popen(["/bin/sh", "-c", script, DAEMON, *args], pass_fds=(fd,), env=env,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)


def request(port, method, body=b"{}", sock=None, token=None):
    """A Connect JSON call; `sock` may be a connection opened earlier."""
    s = sock or socket.create_connection(("127.0.0.1", port), timeout=30)
    s.settimeout(30)
    head = (f"POST /revkit.v1.{method} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n")
    if token:
        head += f"Authorization: Bearer {token}\r\n"
    s.sendall(head.encode() + b"\r\n" + body)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    head, _, payload = data.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head else 0
    if b"transfer-encoding: chunked" in head.lower():
        out, rest = b"", payload
        while rest:
            size, _, rest = rest.partition(b"\r\n")
            n = int(size, 16)
            if n == 0:
                break
            out, rest = out + rest[:n], rest[n + 2:]
        payload = out
    try:
        return status, json.loads(payload or b"{}")
    except ValueError:
        return status, {"raw": payload.decode(errors="replace")}


def stop(proc):
    if proc.poll() is None:
        os.kill(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            os.kill(proc.pid, signal.SIGKILL)
            proc.wait()


def main():
    if not DAEMON or not os.path.exists(DAEMON):
        raise SystemExit(f"rk-daemon not found: {DAEMON!r}")
    with tempfile.TemporaryDirectory(prefix="rk-sockact-") as tmp:
        base = ["--backend", "fake", "--no-grpc", "--no-web-root"]

        # 1. Default flags: activation by a waiting client, accounts on.
        sock = listener()
        port = sock.getsockname()[1]
        early = socket.create_connection(("127.0.0.1", port), timeout=30)  # queued in the backlog
        with open(os.path.join(tmp, "d1.log"), "wb") as log:
            d = spawn(sock, base, tmp, log)
        sock.close()  # the daemon holds it now (systemd would keep its copy)
        try:
            status, info = request(port, "MetaService/GetServerInfo", sock=early)
            check(status == 200, f"the request that was waiting is answered ({status})")
            check(info.get("socketActivated") is True, "GetServerInfo.socket_activated")
            check("daemon-info" in info.get("features", []), "feature daemon-info")
            check("auth-required" in info.get("features", []), "accounts are on without --no-auth")
            check(not info.get("launchArgs"), "an anonymous caller is not told the command line")
            check(int(info.get("uptimeSeconds", "0")) >= 0, "uptime reported")
            status, who = request(port, "AuthService/WhoAmI")
            check(status == 200 and who.get("authEnabled") is True and not who.get("identity"),
                  "WhoAmI: authentication enabled, caller anonymous")
            status, _ = request(port, "ProjectService/ListProjects")
            check(status == 401, f"ListProjects without credentials is refused ({status})")
            log_text = open(os.path.join(tmp, "d1.log"), "rb").read().decode(errors="replace")
            check("accounts and tokens in " + os.path.join(tmp, "data", "revkit", "auth.db") in log_text,
                  "the default credential file is used")
            check("HTTP on the socket the service manager passed, 127.0.0.1:" + str(port) in log_text,
                  "the daemon says it serves the inherited socket")
        finally:
            stop(d)
        check(d.returncode == 0, f"the daemon stops cleanly on SIGTERM ({d.returncode})")

        # 2. --no-auth stays an explicit, loopback-only choice.
        sock = listener()
        port = sock.getsockname()[1]
        with open(os.path.join(tmp, "d2.log"), "wb") as log:
            d = spawn(sock, base + ["--no-auth"], tmp, log)
        sock.close()
        try:
            status, info = request(port, "MetaService/GetServerInfo")
            check(status == 200 and "auth-required" not in info.get("features", []), "--no-auth on loopback serves")
            check(info.get("launchArgs", [])[1:] == base + ["--no-auth"],
                  f"the command line, to an admin: {info.get('launchArgs')}")
        finally:
            stop(d)

        # 3. Off loopback: refused without accounts, and in plaintext with them.
        for extra, why in ((["--no-auth"], b"without authentication"), ([], b"refusing plaintext")):
            sock = listener("0.0.0.0")
            log_path = os.path.join(tmp, "d3.log")
            with open(log_path, "wb") as log:
                d = spawn(sock, base + extra, tmp, log)
            sock.close()
            try:
                code = d.wait(timeout=30)
            except subprocess.TimeoutExpired:
                stop(d)
                code = None
            text = open(log_path, "rb").read()
            check(code == 1 and why in text, f"a 0.0.0.0 socket with {extra or 'accounts'} is refused: {code}, "
                                             f"{text.decode(errors='replace').strip().splitlines()[-1:]}")

    print("socket activation: " + ("all passed" if not failures else f"{failures} failed"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
