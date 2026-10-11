#!/usr/bin/env python3
"""rk-daemon's MetaService.RestartDaemon (docs/ui.md, "Restart daemon"):

  - a daemon started directly runs itself again in the same process: the
    same PID answers on the same port after the restart, with a fresh
    uptime and the same command line, and its log has the audit line;
  - a dry run restarts nothing and says how (mode "reexec");
  - with accounts, a viewer's call is refused and nothing restarts;
  - under socket activation (the test plays systemd, as
    socket_activation_test.py does) the daemon says "exit", exits 0 after
    the restart, and the socket it was given stays open for the next one.

    restart_test.py path/to/rk-daemon

Fake backend, ports from 53900-53999; only the daemons this test starts are
stopped, by PID. Python's standard library only.
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


def free_port():
    for port in range(53900, 54000):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            return port
        except OSError:
            pass
        finally:
            s.close()
    raise SystemExit("no free port in 53900-53999")


def call(port, method, body=None, token=None, timeout=10):
    """A Connect JSON call: (HTTP status, decoded body)."""
    data = json.dumps(body or {}).encode()
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    head = (f"POST /revkit.v1.{method} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(data)}\r\nConnection: close\r\n")
    if token:
        head += f"Authorization: Bearer {token}\r\n"
    s.sendall((head + "\r\n").encode() + data)
    out = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        out += chunk
    s.close()
    status = int(out.split(b" ", 2)[1])
    payload = out.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in out else b""
    try:
        return status, json.loads(payload or b"{}")
    except ValueError:
        return status, {"raw": payload.decode(errors="replace")}


def wait_up(port, seconds=60):
    end = time.time() + seconds
    while time.time() < end:
        try:
            st, info = call(port, "MetaService/GetServerInfo", timeout=2)
            if st == 200:
                return info
        except OSError:
            pass
        time.sleep(0.1)
    return None


def stop(p):
    if p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(15)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()


def env_for(tmp):
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": tmp,
        "XDG_DATA_HOME": os.path.join(tmp, "data"),
        "XDG_CONFIG_HOME": os.path.join(tmp, "config"),
    }


def reexec(tmp):
    port = free_port()
    log_path = os.path.join(tmp, "reexec.log")
    log = open(log_path, "wb")
    args = [DAEMON, "--backend", "fake", "--http", f"127.0.0.1:{port}", "--no-grpc", "--no-auth"]
    p = subprocess.Popen(args, env=env_for(tmp), stdout=subprocess.DEVNULL, stderr=log)
    try:
        info = wait_up(port)
        check(info is not None, "the daemon answers")
        if not info:
            return
        check("daemon-restart" in info.get("features", []), "feature daemon-restart")
        st, dry = call(port, "MetaService/RestartDaemon", {"dryRun": True})
        check(st == 200 and dry.get("mode") == "reexec", f"dry run: {st} {dry}")
        time.sleep(1)
        check(p.poll() is None and call(port, "MetaService/GetServerInfo")[0] == 200, "a dry run restarts nothing")
        time.sleep(1.2)  # an uptime above a second, to see it start again
        st, resp = call(port, "MetaService/RestartDaemon", {"reason": "restart_test"})
        check(st == 200 and resp.get("mode") == "reexec", f"restart: {st} {resp}")
        # Down, then back on the same port.
        down = False
        end = time.time() + 15
        while time.time() < end and not down:
            try:
                down = call(port, "MetaService/GetServerInfo", timeout=1)[0] != 200
            except OSError:
                down = True
            time.sleep(0.05)
        again = wait_up(port)
        check(again is not None, "back on the same port")
        check(p.poll() is None, "the same process (PID) runs it")
        if again:
            check(int(again.get("uptimeSeconds", "0")) <= 1, f"a fresh uptime: {again.get('uptimeSeconds')}")
            check(again.get("launchArgs") == args, f"the same command line: {again.get('launchArgs')}")
        with open(f"/proc/{p.pid}/cmdline", "rb") as f:
            check(f.read().split(b"\0")[:-1] == [a.encode() for a in args], "argv after exec")
    finally:
        stop(p)
        log.close()
    text = open(log_path, errors="replace").read()
    check("audit: restart (reexec) requested by anonymous" in text and "restart_test" in text, "the audit line")
    check(text.count("rk-daemon: backend fake") == 2, "started twice")


def viewer_refused(tmp):
    port = free_port()
    auth = os.path.join(tmp, "auth.db")
    env = env_for(tmp)
    out = subprocess.run([DAEMON, "token", "create", "vic", "--role", "viewer", "--auth-file", auth],
                         env=env, capture_output=True, text=True)
    token = out.stdout.strip().split()[-1] if out.returncode == 0 and out.stdout.strip() else ""
    check(bool(token), f"a viewer token ({out.stderr.strip()[:200]})")
    p = subprocess.Popen([DAEMON, "--backend", "fake", "--http", f"127.0.0.1:{port}", "--no-grpc", "--auth-file", auth],
                         env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        check(wait_up(port) is not None, "the daemon with accounts answers")
        st, _ = call(port, "MetaService/RestartDaemon", {}, token=token)
        check(st == 403, f"a viewer is refused: {st}")
        st, _ = call(port, "MetaService/RestartDaemon", {})
        check(st == 401, f"an anonymous caller is refused: {st}")
        time.sleep(0.8)
        check(p.poll() is None, "nothing restarted")
    finally:
        stop(p)


def socket_activated(tmp):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for port in range(53900, 54000):
        try:
            sock.bind(("127.0.0.1", port))
            break
        except OSError:
            continue
    sock.listen(16)
    port = sock.getsockname()[1]
    fd = sock.fileno()
    move = "" if fd == 3 else f"exec 3<&{fd} {fd}<&-; "
    script = move + 'export LISTEN_PID=$$ LISTEN_FDS=1 LISTEN_FDNAMES=http; exec "$0" "$@"'
    p = subprocess.Popen(["/bin/sh", "-c", script, DAEMON, "--backend", "fake", "--no-grpc", "--no-auth"],
                         pass_fds=(fd,), env=env_for(tmp), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        info = wait_up(port)
        check(info is not None and info.get("socketActivated"), "socket activated")
        st, resp = call(port, "MetaService/RestartDaemon", {"reason": "restart_test"})
        check(st == 200 and resp.get("mode") == "exit", f"restart under socket activation: {st} {resp}")
        try:
            code = p.wait(20)
        except subprocess.TimeoutExpired:
            code = None
        check(code == 0, f"exits 0 for systemd to start it again: {code}")
        # The socket is the test's (systemd's): a client can still connect.
        c = socket.create_connection(("127.0.0.1", port), timeout=2)
        c.close()
        check(True, "the socket stays open")
    finally:
        stop(p)
        sock.close()


def main():
    if not DAEMON or not os.path.exists(DAEMON):
        raise SystemExit(f"usage: {sys.argv[0]} path/to/rk-daemon")
    with tempfile.TemporaryDirectory(prefix="rk-restart-") as tmp:
        reexec(tmp)
        viewer_refused(tmp)
        socket_activated(tmp)
    print("restart: all ok" if not failures else f"restart: {failures} failed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
