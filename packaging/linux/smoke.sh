#!/bin/sh
# Smoke test of the Linux packages on clean distribution images (Docker):
# nothing installed beyond the image itself (no compiler, Python, curl or
# Node in the container). For each image:
#
#   1. unpack the .tar.gz under /opt; every binary runs (--version) and
#      ldd finds every library;
#   2. rk-decomp decompiles a function of a test program (compiled here, on
#      the host) and rk-lift --analyze --decompile a binary of the image
#      itself (/bin/ls), with the bundled Ghidra specs;
#   3. a missing Ghidra is reported clearly (GHIDRA_INSTALL_DIR=/nonexistent);
#   4. rk-daemon --no-auth (loopback, host network) imports both; from the
#      host, the Python SDK (the wheel in a fresh venv) lists functions and
#      decompiles, and headless Chrome opens the web UI the daemon serves
#      (ui-smoke.mjs: the program, the decompiler, the About box);
#   5. rk-daemon with an account, an API token and a self-signed TLS
#      certificate: the SDK connects with the token and the pinned
#      fingerprint;
#   6. with --deb, the .deb installs with apt-get in a second clean container
#      and decompiles from /usr/bin; rk-script, with no Python there, says
#      what to install, and once apt installs python3 and python3-venv
#      (network), makes its environment from the shipped wheel and runs a
#      starter script on a throwaway daemon.
#
#   packaging/linux/smoke.sh --tarball T.tar.gz --python VENV_PYTHON [--deb D.deb]
#                            [--images "ubuntu:24.04 debian:12"] [--port-base 51010]
#
# Ports: port-base .. port-base+9 per image, on 127.0.0.1 (host network).
# Exits 77 when Docker is unavailable.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
tarball= deb= python= images="ubuntu:24.04 debian:12" port_base=51010
while [ $# -gt 0 ]; do
  case $1 in
    --tarball) tarball=$2; shift 2 ;;
    --deb) deb=$2; shift 2 ;;
    --python) python=$2; shift 2 ;;
    --images) images=$2; shift 2 ;;
    --port-base) port_base=$2; shift 2 ;;
    *) echo "smoke: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -f "$tarball" ] || { echo "smoke: --tarball missing" >&2; exit 2; }
[ -x "$python" ] || { echo "smoke: --python must be a Python with the revkit wheel installed" >&2; exit 2; }
if ! docker info >/dev/null 2>&1; then
  echo "smoke: Docker is not available; skipped" >&2
  exit 77
fi

tarball=$(cd "$(dirname "$tarball")" && pwd)/$(basename "$tarball")
name=$(basename "$tarball" .tar.gz)
# The build's version, from the bundle's name (revkit-<version>-linux-x86_64).
version=${name#revkit-}
version=${version%-linux-*}
work=$(mktemp -d "${TMPDIR:-/tmp}/rk-smoke.XXXXXX")
containers=""
cleanup() {
  for c in $containers; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

# The test program, built on the host (the containers have no compiler).
cat > "$work/prog.c" <<'EOF'
#include <stdio.h>
#include <string.h>
__attribute__((noinline)) unsigned checksum(const unsigned char *p, int n) {
  unsigned h = 0x811c9dc5;
  for (int i = 0; i < n; i++) h = (h ^ p[i]) * 0x1000193;
  return h;
}
int main(int argc, char **argv) {
  unsigned r = checksum((const unsigned char *)argv[0], (int)strlen(argv[0]));
  printf("%u\n", r);
  return (int)(r & 1);
}
EOF
${CC:-cc} -O1 -g -o "$work/prog" "$work/prog.c"
cp "$tarball" "$work/revkit.tar.gz"
[ -z "$deb" ] || cp "$deb" "$work/revkit.deb"
chmod -R a+rX "$work"

fail() { echo "smoke: FAILED ($image): $*" >&2; exit 1; }
step() { echo "== smoke ($image): $*"; }
# wait_port PORT: until something listens on 127.0.0.1:PORT (30 s).
wait_port() {
  "$python" - "$1" <<'EOF'
import socket, sys, time
deadline = time.time() + 30
while time.time() < deadline:
    try:
        socket.create_connection(("127.0.0.1", int(sys.argv[1])), 1).close()
        sys.exit(0)
    except OSError:
        time.sleep(0.2)
sys.exit(1)
EOF
}

for image in $images; do
  c="rk-smoke-$(echo "$image" | tr ':./' '---')-$$"
  containers="$containers $c"
  p=$port_base
  port_base=$((port_base + 10))
  docker run -d ${RK_SMOKE_PLATFORM:+--platform "$RK_SMOKE_PLATFORM"} --name "$c" --network host -v "$work:/work:ro" "$image" sleep infinity >/dev/null
  x() { docker exec "$c" "$@"; }

  step "unpack $name.tar.gz"
  x tar -xzf /work/revkit.tar.gz -C /opt
  bin=/opt/$name/bin
  for t in rk-daemon rk-decompd rk-lift rk-decomp rk-emu rk-dbg rk-diff rk-infer rk-debuginfo rk-cparse rk-bsim; do
    out=$(x "$bin/$t" --version) || fail "$t --version"
    case $out in "$t $version "*) ;; *) fail "$t --version printed: $out" ;; esac
    if x ldd "$bin/$t" | grep -q "not found"; then x ldd "$bin/$t"; fail "$t: missing libraries"; fi
  done
  echo "   $(x "$bin/rk-daemon" --version); every binary runs, every library found"

  step "rk-decomp and rk-lift with the bundled Ghidra specs"
  x "$bin/rk-decomp" --file /work/prog --symbol checksum > "$work/decomp-$c.c" 2>&1 || { cat "$work/decomp-$c.c"; fail "rk-decomp"; }
  grep -q "checksum" "$work/decomp-$c.c" || fail "rk-decomp output lacks checksum"
  x sh -c "cd /tmp && $bin/rk-lift --analyze --decompile --no-instructions --stats /tmp/ls-stats.json -o /tmp/ls.json /bin/ls" \
    > "$work/lift-$c" 2>&1 || { cat "$work/lift-$c"; fail "rk-lift --analyze --decompile /bin/ls"; }
  n=$(x cat /tmp/ls-stats.json | tr -d ' \n' | grep -o '"decompiled":[0-9]*' | head -n1 | grep -o '[0-9]*$')
  [ "${n:-0}" -gt 50 ] || fail "rk-lift decompiled only ${n:-0} functions of /bin/ls"
  echo "   rk-decomp: $(wc -l < "$work/decomp-$c.c") lines of C for checksum; rk-lift: $n functions of /bin/ls decompiled"

  step "a missing Ghidra is reported"
  if x env GHIDRA_INSTALL_DIR=/nonexistent "$bin/rk-lift" /work/prog > "$work/err-$c" 2>&1; then fail "rk-lift ran without Ghidra specs"; fi
  grep -q "GHIDRA_INSTALL_DIR" "$work/err-$c" || { cat "$work/err-$c"; fail "unclear error"; }
  sed -n 1p "$work/err-$c"

  step "rk-daemon --no-auth: Python SDK and the web UI (headless Chrome)"
  docker exec -d "$c" sh -c "echo \$\$ > /tmp/daemon.pid; exec $bin/rk-daemon --no-auth --grpc 127.0.0.1:$p --http 127.0.0.1:$((p + 1)) \
      --project-dir /tmp/projects --open /work/prog --open /bin/ls > /tmp/daemon.log 2>&1"
  wait_port $((p + 1)) || { x cat /tmp/daemon.log; fail "daemon did not start"; }
  "$python" - "127.0.0.1:$p" "$version" <<'EOF' || { x cat /tmp/daemon.log; fail "Python SDK"; }
import sys
from revkit import Client
with Client(sys.argv[1]) as rk:
    info = rk.server_info()
    assert sys.argv[2] in info.server_version, info.server_version
    prog = rk.program("default/prog")
    fns = {f.name: f for f in prog.functions()}
    c = prog.decompile(fns["checksum"].entry.offset).text
    assert "0x1000193" in c or "16777619" in c, c
    ls = sum(1 for _ in rk.program("default/ls").functions())
    print(f"   SDK: {info.server_version}; prog has {len(fns)} functions; ls has {ls}; checksum decompiles")
EOF
  RK_BROWSER=${RK_BROWSER:-/usr/bin/google-chrome} node "$here/ui-smoke.mjs" "http://127.0.0.1:$((p + 1))" default/prog checksum "$version" \
    || fail "web UI"
  x sh -c 'kill $(cat /tmp/daemon.pid)' || true

  step "rk-daemon with an account, a token and TLS (as on a server)"
  x sh -c "echo 'correct horse battery staple' | $bin/rk-daemon user add smoke --role admin --password-stdin --project-dir /tmp/srv" >/dev/null
  token=$(x "$bin/rk-daemon" token create --name smoke-agent --role editor --project-dir /tmp/srv 2>/dev/null | tail -n1)
  [ -n "$token" ] || fail "token create"
  docker exec -d "$c" sh -c "echo \$\$ > /tmp/daemon.pid; exec $bin/rk-daemon --project-dir /tmp/srv --tls-self-signed --grpc 127.0.0.1:$((p + 2)) \
      --http 127.0.0.1:$((p + 3)) --open /work/prog > /tmp/daemon-tls.log 2>&1"
  wait_port $((p + 3)) || { x cat /tmp/daemon-tls.log; fail "TLS daemon did not start"; }
  fp=$(x "$bin/rk-daemon" tls fingerprint --project-dir /tmp/srv)
  [ -n "$fp" ] || fail "tls fingerprint"
  "$python" - "127.0.0.1:$((p + 2))" "$token" "$fp" <<'EOF' || { x cat /tmp/daemon-tls.log; fail "SDK over TLS with a token"; }
import sys
from revkit import Client
with Client(sys.argv[1], token=sys.argv[2], fingerprint=sys.argv[3]) as rk:
    who = rk.whoami()
    assert who.auth_enabled and who.identity.name, who
    prog = rk.program("default/prog")
    f = next(f for f in prog.functions() if f.name == "main")
    assert "checksum" in prog.decompile(f.entry.offset).text
    print(f"   TLS + token: signed in as {who.identity.name}; main decompiles")
EOF
  x sh -c 'kill $(cat /tmp/daemon.pid)' || true
  docker rm -f "$c" >/dev/null

  if [ -n "$deb" ]; then
    step "apt-get install the .deb"
    d="$c-deb"
    containers="$containers $d"
    docker run -d ${RK_SMOKE_PLATFORM:+--platform "$RK_SMOKE_PLATFORM"} --name "$d" -v "$work:/work:ro" "$image" sleep infinity >/dev/null
    docker exec "$d" apt-get install -y -q /work/revkit.deb > "$work/apt-$d" 2>&1 || { cat "$work/apt-$d"; fail "apt-get install"; }
    docker exec "$d" rk-daemon --version
    docker exec "$d" sh -c "rk-decomp --file /work/prog --symbol checksum | grep -q checksum" || fail "rk-decomp from the .deb"
    docker exec "$d" sh -c "test -f /usr/share/revkit/ui/index.html && test -d /usr/share/revkit/ghidra/Ghidra/Processors" \
      || fail "the .deb lacks the UI or the specs"
    echo "   installed to /usr; rk-decomp decompiles"
    # rk-script and the SDK wheel it makes the scripts' Python from
    # (docs/scripting.md#rk-script); Python is only recommended.
    docker exec "$d" sh -c "test -x /usr/bin/rk-script && ls /usr/share/revkit/python/revkit-*.whl >/dev/null" \
      || fail "the .deb lacks rk-script or the SDK wheel"
    if ! docker exec "$d" sh -c "command -v python3" >/dev/null 2>&1; then
      out=$(docker exec "$d" rk-script list 2>&1) && fail "rk-script ran without a Python"
      echo "$out" | grep -q "python3-venv" || fail "rk-script without Python says: $out"
      echo "   without Python, rk-script says what to install"
    fi
    step "rk-script from the .deb: its Python made on first use (apt and pip need the network)"
    if docker exec "$d" sh -c "apt-get update -q && apt-get install -y -q --no-install-recommends python3 python3-venv" \
        > "$work/apt-py-$d" 2>&1; then
      docker exec "$d" rk-script list > "$work/list-$d" 2>&1 || { cat "$work/list-$d"; fail "rk-script list"; }
      grep -q tag_functions_by_complexity "$work/list-$d" || { cat "$work/list-$d"; fail "rk-script list shows no starters"; }
      docker exec "$d" test -x /root/.local/share/revkit/pyenv/bin/python || fail "no ~/.local/share/revkit/pyenv"
      docker exec "$d" rk-script run tag_functions_by_complexity --import /work/prog --arg measure=instructions --json \
        > "$work/run-$d" 2>"$work/run-err-$d" || { cat "$work/run-$d" "$work/run-err-$d"; fail "rk-script run"; }
      grep -Eq '"status": ?"ok"' "$work/run-$d" || { cat "$work/run-$d" "$work/run-err-$d"; fail "rk-script run: not ok"; }
      echo "   rk-script made ~/.local/share/revkit/pyenv from the wheel; a shipped script ran on a throwaway daemon"
    else
      echo "   (apt can't reach its archive: rk-script's first run not checked)"
    fi
    docker rm -f "$d" >/dev/null
  fi
  echo "== smoke ($image): passed"
done
