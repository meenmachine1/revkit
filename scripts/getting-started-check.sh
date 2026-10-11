#!/bin/sh
# Runs the commands docs/getting-started.md shows, against a portable
# bundle, so the page stays true. Everything happens under a temporary
# directory with its own HOME (nothing touches ~/.config or ~/.local), and
# the daemons listen on 127.0.0.1 ports PORT..PORT+9 instead of the
# documented 50051/50052 (which may be in use).
#
#   scripts/getting-started-check.sh [TARBALL] [--port 51040]
#
# TARBALL defaults to build/dist/revkit-<version>-linux-x86_64.tar.gz, <version>
# being this commit's (scripts/version.sh build). Needs
# a C compiler, Python 3.10+ with venv and network access for pip (grpcio,
# protobuf, mcp).
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
tarball=$root/build/dist/revkit-$("$root/scripts/version.sh" build)-linux-x86_64.tar.gz
port=51040
while [ $# -gt 0 ]; do
  case $1 in
    --port) port=$2; shift 2 ;;
    *) tarball=$1; shift ;;
  esac
done
[ -f "$tarball" ] || { echo "check: $tarball missing (scripts/package.sh)" >&2; exit 2; }
# The build's version, from the bundle's name (revkit-<version>-linux-x86_64).
version=$(basename "$tarball" .tar.gz)
version=${version#revkit-}
version=${version%-linux-x86_64}

t=$(mktemp -d "${TMPDIR:-/tmp}/rk-gs.XXXXXX")
pids=""
cleanup() {
  for p in $pids; do kill "$p" 2>/dev/null || true; done
  rm -rf "$t"
}
trap cleanup EXIT INT TERM
export HOME=$t/home XDG_CONFIG_HOME= XDG_DATA_HOME=
unset GHIDRA_INSTALL_DIR || true
mkdir -p "$HOME"
cd "$t"

ok() { echo "  ok: $*"; }
fail() { echo "check: FAILED: $*" >&2; exit 1; }
# daemon LOG ARGS...: starts rk-daemon in the background, waits for its HTTP port.
daemon() {
  log=$1
  shift
  rk-daemon "$@" > "$log" 2>&1 &
  pids="$pids $!"
  last=$!
  for _ in $(seq 1 150); do
    grep -q "listening\|HTTP (Connect" "$log" 2>/dev/null && return 0
    kill -0 "$last" 2>/dev/null || { cat "$log"; fail "rk-daemon $*"; }
    sleep 0.2
  done
  cat "$log"
  fail "rk-daemon $* did not start"
}
stop() { kill "$last" 2>/dev/null; wait "$last" 2>/dev/null || true; }

echo "== Install"
mkdir -p ~/opt && tar -xzf "$tarball" -C ~/opt
export PATH=$HOME/opt/revkit-$version-linux-x86_64/bin:$PATH
rk-daemon --version | grep -q "^rk-daemon $version (git " || fail "rk-daemon --version"
ok "$(rk-daemon --version)"

echo "== Test programs"
cat > prog.c <<'EOF'
#include <stdio.h>
#include <string.h>
struct point { int x, y; };
struct point origin;
__attribute__((noinline)) unsigned checksum(const unsigned char *p, int n) {
  unsigned h = 0x811c9dc5;
  for (int i = 0; i < n; i++) h = (h ^ p[i]) * 0x1000193;
  return h;
}
int main(int argc, char **argv) {
  unsigned r = checksum((const unsigned char *)argv[0], (int)strlen(argv[0]));
  printf("%u %d\n", r, origin.x);
  return (int)(r & 1);
}
EOF
${CC:-cc} -O1 -g -o prog prog.c
sed 's/0x1000193/0x1000197/' prog.c > prog-v2.c && ${CC:-cc} -O1 -g -o prog-v2 prog-v2.c
ok "prog, prog-v2"

echo "== Ghidra processor specs"
out=$(GHIDRA_INSTALL_DIR=/nonexistent rk-lift prog 2>&1) && fail "rk-lift ran without specs"
first=$(echo "$out" | sed -n 1p)
[ "$first" = 'rk-lift: Ghidra processor specs: /nonexistent (from $GHIDRA_INSTALL_DIR) does not exist.' ] \
  || fail "unexpected message: $first"
ok "missing Ghidra: $first"
mkdir -p ~/.config/revkit
echo "ghidra = $HOME/opt/revkit-$version-linux-x86_64/share/revkit/ghidra" > ~/.config/revkit/revkit.conf
daemon conf.log --no-auth --grpc 127.0.0.1:$port --http 127.0.0.1:$((port + 1)) --open prog
grep -q "Ghidra processor specs from .*share/revkit/ghidra (.*revkit.conf, Ghidra 12" conf.log || fail "revkit.conf not used"
ok "revkit.conf is used"
stop
rm ~/.config/revkit/revkit.conf

echo "== First run"
daemon first.log --no-auth --grpc 127.0.0.1:$port --http 127.0.0.1:$((port + 1)) --open /bin/ls
grep -q "Ghidra processor specs from .*/share/revkit/ghidra (bundled, Ghidra 12" first.log || fail "bundled specs"
ok "bundled specs"
grep -q "web UI at http://revkit.localhost:$((port + 1))/ (from .*share/revkit/ui)" first.log || fail "web UI root"
ok "web UI served from share/revkit/ui"

echo "== The Python SDK in 10 lines"
python3 -m venv ~/rk-venv
wheel=$(echo ~/opt/revkit-$version-linux-x86_64/share/revkit/sdk/revkit-*-py3-none-any.whl)
~/rk-venv/bin/pip install -q "$wheel"
cat > ten.py <<EOF
from revkit import Client

with Client("127.0.0.1:$port", actor="user:alice") as rk:
    prog = rk.program("default/ls")
    funcs = list(prog.functions())
    big = max(funcs, key=lambda f: f.instruction_count)
    print(len(funcs), "functions; the largest is", big.name)
    print(prog.decompile(big.entry.offset).text[:300])
    prog.rename(big.entry.offset, "largest_function", reason="most instructions")
    print(prog.function(big.entry.offset).name)
EOF
~/rk-venv/bin/python ten.py > ten.out
tail -n 1 ten.out | grep -qx largest_function || { cat ten.out; fail "the 10-line example"; }
ok "$(head -n 1 ten.out)"
cat > upload.py <<EOF
from revkit import Client
with Client("127.0.0.1:$port", actor="user:alice") as rk:
    r = rk.import_program("default", content=open("prog", "rb").read(), name="uploaded")
    print(r.program.program_id)
EOF
~/rk-venv/bin/python upload.py | grep -qx default/uploaded || fail "import_program"
ok "import_program(content=...)"
stop

echo "== --project-dir and --browse-root"
mkdir -p ~/samples && cp prog ~/samples/
daemon pd1.log --no-auth --grpc 127.0.0.1:$port --http 127.0.0.1:$((port + 1)) --project-dir ~/revkit-projects \
  --browse-root ~/samples --open prog
stop
daemon pd2.log --no-auth --grpc 127.0.0.1:$port --http 127.0.0.1:$((port + 1)) --project-dir ~/revkit-projects \
  --browse-root ~/samples
grep -q "reopened default/prog" pd2.log || fail "--project-dir did not reopen"
ok "reopened default/prog"
stop

echo "== Accounts on one machine"
echo 'a long enough password' | rk-daemon user add alice --role admin --project-dir ~/revkit-projects --password-stdin 2>/dev/null
daemon acct.log --project-dir ~/revkit-projects --grpc 127.0.0.1:$port --http 127.0.0.1:$((port + 1))
~/rk-venv/bin/python - "$port" <<'EOF' || fail "alice signs in"
import sys
from revkit import Client
rk = Client.login(f"127.0.0.1:{sys.argv[1]}", "alice", "a long enough password")
assert rk.whoami().identity.name == "alice"
EOF
ok "alice signs in"
stop

echo "== A shared server with accounts and TLS"
srv=$t/srv
echo 'another long password' | rk-daemon user add alice --role admin --project-dir "$srv" --password-stdin 2>/dev/null
daemon srv.log --project-dir "$srv" --tls-self-signed --tls-san rk.example.lan \
  --http 127.0.0.1:$((port + 3)) --grpc 127.0.0.1:$((port + 2)) --open prog
grep -q "TLS certificate SHA-256 fingerprint" srv.log || fail "no certificate"
ok "self-signed certificate"
fp=$(rk-daemon tls fingerprint --project-dir "$srv")
grep -q "$fp" srv.log || fail "fingerprint"
ok "tls fingerprint matches the log"
echo 'bob password here' | rk-daemon user add bob --role editor --project-dir "$srv" --password-stdin 2>/dev/null
ci=$(rk-daemon token create --name ci --role editor --user bob --ttl-days 30 --project-dir "$srv" 2>/dev/null)
claude=$(rk-daemon token create --name claude --role editor --project-dir "$srv" 2>/dev/null)
~/rk-venv/bin/python - "$((port + 2))" "$ci" "$claude" "$fp" <<'EOF' || fail "tokens: ci acts as user:bob, claude as agent:claude"
import sys
from revkit import Client
port, ci, claude, fp = sys.argv[1:]
with Client(f"127.0.0.1:{port}", token=ci, fingerprint=fp) as rk:
    assert rk.whoami().identity.name == "bob", rk.whoami()
with Client(f"127.0.0.1:{port}", token=claude, fingerprint=fp) as rk:
    who = rk.whoami().identity
    assert who.name == "claude", who
EOF
ok "tokens: ci acts as user:bob, claude as agent:claude"
# (The daemon checks the address before it binds anything.)
plain=$(timeout 20 rk-daemon --project-dir "$srv" --http 0.0.0.0:$((port + 5)) --grpc 127.0.0.1:$((port + 4)) 2>&1 || true)
echo "$plain" | grep -q "refusing plaintext on 0.0.0.0" || fail "plaintext on 0.0.0.0 was not refused: $plain"
ok "plaintext off loopback refused: $(echo "$plain" | grep refusing | head -n 1)"

echo "== MCP"
~/rk-venv/bin/pip install -q "$wheel[mcp]"
~/rk-venv/bin/python - "$((port + 2))" "$claude" "$fp" <<'EOF' || fail "revkit-mcp lists its tools over stdio"
import json, subprocess, sys, os
port, token, fp = sys.argv[1:]
p = subprocess.Popen([os.path.expanduser("~/rk-venv/bin/revkit-mcp"), "--daemon", f"127.0.0.1:{port}", "--token", token,
                      "--fingerprint", fp], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def send(m):
    p.stdin.write(json.dumps(m) + "\n"); p.stdin.flush()
send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {},
      "clientInfo": {"name": "check", "version": "0"}}})
init = json.loads(p.stdout.readline())
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
tools = [t["name"] for t in json.loads(p.stdout.readline())["result"]["tools"]]
p.terminate()
assert init["result"]["serverInfo"]["name"] == "revkit", init
assert "decompile" in tools and "rename" in tools, tools
print("    tools:", ", ".join(tools))
EOF
ok "revkit-mcp lists its tools over stdio"
stop

echo "== Command-line tools"
rk-decomp --file prog --symbol checksum | grep -q "checksum" || fail "rk-decomp"
ok "rk-decomp"
rk-lift --analyze --decompile --no-instructions -o prog.json prog 2>/dev/null && grep -q '"checksum"' prog.json || fail "rk-lift"
ok "rk-lift"
rk-emu --mode call --entry checksum --arg 0x0 --arg 0 prog > emu.out 2>&1
grep -qi "0x811c9dc5" emu.out || { cat emu.out; fail "rk-emu"; }
ok "rk-emu returns 0x811c9dc5"
rk-debuginfo --c prog | grep -q "struct point" || fail "rk-debuginfo --c"
ok "rk-debuginfo --c"
rk-diff prog prog-v2 > matches.json 2>/dev/null && grep -q '"matches"' matches.json || fail "rk-diff"
ok "rk-diff: $(grep -c '"a":"0x' matches.json) matches"
for t in rk-daemon rk-decompd rk-lift rk-decomp rk-emu rk-dbg rk-diff rk-infer rk-debuginfo rk-cparse; do
  "$t" --version | grep -q "^$t $version " || fail "$t --version"
done
ok "every tool has --version"

echo "== Plugins"
daemon plug.log --no-auth --grpc 127.0.0.1:$port --http 127.0.0.1:$((port + 1)) \
  --plugin-dir ~/opt/revkit-$version-linux-x86_64/share/revkit/plugins --open prog
n=$(grep -c "rk-daemon: plugin " plug.log || true)
[ "$n" -ge 4 ] || fail "plugins"
ok "$n example plugins loaded"
stop
[ -f ~/opt/revkit-$version-linux-x86_64/share/revkit/sdk/plugins/c/revkit_plugin.h ] || fail "plugin SDK"
ok "C plugin SDK in share/revkit/sdk/plugins"

echo "getting-started: every command ran"
