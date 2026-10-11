#!/bin/sh
# Tests scripts/version.sh build (docs/packaging.md#version) in a scratch git
# repository: two commits a second apart, then a third a day later, order
# correctly as Debian versions (dpkg --compare-versions), PEP 440 versions
# (Python's packaging, if installed) and semver (npm's semver, if found);
# every snapshot sorts below the plain release; a commit tagged v<VERSION> and
# REVKIT_VERSION=X.Y.Z build the plain version; a modified tree is ".dirty".
#
#   scripts/version-test.sh        (ctest: version_build; scripts/ci.sh --package)
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/rk-version-test.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
fails=0
fail() { echo "version-test: FAIL: $*" >&2; fails=$((fails + 1)); }
ok() { echo "version-test: ok: $*"; }

mkdir -p "$work/repo/scripts"
cp "$root/scripts/version.sh" "$work/repo/scripts/"
echo 1.2.3 > "$work/repo/VERSION"
cd "$work/repo"
unset REVKIT_VERSION || true
export GIT_CONFIG_NOSYSTEM=1 HOME="$work" GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
git init -q .
git add -A
v=scripts/version.sh
commit() { # commit TIME MESSAGE
  echo "$2" >> log
  git add log
  GIT_AUTHOR_DATE=$1 GIT_COMMITTER_DATE=$1 git commit -q -m "$2"
}
commit "2026-10-07T23:59:59-04:00" one
a_deb=$($v build) a_py=$($v build python) a_npm=$($v build npm)
commit "2026-10-08T00:00:00-04:00" two
b_deb=$($v build) b_py=$($v build python) b_npm=$($v build npm)
commit "2026-10-09T00:00:00-04:00" three
c_deb=$($v build) c_py=$($v build python) c_npm=$($v build npm)
sha=$(git rev-parse --short=12 HEAD)

[ "$c_deb" = "1.2.3~git20261009040000.$sha" ] && ok "deb $c_deb" || fail "deb form: $c_deb"
[ "$c_py" = "1.2.3.dev20261009040000+g$sha" ] && ok "python $c_py" || fail "python form: $c_py"
[ "$c_npm" = "1.2.3-git.20261009040000.g$sha" ] && ok "npm $c_npm" || fail "npm form: $c_npm"

# Debian ordering: a < b < c < 1.2.3 < 1.2.4~git...
for pair in "$a_deb $b_deb" "$b_deb $c_deb" "$c_deb 1.2.3" "1.2.3 1.2.4~git20200101000000.0123456789ab"; do
  set -- $pair
  dpkg --compare-versions "$1" lt "$2" && ok "dpkg: $1 < $2" || fail "dpkg: $1 is not < $2"
done

if python3 -c "import packaging.version" 2>/dev/null; then
  python3 - "$a_py" "$b_py" "$c_py" 1.2.3 <<'EOF' && ok "PEP 440: $a_py < $b_py < $c_py < 1.2.3" || fail "PEP 440 ordering"
import sys
from packaging.version import Version
vs = [Version(s) for s in sys.argv[1:]]
assert all(str(v) == s for v, s in zip(vs, sys.argv[1:])), "not normalized"
assert vs == sorted(vs) and len(set(vs)) == len(vs), vs
EOF
else
  echo "version-test: skipped PEP 440 ordering (no Python packaging module)"
fi

semver=
command -v npm >/dev/null && semver=$(npm root -g 2>/dev/null)/npm/node_modules/semver
if [ -n "$semver" ] && [ -f "$semver/package.json" ]; then
  node - "$semver" "$a_npm" "$b_npm" "$c_npm" 1.2.3 <<'EOF' && ok "semver: $a_npm < $b_npm < $c_npm < 1.2.3" || fail "semver ordering"
const [semverDir, ...vs] = process.argv.slice(2);
const semver = require(semverDir);
for (const v of vs) if (semver.valid(v) !== v) throw new Error(`invalid semver ${v}`);
for (let i = 1; i < vs.length; i++) if (semver.compare(vs[i - 1], vs[i]) >= 0) throw new Error(`${vs[i - 1]} >= ${vs[i]}`);
EOF
else
  echo "version-test: skipped semver ordering (npm's semver not found)"
fi

# An all-digit commit hash would be an invalid semver identifier without the "g".
case $c_npm in *.g[0-9a-f]*) ;; *) fail "npm form lacks the g prefix: $c_npm" ;; esac

echo change >> log
case $($v build) in *.dirty) ok "modified tree: $($v build)" ;; *) fail "modified tree not .dirty: $($v build)" ;; esac
case $($v build python) in *+g$sha.dirty) ;; *) fail "python dirty form: $($v build python)" ;; esac
git checkout -q log

git tag v1.2.2
[ "$($v build)" != 1.2.2 ] && [ "$($v build)" != 1.2.3 ] && ok "a tag other than v1.2.3 is still a snapshot" || fail "other tag"
git tag v1.2.3-pre.1
case $($v build) in 1.2.3~git*) ok "a pre-release tag is still a snapshot" ;; *) fail "pre-release tag: $($v build)" ;; esac
git tag v1.2.3
for f in deb python npm; do
  [ "$($v build $f)" = 1.2.3 ] && ok "tagged v1.2.3 ($f): 1.2.3" || fail "tagged ($f): $($v build $f)"
done
commit "2026-10-10T00:00:00Z" four
[ "$(REVKIT_VERSION=1.2.3 $v build npm)" = 1.2.3 ] && ok "REVKIT_VERSION=1.2.3: 1.2.3" || fail "REVKIT_VERSION"
REVKIT_VERSION=1.2 $v build >/dev/null 2>&1 && fail "REVKIT_VERSION=1.2 accepted" || ok "REVKIT_VERSION=1.2 rejected"

rm -rf .git
[ "$($v build)" = 1.2.3 ] && ok "no git: 1.2.3" || fail "no git: $($v build)"

[ "$fails" = 0 ] && echo "version-test: all passed" || { echo "version-test: $fails failed" >&2; exit 1; }
