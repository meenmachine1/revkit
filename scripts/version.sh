#!/bin/sh
# revkit's version lives in VERSION. CMake reads it directly (every binary's
# --version, GetServerInfo.server_version) and so does the UI build (the
# About box); the package manifests that need a literal copy are kept equal
# by this script:
#
#   sdk/python/revkit/__init__.py      __version__ (pyproject.toml reads it)
#   sdk/ts/package.json, package-lock.json
#   ui/package.json, package-lock.json
#   ui/tauri/src-tauri/Cargo.toml, Cargo.lock (tauri.conf.json reads Cargo.toml)
#
#   scripts/version.sh            print the version
#   scripts/version.sh check      exit 1 if a copy differs (scripts/ci.sh runs it)
#   scripts/version.sh set X.Y.Z  write VERSION and every copy
#   scripts/version.sh build [deb | python | npm]
#                                 the version this build's packages carry
#
# Build versions (docs/packaging.md#version): a build of the commit tagged
# v<VERSION>, or one with REVKIT_VERSION=X.Y.Z in the environment, is the
# plain version. Any other build of a git checkout is a snapshot below it,
# stamped with the commit's time (UTC) so that later commits sort higher:
#
#   deb (default; also --version,   0.1.0~git20261008003044.431366830e06
#        the tarball, the AppImage)
#   python (PEP 440)                0.1.0.dev20261008003044+g431366830e06
#   npm (semver)                    0.1.0-git.20261008003044.g431366830e06
#
# ".dirty" is appended (python: "+g<sha>.dirty") when tracked files have
# uncommitted changes. Without git, the plain version.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
v=$(head -n1 VERSION)

# file|sed-extract|sed-replace (with @V@ for the version)
copies() {
  cat <<'EOF'
sdk/python/revkit/__init__.py|s/^__version__ = "\(.*\)"$/\1/p|s/^__version__ = ".*"$/__version__ = "@V@"/
sdk/ts/package.json|2,4s/^  "version": "\(.*\)",$/\1/p|2,4s/^  "version": ".*",$/  "version": "@V@",/
sdk/ts/package-lock.json|2,4s/^  "version": "\(.*\)",$/\1/p|2,4s/^  "version": ".*",$/  "version": "@V@",/;8,10s/^      "version": ".*",$/      "version": "@V@",/
ui/package.json|2,5s/^  "version": "\(.*\)",$/\1/p|2,5s/^  "version": ".*",$/  "version": "@V@",/
ui/package-lock.json|2,4s/^  "version": "\(.*\)",$/\1/p|2,4s/^  "version": ".*",$/  "version": "@V@",/;8,10s/^      "version": ".*",$/      "version": "@V@",/
ui/tauri/src-tauri/Cargo.toml|1,4s/^version = "\(.*\)"$/\1/p|1,4s/^version = ".*"$/version = "@V@"/
ui/tauri/src-tauri/Cargo.lock|/^name = "revkit-shell"$/{n;s/^version = "\(.*\)"$/\1/p;}|/^name = "revkit-shell"$/{n;s/^version = ".*"$/version = "@V@"/;}
EOF
}

case ${1:-} in
  "") echo "$v" ;;
  check)
    bad=0
    copies | while IFS='|' read -r file get put; do
      got=$(sed -n "$get" "$file" | head -n1)
      if [ "$got" != "$v" ]; then
        echo "version: $file has \"$got\", VERSION has \"$v\" (scripts/version.sh set $v)" >&2
        echo bad
      fi
    done | grep -q bad && bad=1
    [ "$bad" = 0 ] && echo "version: $v everywhere"
    exit $bad ;;
  set)
    new=${2:?usage: scripts/version.sh set X.Y.Z}
    echo "$new" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$' || { echo "version: bad version $new" >&2; exit 2; }
    echo "$new" > VERSION
    copies | while IFS='|' read -r file get put; do
      sed -i "$(echo "$put" | sed "s/@V@/$new/g")" "$file"
    done
    exec "$0" check ;;
  build)
    form=${2:-deb}
    case $form in deb|python|npm) ;; *) echo "usage: $0 build [deb | python | npm]" >&2; exit 2 ;; esac
    if [ -n "${REVKIT_VERSION:-}" ]; then
      echo "$REVKIT_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
        || { echo "version: REVKIT_VERSION must be X.Y.Z, not $REVKIT_VERSION" >&2; exit 2; }
      echo "$REVKIT_VERSION"; exit 0
    fi
    sha=$(git rev-parse --short=12 HEAD 2>/dev/null) || { echo "$v"; exit 0; }
    if git tag --points-at HEAD | grep -qx "v$v"; then echo "$v"; exit 0; fi
    stamp=$(TZ=UTC0 git log -1 --format=%cd --date=format-local:%Y%m%d%H%M%S HEAD)
    dirty=
    [ -z "$(git status --porcelain --untracked-files=no)" ] || dirty=.dirty
    case $form in
      deb) echo "$v~git$stamp.$sha$dirty" ;;
      python) echo "$v.dev$stamp+g$sha$dirty" ;;
      npm) echo "$v-git.$stamp.g$sha$dirty" ;;
    esac ;;
  *) echo "usage: $0 [check | set X.Y.Z | build [deb | python | npm]]" >&2; exit 2 ;;
esac
