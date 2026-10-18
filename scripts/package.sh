#!/bin/sh
# Builds every revkit artifact into build/dist/ (never committed;
# docs/packaging.md). <v> is the build's version (scripts/version.sh build):
# 0.1.0 for the commit tagged v0.1.0 or with REVKIT_VERSION=0.1.0, else a
# snapshot that sorts below it and above earlier commits'
# (0.1.0~git20261008003044.431366830e06; the Python packages say
# 0.1.0.dev20261008003044+g431366830e06, the npm package
# 0.1.0-git.20261008003044.g431366830e06). A native build first empties
# build/dist, so it holds only this build's artifacts.
#
#   revkit-<v>-linux-x86_64.tar.gz   portable bundle: bin/, lib/revkit/ (private
#                                    libraries), share/revkit/{ui,ghidra,plugins,sdk,python},
#                                    share/doc/revkit (notices, licenses); runs from
#                                    any directory on glibc >= 2.34 with GCC 12's
#                                    libstdc++ (Ubuntu 22.04, Debian 12 and later)
#   revkit_<v>_amd64.deb             the same tree under /usr (CPack)
#   revkit-<pv>-py3-none-any.whl,    the Python SDK and MCP server
#   revkit-<pv>.tar.gz
#   revkit-api-<nv>.tgz              the TypeScript SDK (npm pack)
#   revkit-desktop_<v>_amd64.deb     the Tauri desktop app (--desktop): the .deb
#   revkit-desktop_<v>_amd64.AppImage  uses the revkit package's daemon, the
#                                    AppImage carries the bundle
#   SHA256SUMS
#
# The native build runs in Docker (packaging/linux/build.Dockerfile, Debian 12)
# with the release preset, so the result does not depend on the host's
# libraries; the UI, the SDKs and the desktop shell build on the host.
#
#   scripts/package.sh [--arch amd64|arm64] [--desktop] [--smoke] [--no-native] [--ghidra DIR] [-j N]
#
#   --arch       the architecture to build for (default amd64; arm64 builds
#                in an emulated arm64 container: slower, and no desktop app)
#   --desktop    also build the desktop app (needs Rust and the Tauri system
#                packages, docs/packaging.md)
#   --smoke      then run packaging/linux/smoke.sh on ubuntu:24.04 and debian:12
#   --no-native  reuse build-release/ and the staged tree (UI/SDK work)
#   --ghidra     the Ghidra install the specs are gathered from (default
#                $GHIDRA_INSTALL_DIR, else ~/ghidra/ghidra_12.1.4_PUBLIC)
#   -j N         parallel build jobs (default $RK_CI_JOBS, else 4)
#
# Needs: Docker, Node 22+ and npm, Python 3.10+ with venv, git.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

desktop=0 smoke=0 native=1 arch=amd64
ghidra=${GHIDRA_INSTALL_DIR:-$HOME/ghidra/ghidra_12.1.4_PUBLIC}
jobs=${RK_CI_JOBS:-4}
while [ $# -gt 0 ]; do
  case $1 in
    --arch) arch=$2; shift 2 ;;
    --desktop) desktop=1; shift ;;
    --smoke) smoke=1; shift ;;
    --no-native) native=0; shift ;;
    --ghidra) ghidra=$2; shift 2 ;;
    -j) jobs=$2; shift 2 ;;
    -h|--help) sed -n '2,42p' "$0"; exit 0 ;;
    *) echo "package: unknown argument $1" >&2; exit 2 ;;
  esac
done

case $arch in
  amd64) triple=x86_64 ;;
  arm64) triple=aarch64 ;;
  *) echo "package: --arch is amd64 or arm64" >&2; exit 2 ;;
esac
if [ "$arch" != amd64 ] && [ "$desktop" = 1 ]; then
  echo "package: the desktop app is built for amd64 only" >&2; exit 2
fi
platform=linux/$arch
scripts/version.sh check >/dev/null
version=$(scripts/version.sh build)          # Debian, the bundle, --version
pyversion=$(scripts/version.sh build python) # PEP 440
npmversion=$(scripts/version.sh build npm)   # semver
export RK_DEB_VERSION=$version RK_NPM_VERSION=$npmversion   # packaging/desktop/build.sh
echo "== package: version $version (Python $pyversion, npm $npmversion)"
sha=$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
  sha="$sha-dirty"
  echo "package: warning: uncommitted changes; versions say git $sha" >&2
fi
# Timestamps in the archives: the commit's, so a rebuild of the same commit
# produces the same files.
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}
export SOURCE_DATE_EPOCH

name=revkit-$version-linux-$triple
pkg=$root/build/pkg          # intermediate files
dist=$root/build/dist        # the artifacts
stage=$pkg/stage/$name
image=revkit-build:bookworm-$arch
[ "$native" = 0 ] || rm -rf "$dist"
mkdir -p "$pkg" "$dist"

say() { echo "== package: $*"; }

# ---- web UI (host Node) ----------------------------------------------------------
say "web UI"
(cd sdk/ts && npm ci --no-audit --no-fund --loglevel=error)
(cd ui && npm ci --no-audit --no-fund --loglevel=error && REVKIT_GIT_SHA=$sha REVKIT_BUILD_VERSION=$version npm run build --silent)

# ---- third-party license texts (npm) ---------------------------------------------
rm -rf "$pkg/licenses"
python3 scripts/third-party-notices.py --sections npm --licenses-dir "$pkg/licenses" --check \
  || { echo "package: THIRD_PARTY_NOTICES.md is out of date: python3 scripts/third-party-notices.py" >&2; exit 1; }

# ---- Ghidra processor specs --------------------------------------------------------
say "Ghidra processor specs from $ghidra"
scripts/gather-ghidra-specs.sh --ghidra "$ghidra" "$pkg/ghidra-specs"

# ---- Python SDK -------------------------------------------------------------------------
# Built from a copy of the tracked sources with __version__ set to the build's,
# before the native build: the bundle and the .deb carry the wheel in
# share/revkit/python, with bin/rk-script (cmake/install.cmake).
say "Python SDK (wheel and sdist, $pyversion)"
rm -rf "$pkg/pyvenv" "$pkg/py" "$pkg/py-src"
mkdir -p "$pkg/py-src"
git ls-files sdk/python | tar -cf - -T - | tar -xf - -C "$pkg/py-src"
sed -i "s/^__version__ = \".*\"$/__version__ = \"$pyversion\"/" "$pkg/py-src/sdk/python/revkit/__init__.py"
grep -q "^__version__ = \"$pyversion\"$" "$pkg/py-src/sdk/python/revkit/__init__.py"
python3 -m venv "$pkg/pyvenv"
"$pkg/pyvenv/bin/pip" install -q build
"$pkg/pyvenv/bin/python" -m build -q --wheel --sdist --outdir "$pkg/py" "$pkg/py-src/sdk/python" >/dev/null
cp "$pkg/py/revkit-$pyversion-py3-none-any.whl" "$pkg/py/revkit-$pyversion.tar.gz" "$dist/"

# ---- native build in Docker (Debian 12) ------------------------------------------------
if [ "$native" = 1 ]; then
  say "native build (Docker, $image, -j $jobs)"
  docker build -q --platform "$platform" -t "$image" -f packaging/linux/build.Dockerfile packaging/linux >/dev/null
  targets="rk-daemon rk-decompd rk-sandbox rk-lift rk-decomp rk-emu rk-dbg rk-diff rk-infer rk-debuginfo rk-cparse rk-bsim revkit_example_plugins"
  rm -rf "$pkg/stage" "$pkg/deb"
  log=$pkg/native-build.log
  echo "   (output in $log)"
  docker run --rm --platform "$platform" -u "$(id -u):$(id -g)" -e HOME=/tmp -e SOURCE_DATE_EPOCH -v "$root:/src" -w /src "$image" sh -euc "
    cmake --preset release --fresh -DREVKIT_GIT_SHA=$sha -DREVKIT_BUILD_VERSION='$version' -DREVKIT_UI_DIST=/src/ui/dist \
          -DREVKIT_GHIDRA_SPECS=/src/build/pkg/ghidra-specs -DREVKIT_EXTRA_LICENSES=/src/build/pkg/licenses \
          -DREVKIT_PYTHON_WHEEL=/src/build/pkg/py/revkit-$pyversion-py3-none-any.whl >/dev/null
    cmake --build build-release -j $jobs --target $targets
    # The Debian copyright file of every library the bundle carries.
    mkdir -p /src/build/pkg/licenses/debian
    for b in build-release/tools/*/rk-*; do [ -x \"\$b\" ] && ldd \"\$b\"; done | awk '/=> \\// {print \$3}' | sort -u |
      while read -r lib; do
        case \$(basename \$lib) in
          ld-linux*|libc.so*|libm.so*|libdl.so*|libpthread.so*|librt.so*|libresolv.so*|libutil.so*|libstdc++.so*|libgcc_s.so*) continue ;;
        esac
        p=\$(dpkg -S \"\$(readlink -f \$lib)\" 2>/dev/null | head -n1 | cut -d: -f1) || p=
        [ -z \"\$p\" ] && p=\$(dpkg -S \"\$lib\" 2>/dev/null | head -n1 | cut -d: -f1)
        [ -n \"\$p\" ] && cp /usr/share/doc/\$p/copyright /src/build/pkg/licenses/debian/\$p.copyright
      done
    cmake --install build-release --strip --prefix /src/build/pkg/stage/$name >/dev/null
    cd build-release && cpack -G DEB -B /src/build/pkg/deb >/dev/null
  " > "$log" 2>&1 || { tail -n 40 "$log" >&2; echo "package: native build failed; see $log" >&2; exit 1; }
  # Lay out the .deb's file name like Debian's (revkit_0.1.0_amd64.deb).
  cp "$pkg/deb/revkit_${version}_${arch}.deb" "$dist/"
elif [ ! -x "$stage/bin/rk-daemon" ]; then
  echo "package: --no-native: no staged $name (a new commit is a new version; build natively)" >&2
  exit 1
fi

# ---- TypeScript SDK -----------------------------------------------------------------------
# npm pack reads the version from package.json: set the build's for the
# pack, then put the file back.
say "TypeScript SDK (npm pack, $npmversion)"
cp sdk/ts/package.json "$pkg/ts-package.json"
trap 'cp "$pkg/ts-package.json" "$root/sdk/ts/package.json"' EXIT
(cd sdk/ts && npm pkg set "version=$npmversion" && npm pack --silent --pack-destination "$dist" >/dev/null)
cp "$pkg/ts-package.json" sdk/ts/package.json
trap - EXIT
mkdir -p "$stage/share/revkit/sdk"
cp "$dist/revkit-api-$npmversion.tgz" "$stage/share/revkit/sdk/"
# The bundle's SDKs side by side (getting-started.md installs the wheel from
# here); share/revkit/python has it too, for rk-script.
cp "$pkg/py/revkit-$pyversion-py3-none-any.whl" "$stage/share/revkit/sdk/"

# ---- the portable bundle --------------------------------------------------------------------
say "$name.tar.gz"
cat > "$stage/README.txt" <<EOF
revkit $version (git $sha), portable Linux $triple bundle

  bin/rk-daemon --no-auth --open /path/to/binary
  then open http://127.0.0.1:50052 in a browser.

Everything runs from this directory (no installation): the executables find
their libraries in lib/revkit and the web UI and Ghidra's processor specs in
share/revkit. Put bin/ on PATH if you like. Getting started:
share/doc/revkit/getting-started.md. Scripts: bin/rk-script (its first run
makes the Python environment the daemon runs scripts with, from
share/revkit/python; python3 with venv needed). Python SDK and MCP server:
pip install share/revkit/python/revkit-$pyversion-py3-none-any.whl
Third-party notices: share/doc/revkit/THIRD_PARTY_NOTICES.md.
EOF
find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
(cd "$pkg/stage" && tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -cf - "$name") \
  | gzip -n -9 > "$dist/$name.tar.gz"

# ---- desktop app ------------------------------------------------------------------------------
if [ "$desktop" = 1 ]; then
  say "desktop app (Tauri)"
  packaging/desktop/build.sh "$dist/$name.tar.gz" "$dist"
fi

(cd "$dist" && rm -f SHA256SUMS && sha256sum -- * > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS)
say "artifacts in build/dist:"
ls -l "$dist" | tail -n +2

if [ "$smoke" = 1 ]; then
  say "smoke test (Docker: ubuntu:24.04, debian:12)"
  rm -rf "$pkg/smoke-venv"
  python3 -m venv "$pkg/smoke-venv"
  "$pkg/smoke-venv/bin/pip" install -q "$dist/revkit-$pyversion-py3-none-any.whl"
  RK_SMOKE_PLATFORM=$platform packaging/linux/smoke.sh --tarball "$dist/$name.tar.gz" --deb "$dist/revkit_${version}_${arch}.deb" \
    --python "$pkg/smoke-venv/bin/python"
fi
