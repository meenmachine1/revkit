#!/bin/sh
# Builds the desktop app, the Tauri shell (ui/tauri/src-tauri), as
#
#   revkit-desktop_<v>_amd64.deb       depends on the revkit package (its
#                                      /usr/bin/rk-daemon is what the app starts)
#   revkit-desktop_<v>_amd64.AppImage  self-contained: carries the portable
#                                      bundle as a resource (revkit.tar.gz), which
#                                      the app unpacks once into its data directory
#
# (ui/tauri/src-tauri/src/main.rs; docs/packaging.md). The bundle travels as
# an archive because linuxdeploy, which assembles the AppImage, would
# otherwise try to resolve its libraries against the build host's. Run by
# scripts/package.sh --desktop:
#
#   packaging/desktop/build.sh TARBALL DIST
#
# TARBALL is the portable bundle (revkit-<v>-linux-x86_64.tar.gz), DIST where
# the .deb and .AppImage go. <v> is the build's Debian version,
# $RK_DEB_VERSION (else scripts/version.sh build); the app itself carries the
# semver form, $RK_NPM_VERSION (else scripts/version.sh build npm), which Tauri
# requires, and the .deb's control file is rewritten to the Debian one (a
# semver pre-release would sort above the release in dpkg). Needs ui/dist built, Rust (cargo) and the
# WebKitGTK 4.1 development packages (docs/packaging.md). The Tauri CLI
# comes from npm (@tauri-apps/cli, pinned below) into build/pkg/tauri-cli.
# Cargo uses at most $RK_CI_JOBS (default 4) jobs.
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
tarball=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
dist=$(cd "$2" && pwd)
version=${RK_DEB_VERSION:-$("$root/scripts/version.sh" build)}
semver=${RK_NPM_VERSION:-$("$root/scripts/version.sh" build npm)}
command -v dpkg-deb >/dev/null || { echo "desktop: dpkg-deb not found" >&2; exit 1; }
cli_version=2.12.1
cli=$root/build/pkg/tauri-cli
export PATH="$HOME/.cargo/bin:$PATH"
command -v cargo >/dev/null || { echo "desktop: cargo not found (https://rustup.rs)" >&2; exit 1; }
[ -f "$root/ui/dist/index.html" ] || { echo "desktop: ui/dist missing (cd ui && npm run build)" >&2; exit 1; }

if [ ! -x "$cli/node_modules/.bin/tauri" ] || [ "$(cat "$cli/.version" 2>/dev/null)" != "$cli_version" ]; then
  rm -rf "$cli"
  mkdir -p "$cli"
  (cd "$cli" && npm init -y >/dev/null && npm install --no-audit --no-fund --loglevel=error "@tauri-apps/cli@$cli_version")
  echo "$cli_version" > "$cli/.version"
fi

# Release settings layered over tauri.conf.json (which stays the dev shell's).
common='"productName": "revkit-desktop", "mainBinaryName": "revkit-desktop", "version": "'$semver'"'
bundle='"active": true, "category": "DeveloperTool", "shortDescription": "revkit reverse-engineering workbench",
  "longDescription": "The revkit web UI in a desktop window, with its own rk-daemon (Ghidra decompiler and SLEIGH engine, the revkit API)."'
cat > "$root/build/pkg/tauri.deb.json" <<EOF
{ $common, "bundle": { $bundle, "targets": ["deb"],
  "linux": { "deb": { "section": "devel", "depends": ["revkit (= $version)", "libc6 (>= $(ldd --version | sed -n '1s/.* //p'))"] } } } }
EOF
cat > "$root/build/pkg/tauri.appimage.json" <<EOF
{ $common, "bundle": { $bundle, "targets": ["appimage"], "resources": { "$tarball": "revkit.tar.gz" } } }
EOF

cd "$root/ui/tauri/src-tauri"
rm -rf target/release/bundle   # a stale AppDir would be bundled again
export CARGO_BUILD_JOBS=${RK_CI_JOBS:-4} APPIMAGE_EXTRACT_AND_RUN=1
# No build-host paths in the binary (Rust's panic locations name the crate
# sources): the Cargo home and the source tree are mapped, as the native
# build's -ffile-prefix-map does.
cargo_home=${CARGO_HOME:-$HOME/.cargo}
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$HOME/.rustup=/rustup --remap-path-prefix=$root=/src"
"$cli/node_modules/.bin/tauri" build --config "$root/build/pkg/tauri.deb.json"
"$cli/node_modules/.bin/tauri" build --config "$root/build/pkg/tauri.appimage.json"
# Tauri names and versions the bundles by the semver form; the .deb gets
# the Debian version (so apt orders snapshots below the release), both the
# Debian file name.
deb=$(ls target/release/bundle/deb/*.deb)
appimage=$(ls target/release/bundle/appimage/*.AppImage)
repack=$root/build/pkg/desktop-deb
rm -rf "$repack"
dpkg-deb -R "$deb" "$repack"
sed -i "s/^Version: .*/Version: $version/" "$repack/DEBIAN/control"
grep -qx "Version: $version" "$repack/DEBIAN/control"
dpkg-deb --root-owner-group -Zxz --build "$repack" "$dist/revkit-desktop_${version}_amd64.deb" >/dev/null
rm -rf "$repack"
cp "$appimage" "$dist/revkit-desktop_${version}_amd64.AppImage"
# The AppImage also carries the build host's GTK and WebKitGTK stack, which
# linuxdeploy copies with each package's copyright file; list those
# packages, their versions and source packages (where their sources are).
appdir=target/release/bundle/appimage/revkit-desktop.AppDir
{
  echo "# Distribution packages whose libraries revkit-desktop_${version}_amd64.AppImage carries"
  echo "# (copied by linuxdeploy from $(. /etc/os-release && echo "$PRETTY_NAME"); copyright files in usr/share/doc)."
  echo "# package version source"
  for d in "$appdir"/usr/share/doc/*/; do
    dpkg-query -W -f='${Package} ${Version} ${source:Package}\n' "$(basename "$d")" 2>/dev/null || true
  done | sort -u
} > "$dist/revkit-desktop_${version}_amd64.AppImage.packages.txt"
echo "desktop: revkit-desktop_${version}_amd64.deb and .AppImage in $dist"
