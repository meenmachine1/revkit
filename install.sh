#!/bin/sh
# Installs revkit for this user, no root needed:
#
#   curl -fsSL https://raw.githubusercontent.com/meenmachine1/revkit/main/install.sh | sh
#
# It downloads the latest release's portable bundle for this machine (Linux
# x86-64 or aarch64), checks it against the release's SHA256SUMS, unpacks it
# into ~/.local/share/revkit and puts the revkit command (and the rk-* tools)
# in ~/.local/bin. Run it again to update. Then: revkit
#
# Where the system is older than the build needs (glibc 2.34 and GCC 12's
# C++ runtime: Ubuntu 22.04, Debian 12; Ubuntu 20.04 is older) and Docker is
# there, the revkit command runs the server in a Debian 12 container instead.
#
# Environment: REVKIT_VERSION (a release tag, default the latest),
# REVKIT_PREFIX (default ~/.local), REVKIT_DOCKER=1 (Docker mode even where
# the bundle runs natively), REVKIT_RELEASES (where release files are
# fetched from; a directory works too, for testing), REVKIT_LAUNCHER (where
# the revkit command is fetched from for a release without it).
set -eu

repo=meenmachine1/revkit
prefix=${REVKIT_PREFIX:-$HOME/.local}
share=$prefix/share/revkit
bindir=$prefix/bin

say() { printf 'revkit install: %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }

fetch() {  # fetch URL-or-path TO
  case $1 in
    /*) cp "$1" "$2" ;;
    *)
      if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 -o "$2" "$1"
      elif command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1"
      else die "needs curl or wget"
      fi ;;
  esac
}

[ "$(uname -s)" = Linux ] || die "revkit's builds are for Linux (on a Mac, run it in a Linux VM)"
case $(uname -m) in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) die "no build for $(uname -m): build from source (README, 'Building from source')" ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# The release: REVKIT_VERSION, else the latest.
tag=${REVKIT_VERSION:-}
if [ -z "$tag" ]; then
  fetch "https://api.github.com/repos/$repo/releases/latest" "$tmp/latest.json" ||
    die "couldn't ask GitHub for the latest release"
  tag=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp/latest.json" | head -n 1)
  [ -n "$tag" ] || die "couldn't read the latest release's tag"
fi
version=${tag#v}
releases=${REVKIT_RELEASES:-https://github.com/$repo/releases/download/$tag}
name=revkit-$version-linux-$arch
say "revkit $version for Linux $arch"

fetch "$releases/SHA256SUMS" "$tmp/SHA256SUMS" || die "couldn't download $releases/SHA256SUMS"
fetch "$releases/$name.tar.gz" "$tmp/$name.tar.gz" || die "couldn't download $releases/$name.tar.gz"
want=$(grep " $name.tar.gz\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
[ -n "$want" ] || die "$name.tar.gz is not in the release's SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1)
else got=$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d' ' -f1)
fi
[ "$got" = "$want" ] || die "$name.tar.gz doesn't match its checksum: not installed"

mkdir -p "$share/releases" "$bindir"
rm -rf "$share/releases/$name.new"
mkdir -p "$share/releases/$name.new"
tar -xzf "$tmp/$name.tar.gz" -C "$share/releases/$name.new"
rm -rf "$share/releases/$name"
mv "$share/releases/$name.new/$name" "$share/releases/$name"
rm -rf "$share/releases/$name.new"
dir=$share/releases/$name

# The revkit command: in the bundle from 0.1.1 on; for an older release,
# from the repository.
if [ ! -x "$dir/bin/revkit" ]; then
  fetch "${REVKIT_LAUNCHER:-https://raw.githubusercontent.com/$repo/main/packaging/revkit}" "$dir/bin/revkit" ||
    die "couldn't download the revkit command"
  chmod +x "$dir/bin/revkit"
fi
ln -sfn "$dir" "$share/current"

# Native, or Docker where this system's C library is too old for the build.
config=${XDG_CONFIG_HOME:-$HOME/.config}/revkit
mkdir -p "$config"
mode=native
if [ "${REVKIT_DOCKER:-}" = 1 ] || ! "$dir/bin/rk-daemon" --version >/dev/null 2>"$tmp/native.err"; then
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    mode=docker
  else
    say "this system can't run the build natively:"
    sed 's/^/  /' "$tmp/native.err" >&2
    die "it needs glibc 2.34 and GCC 12's C++ runtime or newer (Ubuntu 22.04, Debian 12, Fedora 36 and later), or Docker (then run this again)"
  fi
fi
if [ "$mode" = docker ]; then
  printf 'mode=docker\nbundle=%s\n' "$share/current" >"$config/launcher.conf"
  say "this system's C library is older than the build's: the revkit command runs the server in Docker (Debian 12)"
  docker pull -q debian:12 >/dev/null || say "couldn't pull debian:12 yet: 'revkit' will try again"
else
  rm -f "$config/launcher.conf"
fi

# The commands, on PATH.
ln -sfn "$share/current/bin/revkit" "$bindir/revkit"
if [ "$mode" = native ]; then
  for t in "$share/current/bin"/rk-*; do
    [ -x "$t" ] && ln -sfn "$share/current/bin/$(basename "$t")" "$bindir/$(basename "$t")"
  done
fi

# Older releases go.
for old in "$share/releases"/revkit-*; do
  [ "$old" = "$dir" ] || rm -rf "$old"
done

say "installed revkit $version in $dir"
case ":$PATH:" in
  *":$bindir:"*) say "run: revkit   (revkit --help for more)" ;;
  *) say "add $bindir to your PATH, e.g.: echo 'export PATH=\"$bindir:\$PATH\"' >> ~/.profile"
     say "then run: revkit" ;;
esac
