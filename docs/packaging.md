# Packaging and releases

How revkit is versioned, built for release and packaged, and what the
packages carry. For users: [getting-started.md](getting-started.md).

## Version

`VERSION` at the source root is the version (0.1.0). It reaches:

- every executable's `--version` (`rk-daemon 0.1.0 (git 5d8b4233ac85)`)
  and `GetServerInfo.server_version`, through `revkit::runtime`
  (`src/runtime`; `cmake/build_info.cmake` writes the version and the git
  commit into a generated header, rewritten only when they change); a
  package build reports its build version instead (below), passed as
  `-DREVKIT_BUILD_VERSION`;
- the web UI's About box (palette: "About revkit"), through `define` in
  `ui/vite.config.ts` (`REVKIT_BUILD_VERSION` in a package build);
- the package manifests that need a literal copy, kept equal by
  `scripts/version.sh`: `sdk/python/revkit/__init__.py` (which
  `pyproject.toml` reads), `sdk/ts/package.json`, `ui/package.json`, their
  lockfiles, and the Tauri shell's `Cargo.toml` (which `tauri.conf.json`
  reads) and `Cargo.lock`.

```sh
scripts/version.sh              # 0.1.0
scripts/version.sh check        # every copy agrees (scripts/ci.sh --package runs it)
scripts/version.sh set 0.2.0    # a release: writes VERSION and every copy
```

The API's own version (`api_major`, `api_minor`, [api.md](api.md)) is
separate and unaffected.

### Build versions

Packages built between releases must differ, or apt can't tell one build
from the next and won't upgrade. `scripts/package.sh` therefore versions
every artifact with `scripts/version.sh build`:

- the commit tagged `v<VERSION>` (`v0.1.0`), or any build with
  `REVKIT_VERSION=X.Y.Z` in the environment, is the release: plain `0.1.0`
  everywhere;
- any other commit is a snapshot of the coming release, stamped with the
  commit's time (committer date, UTC, to the second, so two commits on one
  day still order) and its hash. Pre-release tags such as `v0.1.0-pre.2`
  are snapshots too: the published pre-releases' packages are snapshot
  packages, and the release still upgrades them.

| Where | Form | Example (commit 431366830e06, 2026-10-08 00:30:44 UTC) |
| --- | --- | --- |
| `.deb`s (`revkit`, `revkit-desktop` and its `Depends`), the bundle and AppImage names, `--version`, `server_version`, the About box | Debian, `~` sorts below the release | `0.1.0~git20261008003044.431366830e06` |
| wheel, sdist, `revkit.__version__` | PEP 440 developmental release with a local label | `0.1.0.dev20261008003044+g431366830e06` |
| npm package, the desktop app's own (Tauri) version | semver pre-release; the `g` keeps an all-digit hash a valid identifier | `0.1.0-git.20261008003044.g431366830e06` |

In each scheme a later commit's version sorts above an earlier one's, and
every snapshot sorts below the plain `0.1.0`
(`dpkg --compare-versions 0.1.0~git20261008003044.431366830e06 lt 0.1.0`).
A tree with uncommitted changes to tracked files appends `.dirty`
(`+g<hash>.dirty` for Python). Without git (a source archive) the build is
the plain version. `scripts/version-test.sh` checks all of this in a
scratch repository (ctest `version_build`; `scripts/ci.sh --package`).

```sh
scripts/version.sh build          # 0.1.0~git20261008003044.431366830e06
scripts/version.sh build python   # 0.1.0.dev20261008003044+g431366830e06
scripts/version.sh build npm      # 0.1.0-git.20261008003044.g431366830e06
REVKIT_VERSION=0.1.0 scripts/package.sh   # a release build without the tag
```

The committed manifests keep the plain `VERSION`: `scripts/package.sh`
builds the Python packages from a copy of `sdk/python` with the build's
`__version__`, sets `sdk/ts/package.json`'s version only for `npm pack`
(and puts the file back), and gives the Tauri CLI the semver form as a
config override. Tauri writes that semver into the desktop `.deb`'s control
file, where `0.1.0-git…` would read as upstream `0.1.0` with a Debian
revision, above the release, so `packaging/desktop/build.sh` repacks the
`.deb` with the Debian version (`dpkg-deb`). The AppImage unpacks its
bundle into a directory named after the app's version, so each build gets
its own.

To upgrade an installed snapshot to a later build:

```sh
cd build/dist && sudo apt install ./revkit_*_amd64.deb ./revkit-desktop_*_amd64.deb
```

Packages built before build versions (up to `v0.1.0-pre.1`) say plain
`0.1.0`, which is above every snapshot, so moving from one of those to a
snapshot is a downgrade to apt, once: add `--allow-downgrades` (with `-y`,
apt refuses without it).

## Release build

The `release` CMake preset (`build-release/`) is what packages are built
from:

| Setting | Why |
| --- | --- |
| `CMAKE_BUILD_TYPE=Release` | optimized, no assertions |
| `REVKIT_BUILD_TESTS=OFF` | no GoogleTest, no test executables |
| `REVKIT_REPRODUCIBLE=ON` | `-ffile-prefix-map` maps the source and build directories to `.` and `build`, and the build id is a hash of the contents, so the binaries don't depend on where they were built |
| `REVKIT_BUNDLE_LIBS=ON` | `cmake --install` copies every shared library the executables need, except glibc and the C++ runtime, into `lib/revkit/` (`install(RUNTIME_DEPENDENCY_SET)`) |
| `GHIDRA_ROOT=""` | no build-host path baked in as the default Ghidra |

Executables are linked with an RPATH of `$ORIGIN/../lib/revkit`, as
`DT_RPATH` (`--disable-new-dtags`) so that it also applies to the bundled
libraries' own dependencies, and find `share/revkit` (the web UI, the
Ghidra specs) relative to themselves, so an installed tree runs from any
directory. `rk-daemon` starts its decompiler workers from `rk-decompd`
beside it, and its external decompilers through `rk-sandbox` beside it
([providers.md](providers.md)).

`scripts/package.sh` builds the preset in Docker on Debian 12
(`packaging/linux/build.Dockerfile`: GCC 12, CMake 3.25, the system gRPC
1.51 and protobuf 3.21), so the binaries need glibc 2.34 or newer (the
newest symbol version they use) and GCC 12's libstdc++ (`GLIBCXX_3.4.30`),
and nothing else from the host: Ubuntu 22.04, Debian 12, Fedora 36 and
later (checked in an Ubuntu 22.04 container). Ubuntu 24.04's toolchain would
need 2.39.
The archives are reproducible from the same commit: file times are the
commit's (`SOURCE_DATE_EPOCH`), entries are sorted and owned by root, and
gzip stores no name or time.

**LTO is off.** The preset builds and runs with
`-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON` (GCC 12, about 25% longer
builds), but GCC's link-time ODR check then reports that Ghidra's bison
parsers each define a different `union yyalloc` (`xml.cc` and the SLEIGH
and C grammars), an upstream one-definition-rule violation that is only
harmless while the parsers are compiled separately; and
`-Walloc-size-larger-than` fires in Ghidra's `prettyprint.cc`. That isn't
clean, and the decompiler, which dominates run time, gains little, so
releases leave LTO off. Turning it on caps LTO links at two at a time with
four LTRANS jobs each (`CMakeLists.txt`).

## Ghidra processor specs

revkit reads Ghidra's processor specifications at run time; where tools
look for them is in [getting-started.md](getting-started.md#ghidra-processor-specs)
(`revkit::runtime::locate_ghidra`). The packages carry a trimmed copy in
`share/revkit/ghidra`, made by:

```sh
scripts/gather-ghidra-specs.sh --ghidra ~/ghidra/ghidra_12.1.4_PUBLIC build/pkg/ghidra-specs
# gather-ghidra-specs: Ghidra 12.1.4 -> build/pkg/ghidra-specs (137 .sla files, 34M)
scripts/gather-ghidra-specs.sh --processors x86,AARCH64,ARM out    # only some processors
```

It copies, unmodified, each processor's compiled `.sla`, `.ldefs`,
`.pspec`, `.cspec`, `.opinion` and `.dwarf` files and function-start
patterns, the four C library type archives (`generic_clib*.gdt`,
`windows_vs12_*.gdt`) and the string model from the Base module, and
`application.properties`, with Ghidra's `LICENSE` (Apache-2.0), every
copied module's `LICENSE.txt`, a `NOTICE` saying what was copied from
which release, and `SHA256SUMS`. None of the copied files is listed as
third-party in Ghidra's module license files. SLEIGH sources, manuals,
Java code and Ghidra's GPL-licensed parts are left out.

## Packages

```sh
scripts/package.sh                  # Linux bundle, .deb, Python and TypeScript SDKs
scripts/package.sh --desktop        # and the desktop app
scripts/package.sh --smoke          # and the clean-container smoke test
```

Everything lands in `build/dist/` (never committed), with `SHA256SUMS`; a
native build empties it first, so it holds one build's artifacts. `<v>`
below is the [build version](#build-versions): `0.1.0` for the release,
`0.1.0~git…` (wheel: `0.1.0.dev…+g…`, npm: `0.1.0-git.….g…`) between
releases.
The script needs Docker, Node 22+, Python 3.10+ and git; `--desktop` also
needs Rust and the Tauri system packages below. It uses at most
`$RK_CI_JOBS` (default 4) build jobs.

| Artifact | Size | What |
| --- | --- | --- |
| `revkit-<v>-linux-x86_64.tar.gz` | 83 MB (168 MB unpacked) | portable bundle: `bin/` (the executables and `rk-script`), `lib/revkit/` (gRPC, protobuf, Abseil, OpenSSL, c-ares, RE2, zlib, liblzma, libbz2), `share/revkit/{ui,ghidra,typeinfo,processors,plugins,scripts,python,sdk}`, `share/doc/revkit` (README, getting started, notices, license texts), `README.txt` |
| `revkit_<v>_amd64.deb` | 83 MB | the same tree under `/usr` (CPack), plus the systemd user units ([below](#start-the-daemon-on-first-use-systemd-socket-activation)); depends on `libc6 (>= 2.36)` and `libstdc++6 (>= 12)` only, and recommends `python3 (>= 3.10)` and `python3-venv` for scripts ([below](#scripts-and-python)) |
| `revkit-<v>-py3-none-any.whl`, `revkit-<v>.tar.gz` | 165 KB | the Python SDK and MCP server (`pip install`; pulls `grpcio` and `protobuf`) |
| `revkit-api-<v>.tgz` | 113 KB | the TypeScript SDK (`npm install`): ES modules and `.d.ts` built by `sdk/ts/build.mjs` (esbuild and tsc) when `npm pack` runs |
| `revkit-desktop_<v>_amd64.deb` | 4 MB | the desktop app; depends on `revkit (= <v>)` and WebKitGTK 4.1 |
| `revkit-desktop_<v>_amd64.AppImage` | 160 MB | the desktop app with the portable bundle inside, and the build host's GTK and WebKitGTK libraries (listed with their source packages in `….AppImage.packages.txt`) |

Executables in the bundle: `rk-daemon`, `rk-decompd`, `rk-sandbox`, `rk-lift`,
`rk-decomp`, `rk-emu`, `rk-dbg`, `rk-diff`, `rk-infer`, `rk-debuginfo`,
`rk-cparse`, `rk-bsim`, and `rk-script` (a shell script).
Measurement and development tools (`rk-backend-bench`, `rk-factbench`,
`rk-sigdiff`, Ghidra's `decomp_dbg`) stay in the source build. The
wheel is in `share/revkit/python/` (bundle and `.deb`); the bundle's
`share/revkit/sdk/` has it too, with the npm package, the C plugin SDK
and the example plugins' sources.

### Scripts and Python

The packages carry the library type archives (`share/revkit/typeinfo`:
glibc's and the Windows API's prototypes, made by the build from the
build host's glibc and mingw-w64 headers: the release build container
(`packaging/linux/build.Dockerfile`) installs `mingw-w64-x86-64-dev` and
`mingw-w64-i686-dev` beside `libc6-dev`;
[types.md](types.md#library-prototypes)), the starter scripts (`share/revkit/scripts`), the
Python SDK's wheel (`share/revkit/python`, built before the native build
and installed by CMake: `REVKIT_PYTHON_WHEEL`) and `bin/rk-script`
(`packaging/linux/rk-script`), which runs the SDK's `rk-script` from
`~/.local/share/revkit/pyenv`, the environment the daemon runs scripts
with. Its first run makes that environment from the wheel (`python3 -m
venv`, then `pip install`, which fetches `grpcio` and `protobuf`), and a
newer wheel after an upgrade is installed on the next run
([scripting.md](scripting.md#rk-script)); the Script Manager's **Set up
Python** does the same through the daemon. Python stays out of `Depends`:
the daemon, the CLIs and the web UI don't need it, so the `.deb` keeps its
promise of depending on the C and C++ runtimes only and *recommends*
`python3 (>= 3.10)` and `python3-venv` (apt installs recommended packages
by default; `--no-install-recommends` leaves them out, and `rk-script`
then says what to install).

### Start the daemon on first use (systemd socket activation)

A browser can't start a program, and the daemon is what serves the web UI,
so with nothing running `http://revkit.localhost:50052/` just fails. The `.deb`
ships two **systemd user units** that fix that, off until you turn them on:

```sh
rk-daemon user add "$USER" --role admin --project-dir ~/.local/share/revkit/projects   # once
systemctl --user enable --now revkit-daemon.socket
# open http://revkit.localhost:50052/ : the first connection starts rk-daemon
```

- `/usr/lib/systemd/user/revkit-daemon.socket` (`packaging/linux/systemd/`):
  systemd listens on `127.0.0.1:50052` (`ListenStream=`,
  `FileDescriptorName=http`). Enabling it starts no daemon.
- `/usr/lib/systemd/user/revkit-daemon.service`: started by the socket on
  the first connection, `rk-daemon --project-dir
  ~/.local/share/revkit/projects --browse-root ~ --grpc 127.0.0.1:50051`.
  The connection that started it waits in the socket's queue and is
  answered as soon as the daemon is up. `Restart=on-failure`; after it
  stops (`systemctl --user stop revkit-daemon.service`, a crash), the next
  connection starts it again, so the UI's **Reconnect** is all it takes.
- **Restart daemon** (the status chip's popover, `MetaService.RestartDaemon`):
  a socket-activated daemon doesn't run itself again. It shuts down
  gracefully and exits 0; systemd keeps the socket listening, and the
  page's next call (it probes twice a second while restarting) starts the
  service again. A clean exit isn't a failure, so `Restart=on-failure`
  doesn't fire and the unit isn't marked failed. A daemon started any
  other way re-executes itself in the same process ([ui.md](ui.md#restart-daemon)).
- **Authentication is on**, as for any `rk-daemon` without `--no-auth`
  ([security.md](security.md#socket-activation)): make the account first
  (the command above). The credential file is
  `~/.local/share/revkit/projects/.revkit/auth.db`.
- **Another port or other flags**: `systemctl --user edit
  revkit-daemon.socket` (an empty `ListenStream=` and then the new one)
  or `revkit-daemon.service` (an empty `ExecStart=`, then yours). Keep the
  socket on loopback; off loopback the daemon refuses to start without
  TLS, exactly as with `--http`.
- **Off again**: `systemctl --user disable --now revkit-daemon.socket
  revkit-daemon.service`.
- The socket listens on `127.0.0.1` only (rk-daemon takes one inherited
  socket); a browser that tries `::1` for `revkit.localhost` first is
  refused at once and uses `127.0.0.1`.
- **Port 80**: `revkit-http80.socket`, a system unit, also off until
  enabled, gives `http://revkit.localhost/` without a port
  ([getting-started.md](getting-started.md#a-port-free-name-httprevkitlocalhost)).
- The portable bundle carries the same files under `lib/systemd/user/`
  for reference; they run `/usr/bin/rk-daemon`, so copy them to
  `~/.config/systemd/user/` with `ExecStart=` pointing at the bundle.

`rk-daemon` takes the socket with systemd's protocol (`LISTEN_PID`,
`LISTEN_FDS`, `LISTEN_FDNAMES`; `sd_listen_fds(3)`), implemented in
`src/api/listen_fds.cc` without libsystemd: it must be one listening TCP
socket, it becomes the HTTP listener in place of `--http`, the variables
are cleared and the descriptor is close-on-exec so no child process takes
it, and stopping the daemon closes only its own copy (never `shutdown()`,
which would end systemd's too). An inherited socket named `grpc` is
refused: gRPC binds its own address when the daemon starts.
`GetServerInfo.socket_activated` tells clients (the UI then offers
`systemctl --user start revkit-daemon.service` as the start command).
Tests: `ListenFds.*` in `revkit_api_tests` (the protocol in a child
process, serving and refusing an inherited socket, a second daemon
answering a client that arrived while none ran) and
`daemon_socket_activation` (`tools/rk-daemon/socket_activation_test.py`:
the real `rk-daemon` started the way systemd starts it, with a client
already waiting). Checked by hand against systemd 255 with a transient
`systemd-run --user --socket-property=ListenStream=...` unit: the first
connection starts the service, and after `systemctl --user stop` the next
one starts it again.

### Smoke test on clean distributions

`packaging/linux/smoke.sh` (run by `scripts/package.sh --smoke` and
`scripts/ci.sh --package`) takes `ubuntu:24.04` and `debian:12` images as
they come, nothing installed (no compiler, Python, curl or Node), and in
each:

1. unpacks the tarball under `/opt`; every executable prints its version
   and `ldd` finds every library;
2. `rk-decomp` decompiles a test program's function (compiled on the
   host) and `rk-lift --analyze --decompile` decompiles the image's own
   `/bin/ls` (over 50 functions required), with the bundled specs;
3. checks the message for a missing Ghidra;
4. runs `rk-daemon --no-auth` (host network, loopback) on both binaries;
   from the host, the Python SDK (the wheel, in a fresh venv) lists and
   decompiles, and headless Chrome opens the web UI the daemon serves,
   goes to a function from the palette, sees it decompiled and reads both
   versions in the About box (`packaging/linux/ui-smoke.mjs`);
5. runs `rk-daemon` with an account, an API token and a self-signed TLS
   certificate; the SDK connects with the token and the pinned
   fingerprint;
6. installs the `.deb` with `apt-get install ./revkit_<v>_amd64.deb` in a
   second clean container and decompiles from `/usr/bin`; `rk-script`
   there, with no Python, says what to install, and once apt has installed
   `python3` and `python3-venv` (when the container reaches the archive),
   makes its environment from the shipped wheel, lists the starters and
   runs one on a program with a throwaway daemon.

`scripts/getting-started-check.sh` runs the commands of
[getting-started.md](getting-started.md) against the bundle (in a
temporary `HOME`, on ports 51040 to 51049).

### Desktop app

`packaging/desktop/build.sh` (run by `scripts/package.sh --desktop`)
builds the Tauri shell with the Tauri CLI from npm (`@tauri-apps/cli`,
pinned, installed into `build/pkg/tauri-cli`) and release settings layered
over `ui/tauri/src-tauri/tauri.conf.json`, which stays the development
shell's. The shell starts its own `rk-daemon` unless told to use another
(`ui/tauri/src-tauri/src/main.rs`,
[getting-started.md](getting-started.md#the-desktop-app)), and starts,
stops and restarts it from the UI's daemon status chip
([ui.md](ui.md#daemon-status)):

- the `.deb` depends on the `revkit` package and starts `/usr/bin/rk-daemon`;
- the AppImage carries the portable bundle as one resource,
  `revkit.tar.gz`, and unpacks it into
  `~/.local/share/dev.revkit.ui/runtime/` on first start (about two
  seconds); linuxdeploy, which assembles AppImages, would otherwise try to
  resolve the bundle's private libraries against the build host's.

The shell is compiled with `--remap-path-prefix` for the Cargo home and
the source tree, so the binary names no build-host paths.

Build requirements (Ubuntu 24.04 names): Rust (rustup), and
`libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev
libjavascriptcoregtk-4.1-dev librsvg2-dev`, plus `file` for the AppImage
step. The app is built on the host, so the desktop artifacts need the
host's glibc (2.39 on Ubuntu 24.04) and its WebKitGTK 4.1 at run time;
the daemon inside the AppImage is the Debian 12 build.

## Third-party notices

`THIRD_PARTY_NOTICES.md` lists every dependency that is vendored
(`third_party/`), fetched (`FetchContent`: LMDB, cpp-httplib, wasmtime,
GoogleTest), linked from the system and bundled (gRPC, protobuf, Abseil,
OpenSSL, c-ares, RE2, zlib, liblzma, libbz2), read at run time (Ghidra's specs) or bundled
into the web UI (npm), with the license obligations. Its npm, Python,
Tauri and wasmtime sections are generated:

```sh
python3 scripts/third-party-notices.py                         # npm, Python (fresh venv), Tauri crates
python3 scripts/third-party-notices.py --sections wasmtime --wasmtime-src ~/src/wasmtime-49.0.2
python3 scripts/third-party-notices.py --sections npm --check  # scripts/package.sh runs this
```

`scripts/package.sh` puts the license texts in `share/doc/revkit/licenses/`:
Ghidra's and LLVM's Apache-2.0 files, LMDB's, cpp-httplib's and
wasmtime's, the npm packages' own `LICENSE` files (`npm/`) and the
Debian copyright file of every bundled system library (`debian/`).

## CI

`scripts/ci.sh --package` runs `scripts/version.sh check`, then
`scripts/package.sh --smoke` (skipped, with a message, when Docker isn't
available). It takes about 20 minutes from a clean `build-release/` with
four jobs (the native build is most of it) and a few minutes when the
native build is up to date, so it is not part of the default run;
`scripts/ci.sh --package-only` runs just this check.
