# External decompilers (providers)

For bytecode, a dedicated decompiler gives far better source than any
p-code route: ILSpy's C# for a .NET assembly, jadx's Java for a DEX or APK,
Vineflower's for a jar. revkit runs such a tool as a **provider**: a child
process in a sandbox, on a program's file or on a file inside a container
(a jar in an APK, a `.pyc` from a PyInstaller archive), with its output (a
source tree, or one file) cached by the input's SHA-256, the provider and
the tool's version. This is step 2 of [bytecode-lifting.md](bytecode-lifting.md#plan)
(approach c). `ProviderService` (api_minor 92, feature
`external-decompilers`), the Python SDK, MCP and the UI's decompiler pane
and file system browser show it.

- [Providers](#providers)
- [What an input is](#what-an-input-is)
- [Finding the tools](#finding-the-tools)
- [Settings](#settings)
- [The sandbox](#the-sandbox)
- [Results and the cache](#results-and-the-cache)
- [Interfaces](#interfaces)
- [Installing the tools](#installing-the-tools)
- [Tests](#tests)
- [Licences](#licences)
- [Known gaps](#known-gaps)

The code: `src/providers` (`revkit::providers`: the definitions, input
detection, the sandbox's two halves and the cache, with no dependency on
the rest of revkit but the container library), `tools/rk-sandbox` (the
helper that confines itself and runs a tool), `src/backend/providers_api.cc`
(the service: settings, inputs, responses), `ui/src/ui/external.ts` and
`ui/src/ui/sourcehl.ts` (the views and the highlighting).

## Providers

| Provider | Tool | Takes | Output | Runs on | Version from |
| --- | --- | --- | --- | --- | --- |
| `ilspy` | `ilspycmd` (ILSpy's command line, a .NET global tool) | `.NET assembly` | a C# project (tree) | .NET 8+ | `--version` |
| `jadx` | jadx | DEX, APK, jar, `.class` | `sources/` (Java) and `resources/` (tree) | Java 11+ | `--version` |
| `vineflower` | Vineflower (Fernflower's maintained fork) | `.class`, jar | Java (tree) | Java 17+ | the jar's `Implementation-Version` |
| `cfr` | CFR | `.class`, jar | Java (tree) | Java 8+ | `--version` (on stderr) |
| `unluac` | unluac | Lua 5.0 to 5.4 chunks | one `.lua` (stdout) | Java 8+ | `--version` |
| `pycdc` | pycdc (Decompyle++) | `.pyc` (1.0 to 3.13, partial past 3.10) | one `.py` (stdout) | native | the binary's hash (it has no version) |
| `webcrack` | webcrack | JavaScript (`.js`, `.mjs`, `.cjs`) | `deobfuscated.js` and the bundle's modules (tree) | Node 18+ | `--version` |
| `wasm-decompile` | WABT's wasm-decompile | WebAssembly modules | one `.dcmp` (C-like pseudo-code) | native | `--version` |

When the caller names no provider, the input's kind picks one: the first
**available** one in order of preference (jar and `.class`: Vineflower,
CFR, jadx), else the first. Every kind lists all the providers that take
it (`ListProvidersResponse.applicable`), and any of them can be chosen.
LuaJIT chunks are recognised but no provider takes them yet
(luajit-decompiler-v2 has no clear licence; [Known gaps](#known-gaps)).

The tools are run, never vendored or linked, so their licences need no
more than the note in [Licences](#licences). wasm-decompile was removed
from WABT in June 2026 (after 1.0.41); 1.0.41 is the last release with it,
and later WABT releases simply don't provide it.

A definition (`providers::Definition`) is data: the kinds, the shape of
the output, where to look for the tool (names on PATH, install locations),
the command line and the version check as templates (`{tool}`,
`{launcher}`, `{jvm}`, `{in}`, `{out}`, `{stem}`, ...), and a revision that
is part of the cache key, bumped when the command line changes. Adding a
provider is one entry in `definitions()` (and its row here); the tests add
a fake one through `Settings::extra`.

## What an input is

`providers::detect_kind` names the input from its bytes, never from its
name (except JavaScript, which only its name and its being text say). The
container detector says what the file is: its [content
kind](filesystems.md#content-kinds) (`container::Guess::content_kind`,
`src/container/bytecode.cc`), which `kind_from_format` maps to the
providers' kinds. There is one detector of these formats; the providers
add only what it can't say from a file's head:

| Kind | From the content kind | Besides |
| --- | --- | --- |
| `dotnet` | `dotnet:il`, `dotnet:mixed` (a PE's CLR header) | |
| `dex` | `dex:035` to `dex:041` (the version) | |
| `apk` | `apk` (a zip whose first members are `AndroidManifest.xml`, `classes.dex` or `resources.arsc`) | a zip with `classes*.dex` or `AndroidManifest.xml` at its root, by its central directory |
| `jar` | `jar` (first members `META-INF/MANIFEST.MF` or classes) | a zip with `.class` members or a manifest, by its central directory |
| `class` | `java-class:<Java version>` (`0xcafebabe` that isn't a universal Mach-O, a class file version and a constant pool) | |
| `pyc` | `pyc:<version>` (CPython's magic number, 2.0 to 3.16, and a code object after the header) | |
| `lua` | `lua:5.1` to `lua:5.5` (the header and its sizes) | |
| `luajit` | `luajit:2.0`, `luajit:2.1` | |
| `wasm` | `wasm` (version 1) | |
| `js` | `js-source` (a `#!` line naming node, deno or bun; a packer's script) | a `.js`, `.mjs` or `.cjs` name and text |

Extracted files carry their kind too: a PyInstaller archive's scripts are
`pyc:3.12` with their header restored, an asar's and pkg's scripts
`js-source`, a firmware image's carved chunks `lua:5.4`
([filesystems.md](filesystems.md#packed-executables)), so the providers
take them as they are. `v8-cache`, `hermes:<n>`, `jsc-bytecode` and the
others have no provider yet.

## Finding the tools

A provider is **available** when its tool is found and answers its
version check, in the sandbox (a tool is never run outside it, the check
included). In order:

1. the path configured for it (`--provider jadx=/opt/jadx/lib/jadx-1.5.6-all.jar`,
   or the settings' `providers[].path`): absolute, a file;
2. its names on the daemon's `PATH` (`ilspycmd`, `jadx`, `pycdc`, ...); a
   launcher script is followed to its jar (jadx's `bin/jadx` to
   `lib/jadx-*-all.jar`), npm's link to webcrack's `dist/cli.js`;
3. the known install locations: `~/.dotnet/tools/ilspycmd` (where `dotnet
   tool install -g` puts it), `~/.local/share/revkit-tools/<tool>/...`
   (the newest version when several are there), `/usr/share/java/<tool>.jar`,
   `/opt/<tool>/...`.

The JVM tools need `java` (the configured `java_path`, `$JAVA_HOME/bin/java`,
or `java` on PATH), webcrack `node` (`node_path`, or PATH), ilspycmd the
.NET runtime (`dotnet_root`, `$DOTNET_ROOT`, beside `dotnet` on PATH, or
`/usr/lib/dotnet`, `/usr/share/dotnet`, `~/.dotnet`). A tool that isn't
found, a jar without Java, or a failed version check leaves the provider
unavailable with the reason (`ProviderInfo.reason`: admins see it whole,
with the paths; others see only that the tool isn't available). The tools
are looked for when first asked and again when the settings change or a
caller asks (`ListProviders.refresh`).

## Settings

The daemon's settings, beside the symbol and debug-file settings, and
like them an admin's (`GetProviderSettings`, `SetProviderSettings`):

| Setting | Default | |
| --- | --- | --- |
| `enabled` | on | off: no provider runs |
| `providers[]` | none | per provider: `path` (the tool or its jar), `disabled` |
| `java_path`, `node_path`, `dotnet_root` | found | the runtimes |
| `timeout_seconds` | 120 | per run, wall clock |
| `memory_bytes` | 4 GiB | per run (see the sandbox) |
| `output_bytes`, `output_files` | 256 MiB, 50,000 | per run: the output directory and stdout together |
| `max_input_bytes` | 512 MiB | the input is copied into the run's scratch directory |
| `cache_max_bytes` | 4 GiB | the result cache, trimmed least recently used first |
| `allow_weak_sandbox` | off | run where the kernel has no Landlock (the tool's file access then isn't confined) |

On the command line: `--no-providers`, `--provider <name>=<path>`,
`--provider-off <name>` (both repeatable), `--provider-timeout <s>`,
`--provider-memory <MiB>`, `--provider-allow-weak-sandbox`. With a project
directory, `SetProviderSettings` keeps them in
`<project dir>/.revkit/providers.json`, read at startup unless any of
these flags is given (as `symbols.json` is). A setting that no longer
passes the checks is dropped.

## The sandbox

The tools parse hostile input, and some (jadx, webcrack) are large
programs on large runtimes, so each run is confined as follows. The daemon
starts `rk-sandbox` with `posix_spawn` (nothing is forked from the
daemon's threads); the helper confines itself, single-threaded, and then
executes the tool in its place:

- **Environment.** Only `PATH=/usr/bin:/bin`, `HOME` and `TMPDIR` (the
  run's own), `LANG`/`LC_ALL`, and the runtime's settings (`DOTNET_ROOT`,
  telemetry, diagnostics and W^X double mapping off, a GC heap limit; the
  JVM's heap, stack and temporary directory on its command line). Nothing
  else of the daemon's environment (tokens, `DBUS_SESSION_BUS_ADDRESS`,
  `XDG_RUNTIME_DIR`) reaches it. stdin is `/dev/null`; stdout and stderr go
  to files; every other descriptor is closed.
- **A scratch directory per run** under the cache's `tmp/`: `in/` holds a
  copy of the input (mode 0444, the directory 0555), `out/` the output,
  `home/` and `tmp/` the tool's own. It is removed after the run.
- **Landlock** (Linux 5.13+; ABI 8 on this host, kernel 7.0): the tool may
  read and execute only below `/usr`, `/lib*`, `/bin`, `/sbin`, `/etc`,
  `/proc` and `/sys` (the system's programs, libraries and configuration;
  runtimes read `/proc/self` and the cgroup files), its own install
  directory and runtime (the jar's directory, the JDK, the .NET root,
  the npm package's `node_modules`), and the input; read and write only
  `out/`, `home/` and `tmp/`; and `/dev/null`, `/dev/zero`, `/dev/full`,
  `/dev/random`, `/dev/urandom`. Everything else is refused: the project
  directory and its databases, `--browse-root`, the user's home (the
  credential file, SSH keys), other scratch directories, `/tmp`. With ABI 4
  TCP bind and connect are refused too, and with ABI 6 abstract Unix
  sockets and signals are scoped to the sandbox (the tool can't signal the
  daemon or any other process). Landlock also stops it from ptracing
  anything outside, which closes `/proc/<pid>/mem`, `environ` and the
  like of other processes.
- **seccomp** (a BPF filter the helper installs last): `socket()` is
  refused (EACCES) for every family, so there is no network and no Unix
  socket to connect to (the user's D-Bus or systemd, which could start
  processes outside); `connect()` is refused; so are `unshare`, `setns`,
  `clone` with namespace flags (and `clone3`, whose flags a filter can't
  read: ENOSYS, and libc falls back to `clone`), mounts, `keyctl` and the
  key syscalls (the session keyring), `io_uring` (which can open sockets
  past the filter), `bpf`, `perf_event_open`, `ptrace`,
  `process_vm_readv`/`writev`, `userfaultfd`, `pidfd_getfd`, module and
  kexec calls, `setsid` and `setpgid` (so nothing leaves the run's process
  group), and every system call of another ABI (x32, i386: the process is
  killed). `no_new_privs` is set first.
- **A network namespace**, empty, where the kernel lets an unprivileged
  process map its uid in a new user namespace. Ubuntu 24.04 and later
  restrict that (AppArmor's `apparmor_restrict_unprivileged_userns`), as on
  this host, where the helper's probe finds it unavailable; the seccomp
  socket rule and Landlock's TCP rule hold either way.
- **Limits**: `RLIMIT_DATA` at the memory limit (it counts the writable
  private mappings a process commits, not the address space the JVM and
  .NET reserve, so those runtimes run under it; `RLIMIT_AS` would stop
  them at start), the JVM's `-Xmx` at 60% of it and .NET's GC heap at 60%;
  `RLIMIT_CPU` at four times the timeout (a multithreaded tool spends CPU
  faster than wall time); `RLIMIT_FSIZE` at the output cap (no one file
  larger); `RLIMIT_NOFILE` 1024; no core dumps.
- **The deadline and the caps**, watched by the daemon: the output
  directory and stdout are measured every 250 ms (bytes and entries,
  links not followed), and past the timeout, the output cap or the file
  cap, or when the caller goes away, the whole process group gets SIGKILL.
  When the tool exits, whatever it left running in its group is killed
  too, before its process is reaped (so the group's id can't have been
  reused). The helper also has `PR_SET_PDEATHSIG` (SIGKILL when the
  daemon thread that started it goes).
- **The output** is read as hostile: after the run, everything below
  `out/` that isn't a regular file or a directory (links, pipes, sockets,
  devices) is deleted, names that aren't valid UTF-8 are percent-encoded,
  modes are reset (0644, 0755), and files are later read component by
  component with `O_NOFOLLOW`, only by the paths the result lists.

`rk-sandbox --probe` prints what the kernel allows (`landlock=8 seccomp=1
netns=0` here); `ListProvidersResponse.sandbox` and every result's
`sandbox` say it in words. Without Landlock a run is refused (the
provider's runs fail with `SANDBOX_ERROR` and the reason) unless an admin
sets `allow_weak_sandbox`; seccomp and the limits still apply then.

What the sandbox doesn't do: it doesn't hide what `/etc`, `/usr`, `/proc`
and `/sys` show any local user (the system's configuration, other
processes' command lines in `/proc/<pid>/cmdline`); it has no cgroup of
its own, so memory is bounded per process (a tool that forks many
processes could use that much each, within the CPU and wall-clock limits,
and the group dies at the deadline) and the number of processes isn't
bounded; and the scratch directory is on the cache's file system, so the
output cap is also the disk the run can fill. A run under a systemd slice
(as the daemon's own unit) is bounded by that slice as well.

## Results and the cache

A result is kept in `<project dir>/.revkit/providers/<sha[0:2]>/<sha>/<provider>-<key>/`
(`key`: a hash of the provider, the tool's version, the definition's
revision and the input's kind; a daemon without a project directory uses
a temporary directory for its life): `out/` (the files) and `result` (the
status, the detail, the time it took, the version, the input's kind, the
file list, the main file, the sandbox), with `stderr` (the last 4 KiB).

- **Kept**: runs that ended on their own: OK, FAILED (a non-zero exit, with
  whatever it wrote) and CRASHED (a signal). The same tool does the same on
  the same bytes, so asking again answers from the cache (`cached`), until
  the tool's version changes or `refresh` asks for a new run.
- **Not kept**: TIMEOUT, OUT_OF_MEMORY, OUTPUT_LIMIT (a larger limit may
  finish), SANDBOX_ERROR and cancelled runs.
- **One run per key at a time**: a second request for the same input and
  provider waits for the first and gets its result. At most two runs at
  once (`max_concurrent`), eight waiting, and more get RESOURCE_EXHAUSTED.
- **Trimmed** to `cache_max_bytes` after each new result, least recently
  used first (a cache hit counts as a use).

The **main file** is what the UI shows first and DecompileExternal
inlines: the one file of a one-file tool; for a tree, the first file in
the provider's language (jadx's under `sources/` first).

## Interfaces

- **API** (`proto/revkit/v1/provider.proto`, [api.md](api.md#external-decompilers)):
  `ListProviders` (every provider, the sandbox and the limits; with an
  input, what it is, which take it, the default and which are cached),
  `DecompileExternal` (runs or answers from the cache; the file list and the
  main file's text), `ReadProviderOutput` (one file of a cached result,
  paged), `GetProviderSettings` and `SetProviderSettings` (admin). An input
  is a program (`program_id`: its stored file) or a file of a file system
  session (`file`: `session_id` and the session path). A program needs a
  viewer of its project, a session file its owner, as reading them does
  ([security.md](security.md#external-decompilers)).
- **Python SDK**: `Client.providers()`, `Client.decompile_external()`
  (an `ExternalDecompilation`: `.ok`, `.status`, `.files`, `.text(path)`,
  `.read(path)`, `.sources()`), `Program.providers()`,
  `Program.decompile_external()`, `FileSystem.providers(path)`,
  `FileSystem.decompile_external(path)`, `Client.provider_settings()`,
  `Client.set_provider_settings()`.
- **MCP**: `list_providers`, `decompile_external` (the main file's text and
  the file list), `read_provider_output`; each takes a `program_id`, or a
  `session_id` from `open_filesystem` and a `path`.
- **UI** ([ui.md](ui.md#external-decompilers)): a bytecode program's
  decompiler pane shows the provider's source with syntax highlighting,
  and a bar switches to Ghidra's C; the file system browser's context menu
  has **Decompile with jadx…** (and the other providers that take the file)
  for a source tree in a dialog.

## Installing the tools

None ship with revkit. Each is the project's own release:

| Tool | Install |
| --- | --- |
| ilspycmd | `dotnet tool install -g ilspycmd` (to `~/.dotnet/tools`) |
| jadx | the release zip from github.com/skylot/jadx, unpacked so that `lib/jadx-*-all.jar` is there |
| Vineflower | `vineflower-<version>.jar` from github.com/Vineflower/vineflower (or Maven Central) |
| CFR | `cfr-<version>.jar` from Maven Central (`org.benf:cfr`) or github.com/leibnitz27/cfr |
| unluac | `unluac_<date>.jar` from sourceforge.net/projects/unluac |
| pycdc | built from github.com/zrax/pycdc (it has no releases) |
| webcrack | `npm install --ignore-scripts webcrack` (into a directory of its own) |
| wasm-decompile | WABT 1.0.41's release tarball from github.com/WebAssembly/wabt |

Configure each one's path, put it on PATH, or put it under
`~/.local/share/revkit-tools/<tool>/` where the daemon looks.

What this host's tests use (2026-10-18), each user-level under
`~/.local/share/revkit-tools/`, checked against the checksum its project
publishes:

| Tool | Version | From | Checked |
| --- | --- | --- | --- |
| ilspycmd | 11.1.0.9782 | already installed (`~/.dotnet/tools`) | |
| jadx | 1.5.6 | `jadx-1.5.6.zip`, GitHub release | SHA-256 (the release's asset digest) |
| Vineflower | 1.12.0 | `vineflower-1.12.0.jar`, GitHub release | SHA-256 (asset digest) |
| CFR | 0.152 | `cfr-0.152.jar`, Maven Central | SHA-1 (Maven Central's `.sha1`) |
| unluac | 1.2.3.569 (2025-12-23) | `unluac_2025_12_23.jar`, SourceForge | SHA-256 (SourceForge's) |
| pycdc | commit b428976 | git, at that commit; compiled with g++ inside `rk-sandbox` (its own build scripts not run) | the commit hash |
| webcrack | 2.16.0 | npm, `--ignore-scripts` (isolated-vm's prebuilt binary) | npm's integrity (SHA-512) |
| wasm-decompile | 1.0.41 | `wabt-1.0.41-linux-x64.tar.gz`, GitHub release | SHA-256 (`.sha256` file and asset digest) |
| luac (fixtures only) | 5.4.9 | `lua-5.4.9.tar.gz`, lua.org; compiled with gcc inside `rk-sandbox` | SHA-256 (lua.org's) |

## Tests

- `src/providers/tests` (`revkit_providers_tests`): the mechanism with a
  fake provider (`fake_provider.sh`, a shell script whose input picks what
  it does): a tree and a one-file output, the version check, the cache
  (again, refresh, another service over the same directory, failures
  kept, trimming), the deadline, the output cap (a large file, a large
  stdout, too many files), a crash (SIGSEGV), a failure and an out-of-memory
  report, a missing tool, a bad configured path and turned-off providers,
  concurrent requests for one input, nothing outliving the run (a child it
  left behind), and what the sandbox refuses (reading, listing and writing
  outside, writing the input, TCP and the D-Bus socket, signalling another
  process; its links and pipes dropped from the output). Input detection
  on every kind's magic and on zips made at test time. Then each real tool
  that is installed, on fixtures built at test time: ILSpy on a `dotnet new
  classlib` library, jadx, Vineflower and CFR on a jar and a `.class` from
  `javac`, pycdc on `py_compile`'s `.pyc`, wasm-decompile on a module
  written out by hand, webcrack on a minified script, unluac on a chunk
  from `luac` (run in the sandbox). A tool that isn't installed is a
  skipped test with the reason. No DEX or APK fixture: making one needs
  `d8` or `aapt2`, which this host doesn't have.
- `sdk/python/tests/test_providers.py` (`python_sdk`): the providers and the
  sandbox through the SDK; ILSpy on a .NET library imported as a program
  (the cache, every file read back, a provider that doesn't take it); a jar
  inside a zip opened as a file system with every installed JVM provider;
  MCP's three tools; the settings (a provider turned off, a timeout,
  refused settings).
- `ui/e2e/providers.ts` (`ui_e2e`): ILSpy's C# in the decompiler pane,
  highlighted, the bar switching to Ghidra's C and back, Run again, the
  project file as XML; the file system browser's Decompile with … on a jar
  in a zip (three providers offered, the files, the Java highlighted, the
  filter, nothing offered for a text file).

## Licences

Run, not vendored: these need no more than this note. Checked against each
project's repository on 2026-10-18:

| Project | Licence |
| --- | --- |
| ILSpy (ilspycmd, ICSharpCode.Decompiler) | MIT |
| jadx | Apache-2.0 |
| Vineflower | Apache-2.0 |
| CFR | MIT |
| unluac | MIT |
| pycdc (Decompyle++) | GPL-3.0 |
| webcrack | MIT |
| WABT (wasm-decompile) | Apache-2.0 |

## Known gaps

- No DEX or APK test fixture (no `d8` or `aapt2` here); jadx is tested on
  jars and `.class` files, and DEX and APK detection on bytes made in the
  test.
- LuaJIT has no provider (luajit-decompiler-v2 has no clear licence; a
  provider that runs it would still be fine, as for every tool here, but
  none is defined yet).
- The output has no addresses: nothing links a line of ILSpy's C# to the IL
  in the listing. Integration (references, search, BSim over bytecode) is
  step 3 and later of [bytecode-lifting.md](bytecode-lifting.md#plan).
- No per-run cgroup (memory is per process, the process count isn't
  bounded) and no network namespace where user namespaces are restricted
  ([The sandbox](#the-sandbox)).
- The UI has no settings dialog for the providers (the API, the SDK and
  the flags set them).
