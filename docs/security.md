# Security: authentication, authorization and TLS

`rk-daemon` serves everything a client can do (read binaries and their
annotations, edit, import files from the host, browse host directories,
run plugins, replicate projects) on two listeners: gRPC for native clients
and an HTTP gateway (Connect, gRPC-web and the web UI) for browsers. This
page says who may do what, how the daemon checks it, and how to set it up.

- [Threat model](#threat-model)
- [The model](#the-model)
- [What is enforced where](#what-is-enforced-where)
- [Setup](#setup)
- [Serving over Tailscale with authentication and TLS](#serving-over-tailscale-with-authentication-and-tls)
- [Clients](#clients)
- [Peers](#peers)
- [Limits and known gaps](#limits-and-known-gaps)
- [Tests](#tests)

## Threat model

**What is worth protecting.**
- The programs under analysis: often proprietary or sensitive, and
  `ReadMemory` returns their bytes.
- The annotations: names, types and comments are work, and their
  provenance (who said what) is what reviewers and reverts rely on.
- The host: `ImportProgram` reads a host path, `OpenProject` opens a host
  directory, `--browse-root` lists host directories, `AttachFidDatabase`
  reads and `CreateFidDatabase` writes a Function ID database at a host
  path, `AttachBSimDatabase` and `CreateBSimDatabase` with a path read and
  write a BSim database there, and command plugins may hold the `file`
  grant. External decompilers ([providers.md](providers.md)) run third-party
  tools on hostile input on the daemon's host, in a sandbox.
- Credentials: passwords, session and API tokens, peer secrets.

**Who the daemon defends against.**
- *Someone on the network path* (coffee-shop Wi-Fi, a shared LAN): reads or
  rewrites traffic. TLS on both listeners, and no plaintext listener off
  loopback unless explicitly allowed.
- *An unauthenticated client* that can reach a port: every RPC except
  `GetServerInfo`, `Login` and `WhoAmI` needs credentials.
- *An authenticated user beyond their role*: a viewer editing, an editor
  importing or browsing the host, anyone but a peer replicating, a user
  outside a project's access list.
- *A user or agent claiming to be someone else*: the server stamps the
  authenticated identity on provenance and refuses mismatches, so blame
  and `RevertByProvenance` can be trusted.
- *A malicious web page in the user's browser* (CSRF, cross-site
  requests riding the session cookie): SameSite=Strict, an Origin check and
  a per-session CSRF token; the cookie is HttpOnly so page scripts (and an
  XSS) can't read it.
- *A web page rebinding its own name to this host* (DNS rebinding): the
  HTTP listener answers only requests whose `Host` names it (below), so
  such a page can't reach a `--no-auth` daemon as an anonymous admin.
- *Password guessing*: scrypt hashes, and per-address and per-account
  login delays.
- *A stolen credential file*: it holds only hashes (scrypt for passwords,
  SHA-256 for 256-bit random tokens).
- *A rogue daemon*: a peer must present a peer token (or the shared peer
  secret); the linking daemon checks the peer's certificate.

**Out of scope.**
- The host itself and whoever administers it: the credential file, the
  TLS key and the project directory are protected by file permissions
  (0600/0700) only.
- Hostile input binaries attacking the loaders or the decompiler (that is
  the job of bounds-checked parsers, decompiler worker processes and,
  later, fuzzing), hostile plugins beyond their sandbox
  ([plugins.md](plugins.md)), and an external decompiler exploited by its
  input beyond the provider sandbox ([below](#external-decompilers)).
- Peers are trusted with data: a daemon holding a peer credential can push
  any op with any provenance, as replication requires
  ([collab.md](collab.md)). Give peer credentials only to daemons you run.
- Admins are trusted: they import, browse the host, and manage accounts.
- Denial of service beyond login throttling (an authenticated client can
  still ask for expensive decompilations).

## The model

### Identities

| Principal | How it authenticates | Provenance the server stamps |
| --- | --- | --- |
| A local **account** | `Login` (name and password) gives a session token: a bearer token for native clients, an HttpOnly cookie for the browser | `user:<account>` |
| An **API token** for a script or an agent | `rk-daemon token create --name N --role R`; sent as `authorization: Bearer rkt_...` | `agent:<token name>` |
| A token **issued to an account** (`--user alice`) | the same, for a user's scripts | `user:<account>`, never above the account's role or projects |
| A **peer** daemon | a token with role `peer`, or the shared `--peer-secret-file` | none: peers replicate other people's ops |
| **Anonymous** (`--no-auth`) | nothing | none (clients' provenance is kept, as before) |

Accounts have a role and an optional project list. Passwords are hashed
with scrypt (N = 2^17, r = 8, p = 1: OWASP's recommendation; 128 MiB and
about 0.3 s per hash, at most two at a time), stored as
`$scrypt$ln=17,r=8,p=1$<salt>$<hash>` so the parameters can be raised later
(a login re-hashes an older hash).

**Why scrypt from OpenSSL.** rk-daemon already depends on OpenSSL for TLS
(and the gRPC packages link it), so `EVP_PBE_scrypt` adds no dependency and
gets the distribution's security updates. scrypt is memory-hard and on
OWASP's list next to Argon2id. Argon2id would need libsodium
(`libsodium-dev`, not installed here) or OpenSSL 3.2 (Ubuntu 24.04 ships
3.0); the hash format names its algorithm, so switching later only needs a
verifier for `$argon2id$` and the re-hash on login.

**Sessions** are opaque: `rks_` and 256 random bits. The daemon stores
their SHA-256, the account, an expiry (`--session-ttl`, default 7 days) and
a CSRF token. They end at logout, at expiry, when the account's password
or role changes, and when the account is deleted; they survive a daemon
restart. **API tokens** are `rkt_<id>_` and 256 random bits; the id is
public (it is how `token list` and `token revoke` name them), the daemon
keeps the SHA-256 of the whole secret and compares it in constant time.
Tokens may expire (`--ttl-days`) and are revoked by id or name.

### Roles

| Role | May |
| --- | --- |
| `viewer` | read: projects and programs, listings, decompilation, xrefs, types, history and blame, subscriptions, presence, plugin facts, parsing pasted C (`ParseC`), exporting a project archive as a download (`ExportProject`) |
| `editor` | also edit: append and retract assertions, revert by provenance, rename programs, create, rename, move and delete (empty) folders, run command plugins, start and cancel analysis, create and drive emulator sessions |
| `admin` | also import and delete programs (by path or upload; deleting is soft, and restoring it is a retraction, which an editor may make), import project archives and upload them (`ImportProjectArchive`, `UploadChunk`), export an archive to a host path, list host files under `--browse-root`, parse C headers from host files under `--browse-root` (`ParseC` with a path or an include directory), open projects by host path, close projects, manage accounts and tokens |
| `peer` | `SyncService` only (replication of every project); nothing else |

The full table is `src/api/auth_policy.cc`; a method without an entry is
refused to everyone, and `AuthPolicyUnit.EveryMethodHasAPolicy` fails until
a new RPC gets one.

**Import progress** (`GetImportProgress`, api_minor 22) needs what
`ImportProgram` needs (admin of the project), and answers only the
identity that started the import: anyone else, admins included, gets
`NOT_FOUND`, so an import's file name and progress don't leak between
accounts. Without authentication every caller is `anonymous` and the
client's random `import_id` keeps imports apart.

**Parsing C** (`TypeService.ParseC`, api_minor 25, [cparse.md](cparse.md))
reads the program's types (viewer) and parses what the caller sends; with
a host path among its sources or include directories it reads the
daemon's files, which needs admin and `--browse-root`: every path and
every `#include` is canonicalized (symlinks, `..`) and must lie under a
root. The parse of untrusted text is bounded in bytes, files, include
depth, macro expansion, tokens, nesting, types and time, and fuzzed
(`cparse_fuzzer`). The SDKs import with `import:header` provenance, which
the server accepts from admins only; an editor imports as itself
(`actor=None`, or `provenance: {}` in TypeScript).
**Raw layout detection** (`DetectRawLayout`, `GetRawDetectProgress`,
`CancelRawDetect`, api_minor 23) reads a host path or an upload and runs
every language's decoder on it, so it needs what `ImportProgram` needs
(admin of the project); its progress and stopping it answer only the
identity that started it, as for imports. It is bounded so that one
caller can't take the daemon: paths must be regular files of at most
1 GiB, uploads fit `max_request_bytes`, two run at a time with eight
more waiting and the rest refused (`RESOURCE_EXHAUSTED`), and each stops
when its caller cancels or (over gRPC) goes away.

**Folders and project archives** (api_minor 37, [api.md](api.md#queries),
[backend.md](backend.md#project-archives)):

| RPC | Needs |
| --- | --- |
| `CreateFolder`, `RenameFolder`, `MoveToFolder`, `DeleteFolder` | editor of the project (an edit like renaming a program; only an empty folder can be deleted, so a delete hides nothing); undone by `RetractAssertions` with `project_id`, editor |
| `ExportProject` | viewer of the project: the archive holds what the caller can already read (the programs' bytes through `ReadMemory`, every assertion through `ListAssertions`); with `host_path`, admin (it writes a file on the daemon's host) |
| `UploadChunk` | admin (only importing reads uploads); an upload is its uploader's alone (anyone else gets `NOT_FOUND`), at most 16 in progress per caller and 16 GiB each, kept in a private temporary directory and forgotten an hour after its last piece |
| `ImportProjectArchive` | admin, as `ImportProgram`: it creates programs from the archive's binaries and runs the loaders on them. Into an existing project it names that project, so a caller limited to some projects may import only into those; a new project names none, which such a caller is refused. A host path for the archive, its binaries or `search_dir` reads the daemon's files, which admins may already do |

An archive is untrusted input, checked in full before anything is written
(backend.md lists the checks, and `project_archive_fuzzer` exercises
them). Its ops keep the provenance they were made with, which is the
point of an archive (history and blame survive), so whoever may import
can bring in ops attributed to anyone: that is why importing is an
admin's, as importer provenance (`import:`) is. The import itself is
recorded as `import:archive` on behalf of the caller, and the folders and
renames it makes as the caller. A project's name from an archive never
reaches the file system as given.

<a id="function-id"></a>
**Function ID** (`AnalysisService`, api_minor 51, [fid.md](fid.md)) reads
database files a user can swap, so both readers (`.fidbf`, `.rkfid`) check
every offset, count and link and fail with an error rather than reading
out of bounds (`fuzz_fid_db` fuzzes them):

| RPC | Needs |
| --- | --- |
| `ListFidDatabases`, `ListFidMatches` | viewer of the project |
| `AttachFidDatabase` | admin of the project: the daemon reads the file at a host path (any path the daemon can read, as `ImportProgram` by path), for the caller or the project |
| `DetachFidDatabase`, `ApplyFidMatch`, `RejectFidMatch` | editor of the project (an apply or reject is the caller's edit) |
| `CreateFidDatabase` | admin of the project: the daemon writes the file at a host path (it replaces what is there) |

A user's attachments are kept beside the projects (`<project
dir>/.fid-users`, by caller); a project's are a project note, replicated
with it, whose paths name files on each daemon's host.

BSim databases (`BSimService`, [bsim.md](bsim.md)) are directories the
daemon reads and writes; a project attaches them (a project note), and
every call but create and attach names an attached one, so only an admin
chooses which host directories are involved. Executable files are read
as hostile (`decode_executable` checks every count and length):

| RPC | Needs |
| --- | --- |
| `ListBSimDatabases`, `ListBSimExecutables`, `ListBSimFunctions` | viewer of the project |
| `CreateBSimDatabase` | editor of the project for one in the project's directory (by name); admin with a host `path` |
| `AttachBSimDatabase` | admin of the project (a host path) |
| `DetachBSimDatabase`, `IngestBSim`, `UpdateBSimExecutable`, `DeleteBSimExecutables` | editor of the project: they change what an attached database holds |

<a id="container-file-systems"></a>
**Container file systems** (`FileSystemService`, api_minor 48,
[filesystems.md](filesystems.md)) read archives, compressed files and
file system images, which are hostile input by design:

| RPC | Needs |
| --- | --- |
| `OpenFileSystem` | viewer of the project for a program's stored file (its bytes are already readable through `ReadMemory`); admin for a host path, an upload or bytes sent, as `ImportProgram` |
| `ListFileSystem`, `ReadFileSystemFile`, `GetFileSystemFileInfo`, `CloseFileSystem`, `ListFileSystems` | viewer; a session is its opener's (anyone else, but an admin, gets `NOT_FOUND`) |
| `ImportFromFileSystem` | editor of the target project: the bytes come from a session the caller holds, not from the host or an upload, as `PatchService.OpenOriginal` |
| `ExtractFromFileSystem` | admin: it writes files on the daemon's host, under `--browse-root` only |

What a container can't do:
- **Exhaust the daemon**: one file decompresses to at most 1 GiB, a session
  holds at most 4 GiB of decompressed data (least recently used dropped
  first), output past 64 MiB may not exceed 1000 times its input, nesting
  stops at 8 levels, a container lists at most 262,144 entries, a link
  chain 40 hops, a directory tree 256 levels; xz and lzma dictionaries are
  capped at 256 MiB and zstd windows at 128 MiB; nothing is decompressed
  before it is read; zip members sharing compressed data are refused. A
  request may lower these limits, never raise them. A caller holds at most
  8 sessions and the daemon 64, each closed after 30 minutes unused.
- **Reach the host through a name**: names are display text and API paths
  (percent-encoded); `..` stops at the container's root and absolute names
  start there. Only extraction writes to the host, and it sanitizes every
  name, opens each directory relative to the last without following links,
  creates files with `O_EXCL | O_NOFOLLOW` and mode 0644, replaces only
  regular files and only when asked, and writes no links, devices or pipes.
- **Follow a link out**: symlinks resolve inside their own container (an
  absolute target from its root); a host directory opened for batch import
  is walked with `openat` and `O_NOFOLLOW` from a descriptor held open, so a
  link (or one swapped in later) never leads out of it.
- Large decompressed files go to unlinked temporary files (`O_TMPFILE`) in
  the daemon's temporary directory, gone when the session drops them.

The parsers are fuzzing targets in the bug scrub
([filesystems.md](filesystems.md#tests-and-fuzzing)).

<a id="external-decompilers"></a>
**External decompilers** (`ProviderService`, api_minor 92,
[providers.md](providers.md)) run a third-party tool (ILSpy, jadx,
Vineflower, CFR, unluac, pycdc, webcrack, wasm-decompile) on bytes the
caller can already read: a program's stored file or a file of a session the
caller opened. The tool parses hostile input and is untrusted itself:

| RPC | Needs |
| --- | --- |
| `ListProviders`, `DecompileExternal`, `ReadProviderOutput` | viewer; with a program, of its project (a caller limited to some projects names only those); with a session file, the session's owner (anyone else, but an admin, gets `NOT_FOUND`) |
| `GetProviderSettings`, `SetProviderSettings` | admin: they name host paths (the tools, the runtimes) and the limits |

Viewers may run them, as they may decompile: the output is derived from
what they can read, and the run is bounded (two at once, eight waiting,
then `RESOURCE_EXHAUSTED`; the timeout, memory and output limits below). A
reason a provider is unavailable names host paths, so only admins see it
whole, with the tool's path and what the sandbox lets it read.

Each run is confined by `rk-sandbox`, which confines itself (it is
single-threaded, started with `posix_spawn`) and then executes the tool:

- **Files (Landlock)**: read and execute below `/usr`, `/lib*`, `/bin`,
  `/sbin`, `/etc`, `/sys`, the tool's own `/proc/<pid>` and the
  system-wide `/proc` files (not other processes'), the tool's install
  directory (a jar alone) and its runtime, and the input (a read-only copy
  in the run's scratch directory);
  read and write only the run's `out/`, `home/` and `tmp/`; nothing else:
  not the project directory, `--browse-root`, the credential file, the
  user's home, `/tmp`. TCP bind and connect are refused (ABI 4); abstract
  Unix sockets and signals are scoped to the sandbox (ABI 6), so it can't
  signal the daemon; Landlock's ptrace rule keeps it out of other
  processes' memory and environment. Without Landlock a run is refused
  unless an admin sets `allow_weak_sandbox`.
- **System calls (seccomp)**: no `socket()` at all (no network, and no Unix
  socket to the user's D-Bus or systemd, which could start processes
  outside the sandbox), no `connect()`; no new namespaces, mounts, keyring
  calls, `io_uring`, BPF, perf, ptrace, `process_vm_*`, `userfaultfd`,
  `pidfd_getfd`, modules or kexec; no `setsid` or `setpgid` (it stays in its
  process group); no `chmod`, `chown` or extended attributes; limits,
  priorities and memory placement (`prlimit64`, `setpriority`,
  `sched_set*`, ...) of its own process only; before Landlock ABI 6,
  signals to itself and its own group only; only the native ABI.
  `no_new_privs`.
- **Network namespace**: an empty one where unprivileged user namespaces
  are allowed. Ubuntu's AppArmor restriction (this host) refuses them; the
  seccomp and Landlock rules above hold either way.
- **Resources**: a wall-clock deadline (120 s) after which the process group
  gets SIGKILL; `RLIMIT_CPU` (four times the deadline), `RLIMIT_DATA` (the
  memory limit, 4 GiB), `RLIMIT_FSIZE` (the output cap, 256 MiB),
  `RLIMIT_NOFILE`; the output's bytes and entries are measured every 250 ms
  and a run past either cap is killed; no core dumps; whatever the tool
  leaves running dies with it; SIGKILL when the daemon's thread goes.
- **Environment**: none of the daemon's (tokens, `DBUS_SESSION_BUS_ADDRESS`,
  `XDG_RUNTIME_DIR`): a fixed `PATH`, its own `HOME` and `TMPDIR`, and the
  runtime's settings; stdin `/dev/null`; no other descriptors.
- **Output**: read as hostile. Links, pipes, sockets and devices it made
  are deleted, names that aren't UTF-8 are encoded, and files are read
  only by the paths the result lists, component by component with
  `O_NOFOLLOW`.

What it doesn't hide: what any local user sees under `/etc`, `/usr`, `/proc`
and `/sys` (other processes' command lines among them). There is no cgroup
per run: memory is bounded per process and the number of processes isn't,
within the CPU and wall-clock limits. Tools are installed by the host's
owner; revkit downloads none.

**Emulator sessions** ([emulator.md](emulator.md)) belong to the identity
that created them: running, stepping, writing and closing need editor;
reading state, memory and the trace need viewer; and either way a session
made by someone else answers `NOT_FOUND` unless the caller is an admin.
The per-client bound becomes per identity. Without authentication sessions
belong to their `client`, as before.

**Debug sessions** (`DebugService`) follow the same rules: owned by their
creator, running, stepping, writing registers or memory, breakpoints,
selecting a thread, interrupting, saving a trace and closing need editor;
state, memory, modules, the timeline and waiting need viewer; listing a
program's traces needs viewer of its project and deleting one editor.
Starting one depends on its target: the emulator or a saved trace needs
editor, but a **live target needs admin**: launching or attaching starts or
controls a process on the daemon's host, and a gdb remote address makes
the daemon connect wherever it names. Live targets are also off unless the
daemon runs with `--debug-live`.

**Diff sessions** ([diff.md](diff.md)) are project records, not anyone's:
listing, reading and running a session need viewer of its project;
creating one, cancelling a run, accepting, rejecting and setting matches,
porting markup and reverting a port need editor. Ported assertions are
stamped `migration:diff`, with the caller who applied them in the reason.

**Scripts** (`ScriptService`, api_minor 31, [scripting.md](scripting.md#the-daemons-script-service)).
A script the daemon runs is **full Python as the daemon's user**: it can
read the credential file, the projects' LMDB files, anything that user
can, and start processes. Letting someone run scripts on the daemon is
therefore equivalent to giving them a shell as that user, and through the
credential file, admin. So:

- **Who**: `rk-daemon --scripts-host-role off|viewer|editor|admin`.
  Without it, scripts run for editors and admins only when **every
  listener is on loopback**; a daemon listening beyond loopback runs
  scripts for nobody until an admin chooses a role. The Python console
  (`RunScript{interactive}`, api_minor 43) is a script for this purpose.
  `RunScript` needs a viewer of the program's project in the policy
  table and the host role on top, so a viewer runs scripts and consoles
  only where an admin chose `viewer`: their runs get a viewer's run token
  (and run with `--read-only`), so they read and their edits are refused,
  but they are still Python as the daemon's user, which is why `viewer` is
  never a default. Saving a script needs an editor whatever the role.
  `ListScripts` says whether the caller may, and why not.
- **As whom**: each run gets a **run token** from the credential store
  (`Store::mint_run_token`): in memory only, never in the file, acting as
  the caller (kind, name, role, projects), re-derived from the account or
  API token on every use (a lowered role, a deleted account or a revoked
  token applies to running scripts at once), and **revoked when the run
  ends**. The script's edits go through the normal authorization and
  stamping: script provenance with `on_behalf_of` the caller. A run token
  can't start scripts itself.
- **Trust**: a per-user or per-project script runs only after the caller
  has confirmed its exact text: the first run of an unseen `name@sha256`,
  or of text changed since the caller's last confirmed run or save, answers
  `trust_required` with the source and hash, and the UI shows them before
  running again with `confirm_sha256`. Pins live in
  `~/.config/revkit/trusted-scripts` (the daemon's user's config,
  `$XDG_CONFIG_HOME`; mode 0600), per caller and script. Shipped scripts
  (installed with revkit) are trusted like the daemon itself. Saving a
  script (`SaveScript`: per-user or per-project libraries only, editor and
  the host role) pins the saver's trust, nobody else's.
- **Runs are the caller's**: answering a prompt, cancelling and moving the
  context need the run's owner (or an admin; anyone else gets
  `NOT_FOUND`); `ListScriptRuns` shows the caller's own runs (an admin's:
  everyone's). At most 8 run at once; a cancelled host gets SIGTERM and
  SIGKILL 2 s later (its whole process group); a client that goes away
  cancels its run.

Untrusted automation belongs in WebAssembly plugins ([plugins.md](plugins.md)),
which are sandboxed. Users of a shared daemon with scripts off run
`rk-script` on their own machine against it, with their own token.

**Per-project access lists** (optional): an account or token with a
project list may only name those projects (`project_id`, the project part
of `program_id`, a `FactKey`'s program, `program_ids`), and `ListProjects`
shows only them. Empty means every project.

### Server-stamped identity: refuse, don't rewrite

Every request that names an author (`AppendAssertions`,
`RetractAssertions`, `RevertByProvenance` and `RunCommand` provenance,
`UpdatePresence`'s `who`) gets the caller's identity:

- kind and id **empty**: the server fills them in (`user:alice`,
  `agent:ci-bot`). This is what clients should send.
- the caller's **own** kind and id (or its kind with an empty id): kept.
- an **admin** may write `import`, `migration`, `analysis` and `plugin`
  provenance with an id of its choosing, for importers such as the Ghidra
  bridge ([ghidra-interop.md](ghidra-interop.md)).
- **a script** (`script:<name>`, api_minor 29): any caller that may edit
  may write it, and the server stamps the caller in `on_behalf_of`
  ("user:alice"), so blame and reverts still name the person
  ([scripting.md](scripting.md#edits-provenance-and-precedence)). An
  admin's importer provenance gets `on_behalf_of` too.
- **anything else** (`user:bob` from alice, `user:alice` from an agent
  token, `agent:x` from a user, an `on_behalf_of` naming anyone but the
  caller): `PERMISSION_DENIED`, naming the authenticated caller.

Refusing rather than silently overwriting means a client never believes it
wrote as someone it didn't, and a misconfigured script fails loudly. The
client's `version`, `session`, `reason` and `tool` are kept. Presence is
not an assertion: its `who` and `display_name` are always overwritten with
the caller's identity, so collaborators' names in the UI come from the
server.

### Transport

Both listeners take one certificate: `--tls-cert`/`--tls-key` (a chain and
its key), or `--tls-self-signed`, which makes an ECDSA P-256 certificate on
first use (for `localhost`, `127.0.0.1`, `::1`, the listen addresses, the
host name and `--tls-san` names), keeps it in `<project-dir>/.revkit/tls/`
(else `~/.local/share/revkit/tls/`; `--tls-dir` to choose) and prints its
SHA-256 fingerprint at every start. TLS 1.2 or later.

A listener off loopback must have TLS, unless `--insecure-allow-remote`
(the daemon then prints a warning: passwords and tokens cross the network
in the clear). `--no-auth` refuses any listener off loopback.

### DNS rebinding

Without a check, a web page could reach a daemon on loopback:

1. A page on a name its owner controls (`evil.example`) makes the name
   resolve to 127.0.0.1 after the page has loaded.
2. Its scripts can then call `http://evil.example:50052/revkit.v1...`.
3. The browser considers those calls same-origin and lets the page read
   the answers.

A `--no-auth` daemon would have answered as to an anonymous admin. That
includes `RunScript` and the Python console, which run code as the user.

The calls still name the attacker's host in their `Host` header, so the
HTTP listener answers a request (API calls, static files and `/healthz`
alike) only if its `Host` is one of these:

- `localhost` or any `*.localhost` name (`revkit.localhost`), which
  browsers resolve to loopback themselves;
- an IP address (`127.0.0.1`, `[::1]`, `100.64.0.1`). Rebinding needs
  a name: a browser sends an address only when it connected to that
  address;
- the names in the TLS certificate (`--tls-cert`, or `--tls-self-signed`
  with its `--tls-san` names);
- on a listener beyond loopback, the name in `--http` and the machine's
  own name (`gethostname`, and `NAME.local` for a name without a dot);
- names given with `--allow-host NAME` (repeatable). A `*.example.com`
  entry covers the subdomains of `example.com`. `allow-host = NAME` lines
  in `revkit.conf` (`~/.config/revkit/revkit.conf` and
  `/etc/revkit/revkit.conf`) add to them.

Any other `Host` gets `421 Misdirected Request` with a line naming
`--allow-host`. The port is not compared. A request without `Host` (not a
browser) is answered.

The Origin checks use the same names. A call that carries a browser
`Origin` must come from one of two kinds of page:

- the daemon's own page: our scheme, one of the names above, and the port
  the request came to;
- a page `--allow-origin` names (the desktop app's `tauri://localhost`, a
  dev server). That is CORS, unchanged.

Any other origin gets `PERMISSION_DENIED` (HTTP 403), with or without a
session cookie. Before this, a session cookie's Origin was compared with
the request's own `Host`, which a rebinding page satisfies.

The gRPC listener has no such check and needs none. Browsers can't make
gRPC calls (HTTP/2 with trailers): their only way in is the HTTP listener.

## What is enforced where

| Check | Where | Both transports? |
| --- | --- | --- |
| Who the caller is (bearer token, session, peer secret) | `AuthGate::Identify` (`src/api/grpc_services.cc`), from `authorization: Bearer` metadata | yes: the gateway forwards to the same handlers through an in-process channel |
| Role and project list per RPC | `Authorize` (`src/api/auth_policy.cc`), called first in every handler | yes |
| Provenance and presence stamping | `StampProvenance`, `StampPresence`, in the handlers before the backend | yes |
| `ListProjects` filtered to the caller's projects | the handler | yes |
| Emulator sessions owned by their creator | `EmulatorSessions` (`src/backend/emulator.cc`), from `CallContext.caller` and `caller_admin` | yes |
| `ParseC` reads host files only for admins, only under `--browse-root` | `Authorize` raises it to admin with a path or include directory; `cparse::host_file_system(roots)` resolves every source and `#include` (`src/backend/parse_c.cc`) | yes |
| Debug sessions owned by their creator; live targets admin-only | `DebugSessions` (`src/backend/debugger.cc`); `Authorize` raises `CreateDebugSession` with `launch` or `remote` to admin | yes |
| Scripts: who may run them, run tokens, trust, run ownership | `ScriptService` (`src/api/script_service.cc`): the host role (`ScriptHostRole`, off beyond loopback by default) on top of `Authorize`; run tokens in `Store` (memory only, revoked at the run's end); trust pins per caller | yes |
| External decompilers: who may run them; the sandbox | `Authorize` (viewer; settings admin); the session's owner in `FileSystemRegistry::Get` (`src/backend/filesystems.cc`); the confinement in `rk-sandbox` (`src/providers/sandbox_exec.cc`: limits, Landlock, seccomp), the deadline, caps and group kill in `run_sandboxed` (`src/providers/sandbox.cc`) | yes |
| Streams end when their session or token does | `Subscribe` and `Pull` re-check at every heartbeat | yes |
| Session cookie, CSRF token, Origin | `ConnectGateway::Impl::Handle` (`src/api/connect_gateway.cc`): a valid cookie becomes the bearer metadata only if the Origin (when sent) is the daemon's own and `x-csrf-token` matches the session's; `WhoAmI`, `Login` and `GetServerInfo` are exempt | gateway only |
| `Host` names the daemon (DNS rebinding) | `HostHeaderAllowed`, a pre-routing handler in `ConnectGateway` (`src/api/connect_gateway.cc`), on every HTTP request; the names from `Server::Start` and `--allow-host` | gateway only (browsers can't speak gRPC) |
| Calls from a foreign `Origin` | `ConnectGateway::Impl::Handle`: an `Origin` that is neither the daemon's own page nor an `--allow-origin` one is refused | gateway only |
| Cookie attributes | `HttpOnly; SameSite=Strict; Path=/; Max-Age`; over TLS also `Secure` and the `__Host-` name; the token is removed from `LoginResponse` | gateway only |
| Response headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on API responses | gateway only |
| Login throttling | `AuthService.Login`: per client address and per account name, 5 free failures, then 1 s doubling to 15 min (`RESOURCE_EXHAUSTED`); a success clears it. Through the gateway the browser's address counts (the gateway proves itself to the handlers with a per-process secret, so a client can't forge `x-forwarded-for`) | yes |
| Constant time | token hashes, the CSRF token, the peer secret; an unknown account costs a dummy scrypt | |
| TLS and loopback rules | `Server::Start` (`src/api/server.cc`), on the address a socket inherited from systemd listens on as on `--http` | both listeners |
| `GetServerInfo.launch_args` to admins only | `Meta::GetServerInfo` (`src/api/grpc_services.cc`) | yes |
| Credential file | `revkit::auth::Store` (`src/auth`): hashes only, 0600 in a 0700 directory, atomic rename under `flock`, re-read when it changes | |

`--no-auth` makes every caller an anonymous admin and stamps nothing: the
behaviour before authentication existed, for loopback development and the
existing tests.

**Where the mode comes from** (`tools/rk-daemon/auth_choice.h`), in this
order:

1. `--no-auth`, or `--auth` (which `--auth-file` implies).
2. `--ask`: ask again. It needs a terminal.
3. `auth = none|accounts` in `~/.config/revkit/revkit.conf`, else in
   `/etc/revkit/revkit.conf`.
4. The first-run question ([getting-started.md](getting-started.md#first-run-on-your-machine)).
   It is asked only when stdin and stderr are both terminals and there
   are no accounts or tokens yet.
5. Accounts.

The rules around it:

- A saved `none` is `--no-auth` in every respect: off loopback the daemon
  refuses to start with the same error.
- A process without a terminal is never asked, so a service, the desktop
  app or a script behaves exactly as before, apart from a saved choice.
- Each start logs the mode and its source in one line.
- The answer is written only to the user's own file, never to `/etc`.

Unauthenticated by design: `GetServerInfo` (version, features and
uptime; the daemon's command line, `launch_args`, only to admins, since it
names host paths),
`Login`, `WhoAmI` (an unauthenticated caller learns only that it is one),
`/healthz`, the static web bundle (the login page is part of it), and gRPC
server reflection (the schema, which is public).

## Setup

### Local development

```sh
build/tools/rk-daemon/rk-daemon --no-auth --open prog       # as before: loopback, no accounts
```

### Accounts on one machine

```sh
rk-daemon user add alice --role admin --project-dir ~/rk    # asks for a password twice
rk-daemon --project-dir ~/rk --open prog                     # loopback: TLS optional
# open http://revkit.localhost:50052 and sign in
```

### Socket activation

The `.deb`'s systemd user units start `rk-daemon` on the first connection
to `127.0.0.1:50052` ([packaging.md](packaging.md#start-the-daemon-on-first-use-systemd-socket-activation)).
They change nothing here:

- The shipped service runs without `--no-auth`, so accounts are on and the
  API needs a session or token as on any start; the socket's existence
  starts a daemon, it doesn't open one up. Make the account first
  (`rk-daemon user add "$USER" --role admin --project-dir
  ~/.local/share/revkit/projects`).
- The inherited socket goes through the same checks as `--http`, on the
  address it actually listens on (`getsockname`): with `--no-auth` it must
  be loopback, and off loopback it needs TLS or `--insecure-allow-remote`.
  A `ListenStream=50052` (all addresses) is therefore refused without TLS.
  `--no-auth` on a loopback socket stays possible, as the explicit flag in
  your own drop-in, exactly as on the command line.
- The units are user units: the daemon runs as you, and other local users
  reach the port only as they would reach any loopback daemon of yours
  (and then meet the login).

`ListenFds.TheListenerRulesApplyToTheInheritedSocket` and
`daemon_socket_activation` check this.

### The desktop app's daemon controls

The desktop app's status chip starts, stops and restarts the app's own
daemon and shows its log through five Tauri commands
(`daemon_status`, `daemon_start`, `daemon_stop`, `daemon_restart`,
`daemon_log`; `ui/tauri/src-tauri/src/main.rs`). They are declared in the
app's ACL manifest (`build.rs`) and granted only to the main window's
bundled page (`capabilities/default.json`, `"local": true`); remote
content (`REVKIT_UI_URL`) gets no IPC. They run the daemon the app always
ran: loopback, free ports (a restart asks for the same HTTP port), accounts
on with the admin token the app made at launch, `--allow-origin
tauri://localhost`. A daemon the app didn't start (`REVKIT_DAEMON`) can't
be controlled.

### Serving the network

```sh
rk-daemon --project-dir ~/rk --tls-self-signed \
    --http 0.0.0.0:50052 --grpc 0.0.0.0:50051 --tls-san rk.example.lan
# rk-daemon: TLS certificate SHA-256 fingerprint 3D:67:84:...
rk-daemon tls fingerprint --project-dir ~/rk                 # the same, later
```

Browsers warn about a self-signed certificate; compare the fingerprint the
browser shows with the daemon's and accept it. With a certificate from a
CA (your own, Let's Encrypt, `tailscale cert`), use `--tls-cert` and
`--tls-key` and there is no warning.

### Accounts and tokens

The commands edit the credential file the daemon uses: `--project-dir DIR`
means `DIR/.revkit/auth.db`, else `~/.local/share/revkit/auth.db`, and
`--auth-file` names one. A running daemon sees changes within a second (a
new token works at once).

```sh
rk-daemon user add bob --role editor [--projects fw,lib] [--password-stdin]
rk-daemon user passwd bob              # ends bob's sessions
rk-daemon user role bob viewer         # ends bob's sessions
rk-daemon user projects bob '*'        # every project again
rk-daemon user del bob                 # with his sessions and tokens
rk-daemon user list
rk-daemon token create --name claude --role editor          # prints the secret once
rk-daemon token create --name bob-ci --role editor --user bob --ttl-days 30
rk-daemon token create --name daemon-b --role peer
rk-daemon token list
rk-daemon token revoke claude
```

Admins can do the same over the API (`AuthService.CreateUser`,
`UpdateUser`, `DeleteUser`, `CreateToken`, `RevokeToken`, ...). Accounts
change their own password with `ChangePassword`.

## Serving over Tailscale with authentication and TLS

A daemon on a tailnet address (here `100.x.y.z`, the machine's Tailscale
IP) is off loopback, so it refuses to start without TLS. Three ways to run
it, best first.

**1. A real certificate from Tailscale** (no browser warning). With MagicDNS
and HTTPS certificates enabled for the tailnet (admin console, DNS page):

```sh
rk-daemon user add alice --role admin --project-dir ~/revkit-projects
sudo tailscale cert --cert-file ~/revkit-projects/.revkit/ts.crt \
    --key-file ~/revkit-projects/.revkit/ts.key <machine>.<tailnet>.ts.net
sudo chown "$USER" ~/revkit-projects/.revkit/ts.*
rk-daemon --http 100.x.y.z:50052 --grpc 127.0.0.1:50051 \
    --project-dir ~/revkit-projects --browse-root ~/samples \
    --tls-cert ~/revkit-projects/.revkit/ts.crt --tls-key ~/revkit-projects/.revkit/ts.key
# browse to https://<machine>.<tailnet>.ts.net:50052 and sign in as alice
```

(`tailscale cert` certificates last 90 days; re-run it and restart the
daemon to renew.)

**2. The daemon's self-signed certificate.** Add `--tls-self-signed` (and
`--tls-san <machine>.<tailnet>.ts.net` if you use the name) to the command
above, without `--tls-cert`/`--tls-key`. The certificate is kept in
`~/revkit-projects/.revkit/tls/`; browse to `https://100.x.y.z:50052`,
compare the fingerprint the browser shows with the one the daemon printed,
and accept it once per browser.

**3. Plaintext over the tailnet** (`--insecure-allow-remote`, no TLS flags).
Tailscale's WireGuard tunnel already encrypts traffic between tailnet
devices, so this is defensible for a private tailnet, but anything on the
machine or any device on the tailnet can see the HTTP traffic, the session
cookie lacks `Secure`, and the daemon warns at every start. Prefer 1 or 2.

In every case `--browse-root` is visible to admins only, and the gRPC
listener on 127.0.0.1:50051 needs a token too. For an agent on the same
machine:

```sh
rk-daemon token create --name claude --role editor --project-dir ~/revkit-projects
RK_TOKEN=rkt_... revkit-mcp --daemon 127.0.0.1:50051 --fingerprint <the daemon's>   # option 2
RK_TOKEN=rkt_... revkit-mcp --daemon 127.0.0.1:50051 --tls --server-name <machine>.<tailnet>.ts.net   # option 1
```

## Clients

**Web UI.** Served by the daemon, it asks `WhoAmI`, shows a login page if
there is no session, and signs in with `Login{session_cookie: true}`: the
daemon keeps the session in its HttpOnly cookie and the page only ever
holds the CSRF token (from `Login`, or `WhoAmI` after a reload), which it
sends as `x-csrf-token`. The toolbar shows `user:<account>` and a Log out
button (also "Log out" in the command palette). Edits leave provenance to
the server. When a session ends, the login page comes back.

From another origin (the Tauri shell, `?api=`), the cookie can't follow
(SameSite=Strict, and cross-origin cookies aren't used), so the page
signs in for a bearer token and keeps it in `localStorage` for that daemon;
the daemon must allow the origin (`--allow-origin tauri://localhost`). The
Tauri shell's default, `http://127.0.0.1:50052`, is loopback, where
plaintext is allowed, so it keeps working with or without accounts. To
reach a TLS daemon from the shell, its certificate must be trusted by
WebKitGTK (the system store), or load the daemon's own copy of the UI
(`REVKIT_UI_URL=https://...`), which signs in with the cookie.

**Python SDK** ([api.md](api.md#python-sdk-sdkpython)):

```python
from revkit import Client
rk = Client("host:50051", token="rkt_...", fingerprint="3D:67:...")      # or RK_TOKEN, RK_TLS_FINGERPRINT
rk = Client("host:50051", token="rkt_...", ca_cert="cert.pem")           # or RK_TLS_CA
rk = Client.login("host:50051", "alice", password, fingerprint="3D:67:...")
rk.whoami().identity   # name, role, the provenance the server stamps
```

A fingerprint pin fetches the server's certificate, checks its SHA-256 and
then trusts exactly that certificate as the root (its name is checked as
`localhost`, which every rk-daemon self-signed certificate carries). With a
token the client sends empty provenance kind and id by default, so the
server fills them in; `actor="@opus-5.5"` adds only a version.

**TypeScript.** `connectTransport(url, binary, { token })` or `{ csrf }` in
a browser; for Node, `nodeTransport({ baseUrl, protocol, token,
fingerprint | ca })` from `@revkit/api/node` (Connect, gRPC-web or gRPC
over TLS with the same pinning).

**MCP server.** `revkit-mcp --daemon host:50051 --token rkt_...
--fingerprint ...` (or `RK_TOKEN`, `RK_TLS_FINGERPRINT`, `RK_TLS_CA`). Give
it an agent token: the daemon records its edits as `agent:<token name>`
(plus `@--agent-version`), and refuses them with a user's token.

**curl and grpcurl.**

```sh
curl --cacert cert.pem -H 'Authorization: Bearer rkt_...' -H 'Content-Type: application/json' \
    -d '{"programId":"default/prog"}' https://localhost:50052/revkit.v1.QueryService/ListFunctions
grpcurl -cacert cert.pem -authority localhost -H 'authorization: Bearer rkt_...' 127.0.0.1:50051 list
```

## Peers

`--peer host:port` links to another daemon ([collab.md](collab.md)); the
link authenticates and checks the peer's certificate:

```sh
# on a: issue b a peer token
rk-daemon token create --name daemon-b --role peer --project-dir ~/rk-a > b.token
# on b: link to a with it, pinning a's certificate
rk-daemon --project-dir ~/rk-b --peer 'a.lan:50051,token-file=b.token,fingerprint=3D:67:...'
```

Per-peer options after the address: `token-file=F`, `ca=F` (a CA or a's
certificate), `fingerprint=SHA256`, `server-name=N`, `tls` (system CAs).
`--peer-token-file`, `--peer-ca`, `--peer-fingerprint` and `--peer-tls` set
defaults for every `--peer`. A fingerprint-pinned peer is linked once its
certificate has been fetched and checked, so it may start later.

Alternatively every daemon of a group shares one secret (32+ characters):
`--peer-secret-file F` makes a daemon accept it from peers and send it on
its own `--peer` links that have no token. One link replicates both ways,
so only the daemon being linked to needs to accept the other.

A peer token reaches `SyncService` and nothing else, on every project; a
user's or agent's token can't replicate. Revoking a peer token ends that
peer's pull streams at their next heartbeat (5 s).

## Symbol servers

Load PDB ([pdb.md](pdb.md#symbol-servers)) can download a program's PDB
from the symbol servers the daemon's symbol path names
(`srv*<cache>*https://msdl.microsoft.com/download/symbols`). That is the
daemon contacting a server on the internet on its users' behalf, so:

- **Off by default.** Nothing is downloaded until an admin turns
  downloads on: `rk-daemon --symbol-downloads`, or
  `ProjectService.SetSymbolSettings` (admin role; `GetSymbolSettings` is
  the admin's too). With downloads off, the path's local stores and
  caches are still used and servers are reported as "not contacted".
- **What a server learns.** Each request names the PDB's file name and its
  GUID and age (`/<name>/<GUID><age>/<name>`), from the requesting
  daemon's address, with a `Microsoft-Symbol-Server` user agent: which
  build of which module someone is analysing. Nothing else about the
  program or the project is sent. Use a private symbol server or local
  stores when that matters.
- **Who can trigger it.** `LoadPdb` is an admin's call on the project (it
  also reads paths on the daemon's host), so a viewer or an editor can't
  make the daemon download. A download is bounded (2 GiB, 60 s timeouts),
  written only into the configured cache under a name built from the
  PDB's name (no directories) and key, checked against the program's
  identity before use, and expanded from a cabinet in memory.
- **Where it goes.** The URL is the admin's. A redirect is followed
  within the same scheme, host and port, or to another host over https
  only (msdl redirects to a CDN); never from https to http, never to a
  location with spaces or control characters, at most five. Certificates
  are checked (the system's roots and the host name). The PDB's name is
  percent-encoded into the path, and a whole download has a deadline (30
  times the read timeout) besides its size limit
  (`src/backend/http_fetch.cc`).

## debuginfod

Load debug file ([backend.md](backend.md#external-debug-files)) can fetch
an ELF's separate debug file from debuginfod servers. The same rules as
the symbol servers', tighter where debuginfod allows it:

- **Off by default.** Nothing is fetched until an admin sets
  `debuginfod` and lists servers (`SetSymbolSettings`, or `rk-daemon
  --debuginfod <url>`). The daemon's `DEBUGINFOD_URLS` is shown as a
  suggestion (`suggested_debuginfod_urls`) and never used by itself.
  Programs loading (imports, projects opening) never fetch: they read only
  files beside the binary, in the configured directories and in the cache.
- **What a server learns.** A request names the program's build ID
  (`/buildid/<id>/debuginfo`), from the daemon's address, with a
  `revkit-debuginfod` user agent: which build someone is analysing.
- **Who can trigger it.** `LoadDebugFile` is an admin's call on the
  project (it reads paths on the daemon's host too).
- **Transport.** `https://` only, unless an admin also allows `http://`
  (`debuginfod_allow_http`); URLs with a user name or password, a query
  or a fragment are refused. Certificates are checked with OpenSSL's
  defaults. A redirect is followed only to the same scheme, host and port
  (at most 5): never to another host, unlike the symbol servers (above).
  A whole transfer has a deadline, 30 times the read timeout.
- **What arrives is untrusted.** At most `debug_file_max_bytes` (1 GiB by
  default) is read before the transfer is dropped; the bytes must be an
  ELF with `.debug_info` whose build ID is the program's before they are
  kept, then the loader and the DWARF reader read them as they read any
  binary. They are written atomically into
  `<project_dir>/.revkit/debuginfod/<build id>/debuginfo` (the build ID is
  checked to be hex), and the cache is trimmed to `debug_cache_max_bytes`.

## Limits and known gaps

- **No single sign-on, MFA or client certificates.** Local accounts and
  bearer tokens only; OIDC and mTLS would plug into `AuthGate::Identify`.
- **Audit trail.** Logins, logouts, account changes and daemon restarts
  (`MetaService.RestartDaemon`, admins only: who, from which address, why,
  how many streams it ended) are logged to stderr only; edits carry their
  author in the assertion log, which is the durable record.
- **Throttling is per daemon and in memory**, and throttling by account
  name lets someone delay a known account's logins by up to 15 minutes.
- **Revocation latency.** A revoked token or deleted account stops working
  within a second (the daemon re-reads its credential file); open streams
  end at their next heartbeat.
- **Peers are trusted with data** (see the threat model), and admins may
  write importer provenance under any importer name.
- **Cross-origin browser sessions** keep their token in `localStorage`,
  readable by an XSS on that origin; same-origin pages use the HttpOnly
  cookie. CORS with credentials (cookies across origins) is not offered.
- **TLS keys** are read once at startup; rotating a certificate needs a
  restart. The self-signed certificate lasts 825 days; delete its directory
  to make a new one (clients pinning it then need the new fingerprint).
- **Rate of expensive calls.** Any authenticated caller can still keep the
  decompiler busy.
- **External decompilers' sandbox** has no cgroup of its own (memory is
  per process, the process count unbounded within the time limits) and
  no network namespace where unprivileged user namespaces are restricted
  (Ubuntu); seccomp refuses every socket regardless
  ([providers.md](providers.md#the-sandbox)).
- **Scripts are not sandboxed.** Whoever may run scripts on the daemon
  (`--scripts-host-role`) has a shell as its user. Trust pins guard against
  running text you haven't seen, not against a malicious person allowed to
  run scripts. A run outlives the logout of the session that started it
  (its run token is tied to the account, not the session) until it ends;
  a console lives until it idles out (`--console-idle-timeout`) or is
  closed. A viewer's console (`--scripts-host-role viewer`) can't edit
  through the API, but it is Python on the daemon's machine: give
  viewers it only where they may have a shell.

## Tests

- `src/auth/tests` (`revkit_auth_tests`): scrypt hashing and malformed
  hashes, encodings and constant-time comparison, accounts, sessions (expiry,
  ending on a new password or role), API tokens (agent, issued to an
  account, peer, expiry, revocation, forged secrets), the peer secret, the
  credential file (hashes only, 0600, shared by two stores, concurrent
  writers), the login throttle, self-signed certificates and fingerprints.
- `src/api/tests/auth_test.cc` (`revkit_api_tests`): gRPC and the gateway
  over TLS only (and refusing a wrong root), login, bearer use and logout,
  API tokens and account management over the API, role denial (viewer
  edits, editor imports and host browsing, peers and non-peers), stamping
  rules (refusals, agent names and versions, admin importers, presence),
  project lists (`ListProjects`, queries, subscriptions), the login
  throttle, streams ending with their session, the browser path (cookie
  attributes, no token in the body, CSRF and Origin refusals, logout
  clearing the cookie, bearer tokens through the gateway, a forged gateway
  header), every RPC refusing anonymous callers, every RPC having a policy,
  and the listener rules.
- `src/api/tests/server_test.cc`: DNS rebinding. The test checks:
  - which `Host` values are accepted (`HostHeader.*`);
  - a foreign `Host` with a matching `Origin` gets 421, on API calls and
    static files alike;
  - `localhost`, `revkit.localhost`, `127.0.0.1` and `[::1]` are
    answered;
  - a foreign `Origin` gets 403, unless `--allow-origin` names it;
  - `--allow-host` names, `*.` patterns and TLS certificate names are
    answered (`ServerHosts.AllowHostAndCertificateNames`).
- `EmulatorApi.SessionsBelongToTheirCaller`: another identity gets
  `NOT_FOUND` on every call and an empty list, the bound is per identity,
  an admin reaches the session.
- `src/backend/tests/collab_test.cc` `CollabTest.AuthenticatedPeersOverTls`:
  a viewer's token and a plaintext link replicate nothing; a peer token over
  TLS with the certificate pinned converges both ways.
- `sdk/python/tests/test_auth.py` (`python_sdk`): tokens over pinned TLS,
  stamped provenance and refused impersonation, no credentials, a wrong pin
  and plaintext, logins and roles, environment configuration, revocation,
  the MCP server with an agent token, and three daemon processes where a
  peer token over TLS replicates and a viewer's token is refused.
- External decompilers: `src/providers/tests` (`revkit_providers_tests`):
  with a fake provider, the deadline, the output and file caps, a crash, a
  child left behind killed with the run, and what the sandbox refuses
  (reading, listing and writing outside its directories, writing the input,
  TCP and the D-Bus socket, signalling another process; links and pipes
  dropped from the output); `AuthPolicyUnit` (every ProviderService method
  has a policy).
- Container file systems: `src/container/tests` (`revkit_container_tests`):
  zip bombs (a file's size, the ratio, the session's budget), overlapping
  zip members, traversal and absolute names, control bytes and invalid
  UTF-8 in names, symlink loops and escapes, truncated and corrupted
  archives, a host directory whose links point out;
  `sdk/python/tests/test_filesystems.py` (`python_sdk`): extraction under
  the browse root only (and never through a traversal name), the roles on
  an authenticated daemon (a viewer browses a program's file but can't open
  a host path or bytes, or import; an editor imports but can't extract;
  sessions are their opener's).
- `sdk/ts/test/auth.ts` (`ts_sdk_auth`): Connect, gRPC-web and gRPC over TLS
  with a pinned certificate, stamped provenance, role and anonymous refusals.
- `ui/e2e/run.ts` (`ui_e2e`): the login page over TLS, a wrong password, the
  cookie's attributes, an edit stamped `user:alice`, a second tab seeing
  alice's cursor, emulating and stepping, a reload keeping the session,
  logout, and signing in from another origin with a bearer token (and
  emulating there).
- Scripts: `src/api/tests/script_service_test.cc` (`revkit_api_tests`):
  scripts off beyond loopback by default and per `--scripts-host-role`, run
  tokens (acting as the caller, never in the file, a lowered role or a
  revoked token applying at once, revoked), trust pins per caller;
  `sdk/python/tests/test_script_service.py` (`python_sdk`), on an
  authenticated TLS daemon: a viewer can't run or save, edits stamped
  `on_behalf_of` `user:alice`, the run token dead after the run, trust
  asked for unseen and changed text and pinned by saving for the saver
  only, and a daemon with scripts off.
