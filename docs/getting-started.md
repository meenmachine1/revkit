# Getting started

revkit is a reverse-engineering workbench. `rk-daemon` loads ELF, PE and
raw firmware images, analyzes them with Ghidra's SLEIGH engine and
decompiler (linked in as C++ libraries, no Java), and serves them through
one API to a web UI, a desktop app, Python and TypeScript SDKs, AI agents
(MCP) and command-line tools. Every edit is an assertion with provenance
(who, when, why) that every client sees live and can undo.

This page takes you from installing revkit to analyzing a binary, alone or
on a shared server, and scripting it. The commands were run against the
0.1.0 packages (`scripts/getting-started-check.sh` runs them again).
Packages built between releases, pre-releases included, carry a snapshot
version such as `0.1.0~git20261008003044.431366830e06` in their file names
(the Python package `0.1.0.dev20261008003044+g431366830e06`); use those
names where this page says `0.1.0`
([packaging.md](packaging.md#build-versions)).

- [Install](#install)
- [Ghidra processor specs](#ghidra-processor-specs)
- [First run on your machine](#first-run-on-your-machine)
- [A shared server with accounts and TLS](#a-shared-server-with-accounts-and-tls)
- [Opening a binary](#opening-a-binary)
- [The main views](#the-main-views)
- [Command-line tools](#command-line-tools)
- [The Python SDK in 10 lines](#the-python-sdk-in-10-lines)
- [MCP for AI agents](#mcp-for-ai-agents)
- [Plugins](#plugins)
- [Where to go next](#where-to-go-next)

## Install

revkit runs on x86-64 Linux with glibc 2.36 or newer (Debian 12, Ubuntu
23.04 and later, Fedora 37 and later). `scripts/package.sh` builds the
packages into `build/dist/` ([packaging.md](packaging.md)).

**Portable bundle** (no root; runs from any directory):

```sh
mkdir -p ~/opt && tar -xzf revkit-0.1.0-linux-x86_64.tar.gz -C ~/opt
export PATH=~/opt/revkit-0.1.0-linux-x86_64/bin:$PATH
rk-daemon --version          # rk-daemon 0.1.0 (git ...)
```

The bundle holds the executables (`bin/`), their libraries (`lib/revkit/`),
the web UI, Ghidra's processor specs and the example plugins
(`share/revkit/`), the Python wheel, the TypeScript package and the plugin
SDK (`share/revkit/sdk/`), and the notices and licenses
(`share/doc/revkit/`).

**Debian package** (the same tree under `/usr`):

```sh
sudo apt install ./revkit_0.1.0_amd64.deb
```

**Desktop app** (Ubuntu 24.04 or newer): `revkit-desktop_0.1.0_amd64.AppImage`
(`chmod +x` it and run it; it carries everything) or
`sudo apt install ./revkit_0.1.0_amd64.deb ./revkit-desktop_0.1.0_amd64.deb`.
It is the web UI in its own window, with its own daemon; see
[The desktop app](#the-desktop-app).

**From source**: see the [README](../README.md#building-from-source). A source build serves
the web UI from `ui/dist` once you have built it, and finds Ghidra as
described next.

## Ghidra processor specs

revkit reads Ghidra's processor specifications (`.sla`, `.ldefs`, `.pspec`,
`.cspec`, plus function-start patterns and the C library type archives) at
run time. The packages carry a copy (`share/revkit/ghidra`, 34 MB,
Apache-2.0), so there is nothing to do. Otherwise every tool looks in this
order:

1. `--ghidra DIR` on the command line;
2. `$GHIDRA_INSTALL_DIR`;
3. a `ghidra = DIR` line in `~/.config/revkit/revkit.conf` (or
   `$XDG_CONFIG_HOME/revkit/revkit.conf`), then `/etc/revkit/revkit.conf`;
4. the package's `share/revkit/ghidra`, found relative to the executable;
5. the `GHIDRA_ROOT` a source build was configured with;
6. common install locations: `~/ghidra/ghidra_*`, `~/ghidra*`,
   `/opt/ghidra/ghidra_*`, `/opt/ghidra*`, `/usr/share/ghidra`,
   `/usr/lib/ghidra` (newest first).

`DIR` is a Ghidra 12.x release (the directory that holds `Ghidra/Processors`,
for example `~/ghidra/ghidra_12.1.4_PUBLIC`) or a tree made by
`scripts/gather-ghidra-specs.sh`. To set it once:

```sh
mkdir -p ~/.config/revkit
echo "ghidra = $HOME/ghidra/ghidra_12.1.4_PUBLIC" > ~/.config/revkit/revkit.conf
```

A directory named in 1 to 3 that doesn't hold the specs is an error, not
skipped; when nothing is found, the message lists every place tried and
how to fix it:

```text
$ GHIDRA_INSTALL_DIR=/nonexistent rk-lift prog
rk-lift: Ghidra processor specs: /nonexistent (from $GHIDRA_INSTALL_DIR) does not exist.
Point it at a Ghidra 12.x install (the directory holding Ghidra/Processors), or at a revkit bundle's share/revkit/ghidra.
```

`rk-daemon` logs the specs it uses, for example
`rk-daemon: Ghidra processor specs from /home/you/opt/revkit-0.1.0-linux-x86_64/share/revkit/ghidra (bundled, Ghidra 12.1.4)`.

## First run on your machine

Started on a terminal for the first time (no accounts yet, no `--no-auth`
or `--auth`), `rk-daemon` asks how people sign in:

```text
rk-daemon: how should people sign in to this daemon?
  1) No sign-in: only this computer can connect, and anyone using it is an admin.
     Good for your own machine.
  2) Accounts: create an admin account now.
Choose 1 or 2:
```

Answer 2, and it asks for a name and a password (twice, not shown) and
makes the admin account, as `rk-daemon user add NAME --role admin` would.
Then it asks "Remember this choice and don't ask again? [y/N]". Yes writes
`auth = none` or `auth = accounts` into `~/.config/revkit/revkit.conf`
(the file of the `ghidra =` line; its other lines are kept). The details:

- `--no-auth` and `--auth` always override the saved choice.
- `--ask` asks again.
- `/etc/revkit/revkit.conf` may set `auth =` for every user; your own file
  wins.
- A saved `auth = none` is exactly `--no-auth`: loopback only.
- Without a terminal (systemd, the desktop app, scripts) nothing is asked.
  A saved choice still applies; otherwise accounts are required, as
  before.
- A restart from the UI (Restart daemon) keeps the mode it started with
  and doesn't ask again.
- Every start says where the mode came from:
  `rk-daemon: no sign-in (auth = none in ~/.config/revkit/revkit.conf; --auth to require accounts)`.

Or say it on the command line:

```sh
rk-daemon --no-auth --open /bin/ls
```

Then open http://revkit.localhost:50052 in a browser (any `*.localhost`
name is this computer: browsers resolve it to loopback themselves, and the
daemon listens on both `127.0.0.1` and `::1`; `http://127.0.0.1:50052`
works too). `--no-auth` means no
accounts: anyone who can reach the ports is an administrator, which is why
the daemon only accepts it on loopback addresses. The daemon has two
listeners: HTTP on 50052 (the web UI, and Connect and gRPC-web for browsers
and TypeScript) and gRPC on 50051 (Python, MCP, other daemons); `--http`
and `--grpc` move them.

Projects live in memory until the daemon stops. To keep your work (every
name, comment and type you assert, plus cached analysis), give it a
directory, and let the web UI's Open dialog browse your samples:

```sh
rk-daemon --no-auth --project-dir ~/revkit-projects --browse-root ~/samples
```

Restarting with the same `--project-dir` reopens every program as you left
it. If other people share the machine, use an account instead of
`--no-auth`:

```sh
rk-daemon user add alice --role admin --project-dir ~/revkit-projects   # asks for a password
rk-daemon --project-dir ~/revkit-projects                                # then sign in at http://revkit.localhost:50052
```

### A port-free name: http://revkit.localhost

Port 80 needs privilege, which the daemon shouldn't hold. The `.deb` ships
an opt-in **system** socket instead (`/usr/lib/systemd/system/`,
`packaging/linux/systemd/revkit-http80.*`): systemd listens on port 80 of
`127.0.0.1` and `::1` only and starts `systemd-socket-proxyd` as a
throwaway sandboxed user (`DynamicUser=yes`, no capabilities), which
forwards each connection to the daemon on `127.0.0.1:50052`:

```sh
sudo systemctl enable --now revkit-http80.socket    # once; off again: disable --now
# open http://revkit.localhost/
```

The daemon must be listening on `127.0.0.1:50052`: started by hand, or on
first use by your user's `revkit-daemon.socket`
([packaging.md](packaging.md#start-the-daemon-on-first-use-systemd-socket-activation)).
It opens nothing new: every local user could already reach port 50052.

The alternatives, and why not:

- **`setcap cap_net_bind_service=+ep` on `rk-daemon`.** Any user running
  the binary may bind any port below 1024, on any address. The capability
  is lost whenever the package replaces the binary. A capable binary also
  runs in secure-execution mode (`LD_LIBRARY_PATH` and friends ignored).
- **`sysctl net.ipv4.ip_unprivileged_port_start=80`.** System-wide: every
  user and program may then take ports 80 to 1023, on every address,
  including 443.
- **A system socket handing its descriptor to your user's daemon.** A
  system socket unit activates system services, not a user's. It would
  have to be a second, system-managed daemon running as you (`User=`),
  with its own projects. And `rk-daemon` takes one inherited socket, while
  port 80 needs two (IPv4 and IPv6).

### The desktop app

The desktop app starts its own `rk-daemon` on free loopback ports, with
projects in `~/.local/share/dev.revkit.ui/projects` and an administrator
account named after you, created on first start. At every start it gives
the window a fresh API token for that account, so there is no login, and
no other local user can call that daemon; your edits are stamped
`user:<you>`. Open binaries with Ctrl+O (the dialog browses your home
directory). The daemon stops when you close the window; its log is
`~/.local/share/dev.revkit.ui/daemon.log`.

To use another daemon, set `REVKIT_DAEMON=http://host:50052` (that daemon
must allow the app's origin: `--allow-origin tauri://localhost`), or
`REVKIT_UI_URL=https://host:50052/` to load that daemon's own copy of the
UI. The `.deb` depends on the `revkit` package (whose daemon it starts) and
on WebKitGTK 4.1; both desktop packages are built on Ubuntu 24.04 and need
its glibc (2.39) or newer. AppImages need FUSE 2 to mount themselves: on
Ubuntu 24.04, `sudo apt install libfuse2t64`, or run
`./revkit-desktop_0.1.0_amd64.AppImage --appimage-extract-and-run`.

## A shared server with accounts and TLS

On the server (here `rk.example.lan`), create an administrator and start the
daemon on the network with a self-signed certificate:

```sh
rk-daemon user add alice --role admin --project-dir /srv/revkit
rk-daemon --project-dir /srv/revkit --tls-self-signed --tls-san rk.example.lan \
    --http 0.0.0.0:50052 --grpc 0.0.0.0:50051 --browse-root /srv/samples
# rk-daemon: TLS certificate SHA-256 fingerprint 3D:67:84:...
```

Without TLS (`--tls-self-signed`, or `--tls-cert` and `--tls-key` with a
certificate from a CA) the daemon refuses non-loopback addresses, because
passwords and tokens would cross the network in the clear. Browsers warn
about a self-signed certificate: compare the fingerprint the browser shows
with the daemon's (`rk-daemon tls fingerprint --project-dir /srv/revkit`),
accept it, and sign in at https://rk.example.lan:50052.

People get accounts with a role (viewer, editor or admin), optionally
limited to some projects; scripts and agents get API tokens:

```sh
rk-daemon user add bob --role editor --project-dir /srv/revkit
rk-daemon token create --name ci --role editor --user bob --ttl-days 30 --project-dir /srv/revkit   # acts as user:bob
rk-daemon token create --name claude --role editor --project-dir /srv/revkit                       # an agent: agent:claude
```

`token create` prints the secret once. A running daemon picks up account
and token changes within a second. Roles, tokens, TLS, peers and the threat
model are in [security.md](security.md).

## Opening a binary

- At startup: `rk-daemon --open FILE` (repeatable) imports into the project
  `default` (with `--project-dir`, only the first time).
- In the web UI: Ctrl+O, or the Open screen when nothing is loaded: upload
  a file from your computer, or pick one on the server under a
  `--browse-root`. Raw firmware takes a processor, a base address and
  memory regions ([firmware.md](firmware.md)).
- From a script: `rk.import_program("default", content=open("fw.elf", "rb").read(), name="fw.elf")`
  uploads a file (`path=` names a file on the daemon's host instead).

ELF (32 and 64-bit, both byte orders) and PE are recognized and mapped to
Ghidra languages for x86, x86-64, AArch64, ARM and Thumb, RISC-V, MIPS,
PowerPC and more, and their DWARF or PDB debug info is read. Mach-O isn't
supported yet. Import starts analysis (functions, data, strings,
references) in the background, and the views fill in as it arrives.

## The main views

The views are tabs in two docks, main and side (drag a tab, or use the
palette, to move it). Everything is in the command palette: Ctrl+K goes to
an address or symbol, Ctrl+Shift+P or F1 lists the commands with their
keys.

| View | Key | What |
| --- | --- | --- |
| Functions | Ctrl+1 | every function, filterable, paged for huge binaries |
| Listing | Ctrl+2 | disassembly with labels, comments, flow arrows and data; Space toggles it with the graph |
| Decompiler | Ctrl+3 | Ghidra's C for the selected function, linked both ways with the listing |
| Graph | Ctrl+4 | the function's basic blocks |
| Calls | Ctrl+5 | callers and callees |
| Data | Ctrl+6 | defined strings and data |
| Types | Ctrl+7 | structures, enums and typedefs, with an editor |
| Emulator or Debugger | Ctrl+8 | run code from here in revkit's emulator, or debug a process or a gdbserver |
| Compare | Ctrl+9 | match two versions of a program and carry names and types across |

Editing: `n` or F2 renames, `;` comments, `y` sets a type or prototype, `x`
lists references, `f` creates a function, `g` goes to an address, `i` shows
who named something and why, Ctrl+Z undoes. Edits show up live in every
other window and client. "About revkit" in the palette shows the UI's and
the daemon's versions.

## Command-line tools

All of them take `--version` and `--help` and find Ghidra as above. With
`prog` built from a C file that has a `checksum(const unsigned char *, int)`:

```sh
rk-decomp --file prog --symbol checksum                              # decompile one function
rk-lift --analyze --decompile --no-instructions -o prog.json prog    # every function, as JSON
rk-emu --mode call --entry checksum --arg 0x0 --arg 0 prog           # call a function in the emulator
rk-debuginfo --c prog                                                # the types its DWARF describes, as C
rk-diff prog prog-v2 > matches.json                                  # match two versions' functions
```

`rk-dbg` debugs (in the emulator, through gdbserver, or a local process)
and `rk-infer` infers prototypes: [emulator.md](emulator.md),
[debugger.md](debugger.md), [diff.md](diff.md), [infer.md](infer.md).

## The Python SDK in 10 lines

```sh
python3 -m venv ~/rk-venv
~/rk-venv/bin/pip install ~/opt/revkit-0.1.0-linux-x86_64/share/revkit/sdk/revkit-0.1.0-py3-none-any.whl
```

With `rk-daemon --no-auth --open /bin/ls` running:

```python
from revkit import Client

with Client("127.0.0.1:50051", actor="user:alice") as rk:
    prog = rk.program("default/ls")
    funcs = list(prog.functions())
    big = max(funcs, key=lambda f: f.instruction_count)
    print(len(funcs), "functions; the largest is", big.name)
    print(prog.decompile(big.entry.offset).text[:300])
    prog.rename(big.entry.offset, "largest_function", reason="most instructions")
    print(prog.function(big.entry.offset).name)
```

Against a server, pass a token and pin its certificate:
`Client("rk.example.lan:50051", token="rkt_...", fingerprint="3D:67:...")`
(the server then stamps who you are, so leave `actor` out).
`revkit.Daemon()` starts a throwaway local daemon for a script. The API,
every service, versioning, and the TypeScript client
(`share/revkit/sdk/revkit-api-0.1.0.tgz`) are in [api.md](api.md).

## MCP for AI agents

The Python package includes an MCP server: an agent can list functions,
read disassembly and decompiled C, follow references, rename and comment,
and every edit is stamped `agent:<name>` with the agent's reason, so you
can review or revert a whole run.

```sh
~/rk-venv/bin/pip install "$HOME/opt/revkit-0.1.0-linux-x86_64/share/revkit/sdk/revkit-0.1.0-py3-none-any.whl[mcp]"
rk-daemon token create --name claude --role editor --project-dir ~/revkit-projects     # prints rkt_...
claude mcp add revkit -- ~/rk-venv/bin/revkit-mcp --daemon 127.0.0.1:50051 --token rkt_...
```

Any MCP client works the same way: `revkit-mcp` speaks stdio (or
`--transport streamable-http`). Against a `--no-auth` daemon, use
`--agent NAME` instead of a token.

The agent's first call is `about`: the workflow (`list_programs`, pick a
program, `list_functions` or the searches, `decompile`, then `rename`,
`retype`, `rename_field`, `set_comment` with a reason, and search again),
how to give addresses (hex, a name, or a Go To expression such as
`main+0x10` or `file:0x200`) and how long results page. Ask it, for
example, "find the function that parses the config file, name it and its
callers, and comment what each does"; then review its edits in the UI
(Blame shows `agent:claude`), and undo one or the whole run. More:
[api.md](api.md#mcp-server-revkitmcp_server).

## Plugins

Plugins are WebAssembly modules (loaders, analyzers and commands) that run
sandboxed inside the daemon. The bundle has four examples:

```sh
rk-daemon --no-auth --plugin-dir ~/opt/revkit-0.1.0-linux-x86_64/share/revkit/plugins --open prog
```

Their results appear in the listing and their commands in the palette. To
write one in C, start from `share/revkit/sdk/plugins` (the freestanding C
SDK and the examples' sources) and [plugins.md](plugins.md).

## Where to go next

- [security.md](security.md): accounts, roles, tokens, TLS, the threat model.
- [api.md](api.md): the API, the SDKs and the MCP server, versioning.
- [ui.md](ui.md): how the UI works.
- [firmware.md](firmware.md): raw images and firmware analysis.
- [processors.md](processors.md): microcontrollers with several memory spaces, HEX and S-record files, what is tested on which processor.
- [emulator.md](emulator.md), [debugger.md](debugger.md): running code.
- [firmware-emulation.md](firmware-emulation.md): running firmware on a
  machine with interrupts and peripherals.
- [diff.md](diff.md): comparing versions.
- [ghidra-interop.md](ghidra-interop.md): moving work between Ghidra projects and revkit.
- [collab.md](collab.md): linking daemons.
- [plugins.md](plugins.md): writing plugins.
- [packaging.md](packaging.md): building the packages; the release build.
- [known-issues.md](known-issues.md): what doesn't work yet.
