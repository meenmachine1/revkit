# revkit

A reverse-engineering workbench built around Ghidra's decompiler and SLEIGH
engine, compiled into a native C++ server. No Java.

One server, `rk-daemon`, loads ELF, PE and raw firmware images, analyzes
them, and serves the results to a web UI, a desktop app, Python and
TypeScript SDKs, an MCP server for AI agents, and command-line tools. People
and agents can work on the same project at once: every rename, type and
comment records who made it and why, and can be undone.

![revkit's main window: functions, listing and decompiler](docs/images/revkit.png)

## Features

- **Decompiler**: Ghidra's decompiler, fed by revkit's own analysis. Measured
  against source code, it beats Ghidra's output on more functions than it
  loses ([decomp-quality.md](docs/decomp-quality.md)).
- **Analysis**: function discovery, data and strings, switch tables,
  prototype inference, DWARF and PDB, C header import, auto-created structs,
  MSVC RTTI, Function ID, library prototypes.
- **Firmware**: raw images with processor and load-address detection, every
  SLEIGH language Ghidra ships (189), Harvard and word-addressed MCUs.
- **Emulator and debugger**: a p-code emulator with rewind and Python hooks;
  live debugging over GDB remote (gdbserver, QEMU, OpenOCD, J-Link) with
  stack unwinding, watches and conditional breakpoints; firmware machines
  with interrupts and peripherals.
- **Comparing binaries**: program diff, function compare with markup
  porting, and BSim similarity search.
- **Collaboration**: accounts, roles, API tokens, TLS, live multi-user
  editing, and replication between servers.
- **Automation**: Python and TypeScript SDKs, an in-app Python console and
  scripts, an MCP server, and sandboxed WebAssembly plugins.
- **Ghidra interop**: bring a Ghidra project's work into revkit and send
  revkit's edits back.

[docs/status.md](docs/status.md) has the details and the numbers behind
them; [docs/ghidra-feature-survey.md](docs/ghidra-feature-survey.md)
compares revkit with Ghidra feature by feature.

## Quick start

revkit runs on Linux, x86-64 or aarch64 (including Linux VMs on Apple
Silicon Macs).

**1. Install** (no root needed):

```sh
curl -fsSL https://raw.githubusercontent.com/meenmachine1/revkit/main/install.sh | sh
```

It downloads the latest release for your machine, checks it against the
release's checksums, and installs it into `~/.local`. Run it again, or
`revkit update`, to update. On a system older than the build (glibc below
2.34: Ubuntu 20.04, say) it runs the server in Docker instead, if Docker is
installed.

**2. Run it:**

```sh
revkit /bin/ls
```

This starts the server, imports `/bin/ls` and opens
<http://revkit.localhost:50052> in your browser. `revkit` on its own opens
it again; `revkit stop`, `revkit status` and `revkit logs` do what they
say. Your work is kept in `~/.local/share/revkit/projects`. Import more
binaries with **Import binary…** or by dropping a file on the page.

Other ways to install, from the [releases page](https://github.com/meenmachine1/revkit/releases):
the desktop app (`revkit-desktop_0.1.0_amd64.AppImage`: make it executable
and run it), a `.deb` (`sudo apt install ./revkit_0.1.0_amd64.deb`, then
`revkit`), or the portable bundle. Running `rk-daemon` yourself (ports,
accounts and TLS, the port-free <http://revkit.localhost>) is in
[getting-started.md](docs/getting-started.md).

**3. Script it** (optional). The Python SDK ships in the bundle:

```sh
python3 -m venv ~/rk-venv
~/rk-venv/bin/pip install "$(ls ~/.local/share/revkit/current/share/revkit/sdk/revkit-*.whl)[mcp]"
```

```python
from revkit import Client

with Client("127.0.0.1:50051", actor="user:me") as rk:
    prog = rk.program("default/ls")
    biggest = max(prog.functions(), key=lambda f: f.instruction_count)
    print(prog.decompile(biggest.entry.offset).text)
    prog.rename(biggest.entry.offset, "biggest_function", reason="most instructions")
```

**4. Connect an AI agent** (optional). With the `[mcp]` extra installed, for
Claude Code:

```sh
claude mcp add revkit -- ~/rk-venv/bin/revkit-mcp --daemon 127.0.0.1:50051 --agent claude
```

Any MCP client works the same way. The agent's edits show up live in the UI,
marked `agent:claude`, and can be reviewed or undone.

## Documentation

| | |
| --- | --- |
| [Getting started](docs/getting-started.md) | Installing, a shared server with accounts and TLS, the views, the SDK, MCP, plugins |
| [UI](docs/ui.md) | Every view, command and key binding |
| [API](docs/api.md) | The gRPC/Connect API, the SDKs and the MCP tools |
| [Firmware](docs/firmware.md) | Raw images, detection, firmware emulation |
| [Debugger](docs/debugger.md) and [emulator](docs/emulator.md) | Targets, timelines, hooks |
| [Collaboration](docs/collab.md) and [security](docs/security.md) | Multi-user, replication, accounts, TLS |
| [Status](docs/status.md) | What's built, with measurements |
| [Development](docs/development.md) | Building, the layout, command-line recipes |

## Building from source

You need CMake 3.20+, Ninja, a C++20 compiler, gRPC and protobuf, OpenSSL,
zlib, liblzma, libzstd, libbz2, GNU patch, Node.js 22 or newer (for the
UI), and a Ghidra 12.x install for its processor specs. On Ubuntu:

```sh
sudo apt install cmake ninja-build g++ libgrpc++-dev libprotobuf-dev protobuf-compiler-grpc \
    libssl-dev zlib1g-dev liblzma-dev libzstd-dev libbz2-dev patch
```

```sh
cmake --preset default && cmake --build --preset default
(cd sdk/ts && npm ci) && (cd ui && npm ci && npm run build)
build/tools/rk-daemon/rk-daemon --no-auth --open /bin/ls
```

The presets look for Ghidra in `~/ghidra/ghidra_12.1.4_PUBLIC`; see
[getting-started.md](docs/getting-started.md#ghidra-processor-specs) for
other locations. Tests, packaging and the repository layout are in
[development.md](docs/development.md).

## License

revkit is licensed under the GNU Affero General Public License, version 3 or
later ([LICENSE](LICENSE)). If you run a modified revkit as a service for
others, the AGPL asks you to offer them its source.

revkit includes third-party code under its own licenses, notably Ghidra's
decompiler and SLEIGH engine (Apache-2.0); see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
