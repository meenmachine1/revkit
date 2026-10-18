# Development

Building revkit from source, the repository layout, and the command-line
tools used in day-to-day development and benchmarking. For installing a
release, see [getting-started.md](getting-started.md).

## Building

Needs CMake 3.20+, Ninja, a C++20 compiler, zlib, liblzma, libzstd and
libbz2 (container file systems; Ubuntu: `zlib1g-dev liblzma-dev libzstd-dev
libbz2-dev`), GNU patch (the decompiler fork's series is applied at
configure time), gRPC and protobuf (Ubuntu:
`libgrpc++-dev libprotobuf-dev protobuf-compiler-grpc libssl-dev`), and a
Ghidra 12.x install for the processor specs (the presets assume
`~/ghidra/ghidra_12.1.4_PUBLIC`; tools also find it as
[getting-started.md](getting-started.md#ghidra-processor-specs) says).

```sh
cmake --preset default        # or asan, tsan; release for packaging
cmake --build --preset default
ctest --preset default
scripts/package.sh            # the packages, into build/dist (docs/packaging.md)
```

`VERSION` holds the version (`scripts/version.sh`); every tool prints it
with `--version`.

Some tests build their fixtures with tools that may be missing and skip
themselves without them: clang (eBPF, Mach-O), javac, node, the dotnet SDK,
and for the bytecode and packer tests ([filesystems.md](filesystems.md#tests-and-fuzzing))
a Python with lupa (real Lua 5.1 to 5.5 and LuaJIT interpreters) and
PyInstaller, in a venv of its own (`$RK_BYTECODE_PYTHON`, else
`~/.cache/revkit/bytecode-venv/bin/python`):

```sh
python3 -m venv ~/.cache/revkit/bytecode-venv && ~/.cache/revkit/bytecode-venv/bin/pip install lupa pyinstaller
```

The web UI is built separately; `rk-daemon` serves `ui/dist`:

```sh
(cd sdk/ts && npm ci) && (cd ui && npm ci && npm run build)
```

## Layout

| Path | What |
| --- | --- |
| `src/<component>/` | Libraries, namespace `revkit::<component>`, headers in `include/revkit/<component>/`, GoogleTest tests in `tests/` |
| `src/decompd/` | Decompiler bundles, the worker pool and the batch driver ([docs/decompd.md](decompd.md)) |
| `tools/` | Executables and scripts (`rk-decomp`, `rk-decompd` worker and repro tool, Ghidra exporter, Ghidra interop, diff tool) |
| `ui/` | Web UI (TypeScript, canvas listing, CodeMirror), Tauri shell, e2e test and benchmarks |
| `sdk/` | Python and TypeScript clients for the API; `sdk/plugins`, the C plugin SDK and example plugins |
| `third_party/ghidra/` | Ghidra's decompiler and SLEIGH engine: pristine Ghidra 12.1.4 plus a patch series applied at build time ([README](../third_party/ghidra/README.md)) |
| `corpus/` | Recipes for the benchmark corpus (binaries are built, not committed) |
| `docs/` | Design notes and formats, including `reference-format.md` and `known-issues.md` (bugs we intend to fix) |

## Command-line recipes

```sh
# Serve a binary to the SDKs, the MCP server and the web UI, then open
# http://revkit.localhost:50052 in a browser and sign in (docs/security.md).
build/tools/rk-daemon/rk-daemon user add me --role admin           # once: an account
build/tools/rk-daemon/rk-daemon --open prog        # gRPC 127.0.0.1:50051, HTTP 127.0.0.1:50052
build/tools/rk-daemon/rk-daemon --no-auth --open prog              # local development: no accounts
build/tools/rk-daemon/rk-daemon --tls-self-signed --http 0.0.0.0:50052 --open prog   # the network: TLS
build/tools/rk-daemon/rk-daemon --project-dir ~/rk --open prog   # persistent projects
build/tools/rk-daemon/rk-daemon --browse-root ~/binaries   # the UI's Open dialog can browse there
build/tools/rk-daemon/rk-daemon --grpc 127.0.0.1:50061 --http 127.0.0.1:50062 --peer 127.0.0.1:50051,token-file=peer.token   # replicate with another daemon

# Decompile a function from an ELF or PE file; the language comes from the loader.
build/tools/rk-decomp/rk-decomp --file prog --symbol main
build/tools/rk-decomp/rk-decomp --file prog.exe --addr 0x140001000

# Raw mode is unchanged: byte 0 of --file is address 0.
build/tools/rk-decomp/rk-decomp --file code.bin --addr 0x0 --lang x86:LE:64:default:gcc

# Instructions and p-code for the file's symbol-derived functions, in the
# reference format (docs/reference-format.md).
build/tools/rk-lift/rk-lift --name elf-x86_64/gcc-O2/debug/zlib -o zlib.json corpus/elf-x86_64/gcc-O2/debug/zlib

# Debug-info ground truth (DWARF; for a PE, its PDB plus any DWARF) in the
# reference format, and a C dump of the types it describes.
build/tools/rk-debuginfo/rk-debuginfo prog.exe > prog.exe.json
build/tools/rk-debuginfo/rk-debuginfo --c prog.exe

# The same, with functions discovered by revkit::analysis.
build/tools/rk-lift/rk-lift --analyze --name elf-x86_64/gcc-O2/debug/zlib -o zlib.json corpus/elf-x86_64/gcc-O2/debug/zlib

# Decompile every function (in decompiler workers), under Ghidra's exported
# inputs (docs/decompiler-inputs.md), and compare the corpus with Ghidra's C.
build/tools/rk-lift/rk-lift --decompile --no-instructions --in-order -j 1 \
    --inputs out/ghidra-db/elf-x86_64/gcc-O2/debug/zlib.json -o zlib-c.json out/corpus/elf-x86_64/gcc-O2/debug/zlib
scripts/decompile-corpus.sh --in-order -P 16
python3 tools/refdiff/refdiff.py out/ref out/revkit-decomp --only c_ast --by-group --group-depth 2
# The same from revkit's own inputs only (nothing exported from Ghidra).
scripts/decompile-corpus.sh --inputs own --out build/corpus-out/revkit-decomp-own --in-order -P 16
python3 tools/refdiff/refdiff.py out/ref build/corpus-out/revkit-decomp-own --common-functions --only functions,c_ast

# A function the decompiler fails on: its bundle, and the repro.
build/tools/rk-lift/rk-lift --analyze --decompile --no-instructions --failure-bundles fails -o out.json prog
build/tools/rk-decompd/rk-decompd --bundle fails/0x401000.bundle      # decompiles it alone, in process
build/tools/rk-decompd/rk-decompd --info fails/0x401000.bundle -v     # what it holds
```

Run code in the emulator ([docs/emulator.md](emulator.md)):

```sh
build/tools/rk-emu/rk-emu prog                                  # a process, to its exit
build/tools/rk-emu/rk-emu --entry fib --arg 10 --trace t.json prog   # a call, with its trace
build/tools/rk-emu/rk-emu --raw --lang ARM:LE:32:v4t:default --region io:d0000000:1000:rw-:volatile \
    --steps 100000 firmware.bin
build/tools/rk-emu/rk-emu --machine board.json --events firmware.bin   # on a board: interrupts, timers, a UART
```

Move work between a Ghidra project and revkit (PyGhidra venv from
`scripts/setup-pyghidra.sh`, SDK from `pip install -e sdk/python`):

```sh
revkit-ghidra-import --ghidra-project ~/work/proj.gpr --program /prog --binary prog   # Ghidra -> revkit
revkit-ghidra-export --binary prog --ghidra-project ~/work/proj.gpr --program /prog   # revkit -> Ghidra
```

Every tool finds Ghidra's processor specs via `--ghidra`, `$GHIDRA_INSTALL_DIR`,
`~/.config/revkit/revkit.conf`, a package's own copy, the build's `GHIDRA_ROOT`
or a common install path, in that order
([getting-started.md](getting-started.md#ghidra-processor-specs)). ELF images load at Ghidra's default base (0x100000 for 64-bit
PIE) so addresses line up with a Ghidra import; `--file-base` keeps the
file's own addresses.

## The Phase 0 harness

```sh
scripts/phase0.sh                    # build corpus (Docker), export Ghidra references, refdiff self-check
scripts/phase0.sh --skip-build --skip-export --candidate out/revkit --baseline B.json
```

See `corpus/README.md`, `tools/ghidra-export/README.md`, `tools/refdiff/README.md`.

## Fuzzing

Fuzzing (clang only): `cmake -B build-fuzz -G Ninja -DCMAKE_CXX_COMPILER=clang++
-DCMAKE_C_COMPILER=clang -DREVKIT_FUZZ=ON -DREVKIT_BUILD_TESTS=OFF`, then run
`build-fuzz/src/loader/fuzz/fuzz_elf`, `fuzz_pe` or `fuzz_macho` (see
`src/loader/fuzz`; seed `fuzz_macho` with `tests/data/macho/build.sh`'s
output).
