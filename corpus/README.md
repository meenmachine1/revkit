# Benchmark corpus

Reproducible recipes for the binaries revkit is measured against. Binaries are
built in Docker and never committed; `manifest.json` (committed) pins every
binary's sha256 and the sha256 of its source inputs.

## Build

```sh
scripts/build-corpus.sh                    # -> out/corpus/, checks corpus/manifest.json
scripts/build-corpus.sh --update-manifest  # after an intended change to the corpus
scripts/build-corpus.sh -- --only 'elf-x86_64/*'   # partial build (skips manifest check)
```

The script downloads the pinned external tarballs to `out/cache/` (verifying
sha256), builds the toolchain image from `docker/Dockerfile` if needed, and runs
`build.py` in it with `--network none`. The first image build takes about
2 minutes; compiling the whole corpus takes about 5 seconds on 32 cores.

The build is bit-reproducible: the base image is pinned by digest, apt
resolves against a fixed `snapshot.debian.org` date, paths are mapped with
`-ffile-prefix-map`, and PE links use `--no-insert-timestamp` and record only the
PDB's file name. Two builds give the same manifest, and the script fails if
the manifest differs from the committed one.

Toolchains (Debian trixie snapshot 2026-09-15): gcc 14.2, clang/lld 19.1.7,
aarch64/riscv64 cross gcc 14.2 and glibc, mingw-w64 12.

## Layout

```
out/corpus/<format>-<arch>/<compiler>-<opt>/debug/<program>[.exe]   (+ .pdb for PE)
out/corpus/<format>-<arch>/<compiler>-<opt>/stripped/<program>[.exe]
out/corpus/manifest.json
```

A config id is `<format>-<arch>/<compiler>-<opt>`, e.g. `elf-aarch64/clang-O2`.
Each config gives two binaries from the same object files:

- `debug`: ELF with DWARF 5; PE with a CodeView PDB next to it (the manifest's
  `pdb` field; the exporter hands it to Ghidra's PDB analyzer explicitly).
- `stripped`: ELF via `llvm-strip --strip-all`; PE relinked with `-s` and no PDB.

All ELF binaries are dynamically linked PIEs. PE binaries statically link the
mingw-w64 CRT, so they contain a few hundred CRT functions.

## Current corpus: 54 binaries

| format-arch | binaries | configs |
| --- | ---: | --- |
| elf-x86_64 | 22 | gcc, clang x O0, O2 |
| elf-aarch64 | 14 | gcc, clang x O0, O2 |
| elf-riscv64 | 12 | gcc, clang x O0, O2 |
| pe-x86_64 | 6 | clang (mingw target, lld, PDB) x O0, O2 |

| program | source | binaries |
| --- | --- | ---: |
| `features` | self-written, `src/features/` | 28 (every ELF config, PE clang O0/O2) |
| `cjson` | cJSON 1.7.18 (`cJSON.c` + its `test.c`) | 14 |
| `zlib` | zlib 1.3.1 (library + `test/minigzip.c`) | 8 |
| `lua` | Lua 5.4.7 interpreter | 4 |

`features` covers loops (nested, do/while, goto, sieve), switches (dense jump
tables, sparse compare trees, fallthrough, char classes), a bytecode VM with a
big dispatch switch, structs (by-value passing and return, bitfields, unions,
linked lists, flexible array members), function pointers (tables, callbacks,
qsort comparators, a hand-rolled vtable), recursion (mutual, tree, quicksort,
Ackermann), varargs (`va_arg` of ints and doubles, `va_copy`, `vsnprintf`),
floating point (float, double, 128-bit long double soft-float on
AArch64/RISC-V, libm), strings, bit manipulation (CRC32, `__int128`, 64-bit
div/mod) and a malloc-based hash table.

## Held-out set: 88 binaries

`heldout.json` defines a second corpus for evaluation only
([docs/heldout.md](../docs/heldout.md)): project families the corpus above
doesn't have, built by the same image and `build.py`, pinned by
`heldout-manifest.json`. No rule may be tuned against it.

```sh
scripts/build-corpus.sh --heldout          # -> out/corpus-heldout, checks corpus/heldout-manifest.json
```

| program | source | binaries | configs |
| --- | --- | ---: | --- |
| `bzip2` | bzip2 1.0.8 (library + `bzip2.c`; CLI, compression) | 28 | every ELF config, PE clang O0/O2 |
| `mujs` | MuJS 1.3.5 (`one.c` + `main.c`; JavaScript interpreter) | 28 | every ELF config, PE clang O0/O2 |
| `tcc` | Tiny C Compiler 0.9.27 (`tcc.c`, `ONE_SOURCE`, x86-64 target; PE target on PE) | 14 | elf-x86_64/*, elf-aarch64/gcc-O2, elf-riscv64/clang-O2, pe-x86_64/clang-O2 |
| `mbedtls` | Mbed TLS 3.6.2 (crypto library, no TLS/X.509, + `programs/test/selftest.c`) | 10 | elf-x86_64/gcc-O2, elf-x86_64/clang-O0, elf-aarch64/clang-O2, elf-riscv64/gcc-O2, pe-x86_64/clang-O0 |
| `sqlite` | SQLite 3.46.1 amalgamation (`sqlite3.c` + `shell.c`) | 8 | elf-x86_64/clang-O2, elf-aarch64/gcc-O2, elf-riscv64/clang-O2, pe-x86_64/clang-O2 |

| format-arch | binaries |
| --- | ---: |
| elf-x86_64 | 30 |
| elf-aarch64 | 22 |
| elf-riscv64 | 22 |
| pe-x86_64 | 14 |

Recipes may also give `generated` (files a configure step would write,
verbatim; tcc's `config.h`) and `libs_by_format`.

## Diffing corpora

`diff.json` and `diff-heldout.json` define the binary-diffing families
([docs/diff.md](../docs/diff.md)): adjacent source versions of programs,
built by the same image and `build.py` for x86-64 gcc -O2 and -O0, x86-64
clang -O2 and AArch64 gcc -O2.

```sh
scripts/build-corpus.sh --diff           # -> out/corpus-diff, checks corpus/diff-manifest.json
scripts/build-corpus.sh --diff-heldout   # -> out/corpus-diff-heldout (docs/heldout.md: measured once)
```

| set | programs (versions) | binaries |
| --- | --- | ---: |
| `diff.json` | zlib 1.2.13, 1.3, 1.3.1; Lua 5.4.5, 5.4.6, 5.4.7; cJSON 1.7.16, 1.7.17, 1.7.18 | 72 |
| `diff-heldout.json` | bzip2 1.0.6, 1.0.7, 1.0.8; MuJS 1.3.4, 1.3.5; SQLite 3.46.0, 3.46.1; Mbed TLS 3.6.1, 3.6.2 | 72 |

Program names carry the version (`out/corpus-diff/elf-x86_64/gcc-O2/stripped/lua-5.4.6`).
`diff-renames.json` lists functions a project renamed between two
versions, for the evaluation's truth.

## Firmware corpus

`corpus/firmware/` defines raw firmware images for several processors
([docs/firmware.md](../docs/firmware.md#other-processors)), built by their
own toolchain image (`corpus/firmware/docker/Dockerfile`: the same pinned
Debian base and snapshot, plus the Debian cross compilers for MIPS,
PowerPC, SuperH, m68k, arm-none-eabi, xtensa-lx106, riscv64-unknown-elf and
sparc64, avr-gcc with avr-libc, and SDCC) and `corpus/firmware/build.py`,
pinned by `corpus/firmware/manifest.json`:

```sh
scripts/build-firmware-corpus.sh                    # -> out/firmware-corpus, checks the manifest
scripts/build-firmware-corpus.sh -- --only 'sh4/*'  # partial build (skips the manifest check)
```

Sources are pinned downloads (`firmware.json` externals, cached in
`out/cache-firmware`): U-Boot 2025.01 (with one patch,
`patches/u-boot-armv7m-function-type.patch`, for binutils 2.43),
FreeRTOS-Kernel 11.1.0, lwIP 2.2.0, littlefs 2.10.1, Monocypher 4.0.2,
heatshrink 0.4.1, mpaland/printf 4.0.0, and Espressif's crosstool-NG
esp-14.2.0 Xtensa toolchain (for the ESP32; GitHub tag archives get a
`file` name in the cache, which `fetch.py` honours), grbl 1.1h and TI's
msp430-gcc 9.3.1.11 (a toolchain, like Espressif's). Two builds give the
same manifest.

| arch | images |
| --- | --- |
| `mips` | `uboot-malta`, `uboot-maltael`, `fwkit-mips-O2`, `fwkit-mipsel-Os` |
| `ppc` | `uboot-MPC837XERDB`, `uboot-MCR3000`, `fwkit-ppc-O2`, `fwkit-ppc-Os` |
| `sh4` | `uboot-r2dplus`, `fwkit-sh4-O2`, `fwkit-sh4-Os` |
| `m68k` | `uboot-M5208EVBE`, `uboot-M5373EVB` (ColdFire), `fwkit-m68k-O2`, `fwkit-m68k-Os` (68020) |
| `cortexm` | `uboot-stm32f429-discovery`, `uboot-stm32f746-disco`, `fwkit-cortexm3-O2`, `fwkit-cortexm4-Os` |
| `xtensa` | `fwkit-esp32-O2`, `fwkit-esp32-Os` (windowed ABI), `fwkit-lx106-O2`, `fwkit-lx106-Os` (CALL0) |
| `avr` | `grbl-atmega328p-Os`, `mcukit-atmega328p-O2`, `mcukit-atmega328p-Os` |
| `mcs51` | `mcukit-8051-O2`, `mcukit-8051-Os` (SDCC, large model) |
| `msp430` | `mcukit-msp430-O2`, `mcukit-msp430-Os` (MSP430G2553), `fwkit-msp430x-Os` (MSP430X, large model) |
| `z80` | `mcukit-z80-Os` (SDCC) |
| `riscv32` | `fwkit-rv32-O2`, `fwkit-rv32-Os` (RV32IMAC, machine mode) |
| `sparc` | `fwkit-sparc-O2`, `fwkit-sparc-Os` (SPARC V8) |

Per image, under `out/firmware-corpus/<arch>/`: `<name>.bin` (the raw
image: the ELF's loaded segments at their load addresses, gaps zero, as
`objcopy -O binary` lays them out), `<name>.elf` (with DWARF) and
`<name>.truth.json` (the DWARF functions inside the image, the symbol
table's, and the `DW_AT_noreturn` ones). The manifest gives each image's
Ghidra language, load address (`base`), entry point, memory regions
(fwkit's RAM and MMIO) and sizes; `scripts/firmware_score.py` and
`ghidra_export.py --firmware-corpus` read their layout from it; a region
may name its memory space (`xram:0:ff00:rw-:space=EXTMEM` on the 8051).
fwkit is `src/fwkit` (the application, a freestanding C library, a
portable FreeRTOS port, startup code and a linker script per processor);
mcukit is `src/mcukit` (a bare-metal firmware for 8- and 16-bit
microcontrollers, with a board layer per processor; SDCC's images take
their truth from its `.cdb` debug records and the map file).

After changing a source, a flag or the toolchain image, rebuild everything
with `scripts/build-firmware-corpus.sh --update-manifest` and commit the
manifest; a partial build (`-- --only ...`) doesn't check or update it.

## Adding binaries (scaling toward ~200)

Everything is driven by `corpus.json`:

- More configs for an existing program: widen its `configs` patterns (fnmatch
  over config ids; `python3 corpus/build.py --list-configs` lists them all,
  including the unselected `pe-x86_64/gcc-*` DWARF-in-PE configs).
- A self-written program: add `src/<name>/` and an entry with
  `"source": "src/<name>"`, `srcs` globs, optional `libs`, `include`, `cflags`,
  `cflags_by_format` and `configs`.
- An open-source project: add an `externals` entry (URL, sha256,
  `strip_components`, license), then a program with `"external": "<name>"`.
  Prefer release tarballs over GitHub archive links where both exist.
- A new toolchain: add it to `TOOLCHAINS` in `build.py` (and its packages to the
  Dockerfile).

Then run `scripts/build-corpus.sh --update-manifest` and commit the manifest.
Every program across all 16 configs would be 32 binaries, so 200 binaries is
roughly 6-7 programs at full width.

## Manifest

`manifest.json` has the toolchain versions and image tag, each program's
origin (path or URL + sha256) and per-file input hashes, and one entry per
binary: `path`, `program`, `config`, `format`, `arch`, `compiler`, `opt`,
`stripped`, `debug_info` (`dwarf`, `pdb` or `none`), `pdb` (PE debug only),
`source_sha256` (digest of the program's source files), `flags_sha256`,
`sha256` and `size`.

## Known limitations

- Mach-O is deferred: there are no Mach-O binaries in the corpus for now.
  (A best-effort route without Apple's SDK works: shim libc headers, clang
  `--target=*-apple-macos11` and `ld64.lld -undefined dynamic_lookup` give
  loadable but not runnable binaries, and Ghidra picks up a `dsymutil` dSYM.
  It was dropped by a scope decision, not for technical reasons; see
  commit 56b2eba for that version.)
- Only PE is built with clang; gcc/mingw PE configs exist but are unselected.
- Toolchain reproducibility depends on `snapshot.debian.org` being reachable
  when the image is first built.
- glibc and the shared libraries are not part of the corpus; imports show
  up as Ghidra's `EXTERNAL` block and PLT thunks.
