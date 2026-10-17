# Status

What is built, component by component, with the measurements behind it.
The [roadmap](roadmap.md) has what's next and the
[feature survey](ghidra-feature-survey.md) compares revkit with Ghidra
feature by feature.

- Ghidra's decompiler and SLEIGH engine built as static libraries, with ELF
  and PE loaders, `rk-lift` and `rk-decomp` (no Java involved).
- `src/debuginfo` reads DWARF and PDBs into a content-hashed type store,
  and `rk-debuginfo` writes their ground truth ([docs/types.md](types.md)).
- `src/cparse` parses C headers into those types for a program's target,
  hash-identical to the debug info's on the whole corpus; `rk-cparse` and
  `TypeService.ParseC` serve it ([docs/cparse.md](cparse.md)).
- `rk-daemon` serves the revkit API (gRPC and Connect/gRPC-web) over real
  binaries: listing, p-code, xrefs, decompilation with token maps, and
  assertions with provenance, blame and revert ([docs/api.md](api.md),
  [docs/backend.md](backend.md)). Functions, the listing's code and
  xrefs come from `revkit::analysis` discovery, which user-asserted
  entries and flow overrides steer. Each project is a fact store
  ([docs/facts.md](facts.md)): edits are assertions, derived data are
  incremental queries, DWARF and PDB debug info are import assertions, and
  `--project-dir` persists projects in LMDB.
- Decompiler parity (Phase 2 gate): given Ghidra's functions, symbols and
  types, all 11380 corpus functions decompile to structurally identical C,
  and the corpus decompiles in about 4.5 s against about 58 s for `analyzeHeadless`
  ([docs/decomp-parity.md](decomp-parity.md)).
- Decompiling from revkit alone (Phase 3): `rk-lift --analyze --decompile`
  and the daemon tell the decompiler what Ghidra's Java side would, from
  revkit's loader, discovery, data analysis and debug info (`src/inputs`):
  92.3% of the functions both sides have decompile to structurally
  identical C (89.2% debug builds, 95.5% stripped; PE 80.7%), with the
  remaining gap measured per kind of fact
  ([docs/decomp-parity.md](decomp-parity.md#from-revkits-own-inputs-phase-3)).
- Data analysis ([docs/data-analysis.md](data-analysis.md)): the data
  Ghidra's analyzers define, as fact-store queries: sized accessed data,
  strings (referenced, and Ghidra's n-gram string search), pointers named
  `PTR_<target>`, switch case labels and Ghidra's no-return evidence, for
  the decompiler and the listing's data rows.
- Ghidra's Decompiler Parameter ID ([docs/param-id.md](param-id.md)):
  where Ghidra runs it (PE below 2 MiB), every function decompiled callees
  first and the parameters, return and convention it finds committed for
  its callers, as Ghidra's analyzer does, as fact-store queries computed
  in the background and published to decompilations as they arrive.
- WebAssembly plugins ([docs/plugins.md](plugins.md)): third-party
  loaders, analyzers and commands run sandboxed in wasmtime (fuel, memory
  cap, no WASI, capabilities) behind a versioned core-wasm interface, with
  a C SDK and examples. Analyzer plugins are fact-engine queries,
  invalidated precisely; commands' edits are assertions with `plugin:`
  provenance; `rk-daemon --plugin-dir`.
- Multi-daemon collaboration: `rk-daemon --peer host:port` replicates
  every project's assertion log with another daemon, both ways (op ids,
  hybrid logical clocks, version-vector catch-up, then live streaming);
  derived facts are recomputed on each, program files are fetched by
  hash, and presence is relayed ([docs/collab.md](collab.md)).
- Security ([docs/security.md](security.md)): local accounts (scrypt),
  login sessions (an HttpOnly, SameSite=Strict cookie with CSRF protection
  for the web UI), API tokens for scripts and agents, viewer/editor/admin
  roles with optional per-project lists, server-stamped provenance
  (`user:<account>`, `agent:<token>`), TLS on both listeners
  (`--tls-self-signed` or a certificate), and authenticated peers;
  `--no-auth` for loopback development.
- Two-way Ghidra interop ([docs/ghidra-interop.md](ghidra-interop.md)):
  a Ghidra project's user work (names, comments, signatures, types, data,
  locals, functions, flow overrides, bookmarks, equates) imports as
  `import:ghidra@<version>` assertions, and revkit's user and agent edits
  apply back to the Ghidra program with their provenance; a headless round
  trip runs in CTest.
- Prototype inference (`src/infer`, [docs/infer.md](infer.md)): every
  function's parameters, types, return and varargs from Ghidra's decompiler
  per function, combined across the call graph to a fixpoint as fact-store
  queries, with library signatures generated from system headers. On the
  stripped corpus, 13.6% of prototypes match the DWARF/PDB truth by
  signature against 4.7% for Ghidra (`rk-infer`, `rk-daemon
  --infer-prototypes`).
- Held-out evaluation ([docs/heldout.md](heldout.md)): 88 binaries of
  bzip2, MuJS, tcc, Mbed TLS and SQLite that no rule was tuned on
  (`scripts/build-corpus.sh --heldout`, `scripts/ci.sh --heldout`). There
  the Phase 4 gate (signature on the matchable subset) is met: revkit
  36.0% against Ghidra's 18.8%, +17.2 pp (+33.1 in-sample); own-input C
  is 75.9% structurally identical (90.1% in-sample; PE 40.0%, 65.3%
  in-sample). Never tune on it.
- Decompiler workers ([docs/decompd.md](decompd.md)): Ghidra's
  decompiler runs in `rk-decompd` worker processes for the daemon,
  `rk-lift` and `rk-infer`, from self-contained per-function input
  bundles (deterministic, hashed: the cache key and an exact repro,
  `rk-decompd --bundle FILE`). A crash, a hang past the hard deadline
  (SIGKILL) or running out of memory costs one function and is a fact
  (`decompile_failure`: kind, bundle hash, decompiler build), shown in the
  UI with Retry and Export repro; output is byte-identical to the
  in-process decompiler's on the tuning corpus.
- A web UI (`ui/`, [ui/README.md](../ui/README.md)) over that API, in a browser
  tab or a Tauri shell: functions, a canvas listing, the decompiler linked
  to it, navigation, a command palette, and renames and comments that show
  live in every client, with provenance and undo ([docs/ui.md](ui.md)).

- Emulator ([docs/emulator.md](emulator.md)): revkit's own p-code
  interpreter over SLEIGH's p-code (values up to 64 bytes, copy-on-write
  memory over the image, MMIO hooks, faults that undo the instruction, a
  bounded deterministic trace), with Linux system calls, C library stubs
  for imports, breakpoints, watchpoints and step over/out. `rk-emu`, the
  API's `EmulatorService` (sessions per client, bounded) and the UI's
  Emulator view. Checked against real execution: 36 C programs for x86-64,
  AArch64 and RISC-V (registers, memory, output, status), static glibc,
  and the ARM firmware fixture from its reset vector.
- Debugger ([docs/debugger.md](debugger.md)): one session model over
  the emulator and live targets through its own GDB remote protocol client
  (gdbserver, qemu-user, qemu-system, OpenOCD, J-Link), launching the
  program locally, PIE slides mapped to the listing, and every stop recorded
  on a timeline the registers, memory and pc mark can be scrubbed through.
  `rk-dbg`, the API's `DebugService` and the UI's Debugger view.
- Firmware emulation ([docs/firmware-emulation.md](firmware-emulation.md)):
  a machine around the emulator's CPU, described in JSON: exception models
  for ARM (vectors, IRQ/FIQ/SWI/aborts, banked modes), Cortex-M (NVIC,
  SysTick, stacking) and MIPS32 (Status/Cause/EPC, Count/Compare), timers,
  UARTs and interrupt controllers (SP804, PL011, PL190, a GIC-lite, PL031
  and configurable ones), auto-ack registers for polling loops,
  WebAssembly peripheral plugins, deterministic time, and a starter
  machine derived from the program. `rk-emu --machine`, machines in
  `EmulatorService` and `DebugService`, and the Debugger's "Emulator
  (machine…)" target with interrupts on the timeline.

- Firmware ([docs/firmware.md](firmware.md)): raw images (`ImportOptions`
  format `raw`, `rk-lift --raw`, the UI's Open dialog) with a header skip,
  a length and RAM/MMIO regions, and firmware-grade discovery for ARM and
  Thumb from the exception vectors alone (literal pools, interworking, ARM
  jump tables, pointer tables, Ghidra's start patterns, an aggressive code
  finder). On a 2 MB ARMv4T camera firmware it finds 98.0% of the user's
  Ghidra functions (precision 96.7%; Ghidra's own default analysis finds
  95.4%), and 80.5% of a 200-function sample decompiles to the same
  structure as Ghidra's (`scripts/bench-firmware.sh`). On a 36-image
  corpus of firmware built from source for twelve processor families
  (MIPS, PowerPC, SuperH-4, 68000/ColdFire, Cortex-M, Xtensa, AVR, 8051,
  MSP430, Z80, RISC-V 32 and SPARC: U-Boot, a FreeRTOS/lwIP firmware, grbl
  and a bare-metal MCU firmware), it finds 83-99.9% of Ghidra's functions
  per processor, and more of the DWARF functions than Ghidra on seven of
  twelve (`scripts/ci.sh --firmware`,
  [docs/firmware.md](firmware.md#other-processors)).

- Processors ([docs/processors.md](processors.md)): every SLEIGH
  language of the Ghidra install loads, lifts, and goes through discovery,
  the decompiler and the emulator (`scripts/processor_sweep.py` over all
  189: no crash, no hang). Harvard and word-addressed microcontrollers
  (AVR, the 8051, PIC) keep their memory spaces: addresses read
  `code:003a` and `mem:0100` as in Ghidra, names are `FUN_code_003a`, and
  the processor spec's default blocks and labels are laid out. Firmware
  loads from flat binaries, Intel HEX, Motorola S-records and AVR ELF.

- Scale: `rk-lift` streams its output (cmake: 23 GB -> 0.4 GB), and large
  real binaries (up to Chrome's 293 MB) are benchmarked with
  `scripts/bench-large.sh`. cmake's `main` arrives decompiled 1.2 s after
  launching `rk-daemon` (parallel discovery, references from discovery's
  decode); decompilation is bounded (timeouts, a varnode bound,
  cancellation, a memory-aware scheduler); prototype inference converges
  on cmake in 9 rounds and 1.84 GB. Results and the two scale gates are in
  [docs/scale.md](scale.md). Idle SLEIGH engines are parked and shared by
  language: 8 tiny programs and lua hold 302 MB instead of 1051 MB
  ([docs/memory.md](memory.md)).

## Loaders

`src/loader` parses ELF32/ELF64 (both endians) and PE32/PE32+ with
bounds-checked readers; malformed input raises `LoadError` or a warning.
Machines map to Ghidra languages for x86, x86-64, AArch64, ARM, RISC-V,
MIPS and PowerPC. Mach-O is deferred. Section contents (compressed ELF
sections inflated) and a PE's CodeView record (PDB path, GUID, age) feed
the debug-info readers. ELF images also list their relocations (`RELATIVE`
targets resolved at the load address, `JUMP_SLOT`/`GLOB_DAT` with symbol
names; nothing is applied to memory), PLT section layout, and init/fini
code from the dynamic table. `src/lift` wraps `ghidra::Sleigh`
over a loaded image, with instruction text matching Ghidra's Java output.
Plain `rk-lift` takes functions from sized symbols, PE exports and the
entry point, and unwind tables (PE `.pdata`, ELF `.eh_frame`, which
survive stripping) named `FUN_<addr>`; `rk-lift --analyze` discovers them.

## Function discovery

`src/analysis` (`revkit::analysis`) finds functions, bodies, thunks,
no-return functions and jump tables as pure queries over the fact engine
(design notes in `src/analysis/include/revkit/analysis/analysis.h` and
`src/analysis/jump_tables.cc`):
- recursive descent from the seeds (entry, symbols, exports, unwind
  entries, init/fini code, PLT stubs) and then from call targets;
- bodies of reachable code only, so padding is excluded;
- import stubs named from `JUMP_SLOT`/`GLOB_DAT`/IAT slots;
- no-return functions known by name or inferred;
- jump tables recovered by probing the p-code with the switch index set to
  0, 1, 2, ... until the guard leaves the path; and computed gotos (labels
  as values: an interpreter's opcode dispatch, CPython's eval loop) whose
  index is a zero-extended byte, probed over its 256 values until the
  entries stop being code near the jump. Without that a function such as
  CPython's `_PyEval_EvalFrameDefault` was its first few blocks, and the
  function list's Size was a few dozen bytes;
- user assertions as inputs: a `FUNCTION_BOUNDS` entry is a seed (its body,
  if given, wins over discovered ones), a removed function is neither seed
  nor call target, and a `FLOW_OVERRIDE` changes the instruction's flow as
  Ghidra's flow overrides do.

Every query is keyed by program (`ProgramKey{id}`, or a `Location` in it),
so one fact store holds a project's programs, each in its own code space.

```cpp
lift::initialize(ghidra_root);
analysis::register_queries(db.engine());
const analysis::ProgramKey prog{"default/prog"};
analysis::import_image(db, prog, image, analysis::describe(image, "x86:LE:64:default:gcc"));
auto functions = db.snapshot().get<analysis::Functions>(prog);
```

Against Ghidra on the 54-binary corpus (`scripts/ci.sh`, baseline
`corpus/baselines/rk-lift-analyze.json`), plain `rk-lift` → `--analyze`:

| arch | functions | names | bodies | instructions |
| --- | --- | --- | --- | --- |
| elf-aarch64 | 69.0% → 84.7% | 67.3% → 84.5% | 69.0% → 84.7% | 98.85% → 99.99% |
| elf-riscv64 | 59.9% → 80.0% | 29.8% → 62.5% | 59.7% → 79.9% | 98.11% → 99.38% |
| elf-x86_64 | 70.7% → 85.5% | 69.1% → 84.8% | 41.8% → 82.0% | 97.17% → 99.79% |
| pe-x86_64 | 77.5% → 96.0% | 43.5% → 62.1% | 42.0% → 96.0% | 96.64% → 99.87% |
| all | 69.4% → 85.7% | 59.4% → 78.4% | 52.7% → 84.2% | 97.77% → 99.80% |

P-code is identical at all 634,731 addresses both sides have.

Ghidra also lists 1,552 placeholder functions in the `EXTERNAL` block it
synthesizes, one per imported symbol. Without them, functions agree 99.2%,
names 90.7% and bodies 97.5%. What still differs:

| cause | count | right |
| --- | --- | --- |
| PE debug names come from the PDB | 485 names | Ghidra (needs PDB import) |
| RISC-V PLT stubs named after their import; Ghidra leaves `FUN_ram_…`, since `jalr t1` writes a register | 298 names | revkit |
| x86-64 gcc Lua: dead epilogues after calls to `lua_error`, which never returns but is declared `int`; revkit infers no-return (Ghidra does too, on AArch64) | 169 bodies | revkit |
| GCC clone names (`print.constprop.0`); Ghidra takes `print` from DWARF | 43 names | Ghidra (needs DWARF names) |
| unreferenced mingw import stubs are functions in stripped PE too; Ghidra only has them where the PDB names them | 52 functions | revkit |
| RISC-V `run_vm`: a jump table Ghidra's decompiler misses | 2 bodies | revkit |
| RISC-V PLT header is a function, as Ghidra makes it on x86-64 and AArch64 | 12 functions | revkit |
| Ghidra functions made of one alignment `nop` (AArch64 gcc cjson) | 10 functions | revkit |
| pointer-only functions without `.pdata` (PE clang-O2 debug, from PDB) | 6 functions | Ghidra; needs data-pointer discovery |

Not done yet:
- discovery from data pointers;
- a cheaper p-code-only decode;
- `analysis.functions` is one whole-program memo.
