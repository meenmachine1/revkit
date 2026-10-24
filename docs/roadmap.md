# Roadmap

What is requested but not built yet, and what is in flight. Each entry says
what it is and why; design notes go in the feature's own doc when work starts.

## Now (2026-10-23)

Landing what the 2026-10-21 round left on branches, then measuring it on
the DS matching-decompilation run:

- `phase16/dsfixes` (`api_minor` 104): what the DS run hit: calls into
  another module no longer taken as no-return, DS I/O volatile by default,
  Thumb-keeping function bounds, per-item refusals in assertion batches
  and faster batches, import name conflicts, store compaction.
- `phase13/nds-kb` (105): the decomp knowledge base
  ([decomp-kb.md](decomp-kb.md)) and NitroFS/NARC as file systems.
- `phase16/matchshape` (106): source-shaped output (narrow-load
  signedness, comparison form, flag-set loop tests, compilable C,
  bitfields, token gaps; inference types loads as the final C does);
  re-measured 2026-10-23 ([decomp-quality.md](decomp-quality.md#source-shape-2026-10-21)):
  every family still wins, the identity rates with Ghidra's C fall on
  purpose and their baselines are re-saved.

Next: rerun the DS run on the result; the vtables, clobber lists and
other follow-ups listed in the 2026-10-21 entry below; carving; the end
of the project's test and scrub ([bug-scrub.md](bug-scrub.md) part 3, Left).

## Round of 2026-10-21

Making revkit a better front end for matching decompilation, from what the
DS experiment found ([known-issues.md](known-issues.md#found-by-a-matching-decompilation-run-on-a-nintendo-ds-game-2026-10-18)),
four at a time:

- ~~**Source-shaped output:** narrow loads and stores typed by their
  instruction's signedness, comparison constants and operand order kept,
  bitfields, signed loop guards, output a C compiler takes as is, and the
  token gaps~~ *done* (`api_minor` 106, feature `decompiler-settings`;
  [decompiler-inputs.md](decompiler-inputs.md#source-shape): the fork's
  source-shape options on by default for revkit's inputs, per-program
  settings for encoded comparisons and compilable C). Left: bitfields
  detected from masks in inferred structures, stack arrays sized right,
  struct copies as one assignment, a var-to-var compare's operand order,
  and inference again when a program's load types change.
- ~~**Inference on 32-bit ARM**, prototypes for 32-bit callees, then C++
  classes from headers as the `this` type~~ *done*: inference on ARM and
  Thumb, MIPS o32 and PowerPC by default
  ([infer.md](infer.md#32-bit-processors),
  [decomp-quality.md](decomp-quality.md#inference-on-32-bit-arm-mips-and-powerpc-2026-10-21):
  firmware composite 3892/10223/515 → 8548/4611/1471, every family
  winning; casts, `noise` and temporaries now lose in those families);
  an SDK's interrupt restore takes its argument and stack arguments past
  r3 are counted (the 32-bit ARM fixture, `tests/data/arm32`); a class an
  imported C++ header defines is `this`'s type
  ([types.md](types.md#c-classes-as-this)). Next: vtables without RTTI
  (`_ZTV` symbols, constructors storing the vtable pointer) and virtual
  calls through a typed vtable; per-function clobber lists for the
  `extraout_` noise; RISC-V rv32 and x86-32 need corpus images.
- **What the DS run hit** (landed 2026-10-23, `api_minor` 104;
  [nds.md](nds.md#what-a-matching-run-needed)): no-return evidence only
  for a program's own code and under `SetNoReturn(false)`, the DS's I/O
  as volatile blocks (`memory_preset`), Thumb-keeping function bounds,
  per-body refusals and `skip_invalid`, batches of C prototypes and data
  definitions 7 to 15 times faster, import name conflicts, store
  compaction (`rk-daemon compact`, `CompactProject`, `--cache-limit-mb`),
  fewer retained analysis revisions. Next: the UI for name conflicts and
  compaction.
- ~~**The decomp knowledge base**~~ *done* (`api_minor` 105, feature
  `decomp-kb`; [decomp-kb.md](decomp-kb.md)): exact matches, names
  through matched callers, BSim near matches with the diff, the export,
  the UI; NitroFS and NARC in the file system browser. Next: prototypes
  and types from the KB, data names through the code, objects as a
  source, functions only vtables reach in a ROM.

## Done 2026-10-18 (later)

Toward what rea covers that revkit doesn't
([the comparison](wishlist.md)), three at a time:

- ~~**Apple applications:** `.app` and `.ipa` bundles, `Info.plist`,
  entitlements and code-signature details~~ *done* (`api_minor` 100,
  feature `apple-bundles`; [apple-apps.md](apple-apps.md): bundles as file
  systems with their frameworks found by `@rpath`, property lists, code
  signatures and provisioning profiles read, not verified); ~~Interface
  Builder nibs and UI actions traced to their Objective-C handlers~~
  *done* (`api_minor` 101, feature `ui-actions`;
  [apple-apps.md](apple-apps.md#interface-builder-and-ui-actions)). Next
  for Apple: asset catalogs, OpenStep plists and `.strings`, segues and
  gesture recognizers, dSYM.
- ~~**Android resources and crash dumps:**~~ *done*: ~~binary `AndroidManifest.xml` and
  `resources.arsc`, Flutter's Dart snapshot details~~ *done* (`api_minor` 98,
  feature `android`; [android.md](android.md)): the manifest as XML and as
  fields (components' exported flags and intent filters, the security
  flags), the resource table and strings, the native libraries by ABI with
  their JNI exports and the DEX's native methods linked to them, imported
  with their neighbours linked, Flutter's snapshot hash and engine build
  ID; ~~ELF core files and Windows minidumps (threads, registers, modules)
  in the debugger views~~ *done* (`api_minor` 102, feature `crash-dumps`;
  [crash-dumps.md](crash-dumps.md)): a stopped, read-only session with the
  signal or exception, the faulting module, function and instruction, CFI
  backtraces through project libraries and host files, the threads.
- ~~**Results that state their unknowns, and EVM:**~~ *done*: evidence and
  limitations on MCP and SDK results (`api_minor` 97, feature
  `result-evidence`; [api.md](api.md#result-evidence)); an EVM bytecode
  processor (`api_minor` 99, feature `evm`; [evm.md](evm.md)).

- **Decomp knowledge base** (requested 2026-10-18): matching
  decompilation as reproducible, transferable work. ~~Import and export
  ds-decomp projects~~ *done*, with `.nds` ROMs, module programs linked
  across modules and decomp scratches (`api_minor` 103, feature `nds`;
  [nds.md](nds.md)); ~~ingest finished decomps (source, compiler and
  flags per unit, a per-function manifest); apply them to a new game by
  Function ID (exact: the name and verbatim source) and BSim (near: a
  starting scratch with the diff); export dsd symbols and source~~ *done*
  (`api_minor` 105, feature `decomp-kb`; [decomp-kb.md](decomp-kb.md));
  left: types and prototypes from the KB, compiled objects as a source,
  and producers beyond the DS (GBA, N64, GameCube/Wii decomps).

- **Matching decompilation, Nintendo DS first:** ~~ds-decomp projects and
  `.nds` ROMs as module programs linked across modules, names back to
  `symbols.txt`, decomp scratches~~ *done* (`api_minor` 103, feature `nds`;
  [nds.md](nds.md)); ~~a decomp knowledge base that applies finished
  decomps to a new game; NitroFS and NARC in the file system browser~~
  *done* (`api_minor` 105; [decomp-kb.md](decomp-kb.md),
  [filesystems.md](filesystems.md#formats)).

- ~~**The end-of-round test**~~ *done* (2026-10-21; [bug-scrub.md](bug-scrub.md#part-3-2026-10-20-the-end-of-round-test)):
  the full ctest and `ui_e2e`, ASan + UBSan over every suite and
  `python_sdk`, TSan over the new concurrency and the rest, the round's 42
  fuzz harnesses and `fuzz_pe`/`fuzz_elf`, and a security review of the
  new attack surface. Found and fixed: a viewer's ds-decomp export
  reading any host file, the provider sandbox's gaps (another process's
  limits and signals, modes, `/proc`), memory bombs from aliased entries
  in the new parsers, five fuzzer finds, and the sanitizer and clang builds.

Then: recording what a program does (run, capture, compare), and carving
(binwalk-style: signatures at any offset checked by each format's own
parser, entries `@0x<offset>.<kind>`, an entropy strip; API, SDK, MCP and
the browser's "Scan for embedded data…"), then squashfs before 4.0.
~~Firmware formats (JFFS2, UBI/UBIFS, YAFFS2, TRX, Android sparse and
vendor boot images, device trees and FIT, Intel HEX and S-records as
containers)~~ *done* ([filesystems.md](filesystems.md#formats)).

## Done 2026-10-18

- ~~**EVM contracts**~~ *done* (`api_minor` 99, feature `evm`;
  [evm.md](evm.md)): revkit's own SLEIGH processor for Ethereum Virtual
  Machine bytecode, compiled by `rk-sleigh` (the fork's SLEIGH compiler, now
  built) from a processors directory beside Ghidra's; runtime and creation
  code, binary or hex text; the dispatcher's functions named by selector
  (a 33-entry table of well-known signatures), JUMPDESTs labelled, computed
  jumps resolved by a stack analysis (656 of 658 in OpenZeppelin's ERC-20
  and ERC-721), `ProgramSummary.evm`. Left: internal functions as
  functions, 256-bit and address types, storage slot names.
- ~~**Results that state their evidence**~~ *done* (`api_minor` 97, feature
  `result-evidence`; [api.md](api.md#result-evidence)): source tiers on every
  fact origin (user, debug info, symbol, library, agent, inferred, guessed,
  default), the unknowns of a function and its decompilation (indirect calls
  and jumps with no known target, flow cut short, a failure, analysis still
  running), and on the core MCP tools an `evidence` envelope (revision,
  provenance, unknowns, limits, the fields holding the target's own text) with
  the `_meta` target-content marker; edits say what changed and how to undo it.
  Left: the envelope on the other MCP tools (callers, callees, the graph,
  listings, the emulator and debugger), unknowns in the lists and in the UI.
- ~~**Bytecode step 1: identify and extract**~~ *done* ([bytecode-lifting.md](bytecode-lifting.md#plan)):
  ~~container formats for PyInstaller, Electron asar, Node pkg, nexe and
  SEA, Bun executables, an appended zip (py2exe, cx_Freeze), and Lua and
  LuaJIT chunks in firmware~~ *done* (`api_minor` 96, feature
  `packed-executables`; [filesystems.md](filesystems.md#packed-executables));
  Deno executables and py2exe's `PYTHONSCRIPT` written up, not read; ~~eBPF objects to
  Ghidra's eBPF language~~ *done*; ~~.NET assemblies recognised by their
  CLR header~~ *done* (`api_minor` 94, feature `dotnet`: IL-only ones
  imported without code analysis); ~~the bytecode formats named in
  detection, with content kinds~~ *done* (`api_minor` 95, feature
  `content-kinds`; [filesystems.md](filesystems.md#content-kinds)).
- ~~**Go function names from pclntab**~~ *done* (`api_minor` 93, feature
  `go-pclntab`; [go.md](go.md)): a stripped Go program's functions named
  from its pclntab (all four layouts; ELF, PIE, PE by its magic, Mach-O),
  their source lines as plate comments, Go's no-return functions, the
  golang compiler spec (Go's register ABI) and package namespaces in the
  symbol tree; a stripped `ls`-sized test program goes from 839 `FUN_` to
  1. Next for Go: strings, runtime types, signatures
  ([go.md](go.md#not-done-yet)).
- ~~**External decompiler providers**~~ *done* (bytecode-lifting.md step
  2; `api_minor` 92, feature `external-decompilers`;
  [providers.md](providers.md)): ILSpy, jadx, Vineflower, CFR, unluac,
  pycdc, webcrack and wasm-decompile as child processes in `rk-sandbox`
  (limits, Landlock, seccomp), cached by input hash, provider and version;
  ILSpy's C# (and the others') in the decompiler pane for bytecode programs,
  Decompile with … in the file system browser; `ProviderService`, the SDK
  and MCP. Next: a DEX/APK fixture (needs `d8`), a LuaJIT provider, linking
  source lines to the listing (step 3).
- ~~**Inferred structures for passed-on pointers**~~ *done*
  ([infer.md](infer.md#structures),
  [decomp-quality.md](decomp-quality.md#inferred-structures-for-passed-on-pointers-2026-10-18)):
  one structure per class of pointers that are one value, nested fields,
  arrays of structures and returns typed; published by the daemon as the
  program's types (`analysis:infer.prototypes`, `/inferred`). Tuning
  composite 1957/809/718 → 2159/667/658, casts through parameters 2,842
  → 77, `members` 5/1688/21 → 672/681/361. Left: length and temporaries
  on -O2 builds (per-field copies), PE clang -O2 a tie, classes of one
  type that never meet, structures on 32-bit targets (inference is off
  there).

## Done in the round after v0.1.2 (2026-10-16)

After v0.1.2:

- **Mach-O**, stage 1: ~~the loader~~ *done* (`api_minor` 90, feature
  `macho`; [macho.md](macho.md)): thin and universal files (a slice per
  program, the default arm64), segments and sections as Ghidra's blocks,
  symbols, exports, binds, rebases and chained fixups, stubs and GOT slots
  named, dylibs linked, UUID, build version, code signature and encryption
  reported, Ghidra's language opinions; a fuzz harness. ~~Objective-C and
  Swift metadata~~ *done* (`api_minor` 91, feature `objc`;
  [macho.md](macho.md#objective-c-and-swift)): classes, methods (relative
  lists too), ivars, properties, protocols, categories and selector
  references typed and named, methods as functions with their prototypes
  and `self` typed, Swift descriptors, accessors and vtables;
  `ListObjcClasses`. The dyld shared cache and kernelcache come later.
- ~~**Decompiler quality against the source, measured again**~~ *done*
  ([decomp-quality.md](decomp-quality.md#re-measured-and-inferences-call-graph-fixed-2026-10-17)):
  unchanged since the last run; five inference fixes (callers' pointers
  behind casts, no-return evidence, parameters passed on, tail calls, one
  type per passed pointer) took the tuning composite from 1758/881/845 to
  1957/809/718. Next: structures for passed-on pointers (`*(T *)((long)
  param_1 + off)` is most of the casts left), then float returns.
- **Build metadata and agent setup:** ~~Go build info and Rust
  cargo-auditable dependencies from ELF, PE and Mach-O~~ (*done*:
  `GetBuildInfo`, `api_minor` 88, feature `build-info`;
  [build-info.md](build-info.md)); ~~agent instructions shipped with the MCP
  server and a setup command for coding agents~~ (*done*: the workflow
  guide as the `revkit://guide` resource and the `investigate` prompt,
  and `revkit-mcp setup` / `revkit mcp setup` for Claude Code, Codex,
  Cursor and Gemini CLI; [api.md](api.md#mcp-server-revkitmcp_server));
  ~~value tracing across calls, building on the slices~~ (*done*, a first
  slice: `TraceValue`, `api_minor` 89, feature `value-trace`, through
  direct calls with matched calls and budgets;
  [api.md](api.md#tracing-a-value-across-calls); memory, resolved indirect
  calls and struct fields are next). Next after it: Go function names from
  pclntab (*done*, [go.md](go.md)).
- **Lifting bytecode and scripts**: the design note is done
  ([bytecode-lifting.md](bytecode-lifting.md)): per-language analysis
  (Python, Lua, JavaScript engines and packers, the JVM and Dalvik, .NET,
  WebAssembly and others), experiments and a phased plan. Next, in its
  order: detection and extraction of packed scripts (PyInstaller, Electron
  `asar`, pkg, Lua chunks) with two quick fixes (`EM_BPF` to eBPF; .NET
  assemblies recognised instead of analysed as x86); external decompiler
  providers (ILSpy, jadx, unluac, pycdc, webcrack); then JVM and Dalvik
  end to end through Ghidra's processors, whose decompilation the
  experiments show needs only ported injections and constant pools.

Deferred from the last round: PE `.pdata` unwinding; MIPS `gp` recovery
for stripped raw firmware and register-seeded jump tables; Ghidra's Auto
Override and carrying fallthrough overrides through Ghidra interop; longer
fuzz runs on the PE and markup parsers.

## Done in the round after v0.1.1 (2026-10-15)

Picked up again after v0.1.1, three at a time:

- **BSim stage 3: apply a match: done.** The name, a skeleton signature,
  or the signature and its types from search hits to the queried
  functions, the way Ghidra's BSim results do, many in one undo step
  (`ApplyBSimMatches`, `api_minor` 76, feature `bsim-apply`;
  [bsim.md](bsim.md#applying-matches)).
- **Comments view: done.** Ghidra's comment window:
  `QueryService.ListComments`, SDK `comments()`, MCP `list_comments`
  (`api_minor` 77, feature `comment-table`; [ui.md](ui.md#comments)).
- **The rest of that branch's queue** (wishlist): ~~symbol tree~~
  (*done*: the Symbol tree view, `api_minor` 82, feature `symbol-tree`;
  [ui.md](ui.md#symbol-tree)),
  ~~relocation table~~ (*done*: the Relocations view, `api_minor` 78,
  feature `relocation-table`; [ui.md](ui.md#relocations)), ~~fallthrough override~~ (*done*:
  `SetFallthrough`, `api_minor` 85, feature `fallthrough-override`;
  [api.md](api.md#fallthrough-overrides)), ~~Clear Flow and Repair~~ (*done*: `api_minor` 83,
  feature `clear-flow`; [listing-edit.md](listing-edit.md#clear-flow-and-repair)), ~~external debug files
  (debuginfod, opt-in like symbol servers)~~ (*done*: build ID, debuglink,
  opt-in debuginfod, `LoadDebugFile`, `api_minor` 86, feature `debug-files`;
  [backend.md](backend.md#external-debug-files)), ~~data settings~~ (*done*:
  `SetDataSettings` per item, field or type, `api_minor` 84, feature
  `data-settings`; [listing-edit.md](listing-edit.md#data-settings)), ~~export C~~
  (*done*: `ExportC`, `api_minor` 80, feature `export-c`;
  [ui.md](ui.md#export-c)), ~~register values over ranges~~ (*done*: MIPS
  `gp`, the PowerPC TOC and the user's values, `api_minor` 87, feature
  `register-values`; [api.md](api.md#register-values)).
- **Library follow-ups**: ~~search a container or root file system for
  libraries~~ (done: `api_minor` 79, feature `library-roots`;
  [filesystems.md](filesystems.md#libraries-of-imported-programs)), ~~a
  library's CFI for unwinding~~ (done:
  [debugger.md](debugger.md#libraries); PE unwind data is left),
  ~~references back from a library~~ (done: `api_minor` 81, feature
  `library-importers`; [api.md](api.md#libraries)), ~~the library tab
  following the pc~~ (done: [debugger.md](debugger.md#libraries)).
- **Then the end-phase bug scrub: done** ([bug-scrub.md](bug-scrub.md),
  part 2): the rest of TSan, a final ASan and UBSan run with `python_sdk`,
  17 new fuzz harnesses, and the security review; its fixes are on master
  and what is left is listed there.

## Feature requests (not started)

Ghidra features revkit lacks, ranked, are in [wishlist.md](wishlist.md)
(from the feature survey, [ghidra-feature-survey.md](ghidra-feature-survey.md)).

_None at the moment._

## In flight

- **Container file systems** (wishlist Tier 1 "Container browser" and
  Tier 3 batch import; [filesystems.md](filesystems.md)), in three steps:
  - **Step 1, the framework, zip, tar, compression and the browser: done.**
    `revkit::container` (sessions over nested containers recognised by
    magic, the limits, sanitized paths), zip, tar, gzip, bzip2, xz, lzma,
    zstd and lz4; `FileSystemService` (`api_minor` 48, feature
    `filesystems`): open, list with what each file is, read, info,
    import (one or a batch, with preview and cap; programs record their
    container path), extract under `--browse-root`; the File System
    Browser (File → Open file system…, Open as file system in the Open
    dialog); Python, TypeScript, MCP and `revkit.script`.
  - **Step 2, file systems: done.** cpio, ar, ISO 9660 (Rock Ridge,
    Joliet), squashfs (all six compressors), ext2/3/4, cramfs (both byte
    orders), FAT12/16/32, uImage, Android boot images, UF2 and partition
    tables (MBR, GPT); firmware members carry the language and load
    address their header names, so batch import takes them as raw images.
  - **Step 3, batch import from the command line: done.** `rk-daemon
    project import-batch <path> --recursive` (a host directory or a
    container, into containers found, with `--preview`, `--max`,
    `--folder`, `--keep-folders`, `--detect-raw`).

- **Scripting** (requested 2026-10-07: "that's what makes all of these
  tools so powerful"). Design: [scripting.md](scripting.md#the-design).
  - **Phase 1, core: done.** `revkit.script` (context, reads, buffered
    one-revision edits, prompts behind a host interface, monitor),
    `PROVENANCE_KIND_SCRIPT` and `Provenance.on_behalf_of`, the batch RPCs
    `DecompileMany`, `FindBytes` and `ListInstructions` (`api_minor` 29),
    `rk-script` (headless, throwaway daemons, `-j`, pre and post scripts,
    JSON summaries), script metadata, ten starter scripts.
  - **Phase 2, daemon and UI: done.** `ScriptService` (`api_minor` 31,
    feature `scripts-host`): shipped, per-user and per-project libraries
    with metadata, runs in Python host processes with a run token acting
    as the caller and revoked at exit, streamed output, progress, prompts
    and tracebacks, cancel (SIGTERM, SIGKILL after 2 s), the cursor
    following into a running script, saving, recent runs; scripts off
    beyond loopback unless `--scripts-host-role` names a role; trust
    confirmation of unseen or changed text, pinned per user; Python
    discovery and `rk-script setup`. The Script Manager (`Ctrl+Shift+S`),
    output panel, prompts as dialogs, trust dialog, a CodeMirror editor,
    palette, key and context-menu entries, one undo step per run, "Revert
    this run"; the Python, TypeScript and MCP clients.
  - **Phase 3, Ghidra compatibility: done.** `revkit.ghidra.compat`: the
    `GhidraScript`/`FlatProgramAPI` subset Ghidra's scripts use
    (`currentProgram` and its managers, addresses, the flat calls, prompts,
    `monitor`, `DecompInterface`) over `revkit.script`, with `ghidra.*`
    imports aliased; `rk-script` and the Script Manager detect Ghidra
    scripts; everything else fails with `Unsupported` naming the API and
    its replacement (a table in scripting.md). 30 of Ghidra's bundled
    scripts as a corpus, compared with Ghidra through PyGhidra: 21 agree on
    the SDK fixture and 20 on the corpus program features, 6 fail with
    `Unsupported`, the rest differ for program-model reasons (the `.plt`'s
    lazy-binding code isn't disassembled; no references from ELF markup or
    from constant propagation). `ListingToken.scalar_bits` (`api_minor`
    34). Python 3 only: Jython scripts need `print()` fixes.
  - **Phase 4: done but for Python in the desktop bundle.** The Python
    console (`api_minor` 43, features `script-console` and
    `script-completion`): Window → Python, a live host per user and program
    (`RunScript{interactive}`) with the cursor followed, history per user,
    Tab completion from the live namespace (`CompleteConsole`: jedi, else
    rlcompleter), signature help, Ctrl+C as `KeyboardInterrupt`
    (`CancelScript{interrupt}`), each statement's edits one revision and
    one undo step (provenance `script:console`), idle hosts closed
    (`--console-idle-timeout`), Ghidra's names on request, and a viewer's
    console read-only (`--scripts-host-role viewer`). Completion and
    signature help in the editor from an index generated from the SDK's
    docstrings. Per-user and per-project libraries for `import` (user
    first). Ten more starter scripts (call graph to DOT, apply a header,
    wrappers, dangerous calls, strings, instruction search, memory dump,
    function signatures export and apply, notes): 22 in all. Left: Python
    bundled in the desktop app. Seen by the Ghidra corpus, outside the shim: comments
    on undefined bytes inside a folded listing row don't show in the
    listing (the row index doesn't split there); the `.plt`'s lazy-binding
    stubs aren't disassembled; disassembling at a function symbol makes the
    function again after a remove.

- **Types and header import** (requested 2026-10-07: creating structs and
  data types, parsing header files). Design: [cparse.md](cparse.md#decisions)
  and the consult it records; phases:
  - **P0, done:** `src/cparse` (preprocessor, C and a C++ subset, layout
    from the compiler spec's data organization, built-in freestanding
    headers, `-E` passthrough, recovery and limits), `rk-cparse`,
    `cparse_fuzzer`; the round trip against DWARF/PDB on the corpus is
    100% (layouts and hashes, four data models) and a CI gate.
  - **P1, done:** `TypeService.ParseC` (api_minor 25), parsed
    `c_declaration` retypes, bound names reaching debug-info globals and
    locals, `parse_c` / `import_header` in the SDKs and the MCP server;
    the UI's "Import header…" (pasted, uploaded or on the daemon's host,
    include folders, defines, the target; a preview of new, replacing and
    identical types with both definitions, diagnostics with their lines,
    a policy per type, `#define` constants as enums, prototypes retyping
    functions by name; one revision with `import:header` provenance, one
    undo), "Edit in C", and C declarations wherever a type is asked for
    (field types, retypes, definitions before a retype's declaration).
    Define-data at addresses came with the listing's edits
    ([listing-edit.md](listing-edit.md)).
  - **P2, done:** editor parity, every layout the daemon's (the draft is C
    ParseC lays out; types the editor didn't touch go by hash, as
    `__revkit_type_<hash>`, instead of a `LayoutType` RPC): explicit
    offsets (insert at an offset into undefined filler, delete leaving
    filler, grow and shrink), bitfields at `byte:bit` with a width,
    natural layout, `packed`, `#pragma pack(N)` and `aligned(N)`, flexible
    arrays, function-pointer fields and pasted member declarations;
    duplicate and rename (a new definition, the new name bound, the old
    name's binding retracted; uses by hash keep the old definition); enum
    values as C expressions with a size and signedness, sorted by value
    ([ui.md](ui.md#types-editor-and-header-import)).
  - **P3, done:** structures from pointer use and from a listing
    selection: `infer.pointer_accesses` (loads, stores and calls through
    each pointer variable, from the decompilation's p-code),
    `TypeService.AutoStructure` (api_minor 32, feature `auto-struct`:
    Auto Create, Auto Fill in, into callees `call_depth` deep, and Create
    Structure from the data in a range), the SDKs' and MCP's helpers and
    the script edits, and in the UI "Auto create structure" / "Auto fill
    in structure" on a decompiler variable and "Create structure from
    selection" in the listing, each a preview then one undo step. On
    stripped Lua the fields made for `lua_State *` parameters land on true
    field starts 99.9% (x86-64) and 99.3% (AArch64) of the time
    ([types.md](types.md#structures-from-pointer-use)). Since 2026-10-07 a
    retyped parameter or local (this, Set type, scripts) is committed to
    the decompiler type-locked, as Ghidra commits a variable, so the body
    shows `p->field_0x10` rather than only the declaration changing
    ([decompiler-inputs.md](decompiler-inputs.md#variable-types)).
  - **P4, done:** type archives and categories (api_minor 35, feature
    `type-archive`): `TypeService.ExportTypeArchive` writes a set of types
    (named, a category, the user's, or all) as a self-checking C header
    (`#pragma pack` and explicit offsets where needed, a `_Static_assert`
    of each size) plus a JSON sidecar of hashes, categories, provenance
    and the data model; importing is ParseC with the sidecar (hashes
    checked), idempotent, and exporting what an archive brought gives the
    same bytes (cJSON, Lua and AArch64 zlib's debug types into their
    stripped twins). Ghidra's C parser reads the corpus archives with
    every layout equal (772 types, 1975 members); clang compiles them for
    their targets. Categories (`SetTypeCategory`), from DWARF's
    `DW_AT_decl_file`, a PDB's `LF_UDT_SRC_LINE` and a header import's
    name; the UI's folder tree with drag and Move to category…, Export
    archive… and Import archive…; the SDKs, MCP and `revkit.script`
    ([types.md](types.md#type-archives)). Project-wide types: done since
    (below, "Project-wide types").

- **Automatic detection of processor, load address and header offset** for
  binaries without a header (requested 2026-10-06): designed in
  [autodetect.md](autodetect.md), being built in phases. Its experiments
  also found that analysing an image under the wrong language has no time
  bound (minutes on a few KB under a dense 8-bit instruction set); discovery
  gets a budget as part of this work.
- **Decompiler quality against the source** ([decomp-quality.md](decomp-quality.md)):
  landed 2026-10-07 (source-truth benchmark, revkit wins the per-function
  composite in every family; inferred prototypes by default in rk-lift
  and, in the background after import, in the daemon). **Pending: the
  blinded judging** of the packet `scripts/decomp-quality.py --judge
  build/judge` writes (480 items, the key apart in `build/judge-key/`),
  run by the lead with blinded judges.
- **Firmware and stripped-ARM parity with Ghidra** ([firmware.md](firmware.md#a-second-arm-firmware-thumb-1-and-thumb-2-compressed-data)).
  Done there: "don't take text for Thumb code" (reported 2026-10-06: an
  unproven candidate must be credible code, not text, fill, random bytes
  or zeroed words, and a function that halts on bad data is now as rare
  as in Ghidra), Thumb-1 far jumps and switch helpers, shrink-wrapped
  prologues, embedded vector tables, stripped ARM ELFs; switches through
  `add pc, rN` whose guard isn't on the first path flow takes, and MIPS
  shrink-wrapped prologues after several early exits (2026-10-07). Data
  types for calls into libc: done with the library archives (below).

## Done

### The Open dialog's stall after an import

Fixed 2026-10-15 (it was in [known-issues.md](known-issues.md)): after an
import answered, the Open dialog asked for the import's last progress
(for the bar) and waited for that answer before opening the program,
with no time limit. When the answer doesn't come it stayed at "Imported
…; opening it…". It now waits at most 1.5 s, and the progress polls give
up on a poll after 10 s and ask again. Headless Chrome against a test
daemon didn't reproduce the stall without help: 57 raw imports of
`fwkit-cortexm3-O2.bin`, by path and by the file chooser, with and
without detection, from the empty workspace and from a program, three at
once with up to 0.8 s of random delay on every call, and with three or
four other tabs holding live streams. Five other tabs (the browser's six
connections to the daemon all held) stall everything, the import as
well. Holding back `GetImportProgress` after the import answered gives
the reported symptom exactly; the e2e check "a raw import opens its
program even when the import's last progress gets no answer" does that.

### SLEIGH engines shared across programs of a language

Done 2026-10-15 ([memory.md](memory.md#sleigh-engines)): SLEIGH engines
idle for 15 s (`rk-daemon --engine-idle`) are parked by a sweeper, two
decoded `.sla` files kept per language (and space truncation) for any
program's next engine to reuse with `Sleigh::reset`. An idle daemon with
8 tiny programs and lua holds 302 MB instead of 1051 MB.

### Project-wide types

Requested 2026-10-08 (wishlist Tier 2 "Project-wide types"), done
2026-10-08 ([types.md](types.md#project-types); `api_minor` 52, feature
`project-types`): types defined at project scope (`TYPE_DEF` keys in the
project's space, which `types.names`, `types.closure` and
`types.resolved` read after the program's own), Move to project and Copy
to program (`TypeService.CopyTypes`), project-scope edits
(`AppendAssertionsRequest.project_scope`) that reach every program's
decompiled C, type archives attached to the project or switched off
(`AssertionBody.type_archive`, `ListTypeArchives`), replicated with the
project and carried in `.rkproj` archives; the Types window's Project
branch, its Move to project and Copy to program, and its Archives
section; the SDKs, MCP (`move_types_to_project`, `copy_types_to_program`,
`list_type_archives`, `set_type_archive`) and `revkit.script`.

### Function ID

[fid.md](fid.md) (`api_minor` 51, feature `function-id`): Ghidra's
Function ID hash computed bit for bit over the C++ SLEIGH engine (the
masks Ghidra's Java disassembler reports, replayed; patch 0011), Ghidra's
shipped `.fidbf` databases read natively (hardened, `fuzz_fid_db`), the
`function-id` analyzer in the background after import naming library
functions at analysis rank (`fid:<db>`, plate comments), `.rkfid`
databases from programs with symbols (`rk-fid create`,
`CreateFidDatabase`), attach and detach per user or project, the Function
ID window (matches, candidates, Apply, Reject, Databases), SDKs, MCP and
revkit.script. Gates: the ELF zlib and Lua libraries at precision 1.0
(recall 0.85 and 0.97) and agreement with Ghidra's FID on its own database
of 0.99 and 1.00; the MSVC CRT gate needs a Windows CRT sysroot this host
lacks, so Ghidra's MSVC tools stand in (agreement with Ghidra on the
shipped databases, [fid.md](fid.md#gates)). Also: chained `.pdata`
entries are no longer function seeds (PE x64).

### Library prototypes

Requested 2026-10-08 (wishlist Tier 2 "Library prototypes"), done
2026-10-08 ([types.md](types.md#library-prototypes),
[decomp-quality.md](decomp-quality.md#library-prototypes-and-format-strings-2026-10-08);
`api_minor` 50, feature `library-types`): revkit's own type archives of
glibc (LP64, ILP32) and the Windows API and C runtime (kernel32, user32,
ntdll, advapi32, ws2_32, msvcrt; LLP64, ILP32), built at build time from
the host's headers with revkit's C parser (`tools/rk-typeinfo`), applied
to imports by name below debug info, the demangler and assertions and
above inference, with Ghidra's `.gdt` for the names they lack; call-site
prototypes from constant printf/scanf formats (Ghidra's Variadic Function
Signature Override). The quality benchmark's composite improves in every
ELF family and holds on PE; library calls' argument counts 1/459/0 →
7/453/0.

### PDB extras

[pdb.md](pdb.md) (`api_minor` 49, feature `pdb-load`): Load PDB on an
open program (a host path, an upload or the symbol path; another build's
with `force`; one undo step), the daemon's symbol path
(`_NT_SYMBOL_PATH`, local stores, HTTP(S) servers with a cache, MSZIP
`.pd_`; downloads off by default, an admin's setting:
[security.md](security.md#symbol-servers)), MSVC 17's `LF_CLASS2` and
`LF_STRUCTURE2`, and PDB classes' vtable pointers to structs of their
virtual functions.

### Hover popups

Requested 2026-10-08 (wishlist Tier 1), done 2026-10-08
([ui.md](ui.md#hover-cards)): resting the pointer on something in the
listing or the decompiler shows a hover card: a reference's target (a
function's signature and first lines of C, else the listing's rows), a
function's signature, a variable's or type's definition (a struct's
layout, the hovered field marked), a scalar in hex, decimal and as
characters with the symbol at that address, and the provenance badge's
sections below. It never takes the focus, scrolls, and closes on Escape.
No new RPC (the existing reads); the SDKs' `preview` and `scalar_text`,
`revkit.script.preview` and MCP's `preview` and `describe_value` give
clients the same. `api_minor` 47, feature `hover`.
### PE analyzers

[pe.md](pe.md#pe-structures-and-exception-data) (`api_minor` 46, feature
`pe-analysis`): headers, section table, export, import, resource, debug
and relocation directories, TLS with its callbacks as functions, the load
config with `__security_cookie` and the Control Flow Guard and SafeSEH
tables (their targets functions), x64 `.pdata`, UNWIND_INFO and
`__C_specific_handler` scope tables, MSVC C++ EH (FuncInfo, unwind and
try maps, catch and unwind funclets as functions).

### MSVC RTTI and vftables

[pe.md](pe.md) (`api_minor` 45, feature `msvc-rtti`): TypeDescriptors,
locators, hierarchies and base classes found and typed (32- and 64-bit),
vftables typed as structs of function pointers and named, functions made
at their entries (`Class::vfuncN`), virtual methods' `this` typed as the
class struct (sized by how far the methods reach) at analysis rank, the
class hierarchy (`GetClassHierarchy`, the Class hierarchy view, Python,
MCP). Tested on clang-cl builds made at test time.

### Byte viewer, navigation and the overview

Requested 2026-10-08 (wishlist Tier 1 "Byte viewer", Tier 3 "Listing and
navigation"), done 2026-10-08 ([ui.md](ui.md#byte-viewer-navigation-and-the-overview),
[api.md](api.md#byte-viewer-overview-and-navigation)): Ghidra's Bytes
window as a dockable view (hex, ASCII, octal, binary, UTF-16 and integer
columns; 8, 16 or 32 bytes a line in groups of 1 to 8; the cursor and the
selection synced both ways with the listing and decompiler; code, data,
undefined and uninitialized bytes tinted, patched ones marked; Edit types
hex or characters as patches, one undo step per edit session; Follow off
pins it); next and previous instruction, data, undefined, label, function,
different byte and note (Ghidra's Ctrl+Alt keys, Shift for previous, and
the palette); Go To expressions (`main+0x10`, `0x1000 + 4*3`,
`file:0x200`) and wildcards (`FUN_*`); a history dropdown; overview and
entropy bars beside the listing's scrollbar; Copy Special (hex, C, Python,
Base64, addresses, the listing's text); the Fields menu's file offset,
function offset, p-code and XREF list. `api_minor` 44 (`GetByteView`,
`GetOverview`, `FindNext`; features `byte-viewer`, `overview`,
`find-next`), with Python SDK helpers.
### Rebase (set image base)

Requested 2026-10-08 (wishlist Tier 1), done 2026-10-08
([memory-map.md](memory-map.md#rebase-setting-the-image-base)): Set
image base in the memory map (and `SetImageBase`, the SDKs, scripts and
MCP) moves a program, every fact recorded about it and its history to a
new base, as one replicated edit that undo moves back. Design: facts are
stored image-relative (to the import base, so nothing migrates) and the
base is a `REBASE` assertion; the fact store indexes the program's keys
moved by it and the program reloads at the new base inside the commit
that moves it, so undo, redo, reverts, peers' merges and reopens are right
by construction. Gate: the corpus's `cjson` with a user's work moved by
+0x10000 reads the same at the shifted addresses (functions, listing,
decompiled C, history, memory) and moves back exactly; a raw firmware
imported at a wrong base is fixed with its work. `api_minor` 42, feature
`rebase`.

### Search

From the wishlist's first tier, done 2026-10-08 ([ui.md](ui.md#search),
[api.md](api.md#search), [scripting.md](scripting.md)): Ghidra's Search
Memory (hex with `??` and nibble wildcards, strings in ASCII, UTF-8 and
UTF-16 in either case, decimals of 1 to 8 bytes, floats and doubles in
either byte order, binary with masks, RE2 regexes over bytes; in a
selection or by code unit), Search Program Text (comments, labels,
signatures, instructions and data as the listing shows them, renames
included), Search for Scalars (a value or range, signed or unsigned) and
a decompiled-code search over `DecompileMany`, each on the daemon as a
stream with progress, limits and cancel. In the UI: floating dialogs with
Next and Previous (`S`, `Ctrl+Shift+E`, `Ctrl+Shift+F`, a Search menu,
`F3` and `Shift+F3`), and a dockable results table (sortable, filterable,
CSV, a listing selection from the results). The SDKs, MCP (four tools)
and `revkit.script` have them; the Ghidra shim's `findBytes`, `find` and
`Memory.findBytes` run on them. On cmake a memory search takes tens of
milliseconds and a program text search a tenth of a second once the
listing is decoded. `api_minor` 41, feature `search`.

### C++ demangling

Requested 2026-10-08 (wishlist Tier 1), done 2026-10-08
([demangle.md](demangle.md), [api.md](api.md#queries), [ui.md](ui.md#demangled-names)):
the demangler analysis names every mangled symbol (Itanium, Microsoft,
Rust, D) by Ghidra's short form with its namespaces and classes in the
function list, listing, decompiler and symbol search, finds either
spelling, and gives functions their mangled signatures' prototypes
(references as pointers, `this` typed, Microsoft calling conventions) at
import rank, below the user's and the debug info's, above agents',
inference and parameter ID. A names setting shows the short, full or
mangled spelling. On the C++ gate (`scripts/demangle_gate.py`, five
builds) every mangled function is named demangled in the C (0 → 1305) and
parameter counts against DWARF go from 643 to 663 of 788; the C corpus's
decompiled-C gates are unchanged. `api_minor` 40, feature `demangle`.

### Equates and user references

Requested 2026-10-08 (wishlist Tier 1), done 2026-10-08
([api.md](api.md#equates-and-user-references),
[decompiler-inputs.md](decompiler-inputs.md#equates), [ui.md](ui.md#equates-and-references)):
Ghidra's Set Equate, Convert and Equates table, and its References (add,
delete, set primary). How a scalar shows (a format, an equate, an enum
member) is an `EQUATE` assertion per operand, shown in the listing and,
as Ghidra's Java side sends equates, as an `EquateSymbol` on the
constant's dynamic hash in the decompiler; a user reference is a
`REFERENCE` assertion that xrefs list with its provenance, discovery
follows (call targets become functions, computed jumps go on at the
user's targets) and the decompiler takes as a call override or a jump
table. In the UI: `E` (enum suggestions, apply to the function or the
program), right-click Convert and References submenus on the listing and
decompiler constants, `R` to add a reference, and the Equates and
References windows; Python, `revkit.script`, MCP, TypeScript and the
Ghidra compat shim (`getEquateTable`, `createEquate`,
`createMemoryReference`, `removeReference`, `setReferencePrimary`).
`api_minor` 39, features `equates` and `user-references`.

### Folders and project archives

Requested 2026-10-08, done 2026-10-08 ([api.md](api.md#queries),
[backend.md](backend.md#project-archives), [ui.md](ui.md),
[security.md](security.md#roles)): programs live in a tree of folders
(create, rename, delete an empty one, move programs and folders), each
edit an assertion on the project's own records that replicates, blames
and undoes like any other, and the project window shows the tree with
drag and drop and a right-click menu. A project, some programs or a
folder export to one `.rkproj` file (a gzip tar with a manifest: the
programs' files, their fact logs with all history and provenance, the
folders, types and regions' bytes; or annotations only, the binaries
found again by SHA-256) and import into a new or an existing project,
checked in full as untrusted input; File → Export project… and Import
project… in the web UI and the desktop app, `rk-daemon project
export|import`, the SDKs and MCP. The round trip gives the same
functions, names, types, comments, decompiled C and undo history.
`api_minor` 37, features `project-folders` and `project-archive`. Also
fixed on the way: inference after a reopen (its effective image was read
back from disk without the image), and a second daemon on one project
directory is now refused.

### Start the daemon from the UI

Requested 2026-10-08 ("a button to start the daemon when you open a UI,
like in the bottom left corner"), done 2026-10-08 ([ui.md](ui.md#daemon-status),
[packaging.md](packaging.md#start-the-daemon-on-first-use-systemd-socket-activation)).
A web page can't start a process, and in a browser the daemon is what
serves the page, so it comes in three parts: a daemon status chip at the
bottom left (connected with the daemon's version and project, connecting,
disconnected; a popover with version, API, uptime and address); in the
desktop app, Start, Stop and Restart and the daemon's log, and a dead
daemon shown red with Start daemon and its last log lines; in a browser,
Reconnect and the command that starts the daemon with the flags it ran
with, and opt-in systemd socket activation from the `.deb`
(`systemctl --user enable --now revkit-daemon.socket`), so opening the
URL starts the daemon. `GetServerInfo` gained the uptime, the command line
(admins only) and `socket_activated` (`api_minor` 36, feature
`daemon-info`). Not done: an idle exit for a socket-activated daemon, and
an inherited gRPC socket (the service binds gRPC itself).

### Clear bytes and define data from the listing

Requested 2026-10-06, done 2026-10-07 ([listing-edit.md](listing-edit.md),
[ui.md](ui.md)): Ghidra's Clear Code Bytes (`c`), Disassemble here (`d`,
in ARM or Thumb, optionally a function) and the Data menu (`b` cycles
byte/word/dword/qword, `'` char, `"` string, `[` array, `t` any type, `p`
pointer; floats, UTF-16, Pascal and fixed-length strings, structs with
their fields as rows) from the listing's keys, right-click menu (with a
recently used group) and palette; constant and volatile ranges for the
decompiler. Each is a `CODE_UNIT` or `MUTABILITY` assertion (`api_minor`
30, feature `listing-edit`) with provenance, undo and blame, which
discovery, data analysis, the listing, references and the decompiler
read, live; Python and TypeScript helpers, script edits and MCP tools.

### Unique package versions

Done 2026-10-07 ([packaging.md](packaging.md#build-versions)): builds
between releases are versioned `0.1.0~git<commit time>.<hash>`
(`0.1.0~git20261008003044.431366830e06`), which apt orders by commit and
below the release; the commit tagged `v0.1.0`, or `REVKIT_VERSION=0.1.0`,
builds plain `0.1.0`. Both `.deb`s, the bundle, the AppImage and
`--version` carry it; the wheel and sdist in PEP 440 form
(`0.1.0.dev20261008003044+g431366830e06`), the npm package and the desktop
app's own version in semver (`0.1.0-git.20261008003044.g431366830e06`).

### Open dialog: raw import, simpler

Requested 2026-10-07, done 2026-10-07 ([ui.md](ui.md#phase-7-daily-use-polish),
"Raw layout detection"): one way to say "raw" (the raw options' own
**Import as raw**, shown with them; detection opens them for a file that
isn't ELF or PE; no checkbox), **High confidence only**, **Select all**
and **Select none** above the suggested regions, the picked file (name,
where, size) shown from its pick through detection and the import, and
regions that overlap the image or each other marked on their rows with
Clip and Untick and never sent (the raw loader's message now names both
blocks and their ranges).

### Memory map: inference and sections' permissions

Done 2026-10-07 ([memory-map.md](memory-map.md#how-the-image-backend-sees-them-a-variant-of-the-program)):
prototype inference reads the effective memory map (`infer.image.effective`),
and an image block's permission edit reaches the emulator for an ELF
section inside a segment too (the segment's region is split at the
section).

### Memory map after import

Requested 2026-10-06, done 2026-10-06 ([memory-map.md](memory-map.md)):
the memory map of every program through the API, the SDKs, MCP and a
Memory Map view, and editing it after import (uninitialized RAM,
zero-filled memory, memory-mapped I/O, another file's bytes at an
address; an image block's name, permissions and volatile flag), each edit
an assertion that analysis, the decompiler and the emulator follow.
`api_minor` 24, feature `memory-map`.

## Later

- ~~**Bug scrub**~~ (*done* 2026-10-16, part 3 2026-10-21: [bug-scrub.md](bug-scrub.md),
  parts 1 to 3): ASan, UBSan and TSan over the test suites, fuzzing the
  parsers, and a security review of the daemon, parsers and sandboxes.
- Mach-O: DWARF and dSYM bundles, Swift demangling and types, the dyld
  shared cache and kernelcache ([macho.md](macho.md#known-gaps)).
