# Roadmap

What is requested but not built yet, and what is in flight. Each entry says
what it is and why; design notes go in the feature's own doc when work starts.

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

- **Bug scrub** (decided 2026-10-07: iterate fast now, scrub at the end):
  ASan, UBSan and TSan over the whole test suite, fuzzing the parsers
  (loaders, cparse, the detector, SLEIGH on hostile bytes, project
  archives: `project_archive_fuzzer`, container formats:
  `container_<format>_fuzzer` and `container_codecs_fuzzer`, Function ID
  databases: `fuzz_fid_db`), and a security
  review of the daemon, parsers and sandboxes. Until then, changes land on
  the default build, the default tests and the accuracy gates.
- Mach-O.
