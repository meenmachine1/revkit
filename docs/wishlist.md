# Wishlist: what Ghidra has that revkit doesn't

The nice-to-haves, separate from the [roadmap](roadmap.md) (what is being
built or decided). Drawn from a feature-by-feature survey of Ghidra 12.1.4
on 2026-10-08: [ghidra-feature-survey.md](ghidra-feature-survey.md) has
every row with its evidence. When an item starts, move it to the roadmap;
when it lands, strike it here.

<!-- survey-summary:wishlist -->
Of 745 Ghidra features: revkit has 345, has part of 189, lacks 211, and 0 are being built (counted by `scripts/survey_summary.py` from the survey's rows).
<!-- /survey-summary:wishlist -->

Value is to a reverse engineer doing real work; effort is S (a day or
less), M (days), L (a week or more).

## Bugs found by the survey

- [x] **Rename on a struct field renames the function.** In the decompiler,
  Rename on a token that isn't a variable or symbol falls back to the
  function (`ui/src/app.ts`, the rename target). S. *Fixed:* field tokens
  carry their struct's hash and offset (api_minor 38, feature
  `field-tokens`); Rename Field and Retype Field edit the struct; a token
  that names nothing says so ([ui.md](ui.md#types-editor-and-header-import)).
- [x] **A prototype's calling convention is ignored.** `FunctionType.cc` is
  kept, but the decompiler is always given `"default"`
  (`src/backend/own_inputs.cc`, `apply`), so `__stdcall`/`__fastcall` and
  the like change nothing. S. *Fixed:* the convention is the compiler
  spec's prototype model where it has one, else the default with a warning
  ([decompiler-inputs.md](decompiler-inputs.md#calling-conventions)).

## Re-ranked 2026-10-09

The survey was judged again on 2026-10-09: most of the old Tier 1 and
half of Tier 2 had landed (struck below, under "Done since the survey").
What is left, ranked by value to someone doing real work, then by effort.

## Tier 1: high value

| Item | What to build | Effort |
| --- | --- | --- |
| Edit Function dialog | ~~Return, parameters, a calling-convention dropdown~~ *done* (`api_minor` 58, feature `calling-conventions`); ~~the user no-return flag~~ *done* (`api_minor` 66, feature `no-return`). Left: the inline flag and custom parameter storage, which no assertion kind carries yet | M |
| ~~Slices and def-use~~ | *Done* (`api_minor` 57, feature `decompile-slices`; [ui.md](ui.md#slices), [api.md](api.md#slices)): ~~Def-use and slice data in Decompile (or a Slice RPC), shown as forward and backward slice and operator highlights, and a def-use highlight~~ | M |
| Value tracing across calls (beyond Ghidra) | ~~Through direct calls, matched, with budgets and the unknowns listed~~ *done* (`api_minor` 89, feature `value-trace`; [api.md](api.md#tracing-a-value-across-calls)). Left: values through memory (stores to loads, stack slots and globals first), indirect calls with known targets, struct fields across functions, listing marks | M |
| BSim database | ~~A persistent signature store with an LSH index (reuse `src/diff/lsh.cc`), program ingest from the CLI and the API, metadata, categories~~ *done* (`api_minor` 69, feature `bsim`; [bsim.md](bsim.md)). Left: function tags | S |
| Similar-function search | ~~From the cursor or a selection against the BSim store: thresholds, a results table~~ *done* (`api_minor` 72, feature `bsim-search`; [bsim.md](bsim.md#searching)). ~~Left: Apply name, signature or signature and types from a hit~~ *done* (`api_minor` 76, feature `bsim-apply`; [bsim.md](bsim.md#applying-matches)) | S |
| Debugger: dynamic listing | ~~Disassemble runtime memory (libraries, unpacked or JIT code), auto-disassembled at the pc~~ *done* (`api_minor` 62, feature `debugger-disassembly`; [debugger.md](debugger.md#runtime-disassembly)); ~~copy runtime memory into the current or a new program to capture unpacked code~~ *done* (`api_minor` 63, feature `debugger-copy`; [debugger.md](debugger.md#copying-runtime-memory)) | L |
| Debugger: stack, watches, value hovers | ~~A stack unwind (API, `rk-dbg bt`, the UI)~~ *done* (`api_minor` 59, feature `debugger-stack`; [debugger.md](debugger.md#call-stack)); ~~watch expressions with types and changed marks~~ *done* (`api_minor` 61, feature `debugger-watches`); ~~variable values in the listing's and decompiler's hover cards at the current snapshot~~ *done* (`api_minor` 60, feature `debugger-values`; [debugger.md](debugger.md#expressions)) | M |
| Emulator snapshots | ~~Resume from a past snapshot (step back and continue)~~ *done* (`api_minor` 65, feature `debugger-rewind`; [debugger.md](debugger.md#rewind)), and ~~emulate from a live target's or a trace's state with lazy reads~~ *done* (`api_minor` 67, feature `debugger-emulate-from`) | M–L |
| ~~Emulator callbacks~~ | *Done* (`api_minor` 68, feature `debugger-hooks`; [debugger.md](debugger.md#hooks)): ~~Python or plugin handlers for stubs, syscalls, MMIO and userops~~ | M |
| ~~Conditional breakpoints~~ | *Done* (`api_minor` 64, feature `debugger-conditions`; [debugger.md](debugger.md#breakpoints)): ~~an expression on hit (emulator and live) and an ignore count; a breakpoint table~~ | M |
| Map libraries to project programs | ~~At runtime~~ *done* (`api_minor` 70, feature `program-libraries`; [debugger.md](debugger.md#libraries)); an offer to import a missing module from the debugger is left (the Open dialog's "Also import the libraries it needs" and Analyze → Libraries… do it from the program) | M |
| Mach-O | ~~The loader~~ *done* (`api_minor` 90, feature `macho`; [macho.md](macho.md)), universal files' slices too; ~~Objective-C and Swift metadata~~ *done* (`api_minor` 91, feature `objc`); ~~app bundles (`.ipa`, `.app`), Info.plist, property lists, code signatures and entitlements, provisioning profiles, frameworks by `@rpath`~~ *done* (`api_minor` 100, feature `apple-bundles`; [apple-apps.md](apple-apps.md)). ~~Interface Builder nibs and their UI actions~~ *done* (`api_minor` 101, feature `ui-actions`). Left: DWARF and dSYM, Swift demangling, message sends resolved to methods, then Apple containers (dyld cache, kernelcache) | L |
| Go binaries | ~~Build info: Go version, modules, settings~~ *done* (`api_minor` 88, feature `build-info`; [build-info.md](build-info.md)). ~~Function names and source lines from pclntab, Go's calling conventions (Ghidra's golang cspecs) and no-return list~~ *done* (`api_minor` 93, feature `go-pclntab`; [go.md](go.md)). Next: strings (pointer and length), runtime types from `typelinks`, signatures (Ghidra's `GoFunctionFixup`), Duff's device entries | M |
| Windows debugging | A dbgeng/WinDbg target or a bridge | L |

## Tier 2: high or medium value, specific workflows

| Item | What to build | Effort |
| --- | --- | --- |
| ~~Compare: apply the rest~~ | ~~Global names and callee signatures from a matched pair~~ *done* (`api_minor` 71, feature `port-globals-callees`; [diff.md](diff.md#comparing-two-functions)) | M |
| Analysis options | Per-analyzer enable and options, and one-shot analyzers on a selection | M |
| Register values over ranges | ~~MIPS gp, PPC TOC~~ (done: api_minor 87, feature `register-values`; [api.md](api.md#register-values)); mode registers (MIPS16, VLE) as context, MIPS `gp` recovered from the code that writes it | M |
| Namespaces and labels | User namespaces and classes, several labels at one address, function-local labels, external locations | M |
| Stack frame | A stack frame editor, or a locals view backed by the decompiler's storage | M |
| Decompiler options per request | Eliminate unreachable code, respect read-only, cast printing, integer format | S–M |
| Memory blocks | Move, split, merge and expand blocks, and overlays | M |
| Key bindings | Rebind a single action, import and export bindings (the Ghidra, IDA Pro and Binary Ninja presets are done) | S |
| Tables | Copy, CSV and sorting on every table (the search results table has them), and filter modes | S |
| SARIF | Export program features and import results with apply actions | M |
| Matching decompilation (Nintendo DS first) | ~~dsd projects and ROMs as module programs linked across modules, names back to symbols.txt, decomp scratches~~ *done* (`api_minor` 103, feature `nds`; [nds.md](nds.md)); ~~a decomp knowledge base (finished decomps applied to a new game: exact and near matches with their source)~~ *done* (`api_minor` 105, feature `decomp-kb`; [decomp-kb.md](decomp-kb.md)); ~~C shaped as the instructions encode it (load signedness, comparison constants, loop guards, bitfields, compilable C)~~ *done* (`api_minor` 106, feature `decompiler-settings`; [decompiler-inputs.md](decompiler-inputs.md#source-shape)). Left: references back across modules, mangling new names, class layouts for mwcc C++ | L |

## Done since the survey

- ~~What a DS matching run needed: no-return evidence for the program's own code only, the DS's I/O volatile, Thumb-keeping bounds, per-body refusals, import name conflicts, store compaction (api_minor 104), [nds.md](nds.md#what-a-matching-run-needed)~~
- ~~Nintendo DS games: ds-decomp projects and .nds ROMs, linked modules, symbols.txt export, decomp scratches (api_minor 103), [nds.md](nds.md)~~
- ~~Results that state their evidence: source tiers, unknowns, limits, target content (api_minor 97), [api.md](api.md#result-evidence)~~
- ~~EVM contracts: revkit's own SLEIGH processor, the SLEIGH compiler `rk-sleigh` (api_minor 99), [evm.md](evm.md)~~
- ~~Search UI (api_minor 41), [ui.md](ui.md#search)~~
- ~~Equates and operand display (api_minor 39), [api.md](api.md#equates-and-user-references)~~
- ~~User references (api_minor 39), [api.md](api.md#equates-and-user-references)~~
- ~~Struct fields in the decompiler (api_minor 53), [ui.md](ui.md#find-uses)~~
- ~~Call-site signature override (api_minor 53), [ui.md](ui.md#signature-overrides)~~
- ~~Hover popups (api_minor 47), [ui.md](ui.md#hover-cards)~~
- ~~C++ demangling (api_minor 40), [demangle.md](demangle.md)~~
- ~~Rebase (api_minor 42), [memory-map.md](memory-map.md#rebase-setting-the-image-base)~~
- ~~Byte viewer (api_minor 44), [ui.md](ui.md#byte-viewer-navigation-and-the-overview)~~
- ~~Container browser (api_minor 48), [filesystems.md](filesystems.md)~~
- ~~Python console (api_minor 43), [scripting.md](scripting.md#the-console)~~
- ~~Function ID (api_minor 51), [fid.md](fid.md)~~
- ~~MSVC RTTI and vftables, [pe.md](pe.md)~~
- ~~PE analyzers, [pe.md](pe.md#pe-structures-and-exception-data)~~
- ~~PDB, [pdb.md](pdb.md)~~
- ~~Library prototypes (api_minor 50), [types.md](types.md#library-prototypes)~~
- ~~Compare (api_minor 54), [diff.md](diff.md#comparing-two-functions)~~
- ~~Project-wide types (api_minor 52), [types.md](types.md#project-types)~~
- ~~Field rename and retype in the decompiler~~ (api_minor 38)
- ~~Calling conventions honoured for user prototypes~~ ([decompiler-inputs.md](decompiler-inputs.md#calling-conventions))
- ~~Keymap presets: Ghidra, IDA Pro, Binary Ninja~~ ([ui.md](ui.md#keymap-presets))
- ~~Resizable dialogs~~ ([ui.md](ui.md#resizable-dialogs))
- ~~Copy from the decompiler, and find in the current function~~ ([ui.md](ui.md#copying-from-the-decompiler))

## Tier 3: medium value

Listing and navigation (done ones struck; [ui.md](ui.md#byte-viewer-navigation-and-the-overview)):
- ~~next/previous navigation by kind~~ (instruction, data, undefined, label, function, different byte, note; Ctrl+Alt keys; api_minor 44, feature `find-next`);
- ~~Go To expressions (`sym+0x10`, file offsets)~~, and wildcards in names (`FUN_*`); a history dropdown;
- ~~an overview and entropy bar~~ (api_minor 44, feature `overview`);
- ~~optional listing fields (file offset, function offset, p-code)~~, and an XREF list on labels (p-code on the instruction's line, not lines under it);
- background colours;
- ~~Copy Special (bytes as hex, C or Python)~~ (also Base64, addresses, the listing's text);
- ~~a comment table~~ (the Comments view, api_minor 77, feature `comment-table`);
- an instruction info window;
- ~~a symbol tree with namespaces, imports and exports~~ (the Symbol tree view, api_minor 82, feature `symbol-tree`);
- ~~a relocation table~~ (the Relocations view, api_minor 78, feature `relocation-table`);
- ~~a fallthrough override~~ (api_minor 85, feature `fallthrough-override`; Auto Override over a selection is left);
- ~~Clear Flow and Repair~~ (api_minor 83, feature `clear-flow`);
- selections from result tables.

Analysis:
- an options UI per analyzer, and one-shot analyzers on a selection;
- register values over ranges: ~~MIPS gp, PPC TOC~~ (api_minor 87, feature `register-values`); mode registers;
- ~~format-string varargs at printf call sites~~ (done, api_minor 50);
- address tables in PE;
- custom parameter storage and the inline flag;
- a stack frame editor;
- external functions and namespaces.

Memory and import:
- move, split, merge and expand blocks, and overlays;
- ~~change the language after import~~ (done: api_minor 73, feature `set-language`, with a variant comparison);
- ~~batch and recursive import~~ (done: [filesystems.md](filesystems.md#importing), `rk-daemon project import-batch`);
- ~~linking dependent libraries~~ (api_minor 70, [api.md](api.md#libraries));
- COFF/.o relocations;
- ~~external debug files (build-id, debuglink, debuginfod)~~ (done: api_minor 86, feature `debug-files`, [backend.md](backend.md#external-debug-files)); source lines;
- ~~crash dumps (minidump, ELF core)~~ (done as debug sessions: `api_minor` 102, feature `crash-dumps`, [crash-dumps.md](crash-dumps.md); minidumps as programs left);
- device trees suggesting the memory map;
- Android DEX/APK and boot images (DEX/APK and other bytecode: [bytecode-lifting.md](bytecode-lifting.md); ~~decompiling them~~ through jadx and the other external decompilers: [providers.md](providers.md); ~~the manifest, resources, JNI libraries and native methods, Flutter's snapshot hash~~ done (`api_minor` 98, feature `android`: [android.md](android.md)); loaders still to come; ~~bytecode named and packers' scripts extracted~~ done: [filesystems.md](filesystems.md#packed-executables); Deno executables, py2exe's `PYTHONSCRIPT` and Nuitka next).

Types:
- ~~data settings (format, endianness, charset)~~ (done: api_minor 84, feature `data-settings`, [listing-edit.md](listing-edit.md#data-settings));
- a type preview;
- find types by size or offset;
- replace or merge types;
- quick field edits from the listing;
- C++ header parsing beyond the subset.

Decompiler:
- pinned decompiler panes;
- decompiling code outside functions;
- ~~Copy and Find in the pane~~ (done);
- ~~def-use and slice highlights~~ (done, api_minor 57);
- per-request options (unreachable code, casts, integer format);
- forcing a union field;
- offset pointers;
- splitting and merging variables;
- ~~exporting C for a function or the program~~ (Export C/C++…, api_minor 80, feature `export-c`).

Graphs:
- hover previews and colours shared with the listing;
- a visual call graph;
- data-reference graphs;
- DOT and GraphML export.

Debugger and emulator:
- more targets (gdbserver over SSH, Wine, rr, core files, lldb-server, kd, x64dbg);
- a breakpoint table;
- watchpoints;
- an editable memory view;
- register groups;
- trace open, save and diff;
- a p-code stepper;
- multi-threaded emulation;
- an emulated file system.

Version tracking:
- data matches;
- a similar-name tier;
- running one tier at a time;
- match tags;
- a markup table;
- a Program Diff aligned by address with per-category apply.

Scripting:
- Java GhidraScripts, run or ported;
- more of Ghidra's Python API (6 of the 30 corpus scripts still `Unsupported`);
- SARIF import and export.

Framework:
- user key bindings (presets done; per-action rebinding not);
- an options dialog (Preferences holds the keymap only);
- floating and split windows;
- table copy, CSV and filter modes (the search results table has copy and CSV);
- comment annotations as links;
- charsets beyond UTF-8/16/32;
- OIDC/SSO and client-certificate auth;
- version history in the UI (browse, diff, revert);
- ~~a SLEIGH compiler in C++ (`rk-sleigh`), for custom processors without Java~~ *done* (with revkit's own processors directory and the EVM processor: [processors.md](processors.md#revkits-own-processors), [evm.md](evm.md));
- a wildcard assembler, and "find instructions like this".
