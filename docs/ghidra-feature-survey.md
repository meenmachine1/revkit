# Ghidra feature survey

Every feature in Ghidra 12.1.4's help (239 pages, 33 modules), plus the
modules without help pages (Ghidra Server, headless, demanglers, the
Microsoft analyzers, processor authoring), compared with revkit on
2026-10-08 (master 8d7b00c), and every Missing, Partial and In progress row
judged again on 2026-10-09 against master 807d127 (after equates, user
references, the searches, field edits, find uses, call-site overrides,
calling conventions, the Python console, demangling, rebase, the byte
viewer, hover cards, containers, Function ID, MSVC, PDB, project and
library types, compare, keymaps, resizable dialogs and decompiler copy
landed). Each row was judged from revkit's docs and code, with an evidence
path for Have and Partial. The prioritised list is
[wishlist.md](wishlist.md); this file is the evidence behind it.

The counts below, Part 1's and Part 2's count tables, and the counts
sentence in the wishlist are computed from the rows by
`scripts/survey_summary.py` (run it after editing a row; `--check` says
whether they are current).

<!-- survey-summary:total -->
| Part | Features | Have | Partial | Missing | In progress |
| --- | ---: | ---: | ---: | ---: | ---: |
| Base (CodeBrowser, analyzers, types, search, symbols, ...) | 271 | 122 | 82 | 67 | 0 |
| Everything else (decompiler, graphs, VT, BSim, FID, debugger, formats, ...) | 461 | 203 | 99 | 159 | 0 |
| **Total** | **732** | **325** | **181** | **226** | **0** |
<!-- /survey-summary:total -->

## Part 1: Ghidra 12.1.4 Base module vs revkit: feature gaps

Surveyed 2026-10-08 against revkit master `8d7b00c` (after `d5c8c1e`); Missing, Partial and
In progress rows judged again 2026-10-09 against `807d127`. Source: Ghidra's
`Base/help/topics` (82 topics), topic by topic. Evidence paths are relative to `~/dev/revkit`.
"In progress" = on an in-flight branch.

Legend: Value = to a reverse engineer doing real work (High/Med/Low). Effort = S/M/L. Effort is
left blank for Have rows.

Key evidence used everywhere:
- `docs/scripting.md` "Unsupported APIs": revkit's own list of Ghidra APIs it lacks (namespaces,
  external locations, program trees, highlights, colors, selections, processor context, stack
  frames, inline flag, custom storage, relocation table, source files, user properties; equates
  and user references left the list when they landed, api_minor 39). Cited below as **Unsupported**.
- `proto/revkit/v1/assertion.proto` `AssertionBody`: the only edit kinds (rename, retype, comment,
  function bounds, flow override, note, define/bind type, patch, memory region, listing edit,
  mutability, type category, operand display (equates and Convert), user reference, image base,
  type archive setting, call-site signature override). No bookmark, label-set, namespace or
  register-value kind.
- `ui/src/app.ts` `commands()`: every UI command and key.

---

### About
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| About (versions, licenses) | Have | `ui/src/ui/about.ts` (UI and daemon versions, licenses) | Low | |
| About Program (format, language, base, sizes, hashes, import info) | Partial | `GetProgramSummary` (`proto/revkit/v1/project.proto` ProgramSummary) and `ProgramInfo.sha256` (format, language, SHA-256, import time); no UI dialog (`ui/src/ui/about.ts` shows only UI and daemon versions), no MD5 or loader details | Low | S |

### Annotations
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Comment annotations (`{@symbol}`, `{@address}`, `{@url}`, `{@program}`, `{@execute}`) rendered as links | Missing | not found: no `{@` annotation parsing in `ui/src` (listing comments, `ui/src/data/listingSource.ts`), nothing in `docs/ui.md` | Med | M |

### AssemblerPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Patch Instruction (inline assembler, completions, encodings) | Have | `ui/src/patch/patch.ts`, `PatchService.Assemble` (`docs/patching.md`), Ctrl+Shift+G | High | |
| Patch Data (edit bytes hex/ASCII) | Have | Ctrl+Shift+H, `PatchBytes`; Patches view, revert (`docs/ui.md` Patching) | High | |

### AutoAnalysisPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Auto analysis on import and after edits | Have | analysis as incremental fact queries re-run by edits (`docs/facts.md`, `docs/backend.md`) | High | |
| Analysis Options panel (enable/disable analyzers, per-analyzer options, saved configs) | Missing | `ListAnalyzers` lists 6 coarse analyzers plus plugins, no options (`src/backend/image_backend.cc` `ListAnalyzers`, `proto/revkit/v1/analysis.proto` `Analyzer`); no UI; `setAnalysisOption` Unsupported (`docs/scripting.md`) | Med | M |
| One Shot analysis (one analyzer, on a selection) | Partial | `StartAnalysis` takes analyzer ids and ranges (`proto/revkit/v1/analysis.proto`); analyzers coarse; the only UI caller is Function ID's Run (`ui/src/ui/fid.ts`) | Low | M |
| Analyze All Open | Have | every program is analysed at import (`ImportOptions.analyze`) | Low | |
| Address Table Analyzer | Partial | firmware pointer tables (`docs/firmware.md`, `search_starts`); PE address tables still "Not done" (`docs/data-analysis.md` Not done) | Med | M |
| ARM Analyzer (const prop, ARM/Thumb switching, LR returns) | Have | `docs/firmware.md` table (interworking, TMode, LRset, `resolve_computed`) | High | |
| ASCII Strings Analyzer (n-gram model) | Have | `docs/data-analysis.md` step 3; its options (min length, alignment) not exposed | High | |
| Data Archive Analyzer (library types applied to imports) | Have | revkit's own archives (glibc LP64/ILP32, Windows DLLs and CRT LLP64/ILP32) built from host headers, then Ghidra's `.gdt` for the rest; prototypes by name at library rank (`docs/types.md#library-prototypes`) | High | |
| Data Reference Analyzer | Have | `docs/data-analysis.md` step 2 (strings, pointers `PTR_`) | High | |
| Decompiler Parameter ID | Have | `docs/param-id.md`; plus whole-program inference `src/infer` (`docs/infer.md`) | High | |
| Demangler Analyzer | Have | names, namespaces and classes, prototypes from mangled signatures (`src/inputs/demangled.cc`, `docs/demangle.md`, api_minor 40) | High | |
| Entry Point Analyzer | Have | discovery seeds (`README.md` "Function discovery") | High | |
| Format String Analyzer (printf-family call-site varargs types) | Have | call-site prototypes from constant printf/scanf formats, decompiled again with them (`docs/types.md#format-strings`) | Med | |
| Image Analyzer (embedded GIF/PNG/BMP) | Missing | not found in `src` (no GIF/PNG/BMP signature markup) | Low | S |
| MIPS / PowerPC address markup (hi/lo pairs, gp/TOC registers) | Partial | generic constant carrying over p-code (`docs/data-analysis.md` step 1); no gp/r2/r13/_SDA_BASE_ register assumptions found in `src` | Med | M |
| Propagate External Parameters | Missing | not found as listing markup; library prototypes typed on imports (`docs/types.md#library-prototypes`, api_minor 50) make the decompiler show typed arguments, but no parameter comments at the call sites | Low | M |
| Scalar Operand Analyzer (address-like immediates become refs) | Partial | addresses computed into registers or stored become refs (`analysis.flow` data_refs, `docs/data-analysis.md`) | Low | S |
| Stack Analyzer (stack variables on the function) | Partial | locals come from the decompiler; `Function.getStackFrame` Unsupported (`docs/scripting.md`) | Low | M |
| Subroutine Reference Analyzer | Have | `xrefs.static` (call refs), `src/backend/image_backend.cc` | Med | |
| Windows x86 PE analyzers (PE header markup, SEH/exception data, RTTI, security cookie) | Have | [pe.md](pe.md) | - | - |
| Aggressive Instruction Finder | Have | firmware aggressive code finder (`README.md` Firmware, `src/analysis/search.cc`) | Med | |
| Condense Filler Bytes | Missing | not found in `src`; `AlignmentDataType` Unsupported (`docs/scripting.md`) | Low | S |

### BlockModel
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Basic block model | Have | `GetFunctionGraph` (`docs/api.md` Function graphs) | Med | |
| Other models (simple, subroutine, isolated/multiple entry, partitioned, call block) | Missing | `SimpleBlockModel`, `PartitionCodeSubModel`, `IsolatedEntrySubModel` Unsupported | Low | M |

### BookmarkPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Add/edit bookmark (category, comment) | Have | notes, Shift+N, `Note{tag,text}`; Ghidra bookmarks import as notes (`docs/ghidra-interop.md`) | Med | |
| Remove bookmark | Have | empty note text clears; undo | Low | |
| Bookmarks window (list, navigate, listing marker) | Have | Notes panel `ui/src/ui/notes.ts` (virtualized, click to go, marker) | Med | |
| Bookmark types (Info/Warning/Error/Analysis) and filter by type/category | Partial | notes carry a free tag only; the Notes panel has no filter (`ui/src/ui/notes.ts`); next/previous note is `Ctrl+Alt+B` (`docs/ui.md` Byte viewer, navigation); analysis makes no bookmarks | Med | S |
| Make selection from bookmarks | Missing | a listing selection of ranges exists now (Search results' Make selection, `ui/src/ui/search.ts` `makeSelection`), but the Notes panel (`ui/src/ui/notes.ts`) has no Make selection; `createSelection` Unsupported | Low | S |

### BundleManager
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Script directories / module paths | Have | shipped, per-user and project script libraries (`docs/ui.md` Scripts) | Low | |
| OSGi bundles, inter-bundle dependencies | Partial | Python imports cover it; no Java bundles (CPython only, `docs/scripting.md`) | Low |  |

### CParserPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Parse C headers (preprocessor, -I, -D, target) | Have | `src/cparse`, Import header… (`docs/cparse.md`, `ui/src/ui/headerimport.ts`); better previews and policies | High | |
| C++ headers | Partial | "C and a C++ subset" (`docs/cparse.md` C++ subset: namespaces, classes; `docs/roadmap.md` Types P0); no templates or full C++ | Med | L |
| Saved parse profiles (.prf per platform) | Partial | target, include folders and defines per import in the header import dialog (`docs/ui.md` Types: editor and header import); no saved profiles | Low | S |
| Parse into program or archive | Have | program, or type archive export (`docs/types.md#type-archives`) | Med | |

### CallTreePlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Incoming/outgoing call trees, level by level, recursion marked | Have | Calls view `ui/src/ui/calls.ts` | Med | |
| Filtering (depth, thunks) and calls through unresolved pointers | Partial | no depth or thunk filters (`ui/src/ui/calls.ts`); calls through unresolved pointers still missing (`docs/ui.md` Known gaps phase 5), though a user's computed-call reference (api_minor 39) now shows | Low | S |
| Navigate, go to call site, make root | Have | click, Alt+click, Enter (`ui/src/ui/calls.ts`) | Low | |

### Charsets
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Charsets beyond ASCII/UTF-8/16/32 (Shift-JIS, GBK, EBCDIC, code pages) | Missing | `StringEncoding` UTF8/UTF16/UTF32 only (`proto/revkit/v1/assertion.proto`); Search memory strings ASCII/UTF-8/UTF-16 only (`docs/api.md` Search) | Med | M |

### ClearPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Clear Code Bytes | Have | `c` key, `ClearCode` (`docs/listing-edit.md`) | High | |
| Clear With Options (symbols, comments, refs, functions, equates, bookmarks, registers over a range) | Missing | only code/data clear (`docs/listing-edit.md`, `c` key); `RevertByProvenance` reverts by author, not by range; no Clear With Options in `ui/src/ui/listingedit.ts` | Med | M |
| Clear Flow and Repair | Missing | not found in `ui/src` or `docs/listing-edit.md` | Med | M |

### ClipboardPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Copy listing rows as text | Have | `copy-rows` Ctrl+C (`ui/src/app.ts`) | Med | |
| Copy Special (bytes as hex string, C/Python array, addresses, labels) | Have | Ctrl+Shift+C: hex, C array, Python bytes, Base64, addresses, the listing's text (`ui/src/data/copyformats.ts`, `docs/ui.md` "Byte viewer, navigation and the overview") | Med | |
| Paste (bytes, labels, comments) | Missing | not found: Copy and Copy special only (`ui/src/data/copyformats.ts`); no paste into the listing | Low | M |

### CodeBrowserPlugin (Listing)
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Listing (address, bytes, labels, mnemonic, operands, comments, header rows) | Have | canvas listing `ui/src/listing/view.ts`, `docs/ui.md` | High | |
| Flow arrows (draw, select, follow) | Have | `docs/ui.md` Flow arrows | Med | |
| Cursor text highlight (same token across rows) | Have | `hoverKey`/`selectedKey` (`ui/src/listing/view.ts:1029`) | Med | |
| Expand/collapse structures and arrays | Have | `+`/`-`, disclosure marker (`docs/ui.md` Listing edits) | Med | |
| Open/close functions; function variables display | Missing | "No post-comment or local-variable lines" (`docs/ui.md` Known gaps v1.1) | Low | M |
| Mouse-hover popups (reference preview, data type, scalar, address, function) | Have | hover cards (`ui/src/ui/hover.ts`, docs/ui.md "Hover cards"), in the listing and the decompiler, provenance below | High | |
| XREF field (inline referrers) | Have | count, and with the Fields menu's XREF list the first three referrers with their kinds on label rows (`ui/src/listing/fields.ts`) | Med | |
| Markers / navigation margin | Partial | note marker, patch bar, breakpoints, pc and now search hits in the gutter (`ui/src/listing/view.ts`, `docs/ui.md` Search); overview and entropy bars (`ui/src/listing/overview.ts`); no program-wide margin of notes, hits or the selection | Med | M |
| Optional fields: file offset, function offset, image-base offset, p-code, source map | Partial | Fields menu: file offset, function offset, p-code (on the instruction's line), XREF list on labels (`ui/src/listing/fields.ts` `FIELD_MENU`); no image-base offset or source map | Med | S |
| Field formatter (add/move/remove fields, custom formats) | Partial | bytes column (Shift+B), header-row and arrow toggles, the Fields menu's optional fields (`ui/src/listing/fields.ts`); no add/move/remove of fields or custom formats | Low | L |
| Fonts and colors options | Partial | light/dark themes only; Preferences has only the keymap (`ui/src/ui/preferences.ts`) | Low | S |
| Listing background colors (set, clear, navigate) | Missing | not found in `ui/src` or the backend; `setBackgroundColor` Unsupported (`docs/scripting.md`) | Med | M |
| Selection tables (range table) | Missing | not found (the selection made from search results has no table of its ranges) | Low | S |

### CommentWindowPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Comment window (all comments, filter, navigate) | Partial | no comment window, but Search: program text with only the Comments field (and regex `.`) lists every comment in the Search results table with sort, filter and go-to (`docs/ui.md` Search, `ui/src/ui/search.ts`, `SearchText` `COMMENTS`) | Med | S |

### CommentsPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Set/edit EOL, pre, post, plate comments | Have | `;`, comment-* commands (`ui/src/app.ts`); plate/pre reach the decompiler | High | |
| Repeatable comments | Partial | kind exists and renders (`ui/src/data/listingSource.ts`), Search program text matches it; no UI to set one (no repeatable item in the Comments submenu, `docs/ui.md` Keymap presets notes revkit has none) | Low | S |
| Delete comments | Have | empty text, undo | Med | |
| Comment history | Have | `GetHistory`/`Blame`, provenance popover `i` (`ui/src/ui/provenance.ts`) | Med | |

### ComputeChecksumsPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Checksums over selection/program (sums, Adler, CRC-16/32, MD5, SHA-1/2) | Partial | sums, Fletcher, Adler-32, CRC-16/32 for export fixups and `DetectChecksum` (`docs/patching.md`); SHA-256/SHA-1/MD5 of container files in the file system browser's Info (`docs/ui.md` File system browser); no ad-hoc checksum of a selection or the program | Low | S |

### ConsolePlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Console (output, clear, find, click address to navigate) | Partial | Python console (api_minor 43, `ui/src/scripts/console.ts`, `docs/ui.md` Python console: REPL, history, completion, Clear) and the script output panel (`ui/src/scripts/manager.ts`); no find in the output, no click on an address to go there | Med | M |

### DataPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Apply built-in types (byte..qword, char, string, UTF-16, Pascal, float, pointer, array) | Have | `b ' " [ t p` keys, Data submenu (`docs/listing-edit.md`) | High | |
| Cycle groups | Have | `b` cycles byte/word/dword/qword (`docs/ui.md`) | Med | |
| Recently used data type | Have | Recently used submenu (`docs/ui.md`) | Med | |
| Favorites | Missing | not found; the listing's Data menu has a Recently used submenu (last five definitions, `docs/ui.md` Listing edits), not user favorites | Low | S |
| Apply program types (struct, union, enum, typedef) at address | Have | `t` type chooser | High | |
| Drag a type from the type manager onto the listing | Missing | not found: drag in `ui/src/ui/types.ts` only files types into folders; the listing takes no drop | Low | S |
| Data settings (hex/dec/char format, endian, charset, padding, mutability) | Partial | mutability only (`SetMutability`: constant/volatile/writable; `DefineData` in `proto/revkit/v1/assertion.proto` has no format, endian or charset settings) | Med | M |
| Create structure from selection | Have | `TypeService.AutoStructure` (`docs/ui.md`) | Med | |
| Dynamic data types (headers laid out by format) | Partial | PE headers, data directories, unwind and exception data laid out as typed data at import (`docs/pe.md` PE structures and exception data, `src/msvc/pe_markup.cc`); no user-applicable dynamic types, no ELF header markup | Low | L |
| Quick-edit a structure field from the listing (Edit Field dialog) | Partial | Rename field and Retype field on a decompiler field token (api_minor 38, `ui/src/app.ts` `renameField`/`retypeField`, `docs/ui.md` Struct fields in the decompiler); listing field rows still read-only (edit in Types) | Med | S |

### DataTypeEditors
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Data type chooser (completion, `*`/`[n]`, browse) | Have | Set type chooser (`docs/ui.md` "Right-click menus and the type chooser") | High | |
| Structure/union editor (insert, delete, move, duplicate, size, packing, alignment, bitfields, flexible arrays) | Have | `ui/src/ui/types.ts`, `docs/ui.md` Types editor | High | |
| Edit as C text | Have | C tab (`docs/ui.md`) | Med | |
| Unpackage component; nested structure from selected components | Missing | not found in the editor (`ui/src/ui/types.ts`) | Low | S |
| Undo/redo and search inside the editor | Missing | "The editor has no undo inside an unsaved edit" (`docs/ui.md` Known gaps phase 5); no search inside the editor | Low | S |
| Field comments, type description | Missing | `Field.comment` exists in `proto/revkit/v1/types.proto` but the editor (`ui/src/ui/types.ts`) neither shows nor edits it; no type description | Med | S |
| Enum editor (expressions, size, signedness, sort, hex) | Have | `docs/ui.md` Enums | Med | |

### DataTypeManagerPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Program types tree (categories, filter) | Have | Types view, folders (`docs/ui.md`, `find-types-tree`) | High | |
| Built-in library archives | Have | `TYPE_SOURCE_LIBRARY` (`docs/api.md` Types): revkit's `share/revkit/typeinfo` archives (`tools/rk-typeinfo`), Ghidra's `.gdt` (`src/inputs/ghidra_archive.cc`) for the rest | Med | |
| File archives (open, create, edit, save) | Partial | own format (C header + JSON sidecar) export/import (`docs/types.md#type-archives`), attached to a project for its prototypes and types (`docs/types.md#project-types`); Ghidra .gdt read only for library types | Med | M |
| Project data type archives / project-wide types | Have | project-scope types every program sees, Move to project, Copy to program, archives attached to the project (`docs/types.md#project-types`) | High | |
| Archive sync (commit, update, revert, disassociate) | Missing | not found (re-import is idempotent by hash) | Med | L |
| Categories (create, rename, move, delete, copy) | Partial | Move to category, drag; no empty folders, no folder rename/delete (`docs/ui.md` Known gaps phase 5) | Low | S |
| Rename, duplicate, edit type | Have | Rename…, Duplicate… (`docs/ui.md`) | Med | |
| Delete type | Partial | retract its assertion (`DataTypeManager.remove`, `docs/scripting.md`); no Delete in the Types view (`ui/src/ui/types.ts` detail buttons: Edit, Edit in C, Duplicate, Rename, Move, Find uses, Apply) | Low | S |
| Replace type everywhere / merge types | Missing | rename rebinds the name only; re-pointing uses rejected (`docs/ui.md` Phase 5 Types); no replace or merge in `ui/src/ui/types.ts` | Med | M |
| Find types by size, structures by size/offset, enums by value | Partial | enums by member value: `FindTypes{enum_value}` (api_minor 39, `proto/revkit/v1/query.proto`), offered in Set equate's suggestions; no search by size or by field offset (`FindTypesRequest` filters name, kind, source, category) | Med | S |
| Apply function data types (prototypes by name) | Have | header import retypes functions from prototypes (`docs/ui.md` Import header) | High | |
| Capture function data types | Missing | not found (type archives export types, `docs/types.md#type-archives`, not function signatures) | Low | S |
| Export types as C header | Have | Export archive… (`docs/types.md`) | Med | |
| Conflict resolution on import | Have | per-type import/skip/rename policy (`docs/ui.md` Import header) | Med | |
| Create labels from enums; show base type; pointer-typedef settings; type as graph | Missing | not found in `ui/src/ui/types.ts` (no labels from enums, base type, pointer-typedef settings or type graph) | Low | S |

### DataTypePreviewPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Preview the bytes at the cursor as several types | Partial | the Bytes view shows hex, ASCII, octal, binary, UTF-16 and signed integers of 1 to 8 bytes at the cursor (`ui/src/bytes/viewer.ts`, `docs/ui.md` Byte viewer); a scalar's hover card shows hex, decimal and char; no float or chosen-type (struct) preview | Med | S |

### DataWindowPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Defined data table (filter by type and text, navigate) | Have | Data view `ui/src/ui/data.ts` (`ListData`) | Med | |

### DbViewerPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Raw database viewer | Partial | `ListAssertions`, `GetHistory` over the log (API, MCP `list_my_changes`); no UI | Low | S |

### DefinedStringsPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Defined strings table (columns, filter, navigate) | Have | Data view, strings category, Ctrl+6 | High | |
| Per-string settings and translation | Missing | see Charsets and TranslateStrings; no per-string settings in the Data view (`ui/src/ui/data.ts`) | Low | S |

### DisassembledViewPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Disassembly preview at any address (data or undefined) | Partial | `GetInstruction` decodes any address (`PseudoDisassembler` row, `docs/scripting.md`); hover cards preview listing rows of a reference's target (`docs/ui.md` Hover cards) but not undefined bytes decoded; no UI view | Low | S |

### DisassemblerPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Disassemble (follow flow) | Have | `d` (`docs/listing-edit.md`) | High | |
| Disassemble ARM / Thumb | Have | menu (`docs/ui.md` Listing edits) | High | |
| Static / restricted disassembly (selection only, no flow) | Missing | not found: `Disassemble` in `proto/revkit/v1/assertion.proto` always follows flow | Low | S |
| Processor options (context: x86 16/32, MIPS16/microMIPS, PPC VLE, etc.) | Partial | ARM/Thumb only (`Disassemble.instruction_set`, `docs/ui.md` Listing edits); VLE as separate languages (`docs/processors.md`) | Med | M |
| Modify instruction flow | Have | flow override `o` | High | |
| Modify instruction length (overlapping code) | Missing | not found | Low | M |

### DockingWindows
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Dockable, tabbed, movable views; remembered layout | Partial | two dock groups, drag, remembered, Search results as a view that comes and goes (`ui/src/ui/dock.ts`, `docs/ui.md` Phase 5 Docked views); no floating windows or splits | Low | M |

### DWARFExternalDebugFilesPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| External debug files (build-id dirs, `.gnu_debuglink`, debuginfod) | Missing | not found in `src` (no debuglink, build-id or debuginfod); no supplementary files (`docs/types.md` Known gaps) | Med | M |

### EclipseIntegration / VSCodeIntegration
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| External IDE for scripts (project generation, launch) | Partial | built-in CodeMirror editor; `from revkit.script import *` for editors (`docs/scripting.md`); no project generator or "edit in VS Code" | Low | S |

### EquatePlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Set/rename/remove equate on an operand | Have | Set equate (`Shift+E`), Rename and Remove everywhere from the Equates window, Remove equate on an operand (api_minor 39, feature `equates`; `ui/src/ui/equates.ts`, `docs/ui.md` Equates and references, `docs/api.md` Equates and user references); listing and decompiler both show it | High |  |
| Apply enum to operand; show/edit enum | Have | Set equate offers the enum members of the scalar's value (`FindTypes{enum_value}`) and asserts the member (`OperandDisplay.equate{enum_type_hash, member}`; `docs/api.md` Equates and user references); enums edited in Types (`ui/src/ui/types.ts`) | High |  |
| View equates table | Have | Equates view (side dock): name, value, uses, go to, Rename, Remove (`ui/src/ui/equates.ts` `EquatesView`, `docs/ui.md` Equates and references) | Med |  |
| Convert operand display (signed/unsigned dec, hex, octal, char, binary, float) | Have | Convert submenu on a listing operand or decompiler constant: hex, signed/unsigned decimal, octal, binary, char, float, default (`OperandDisplay.format`, `ui/src/app.ts` Convert menu, `docs/ui.md` Equates and references) | High |  |

### ExporterPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Original file (with patches) | Have | `ExportProgram` FILE, checksum fixups (`proto/revkit/v1/patch.proto`, `docs/patching.md`) | High | |
| Raw bytes | Have | `EXPORT_FORMAT_IMAGE` | Med | |
| C/C++ (whole program) | Partial | Copy function (the whole C) in the decompiler (`ui/src/app.ts` `decomp-copy-all`), `export_functions` starter (C via DecompileMany, `sdk/python/revkit/scripts/export_functions.py`), type archive header; no one-step .c/.h export of the program | Med | S |
| ASCII / HTML listing | Partial | Copy rows as shown and Copy special's listing text (`ui/src/data/copyformats.ts`); no file export of the listing | Low | S |
| Intel HEX | Missing | import only (`raw_format` ihex, `ui/src/ui/open.ts`); `ExportProgram` writes the file or the image only (`proto/revkit/v1/patch.proto` `ExportFormat`) | Med | S |
| XML / SARIF | Missing | Ghidra interop JSON covers user work only (`docs/ghidra-interop.md`, `sdk/python/revkit/ghidra/exporter.py`); no XML or SARIF | Low | M |
| GZF (packed program) | Have | project archives (api_minor 37, feature `project-archive`): Export program…, Export folder… or Export project… as one `.rkproj` (optionally annotations only) and Import project… (`ui/src/ui/archive.ts`, `docs/ui.md` Project tree and archives, `docs/backend.md#project-archives`) | Med |  |
| GDT (type archive) | Have | Export type archive… (own C header + JSON format) | Med | |

### FallThroughPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Set/clear fallthrough address, auto override | Missing | `FlowOverrideKind` has none/branch/call/call-return/return only (`proto/revkit/v1/assertion.proto`); no fallthrough override | Med | S |

### FileSystemBrowserPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Open container file systems (zip, tar, cpio, ISO, squashfs, ext, firmware packages, nested) | Have | `FileSystemService`, the File System Browser (`docs/filesystems.md`) | - | - |
| Import/batch import/export from a container; view as text/image | Partial | import, batch import (preview, cap) and extract (`docs/filesystems.md`, `ui/src/ui/filesystem.ts`); no text or image view ("no text or hex preview pane", `docs/ui.md` File system browser Not yet) | Low | S |

### FlowSelection
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Select by flow (forward/backward, scoped) | Missing | not found in `ui/src` (no flow-based selection) | Low | S |

### FrontEndPlugin (project window)
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Create/open/switch projects | Have | project switcher (`docs/ui.md` Programs and projects), `ProjectService` | High | |
| Delete project | Missing | no DeleteProject RPC (`proto/revkit/v1/project.proto` ProjectService) | Low | S |
| Project data tree: folders, move, copy | Partial | project folders (api_minor 37, feature `project-folders`): tree, New folder, Rename, Move to, Delete (empty), drag (`ui/src/ui/open.ts`, `docs/ui.md` Project tree and archives); no copy of a program or folder, no multi-select move | Med |  |
| Archive / restore project | Have | Export project… and Import project… as `.rkproj` (into a new or this project, missing binaries found by SHA-256 or added) (api_minor 37, `ui/src/ui/archive.ts`, `docs/ui.md` Project tree and archives; `rk-daemon project export/import`) | Med |  |
| Rename/delete programs | Have | `RenameProgram`, soft `DeleteProgram` with undo (`docs/api.md`) | Med | |
| Shared projects, server connection, access lists, change password | Have | accounts, roles, per-project lists, TLS (`docs/security.md`), `ChangePassword` | High | |
| Read-only views of other projects | Partial | viewer role, switch project; no side-by-side views | Low | S |
| Tool chest, tool connections, workspaces | Partial | many browser tabs on one daemon, presence (`docs/ui.md` Presence); no cross-program cursor linking | Low | S |
| Extensions (install, enable) and plugin path | Partial | WASM plugins via `--plugin-dir` (`docs/plugins.md`); no install UI | Low | S |
| PKI client certificates | Missing | not found: "No single sign-on, MFA or client certificates" (`docs/security.md`); accounts, tokens and TLS server certs only | Low | M |

### FunctionComparison
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Side-by-side listing, decompiler and graph diff with highlights | Have | Compare view (`docs/ui.md` Compare) | High | |
| Compare any functions on demand (same program, several at once) | Partial | Any two (one program or two): `CompareFunctions`, Compare with… (api_minor 54); not several at once | Med | S |
| Next/previous difference; ignore constants/registers options | Partial | n/p difference Have; only default-name abstraction (`docs/ui.md`) | Low | S |
| Apply actions (names, signatures, comments) | Have | Apply markup… (`docs/ui.md` Compare) | Med | |

### FunctionPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Create function | Have | `f`, Disassemble and create function | High | |
| Re-create / edit function body | Partial | `set_function(entry, body)` in scripts/API; UI only create/remove (`ui/src/app.ts` `fn-create`, `fn-remove`) | Low | S |
| Create multiple functions (selection) | Partial | starter `create_functions_at_call_targets`; UI creates one at a time (Disassemble and create function, `docs/ui.md` Listing edits) | Low | S |
| Delete function | Have | Shift+F | Med | |
| Rename function | Have | n/F2 | High | |
| Edit signature (return, params, varargs, noreturn, calling convention) | Have | `y` with a C prototype (`int __stdcall f(int)`, `__attribute__((noreturn))`), Unsupported table rows | High | |
| Custom variable storage / edit parameter storage | Missing | "revkit keeps the decompiler's storage" (`Function.setCustomVariableStorage` Unsupported, `docs/scripting.md`) | Med | M |
| Inline flag | Missing | "no inline flag in revkit" (`Function.setInline` Unsupported, `docs/scripting.md`) | Med | S |
| Call-fixup | Partial | the compiler spec's call fixups are installed by function name automatically, as Ghidra's Call-Fixup Installer (`src/inputs/assemble.cc` `call_fixup`, `src/lift/abi.cc`); no way to set a call-fixup on a function by hand | Low | S |
| Thunks (set thunked function) | Partial | thunks found automatically; `setThunkedFunction` Unsupported | Low | S |
| External functions / locations | Partial | imports are thunks named after targets, typed from library archives by name (`docs/types.md#library-prototypes`, api_minor 50), and resolved to the library programs' functions (`ResolveImport`, the functions list's "→ libc.so.6!strlen"; `docs/api.md#libraries`, api_minor 70); no external locations as listing objects (`getExternalManager` Unsupported) | Med | M |
| Function purge / stack depth change | Partial | a function's purge comes from its prototype's calling convention model (`extrapop`, `docs/decompiler-inputs.md` Calling conventions; set via Set type, e.g. `__stdcall`); no explicit purge field, no per-call stack depth change | Med | S |
| Rename/retype parameters and locals | Have | decompiler rename/retype by storage key (`docs/ui.md`) | High | |
| Add/delete local variables (listing level) | Missing | "locals come from the decompiler" (`Function.addLocalVariable` Unsupported, `docs/scripting.md`); rename_local/retype_local only | Low | M |
| Create function definition (type from a signature) | Missing | not found: Types' New… makes struct, union, enum, typedef (`ui/src/ui/types.ts`); a function typedef can be written in Edit in C, but no action from a function's signature | Low | S |

### FunctionTagPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Function tags (create, assign, tag window, filter functions by tag, load external tags) | Partial | notes with tags at the entry (`Function.addTag` -> note); no tag window or tag filter in Functions (`ui/src/ui/functions.ts`) | Med | S |

### FunctionWindowPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Functions table (signature, size, refs; sort; filters) | Have | `ui/src/ui/functions.ts`, `function-list-filters` (`docs/ui.md`) | High | |
| Compare selected functions | Partial | Ctrl+click marks two functions in the function list and "Compare the marked" opens them (`ui/src/app.ts` `fn-menu-compare-marked`, `docs/ui.md` Compare two functions); two at a time only | Low | S |

### GhidraScriptMgrPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Script manager (category tree, filter, description, run, bind key, palette launch) | Have | `ui/src/scripts/manager.ts` (`docs/ui.md` Scripts) | High | |
| Edit, save, new script | Have | CodeMirror editor, Save, New… | Med | |
| Rename/delete script | Missing | not found in `ui/src/scripts/manager.ts` | Low | S |
| Run Ghidra scripts | Partial | Python `revkit.ghidra.compat` shim, 21 of 30 corpus scripts agree (`docs/scripting.md`); no Java | Med | L |

### GhidraServer
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Multi-user server | Have | `rk-daemon` accounts, TLS, peers (`docs/security.md`, `docs/collab.md`) | High | |

### Graph
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Graph display (function graph, call graph) | Have | `ui/src/graph/cfg.ts`, Calls view | High | |
| Graph export (DOT, GraphML) and generic graph service | Partial | the `export_call_graph` starter script writes the call graph as DOT (`sdk/python/revkit/scripts/export_call_graph.py`); no GraphML, no export from the graph views, no generic graph service | Low | S |

### HeadlessAnalyzer
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Headless import, analysis, pre/post scripts | Have | `rk-script` (headless, `-j`, pre/post, JSON summaries), `rk-lift` (`docs/scripting.md`) | High | |

### ImporterPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Import ELF, PE, raw, Intel HEX, S-records, AVR ELF | Have | `ImportProgram` (`docs/api.md` Raw images, `docs/processors.md`) | High | |
| Mach-O | Missing | deferred (`docs/roadmap.md` Later; `README.md` Loaders: "Mach-O is deferred") | High | L |
| COFF / `.o` / `.lib`, MZ/NE (DOS), OMF, DYLD cache, XML/SARIF, GZF | Missing | not found; "Linked images only: no relocation of `.o` files" (`docs/types.md`); `ar` archives open in the file system browser but members aren't loaded as objects | Med | L |
| Drag-and-drop import | Have | Open dialog drop (`docs/known-issues.md`) | Med | |
| Batch import | Have | `docs/filesystems.md` | - | - |
| Add To Program | Have | memory map "bytes from a file" (`docs/memory-map.md`) | Med | |
| Load libraries, library search path, link project libraries | Have | `ImportOptions.import_libraries` with `library_search_paths` and a depth (the Open dialog's "Also import the libraries it needs"), resolution by name or soname and `LinkProgramLibrary`, Analyze → Libraries… (`docs/api.md#libraries`, `docs/ui.md` "Libraries"; api_minor 70) | - | - |
| Import selection (bytes into a new program) | Missing | not found | Low | S |
| Language/compiler spec chooser | Partial | `ListLanguages`, raw autodetect with alternatives (`docs/autodetect.md`, `ui/src/ui/rawdetect.ts`); ELF/PE language from the loader, no chooser there | Low | S |
| Raw binary options (base, offset, length, regions) | Have | `docs/api.md` Raw images; autodetect (better) | High | |
| ELF options (image base, apply relocations) | Partial | image base / `--file-base`, Set image base after import (api_minor 42, `docs/memory-map.md`); relocations listed, not applied (`README.md` Loaders) | Med | M |
| Processor-defined labels and blocks | Have | `docs/processors.md` | Med | |
| PE options (ordinal lookup, .NET CLI headers) | Partial | export ordinals parsed (`src/loader/pe.cc`); no CLI/.NET | Low | M |

### LabelMgrPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Add/rename label at an address | Have | `Rename{address}`, n/F2 | High | |
| Multiple labels per address, primary label | Missing | "one name per address" (`getNamespace` Unsupported, `docs/scripting.md`; `docs/ghidra-interop.md`) | Med | M |
| Namespaces, function-local labels | Partial | namespaces and classes from demangled names shown in every view, searched and gone to as `ns::name` (api_minor 40, `docs/demangle.md`, `docs/ui.md` Demangled names); no user namespaces or function-local labels (`createNamespace` Unsupported) | Med | M |
| Remove label | Partial | derived names can't be deleted; rename or undo (Unsupported) | Low | S |
| External entry point | Missing | `addEntryPoint` Unsupported (`docs/scripting.md`) | Low | S |
| Label history | Have | `GetHistory`/`Blame` (`docs/api.md`) | Med | |

### LanguageProviderPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Change a program's language/compiler spec | Have | `ProjectService.SetProgramLanguage` and `CompareLanguages` (api_minor 73, feature `set-language`; docs/api.md "Changing a program's language", `ui/src/ui/language.ts`): in place, every edit kept, one undo step; variants compared on the program's code with auto-detection's pick | Med | |
| Show p-code | Have | the listing's Fields menu shows each instruction's p-code (`ui/src/listing/fields.ts` `pcode`, api_minor 44, `docs/ui.md` Byte viewer, navigation and the overview); `GetInstruction` p-code, `rk-lift` | Low |  |

### LibreTranslatePlugin / TranslateStringsPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Translate strings (manual, service, show translated) | Missing | not found | Low | M |

### LocationReferencesPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| References to an address, label or function | Have | Show references to… `x` (`ui/src/ui/xrefs.ts`) | High | |
| References to a data type or structure field | Have | Find uses of type and Find uses of field from the decompiler and the Types view, results in Search results (api_minor 53, `FindTypeUses`; `ui/src/app.ts` `findUses`, `docs/ui.md` Find uses, `docs/api.md` Find uses of a type or field) | High |  |

### MemoryMapPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Memory map table | Have | `ui/src/ui/memmap.ts` (`docs/memory-map.md`) | High | |
| Rename, R/W/X, volatile | Have | `UpdateMemoryRegion` | High | |
| Add block (uninit, zero-filled, MMIO, bytes from file) | Have | `AddMemoryRegion` | High | |
| Delete block | Partial | added regions only; image blocks revert (`docs/memory-map.md`, `ui/src/ui/memmap.ts`) | Low | S |
| Move, split, merge, expand up/down | Missing | not found; `Memory.split`/`join` Unsupported; Set image base moves the whole program, not a block (`docs/memory-map.md`) | Med | M |
| Set image base (rebase) | Have | `SetImageBase`, Set image base… (`docs/memory-map.md` "Rebase", api_minor 42): every fact and its history move, one undoable edit | High | |
| Overlay blocks / overlay spaces | Missing | "overlays are not offered" (`docs/memory-map.md` Known gaps) | Med | L |
| Artificial flag, block comment, initialize block | Missing | not found | Low | S |

### Misc (Address Expressions)
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Address expressions in Go To (`main+0x10`, arithmetic) | Have | `ui/src/data/expr.ts` (sym+off, + - * /, parentheses, `file:`, `space:`), unit-tested (`ui/test/expr.ts`) | Med | |

### Navigation
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Go To address / label | Have | Ctrl+K/g palette (`ui/src/app.ts` `searchItems`) | High | |
| Go To with wildcards, namespace paths, case options, file offset | Partial | wildcards (`FUN_*`, `?`), `ns::name`, expressions, `file:0x200` (`ui/src/data/expr.ts`, `docs/ui.md` Byte viewer, navigation and the overview); exact name lookup only, no case options | Med | S |
| Next/previous instruction, data, undefined, label, function, bookmark, different byte | Have | Ctrl+Alt+I/D/U/L/F/B/V (Shift: previous) and the palette, `QueryService.FindNext` (api_minor 44) | Med | |
| Back/forward history | Have | Alt+←/→ (per tab, in memory) | High | |
| Next/previous function in history; clear history | Missing | a history dropdown lists places with their function (`docs/ui.md` History, `ui/src/app.ts` `history`), but no next/previous function in history and no clear history | Low | S |

### OverviewPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Overview bar by address type (code, data, undefined, function) | Have | code, data, undefined, external, uninitialized (`QueryService.GetOverview`, `ui/src/listing/overview.ts`) | Med | |
| Entropy bar | Have | beside the listing's scrollbar, per slice (`QueryService.GetOverview`, `ui/src/listing/overview.ts`) | Med | |

### PrintingPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Print listing | Missing | not found | Low | S |

### ProgramManagerPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Open program (dialog, recent) | Have | Open dialog, `?program=` URL (`ui/src/ui/open.ts`) | High | |
| Several open programs, next/previous program | Partial | one program per browser tab | Low | S |
| Save / Save All | Have | every edit commits (`saveProgram` row in `docs/scripting.md`) | High | |
| Save As (copy a program) | Partial | Export program… then Import project… into this project makes a copy (a taken name gets " (2)") (`ui/src/ui/archive.ts`, `docs/ui.md` Project tree and archives); no one-step Save As | Low | S |
| Program options/properties dialog | Partial | `ProgramSummary` via API; Preferences has the keymap only (`ui/src/ui/preferences.ts`); analysis options are daemon flags | Low | S |

### ProgramTreePlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Program trees (folders, fragments, modularization, views) | Missing | "no program trees (fragments) in revkit" (`Program.getTreeManager` Unsupported) | Low | M |

### PropertyManagerPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| User property viewer | Missing | `getUsrPropertyManager` → notes (Unsupported) | Low | S |

### ReferencesPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| View forward/back references | Have | `GetXrefs` TO/FROM (`docs/api.md` Xrefs), xrefs dialog | High | |
| Add memory reference (incl. computed jump/call targets) | Have | Add reference from here… (`Shift+R`, References submenu): to an address or symbol, Ghidra's RefTypes incl. computed jump and call, operand or instruction, primary (api_minor 39, `UserReference`; `ui/src/ui/references.ts`, `docs/api.md` Equates and user references); discovery, xrefs, listing and decompiler read it | High |  |
| Edit/delete references, set primary | Have | Delete a reference (the user's or analysis's) and Set primary from the References submenu or window (`ui/src/ui/references.ts`, `docs/ui.md` Equates and references); edit is delete then add | Med |  |
| Stack and register references | Missing | "revkit has no stack references" / "no register references" (`addStackReference`, `addRegisterReference` Unsupported, `docs/scripting.md`); `UserReference` is memory only | Low | M |
| External references / external program names | Missing | "no external references" (`addExternalReference` Unsupported, `docs/scripting.md`) | Med | M |
| Create offset references table | Missing | not found in `ui/src/ui/references.ts`; `addOffsetMemReference` Unsupported | Low | S |

### RegisterPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Register values over ranges (context, gp/r2/DS-style constants) | Partial | ARM/Thumb mode only (`Disassemble.isa`); `getProgramContext` Unsupported | Med | M |
| Register manager view | Missing | not found | Low | S |

### RelocationTablePlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Relocation table view | Missing | read by the loader (`src/backend/relocate.cc`), "not listed to scripts" (`Program.getRelocationTable` Unsupported); no view in `ui/src` | Med | S |

### Repository (Merge Program Files)
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Automatic merge of concurrent work | Have | assertion log, HLC, precedence (`docs/collab.md`, `docs/api.md`) | High | |
| Interactive conflict resolution | Partial | precedence decides; `Blame.concurrent_seqs` lists losers (`docs/api.md`) | Low | M |

### ResourceActionsPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Save embedded image resources | Missing | not found | Low | S |

### RuntimeInfoPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Installed processors list | Partial | `ListLanguages` (`docs/api.md`); shown only in raw import | Low | S |
| Runtime info (memory, versions, uptime) | Partial | the daemon status chip's popover: server version, API, uptime, address, project (`ui/src/ui/daemon.ts`, `docs/ui.md` Daemon status); About lists versions and features (`ui/src/ui/about.ts`); no memory usage | Low |  |

### ScalarSearchPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Search scalars (value or range) in instructions and data | Have | Search: scalars, a value, a range or every scalar, in instructions and/or data, results table (api_minor 41, `SearchScalars`; `ui/src/ui/search.ts`, `docs/ui.md` Search) | High |  |

### Search
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Search memory (hex with masks, alignment, executable only) | Have | Search memory dialog (`S`): hex with nibble wildcards, masks, alignment, executable blocks only, code-unit kinds, selection scope (api_minor 41, `SearchMemory`; `ui/src/ui/search.ts`, `docs/ui.md` Search) | High |  |
| Search formats: string, decimal, float/double, binary, regex | Have | Search memory formats Hex, String (ASCII/UTF-8/UTF-16, case, escapes), Decimal (1-8 bytes), Float, Double, Binary with masked bits, Regex (RE2) (`docs/api.md` Search) | Med |  |
| Incremental next/previous match, results table | Have | Next/Previous in the dialogs, F3/Shift+F3 repeat, a dockable Search results view with sort, filter, Copy CSV and the last ten result sets (`ui/src/ui/search.ts`, `docs/ui.md` Search) | High |  |
| Search program text (labels, comments, instructions, data) | Have | Search program text (`Ctrl+F`): functions, comments, labels, mnemonics, operands, data mnemonics and values as shown, regex, case, whole word (api_minor 41, `SearchText`; `docs/ui.md` Search) | High |  |
| Search for strings (on demand, min length, alignment, encoding, make string) | Partial | analysis strings in the Data view (`ui/src/ui/data.ts`); a memory search with a regex such as `[\x20-\x7e]{4,}` finds runs (`docs/api.md` Search); no string search with min length, alignment and Make string | Med | S |
| Instruction pattern search (operands masked) | Partial | Search memory's Binary format takes `x`/`?` for masked bits (`docs/api.md` Search; the documented substitute for `InstructionSearchApi`, `docs/scripting.md`); no instruction-aware operand masking from a selection | Med | M |
| Search for matching instructions (mnemonic) | Partial | Search program text over the Mnemonics and Operands fields, plain or regex, finds instructions by text (`docs/ui.md` Search); no search for sequences matching the selected instructions | Med | S |
| Search for address tables | Missing | not found (no address-table search in `ui/src/ui/search.ts`) | Low | S |
| Search for direct references to an address | Partial | Search memory for the address as a pointer-sized Decimal in the program's byte order finds its direct references (`docs/api.md` Search); xrefs for analysed ones; no one-step Search for Direct References | Med | S |
| Search and replace (bulk rename of symbols, comments, types; regex) | Missing | not found in `ui/src/ui/search.ts` (no replace) | Med | M |
| Combine searches (union, intersect, difference) | Missing | not found; a search can be limited to a selection made from another's results (`docs/ui.md` Search), but no union, intersect or difference of result sets | Low | S |

### SelectBlockPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Select bytes (from address, length, to address) | Missing | not found | Low | S |

### Selection
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Mouse and keyboard selection | Have | drag, Shift+click, Shift+arrows (`ui/src/listing/view.ts`) | High | |
| Select function / all / complement; next/previous selected range | Missing | not found (the listing's selection is rows by drag, Shift+click or Shift+arrows, `docs/ui.md` Copying from the decompiler) | Low | S |
| Make selection from tables (search hits, xrefs, bookmarks) | Partial | Make selection from search results and find-uses results (`ui/src/ui/search.ts` `makeSelection`, `docs/ui.md` Search); not from xrefs, notes or other tables; `createSelection` Unsupported for scripts | Med | M |

### SetHighlightPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Highlights from selections (set, add, subtract, navigate) | Missing | `createHighlight` Unsupported; search hits are marked in the gutter, not highlights (`docs/ui.md` Search) | Low | S |

### ShowInstructionInfoPlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Instruction info (operands, p-code, raw, context) | Partial | `GetInstruction` (`docs/api.md` Instructions), MCP `instruction`, the listing's p-code field (`ui/src/listing/fields.ts`); no instruction info window | Med | S |
| Processor manual lookup | Missing | not found | Med | S |

### Snapshots
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Snapshot (cloned) views | Partial | several browser tabs on the same program; the Bytes view's Follow off pins it (`docs/ui.md` Byte viewer) | Low | S |

### SourceFilesTablePlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Source files and source map from line info; view source; path transforms | Missing | only `.debug_line` header file names read; PDB line numbers not read (`docs/types.md` Known gaps) | Med | M |

### StackEditor
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Stack frame editor | Missing | locals come from the decompiler; `Function.getStackFrame` Unsupported | Med | M |

### SymbolTablePlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Symbol table (every symbol, filter, sort, columns) | Partial | `ListSymbols` (`docs/api.md` Symbols), palette and Go To wildcards, Functions and Data views; no symbol table view (none in `ui/src/app.ts` views) | Med | S |
| Symbol references pane | Have | xrefs dialog | Med | |
| Rename/delete from table, pin, temporary table from selection | Partial | rename with n; no table actions | Low | S |

### SymbolTreePlugin
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Symbol tree (imports, exports, functions, labels, classes, namespaces) | Partial | Functions panel, Types tree, Class hierarchy view from MSVC RTTI (`ui/src/ui/classes.ts`, `docs/ui.md` Class hierarchy); no imports/exports/namespace tree | Med | M |
| Create class or namespace, convert namespace to class, move symbols | Missing | "revkit names are global" (`createNamespace`, `createClass` Unsupported) | Med | M |
| Create library, external location, set external program | Partial | set external program: `LinkProgramLibrary` / SDK `link_library` (api_minor 70); no external locations (Unsupported) | Low | M |

### Tool
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Key bindings (change, remove, import/export) | Partial | keymap presets Ghidra, IDA Pro and Binary Ninja with a cheat sheet (`ui/src/ui/keymap.ts`, `docs/ui.md` Keymap presets) and script keys (`rk.scriptKeys`); built-in keys can't be changed one by one, no import/export | Med | S |
| Tool options dialog | Partial | File -> Preferences… with the keymap only (`ui/src/ui/preferences.ts`); theme, bytes column, header rows, arrows, overview toggles in the palette and Fields menu | Low | S |
| Undo/redo | Have | retractions, one step per run or import, live in every client (`docs/ui.md`) | High | |
| Show log | Partial | the desktop app's daemon popover has Show daemon log (last 256 KB) (`ui/src/ui/daemon.ts`, `docs/ui.md` Daemon status); no log view in a browser | Low |  |
| Configure tool / plugins | Partial | daemon features and WASM plugins; no per-user plugin enablement | Low | S |

### ValidateProgram
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Post-analysis problem detection / program validator | Partial | decompile failures are facts, filterable in Functions (`docs/api.md` Failures) | Low | S |

### VersionControl
| Feature | Status | revkit evidence / what's missing | Value | Effort |
|---|---|---|---|---|
| Share, check in/out, update | Have | live replicated assertion log; no checkouts needed (`docs/collab.md`) | High | |
| Version history, view an old version | Partial | per-fact `GetHistory`/`Blame` with history and Undo in the provenance popover, snapshot reads at a revision (`docs/api.md` Revisions); no UI to browse or diff a past revision | Low | M |

### Informational topics (no features to compare)
Glossary, Intro, Misc (Appendix, Tips, Welcome), Program, Project. Not counted.

---

### Gaps worth doing (Missing or Partial, High or Med value)

High value:
1. ~~**Search UI**: memory search (hex/string/decimal/regex, masks) with next/previous and a results table over `FindBytes`; add string/number encodings to `FindBytes`.~~ *Done (api_minor 41).*
2. ~~**Search program text**: comments, instruction and data text, labels, with results table.~~ *Done (api_minor 41).*
3. ~~**Scalar search**: find instructions and data using a value or range (operands carry `scalar_bits`).~~ *Done (api_minor 41).*
4. ~~**Equates and operand display**: an `EQUATE` assertion (name/enum member per operand), Convert (dec/hex/char/binary/float), equates table; read by the listing and decompiler.~~ *Done (api_minor 39).*
5. ~~**User references**: a `REFERENCE` assertion (add/delete/primary, computed jump/call targets) that discovery, xrefs and the decompiler read.~~ *Done (api_minor 39).*
6. ~~**References to a data type / struct field**: find every use of a type and field across functions.~~ *Done (api_minor 53).*
7. ~~**Hover popups**: reference preview, data type, scalar values, function signature on hover in listing and decompiler.~~ *Done: [ui.md](ui.md#hover-cards).*
8. ~~**Rebase (set image base)** after import.~~ *Done: [memory-map.md](memory-map.md#rebase-setting-the-image-base).*
9. ~~**Container file systems**: open zip/tar/cpio/ISO/squashfs/firmware packages, import members (nested).~~ *Done (api_minor 48, [filesystems.md](filesystems.md)).*
10. ~~**Demangle ELF/PE C++ names**~~ with `src/demangle` (names and signatures in listing, functions, decompiler). *Done: [demangle.md](demangle.md).*
11. ~~**PE analyzers**: type PE headers, SEH/unwind data, RTTI class names, `__security_cookie`.~~ *Done (api_minor 45, 46, [pe.md](pe.md)).*
12. ~~**libc/library prototypes on ELF imports** (Data Archive Analyzer parity).~~ *Done: [types.md](types.md#library-prototypes).*
13. ~~**Project-wide types** shared by a project's programs (project archive).~~ *Done: [types.md](types.md#project-types).*
14. **Mach-O loader** (deferred; still the biggest format gap).

Med value:
15. Analysis options UI: per-analyzer enable/options, one-shot analyzers on a selection.
16. Address table analyzer for PE; MIPS gp / PPC TOC register assumptions; ~~format-string varargs at printf call sites~~ (*done: [types.md](types.md#format-strings)*).
17. Register values over ranges (context for MIPS16/VLE/x86 modes, constant registers).
18. Fallthrough-address override.
19. ~~Next/previous navigation (instruction, data, undefined, label, function, note)~~ (done, api_minor 44).
20. ~~Go To expressions (`sym+0x10`), wildcards, file offset~~ (done, api_minor 44).
21. ~~Overview bar (code/data/undefined) and entropy bar beside the listing~~ (done, api_minor 44).
22. ~~Listing optional fields (file offset, function offset, p-code); inline XREF field~~ (done, api_minor 44).
23. Listing background colors and selection-from-tables; make program selections from results.
24. Comment window (table of all comments).
25. ~~Copy Special (bytes as hex/C/Python, addresses)~~ (done, api_minor 44).
26. Clear With Options; Clear Flow and Repair.
27. Note types and tag filter in the Notes panel; function tag window and filter.
28. Data settings (display format, endian, charset); data type preview at cursor.
29. Quick-edit structure field from the listing; field comments and type descriptions in the editor.
30. Find types by size/offset/enum value; replace/merge types; archive sync.
31. Custom parameter storage, inline flag, function purge/stack depth.
32. External functions/locations and external program names; multiple labels and namespaces/classes.
33. Stack frame editor (or a locals view backed by decompiler storage).
34. Memory map: move/split/merge/expand, overlays.
35. Change a program's language after import.
36. Charsets beyond UTF-8/16/32.
37. Batch import; load libraries and a library search path; COFF/.o with relocation; ELF relocations applied.
38. Intel HEX export; one-step C/C++ export of the program.
39. External debug files (build-id, debuglink, debuginfod); source files and line map from `.debug_line`.
40. Instruction info window and processor manual lookup; instruction pattern and mnemonic search; direct-reference search; search and replace.
41. Symbol table view and symbol tree (imports/exports/namespaces).
42. Key binding customization for built-in commands (keymap presets for Ghidra, IDA Pro and Binary Ninja done; per-action rebinding not).
43. Comment annotations (`{@symbol}`, `{@url}`) as links.
44. ~~Console REPL (planned, Scripting Phase 4).~~ *Done (api_minor 43).*
45. ~~Compare any two functions on demand.~~ *Done (api_minor 54).*
46. Relocation table view.
47. C++ header parsing beyond the subset.

---

### Counts

Per topic: Have / Partial / Missing / In progress.

<!-- survey-summary:part1 -->
| Topic | Have | Partial | Missing | In progress |
|---|---|---|---|---|
| About | 1 | 1 | 0 | 0 |
| Annotations | 0 | 0 | 1 | 0 |
| AssemblerPlugin | 2 | 0 | 0 | 0 |
| AutoAnalysisPlugin | 13 | 5 | 4 | 0 |
| BlockModel | 1 | 0 | 1 | 0 |
| BookmarkPlugin | 3 | 1 | 1 | 0 |
| BundleManager | 1 | 1 | 0 | 0 |
| CParserPlugin | 2 | 2 | 0 | 0 |
| CallTreePlugin | 2 | 1 | 0 | 0 |
| Charsets | 0 | 0 | 1 | 0 |
| ClearPlugin | 1 | 0 | 2 | 0 |
| ClipboardPlugin | 2 | 0 | 1 | 0 |
| CodeBrowserPlugin (Listing) | 6 | 4 | 3 | 0 |
| CommentWindowPlugin | 0 | 1 | 0 | 0 |
| CommentsPlugin | 3 | 1 | 0 | 0 |
| ComputeChecksumsPlugin | 0 | 1 | 0 | 0 |
| ConsolePlugin | 0 | 1 | 0 | 0 |
| DataPlugin | 5 | 3 | 2 | 0 |
| DataTypeEditors | 4 | 0 | 3 | 0 |
| DataTypeManagerPlugin | 7 | 4 | 4 | 0 |
| DataTypePreviewPlugin | 0 | 1 | 0 | 0 |
| DataWindowPlugin | 1 | 0 | 0 | 0 |
| DbViewerPlugin | 0 | 1 | 0 | 0 |
| DefinedStringsPlugin | 1 | 0 | 1 | 0 |
| DisassembledViewPlugin | 0 | 1 | 0 | 0 |
| DisassemblerPlugin | 3 | 1 | 2 | 0 |
| DockingWindows | 0 | 1 | 0 | 0 |
| DWARFExternalDebugFilesPlugin | 0 | 0 | 1 | 0 |
| EclipseIntegration / VSCodeIntegration | 0 | 1 | 0 | 0 |
| EquatePlugin | 4 | 0 | 0 | 0 |
| ExporterPlugin | 4 | 2 | 2 | 0 |
| FallThroughPlugin | 0 | 0 | 1 | 0 |
| FileSystemBrowserPlugin | 1 | 1 | 0 | 0 |
| FlowSelection | 0 | 0 | 1 | 0 |
| FrontEndPlugin (project window) | 4 | 4 | 2 | 0 |
| FunctionComparison | 2 | 2 | 0 | 0 |
| FunctionPlugin | 5 | 6 | 4 | 0 |
| FunctionTagPlugin | 0 | 1 | 0 | 0 |
| FunctionWindowPlugin | 1 | 1 | 0 | 0 |
| GhidraScriptMgrPlugin | 2 | 1 | 1 | 0 |
| GhidraServer | 1 | 0 | 0 | 0 |
| Graph | 1 | 1 | 0 | 0 |
| HeadlessAnalyzer | 1 | 0 | 0 | 0 |
| ImporterPlugin | 7 | 3 | 3 | 0 |
| LabelMgrPlugin | 2 | 2 | 2 | 0 |
| LanguageProviderPlugin | 2 | 0 | 0 | 0 |
| LibreTranslatePlugin / TranslateStringsPlugin | 0 | 0 | 1 | 0 |
| LocationReferencesPlugin | 2 | 0 | 0 | 0 |
| MemoryMapPlugin | 4 | 1 | 3 | 0 |
| Misc (Address Expressions) | 1 | 0 | 0 | 0 |
| Navigation | 3 | 1 | 1 | 0 |
| OverviewPlugin | 2 | 0 | 0 | 0 |
| PrintingPlugin | 0 | 0 | 1 | 0 |
| ProgramManagerPlugin | 2 | 3 | 0 | 0 |
| ProgramTreePlugin | 0 | 0 | 1 | 0 |
| PropertyManagerPlugin | 0 | 0 | 1 | 0 |
| ReferencesPlugin | 3 | 0 | 3 | 0 |
| RegisterPlugin | 0 | 1 | 1 | 0 |
| RelocationTablePlugin | 0 | 0 | 1 | 0 |
| Repository (Merge Program Files) | 1 | 1 | 0 | 0 |
| ResourceActionsPlugin | 0 | 0 | 1 | 0 |
| RuntimeInfoPlugin | 0 | 2 | 0 | 0 |
| ScalarSearchPlugin | 1 | 0 | 0 | 0 |
| Search | 4 | 4 | 3 | 0 |
| SelectBlockPlugin | 0 | 0 | 1 | 0 |
| Selection | 1 | 1 | 1 | 0 |
| SetHighlightPlugin | 0 | 0 | 1 | 0 |
| ShowInstructionInfoPlugin | 0 | 1 | 1 | 0 |
| Snapshots | 0 | 1 | 0 | 0 |
| SourceFilesTablePlugin | 0 | 0 | 1 | 0 |
| StackEditor | 0 | 0 | 1 | 0 |
| SymbolTablePlugin | 1 | 2 | 0 | 0 |
| SymbolTreePlugin | 0 | 2 | 1 | 0 |
| Tool | 1 | 4 | 0 | 0 |
| ValidateProgram | 0 | 1 | 0 | 0 |
| VersionControl | 1 | 1 | 0 | 0 |
| **Total (76 topics, 271 features)** | **122** | **82** | **67** | **0** |
<!-- /survey-summary:part1 -->

## Part 2: Ghidra 12.1.4 vs revkit: every module except Base

This survey covers revkit master `d5c8c1e`; the repo was at `8d7b00c` when it was read. Its Missing, Partial and In progress rows were judged again on 2026-10-09 against `807d127`. It is read-only research.
- **Have:** revkit does it, roughly as well or better.
- **Partial:** revkit does some of it.
- **Missing:** not found in the docs, `src/`, `ui/src/`, `proto/` or `sdk/`.
- **In progress:** a branch in flight.

Value and Effort are left as "-" for Have rows. All revkit paths are relative to `~/dev/revkit`.

**Verified by hand:**
- ~~In the decompiler, Rename on a non-nameable token (a struct field, for example) falls back to renaming the function.~~ Fixed: field tokens carry their struct and offset (api_minor 38), and a token that names nothing says so.
- ~~A user-asserted prototype is always committed with convention `"default"`.~~ Fixed: the convention is the compiler spec's prototype model ([decompiler-inputs.md](decompiler-inputs.md#calling-conventions)).
- ~~Same-program function compare is refused.~~ Fixed: `CompareFunctions` compares any two functions (api_minor 54).
- ~~`docs/scripting.md` says "no Function ID databases".~~ Function ID landed (api_minor 51).

**Not covered here:** Itanium (GCC) RTTI, the Base analyzers and Base loaders. Another survey covers those.

### 1. Tables

#### Decompiler: window and actions (DecompilePlugin)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Follows listing navigation | Have | `ui/src/app.ts` `loadDecompile`; `docs/ui.md` "Decompiler-first" | - | - |
| Cross-highlighting C and listing | Have | `ui/src/decomp/pane.ts` `highlightAddress`/`onSelectAddress`; `CodeToken.address` | - | - |
| Redecompile after any annotation (incl. other users') | Have | DECOMPILE invalidation (`docs/ui.md` "Invalidation") | - | - |
| Failure and warning display | Have (better) | failure banner, Retry, Export repro (`app.ts` `showFailure`, `docs/decompd.md`) | - | - |
| Snapshot decompiler windows | Missing | one `DecompilerPane` (`ui/src/decomp/pane.ts`); no pinned or snapshot panes (only the byte viewer's Follow off pins its view) | Med | M |
| Decompile undefined function (code outside a function) | Missing | `ui/src/app.ts` still shows "is not inside a known function" for code outside a function (`showDecompileFor`) | Med | M |
| Export to C (function or program) | Partial | one function's C to the clipboard (`decomp-copy-all`, Copy function, `ui/src/app.ts`); a program's C only via the `export_functions` starter script (`docs/scripting.md`); no Export to C file action | Med | S |
| Re-decompile, Debug Function Decompilation | Partial | Retry and Export repro buttons on a failure only (`ui/src/app.ts` `retryDecompile`, `exportRepro`); no re-decompile or debug bundle for a function that decompiled | Low | S |
| Toolbar: Eliminate unreachable, Respect read-only | Missing | `DecompileOptions` (`proto/revkit/v1/decompile.proto`) still has only `include_text`, `timeout_ms`, `escalate`, `include_bundle` | Med | M |
| Copy selected C | Have | drag, Shift+click, double and triple click select; `Ctrl+C` copies the selection or the token, Copy and Copy function in the right-click menu (`decomp-copy`, `decomp-copy-all`; `ui/src/decomp/pane.ts` `copyText`; `docs/ui.md` "Copying from the decompiler") | - | - |
| Graph data flow / control flow from the decompiler | Partial | the high p-code data-flow graph is exposed (`DecompileOptions.include_dataflow`: `DecompiledFunction.dataflow` nodes and ops; api_minor 57) and walked by `SliceDecompiled`; no graph view of it | Low | M |
| Token highlight, brace matching, next/previous brace | Partial | same-identity tokens marked (`ui/src/decomp/pane.ts` `paintMarks`, `selMark`); no brace pairing or next/previous brace | Low | S |
| Double-click navigation | Partial | double click follows FUNCTION_NAME and GLOBAL_VARIABLE targets (`ui/src/decomp/pane.ts` `followAt`); a constant that is an address only gets a hover card, goto labels don't follow | Med | S |
| Highlight all, next/previous highlight | Partial | matching identifiers marked (`pane.ts` `paintMarks`); no next/previous highlight | Med | S |
| Secondary (persistent, colored) highlights | Missing | no persistent or coloured highlights in `ui/src/decomp/pane.ts` | Med | S |
| Find in the decompiler (text/regex) | Have | Search: decompiled code with the "current function" scope (`ui/src/ui/search.ts`, `search-decompiled`; `SearchDecompiled` regex, case, whole word in `proto/revkit/v1/query.proto`): the match is marked in the pane (`pane.ts` `revealLine`) and F3/Shift+F3 step through results; no in-pane find bar | - | - |
| Highlight def-use | Have | Highlight ▸ Def-use (`ui/src/app.ts` `slice-def-use`), `QueryService.SliceDecompiled` `SLICE_KIND_DEF_USE` over `DecompiledFunction.dataflow` (api_minor 57, `docs/api.md` Slices) | - | - |
| Forward/backward slice, operator slices | Have | Highlight ▸ Forward, Backward, Forward and Backward operator slice, mirrored to the listing, Ctrl+. and Ctrl+, through them (`ui/src/app.ts` `sliceCommands`, `src/backend/slice.cc`; api_minor 57); `Program.slice` and the `slice_decompiled` MCP tool | - | - |
| Comments from a token | Have | `app.ts` `commentSpec` | - | - |
| Rename local / parameter | Have | `renameSpec` by `storageKey` | - | - |
| Retype local / parameter (committed, locked) | Have | `docs/decompiler-inputs.md#variable-types` | - | - |
| Rename / retype global | Have | `renameSpec`/`retypeSpec` address target | - | - |
| Rename function into a namespace (`a::b`) | Partial | rename works, but a user rename's `a::b` stays text (namespaces are split only for demangled names: `src/inputs/assemble.cc` `demangled`; `docs/ghidra-interop.md` Namespaces flatten to `ns::name`) | Med | M |
| Rename / remove label from the decompiler | Missing | LABEL tokens still not nameable (`ui/src/decomp/pane.ts` `nameable`); the listing can rename labels | Low | S |
| Rename field | Have | Rename field (`rename-field`, `ui/src/app.ts` `renameField`): FIELD tokens carry `parent_type_hash` and `field_offset` (api_minor 38, feature `field-tokens`); edits the struct in one undo step (`docs/ui.md` "Struct fields in the decompiler"); the fall-back-to-function bug is fixed | - | - |
| Retype field | Have | Retype field (`retype-field`, `ui/src/app.ts` `retypeField`) by the token's struct hash and offset (api_minor 38; `docs/ui.md` "Struct fields in the decompiler") | - | - |
| Retype return | Have | prototype as C (`y`); `applyReturnType` | - | - |
| Edit function signature | Have | the Edit Function dialog (`F`; `ui/src/ui/editfunction.ts`): name, return, parameters, varargs, a calling-convention dropdown from the compiler spec (`ListCallingConventions`, api_minor 58) and No return (`SetNoReturn`, api_minor 66), or the prototype as C via ParseC; the convention reaches the decompiler as the spec's model (`docs/decompiler-inputs.md#calling-conventions`); no custom storage or inline | - | - |
| Commit params/return | Partial | `y` prefilled from the decompiler's declaration; Param ID commits during analysis (`docs/param-id.md`); no Commit Params/Return action | Med | S |
| Commit local names | Missing | no bulk commit of local names in `ui/src/app.ts` commands | Low | S |
| Override signature at a call site | Have | Override signature (this call), Edit signature override, Remove signature override (`callsig-override`, `callsig-edit`, `callsig-remove` in `ui/src/app.ts`; `CallSignatureOverride`, api_minor 53, feature `call-signature-override`; `docs/ui.md` "Signature overrides", `docs/decompiler-inputs.md#call-site-signature-overrides`) | - | - |
| Convert constant (bin/dec/hex/oct/char) | Have | Convert scalar to hex, decimal, octal, binary, char, float and back on a decompiler constant (`conv-*` commands, `ui/src/app.ts`; `EQUATE` assertion / `OperandDisplay` with `CodeToken.constant_hash`, api_minor 39, feature `equates`; `docs/ui.md` "Equates and references") | - | - |
| Set / remove equate | Have | Set equate (`E`) with enum suggestions and Remove equate on a decompiler constant (`eq-set`, `eq-remove`, `ui/src/ui/equates.ts`), the Equates window; read by the listing and the decompiler (api_minor 39; `docs/api.md#equates-and-user-references`) | - | - |
| Force union field | Missing | not found in `ui/src/app.ts`, `proto/revkit/v1/assertion.proto` or docs (still on `docs/wishlist.md`) | Med | M |
| Adjust pointer offset (offset-pointer typedef) | Missing | no offset attribute on pointers in `proto/revkit/v1/types.proto` (still on `docs/wishlist.md`) | Med | M |
| Auto create / fill in structure | Have | `ui/src/ui/autostruct.ts`, `TypeService.AutoStructure` | - | - |
| Edit data type from a type token | Partial | TYPE tokens have a hover card with the definition (`ui/src/ui/hover.ts`) and Find uses of type; no Edit data type action from the token (the type editor is `ui/src/ui/types.ts`) | Med | S |
| Split out as new variable / merge | Missing | not found (still on `docs/wishlist.md`) | Med | M |
| Find uses of a data type | Have | Find uses of type and Find uses of field from decompiler tokens and the Types window (`ui/src/app.ts` `findUses`, `ui/src/ui/search.ts` `Search.findUses`; `FindTypeUses`, api_minor 53, feature `type-uses`; `docs/ui.md` "Find uses") | - | - |
| Find references to function or global | Have | `x` (`app.ts:1731`) | - | - |
| References to other tokens' addresses | Partial | references to a function, a callee or a global (`ui/src/app.ts` `xrefs`); fields and types via Find uses; a local, a constant or other token still falls back to the function entry | Low | S |
| Back / forward / go to | Have | Alt+Left/Right, Ctrl+K | - | - |

#### Decompiler: options and annotations

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Decompiler timeout | Partial | `DecompileOptions.timeout_ms`, `escalate` in the API; no settings UI (`ui/src/ui/preferences.ts` has the keymap only) | Low | S |
| Cache | Have | memoized per input-bundle hash (`docs/decompd.md`) | - | - |
| Max instructions, jump-table entries, payload | Missing | not in `DecompileOptions` (`proto/revkit/v1/decompile.proto`) | Low | S |
| Eliminate unreachable code (option) | Missing | internal only (Param ID mode); not in `DecompileOptions` | Med | M |
| Respect read-only flags | Partial | const/volatile from the Data menu reach the decompiler (`docs/listing-edit.md`, `SetMutability`); no toggle | Med | S |
| Alias blocking, split accesses, in-place operators | Missing | not exposed in `DecompileOptions` | Low | M |
| Constant pointers, for-loops, predication, bitfields, NaN, extended precision | Missing | not exposed in `DecompileOptions` | Low | M |
| Disable printing of casts | Missing | not found in `DecompileOptions` or the UI | Med | S |
| Integer format (hex, decimal, best fit) | Missing | no program-wide integer format option; only per-constant Convert (`conv-*`, api_minor 39) | Med | S |
| Token colors, background, font | Partial | dark/light themes; no per-token colour or font settings | Low | S |
| Brace style, indent, line width, line numbers | Missing | fixed 2-space indent (`ui/src/decomp/pane.ts`); no line numbers or style options | Low | S |
| Which comment kinds print | Partial | the decompiler prints the comments it is given (`docs/decompiler-inputs.md` `comments`); no per-kind toggles | Low | S |
| Namespaces, NULL, calling convention printing | Missing | no printing options; namespaces are printed minimally qualified as Ghidra's default (`docs/demangle.md`), not configurable | Low | S |
| Spec extensions (user prototypes, callfixup, callotherfixup) | Missing | spec built-ins only (`src/lift/abi.cc`); no user callfixup or callotherfixup | Med | L |
| Forced data types (committed annotations) | Have | assertions become decompiler inputs (`docs/decompiler-inputs.md`) | - | - |
| Calling convention honored for user prototypes | Have | an asserted prototype's convention is the compiler spec's prototype model, locked, with its storage and extrapop; an unknown one falls back to the default with a warning (`src/backend/own_inputs.cc` `QueryLookup::prototype_from`; `docs/decompiler-inputs.md#calling-conventions`) | - | - |
| Custom variable storage | Missing | "Custom variable storage isn't exported" (`docs/ghidra-interop.md`); no storage assertion in `assertion.proto` | Med | L |
| User no-return / inline flags | Partial | no-return: `SetNoReturn` (api_minor 66, feature `no-return`), set or cleared, steers discovery, flow and the decompiler (`docs/decompiler-inputs.md#no-return`); Set/Clear no return in the listing, decompiler and function list menus, the Edit Function dialog, SDK `set_no_return`, MCP `set_no_return`; no inline flag | Low | S |
| Read-only / volatile memory | Have | `SetMutability` assertion | - | - |
| Flow overrides | Have | `o` → `FlowOverride` assertion | - | - |

#### DecompilerDependent (Decompiler Text Finder, Taint)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Search decompiled text (all functions, regex, results table) | Have | Search: decompiled code (`ui/src/ui/search.ts`; `SearchDecompiled` in `proto/revkit/v1/query.proto`, api_minor 41): every function, the selection's or the current one; regex, case, whole word; streaming results table (Function, Line, Text, Address) with sort, filter, Copy CSV; `docs/ui.md` "Search" | - | - |
| Select functions from results | Partial | the results' Make selection selects the matched lines' addresses (`docs/ui.md` "Search"), not the functions' bodies | Low | S |
| Taint: mark source, sink, gate; clear | Missing | no taint in `src/`, `proto/`, `ui/src/` or docs | Med | L |
| Taint: export p-code facts, run queries | Missing | not found; `find_format_string_sinks` starter script is one fixed pattern (`docs/scripting.md`) | Med | L |
| Taint: slice tree viewer | Missing | not found | Low | M |
| Taint: load SARIF, apply highlights | Missing | no SARIF import (`docs/wishlist.md` lists it) | Low | M |

#### FunctionGraph and Graph (VisualGraph)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Block graph with instructions | Have | `ui/src/graph/cfg.ts`, `GetFunctionGraph` | - | - |
| Toggle listing / graph in place | Have | Space | - | - |
| Selection sync with listing and decompiler | Have | `cfg.ts` `onSelect` | - | - |
| Pan, zoom, fit, 1:1 | Have | `cfg.ts`; keys 0, 1, +, - | - | - |
| Satellite view | Have | minimap `m` (not undockable) | - | - |
| Level-of-detail painting | Have | bars below 6 px/line (`docs/ui.md` Phase 5) | - | - |
| Edge colors by flow kind | Have (better) | switch edges labelled with cases | - | - |
| Refresh after edit without relayout | Have | layout reuse | - | - |
| Graph of an undefined function | Missing | `GetFunctionGraph` needs a function | Low | M |
| Multi-select, rubber band, drag vertices | Missing | single selection in `ui/src/graph/cfg.ts` | Low | M |
| Hover popups (block, edge previews) | Missing | hover outlines only (`cfg.ts` `hoverBlock`); hover cards are listing and decompiler only (`docs/ui.md` "Hover cards") | Med | S |
| Select / follow edges | Missing | hit-testing blocks only (`cfg.ts`) | Low | S |
| Vertex background colors (shared with listing) | Missing | not found | Med | M |
| Group / ungroup any selection with text | Partial | dominance groups and collapse only (`cfg.ts` `foldSelected`) | Med | M |
| Graph state saved (colors, groups, zoom) | Missing | folds last for the tab's life (`docs/ui.md` Known gaps (phase 5)) | Low | S |
| Path highlights (scoped flow, paths to/from, loops) | Missing | not found | Med | M |
| Layouts: nested code (FunctionGraphDecompilerExtension), flow chart | Partial | ELK layered only (`ui/src/graph/elk.ts`) | Med | M |
| Graph options (relayout, wheel, animation, condensed) | Missing | minimap pref only | Low | S |
| Program selection from blocks or paths | Missing | not found | Low | S |
| Graph snapshot | Missing | one graph view | Low | M |

#### GraphFunctionCalls (Function Call Graph)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Callers and callees by level | Partial | `ui/src/ui/calls.ts`: two expandable trees, not a graph | Med | M |
| Show/hide a node's incoming/outgoing calls | Have | per-node expansion | - | - |
| Level and cross-level edges, layouts | Missing | not possible in a tree | Low | M |
| Re-root on a function | Have | Enter on a row | - | - |
| Toggle "follow location changes" | Partial | always follows; no toggle (`ui/src/ui/calls.ts`) | Low | S |

#### GraphServices, ProgramGraph, DataGraph

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| General graph display (layouts, shapes by type, lens) | Missing | not found | Low | L |
| Graph filters, hide, grow selection, subgraph | Missing | not found | Low | M |
| Collapse / expand vertices | Partial | function graph only | Low | - |
| Graph export (DOT, GraphML, GML, JSON, CSV) | Partial | the `export_call_graph` starter script writes the call graph (whole program or from a root to a depth) as Graphviz DOT or JSON (`docs/scripting.md` starter scripts); no export of the function graph, no GraphML, GML or CSV, no export action in a graph view | Med | S |
| Code-flow graph of a function | Have | function graph | - | - |
| Block flow over a selection or whole program | Missing | per function only | Low | M |
| Call graph of a selection / whole program | Missing | calls view is per function; no display of a program's call graph (only the `export_call_graph` script's DOT/JSON) | Med | M |
| Data-reference graph (to/from, depth) | Missing | references dialog only (`ui/src/ui/xrefs.ts`) | Med | M |
| Reuse / append graph, show location | Missing | not found | Low | S |
| Data Graph: data items as vertices, expand fields, follow pointers | Missing | not found | Med | M |
| Data Graph: navigation options, original source | Missing | not found | Low | S |

#### ByteViewer

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Byte viewer synced to the listing | Have | the Bytes view, cursor and selection both ways (`ui/src/bytes/viewer.ts`, `QueryService.GetByteView`) | High | |
| Chars view with charset (ASCII, UTF-8, UTF-16) | Partial | ASCII and UTF-16 columns (`ui/src/bytes/viewer.ts` `COLUMNS`); no UTF-8 or other charsets | Med | S |
| Bytes per line, alignment offset, group size | Partial | auto, 8, 16 or 32 a line, groups of 1/2/4/8 (`ui/src/bytes/viewer.ts`); no alignment offset | Low | S |
| Multi-byte formats (short/int/long, octal, binary) | Have | octal, binary, and signed integers by group size in the program's byte order (`ui/src/bytes/viewer.ts`) | Low | |
| Address view | Missing | no column that reads groups as addresses (`ui/src/bytes/viewer.ts` columns: hex, ASCII, octal, binary, UTF-16, int) | Med | S |
| Disassembled view (defined vs undefined) | Have | code, data, undefined and uninitialized bytes tinted, the cursor's code unit underlined (`ui/src/bytes/viewer.ts`) | Low | |
| Edit bytes in hex or chars | Have | Edit in the Bytes view: typed hex or characters as patches, one undo step per edit session (`ui/src/bytes/viewer.ts`) | High | |
| Changed bytes highlighted | Have | patched rows tinted (`docs/ui.md` Patching) | - | - |
| Undo/redo byte edits | Have | undo stack, Patches view Revert | - | - |
| Block boundaries, colors, font options | Partial | the viewer exists: lines skip block gaps and the status line names the block (`ui/src/bytes/viewer.ts`), colours follow the theme (`ui/src/bytes/bytes.css`); no block separators, colour or font options | Low | S |
| Custom formats (plugins) | Missing | fixed columns in `ui/src/bytes/viewer.ts`; plugins are analyzers, commands, loaders, peripherals (`docs/plugins.md`) | Low | M |

#### VersionTracking: sessions, correlators

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Create session (source, destination) | Have | Compare programs dialog (`ui/src/diff/view.ts`); `CreateDiffSession` (`proto/revkit/v1/diff.proto`) | - | - |
| Swap source/destination | Missing | no swap in the Compare programs dialog (`ui/src/diff/view.ts`); Swap exists only for two compared functions | Low | S |
| Session saved and reopened | Have | NOTE assertion (`src/backend/diff_session.cc`, `ListDiffSessions`); run state not persisted (`docs/diff.md` Known gaps) | - | - |
| Rename / delete session | Missing | not in UI or proto (`docs/ui.md` Known gaps (Compare)) | Low | S |
| Add to session (run more correlators later) | Partial | re-run incremental; only `DiffOptions.similarity_tiers` selectable (`proto/revkit/v1/diff.proto`) | Med | M |
| Limit correlation to a selection/range | Missing | no range in `DiffOptions` | Med | S |
| Precondition validators (blocks, counts, % analyzed) | Missing | not found | Med | S |
| Exact Symbol Name Match | Have | F0 name tier (`src/diff/features.cc`, `match.cc`) | - | - |
| Duplicate Exact Symbol Name (1:N) | Missing | ties left unmatched (reason TIE) | Low | S |
| Similar Symbol Name Match | Missing | not found (`docs/wishlist.md` "a similar-name tier") | Med | S |
| Exact Function Bytes Match | Have | F1 masked bytes, `DIFF_TIER_BYTES` | - | - |
| Exact Function Instructions (operand-masked) | Have | F2 p-code tier, `DIFF_TIER_PCODE` | - | - |
| Exact Function Mnemonics | Have | covered by F2/F3 (`docs/diff.md` Matching) | - | - |
| Duplicate Function Instructions (M:N) | Partial | address-order tier between matched neighbours; other duplicates stay ties | Med | S |
| Exact / Duplicate Data Match | Missing | functions only; data used for propagation | Med | M |
| Similar Data Match | Missing | not found | Low | M |
| Function/Data/Combined Reference correlators | Have | callee, caller, string, data propagation and F4 refs tier (`docs/diff.md`) | - | - |
| Implied matches | Have | propagation (`DIFF_RELATION_CALLEE/CALLER`) | - | - |
| Manual match | Have | m / u / a / r and a row's menu in Compare; `SetMatch`, `Unmatch` (api_minor 54) | High | S |
| Legacy import correlator | Missing | not found | Low | S |
| BinDiff-style extras (MD index, call order, calibrated confidence) | Have (beyond Ghidra) | F3, call-order tier, `DIFF_CHANGE_KIND_UNCHANGED` (`docs/diff.md`) | - | - |
| Auto Version Tracking | Have | `ApplyMarkup{min_confidence}`, `rk.diff(...).apply()`, `tools/rk-diff` | - | - |
| AutoVT tuning options | Partial | threshold, policy, items only; tier thresholds fixed in `src/diff/match.cc` | Low | S |
| Scripted/headless VT | Have | `sdk/python/revkit/diff.py`, MCP `compare_programs`/`diff_*`, `rk-diff` | - | - |

#### VersionTracking: match table, markup, apply

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Matches table (sort, score, confidence, status) | Have | `ui/src/diff/view.ts`, `ListMatches` (`DiffSort`) | - | - |
| Match filters (text, confidence, status, type) | Have | `DiffMatchFilter` | - | - |
| Length / per-column filters | Missing | not in `DiffMatchFilter` (`proto/revkit/v1/diff.proto`) | Low | S |
| Accept match | Have | `a`, `AcceptMatches` | - | - |
| Reject match | Have | `r`, `RejectMatches` | - | - |
| Apply blocked match (clear conflicts) | Have | Match with... (`m`, a row's menu, the candidates' buttons in Only in A/B) calls `SetMatch`, which retracts the accepted matches either function takes part in and accepts the pair (`ui/src/diff/view.ts`; `docs/ui.md` "Manual matching", api_minor 54); markup applies as a separate step | - | - |
| Clear / reset match (unapply) | Have | `RevertApply`, retraction via `depends_on`, Ctrl+Z | - | - |
| Match tags | Missing | not found | Med | S |
| Make selection in source/destination | Missing | not found | Low | S |
| Compare functions from the match table | Have | listing, graph, C panes (`ui/src/diff/{aligned,graph,decomp}.ts`) | - | - |
| Unmatched lists with candidates and reasons | Have (beyond Ghidra) | `ListUnmatched` (TIE, WEAK, NO_CANDIDATE) | - | - |
| Per-match evidence, "what changed" summary | Have (beyond Ghidra) | `DiffEvidence.detail`, `SummarizeFunctionDiffs` | - | - |
| Markup items table (per item, values, status) | Partial | per-item apply from the C pane's tokens (name, signature, a variable's name or type, a comment) and `PortFunctionMarkup` dry runs listing each item with before and after (`proto/revkit/v1/diff.proto` `PortedMarkup`, api_minor 54); the session's Apply dialog shows counts only; no markup items table with status | Med | M |
| Markup item status (don't care / don't know / reject) | Missing | not found | Low | S |
| Edit a markup item's destination | Missing | not found | Low | S |
| Port function name (replace default only) | Have | `DIFF_MARKUP_ITEM_NAMES`, over `FUN_` names | - | - |
| Name policies add / add as primary / replace always | Missing | never over an asserted name, by design (`DIFF_APPLY_POLICY_*`) | Low | S |
| Port labels at non-entry addresses | Missing | function name only | Med | M |
| Port function signature with types | Have | `DIFF_MARKUP_ITEM_PROTOTYPES`, type closure by hash | - | - |
| Signature sub-options | Partial | session apply ports the whole prototype under one policy; `PortFunctionMarkup` separates signature, each variable's name and type, and comments (api_minor 54); no return-type, convention or flag sub-options | Low | S |
| Port comments (all kinds, per instruction) | Have | by the instruction map for modified pairs (api_minor 54; `docs/diff.md`) | High | M |
| Port data types for data matches | Missing | no data matches | Med | M |
| Accept options (apply on accept, implied matches) | Partial | implied automatic; apply is a separate step | Low | S |
| Implied matches table (votes, conflicts) | Partial | parent pair in evidence; no table | Low | M |
| Related matches for the function at the cursor | Partial | `GetFunctionDiff` with one entry; no panel in the code view | Med | S |
| Functions table: pick two and match | Have | Only in A/B rows' candidate buttons match a row with one, and `m` (Match with...) picks the other side's function by name, candidates first (`ui/src/diff/view.ts`, `SetMatch`; `docs/ui.md` "Manual matching", api_minor 54) | - | - |
| Stale-port detection | Missing | no stale detection (`docs/diff.md` Known gaps) | Med | M |

#### VersionTrackingBSim

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| BSim correlator (feature vectors, seeds, call-graph extension) | Have | `bsim` tier (`src/diff/residue.cc`, `src/backend/signatures.cc`, `docs/diff.md` F5) | - | - |
| Seed / match thresholds as options | Partial | fixed in `src/diff/residue.cc` | Low | S |
| Accepted matches as seeds | Have | accepted pairs seed refinement | - | - |
| Memory model (small/medium/large) | Missing | n/a: prefilter top-16 above 25M pairs | Low | - |

#### BSim: signatures, database, command line

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Signature generation | Have | `src/decompd/signature.cc`, `diff.signature` query | - | - |
| Headless signature generation | Have | `rk-lift --signatures FILE` (`tools/rk-lift/main.cc`) | - | - |
| Weights, idf, cosine, significance (bit-exact) | Have | `src/diff/lsh.cc`, `third_party/bsim`, `lsh_test` | - | - |
| Weight tables (32/64/nosize) | Have | `weights_for`, `rk-sigdiff --weights` | - | - |
| Offline signature comparison | Have | `tools/rk-sigdiff` | - | - |
| Database backends (H2 file, PostgreSQL, Elasticsearch) | Partial | revkit's own file store (`src/bsim`, `docs/bsim.md`): a directory per database, one file per executable; no H2, PostgreSQL or Elasticsearch | Low | L |
| `createdatabase` with templates | Have | `rk-bsim create --template 64\|32\|nosize`, `CreateBSimDatabase` (`docs/bsim.md`) | - | - |
| Ingest executables (`commitsigs`, updates) | Have | `rk-bsim ingest`, `IngestBSim` (signs and stores; the same file again replaces it) | - | - |
| LSH index (rebuild, drop, prewarm) | Partial | SimHash buckets stored per function at ingest, the index built at open (`docs/bsim.md#the-lsh-index`); no drop or prewarm commands | Low | S |
| Executable categories, function tags | Partial | categories (`--category`, `UpdateBSimExecutable`); no function tags | Med | S |
| Listing/maintenance commands (listexes, listfuncs, delete, metadata) | Have | `rk-bsim info/list/functions/set/delete`, `ListBSimExecutables`, `ListBSimFunctions`, `UpdateBSimExecutable`, `DeleteBSimExecutables` | - | - |
| DB users, auth, PKI | Partial | through the daemon's roles (`BSimService` policies, `docs/security.md`); the files have no users of their own | Low | M |
| Decompile failure flags | Have | `decompd::FunctionSignature` flags (`docs/decompd.md`) | - | - |

#### BSimSearchPlugin

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Manage BSim servers | Have | a project's databases (`CreateBSimDatabase`, `AttachBSimDatabase`, `DetachBSimDatabase`, `ListBSimDatabases`); the BSim view's Databases… (`docs/ui.md#bsim`) | - | - |
| Similar function search (cursor/selection vs DB) | Have | `SearchBSim` (api_minor 72), the BSim view and Find similar functions (BSim) in the listing, decompiler and function list menus, `rk-bsim query`, SDK, MCP `bsim_search` (`docs/bsim.md#searching`) | - | - |
| Thresholds (similarity, confidence, max matches) | Have | `SearchBSim` min_similarity, min_confidence, max_matches; the BSim view's options | - | - |
| Search filters (exe, arch, compiler, calls, date, tags) | Partial | executables, languages, function name, categories, analysis names (`SearchBSim`); no compiler, call-count, date or tag filters | Med | S |
| Overview query (hit counts, self-significance) | Have | `SearchBSim` overview, the BSim view's Overview, MCP `bsim_overview` | - | - |
| Results table | Have | the BSim view (`ui/src/ui/bsim.ts`): function, similarity, confidence, match, executable | - | - |
| Executable match summary | Missing | not found | Med | S |
| Apply name / signature / signature+types from a hit | Missing | no hits to apply from; `PortFunctionMarkup` (api_minor 54) ports between two chosen functions | High | S |
| Compare functions from a hit, load executable | Partial | a hit whose file is a program of the project opens side by side in Compare (`BSimMatch.program_id`); no loading of an executable that isn't | Med | S |
| Post-search filters, search info | Missing | not found | Low | S |

#### BSimFeatureVisualizer

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Feature table for the current function | Partial | per-block feature attribution in the engine (`docs/decompd.md` signatures, `debugSignature`); no API or UI | Low | M |
| Feature graph and decompiler highlights | Missing | not found | Low | M |

#### ProgramDiff

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Open a second program as an address-aligned Diff view | Missing | revkit's diff is function matching | Med | M |
| Diff against an earlier version | Partial | reads at a pinned revision, `GetHistory`, `Blame`; no program-wide view (`docs/wishlist.md` "version history in the UI") | Med | M |
| Diff categories (bytes, code units, labels, refs, comments, functions, equates, bookmarks, context) | Partial | bytes: Patches "Compare with original" (`ui/src/patch/patch.ts`); functions: Compare; others not | Med | M |
| Limit Diff to a selection | Missing | not found | Low | S |
| Next/previous difference program-wide, marker margin | Partial | n/p inside a function pair only | Med | S |
| Diff details at a location | Missing | not found | Low | S |
| Apply differences (ignore, replace, merge) per category | Missing | function-level ApplyMarkup and PortFunctionMarkup only | Med | M |
| Apply-settings presets | Missing | not found | Low | S |

#### FunctionID

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Function ID analyzer (hash lookup, library names) | Have | the `function-id` analyzer (`src/fid`, `src/backend/fid.cc`; [fid.md](fid.md)) | - | - |
| Full and specific hashes | Have | Ghidra's bit for bit (`src/fid/hash.cc`, `src/lift/fid_insn.cc`) | - | - |
| Parent/child disambiguation | Have | superior/inferior relations in scoring (`src/fid/match.cc`) | - | - |
| Scoring thresholds, bookmarks, always-apply labels | Partial | Ghidra's thresholds and naming; plate comments; no bookmarks or always-apply option (`docs/fid.md`) | Low | S |
| Library metadata (name, version, variant) | Have | `FidLibrary`, plate comments, the Function ID window | - | - |
| Shipped databases (MSVC x86/x64 libs) | Have | Ghidra's `.fidbf` files, builtin under the Ghidra root | - | - |
| Create, attach, detach, choose FidDbs | Have | `CreateFidDatabase`, `Attach/DetachFidDatabase` (user, project), the Databases dialog | - | - |
| Populate FidDb from programs | Have | `rk-fid create`, `CreateFidDatabase` (`src/fid/create.cc`) | - | - |
| Debug search window, mitigation flags | Missing | Ghidra's FidDebug views not ported (`docs/fid.md`) | Low | M |
| Read Ghidra's `.fidbf` files | Have | `src/fid/db.cc` (raw `.fidbf`; packed `.fidb` must be saved raw) | - | - |

#### BytePatterns (Function Bit Patterns Explorer)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Use function-start patterns in analysis | Have | `src/analysis/patterns.cc` reads Ghidra's `data/patterns` | - | - |
| Gather first/pre/return bytes with context | Missing | not found | Low | M |
| Byte/instruction-sequence trees with filters | Missing | not found | Low | M |
| Alignment tab | Missing | not found | Low | S |
| Pattern clipboard, evaluate, export pattern XML | Missing | not found | Low | M |
| Mine sequential patterns | Missing | not found | Low | M |

#### CodeCompare (Function Comparison window)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Side-by-side listing with differences | Have (beyond Ghidra) | `ui/src/diff/aligned.ts`: changed, inserted, deleted, moved rows, token LCS | - | - |
| Listing diff settings (ignore bytes, constants, registers) | Partial | built-in `exact` vs `kind` tokens (`src/diff/correlate.cc`); no toggles in `ui/src/diff/aligned.ts` | Low | S |
| Side-by-side function graph diff | Have (beyond Ghidra) | `ui/src/diff/graph.ts` | - | - |
| Side-by-side decompiler diff | Have | lines aligned by LCS with variables abstracted; variables paired across (`ui/src/diff/decomp.ts`, api_minor 54) | High | M |
| Decompiler token matching and colouring | Partial | variables paired and underlined where named differently (`ui/src/diff/decomp.ts`); other tokens not matched | Med | M |
| Toggle exact constant matching | Missing | not found | Low | S |
| Synchronized scrolling | Have | one scroll container (`docs/ui.md` Compare) | - | - |
| Next/previous difference | Have | n/p (`ui/src/app.ts:2676`) | - | - |
| Compare any two functions (incl. same program) | Have | `CompareFunctions` (api_minor 54), Compare with… from the listing, decompiler and function list | High | S |
| Compare more than two functions | Missing | two at a time (`docs/ui.md` Known gaps (Compare)) | Med | M |
| Compare matching callees | Missing | no comparing callees from a call row (`docs/diff.md` Comparing two functions, Gaps) | Med | S |
| Apply name / signature from the other function | Have | the C pane's token menu, Apply all, `PortFunctionMarkup` (api_minor 54) | Med | S |
| Apply local/global names, variable types, callee signatures from matched tokens | Have | local and parameter names and types, comments (api_minor 54); globals' names and types and callees' names and signatures, paired by aligned references and calls (api_minor 71, feature `port-globals-callees`), from the Compare C pane's tokens and Apply all ([diff.md](diff.md#comparing-two-functions)) | - | - |
| Hover popups, find, split toggles | Missing | not found in `ui/src/diff/aligned.ts`, `decomp.ts` | Low | S |

#### Debugger: targets, agents, connections (Debugger-agent-gdb/lldb/dbgeng/drgn/x64dbg, Debugger-jpda, Debugger-rmi-trace)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| GDB: launch locally | Have | gdbserver over a socketpair, `src/debug/launch.cc`; `rk-dbg --launch`; UI "Launch locally" | - | - |
| GDB: attach to PID | Have | `DebugLaunchTarget.attach_pid`, `rk-dbg --attach` (`src/debug/gdb_remote.cc`) | - | - |
| GDB: remote stub (gdbserver, OpenOCD, J-Link) | Have | `src/debug/rsp.cc`, `gdb_remote.cc`, `DebugRemoteTarget`; extended mode `vAttach` | - | - |
| GDB: QEMU user-mode | Have | `launch()` runs `qemu-<arch> -g`; `DebugLaunchTarget.qemu` | - | - |
| GDB: QEMU system | Have | `launch_qemu_system()`, `rk-dbg --qemu-system` | - | - |
| gdbserver via SSH launcher | Partial | connect to a hand-started gdbserver's host:port; no SSH launch (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | M |
| GDB + Wine (PE on Linux) | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | M |
| rr record/replay, reverse execution | Missing | not found; no `bs`/`bc` reverse packets (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | M |
| Core dump debugging (gdb core, drgn core) | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | M |
| drgn: live Linux kernel | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | L |
| LLDB local (macOS) / remote | Missing | not found; lldb gdb-remote dialect untested (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | M |
| LLDB Android (lldb-server) | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | M |
| LLDB macOS kernel | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | L |
| dbgeng (WinDbg) local, attach, extended | Missing | not found; no Windows host support (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | High | L |
| dbgeng remote / process server | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | L |
| dbgeng Windows kernel (kd), EXDI | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | L |
| dbgeng TTD trace import | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | L |
| x64dbg local / attach | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | L |
| JPDA (Java: launch, JDWP, by PID) | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | L |
| Trace RMI: outside agents stream traces in | Missing | not found; agents are built in only (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | L |
| Connections: outbound / accept / server | Partial | outbound RSP only (`DebugRemoteTarget`) (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | M |
| Launcher dialog (args, env, image, arch) | Partial | API has args, env, qemu (`DebugLaunchTarget`); UI has args only (`ui/src/debug/panel.ts:348`) (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | S |
| Launcher terminal (stdin/stdout) | Partial | output shown (`DebugState.output`); no stdin for launched processes (`WriteDebugInput` is UART only) (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | S |
| Non-stop mode, stop on library load | Missing | all-stop only (`docs/debugger.md` "Limits") (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | M |

#### Debugger: control, console, platform, model (DebuggerControlPlugin, DebuggerConsolePlugin, DebuggerPlatformPlugin, DebuggerModelPlugin)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Resume / interrupt | Have | `ResumeDebugSession`, `InterruptDebugSession`; UI F9, Pause; `rk-dbg c`, `interrupt` | - | - |
| Step into / over / out | Have | `DebugRunMode`; over/out built for single-step targets (`src/debug/session.cc`); F7, F8, Shift+F8 | - | - |
| Run to address | Have | `ResumeDebugSessionRequest.until`, `rk-dbg until`; no UI "run to cursor" | Med | - |
| Step extended / repeat last | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | S |
| Kill / detach | Have | `CloseDebugSession.kill`; `rk-dbg kill`, `detach`; UI close | - | - |
| Control mode: target vs trace vs emulator | Have | target (a live session: runs, edits go to the process), trace (a recording or saved trace: read-only, any snapshot), emulator from either (Emulate: the stop's or a snapshot's state, memory read lazily, what-if without touching the target, closing returns to it; api_minor 67) and the emulator's own rewind (api_minor 65); one view switches between them ([debugger.md](debugger.md#emulating-from-a-stop)); unlike Ghidra, edits made in trace mode aren't kept as trace patches | - | - |
| Edits to a trace | Missing | saved traces read-only (`TraceTarget`) (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | M |
| Emulator edits as patch steps in a schedule | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | L |
| Several traces/targets open at once | Partial | API 8 sessions per client; UI one session (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | M |
| Console (log with actionable messages) | Partial | UI notifications, `rk-dbg` output; no console (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | S |
| Raw debugger / monitor commands | Partial | `qRcmd` via `rk-dbg monitor`; not in API or UI (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | S |
| Platform selection (language override per session) | Partial | registers mapped to the program's SLEIGH language (`gdb_remote.cc`); `--lang` for raw (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | M |
| Model object tree (objects, elements, attributes) | Missing | fixed target model (`src/debug/target.hh`) (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | M |

#### Debugger: breakpoints (DebuggerBreakpointsPlugin, DebuggerBreakpointMarkerPlugin)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Toggle breakpoint in listing | Have | gutter click (`ListingView.onGutterClick`), palette toggle (`ui/src/app.ts:2632`) | - | - |
| Breakpoint markers in decompiler / function graph | Partial | palette toggle (`emu-break`, `ui/src/app.ts`) works from any view; markers drawn in the listing gutter only, none in `ui/src/decomp/pane.ts` or `ui/src/graph/cfg.ts` | Med | S |
| SW / HW / read / write / access, length | Have | `DebugBreakpointKind`, `size`; `rk-dbg hbreak/watch/rwatch/awatch`; UI sets SW only | - | - |
| Watchpoints in the UI | Missing | UI adds `DebugBreakpointKind.SOFTWARE` only (`ui/src/debug/panel.ts` `create`, `toggleBreakpoint`); API and `rk-dbg watch/rwatch/awatch` have them | Med | S |
| Breakpoints table (address, module, kinds, hits, state) | Have | the Debugger view's Breakpoints box (feature `debugger-conditions`): address, condition, ignore count, hits, enabled, a failed condition marked; `rk-dbg info breakpoints` ([debugger.md](debugger.md#breakpoints)) | - | - |
| Enable / disable breakpoints | Have | `DebugBreakpointUpdate.disabled` (api_minor 64): kept, out of the target; the table's checkbox, `rk-dbg disable/enable` | - | - |
| Clear / clear all | Have | `remove_ids`, `clear`; UI "Clear breakpoints" | - | - |
| Breakpoints persisted with the program | Partial | UI set kept in memory across sessions (`DebuggerPanel.breakpoints`, `ui/src/debug/panel.ts`), not saved with the program | Med | S |
| Pending breakpoints mapped onto a module later | Have | `DebugBreakpoint.pending`, program-address mapping (`docs/debugger.md` "Addresses") | - | - |
| Conditional breakpoints (Sleigh condition) | Have | a C expression (as watches take) and an ignore count, emulator and live (api_minor 64, feature `debugger-conditions`): runs pass over hits where it doesn't hold, unrecorded; a condition that fails stops with its error; Debugger ▸ Breakpoint condition…, `rk-dbg break … if`, `condition`, `ignore`, SDK, MCP ([debugger.md](debugger.md#breakpoints)) | - | - |
| Breakpoint injection (Sleigh at the breakpoint) | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | M |
| Exception breakpoints (irq, svc...) | Have (revkit only) | `exception_breaks` (`docs/firmware-emulation.md`) | - | - |

#### Debugger: dynamic listing, memory, copy, sync (DebuggerListingPlugin, DebuggerMemoryBytesPlugin, DebuggerDisassemblerPlugin, DebuggerCopyActionsPlugin, DebuggerMemviewPlugin, DynamicStaticSynchronizationPlugin)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Static listing, graph, decompiler follow and mark the pc | Have | `CfgView.pc`, `DecompilerPane.setPc`, mapped by slide | - | - |
| Dynamic listing (runtime memory as code, incl. outside the program) | Partial | `DisassembleDebugMemory` (api_minor 62, feature `debugger-disassembly`): instructions anywhere in target memory with symbols, branch targets, pc and breakpoint marks, in the Debugger view's Disassembly box, `rk-dbg disas`, SDK, MCP ([debugger.md](debugger.md#runtime-disassembly)); not a full listing (no data units, comments, references or edits on runtime memory) | Med | L |
| Track location (PC / SP / expression) | Partial | listing tracks pc; memory view takes an address or register (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | S |
| Auto-disassemble at pc / Disassemble runtime memory | Have | the Disassembly box follows the pc out of the program; a library frame from the Stack; Debugger ▸ Disassemble runtime memory… at an address or expression ([debugger.md](debugger.md#runtime-disassembly)) | - | - |
| Read memory, auto-refresh per stop | Have | `ReadDebugMemory` | - | - |
| Dynamic bytes view | Partial | 8x16 hex+ASCII, stale/unknown marked (`ui/src/debug/panel.ts` memory box); no scrolling or formats; the Bytes view (`ui/src/bytes/viewer.ts`) shows program bytes, not target memory | Med | M |
| Edit memory in the bytes view | Partial | `WriteDebugMemory`, `rk-dbg write`, Python; the debugger's memory box is read-only, and the Bytes view's Edit patches the program (`PatchBytes`), not the target | Med | S |
| Assemble/patch instruction into target | Missing | not wired to `src/asm` (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | M |
| Patch typed data in target | Partial | raw bytes via API/CLI (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | S |
| Copy runtime memory into current program (capture unpacked code) | Have | `CopyDebugMemory` (api_minor 63, feature `debugger-copy`): a range or a mapped region as a new block at its runtime address, as patches (only what differs), or as a new program; one revision, one undo; Debugger ▸ Copy runtime memory into the program…, SDK `copy_memory`, MCP `debug_copy_memory` ([debugger.md](debugger.md#copying-runtime-memory)) | - | - |
| Copy into new program | Have | `CopyDebugMemory` mode `NEW_PROGRAM`: a raw program in the program's language based at the runtime address ([debugger.md](debugger.md#copying-runtime-memory)) | - | - |
| Export trace view | Partial | `.rktrace`/JSON (`rk-dbg save`, `SaveDebugTrace`); no memory-image export (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | S |
| Memview (regions/modules/threads over time) | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | M |
| Sync static/dynamic locations | Have | listing follows pc through the mapping | - | - |
| Sync selections static/dynamic | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | S |
| Open program for module | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | S |

#### Debugger: registers, stack, watches, hovers, threads (DebuggerRegistersPlugin, DebuggerStackPlugin, DebuggerWatchesPlugin, VariableValueHoverPlugin, DebuggerThreadsPlugin)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Registers with changed highlight | Have | `DebugRegisterValue.changed`; `panel.ts:774` | - | - |
| Edit registers | Have | double-click (`panel.ts` `editRegister`), `WriteDebugRegisters`, `rk-dbg set` | - | - |
| Choose displayed registers (FP, vector, system) | Partial | API `all_registers`, `group`; UI display set only (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | S |
| Register types (float, pointer, struct) | Missing | hex only (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | S |
| Go to address in a register | Partial | memory view accepts a register name (`ui/src/debug/panel.ts`, the memory box); no jump of the listing to it; Go To expressions (`ui/src/data/expr.ts`) know symbols, not registers | Med | S |
| Derived flags (CF, ZF...) | Have | `docs/debugger.md` "Register names" | - | - |
| Stack view / unwind (frames, return addresses) | Have | `GetDebugBacktrace` (api_minor 59, feature `debugger-stack`): CFI from `.eh_frame`/`.debug_frame`, function entry, frame pointer, link register, stack scan (`src/debug/unwind.cc`); UI Stack box (click: listing, decompiler, the frame's registers), `rk-dbg bt`, SDK `backtrace`, MCP `debug_backtrace` ([debugger.md](debugger.md#call-stack)) | - | - |
| Watches (expressions, typed values, changed marks) | Have | the Debugger view's Watches box over `EvaluateDebug` (api_minor 60, 61; features `debugger-values`, `debugger-watches`): C expressions with the program's types, changed since the previous stop, struct fields, added from the listing's and decompiler's Debugger menu; `rk-dbg print`/`display`, SDK `evaluate`, MCP `debug_evaluate` ([debugger.md](debugger.md#expressions)) | - | - |
| Watch: apply type to listing, select reads | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | S |
| Variable value hovers in listing/decompiler | Have | `EvaluateDebug` (api_minor 60, feature `debugger-values`): a decompiler variable through its storage in its innermost frame, a listing register in the selected frame, a memory operand's address (the instruction's p-code with the frame's registers) and value, typed by the decompiler's variable at that slot; in the hover cards ([debugger.md](debugger.md#expressions)) | - | - |
| Threads table and selection | Have | `SelectDebugThread`, `DebugThread`; UI click; `rk-dbg threads` | - | - |
| Per-thread timeline lanes | Partial | snapshots carry `thread`; no lanes (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | M |

#### Debugger: modules, regions, static mapping (DebuggerModulesPlugin, DebuggerRegionsPlugin, DebuggerStaticMappingPlugin)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Modules table | Have | `ListDebugModules` (svr4 libraries, exec-file); UI Modules box | - | - |
| Sections table / filter by module | Missing | modules only (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | S |
| Auto-map module to its program (slide) | Have | slide from AT_ENTRY or `l_addr` (`docs/debugger.md` "Addresses") | - | - |
| Map libraries to other project programs | Have | runtime modules that are project programs are mapped (locations, the stack's function names, disassembly, `DebugModule.program_id`), and the UI opens the library program at the pc ([debugger.md](debugger.md#libraries); api_minor 70) | - | - |
| Import missing module into the project | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | M |
| Map manually / identically | Partial | one `slide` override (`CreateDebugSessionRequest.slide`) (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | S |
| Memory regions table | Partial | API `regions`, `rk-dbg maps`; not in UI (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | S |
| Add / delete regions in trace or emulator | Missing | emulator maps regions at start only (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | S |
| Map regions to program blocks | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | S |
| Static mappings table (several ranges) | Partial | single slide (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | M |

#### Debugger: time, traces, diff, p-code stepper (DebuggerTimePlugin, DebuggerTimeOverviewPlugin, DebuggerTraceManagerServicePlugin, DebuggerTraceViewDiffPlugin, DebuggerPcodeStepperPlugin)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Snapshot per stop, register/memory history | Have | `src/debug/timeline.cc`; emulator records every instruction | - | - |
| Navigate snapshots back/forward | Have | UI scrubber, "Now"; `rk-dbg snap N`; `GetDebugState(snapshot)` | - | - |
| Time table (snap, event, thread) | Partial | `GetDebugTimeline`, `rk-dbg timeline`; UI slider only (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | S |
| Rename snapshot, go to time by schedule | Missing | index only (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | S |
| Time overview bar | Partial | firmware exception marks under the scrubber (`panel.ts:448`) (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | S |
| Open / save / close traces | Partial | API `SaveDebugTrace`, `ListDebugTraces`, `DebugTraceTarget`; not in UI; `rk-dbg` can't load (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | S |
| Save by default, close dead traces | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | S |
| Compare two times (memory/register diff) | Partial | registers vs previous snapshot only (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | M |
| P-code stepper (op-level stepping, uniques) | Partial | `rk-emu --print-pcode` only (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Med | M |
| Emulate trace p-code backward/forward | Missing | not found (rechecked at 807d127: no change to `src/debug`, `ui/src/debug/panel.ts`, `proto/revkit/v1/debugger.proto` or `docs/debugger.md` since the survey) | Low | M |
| Resume execution from a past snapshot | Have | the emulator: Resume from here and Back (`RewindDebugSession`, api_minor 65, [debugger.md](debugger.md#rewind)); a live session or trace: Emulate from the snapshot (api_minor 67, [debugger.md](debugger.md#emulating-from-a-stop)) | - | - |

#### Emulator (DebuggerEmulationServicePlugin, Framework/Emulation, SystemEmulation, TaintAnalysis)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Emulate program from current address | Have | UI "Emulate from here"; `CreateEmulatorSession`; `rk-emu --entry` | - | - |
| Stack setup (argv, envp, auxv) | Have | call and process modes; `--reg sp=` | - | - |
| Multi-threaded emulation | Missing | single thread (`docs/emulator.md`) (rechecked at 807d127: no change to `src/emu`, `proto/revkit/v1/emulator.proto` or `docs/emulator.md` since the survey) | Med | L |
| Choose emulator (default, JIT, taint) | Missing | one interpreter (rechecked at 807d127: no change to `src/emu`, `proto/revkit/v1/emulator.proto` or `docs/emulator.md` since the survey) | Low | M |
| Emulate from a live target or trace state (lazy reads) | Have | `DebugEmulatorTarget.from_session`, `from_snapshot` (api_minor 67, feature `debugger-emulate-from`): registers from the stop or snapshot, the source's memory map, memory read a page at a time when first touched then copy-on-write (`emu::Options::backing`); Emulate in the Debugger view, SDK `debug(from_session=)`, MCP `debug_start(from_session=)` ([debugger.md](debugger.md#emulating-from-a-stop)) | - | - |
| Emulator step back | Have | `RewindDebugSession` (api_minor 65, feature `debugger-rewind`): copy-on-write checkpoints at every stop, any recorded snapshot by restoring the nearest and replaying; Back (Shift+F7) and Resume from here in the Debugger view, the later snapshots dropped or kept as a trace; `rk-dbg back`/`rewind`, SDK `rewind`/`step_back`, MCP `debug_rewind` ([debugger.md](debugger.md#rewind)); not on a machine | - | - |
| Skip over (advance pc without executing) | Missing | not found (rechecked at 807d127: no change to `src/emu`, `proto/revkit/v1/emulator.proto` or `docs/emulator.md` since the survey) | Med | S |
| P-code interpreter for any SLEIGH language | Have | `src/emu/interp.cc`, up to 64-byte values (`src/emu/wide.hh`) | - | - |
| Faults that undo the instruction | Have (better) | `src/emu/emulator.cc` | - | - |
| Emulator watchpoints | Have | `add_watchpoint`, `--watch` | - | - |
| JIT emulator | Missing | interpreter ~2.8M instr/s (`docs/emulator.md` "Speed") (rechecked at 807d127: no change to `src/emu`, `proto/revkit/v1/emulator.proto` or `docs/emulator.md` since the survey) | Med | L |
| Custom userop libraries | Have | C++ `on_userop` and built-ins; from Python, `hook_userop` (api_minor 68, [debugger.md](debugger.md#hooks)) | - | - |
| Structured Sleigh (userops in a DSL) | Missing | not found (rechecked at 807d127: no change to `src/emu`, `proto/revkit/v1/emulator.proto` or `docs/emulator.md` since the survey) | Low | M |
| Linux syscall library | Have (better) | `src/emu/linux.cc`: x86-64, x86, AArch64, ARM, RISC-V (Ghidra: amd64, x86) | - | - |
| Emulated Unix file system (open/read files) | Missing | `openat` returns `-ENOENT` (`docs/emulator.md` "System calls") (rechecked at 807d127: no change to `src/emu`, `proto/revkit/v1/emulator.proto` or `docs/emulator.md` since the survey) | Med | M |
| Import stubs for libc/PE imports | Have (revkit only) | `src/emu/stubs.cc` | - | - |
| EmulatorHelper-style scripting | Have | Python `Program.emulate`, `EmulatorSession` (`sdk/python/revkit/client.py:2321`); MCP `emu_*` | - | - |
| Script callbacks (stub, syscall, MMIO, userop in Python) | Have | `SetDebugHooks`, `AnswerDebugHook` (api_minor 68, feature `debugger-hooks`): a run stops at a hooked function, system call, MMIO access or user op and the client answers; SDK `hook_function`, `hook_syscall`, `hook_mmio`, `hook_userop` answered by `run()`, `revkit.hooklib` (constants, sequences, call logs, printf, strlen, memset), MCP `emu_call` ([debugger.md](debugger.md#hooks)) | - | - |
| Access trace (reads, writes, MMIO) | Have | `src/emu/trace.cc`, `--trace` JSON | - | - |
| Taint-tracking emulator, taint columns | Missing | not found (rechecked at 807d127: no change to `src/emu`, `proto/revkit/v1/emulator.proto` or `docs/emulator.md` since the survey) | Med | L |
| Paired-state emulator framework | Missing | not found (rechecked at 807d127: no change to `src/emu`, `proto/revkit/v1/emulator.proto` or `docs/emulator.md` since the survey) | Low | L |
| Run-time ISA context (Thumb, IT, MIPS16, VLE) | Partial | ARM Thumb and IT; not MIPS16, microMIPS, VLE (rechecked at 807d127: no change to `src/emu`, `proto/revkit/v1/emulator.proto` or `docs/emulator.md` since the survey) | Low | M |
| Firmware machines (exceptions, peripherals, IRQs) | Have (revkit only) | `src/emu/machine.cc`, `peripherals.cc`; `docs/firmware-emulation.md` | - | - |

#### Docking (framework UI: windows, keys, themes, options, tables, filters)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Dock views, drag between areas, layout remembered | Partial | Two tab groups, main and side, drag, palette moves, an overflow menu (`dock-more`) and closable views (search results); layout in localStorage `rk.layout` (`ui/src/ui/dock.ts`). No free splits, no floating or second windows | Med | M |
| Snapshot / cloned views (a second listing or decompiler, disconnected) | Missing | not found: one instance per view (`ui/src/ui/dock.ts`); the closest is the Bytes view's Follow toggle, which pins that one view in place (`ui/src/bytes/viewer.ts`, ui.md "Byte viewer, navigation and the overview"), not a second listing or decompiler | Med | M |
| Named tool configurations (save, switch, export tools) | Missing | not found; one layout per browser (`rk.layout`, `ui/src/ui/dock.ts`); Preferences holds the keymap only (`ui/src/ui/preferences.ts`) | Low | M |
| Command palette / Actions dialog (every action with its key) | Have | `ui/src/ui/palette.ts` (Ctrl+Shift+P, F1); ui.md "Keyboard and accessibility" | - | - |
| Keyboard component traversal | Have | single Tab stops per tab group, `ui/e2e/a11y.ts` (ui.md Phase 7) | - | - |
| Key binding customization (rebind, import/export bindings) | Partial | three keymap presets, Ghidra, IDA Pro, Binary Ninja (`ui/src/ui/keymap.ts`, File > Preferences `ui/src/ui/preferences.ts`, palette *Keymap: ...*), a filterable cheat sheet (*Help: Keyboard shortcuts*), ui.md "Keymap presets"; no rebinding of single actions, no import/export of bindings | Med | S |
| Theme switch (light / dark) | Have | `ui/src/app.ts` `toggleTheme`, `?theme=`, `rk.theme` pref, WCAG AA both themes | - | - |
| Theme editor (colors, fonts, icons; create, import, export themes) | Missing | not found; CSS variables in `ui/src/style.css` and two themes only (`toggleTheme`) | Low | M |
| Font size up/down | Partial | browser zoom only; no font preference among the `rk.*` prefs (`ui/src/ui/dom.ts` prefs, grep of `ui/src`); the listing's `fontSize: 13` is fixed in `ui/src/app.ts` | Low | S |
| Tool Options dialog (all plugin options in one place, restore defaults) | Partial | File > Preferences dialog exists but holds only the keymap (`ui/src/ui/preferences.ts` `showPreferences`); other options are scattered toggles and per-view menus (`rk.arrows`, `rk.bytes`, `rk.fields`, `rk.overview`, `rk.bv.*`, `rk.fn.sort`); no single options dialog or restore defaults | Med | M |
| Context help (F1 on an action opens its docs) | Partial | F1 opens the command palette (`App.onKey`, `ui/src/app.ts`; `commands` action); *Help: Keyboard shortcuts* lists keys (`ui/src/ui/preferences.ts` `showShortcuts`); no per-action docs, docs only in repo `docs/` | Low | M |
| Table: sort by column | Partial | functions (`ui/src/ui/functions.ts` column bar), Compare match table (`ui/src/diff/view.ts`), Search results headers with `aria-sort` (`ui/src/ui/search.ts`, ui.md "Search"); not the Equates, Function ID, memory map, modules or other tables | Med | S |
| Table: choose / reorder columns, column settings | Missing | not found for tables; only the listing's Fields menu (`ui/src/listing/fields.ts`) and the Bytes view's Columns menu (`ui/src/bytes/viewer.ts`) choose columns | Low | M |
| Table: copy rows / copy column | Partial | Search results table: Ctrl+C and **Copy CSV** copy the rows shown or chosen (`ui/src/ui/search.ts` `copyCsv`, ui.md "Search"); the listing's Copy rows (`copy-rows`, `ui/src/app.ts`); no copy column, and other tables (functions, Equates, Function ID, memory map) have no copy | Med | S |
| Table: export to CSV | Partial | Search results (memory, text, scalars, decompiled, Find uses) copy as CSV with a header to the clipboard (`ui/src/ui/search.ts` `csv`, `copyCsv`); no save-to-file and no CSV from other tables (scripts can write CSV) | Med | S |
| Tree/table text filter | Have | functions filter (daemon `name_contains`), types search, Compare filters | - | - |
| Filter options: starts-with, regex, glob, case, invert, multi-term | Missing | functions filter is a daemon substring (`name_contains`, `ui/src/ui/functions.ts`); search results filter is substring (`ui/src/ui/search.ts`); Go To wildcards (`FUN_*`) only in the palette (`ui/src/data/expr.ts`); no regex/starts-with/invert filter modes | Med | S |
| Table column filters (typed constraints, save/load filters) | Missing | not found; functions "Show" presets only (`ui/src/ui/functions.ts`) | Low | M |

#### FileFormats (file systems, containers, extra loaders)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| File System Browser (open an archive or image, browse, extract, import from inside) | Have | `src/container`, `ui/src/ui/filesystem.ts` (`docs/filesystems.md`) | - | - |
| Nested containers (zip in tar.gz in an image, FSRL paths, import depth) | Have | session paths with `!`, container paths in provenance (`docs/filesystems.md`) | - | - |
| Single-file compression wrappers (gzip, bzip2, xz, lz4, zstd, lzfse, LZSS) opened transparently | Partial | gzip, bzip2, xz, lzma, zstd, lz4 as containers of one file, offered as Open as file system on import (`src/container/compressed.cc`, `decompress.cc`; `docs/filesystems.md` "Formats", `ui/src/ui/open.ts` `looksLikeContainer`); no lzfse, LZSS | Low | S |
| Archives: zip, 7z, tar, cpio, ISO9660, ar/COFF `.a`/`.lib`, OMF libs | Partial | zip, tar, cpio, ISO 9660, ar (`src/container/*.cc`, `docs/filesystems.md` "Formats"); 7z, rar, cab, OMF not read (`docs/filesystems.md` "Known gaps") | Low | M |
| Firmware/OS file systems: ext4, squashfs, cramfs, YAFFS2, HFS+, DMG, Android sparse | Partial | ext2/3/4, squashfs, cramfs, FAT, partition tables (`src/container/ext.cc`, `squashfs.cc`, `cramfs.cc`, `fat.cc`; `docs/filesystems.md`); no YAFFS2, HFS+, DMG, Android sparse ("Known gaps") | Med | M |
| Android: APK, DEX/CDex, ODEX/OAT/VDEX/ART loaders, dex2jar/smali | Missing | Dalvik languages load raw only, no DEX loader, no decompile (`docs/processors.md:152,246`); APK browses as a zip (`docs/filesystems.md`), DEX only named by detection ("What each file is") | Med | L |
| Android boot / vendor_boot images, FBPK | Partial | Android boot images v0-v4 (`src/container/firmware.cc`, `docs/filesystems.md` "Formats"); no vendor_boot, FBPK | Low | S |
| Apple: dyld shared cache, kernelcache/Mach-O fileset, universal binaries, IPSW, img2/3/4, iBoot | Missing | Mach-O deferred (README "Loaders", roadmap "Later"); `docs/filesystems.md` "Known gaps" lists no dmg/Apple containers; detection only names Mach-O as data | Med | L |
| Device tree (FDT/DTB) markup | Missing | not found: a DTB is only named by detection (`docs/filesystems.md` "What each file is") and listed as an Android boot image member; no markup or memory-map suggestion (wishlist "Memory and import") | Med | S |
| Crash dumps (Windows minidump/pagedump/userdump, Apport) loader | Missing | not found (grep for minidump/MDMP/Apport in `src`, `docs`); wishlist "crash dumps" open | Med | M |
| Java `.class`/JAR loading, Decompile JAR, Export Eclipse project | Missing | not found; a JAR browses as a zip (`docs/filesystems.md`) but `.class` isn't loaded | Low | L |
| CaRT neutered malware files | Missing | not found (grep of `src/container`, `docs/filesystems.md`) | Low | S |
| iOS crypto key template | Missing | not found (grep of `src/container`, `docs/filesystems.md`) | Low | S |
| Batch import (many files, recursive folders, into containers) | Have | `ImportFromFileSystem` (preview, cap, into containers), the browser's Import programs below…, `rk-daemon project import-batch` (`docs/filesystems.md`) | - | - |
| Third-party loaders as extensions | Have | WebAssembly loader plugins by magic (`docs/plugins.md` "Loaders", `sdk/plugins/examples/rkraw-loader`) | - | - |

#### PDB

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Platform-independent PDB reader (no DIA) | Have | own MSF 7.00 reader, `src/debuginfo/pdb.cc`, `docs/types.md` "PDB coverage" | - | - |
| Auto-find PDB (CodeView path, beside binary) with GUID/age check | Have | `docs/backend.md:330-334`; `PdbIdentity::matches()` | - | - |
| Load PDB File on an open program (pick file, force non-exact match) | Have | `LoadPdb`, palette Load PDB… ([pdb.md](pdb.md)) | - | - |
| Symbol servers: local symbol store, HTTP(S) servers (msdl), `_NT_SYMBOL_PATH`, `.pd_` decompression, search list config | Have | [pdb.md](pdb.md#symbol-servers) (MSZIP `.pd_` only) | - | - |
| Search options: ignore age / ignore GUID, override name/GUID/age | Partial | `LoadPdb.force` ignores both GUID and age with a warning ([pdb.md](pdb.md) "Load PDB"); no separate age/GUID or override | Low | S |
| Apply control: all / data types only / publics only | Missing | not found: `LoadPdb` applies names, prototypes, globals and types together ([pdb.md](pdb.md) "Known gaps", `proto/revkit/v1/project.proto` `LoadPdbRequest`) | Low | S |
| Structs, unions, enums, typedefs | Have | `docs/types.md:357-370`; 116/116 named types match DWARF (types.md "One type, either format") | - | - |
| C++ classes (methods, vtables, virtual bases, static members) | Partial | vtable pointers to structs of the introduced virtuals ([pdb.md](pdb.md#c-classes)); virtual bases' vbtable pointers, non-virtual methods and static members skipped ([pdb.md](pdb.md) "Known gaps") | Med | M |
| Function prototypes, parameter names | Have | `docs/types.md:371-378` | - | - |
| Stack variable names and types | Have | `S_LOCAL`/`S_REGREL32`/`S_BPREL32`/`S_REGISTER` (`docs/types.md:353-356`) | - | - |
| Source line numbers | Missing | "no line numbers (C13 subsections)" (`docs/types.md` "Known gaps") | Med | M |
| Public/global symbols applied | Partial | functions known only from `S_PUB32` not made functions; no `S_CONSTANT`, `S_GTHREAD32`/`S_LTHREAD32` (`docs/types.md` "Known gaps") | Med | S |
| Newer MSVC records (`LF_CLASS2`/`LF_STRUCTURE2`), type servers, PCH types, PDB 2.00 | Partial | `LF_CLASS2`/`LF_STRUCTURE2`/`LF_INTERFACE2` read ([pdb.md](pdb.md#c-classes)); no type servers (`LF_TYPESERVER2`), PCH types, PDB 2.00 (`docs/types.md` "PDB coverage", "Known gaps") | Med | M |
| PDB.XML / MSDIA path | Missing | not needed (own reader, `src/debuginfo/pdb.cc`); legacy | Low | - |

#### PyGhidra

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Standalone Python driving the tool (open program, analyze, script) | Have | Python SDK, `revkit.Daemon` throwaway daemons, `rk-script` (`docs/scripting.md`, `sdk/python`) | - | - |
| Python 3 scripts in the tool (Script Manager) | Have | `ScriptService`, Script Manager Ctrl+Shift+S (`docs/scripting.md` "The daemon's script service", `ui/src/scripts/manager.ts`) | - | - |
| Run existing Ghidra Python scripts | Partial | `revkit.ghidra.compat` shim: 21/30 bundled scripts agree on the fixture (20 on features), 6 `Unsupported` (`docs/scripting.md` "Running Ghidra scripts"); also bindable in the console (Ghidra names) | Med | M |
| Interactive interpreter in the tool (REPL with `currentProgram`, `currentAddress`, selection) | Have | Python console view, *Show Python (the console)* (`ui/src/scripts/console.ts`; ui.md "Python console"; `docs/scripting.md` "The console"; `RunScript{interactive}`, api_minor 43, feature `script-console`): a live host per user and program with `current_program`, `current_address`, `current_function`, `current_selection` following the cursor, and Ghidra's `currentProgram`, `currentAddress`, `currentSelection` on request | - | - |
| Interpreter code completion, history, interrupt, reset | Have | Tab completion from the live namespace (`CompleteConsole`, jedi or rlcompleter, feature `script-completion`) with signature help on `(` (`ui/src/scripts/assist.ts`), history per user (last 1,000, Up/Down), Ctrl+C interrupt (`CancelScript{interrupt}`), Restart and `exit()` (ui.md "Python console", `docs/scripting.md` "The console") | - | - |
| `help()` with API docs | Have | `help()` works in the in-tool console (its banner suggests `help(rename)`, `ui/src/scripts/console.ts`), and completions carry each name's signature and docstring line (`CompleteConsole`, `docs/scripting.md` "The console"); SDK docstrings | - | - |

#### Sarif

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Export program features to SARIF (functions, symbols, comments, types, refs, memory map...) | Missing | not found (`grep -ri sarif` empty); revkit's own interchange is Ghidra-interop JSON and type archives (`docs/ghidra-interop.md`, `docs/types.md` "Type archives") (rechecked at 807d127: `grep -ril sarif src proto ui/src sdk` empty) | Med | M |
| Import SARIF into a program (new or existing) | Missing | not found (rechecked at 807d127: `grep -ril sarif src proto ui/src sdk` empty) | Med | M |
| SARIF results table with apply actions (bookmarks, comments, highlights, retype) | Missing | not found; plugin facts drawn on rows are the closest (`docs/plugins.md`) (rechecked at 807d127: `grep -ril sarif src proto ui/src sdk` empty) | Med | M |
| Custom result/run handlers, SARIF graphs | Missing | not found (rechecked at 807d127: `grep -ril sarif src proto ui/src sdk` empty) | Low | M |

#### SourceCodeLookup

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Go To Symbol Source (in an IDE, from listing or decompiler) | Missing | not found; of DWARF `.debug_line` only the file names are read (`docs/types.md` "Known gaps"), PDB line numbers not read | Low | M |

#### GhidraGo

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Hyperlink to a program location | Have | web URL `?program=<id>#<address>` (`ui/src/main.ts:102`, `ui/src/app.ts:404,739`) | - | - |
| Symbol in the link (`#main`), OS protocol handler opening the desktop app | Partial | address only: the hash is read with `parseAddress` (`ui/src/app.ts` load and `hashchange`), no symbol or expression; no `revkit://` handler in `ui/tauri` found | Low | S |

#### WildcardAssembler

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Assembler API (text to bytes) | Have | `src/asm`, `rk-asm` (`docs/patching.md` "The assembler") | - | - |
| Wildcard operands with numeric/regex filters, all encodings plus wildcard bit locations | Missing | not found; `src/asm` and `rk-asm` assemble one encoding with no wildcard operands (`docs/patching.md` "The assembler") | Med | M |
| Find instructions matching a wildcarded pattern | Partial | Search Memory with nibble wildcards (`48 8b ?? e8`, `4? ?f`) in the UI and API (`ui/src/ui/search.ts`, `docs/api.md` "Search", `search_memory` in MCP) and Search Program Text by regex over Mnemonics and Operands (ui.md "Search"); the pattern is hand-written, not made from a wildcarded instruction | Med | S |

#### Ghidra Server and shared projects

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Shared multi-user server | Have | `rk-daemon` with accounts, TLS, sessions (`docs/security.md`) | - | - |
| Concurrent edits merged (check-out, check-in, merge) | Have | different model: every edit is a live assertion all clients see; no check-out needed (`docs/api.md` "Assertions", `docs/collab.md`) | - | - |
| Exclusive check-out (lock a program) | Missing | not found: edits are live assertions with no lock (`docs/collab.md`, `docs/api.md` "Assertions"; grep for check-out/exclusive in `docs`) | Low | S |
| Per-repository access (read / write / admin) | Have | viewer/editor/admin roles, per-project access lists (`docs/security.md:104-215`) | - | - |
| Auth: password | Have | scrypt local accounts, API tokens (`docs/security.md` "Identities") | - | - |
| Auth: PKI/client certificates, Active Directory/Kerberos/JAAS, SSH keys | Missing | "No single sign-on, MFA or client certificates"; OIDC and mTLS would plug into `AuthGate::Identify` (`docs/security.md` "Limits and known gaps") | Med | M |
| Server admin CLI (users, passwords, repos) | Have | `rk-daemon user add`, `token create` (README "Use", `docs/collab.md:22`) | - | - |
| Version history: list versions, open or diff an older version, check-in comments | Partial | per-key history and blame (`GetHistory`, `Blame`, `proto/revkit/v1/assertion.proto`; `docs/api.md`), reads at a retained revision; no UI to open, browse or diff an old program version (no `GetHistory` caller in `ui/src`); retention window | Med | M |
| Revert a program to a version / undo checkout | Partial | undo, `RevertByProvenance` (`proto/revkit/v1/assertion.proto`), "Revert this run"; no revert-to-revision | Med | S |
| Offline work then sync | Have | multi-daemon replication with catch-up (`docs/collab.md`) | - | - |
| Project folders | Have | folders as assertions: `CreateFolder`, `RenameFolder`, `DeleteFolder`, `MoveToFolder` (`proto/revkit/v1/project.proto`, api_minor 37, feature `project-folders`); the Open dialog is a project tree with New folder, Rename, Move to, drag and drop, Undo (`ui/src/ui/open.ts`, ui.md "Project tree and archives") | - | - |
| Project archive export/import (`.gar`) | Have | `.rkproj` archives of a project, folder or program, with or without binaries: `ExportProject`, `ImportProjectArchive` (`proto/revkit/v1/project.proto`, feature `project-archive`), File > Export project / Import project (`ui/src/ui/archive.ts`), `rk-daemon project export`, `project import` (`tools/rk-daemon/main.cc`; ui.md "Project tree and archives", `docs/backend.md` "Project archives") | - | - |
| Server status / start control | Have | daemon status chip with version, API, uptime, project, Reconnect and the start command (`ui/src/ui/daemon.ts`, `GetServerInfo`); **Restart daemon...** for admins (`MetaService.RestartDaemon`, api_minor 55, feature `daemon-restart`, `proto/revkit/v1/meta.proto`); Start, Stop, Restart and Show daemon log in the desktop app (ui.md "Daemon status") | - | - |
| Open from a Ghidra Server repository (`ghidra://`) | Missing | not found; interop is local Ghidra projects via PyGhidra (`docs/ghidra-interop.md`) | Low | M |

#### Headless analyzer

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Import and analyze headless | Have | `rk-lift --analyze`, `rk-script --import`, `rk-daemon --open` (README "Use") | - | - |
| Pre- and post-scripts | Have | `rk-script --pre/--post` (`docs/scripting.md` "rk-script") | - | - |
| Process programs already in a project | Have | `rk-script --program ID --project-dir D` | - | - |
| Parallel processing | Have | `rk-script -j N`, `rk-lift -j` (Ghidra's headless is serial per run) | - | - |
| Per-file analysis timeout | Have | `--analysis-timeout` (`docs/scripting.md:296`) | - | - |
| Processor / compiler spec / loader override, no-analysis | Have | `rk-lift --lang`, `ImportOptions.language_id`, `compiler_spec_id`, `format`, `analyze` (`proto/revkit/v1/project.proto:635-643`) | - | - |
| Recursive folder import (`-recursive`, into containers) | Have | `rk-daemon project import-batch <dir> --recursive` (`docs/filesystems.md`) | - | - |
| Load and link dependent libraries (`-librarySearchPaths`) | Have | `ImportOptions.import_libraries`, `library_search_paths`, `library_depth`; SDK `import_program(import_libraries=True, library_search_paths=[...])`, MCP `import_program`; imports linked to the library programs (`docs/api.md#libraries`, api_minor 70) | - | - |
| Commit results to the shared server | Have | `rk-script --daemon host:port --token` writes to the shared daemon | - | - |
| Java GhidraScripts headless | Missing | Python only; `java.*` unsupported (`docs/scripting.md` "Running Ghidra scripts") | Med | L |
| Script log, machine-readable results | Have | `--json` per-program results (`docs/scripting.md` "rk-script") | - | - |

#### Demanglers (GnuDemangler, MicrosoftDemangler/MicrosoftDmang, SwiftDemangler)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Itanium/GNU demangling (incl. Rust legacy, D) | Have | `src/demangle/structured.cc` over LLVM's ASTs, the C++ runtime's demangler where LLVM can't parse; every ELF/PE symbol (`docs/demangle.md`) | High | |
| Microsoft demangling | Have | same (`src/demangle/structured.cc`): member status, return types, calling conventions | High | |
| Demangler analyzer: names, namespaces/classes, signature and calling convention from the mangled name | Have | derived names and import-rank prototypes (`docs/demangle.md`); a mangled/short/full names setting in the UI | High | |
| Swift demangler and Swift types | Missing | "Swift names aren't demangled (Mach-O is deferred)" (`docs/demangle.md`) | Low | M |

#### MicrosoftCodeAnalyzer

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| MSVC RTTI (TypeDescriptor, RTTI 1-4, class names) | Have | `src/msvc`, [pe.md](pe.md) | - | - |
| vftables found, typed and named; class hierarchy | Have | vftable structs, `Class::vfuncN`, `this` typed, `GetClassHierarchy` and the Class hierarchy view ([pe.md](pe.md)) | - | - |
| C++ EH structures (FuncInfo, unwind/try-block/IP-to-state maps, catch handlers, ES type lists) | Partial | FH3 FuncInfo and its maps, catch and unwind funclets ([pe.md](pe.md#pe-structures-and-exception-data), `src/msvc`); no `__CxxFrameHandler4` (EH4) data, ES type lists, throw infos (pe.md "Known gaps") | Med | M |
| PE `.pdata`/`UNWIND_INFO`, load config, TLS typed as data | Have | [pe.md](pe.md#pe-structures-and-exception-data) | - | - |
| TEB/TIB segment typing (`fs:`/`gs:`) | Missing | not found (no TEB/TIB typing in `src/msvc`, `src/loader`, `docs/pe.md`) | Low | S |
| Windows resource references | Missing | not found: the resource directory tree is typed as data (`docs/pe.md` PE structures table, "resources"), but no references from code to resources | Low | S |
| Propagate external (Win API) parameters to call sites | Partial | library prototypes (glibc, kernel32, user32, ntdll, advapi32, ws2_32, msvcrt) applied to imports at library rank reach the decompiler (`docs/types.md` "Library prototypes", api_minor 50, `src/infer/data/win64.sigs`); no listing-level argument markup at call sites | Low | S |

#### Recognizers

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Recognize embedded/whole-file archive and compression formats (~40 magics) | Partial | whole-file recognition by magic of about 20 container and compression formats (`container::identify`, `src/container/identify.cc`; `docs/filesystems.md` "Formats"), offered on import as Open as file system (`ui/src/ui/open.ts`); raw detection refuses high-entropy data (`src/detect/detect.cc`); no scan for archives embedded at an offset (only a zip self-extractor's prefix), and 7z, rar, cab and others not recognised | Med | S |

#### Processor-module authoring (SLEIGH)

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Load any compiled SLEIGH language (`.sla`/`.ldefs`/`.pspec`/`.cspec`) | Have | all 189 languages of the Ghidra tree it points at (`docs/processors.md`, `--ghidra`, `docs/getting-started.md:75`) | - | - |
| Compile `.slaspec` (SLEIGH compiler) | Missing | `third_party/ghidra/CMakeLists.txt` builds the runtime only (no `slgh_compile`); a tree with only `.slaspec` is refused (`src/runtime/runtime.cc`) | Med | S |
| SLEIGH editor (syntax, navigation, errors) | Missing | not found (grep of `ui/src`, `docs`) | Low | M |
| Reload an edited processor without restart | Missing | not found (`src/runtime`) | Low | M |

#### Other modules without help pages

| Feature | Status | revkit evidence (path) or what's missing | Value | Effort |
| --- | --- | --- | --- | --- |
| Debugger-isf: ISF export / server for Volatility | Missing | not found (grep for ISF/Volatility in `src`, `docs`) | Low | M |
| Debugger-importers: Tenet trace import | Missing | not found (grep for Tenet in `src`, `docs`) | Low | M |
| FunctionGraphDecompilerExtension: nested (structured) graph layout | Missing | graph uses ELK layered only (`ui/src/graph/`, `docs/ui.md` Phase 5) | Low | M |

### 2. Gaps worth doing (Missing or Partial, High or Med value)

##### Decompiler, graphs, byte viewer
- ~~**High: Field rename and retype.** Put the struct type hash and offset on FIELD tokens and add Rename Field and Retype Field. Also fix the fallback that renames the function when Rename is pressed on a field (`ui/src/app.ts:1239`).~~ *Done (api_minor 38, feature `field-tokens`).*
- **High: Calling conventions.** ~~Honour the asserted convention when a user prototype is committed~~ (done: [decompiler-inputs.md](decompiler-inputs.md#calling-conventions)). ~~Add no-return and a structured signature editor (convention, varargs)~~ (done: the Edit Function dialog, api_minor 58; `SetNoReturn`, api_minor 66). Inline flags and custom storage remain.
- ~~**High: Call-site signature override.** A new assertion kind that reaches the decompiler's inputs, with Override, Edit and Remove on call tokens.~~ *Done (api_minor 53, feature `call-signature-override`).*
- ~~**High: Convert constants and equates.** A per-scalar display-format/equate fact shared by the listing and the decompiler: hex, dec, oct, bin, char and enum names.~~ *Done (api_minor 39, feature `equates`).*
- ~~**High: Slices.** Def-use and slice data in Decompile (or a Slice RPC), shown as forward/backward and operator slice highlights.~~ *Done (api_minor 57, feature `decompile-slices`; [ui.md](ui.md#slices)).*
- ~~**High: Search decompiled text.** A UI over `DecompileMany` with regex, a results table and Select Functions.~~ *Done (api_minor 41, feature `search`; Make selection selects lines, not whole functions).*
- ~~**High: Byte viewer.** A dockable hex + chars view synced to the cursor, with inline editing through the PatchService.~~ *Done (api_minor 44, feature `byte-viewer`).*
- **Med: Decompiler pane basics.**
  - snapshot (pinned) decompiler panes;
  - decompiling code outside functions;
  - ~~Copy and Find in the pane~~ (done: text copy, and Search decompiled code in the current function);
  - secondary highlights;
  - next/previous highlight;
  - double-click a constant to go to that address;
  - Export C for one function and for the program.
- **Med: Decompiler options per request.** Eliminate unreachable code, respect read-only, cast printing, integer format, user spec extensions (prototypes, callfixups).
- **Med: More type edits from the decompiler.**
  - force a union field;
  - offset pointers;
  - split or merge variables;
  - ~~find uses of a type~~ (done, api_minor 53);
  - a TYPE token opens the type editor;
  - rename into namespaces;
  - commit params/return in one action.
- ~~**Med: Def-use highlight.**~~ *Done (api_minor 57).*
- **Med: Function graph.**
  - hover previews;
  - vertex colors mirrored to the listing;
  - free grouping with text;
  - path highlighting;
  - the nested-code layout.
- **Med: Other graphs.**
  - a visual call graph;
  - program-wide call graphs and data-reference graphs;
  - a Data Graph;
  - graph export to DOT and GraphML.
- **Med: Byte viewer extras.** A chars view with charset and an address view.
- **Med: Taint analysis.** Source, sink and gate marking, and queries over p-code facts.

##### Debugger and emulator
- ~~**High: Dynamic listing.** Disassemble runtime memory (libraries, unpacked or JIT code), auto-disassembled at the pc.~~ *Done as runtime disassembly (api_minor 62, [debugger.md](debugger.md#runtime-disassembly)); a full listing over runtime memory remains.*
- ~~**High: Copy runtime memory into the current or a new program.** This is how you capture unpacked or decrypted code.~~ *Done (api_minor 63, [debugger.md](debugger.md#copying-runtime-memory)).*
- ~~**High: Stack view and unwind.** Use frame info and function bounds; expose it in the API, `rk-dbg bt` and the UI.~~ *Done (api_minor 59, [debugger.md](debugger.md#call-stack)).*
- ~~**High: Watches.** Expressions over registers and memory, with a type, evaluated at any snapshot, with changed marks.~~ *Done (api_minor 60, 61, [debugger.md](debugger.md#expressions)).*
- ~~**High: Variable value hovers** in the decompiler and listing, through each variable's storage, at the current snapshot.~~ *Done (api_minor 60, [debugger.md](debugger.md#expressions)).*
- ~~**High: Conditional breakpoints.** An expression evaluated on hit (emulator and live), plus an ignore count.~~ *Done (api_minor 64, [debugger.md](debugger.md#breakpoints)).*
- ~~**High: Resume from a past snapshot.** Emulator checkpoint and restore (copy-on-write pages exist), so you can step back and continue.~~ *Done (api_minor 65, [debugger.md](debugger.md#rewind)); firmware on a machine remains.*
- **High: Emulate from a live or trace state.** Fork an emulator session whose memory reads come lazily from the target or snapshot.
- **High: Map libraries to project programs** at runtime, and offer to import missing modules.
- **High: Windows debugging (dbgeng/WinDbg agent).** A Windows target, or a bridge to an external dbgeng.
- ~~**High: Emulator script callbacks.** Python or plugin handlers for stubs, syscalls, MMIO and userops (streamed RPC or plugin ABI).~~ *Done as hooks the client answers (api_minor 68, [debugger.md](debugger.md#hooks)).*
- ~~**High: Control modes.** Hand a live target's state to the emulator; record emulator writes as patch steps.~~ *Done (api_minor 67, [debugger.md](debugger.md#emulating-from-a-stop)); the emulator's writes go into the program with Copy runtime memory (patches).*
- **Med: More targets.**
  - gdbserver over SSH;
  - Wine for PE programs;
  - rr reverse execution (`bs`/`bc`);
  - ELF core dumps as a trace target;
  - LLDB/debugserver for macOS and lldb-server for Android;
  - Windows kernel (kd) and TTD import;
  - x64dbg;
  - a Trace-RMI-style API for outside agents to push snapshots.
- **Med: Launcher.** Env, image and arch options in the UI, and stdin for launched processes.
- **Med: Monitor commands.** Expose `qRcmd` in the API and UI.
- **Med: Several debug sessions in the UI.**
- **Med: Breakpoints.**
  - markers in the decompiler and graph;
  - a watchpoint/HW UI;
  - ~~a breakpoint table with enable/disable and hit counts~~ *(done, api_minor 64)*;
  - saved with the project;
  - Sleigh injection.
- **Med: Memory view.**
  - a scrollable, editable bytes view with formats;
  - follow SP or an expression;
  - assemble into the target with `src/asm`;
  - export a snapshot as a memory image.
- **Med: Registers.** Display groups (FP, vector); show as float or pointer; jump from a value to the listing.
- **Med: Regions table in the UI**, and static mappings with several ranges.
- **Med: Traces.**
  - a time table panel;
  - open and save traces in the UI, and load them in `rk-dbg`;
  - memory diff between two snapshots;
  - a p-code op stepper.
- **Med: Emulator.**
  - multi-threaded emulation;
  - Skip Over;
  - a JIT or other speed-up;
  - an emulated Unix file system for `open`/`read`;
  - userops through the API;
  - taint tracking.

##### Version tracking, BSim, Function ID, comparison
- ~~**High: BSim database.** A persistent signature store with an LSH index, ingest of programs (CLI and API), metadata, categories and tags. Reuse `src/diff/lsh.cc` and `SignatureJob`.~~ *Done* ([bsim.md](bsim.md), `api_minor` 69) but function tags.
- **High: Similar-function search.** ~~From the cursor or selection, with thresholds, a results table~~ *done* (`api_minor` 72, [bsim.md](bsim.md#searching)); an executable summary, and Apply name, signature or signature+types.
- ~~**High: Function ID.**~~ Done ([fid.md](fid.md), `api_minor` 51): Ghidra's hashes, `.fidbf` databases, the analyzer, creating and attaching databases.
- ~~**High: Manual match in the Compare UI.** Pick from the Only-in lists, then match, accept or apply (`SetMatch` exists).~~ *Done (api_minor 54).*
- ~~**High: Compare any two functions,** including within one program, from the listing or functions panel.~~ *Done (api_minor 54, feature `function-compare`).*
- ~~**High: Decompiler token matching in the C diff pane,** then apply local and global names, variable types and callee signatures token by token.~~ *Done (api_minor 54).*
- ~~**High: Port instruction-level comments** through the instruction map for modified pairs.~~ *Done (api_minor 54).*
- **Med: VT data matches.** Exact, duplicate and similar, with type and label porting, and labels at non-entry addresses.
- **Med: More VT options.**
  - a similar-symbol-name tier;
  - restrict a diff to a range;
  - run tiers one at a time;
  - a preconditions panel;
  - match tags;
  - a per-item markup table;
  - stale-port detection;
  - a related-matches panel.
- **Med: Function comparison.** Compare matching callees from a call row; compare several functions at once.
- **Med: Address-aligned Program Diff** across categories, with per-category apply and merge, program-wide markers, and a diff against an earlier revision.
- **Med: BSim search extras.** Filters (exe, arch, compiler, calls, tags), an overview query, and database list/delete commands.

##### Formats, PDB, demanglers, MSVC, framework, scripting, server
- ~~**High: Demangler analyzer.**~~ *Done ([demangle.md](demangle.md)):* demangled names with namespaces and classes everywhere, and the mangled signatures' parameter types and calling conventions as import-rank prototypes.
- ~~**High: MSVC RTTI and vftables.** Find TypeDescriptor and RTTI 1-4, name the classes, and type and name the vftables. Build a class hierarchy, and feed `this` types into the decompiler.~~ *Done (api_minor 45, [pe.md](pe.md)).*
- ~~**High: PDB symbol servers.**~~ *Done ([pdb.md](pdb.md)):*
  - a local symbol store and HTTP(S) servers (msdl);
  - `_NT_SYMBOL_PATH`;
  - `.pd_` decompression;
  - a search-path config in the daemon.
- ~~**High: "Load PDB" on an open program.** Pick a file and force a non-exact match (ignore age or GUID). This needs an API RPC and a UI action; the CLI already has `--pdb`.~~ *Done (api_minor 49, [pdb.md](pdb.md)).*
- ~~**High: Newer MSVC PDB records.** `LF_CLASS2`/`LF_STRUCTURE2` (MSVC 17.x), plus type servers and PCH types.~~ *Done for `LF_CLASS2`/`LF_STRUCTURE2` ([pdb.md](pdb.md)); type servers and PCH types remain.*
- ~~**High: File System Browser with nested containers.**~~ *Done (api_minor 48, [filesystems.md](filesystems.md); 7z and YAFFS2 aren't read):*
  - zip, tar, gzip/xz/bzip2/lz4/zstd, 7z, cpio, ISO;
  - ext4, squashfs, cramfs, YAFFS2;
  - browse, extract, and import from inside, recursively.
- ~~**High: In-UI Python console (REPL).** A live host bound to `current_program`, `current_address` and the selection, with completion and history (roadmap Scripting Phase 4).~~ *Done (api_minor 43, [scripting.md](scripting.md#the-console)).*
- **Med: Transparent decompression of single-file wrappers** (gzip, xz, ...) at import, and container-magic recognition in the detector (designed in autodetect.md).
- **Med: Android.**
  - a DEX/APK loader;
  - the injections Dalvik needs to decompile;
  - boot.img and vendor_boot.
- **Med: Apple containers** (dyld cache, kernelcache, universal binaries), once Mach-O lands.
- **Med: Device-tree (DTB) parsing.** Mark it up and use it to suggest the memory map for firmware.
- **Med: Crash dumps.** Load Windows minidumps and ELF cores as programs (shares work with the debugger's core target).
- ~~**Med: Batch import.** Recursive folders and `-recursive`-style headless import, plus multi-file import in the UI.~~ *Done ([filesystems.md](filesystems.md#importing), `rk-daemon project import-batch`).*
- **Med: Link dependent libraries.** Load them and resolve imports to other programs in the project (`-librarySearchPaths`).
- **Med: Java GhidraScripts.** Run them, or translate them with a guided port; today only Python runs.
- **Med: Run more of Ghidra's Python scripts.** Widen `revkit.ghidra.compat` (6 of 30 still `Unsupported`).
- **Med: PDB C++ classes** (methods, vtable pointers, virtual bases), source line numbers, `S_PUB32`-only functions, `S_CONSTANT` and thread-local data.
- **Med: MSVC EH structures** (FuncInfo, unwind/try maps, catch handlers), shown as data and as handler targets.
- **Med: SARIF.** Export program features and import results into a results table with apply actions (comments, bookmarks, highlights, retypes).
- **Med: Wildcard assembler.** Wildcards in `src/asm` that return every encoding and the bits each wildcard occupies, plus a "find instructions like this" search over `FindBytes`.
- **Med: SLEIGH compiler.** Build Ghidra's C++ `slgh_compile` into revkit (`rk-sleigh`) so custom processors compile without Java, and load languages from an extra directory.
- **Med: Version history in the UI.** Open, browse and diff a program at an older revision, and revert to a revision.
- **Med: Auth.** OIDC/SSO and client certificates (mTLS); Ghidra has PKI, AD/Kerberos and SSH keys.
- **Med: Docking.**
  - more than two dock areas, split and floating windows;
  - snapshot (cloned) views;
  - user-defined key bindings (keymap presets for Ghidra, IDA Pro and Binary Ninja are done; rebinding one action is not);
  - an options dialog.
- **Med: Tables.** Copy rows or columns, export CSV, sort on every table, and filter modes (starts-with, regex, glob, invert, multi-term). The search results table has Copy, Copy CSV and sorting; the others don't.

### 3. Counts

<!-- survey-summary:part2 -->
| Module / topic | Have | Partial | Missing | In progress |
|---|---|---|---|---|
| Decompiler: window and actions | 23 | 10 | 9 | 0 |
| Decompiler: options and annotations | 5 | 5 | 10 | 0 |
| DecompilerDependent | 1 | 1 | 4 | 0 |
| FunctionGraph and Graph | 8 | 2 | 10 | 0 |
| GraphFunctionCalls | 2 | 2 | 1 | 0 |
| GraphServices, ProgramGraph, DataGraph | 1 | 2 | 8 | 0 |
| ByteViewer | 6 | 3 | 2 | 0 |
| VersionTracking: sessions, correlators | 12 | 3 | 9 | 0 |
| VersionTracking: match table, markup, apply | 13 | 5 | 9 | 0 |
| VersionTrackingBSim | 2 | 1 | 1 | 0 |
| BSim: signatures, database, command line | 9 | 4 | 0 | 0 |
| BSimSearchPlugin | 5 | 2 | 3 | 0 |
| BSimFeatureVisualizer | 0 | 1 | 1 | 0 |
| ProgramDiff | 0 | 3 | 5 | 0 |
| FunctionID | 8 | 1 | 1 | 0 |
| BytePatterns | 1 | 0 | 5 | 0 |
| CodeCompare | 8 | 2 | 4 | 0 |
| Debugger: targets, agents, connections | 5 | 4 | 15 | 0 |
| Debugger: control, console, platform, model | 5 | 4 | 4 | 0 |
| Debugger: breakpoints | 8 | 2 | 2 | 0 |
| Debugger: dynamic listing, memory, copy, sync | 6 | 6 | 4 | 0 |
| Debugger: registers, stack, watches, hovers, threads | 7 | 3 | 2 | 0 |
| Debugger: modules, regions, static mapping | 3 | 3 | 4 | 0 |
| Debugger: time, traces, diff, p-code stepper | 3 | 5 | 3 | 0 |
| Emulator | 14 | 1 | 8 | 0 |
| Docking | 4 | 8 | 6 | 0 |
| FileFormats | 4 | 4 | 7 | 0 |
| PDB | 7 | 4 | 3 | 0 |
| PyGhidra | 5 | 1 | 0 | 0 |
| Sarif | 0 | 0 | 4 | 0 |
| SourceCodeLookup | 0 | 0 | 1 | 0 |
| GhidraGo | 1 | 1 | 0 | 0 |
| WildcardAssembler | 1 | 1 | 1 | 0 |
| Ghidra Server and shared projects | 9 | 2 | 3 | 0 |
| Headless analyzer | 10 | 0 | 1 | 0 |
| Demanglers | 3 | 0 | 1 | 0 |
| MicrosoftCodeAnalyzer | 3 | 2 | 2 | 0 |
| Recognizers | 0 | 1 | 0 | 0 |
| Processor-module authoring | 1 | 0 | 3 | 0 |
| Other modules without help pages | 0 | 0 | 3 | 0 |
| **Total (40 modules, 461 features)** | **203** | **99** | **159** | **0** |
<!-- /survey-summary:part2 -->

"In progress" rows are branches in flight and are not counted as Missing. Rows marked "Have (better)", "Have (beyond Ghidra)" or "Have (revkit only)" count as Have.
