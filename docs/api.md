# revkit API (v1)

Every revkit client (the web UI in Tauri or a browser tab, the Python SDK,
the CLI and the MCP server for agents) talks to `rk-daemon` through one
typed API, defined in [`proto/revkit/v1/`](../proto/revkit/v1). No client
has a private hook: if the UI can do it, a script or an agent can too.

- [Schema overview](#schema-overview)
  - [Import progress](#import-progress)
  - [Parsing C](#parsing-c)
  - [Binary diffing](#binary-diffing)
  - [Firmware emulation](#firmware-emulation)
- [Transport decision](#transport-decision)
- [Versioning and compatibility](#versioning-and-compatibility)
- [Running the daemon](#running-the-daemon)
- [Clients: Python, TypeScript, MCP](#clients)
- [Backend seam and the fake backend](#backend-seam)
- [Build-time impact](#build-time-impact)
- [Known gaps](#known-gaps)

## Schema overview

| Service | RPCs | File |
| --- | --- | --- |
| `MetaService` | `GetServerInfo` (API version, features, limits), `RestartDaemon` (admins; `api_minor` 55, feature `daemon-restart`) | `meta.proto` |
| `ProjectService` | `ListProjects`, `OpenProject`, `CloseProject`, `ListPrograms`, `ImportProgram`, `GetProgramSummary`, `ListHostFiles`, `ListLanguages`, `RenameProgram`, `DeleteProgram`, `GetImportProgress` (`api_minor` 22, feature `import-progress`; [below](#import-progress)), `DetectRawLayout`, `GetRawDetectProgress`, `CancelRawDetect` (`api_minor` 23, feature `raw-detect`; [below](#raw-layout-detection)), `AddMemoryRegion`, `UpdateMemoryRegion`, `RemoveMemoryRegion` (`api_minor` 24, feature `memory-map`; [memory-map.md](memory-map.md)), `LoadPdb`, `GetSymbolSettings`, `SetSymbolSettings` (`api_minor` 49, feature `pdb-load`; [pdb.md](pdb.md)), `LoadDebugFile` (`api_minor` 86, feature `debug-files`; [backend.md](backend.md#external-debug-files)); `ImportDsdProject`, `ImportNdsRom`, `ExportDsdSymbols` (Nintendo DS games; `api_minor` 103, feature `nds`; [below](#nintendo-ds-games)); `BuildDecompKb`, `ApplyDecompKb` (`api_minor` 105, feature `decomp-kb`; [below](#decomp-knowledge-base)) | `project.proto` |
| `AssertionService` | `AppendAssertions`, `RetractAssertions`, `GetHistory`, `Blame`, `ListAssertions`, `RevertByProvenance` | `assertion.proto` |
| `QueryService` | `GetMemoryMap`, `ReadMemory`, `ListFunctions`, `ListSymbols`, `GetFunction`, `GetListing`, `GetInstruction`, `GetXrefs`, `Decompile`, `GetTypes`, `FindTypes`, `GetFunctionGraph`, `ListData`, `ListComments` (`api_minor` 77, feature `comment-table`), `ListRelocations` (`api_minor` 78, feature `relocation-table`), `GetBuildInfo` (`api_minor` 88, feature `build-info`; [build-info.md](build-info.md)), `TraceValue` (`api_minor` 89, feature `value-trace`; [below](#tracing-a-value-across-calls)), `ExportC` (`api_minor` 80, feature `export-c`; server stream), `ListSymbolTree` (`api_minor` 82, feature `symbol-tree`), `PlanClearFlow` (`api_minor` 83, feature `clear-flow`), `ListRegisterValues` (`api_minor` 87, feature `register-values`; [below](#register-values)), `GetClassHierarchy` (`api_minor` 45, feature `msvc-rtti`; [below](#msvc-classes)), `ListObjcClasses` (`api_minor` 91, feature `objc`; [below](#mach-o)); `ListCallingConventions` (`api_minor` 58, feature `calling-conventions`; [below](#calling-conventions)); batch reads for scripts `DecompileMany` and `ListInstructions` (server streams) and `FindBytes` (`api_minor` 29, feature `script-batch`; [below](#batch-reads-for-scripts), [scripting.md](scripting.md)); the searches `SearchMemory`, `SearchText`, `SearchScalars` and `SearchDecompiled`, `FindTypeUses` (`api_minor` 53, feature `type-uses`) (server streams; `api_minor` 41, feature `search`; [below](#search)); `ExportDecompScratch` (one function as a matching decompilation's scratch; `api_minor` 103, feature `nds`; [below](#nintendo-ds-games)) | `query.proto` (models in `listing.proto`, `decompile.proto`, `types.proto`) |
| `SubscriptionService` | `Subscribe` (server stream) | `subscription.proto` |
| `AnalysisService` | `ListAnalyzers`, `StartAnalysis`, `CancelAnalysis`, `GetAnalysisStatus`. Since `api_minor` 28 (feature `background-inference`, when the daemon infers prototypes: `rk-daemon --infer-prototypes auto`, the default) the analyzer `infer.prototypes` runs in the background after import as a job `GetAnalysisStatus` lists while it runs (with its phase and progress; `idle` is false until it ends), `CancelAnalysis` stops it, `StartAnalysis` with `infer.prototypes` queues it again; its prototypes reach decompilations and `GetFunction` (origin `derived: infer.prototypes`) when it finishes ([infer.md](infer.md)). Function ID (`api_minor` 51, feature `function-id`; [below](#function-id), [fid.md](fid.md)): `ListFidDatabases`, `AttachFidDatabase`, `DetachFidDatabase`, `ListFidMatches`, `ApplyFidMatch`, `RejectFidMatch`, `CreateFidDatabase`, and the analyzer `function-id` in the background after import | `analysis.proto` |
| `PluginService` | `ListPlugins`, `RunCommand`, `GetPluginFacts` (WebAssembly plugins, [plugins.md](plugins.md)) | `plugin.proto` |
| `PresenceService` | `UpdatePresence`, `ListPresence` (`api_minor` 5, feature `presence`) | `presence.proto` |
| `SyncService` | `GetSyncState`, `Pull` (server stream), `Push`, `FetchProgram`: daemon-to-daemon replication (`api_minor` 5, feature `sync`) | `sync.proto` |
| `AuthService` | `Login`, `Logout`, `WhoAmI`, `ChangePassword`, `ListUsers`, `CreateUser`, `UpdateUser`, `DeleteUser`, `ListTokens`, `CreateToken`, `RevokeToken` (`api_minor` 13, feature `auth`; [security.md](security.md)) | `auth.proto` |
| `EmulatorService` | `CreateEmulatorSession`, `RunEmulator`, `GetEmulatorState`, `WriteEmulatorRegisters`, `ReadEmulatorMemory`, `WriteEmulatorMemory`, `SetEmulatorBreakpoints`, `GetEmulatorTrace`, `ListEmulatorSessions`, `CloseEmulatorSession`: emulation sessions, the caller's state rather than facts (`api_minor` 12, feature `emulator`; [emulator.md](emulator.md#api)). Firmware on a machine (`api_minor` 20, feature `firmware-emulation`; [firmware-emulation.md](firmware-emulation.md), [below](#firmware-emulation)): `WriteEmulatorInput`, `GetEmulatorMachine`, `ListMachines`, `GetMachine`, `SaveMachine`, `DeleteMachine`, `DeriveMachine`, `ListPeripheralKinds` | `emulator.proto` |
| `TypeService` | `ParseC`: C headers or pasted declarations into types for the program's target, asserting nothing (`api_minor` 25, feature `parse-c`; [below](#parsing-c), [cparse.md](cparse.md)). `AutoStructure`: a structure from how a pointer variable is used, or from the data in a range, asserting nothing (`api_minor` 32, feature `auto-struct`; field edits and chained structures from a field: `api_minor` 56, feature `auto-struct-edit`; [below](#structures-from-pointer-use)) | `types.proto` |
| `DiffService` | `CreateDiffSession`, `ListDiffSessions`, `RunDiff`, `GetDiffStatus`, `CancelDiff`, `ListMatches`, `ListUnmatched`, `GetFunctionDiff`, `SummarizeFunctionDiffs`, `AcceptMatches`, `RejectMatches`, `SetMatch`, `ApplyMarkup`, `RevertApply`, `Unmatch`, `CompareFunctions`, `PortFunctionMarkup`: binary diffing and version tracking between two programs of a project, porting names, comments and prototypes (`api_minor` 16, feature `diff`; what changed inside a pair: `api_minor` 17, feature `diff-detail`; any two functions, markup ported between them, unmatching: `api_minor` 54, feature `function-compare`; [diff.md](diff.md), [below](#binary-diffing)) | `diff.proto` |
| `PatchService` | `Assemble`, `PatchInstruction`, `PatchBytes`, `ListPatches`, `RevertPatches`, `ExportProgram`, `DetectChecksum`, `GetExportSettings`, `SetExportSettings`, `OpenOriginal`: assembling, byte patches as assertions, export with checksum fixups (`api_minor` 27, features `patch`, `assemble`, `export-fixups`; [patching.md](patching.md), [below](#patching)) | `patch.proto` |
| `ScriptService` | `ListScripts`, `GetScript`, `RunScript` (server stream: started, output, progress, prompts, then result or error; or trust_required), `AnswerPrompt`, `CancelScript`, `UpdateContext`, `SaveScript`, `ListScriptRuns`: Python scripts the daemon runs in host processes with a run token acting as the caller (`api_minor` 31, feature `scripts-host`; [below](#scripts-the-daemon-runs), [scripting.md](scripting.md#the-daemons-script-service)); `SetupScriptPython` (server stream) makes the Python they run with (`api_minor` 33, feature `scripts-setup`); the Python console, `RunScript{interactive}` with `CompleteConsole` and `CancelScript{interrupt}` (`api_minor` 43, features `script-console`, `script-completion`; [scripting.md](scripting.md#the-console)) | `script.proto` |
| `FileSystemService` | `OpenFileSystem`, `ListFileSystem`, `ReadFileSystemFile`, `GetFileSystemFileInfo`, `ImportFromFileSystem`, `ExtractFromFileSystem`, `CloseFileSystem`, `ListFileSystems`: archives, compressed files, file system images and firmware packages as trees of files, nested to any depth; reading, describing, importing (one or a batch) and extracting their files (`api_minor` 48, feature `filesystems`; [below](#container-file-systems), [filesystems.md](filesystems.md)); `GetAndroidPackage`, `DecodeAndroidXml`, `ListAndroidResources`: an APK's manifest, resources, native libraries and methods, Flutter facts (`api_minor` 98, feature `android`; [below](#android-packages), [android.md](android.md)) | `filesystem.proto` |
| `BSimService` | `CreateBSimDatabase`, `AttachBSimDatabase`, `DetachBSimDatabase`, `ListBSimDatabases`, `IngestBSim`, `ListBSimExecutables`, `ListBSimFunctions`, `UpdateBSimExecutable`, `DeleteBSimExecutables`, `SearchBSim`: BSim signature databases, persistent stores of executables' functions and their feature vectors with an LSH index; ingesting a project's programs, listing, categorizing and deleting what is stored (`api_minor` 69, feature `bsim`); functions similar to a program's, with thresholds, filters and an overview (`api_minor` 72, feature `bsim-search`); `ApplyBSimMatches`: a match's name, signature, or signature and types applied to the queried function, one revision for many (`api_minor` 76, feature `bsim-apply`; [bsim.md](bsim.md#applying-matches)) | `bsim.proto` |
| `ProviderService` | `ListProviders`, `DecompileExternal`, `ReadProviderOutput`, `GetProviderSettings`, `SetProviderSettings`: external decompilers (ILSpy, jadx, Vineflower, CFR, unluac, pycdc, webcrack, wasm-decompile) run in a sandbox on a program's file or a file of a file system session, their output cached (`api_minor` 92, feature `external-decompilers`; [below](#external-decompilers), [providers.md](providers.md)) | `provider.proto` |
| `DebugService` | `CreateDebugSession` (the emulator, a GDB remote stub, a launched or attached process, a saved trace, a crash dump: `api_minor` 102, [below](#crash-dumps)), `GetDebugCrash`, `CloseDebugSession`, `ListDebugSessions`, `ResumeDebugSession`, `WaitDebugSession`, `InterruptDebugSession`, `GetDebugState`, `WriteDebugRegisters`, `ReadDebugMemory`, `WriteDebugMemory`, `SetDebugBreakpoints`, `SelectDebugThread`, `ListDebugModules`, `GetDebugTimeline`, `SaveDebugTrace`, `ListDebugTraces`, `DeleteDebugTrace`: debug sessions with a recorded timeline, the caller's state rather than facts; state and memory can be read at any recorded snapshot (`api_minor` 14, features `debugger`, and `debugger-live` with `rk-daemon --debug-live`). The emulator target on a machine (`api_minor` 20, feature `firmware-emulation`): `WriteDebugInput`, `GetDebugMachine`. The call stack (`api_minor` 59, feature `debugger-stack`): `GetDebugBacktrace`. Values (`api_minor` 60, feature `debugger-values`): `EvaluateDebug`; watches in a function's frame, `DebugEvalItem.frame_function` (`api_minor` 61, feature `debugger-watches`). Runtime disassembly (`api_minor` 62, feature `debugger-disassembly`): `DisassembleDebugMemory`. Copying runtime memory into the program (`api_minor` 63, feature `debugger-copy`): `CopyDebugMemory`. Conditional breakpoints (`api_minor` 64, feature `debugger-conditions`): `DebugBreakpointSpec.condition`, `ignore_count`, `disabled`, `SetDebugBreakpointsRequest.update`. Rewinding the emulator (`api_minor` 65, feature `debugger-rewind`): `RewindDebugSession`, `DebugState.rewindable`. An emulator from another session's state (`api_minor` 67, feature `debugger-emulate-from`): `DebugEmulatorTarget.from_session`, `from_snapshot`. Hooks the client answers (`api_minor` 68, feature `debugger-hooks`): `SetDebugHooks`, `AnswerDebugHook`, `DebugStop.hook` | `debugger.proto` |

**Authentication** (`api_minor` 13, [security.md](security.md)). Unless the
daemon runs with `--no-auth`, every call except `GetServerInfo`, `Login`
and `WhoAmI` carries `authorization: Bearer <token>` (a session token from
`Login` or an API token), or, from a page the daemon serves, its session
cookie plus `x-csrf-token`. Each RPC needs a role (viewer reads, editor
edits, admin imports, browses the host and manages accounts, peer
replicates) and may be limited to some projects: `UNAUTHENTICATED` without
valid credentials, `PERMISSION_DENIED` beyond them. The server stamps the
caller's identity on provenance (`user:<account>`, `agent:<token name>`):
send kind and id empty; provenance naming someone else is refused. With
authentication on, `GetServerInfo` lists `auth-required` and
`provenance-stamping`.

Shared vocabulary lives in `common.proto`.

**Plugins** (`api_minor` 6, feature `plugins`). `ListPlugins` lists the
WebAssembly plugins the daemon loaded (and rejected). `GetPluginFacts`
serves what analyzer plugins derive, each fact with `origin.derived.rule
= "plugin:<name>@<version>"`; results are memoized fact-store queries.
`RunCommand` runs a command plugin and appends its edits as one batch of
assertions with provenance `plugin:<name>@<version>` (the new
`PROVENANCE_KIND_PLUGIN`, which ranks with `AGENT`), or the calling
agent's. `ImportOptions.format` may name a loader plugin, and files the
built-in loaders reject are offered to loader plugins by magic. See
[plugins.md](plugins.md). Peripheral plugins (`PLUGIN_KIND_PERIPHERAL`,
`api_minor` 20, feature `peripheral-plugins`) are devices of an emulated
machine: `ListPlugins` lists them with their interrupt outputs, inputs
and register block size, and `EmulatorService.ListPeripheralKinds` beside
the built-in kinds.

### Addresses

`Address{space, offset}`. An empty `space` means the program's default
code/data space, which is what nearly every message uses. Varnodes name
their space explicitly (`ram`, `register`, `unique`, `const`, `stack`).
Ranges are inclusive `[first, last]`, so the last byte of a 64-bit space is
representable. In JSON, 64-bit integers are decimal strings
(`"offset": "4198464"`), following the proto3 JSON rules.

Offsets count bytes, as SLEIGH's addresses and Ghidra's
`Address.getOffset()` do, also in word-addressed spaces: AVR's
`code:0x003a` (a word address, as Ghidra and the UI show it) is offset
`0x74`. A program whose language has several memory spaces (AVR's `code`
and `mem`, the 8051's `CODE`, `INTMEM`, `EXTMEM` and `SFR`, PIC's `DATA`)
folds the other spaces' addresses into the default space's offsets, so
every address of the program is one number (`api_minor` 26, feature
`address-spaces`): `ProgramSummary.spaces` gives each memory space's
`key_base`, `word_size`, `size` and whether it `is_default` or is an
`alias` of the default space's bytes (AVR's `codebyte`), and an address in
a space is `key_base` plus its byte offset there. Responses use that form
with an empty `space`; requests (`ReadMemory`, listing windows) also take
`{space: "mem", offset: 0x100}`. To show an address as Ghidra does, find
the space with the largest `key_base` not above it and print
`name:(offset - key_base) / word_size` ([processors.md](processors.md)).

### Revisions and snapshot reads

A project is one fact database, and its **revision** is a counter shared by
all programs in it. Every commit (an append, a retraction, an import or an
analysis step) creates a new revision.

- Every read takes `ReadOptions`:
  - `revision = 0` reads head;
  - `revision = N` reads the immutable snapshot at N;
  - `min_revision = N` waits until head ≥ N (read-your-writes across
    connections, bounded by the deadline).
- Every read response carries a `Snapshot{revision, head_revision}`. To
  make a burst of reads mutually consistent while edits land (listing pages,
  decompile, xrefs for one view), pin `revision` to the first response's
  `snapshot.revision`.
- Page tokens embed the first page's revision, so paging is consistent
  without explicit pinning.
- Servers retain a window of revisions (`ServerInfo.retained_revisions`,
  `ProjectInfo.oldest_retained_revision`). Older reads fail with
  `FAILED_PRECONDITION` and a message starting `REVISION_EXPIRED`; reads
  newer than head fail with `OUT_OF_RANGE`.

### Assertions, provenance, blame

The assertion log is append-only. User, importer and agent edits are
*assertions*, each with:
- a server-assigned `seq`, the `revision` that committed it, and a time;
- a global identity `id` (`OpId{replica, counter}`) and a hybrid logical
  clock `stamp` (feature `op-ids`, `api_minor` 5). When daemons share a
  project ([collab.md](collab.md)), an entry has a different `seq` and
  `revision` on each daemon but the same `id` everywhere; `retracts_id`,
  `depends_on_id` and `retracted_by_ids` name the related entries the
  same way;
- `Provenance{kind, id, version, session, reason, tool, on_behalf_of}`,
  written in text as `kind:id[@version]` (`user:alice`, `import:elf`,
  `agent:claude@opus-5.5`, `script:fix-names@3f2a9c01b7de`). A script's
  edits (`PROVENANCE_KIND_SCRIPT`, `api_minor` 29, feature
  `script-provenance`) carry the script's name, the first 12 hex digits of
  its SHA-256 and the run as session; `on_behalf_of` names who ran it
  ("user:alice"), stamped by the server with authentication (and on an
  admin's importer provenance), so blame reads "alice via
  script:fix-names" ([scripting.md](scripting.md#edits-provenance-and-precedence)).

Undo appends a retraction; nothing is ever deleted, so every value stays
blame-able. Retracting a retraction reinstates its target.

| Body | Fact key it sets (`FactKey{program_id, kind, address, sub}`) |
| --- | --- |
| `Rename{target, name}` | `NAME@addr`; for locals `NAME@function` with `sub = "local:<storage_key>"` |
| `Retype{target, TypeSpec}` | `TYPE@addr` (a function's prototype at its entry); locals as above. Since `api_minor` 25 a `c_declaration` the C parser reads becomes a hashed type, defined by the same request (its `TYPE_DEF` assertions follow the request's in the response); text it can't read is kept as text, as before |
| `Comment{address, kind, text}` | `COMMENT@addr`, `sub` = `eol`/`pre`/`post`/`plate`/`repeatable`/`decompiler` |
| `SetFunctionBounds{entry, body, remove}` | `FUNCTION_BOUNDS@entry` |
| `FlowOverride{address, kind}` | `FLOW_OVERRIDE@addr` |
| `SetNoReturn{function, no_return}` | `NO_RETURN@entry`: whether calls to the function end their caller's flow (true) or it returns even where analysis says it doesn't (false); the address must be a function's entry (`api_minor` 66, feature `no-return`; [decompiler-inputs.md](decompiler-inputs.md#no-return)) |
| `SetFallthrough{address, target, no_fallthrough}` | `FALLTHROUGH@addr`: where control goes on after the instruction, instead of the next one (`target`), nowhere (`no_fallthrough`), or, with neither, its own again (Ghidra's Set and Clear Fallthrough; `api_minor` 85, feature `fallthrough-override`; [below](#fallthrough-overrides)) |
| `SetRegisterValue{register_name, range, value, clear}` | `REGISTER_VALUE@range.first`, `sub` = `<register>:<hex length>`: the register holds `value` over the range (`clear`: no value there), which analysis's references and the decompiler take as known (Ghidra's Set Register Values; `api_minor` 87, feature `register-values`; [below](#register-values)) |
| `SetDecompilerSettings{settings}` | `NOTE@0`, `sub` = `revkit:decompiler-settings` (reserved): how the decompiler shapes the program's C, every decompilation redone with it (`api_minor` 106, feature `decompiler-settings`; [below](#decompiler-settings)) |
| `Note{address, tag, text}` | `NOTE@addr`, `sub = tag` |
| `DefineType{TypeNode}` | `TYPE_DEF`, `sub` = the type's content hash (`api_minor` 4, feature `define-types`) |
| `BindTypeName{type}` | `TYPE_DEF`, `sub` = `name:<struct\|union\|enum\|typedef> <name>` (`api_minor` 11, feature `type-names`) |
| `Note{tag, text}` by `RenameProgram` / `DeleteProgram` only | `NOTE` with no address, `sub` = `revkit:program.name` (the name) or `revkit:program.deleted` (`api_minor` 19, feature `program-management`; refused as note tags) |
| `DiffMatch{session, entry_a, entry_b, …}` (DiffService only) | `MATCH` at B's entry, `sub` = the session (`<session>/reject/0x<A entry>` for a rejected pair) (`api_minor` 16, feature `diff`) |
| `MemoryRegionEdit{region_id, block_start, …}` (Add/Update/RemoveMemoryRegion only) | `MEMORY_REGION` at address 0, `sub` = `region:<id>` (a region added after import) or `block:<hex start>` (an edit to an image block); `""` removes it (`api_minor` 24, feature `memory-map`) |
| `ListingEdit{address, clear{length} \| disassemble{instruction_set, function} \| data{type, count, string, layout, collapsed}}` | `CODE_UNIT@address`, `sub` = `clear:<hex length>`, `code` or `data`: what the bytes are, as Ghidra's Clear Code Bytes, Disassemble and Data menu say; overlapping edits compose newest first; a data definition's type is parsed and laid out by the server, which fills `size`, `type_hash` and `type_name` and defines new types in the same request (`api_minor` 30, feature `listing-edit`; [listing-edit.md](listing-edit.md)) |
| `SetMutability{address, length, mutability}` | `MUTABILITY@address`, `sub` = the length in hex: constant, volatile, writable (`NORMAL`) or as the memory map says (`DEFAULT`) for the decompiler (`api_minor` 30) |
| `SetDataSettings{address, field \| type_name, settings}` | `NOTE@address`, `sub` = `revkit:data-settings` (the item) or `revkit:data-settings:<field>` (a struct field's row); with `type_name`, `NOTE@0`, `sub` = `revkit:data-type-settings:<type>` (the type's defaults): how a data item displays, Ghidra's Data Settings and Default Settings (`DataSettings`: format, signedness, endian, padding, charset, termination, pointer kind, mask and shift); settings with nothing set remove them. NOTE keys, so older daemons open such projects and import their archives; `Note` bodies can't use these tags (`api_minor` 84, feature `data-settings`; [listing-edit.md](listing-edit.md#data-settings)) |
| `OperandDisplay{address, operand_index, value, format \| equate{name \| enum_type_hash, member}, constant_hash, apply_to}` | `EQUATE@address`, `sub` = `<operand>:<hex value>` (or `h<hex hash>:<hex value>` for a decompiler constant no operand holds): how one scalar shows in the listing and the decompiler, Ghidra's Convert and Set Equate (`api_minor` 39, feature `equates`; [below](#equates-and-user-references)) |
| `UserReference{from, operand_index, to, type, primary, remove}` | `REFERENCE@from`, `sub` = `<operand>:<hex to>` or `i:<hex to>` (the whole instruction): a reference the user added, or deleted (`api_minor` 39, feature `user-references`; [below](#equates-and-user-references)) |
| `ImageBaseBody{image_base, previous_image_base, import_image_base}` (SetImageBase only) | `REBASE` at address 0: the program's image base; every other key of the program reads at its address moved by the base's difference from the import base, and keeps it image-relative in the log (`api_minor` 42, feature `rebase`; [memory-map.md](memory-map.md#rebase-setting-the-image-base)) |

`SetFunctionBounds`, `FlowOverride`, `SetFallthrough` and `SetNoReturn` steer function discovery on the
image backend (feature `function-discovery`): an asserted entry is a
discovery seed (an empty `body` means the body discovery finds), `remove`
says no function starts there, and an override changes the instruction's
flow as Ghidra's do; bodies, the listing, xrefs and decompilations follow
([backend.md](backend.md#function-discovery)).

`DefineType` puts a type into the program's type store, so a `Retype` can
name it by `type_hash` (which, for a function's prototype, the decompiler
uses). A `TypeNode` mirrors revkit's type model ([types.md](types.md)) and
refers to other types by hash or, for types defined together (recursive
structs), by `assertion_index` within the same request; the server interns
the request's types as one batch, so equal types get equal hashes, and stores
each body with its references as hashes. `validate_only` returns the hashes
(in each key's `sub`) without committing, so a client can retype by hash in
the same atomic request. `GetTypes` describes each type field by field
(`kind`, `rank`, pointer and array targets, fields, enumerators, parameters;
feature `type-details`).

**Editing a type.** A hash names one immutable definition, so editing
`struct point` defines a new one. `BindTypeName` (`api_minor` 11, feature
`type-names`) makes a named struct, union, enum or typedef *the
program's* definition of its name, the way an edit in Ghidra's data type
manager reaches every use: wherever a type of that kind and name is used
(an asserted or debug-info prototype, a global's or variable's displayed
type, a field of another type), the decompiler and every display use the
bound definition instead (`types.resolved`, [backend.md](backend.md)).
`GetTypes` is unaffected. An editor defines the new version and binds it
in one request (`bind_type_name.type.assertion_index`); retracting the
binding restores the previous one (or none), so undo is one retraction.
Rebinding a name invalidates `TYPES`, `FUNCTION_LIST`, the whole
`LISTING` and the decompilations served so far. Bindings follow assertion
precedence like any key, and only explicit bindings substitute: two DWARF
units defining one name differently stay as they are.

Local variables are named by `storage_key` (`param:0`, `register:EAX@0x40104b`,
`stack:-0x14`), which `Decompile` returns on every variable. Renaming one
doesn't change its identity.

How assertions resolve:
- **Precedence.** When assertions on one key conflict, the store picks the
  winner: user > import = migration > agent = plugin = script > analysis,
  and the later one
  among equals, "later" meaning the higher `(stamp, id.replica,
  id.counter)`, which every daemon agrees on and which never puts an edit
  before one its author had seen. `Blame.concurrent_seqs` lists live
  losers of the winner's rank made concurrently with it (by another
  person or daemon, without seeing it). `Blame` returns the effective value, its origin (the winning
  assertion, or the derivation when only analysis supplies a value) and
  every candidate with its status (`EFFECTIVE`, `SHADOWED`, `RETRACTED`,
  `DEPENDENCY_DEAD`). `GetHistory` returns every entry touching a key, oldest
  first.
- **Bulk revert.** `RevertByProvenance` reverts a matching author's work in
  one revision, following the fact store (`FactDb::Transaction::revert`):
  every assertion and every retraction they made is retracted, live or
  not. Retracting their retractions restores what they removed, and
  retracting their already-retracted assertions means a later undo of one
  of their retractions cannot revive them. A full revert therefore reads as
  if the author had never acted; it is itself undoable. The usual filter is
  `{kind: AGENT, session: <run id>}`, or `{session: <run id>}` for a script
  run; `on_behalf_of` (`api_minor` 29) narrows a filter to what someone's
  scripts did, here and in `ListAssertions`.
- **Batches.** `AppendAssertions` is atomic: one revision, or an
  `INVALID_ARGUMENT` naming each refused body and why (`assertions[1]:
  name contains whitespace...; assertions[4]: ...`, the first 20, then how
  many more). With `skip_invalid` (`api_minor` 104, feature
  `assertion-refusals`) the bodies that validate land in one revision and
  `AppendAssertionsResponse.refused` lists the others (`RefusedAssertion{index,
  reason}`; no revision when every body is refused; `define_type` bodies are
  checked together, so one that doesn't parse still refuses the batch). It
  supports `validate_only` and optimistic concurrency
  (`expected_head_revision` → `ABORTED`).
- **Provenance on reads.** Values that queries return carry a
  `FactOrigin`: either `asserted{seq, provenance}` or
  `derived{rule, inputs, confidence, computed_at_revision}`. That covers
  function names, bounds and prototypes, labels, comments, variable names and
  types, xrefs and memory blocks, so a UI can show who said what without a
  second call.

### Result evidence

`api_minor` 97, feature `result-evidence`. A read says what it rests on and
what it leaves unknown, so a client (an agent above all) can tell "there is
no caller" from "no caller was found".

- **Source tiers.** `FactOrigin.tier` (`SourceTier`) says how far to trust a
  value, from who said it. It is for reading, not precedence: which
  assertion wins is still the fact store's rule above.

  | Tier | From |
  | --- | --- |
  | `USER` | a person (`user:`) |
  | `DEBUG_INFO` | DWARF, PDB, a debug file, Go's pclntab (`import:dwarf`, `import:pdb`, `analysis:go`) |
  | `SYMBOL` | the file's own tables and metadata: symbols, imports, sections, PE and Objective-C structures, RTTI, demangled names (`import:<format>`, `analysis:pe`, `derived:names.loader`, `derived:analysis.demangler`) |
  | `LIBRARY` | a library match: Function ID, a type archive's prototype (`analysis:fid`, `derived:library:<archive>`) |
  | `AGENT` | an agent, plugin or script (`agent:`, `plugin:`, `script:`): a claim with a reason |
  | `INFERRED` | analysis from rules that follow from the bytes: bounds, xrefs, strings, parameter ID, the decompilation itself; markup ported by a comparison |
  | `GUESSED` | a heuristic below 0.9 confidence: the decompiler's variable names (0.5) and types (0.6), its prototype without parameter ID (0.7) |
  | `DEFAULT` | a placeholder: `FUN_00401000`, `DAT_...` |

  The rule is `TierOf` in `src/backend/api_util.cc`; the SDK's
  `revkit.evidence.source_tier` applies the same rule when an older daemon
  left the tier unset.
- **Unknowns.** `DecompiledFunction.unknowns` and, from `GetFunction` (not
  the lists), `Function.unknowns` are `Unknown{kind, address, detail}`:

  | `UnknownKind` | Meaning |
  | --- | --- |
  | `INDIRECT_CALL` | a call through a register or memory whose target nothing resolved: no reference (call, user reference, import slot) and, in a decompilation, no named callee |
  | `INDIRECT_JUMP` | a computed jump with no recovered destinations (a switch table analysis couldn't read; a thunk's jump through its slot doesn't count) |
  | `FLOW_TRUNCATED` | analysis stopped following the function at its instruction limit |
  | `DECOMPILE_FAILED` | the decompiler failed (`DecompileResponse.failure` says how) |
  | `ANALYSIS_RUNNING` | parameter ID, inference or Function ID still running on the program: prototypes, types and names may change |
  | `BUDGET` | a limit cut the list (at most 64 indirect calls and jumps are listed per function, then a count) |
  | `NOT_ANALYZED` | code analysis was skipped (an IL-only .NET assembly) |

  An unknown's absence is the claim: a decompilation with no
  `INDIRECT_CALL` resolved every call it makes. The flow facts come from
  analysis's flow graph (`analysis::Flow`), the same memoized query the
  listing and Clear Flow use, so they cost one lookup per function.
- **Staleness.** Every response's `Snapshot` (`revision`, `head_revision`)
  already said which revision it read; `revision < head_revision` means a
  later edit may have changed it.

### Queries

- **Functions.** `ListFunctions` filters by name and range, sorts by address
  or name, and paginates; `offset` (with no page token) starts at a
  position, for virtualized lists (`api_minor` 7, feature
  `function-list-offset`). `GetFunction` looks up by entry or by
  `containing: true`. Since `api_minor` 19 (feature
  `function-list-filters`) it also sorts by body size and by references
  to the entry (`FunctionSort` `SIZE`, `XREFS`; ties in address order),
  any sort `descending`, and filters by naming (`named`: `NAMED`, or
  `UNNAMED` for `FUN_` defaults), thunks (`ONLY`, `EXCLUDE`) and
  `decompile_failed`; each `Function` carries `size`, `xref_count` and
  `decompile_failed` (the last decompilation this daemon served for it,
  or parameter ID's, failed; functions not yet decompiled are false).
  `prototype` is the asserted prototype (a user's, an agent's, debug
  info's; a function type asserted by hash is printed with the function's
  name), else the signature parameter ID committed (`prototype_origin`
  derived from `analysis.param_id`), else empty. Since `api_minor` 39
  (feature `demangle`, [demangle.md](demangle.md)) names from mangled
  symbols are demangled (`geo::Shape::scale`; `Function.demangled` and
  `Symbol.demangled` give the mangled spelling and the demangler's full
  output), `name_contains` and `ListSymbols.name_equals` match either
  spelling, and a function's mangled signature gives its `prototype`
  (`derived: analysis.demangler`) under the user's and the debug info's and
  over an agent's, inference and parameter ID. Since `api_minor` 50 (feature
  `library-types`) a function the library archives declare by name (an
  import's stub, a like-named function) shows the archive's prototype
  with origin `derived: library:<archive>` (`library:libc-lp64`), under
  asserted ones and over inference and parameter ID, and the daemon's
  decompilations give a printf- or scanf-like call with a constant format
  exactly the arguments the format names
  ([types.md](types.md#library-prototypes)).
- **A program's compiler and size.** `ProgramInfo.compiler_spec_id` (the
  compiler specification, `gcc`, `windows`, `default`) and `file_size`
  (the imported file's bytes) come with every `ProgramInfo`, so a project
  window can show them without loading each program (`GetProgramSummary`
  has them too, but reads the program). Older daemons leave them empty
  and 0; no feature flag.
- **Program management** (`api_minor` 19, feature `program-management`).
  `RenameProgram` gives a program a display name (`ProgramInfo.name`; its
  `program_id` never changes, so links, diff sessions and agents' notes
  keep working; an empty name restores the imported one). `DeleteProgram`
  deletes softly: `ListPrograms` and `OpenProject` stop listing the program
  and `ProjectInfo.program_count` stops counting it, but every fact stays
  in the log and the id keeps answering reads, so open windows, diff
  sessions and history still work. Both are assertions on the program's
  record (keys in the table above), with provenance, blame and
  precedence like any edit, and replicated to peers: `RetractAssertions`
  on the returned `assertion.seq` (same `program_id`) undoes a rename or
  restores a deleted program. `ListPrograms` with `include_deleted` lists
  deleted programs too (`ProgramInfo.deleted`, `deleted_origin` naming the
  assertion to retract), which is what a trash view reads; a deleted
  program can't be renamed until restored. Renaming needs editor,
  deleting admin (as importing does); restoring is a retraction, which
  editors may make. Subscribers get a `PROGRAM` invalidation for the
  program. **Decision:** a soft delete, because the project is one
  append-only fact database: removing a program's facts would mean
  rewriting the log, and an accidental delete must be undoable like every
  other edit. A purge that reclaims the space (rewriting the project
  without a deleted program) is not offered yet; until then a deleted
  program costs its disk space and nothing else (its derived facts are
  computed only when read).
- **Folders** (`api_minor` 37, feature `project-folders`). Programs live
  in a tree of folders, as in Ghidra's project window. `CreateFolder`
  (in `parent_id`, empty for the root), `RenameFolder`, `DeleteFolder`
  (only an empty one: no subfolders and no listed programs) and
  `MoveToFolder` (programs and folders into a folder, in one revision)
  edit it; `ListPrograms` and `OpenProject` return every folder
  (`ProjectFolder`: id, parent, name, path, origin; parents first) and
  each program's `folder_id`, `folder_path` and `folder_origin`. Folder
  ids are opaque and stable across renames and moves; paths are for
  people ("/libs/json"). A folder is one assertion on the project's own
  records, keyed by its id (`"<parent id>/<name>"`, `""` once deleted),
  and a program's folder one on its record, so both have provenance,
  blame and undo, replicate to peers and survive a reopen; a project from
  before folders has every program at the root. Undo is
  `RetractAssertions` with **`project_id`** (and no `program_id`): it
  retracts the project's own ops (folders) or any of its programs'.
  Subscribers get a `PROJECT_TREE` invalidation (with the program's id
  for a move, empty for a folder), whatever programs they filter on.
  Locally a sibling can't repeat a folder's name and a folder can't move
  into itself; concurrent edits on two daemons can still leave two
  siblings with one name (their ids tell them apart) or a cycle, which
  every daemon breaks the same way: the lowest folder id of the cycle
  hangs from the root. Folders nest at most 64 deep. Creating, renaming,
  moving and deleting folders need editor.
- **Project archives** (`api_minor` 37, feature `project-archive`;
  [backend.md](backend.md#project-archives) has the format). A whole
  project, some programs or a folder become one `.rkproj` file holding
  the programs' files, their fact logs (every edit with its history and
  provenance, debug-info imports, types, diff sessions between exported
  programs), the folder layout and memory-map regions' bytes; nothing
  derived. `ExportProject` streams it: an `ExportSummary` (a file name,
  the manifest), then the bytes in messages of at most 1 MiB; with
  `host_path` the daemon writes it on its own host instead (admin).
  `annotations_only` leaves the programs' files out: each is found again
  by SHA-256 on import. `ImportProjectArchive` takes the archive as a
  host path (admin), bytes (at most the daemon's message size) or an
  upload (`UploadChunk`: pieces in order, up to 16 GiB, the caller's
  alone, forgotten an hour after the last piece), and imports it into a
  new project (`new_project_name`, default the archive's; its id is the
  name with anything but letters, digits, `.`, `_` and `-` replaced) or
  into `project_id` as new programs under `folder_id`, folders of the
  same path reused. A program whose name is taken in its folder gets
  " (2)" (a rename the importer can undo, reported in `warnings`).
  Annotations-only binaries come from `binaries` (files matched by
  SHA-256, in any order), the target project's programs, then
  `search_dir` on the daemon's host (admin); `skip_missing` imports the
  rest, `inspect_only` only describes the archive and where each binary
  was found. The archive is checked in full before anything is touched
  (format and version, every path, size and hash, every op of the log);
  one this daemon can't read is refused with the reason (a newer
  `format_version`: `FAILED_PRECONDITION` saying so; a malformed one:
  `INVALID_ARGUMENT`). Imported ops keep their provenance, stamps and
  history, so blame, undo and reverts work as on the original; the
  import itself is recorded as `import:archive` on behalf of the caller.
  Exporting needs viewer of the project; importing needs admin
  ([security.md](security.md#roles)). `rk-daemon project export|import`
  does the same on a project directory no daemon is using.
- **Host files.** `ListHostFiles` lists a directory on the daemon's host so
  a client can pick a file to import by path (`ImportProgram.path`) without
  uploading it or opening a native file chooser. Only directories under the
  daemon's `--browse-root` roots are listed; paths are canonicalised first, so
  neither `..` nor a symlink leaves a root, and without roots it answers
  FAILED_PRECONDITION. It returns names, sizes and times, never contents.
  Added in `api_minor` 10 (feature `host-files`).
- **Languages.** `ListLanguages` lists every processor language the daemon's
  Ghidra install defines (id, processor, byte order, address size, variant,
  description, compiler specs), for picking `ImportOptions.language_id` on a
  raw import. Deprecated ones only with `include_deprecated`. Any viewer may
  call it. Added in `api_minor` 15 (feature `languages`).
- **Raw images.** `ImportProgram` with `options.format = "raw"` (`api_minor`
  9, feature `raw-import`) loads a flat binary such as firmware the way
  Ghidra's Raw Binary loader does: the file's bytes as one block at
  `image_base` (0 when `has_image_base` is false), read/write/execute
  unless `raw_permissions` says otherwise (`"r-x"`). `language_id` is
  required (`"ARM:LE:32:v4t"`, compiler in `compiler_spec_id`);
  `raw_offset` skips a header, `raw_length` (0: to the end) bounds the
  image, `entry_point` adds an entry, and `regions` declares more memory
  (`MemoryRegion`: name, start, size, permissions, `initialized`,
  `is_volatile`), such as RAM and memory-mapped I/O. The layout is part of
  the program's record, so a persistent project reopens identically.
  Memory can also be added, changed or removed after import, for any
  format (the memory map, below).
  Discovery searches raw images for functions as firmware needs
  ([firmware.md](firmware.md)). Raw options without `format: "raw"` are
  `INVALID_ARGUMENT`. `raw_format` (`api_minor` 26) says what the file
  holds: `"binary"`, `"ihex"` (Intel HEX) or `"srec"` (Motorola
  S-records), or empty to tell by content; a HEX or S-record file gives a
  block per contiguous run of its records at their addresses and its start
  address as the entry. `raw_space` loads the image in another memory space
  (an 8051 data dump in `EXTMEM`) and `MemoryRegion.space` puts a region in
  one; the language's processor spec adds its default blocks (AVR's SRAM
  and I/O) and labels ([processors.md](processors.md)).
- **Symbols.** `ListSymbols` finds functions and labels (globals, imports,
  `LAB_`/`DAT_` defaults, and any address with an asserted name) by
  substring (`name_contains`) or exact name (`name_equals`), filtered by
  kind and range, in address order. It is what "go to symbol" uses. Added
  in `api_minor` 2 (feature `symbols`); older daemons answer
  `UNIMPLEMENTED`.
- **Listing.** `GetListing` takes a **row window** (`first_row`, `row_count`,
  for virtual scrolling with `total_rows`) or an **address window**
  (`start`, `end`, `max_rows`, `rows_before`, to jump to and centre on an
  address).
  - Rows are instructions, data or coalesced undefined runs. Each has bytes,
    labels, comments, containing function, xref count and display tokens.
  - Tokens are typed: `MNEMONIC`, `REGISTER` with its varnode, `SCALAR`
    with its value, `SYMBOL`/`ADDRESS` with a navigation target, and so on.
    Concatenating token texts gives the display string.
  - Row numbers are only meaningful together with the response's revision.
  - With `header_rows` (`api_minor` 7, feature `listing-header-rows`), the
    display lines above each code unit are rows too, of kind `HEADER` with
    a `header` saying what they show, in Ghidra's order: plate comment
    lines, a function's signature (the asserted prototype, else
    `undefined name()`), the label, pre-comment lines. Row numbers,
    `total_rows` and the windows a client applies from subscriptions
    (`header_rows` there) are then in this numbering. An address window
    anchors on the code unit, with its header rows counting toward
    `rows_before`.
  - Instruction rows carry their `flow` after any override, their static
    `flow_targets` (branches, calls, jump-table cases) and the effective
    `flow_override` with its origin (feature `listing-flow`), which is what
    a client draws flow arrows from. A non-data row whose address has an
    asserted type shows it as `data_type`.
- **Instructions.** `GetInstruction` returns the decoded instruction,
  operands with their references, flow kind and targets, the effective flow
  override, and raw SLEIGH p-code. `PcodeOpcode` values equal Ghidra's
  `CPUI_*`, and `mnemonic` is always set for display.
- **Xrefs.** `GetXrefs` takes an address or a range and a direction
  (`TO`/`FROM`/`BOTH`). Each xref names the containing function of
  `from_address` and the symbol at `to_address`. A user reference
  (`UserReference`, api_minor 39) has its assertion as `origin` and
  `primary` when it is its operand's primary one; a reference the user
  deleted isn't listed ([below](#equates-and-user-references)).
- **Decompilation.** `Decompile` returns structure, not just text:
  - `lines` of `CodeToken`s with Ghidra-compatible kinds;
  - each token's source instruction `address`, its `varnode_indices` into a
    per-function SSA varnode table (with defining address and owning
    variable), its `variable_index` into `variables`, and a navigation
    `target` for function and global names; a FIELD token's
    `parent_type_hash` (the struct or union it is a member of, for
    `GetTypes`) and `field_offset` (api_minor 38, feature `field-tokens`),
    what Rename Field and Retype Field in the UI act on;
  - `prototype` (C text, return type, parameter indices, calling
    convention), `variables` with `storage_key`, and the plain `text` on
    request.
  - **Failures** (`api_minor` 8, feature `decompile-failures`). Ghidra's
    decompiler runs in worker processes ([decompd.md](decompd.md)), so a
    crash, a hang or running out of memory costs one function. The
    response is then OK with `failure` set (`DecompileFailure`: `kind`
    `SEGV`/`FPE`/`ABORT`/`TIMEOUT`/`OOM`, the input bundle's
    `bundle_hash`, the `decompiler_build`, the `deadline_ms` in force,
    the worker's `stderr_tail`, a `detail` such as `SIGSEGV` or "killed at
    the 39.5 s deadline") and `function` holding only an error line. A
    run past its timeout (`DecompileOptions.timeout_ms` or the server's)
    or the server's varnode bound is a `TIMEOUT` or `OOM` failure too:
    servers before api_minor 8 answered those with `DEADLINE_EXCEEDED`
    and `RESOURCE_EXHAUSTED`. A failure is the function's result until
    its inputs or the decompiler change; a `TIMEOUT` (`can_escalate`)
    may be retried once with a longer deadline, `DecompileOptions.escalate`
    with `timeout_ms` (default four times the failed deadline), whose
    result then stands for that bundle (`escalated`). Escalating again, or
    another kind of failure, is `FAILED_PRECONDITION`.
    `DecompileOptions.include_bundle` returns the bundle itself
    (`DecompileFailure.bundle`): `rk-decompd --bundle FILE` reproduces the
    failure without the daemon. A client that goes away still gets
    `CANCELLED`.
- **Types.** `GetTypes` resolves content hashes, optionally with transitive
  dependencies. A hash covers a type's canonical form *including the hashes
  of the types it references*, so `GetTypes` results can be cached forever
  across revisions and programs. `FindTypes` searches the program's named
  types (structs, unions, enums, typedefs) by name, kind and source
  (`api_minor` 11, feature `find-types`; earlier image backends returned
  nothing): its own (`TYPE_SOURCE_PROGRAM`: debug info and `DefineType`,
  origin the assertion) and the library archives applied to its imports
  (`TYPE_SOURCE_LIBRARY`: revkit's own, `libc-lp64` for 64-bit ELF or
  the Windows DLLs' for PE, then Ghidra's `generic_clib_64` or
  `windows_vs12_64` for names they lack; origin `derived:
  library:<archive>`, the archive the type came from; `api_minor` 50,
  feature `library-types`, [types.md](types.md#library-prototypes)). Library
  types are described, referenced by `DefineType` and applied by hash like
  the program's own, without being asserted. A name bound to another
  definition is listed once, `bound`; `include_superseded` adds the
  definitions it replaced (`superseded`). For a category tree that loads
  lazily (`api_minor` 19, feature `find-types-tree`), `name_prefix`
  narrows to names starting with a prefix (a namespace, `std::`, or an
  initial letter) and `summary_only` leaves out fields, enumerators and C
  definitions; `page.total_count` with a page size of 1 counts a branch.
- **Function graphs.** `GetFunctionGraph` (`api_minor` 11, feature
  `function-graph`) returns a function's basic blocks, each with its
  instructions as listing rows (tokens, flow, targets, labels, comments),
  and the edges between them by kind: `FALL_THROUGH`, `CONDITIONAL_TRUE`
  (taken), `CONDITIONAL_FALSE`, `UNCONDITIONAL`, `SWITCH` (a recovered
  jump table's cases). A block starts at the entry, at a jump target and
  after a block-ending instruction (branch, jump, return, computed jump,
  halt, a call to a no-return function, a tail call, an instruction with
  a fallthrough override); calls don't end blocks. A fallthrough
  override's address starts a block too, with a `FALL_THROUGH` edge to it
  (none for no fallthrough). Blocks control leaves the function from are
  `exit`. Cut at 50,000 instructions (`truncated`).
- **Defined data.** `ListData` (`api_minor` 11, feature `data-list`)
  lists the program's defined data in address order: data analysis's
  strings, pointers and accessed `undefinedN`, and globals whose type is
  asserted, each with its value (a string's characters, a pointer's
  target), label, reference count and origin; filtered by category and
  text, paged by token or `offset`.
- **Comments.** `ListComments` (`api_minor` 77, feature `comment-table`)
  lists every comment of the program (Ghidra's comment window) in address
  order, then kind: its kind, text, the function it is in, the address's
  label and who wrote it; filtered by kinds, text (case-insensitive) and
  an address range, paged by token at one revision. The UI's Comments
  view ([ui.md](ui.md#comments)), the SDK's `Program.comments()` and MCP
  `list_comments` use it.
- **Data settings** (`api_minor` 84, feature `data-settings`). A DATA
  row's tokens show its value as its settings say (`SetDataSettings`
  above), and the row carries them: `data_settings` (its own: the item's,
  for a struct field its own) with `data_settings_origin`,
  `data_settings_type` (the type its defaults are kept by: the element's
  C type, or `string`, `unicode`, `pointer`, `undefined4` for data
  analysis's rows) and `data_type_settings` (that type's defaults).
  Listing search (`SearchText`) reads the rows as shown.
  [listing-edit.md](listing-edit.md#data-settings).
- **Build info** (`api_minor` 88, feature `build-info`;
  [build-info.md](build-info.md)). `GetBuildInfo` reads the build metadata
  the toolchain left in the file: `go` (Go 1.13 and later: `go_version`,
  the main package `path`, `main` and `deps` modules with `version`,
  `sum` and `replacement`, `settings` such as `-ldflags`, `GOOS`,
  `GOARCH`, `CGO_ENABLED`, `vcs.revision`, `vcs.time`; `format` "inline"
  for Go 1.18 and later or "pointer" before; the header's `address`; the
  `module_text` and the lines it didn't take, `unparsed`), `rust`
  (cargo-auditable's `packages` with `name`, `version`, `source`, `kind`,
  `dependencies` as indexes and the `root`), `rustc_version` (an ELF's
  `.comment`) and `rustc_commits` (`/rustc/<hash>/` paths). Unset when the
  file has none; metadata that is there but doesn't decode is a line in
  `warnings`. The UI's Build info… ([ui.md](ui.md#build-info)), the SDK's
  `Program.build_info()` and MCP `build_info` use it. Since `api_minor`
  93 (feature `go-pclntab`; [go.md](go.md)) also `go_pclntab`, a Go
  program's function table (kept by stripped binaries): its `layout`
  ("1.2", "1.16", "1.18", "1.20"), `address`, `function_count` and
  `functions_read`, `file_count`, `text_start`, `moduledata` and
  `found_by` ("section", "symbol", "scan").
- **Go programs** (`api_minor` 93, feature `go-pclntab`; [go.md](go.md)).
  At import a Go program's pclntab names its functions as `analysis:go`
  assertions (function bounds, names where the file's symbols and the
  debug info name nothing, a plate comment with each one's source file
  and line, no-return marks for Go's runtime functions that never return;
  the import's warnings count them), and a Go program on amd64 (Go 1.17
  and later), arm64 (1.18 and later) or i386 gets Ghidra's golang
  compiler spec (`compiler_spec_id` "golang"), whose default prototype is
  Go's register ABI. `ListSymbolTree` puts a Go program's functions in
  namespaces by package path.
- **Register values** (`api_minor` 87, feature `register-values`).
  `ListRegisterValues` lists the ranges where a register holds a value,
  by register then address, with who set each: an assertion
  (`SetRegisterValue`, its `key`) or analysis's default from the loader
  (`origin.derived.rule` `analysis.register_values:mips-gp`); filtered by
  register and address range, paged. `registers` names the registers
  values may be set on ([below](#register-values)).
- **Clear Flow and Repair** (`api_minor` 83, feature `clear-flow`).
  `PlanClearFlow` plans Ghidra's Clear Flow and Repair from an instruction
  (`follow_calls`: into its callees too): the `ranges` whose ClearCode
  edits clear the code only that flow reaches, the `instructions` it
  reaches, the ones other code reaches and that stay (`kept`), and the
  `functions` whose entries go. It writes nothing; a client asserts the
  ranges in one `AppendAssertions` (one undo step;
  [listing-edit.md](listing-edit.md#clear-flow-and-repair)).
- **Symbol tree** (`api_minor` 82, feature `symbol-tree`).
  `ListSymbolTree` lists one level of Ghidra's symbol tree: with no
  `path`, the folders Imports, Exports, Functions, Labels, Classes and
  Namespaces with their sizes (`children`); `["Imports"]` the libraries
  (`<EXTERNAL>` when the file doesn't say), `["Imports", lib]` its imports
  (at the thunk, else the slot); `["Exports"]`, `["Functions"]`,
  `["Labels"]`; `["Classes"]` every class by its qualified name (the
  demangler's scopes and MSVC RTTI's), `["Classes", "geo::Circle", ...]` a
  class's members and inner classes; `["Namespaces", "geo", ...]` a
  namespace's inner namespaces, classes and symbols. Namespaces come from
  the effective names at the revision (split at the top-level `::`), so a
  rename into `ns::name` moves a symbol. Each node has `name` (within its
  scope), `kind`, `address` (symbols), `full_name` and `children`;
  `name_contains` filters a level, paged by token. The UI's Symbol tree
  ([ui.md](ui.md#symbol-tree)), the SDK's `Program.symbol_tree()` and MCP
  `symbol_tree` use it.
- **Export C** (`api_minor` 80, feature `export-c`). `ExportC` is
  Ghidra's C/C++ exporter as a server stream: the request's `functions`
  (or `all`) decompiled at one revision, as `DecompileMany` would, with
  progress messages (`done` of `total`) meanwhile; then a message with the
  file names (`<name>.c`, and `<name>.h` with `header`) and the header,
  then the source in parts of at most 1 MiB in address order, and a
  `finished` message with the count and the entries the decompiler failed
  on (the source says why in a comment). The header has Ghidra's built-in
  type names, the program's named types (as `ExportTypeArchive` with
  `TYPE_ARCHIVE_SCOPE_ALL` writes them, with its `notes`), a typedef of
  each tag, and each function's prototype. The UI's Export C/C++…
  ([ui.md](ui.md#export-c)), the SDK's `Program.export_c()` and MCP
  `export_c` use it.
- **Relocations.** `ListRelocations` (`api_minor` 78, feature
  `relocation-table`) lists the relocations the file carries, in address
  order (Ghidra's relocation table): ELF dynamic and object relocations,
  and a PE's base relocations (`format` says which). Each has its raw
  `type` and `type_name`, a `kind` (RELATIVE, IRELATIVE, JUMP_SLOT,
  GLOB_DAT, ABSOLUTE or OTHER), the `symbol`, the `addend` (explicit for
  RELA, else the stored word), the `target` when it points into this
  program (with `target_name`) and the `original` bytes there; filtered by
  an address range and a text in the symbol or type name, paged by token at
  one revision. The UI's Relocations view ([ui.md](ui.md#relocations)), the
  SDK's `Program.relocations()`, MCP `list_relocations` and the Ghidra
  shim's `getRelocationTable()` use it.
- **Memory map** (`api_minor` 24, feature `memory-map`;
  [memory-map.md](memory-map.md)). `GetMemoryMap` lists every program's
  blocks, whatever its format, in address order: the image's own (as
  edited) and the regions added since import, each with its range,
  permissions, `initialized`, `is_volatile`, `source` (`IMAGE` with the
  file offset, `FILE` with another file's name, offset, length and
  sha256, `ZERO`, `NONE`), `region_id` (added regions), `edited` (image
  blocks) and `origin` (the loader, or the assertion that added or last
  changed it); `rejected` lists added regions the map can't place (an
  overlap after an undo or concurrent edits) with the reason.
  `ProjectService.AddMemoryRegion` adds uninitialized RAM, zero-filled
  memory, memory-mapped I/O (`is_volatile`) or bytes from another file
  (`path` on the daemon's host, which needs admin as `ImportProgram` does,
  or uploaded `content`; `file_offset`, `length`; `size` 0 = their
  length), Ghidra's "Add To Program"; `UpdateMemoryRegion` changes a
  region (`region_id`: name, start, size, permissions, initialized,
  volatile) or an image block (`block_start`: name, permissions,
  volatile); `RemoveMemoryRegion` removes a region or reverts a block's
  edits. Each is one `MEMORY_REGION` assertion, returned for undo
  (`RetractAssertions`); overlaps and wrapping are `INVALID_ARGUMENT`
  naming the block, as the raw loader words them; `validate_only` checks
  without asserting. Discovery, references, data, the listing, the
  decompiler and the emulator follow the map; subscribers get the
  program in `invalidate_all_programs` and a `MEMORY` invalidation.

### Changing a program's language

`api_minor` 73, feature `set-language`. Ghidra's Set Language, and a way to
tell processor variants apart.

- **`ProjectService.SetProgramLanguage`** moves a program to another
  language (and compiler spec) in place: the same bytes at the same
  addresses, so every name, comment, type and other edit stays, and
  analysis, the listing and the decompiler run again in the new language.
  It is one `FACT_KIND_LANGUAGE` assertion (address 0 in the program, the
  value `"<language>|<compiler>"`, the body `ProgramLanguageBody`),
  replicated and undone like any edit; `language_id` empty goes back to the
  language the program was imported with, an empty `compiler_spec_id`
  takes the language's default. It persists, survives a rebase (and a
  rebase survives it), and reaches peers and project archives.
  `validate_only` checks without changing anything.
- **Analyzed before it is published.** The call returns once the program
  has been analyzed in the new language (the import's analysis, in
  parallel: about as long as the import's). Until then the change isn't
  published: every read still gets the previous revision, so views keep
  what they show, and then find the new analysis done. With a
  `progress_id` (`api_minor` 74, feature `language-progress`), the switch
  is followed as an import is: `GetImportProgress` with the program's
  project and the id as `import_id`, through `LOADING`, `FUNCTIONS` and
  `DATA` to `DONE` ("In ARM:LE:32:v7: 4,581 functions").
- **Refused:** an unknown language or compiler spec (`INVALID_ARGUMENT`); a
  language that lays memory out differently (other address spaces, address
  or word sizes: AVR's code and data spaces after ARM's single space), whose
  facts couldn't move in place (`FAILED_PRECONDITION`: import the file
  again in it); a program a loader plugin loaded.
- **`ProjectService.CompareLanguages`** answers "is it v5, v7 or v8?": every
  variant of the program's processor in its byte order (both modes where
  the processor has them: ARM and Thumb) swept over up to 24 samples of
  4 KiB of its executable bytes, as auto-detection sweeps a raw file. Each
  `LanguageFit` gives the share of bytes decoded, invalid and unimplemented
  instructions, the instructions control flow reaches and the reached runs
  cut short, whether it is the current language, and whether
  `SetProgramLanguage` would accept it. The one auto-detection picks (the
  least capable variant that decodes the code as fully as any, with
  Thumb-2 and Cortex-M vector evidence) is `recommended`, with why in
  `note`. `language_ids` compares others (the other byte order, say).
  Typically a few seconds.

SDK: `Program.set_language(language_id, compiler_spec_id="")`,
`Program.compare_languages()`. MCP: `compare_languages`, `set_language`.

### Mach-O

`api_minor` 90, feature `macho` ([macho.md](macho.md)). The loaders read
Mach-O files (thin, and universal ones' slices) as Ghidra's Mac OS X
Mach-O loader does; `ProgramInfo.format` is `macho`.

- **Slices.** A universal file loads its first `arm64`/`arm64e` slice,
  else its first `x86_64` one, else its first; `ImportOptions.macho_slice`
  names another by its arch (`x86_64`, `arm64e`, `armv7`, `i386`, ...) or
  index (`#1`), and a slice the file lacks is `INVALID_ARGUMENT` naming the
  ones it has. `ProgramInfo.macho_slice` is the slice a program is and
  `macho_slices` the file's slices (both empty for a thin file).
  `ImportProgramRequest.program_file` (a `source` beside `path` and
  `content`) imports a program's stored file again, from the same project
  (`NOT_FOUND` otherwise): with `macho_slice`, the file's other slice,
  named `<program>-<slice>` by default. The program keeps the whole file:
  `sha256` is the universal file's.
- **The summary.** `ProgramSummary.macho` (`MachoSummary`): arch, CPU type
  and subtype, file type (`execute`, `dylib`, `bundle`, `object`, ...),
  `LC_UUID` as dyld prints it (`build_id` has it as lower-case hex), the
  platform, minimum OS and SDK (`LC_BUILD_VERSION`, else
  `LC_VERSION_MIN_*`), source version, install name, dylinker, the dylibs
  (`MachoDylib`: install name, kind `load`, `weak`, `reexport`, `lazy` or
  `upward`, versions), rpaths, the slices (`MachoSlice`: arch, CPU, offset,
  size) and `slice_index`, `code_signed`, `encrypted` with the encrypted
  range, `fixups` (`chained`, `opcodes` or empty) and the header flags.
- **Libraries.** A Mach-O's `needed` are its dylibs' install names; one
  resolves to a program named as its file or with that install name, an
  import to its own dylib first (two-level namespace); `import_libraries`
  expands `@executable_path`, `@loader_path` and `@rpath` (the loading
  image's `LC_RPATH`s, then its loaders', `api_minor` 100;
  [apple-apps.md](apple-apps.md#libraries-in-a-bundle)), then looks for each
  by its file name in the search paths, the file's directory and its
  `LC_RPATH`s, and loads the slice of the program's CPU
  ([Libraries](#libraries)).
- **Code signature** (`api_minor` 100, feature `apple-bundles`).
  `MachoSummary.code_signature` (`CodeSignature`): `LC_CODE_SIGNATURE`'s
  CodeDirectories (identifier, team id, flags by codesign's names such as
  `runtime`, hash type, page size, slots, special hashes, the executable
  segment, CDHash; alternates marked), the entitlements (XML, else DER) as
  a `PlistValue`, the requirements as text, whether a CMS signature is
  there and its certificates' names, `adhoc`, every blob, warnings, and
  where it is in the file. Read, never verified
  ([apple-apps.md](apple-apps.md#code-signatures)).
- **Relocations.** `ListRelocations` lists binds, lazy binds, rebases and
  chained fixups (`format` `macho`, type names `BIND_TYPE_POINTER`,
  `REBASE_TYPE_POINTER`, `DYLD_CHAINED_PTR_64`, ...).
- **Objective-C and Swift** (`api_minor` 91, feature `objc`). At import a
  Mach-O's Objective-C metadata becomes typed data, names and functions
  (`analysis:objc`) and its methods' prototypes (`import:objc`), its Swift
  descriptors names and functions (`analysis:swift`), as the PE analysis
  does (the import's warnings count them). `ListObjcClasses` lists the
  classes by name (each method with its selector, type encoding,
  implementation, category and the function's current name; ivars,
  properties, protocols, categories; a class only categories extend is
  `external`), the protocols and the Swift types; `name_contains` filters
  all three by name, in any case. A viewer may call it; an empty answer
  for other formats ([macho.md](macho.md#objective-c-and-swift)).

### EVM contracts

`api_minor` 99, feature `evm` ([evm.md](evm.md)). Ethereum Virtual
Machine bytecode imports as format `evm`: binary or hex text, runtime or
creation code, detected by solc's prologue (`6080604052`) when
`ImportOptions` names no format or language, or forced with `format:
"evm"`. It is a raw image of revkit's own processor `EVM:BE:32:default`
(block `runtime` at 0; creation code's `init` at `0x100000`), with
`analysis:evm` functions (the dispatcher, the constructor, one per
selector, named from a short table of well-known signatures or
`func_0x<selector>`), `tag_<offset>` labels and code marks on JUMPDESTs,
and computed-jump references from a stack analysis.
`ProgramSummary.evm` (`EvmSummary`) has the layout, the dispatcher's
`EvmFunction`s (selector, entry, name, signature, standard) and the jump
counts: `jumps`, `direct_jumps`, `resolved_jumps`, `unresolved_jumps`,
`unreached_jumps`. The raw loader's `hexbytes` container
(`raw_format: "hexbytes"`) reads hex text for any raw import.

### .NET assemblies

`api_minor` 94, feature `dotnet`. A PE with a CLR header (data directory
14, `IMAGE_COR20_HEADER`) is a .NET assembly, and `ProgramInfo.dotnet`
(`DotNetAssembly`) says what the header and the metadata root say: the
metadata version (`v4.0.30319`), the runtime version (`2.5`), the flags,
`il_only` or `mixed_mode`, `ready_to_run`, strong-name signing, 32-bit
requirements, the entry point's token (or native RVA), the metadata
streams and a `description` line.

- **IL-only assemblies are imported without code analysis**
  (`code_analysis_skipped`): their code is CIL, not machine code, so
  nothing is decoded as instructions or discovered as functions (before,
  the IL was disassembled as x86 from the entry stub). The import
  succeeds, and its warnings say so: the headers, sections, resources,
  strings and bytes stay browsable, and the stored file is there for a
  decompiler: `DecompileExternal` gives its C# from ILSpy
  ([below](#external-decompilers)). The import isn't refused, so the
  program is in the project for the providers to attach their output to.
- **Mixed-mode (C++/CLI) and ReadyToRun images** have native code beside
  the IL, which is analysed as usual; the warnings say the IL isn't.
- The Python SDK's `Program.dotnet()`, MCP's `program_summary` (`dotnet`)
  and the Open dialog's details show it; the file browser names an
  assembly's content kind `dotnet:il` or `dotnet:mixed`.

### Libraries

`api_minor` 70, feature `program-libraries`. A program's shared libraries,
the project programs they are, and where its imports go (Ghidra's "Load
libraries" and "Link existing project libraries"; the debugger's "Map
libraries to other project programs").

- **What a program needs.** The loader keeps the file's library list:
  ELF `DT_NEEDED` (in order), PE the import directory's DLLs (each once);
  its own name as a library (ELF `DT_SONAME`, PE the export directory's DLL
  name), ELF `DT_RUNPATH` (else `DT_RPATH`) and the GNU build ID note.
  `ListProgramLibraries` answers with `soname` and `build_id` too. PE delay
  imports and ELF symbol versions are not read (an import named
  `free@GLIBC_2.2.5` is looked up as `free`).
- **Which program a library is** (`ProgramLibrary.resolution`): `LINKED`,
  the program a `LinkProgramLibrary` assertion names; else `NAME`, a program
  whose display or imported name is the library's; else `SONAME`, a program
  whose own library name it is; a program in the same folder wins a tie,
  then the earliest imported; else `NONE` ("not in project"). PE names
  compare without case. Libraries' libraries follow breadth first (`depth`
  1, 2, 3, with `needed_by`), each name once.
- **Where an import goes** (`ResolvedImport`): the program's imports are its
  import slots (GOT entries with `JUMP_SLOT`, `GLOB_DAT` or an absolute
  relocation against an undefined symbol; IAT entries) and the thunks that
  jump through them (PLT stubs, `jmp [IAT]`). A PE import is looked up in
  its DLL's program; an ELF one in the libraries in load order (its own,
  then theirs), as the dynamic linker's global scope does. The library's
  exports are its defined global and weak dynamic symbols (functions,
  indirect functions, objects), or its export directory's named exports
  (forwarders left out). `address` is the function's current address in the
  library program (after `SetImageBase`), `function_name` its name there (a
  rename shows). `ResolveImport` answers for one import, by name or by the
  thunk's or slot's address (or one inside the thunk).
- **`LinkProgramLibrary`** asserts which program a library is (or, with an
  empty target, that it is found by name again): a NOTE on the program's
  record (sub `revkit:program.library:<name>`, reserved like the name and
  folder subs), blamed, undone by `RetractAssertions`, replicated. The
  target must be in the same project and not the program itself. Project
  archives don't carry links (program ids change on import there).
- **Importing the libraries** (`ImportOptions.import_libraries`,
  `library_search_paths`, `library_depth`): after the program, each library
  it needs that resolves to no program is looked for by its name in, in
  order, the search paths, the file's directory and its runpath (`$ORIGIN`
  expanded), then, for a file imported by `path` (not an upload or a
  container's member), the host's library directories (`/lib`, `/usr/lib`,
  their multiarch `x86_64-linux-gnu` and `lib64` forms, `/usr/local/lib`);
  the first file of the same format, word size and machine (endianness for
  ELF) is imported under the library's name, with the program's `analyze`.
  Then their libraries, to `library_depth` levels (0: 2; at most 8; at most
  64 libraries per import). `ImportProgramRequest.folder_id` puts the program
  and every library imported with it in that folder. The response lists
  them (`libraries`) and the names found nowhere (`libraries_not_found`, with
  who needs them); a library that fails to import is a warning. Reading the
  host's files is an import by path, so it needs admin (as `ImportProgram`
  does); the search never leaves the directories named.
- **The program's own root file system** (`api_minor` 79, feature
  `library-roots`): firmware's libraries are in its root file system, not
  the host's, so the host's directories give the wrong libc or none.
  - **An extracted root on the host.** `ImportOptions.library_root` names
    it (a directory under a `--browse-root`; else `PERMISSION_DENIED`, and
    `FAILED_PRECONDITION` with no `--browse-root`). Without it, a file
    imported by path that lies under a `--browse-root` uses the nearest
    directory above it, at or below that root and not `/`, that has `lib`
    or `usr/lib` and one of `bin`, `sbin`, `usr/bin` or `etc` (one named
    `usr` or `local` is passed over). `ImportProgramResponse.library_root`
    says which root was used. Inside it, after `library_search_paths` (host
    directories, as before): the file's directory, its runpath (`$ORIGIN`
    the file's directory, absolute entries inside the root), the
    directories the root's `/etc/ld.so.conf` names (one level of
    `include`, globs in the last component), then `/lib` and `/usr/lib`
    with their multiarch and 64-bit forms and `/usr/local/lib`, instead of
    the host's. Symbolic links are followed inside the root only (an
    absolute target is from the root, `..` stops there, 40 hops), each
    component checked with `lstat`, so nothing outside it is read. A PE
    looks beside the exe.
  - **A container** ([filesystems.md](filesystems.md#libraries-of-imported-programs)):
    `FileSystemService.ImportFromFileSystem` with `import_libraries` looks
    in the container layer each program came from, the same way, with
    `library_search_paths` as paths inside it; libraries found are
    imported from their bytes with their container path, as items with
    `library_of` (the program that needs them) in the program's folder;
    `libraries_not_found` and `library_warnings` list the rest. This reads
    only the session, so it needs editor, as the import does.
- **References back from a library** (`QueryService.ListLibraryImporters`,
  `api_minor` 81, feature `library-importers`): for a library program, the
  project's programs whose imports resolve to it (as above: a link, else
  the name or soname, then the export lookup), each import that does
  (`LibraryImporter.resolved`: its name, thunk and slot in the importer, the
  function's `address` here), and with `include_references` the importer's
  references to it: to the thunk, and to the slot but for the thunk's own
  jump through it (at most `max_references` each, 50 by default, 1000 at
  most; `references_truncated` past that). One export by `address` (the
  function at or containing it) or `name`; neither gives every import of
  the library. The importers are read at their head; ordered by name, then
  by slot. A viewer's call. SDK `Client.library_importers`, MCP
  `list_library_importers`; the UI's References dialog lists them
  ([ui.md](ui.md#libraries)).
- **The debugger** ([debugger.md](debugger.md#libraries)): a runtime module
  that is another project program (the library of its name the program
  links, else a program of its name or soname) is mapped:
  `DebugLocation.library_program_id`, `library_address`, `library_function`;
  `DebugModule.program_id` and `library_slide`; stack frames in it are
  named from its functions, and its disassembly reads `libc.so.6!strlen+0x10`.

### Nintendo DS games

`api_minor` 103, feature `nds` ([nds.md](nds.md)). A DS game as one raw
program per module (`main`, the autoloads, the ARM9 overlays as
`ARM:LE:32:v5t`; the ARM7 and its overlays as `ARM:LE:32:v4t`), in a new
folder, linked to one another by address.

- **`ProjectService.ImportDsdProject{project_id, config_path, folder_id,
  folder_name, modules, skip_arm7, analyze, provenance}`**: a ds-decomp
  project's `config.yaml` on the daemon's host. Every file read must be
  under a `--browse-root` (`FAILED_PRECONDITION` without one,
  `PERMISSION_DENIED` outside); admin. The binaries come from the extract
  the config's `rom_config` names (else each module's built `object`).
  `delinks.txt`'s sections are the blocks, its units plate comments
  (`import:dsd`); `symbols.txt` is the image's symbol table
  (`loader::RawOptions::symbols`, kept in the program's raw record): names,
  sizes, Thumb modes, demangling as an ELF's. Response
  (`ImportDsdProjectResponse`): the folder and per module
  (`NdsModuleImport`) its program, address, size, `.bss`, counts (symbols,
  functions, Thumb functions, data symbols, relocations, cross-module and
  ambiguous ones, sections, units), links, warnings, or why it failed.
- **`ProjectService.ImportNdsRom{project_id, path | content |
  program_file, folder_id, folder_name, modules, skip_arm7, analyze,
  provenance}`**: a `.nds` image: header, BLZ-decompressed ARM9 split into
  main and its autoloads by the module parameters, decompressed overlays,
  the ARM7. No symbols. `INVALID_ARGUMENT` for a file that isn't a DS ROM.
  `ImportNdsRomResponse` is `ImportDsdProjectResponse` under another name;
  `NdsModuleImport.compressed` marks decompressed modules and
  `ProgramInfo.container_path` is `nds://<file>!/<module>`.
- **Module links**: each program's record has a NOTE, sub
  `revkit:program.dsd` (reserved), with its source and `link <module>
  <program id>` lines. Where a program's code or data refers to an
  address none of its blocks holds and exactly one linked module maps it,
  the decompiler takes that program's function, data and label there as
  its own decompilations see them (renames, prototypes, types; each a
  dependency), and the listing shows the name with
  **`ListingToken.target_program_id`** (new) naming the program.
- **`ProjectService.ExportDsdSymbols{project_id, program_ids, folder_id,
  write, no_new_symbols, no_renames, include_text, read, provenance}`**:
  per module program, its `symbols.txt` with revkit's names
  (`DsdSymbolsExport`: `diff`, `text` with `include_text`, counts,
  `changes` as `DsdSymbolChange{kind renamed|added|skipped, address,
  old_name, new_name, line, reason}`, `written`, `backup_path`) and all
  diffs in `patch`. The rule for mangled names: a function not renamed, or
  renamed to the listed name's demangled form, keeps the listed spelling;
  any other name is written as typed. `write` (admin, files under a
  `--browse-root`) backs each file up as `symbols.txt.bak-<UTC time>` first.
  A viewer's call otherwise.
- **`QueryService.ExportDecompScratch{program_id, function, read, module,
  timeout_ms}`**: `text` (a `// PROBE: <symbol> <module> <address>` line,
  Ghidra's built-in type names, the named types the function uses, its
  callees' prototypes, linked modules' included, its globals, then its C),
  `context` and `source` (for a decomp.me scratch), `probe`,
  `function_name`, `symbol` (as the file spells it), `module`, counts,
  `notes`, `failure`. A viewer's call.
- **Library prototypes**: a raw image's `_name` no longer takes a library
  archive's `name` (`LibraryPrototypes::find`'s underscore rule is for
  ELF, PE and Mach-O symbols); inputs.program version 16.

`api_minor` 104 ([nds.md](nds.md#what-a-matching-run-needed)):

- **The DS's memory map** (feature `memory-preset`): the DS imports map
  each module's I/O ports, shared WRAM and main memory's shared area as
  volatile blocks; **`ImportOptions.memory_preset`** (`"nds-arm9"`,
  `"nds-arm7"`) does the same for a raw import.
- **Name conflicts** (feature `import-conflict`): **`NameConflict`**
  `on_conflict` on `ImportProgramRequest`, `ImportDsdProjectRequest` and
  `ImportNdsRomRequest` (`KEEP_BOTH`, the default; `REPLACE`; `REFUSE`:
  `ALREADY_EXISTS`); **`ImportProgramResponse.name_taken_by`**,
  **`replaced_program_id`**, **`ImportDsdProjectResponse.folder_taken_by`**,
  **`replaced_program_ids`** (and the same on `ImportNdsRomResponse`).
- **Function bounds' instruction set** (feature `bounds-isa`):
  **`SetFunctionBounds.instruction_set`**; unset, an untagged entry keeps
  the function's (or the code's) instruction set.

Python: `Client.import_dsd_project`, `import_nds_rom`,
`export_dsd_symbols`, `Program.decomp_scratch`. MCP: `import_dsd_project`,
`import_nds_rom`, `export_dsd_symbols`, `decomp_scratch`. UI: File →
Import ds-decomp project…, Import DS ROM…, Export ds-decomp symbols…; the
decompiler's Copy as decomp scratch ([ui.md](ui.md#nintendo-ds)).

Since `api_minor` 105, `ImportNdsRom` also asserts a function at each
address one module calls in another (a `ListingEdit` Disassemble with
`function`, ARM or Thumb by the call; a few rounds), so a ROM's functions
that only other modules call are found.

### Decomp knowledge base

`api_minor` 105, feature `decomp-kb` ([decomp-kb.md](decomp-kb.md)). Both
calls read and write files on the daemon's host: admin, paths under a
`--browse-root` (`FAILED_PRECONDITION` without one, `PERMISSION_DENIED`
outside).

- **`ProjectService.BuildDecompKb{project_id, program_ids | folder_id,
  kb_path, game, source_root, manifest_path, compiler, flags,
  skip_near_index, threads, provenance}`**: a finished game's module
  programs into the KB directory `kb_path` (made if missing; a game
  ingested again replaces its records): `DecompKbFunction` records in
  `functions.jsonl` (hashes, `small`, `anonymous`, `calls`
  (`DecompKbCall{offset, symbol, address}`), `instructions`, unit, source,
  text, compiler, flags, status and the manifest's `fuzzy`, `library`,
  `object`, `variant`, `relocations`, `manifest_hash`), unit files under
  `sources/`, and the BSim near index `near.rkbsim`. The manifest is
  JSON lines in a matching pipeline's fields ([decomp-kb.md](decomp-kb.md#the-manifest)).
  `BuildDecompKbResponse`: `functions`, `with_source`, `units`,
  `too_short` (small ones, kept), `unnamed` (left out), `anonymous`,
  `from_manifest`, `near_indexed`, `total`, `warnings`.
- **`ProjectService.ApplyDecompKb{project_id, program_ids | folder_id,
  kb_path, apply, overwrite, include_unit_source, near, min_similarity,
  max_near, export_dir, threads, provenance}`**: the programs' functions
  matched against the KB: `DecompKbMatch{program_id, address,
  current_name, verdict exact|call|candidate|near, functions, applied,
  reason, unit_source, similarity, confidence, diff}`. `apply` names the
  exact and call matches (placeholder names only unless `overwrite`) with
  the linker's spelling as the `revkit:dsd.symbol` note, and a plate
  comment, one revision per program. `export_dir` writes the matches as
  files (`DecompKbExport{dir, files, sources, scratches, symbols_files,
  patch}` in `exported`). Counts: `hashed`, `exact`, `by_call`,
  `candidates`, `ambiguous`, `near`, `applied`.

Python: `Client.build_decomp_kb`, `Client.apply_decomp_kb`. MCP:
`build_decomp_kb`, `apply_decomp_kb`. UI: File → Apply decomp knowledge
base… ([ui.md](ui.md#decomp-knowledge-base)).

### Batch reads for scripts

`api_minor` 29, feature `script-batch` ([scripting.md](scripting.md#batch-rpcs)):

- `DecompileMany` streams decompilations of `functions` (or `all`) at one
  revision, held for the whole call (`ReadOptions.revision`, else the head
  at the start; an expired pin fails at once with `REVISION_EXPIRED`),
  functions served before first, `parallelism` at a time (default the
  decompiler workers plus one) in completion order. Each message has the
  request `index`, `total`, `entry`, `function`/`failure` as `Decompile`
  or an `error`, `served_before`, `function_ms` and `elapsed_ms`.
  `escalate` and `include_bundle` are refused: retry one function with
  `Decompile`.
- `FindBytes` searches initialized memory (as patched) for a 1-256 byte
  `pattern` under an optional bit `mask`, in a `range`, at an `alignment`,
  optionally only in executable blocks; at most `max_results` (1000 by
  default, 100,000 at most) with `truncated`.
- `ListInstructions` streams the instructions of a `range` or a
  `function`'s body as `InstructionDetail`s (`GetInstruction`'s message),
  with p-code unless `omit_pcode`, up to `limit`.

Viewers of the project may call all three, as they may the per-item reads.

### Search

`api_minor` 41, feature `search` (Ghidra's Search Memory, Search Program
Text, Search for Scalars and Decompiler Text Finder; the UI's dialogs and
results table are in [ui.md](ui.md#search)). Four server streams in
`QueryService`, each at one revision (the request's `ReadOptions`, else
the head when it starts). Every message carries matches found since the
last (in the search's order) and progress; the last one has `done`, and
`truncated` when there were more than `max_results` (default 1000, at
most 100,000). Cancelling the call stops the search. Viewers of the
project may call them.

- **Where and from where.** `SearchScope` limits a search to `ranges` (a
  selection; empty: everywhere) and, for memory and scalars, to code
  units: `instructions`, `defined_data`, `undefined` (all false: any),
  and `executable_only` blocks. `SearchStart` is Next and Previous: matches
  strictly after `from` (before it with `backward`, in reverse order),
  and with `wrap`, the rest from the other end, marked `wrapped`. Unset:
  the whole program, forward.
- **`SearchMemory`** reads `query` as `format`: `HEX` ("48 8b ?? e8",
  "488b??e8", nibble wildcards "4? ?f"; `?` and `.`), `STRING` in
  `encoding` (ASCII, UTF-8, UTF-16 in the byte order), ASCII letters in
  either case unless `case_sensitive`, and with `escape_sequences`
  `\n \t \r \0 \\ \" \xHH \uHHHH`; `DECIMAL` (whitespace-separated
  integers, decimal or `0x`, each `value_size` 1, 2, 4 or 8 bytes,
  `unsigned_values` refusing negatives; a signed search takes the unsigned
  spelling too, 255 for a byte's -1), `FLOAT` and `DOUBLE` (IEEE, exact
  bits), `BINARY` (eight digits a byte, `x`/`?`/`.` for a bit that may be
  either) and `REGEX` (RE2 over bytes in Latin-1: `\xHH` is a byte, `.`
  any byte but `\n`, `(?s)` lets it match `\n`; leftmost-first, at most
  4 KiB long, no backreferences or lookaround). `byte_order` is the
  program's unless set. It searches initialized blocks as patched, in
  1 MiB chunks: `memchr` on a whole byte of the pattern, else a table of
  the bytes one position accepts, then every position; RE2 for regexes.
  Matches overlap (each start is reported). The first message's `pattern`
  is the bytes searched for ("48 8b ?? e8"; a mask inside a nibble is
  `[v/m]`). With `details`, each `MemoryMatch` has the label at the
  address (or `symbol+0x3` inside a labelled unit), the code unit as the
  listing shows it (`preview`: "MOV EAX,0x811c9dc5", `ds "usage"`,
  "undefined[16]") and its start, and the function.
- **`SearchText`** matches what the listing shows, so renames count:
  `TextField` `COMMENTS` (plate, pre, end-of-line, post and repeatable,
  line by line), `LABELS` (the symbol at an address, `FUN_`/`LAB_`/`DAT_`
  included), `FUNCTIONS` (signatures as the header shows them),
  `MNEMONICS`, `OPERANDS` (an address as the symbol it names), and
  `DATA_MNEMONICS` and `DATA_VALUES` of defined data; `fields` empty is
  all. With both `MNEMONICS` and `OPERANDS` an instruction is one line
  ("CALL checksum"), the field reported being where the match starts.
  Plain text or `regex` (RE2, UTF-8), `case_sensitive` (insensitive:
  ASCII folding for plain ASCII text, Unicode folding otherwise),
  `whole_word`. Each `TextMatch` has the line, the match's UTF-8 byte
  offset and length, the comment's kind, the label and the function.
- **`SearchScalars`** finds instructions whose operands, and defined data
  of an integer type (`byte` … `qword`, `undefinedN`, `int`, `uint32_t`
  and the like; not pointers), hold a scalar in [`min`, `max`] (either
  open): a scalar matches if its value read as signed (sign-extended from
  its width) or as unsigned is in range, so an 8-bit `0xff` is both 255
  and -1. A scalar printed as the address it references counts, as in
  Ghidra. Each `ScalarMatch` has both readings, the width, the operand
  (-1 for data), the instruction or data as shown and the function.
- **`SearchDecompiled`** decompiles `functions`, those whose entry is in
  `ranges` (a selection inside a function searches it), or `all`, through
  `DecompileMany` (its workers, its `parallelism`, the memo: a function
  decompiled before costs nothing) and matches each line of C (tokens
  joined, without the indent), plain or `regex`. A `DecompiledMatch` has
  the function, the index into `DecompiledFunction.lines`, the line and
  the match, and the line's address. Progress counts functions
  (`functions_done` of `functions_total`, `functions_failed` that didn't
  decompile). It stops once it has `max_results`.
- **How row searches read the listing.** `SearchText` and `SearchScalars`
  walk the listing's rows in address order, a few thousand at a time on
  up to 8 threads, handed back in order. They read `listing.search_page`,
  a compact form of a 256-row page (each row's text and the scalars in it,
  not the token objects; about a tenth of the memory), decoded on its own
  rather than from `listing.page`: a large program's whole listing is
  then searchable from memory, and a search neither keeps nor evicts the
  pages the listing view uses. A run of undefined bytes (a `.bss`) is
  looked at only where it has a label or comment. A memory match's
  details decode the one instruction it is in.

**Performance** (`scripts/bench-search.py`; RelWithDebInfo, the 32-thread
machine of [scale.md](scale.md), shared, load 9 to 13). cmake
(11.8 MB, 2.13M instructions, 19,409 functions) and a 16 MiB firmware
image (the firmware corpus's PowerPC U-Boot at its load address, then
15 MiB of pseudo-random bytes standing in for a compressed kernel and
root file system, then erased flash; raw, PowerPC:BE:32), wall time
through the Python SDK:

| search | cmake | firmware (16 MiB) |
| --- | ---: | ---: |
| memory, hex with wildcards (`48 8b ?? e8` / `7c 08 02 a6`), all of memory | 22 ms (5,532) | 10 ms (1,272) |
| the same with details (label, code unit, function) | 80 ms | 16 ms |
| memory, a string in any case | 18 ms | 24 ms |
| memory, a string in UTF-16 | 24 ms | 16 ms |
| memory, a 4-byte decimal / a double | 12 / 34 ms | 16 / 14 ms |
| memory, regex `[\x20-\x7e]{64}` | 158 ms (100,000, the cap) | 40 ms (3,406) |
| memory, binary with masks, no match (a full pass) | 21 ms | 21 ms |
| memory, Next / Previous from the middle | 2 / 3 ms | 7 / 8 ms |
| program text, the first after import (decodes the listing) | 3.0 s | 133 ms |
| program text, an instruction (`xor eax,eax` / `mfspr r0,LR`) | 142 ms (9,792) | 7 ms (1,238) |
| program text, a regex over instructions | 118 ms (100,000, the cap) | 8 ms (7,500) |
| program text, labels and comments only | 75 ms | 5 ms |
| program text, Next from the middle | 16 ms | 1 ms |
| scalars, one value (0x1000) | 39 ms (49) | 3 ms (42) |
| scalars, a range (0..0xff) | 96 ms (100,000, the cap) | 23 ms (44,576) |
| decompiled C, 500 functions spread over the program, not yet decompiled | 32 s (4,489 lines) | 2.6 s (2,073) |
| the same, memoized | 40 ms | 25 ms |

cmake has 2.13M instructions in 2.1M listing rows; the firmware's
analysis finds code only in the U-Boot part. The decompiled search's
cold time is the decompiler's (two `rk-decompd` workers, the default):
the search adds nothing measurable to it.


### Scripts the daemon runs

`api_minor` 31, feature `scripts-host` (`script.proto`;
[scripting.md](scripting.md#the-daemons-script-service), safety in
[security.md](security.md#roles)):

- `ListScripts{project_id}`: the shipped library (`share/revkit/scripts`,
  or the source tree's `sdk/python/revkit/scripts`), the per-user one
  (`~/.config/revkit/scripts`, `rk-daemon --scripts-dir`) and, with
  `--project-dir`, the project's (`<project-dir>/<project>/scripts`), each
  a `ScriptInfo`: `script_id` (`shipped/x.py`, `user/x.py`,
  `project/<p>/x.py`), the metadata (`category`, `description`,
  `menupath`, `keybinding`, `context`, `args`), `sha256`, `trusted`,
  `writable`. `host_enabled` (and `host_disabled_reason`) says whether
  the daemon runs scripts for the caller; `python` (or `python_problem`)
  which Python it runs them with.
- `RunScript{script_id, program_id, args, context, confirm_sha256,
  reason}` streams `started`, then `output` (stdout/stderr text, one
  message per line or more), `progress` (current, maximum, message; at
  most ten a second), `prompt` (id, kind, name, message, default,
  choices), and finally `result` (status, `revisions`, `seqs`, seconds)
  or `error` (`result` with status `error` or `cancelled`, message,
  traceback with the script's path shown as its id, `script_id` and
  `line` where it failed). An unconfirmed user or project script answers
  only `trust_required` (the `ScriptInfo`, the source, `unseen` or
  `changed`, the previous hash); run again with `confirm_sha256`. Policy:
  viewer of the program's project in the gate, then the daemon's host
  role (editor by default; a viewer's run, under `--scripts-host-role
  viewer`, gets a viewer's run token and `--read-only`, so it can't
  edit).
- `AnswerPrompt{run_id, prompt_id, value | values | cancelled}`,
  `CancelScript{run_id}` (SIGTERM, then SIGKILL 2 s later; cancelling the
  `RunScript` call does the same; with `interrupt` (`api_minor` 43):
  SIGINT, a `KeyboardInterrupt` in what it runs), `UpdateContext{run_id,
  context}`: the run's owner (or an admin).
- **The console** (`api_minor` 43, feature `script-console`):
  `RunScript{program_id, interactive: true, input, context, ghidra_names}`
  runs `input` in the caller's console of the program, a host process
  (`python -m revkit.script.console`) the daemon keeps per caller and
  program, starting it when there is none or it died (then
  `started.console_started`), closing it after `--console-idle-timeout`
  seconds idle (default 1800; 0: never), at most 16 at once
  (`RESOURCE_EXHAUSTED`). The stream: `started` (the console's `run_id`,
  `console_started`, the caller's `history`, `read_only`,
  `python_version`, `completion_engine`), `output` and `prompt` as a run's,
  then `console_result` (`more`: an open block, nothing ran; `status`
  `ok`, `error` (the traceback went to stderr), `interrupted` or `exit`;
  the statement's `revisions` and `seqs`, `discarded`, `seconds`,
  `error`), or `error` when the host died during it. Empty `input` only
  opens it. One statement at a time per console (`FAILED_PRECONDITION`
  while one runs); cancelling the call interrupts the statement and keeps
  the console. `CancelScript{run_id}` with the console's id closes it,
  `{interrupt}` is Ctrl+C; `UpdateContext{run_id}` moves its cursor;
  `AnswerPrompt` answers its prompts.
- `CompleteConsole{program_id, text, limit}` (feature
  `script-completion`): completions for `text` (the input up to the
  cursor) from the caller's live console of the program: each
  `ConsoleCompletion` has `text`, `kind`, `signature` (without
  annotations: `decompile_many(funcs=None, *, text=True, parallelism=0)`)
  and `doc`; `prefix_length` is how much of `text` they replace; `engine`
  is `jedi` or `rlcompleter`. Answered while a statement runs.
  `FAILED_PRECONDITION` when the caller has no console open there.
- `SaveScript{library, project_id, file_name, source, expected_sha256}`:
  per-user or per-project only; empty `expected_sha256` creates
  (`ALREADY_EXISTS` if the file is there), otherwise it must match
  (`ABORTED`: changed since read). Pins the saver's trust.
- `ListScriptRuns{program_id, limit}`: recent runs in memory (200), the
  caller's own (an admin's: everyone's), newest first.
- `SetupScriptPython{force}` (`api_minor` 33, feature `scripts-setup`):
  makes `~/.local/share/revkit/pyenv` (`$XDG_DATA_HOME/revkit/pyenv`) on
  the daemon's machine, as `rk-script setup` does: `python3 -m venv`
  (`rk-daemon --script-setup-python` names another Python; skipped when
  the environment exists, unless `force`), then `pip install --upgrade`
  of the SDK the daemon ships (`share/revkit/python`'s wheel, else
  `share/revkit/sdk`'s, else the source tree's `sdk/python`; pip fetches
  `grpcio` and `protobuf`), then the import check. Streams `output` (each
  command as `$ ...`, then what it prints), then `result` (`ok`, the
  `python` scripts now run with, `error` saying what failed and what to
  do: install `python3-venv`, reach PyPI or a mirror, ...; `directory`).
  One at a time (`ABORTED` while another runs); `FAILED_PRECONDITION`
  when `--script-python` names the Python. Policy: editor, plus the
  daemon's host role, as running a script.

Errors: `FAILED_PRECONDITION` when no Python imports revkit (with the
setup hint), `PERMISSION_DENIED` when scripts are off for the caller,
`RESOURCE_EXHAUSTED` beyond 8 runs (or 16 consoles) at once.

### Import progress

`ImportProgram` is one blocking call: loading, debug info, function
discovery, data analysis and saving all happen before it answers, which
takes seconds for a large ELF and can take tens of seconds for raw
firmware. Since `api_minor` 22 (feature `import-progress`) a client can
follow it:

- **API.** Send a random `ImportProgramRequest.import_id` (at most 128
  characters) and, while the call runs, poll
  `ProjectService.GetImportProgress{project_id, import_id}` (the UI polls
  every 250 ms). It answers `phase` (`ImportPhase`), `message` (a line for
  people: "Finding functions: 3,120 found", "Reading DWARF debug info
  (21.2 MB)", "Saving to the project"), `progress` (0..1, never decreasing;
  -1 before the import has started), `done`, `error` (why it failed),
  `program_id`, `functions_found` and `elapsed_seconds`. An id the daemon
  hasn't seen yet (the request is still uploading) answers `NOT_FOUND`:
  ask again. An id the same caller is still importing under is refused
  (`ALREADY_EXISTS`). Without an `import_id` nothing is recorded. The
  Python SDK's `import_program(..., progress=callback)` polls for you.
- **Who can read it.** The same role as `ImportProgram` (admin, project
  scoped), and only the identity that started the import
  (`CallContext.caller`, "user:alice"): anyone else, admins included,
  gets `NOT_FOUND`. Without authentication every caller is `anonymous`,
  and the random id is what keeps imports apart. Entries are kept for
  five minutes after the import ends (at most 64 ended ones per caller).
- **Phases,** in order; one with nothing to do is skipped:

  | Phase | What runs | Sub-progress |
  | --- | --- | --- |
  | `READING` | reading the file (or taking the upload) and hashing it | elapsed time |
  | `LOADING` | format detection, ELF/PE/raw sections, symbols, relocations, the language; storing the image in the project when there is no debug info | elapsed time |
  | `DEBUG_INFO` | DWARF (or a PE's PDB): names, prototypes, types; then storing the image and the debug info's assertions | elapsed time |
  | `FUNCTIONS` | disassembling from the seeds, the discovery fixpoint (with the firmware search on raw images: start patterns, then code nothing calls), bodies, then every function's references | bytes decoded, and the stage and functions found in the message |
  | `DATA` | data analysis (strings and pointers), then the listing's rows and the decompiler's inputs | elapsed time, a step between the two |
  | `PROTOTYPES` | no longer entered: inference runs after the import, in the background, as the analysis job `infer.prototypes` ([infer.md](infer.md)) | |
  | `SAVING` | writing the project to disk (persistent projects) | elapsed time |
  | `DONE` | answered, or failed (`error`) | |

- **The fraction.** Each phase gets a share of the bar in proportion to
  what it is expected to cost for this file (`ImportCosts::estimate` in
  `src/backend/import_progress.cc`), from the file's size at first and
  re-planned once it is parsed (code bytes, DWARF bytes, whether
  discovery runs in parallel, whether the project is saved). A share
  handed out never changes, so the fraction never goes back. Inside a
  phase it moves with real work where that is cheap to count, and with
  elapsed time against the estimate elsewhere (in step with the estimate
  up to 85% of the phase, then creeping towards 95%, so an overrun slows
  the bar and never shows the phase finished). Discovery publishes its
  progress through `analysis::DiscoveryProgress`: relaxed atomics that
  each flow adds to as it is computed (it finds its program's progress
  through a pointer each thread caches, so no lock unless a watch changed)
  and the fixpoint sets at each round; a memoized discovery reports
  nothing. The fraction is bytes decoded against the code's size times
  the share discovery is expected to reach (0.9 for compiled code, 0.7 for
  firmware), and, so a long search never stalls the bar, time as
  t / (t + estimate). On raw firmware the decoding finishes early and the
  search runs round after round for as long as it finds starts, which
  nothing predicts (0.7 to 40 s per MB on the firmware corpus): there the
  bar slows down while the message counts the functions found, and can
  jump when the search ends early.
- **Measured** (RelWithDebInfo, 8 analysis threads, persistent project;
  `REVKIT_TIMING=1` prints each phase's time against its estimate):

  | File | Reading | Loading | Debug info | Functions | Data | Saving | Total |
  | --- | --- | --- | --- | --- | --- | --- | --- |
  | `/usr/bin/cmake`, 11.8 MB ELF, 9.5 MB code, 19,409 functions | 31 ms | 136 ms | | 911 ms | 384 ms | 680 ms | 2.1 s |
  | `rk-debuginfo` (this build), 24 MB ELF, 21 MB DWARF, 1,805 functions | 68 ms | 8 ms | 435 ms | 588 ms | 150 ms | 256 ms | 1.5 s |
  | `/usr/bin/bash`, 1.4 MB ELF, 2,578 functions (discovery on one thread) | 5 ms | 89 ms | | 845 ms | 174 ms | 255 ms | 1.4 s |
  | `armfw` with 12,000 bulk functions (`build.sh ... -O2 12000`), 1.3 MB raw ARMv4T, 11,061 functions | 3 ms | 57 ms | | 1,560 ms | 99 ms | 376-730 ms | 2.1-2.4 s |
  | `uboot-stm32f746-disco.bin`, 325 KB raw Cortex-M, 1,554 functions | 1 ms | 41 ms | | 4,079 ms | 132 ms | 223 ms | 4.5 s |

  Discovery dominates raw images (60-95% of the time; on the firmware
  corpus from 0.13 s for an ESP32 image to 7 s for an SH-4 one, mostly the
  search); compiled binaries split their time between discovery, data
  analysis and saving. Following the progress costs nothing measurable:
  cmake imports (in memory) in 1.43 s with it and 1.43 s on master, flows
  in 673 and 671 ms (means of four).

### Parsing C

`TypeService.ParseC` (`api_minor` 25, feature `parse-c`) parses C for a
program: headers or pasted declarations, as text (`ParseCSource.text`) or
as files on the daemon's host (`path`, and `include_dirs`,
`system_include_dirs`), with `defines` and `undefines`, for the program's
target (its compiler spec's data model; `profile` names another, such as
`x86_64-w64-mingw32`). It asserts nothing. The response holds:

- `nodes`: every type the named types, prototypes and constant enums need
  that the program doesn't already have, as `DefineType`-ready
  `TypeNode`s whose references are `assertion_index` into `nodes` (or
  hashes of the program's types), and `hashes[i]`, what `nodes[i]` will
  intern to;
- `named`: each struct, union, enum and typedef the sources declare (only
  their own; system headers' with `include_system`), with its node, hash,
  file and line, and `existing_hash`, the program's definition of the name
  (bound, else its own, else the library archive's): equal is identical,
  empty is new, different is listed in `conflicts` too, with `same_layout`
  when only names or member types differ;
- `prototypes` (with `options.prototypes`), `constants` (integer
  `#define`s; with `defines_as_enum` also one enum per file),
  `diagnostics` (file, line, column, severity), `errors`, `limit_hit`, the
  `profile` used and its notes, and the host `files` read.

Names the sources use but don't declare are the program's types; a struct
they only declare is the program's definition. A type name
`__revkit_type_<hash>` is the program's type with that hash itself (not a
typedef of it), so a client can write a type it has by hash where C wants
a type name; an anonymous struct or union so named, alone in a member
declaration, is an anonymous member (the UI's type editor writes the
fields an edit didn't touch this way, so they keep their exact types and
an unchanged struct parses to its own hash). For previews, `displays[i]`
is `nodes[i]`'s C spelling, each named type carries its `c_definition`,
and each diagnostic its `source_line` (the text of that line, from the
pasted text or the host file). To import, define the
chosen nodes and bind their names in one `AppendAssertions` (the SDKs'
`import_header`): one revision, one undo. The SDKs use provenance
`import:header`, the header's name as its version and a session per
import, so `RevertByProvenance` on the session undoes exactly that import.
A request with host paths needs admin (as importing a program does) and
`--browse-root` on the daemon (else `FAILED_PRECONDITION`): every path and
`#include` must resolve, after symlinks and `..`, under a root
(`NOT_FOUND`, `PERMISSION_DENIED`). Pasted text needs viewer. Parses are
bounded in bytes, include depth, macro expansion, nesting and time
([cparse.md](cparse.md#untrusted-input)).

`TypeNode` gained `is_complex` (FLOAT), `reference` (POINTER: a C++ lvalue
or rvalue reference) and `is_class` (STRUCT), which `TypeDefinition`
reports too, so every type the parser makes round-trips through
`DefineType`.

### Project types and archives

`api_minor` 52, feature `project-types` ([types.md](types.md#project-types)):

- `AppendAssertionsRequest.project_scope`: the request's `define_type`,
  `bind_type_name` and `type_category` bodies are the project's (keyed in
  its space; any other body is `INVALID_ARGUMENT`), seen by every program
  of the project after its own. `program_id` names any program of the
  project (the data model the types are laid out for).
- `TypeService.CopyTypes{program_id, keys, mode, provenance}`:
  `MOVE_TO_PROJECT` makes the program's named types the project's (their
  records and what they reach defined there, each name bound and filed,
  the program's own definitions, binding and filing retracted);
  `COPY_TO_PROGRAM` copies the project's into the program and binds the
  names there. One revision; the response has the types (`key`, `hash`),
  `records`, `asserted`, `retracted` and the revision's `seqs` (retract
  them to undo). `NOT_FOUND`: a name the source scope doesn't define;
  `FAILED_PRECONDITION`: several definitions and no binding. Editor role.
- `AssertionBody.type_archive` (`TypeArchiveSetting{name, enabled,
  header, sidecar, detach}`): a library archive (a shipped one's name,
  `ghidra` for Ghidra's `.gdt`) switched on or off for the project, an
  archive attached (its header, and sidecar if any: checked as
  `ParseC` checks one), or detached. Switching an attached archive keeps
  its header. Any program of the project may carry the request.
- `TypeService.ListTypeArchives{program_id}`: `TypeArchiveInfo` per
  archive: `name`, `kind` (`SHIPPED`, `GHIDRA`, `ATTACHED`), `enabled`,
  `applies` (to this program), `functions` and `types` it gives the
  program, `data_model`, `origin`, `diagnostics`, and `origin_fact` (who
  switched or attached it; derived `library.default` otherwise). Viewer
  role.
- `FindTypes` source `TYPE_SOURCE_PROJECT` and `TypeDefinition.project`;
  `FactKey.project` on keys in the project's space (project types,
  archive settings), whose `program_id` is empty in what the server sends;
  `RetractAssertions` through any program retracts them.

### Type archives and categories

`TypeService.ExportTypeArchive` (`api_minor` 35, feature `type-archive`;
[types.md](types.md#type-archives)) writes a set of a program's types as
a type archive and asserts nothing. The request names the types by
`scope`: `SELECTED` (`keys` such as "struct cJSON", the program's
definition of each, and `hashes`, those very types), `CATEGORY` (every
type filed under `category` or below it), `USER` (every name a
`BindTypeName` binds: the types made, edited or imported in revkit) or
`ALL` (the program's own, the debug info's too; not the library
archive's); unset is `SELECTED` when keys or hashes are given,
`CATEGORY` when a category is, else `USER`. Every named type they reach
comes along. The response has the `header` (`<name>.h`: one
self-contained C header in dependency order, `#pragma pack` or explicit
offsets where C's natural layout differs, a `_Static_assert` of every
size), the `sidecar` (`<name>.json`: `TypeArchiveSidecar` as protobuf
JSON, also in `archive`), their file names, and `notes` with
`mismatches`: the types the header can't reproduce (C++ types; a name
two definitions share). The `name` defaults to the provenance's origin
(below). Types are read as their uses see them (`types.resolved`).
`NOT_FOUND`: a key or hash the program doesn't have;
`FAILED_PRECONDITION`: an empty category or no types in scope. Viewer
role.

The sidecar holds the format (`"revkit-type-archive"`, version 1), the
header's name and SHA-256, the `data_model` (the cparse target: sizes,
alignments, char signedness, bitfield model, and a one-line
`description`), the `provenance` (`generator` "revkit" and `origin`: the
program the types were first exported from), and per type, in header
order, its `key`, the `hash` the header parses to, its `size`, the
definition's `line`, its `category`, the `form` written (`natural`,
`pack(N)`, `explicit`, `typedef`, `declaration`) and, only when the
header can't reproduce it, the program's own `source_hash`. A library
archive ([types.md](types.md#library-prototypes), `api_minor` 50) also
lists its prototypes, key `function <name>` and form `prototype`, with
`noreturn`; `ParseC` verifies them as it verifies types (the
`ParseCResponse.prototypes` hash), and an import of one brings the types
and leaves the prototypes (applying them by name is analysis's).

Importing is `ParseC` with the header as the source and the sidecar as
`archive_sidecar`: the header is parsed for the sidecar's data model
(unless `profile` names one; a note says when it isn't the program's),
with no program types in scope, and `ParseCResponse.archive` says how it
compares: `verified` of `types`, each `mismatch` (expected and parsed
hash) and `header_changed` (the SHA-256 differs). Each named type's
`category` is the archive's. The SDKs' `import_type_archive` refuses
mismatches, binds every name the program doesn't already define as the
archive does (`existing_library`: a library archive's definition counts
as none), files every name under the archive's category, and uses
provenance `import:archive` with the archive's origin as its version, so
`ExportTypeArchive` of what an archive imported gives the same bytes.
Importing an archive again finds every type identical and sends
nothing.

**Categories.** `SetTypeCategory` (`AssertionBody.type_category`; key
`TYPE_DEF` with sub `category:<named key>`) files a named type under a
'/'-separated path ("/net/http"; "" or "/" is the top; no empty, "." or
".." parts, at most 1024 bytes and 32 levels: else `INVALID_ARGUMENT`).
The path is the name's, for every definition of it. `FindTypes` filters
by `category` (in it or below; `category_exact` only in it, and "/"
exact the types with none) and with `include_categories` lists every
category with how many types are directly in it (the top as "/", and
each category's ancestors), and its `TypeDefinition`s carry their
`category` (`GetTypes` doesn't: a hash names a definition, not a name).
The DWARF importer files a named type under its `DW_AT_decl_file`'s
name, the PDB importer under its `LF_UDT_SRC_LINE` file's, and a header
import (`ParseCNamedType.category`) under the header's name, with
`existing_category` the program's current one.

### Fallthrough overrides

Ghidra's Set Fallthrough and Clear Fallthrough (`api_minor` 85, feature
`fallthrough-override`). `SetFallthrough{address, target}` says control
goes on at `target` after the instruction at `address` instead of at the
next instruction: the usual case is a call followed by inline data (an
argument block, a string the callee skips) or a jump over junk bytes.
`no_fallthrough` says it doesn't go on at all; neither clears the
override, whoever set it (a `target` at the next instruction of one that
falls through clears it too, as Ghidra's `setFallThrough` does). Each is
one assertion: one undo step, with the request's provenance and reason.
An instruction is required at `address` and `target` must be in memory.

On the image backend the override wins over what the instruction and
analysis say (a jump made to fall through, a call to a no-return function
going on):

- **Discovery** (`analysis.flow`, `analysis.functions`, no-return
  inference, thunks): the flow goes on at `target`, so the bytes between
  stay out of the function's body; with `no_fallthrough` the body ends
  there. An instruction with an override is no thunk's.
- **The listing**: `ListingRow.fallthrough_override`, `fallthrough` (unset
  for none) and `fallthrough_origin`; `InstructionDetail.fall_through` is
  the override's (unset for none), with `fallthrough_override` and
  `fallthrough_origin`.
- **References**: an `XREF_KIND_FALLTHROUGH` reference from the
  instruction to `target` (Ghidra's `FALL_THROUGH`), on no operand.
- **The function graph** (`GetFunctionGraph`), Clear Flow and Repair
  (`PlanClearFlow`), the version-tracking and BSim block structure, the
  Function ID hash's extent and the stack-variable walk follow it.
- **The decompiler**, as Ghidra's Java side changes the p-code it sends
  (`PcodeEmit`): a `BRANCH` or `CBRANCH` the instruction makes to its next
  address goes to `target` instead, and a `BRANCH` to `target` ends its
  p-code. With `no_fallthrough` the p-code is unchanged, as in Ghidra, and
  the next address, when the function's body has no code there, doesn't
  decode, so the decompiler's flow stops there (`halt_baddata()`), as
  Ghidra's does where no instruction follows
  ([decompiler-inputs.md](decompiler-inputs.md#fallthrough-overrides)).
- The emulator runs the instructions' own p-code, as Ghidra's does: it
  doesn't follow overrides.
- Not yet: Ghidra's Auto Override (an override for every instruction
  before data in a selection), and the Ghidra interop
  ([ghidra-interop.md](ghidra-interop.md)) doesn't carry fallthrough
  overrides either way.

The SDK has `Program.set_fallthrough(addr, target)` (`None`: no
fallthrough) and `clear_fallthrough(addr)`; MCP `set_fallthrough`
(`target`, `no_fallthrough` or `clear`). The UI's listing menu has Set
fallthrough… and Clear fallthrough ([ui.md](ui.md#fallthrough-overrides)).

### Equates and user references

Ghidra's Set Equate, Convert and Equates Table, and its References
(add, delete, set primary), as assertions (`api_minor` 39, features
`equates` and `user-references`): they share undo, blame, history,
revert by provenance, collaboration and change events with every other
edit, and go through `AppendAssertions` (no new RPCs).

**How a scalar shows.** `OperandDisplay{address, operand_index, value,
format | equate, constant_hash, apply_to}` keys `EQUATE` at the
instruction, `sub` = `<operand>:<value in hex>`:

- `value` is the scalar's value as a 64-bit pattern: `ListingToken.value`
  (an operand's scalar, sign-extended as the disassembler prints it), or a
  decompiler constant's `CodeToken.value`. Without `operand_index` the
  server finds the operand holding it (a sign- or zero-extended form
  counts) and stores the operand and its own value. A decompiler constant
  no operand of its instruction holds (one the decompiler computed) is named
  by `constant_hash` (`CodeToken.constant_hash`, Ghidra's `DynamicHash`):
  `sub` = `h<hash in hex>:<value in hex>`, and it shows in the decompiler
  only.
- `format` is Ghidra's Convert: `HEX` (`0xfffffff0`), `SIGNED_DECIMAL`
  (`-16`), `UNSIGNED_DECIMAL` (`4294967280`), `OCTAL` (`37777777760o`),
  `BINARY` (`11110000b`), `CHAR` (`'A'`, `'AB'`, `'\n'`, `'\x01'`) and
  `FLOAT` (the bits as a float or double: 32- and 64-bit scalars only).
  `UNSPECIFIED`, or no display at all, shows the disassembler's text again
  whoever set the display.
- `equate{name}` shows a name in place of the value (Set Equate); a name
  has one value program-wide, so a second value under a used name is
  refused (`INVALID_ARGUMENT`, naming the value and where it is).
  `equate{enum_type_hash, member}` is an enum member (Ghidra's enum
  equates): the enum must be the program's or the library's, and the
  member's value the scalar's at the enum's width; the server fills
  `name`. `FindTypes{enum_value}` lists the enums with a member of a
  value, the suggestions a Set Equate dialog offers.
- `apply_to` `FUNCTION` or `PROGRAM` sets the same display on every other
  operand holding the value in the function containing `address` or in the
  program (Ghidra's "apply to all scalars"): the response has one
  assertion per operand, the requested one first and the others after the
  request's, all in one revision, so undo is one `RetractAssertions` of
  their seqs. At most 100,000 operands.

The listing shows the operand's text as the display says, with the
assertion as `ListingToken.display_origin` (its `value` stays the
scalar's). The decompiler gets the same display as Ghidra's Java side
sends equates: an `EquateSymbol` on each constant the instruction's p-code
holds with the value, attached by its dynamic hash
([decompiler-inputs.md](decompiler-inputs.md#equates)); the constant's
token then shows the name or the format and has `display_set`.

There is no equates table RPC: `ListAssertions{kinds: [FACT_KIND_EQUATE]}`
gives every display, and the effective ones (`ASSERTION_STATUS_EFFECTIVE`)
with an equate are the table: name, value, references. Renaming or
removing an equate everywhere is one `AppendAssertions` of a display per
reference (the SDKs' helpers do it).

**User references.** `UserReference{from, operand_index, to, type,
primary, remove}` keys `REFERENCE` at the instruction it is from, `sub` =
`<operand>:<to in hex>`, or `i:<to in hex>` without `operand_index` (the
instruction as a whole, Ghidra's mnemonic reference). `type` is Ghidra's
`RefType`: `DATA` (an address taken; `XREF_KIND_DATA_POINTER`),
`DATA_READ`, `DATA_WRITE`, `CALL`, `JUMP`, `COMPUTED_CALL`
(`XREF_KIND_INDIRECT_CALL`) or `COMPUTED_JUMP` (`XREF_KIND_INDIRECT_JUMP`).

- **Xrefs** list it with the assertion as `origin`, in place of an
  analysis reference from the same instruction to the same address of the
  same kind. `remove` deletes a reference: the user's at its key, and every
  reference analysis made from the instruction to `to` (of any kind): it
  leaves xrefs, the listing's reference counts and default names, while
  discovery keeps what it found from it.
- **Discovery** follows them: a call type (`CALL`, `COMPUTED_CALL`) from
  any instruction a function's flow reaches makes its target a function,
  as a call does; a jump type from a computed jump adds a target the flow
  goes on at (a switch's case). A `FUNCTION_BOUNDS` removal still wins.
- **The decompiler**: the primary (or only) user call reference of a
  computed call makes it a direct call to the target (Ghidra's call
  override reference); a computed jump's user jump references, with the
  targets analysis recovered, are its table, given even where the
  decompiler recovers one ([decompiler-inputs.md](decompiler-inputs.md#user-references)).
- **Primary**: an operand has one primary reference, so asserting a
  primary one makes the operand's other primary user references
  non-primary in the same revision (their assertions follow the
  request's in the response), as Ghidra's `setPrimary` does.
- **The listing**: `primary` shows the operand as the target's symbol
  (in place of its scalar, or after the operand as `=>symbol`), with the
  assertion as `ListingToken.reference_origin`.

Refused with `INVALID_ARGUMENT`: no instruction at `from` (or at an
`OperandDisplay`'s address), an address outside memory, a reference with
no `type` (unless `remove`), an operand that holds no scalar of the value,
a float display of a scalar of another width, an unknown enum or member.

**Python** (`revkit.Program`, and buffered in `revkit.script`), **MCP**
and **TypeScript** helpers build these bodies and fold the equates table;
the Ghidra compat shim's `getEquateTable`, `createEquate`,
`createMemoryReference`, `removeReference` and `setReferencePrimary` map
onto them ([scripting.md](scripting.md)).

### Find uses of a type or field

`api_minor` 53, feature `type-uses` (Ghidra's Find Uses of on a data type
or a field; the UI's actions are in [ui.md](ui.md#find-uses)).
`QueryService.FindTypeUses` is a server stream like `SearchDecompiled`:
it decompiles every function (or `functions` by entry, or those whose
entry is in `ranges`; none of the three, or `all`, is every function) over
`DecompileMany`'s workers and memo at one revision, so functions decompiled
before come first and cost nothing, and reads each result's tokens:

- **FIELD tokens** whose `parent_type_hash` is `type_hash` (the
  `field-tokens` data, api_minor 38) are `TYPE_USE_KIND_FIELD` uses, with
  the field's name and offset. With `field_offset` only that field's
  (with `field_name` too, one union member's, as all are at offset 0).
- **TYPE tokens** naming the type are `TYPE_USE_KIND_TYPE` uses (a
  variable's or parameter's declaration, a prototype, a cast; a pointer to
  it counts, as does a typedef of it): `CodeToken.type_hash` is set on a
  TYPE token that names a struct or union of the program from api_minor 53
  (empty where a retype replaced the declaration's type). Not with
  `field_offset`.
- **Access** (`FieldAccess`), from the statement around a field use: the
  token's member chain (`p->a.b[2]`) assigned is `WRITE` (a field of a
  field written writes the outer one too), a compound assignment, `++` or
  `--` is `READ_WRITE`, `&p->x` is `ADDRESS`, anything else `READ`.

Each `TypeUse` has the function and its name, the token's instruction
`address` (else the line's), the line's index and text with the token's
place in it (`match_start`, `match_length`, UTF-8 bytes). Messages bring
uses found since the last, in completion order with a function's uses
together, and progress (`functions_done` of `functions_total`,
`functions_failed` that didn't decompile and weren't read); the last has
`done`, and `truncated` past `max_results` (default 1000, at most
100,000). Cancelling the call stops work not yet started. An unknown type
hash is `NOT_FOUND`, a `field_name` without `field_offset`
`INVALID_ARGUMENT`. Viewers of the project may call it.

Only the decompiler's output is read: a use the decompiler doesn't print
as a field of the type (a raw offset from a pointer it doesn't know the
type of, a global data item of the type that no function names, a field
copied as part of the whole struct) isn't found. **Python**:
`Program.find_type_uses(struct, field=None, functions=, ranges=,
progress=, cancel=)` (struct by name or hash, the field by name or offset);
**MCP**: `find_type_uses`; **TypeScript**: `findTypeUses(rk, request, {
onProgress, signal })`.

### Slices

`api_minor` 57, feature `decompile-slices` (Ghidra's Highlight Def-use,
Highlight Forward and Backward Slice, and Forward and Backward Operator
Slice; the UI's are in [ui.md](ui.md#slices)).
`QueryService.SliceDecompiled{program_id, function, kind, token |
varnode_index | variable_index}` walks the decompiler's data-flow graph of
the function as Decompile serves it at the revision read:

- **Where it starts**: a token (`TokenPosition{line, token}`, as Decompile
  numbers them), its varnodes; a token printed from an op and printing no
  value (`return`, an operator, a call's name) starts from the op's output
  going forward and from its inputs going backward. Or a varnode
  (`DecompiledFunction.varnodes`), or a variable (each of its varnodes).
- **`SLICE_KIND_DEF_USE`**: the varnode's definition and uses, the tokens
  that print it. **`FORWARD`**: every varnode computed from it,
  transitively, through the ops that read it (MULTIEQUAL and INDIRECT
  included). **`BACKWARD`**: every varnode it is computed from, back to the
  function's inputs and constants. **`FORWARD_OPS`** and
  **`BACKWARD_OPS`**: the same walks, as the ops they run through, and the
  tokens printed from those ops.
- **The answer**: the `tokens` in reading order, the instructions their
  ops belong to (`addresses`, ascending: what a listing marks), the
  slice's printed varnodes and a `start` caption ("uVar1", "return").

A token printing no value and from no op (a keyword, a type, `;`), or a
position past the function, is `INVALID_ARGUMENT`; a function the
decompiler failed on is `FAILED_PRECONDITION`. Viewers of the project may
call it. The graph itself is `DecompiledFunction.dataflow` with each
token's `op_index` (`DataFlow{nodes, ops}`: a node's defining op, the
first `varnodes_size` nodes being the varnodes table's and the rest
varnodes no token prints; an op's address, opcode name, output and
inputs), sent only with `DecompileOptions.include_dataflow`, so a plain
Decompile is no bigger. **Python**: `Program.slice(function, kind,
variable= | token= | varnode=)` (kind "def_use", "forward", "backward",
"forward_ops", "backward_ops"; a variable by name or index); **MCP**:
`slice_decompiled` (a variable by name: the C lines it touches with the
slice's tokens on each, and the instructions).

### Tracing a value across calls

`api_minor` 89, feature `value-trace`. `QueryService.TraceValue{program_id,
function, direction, token | varnode_index | variable_index, max_depth,
max_functions, max_nodes, max_edges}` carries the slices' walk (above)
through direct calls, decompiling each function it reaches as Decompile
serves it at the revision read:

- **Backward** (`TRACE_DIRECTION_BACKWARD`: where the value comes from):
  inside a function, the ops that compute it back to inputs and constants;
  a call's output continues at each value the callee returns (its RETURN
  ops); a parameter continues at the matching argument of each direct call
  of the function (through its thunks).
- **Forward** (where it goes): the ops that read it; an argument continues
  at the callee's parameter; a returned value at the output of the calls.
  From a `return` token it starts at the returned value.
- **Calls are matched**: a walk that entered a callee from one call leaves
  it through that call only (a returned value goes back to that call's
  output, a parameter to that call's argument); only a walk leaving the
  function it started in goes to every caller. So tracing `x` in `combine`
  into `scale` comes back out to `combine`, not to `scale`'s other callers.
- **Budgets** (0: the default): calls crossed on one path (`max_depth`,
  default 3, at most 8; returning through a matched call costs nothing),
  functions decompiled (`max_functions`, 12, at most 64), values
  (`max_nodes`, 2000, at most 20000) and edges (`max_edges`, 4000, at
  most 40000). Where one stops the walk there is an unknown of kind BUDGET
  and `truncated` is set.
- **Unknowns, not guesses** (`unknowns`, each with the value it stopped
  at, the instruction and a sentence): `INDIRECT_CALL` (called through, or
  passed to or returned by, a function pointer), `EXTERNAL_CALL` (an import
  or a call with no known target: `strlen (import)`), `MEMORY` (read by a
  load or written by a store: what else touches that memory isn't
  followed; a global's writers), `NO_CALLERS` (a parameter or returned value
  of a function nothing calls directly: an entry point, a callback),
  `DECOMPILE_FAILED`, `BUDGET`, `UNMATCHED` (the callee doesn't use that
  parameter, the call passes fewer arguments, the caller ignores the
  result, an input that is no parameter).
- **The answer**: `functions` in the order reached (the start's first),
  each with `depth` (calls from the start: positive in callees, negative in
  callers), the C `lines` it touches (index, text, the tokens printing
  traced values) and the `addresses` of the ops computing them; the
  `nodes` (function, its data-flow node, varnode, what prints it, the
  defining instruction, depth) and `edges` in data-flow order (`DATAFLOW`
  inside a function, `ARGUMENT` from a call's argument to the callee's
  parameter, `RETURN` from a returned value to the call's output, each with
  the instruction and the op); `start_nodes`; `start` (a caption).

A start that prints no value is `INVALID_ARGUMENT`, as for slices; a start
function the decompiler failed on is `FAILED_PRECONDITION`. Viewers of the
project may call it. **Python**: `Program.trace(function, "backward" |
"forward", variable= | token= | varnode=, max_depth=, max_functions=, ...)`;
**MCP**: `trace_value` (a variable by name: each function with its lines
and depth, the calls crossed, the unknowns); the UI's **Trace value across
calls** ([ui.md](ui.md#tracing-a-value-across-calls)).

Not followed yet (the next steps): values through memory (a store and the
loads that may read it: needs alias analysis, starting with stack slots
and globals at constant addresses), indirect calls whose targets are known
(resolved jump tables, user references, vtables from MSVC RTTI), a
struct field's flow from writers to readers across functions
(`FindTypeUses` has the accesses), and the instructions of traced values
marked in the listing as slices do.

### Call-site signature overrides

`api_minor` 53, feature `call-signature-override` (Ghidra's Override
Signature, Edit Signature Override and Remove Signature Override on a
call; the UI's actions are in [ui.md](ui.md#signature-overrides)).
`CallSignatureOverride{call, signature}` keys `CALL_SIGNATURE` at the call
instruction, `sub` "", and goes through `AppendAssertions` like any edit:
one undo step, blame, history, revert by provenance, replicated to peers
and kept in project archives.

- `signature` is a `TypeSpec`: a function type's hash, or a C prototype
  (`"int sum(int n, int a, int b)"`, the name ignored) parsed against the
  program's types; types it lacks are defined with it, as for a retype.
  The value is `h:<hash>`: a prototype that doesn't parse, or a type that
  isn't a function's, is refused (`INVALID_ARGUMENT`).
- `call` must be a call instruction: a direct or computed call (its p-code
  has `CALL` or `CALLIND`), or a branch a `FlowOverride` makes a call.
- An unset `signature` removes the override (the value ""), as Ghidra's
  Remove Signature Override does; retracting the assertion undoes it.

The decompiler takes the prototype for that call alone, in place of its
callee's (`Override::insertProtoOverride`, what Ghidra's Java side sends as
a call's prototype override): its return, parameters (types and names,
the storage assigned by its calling convention) and varargs. For a call to
a varargs function, the arguments this call passes; for a computed call,
its target's prototype; for a callee whose prototype is wrong at this call,
the right one. It wins over a format string's call-site prototype
([types.md](types.md#format-strings)). The function containing the call
is decompiled again (its decompilation and the call's listing row are
invalidated); its callee and other callers are untouched.

`ListingRow.call_signature` (with `call_signature_origin`, who set it)
shows the override on the call's row, and a decompiler `FUNCTION_NAME`
token of the call has `CodeToken.call_signature`: the prototype as C,
named for the callee (`"int sum(int n, int a, int b)"`; `"int (int a)"`
for a computed call). **Python**: `Program.override_call_signature(call,
c_prototype | type_hash=)`, `remove_call_signature(call)` and
`call_signature(call)`; `fact_key` kind `"call_signature"`; **MCP**:
`override_call_signature` (an empty prototype removes it); **TypeScript**:
an `AssertionBody` with `callSignature`.

### Register values

`api_minor` 87, feature `register-values` (Ghidra's Set Register Values,
Clear Register Values and the register manager; the UI's in
[ui.md](ui.md#register-values)). A register holds a constant wherever
code runs in an address range, and analysis and the decompiler take it as
known there: MIPS `gp`, so `gp`-relative loads and stores reach the small
data they address; the PowerPC 64 TOC in `r2`; PowerPC 32's small data
bases in `r13` and `r2`; any register a program keeps constant over a
range (a segment-like base).

**Analysis's values** come from the ELF file, as Ghidra's MIPS and
PowerPC support sets them (`ProgramInfo::register_defaults`,
`src/analysis/program.cc`):

| Processor | Register and value | Where | Origin |
| --- | --- | --- | --- |
| MIPS | `gp` = `DT_MIPS_GP_VALUE` (the loader's `_mips_gp_value`), else the `_gp` (or `_GP`) symbol (`MipsAddressAnalyzer`), else `__gnu_local_gp`, else the GOT's base + 0x7ff0 (`.got`, or `DT_PLTGOT`; the ABI's `gp`, as Ghidra's MIPS relocations compute it) | the executable memory | `mips-gp` |
| PowerPC 64, ELFv1 | `r2` = the TOC of the function's `.opd` descriptor (`PowerPC64_ElfExtension.markupDescriptorEntry`) | each function's entry | `ppc64-opd` |
| PowerPC 64, ELFv2 | `r2` = the TOC base: `.TOC.`, else `.got` + 0x8000, else `.toc`'s start (Ghidra's `TOC_BASE` prefers `.toc`) | the executable memory | `ppc64-toc` |
| PowerPC 64, ELFv2 | `r12` = the function's global entry, which it computes `r2` from (`setEntryPointContext`) | each function symbol's address and the entry point | `ppc64-entry` |
| PowerPC 32 | `r13` = `_SDA_BASE_`, `r2` = `_SDA2_BASE_` (EABI small data; Ghidra sets them when relocations use them, revkit wherever the symbols are defined) | the executable memory | `ppc-sda`, `ppc-sda2` |

RISC-V's `gp` (`__global_pointer$`) stays a decompiler input only
([decompiler-inputs.md](decompiler-inputs.md)). Not done: Ghidra's
recovery of a `gp` the code writes (`_gp_1`, from `MipsAddressAnalyzer`'s
"Recover global GP register writes"), which a stripped MIPS image without
a GOT would need, and `t9` at a MIPS function's entry.

**The user's values.** `SetRegisterValue{register_name, range, value,
clear}` keys `REGISTER_VALUE` at `range.first`, `sub`
`"<register>:<hex length>"` (`gp:18`); the value is the value in hex, or
`none` for `clear`. It goes through `AppendAssertions` like any edit: one
undo step (several ranges, a function's body, in one request), blame,
history, revert by provenance, replicated to peers and kept in project
archives. Overlapping ranges of one register compose like `MUTABILITY`:
each byte goes to the live assertion of the highest precedence, then the
most recent, and all of them over analysis's values; a `clear` takes away
what is under it (analysis's `_gp` over a function, an older value).

- `register_name` is the language's register, matched exactly and then
  ignoring case, and stored as the language spells it (`GP` is `gp`); at
  most 8 bytes, and not a context register: `TMode`, MIPS16's or VLE's
  mode decide how code decodes, which Disassemble ARM / Thumb
  ([listing-edit.md](listing-edit.md)) sets.
- `value` must fit the register; `range.first` and `range.last` must be
  in memory, `first` no later than `last`.

**How they are used** (`src/analysis/register_values.h`):

- *References.* A flow's constants (`analysis.flow`'s data references,
  [data-analysis.md](data-analysis.md) step 1) start with the values at
  the instruction: a register with a value there that the flow doesn't
  know (never written on the path, written with an unknown value such as
  `lw gp, 16(sp)` after a call, forgotten at a call) reads as that value.
  The loads, stores and addresses found only through them are the
  instruction's references too (xrefs: from a delay slot when there is
  one), so data analysis defines and labels what they reach
  (`DAT_`, strings, pointers), and the listing shows the target after the
  operand that names the register, as Ghidra does:
  `lw at,-0x7fe0(gp)=>counter`. A value the code computes (`lui gp, …;
  addiu gp, …`) wins over the range's.
- *The decompiler* takes the values at a function's entry as tracked
  registers (`getTrackedRegisters`), over the inputs' own (a clear removes
  analysis's), so `*(int *)(unaff_gp + -0x7fe0)` is `counter`.
- *Invalidation.* An edit invalidates the listing over its range (the
  marks), the decompilations of the functions over it, and what the
  references then changed (rows, labels, xrefs; as for a flow override).
  A rebase moves the ranges, not the values.

`ListRegisterValues{register_name, range}` returns the painted map
(`RegisterValueRange`: register, range, value, `origin`, and `key` for an
assertion's), by register then address, and `registers` (the registers
values may be set on, with their sizes). `ListingRow.register_values`
(`RegisterAssumption`: register, value, `analysis`, `origin`) marks the
row where a range starts and a function's entry row, as Ghidra's
`assume gp = 0x418ff0`. **Python**: `Program.set_register_value(register,
value, first, last=None, function=None)`, `clear_register_value(...)`,
`register_values(register="", first=, last=)`, `register_value(register,
addr)`, `value_registers()`; **MCP**: `set_register_value` (with `clear`),
`list_register_values`; **TypeScript**: an `AssertionBody` with
`registerValue`.

**Measured** on the firmware corpus's fwkit sources (FreeRTOS, lwIP,
littlefs, monocypher; `corpus/firmware`) built with clang 18 and ld.lld at
`-O2` as a little-endian MIPS32 program with small data (`-G 8`, `_gp` in
the linker script) and as a PowerPC 64 ELFv2 program, with analysis's
register values and with every range cleared (the same daemon, so the
feature off). The corpus's own MIPS and PowerPC images are raw and built
with `-G0` (U-Boot keeps `gd` elsewhere), so the firmware gate's figures
are unchanged.

| Program | | Data references | Function → global references | Functions whose C has `unaff_gp`, `in_r2`, `in_r12` | Global names in the C |
| --- | --- | ---: | ---: | ---: | ---: |
| fwkit MIPS `-G 8` (571 functions) | without | 2778 | 6 | 186 | 402 |
| | with `gp` | 3527 | 352 | 0 | 741 |
| fwkit PowerPC 64 ELFv2 (906 functions) | without | 0 | 0 | 618 | 177 |
| | with `r2`, `r12` | 3398 | 550 | 0 | 1193 |

("Function → global references": distinct pairs of a function and a
symbol-table object it reads, writes or takes the address of; "global
names": symbol-table objects named in each function's C, summed.)

### Decompiler settings

`api_minor` 106, feature `decompiler-settings`
([decompiler-inputs.md](decompiler-inputs.md#source-shape)). From this
version revkit's decompilations follow what the instructions encode where
Ghidra's canonical forms differ: a loaded value's signedness follows its
load's extension (`ldrh` and `ldrb` unsigned, `ldrsh` signed), a
comparison against a constant has the constant on the right
(`x > 8`, not `8 < x`; `x >= 0`, not `-1 < x`), a signed flag test of a
decrement's result is one test (`subs r2,r2,#1; bgt`: `n > 0`, not
`iVar2 != 0 && bVar1`), and a structure's bitfields print as fields. A
program's settings change that:

`SetDecompilerSettings{settings: DecompilerSettings{comparison_form,
compilable_c, load_types, ghidra_flag_tests}}` keys a `NOTE` at 0 with the
reserved sub `revkit:decompiler-settings` (its text the serialized
settings); one undo step, blame and history as any assertion, kept in
project archives. Every field's default is revkit's, so empty settings (or
retracting the assertion) give them back. Every decompilation of the
program is redone (`QUERY_KIND_DECOMPILE` for the program); `Decompile`,
`DecompileMany`, `ExportC`, `ExportDecompScratch` and the slices all see
them.

- `comparison_form`: `COMPARISON_FORM_RIGHT` (the default), `_ENCODED`
  (also the constant the instruction compares against where the decompiler
  moved it by one: `x >= 9`, `x <= 0`; for Metrowerks CodeWarrior, whose
  constants are the source's, where GCC and LLVM rewrite `x < 10` as
  `x <= 9` themselves) or `_GHIDRA` (`8 < x`, `x < 1`).
- `load_types`: `LOAD_TYPES_ALL` (the default), `_WORDS` (but for
  zero-extended bytes: compilers also load a signed `char` with `movzx` or
  `ldrb`, and `byte` can displace a string buffer's `char`) or `_GHIDRA`
  (by their uses alone). Inferred prototypes
  ([infer.md](infer.md#load-types)) are inferred with the default's load
  types; a program's `load_types` doesn't infer them again.
- `compilable_c`: C a compiler accepts as it is (`*(T *)((char *)&x + 2)`
  for `x._2_2_`, `*(T *)&x` for `_x`, `;` after a label ending a block,
  casts on pointer/integer conversions, `unsigned short` for DWARF's
  `unsigned_short`). Off by default: the casts cost readability.
- `ghidra_flag_tests`: Ghidra's two tests for `subs; bgt`.

A matching decompilation of a Nintendo DS game ([nds.md](nds.md)) wants
`comparison_form` encoded and, for scratches, `compilable_c`.

**Tokens.** A volatile register's token (a read or write through an
address in a volatile region, which the decompiler prints from its user
op's annotation) is a `GLOBAL_VARIABLE` with the global at the address as
its variable entry, or, where there is none, the address as its `target`
(it was `PUNCTUATION` with neither); a string literal's `STRING` token has
the string's address as its `target`; a bitfield's `FIELD` token has its
structure (`parent_type_hash`) and the offset of the bytes holding it
(`field_offset`). `Variable.type.display` and `FunctionPrototype`'s are
C's spelling of the type (`code **`, `int[16]`, `char (*)[8]`), where they
were the decompiler's debug spelling (`code() * *`, `int [16]`).

Python: `Program.set_decompiler_settings(comparison_form="encoded",
load_types="all", compilable_c=True, ghidra_flag_tests=False)` (no
arguments: revkit's defaults). rk-lift: `--source-shape <list>`,
`--no-source-shape`, `--compilable-c`.

### Structures from pointer use

`TypeService.AutoStructure` (`api_minor` 32, feature `auto-struct`;
[types.md](types.md#structures-from-pointer-use)) is Ghidra's Auto Create
Structure, Auto Fill in Structure and Create Structure, asserting
nothing. The request names a `variable` (`AutoStructureVariable`: the
function's entry and the variable's `storage_key` from its
decompilation) or a `range` (`AddressRange`, inclusive), a `mode`
(`CREATE`, or `FILL` the structure the variable points to; a range only
creates), `call_depth` (how many calls deep to follow the pointer into
the functions it is passed to; unset 1, at most 4) and a `name` (empty:
`astruct`, or the first `astruct_N` the program doesn't name). The
response:

- `fields` (offset, size, name, `type_display`, `type_hash`, `source`:
  `ACCESS`, `EXISTING` or `DATA`, how many accesses start there, and
  `truncated` when the accesses were wider than the room before the next
  field), `size`, `name`, `named_key` ("struct astruct"; empty for an
  anonymous structure being filled in) and `c_definition`;
- `nodes` and `hashes`, `DefineType`-ready as `ParseCResponse.nodes`
  (references are `assertion_index` into `nodes` or hashes of the
  program's types): the structure at `struct_index` and a pointer to it at
  `pointer_index`, with `struct_hash` and `pointer_hash`; `existing_hash`
  is the structure a `FILL` started from;
- for a variable, every access found (`PointerAccess`: function and
  variable, offset from the structure's start, size, `LOAD`, `STORE` or
  `PASSED` with the callee and parameter, what the value is, the
  instruction, the call depth), the functions read, and `notes`
  ("FUN_x failed to decompile"); `unchanged` when nothing would change.

To apply it, put `nodes` first in one `AppendAssertionsRequest` (in
order, as they are), then `bind_type_name{assertion_index: struct_index}`
when `named_key` is set, then a `retype` of the variable to
`pointer_hash`, or for a range a `listing_edit` defining `struct_hash` at
`range.first` (a Define data may name a type defined earlier in the same
request): one revision, one undo, the client's provenance. The SDKs'
helpers do this (`auto_structure_bodies`, `autoStructureBodies`).
With feature `auto-struct-edit` (`api_minor` 56) the request also takes
`edits` (`AutoStructureFieldEdit`: by offset, a new `name`, a new type as
`type_c` or `type_hash`, `remove`, or `add` in filler) and a third source,
`field` (`AutoStructureFieldTarget`: the function, the outer structure's
hash, the field's offset and the `base_storage_key` it is read through,
"param:0" or a path "param:0->0x20"); the response adds `field_errors`
(offset, message: the edits left out), `AutoStructureField.edited`, and
for a field target `outer_index`, `outer_hash` and `outer_named_key`: also
bind `outer_index` (and retype nothing) to apply it
([types.md](types.md#editing-the-preview-and-chaining-api_minor-56)).
`NOT_FOUND`: no function at the address, or no such variable in its
decompilation; `FAILED_PRECONDITION`: `FILL` on a variable that doesn't
point to a structure, a field target too small for a pointer or not used
as one; `ALREADY_EXISTS`: a `name` the program has;
`INVALID_ARGUMENT`: no source, a range over 1 MiB or outside memory,
`FILL` with a range. Viewer role (it reads); applying needs an editor's.

### Raw layout detection

A raw import (`ImportOptions` format `raw`) needs what a file with no
header doesn't say: the language, the load address, where the image
starts in the file, and the memory beside it. Since `api_minor` 23
(feature `raw-detect`) the daemon suggests them from the file's bytes
(`revkit::detect`, [autodetect.md](autodetect.md)); nothing is imported or
stored, and the client decides what to import.

- **API.** `ProjectService.DetectRawLayout{project_id, path | content,
  hints, detect_id}` names the file as `ImportProgram` does. It answers
  up to three `suggestions`, best first. Each is a `RawLayoutSuggestion`:
  - `options`, ready for `ImportProgramRequest.options`: format `raw`,
    `language_id` and `compiler_spec_id`, `has_image_base`/`image_base`
    (false: undetermined, e.g. position-independent code), `raw_offset`
    and `regions`;
  - a `DetectConfidence` (`HIGH`, `MEDIUM`, `LOW`) per answer: processor,
    variant, base and offset;
  - `evidence` (`{about, text}` sentences for people: "15702 instructions
    decode (96% of the sampled bytes); 95% of 1503 relative branches land
    on an instruction nearby (1% of the same bytes shuffled)");
  - `tie_group` (the languages the evidence can't tell from
    `language_id`), `score` (for ordering only) and `language_pinned`;
  - `region_details` (first suggestion only): each of `options.regions`
    as a `RawRegionSuggestion` with its `kind` (`RAM`, `MMIO`), the
    `region` as an import takes it, its `spec` ("ram:20000000:8000"), a
    `confidence` and its `evidence` sentences; plus memory the code
    accesses that nothing classifies (kind `UNKNOWN`, which
    `options.regions` leaves out).

  With a `refusal` (`reason` `high-entropy`, `not-code`,
  `unknown-processor` or `too-small`, and a `detail` sentence) the
  suggestions are the closest guesses, to show and not to apply; clients
  should show an unknown reason as it is. `segments` maps the whole file
  as padding, high-entropy, text and code-like stretches; `file_size` and
  `elapsed_seconds` close the response. `HIGH` is meant to be relied on
  (detection is tuned to keep wrong `HIGH` answers at zero); anything else
  is for the user to check, and the UI never imports without the user
  confirming.
- **Hints.** `hints.language_id` ("ARM:LE:32:v7", with or without
  `:compiler`) tries only its processor's languages, and the suggestion
  whose language or tie group covers it names it and comes first
  (`language_pinned`); `hints.processor` ("ARM", "MIPS") only narrows the
  search. An unknown language or processor is `INVALID_ARGUMENT`.
- **Progress and stopping,** as for an import: send a random `detect_id`
  (at most 128 characters) and poll `GetRawDetectProgress{project_id,
  detect_id}` while the call runs. It answers `phase` (`QUEUED`, `READING`,
  `SEGMENTS`, `PROCESSOR`, `LAYOUT`, `DONE`), `message` ("Trying 76
  languages: 43 done", "Working out the load address, where the image
  starts in the file and the variant"), `progress` (0..1, never decreasing; -1 while
  queued), `done`, `error`, `cancelled`, `candidates_done`/`_total` and
  `elapsed_seconds`. `CancelRawDetect{project_id, detect_id}` stops it:
  the detector checks between candidates, and `DetectRawLayout` answers
  `CANCELLED`. A gRPC caller that goes away stops it too; the HTTP
  gateway's unary calls don't tell the daemon, so browser clients cancel
  explicitly (the TypeScript SDK's `detectRawLayout` does when its signal
  aborts). Only the caller that started a detection can read or stop it
  (anyone else gets `NOT_FOUND`), and entries are kept five minutes after
  it ends, at most 64 ended ones per caller.
- **Limits.** The role `ImportProgram` needs (admin, project scoped: it
  reads a host path and runs the decoders on what it is given), and the
  project must be open. Uploads are bounded by
  `ServerInfo.max_request_bytes`; paths must be regular files of at most
  1 GiB, checked before anything is read. The daemon runs two detections
  at a time, each on `--analysis-threads` threads (default the
  hardware's, at most 8); eight more
  wait (phase `QUEUED`) and the rest are refused with
  `RESOURCE_EXHAUSTED`. Waiting and running both end when the call is
  cancelled.
- **Cost.** One pass decodes samples of the file as every candidate
  language (76 on the default install), then works
  out the best answer's layout. Measured on 8 threads (RelWithDebInfo):
  armfw scaled to 220 KB (`build.sh ... -O2 2000`) 1.7 s on an idle
  machine and 2.8-3.3 s with the machine busy, scaled to 0.9 MB 5.1-5.5 s
  busy; 4 MB of random bytes is refused as `high-entropy` in 10 ms.
  `rk-lift --detect FILE` prints the same answer as JSON.

### Binary diffing

`DiffService` (`api_minor` 16, feature `diff`; [diff.md](diff.md)) matches
the functions of two programs of a project and ports markup from the
analysed one (A) to the new one (B):

- **Sessions.** `CreateDiffSession{project, program_a, program_b, name,
  options, run}` records a session (a project record: one revision);
  `ListDiffSessions` lists them, newest first.
- **Runs.** `RunDiff` computes the session's matches at head in the
  background (every function's fingerprints, then the matching);
  `GetDiffStatus` reports its phase, progress, the revision it computed
  at, its timings and the counts; `CancelDiff` stops it. Reads don't need
  a run: they compute the matches on demand. A run after edits recomputes
  only what changed.
- **Reads.** `ListMatches` filters by tier, confidence range, status
  (proposed, accepted, applied), change kind (unchanged: equal masked
  bytes; modified) and name, sorts (by either side's address or name,
  confidence, similarity, tier, status) and pages (tokens, or `offset`);
  each `DiffMatch` carries both functions, the tier, a calibrated
  confidence, a similarity, the status, the evidence (tier, relation,
  parent pair, round, group, and in words) and the Match assertion's seq.
  `ListUnmatched{side}` gives the functions without a match, with the
  reason (a tie, weak candidates, none) and their candidates.
  `GetFunctionDiff{entry_a and/or entry_b}` gives both functions'
  summaries (sizes, callees, fingerprints, prototype) and the match or the
  candidates.
- **Inside a pair** (`api_minor` 17, feature `diff-detail`).
  `GetFunctionDiff{…, detail: true}` adds `DiffDetail`: each side's
  blocks (`DiffBlock`: range, status UNCHANGED/MODIFIED/ADDED/REMOVED, the
  one-to-one partner, rows, successors), each side's instructions
  (`DiffRow`: address, text and tokens as the listing shows them, label,
  comment, flow; status EQUAL/CHANGED/INSERTED/DELETED, partner row, block,
  moved), the aligned `lines` (a row index per side, -1 for a gap), the
  `hunks` (lines where a difference starts), the `references` gained or
  lost (calls and data, named, a call target's match on the other side,
  `unmatched` for a callee only one side has) and a `DiffChangeSummary`
  (counts and a line of text). `DiffRow` carries the row's tokens as
  `DiffToken` (a `ListingTokenKind` number) because `diff.proto` can't
  import `listing.proto` (it depends on it through `assertion.proto`).
  `SummarizeFunctionDiffs{pairs}` (at most 500) returns the summaries
  alone, for a match table. The correlation is memoized per pair
  (`diff.correlation`); a read applies the session's current matches to
  calls. Details: [diff.md](diff.md#inside-a-function).
- **Decisions** are assertions (`FACT_KIND_MATCH` in B's space, body
  `diff_match`, written only by DiffService): `AcceptMatches` (pairs, or
  every proposal at or above `min_confidence`; a pair conflicting with
  someone's accepted match is `FAILED_PRECONDITION`), `RejectMatches` (the
  pair is never proposed again; an accepted or applied match of it is
  retracted), `SetMatch` (by hand; replaces the matches either function
  had). Proposals are derived, so a decision costs a commit and the
  incremental re-application, not a re-match.
- **Porting.** `ApplyMarkup{pairs | min_confidence (0.95), items, policy,
  dry_run}` ports names (only over default names), comments
  (function-level; every comment of an unchanged function at the same
  offset) and prototypes (with their type closure defined by hash, never
  bound) as one revision: provenance `MIGRATION` id `diff`, version = the
  session, session = the run id (`run_id` in the response, with the counts
  and the assertions' `seqs`); each assertion depends on its pair's Match
  (recorded by the run when the pair wasn't accepted) and carries
  `Assertion.ported_from` (source program, function, address, source
  assertion, Match). Retracting the Match removes what was ported through
  it. `RevertApply{session, run_id}` retracts a run in one revision.
- **Any two functions** (`api_minor` 54, feature `function-compare`;
  [diff.md](diff.md#comparing-two-functions)). `CompareFunctions{program_a,
  entry_a, program_b, entry_b, session_id?, markup}`: two functions of one
  program or two, with or without a session; the summaries, `DiffDetail`,
  and with `markup` a `CompareMarkup` (signatures, the variables paired
  across with evidence, comments with their place on the other side).
  `PortFunctionMarkup{from_program, from_entry, to_program, to_entry,
  items, overwrite, dry_run}` carries the name, signature, variables'
  names and types and comments either way as one revision by the caller
  (`ported_from` on each assertion; `seqs` undo it). `Unmatch{pairs}`
  retracts the pairs' decisions; `AcceptMatches`, `RejectMatches` and
  `SetMatch` return `seqs`, every op of the decision, for a one-step undo.
  ApplyMarkup's comments of a modified pair go by the instruction map.
- **Invalidation.** `QUERY_KIND_DIFF_SESSION` with `diff_session_id`, sent
  for both of the session's programs when either's functions or names
  change, or the session's Match assertions or record.
- **Roles.** Reads and runs need viewer; creating a session, cancelling a
  run, decisions and ports need editor.

### Firmware emulation

`EmulatorService` and `DebugService` run firmware on a **machine**
(`api_minor` 20, feature `firmware-emulation`;
[firmware-emulation.md](firmware-emulation.md)): a CPU exception model,
memory, peripherals, their interrupt wiring and a clock.

`CreateEmulatorSessionRequest.machine` is a machine description (JSON:
memory, the image load, peripherals, interrupt wiring, a clock), and
`machine_name` one saved with the program; `DebugService`'s emulator
target takes the same. The session then runs the program on that
board: the machine sets the entry (its reset vector unless it or the
request names one), `mode` and `arguments` don't apply, and `stdin`
goes to the console UART. A description that doesn't parse or fit the
program is `INVALID_ARGUMENT` with a line and column.

- Responses describe the machine (`EmulatorMachineInfo`: CPU model,
  devices, clock). States carry `machine`, `tick` and `waiting`.
  Stop kinds `EXCEPTION` (an exception breakpoint) and `IDLE` (waiting
  for an interrupt nothing is scheduled to raise) are new in both
  services; clients that don't know them see an unknown enum value.
- `WriteEmulatorInput` / `WriteDebugInput` send bytes to a UART.
  `GetEmulatorMachine` / `GetDebugMachine` return the CPU's mode, the
  banked and system registers, each device's state, pending lines, the
  machine's log, and the exceptions taken from `from_event` on (the
  machine keeps the last 4,096).
- `SetEmulatorBreakpoints` / `SetDebugBreakpoints` take
  `exception_breaks` (`irq`, `fiq`, `swi`, `svc`, `systick`, `irq:4`,
  `any`, `return`) when `set_exception_breaks`.
- Trace entries carry `exception` and `exception_number`, and the
  summary counts `exceptions`. Timeline snapshots carry `event` and
  `event_number`; `GetDebugTimelineRequest.events_only` lists only
  those. Time travel does not cover the machine's banked registers or
  its devices ([debugger.md](debugger.md#recording-and-time-travel)).
- `ListMachines`, `GetMachine`, `SaveMachine`, `DeleteMachine` keep
  descriptions with a program (in the project's directory when it has
  one; at most 64, 4 MiB each; checked when saved). `DeriveMachine`
  writes a starter from the program's memory, the MMIO its code
  reaches and trial runs, with notes on what it guessed.
  `ListPeripheralKinds` lists the built-in peripheral kinds and, with
  feature `peripheral-plugins`, the daemon's peripheral plugins.
- Roles: creating a session on a machine is creating an emulator
  session; input is a write to it (editor, its owner); saving,
  deleting and deriving machines need editor on the program's project,
  listing and reading them viewer.

### Patching

`PatchService` (`api_minor` 27, features `patch`, `assemble`,
`export-fixups`; [patching.md](patching.md)) changes a program's bytes and
exports the result:

- **Patches are assertions**: `FACT_KIND_PATCH` at the first address, body
  `patch` (`PatchBody{bytes}`, 1 to 256 bytes). Generic `AppendAssertions`
  refuses the body: write through `PatchInstruction` or `PatchBytes`.
  Overlapping patches compose, the later one winning. `RetractAssertions`,
  `RevertByProvenance`, history, blame and replication work as for any
  fact. Every read (listing, instructions, `ReadMemory`, xrefs, the
  decompiler, emulator and debugger sessions, diffing) sees the bytes as
  patched; `ListingRow.patched` and `original_bytes` (fields 40, 41) mark
  patched rows.
- **Assembling.** `Assemble{address, text, cursor?, complete?, context?}`
  assembles one instruction at the address with the processor context
  there (`context` overrides variables, e.g. `TMode: 1` for Thumb): the
  `candidates` (bytes, text as the disassembler prints them, bits changed
  from the current bytes, whether it is the current encoding), ranked
  shortest first, then nearest the current bytes or the canonical
  encoding; else `error`, `error_column` and the `expected` terminals.
  With `complete`, `completions` at the cursor from `completion_from`.
  `current_text` and `current_bytes` are what is there now.
- **Writing.** `PatchInstruction{address, text, bytes?, pad?, context?}`
  assembles and writes the first candidate, or the given `bytes` after
  checking they are one of the candidates; `pad` fills the rest of a
  longer instruction with NOPs. `PatchBytes{address, data}` writes bytes.
  Both are one revision and return its `seqs`; both take
  `expected_head_revision`. Patches must lie in the file's bytes (not
  `.bss`, a declared RAM region or synthesized memory).
- **Listing and reverting.** `ListPatches{range?}`: each live patch with
  its bytes, the original bytes, both disassembled, the text typed, the
  function, provenance, revision and time, and how many of its bytes later
  patches override. `RevertPatches{seqs | range}` retracts in one
  revision.
- **Export.** `ExportProgram{settings | use_stored_settings, host_path?,
  skip_verify?}`: the imported file with the patches at their file offsets
  (or only the image: `EXPORT_FORMAT_IMAGE`), then the fixups (checksum
  fields, the PE CheckSum, the file name from `file_name_template`); the
  response carries the bytes (or the path written on the daemon's host),
  the name, size, SHA-256, the changes, and a verification (the output
  loaded again and compared with the patched program, the fixups
  recomputed). `GetExportSettings`/`SetExportSettings` keep settings with
  the program (a `NOTE` assertion tagged `patch.export`).
- **Detecting a checksum.** `DetectChecksum{expected? | file_name?,
  patched?}` tries sums, Fletcher, Adler, CRC-16 and CRC-32 variants over
  candidate ranges of the file against its header words and the value (hex
  digits, or the hex run in a file name); each hit is a `ChecksumSpec` with
  evidence and, from a file name, its template.
- **The original.** `OpenOriginal` imports the program's file as it was
  (same options) as `<name> (original)` once, for a DiffService session
  against the patched program.
- **Invalidation.** A patch invalidates what read the bytes like any edit,
  plus `QUERY_KIND_PATCHES` for the program (`ListPatches`).
- **Roles.** `Assemble`, `ListPatches`, `DetectChecksum`,
  `GetExportSettings` and `ExportProgram` returning the bytes need viewer;
  `PatchInstruction`, `PatchBytes`, `RevertPatches`, `SetExportSettings`
  and `OpenOriginal` editor (opening the original imports, but only the
  program's own file); `ExportProgram` with `host_path` admin, like
  importing from the host.

### Byte viewer, overview and navigation

Three light reads for the UI's byte viewer, the overview bars and
next/previous by kind (`api_minor` 44, features `byte-viewer`, `overview`
and `find-next`; [ui.md](ui.md#byte-viewer-navigation-and-the-overview)).
All are snapshot reads of the listing the daemon already holds (the row
index, `listing.rows`), the memory map and the bytes as patched; none
memoizes anything new.

- **`GetByteView`** reads up to 64 KiB from an address: `data` as patched,
  as long as asked, with zeros for uninitialized memory and for addresses
  outside every block; `runs` cover the range in address order, one per
  instruction or data item (the first and last may reach past the range:
  a code unit it cuts) and one per stretch of undefined or uninitialized
  bytes (`ByteKind` `CODE`, `DATA`, `UNDEFINED`, `UNINITIALIZED`); and
  `patched` lists the stretches whose bytes differ from the file's, with
  the file's bytes. ReadMemory stops at uninitialized memory and says
  nothing of code units; a hex view needs both, in one call per screen.
- **`GetOverview`** cuts the memory blocks, in address order, into about
  `buckets` slices (default 512, at most 8192; every block gets one, so a
  program with many blocks gets more), each inside one block, with its
  bytes by kind (`code`, `data`, `undefined`, `external`,
  `uninitialized`, adding up to `length`), the kind most of them are, and
  the Shannon entropy of its bytes in bits per byte. External bytes are
  import slots, PLT sections and import thunks' bodies. Entropy is over
  a sample when the slice is large (about 8 MiB read in all, in eight
  stretches per slice), so the call stays cheap on a big program; it is
  0 for uninitialized memory.
- **`FindNext`** finds the next (`backward`: previous) place of a
  `NavigationKind` from an address. `INSTRUCTION`, `DATA` and `UNDEFINED`
  go by runs, as Ghidra's Next Instruction does: forward, the first one
  after the run of that kind the address is in; backward, the last one
  before it. Two listing spans in one block with at most 16 bytes the
  listing shows no row for between them (a byte no flow reached between
  two functions) are one run; a block boundary ends a run. `LABEL` is the
  next address with a name (function entries included), `FUNCTION` the
  next entry, `NOTE` the next address with a note (Ghidra's bookmarks),
  and `DIFFERENT_BYTE` the next initialized byte whose value differs from
  the one at the address (any initialized byte, when that one has none).
  `found` is false when there is none.

The Python SDK has `Program.byte_view`, `Program.overview` and
`Program.find_next(addr, "instruction" | "data" | "undefined" | "label" |
"function" | "different_byte" | "note", backward=False)`.

### MSVC classes

`QueryService.GetClassHierarchy` (`api_minor` 45, feature `msvc-rtti`;
[pe.md](pe.md)) lists the C++ classes MSVC run-time type information names
in a PE, by name: each class's TypeDescriptor and hierarchy descriptor,
its bases in BaseClassArray order (direct or not, virtual, the
subobject's offset, the vbtable offset and index), the classes that derive
from it directly, its vftables (address, the name the program gives it
now, the subobject they belong to, the locator, and each slot's function
with its effective name) and the struct virtual methods' `this` points to
(`type_name`, and `type_hash` where the program defines it).
`name_contains` filters by a case-insensitive substring. A program without
MSVC RTTI has none. The import's analysis also asserts the RTTI
structures as typed data, names them, makes functions at vftable entries
and gives virtual methods `this` (`analysis:msvc` assertions; a
`RevertByProvenance` of them takes it back). The Python SDK has
`Program.classes()`; MCP `list_classes`.


### Calling conventions

`QueryService.ListCallingConventions` (`api_minor` 58, feature
`calling-conventions`) lists what a function of the program can be
declared as: the compiler spec's `<prototype>` and `<modelalias>` names
(`lift::prototype_models`), the spec's `<default_proto>` first with
`is_default` (and as `default_name`), and each one's `c_spelling`, how a C
declaration says it (`__stdcall`, `__fastcall`, `__thiscall`,
`__attribute__((ms_abi))` for `MSABI`; empty for a model revkit's C parser
can't spell yet). A function gets a convention through its prototype: a
`Retype` of the function's address with a `c_declaration` using the
spelling (`int __fastcall f(int a, int b)`), which reaches the decompiler
as that model ([decompiler-inputs.md](decompiler-inputs.md#calling-conventions)).
No convention in the declaration is the spec's default. Python
`Program.calling_conventions()`; MCP `list_calling_conventions`. The UI's
Edit Function dialog uses it ([ui.md](ui.md#edit-function)).
### Function ID

`api_minor` 51, feature `function-id` ([fid.md](fid.md)). The analyzer
`function-id` names statically linked library functions by Ghidra's
Function ID hash, from Ghidra's shipped `.fidbf` databases and attached
`.rkfid` ones. It runs in the background after a PE or ELF import when an
attached database is for the program's language (`rk-daemon --function-id
off` turns it off), and on `StartAnalysis(analyzers: ["function-id"])`;
its job shows on `GetAnalysisStatus` and `CancelAnalysis` stops it. Its
names are `ANALYSIS` assertions with provenance id `fid:<database>` and a
reason (verdict, score, library), with Ghidra's plate comment: only over
discovery's default names (`FUN_…`) and its own, never over a symbol, an
export, the demangler, debug info, a user or an agent. A run retracts the
names it no longer makes.

- `ListFidDatabases{project_id | program_id}`: the databases in force for
  the caller: Ghidra's (`FID_SCOPE_BUILTIN`, id `builtin:<name>`, under
  the daemon's Ghidra root, attached unless detached), the caller's
  (`FID_SCOPE_USER`) and the project's (`FID_SCOPE_PROJECT`, a project
  note), each with its format, libraries, function count, `error` when it
  can't be read, and with `program_id`, `applies` (a library for the
  program's language).
- `AttachFidDatabase{project_id, path, scope}` (admin: the daemon reads the
  file) attaches a file for the caller or the project, or a builtin id
  again; `DetachFidDatabase{project_id, id, scope}` detaches one (a
  builtin one is detached for that scope).
- `ListFidMatches{program_id}`: the last run (not persisted; `revision` 0
  when none): each match's entry, `current_name`, the `name` Function ID
  gives (`""` when names differ and score under 30, `FID_conflict:<name>`
  when they differ in their base), `verdict`, `score`, `candidates` (name,
  library, database, score and its parts, `specific`), `libraries`,
  `comment`, the hash, and `status`: `APPLIED` (its assertion is the
  name), `KEPT` (a better-ranked name stays), `UNAPPLIED`, `REJECTED`,
  `ACCEPTED` (named as a candidate by someone).
- `ApplyFidMatch{program_id, entry, name}` asserts a candidate's name (by
  default the proposed one) as the caller; `RejectFidMatch{program_id,
  entry}` retracts Function ID's name and plate there and records the
  entry (program note `revkit:fid.rejected`) so runs leave it.
- `CreateFidDatabase{project_id, program_ids, path, family, version,
  variant, common_symbols, attach}` (admin: the daemon writes the file)
  writes a `.rkfid` from programs of the project with the names they have,
  reports what it left out (`no_symbol`, `thunk`, `too_short`,
  `duplicate`) and the callee names it couldn't relate, and attaches it
  for the caller or the project if asked.

Python: `Program.fid_matches()`, `run_fid()`, `fid_databases()`,
`apply_fid(entry, name="")`, `reject_fid(entry)`; `Client.fid_databases()`,
`attach_fid_database(path, scope=)`, `detach_fid_database(id, scope=)`,
`create_fid_database(path, program_ids, family, ...)`. revkit.script:
`fid_matches()`, `run_fid()`, `apply_fid()`, `reject_fid()`. TypeScript:
`rk.analysis.listFidMatches(...)` and the rest of the generated client.
MCP: `fid_matches`, `apply_fid_match`, `reject_fid_match`,
`fid_databases`, `attach_fid_database`, `create_fid_database`.

### Container file systems

`FileSystemService` (`api_minor` 48, feature `filesystems`;
[filesystems.md](filesystems.md)) opens containers as trees of files:

- **Sessions.** `OpenFileSystem{project_id, host_path | program_id |
  upload_id | content, name?, limits?}` opens the outermost container (a
  host file or, for batch import, a directory; a program's stored file;
  an upload; bytes) and returns a `session_id`, the root layer
  (`FileSystemLayer`: format, description, warnings, its path and
  container path) and the limits in force (a request may lower
  `FileSystemLimits`, never raise them). Sessions belong to their opener,
  at most 8 per caller and 64 in all, and close after 30 minutes unused;
  `CloseFileSystem` closes one, `ListFileSystems` lists the caller's.
- **Paths.** `!` separates nested layers and names are percent-encoded
  where they must be: `/pkg/data.tar.gz!/data.tar!/usr/bin/tool`. Pass back
  the paths a listing returns. Nested containers are mounted on demand,
  recognised by magic.
- **Listing.** `ListFileSystem{session_id, path, detect?, recursive?,
  offset?, limit?}`: a directory's entries, or a container file's root (its
  path, or the path with `!`); `layer` says which container it is in.
  `FileSystemEntry`: display `name` (U+FFFD for what isn't text), `path`,
  `kind`, `size` (or `size_unknown`), `stored_size`, `permissions`
  (`rwxr-xr-x`) and `mode`, owner, `modified`, a link's `link_target` and
  `link_path` (resolved inside its container; empty when it leaves it or
  loops), `note` and `unreadable` (encrypted, an unsupported method),
  `renamed` (a traversal or clashing name), and with `detect` what it is:
  `detected`, `detected_kind` (`elf`, `pe`, `macho`, `container`, `raw`,
  `text`, `data`, `empty`, and from `api_minor` 95 `bytecode`: a `.pyc`, a
  Lua or LuaJIT chunk, a Java class, DEX, WebAssembly, Hermes, a V8 code
  cache, which were `data` before), `container_format`, `processor`; a
  firmware member's `language_id` and `load_address` from its header.
  Detection is bounded to about two seconds per call (`detect_incomplete`).
- **Content kinds** (`api_minor` 95, feature `content-kinds`).
  `FileSystemEntry.content_kind` says what a decompiler for scripts and
  bytecode would take the file as, `family:version` where the header says
  the version: `pyc:3.12`, `lua:5.4`, `luajit:2.1`, `java-class:21`,
  `dex:035`, `wasm`, `hermes:96`, `v8-cache`, `dotnet:il`, `jar`, `apk`,
  `js-source`, ... ([the list](filesystems.md#content-kinds)). From the
  file's own header when it has one (with `detect`); else from what its
  container says (an asar's `.js` members, in every listing). Empty for
  native programs and plain data.
- **Packed executables** (`api_minor` 96, feature `packed-executables`).
  An ELF, PE or Mach-O carrying a packer's archive (PyInstaller, pkg,
  nexe, Node SEA, Bun, an appended zip) keeps `detected_kind` `elf`/`pe`
  and gets `container_format` naming the archive (in a listing only when
  the file is stored plainly; always in `GetFileSystemFileInfo`); data
  holding Lua chunks gets `lua-chunks`. `OpenFileSystem` on such a file,
  or on its program (`ProgramInfo.payload_format`), opens the archive.
  A batch import still imports the program and doesn't descend into its
  archive. Importing bytecode as a program (a `.pyc`, a class file) fails
  with `FAILED_PRECONDITION` saying what it is.
- **Apple bundles** (`api_minor` 100, feature `apple-bundles`;
  [apple-apps.md](apple-apps.md)). `FileSystemEntry.bundle_kind` names a
  directory that is a bundle (`app`, `framework`, `appex`, `bundle`, `xpc`,
  `plugin`, `storyboardc`, ...), and content kinds name Apple's files
  (`plist:xml`, `plist:binary`, `keyed-archive`, `nib:archive`,
  `nib:keyed`, `mobileprovision`, `ipa`). `GetAppleBundle{session_id,
  path, skip_info_plist?}` describes the bundle at a directory, around a
  file, or in an .ipa (`Payload/*.app`; `apps` lists them): `AppleBundle`
  with its layout (`shallow`, `deep`, `versioned`), platform, Info.plist's
  keys (`AppleBundleInfo`) and the whole of it, the main executable's path,
  description and `CodeSignature`, the nested bundles (`AppleBundleRef`:
  path, kind, role, identifier, executable, extension point, version), the
  Interface Builder files, the provisioning profile (`ProvisioningProfile`)
  and warnings. `ReadPropertyList{session_id, path, max_values?,
  max_data_bytes?}`: a plist (XML, binary, or a provisioning profile's) as
  a `PlistValue` tree, capped (`truncated`, per container `omitted`).
  Neither verifies a signature. A file that isn't a plist is
  `INVALID_ARGUMENT`; no bundle at or around a path `NOT_FOUND`.
  `ReadPropertyListRequest.resolve_keyed_archive` (`api_minor` 101) returns
  an NSKeyedArchiver archive as a tree of its objects.
- **UI actions** (`api_minor` 101, feature `ui-actions`;
  [apple-apps.md](apple-apps.md#interface-builder-and-ui-actions)).
  `ListUiActions{session_id, path, program_id?, include_documents?}` reads
  the compiled nibs and storyboards of a bundle, an .ipa, a `.storyboardc`
  or one nib, and traces each control's action (`UiAction`: the control,
  its UIKit events, the selector, the target and its class, how that class
  is known) to the Objective-C method that runs it in the program's
  metadata (`resolution` `resolved`, `resolved-by-selector`, `ambiguous`,
  `external`, `unresolved` or `no-program`; the method's name, the class
  implementing it, its implementation's address and the function's name).
  The program is `program_id`, else the session's project's program
  imported from the bundle's main executable. Outlets come as `UiOutlet`;
  `include_documents` adds each nib's objects and connections
  (`InterfaceDocument`). Viewer, and of the program's project when it is
  named.
- **Reading.** `ReadFileSystemFile{session_id, path, offset, length}` (at
  most 4 MiB a call; links followed). `GetFileSystemFileInfo{session_id,
  path, hashes?}`: the entry, its `container_path`
  (`zip://fw.zip!/bin/busybox`), the first 64 bytes, the container it
  holds (mounted), and with `hashes` SHA-256, SHA-1 and MD5.
- **Importing.** `ImportFromFileSystem{session_id, project_id, folder_id?,
  paths, recursive?, descend?, programs_only?, detect_raw?, preview?,
  max_programs?, options?, keep_folders?, provenance}`: one file named
  alone is imported whatever it is; directories and containers found
  (`descend`) give their programs only (ELF, PE, raw images whose header
  names their processor, or with `detect_raw` those raw detection
  identifies). Each item (`FileSystemImport`) says `import` (preview),
  `imported` (with its `ProgramInfo`), `skipped` or `failed`, and why;
  `max_programs` (default 100, at most 1000) caps the count (`capped`).
  Programs record `ProgramInfo.container_path`.
- **Extracting.** `ExtractFromFileSystem{session_id, paths, host_dir,
  overwrite?}` writes files (directories with everything below) under
  `--browse-root` with sanitized names; links, devices and pipes are
  skipped with the reason.
- **Errors.** A limit is `RESOURCE_EXHAUSTED` (a decompression bomb, too
  many entries, too deep, a link loop), a missing file `NOT_FOUND`,
  malformed data or a file that isn't a container `INVALID_ARGUMENT`.
- **Roles.** `OpenFileSystem` needs viewer of the project for a program's
  stored file and admin otherwise; listing, reading and info viewer (and
  the session's owner); `ImportFromFileSystem` editor of the target
  project; `ExtractFromFileSystem` admin
  ([security.md](security.md#container-file-systems)).

### Android packages

Three calls of `FileSystemService` (`api_minor` 98, feature `android`;
[android.md](android.md)) read an APK in a file system session, by the
APK's session path (`""` when the file system itself is one; any path
inside the APK names it too):

- **`GetAndroidPackage{session_id, path, skip_native?, skip_dex?}`** →
  `AndroidPackage`: `manifest` (`AndroidManifest`: `package`,
  `version_code`, `version_name`, `min_sdk`, `target_sdk`, `max_sdk`,
  `compile_sdk`, permissions used and declared, features, the
  `application_class`, `label`, `icon`, `theme`, the optional flags
  `debuggable`, `allow_backup`, `uses_cleartext_traffic`,
  `extract_native_libs`, ..., `network_security_config` and its file,
  `components` with `exported` (Android's decision) and
  `exported_explicit`, their permissions and intent filters, `meta_data`),
  `manifest_xml` and `manifest_xml_resolved`, the `resources` summary
  (packages, types with their entries and configurations), `abis`,
  `native_libraries` (session `path`, machine, soname, build ID, needed,
  `jni_exports`, `jni_onload`, the Flutter role), `dex_files`,
  `native_methods` (class, method, signature, the two JNI names, the
  `libraries` exporting them), `flutter` (per ABI the Dart snapshots'
  headers, `snapshot_hash`, features, the engine's build ID and labelled
  strings; the hash every ABI agrees on), `warnings`.
- **`DecodeAndroidXml{session_id, path, resolve?}`** → the compiled XML
  file as XML text (`xml`), its `root` element, `warnings`; references
  named from the package's `resources.arsc`, or resolved with `resolve`.
- **`ListAndroidResources{session_id, path, type?, config?, query?,
  offset?, limit?}`** → `entries` (`AndroidResourceEntry`: `id`, `name`
  such as `@string/app_name`, `type`, `key`, `config`, `value`,
  `value_type`, `reference`, a bag's `parent` and `items`), `total`, and
  the `types` and `configs` there are. `config` `""` is the default
  configuration and `*` every one; `limit` 500 by default, at most 5000.

Not an APK (no `AndroidManifest.xml` at the layer's root) or malformed
data is `INVALID_ARGUMENT`; a member over the session's limits
`RESOURCE_EXHAUSTED`. Viewer, and the session's owner, as the other reads.

### Crash dumps

`api_minor` 102, feature `crash-dumps` ([crash-dumps.md](crash-dumps.md)): an ELF
core file or a Windows minidump as a debug session, stopped where the
program crashed and read-only.

- **`CreateDebugSession{program_id, crash{dump_program_id | host_path |
  upload_id}}`**: `program_id` is the program to see the crash through (the
  crashed executable, best); the dump is a program of the same project (an
  ELF core imports as one; `ProgramInfo.crash_dump` says `elf-core`), a host
  file or an upload (those two: admin). The session's `target_kind` is
  `crash-dump`; reads work as for any stopped session (registers, memory,
  threads, modules, the memory map, `GetDebugBacktrace`, `EvaluateDebug`,
  `DisassembleDebugMemory`, `CopyDebugMemory`); resuming, breakpoints and
  writes are `FAILED_PRECONDITION`. Bytes the dump lacks are read from the
  session's program, the project programs its modules are, or (an admin's
  session) the mapped files under `--browse-root`.
- **`GetDebugCrash{session_id, max_frames}`** → `DebugCrash` (also in
  `CreateDebugSessionResponse.crash`): `format`, `arch`, `reason`, the
  signal (`signal`, `signal_name`, `signal_code`, `code_name`) or exception
  (`exception_code`, `exception_name`, `access`), `fault_address`,
  `crashed_thread`, `pc` with `module`, `module_offset` and `function`, the
  faulting `instruction` and its bytes, the `backtrace` (`DebugFrame`s),
  `threads` (each with its pc and `where`), `modules` (with the project
  `program_id` they are, a minidump's version and PDB name and GUID, a build
  ID), `pid`, `command`, `args`, `os`, `cpu`, `segments`, `dumped_bytes`,
  `main_program_id` (the project's program of the dump's executable when the
  session's isn't it), `summary` (the report as text), `comments`,
  `warnings`. Another session's is `FAILED_PRECONDITION`.

### External decompilers

`ProviderService` (`api_minor` 92, feature `external-decompilers`;
[providers.md](providers.md)) runs a dedicated decompiler on bytecode, as
a sandboxed child process of the daemon:

- **Inputs.** `ProviderInput`: a program (`program_id`: its stored file) or
  a file of a file system session (`file{session_id, path}`). What it is
  comes from its bytes: `ProviderInputKind{kind, version, description}`,
  `kind` one of `dotnet`, `dex`, `apk`, `jar`, `class`, `pyc`, `lua`,
  `luajit`, `wasm`, `js`, or empty.
- **Providers.** `ListProviders{input?, refresh?}`: each `ProviderInfo`
  (`name`: `ilspy`, `jadx`, `vineflower`, `cfr`, `unluac`, `pycdc`,
  `webcrack`, `wasm-decompile`; `title`, `tool`, `license`, `homepage`,
  `kinds`, `output` `tree` or `file`, `language`, `available`, `disabled`,
  `version`, `reason`; for admins `path`, `found_by` and the sandbox's
  `read_paths`), the `sandbox` the daemon enforces and the `limits`; with an
  input, its `input_kind`, the providers that take it (`applicable`, in
  order of preference), the `default_provider` and those with a `cached`
  result. `refresh` looks for the tools again.
- **Running.** `DecompileExternal{input, provider?, refresh?,
  max_inline_bytes?}` runs the provider (the default for the input's kind
  when empty) or answers from the cache (`cached`): `status`
  (`PROVIDER_RUN_STATUS_OK`, `FAILED`, `CRASHED`, `TIMEOUT`,
  `OUT_OF_MEMORY`, `OUTPUT_LIMIT`, `SANDBOX_ERROR`), `detail`, `stderr_tail`,
  `seconds`, `provider_version`, `input_sha256`, `output`, `language`, the
  `files` (`path`, `size`, `language`), `total_bytes`, and the `main_file`
  with its text inline (`main_text`, `main_truncated`; 1 MiB by default).
  A tool's failure is a status; a request that can't run is an error:
  `FAILED_PRECONDITION` for an input no provider takes or a provider that
  isn't available, `INVALID_ARGUMENT` for a provider that doesn't take the
  kind or an input over `max_input_bytes`, `RESOURCE_EXHAUSTED` past two
  running and eight waiting, `CANCELLED` when the caller goes away (the
  tool is killed). The call waits for the tool (120 s by default), so give
  it a long deadline.
- **Reading.** `ReadProviderOutput{input, provider?, path, offset,
  max_bytes}`: a file of the cached result (`data`, `size`, `language`,
  `truncated`), 1 MiB a call by default and at most 16 MiB; `NOT_FOUND`
  before `DecompileExternal` has run or for a path the result doesn't list.
- **Settings.** `GetProviderSettings` and `SetProviderSettings` (admin):
  `ProviderSettings{enabled, providers[]{name, path, disabled}, java_path,
  node_path, dotnet_root, timeout_seconds, memory_bytes, output_bytes,
  output_files, max_input_bytes, cache_max_bytes, allow_weak_sandbox}` (0:
  the default); paths must be absolute and names known
  (`INVALID_ARGUMENT`). Kept in `<project dir>/.revkit/providers.json`;
  `GetProviderSettingsResponse.cache_dir` says where results are.
- **Roles.** Listing, running and reading need a viewer (of the program's
  project; a session's owner), as reading the input does; the settings an
  admin ([security.md](security.md#external-decompilers)).

### Subscriptions and cache invalidation

`Subscribe(project_id, program_ids?, from_revision?, include_assertions?)`
streams one event per committed revision, in order and without gaps.

1. **Hello.** First comes `Hello{head_revision, resync_required}`.
2. **Revisions.** Each later revision sends a
   `RevisionEvent{revision, previous_revision, cause, provenance,
   assertion_seqs, assertions?, changed_keys, invalidated,
   invalidate_all_programs}`. Interleaved with these come `Heartbeat`s every
   `heartbeat_seconds` and `AnalysisProgress`.
3. **Resume.** A client resumes with `from_revision = last applied` and
   gets every revision since. If that is outside the server's window,
   `resync_required` tells it to drop its caches.
4. **Slow subscribers.** A subscriber more than 10,000 events behind is
   ended with `RESOURCE_EXHAUSTED` and should resume the same way.

Clients cache query results by (request, revision) and, for each event,
refetch only what `invalidated` names. The list is conservative: it may
over-invalidate but never under-invalidates.

| `QueryKind` | Refetch |
| --- | --- |
| `PROGRAM` | `GetProgramSummary`, `ListPrograms` |
| `MEMORY` | `GetMemoryMap`, `ReadMemory`; a memory-map edit sends it with the program in `invalidate_all_programs` (`api_minor` 24, feature `memory-map`) |
| `FUNCTION_LIST` | `ListFunctions` |
| `FUNCTION` @address | `GetFunction` for that entry |
| `LISTING` range (unset = whole program) | `GetListing` pages overlapping the range. Where code or data were (un)defined (`rows` set), `rows` and `previous_rows` are the row windows the range covers now and at `previous_revision`: rows before it keep their numbers, rows after it move by `rows.row_count - previous_rows.row_count`. `header_rows` / `previous_header_rows` are the same for clients reading with header rows, set wherever that numbering changed (also when a label, a plate or pre-comment line or a function entry came or went); they are sent once some client has read the program's listing with header rows. Row numbering may change when the range is unset |
| `INSTRUCTION` range | `GetInstruction` in the range |
| `XREFS` range | `GetXrefs` touching the range |
| `DECOMPILE` @address | `Decompile` of that function |
| `TYPES` | `FindTypes` (`GetTypes` is immutable by hash) |
| `PLUGIN_FACTS` range (unset = whole program) | `GetPluginFacts`: what analyzer plugins read changed (a name, function bounds, a flow override); only daemons with analyzer plugins send it (`api_minor` 11, feature `plugin-facts-invalidation`) |
| `ASSERTIONS` @address | `ListAssertions`, `GetHistory`, `Blame` for the changed keys |
| `PATCHES` | `ListPatches` of the program: a patch was written or reverted (`api_minor` 27, feature `patch`) |
| `PROJECT_TREE` | `ListPrograms`' folders and programs' folders: a folder was created, renamed, moved or deleted (`program_id` empty), or a program moved (its id). Project-level entries (an empty `program_id` in `changed_keys`, `invalidated` and `assertions`) reach every subscriber of the project, whatever `program_ids` it filters on (`api_minor` 37, feature `project-folders`) |
| `DIFF_SESSION` (`diff_session_id`) | `ListMatches`, `ListUnmatched`, `GetFunctionDiff`, `ListDiffSessions` of that session: either program's functions or names, or its Match assertions changed (`api_minor` 16, feature `diff`) |

Revisions that merge edits made on another daemon have cause
`CHANGE_CAUSE_REPLICATION` and the same invalidation as a local edit.
With `include_presence` (feature `presence`, `api_minor` 5), the stream also carries
`Presence` entries: who is viewing which program at which address
([collab.md](collab.md#presence)); clients publish their own with
`PresenceService.UpdatePresence` and drop entries past `expires_at`.

Example: renaming `FUN_00401040` invalidates the function list, that
function, its decompilation, the listing rows that reference it (and their
instructions), and the decompilation of every caller, because call sites
print the name. Asserting a function entry that only a data pointer
reaches invalidates the new functions (it and what it calls), the
decompilations that looked its address up, and the `LISTING` range whose
data rows became instructions, with its row windows (feature
`listing-row-invalidation`, added in `api_minor` 3). Naming an unlabelled
instruction adds a label line in the header-rows numbering: one `LISTING`
entry whose `header_rows` window is one row longer than its
`previous_header_rows` (`api_minor` 7).

### Errors

Errors use standard gRPC status codes. Over Connect they appear as
`{"code": "not_found", "message": ...}` with the matching HTTP status.

| Code | Meaning |
| --- | --- |
| `NOT_FOUND` | Unknown project, program, function, instruction, job or seq |
| `INVALID_ARGUMENT` | Malformed request; writes name the offending `assertions[i]` |
| `FAILED_PRECONDITION` | Project closed; `REVISION_EXPIRED`; retracting something already retracted |
| `OUT_OF_RANGE` | Pinned revision newer than head |
| `ABORTED` | `expected_head_revision` did not match |
| `DEADLINE_EXCEEDED` | Deadline hit, including `min_revision` waits |
| `RESOURCE_EXHAUSTED` | Subscriber fell behind |
| `UNAVAILABLE` | Daemon shutting down |
| `UNAUTHENTICATED` | No valid credentials, a wrong password, or an ended session ([security.md](security.md)) |
| `PERMISSION_DENIED` | The caller's role or project list doesn't allow the call, or its provenance names someone else; also a cookie request without the CSRF token |
| `UNIMPLEMENTED` | Unknown method, or wrong content type for a method's streaming kind |

## Transport decision

**Choice:** gRPC C++ over HTTP/2 for native clients, plus an in-process
HTTP/1.1 gateway (cpp-httplib) that speaks Connect and gRPC-web. Both are
served by `rk-daemon` itself, from one process, on two ports
(default `127.0.0.1:50051` for gRPC and `127.0.0.1:50052` for the browser
protocols and the web bundle).

### How the gateway works

The gateway has no per-method code:
1. It looks the method up in the generated descriptor pool.
2. For JSON, it transcodes with protobuf's `TypeResolver`, ignoring unknown
   fields so newer clients work against older daemons.
3. It forwards the call to the gRPC server over
   `grpc::Server::InProcessChannel` using the generic stub. Unary and
   server-streaming calls both run as "send one message, half-close, read to
   the end".

What this buys:
- **One implementation.** Both transports run exactly the same handlers,
  limits, deadlines and (later) interceptors for auth and logging. An RPC
  added to the schema is reachable from browsers as soon as the gRPC service
  implements it.
- **Clean disconnects.** When a browser goes away, the gateway cancels the
  in-process call.

The cost is one extra in-memory serialization per call, which is negligible
next to any real query.

### Protocol behaviour

- **Connect unary.** `POST /revkit.v1.<Service>/<Method>` with
  `application/json` or `application/proto`. It is curl-able and errors come
  back as JSON.
- **Connect server streaming.** Uses `application/connect+json` or
  `+proto`, enveloped messages and an end-of-stream frame. It works over
  HTTP/1.1 `fetch()` streaming in every evergreen browser.
- **gRPC-web.** Uses `application/grpc-web(+proto)` with a trailer frame.
  It is served too because it costs about 40 lines over the shared framing,
  and it lets grpc-web-only tooling work.
- **CORS.** Allowed per origin (`--allow-origin`), for a dev server or the
  Tauri origin. The bundle served from `--web-root` is same-origin and
  needs none.

### Alternatives considered

| Option | Why not |
| --- | --- |
| Envoy or `grpcwebproxy` sidecar | Not "served directly by the daemon": a second process to ship, configure and keep in sync, in Tauri and in headless deployments |
| Our own HTTP/2 server (nghttp2) speaking gRPC + Connect on one port | Smallest dependency set, but we would own HTTP/2 flow control, keepalive and deadlines, which gRPC C++ already gets right and which the Python SDK's grpcio relies on |
| Per-method Connect handlers written by hand | Two registrations per RPC that drift. The descriptor-driven gateway needs none |
| gRPC-web only | Binary-only and hard to debug. Connect gives curl-able JSON, plain JSON errors and later GET caching, and Connect-ES speaks both anyway |
| Connect over HTTP/2 to browsers | Browsers only do HTTP/2 over TLS. HTTP/1.1 carries unary and server streaming fine, and browsers cannot do bidi streaming over either |

The one real limit of HTTP/1.1 is browsers' six connections per origin,
and each open stream holds one. The API therefore has a single
project-wide `Subscribe` with a program filter, and the UI should keep
one stream per tab.

### Verification

The official Connect-ES v2 client passes `sdk/ts/test/smoke.ts` against
the daemon over Connect JSON, Connect binary, gRPC-web, gRPC (HTTP/2) and
Connect server streaming. GoogleTest covers the same protocols with a
raw HTTP client.

### Dependencies

gRPC 1.51 and protobuf 3.21 come from the system packages (`libgrpc++-dev`,
`libprotobuf-dev`, `protobuf-compiler-grpc`), found through pkg-config.
There is no gRPC source build: that would add roughly 10 CPU-heavy minutes
to every fresh build directory (default, asan and tsan each). cpp-httplib is
a single header, fetched by `FetchContent` and pinned by hash. Without the
system packages, `src/api` and `rk-daemon` are skipped with a CMake warning
and the rest of revkit builds unchanged.

## Versioning and compatibility

The protobuf package is the major version: `revkit.v1`. These rules hold for
every change merged to master. Before the first tagged release, a breaking
change to v1 needs the breaking check overridden in review and every client
in the tree updated in the same change.

**Allowed within v1** (additive, wire- *and* JSON-compatible):
- New fields with new numbers, new messages, RPCs and services, new enum
  values.
- A new field's zero value must mean "behave as before". For example, a new
  filter left empty means "no filter".
- New members of an existing `oneof` only where an old client that ignores
  the new case still behaves correctly.

**Forbidden within v1:**
- Changing a field's number, type, cardinality (singular ↔ repeated or
  map) or `oneof` membership.
- Renaming fields or enum values. JSON (Connect) uses names, so a rename
  breaks browsers even though the binary wire is unchanged.
- Changing an RPC's request or response type, or its streaming kind.
- Changing semantics or defaults of existing fields.
- Removing anything. Mark it `[deprecated = true]`, keep serving it for the
  life of v1, and when v2 drops it, `reserved` its number and name.

**Breaking changes** go into a new package, `proto/revkit/v2/`, which the
daemon serves side by side with v1 for at least one release cycle. v1 is
then frozen.

**Discovery.** Clients call `MetaService.GetServerInfo` first.
- `api_minor` increments with each additive change. Branches developed in
  parallel may each bump it; on merge, each additive change takes the next
  number, which is why clients should check features rather than numbers.
  106 added program decompiler settings (`SetDecompilerSettings`
  assertions, `DecompilerSettings`, `ComparisonForm`, `LoadTypes`) and made
  the source-shape options revkit's default (load signedness from the
  load's extension, comparisons with the constant on the right, one test
  for a decrement's flag test, bitfields as fields), with targets on
  volatile registers' and string literals' tokens and C type spellings in
  `Variable.type.display` (feature `decompiler-settings`;
  [above](#decompiler-settings));
  105 added the decomp knowledge base (`ProjectService.BuildDecompKb`,
  `ApplyDecompKb`, `DecompKbFunction`, `DecompKbCall`, `DecompKbMatch`,
  `DecompKbExport`; `ImportNdsRom`'s functions at other modules' call
  targets; feature `decomp-kb`; [above](#decomp-knowledge-base),
  [decomp-kb.md](decomp-kb.md));
  104 added what a DS matching-decompilation run needed: per-body
  refusals and `AppendAssertionsRequest.skip_invalid`,
  `AppendAssertionsResponse.refused`, `RefusedAssertion` (feature
  `assertion-refusals`); `SetFunctionBounds.instruction_set` (feature
  `bounds-isa`); `ImportOptions.memory_preset` and the DS imports' volatile
  I/O blocks (feature `memory-preset`); `NameConflict` and `on_conflict` on
  the imports, `ImportProgramResponse.name_taken_by`,
  `replaced_program_id`, `ImportDsdProjectResponse.folder_taken_by`,
  `replaced_program_ids` (feature `import-conflict`);
  `ProjectService.CompactProject`, `CompactRule` (feature `compact`;
  [backend.md](backend.md#compaction));
  103 added Nintendo DS games (`ProjectService.ImportDsdProject`,
  `ImportNdsRom`, `ExportDsdSymbols`, `QueryService.ExportDecompScratch`,
  `NdsModuleImport`, `DsdSymbolsExport`, `DsdSymbolChange`,
  `ListingToken.target_program_id`, the `revkit:program.dsd` record and its
  module links; feature `nds`; [above](#nintendo-ds-games), [nds.md](nds.md));
  102 added crash dumps as debug sessions (`DebugCrashTarget`,
  `DebugService.GetDebugCrash`, `DebugCrash`, `ProgramInfo.crash_dump`;
  feature `crash-dumps`; [crash-dumps.md](crash-dumps.md));
  101 added Interface Builder's nibs and storyboards and their UI actions
  traced to Objective-C methods (`FileSystemService.ListUiActions`,
  `ReadPropertyListRequest.resolve_keyed_archive`; feature `ui-actions`;
  [apple-apps.md](apple-apps.md#interface-builder-and-ui-actions));
  100 added Apple bundles, property lists and code signatures
  (`FileSystemService.GetAppleBundle`, `ReadPropertyList`,
  `FileSystemEntry.bundle_kind`, `MachoSummary.code_signature`, the Apple
  content kinds, `@rpath` resolution in `import_libraries`; feature
  `apple-bundles`; [apple-apps.md](apple-apps.md));
  99 added EVM contracts (`ImportOptions.format` `evm`, detected by
  content too; `raw_format` `hexbytes`; `ProgramSummary.evm`, `EvmSummary`,
  `EvmFunction`; `analysis:evm` assertions; revkit's own processors
  directory and `EVM:BE:32:default`; feature `evm`; [evm.md](evm.md));
  98 added Android packages (`FileSystemService.GetAndroidPackage`,
  `DecodeAndroidXml`, `ListAndroidResources`; feature `android`;
  [android.md](android.md));
  97 added result evidence (`FactOrigin.tier` and `SourceTier`, `Unknown`
  and `UnknownKind`, `DecompiledFunction.unknowns`, `Function.unknowns`
  from `GetFunction`; feature `result-evidence`; [Result
  evidence](#result-evidence)) and the MCP tools' evidence envelope;
  96 added packed executables and Lua in firmware as file systems (formats
  `asar`, `pyinstaller`, `pyz`, `node-sea`, `pkg`, `nexe`, `bun`,
  `lua-chunks`, and `zip` for an appended zip; `FileSystemEntry.container_format`
  on a program carrying one, `ProgramInfo.payload_format`; feature
  `packed-executables`; [filesystems.md](filesystems.md#packed-executables));
  95 added content kinds in file system listings
  (`FileSystemEntry.content_kind`, `detected_kind` `bytecode`; feature
  `content-kinds`; [filesystems.md](filesystems.md#content-kinds));
  94 added .NET assemblies recognised by their CLR header, IL-only ones
  imported without code analysis (`ProgramInfo.dotnet`,
  `DotNetAssembly`; feature `dotnet`; [below](#net-assemblies));
  93 added Go function names, source lines and no-return marks from the
  pclntab at import (`analysis:go` assertions), the golang compiler spec
  for Go programs, Go package namespaces in `ListSymbolTree` and
  `GetBuildInfoResponse.go_pclntab` (`GoPclntab`; feature `go-pclntab`;
  [go.md](go.md));
  92 added `ProviderService` (external decompilers: `ListProviders`,
  `DecompileExternal`, `ReadProviderOutput`, `GetProviderSettings`,
  `SetProviderSettings`; feature `external-decompilers`;
  [providers.md](providers.md));
  91 added Objective-C and Swift metadata at import (`analysis:objc`,
  `analysis:swift` and `import:objc` assertions) and
  `QueryService.ListObjcClasses` (`ObjcClass`, `ObjcMethod`, `ObjcIvar`,
  `ObjcProperty`, `ObjcProtocol`, `SwiftType`; feature `objc`;
  [macho.md](macho.md#objective-c-and-swift));
  90 added Mach-O (format `macho`; [macho.md](macho.md)):
  `ImportOptions.macho_slice` (a universal file's slice by arch name or
  `#N`), `ImportProgramRequest.program_file` (a program's stored file
  imported again), `ProgramInfo.macho_slice` and `macho_slices`, and
  `ProgramSummary.macho` (`MachoSummary`, `MachoDylib`, `MachoSlice`;
  feature `macho`; [below](#mach-o));
  89 added `QueryService.TraceValue` (`TraceValueRequest`/`Response`,
  `TraceDirection`, `TraceNode`, `TraceEdge`, `TraceEdgeKind`,
  `TraceUnknown`, `TraceUnknownKind`, `TraceFunction`, `TraceLine`; feature
  `value-trace`; [above](#tracing-a-value-across-calls));
  88 added `QueryService.GetBuildInfo` (`GoBuildInfo`, `GoModule`,
  `GoModuleReplacement`, `GoBuildSetting`, `RustDependencies`,
  `RustPackage`; feature `build-info`; [build-info.md](build-info.md));
  87 added register values over ranges: `SetRegisterValue` assertions
  (`FACT_KIND_REGISTER_VALUE`), `QueryService.ListRegisterValues`
  (`RegisterValueRange`, `RegisterDescription`),
  `ListingRow.register_values` (`RegisterAssumption`) and analysis's MIPS
  `gp` and PowerPC TOC (feature `register-values`;
  [above](#register-values));
  86 added `ProjectService.LoadDebugFile` (`LoadDebugFileRequest`/`Response`:
  an ELF's separate debug file by path, upload or search),
  `SymbolSettings.debug_dirs`, `debuginfod`, `debuginfod_urls`,
  `debuginfod_allow_http`, `debug_file_max_bytes`, `debug_cache_max_bytes`
  and `debug_cache_dir`, `GetSymbolSettingsResponse.suggested_debuginfod_urls`,
  and `ProgramSummary.build_id`, `debuglink`, `debug_file` (feature
  `debug-files`; [backend.md](backend.md#external-debug-files));
  85 added `SetFallthrough` assertions (`FACT_KIND_FALLTHROUGH`,
  `ListingRow.fallthrough_override`, `fallthrough`, `fallthrough_origin`,
  `InstructionDetail.fallthrough_override`, `fallthrough_origin`,
  `XREF_KIND_FALLTHROUGH`; feature `fallthrough-override`;
  [Fallthrough overrides](#fallthrough-overrides));
  84 added `SetDataSettings` assertions (`AssertionBody.data_settings`,
  `DataSettings` and its enums) and `ListingRow.data_settings`,
  `data_settings_origin`, `data_settings_type`, `data_type_settings`
  (feature `data-settings`; [listing-edit.md](listing-edit.md#data-settings));
  83 added `QueryService.PlanClearFlow` (`ClearFlowRange`; feature
  `clear-flow`; [listing-edit.md](listing-edit.md#clear-flow-and-repair));
  82 added `QueryService.ListSymbolTree` (`SymbolTreeNode`,
  `SymbolTreeNodeKind`; feature `symbol-tree`; [Queries](#queries));
  81 added `QueryService.ListLibraryImporters` (`LibraryImporter`; feature
  `library-importers`; [above](#libraries));
  80 added `QueryService.ExportC` (server stream; feature `export-c`;
  [Queries](#queries));
  79 added `ImportOptions.library_root`, `ImportProgramResponse.library_root`,
  and libraries in container imports (`ImportFromFileSystem` with
  `import_libraries`: `FileSystemImport.library_of`,
  `ImportFromFileSystemResponse.libraries_not_found` and
  `library_warnings`; feature `library-roots`;
  [above](#libraries));
  78 added `QueryService.ListRelocations` (`ProgramRelocation`,
  `RelocationKind`; feature `relocation-table`; [ui.md](ui.md#relocations));
  77 added `QueryService.ListComments` (`ProgramComment`; feature
  `comment-table`; [ui.md](ui.md#comments));
  76 added `BSimService.ApplyBSimMatches` (`BSimApplyKind`,
  `BSimApplyPair`, `BSimApplied`, `BSimApplyStatus`) and
  `PortedFrom.bsim_database` and `bsim_executable` (feature `bsim-apply`;
  [bsim.md](bsim.md#applying-matches));
  74 added `SetProgramLanguageRequest.progress_id`, followed with
  `GetImportProgress` (feature `language-progress`;
  [above](#changing-a-programs-language));
  73 added `ProjectService.SetProgramLanguage` and `CompareLanguages`
  (`LanguageFit`), `FACT_KIND_LANGUAGE` and `AssertionBody.language`
  (`ProgramLanguageBody`; feature `set-language`;
  [above](#changing-a-programs-language));
  72 added `BSimService.SearchBSim` (`BSimMatch`, `BSimQueryResult`;
  feature `bsim-search`; [bsim.md](bsim.md#searching));
  71 added `FunctionMarkupKind` `GLOBAL_NAME`, `GLOBAL_TYPE`,
  `CALLEE_NAME` and `CALLEE_SIGNATURE` and
  `PortFunctionMarkupResponse.globals` and `callees` (feature
  `port-globals-callees`; [diff.md](diff.md#comparing-two-functions));
  70 added shared libraries: `ProjectService.ListProgramLibraries`,
  `LinkProgramLibrary` and `ResolveImport`, `ImportOptions.import_libraries`,
  `library_search_paths` and `library_depth`, `ImportProgramRequest.folder_id`,
  `ImportProgramResponse.libraries` and `libraries_not_found`,
  `DebugLocation.library_program_id`, `library_address` and
  `library_function`, `DebugModule.program_id` and `library_slide` (feature
  `program-libraries`; [Libraries](#libraries));
  69 added `BSimService` (`CreateBSimDatabase`, `AttachBSimDatabase`,
  `DetachBSimDatabase`, `ListBSimDatabases`, `IngestBSim`,
  `ListBSimExecutables`, `ListBSimFunctions`, `UpdateBSimExecutable`,
  `DeleteBSimExecutables`; feature `bsim`; [bsim.md](bsim.md));
  68 added `DebugService.SetDebugHooks` and `AnswerDebugHook`
  (`DebugHookKind`, `DebugHookSpec`, `DebugHook`, `DebugHookEvent`) and
  `DebugStop.hook` (feature `debugger-hooks`;
  [debugger.md](debugger.md#hooks));
  67 added `DebugEmulatorTarget.from_session` and `from_snapshot`
  (feature `debugger-emulate-from`;
  [debugger.md](debugger.md#emulating-from-a-stop));
  66 added the `SetNoReturn` assertion body (`FACT_KIND_NO_RETURN`;
  feature `no-return`; [decompiler-inputs.md](decompiler-inputs.md#no-return));
  65 added `DebugService.RewindDebugSession` and `DebugState.rewindable`
  (feature `debugger-rewind`; [debugger.md](debugger.md#rewind));
  64 added conditional breakpoints: `DebugBreakpointSpec.condition`,
  `ignore_count` and `disabled`, `DebugBreakpointUpdate`
  (`SetDebugBreakpointsRequest.update`), and `DebugBreakpoint`'s
  `condition`, `ignore_count`, `disabled` and `condition_error` (feature
  `debugger-conditions`; [debugger.md](debugger.md#breakpoints));
  63 added `DebugService.CopyDebugMemory` (`DebugCopyMode`; feature
  `debugger-copy`; [debugger.md](debugger.md#copying-runtime-memory));
  62 added `DebugService.DisassembleDebugMemory` (`DebugInstruction`;
  feature `debugger-disassembly`;
  [debugger.md](debugger.md#runtime-disassembly));
  61 added `DebugEvalItem.frame_function` (feature `debugger-watches`;
  [debugger.md](debugger.md#expressions));
  60 added `DebugService.EvaluateDebug` (`DebugEvalItem`,
  `DebugVariable`, `DebugOperand`, `DebugValue`; feature `debugger-values`;
  [debugger.md](debugger.md#expressions));
  59 added `DebugService.GetDebugBacktrace` (`DebugFrame`; feature
  `debugger-stack`; [debugger.md](debugger.md#call-stack));
  58 added `QueryService.ListCallingConventions` (`CallingConvention`:
  name, `is_default`, `c_spelling`; feature `calling-conventions`;
  [Calling conventions](#calling-conventions); the UI's Edit Function);
  57 added `QueryService.SliceDecompiled` (`SliceKind`,
  `TokenPosition`), `DecompileOptions.include_dataflow`,
  `DecompiledFunction.dataflow` (`DataFlow`, `DataFlowNode`,
  `DataFlowOp`) and `CodeToken.op_index` (feature `decompile-slices`;
  [Slices](#slices));
  56 added `AutoStructureRequest.edits` (`AutoStructureFieldEdit`) and the
  `field` source (`AutoStructureFieldTarget`), `AutoStructureResponse.field_errors`,
  `outer_index`, `outer_hash` and `outer_named_key`, `AutoStructureField.edited`
  (feature `auto-struct-edit`; [Structures from pointer use](#structures-from-pointer-use));
  55 added `MetaService.RestartDaemon` (`RestartDaemonRequest.dry_run`
  and `reason`, `RestartDaemonResponse.mode` and `open_streams`; admins
  only; feature `daemon-restart`, added by the transport when the process
  can restart itself; the status chip's Restart daemon,
  [ui.md](ui.md#restart-daemon));
  54 added `DiffService.CompareFunctions` (`CompareMarkup`,
  `CompareVariablePair`, `CompareComment`), `PortFunctionMarkup`
  (`FunctionMarkupItem`, `PortedMarkup`) and `Unmatch`, and `seqs` on
  `AcceptMatchesResponse`, `RejectMatchesResponse` and `SetMatchResponse`;
  ApplyMarkup ports a modified pair's instruction comments by the
  instruction map (feature `function-compare`;
  [diff.md](diff.md#comparing-two-functions));
  53 added `QueryService.FindTypeUses` with `TypeUse`, `TypeUseKind`
  and `FieldAccess`, and `CodeToken.type_hash` on TYPE tokens naming a
  struct (feature `type-uses`; [below](#find-uses-of-a-type-or-field)),
  and `AssertionBody.call_signature` (`CallSignatureOverride`,
  `FACT_KIND_CALL_SIGNATURE`), `CodeToken.call_signature` and
  `ListingRow.call_signature` / `call_signature_origin` (feature
  `call-signature-override`; [below](#call-site-signature-overrides));
  51 added Function ID (feature `function-id`, [fid.md](fid.md)):
  `AnalysisService.ListFidDatabases`, `AttachFidDatabase`,
  `DetachFidDatabase`, `ListFidMatches`, `ApplyFidMatch`,
  `RejectFidMatch`, `CreateFidDatabase` and their messages (`FidScope`,
  `FidDatabase`, `FidLibrary`, `FidMatch`, `FidCandidate`,
  `FidMatchStatus`), and the analyzer `function-id`;
  49 added `ProjectService.LoadPdb`, `GetSymbolSettings` and
  `SetSymbolSettings` with `LoadPdbRequest`/`Response` and
  `SymbolSettings` (feature `pdb-load`; [pdb.md](pdb.md));
  48 added `FileSystemService` (`OpenFileSystem`, `ListFileSystem`,
  `ReadFileSystemFile`, `GetFileSystemFileInfo`, `ImportFromFileSystem`,
  `ExtractFromFileSystem`, `CloseFileSystem`, `ListFileSystems` and their
  messages) and `ProgramInfo.container_path` (feature `filesystems`);
  47 added feature `hover` (the UI's hover cards, [ui.md](ui.md#hover-cards),
  from the existing reads; the SDKs' `preview`);
  46 added feature `pe-analysis`: the PE's headers, directories, load
  config, TLS, guard tables and exception data asserted at import
  (`analysis:pe`, [pe.md](pe.md#pe-structures-and-exception-data));
  45 added `QueryService.GetClassHierarchy` with `RttiClass`, `RttiBase`,
  `RttiVftable` and `RttiVirtualFunction` (feature `msvc-rtti`;
  [MSVC classes](#msvc-classes), [pe.md](pe.md));
  44 added `QueryService.GetByteView`, `GetOverview` and `FindNext` with
  their messages, `ByteKind` and `NavigationKind` (features
  `byte-viewer`, `overview`, `find-next`;
  [Byte viewer, overview and navigation](#byte-viewer-overview-and-navigation));
  43 added the Python console: `RunScriptRequest.interactive`, `input`
  and `ghidra_names`, `ScriptStarted.console_started`, `history`,
  `read_only`, `python_version` and `completion_engine`,
  `RunScriptResponse.console_result` (`ConsoleResult`),
  `CancelScriptRequest.interrupt` (feature `script-console`) and
  `ScriptService.CompleteConsole` (feature `script-completion`);
  42 added `ProjectService.SetImageBase` (feature `rebase`,
  [memory-map.md](memory-map.md#rebase-setting-the-image-base)):
  `SetImageBaseRequest`/`Response`, `FACT_KIND_REBASE`,
  `AssertionBody.image_base` (`ImageBaseBody`) and
  `ProgramSummary.import_image_base`;
  41 added `QueryService.SearchMemory`, `SearchText`, `SearchScalars`
  and `SearchDecompiled` and their messages (`SearchFormat`,
  `SearchEncoding`, `SearchScope`, `SearchStart`, `TextField`, the
  matches; feature `search`);
  40 added demangled names (feature `demangle`, [demangle.md](demangle.md)):
  `DemangledName` and the `demangled` field of `Function`, `Symbol`,
  `Label`, `ListingToken`, `ListingHeader` and `CodeToken`; name searches
  match mangled spellings, and functions get their mangled signatures'
  prototypes (origin `derived: analysis.demangler`);
  39 added equates and user references: `AssertionBody.operand_display`
  (`OperandDisplay`, `EquateName`, `EquateScope`, `ScalarFormat`,
  `FACT_KIND_EQUATE`, `ListingToken.display_origin`,
  `CodeToken.constant_hash` and `display_set`,
  `FindTypesRequest.enum_value`; feature `equates`) and
  `AssertionBody.reference` (`UserReference`, `ReferenceType`,
  `FACT_KIND_REFERENCE`, `ListingToken.reference_origin`,
  `Xref.primary`; feature `user-references`);
  38 added `CodeToken.parent_type_hash` and `field_offset` on FIELD
  tokens (feature `field-tokens`): the struct a field belongs to, by
  hash, and its offset;
  37 added folders (`CreateFolder`, `RenameFolder`, `DeleteFolder`,
  `MoveToFolder`, `ProjectFolder`, `ProgramInfo.folder_id`,
  `folder_path` and `folder_origin`, the `folders` of `ListPrograms` and
  `OpenProject`, `RetractAssertionsRequest.project_id`,
  `QUERY_KIND_PROJECT_TREE`; feature `project-folders`) and project
  archives (`ExportProject`, `UploadChunk`, `ImportProjectArchive` and
  their messages; feature `project-archive`);
  36 added `GetServerInfoResponse.uptime_seconds`, `launch_args` (admins
  only) and `socket_activated` (feature `daemon-info`, added by the
  transport; the UI's daemon status chip, [ui.md](ui.md#daemon-status));
  35 added type archives and categories (feature `type-archive`):
  `TypeService.ExportTypeArchive` and its messages (`TypeArchiveSidecar`
  and the rest), `ParseCRequest.archive_sidecar` and
  `ParseCResponse.archive`, `ParseCNamedType.category`,
  `existing_category` and `existing_library`, `AssertionBody.type_category`
  (`SetTypeCategory`), `FindTypesRequest.category`, `category_exact` and
  `include_categories`, `FindTypesResponse.categories` and
  `TypeDefinition.category`; debug info files its types under their
  headers;
  34 added `ListingToken.scalar_bits` and `value` on the ADDRESS and SYMBOL
  tokens the disassembler printed as scalars (feature `token-scalars`;
  the Ghidra compatibility shim builds Ghidra's operand objects from them,
  [scripting.md](scripting.md#running-ghidra-scripts));
  33 added `ScriptService.SetupScriptPython` (feature `scripts-setup`);
  32 added `TypeService.AutoStructure` and its messages (feature
  `auto-struct`), and a Define data may name a type the same request
  defines;
  31 added `ScriptService` (feature `scripts-host`);
  30 added `AssertionBody.listing_edit` (`ListingEdit`: Clear, Disassemble
  here, Define data) and `AssertionBody.mutability` (`SetMutability`),
  `FACT_KIND_CODE_UNIT` and `FACT_KIND_MUTABILITY`, `ListingRow.data_field`,
  `data_parent`, `data_depth`, `data_components`, `data_collapsed`,
  `unit_origin`, `mutability` and `mutability_origin`, and
  `DATA_CATEGORY_DEFINED` (feature `listing-edit`);
  29 added `QueryService.DecompileMany`, `FindBytes` and
  `ListInstructions` (feature `script-batch`), `PROVENANCE_KIND_SCRIPT`,
  `Provenance.on_behalf_of` and `ProvenanceFilter.on_behalf_of` (feature
  `script-provenance`);
  28 added background prototype inference as an analysis job (feature
  `background-inference`);
  27 added `PatchService` (features `patch`, `assemble`, `export-fixups`),
  `FACT_KIND_PATCH`, `AssertionBody.patch`, `ListingRow.patched` and
  `original_bytes` and `QUERY_KIND_PATCHES`;
  26 added address spaces (`AddressSpaceInfo.key_base`, `is_default`,
  `alias`; `ImportOptions.raw_space` and `raw_format`,
  `MemoryRegion.space`; feature `address-spaces`);
  25 added `TypeService.ParseC` and its messages (with `__revkit_type_<hash>`
  type names, `displays`, `c_definition` and `source_line`),
  `TypeNode.is_complex`, `reference` and `is_class` (and the same in
  `TypeDefinition`), and the parsing of `Retype` `c_declaration`s (feature
  `parse-c`);
  24 added `AddMemoryRegion`, `UpdateMemoryRegion`, `RemoveMemoryRegion`,
  `GetMemoryMapResponse.rejected`, `MemoryBlock.is_volatile`,
  `region_id`, `edited`, `source` and `rejected`, `FACT_KIND_MEMORY_REGION`
  and `AssertionBody.memory_region` (feature `memory-map`);
  23 added `DetectRawLayout`, `GetRawDetectProgress`, `CancelRawDetect`
  and their messages (feature `raw-detect`);
  22 added `ImportProgramRequest.import_id`, `GetImportProgress` and
  `ImportPhase` (feature `import-progress`); 21 belongs to a branch
  developed alongside;
  20 added firmware emulation (feature `firmware-emulation`): machines
  in `CreateEmulatorSession` and `CreateDebugSession`, `WriteEmulatorInput`,
  `GetEmulatorMachine`, `ListMachines`, `GetMachine`, `SaveMachine`,
  `DeleteMachine`, `DeriveMachine`, `ListPeripheralKinds`, `WriteDebugInput`,
  `GetDebugMachine`, exception breakpoints, the `EXCEPTION` and `IDLE` stop
  kinds, events on trace entries and timeline snapshots, and
  `PLUGIN_KIND_PERIPHERAL` (feature `peripheral-plugins`);
  19 added `RenameProgram`, `DeleteProgram`, `ListProgramsRequest.include_deleted`
  and `ProgramInfo.deleted`, `deleted_origin`, `name_origin` (feature
  `program-management`), `ListFunctions` sorts by size and references,
  `descending` and filters, `Function.size`, `xref_count`,
  `decompile_failed` and parameter ID's prototypes (feature
  `function-list-filters`), and `FindTypes` `name_prefix` and
  `summary_only` (feature `find-types-tree`);
  18 belongs to a branch developed alongside;
  17 added `GetFunctionDiffRequest.detail`, `DiffDetail` and
  `SummarizeFunctionDiffs` (feature `diff-detail`);
  16 added `DiffService` (feature `diff`), `FACT_KIND_MATCH`,
  `AssertionBody.diff_match`, `Assertion.ported_from` and
  `QUERY_KIND_DIFF_SESSION`;
  15 added `ListLanguages` (feature `languages`); 14 added `DebugService` (features `debugger`,
  `debugger-live`); 13 added `AuthService` and server-stamped provenance (feature `auth`,
  plus `auth-required` and `provenance-stamping` when the daemon enforces
  them; [security.md](security.md)); 12 added `EmulatorService` (feature
  `emulator`, [emulator.md](emulator.md)); 11 added `FindTypes` on the
  image backend with `sources` and
  `include_superseded` (feature `find-types`), `BindTypeName`
  (`type-names`), `GetFunctionGraph` (`function-graph`), `ListData`
  (`data-list`) and `QUERY_KIND_PLUGIN_FACTS`
  (`plugin-facts-invalidation`); 10 added `ListHostFiles` (feature `host-files`), 9 raw imports
  (`ImportOptions` format `"raw"` and its fields, feature `raw-import`),
  8 decompiler failures (`DecompileResponse.failure`,
  `DecompileOptions.escalate` and `include_bundle`; feature
  `decompile-failures`), 7 header rows,
  6 `PluginService`, `PROVENANCE_KIND_PLUGIN` and loader plugins in
  `ImportOptions.format` (feature `plugins`); 5 is collab's sync and
  presence.
- `features` names optional capabilities, which can depend on the backend
  (for example `decompile`, `snapshot-reads`, `fake-backend`). Prefer
  feature checks to version checks, and ignore unknown feature names.

**Unknown data.**
- Enum zero values are always `*_UNSPECIFIED`. Clients must tolerate
  unknown enum values (display them as unknown); servers may add values in
  any minor.
- Binary decoding preserves unknown fields.
- The JSON gateway ignores unknown request fields, so newer clients degrade
  gracefully against older daemons.

**Enforcement.**
- `proto/check.sh [ref]` runs `buf lint` (STANDARD) and `buf breaking`
  (WIRE_JSON) against `ref` (default `master`) using the `bufbuild/buf`
  Docker image. CI should run it on every change touching `proto/`.
- Generated client code is committed. `sdk/python/tests/test_stubs.py`
  fails when the Python stubs drift from `proto/`, and the C++ code is
  generated at build time.

## Running the daemon

```sh
cmake --preset default && cmake --build --preset default
build/tools/rk-daemon/rk-daemon --open prog          # gRPC :50051, HTTP :50052; prog is default/prog
build/tools/rk-daemon/rk-daemon --backend fake       # the synthetic demo program instead
build/tools/rk-daemon/rk-daemon --grpc 0.0.0.0:7000 --http 127.0.0.1:0 \
    --web-root ui/dist --allow-origin http://localhost:5173 --port-file /tmp/rk.json
```

Flags:

| Flag | Meaning |
| --- | --- |
| `--backend image\|fake` | `image` (default) serves real ELF/PE binaries ([backend.md](backend.md)); `fake` serves the synthetic `demo/hello` for tests |
| `--open <file>` | Import a binary into project `default` at startup (repeatable; image backend) |
| `--ghidra <dir>` | Ghidra install with the processor specs (default `$GHIDRA_INSTALL_DIR`, else the build's `GHIDRA_ROOT`) |
| `--decompilers <n>` | Decompiler worker processes (`rk-decompd`), shared by every program (default 2) |
| `--decompile-timeout <s>` | A decompilation's timeout (default 30 s); its worker is killed at 1.25 times it plus 2 s |
| `--param-id auto\|on\|off` | Ghidra's Decompiler Parameter ID ([param-id.md](param-id.md)): `auto` (default) as Ghidra enables it, for PEs under 2 MiB; `on` for any program (ELF too), so `ListFunctions` and the decompiler get its committed signatures |
| `--decompile-in-process` | Decompile in the daemon itself, for debugging under gdb only (a decompiler crash then ends the daemon) |
| `--project-dir <dir>` | Keep projects in `<dir>/<project>/` (LMDB) and reopen them at startup with their assertions and cached derived facts; `--open` skips files the project already has |
| `--grpc`, `--http` | Listen addresses; port 0 picks a free port. An `--http` of `127.0.0.1`, `::1` or `localhost` (the default) listens on both loopback addresses, on the same port, so `http://revkit.localhost:50052` works whichever a browser tries |
| `--no-grpc`, `--no-http` | Disable one listener |
| `--web-root <dir>` | Static UI bundle served at `/` |
| `--allow-origin <origin>` | CORS origin (repeatable; `*` for any) |
| `--allow-host <name>` | Another name the HTTP listener answers to (repeatable; `*.example.com` for subdomains; also `allow-host = NAME` in `revkit.conf`). Always answered: `localhost`, `*.localhost`, IP addresses, the TLS certificate's names and, beyond loopback, the machine's name; any other `Host` gets 421 (DNS rebinding, [security.md](security.md#dns-rebinding)) |
| `--retain <n>` | Revisions kept readable per project |
| `--port-file <path>` | Write `{"grpc": N, "http": M}` once listening |
| `--plugin-dir <dir>` | Load WebAssembly plugins (`NAME.wasm` + `NAME.json`) from dir (repeatable; image backend; [plugins.md](plugins.md)) |
| `--scripts-host-role off\|viewer\|editor\|admin` | Who the daemon runs Python scripts and consoles for (`ScriptService`). Default: editor when every listener is on loopback, off otherwise. `viewer` lets viewers run them too, read-only (their run tokens can't edit). A script is full Python as the daemon's user ([security.md](security.md#roles)) |
| `--console-idle-timeout <seconds>` | Close a Python console idle this long (default 1800; 0: never) |
| `--script-python <path>` | The Python scripts run with (default: the first of `$REVKIT_PYTHON`, `~/.local/share/revkit/pyenv/bin/python` and `python3` that can import revkit; `rk-script setup` makes the second) |
| `--script-setup-python <path>` | The Python `SetupScriptPython` (the Script Manager's "Set up Python") makes the scripts' environment from (default `python3`) |
| `--scripts-dir <dir>` | The per-user script library (default `~/.config/revkit/scripts`) |
| `--plugin-grant <name>=<cap>[,<cap>]` | Grant a plugin a capability beyond `memory` and `code`: `file` reads the raw binary (repeatable) |
| `--peer <host:port>[,opt]...` | Replicate every project with the daemon whose gRPC listener is there, both ways (repeatable; image backend; [collab.md](collab.md)); options `token-file=`, `ca=`, `fingerprint=`, `server-name=`, `tls` ([security.md](security.md#peers)) |
| `--no-auth` | No accounts or tokens: every caller is an anonymous admin, as before api_minor 13. Loopback listeners only |
| `--auth-file <path>` | Accounts, API tokens and sessions (default `<project-dir>/.revkit/auth.db`, else `~/.local/share/revkit/auth.db`); manage them with `rk-daemon user ...` and `rk-daemon token ...` |
| `--session-ttl <hours>` | Login sessions last this long (default 168) |
| `--tls-cert <pem>`, `--tls-key <pem>` | TLS for both listeners |
| `--tls-self-signed` | TLS with a self-signed certificate made once and kept in `<project-dir>/.revkit/tls` (`--tls-dir`, `--tls-san` for more names); its fingerprint is printed |
| `--insecure-allow-remote` | Allow a plaintext listener off loopback (with a warning) |
| `--peer-secret-file`, `--peer-token-file`, `--peer-ca`, `--peer-fingerprint`, `--peer-tls` | Peer credentials and certificate checks ([security.md](security.md#peers)) |

`SIGINT` and `SIGTERM` shut down gracefully: open streams end with
`UNAVAILABLE`.

### Browser protocol with curl

These examples assume `--no-auth` on loopback. With accounts, add
`-H 'Authorization: Bearer <token>'` (from `rk-daemon token create`), and
with TLS use `https://` and `--cacert` ([security.md](security.md#clients)).

With the image backend (`rk-daemon --open prog`; the program id is
`default/prog`, addresses are decimal strings):

```sh
H='Content-Type: application/json'
curl -sS -H "$H" -d '{"programId":"default/prog","nameContains":"main"}' localhost:50052/revkit.v1.QueryService/ListFunctions
curl -sS -H "$H" -d '{"projectId":"default","path":"/abs/path/to/other.exe"}' localhost:50052/revkit.v1.ProjectService/ImportProgram
```

With the fake backend (`rk-daemon --backend fake`):

```sh
H='Content-Type: application/json'
curl -sS -H "$H" -d '{}' localhost:50052/revkit.v1.MetaService/GetServerInfo
curl -sS -H "$H" -d '{"programId":"demo/hello"}' localhost:50052/revkit.v1.QueryService/ListFunctions
curl -sS -H "$H" -d '{"programId":"demo/hello","function":{"offset":"4198464"},"options":{"includeText":true}}' \
  localhost:50052/revkit.v1.QueryService/Decompile
curl -sS -H "$H" -d '{"programId":"demo/hello","provenance":{"kind":"PROVENANCE_KIND_USER","id":"me"},
  "assertions":[{"body":{"rename":{"target":{"address":{"offset":"4198464"}},"name":"checksum"}}}]}' \
  localhost:50052/revkit.v1.AssertionService/AppendAssertions
# Server streaming (Connect envelope: 1 flag byte + 4-byte big-endian length):
printf '\0\0\0\0\024{"projectId":"demo"}' | curl -sSN -H 'Content-Type: application/connect+json' \
  --data-binary @- localhost:50052/revkit.v1.SubscriptionService/Subscribe | cat -v
```

The gRPC port has server reflection, so `grpcurl -plaintext localhost:50051
list` works.

## Clients

### Python SDK (`sdk/python`)

```sh
python3 -m venv ~/.cache/revkit/venv
~/.cache/revkit/venv/bin/pip install -e 'sdk/python[dev,mcp]'
```

```python
from revkit import Client

with Client("127.0.0.1:50051", actor="user:alice") as rk:      # a --no-auth daemon
    prog = rk.program("demo/hello")
    for f in prog.functions():               # pages transparently, one snapshot
        print(hex(f.entry.offset), f.name)
    with rk.subscribe("demo") as sub:
        prog.rename(0x401040, "checksum", reason="FNV-1a")
        print(sub.next_revision().invalidated)
    print(prog.decompile(0x401010).text)
    print(prog.blame(prog.key("name", 0x401040)).value_text)
    old = prog.at(1).function(0x401040).name  # pinned snapshot read
    prog.revert(kind="user", id="alice")     # bulk revert by provenance
    s = rk.diff("default", "default/v1", "default/v2")  # image backend: DiffService (revkit.diff, docs/diff.md)
    s.apply(min_confidence=0.95)
```

Folders and project archives (`api_minor` 37): folders by path or id,
archives to and from local files (uploaded in pieces):

```python
rk.move_to_folder("default", rk.folder_id("default", "/libs/json", create=True), programs=["default/cjson"])
rk.export_project("default", "work.rkproj")                         # or programs=, folders=, annotations_only=True
rk.import_project("work.rkproj", name="copy")                       # a new project
rk.import_project("notes.rkproj", into="default", folder="/incoming", binaries=["fw.bin"], search_dir="/srv/fw")
```

Container file systems (`api_minor` 48; [filesystems.md](filesystems.md)):
a zip, tar, compressed file or file system image, nested to any depth:

```python
with rk.open_filesystem("default", file="fw.zip") as fs:          # or host_path=, program_id=
    for e in fs.list("/pkg").entries:
        print(e.name, e.detected, e.container_format)               # "data.tar.gz", "gzip compressed", "gzip"
    data = fs.read("/pkg/data.tar.gz!/data.tar!/usr/bin/tool")
    print(fs.info("/bin/busybox", hashes=True).sha256)
    fs.import_("/", recursive=True, descend=True, preview=True)    # what a batch import would take
    fs.import_("/bin/busybox")                                       # program.container_path "zip://fw.zip!/bin/busybox"
```

Apple bundles (`api_minor` 100; [apple-apps.md](apple-apps.md)): an .ipa or
an .app, its Info.plist, signature and profile, read and not verified:

```python
with rk.open_filesystem("default", file="Demo.ipa") as fs:
    b = fs.apple_bundle("/").bundle                                 # Payload/Demo.app
    print(b.info.identifier, b.info.short_version, list(b.info.url_schemes))
    print(b.code_signature.code_directories[0].team_id, [n.role for n in b.nested])
    info = revkit.plist_value(b.info_plist)                         # the whole Info.plist as a dict
    fs.import_([b.executable_path], import_libraries=True)          # with its frameworks, by @rpath
    for a in fs.ui_actions("/").actions:                            # api_minor 101: the nibs' actions
        print(a.control_class, list(a.events), a.selector, a.resolution, a.method)  # "-[ViewController buttonTapped:]"
print(rk.program("default/Demo").entitlements()["get-task-allow"])
```

External decompilers (`api_minor` 92; [providers.md](providers.md)): a
dedicated decompiler's source for bytecode, run in the daemon's sandbox:

```python
prog = rk.program("default/Tiny.dll")
print(prog.providers().input_kind.description)                     # ".NET assembly"
ext = prog.decompile_external()                                     # ILSpy (the default for .NET)
print(ext.ok, ext.provider, ext.version, ext.cached, ext.files)
print(ext.text())                                                   # the main file's C#
with rk.open_filesystem("default", file="release.zip") as fs:
    for path, java in fs.decompile_external("/app.apk").sources():     # jadx: (path, Java) pairs
        ...
    pkg = fs.android_package("/app.apk")                              # api_minor 98, docs/android.md
    print(pkg.manifest.package, pkg.manifest.debuggable, [c.name for c in pkg.manifest.components if c.exported])
    print(fs.android_strings("/app.apk", config="fr"))                 # the strings table
    for m in pkg.native_methods:                                       # native methods and their exports
        print(m.class_name, m.method, m.jni_name, list(m.libraries))
with rk.program("default/crash").crash_dump(host_path="/srv/cores/core.4242") as dbg:   # api_minor 102
    c = dbg.crash()                                                    # docs/crash-dumps.md
    print(c.reason, c.function, c.instruction)                         # SIGSEGV (SEGV_MAPERR) at 0x0, lib_store+0x4, ...
    print(c.summary)                                                   # the backtrace, the threads
```

Against a daemon with accounts, pass a token (or a login) and how to trust
its certificate; the daemon stamps who you are, so leave `actor` unset:

```python
rk = Client("host:50051", token="rkt_...", fingerprint="3D:67:...")   # or RK_TOKEN, RK_TLS_FINGERPRINT / RK_TLS_CA
rk = Client.login("host:50051", "alice", password, ca_cert="cert.pem")
print(rk.whoami().identity.name)
```

How it fits together:
- Everything returns the generated messages in `revkit.v1`, and
  `Client.stubs` exposes the raw stubs.
- `revkit.Daemon()` starts a throwaway daemon on free ports (image backend;
  `Daemon(None, "--backend", "fake")` for the synthetic program, as the SDK's
  own fixture does), with `--no-auth`; `Daemon(..., auth=True)` gives it its
  own credential file and self-signed certificate, `add_user`,
  `create_token` and `client()` (which pins the certificate).
- `import_program(..., progress=callback)` (feature `import-progress`)
  calls `callback` with each `GetImportProgressResponse` while the import
  runs, from a polling thread, and once when it has ended.
  `import_program(..., macho_slice="x86_64")` loads a universal Mach-O's
  other slice, `program_file=<program_id>` a stored file again (feature
  `macho`); `Program.macho()` is the summary's `MachoSummary` (None for
  other formats).
- `detect_raw_layout(project_id, path=... | content=..., language_id=,
  processor=, progress=callback, cancel=event, timeout=600)` (feature
  `raw-detect`; its own deadline, not the client's unary one)
  returns the `DetectRawLayoutResponse`; `progress` gets each
  `GetRawDetectProgressResponse`, and setting `cancel` stops the
  detection on the daemon. A suggestion imports as it is:
  `import_program(project_id, path=..., options=s.options)`; or by
  field, with `raw_offset` and `regions` (`memory_region("ram:20000000:40000:rw-")`;
  `format_memory_region` the other way). `detect_confidence` names a
  `DetectConfidence`.
- `Program.search_memory(query, format=, encoding=, case_sensitive=,
  escapes=, size=, unsigned=, byte_order=, ranges=, code_units=,
  executable_only=, alignment=, start=, backward=, wrap=, max_results=,
  details=)`, `search_text(query, regex=, case_sensitive=, whole_word=,
  fields=, ranges=, start=, ...)`, `search_scalars(min, max, value=,
  instructions=, data=, ...)` and `search_decompiled(query, functions=,
  ranges=, parallelism=, ...)` (feature `search`): each runs the stream
  to its end and returns the match messages, calls `progress(message)`
  on each, stops when `cancel` (a `threading.Event`) is set, and keeps
  the last message in `Program.last_search` (`truncated`, `elapsed_ms`,
  a memory search's `pattern`). `masked_query(bytes, mask)` and
  `latin1_regex(pattern)` turn bytes into binary and regex queries.
- `Program.decompile_many`, `instructions`, `find_bytes` (with
  `byte_pattern("48 8b ?? 05")`), `strings` and `data` (`api_minor` 29;
  the first three need feature `script-batch`); `describe_provenance`
  says "alice via script:fix-names". Scripts: `revkit.script` and
  `rk-script` ([scripting.md](scripting.md)).
- Scripts the daemon runs (feature `scripts-host`): `Client.list_scripts`,
  `script_source`, `save_script`, `script_runs`, and `run_script(script_id,
  program_id, args=, address=, selection=, confirm_sha256=)`, which returns
  a `ScriptRun`: iterate it for the events, `answer(prompt, value)`,
  `cancel()`, `update_context(address=)`, or `wait(answers)` with a dict by
  prompt name or a function; then `status`, `result`, `error`, `trust`,
  `text`. `setup_script_python(force=, output=)` (feature `scripts-setup`)
  makes the daemon's script Python and returns the result.
  `Client.console(program_id, ghidra_names=)` (feature `script-console`)
  is the caller's console there: `run(source, address=, selection=,
  answers=)` returns a `ConsoleStatement` (`status`, `more`, `stdout`,
  `stderr`, `revisions`, `seqs`, `error`, `started`); `open()`,
  `complete(text)`, `interrupt()`, `update_context(address=)`, `close()`.
- `Program.add_memory_region`, `update_memory_region`,
  `remove_memory_region` and `memory_map(rejected=...)` (feature
  `memory-map`) edit and read the memory map after import
  ([memory-map.md](memory-map.md#using-it)).
- `Program.set_fallthrough` and `clear_fallthrough` (feature
  `fallthrough-override`; [Fallthrough overrides](#fallthrough-overrides)).
- `Program.define_data`, `clear_code`, `clear_flow` (and `plan_clear_flow`; feature `clear-flow`), `disassemble` and `set_mutability`
  (feature `listing-edit`, [listing-edit.md](listing-edit.md#using-it)),
  and the buffered script edits `define_data`, `clear`, `disassemble` and
  `set_mutability`.
- `Program.load_debug_file(path=None, *, local_file=None, search=False,
  force=False)`, `Client.set_debug_file_settings(dirs=, debuginfod=, urls=,
  allow_http=, max_bytes=, cache_max_bytes=)` and
  `Client.debuginfod_suggestions()` (feature `debug-files`;
  [backend.md](backend.md#external-debug-files)); `set_symbol_settings`
  keeps the debug file settings.
- `Program.set_data_settings(addr, field="", format=, signed=, endian=,
  padding=, charset=, termination=, pointer=, mask=, shift=)` and
  `set_type_data_settings(type_name, ...)` (feature `data-settings`;
  `data_settings` and `data_settings_body` build the message and body):
  how a data item, a struct field or every item of a type displays
  ([listing-edit.md](listing-edit.md#data-settings)).
- `Program.set_register_value`, `clear_register_value` (over a range or
  a function's body), `register_values`, `register_value` and
  `value_registers` (feature `register-values`; [above](#register-values)).
- `Program.set_decompiler_settings(comparison_form=, load_types=,
  compilable_c=, ghidra_flag_tests=)` (feature `decompiler-settings`;
  [above](#decompiler-settings)).
- `Program.convert`, `set_equate`, `set_enum_equate`, `clear_display`,
  `equates()` (the table folded from `ListAssertions`), `rename_equate`,
  `remove_equate`, `enums_with_value`, `add_reference`,
  `remove_reference` and `set_primary_reference` (features `equates`,
  `user-references`; `operand_display_body` and `reference_body` build the
  bodies), and the same as buffered script edits
  ([above](#equates-and-user-references)).
- `Program.auto_structure(function, storage_key, fill=, call_depth=,
  name=)` and `structure_from_range(first, last, name=)` preview a
  structure (feature `auto-struct`); `apply_structure(made, function=,
  storage_key=)` or `(made, at=)` applies it in one revision
  (`auto_structure_bodies` builds the request); `auto_create_structure`,
  `auto_fill_structure` and `create_structure` do both; the buffered
  script edits `auto_create_structure`, `auto_fill_structure` and
  `create_structure` too.
- `Program.rename_field(struct, field, new_name)` and
  `retype_field(struct, field, c_type)` edit one field of a struct or
  union as the UI's Types view does (Rename Field, Retype Field): the
  struct by hash or name (`composite_type`: "struct node", "node", or a
  typedef of it; an older version's hash edits the current one), the field
  by name or offset; its next version is written as C (unchanged fields by
  hash, a struct's fields at their offsets with undefined filler between),
  laid out by `ParseC`, and defined and bound to its name in one revision
  (`field_edit_bodies` returns the bodies and the struct's new C). A type
  that would overlap the next field or end past the struct is refused.
- `Program.resolve(text)` evaluates a Go To expression to an address
  (`revkit.expr`, as the UI's palette reads them: hex numbers, symbol
  names exactly, `+ - * /` and parentheses, `file:<offset>`,
  `<space>:<offset>`); `symbol_address(name)` and
  `file_offset_address(offset)` are its lookups.
- Type archives and categories (feature `type-archive`):
  `Program.export_type_archive(keys, scope=, hashes=, category=, name=,
  directory=)` (writes both files to `directory` too),
  `parse_type_archive(header, sidecar)`, `import_type_archive(archive,
  sidecar=)` (a header path with its `.json` beside it, a parse, or another
  program's export; None when there is nothing to do; refuses mismatched
  hashes unless `allow_mismatches`), `set_type_category(keys, path)`,
  `type_categories()` and `find_types(category=, exact=)`;
  `header_import_bodies(..., include_library=, categories=)` and
  `type_category_body`; the script helpers `export_type_archive`,
  `import_type_archive`, `set_type_category` and `type_categories`.
- Project types and archives (feature `project-types`):
  `Program.move_types_to_project(keys)`, `copy_types_to_program(keys)`,
  `append_project(*bodies)` (project-scope type bodies),
  `project_types(name_contains)`, `type_archives()`,
  `set_type_archive_enabled(name, enabled)`, `attach_type_archive(header
  path, text with name=, or an export)` and `detach_type_archive(name)`;
  the script helpers `move_types_to_project`, `copy_types_to_program`,
  `type_archives` and `set_type_archive_enabled`
  (`tests/test_project_types.py`).
- Find uses and signature overrides (features `type-uses`,
  `call-signature-override`): `Program.find_type_uses(struct, field)`,
  `override_call_signature(call, c_prototype)`,
  `remove_call_signature(call)` and `call_signature(call)`
  (`tests/test_call_signature.py`).
- Result evidence (feature `result-evidence`, [Result
  evidence](#result-evidence)): origins carry `.tier`, and
  `Program.decompile(...).unknowns` and `Program.function(...).unknowns`
  list what analysis couldn't determine. `revkit.evidence` reads them:
  `source(origin)` is `{"by": "import:elf", "tier": "symbol"}`,
  `source_tier(origin)` derives the tier for an older daemon,
  `unknowns(message)` and `unknown_dict(u)` give dicts.
  `Program.decompile_result` returns the whole response (`.failure`,
  `.snapshot`).
- To regenerate the stubs after a schema change, run
  `sdk/python/generate.sh ~/.cache/revkit/venv/bin/python` and commit the
  result.
- `ctest` runs the SDK tests when `REVKIT_PYTHON` (default
  `~/.cache/revkit/venv/bin/python`) has grpcio and pytest, in four parts
  that run in parallel: `python_sdk_1` to `python_sdk_4`, the test modules
  dealt round-robin. `ctest -L python_sdk` runs them all. Manually:

  ```sh
  cd sdk/python
  RK_DAEMON=../../build/tools/rk-daemon/rk-daemon ~/.cache/revkit/venv/bin/python -m pytest
  ```

### TypeScript (`sdk/ts`)

The generated code (protobuf-es v2) and its lockfile are committed.
Connect-ES v2 builds typed clients straight from the generated service
descriptors.

```sh
sdk/ts/generate.sh                         # buf + protoc-gen-es in node:22 Docker
sdk/ts/generate.sh typecheck
sdk/ts/generate.sh smoke http://127.0.0.1:50052 http://127.0.0.1:50051   # against rk-daemon --backend fake
```

With Node installed: `npm ci && npm run generate`.

```ts
import { createRevkit, connectTransport } from "@revkit/api";
const rk = createRevkit(connectTransport());   // same-origin when served by rk-daemon
const { functions } = await rk.queries.listFunctions({ programId: "demo/hello" });
for await (const ev of rk.subscriptions.subscribe({ projectId: "demo" })) { /* ... */ }

// With accounts: a token, or (a page the daemon serves) the session's CSRF token.
const authed = createRevkit(connectTransport(origin, false, { token: "rkt_..." }));
// Node over TLS with the daemon's certificate pinned (also protocol "grpc", "grpc-web").
import { nodeTransport } from "@revkit/api/node";
const node = createRevkit(await nodeTransport({ baseUrl: "https://host:50052", token, fingerprint }));

// A header into a program (api_minor 25): parse, choose, import as one revision.
import { parseC, importHeader, headerImportPlan, typeByHash } from "@revkit/api";
const parsed = await parseC(rk, { programId, sources: [{ kind: { case: "text", value: header }, name: "cJSON.h" }] });
await importHeader(rk, programId, parsed, { keys: ["struct cJSON"], rename: { "struct cJSON": "cjson_t" }, file: "cJSON.h" });
// headerImportPlan: the same bodies, plus prototypes' function types and
// unbound roots, with where each ParseC node went; typeByHash(hash) is a
// type the program has, by hash, in C ("__revkit_type_<hash>").
```

`clearCode`, `disassemble`, `defineData`, `setMutability` and
`setDataSettings` (feature `data-settings`, `DATA_SETTINGS_FEATURE`)
(`listingEdit`, feature `listing-edit`, `LISTING_EDIT_FEATURE`) build the
`AppendAssertions` bodies of the listing's edits; `listingEditOf(resp)`
finds the edit in a response (`sdk/ts/test/listing_edit.ts`, run by
`ctest` as `ts_sdk_listing_edit`).

Type archives and categories (feature `type-archive`,
`TYPE_ARCHIVE_FEATURE`): `exportTypeArchive(rk, request)`,
`parseTypeArchive(rk, programId, {header, sidecar})`,
`importTypeArchive(rk, programId, parsed, options)` (one
`AppendAssertions` with `import:archive` provenance and the archive's
origin; null when there is nothing to do), `typeArchiveImportBodies`,
`typeCategoryBodies(keys, path)`, `setTypeCategory` and
`normalizeCategory`; `headerImportPlan`'s `includeLibrary` and
`categories` ("chosen", the default, files a header's types under its
name; "all"; "none") (`sdk/ts/test/archives.ts`, `ts_sdk_archives`).

Project types and archives (feature `project-types`,
`PROJECT_TYPES_FEATURE`; `LIBRARY_TYPES_FEATURE` for the library
archives): `moveTypesToProject`, `copyTypesToProgram`,
`appendProjectTypes(rk, programId, bodies, provenance)`,
`listTypeArchives`, `typeArchiveBody`, `setTypeArchiveEnabled`,
`attachTypeArchive` and `detachTypeArchive` (`sdk/ts/test/projecttypes.ts`,
`ts_sdk_projecttypes`).

Structures (feature `auto-struct`, `AUTO_STRUCT_FEATURE`):
`autoStructureRequest(programId, fn, storageKey, {fill, callDepth, name})`
and `structureFromRangeRequest(programId, first, last, name)` build
`AutoStructure` requests for `rk.types.autoStructure`;
`autoStructureBodies(made, {function, storageKey} | {at})` the bodies that
apply the result in one `AppendAssertions` (`sdk/ts/test/structures.ts`,
`ts_sdk_structures`).

Searches (feature `search`, `SEARCH_FEATURE`): `searchMemory`,
`searchText`, `searchScalars` and `searchDecompiled(rk, request,
{onProgress, signal})` run a search to its end and resolve with its
`matches` and `last` message; `splitMatch(text, start, length)` cuts a
text or decompiled match (UTF-8 offsets) into JavaScript strings
(`sdk/ts/test/search.ts`, `ts_sdk_search`).

Scripts the daemon runs (feature `scripts-host`, `SCRIPTS_HOST_FEATURE`):
`rk.scripts` is the `ScriptService` client; `runScript(rk, {scriptId,
programId, args, address, selection}, {onOutput, onProgress, onPrompt,
onTrust, signal})` runs one to its end, answering prompts with `onPrompt`
(null dismisses), asking `onTrust` when the script's text is unconfirmed
and re-running with its hash, and cancelling when `signal` aborts.
`setupScriptPython(rk, {force, onOutput, signal})` (feature
`scripts-setup`, `SCRIPTS_SETUP_FEATURE`) makes the daemon's script
Python, resolving with the result.
`consoleRun(rk, {programId, input, address, selection, ghidraNames},
{onStarted, onOutput, onPrompt, signal})` (feature `script-console`,
`SCRIPT_CONSOLE_FEATURE`) runs a statement in the caller's console and
resolves with its outcome (`status`, `more`, `result`, `runId`); aborting
`signal` interrupts it. `completeConsole(rk, programId, text)` (feature
`script-completion`) completes from the console's namespace.
`scriptsForContext`, `normalizeKeybinding` ("ctrl shift R" to
"Ctrl+Shift+R") and `scriptCategoryTree` serve the UI. `ctest` runs them as
`ts_sdk_scripts` (`sdk/ts/test/scripts.ts`).

`detectRawLayout(rk, request, {onProgress, signal, pollMs})` (feature
`raw-detect`, `RAW_DETECT_FEATURE`) runs `DetectRawLayout` with a random
`detect_id`, polls its progress into `onProgress`, and when `signal`
aborts calls `CancelRawDetect` and rejects with `Code.Canceled`;
`confidenceName` names a `DetectConfidence`. `ctest` runs it against a
daemon as `ts_sdk_detect` (`sdk/ts/test/detect.ts`).

Container file systems (`api_minor` 48, `FILESYSTEMS_FEATURE`;
`src/filesystems.ts`): `openFileSystem(rk, project, {hostPath} |
{programId} | {file, name})` (bytes past 16 MiB are uploaded) returns a
`FileSystemSession` with `list`, `entries`, `read`, `info`, `import`,
`extract` and `close`; `displayPath`, `encodeName`, `joinPath`,
`parentPath` and `pathLayers` handle session paths, `isBrowsable` and
`isProgram` read an entry, and `looksLikeContainer` checks a file's first
bytes in the client (`ts_sdk_filesystems`, `sdk/ts/test/filesystems.ts`).
Apple bundles (`api_minor` 100, `APPLE_BUNDLES_FEATURE`): `appleBundle(path)`
and `propertyList(path)` on a session, and `plistValue` for a `PlistValue`
as plain data; `uiActions(path)` (`api_minor` 101, `UI_ACTIONS_FEATURE`).

Folders and archives (`api_minor` 37, `PROJECT_FOLDERS_FEATURE`,
`PROJECT_ARCHIVE_FEATURE`; `src/projects.ts`): `resolveFolder` and
`ensureFolder` (a path to an id, making the missing folders),
`moveToFolderPath`, `undoFolderEdit` (`RetractAssertions` by project),
`buildProjectTree(listPrograms)` (folders and programs as a tree) with
`walkFolders` and `folderWithin`; `exportProject(rk, request)` collects
the `ExportProject` stream into bytes and a file name, `uploadFile`
sends a `Blob` or bytes in `UploadChunk` pieces (4 MiB) and returns the
upload id, and `importProjectArchive` uploads an archive (and an
annotations-only archive's binaries) and imports it (`ts_sdk_projects`,
`sdk/ts/test/projects.ts`).

### MCP server (`revkit.mcp_server`)

```sh
revkit-mcp --daemon 127.0.0.1:50051 --agent claude --agent-version opus-5.5   # stdio
```

189 tools, all built on the public SDK. `about` (and the server's
instructions) gives an agent the workflow (list programs, pick one, find
functions, decompile, rename, retype and comment with a reason, search
again), the address syntax, how long results page, its provenance and the
daemon's features.

**The workflow guide.** `revkit/agent_guide.md`, installed with the SDK,
is the longer version: finding or importing a program, getting one's
bearings, finding what matters, reading, recording what one learns with
reasons, reviewing and undoing, BSim and comparing, running code. The
server serves it as the resource `revkit://guide` (`text/markdown`) and as
the prompt `investigate` (arguments `goal` and `program_id`: the guide,
then the task); `about` points at both. The prompt `match_decomp`
(arguments `goal` and `project_id`) starts a matching-decompilation task
with the same guide and points at its "Matching decompilation" section:
`import_dsd_project`, `set_decompiler_settings` (the per-program
decompiler settings, api_minor 106, also an MCP tool), `decomp_scratch`,
`build_decomp_kb`/`apply_decomp_kb` and `export_dsd_symbols`.

**Registering it with an agent: `revkit-mcp setup`** (or `revkit mcp
setup` from the `revkit` launcher, which passes the daemon's address). It
writes the server into the user config of each agent it finds (or those
named with `--client claude|codex|cursor|gemini|all`; `--scope project`
for the current directory's project config instead), with
`--daemon <address> --agent <the agent's name>`:

| Agent | Where (user scope; project scope) | Entry |
| --- | --- | --- |
| Claude Code | `claude mcp add-json --scope user` when the `claude` command is there, else `mcpServers` in `~/.claude.json`; `.mcp.json` | `{"type": "stdio", "command", "args", "env"}` |
| Codex | `~/.codex/config.toml` (`$CODEX_HOME`); `.codex/config.toml` | `[mcp_servers.revkit]` with `command`, `args`, `[mcp_servers.revkit.env]` |
| Cursor | `~/.cursor/mcp.json`; `.cursor/mcp.json` | `{"type": "stdio", "command", "args", "env"}` |
| Gemini CLI | `~/.gemini/settings.json`; `.gemini/settings.json` | `{"command", "args", "env"}` |

It shows each change (a diff, or the command it would run) and asks
before writing (`--yes` doesn't ask; without a terminal it writes nothing
unless given `--yes`); `--dry-run` only shows. A file it changes is copied
first to `<file>.revkit-backup-<time>`, other servers and settings in it
are kept, and an entry already as it would write it is left alone, so
running it again changes nothing. A token is never written into a config:
`--token-file` puts the file's path in `RK_TOKEN_FILE`. `--command` names
another `revkit-mcp`, `--name` another server name. The formats are each
tool's documented ones (cited in `revkit/mcp_setup.py`); setup needs only
Python's standard library.

| Group | Tools |
| --- | --- |
| Start | `about` |
| Nintendo DS | `import_dsd_project` (a ds-decomp project as module programs, linked across modules), `import_nds_rom` (a .nds image), `export_dsd_symbols` (revkit's names as symbols.txt diffs; `write` writes them, backed up), `decomp_scratch` (one function as a PROBE-line scratch with the declarations it uses) |
| Programs | `list_programs`, `program_summary`, `build_info` (a Go binary's Go version, modules and build settings; a Rust binary's cargo-auditable crates, rustc version and commits), `analysis_status`, `list_languages`, `detect_raw_layout` (admin; read-only: suggestions with hex addresses, a confidence per answer, evidence, tie group, the refusal), `import_program` (admin; `raw_offset` and `regions` for raw images, `macho_slice` for a universal Mach-O; `program_summary` has a `macho` object for one), `load_pdb` (a PE's PDB; feature `pdb-load`), `load_debug_file` (a stripped ELF's separate debug file by path, or found by build ID and debuglink, and on debuginfod servers only when an admin turned them on; feature `debug-files`) |
| Project | `create_folder` (a path, with its parents), `move_to_folder`, `rename_folder`, `delete_folder`, `export_project` (a .rkproj on the server's machine; programs, folders, annotations only), `import_project` (admin; into a new or an existing project, binaries by local path); `list_programs` shows each program's folder |
| Code | `list_functions` (filters: named or unnamed, thunks, decompile failures, an address range; sorted by address or name), `search_symbols`, `get_function`, `disassemble` (with the address to continue from), `decompile` (by line; with variable storage keys, and the struct fields it uses: name, offset and the struct's hash), `instruction` (p-code), `function_graph` (by block; optionally without instructions), `callers`, `callees`, `xrefs` (by kind), `list_classes` (C++ classes from MSVC RTTI; feature `msvc-rtti`), `list_objc_classes` (a Mach-O's Objective-C classes, protocols and Swift types; feature `objc`), `list_calling_conventions` (the compiler spec's models and their C spelling; feature `calling-conventions`) |
| Navigation | `find_next` (the next or previous function, label, instruction, data, undefined bytes, different byte or note; feature `find-next`), `overview` (each block's and each slice's bytes by kind and entropy, and the high-entropy regions; feature `overview`) |

| File systems | `open_filesystem` (a local file, a host path or a program's stored file; archives, compressed files, file system images, firmware packages), `list_filesystem` (with what each file is), `read_filesystem_file`, `filesystem_file_info` (hashes, the container path, the container it holds), `import_from_filesystem` (one file, or a batch: programs below folders and inside nested containers, with `preview` and `max_programs`), `close_filesystem`; an APK's `android_package` (manifest fields, resources, native libraries and methods, Flutter), `android_resources`, `android_xml`, `apple_bundle` (an .ipa's or .app's Info.plist, executable, code signature, nested bundles and profile; feature `apple-bundles`), `read_property_list`, `list_ui_actions` (each control's action in the nibs and storyboards, traced to its Objective-C method; feature `ui-actions`) |
| External decompilers | `list_providers` (which are installed; with a program or a file of an open file system, what it is and which take it), `decompile_external` (a .NET assembly's C# from ILSpy, a DEX's or jar's Java, a `.pyc`'s Python, ...: the main file and the file list), `read_provider_output` (any file of the output; feature `external-decompilers`) |
| Code | `list_functions`, `search_symbols`, `get_function`, `disassemble`, `decompile` (with variable storage keys, and the struct fields it uses: name, offset and the struct's hash), `instruction` (p-code), `function_graph`, `callers`, `callees`, `xrefs` |
| Search | `search_memory` (hex with wildcards, strings in ASCII/UTF-8/UTF-16, decimals, floats, binary, regex; the label and code unit of each match), `search_text` (what the listing shows: comments, labels, signatures, instructions, data; plain or regex), `search_scalars` (a value or range in operands and data), `search_decompiled` (C of every function or those listed), `find_type_uses` (where a struct or one field is used, with each field use's access; feature `type-uses`), `slice_decompiled` (where a variable's value comes from or flows to in the C; feature `decompile-slices`), `trace_value` (the same across calls: into callees' returns and parameters, out to callers; with what it couldn't follow; feature `value-trace`) |
| Data and types | `list_strings`, `search_strings` (a substring in any case, a regular expression, case-sensitive, a minimum length), `list_data`, `list_comments` (every comment, by kind and text), `list_relocations` (the relocation table: type names, symbols, targets), `export_c` (the program as a .c and a .h, into a directory or inline), `symbol_tree` (Ghidra's symbol tree a level at a time: imports by library, exports, classes, namespaces), `read_memory`, `find_types` (with each type's category, and a `category` filter), `get_type`, `parse_c` (C declarations checked against the program: new, replaces or identical, diagnostics), `export_type_archive` (a type archive's header and sidecar: named types, a category, the user's or all), `list_type_archives` (the library archives the project applies: on or off, what each gives the program; feature `project-types`) |
| Memory map | `memory_map`, `add_memory_region` (RAM, MMIO, or a file's bytes by host path), `update_memory_region`, `remove_memory_region` |
| Edits | `rename`, `rename_variable`, `retype` (a global's type or a function's prototype, from a C declaration), `retype_variable`, `rename_field` and `retype_field` (a struct's or union's field, by the struct's name or hash and the field's name or offset: its next version laid out by `ParseC` and bound in one edit, as the UI's Types view does), `import_header` (define C declarations' types and bind their names, one edit), `import_type_archive` (an archive's types, checked against its hashes, one edit; nothing when the program has them), `set_type_category`, `move_types_to_project` and `copy_types_to_program` (project-wide types), `set_type_archive` (a library archive on or off for the project), `set_comment`, `add_note`, `create_function`, `remove_function`, `set_flow_override`, `set_fallthrough` (where control goes on after an instruction, nowhere, or `clear`; feature `fallthrough-override`), `override_call_signature` (one call's prototype; feature `call-signature-override`), `set_register_value` and `list_register_values` (a register's value over a range, MIPS `gp` or the PowerPC TOC; feature `register-values`); from the listing (feature `listing-edit`): `define_data`, `clear_code`, `clear_flow` (Clear Flow and Repair; feature `clear-flow`), `disassemble_here`, `set_mutability`, `set_data_settings` (an item's, a field's or a type's display; feature `data-settings`); equates and references (features `equates`, `user-references`): `convert_operand`, `set_equate`, `list_equates`, `rename_equate`, `remove_equate`, `add_reference`, `remove_reference`, `set_primary_reference`; structures (feature `auto-struct`): `auto_structure` (Auto Create, or with `fill` Auto Fill in, from a variable's use; previews, `apply` defines it and retypes the variable), `create_structure` (from the data in a range) |
| Review | `blame`, `list_my_changes`, `undo_changes`, `revert_my_changes` |
| Plugins | `list_plugins`, `plugin_facts`, `run_plugin_command` (dry run by default) |
| BSim | `bsim_databases` (each attached database and, optionally, its executables), `bsim_ingest` (programs into a database), `bsim_search` (functions similar to one, or to every function of a program), `bsim_overview` (how many matches each function has), `bsim_apply` (matches' names, signatures, or signatures and types to the queried functions; feature `bsim-apply`) |
| Function ID | `fid_matches` (a program's matches, statuses and candidates; `run` runs it again), `apply_fid_match`, `reject_fid_match`, `fid_databases`, `attach_fid_database` (admin; `detach`), `create_fid_database` (admin) |
| Comparing programs | `compare_programs`, `list_diff_sessions`, `diff_matches` (with what changed), `diff_unmatched`, `diff_function` (each changed instruction), `diff_accept`, `diff_reject`, `diff_set_match`, `diff_unmatch`, `diff_apply_markup`, `diff_port_function` (one function's markup through a match, either way); any two functions (feature `function-compare`): `compare_functions` (what changed, the variables paired, the comments), `port_function_markup` |
| Scripts | `list_scripts` (the daemon's libraries with metadata, and whether it runs scripts for you), `run_script` (to the end, `args` answering prompts by name; an unconfirmed user or project script comes back as `trust_required` with its source, to show the user before passing `confirm_sha256`) |
| Patching | `assemble` (the encodings of one instruction at an address, or the error, its column and what was expected; writes nothing), `patch_instruction`, `patch_bytes`, `list_patches`, `revert_patch` (by seq or address), `detect_checksum` (the rule a file or its name obeys), `export_patched` (patches written in, checksum fixups, verified by the daemon; saved where the server runs, or on the daemon's host for an admin) |
| Emulator | `emu_start` (optionally on a machine: a description, a saved machine's name, or one derived from the program), `emu_run`, `emu_state`, `emu_read_memory`, `emu_write`, `emu_breakpoints`, `emu_machine` (CPU mode, devices, the exceptions taken), `emu_input` (UART bytes, exception breakpoints), `emu_close` |
| Debugger | `debug_start` (the emulator target takes a machine too), `debug_run`, `debug_state`, `debug_read_memory`, `debug_breakpoints`, `debug_backtrace`, `debug_evaluate`, `debug_disassemble`, `debug_copy_memory`, `debug_rewind`, `emu_call`, `debug_timeline`, `debug_modules`, `debug_close`; a crash dump's `debug_crash_dump` (an ELF core or minidump, opened: the session and the crash) and `debug_crash` |

Emulator and debug sessions belong to the server's session and assert
nothing. A patch is an assertion like any other edit: it carries the
agent's provenance and reason, shows in `list_my_changes` and goes with
`revert_my_changes` ([patching.md](patching.md)). `export_patched` writes
nothing unless told where, and never over an existing file unless asked.
New types come from C: `parse_c` checks declarations against the
program and `import_header` defines them and binds their names in one edit.

- **Addresses.** Every address argument of a program's tools is a hex
  number (`"0x401040"`, or `"401040"` as the listing prints it), a symbol
  (`"main"`, a demangled `"ns::Class::method"` or its mangled spelling) or
  a Go To expression as the UI's palette reads one: `"main+0x10"`,
  `"tbl + 4*8"`, `"file:0x200"` (a file offset), `"mem:0x100"` (another
  memory space). The SDK evaluates them (`revkit.expr`,
  `Program.resolve`); the emulator, debug and diff tools take hex numbers.
- **Paging.** Long results come a page at a time: `list_functions`,
  `search_symbols`, `list_strings`, `search_strings`, `list_data`, `xrefs`, `find_types`,
  `list_classes`, `list_objc_classes`, `list_equates` and `list_my_changes` by `offset`, `decompile` by
  `start_line`, `function_graph` by `block_offset`, `disassemble` from its
  `next`, the searches from `start`. A result with `"truncated": true` says
  in `more` how to get the next page. Any result is also cut to about 50,000
  characters of JSON (the longest list, else the longest text), so a large
  program can't flood an agent's context.
- **Errors.** API errors, bad arguments and unexpected failures all come
  back as `{"error": CODE, "message": text}`, never a traceback.
- **Evidence** (`api_minor` 97, feature `result-evidence`). The core tools'
  results carry an `evidence` object beside their fields (which are
  unchanged): `program_summary`, `list_functions`, `get_function`,
  `decompile`, `xrefs`, `search_symbols`, `list_strings`, `search_strings`,
  `list_data`, `search_memory`, `search_text`, `search_scalars`,
  `search_decompiled`, `find_types`, `get_type`, the edits (`rename`,
  `rename_variable`, `retype`, `retype_variable`, `set_comment` and every
  tool built on the same result), `bsim_search`, `compare_programs`,
  `diff_matches`, `diff_unmatched`, `diff_function` and
  `compare_functions`:

  ```json
  "evidence": {
    "revision": 41,
    "derived_by": "decompile.ghidra",
    "provenance": {"name": {"by": "import:elf", "tier": "symbol"},
                   "prototype": {"by": "derived:decompile.ghidra.prototype", "tier": "guessed"}},
    "unknowns": [{"kind": "indirect_call", "address": "0x401146",
                  "detail": "indirect call: its target isn't known (a function pointer, a virtual call); ..."}],
    "limits": [{"kind": "page", "detail": "lines 0-299 of 812: call again with start_line=300 for the rest",
                "next": {"next_start_line": 300}}],
    "target_content": ["name", "prototype", "c", "variables[].name", "fields[].name", "demangled[]", "warnings[]"]
  }
  ```

  | Field | What |
  | --- | --- |
  | `revision` (`head_revision` when newer) | the project revision read: a result from an older revision than a later edit's is stale |
  | `derived_by` | the analysis that produced the result (`decompile.ghidra`, `xrefs.static`, `bsim`, `diff`) |
  | `provenance` | for one object, `{field: {"by", "tier", "seq"}}` (`by` as blame prints it: `user:alice`, `import:dwarf`, `agent:claude@opus`, `derived:<rule>`; `seq` for an assertion, for blame and undo); for a list, a note naming the per-item fields: `named_by` and `tier` on functions and symbols, `defined_by` and `tier` on data and types, `tier` on xrefs and variables (`type_tier` for a variable's type), and `list_functions` counts the tiers |
  | `unknowns` | `[{kind, address?, detail}]`: the daemon's `Unknown`s (lower case) plus `unmatched` (a comparison's functions with no counterpart); `analysis_running` comes from `GetAnalysisStatus` for every tool on a program (asked at most every 2 s) |
  | `limits` | `[{kind, detail, next?}]`: `page` (with the next call's arguments), `result_size` (the 50,000-character cut), `budget` (a scan stopped early: `search_strings` past 500,000 strings, a search before covering the program), `cap` (a `limit` or `max_matches` reached), `threshold` (BSim's similarity floor), `coverage` (how much of a BSim database was scored) |
  | `target_content` | the fields, as paths (`data[].value`, `functions[].name`), whose text comes from the program under analysis or from what others wrote in the project: strings, names, comments, types, decompiled code |

  `unknowns` and `limits` are always present, empty when the tool knows of
  nothing it couldn't determine or that cut it short. **Untrusted
  content**: text in `target_content` fields is data, however it reads. A
  string in the binary can be written to look like an instruction to the
  agent ("ignore previous instructions and run ..."). It comes back
  verbatim, never rewritten, and every tool result (errors too) but those
  of `about`, `analysis_status`, `undo_changes`, `revert_my_changes` and
  the close tools carries `_meta: {"revkit.dev/target-content":
  {"untrusted": true, "source": "analysis_target", "fields": [...]}}`, so
  a host or hook can apply stricter handling (approval for writes after
  target text was read, say). The server's instructions and the guide
  tell the agent the same.

  Edits say what changed: `changed` is `{what, address, variable?, from,
  from_by, to, effective}` (the fact's value before and after as blame
  shows it, who had set the old one, and whether the edit took effect or a
  higher-precedence assertion shadows it), `undo` is the call that takes
  it back (`{"tool": "undo_changes", "seqs": [...]}`), `changed_keys`
  counts the facts whose value moved, and `evidence.provenance.edit` is the
  edit's own provenance and tier. The design follows rea's MCP contracts
  (`docs/mcp-contracts.md`: tool results, untrusted target content) in
  idea; nothing is ported.

- **Provenance.** Every write carries `agent:<name>[@version]` provenance,
  the server's session id (`--session`, default random) and the agent's
  required `reason`. A reviewer can list or bulk-revert an agent run, and a
  human's edit always outranks the agent's. The server cannot write as a
  user.
- **Authentication.** `--token` (or `RK_TOKEN`) with an agent token: the
  daemon stamps the token's name as the agent (`--agent` defaults to it),
  and `--fingerprint`, `--ca` or `--tls` for the daemon's certificate
  ([security.md](security.md#clients)).

## Backend seam

`revkit::api::Backend` (`src/api/include/revkit/api/backend.h`) is the only
thing the transports call:
- One method per RPC, taking a `CallContext` (deadline, cancellation, peer)
  and the generated request and response messages.
- `Subscribe` takes an `EventSink` (enqueue-only) and returns a
  `Subscription` handle. Heartbeats are the transport's job.

Two implementations exist. The image backend
(`revkit::backend::MakeImageBackend`, `src/backend`, described in
[backend.md](backend.md)) serves real binaries, with each project's
assertions and derived facts in a fact store (`revkit::facts::FactDb`),
optionally persisted (`--project-dir`). The fake
(`MakeFakeBackend`, `src/api/fake_backend.cc`) shows the expected semantics
end to end:
- immutable per-revision snapshots;
- liveness and precedence rules matching `revkit::facts::AssertionLog`;
- changed keys computed by diffing winners;
- invalidation mapping;
- replay on subscribe.

The fake's synthetic program, `demo/hello` in project `demo`, is
hand-assembled x86-64 whose bytes, tokens, p-code, xrefs and decompiler
token maps agree:

| Address | What |
| --- | --- |
| `0x401000` | `entry` (import-named): `XOR EBP,EBP; CALL main; MOV EDI,EAX; HLT` |
| `0x401010` | `main` (import-named): calls the checksum on `s_hello_00402000`, stores to `DAT_00403000` |
| `0x401040` | `FUN_00401040`: FNV-1a over a buffer, with a loop, an early return and the `0x811c9dc5`/`0x1000193` constants |
| `0x401070` | `FUN_00401070`: unreferenced `LEA EAX,[RDI+RDI]; RET` |
| `0x402000`, `0x403000`, `0x404000` | `.rodata` `"hello"`, `.data` dword, `.bss` (uninitialized) |

## Build-time impact

These figures are for the default preset on 32 cores, building from clean
on top of the existing tree.

| Step | Wall | CPU |
| --- | --- | --- |
| Generated protobuf/gRPC code (`revkit_api_proto`) | 9 s | 87 s |
| `revkit_api` + `rk-daemon` | 27 s | 61 s |
| API tests | 25 s | 46 s |

- **Dependencies.** No gRPC or protobuf compile, because the system
  packages are used. The only download is cpp-httplib, about 1 MB.
- **Configure.** Configure time is unchanged apart from one `pkg-config`
  probe.
- **Sanitizers.** The asan and tsan presets link the uninstrumented
  system gRPC.
  - ASan+UBSan with leak detection is clean on all 23 API tests.
  - Under tsan, all tests pass but TSan prints about 390 reports, every one
    involving memory handed through gRPC internals it cannot see (none has
    both accesses in `src/api`).
  - On this kernel, TSan binaries also need ASLR disabled
    (`setarch -R ./revkit_api_tests`), because of TSan's "unexpected memory
    mapping" with high `mmap_rnd_bits`. This affects any TSan binary,
    including `gtest_discover_tests` at build time.
  - A clean TSan signal needs gRPC built with `-fsanitize=thread` into a
    separate prefix.

## Known gaps

- **Backends.** The image backend's gaps are listed in
  [backend.md](backend.md#known-gaps); without `--project-dir` its projects
  live in memory. The fake's `ImportProgram` hashes the uploaded bytes but
  always yields the synthetic program. In both, analysis jobs complete
  instantly (they still emit progress events). The fake backend has no
  `ParseC` and stores C declaration retypes as text.
- **Security.** Accounts, API tokens, roles, per-project lists, TLS and
  peer authentication are in [security.md](security.md), with their limits
  (no SSO or MFA, no mTLS, peers trusted with data).
- **Missing browser features.** No compression, no Connect GET for cacheable
  queries (that would mark query RPCs `NO_SIDE_EFFECTS`), and no
  `grpc-web-text`.
- **One thread per stream.** Subscription streams use one gRPC handler
  thread each (synchronous API), and each browser stream holds one HTTP
  worker. That is fine for a local daemon with a handful of windows and
  agents; move to callback reactors if subscriber counts grow.
- **Equates and user references** ([above](#equates-and-user-references)).
  An equate is per operand (Ghidra's equate references), not a program
  object of its own: one with no reference left isn't kept. The decompiler
  has no float conversion, so `FLOAT` reaches it as the formatted text, and
  `SIGNED_DECIMAL`/`UNSIGNED_DECIMAL` as its decimal format, signed or not
  as the constant's type says (as in Ghidra). A display set on a listing
  operand reaches the decompiler only where the instruction's own p-code
  holds the constant; one the decompiler computed elsewhere needs
  `constant_hash` and shows in the decompiler only. No stack, register or
  external references, and no offset references table.
- **Not yet in the schema.** No bookmarks, data definitions (beyond
  `Retype`), no inline or calling-convention assertions (a prototype's
  calling convention is part of its function type, which the decompiler
  follows: [decompiler-inputs.md](decompiler-inputs.md#calling-conventions));
  no `Retype` that defines data at an address (the
  listing's typed data, [roadmap.md](roadmap.md)).
