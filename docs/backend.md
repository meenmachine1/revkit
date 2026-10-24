# Image backend

`rk-daemon` serves real ELF and PE binaries through the API's `Backend` seam
(`revkit::api::Backend`, see [api.md](api.md#backend-seam)). Each project is
one fact database ([facts.md](facts.md)): every edit is an assertion in it,
API revisions are its revisions, and everything the backend derives from a
program is a memoized, persisted fact-store query. This page covers the
model, what is derived and how it is invalidated, persistence, concurrency
and what it costs.

```sh
build/tools/rk-daemon/rk-daemon --open path/to/binary                    # in memory
build/tools/rk-daemon/rk-daemon --project-dir ~/rk --open path/to/binary # persistent
build/tools/rk-daemon/rk-daemon --backend fake                           # synthetic demo program
```

## Where it lives

`src/backend` (`revkit::backend`, `MakeImageBackend()` in
`include/revkit/backend/image_backend.h`), separate from `src/api` so the
API layer (schema, transports, fake) stays free of Ghidra.

| File | Role |
| --- | --- |
| `queries.{h,cc}` | Every fact-store input and query the backend registers, with rule names and versions. `RegisterQueries` is the one registration point. |
| `model.{h,cc}` | The values of those queries and their canonical encodings |
| `program.{h,cc}` | One loaded binary: image, language, lifter and decompiler pools, and the pure analyses the queries run on discovery's results (listing spans, references, labels, rows, pages) |
| `decompiler.{h,cc}` | `DecompilerPool`: decompilations in decompiler workers ([decompd.md](decompd.md)), from bundles answered by a `RunLookup`; the worker side's `PrintC` whose emitter records typed tokens (mode `tokens`) |
| `own_inputs.{h,cc}` | The decompiler's facts as queries over `revkit::inputs` (the assembly rk-lift `--analyze --decompile` measures) and `QueryLookup`, which reads them per run with assertions laid over them |
| `debug_import.{h,cc}` | DWARF and PDB debug info as `import:dwarf` / `import:pdb` assertions |
| `msvc_import.{h,cc}` | revkit::msvc's markup of a PE (RTTI, vftables, PE structures, exception data) as `analysis:msvc` / `analysis:pe` assertions ([pe.md](pe.md)) |
| `symbol_server.{h,cc}` | symbol paths, stores, servers and `.pd_` cabinets for Load PDB ([pdb.md](pdb.md)) |
| `type_record.{h,cc}` | Types as fact-store records keyed by content hash |
| `define_type.{h,cc}` | `DefineType` bodies interned as one batch into records; stored types as the API's `TypeDefinition` and as `TypeNode`s |
| `parse_c.{h,cc}` | `TypeService.ParseC` and parsed `c_declaration` retypes: `revkit::cparse` over the program's target (its compiler spec) and named types ([cparse.md](cparse.md)) |
| `library_types.{h,cc}` | the library type archives' named types as revkit type records |
| `image_backend.cc` | RPC handlers, projects, revisions, overlays, change effects, subscriptions |
| `import_progress.{h,cc}` | An import's phases, their expected costs and the fraction `GetImportProgress` reports, per caller |
| `raw_detect.{h,cc}` | `DetectRawLayout`: `revkit::detect`'s report as raw import options, its progress per caller, and the slots that bound how many run at once |
| `api_util.{h,cc}` | Provenance filters, origins, page tokens, event filtering |
| `relocate.{h,cc}`, `pool.h` | `R_*_RELATIVE` relocations for rebased PIEs; a bounded pool of single-thread objects |
| `rebase.{h,cc}` | what moves with a program's image base: the backend's `facts::Relocator` (reference targets, image block starts, region starts, request bodies in op metadata) ([memory-map.md](memory-map.md#rebase-setting-the-image-base)) |

## The model

**Assertions.** Rename, retype, comment, function bounds, flow override and
note are `facts::FactDb` assertions. A program's addresses live in its own
fact-store space (program with ordinal *k*: space 16 + 2*k*; its file's
bytes in 17 + 2*k*), so the keys of two programs never collide. The
ordinal is a hash of the program id and file hash, probing past used
ones, so daemons sharing a project ([collab.md](collab.md)) agree on it
without coordinating.

| API body | Fact key | Value |
| --- | --- | --- |
| `Rename` | `NAME@addr`, locals `sub = local:<storage>` | the name (empty: back to the default) |
| `Retype` | `TYPE@addr`, locals as above | `h:<type hash>` (a `type_hash`, or a `c_declaration` the C parser read, whose types the request defines too), or `c:<C declaration>` (text it can't read, and every C retype before it) |
| `Comment` | `COMMENT@addr`, `sub` = kind | the text |
| `SetFunctionBounds` | `FUNCTION_BOUNDS@entry` | the body as an `AddressSet` (empty: the seed's body), or `0` for `remove` |
| `FlowOverride` | `FLOW_OVERRIDE@addr` | the kind |
| `SetFallthrough` | `FALLTHROUGH@addr` | the target as an `Address`, `1` for no fallthrough, `0` cleared |
| `Note` | `NOTE@addr`, `sub` = tag | the text |
| `DefineType`, and debug info types | `TYPE_DEF`, `sub` = type hash | the type record |
| `AddMemoryRegion`, `UpdateMemoryRegion`, `RemoveMemoryRegion` | `MEMORY_REGION@0`, `sub` = `region:<id>` or `block:<hex start>` | the region or block edit (`analysis/memory.h`), `""` when removed ([memory-map.md](memory-map.md)) |
| `ListingEdit` (Clear, Disassemble here, Define data) | `CODE_UNIT@addr`, `sub` = `clear:<hex length>`, `code` or `data` | the mark (`analysis/units.h`: a data definition with its type's layout) ([listing-edit.md](listing-edit.md)) |
| `SetMutability` | `MUTABILITY@addr`, `sub` = the length in hex | the range's mutability |
| `OperandDisplay` (Convert, Set Equate) | `EQUATE@addr`, `sub` = `<operand>:<hex value>` or `h<hex hash>:<hex value>` | `f:<format>`, `e:<name>` or `m:<enum hash>:<member>` (`analysis/user_refs.h`); `""` for the disassembler's display |
| `UserReference` | `REFERENCE@from`, `sub` = `<operand>:<hex to>` or `i:<hex to>` | `<type>` then `p` when primary, or `remove` (`analysis/user_refs.h`) |
| `SetImageBase` | `REBASE@0` | the `facts::Shift` as text, `<delta hex>/<bits>` (the new base minus the import base): the store indexes the program's keys moved by it, and keeps them image-relative in the log ([memory-map.md](memory-map.md#rebase-setting-the-image-base)) |
| `RenameProgram`, `DeleteProgram`, `MoveToFolder` (a program) | `NOTE` in the project space at the program's ordinal, `sub` = `revkit:program.name`, `revkit:program.deleted`, `revkit:program.folder` | the name, `"deleted"`, the folder's id (`""`: the root) |
| `DefineType`, `BindTypeName`, `SetTypeCategory` with `project_scope`, and `CopyTypes` to the project | `TYPE_DEF` in the project space at 0, `sub` = hash, `name:<key>`, `category:<key>` | as a program's ([types.md](types.md#project-types)) |
| `type_archive` (a library archive on or off, an archive attached) | `NOTE` in the project space at 2^48+1, `sub` = `revkit:type-archive:<name>` | the `TypeArchiveSetting`, `""` once detached |
| `CreateFolder`, `RenameFolder`, `MoveToFolder` (a folder), `DeleteFolder` | `NOTE` in the project space at 2^48, `sub` = `revkit:folder:<id>` | `"<parent id>/<name>"`, `""` once deleted |

Each op's `meta` (opaque to the store, persisted with it) keeps what the API
needs to render it again: the full provenance (session, reason, tool), the
request body and the revision it was committed at. Liveness, precedence,
blame, history and retraction are the store's; there is no backend log and
no per-commit copy of project state. Every commit that appends ops publishes
exactly one fact-store revision (`LogLength` in facts.md), and that is the
API revision.

**Reads** pin a fact-store `Snapshot`. The project keeps the snapshots of
the last `retained_revisions` revisions, plus the log length at each, so a
read pinned to revision *N* sees inputs, derived facts and assertion
statuses (`blame(key, upto)`, `status(seq, upto)`) exactly as of *N*.

**Revert** follows the store: `RevertByProvenance` retracts every op of the
matching author, assertions and retractions, live or not, newest first, in
one revision. A full revert reads as if the author never acted, even if
someone later undoes one of the author's retractions ([api.md](api.md)).

**Import** is one revision: the file's bytes, the loaded image's bytes (in
the program's space, relocated as Ghidra loads them: what function
discovery decodes), a record of the program (a `NOTE` assertion in the
project space holding its `ProgramSource`), its debug info as import
assertions, and the inputs: the backend's and discovery's `ProgramInfo`
(`analysis::stage_image`, keyed by program id) and the plugins'
`plugins.program` (memory map, entry, where the file's bytes are).
With an `import_id`, each step is recorded for the caller to poll
(`GetImportProgress`, `import_progress.{h,cc}`; [api.md](api.md#import-progress)).
A file the built-in loaders reject goes to a loader plugin whose magic
matches ([plugins.md](plugins.md#loaders)); its program record keeps
the plugin's `name@version` to reload it on reopen.

## Loader-derived names: derived facts, not assertions

Symbol, export and import names come from the file. They are held as
**derived facts** (`analysis.functions` for function names: symbols,
exports, import stubs named after their imports, thunks after their
targets; `names.loader` for labels and PE import slots, `names.default`
adding `FUN_`/`LAB_`/`DAT_` for unnamed reference targets), not as
`import:` assertions:

- They are a pure function of the file, so the store can recompute them at
  any time, and a better naming rule is a version bump that recomputes
  them, not a migration of thousands of assertions.
- They cost nothing in the log. A large binary has tens of thousands of
  symbols; as assertions they would be replayed on every open and listed by
  every `ListAssertions`.
- **Precedence**: the effective name is the winning live assertion if there
  is one (user > import > agent > analysis), else the derived default.
  Mangled names are demangled the same way, as derived facts (the
  demangler analysis, [demangle.md](demangle.md)): `Func` and `Label` keep
  the mangled spelling beside the name.
  Loader names therefore rank below every assertion, user ones included,
  and blame reports them as `derived: analysis.functions`, `names.loader`
  or `names.default`.

Debug info is different: it is a second source that can disagree with the
symbols, so DWARF and PDB names, prototypes and types are `import:dwarf` and
`import:pdb` assertions, which outrank agents and analysis and lose to users.

## Derived data as queries

Every rule is a fact-engine query with a name and a version
(`queries.h`). Memos record the facts they read with fingerprints, so a
value stays valid exactly as long as those facts do.

| Rule | Value | Reads |
| --- | --- | --- |
| `analysis.memory` | the effective memory map: the loader's blocks with the `MEMORY_REGION` edits ([memory-map.md](memory-map.md)) | `analysis.program.loaded`, `analysis.data_program.loaded`, `MEMORY_REGION` keys, the first page of an added region's bytes |
| `analysis.program`, `analysis.data_program` | what discovery and data analysis know of the program: the loader's (unchanged without edits) with the map's mapped ranges, code, byte sources and blocks | `analysis.*.loaded`, `analysis.memory` |
| `analysis.*` | function discovery (`src/analysis`, keyed by program id): flows (with their data references), thunks, the fixpoint, one function; data analysis (`analysis.data`, `analysis.no_return_evidence`, [data-analysis.md](data-analysis.md)) | the image's bytes (and added regions'), `analysis.program`, `analysis.data_program`, `FUNCTION_BOUNDS`, `FLOW_OVERRIDE` and `FALLTHROUGH` assertions |
| `analysis.param_id*` | Ghidra's Decompiler Parameter ID: its plan, one function's dependencies, what it commits for one function ([param-id.md](param-id.md)); decompilations read the commits as published (`param_id.published`) by a background pass | `param_id.mode`, `analysis.functions`, `analysis.flow`, the function's decompilation's lookups |
| `functions.table` | effective functions and bodies, names, no-return and thunk flags | `analysis.functions` |
| `names.loader` | non-function symbols, PE import slots, with sizes | source, discovery's seeds |
| `listing.code` | spans of the instructions discovery reached | `analysis.functions` |
| `xrefs.function` | one function's references, jump-table cases included: what `analysis.flow` recorded while decoding (`FlowGraph::refs`); an operand is decoded when the reference is served | `analysis.function`, `analysis.flow` |
| `xrefs.static` | every function's references, by from and by to | `functions.table`, `xrefs.function` |
| `names.default` | loader names plus `FUN_`/`LAB_`/`DAT_` for reference targets, and data analysis's names (`s_<text>_<addr>`, `PTR_<target>_<addr>`) | names.loader, functions.table, xrefs.static, analysis.data |
| `listing.rows` | row ↔ address for the whole program; one DATA row per data item | listing.code, names.default, analysis.data |
| `listing.page` | 256 rows: bytes, SLEIGH tokens, the decoded flow and static targets (version 2) | listing.rows |
| `listing.header_bucket` | header lines per code unit in one 64 KiB bucket (the key index's), for GetListing's `header_rows` numbering: plate and pre-comment lines, function signatures, labels | listing.rows, functions.table, names.default, the bucket's `NAME` and plate/pre `COMMENT` keys |
| `listing.header_slots` | the buckets that can have header lines | functions.table, names.default, the `NAME` and `COMMENT` bucket directories |
| `listing.headers` | the non-empty buckets with their row extents and line totals (prefix sums are computed on load) | listing.header_slots, listing.header_bucket |
| `symbols.effective` | name, kind, size, hashed type (and its assertion's rank) and no-return at one address | `analysis.function` there, `NAME`/`TYPE` there (`TYPE`'s `AssertedOrder`), names.default |
| `analysis.demangler`, `analysis.demangler.scopes` | a function's prototype from its mangled name; the class scopes the program's symbols show ([demangle.md](demangle.md)) | `analysis.function` there, the loaded image's symbols |
| `symbols.container` | the sized label around one address | names.default |
| `types.closure` | a type hash and every type it reaches (`GetTypes`) | `TYPE_DEF` keys, else the project's, else `types.library` |
| `library.prototypes` | revkit's library archives for the program (`libc-lp64`, the Windows DLLs', ...; [types.md](types.md#library-prototypes)), less those the project switched off, plus those attached to it, parsed for its target: prototypes by name, named types; computed in each process (not persisted), its value's encoding their identity | the image's format and address size, the program's profile, the archives' headers |
| `types.library` | the library archives' named types (revkit's, then Ghidra's `generic_clib_64`, `windows_vs12_64`, ... for names they lack) as revkit types, records by hash with the archive each came from (`library_types.cc`) | `library.prototypes`, the image's format and data organization, Ghidra's archive |
| `types.names` | the program's named types and the names `BindTypeName` binds (`FindTypes`), then the project's ([types.md](types.md#project-types)) where the program has neither | every `TYPE_DEF` key, the project's, `types.library` |
| `types.categories` | the category each named type is filed under (`SetTypeCategory`; `FindTypes`, `ExportTypeArchive`), the project's for names the program doesn't file | every `TYPE_DEF` key, the project's |
| `types.archive_settings` | the project's type archive settings: library archives switched off, archives attached (`AssertionBody.type_archive`; [types.md](types.md#project-types)) | the `NOTE` keys at 2^48+1 in the project space |
| `types.resolved` | a closure in which every named type whose name is bound to another definition is that definition (`GetTypes` never reads it) | `TYPE_DEF` keys there (the program's, else the project's), the bindings of the names it meets (the program's, else the project's) |
| `decompile.inputs` | a function's body, the comments it shows, its flow overrides, discovery's jump tables in it | `analysis.function`/`analysis.flow` there, `COMMENT`/`FLOW_OVERRIDE` keys in its body |
| `inputs.static` | what of the decompiler's program inputs the image alone decides (`inputs::assemble_static`): memory with the EXTERNAL and thread blocks, relocation patches, EXTERNAL functions and data, PE imports, the loader's symbols, relocated pointer slots' values; a change to the function list doesn't recompute it | program.source, analysis.program |
| `inputs.program` | everything else `revkit::inputs::assemble_program` gives the decompiler for the program: functions with signatures and debug-info locals, data (analysis's strings, pointers and accessed data among it), labels, imports with the library archives' prototypes, types (relocated pointer slots are made per address by `inputs.address`) | inputs.static, analysis.functions, analysis.data, analysis.no_return_evidence, library.prototypes |
| `inputs.image` | what a decompiler instance is built with: memory blocks, relocated bytes, synthesized memory, the address prefix | inputs.static |
| `inputs.sets` | function entries and the no-return ones (known names, Ghidra's evidence, thunks of either) | analysis.functions, analysis.no_return_evidence |
| `inputs.function` | one function's stack variables, flow overrides and code labels (`inputs::assemble_function`) | analysis.function/flow there, inputs.sets, inputs.address |
| `inputs.address` | what the decompiler is told about one address: the function starting or containing it (without its extent), data, label, external reference, block, tracked registers, comments | inputs.program |
| `inputs.type` | one type definition by id | inputs.program |
| `decompile.ghidra` | Ghidra's output for one function, with its data-flow graph (every varnode and live p-code op; what `SliceDecompiled` walks, sent to clients only on request) | source, decompiler options, decompile.inputs, inputs.image, and `inputs.address` / `inputs.function` / `inputs.type` / `symbols.effective` / `types.resolved` for every address, function and type the decompiler looked up |
| `infer.pointer_accesses` | the loads, stores and calls through one variable of a function, by storage key (`auto_struct.h`; what `TypeService.AutoStructure` composes structures from) | `decompile.ghidra` of that function, which records them for every pointer-sized variable |
| `diff.*` | binary diffing ([diff.md](diff.md)): a function's fingerprints (`diff.features`), two programs' matching (`diff.proposals`), a session's matches with its decisions (`diff.matches`), the project's sessions (`diff.sessions`) | `analysis.function`/`analysis.flow` and the bytes they decode, `NAME` at the entry; every function of both programs; the session's `MATCH` keys; `NOTE` records in the project space |
| `plugins.*` | analyzer plugins (`plugins.analyze`) and the fact blobs they read: program info, functions, a function's code with p-code, effective names ([plugins.md](plugins.md#analyzers-as-queries)) | `plugins.program`, `analysis.*`, the pages read, NAME assertions |

The inputs are the assertion log (`AssertedFact` and its key index
`AssertedKeys`, with `AssertedSpan` narrowing it to 256 bytes), the file's
and the image's bytes, and the inputs set at import: `program.source`
(identity, options and the loaded image), `analysis.program.loaded` and
`analysis.data_program.loaded` (what discovery and data analysis start
from, before memory-map edits), `project.programs` and
`decompiler.options`. Rules that read the loaded program's memory read it
with the memory map at their revision (`EffectiveProgram`,
[memory-map.md](memory-map.md#how-the-image-backend-sees-them-a-variant-of-the-program)).

### Function discovery

`RegisterQueries` registers `src/analysis`'s queries, keyed by program id,
so each program of a project has its own discovery in the project's one
store. The seeds the backend used to list on its own (symbols, exports,
the entry point, unwind tables) are discovery's seeds, with init/fini code
and PLT stubs; `functions.table` is what discovery finds from them:
recursive descent, call targets, import stubs named after their imports,
thunks, no-return functions and jump tables, bodies without padding
(README, "Function discovery").

User assertions are discovery's inputs, so they win and propagate:

| Assertion | What discovery does |
| --- | --- |
| `SetFunctionBounds{entry}` | the entry is a seed: it and what it calls become functions, their flows are decoded, other bodies stop at it |
| `SetFunctionBounds{entry, body}` | the same, and the body is the asserted one; it is taken out of every other function's body |
| `SetFunctionBounds{entry, remove}` | nothing starts there: not a seed, not a call target, and flows run on through it (a false start merges back into its function) |
| `ListingEdit` clear, and data | nothing starts in those bytes and flows stop there; data analysis leaves them alone, or lays the user's item ([listing-edit.md](listing-edit.md)) |
| `ListingEdit` disassemble | an entry: code that isn't a function (a function when asked, or once called), whose flow decodes through older cleared bytes and outside executable memory |
| `SetNoReturn{function, no_return}` | true: a known no-return function (calls to it end their caller's flow, as an exit-like name's do); false: never inferred no-return, so callers' flow goes on after its calls ([decompiler-inputs.md](decompiler-inputs.md#no-return)) |
| `FlowOverride{address, kind}` | the instruction's flow changes as Ghidra's flow overrides change it (`BRANCH`: a call is a jump in the function; `CALL`; `CALL_RETURN`: a tail call; `RETURN`), so bodies, callees and no-return inference follow |
| `SetFallthrough{address, target, no_fallthrough}` | the instruction's fallthrough goes on at `target` (or nowhere) instead of the next instruction, over what the instruction and analysis say; bodies, no-return inference, references (a `FALL_THROUGH` one) and the decompiler's p-code follow ([api.md](api.md#fallthrough-overrides)) |
| `SetRegisterValue{register_name, range, value, clear}` | not discovery: a flow's constants read the register as that value in the range, so its data references (and what data analysis lays down from them) and xrefs follow; the decompiler gets the value at an entry as a tracked register ([api.md](api.md#register-values)) |

`analysis.flow` reads the overrides on the instructions it decodes, and the
bounds at the seeds it reaches, through the 256-byte spans of the key index
(`facts::AssertedSpan`); `analysis.functions` reads every `FUNCTION_BOUNDS`
key. Names stay layered on top (`symbols.effective`): they don't change
discovery.

**Listing.** Instruction rows are the instructions some function's walk
reached (`FunctionList::code`); everything else in a block, alignment
padding, data in code and code nothing reaches, is `undefined` data rows
(16-byte lines, split at labels). An edit that changes discovery rebuilds
the rows it affects.

**References** are taken per function from its analysed body (`xrefs.function`):
p-code operands as before, and a recovered jump table's cases as
`INDIRECT_JUMP` references from the jump.

**Decompiler.** The decompiler is told what Ghidra's Java side would tell it
(`DecompileCallback`, `HighFunction.encode`), assembled by `revkit::inputs`
from the loader, discovery and the debug info, the same facts
`rk-lift --analyze --decompile` decompiles with and
[decomp-parity.md](decomp-parity.md#from-revkits-own-inputs-phase-3)
measures: relocated pointer slots and the ELF `EXTERNAL` block, `CALL_RETURN`
on import stubs, discovery's no-return functions, PE import slots and thread
block, tracked registers, `LAB_` labels where code is referred to, DWARF and
PDB prototypes, locals, globals and types, library prototypes from Ghidra's
type archives, and stack variables. Discovery's recovered jump tables are
given as overrides only where the decompiler can't recover a table itself
(it warns that it treats the jump as a call or a return; the function is
then decompiled again with the table installed).

### What a decompilation depends on

Ghidra's decompiler asks about addresses as it goes. It runs in a worker
process from a bundle ([decompd.md](decompd.md)) that holds the answers to
what it will ask: the daemon predicts the lookups from the function's body
and answers them through a `QueryLookup` reading `inputs.address`,
`inputs.function`, `inputs.type` and `symbols.effective` through the query
context, and looks up what the worker reports it missed (running again if
an answer differs from the worker's guess). So:

- the bundle's reads are its dependencies (a little more than the
  decompiler asks, since they are predicted), and nothing else is: a
  decompilation of `f` depends on what the program's facts say at the
  addresses `f`'s decompilation consulted (a callee's name, prototype and
  no-return flag, not its extent or its stack variables), `f`'s own stack
  variables, flow overrides and labels, the types it used, `f`'s comments,
  flow-override assertions and jump tables, and the decompiler options;
- assertions are laid over the program's facts: a rename replaces the name
  (and drops a debug-info label), an asserted prototype (`h:` type hash)
  other than the debug info's own becomes a user-defined signature, and an
  asserted data type replaces the data's; their types are encoded as
  Ghidra's debug-info import names them;
- nothing a worker installs outlives a run, so a worker left in any state
  by an earlier run (another revision, another function, another
  program) still produces the output for the caller's revision;
- the addresses the worker reports it asked are the run's `touched` set
  (subscribers' invalidation hints).

A worker that crashes, runs past its deadline or out of memory gives a
`DecompileOutput` with a failure and the bundle: memoized like any output,
so it is retried only when the bundle's facts or the decompiler build
change (a timeout once more on request: `DecompileOptions.escalate`).

### Invalidation, measured

`FactStoreTest` (`src/backend/tests/fact_store_test.cc`) counts executions
per rule with `QueryCounters`, decompiling every function after an edit:

| Edit | Recomputed | Not recomputed (validated by fingerprint) |
| --- | --- | --- |
| rename a function | its decompilation and exactly the decompilations that name it (for `checksum`: `main`, `twice`, `buffer_checksum`) | sweep, rows, xrefs, seeds, default names, every other decompilation |
| plate, pre or decompiler comment | the containing function's decompilation (plate and pre: also that address's `listing.header_bucket` and `listing.headers`) | everything else |
| end-of-line comment, local rename, C-text prototype or variable retype the parser can't read | nothing: they are overlays (a rename also re-runs its `listing.header_bucket`, which cuts off unless a label line came or went) | every decompilation |
| parameter or local retype by hash (a parsed C one too) | the function's decompilation (`symbols.variable_types`); a parameter's, also the decompilations that consulted its locked prototype | everything else |
| hashed prototype (`h:`, a parsed C one too) | the function and the decompilations that consulted it | everything else |
| function bounds: an asserted entry only a data pointer reaches (`AssertedEntryRerunsExactlyTheAffectedDiscovery`) | its flow and its callee's (2 flows, 2 thunk checks), the discovery fixpoint once, their references (2 `xrefs.function`), the listing; decompilations of the two new functions and of `main`, which looked the entry up | every other flow, function's references and decompilation |
| flow override (`BRANCH` on that entry's call) | that entry's flow, the fixpoint, the listing; that function's decompilation | every other decompilation |

Subscribers' `invalidated` lists are computed separately (`Effects()` in
`image_backend.cc`) and stay conservative: static callers, plus the
functions whose served decompilations looked the address up. An edit that
steers discovery (bounds, flow overrides) is diffed on both sides of the
commit (`DiscoveryEffects()`): functions that came, went or changed (their
pages, decompilations and callers), references and default labels that
changed, and the listing rows rebuilt, reported as `LISTING` ranges with
`rows` and `previous_rows` windows so a client can shift the rows it cached
after them ([api.md](api.md#subscriptions-and-cache-invalidation)). Other
edits can't change discovery, so their commit reuses the previous
revision's functions and references.

## Persistence

With `ImageBackendOptions::project_dir` (`rk-daemon --project-dir DIR`),
each project is an LMDB environment in `DIR/<project id>/`, and every
project there is reopened at startup:

- The log, the file's bytes (so the directory is self-contained) and the
  derived memos are the fact store's tables; the project's name and path
  are in its meta table.
- On reopen the store replays the log; the backend finds the program
  records in it, reloads each program from the stored bytes and sets its
  inputs again. Memos are loaded lazily and validated by fingerprint, so
  nothing is recomputed: the program source's fingerprint covers the file's
  hash and the load options, not the in-memory image. The reopened project
  starts at a new revision; earlier revisions are no longer readable.
- Memos reach disk when evicted (`memo_budget`), after an import, on
  `CloseProject` and when the backend shuts down. One that never reached
  disk is recomputed, which only costs time.
- A rule whose version changed recomputes on reopen; its dependents
  validate, and only those whose inputs really changed recompute.
  `FactStoreTest.RuleVersionBumpRecomputesOnlyThatRule` stamps
  `analysis.functions`' stored memos with another version: discovery's
  fixpoint reruns once, and flows, rows, xrefs, names and every
  decompilation are validated, not recomputed.
- A daemon holds `DIR/.revkit/lock` (`flock`) while it runs, as do
  `rk-daemon project export|import`: a second one on the same directory
  is refused ("another rk-daemon is using the project directory")
  instead of corrupting it.
- A rule whose values hold live objects says `persistent = false`
  (`infer.image.effective`: the image and a decompiler pool): it is never
  written or read back, so each process computes it again, and its
  dependents validate against the new value (`FactDbOnDisk.NonPersistentRulesAreComputedInEachProcess`).
- Discovery's `analysis.program.loaded` input is not persisted
  (client-defined inputs aren't); a reopen sets it again from the reloaded
  image, and its fingerprint is the same, so discovery's memos validate.
  Memory-map edits are assertions, so they come back with the log, and
  their regions' bytes with the store's bytes.

On Lua's debug build, after decompiling everything and one rename, the
project directory is 27 MB. Reopening takes 40 ms, the first listing page
1 ms, and 685 of 699 decompilations load from disk. The other 14 had looked
the renamed function up without being among the static callers the
benchmark re-decompiled after the rename, so their stored memos were stale
and recomputed, as they should.

## Compaction

`api_minor` 104, feature `compact`. `src/backend/compact.{h,cc}`,
`facts::Storage::compact` (`lmdb_storage.cc`).

LMDB keeps its file at its high-water mark: a memo replaced or deleted
frees pages inside the file for later writes, but the file never shrinks,
and memos nothing reads again stay forever (a rule whose version changed,
a decompilation of an option set no longer asked for, a program deleted).
A project that decompiled everything a few times over takes far more disk
than its log and bytes.

```sh
rk-daemon compact ~/rk                              # every project; the daemon stopped
rk-daemon compact ~/rk --project default --dry-run  # what it would drop, by rule
rk-daemon compact ~/rk --drop-caches                # every memo: the smallest store
rk-daemon compact ~/rk --cache-limit-mb 512         # the memos used last, up to 512 MiB
```

- **What goes.** Always the memos of rules this build doesn't register or
  whose version changed (they can only be recomputed); with
  `--drop-caches` every memo (each recomputes on first use, as after an
  import); with `--cache-limit-mb` the memos beyond that size, those used
  longest ago first (a memo's revision of last use). The log (every
  assertion and retraction: history, undo, blame and replication read it),
  the programs' stored files and the meta table are never touched.
- **The rewrite.** The deletions, then `mdb_env_copy2(MDB_CP_COMPACT)` (as
  `mdb_copy -c`) into `<store>/.compact/`, renamed over `data.mdb`: a crash
  leaves the old store or the new one. Reads and writes of the store wait
  while it runs (a shared lock around the environment, which the rewrite
  replaces).
- **When.** `rk-daemon compact <dir>` takes the directory's lock, so it
  runs while no daemon uses the directory. A running daemon has
  `ProjectService.CompactProject{project_id, drop_caches,
  cache_limit_bytes, dry_run}` (admin) for a closed project
  (`FAILED_PRECONDITION` while open: `CloseProject` first, `OpenProject`
  after); the response has the file's size before and after, the log's and
  the bytes' share, and each rule's memos (`CompactRule`). Python:
  `Client.compact_project`.
- **A limit as projects open.** `rk-daemon --cache-limit-mb <MiB>`
  (`ImageBackendOptions::persisted_cache_limit`) drops each project's
  stored memos beyond the limit when it opens, without the rewrite: LMDB
  reuses the freed pages, so the store stops growing past about the limit
  plus a session's work. Off by default.

## Project archives

`api_minor` 37, feature `project-archive` ([api.md](api.md#queries),
"Project archives"). `src/backend/project_archive.{h,cc}` (the container,
the manifest, the op log and its checks, all pure) and `ExportProject`,
`UploadChunk` and `ImportProjectArchive` in `image_backend.cc`.

```sh
rk-daemon project export --project-dir ~/rk --project default -o work.rkproj
rk-daemon project export --project-dir ~/rk --folder /firmware --annotations-only -o notes.rkproj
rk-daemon project import --project-dir ~/rk2 work.rkproj --name work          # a new project
rk-daemon project import --project-dir ~/rk notes.rkproj --into default --folder /incoming --search-dir ~/fw
```

**The file** is a gzip-compressed POSIX (ustar) tar, so `tar tzf` lists it:

| Member | What |
| --- | --- |
| `manifest.json` (first) | a `revkit.v1.ProjectArchiveManifest` as protobuf JSON: `format` `"revkit-project-archive"`, `format_version` 1, `op_format` 1, who made it and when, the project's name, `annotations_only`, every folder path (parents first), and per program its key (`p0`, `p1`, ...), display name, original id, SHA-256, size, format, language, folder, ordinal, op count and its regions' files; `log`: `log.bin`'s size, SHA-256 and op count |
| `log.bin` | `RKLOG1\n`, then each op as a varint length and the fact store's encoding of a `facts::Op` (as `SyncService` sends it: key, value, provenance, stamp, global id, references by id, the API's metadata), in log order, local seqs zeroed |
| `programs/<key>/program.bin` | the program's file as imported (not in annotations-only archives) |
| `programs/<key>/regions/<sha256>.bin` | bytes a memory-map region took from another file, placed back at the manifest's offset in the program's file space (kept in annotations-only archives too: they are part of the work, and can't be found by the program's hash) |

Members carry no timestamps, so equal projects give equal archives.

**What goes in.** The ops on the chosen programs' keys and records (their
names and deletions), with every retraction of them: user, agent, script
and plugin edits, debug-info and header imports, types (`TYPE_DEF`),
patches, listing and memory-map edits, undone and redone edits, reverts.
Diff sessions go in when both their programs do. Folders don't go in as
ops: the manifest holds the layout (a whole project as it is; an exported
folder as a top-level folder; a program with the folders above it), and
the import makes the folders again. Derived facts (functions, listings,
references, decompilations, inferred prototypes) are left out and
computed again by the import's analysis. Deleted programs are left out.

**Import** reads the archive in full before touching a project, then:
1. picks a program id (`<project>/<name>`, `-2` when taken) and a fresh
   ordinal for each program, so its fact spaces are new;
2. rewrites the ops (`archive::RewriteLog`): keys and address-set values
   into the new spaces, program records with the new id, ordinal and
   spaces (and no host path), region values to the new file space, diff
   sessions under new ids; each source replica becomes a fresh random
   replica with dense counters, references by id remapped. Provenance,
   stamps, wall times and metadata stay, so precedence, recency, blame,
   history, undo and reverts read as they did. An op stamped more than a
   day past the importing daemon's clock is refused (`Limits::max_stamp`):
   it would sort after every later edit, and one at the top of the range
   wrapped the clock (docs/bug-scrub.md, part 2);
3. merges them as a new peer's ops in one revision (`Transaction::merge`,
   [collab.md](collab.md)), the regions' bytes with them, and loads each
   program from its record and bytes as a peer's program loads
   (`LoadRemoteProgram`), then analyses it;
4. makes the folders under the destination (reusing folders of the same
   path) and puts each program in its own, renaming a program whose name
   is taken in its folder ("name (2)"): one revision with the caller's
   provenance.

Because imported ops are ordinary ops under new replicas, a project made
from an archive replicates to peers like any other, and importing one
archive twice gives two independent sets of programs.

**Untrusted input.** An archive is data from anywhere. The reader:
- names no file after anything in the archive: it accepts only the
  members the manifest declares, by exact path, and writes them under
  names of its own into a private scratch directory (`mkdtemp`, removed
  after the import);
- refuses links, directories, devices, the ustar prefix field, a member
  twice, a member the manifest doesn't declare, a size or SHA-256 other
  than declared, and a truncated or corrupt stream;
- reads the manifest first (at most 16 MiB) and then never decompresses
  more than the members it declares (bounded: 4 GiB per program or
  region, 8 GiB of log, 32 GiB in all, 4096 programs, 65536 folders): a
  decompression bomb stops at its own header
  (`ProjectArchiveContainer.StopsAtWhatTheManifestDeclares`);
- checks the version before anything else (leniently, so a newer archive
  is told apart from a broken one): another `format`, a newer
  `format_version` or another `op_format` is refused with a message
  saying so (`FAILED_PRECONDITION`);
- checks names, folder paths (no `.`, `..`, empty parts or `/`), hashes,
  ordinals and region offsets;
- decodes every op and checks it (`archive::ValidateLog`): a unique id;
  a retraction only of an earlier op on the same key; dependencies on
  earlier ops; keys only in the archive's programs' spaces or their
  records; values of the kind's type, the encoded ones decodable
  (program records matching the manifest, memory-map edits in the
  program's file space, listing edits, types, diff sessions between the
  archive's programs).

The project's name never reaches the file system as given: the project
id (its directory under `--project-dir`) keeps letters, digits, `.`, `_`
and `-` and can't start with `.`. `src/backend/fuzz/project_archive_fuzzer.cc`
(`REVKIT_FUZZ`) runs all of the above on arbitrary bytes, for the bug scrub.

**Checks.** `src/backend/tests/project_org_test.cc`: the container's
refusals (versions, paths, sizes, hashes, links, bombs, garbage), the
ops' validation and rewrite, and the round trip on the corpus's `cjson`
(DWARF) and `zlib` with a user's work (renames, a parsed struct and a
prototype using it, a type filed under a category, comments, a patch, a listing edit, a memory region
with another file's bytes, an undone edit, an undone and redone one, an
agent's rename shadowed by the debug info, a diff session, folders):
exported and imported into a fresh project, full and annotations-only,
the function list (entries, names, prototypes), the decompiled C of the
edited functions and twelve others, every op in order with its status
and what retracts it (the undo history), the effective assertions, the
memory map and the bytes read through it, and the types in the category are the same;
undo works on the copy. Selections and merges, uploads and host paths
too. `sdk/python/tests/test_project_org.py` does it through the SDK, the
CLI (then a daemon reopening the imported project), the roles and MCP.

## Debug info

At import, an image's DWARF (`debuginfo::dwarf_sections`) and a PE's PDB are
read and become assertions in the import revision:

- function and global variable names (`import:dwarf`, `import:pdb`);
- prototypes and variable types as `TYPE` = `h:<hash>`, except for
  functions DWARF marks `DW_CC_nocall` (their ABI was changed);
- one `TYPE_DEF` record per type those hashes reach.

The PDB is looked up as `rk-debuginfo` does (the debug directory's path, its
file name beside the binary, then `<stem>.pdb`) and must match the image's
CodeView GUID and age. A PDB can also be loaded later, from a path, an upload
or the symbol path ([pdb.md](pdb.md)). It is staged after DWARF, so it wins ties. `GetTypes`
serves the records. The tests compare decompiled prototypes with the debug
info's own, printed in Ghidra's notation: the test program built with `-g`
matches exactly, and so does every compared function of the corpus's clang
`-O2` `features.exe` against its PDB.

### External debug files

`api_minor` 86, feature `debug-files` (`src/backend/debug_files.{h,cc}`).
A stripped ELF's DWARF is often in a separate file, which the binary names
two ways: its GNU build ID note (`NT_GNU_BUILD_ID`) and its
`.gnu_debuglink` section (a file name and the CRC-32 of that file). A
candidate is used only when it is an ELF with `.debug_info` whose build ID
is the program's (for a program without one, whose CRC-32 is the
debuglink's); its sections go through the same reader as an embedded
`.debug_info` (`inputs::read_debug_info`, then `debuginfo::import_dwarf`),
at the binary's link-time addresses.

**Where it is looked for**, in order (`FindDebugFile`):

| Where | Paths |
| --- | --- |
| beside the binary | `<dir>/<debuglink>`, `<dir>/.debug/<debuglink>` |
| each of the settings' `debug_dirs`, then `/usr/lib/debug` (searches only) | `<d>/.build-id/<xx>/<rest>.debug`, `<d>/<dir>/<debuglink>`, `<d>/<debuglink>` |
| the cache | `<project_dir>/.revkit/debuginfod/<build id>/debuginfo` |
| debuginfod servers (searches only, when on) | `GET <url>/buildid/<build id>/debuginfo`, kept in the cache |

**At load** (an import, and every time a project opens) an ELF without
`.debug_info` takes the first file found beside the binary, in
`debug_dirs` or in the cache, never from the network or `/usr/lib/debug`
(so what a program's analysis reads doesn't depend on what the host
happens to have installed): its DWARF is the program's, as if embedded.
The decompiler's inputs (local variables, types) come from it, and an
import stages its names, prototypes, types and categories as
`import:dwarf` assertions. `ProgramSummary` says the `build_id`, the
`debuglink` and the `debug_file` read.

**Load debug file** (`ProjectService.LoadDebugFile`, admin) does it for a
program already open, from a path on the daemon's host, an upload, or
`search` (the table above, `/usr/lib/debug` and the servers included). A
file of another build is refused (`FAILED_PRECONDITION` naming both build
IDs) unless `force`; a file that isn't an ELF with DWARF is refused even
then. Its DWARF becomes `import:dwarf` assertions in one revision, with a
note on the image base (`revkit:debug-file`) naming the file, and the
response's seqs undo it (`RetractAssertions`). An exact file is also kept
in the cache, so the program reads it at its next load: from then on the
decompiler has its variables too (within the session that loaded it, the
names, prototypes and types apply at once, as Load PDB's do). `search_log`
says each place tried.

**Settings** are the symbol settings' siblings (`SymbolSettings`;
`GetSymbolSettings` and `SetSymbolSettings`, admin; kept in
`<project_dir>/.revkit/symbols.json`): `debug_dirs`, `debuginfod` (off by
default), `debuginfod_urls` (https only unless `debuginfod_allow_http`),
`debug_file_max_bytes` (default 1 GiB, a read or a download) and
`debug_cache_max_bytes` (default 4 GiB; the oldest files go first), and
read-only `debug_cache_dir`. `GetSymbolSettingsResponse.suggested_debuginfod_urls`
lists what the daemon's `DEBUGINFOD_URLS` names, for the UI to offer: it is
never used unless an admin sets it. `rk-daemon --debug-dir <dir>` and
`--debuginfod <url>` (repeatable; the latter turns fetching on) set them
for a run. An older client's `SetSymbolSettings`, which doesn't know the
new fields, turns fetching off and clears the directories (the safe
direction); the Python SDK's `set_symbol_settings` keeps them.

**Network and trust** ([security.md](security.md#debuginfod)): a server is
contacted only with `debuginfod` on, by an admin's `LoadDebugFile`
`search`; redirects are followed only on the same host (scheme, host and
port); a file over the size limit is dropped as it arrives; what arrives
is checked (an ELF with the program's build ID) before it is kept, and is
then read by the loader and the DWARF reader as any binary is.

**Using it.** Python: `Program.load_debug_file(path=None, *,
local_file=None, search=False, force=False)`,
`Client.set_debug_file_settings(dirs=, debuginfod=, urls=, allow_http=,
max_bytes=, cache_max_bytes=)` and `Client.debuginfod_suggestions()`. MCP:
`load_debug_file(program_id, path="", search=False, force=False)`. UI: the
Analyze menu's *Load debug file…* and *Debug file directories and
debuginfod…* ([ui.md](ui.md#load-debug-file)).

**Tests.** `src/backend/tests/debug_files_test.cc`: a program built with
`-g` and a build ID, split with `objcopy --only-keep-debug`, stripped and
given a debuglink; the debuglink and its CRC (a damaged copy refused), the
file found beside the binary, in `.debug/`, in a build-ID tree and under a
mirrored directory; an import reading it beside the binary (the decompiler
names a local the DWARF names); `LoadDebugFile` by path (another build's
refused, a stripped binary refused even forced, undo), and the next load
reading it from the cache; debuginfod from an `httplib` server on a
loopback port: not asked while off (`DEBUGINFOD_URLS` only suggested), http
refused unless allowed, another build's file not kept, a redirect to
another port not followed, a same-host one followed, the size limit, then
the cache without asking; the cache's size. `sdk/python/tests/test_debug_files.py`:
the SDK by path and undo, the settings, a fake debuginfod (Python's
`http.server`), MCP from the cache. Untested: a real HTTPS server (the
client is the symbol servers', with OpenSSL's certificate checks) and the
real internet.

## Concurrency

- **Writers.** One writer per project (`Project::write_mu`, then the
  store's own writer). The commit runs outside the backend's global lock;
  publishing the revision (head, retained snapshot, event, broadcast) takes
  it briefly, so events stay in revision order.
- **Readers** take a retained snapshot under the global lock, release it
  and read lock-free. Queries for different keys run in parallel; a key is
  computed by one thread while others wait (facts.md).
- **Imports** load, describe the program and read debug info outside any
  lock. Discovery runs after the import's commit: the seeds' flows, then
  discovery's fixpoint (whose walks, sorts and bodies, and each round's
  new flows, run on the project engine's pool, `Engine::set_pool`), then
  every function's references, and then side by side the listing's rows,
  the decompiler's program inputs and a decompiler instance built with
  them, on a shared thread pool (`ImageBackendOptions::analysis_threads`,
  `rk-daemon --analysis-threads`) from 1 MiB of code, on the calling
  thread below (each thread needs SLEIGH engines, built one at a time at
  tens of milliseconds each; discovery's are freed after the import).
  `REVKIT_TIMING=1` prints the phases.
- **Decompiler workers.** Every program shares the backend's worker pool
  (`ImageBackendOptions::decompile_workers`, else
  `decompilers_per_program`; `rk-daemon --decompilers`, default 2). A
  decompilation assembles its bundle on the calling thread (reading facts,
  never holding a worker), then waits for a worker; the import warms one
  and the SLEIGH engine that predicts bundles.
- **Idle SLEIGH engines** are parked after `engine_idle_seconds`
  (`rk-daemon --engine-idle`, 15 s) by a sweeper thread, keeping two
  decoded `.sla` files per language for any program to reuse
  ([memory.md](memory.md#sleigh-engines)).
- **Ghidra's process-wide state.** Building engines, architectures and
  printers holds `lift::lock_ghidra_globals()` exclusively; printing holds
  it shared (in a worker, or in the daemon with `--decompile-in-process`).

## Performance

`rk-backend-bench <binary> [--no-debug-info] [--project-dir dir]` drives the
backend through the same calls `rk-daemon` serves.

**Lua 5.4** (`corpus/elf-x86_64/gcc-O2/debug/lua`, 1.2 MB, 53,412 rows,
699 functions; its DWARF is imported: 689 functions, 48 globals, 787
types). The backend before the fact store ("before") and this one ("after")
ran alternately, three times each, on 32 cores with load average 6 to 11
(other builds were running); the table shows the median run.

| Operation | before p50 / p95 ms | after p50 / p95 ms |
| --- | --- | --- |
| Import (with DWARF; 135 ms without) | 131 | 154 |
| Listing, 100 rows, scroll, cold pages | 0.06 / 0.78 | 0.06 / 0.86 |
| Listing, 100 rows, scroll, warm | 0.05 / 0.06 | 0.05 / 0.06 |
| Listing, 100 rows centred on a function | 0.06 / 1.06 | 0.07 / 1.15 |
| Decompile every function, cold | 1.63 / 18.3 (max 1364) | 1.76 / 18.4 (max 1279) |
| Decompile every function, cached | 0.03 / 0.43 | 0.03 / 0.42 |
| Rename: commit + invalidation, in memory | 0.31 to 0.63 | 0.24 |
| Rename: commit + invalidation, LMDB (synced) | | 2.7 to 4.8 |
| Re-decompile the renamed function's 66 callers | 2.48 / 24.6 | 2.48 / 23.5 |
| Decompile all, 1 thread / 8 threads | 6.7 s / 2.3 s | 6.7 s / 2.3 s |

- **Listing** costs the same at p50 and about 10% more at p95: names,
  comments and function membership are now read per request from the
  snapshot (one key-index bucket read per 64 KiB, then lookups) instead of
  from a per-revision map built at the first read of each revision.
- **Import** is 23 ms slower: reading DWARF and staging about 2,200 import
  assertions in one commit, plus writing the file's bytes to the store.
- **Decompilation** is unchanged. Tracking costs one hash lookup per symbol
  lookup; resolving a symbol the first time in a run is a memoized query.
  An early version asked for the containing label on every
  `findContainer` call and was 1.6 times slower; that answer is now
  memoized per address per run.
- **Rename** commits faster than before, since nothing is copied per
  commit; on LMDB the commit waits for fsync.
- **Persistent projects** (`--project-dir`): reopening Lua with 699 cached
  decompilations takes 40 to 70 ms; decompiling everything again loads
  each from disk (p50 0.13 to 0.23 ms). The directory is 27 MB.

### Function discovery

The same benchmark before and after the backend took its functions,
listing and references from `src/analysis` (Lua, gcc -O2; three
alternating runs each, 32 cores, load average 5 to 7; median run). The
program has 786 functions now (PLT stubs and discovered call targets)
instead of 699, and 52,942 rows instead of 53,412 (padding is coalesced
data rather than undecodable bytes and `nop`s).

| Operation | before p50 / p95 ms | after p50 / p95 ms |
| --- | --- | --- |
| Import, debug build (with DWARF) | 158 | 453 |
| Import, stripped | 146 | 553 |
| Listing, 100 rows, scroll, cold pages | 0.06 / 0.87 | 0.08 / 0.84 |
| Listing, 100 rows centred on a function | 0.07 / 1.15 | 0.08 / 1.01 |
| Decompile every function, cold | 1.78 / 19.7 (max 1399) | 1.41 / 20.3 (max 2507) |
| Decompile every function, cached | 0.04 / 0.47 | 0.04 / 0.35 |
| Rename: commit + invalidation | 0.26 | 0.25 |
| Decompile all, 1 thread / 8 threads | 7.2 s / 2.8 s | 7.2 s / 3.6 s |

- **Import** is about 3x slower (+300 ms): the old sweep decoded each byte
  of code once; discovery decodes every reached instruction with display
  text (about 120 ms), probes jump tables (20 ms), builds its own SLEIGH
  engine (50 ms, once per process), runs the fixpoint (45 ms), and the
  references decode the bodies again (100 ms). Programs under 1 MiB of
  code are analysed on one thread: a cold pool spent more building engines
  than it saved.
- **Decompilation** is the same per function. The slowest (`resume`,
  2.5 s) is one the decompiler can't recover a jump table in, so it runs
  twice, the second time with discovery's table.
- **Rename** is unchanged: an edit that can't steer discovery reuses the
  previous revision's functions and references in its commit.

## Known gaps

- **Listing.** Data rows are 16-byte `undefined` lines; no typed data yet.
  Code only a data pointer reaches is data until someone asserts its entry
  (discovery doesn't follow data pointers), except in raw images, where the
  firmware search follows code pointers and start patterns
  ([firmware.md](firmware.md)). Instructions an asserted body
  claims but no flow decoded stay data.
- **Discovery granularity.** `analysis.functions` is one whole-program
  memo: any edit that steers discovery reruns the fixpoint (over memoized
  flows, about 45 ms on Lua). Flows read flow overrides by 256-byte span,
  so an override re-runs the other flows with a flow instruction in its
  span (they cut off). The backend projects (`functions.table`,
  `listing.code`, `xrefs.static`, `names.default`, `listing.rows`) are
  whole-program too.
- **Import time.** Discovery decodes every reached instruction with
  display text and tokens, and references decode them again; a p-code-only
  decode (`Lifter::lift_pcode`, on another branch) would cut both. Small
  programs build one discovery SLEIGH engine per process, which the first
  import pays for.
- **Decompiler inputs.** Inferred no-return functions (Lua's `lua_error` on
  x86-64) are told to the decompiler, which Ghidra's x86-64 analysis
  doesn't infer, so callers' output differs from Ghidra's there. A jump
  table given as an override has its destinations sorted and deduplicated
  (case labels from Ghidra's trivial model), and costs a second decompile.
- **Functions.** Names asserted by a user don't feed discovery (a function
  renamed `exit` isn't no-return).
- **Types.** Only types reachable from asserted prototypes and globals are
  imported (locals' too, so their names can be rebound). Bitfields are
  left out of the structs given to Ghidra. A C retype the parser can't
  read is display only, as all of them were before `revkit::cparse`. A
  bound type name (`BindTypeName`) reaches asserted and debug-info
  prototypes (a debug-info prototype is given again, from the same
  source, when a type it reaches is rebound), debug-info globals and
  locals (`own_inputs.cc`; a stack local keeps its slot's size, so a
  rebinding that resizes its type leaves it alone) and every display.
  Rebinding invalidates every decompilation served so far (subscribers'
  events); the fact store itself re-runs only those whose
  `types.resolved` changed.
- **Instruction facts.** The decompiler reads the program's bytes, which
  never change after import; its dependency on them is the file's hash in
  the program source, not per-instruction facts.
- **Origins.** `computed_at_revision` reports the revision read, not the
  one the memo was computed at.
- **Persistence.** Memos computed since the last flush are lost in a crash
  (recomputed later). Two daemons can't open one project directory (the
  second is refused); to share a project, link daemons with `--peer`
  ([collab.md](collab.md)).
- **Archives.** An archive is read into memory per member (the log, then
  one program at a time) and the import's analysis runs in the call, so a
  large archive takes as long as importing its programs. Folder edits
  aren't in archives as history (the layout is), and neither are
  deleted programs. A program whose loader plugin the importing daemon
  lacks is reported in `warnings` and not loaded.
- **Subscriptions.** Decompilations named in `invalidated` beyond static
  callers come from decompilations served in this process.
- **Decompile.** No line wrapping, and local renames are display
  overlays that can't steer the decompiler. A run is bounded
  (`ImageBackendOptions::decompile_timeout_seconds`; `rk-daemon` uses 30 s, as Ghidra,
  which a request's `timeout_ms` replaces and its deadline shortens;
  `decompile_max_varnodes`, 1M) and stops when its client cancels (which
  kills its worker: `CANCELLED`, not cached). A run over its timeout or
  varnode bound, a worker killed at its hard deadline (1.25 times the
  timeout plus 2 s) and a worker that crashed are failures
  (`DecompileResponse.failure`, [decompd.md](decompd.md)). Escalated
  results live in memory only: a reopened project shows the timeout
  again until escalated again. Asserted
  parameter and local types are committed to the decompiler
  ([decompiler-inputs.md](decompiler-inputs.md#variable-types)) and
  printed in their declarations (an overlay on the declaration's TYPE
  tokens); a typed temporary, or a parameter of a function whose prototype
  nothing locked, costs a second run. A C prototype the parser reads is applied
  (the decompiler prints it); one it can't is not, and
  `prototype.c_declaration` carries the text as written either way.
- **Header rows.** Commits compute the header-rows windows for
  subscribers only once a client has read the listing with header rows. A
  name or comment edit reads just the edited addresses at the new revision
  (about 1 ms on cmake and libLLVM); an edit that steers discovery diffs
  both revisions' bucket memos. Labels and comments at addresses inside a
  coalesced data row get no lines (as before, they aren't shown). The
  first listing read after any edit validates discovery's results (about
  0.1 s on cmake, seconds on libLLVM), with or without header rows; that
  cost predates them.
