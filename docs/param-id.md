# Decompiler Parameter ID (Ghidra's analyzer, reproduced)

On a stripped program, Ghidra's auto-analysis runs its decompiler over
every function, callees first, and writes the parameters, return type and
calling convention it finds back into the program database with source
`ANALYSIS`. Callers are then decompiled against those locked signatures:
they pass the right number of arguments, read typed returns, and a wrapper
that passes registers through to a callee gets them as parameters.
revkit reproduces the analyzer as part of its default analysis, as fact
queries, so that decompiling from revkit's own inputs matches Ghidra's C
([decomp-parity.md](decomp-parity.md#from-revkits-own-inputs-phase-3)).

This is parity with what Ghidra feeds its decompiler. Matching the
*source's* prototypes is `src/infer`'s job ([infer.md](infer.md)), opt-in
and layered on top (below).

## What Ghidra does

From Ghidra 12.1.4's sources (`DecompilerFunctionAnalyzer`,
`DecompilerParameterIdCmd`, `HighFunctionDBUtil`, `AcyclicCallGraphBuilder`,
`PcodeDataTypeManager`, in `Features/Decompiler` and
`Framework/SoftwareModeling`):

**When it runs.** The analyzer "Decompiler Parameter ID" is a function
analyzer at priority `DATA_TYPE_PROPOGATION.after().after()`, enabled by
default only for a **PE whose memory has fewer than 2 MiB of addresses**
(`getDefaultEnablement`: "only do for windows by default, windows has good
type info"; `Memory.getNumAddresses`, every block). On ELF, Mach-O and raw
images (firmware) it is off unless a user turns it on. The corpus exports
confirm it: every program's own function on stripped PE has signature
source `ANALYSIS`, none on ELF or on the firmware images (their database
prototypes are all `undefined FUN_x()`).

**Options and their defaults**: clear level `ANALYSIS`, commit data types
on, commit void return values off, decompiler timeout 60 s.

**The command** (`DecompilerParameterIdCmd.applyTo`):

1. `AcyclicCallGraphBuilder(program, set, killThunks = true)`: the
   functions of the analyzed set, each thunk replaced by the function it
   finally thunks (`getThunkedFunction(true)`, an external function for an
   import's). A depth-first walk from start points adds a dependency from
   each function to every function it calls (call references, which
   includes computed calls analysis resolved and the jumps
   `SharedReturnAnalysisCmd` turned into `CALL_RETURN`) unless the callee
   is on the walk's stack: **in a recursion, the call back to a function
   being walked is dropped**, so the callee of that edge is decompiled
   first, with its caller not yet committed. Start points are entry points
   and functions nothing calls, in the iteration order of the
   `java.util.HashSet<Address>` holding the functions; when they run out,
   the lowest address left (a cycle nothing outside calls).
2. `resetFunctionSourceTypes`: signatures (and returns) of source
   `ANALYSIS` or lower go back to `DEFAULT`; higher sources stay.
3. `ConcurrentGraphQ`: each function is decompiled once everything it
   depends on is done, on the shared analysis thread pool.
4. `analyzeFunction` skips **thunks**, functions whose signature source
   is not `DEFAULT` (**imported** from debug info or a type archive, or
   **user-defined**), **external** functions and **external glue** (entry
   in a block named `EXTERNAL`, `.plt` or `__stub_helper`). Otherwise it
   decompiles with a `DecompInterface` set up as `toggleCCode(false)`,
   `toggleSyntaxTree(false)`, simplification style `decompile`, options
   from the program with **`setEliminateUnreachable(false)`**, and the 60 s
   timeout. A decompilation that doesn't complete commits nothing.
5. `hasInconsistentResults` would refuse a result with an `in_` register
   local, but it inspects each symbol's `HighVariable`, which exists only
   when the syntax tree is sent: with it off, the check never fires.
6. `HighFunctionDBUtil.commitParamsToDatabase(hfunc, useDataTypes = true,
   COMMIT_NO_VOID, ANALYSIS)`:
   - the convention is the decompiler's prototype model, the compiler
     spec's default where it was `unknown` (`getPrototypeModelForCommit`);
   - the return is the decompiler's type and storage, **unless it is
     `void`, in which case the function keeps its return** (`undefined`,
     no storage: an unlocked `void` to later decompilations);
   - the parameters are the local symbol map's parameter symbols in
     order: name (`param_N`), data type and storage;
   - `updateFunction(..., DYNAMIC_STORAGE_ALL_PARAMS, force, ANALYSIS)`,
     then `CUSTOM_STORAGE` if the convention would place the parameters or
     the return elsewhere than the decompiler did (a first parameter in
     XMM0, a return in RDX);
   - varargs from the prototype.
   Types go through Java: `PcodeDataTypeManager.decodeDataType` maps the
   decompiler's core `code` type to `DEFAULT` (`undefined`), unnamed
   unknown bytes to `undefinedN` up to 8 bytes and to `undefined1[n]`
   beyond, invented structures and relative pointers to undefined bytes of
   their size, unnamed integers to Java's integer of that size.
7. `checkModelNameConsistency`: a `__stdcall` function with parameters and
   a stack purge of 0 becomes `__cdecl` (32-bit x86 only).

**What it does not commit**: local variables (`commitLocalNamesToDatabase`
isn't called), the stack purge (extrapop), parameter names other than the
decompiler's defaults, a `void` return, anything for thunks, externals,
glue or functions with a better signature, anything when the decompilation
fails or times out. It never runs on ELF or raw images by default, so
**it changes nothing on ELF programs or firmware** in Ghidra's own output.

## What revkit reproduces

| Ghidra | revkit |
| --- | --- |
| default enablement | `inputs::param_id_default` (PE, memory blocks under 2 MiB of addresses); `ParamIdMode` `auto` (default), `on`, `off` |
| `AcyclicCallGraphBuilder` | `inputs::param_id_plan` over `inputs::call_graph_nodes` (discovery's functions and flows: calls, resolved computed calls, shared-return jumps; thunks followed to their final target; seeds that are the entry, exports or processor vectors as entry points). The walk is Java's, including the start order: `java.util.HashMap`'s bucket layout, resizes and red-black tree bins, checked against OpenJDK 21 (`ParamIdPlan.JavaHashSetOrder`) |
| `analyzeFunction`'s skips | `inputs::param_id_skip` |
| its `DecompInterface` | worker mode `param_id` (`decompd::Mode::param_id`): c_text's decompiler with the `unreachable` action off, the function's model read instead of printed |
| `commitParamsToDatabase` | `lift::commit_signature` (`src/lift/param_id.cc`): the model, the return (or nothing for `void`), the parameter symbols, custom storage where `InputDecompiler::assign_storage` (Java's dynamic storage) differs, types as Java decodes them (`lift::type_reference`) |
| the database afterwards | `inputs::apply_param_id`: signature source `analysis`, explicit storage; a thunk shows its target's |

Not reproduced: `checkModelNameConsistency` (32-bit PE only, which the
corpora don't have); external functions' numbering in Ghidra's `EXTERNAL`
space, which enters the start order only through the HashSet (approximated
by import slot order); and keys of equal hash in a tree bin, which Java
orders by identity hash code (address order here; distinct functions of
one program don't collide).

**Determinism.** Ghidra's pool decompiles independent functions in any
order, but a function only ever sees its dependencies committed (a callee
is either a dependency, done before it, or a function on the walk's stack
above it, done after), so its result is fixed. revkit makes that exact: a
function's decompilation sees the commits of its dependencies and nothing
else (`decompd::CommittedLookup`, or the backend's `QueryLookup` in its
parameter-ID view), so results are the same at any thread count (save for
decompilations that run into the timeout).

## Where it runs

**rk-lift** (`--analyze --decompile`, the corpus and held-out gates):
after the inputs are assembled, `decompd::param_id_functions` decompiles
the plan's functions in workers, dependencies first and in parallel, and
`inputs::apply_param_id` lays the commits over the inputs before the final
decompilation (and `--dump-inputs`). `--param-id auto|on|off`,
`--param-id-timeout` (60 s), `--no-own param_id`.

**The image backend** (`src/backend/param_id.h`), as queries:

| Query | What | Reads |
| --- | --- | --- |
| `param_id.mode` (input) | auto, on or off (`ImageBackendOptions::param_id`), staged at import and on reopen | |
| `analysis.param_id_plan` | whether the analyzer runs, and its dependency graph | `param_id.mode`, `inputs.static` (memory), `analysis.functions`, every `analysis.flow` |
| `analysis.param_id_deps` | one function's slice of the plan | `analysis.param_id_plan` |
| `analysis.param_id` | what the analyzer commits for one function: its decompilation in mode `param_id`, seeing exactly its dependencies' commits | `analysis.param_id_deps`, the dependencies' `analysis.param_id` it looks up, and whatever its decompilation looks up (`QueryLookup`) |
| `param_id.published` (input) | the commit decompilations see, one key per function (and thunk) | |

Decompilations (`decompile.ghidra`) read only `param_id.published`, for
each function they look up. The backend computes `analysis.param_id` in
the background and publishes it:

- **When**: after an import's analysis, after every commit that changes a
  program's facts (user edits, replication; not its own), and on reopen
  (published values aren't persisted; the commits are memoized and
  validate). Requests are coalesced per program.
- **How**: callees first, each function as soon as its dependencies are
  done (as `ConcurrentGraphQ`), on at most `decompile_workers - 1`
  decompilations at once so that an interactive decompilation always finds
  a worker. Results are published as they arrive, at most every 2 s, in
  revisions of cause `CHANGE_CAUSE_ANALYSIS`; a function whose published
  signature changes invalidates what a prototype edit would (its
  decompilation, its callers', those that looked it up).
- `GetAnalysisStatus` lists the pass as a `decompiler_parameter_id` job
  and isn't `idle` until it is done.

**Why in the background.** It is a whole-program decompilation. Done
eagerly at import it would cost a program's full decompilation time before
the first decompile (cmake, forced on: see Cost); lazily, the first
decompilation of `main` would wait for every function `main` reaches. In
the background, the first decompilation is as fast as without the analyzer
and is redone when its callees' signatures arrive; with Ghidra's default
enablement the pass only ever runs on PE programs below 2 MiB.

**Precision.** An edit re-runs only the commits whose decompilation looked
up what it changed (a user prototype on a leaf: the leaf, its callers, and
theirs while their commits change), and a published change re-decompiles
only the functions that look the function up
(`ParamIdTest.UserPrototypesOutrankAndRecomputeOnlyWhatTheyReach`).

**Precedence.** In the decompiler's lookups (`QueryLookup::with_overlay`):
the user's prototype assertions, then the debug info's and the type
archives' signatures (both are signature sources above `DEFAULT`, which
the analyzer never touches), then revkit::infer's prototype where the
program was imported with `infer_prototypes`, then the analyzer's commit.
Inference refines what the analyzer would commit: it starts from the same
decompiler view and adds callers', callees' and the ABI's evidence across
the call graph to a fixpoint, so where it has a prototype it wins, and the
analyzer's stands where it has none. The analyzer's own decompilations see
neither inference nor anything published, only the user's and the debug
info's prototypes and their dependencies' commits, as in Ghidra.
`rk-infer` and its Phase 4 gate don't involve the analyzer.

## Results

Own inputs (`rk-lift --analyze --decompile`), `c_ast` on the functions
both sides have; before: master with data analysis, after: this analyzer
(`scripts/decompile-corpus.sh --inputs own`, `corpus/baselines/rk-decomp-own.json`
re-saved):

| tuning corpus | before | after |
| --- | ---: | ---: |
| all (9,812 functions) | 90.1% (8,845) | **92.3%** (9,060) |
| ELF (8,416) | 94.3% | 94.3% (the analyzer doesn't run) |
| PE (1,396) | 65.3% (911) | **80.7%** (1,126) |
| PE stripped, clang -O0 / -O2 | 58.6% / 54.7% | **88.9% / 85.8%** |
| PE debug, clang -O0 / -O2 | 71.8% / 74.9% | 73.3% / 75.8% |

Debug PEs change little: the PDB gives almost every function a signature
the analyzer leaves alone (7 of 208 functions are analyzed in
`features.exe`). The signatures themselves: on the stripped PEs, 540 of
the 557 functions Ghidra's database has with source `ANALYSIS` get the
same convention, return, parameter names, types and storage, and custom
storage flag from revkit (all 20 on the debug PEs); the 17 others differ by
a type that comes from elsewhere (5 returns per binary typed with PE header
structures revkit's data analysis doesn't lay down, `IMAGE_SECTION_HEADER *`,
and two parameters' pointees in cJSON).

**The remaining signature gap** (`scripts/decomp-ablation.py --own`,
[decomp-parity.md](decomp-parity.md#the-remaining-gap)): replacing
revkit's signatures with the ones Ghidra's analyzer committed gained 207
functions before (90.1% → 92.3%: the ceiling) and now loses 8 (revkit's
fit its other facts better than Ghidra's); the program's own signatures
from elsewhere (debug info) lose 139 as before. No kind of signature is
left that swapping in Ghidra's would gain on.

**Firmware and ELF**: unchanged, as in Ghidra, which doesn't run the
analyzer there (`scripts/ci.sh --firmware`: every processor's C as before;
the ARM camera firmware's sample as before, 70.0% identical tokens). The
firmware gaps attributed to parameter analysis ([firmware.md](firmware.md))
come from elsewhere: Ghidra's firmware databases hold only default
prototypes, and forcing the analyzer on (`--param-id on`) takes `ast` from
72/70/61/66/37/63% (Cortex-M, 68000, MIPS, PowerPC, SuperH, Xtensa) to
22/38/22/20/33/26%.

**Held out** (`scripts/ci.sh --heldout-only`, run once, summary rates
only, [heldout.md](heldout.md)): own inputs' `c_ast` 75.9% → **81.9%**
(48,729 of 59,525 functions), PE 40.0% → **69.0%** (8,491 of 12,309),
stripped builds 79.3% → 91.3%, ELF unchanged (85.2%). Phase 4's held-out
gate is unaffected (matchable subset, signature: revkit 36.5%, Ghidra
18.8%, +17.7 pp: met).

## Cost

Same machine as [decomp-parity.md](decomp-parity.md#speed), shared with
other jobs (load 3 to 15 during these runs).

**rk-lift**: one more decompilation of each analyzed function. On the
tuning corpus's stripped PEs (138 to 214 functions, one thread) the pass
takes 1.1 to 2.6 s beside 1.2 to 2.8 s for the final decompilation; debug
PEs analyze a handful of functions (0.1 s); ELF and raw images none.

**The backend** (`rk-backend-bench --cold-start`, which also waits for the
pass and decompiles the same function again):

| | import | first decompilation | in all | the pass | the function again |
| --- | ---: | ---: | ---: | ---: | ---: |
| cmake (ELF, 19,409 functions), `auto` (Ghidra's default: off) | 1.38 s | 12 ms | **1.40 s** | none | |
| cmake, forced on, 8 workers | 1.47 s | 12 ms | **1.49 s** | 86 s (158 s at load 14) in the background, 40 to 67 revisions | 0.36 to 0.57 s |
| libLLVM (ELF, 119K functions), `auto` | 35.5 s | 1.0 s (`_DT_INIT`) | 36.6 s | none | |
| cjson.exe stripped (PE, 214 functions), `auto` | | | | about 2 s | |

The cold-start gate (`scripts/scale-check.sh`: cmake's `main` within 2 s)
holds either way, at 1.43 s: the first decompilation never waits for the
analyzer, which is the point of running it in the background (eagerly,
cmake's import would take 86 s or more; lazily, `main` would wait for
every function it reaches). With Ghidra's default enablement the pass
only ever runs on PEs below 2 MiB of addresses, a few thousand functions
at most: seconds to a minute in the background on the default 2 workers
(1 for the pass).

Forced on, the pass's cost is a whole-program decompilation's: cmake's
peak resident memory goes from 0.9 GB to 3.6 GB (the memos each
decompilation leaves, about 140 KB per function), and on libLLVM, forced
on and in memory, the backend passed 11.5 GB before the run was stopped
(one decompilation pass of libLLVM is about 8,400 CPU-seconds,
[infer.md](infer.md#scale): about 20 minutes on 7 workers). An in-memory
project keeps every memo (spilling needs a project directory), so forcing
the analyzer on a program that size wants `--project-dir`.

## Known gaps

- Ghidra re-runs the analyzer on functions created later in auto-analysis
  (each "added" set); revkit runs it once over the final function list.
- Signature differences that remain on the tuning corpus are inputs, not
  the analyzer: PE header structures (`IMAGE_SECTION_HEADER *` returns)
  revkit's data analysis doesn't type, and `undefined8 *` against
  `undefined4 *` where a callee's data differs.
- The backend's function list and listing header rows show asserted and
  debug-info signatures, not the analyzer's (the decompiler shows them).
- `rk-daemon` has no flag for the mode yet (the default is Ghidra's).
- Forced on a very large program, the pass's memos make an in-memory
  project grow with the program (above).
