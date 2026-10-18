# Prototype and type inference (Phase 4)

`src/infer` (`revkit::infer`) infers every function's prototype in a
binary: parameters, their types, the return type and varargs, starting
from what Ghidra's decompiler concludes about each function and improving
it across the call graph to a fixpoint. This note covers the method, the
gate measurement, what it does to decompiled C, scale, and the gaps.

> **Phase 4 gate:** on stripped corpus binaries, scored against DWARF
> ground truth, exact-prototype recovery exceeds Ghidra's default analysis
> by ≥10 percentage points; the fixpoint converges within budget on a
> 100 MB binary.

**Result: not met at +10 pp.** Exact prototypes are out of reach for both
sides on stripped binaries (they need the names). At the level the
reference format gates on, **signature** (types exact after notation
normalization, names ignored), revkit recovers **13.6%** of 3481 functions
against Ghidra's **4.7%: +8.9 pp** (per arch +6.5 to +18.5 pp, below).
About three quarters of the truth prototypes name a program's own structs
(`lua_State *`, `cJSON *`, `z_stream_s *`), which no stripped-binary
analysis can name, so the reachable ceiling is about 25%; revkit gets
just over half of that. The fixpoint converges on every corpus binary
(at most 9 rounds) and on `/usr/bin/cmake` in 9 rounds, about 6 to 10
minutes and 1.84 GB (below).

```sh
build/tools/rk-infer/rk-infer [-j N] [--local] [--decompile [--no-feedback]] [-o out.json] BINARY
python3 tools/rk-infer/score.py          # the gate table; scripts/ci.sh runs it against a baseline
python3 tools/rk-infer/c_quality.py      # decompiled C with and without inferred prototypes
rk-daemon --open BINARY   # the backend's decompiler uses them (default auto; --infer-prototypes on|off)
```

## Method

### Observing one function

`infer.observe` (`decompiler.h`) runs Ghidra's decompiler on one function
with an `ImageArchitecture` whose global scope asks a `SymbolEnv` about
every address the decompiler looks up, so a decompilation's dependencies
are exactly the callees and function pointers it consulted. It records:

- the parameters and return value the language's `.cspec` prototype model
  gives the function (storage read before written, storage live at its
  returns), typed by the decompiler's own type propagation;
- how many low bytes each parameter's uses take (an `int` passed in a
  64-bit register is truncated by every use; RISC-V passes it
  sign-extended and some 32-bit operation truncates it), and how wide the
  returned values are before extension into the return register;
- per call site: the arguments (storage from the call's parameter trials,
  types from the caller's variables), constants passed (function and
  static-data addresses), and whether and how widely the result is read;
- the prologue as decoded, before any analysis: argument registers stored
  before anything writes them (a register save area) and an AL read.

### Rounds and the fixpoint

Rounds are explicit in the query keys (`RoundKey{Location, round}`), and
they work through the call graph in order (`infer.order`): its strongly
connected components, with the members of each function-pointer table
family joined into one, ranked callees first.

| Query | Value | Reads |
| --- | --- | --- |
| `infer.image.effective` | the staged image (`infer.image`) with the memory map's edits laid over it, and a decompiler pool over that; the staged one itself without edits ([memory-map.md](memory-map.md)) | `infer.image`, `analysis.memory` |
| `infer.callgraph` | callers and callees (direct and tail calls), import stubs, import slots, functions only tables of pointers reach, and which functions don't return: discovery's, and those the no-return evidence finds, as the decompiler is told (else a caller's decompilation runs on past such a call into the next function's code, whose argument registers look like the caller's parameters), and the unconditional jumps to another function's entry, which its decompilations take as tail calls (`CALL_RETURN` flow overrides, as Ghidra's SharedReturnAnalysisCmd and the final C's inputs have them; else a jump into luaL_error takes in its register save area, whose stores read every argument register) | `analysis.functions`, `analysis.flow`, `analysis.no_return_evidence` |
| `infer.order` | each function's rank: its component's position, callees first | `infer.callgraph`, `infer.families` |
| `infer.observe` (f, k) | f decompiled with its callees' prototypes locked: round k's for callees ranked below f, round k-1's for the rest (round 0: only library prototypes) | `infer.round` (callees, k or k-1) |
| `infer.own` (f, k) | f's prototype from its own evidence | `infer.observe` (f, 0 and k; callers, 0 and k, or k-1 for callers ranked above f) |
| `infer.families`, `infer.callbacks` | function-pointer tables in data; functions passed to library callbacks | `infer.image.effective`, `infer.observe` (*, 0) |
| `infer.round` (f, k) | `infer.own`, a callback's or a table family's type, joined with round k-1 | `infer.round` (f, k-1) |
| `infer.fixpoint` | rounds until two in a row change no prototype, at most 16 | every `infer.round` |
| `infer.prototype` | one function's final prototype | `infer.fixpoint` |

Within a round a query reads round k only of queries ranked strictly below
it, and round k-1 of the rest (its own component included), so there are
no query cycles and the result is the same whatever the thread schedule.
(The engine's cycle hook would also do, but which participant recovers
there depends on which thread detects the cycle, facts.md.) What a callee
learns reaches all its callers' callers in the same round, instead of one
call edge per round as when round k read only round k-1 (until this
change). Callers ranked above a function are seen a round late, so one
unchanged round isn't yet the fixpoint: the next can still move a function
whose callers changed in the last; two unchanged rounds are.

`infer::run()` computes each round for every function in parallel with
`Snapshot::get_all`, callees first; `infer.fixpoint` then reads memoized
values. A later round whose consulted callees didn't change reuses the
previous observation, and so does round 1 where round 0 consulted none of
the program's own functions. An observation reads the callee prototypes it
will lock before it leases a decompiler (computing those leases decompilers
of their own), and at most two functions of 8 KB of code or more decompile
at once. A function whose decompilation grows past `max_varnodes` (100K,
about 75 MB; the corpus's largest has 29K) isn't observed, only seen from
its callers (`Observation::too_large`, deterministic, unlike a timeout).

**Termination.** Each round's prototype is the join of the previous one
and the new evidence (`join` in `merge.h`), so a type only ever becomes
more specific in a finite lattice; a prototype that still changes more
than `change_budget` (3) times is widened (types forgotten, shape kept)
and frozen; rounds are capped at 16. On the corpus nothing is widened.

### Combining evidence (`merge.cc`)

- **Storage.** The positions round 0 and the current round agree on, or
  whichever sees any: round 0 sees a register a call passes through to an
  unknown callee as a parameter (too many), a later round sees one a
  callee with a parameter too many reads (also too many), and a wrapper
  that tail-calls a function unknown at round 0 shows none there. A
  register only a later round sees is a parameter when the function passes
  it on unchanged (`Slot::from_param`) to a callee that reads it: the
  callee's round-0 or previous round's view has it, its own code uses it
  (not only passes it on, `Slot::passed_only`, nor stores it in a register
  save area) or passes it on to one that does (followed through up to four
  callees; an import reads what its library prototype names), and it is
  one of the callee's named parameters (luaL_checklstring's `len`,
  passed straight to lua_tolstring, which round 0 doesn't see: the
  decompiler takes only registers written before a call as an unknown
  callee's arguments). Integer registers only, without holes, and none
  where the function reads every argument register (a save area's
  pattern).
  Positions are ordered by the convention (`abi.cc`: System V, Windows
  x64, AAPCS64, RISC-V LP64D), integers before floats where the
  convention doesn't say.
- **Callee → caller.** Callees are decompiled locked, so their parameter
  types flow into the caller's variables and from there into the caller's
  own parameters: a value passed to `fprintf`'s `FILE *` makes a parameter
  `_IO_FILE *`, one passed to an inferred `int` parameter narrows a
  64-bit register to `int`.
- **Caller → callee.** What callers pass: a pointer, a char or a float
  type refines the callee's integer or unknown view (at a call locked to
  the callee's previous prototype the decompiler casts a pointer passed
  to an integer parameter, `(ulong)param_1`, and the observation takes the
  caller's pointer from before the cast; a pointer cast to another pointer
  type stays the parameter's); the address of static
  data makes a parameter a pointer, the address of a function a function
  pointer with that function's prototype (`_func_int_int_int *`). How
  results are used: the widest read decides a return's width (an `int`
  zero-extended into RAX is an `int`); a function with no return of its
  own whose callers mostly read the register returns a value; callers'
  pointer use types a return. Recursive calls count.
- **Returns.** A function ending in a tail call returns what the callee
  returns (round 0 can't see it, and with the callee locked the decompiler
  still leaves it unknown); a returned static address is a pointer; a returned function
  address a function pointer; an element loaded from a function-pointer
  table has that table's type.
- **Varargs.** A run of saved argument registers ending at the last one
  (the register save area; Windows' home slots, saved last-to-first or
  after the named ones), or AL read on System V. The first saved register
  gives the named count; float registers saved alongside are dropped.
- **Library callbacks.** A function passed to a library function's
  function-pointer parameter gets the type the library calls it with
  (`qsort`'s comparator, `bsearch`, `pthread_create`, `signal`,
  `__libc_start_main`'s `main`, whose parameters C lets it omit).
- **Function-pointer tables.** Code pointers at a constant stride in data
  (an array of pointers, or one field of an array of structs) are one C
  type: members vote on arity, return presence, varargs and each type;
  unsigned wins a tie on an integer, as in Ghidra's lattice (signed is the
  default for arithmetic, unsigned needs evidence). Targets that are
  neither an entry nor inside a body (callbacks without unwind info, which
  discovery doesn't follow) become functions.
- **One pointer, one type.** After the fixpoint, the parameters a pointer
  passes through unchanged (the last round's `Slot::from_param` edges,
  integer registers) form classes; where every member is a pointer and
  they disagree on its target (Lua's lua_State * as `long *` in most
  functions, `char *` in some), all take the target most of them have, so
  the calls between them need no cast. No majority: each keeps its own.
- **Priors.** What remains unknown is spelled as the system headers
  spell values most often (`SigDb::priors`, counted from the glibc
  database): an untyped integer-register return is `int` (a register's
  width isn't the value's), an 8-byte integer parameter `size_t`
  (`ulong`), a 4-byte one `int` (decompiler signedness for parameters
  comes from comparisons compilers choose freely: when Ghidra says `uint`
  the truth is `int` 2 times out of 3), a pointer to bytes `char *`, a
  returned `void *` `char *`, a value in a float register `double`.

### Library signatures

`tools/rk-sigdb/gen_sigdb.py` generates the databases compiled into
`src/infer` (`data/*.sigs`, embedded by `embed.cmake`): it runs
`clang -Xclang -ast-dump=json` over the host's headers, resolves typedefs
to what they name (as the typedef-resolved truth does: `FILE *` is
`_IO_FILE *`, `size_t` is `ulong`), and writes one line per function in
Ghidra's notation, with callback signatures and glibc's asm-label aliases
(`__isoc99_sscanf`).

| Database | Source | Functions |
| --- | --- | ---: |
| `glibc-lp64.sigs` (ELF, LP64) | glibc 2.39 headers in `/usr/include` (99 headers, `_GNU_SOURCE`, fortify) | 3051 |
| `win64.sigs` (PE) | mingw-w64 12 headers (`windows.h` lean, msvcrt C headers) | 9072 |

**Licenses.** Only interface facts are kept (function names and their
parameter and return types), no header text. glibc's headers are
LGPL-2.1-or-later; mingw-w64's are public domain or ZPL 2.1 (its
`COPYING.MinGW-w64-runtime`). Ghidra's `.gdt` archives (Apache-2.0
Ghidra, data derived from vendor headers) are not used: they are Ghidra
database files readable only through Ghidra's Java API, and generating our
own keeps the build free of Java.

## The gate

`tools/rk-infer/score.py` scores every stripped corpus binary with a debug
twin: the truth is `rk-debuginfo --resolve-typedefs` on the debug build
(a PE's PDB alone, `--no-dwarf`), revkit is `rk-infer` on the stripped
build, Ghidra is the signature line of its decompiled C on the stripped
build (`out/ref`, as `protonorm.py --decompiled`, the baseline
`docs/types.md` reports). Levels are protonorm's: exact, normalized,
signature, arity. revkit / Ghidra / gain in percent:

| arch | functions | exact | normalized | signature | arity |
| --- | ---: | --- | --- | --- | --- |
| **all** | 3481 | 0.1 / 0.0 / +0.1 | 0.1 / 0.0 / +0.1 | **13.6 / 4.7 / +8.9** | 90.3 / 85.7 / +4.6 |
| elf-x86_64 | 1650 | 0.0 / 0.0 / +0.0 | 0.0 / 0.0 / +0.0 | 10.8 / 4.4 / +6.5 | 91.3 / 85.3 / +5.9 |
| elf-aarch64 | 1116 | 0.0 / 0.0 / +0.0 | 0.0 / 0.0 / +0.0 | 13.1 / 4.7 / +8.4 | 87.9 / 87.2 / +0.7 |
| elf-riscv64 | 483 | 0.2 / 0.0 / +0.2 | 0.2 / 0.0 / +0.2 | 18.2 / 4.8 / +13.5 | 94.4 / 89.0 / +5.4 |
| pe-x86_64 | 232 | 0.4 / 0.0 / +0.4 | 0.4 / 0.0 / +0.4 | 26.3 / 7.8 / +18.5 | 85.8 / 73.7 / +12.1 |

Per compiler and optimization (signature, revkit / Ghidra):

| group | n | signature | | group | n | signature |
| --- | ---: | --- | --- | --- | ---: | --- |
| aarch64/clang-O0 | 95 | 48.4 / 18.9 | | riscv64/gcc-O2 | 172 | 7.6 / 2.3 |
| aarch64/clang-O2 | 797 | 3.3 / 1.0 | | x86_64/clang-O0 | 368 | 16.8 / 7.9 |
| aarch64/gcc-O0 | 95 | 51.6 / 18.9 | | x86_64/clang-O2 | 121 | 19.0 / 6.6 |
| aarch64/gcc-O2 | 129 | 19.4 / 6.2 | | x86_64/gcc-O0 | 210 | 26.2 / 9.5 |
| riscv64/clang-O0 | 95 | 36.8 / 8.4 | | x86_64/gcc-O2 | 951 | 4.1 / 1.6 |
| riscv64/clang-O2 | 121 | 7.4 / 1.7 | | pe/clang-O0 | 101 | 41.6 / 15.8 |
| riscv64/gcc-O0 | 95 | 32.6 / 9.5 | | pe/clang-O2 | 131 | 14.5 / 1.5 |

The two large groups at 3-4% are Lua builds: 1327 Lua functions, 32 of
them free of Lua's own structs.

**Why exact is unreachable.** Exact compares the strings, so it needs the
function's name and every parameter's name. A stripped ELF executable has
neither; a PE keeps export names but never parameter names, so only
parameterless exports can match (`char * cJSON_Version(void)`: revkit
gets those, Ghidra's `longlong`/`undefined8` doesn't). Normalized has the
same problem. Signature drops the names and is what the reference format
says to gate on (docs/reference-format.md, "Comparing prototypes").

**What the remaining signature misses are.** Of the 3481 truth
prototypes, 2557 name a struct, union or enum of the program (or a
function type over one) and can't match without names. Of the 924 left
(basic types, library structs, function types over basic types), revkit
gets 474, Ghidra 165. The misses, in order:
signedness and width of returns with no evidence either way (`uint`
checksums where the decompiler sees `int`; `ulong` results the `int` prior
narrows), the priors' cost (zlib's `uInt` and `Bytef *` become `int` and
`char *`), `void *` parameters a function uses as something more specific,
long doubles, struct returns by hidden pointer, the order of mixed integer
and float parameters on System V (not in the registers), and functions
whose return comes straight from a call (`return g(x)`) with no callers to
read it.

**Development method.** The rules were developed against this corpus's
truth, so the corpus is not an independent test set. The priors are
counted from the glibc headers, not the corpus, and each rule is a
general property of C or an ABI; the table above is what they give on
this corpus, not a held-out estimate.

**Held out.** The gate is now defined on held-out binaries and on the
matchable subset (truth prototypes naming only primitives and libc/OS
types; [heldout.md](heldout.md)). There revkit gets 36.0% against
Ghidra's 18.8% by signature, **+17.2 pp: met** (this corpus's matchable
subset: 50.8% / 17.7%, +33.1 pp). On all held-out functions the gain is
+3.5 pp (7.3% / 3.8%).

## Decompiled C

`tools/rk-infer/c_quality.py` decompiles every stripped binary with every
function's inferred prototype locked (feedback) and without (only the
imports' library prototypes, the decompiler's own view), and compares, per
function with truth:

| arch | signature line | noise tokens / function | similarity to Ghidra's debug-build C |
| --- | --- | --- | --- |
| **all** | 4.7% → 13.3% | 5.73 → 5.21 (−9%) | 0.689 → 0.693 |
| elf-x86_64 | 4.2% → 10.6% | 4.82 → 3.75 (−22%) | 0.693 → 0.693 |
| elf-aarch64 | 4.5% → 12.7% | 7.97 → 8.67 (+9%) | 0.673 → 0.671 |
| elf-riscv64 | 3.9% → 17.8% | 4.34 → 3.31 (−24%) | 0.682 → 0.709 |
| pe-x86_64 | 9.9% → 25.4% | 4.34 → 2.92 (−33%) | 0.752 → 0.760 |

Noise tokens are what the decompiler prints when prototypes are missing or
wrong: `in_*` (a register read that isn't a parameter), `extraout_*` (a
register a call leaves that isn't its return), `unaff_*` and `undefinedN`.
Similarity is the difflib ratio of token sequences with identifiers
renamed, against Ghidra's decompilation of the debug build (which has the
DWARF prototypes). AArch64 gets noisier: its arity gain is smallest
(+0.7 pp), and a locked prototype with a wrong parameter count costs more
than an unlocked one.

**In the backend.** `ImageBackendOptions::infer_prototypes` is `off`,
`automatic` or `on` (`rk-daemon --infer-prototypes auto|on|off`; the
daemon's default is `auto`, the library's `off`). Automatic is rk-lift's
rule (below): programs without debug info where `infer::supports` knows
the convention. An import (and a reopen, and a program arriving from a
peer) stages infer's image input; inference then runs **in the
background**, never during the import: on cmake it takes 400 to 600 s,
and an import that waited for it would be useless that long. The
backend's inference thread (`InferLoop`, one program at a time, on the
import-time analysis threads less one; its decompilations in infer's own
worker processes, not the interactive ones) runs `infer::run` at the head
revision as an analysis job, `infer.prototypes`:

- **Progress**: the job is in `GetAnalysisStatus` (which isn't `idle`
  until it ends) and on subscriptions as `AnalysisProgress`, its phase
  `round k: done/total functions`, at most once a second, each round a
  tenth of the bar (a run usually converges in about ten: cmake took 646 s
  for 10 rounds on 6 threads, at load 10).
- **Cancel**: `CancelAnalysis` with its job id stops it before the next
  function's observation (`infer::RunControl`); the job ends `CANCELLED`
  and nothing is published. What it computed stays memoized, so
  `StartAnalysis` with `infer.prototypes` resumes rather than restarts.
- **Results** are published when the fixpoint is reached, in one revision
  of cause `ANALYSIS` (provenance `analysis:infer.prototypes`): the input
  `infer.published`, one key per function. Decompilations read only that
  (never `infer.prototype`, which would make the first decompilation wait
  for the whole program), so before it arrives a function decompiles as
  without inference, and when it arrives exactly the functions whose
  lookups it changed are redone (as a prototype edit would).
  `GetFunction` shows the prototype with origin `derived:
  infer.prototypes`.
- **Again**: on reopen (published values aren't persisted; the rounds are
  memoized and validate) and after an edit to the program's memory map
  or patches (discovery changes; only what it reaches recomputes).

When the decompiler asks about a function, the backend's `QueryLookup`
(`src/backend/own_inputs.cc`) gives one that nothing asserts a prototype
for and that has no debug-info or library signature the inferred
prototype, converted to a `revkit::types` function type
(`infer/types_bridge.h`) and encoded by the same `inputs::GhidraTypes` path
asserted prototypes take, with signature source `analysis`: in its own
decompilation and at the calls to it. `FactStoreTest.
InferredPrototypesReachTheDecompiler` checks it (waiting for the job): the decompiler alone
shows `uint checksum(byte *param_1,int param_2)`, with inference `uint
checksum(char *param_1,int param_2)`, and the caller passes `(char *)`.
Where the program also gets Ghidra's Decompiler Parameter ID (by default
a PE below 2 MiB; [param-id.md](param-id.md)), the inferred prototype wins
over the analyzer's commit and the commit stands where inference has none:
inference refines what Ghidra's analysis would give, never the reverse,
and the analyzer's own decompilations don't see inference. `rk-infer`
and this gate don't involve the analyzer.
The hook is one commit (`backend: inferred prototypes reach the
decompiler through own inputs`), separate from `src/infer`;
`infer::prototype_for(snapshot, location)` and `ghidra_types.h` serve other
front ends.

### By default in rk-lift

`rk-lift --analyze --decompile` locks inferred prototypes by default (as
does the daemon, in the background, above): for functions with no library prototype, in programs
without debug info, where inference has a convention (`infer::supports`:
the 64-bit ones above). Against the original source this wins in every
tuning family ([decomp-quality.md](decomp-quality.md)). For the
decompiler, an unknown return keeps its register's width
(`Options::keep_return_width`): `finalize`'s prior spells an unknown
8-byte return as `int` (the commonest return that fits), which suits
the exact-signature score but made every caller reading the whole
register see `CONCAT44(extraout_var, x)`. The gate above and `rk-infer`
keep the old spelling.

Known errors that show in the C: callees inferred with a parameter too
many (their callers pass an undefined `in_` value), and a function
returning a callee's float result unknown at round 0 (`luaL_checknumber`)
inferred as returning an integer, so its callers read an `extraout_` or
an unset variable.

## Scale

`/usr/bin/cmake` (11.8 MB, stripped C++), `rk-infer -j 8` on the shared
32-core machine (`--stats` reports each round: wall time, decompilations,
the slowest, the prototypes that changed):

| | before (master 1e1ea40) | after |
| --- | ---: | ---: |
| functions | 19,409 | 19,409 |
| rounds | **16, the cap** (19171, 3410, 915, 312, 165, 27, 11, 14, 14, 6, 4, 6, 9, 10, 3, 1, 0 changed) | **9, converged** (3062, 1098, 118, 58, 14, 3, 1, 0, 0) |
| widened | 56 | 3 |
| decompilations | 45,156 | 31,653 |
| inference, wall | 758-772 s (load 8-15) | 393-608 s (load 12-18, beside other benchmarks) |
| CPU | 4800 s | 1900-2480 s |
| peak RSS | 6.25-6.4 GB | **1.84 GB** |

The final prototypes are the same in every after-run (the order, the
bound, the memory measures change no result), and the tuning corpus
scores exactly as before (13.6% signature, +8.9 pp; every arch the same).

**Diagnosis.** Per-round stats of the old fixpoint on cmake: rounds 5 to
15 changed 3 to 27 prototypes each, and of the 102 functions that changed
there only 3 changed twice. So the tail was **slow propagation, not
oscillation**: each round carried what a callee had learned one call edge
up the call graph (a prototype only joins upward in a finite lattice, so
it can't oscillate; widening caught the functions on long chains that
changed four times). The time went to rounds 0 and 1 (every function
decompiled twice: 106 and 131 s) and to the largest functions, decompiled
again whenever a callee changed, each round waiting for the slowest (15 to
75 s for functions of 100K to 500K varnodes). Memory was SLEIGH engines
(each nested decompilation, one per level of the call graph, leased a
decompiler and a prologue lifter of its own: 1.57 of 1.79 GB live on
bash), memoized observations, and malloc arenas keeping what each round
freed.

**Fixes.** Rounds in call-graph order (above), so chains resolve in one
round; round 1 skips leaves; the varnode bound; callee prototypes read
before a decompiler is leased, so a thread holds one at a time; one
prologue decoder per pool, results cached per function; discovery's
SLEIGH engines freed after discovery; memos past `--memo-budget` (256 MB)
spilled to a scratch LMDB store (`--store`); four malloc arenas, trimmed
between rounds and every 256 observations; at most two large functions
decompiling at once.

**libLLVM (the 100 MB part of the gate): projected, not measured.** One
pass of the decompiler over libLLVM's 119K functions took about 8,400
CPU-seconds (rk-lift, 30 s timeout), and inference on cmake costs about
3.9 passes (2,480 CPU-s against rk-lift's 634); that projects to about
33,000 CPU-seconds, **about 70 minutes on 8 threads** (35 on 16), in about
the same number of rounds (the call graph's depth, not its size, sets
them). Memory: decompiler working sets are bounded as on cmake, memos
spill past 256 MB, and the call graph, order and per-key slots grow with
the function count (cmake's 1.84 GB, about a gigabyte more): **about 3
GB projected**, inside 4 GB. Not measured yet. The function that hangs
inside the decompiler where the varnode bound can't stop it (docs/scale.md,
"Bounded decompilation") no longer stalls a run: inference's
decompilations now run in decompiler workers ([decompd.md](decompd.md)),
under a 30 s timeout (`Options::timeout_seconds`) whose hard deadline
kills the worker, and a crash costs one observation (the function is then
seen from its callers only). `rk-infer` ends with a summary of the
decompilations that failed.

**Workers.** Each observation's bundle holds the image's bytes the
decompiler reads and the `SymbolEnv`'s answers: import slots for the
addresses the body names and functions at its call targets, predicted
from the body; the rest (function pointers, mostly) the worker asks for,
and the parent looks up and reruns only when the answer isn't "nothing".
What the decompiler consulted is what the worker reports it asked, so
rounds' reuse of earlier observations is unchanged. Prototypes and
`--decompile` output are byte-identical to the in-process decompiler's on
Lua and zlib; Lua's inference takes 3.9 s instead of 3.0 s at `-j 4`.

On the corpus (27 binaries, 2 threads each) inference takes 70 to 200 s
in all depending on the load; every binary converges in at most 9 rounds
(the two-unchanged-rounds rule included), nothing widened.

## Pointer accesses

`infer::pointer_accesses` (`accesses.h`) walks a decompiled function's
p-code from one variable, as Ghidra's `FillOutStructureHelper` does, and
`infer::compose_structure` turns what it finds into a structure's fields.
The backend runs the walk in its decompiler workers for every
pointer-sized parameter and local and serves it as the query
`infer.pointer_accesses`; TypeService.AutoStructure builds on it
([types.md](types.md#structures-from-pointer-use)). Inference runs the
same walk in its own observations, for the structures below.

## Structures

A struct pointer typed as a pointer to its first word (`long *`) costs two
casts per field, `*(int *)((long)param_1 + 0x2c)`, where the source has
`p->n`. After the fixpoint (`infer.fixpoint`, version 4), inference
composes a structure per class of pointers that are one value, and types
the class's parameters and returns with a pointer to it
(`InferredStructure` in `FixpointResult::structures`; `structures.cc`):

- **What it reads.** Each observation (`infer.observe`, version 6) keeps,
  per pointer-sized parameter and per pointer-sized call result, the
  accesses through it (`Observation::pointer_uses`, `results`: offset,
  size, kind; calls it is passed to), through each value loaded through it
  (one level: `param_1->field_0x18->...`), whether it is returned
  unchanged, and the offsets whose loaded value flows back into it (`p =
  p->next`). The last round's observations are read, so callees are
  locked to their final prototypes.
- **Classes.** Nodes are those values; union-find joins a parameter passed
  on unchanged with the callee's (the `Slot::from_param` edges), what a
  function returns unchanged with its return, a call's result with its
  callee's return, a result or a field passed on with the callee's
  parameter, and a self-pointing field with its variable. Joining two
  classes joins their fields offset by offset (one field, one type), so
  `L->l_G` read in 88 functions is one class, global_State (`astruct_53`, 0x588 bytes, in x86-64 gcc -O2 Lua).
- **Conservative joins.** An edge into a callee's node joins at once when
  the callee itself reads or writes through it (three or more accesses);
  a callee that only passes the pointer on, an allocator returning fresh
  memory, or a `void *` sink joins only when every value reaching it is
  of one class, else it is *generic* and keeps its own type (Lua's
  `luaM_malloc_`, a free wrapper). Two classes whose accesses contradict
  (a pointer field read as a float or a narrower integer, or accessed
  inside, at two offsets or more, or in a quarter of the smaller one's
  accesses) aren't joined: each keeps its own structure.
- **Which classes.** Two or more distinct offsets and three or more
  accesses, mixed in size or kind. One scalar at its stride is an array
  (`int *`, `char **`: left as it is); bytes read one by one in runs of
  eight or more are a buffer (an unrolled checksum); a pointer passed to a
  library function's `char *` parameter is a string; a pointer something
  else typed (a library struct like `_IO_FILE *`, a function, a callback's
  prototype such as main's `char **argv`) is never replaced, and inference
  only fills prototypes nothing else gives (debug info, the library
  archives and the user's prototypes rank above it).
- **Arrays of structures.** Accesses that repeat at one stride (every
  remainder one size, no overlaps) with negative offsets (a pointer to a
  stack's top, `top[-1]`) or every element alike are an array of one
  element structure, sized by the stride: Lua's TValue stack is
  `astruct_4 *`, 16 bytes, and `L->top + n` needs no cast.
- **Fields** are composed (`compose_structure`, its `keep_wide` mode: a
  wide field stays whole where splitting it at narrower accesses inside
  costs more, so a union's `int` isn't assembled from bytes) from every
  access of every member, as pointers (to the structure of the class the
  field's value belongs to, else to the element of its array, else
  `char *`), floats, integers (the priors' spelling where the sign is
  unknown) or `undefinedN`; the size is the furthest access (up to 64 KiB)
  rounded up to the fields' alignment.
- **Names** are `astruct_<n>`, numbered by each class's first member
  (entry, then position); deterministic for any thread schedule.

On the tuning corpus the 27 stripped binaries get 1 to 65 structures
each; against the debug build's prototypes, 469 of the 473 parameters of
x86-64 gcc -O2 Lua's largest class are `lua_State *` (the others
`GCObject *` and `TString *`, which start like it), and the structure's
size is lua_State's, 200 bytes; the next classes are FuncState (53 of
54), expdesc and LexState (all 37). `rk-infer` writes them under `"structures"` (`--no-structures`
without); `rk-lift --analyze --decompile` gives them to the decompiler
(`--no-infer-structures` without), and the daemon publishes them as the
program's types ([below](#in-the-daemon)). On `/usr/bin/cmake` (19,409
functions) the pass adds nothing measurable: 368 s wall, 1.65 GB peak
(398 s and 1.62 GB without; 4,318 structures).

### In the daemon

The published prototypes (`infer.published`) name the structures; the
same revision asserts each structure's TYPE_DEF records, binds `struct
astruct_<n>` to it and files it under `/inferred`, with the analysis's
provenance (`analysis:infer.prototypes`), so they show among the
program's types (FindTypes: origin the analysis) and the user renames,
edits or reverts them like any type: the decompiler resolves each name
through the program's binding (`types.resolved`), so an edit of the
structure (a field renamed) reaches every function pointing to it, and a
structure whose assertions are retracted leaves its parameters pointing
to undefined bytes. A name someone else binds (Auto Structure's
`astruct_<n>`, the user's) moves the structure to the next free number; a
binding of inference's the user retracted isn't asserted again
(`FactStoreTest.InferredStructuresArePublishedAsProgramTypes`). As
program types they are exported with the rest (a type archive of scope
`all`), and Auto Structure's next name skips theirs.

## Known gaps

- **Exact names** can't be recovered (above). An inferred structure is
  named `astruct_<n>`, so a signature naming the program's struct can't
  match.
- **Structures** ([above](#structures)): classes of one type that never
  pass a value to each other stay apart (Lua's expdesc is five), so calls
  between them cast; locals that are neither a parameter nor a call's
  result aren't classed; one level of fields per observation; unions and
  embedded structures are overlapping fields; 32-bit targets get none
  (inference is off there). `rk-infer --decompile` (`c_quality.py`) shows
  them as incomplete structs: its decompiler isn't given their layouts.
- **Signedness and width of returns** without callers or decisive uses
  fall back to priors (`int`), so 64-bit results (`size_t`, `long`) and
  `uint` checksums are often wrong; integer *rank* on LLP64 (`long` vs
  `int`, both 4 bytes) isn't modelled.
- **Parameter order** on System V when integers and floats mix is not in
  the registers; integers come first.
- **Invalidation.** Every `infer.round` reads its neighbours' previous
  round, and `infer.prototype` reads the whole-program fixpoint, so in the
  backend any edit that moves one prototype revalidates all decompilations
  (memos validate by fingerprint, but a changed prototype recomputes every
  decompilation). A per-function projection of the fixpoint, and rounds
  started from the previous revision's result, would narrow both.
- **Pointers to opaque structs stay size 0.** A locked prototype's pointer
  to a struct known only by name (`_IO_FILE *`) points at an incomplete,
  zero-size struct, the decompiler's own form for a forward declaration.
  It made the decompiler's store splitting divide by zero
  (`SplitDatatype::buildPointers`, SIGFPE on held-out MuJS x86-64 gcc-O2);
  the decompiler fork's patch 0003 now fails that function cleanly
  ([third_party/ghidra/UPSTREAM.md](../third_party/ghidra/UPSTREAM.md)).
  `decompiler_safe` rejects genuinely degenerate types (zero-size
  non-aggregates, arrays of none or of zero-size elements) before they are
  locked, which inference doesn't produce today. Giving opaque structs a
  size instead (undefined bytes, or Ghidra's size-1 encoding) moves the
  tuning corpus's signature score (-0.1 to -0.4 pp on some arches) and,
  for size 1, made results vary from run to run, so it waits for the
  held-out accuracy work.
- **Rounds in call-graph order serialize along chains.** Round 1 (every
  non-leaf function, with its callees' prototypes of the same round) is
  the longest: a function waits for its callees ranked below it, so the
  8 threads aren't all busy (cmake: 166 s for 871 CPU-s).
- **Discovery.** Functions only code pointers in instructions reach (a
  callback loaded with `lea` and passed) are still not functions; tables
  in data are followed here, which `src/analysis` could adopt as seeds.
- **Languages.** Calling-convention tables exist for x86-64 (System V,
  Windows), AArch64 and RISC-V 64; other languages get the decompiler's
  own view only. 32-bit targets are untested.
- **Library databases** are glibc (also used for the AArch64 and RISC-V
  ELF builds, whose `char` signedness and `va_list` differ, neither of
  which the printed types show) and mingw-w64; no C++ standard library.
