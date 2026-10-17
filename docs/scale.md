# Scale: large real binaries

The design's scale gates:

- a **100 MB binary must fit a 4 GB memory budget**;
- **cold start to the first decompiled function must take under 2 s** on a
  10 MB binary.

**Results** (details below; the second round, `phase4/scale2`, in
[Round 2](#round-2-first-decompile-bounded-decompilation-inference)):

- **First decompile under 2 s on 10 MB: passes.** On cmake (11.8 MB file,
  9.5 MB of code) `main` arrives decompiled **1.13 to 1.22 s** after
  launching `rk-daemon` (three runs at load 3.5 to 4), against 2.11 to
  2.23 s before round 2 under the same conditions and 7.8 to 8.4 s before
  round 1. `scripts/scale-check.sh` checks it in CI. Data analysis and
  later work had brought it to about 2.2-2.5 s at the load this machine now
  carries (10-15 on 32 threads); [round 4](#round-4-cold-start-regression)
  takes it to **1.45 s on a quiet machine** (load 2; master 1.64 s, the
  round-3 tree 1.28 s at the same moments) and 1.7-2.1 s at load 13-15.
- **100 MB in 4 GB: passes**, whole-program decompilation included since
  round 3 ([decompiler workers](#round-3-decompiler-workers)): libLLVM's
  127,008 functions decompile in 33 minutes at a peak of 3.99 GiB for
  `rk-lift` and its 8 workers together; the functions that hang inside the
  decompiler are killed at their deadline and reported as timeouts. libLLVM (144 MB file, 63 MB of
  code, 15.3M instructions) peaks at 1.0 GB for `rk-lift`, 2.9 GB for
  `rk-lift --analyze`, and 3.72 GiB for the daemon's import and first
  decompile (3.92 GiB before round 2). `rk-lift --analyze --decompile -j 8`
  on libLLVM: see [Round 2](#bounded-decompilation). Chrome (293 MB, 227 MB
  of code) passes for `rk-lift` (0.9 GB) but not for discovery (4.1 GB) or
  the daemon (5.1 GB); round 2 didn't remeasure it.

## The benchmark set

`corpus/large/manifest.json` lists the binaries by path and sha256; they are
files of this host's packages and are not committed.

| id | file | code (.text) | format | source |
| --- | ---: | ---: | --- | --- |
| bash | 1.4 MB | 0.97 MB | ELF x86-64 PIE | Ubuntu 24.04 `bash` |
| libstdc++-aarch64 | 3.3 MB | 1.7 MB | ELF AArch64 .so | `libstdc++6-arm64-cross` |
| libstdc++-mingw | 26.8 MB | 1.3 MB | PE32+ DLL (with DWARF) | `gcc-mingw-w64-x86-64-win32-runtime` |
| cmake | 11.8 MB | 9.5 MB | ELF x86-64 PIE, stripped | `cmake` 3.28 |
| libclang-cpp | 64.8 MB | 41.6 MB | ELF x86-64 .so, stripped | `libclang-cpp18` |
| libLLVM | 143.5 MB | 63.0 MB | ELF x86-64 .so, stripped | `libllvm20` |
| chrome | 293.2 MB | 227.3 MB | ELF x86-64 PIE, stripped | `google-chrome-stable` 153 |

## Reproducing

```sh
cmake --build --preset default
scripts/bench-large.sh                                  # everything: rk-lift x3 and the daemon, every binary
scripts/bench-large.sh --only cmake --stages daemon     # one cell
scripts/bench-large.sh --rk-lift old/rk-lift --mem-cap 12000 --out build/bench-before   # a baseline, capped
scripts/bench-large.sh --report --out build/bench-large # Markdown table
scripts/bench-coldstart.py /usr/bin/cmake --function FUN_001f2130   # one cold start, through the SDK
build/tools/rk-backend-bench/rk-backend-bench /usr/bin/cmake --cold-start FUN_001f2130   # the same in process
```

`bench-large.sh` records wall time, peak RSS, CPU time and utilisation
(`/usr/bin/time`), the 1-minute load average, and rk-lift's `--stats` (phase
times, instruction count, slowest decompiled functions) as JSON lines.
`--mem-cap` runs each stage in a systemd user scope with that memory limit
and no swap: the old rk-lift needs ~23 GB on cmake, and on a shared
31 GB machine it is better killed at 12 GB (exit 137) than allowed to push
everyone into swap. The daemon stage launches `rk-daemon` and drives it
through the Python SDK (`scripts/bench-coldstart.py`): import, the first
100-row listing page, the first page of functions, then one decompile
(`main` if a function has that name, else the entry point's function).

## Machine and method

Intel i9-14900F (8 performance + 16 efficiency cores, 32 threads), 31 GB,
RelWithDebInfo build. The machine was shared with other agents' builds and
test runs throughout: the load average column is what `/proc/loadavg` said
when each stage finished, and wall times under load 10 to 50 are worth
little to more than one digit. CPU seconds and peak RSS are much less
sensitive to load. Each cell is one run; earlier repeated runs of the
cold start and of cmake discovery agree with these within the noise noted.
`-j 8` throughout.

"Before" is rk-lift at e187142 (master when this work started) and the
daemon at c1e1af6 (master after function discovery started driving the
daemon, the import path this work then optimised). "After" is this branch
before merging master's own decompiler inputs (e0eb2ae); the cold-start
gate and libLLVM's daemon were measured again after that merge (rows
marked so), since it changed the decompile path.

## Results

### rk-lift

| binary | stage | before: wall / peak RSS | after: wall / peak RSS / CPU | notes |
| --- | --- | ---: | ---: | --- |
| bash | plain | 2.8 s / 1.7 GB | 1.1 s / 97 MB / 1.8 s | 239K instructions |
| bash | `--analyze` | 3.4 s / 2.0 GB | 1.3 s / 185 MB / 2.0 s | |
| bash | `--analyze --decompile` | 24.8 s / 2.5 GB | 19.3 s / 0.8 GB / 134 s | 2578 functions; slowest 15.9 s |
| libstdc++-aarch64 | plain | 3.6 s / 2.4 GB | 1.1 s / 149 MB / 3.1 s | 412K instructions |
| libstdc++-aarch64 | `--analyze` | 9.6 s / 2.7 GB | 1.9 s / 279 MB / 5.0 s | |
| libstdc++-mingw | plain | 5.1 s / 2.5 GB | 1.3 s / 169 MB / 2.7 s | 321K instructions |
| libstdc++-mingw | `--analyze` | 8.3 s / 2.8 GB | 2.3 s / 258 MB / 4.0 s | |
| cmake | plain | killed at 12 GB (needs ~23 GB) | 2.2 s / 396 MB / 10.5 s | 2.13M instructions, 816 MB of JSON |
| cmake | `--analyze` | killed at 12 GB | 4.2 s / 677 MB / 17.8 s | discovery 1.8 s |
| cmake | `--analyze --decompile` | 76.5 s / 5.6 GB at -j 16 (streaming only) | 123.6 s / 3.8 GB / 953 s (load 16) | 19409 functions; slowest 65.6 s |
| libclang-cpp | plain | killed at 12 GB | 10.1 s / 830 MB / 52.5 s | 10.6M instructions |
| libclang-cpp | `--analyze` | killed at 12 GB | 21.9 s / 2.1 GB / 114 s | discovery 12.2 s |
| libLLVM | plain | killed at 12 GB | 18.0 s / 1.0 GB / 98.6 s | 15.3M instructions |
| libLLVM | `--analyze` | killed at 12 GB | 51.6 s / 2.8 GB / 258 s | discovery 27.5 s |
| libLLVM | `--analyze --decompile` | | killed at the 16 GB cap after 1217 s (9524 CPU-s, load 39) | |
| chrome | plain | | 10.7 s / 891 MB / 28.9 s | 31K functions from symbols and unwind data |
| chrome | `--analyze` | | 361 s / 4.1 GB / 1050 s (load 55) | 169K functions, 18.0M instructions; discovery 312 s |

The plain and `--analyze` outputs are byte-identical before and after on the
whole 54-binary corpus, on bash, and (for discovery) on cmake and
libclang-cpp; the corpus CI gates check it on every run.

### Daemon cold start (rk-daemon + Python SDK)

Seconds from launching `rk-daemon`; peak RSS is the daemon's.

| binary | before: import / first decompile / peak | after: import / first decompile / peak | decompiled | load |
| --- | ---: | ---: | --- | ---: |
| bash | 5.1 / 9.1 s / 254 MB | 1.4 / 3.7 s / 246 MB | `main` (2.3 s itself) | 11 |
| libstdc++-aarch64 | 1.6 / 1.7 s / 664 MB | 1.1 / 1.2 s / 677 MB | `_DT_INIT` | 7 |
| libstdc++-mingw | 3.4 / 3.5 s / 826 MB | 2.3 / 2.4 s / 814 MB | `DllMainCRTStartup` | 7 |
| **cmake** | **7.8 / 8.0 s / 1.0 GB** | **2.18 / 2.26 s / 923 MB** | entry (77 ms) | 11 |
| libclang-cpp | 47.1 / 47.5 s / 3.5 GB | 16.2 / 16.5 s / 2.9 GB | `_DT_INIT` | 8 |
| **libLLVM** | **86.0 / 86.4 s / 4.6 GB** | **49.4 / 50.6 s / 3.7 GB** | `_DT_INIT` | 21 |
| libLLVM, after merging own-decomp | | 32.8 / 34.3 s / 3.92 GiB | `_DT_INIT` (1.26 s: `inputs.program` for the whole program) | 9.5 |
| **cmake, after merging own-decomp** | | **1.98-2.01 / 2.10-2.12 s / 0.9 GB** | `main` (`FUN_001f2130`, 107-115 ms), 3 runs | 7.5-8 |
| chrome | | 544 / 546 s / 5.1 GB | `_start` | 7 |

The first listing page and the first page of functions arrive within 1 ms
of the import: the import computes the listing.

## What changed

**rk-lift streams its output.** It used to keep every lifted instruction in
a map and then build the whole reference document as a JSON tree: about
10 KB per instruction, 23 GB for cmake. Now a first pass walks the function
bodies with `Lifter::measure` (instruction lengths only, with the same
context effects as a full decode) into a byte-per-address index, and a
second pass lifts in address order and appends each instruction's compact
line to a buffered `DocumentWriter` that writes the canonical layout of
`refformat.py dumps()` key by key. With `-j`, both passes run on several
SLEIGH engines: slices of the function list for the first (merged in order,
which finds the same instructions because a decode depends only on its
address once nothing changes the context), batches of addresses for the
second, written in order. Languages whose instructions change the context
(`globalset`, e.g. ARM Thumb switches) fall back to one ordered walk. The
smoke test checks that the output equals `refformat.dumps()` of itself and
is identical with three engines.

**Decoding without display text.** Discovery and the daemon's reference
extraction only need lengths and p-code, but every decode printed the
instruction and walked its operands for typed tokens: about a third of the
cost. `Lifter::lift_pcode` skips that; the backend decodes text again only
for instructions that have a reference, to tell which operand it is in.
SLEIGH engines also build in parallel now (the `.sla` decode, most of the
50 ms, runs outside Ghidra's global lock, as `ImageArchitecture` already
did).

**Discovery's fixpoint.** `infer_no_return` re-walked every function on
every iteration; now only walks that reached a call to a function just found
never to return are redone (a walk reads the no-return set only there).
Walks mark visited instructions by index in the flow graph instead of
hashing addresses; ownership of shared code is one sorted 16-byte-per-
instruction vector instead of a hash map, and walks are freed as soon as it
is built. Thunk checks for every entry, which the fixpoint asked for one at
a time, are computed on the thread pool first. Jump-table probing copied the
whole p-code evaluator, node-based maps and history vectors included, for
every probed index; the evaluator's maps are sorted vectors now, and probes
fork only the state they need (Chrome had single flows taking 100 s).
Results are identical; cmake's discovery went from 8.6 to 4.7 s on one
thread and from 3.8 to 1.6-2.3 s at `-j 8`.

**Memory held by an import.** A memo's dependency list is shrunk to fit;
an in-memory project's store no longer copies the file's pages into a
private storage nothing can read back; the import drops its whole-file
string copy once the bytes are staged.

**rk-lift --analyze --decompile** now passes discovery's no-return flags to
the decompiler. Without them the decompiler followed flow past calls to
`exit()` into the next function: wrong output, and on bash half the
decompile time (135 to 71 CPU-s) and RSS (2.5 to 0.96 GB at `-j 8`).

**Own decompiler inputs** (merged from master late): assembling a
program's inputs asked, for every symbol and data pointer, whether any
function's body contains the address by scanning every function; it is an
index now. That took cmake's first decompile in the daemon from 600 ms to
110 ms. On libLLVM, building `inputs.program` for the whole program still
makes the first decompile cost 1.3 s.

**Smaller things.** `ThreadPool` no longer lets a worker destroy the
exception the caller is rethrowing (a TSan report that failed CI now and
then). `scripts/scale-check.sh`, run by `ci.sh`, fails if rk-lift on bash
exceeds 150 MB or `--analyze` 400 MB (39 and 130 MB now).

## Round 2: first decompile, bounded decompilation, inference

`phase4/scale2`. "Before" is master at 1e1ea40 (round 1 merged); both
sides measured on the same machine in alternating runs, with the load
average given (the machine was shared with other agents throughout,
often at load 15 to 20).

### First decompile

| cmake, `rk-daemon` + Python SDK | before | after |
| --- | ---: | ---: |
| import returned | 2.00-2.12 s | 1.10-1.19 s |
| first listing page | 2.00-2.12 s | 1.10-1.19 s |
| `main` decompiled | **2.11-2.23 s** | **1.13-1.22 s** |
| the decompile itself | 108-117 ms | 20-28 ms |
| daemon CPU | 7.6-8.5 s | 5.4-6.2 s |
| peak RSS | 869-911 MB | 819-856 MB |

(three runs each, load 3 to 8). In process (`rk-backend-bench --cold-start`,
`REVKIT_TIMING=1` for the phases), at load 9:

| phase | before | after |
| --- | ---: | ---: |
| decode the seeds' flows (8 threads) | 0.5-0.9 s | 0.5-0.9 s |
| discovery's fixpoint | 0.73-1.2 s | 0.16-0.30 s |
| references | 0.5-1.1 s | 0.02-0.06 s |
| rows; decompiler inputs and instance | 0.14-0.27 s; at the first decompile | 0.1-0.14 s, side by side |
| first decompile | 0.11 s | 0.02 s |

What changed, in that order of effect:

- **Discovery's fixpoint runs on the analysis pool.** Walks for no-return
  inference, the sorts of decoded instructions (to reject call targets
  inside instructions, and for ownership) and the bodies were one thread;
  now they are split over the engine's pool (`QueryContext::parallel_for`),
  and each round's new entries are decoded in parallel
  (`QueryContext::get_all`, which records the keys as dependencies in key
  order, so memos don't depend on the schedule). Results are identical
  (rk-lift `--analyze` byte for byte on bash, cmake, libclang-cpp).
- **References come from discovery's decode.** `xrefs.function` decoded
  every instruction again for its p-code, and the display text of every
  instruction with a reference to place it in an operand. `analysis.flow`
  now records each instruction's references as it decodes
  (`FlowGraph::refs`, with `ProgramInfo::references`), and the operand is
  decoded when `GetXrefs` serves a reference. Every reference and operand
  is identical on bash, cmake, libstdc++ (AArch64, PE) and RISC-V corpus
  binaries.
- **The import prepares the first decompilation.** Beside the listing's
  rows it computes the decompiler's program inputs and builds a decompiler
  instance (`DecompilerPool::Warm`).

**Why not a decompile before analysis finishes.** A first decompile served
before whole-program discovery would be a provisional value: the
decompiler's output depends on whole-program facts (callees' no-return
flags, which come from the fixpoint; bodies cut at entries other
functions' calls discover; labels from other functions' references), so it
would differ from the revision's real answer, and the fact store's
invariant that every served value is the pure function of a revision
would need an exception plus a new invalidation path for every client.
Making the analysis cheaper keeps every answer exact and also speeds up
`rk-lift --analyze`, large imports (libLLVM 32.8 to 17-26 s) and edits
that steer discovery; at about 1.2 s the cold start has 0.8 s of margin.
The import also still returns only once the listing is ready, so a client
that asks for the listing first waits no longer than before.

**CI.** `scripts/scale-check.sh` (run by `ci.sh`) decompiles cmake's `main`
with `rk-backend-bench --cold-start` up to three times and fails above
2 s, unless the load average is over half the cores (then it reports
without judging: on a saturated shared machine the number says nothing).
Since round 4 it judges CPU time at any load and wall time only on a quiet
machine ([the gate](#the-gate)).

### The decompiler's inputs: a function-list change

`inputs.program` was one assembly over the image and discovery's
functions. It is split (identical output: `rk-lift --dump-inputs` byte for
byte on ELF x86-64, AArch64, RISC-V and PE, with and without DWARF/PDB):

- `inputs.static`: what the image alone decides (memory with the
  EXTERNAL and thread blocks, relocation patches, EXTERNAL functions and
  data, PE imports, the loader's symbols, relocated pointer slots'
  values). A change to the function list doesn't recompute it, and
  `inputs.image` reads only it, so decompiler instances survive the change.
- `inputs.program`: the function-dependent part laid over it, without the
  relocated pointer slots (800K on libLLVM, the largest part left), which
  `inputs.address` now makes for the address it is asked about.

| libLLVM, remove one function (`rk-backend-bench --cold-start --edit-functions`) | before | after |
| --- | ---: | ---: |
| program inputs rebuilt | 683 ms (static 128 + 556) | 190-230 ms |
| the next decompilation | 1.34 s | 0.60-0.69 s |

The commit of such an edit still takes 18 to 22 s on libLLVM: it
recomputes discovery, every function's references and the listing to
diff them for subscribers (`DiscoveryEffects`), on one thread, and about
40% of it is the in-memory project evicting memos over its 2 GB budget
into an in-memory store and reading them back. Not addressed here.

### Bounded decompilation

**Timeouts and cancellation.** `lift::DecompileBudget` adds a check to
every rule pool and action group of the decompiler's root action (and of
the jump-table recovery action), without changing the decompiler; the
check throws once a run is past its deadline, past a varnode bound (a
deterministic stand-in for memory: about 700-760 bytes of resident memory
per varnode at a function's peak on cmake's largest), or cancelled. The
run's `DecompileResult::stopped` says which, and the instance, left
mid-analysis, is rebuilt.

- `rk-daemon`: `--decompile-timeout` (default 30 s, Ghidra's), which a
  request's `DecompileOptions.timeout_ms` replaces and its deadline
  shortens; `--decompile-max-varnodes` (default 1M); a client that goes
  away cancels its decompilation. A stopped run fails the request with
  `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED` or `CANCELLED` (the API's
  documented codes) and is never cached.
- `rk-lift`: `--timeout` (default 30 s; 0 for none), `--max-varnodes`
  (default: a quarter of the memory budget), `--memory-budget` (default
  4096 MB).

**The scheduler.** Largest first, but a function starts only while the
estimated working sets of the runs in flight fit beside the process's
baseline (an estimate from the body's size, up to 24 varnodes per byte,
capped at the varnode bound); the smallest functions fill in, and measured
RSS over the budget admits only tiny functions and rebuilds instances now
and then. Instances share one index over the inputs and one copy of the
relocation patches (8 instances on libLLVM: 1.6 GB to 0.45 GB), cap their
caches, and refresh their kept types every 1024 functions; rk-lift drops
discovery's memos past 512 MB once discovery is done, assembles each
function's inputs holding only its flow, spills the C text to a scratch
file, and limits malloc to four arenas.

**libLLVM, `rk-lift --analyze --decompile --no-instructions -j 8
--memory-budget 3584`** (load about 12, beside other agents' jobs):

| | before | after |
| --- | ---: | ---: |
| outcome | killed at the 16 GB cap after 20 min | 119,342 of 119,343 functions in 33 min; the last never ends (below) |
| setup (discovery, inputs, 8 instances) | | 1.74 GB before the instances, 2.2 GB after (1.6 GB of instances before sharing) |
| RSS, sampled at each function's end | > 16 GB | 2.0-3.0 GB for most of the run; 4.2 GB at the highest before function 103,806; 4.4-5.1 GB after it |
| stopped runs | | 22 (timeouts at 30 s, and the varnode bound) |

**Gate: not met in process.** Two things the cooperative bounds can't
handle, both from inside Ghidra's decompiler:

1. **A hang no check reaches.** Function `0x34998c0` spends its time in a
   single application of `ActionDeadCode` during jump-table recovery, in
   `Varnode::eraseDescend` (quadratic in a descendant list); checks run
   between actions and rule applications, so the 30 s timeout never fires
   (40 CPU-minutes when the run was stopped). Held-out MuJS has the same
   kind of hang (docs/heldout.md).
2. **Memory a stopped run leaves behind.** After `0x101b950` was stopped
   at about 990K varnodes, RSS stayed about 1.5 GB higher for the rest of
   the run, with the instance rebuilt and malloc trimmed (the process's
   main heap, 3.1 GB of it, doesn't shrink). Other stopped runs of up to
   2.1M varnodes left nothing; which state of the decompiler the stop
   interrupts seems to decide it.

Both need what the next step brings: the decompiler in worker processes
(SIGKILL on a hard deadline, rlimits, a worker's memory returned when it
exits), with these bounds as the graceful path and this scheduler as the
policy. cmake decompiles completely within its budget (`-j 4`, varnode
bound 20K, 10 s timeout: RSS flat at 1.19 GB from the 8,000th function to
the last of 19,409).

### Inference

See [infer.md](infer.md#scale): cmake converges in 9 rounds (it was capped
at 16), in about 6 to 10 minutes on 8 threads (the measured 393 to 608 s
were at load 12 to 18), peak 1.84 GB (6.25 GB before).

## Round 3: decompiler workers

`phase4/workers`: the decompiler runs in worker processes, from
self-contained bundles ([decompd.md](decompd.md)). Measured against
master (the in-process decompiler) on the same machine, shared with other
agents' jobs (load noted).

### First decompile

cmake's `main` from launching `rk-daemon` (`rk-backend-bench --cold-start`,
three runs, load 2 to 5): **1.09 to 1.16 s** against 1.09 to 1.12 s in
process. The decompilation itself takes 12 ms against 19 ms: 2.2 ms to
assemble the 62 KB bundle (prediction 0.4 ms), 8.7 ms in the worker,
0.3 ms of IPC. The import warms a worker and the prediction engine beside
the listing, so the first decompilation pays for neither
(`REVKIT_TIMING=1` prints the split).

### Overhead per function

| | cmake's `main` | libLLVM, whole program (per function) |
| --- | ---: | ---: |
| assembling the bundle (parent CPU) | 2.2 ms | 2.1 ms |
| IPC (round trip minus the worker's run) | 0.3 ms | 0.29 ms |
| bundle size | 62 KB | 22.6 KB on average |
| functions whose first bundle missed something | | 18.5% |
| rerun because a missed answer mattered | | 5.5% |
| still missing answers after 8 runs | | 6 of 127,008 |

On the tuning corpus under Ghidra's inputs, Lua (the slowest binary)
takes 3.4 s against 2.6 s in process: 4 of its 872 functions rerun, the
worker's decompile time is the same, and the rest is assembling bundles
and IPC.

### libLLVM, whole program

`rk-lift --analyze --decompile --no-instructions -j 8 --memory-budget
4096` (load 5 to 15, part of the time beside other agents' jobs), parent
and workers' memory sampled every 0.5 s (`scripts/tree-memory.py`, PSS):

| | round 2 (in process) | round 3 (workers) |
| --- | ---: | ---: |
| outcome | 119,342 of 119,343 functions in 33 min, then one never ends | **127,008 functions in 32.6 min** (1957 s wall, 8,786 CPU-s), and the run ends |
| peak memory | 4.4-5.1 GB (parent; after one stopped run 1.5 GB stayed) | **3.99 GiB, parent and workers** (parent 1.77, workers 2.21) |
| failures | | 34: 31 timeouts (20 of them killed at the 39.5 s hard deadline, inside one decompiler step), 3 over the varnode bound |
| other | | 60 workers started, 40 recycled; 5 runs evicted for memory and run again alone |

(Discovery finds 127,008 functions now, against 119,343 in round 2;
`master` gained them meanwhile.) Which functions time out moves by a few
at the margin with the load (29 to 31 over three runs). The memory needed
the guard: with the scheduler alone, which counts a worker's memory when
its run ends, the same run peaked at 5.16 GiB with 8 large functions in
flight; the guard (every 100 ms, the parent's and every worker's memory;
over 95% of the budget, the busy worker holding the most is killed and its
function run again alone, with the same bundle) keeps it under the budget
at the cost of 5 repeated runs.

## Round 4: cold start regression

`phase8/coldstart`. The scale gate had failed every CI run since data
analysis landed: 2.1-2.4 s at load 6-15. Every number below is
`rk-backend-bench /usr/bin/cmake --cold-start FUN_001f2130` (RelWithDebInfo,
`build/`, as the gate), with the builds measured **interleaved**, one run
of each in turn, and medians; the load was 9-18 throughout (another user's
model training holds about 10 on its own, plus other agents' builds), so
only same-moment comparisons mean anything. CPU is the process's user and
system time when the decompilation arrives (`/proc/<pid>/stat`; now also
printed by `rk-backend-bench` and the gate as "ms CPU"). It moves with load
much less than wall time, but still by 20-40% between load 9 and 18 (SMT
siblings and efficiency cores): it shows work added, not latency.

### Where it grew

Master's merges since round 3 (6 runs each, load 9.3-9.7):

| tree | wall | CPU | flows | rows, decompiler inputs | decompile |
| --- | ---: | ---: | ---: | ---: | ---: |
| a83a00a (round 3 merged) | 1.75 s | 8.9 s | 909 ms | 97 ms | 17 ms |
| eae9a4a (data analysis merged) | 2.09 s | 11.4 s | 1165 ms | 298 ms | 16 ms |
| bdc1fa5, f8f5a62, 0e69147 (paramid ... import progress) | 2.14-2.19 s | 10.9-11.4 s | 1122-1169 ms | 291-324 ms | 15-21 ms |
| 358201a (firmware parity) | 2.32 s | 11.9 s | 1221 ms | 329 ms | 55 ms |
| 3c98bd3 (processors, patching, C parser) | 2.38 s | 12.3 s | 1223 ms | 344 ms | 55 ms |

Inside the data analysis branch (6 runs each, load 11.8): its first
commit (78f1bf5) added 0.9 s of data analysis to the decompiler's inputs;
26131ea moved the data references into `analysis.flow`'s own decode (flows
+250 ms, inputs back to 235 ms); ea3a4f8 added Ghidra's no-return evidence
(`analysis.no_return_evidence`, one thread over every call site). The
merges between it and the firmware work changed nothing measurable (five
more trees, 5 runs each at load 7). The firmware parity work (9592a36)
gave the stack analysis its own SLEIGH engine (`Program::walk_lifter`),
built by the first decompilation: 35-50 ms of it.

So most of the growth is real work for real results (data analysis is
what took own-input C from 57% to 76% on the held-out set), and the rest
is serial: what waited on one thread while seven idled.

### What the import did serially

A timeline of one import (load 3-11) showed, besides the parallel decode:

- discovery's SLEIGH engines torn down one after another before the import
  returned: 13 engines, 130-150 ms;
- the no-return evidence on one thread, 110-170 ms, the longest chain of
  the import's tail (data analysis then the rows took 110-130 + 80-110 ms
  beside it);
- each analysis thread building two engines at the start of the decode
  (one for the flow, one for the `analysis.jump_stub` it asks for inside
  it), 35-65 ms each, and two more built one after the other by the load
  (the program's own, and `describe()`'s for the language's spaces);
- the walk lifter built by the first decompilation (35-50 ms).

### Changes

All keep every result identical: `rk-lift --analyze` output byte for byte
(bash, cmake, cJSON and features as ELF, AArch64 and PE, two Cortex-M, a
MIPS and a PowerPC raw image, a stripped Cortex-M ELF), the decompiled C of
cmake's `main` through rk-lift and through the daemon (with 11 more
functions of cmake and bash).

- The idle engines are torn down in parallel, beside the import's tail
  (`release_idle_decoders(pool)`).
- A decoder made while another for the same engine is alive on the same
  thread shares its engine (`detail::Decoder`): window decodes depend on
  nothing but their bytes, and the outer one is suspended meanwhile. 8
  engines instead of 13.
- Those engines are built on the analysis pool while the import parses the
  debug info, describes and stores the program
  (`analysis::prepare_decoders`, `Program::Options::discovery_pool`), and
  `describe()`'s language facts beside the program's load
  (`analysis::prepare_language`).
- The import's tail warms the walk lifter beside the decompiler instance.
- The no-return evidence remembers each call site's verdict (the second
  pass asked again) and walks a flow by index; `ByteReader` remembers the
  page it read last; the data references keep register values in a sorted
  vector (copied at every branch), visit with a hash set, find an
  instruction once, and skip the second operand when the first is unknown.

### After (cmake, interleaved, medians)

| tree | load | wall | CPU | flows | rows, decompiler inputs | decompile |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| a83a00a (round 3) | 15.1 | 1.90 s | 10.0 s | 1031 ms | 109 ms | 17 ms |
| 0ee1a1e (master) | 15.1 | 2.47 s | 12.8 s | 1343 ms | 315 ms | 56 ms |
| this branch | 15.1 | 2.08 s | 12.8 s | 1145 ms | 302 ms | 17 ms |
| 0ee1a1e (master) | 12.9 | 2.18 s | 11.4 s | 1167 ms | 274 ms | 50 ms |
| this branch | 12.8 | 1.74 s | 10.9 s | 979 ms | 223 ms | 14 ms |
| a83a00a (round 3) | 2.3 | 1.28 s | 6.5 s | 658 ms | 64 ms | 13 ms |
| 0ee1a1e (master) | 2.3 | 1.64 s | 8.2 s | 826 ms | 224 ms | 45 ms |
| this branch | 2.3 | 1.45 s | 8.6 s | 747 ms | 204 ms | 13 ms |

(16, 10 and 8 runs of each; the last on a machine otherwise idle, which
took the round-3 tree back to its documented 1.2 s.) The prebuilt engines
cost some CPU (9 built ahead whether or not every thread needs one) for
wall time. What remains against round 3 is CPU the data analysis needs
(+2.8 s of 12.8 at load 15, about 30%: the data references along every
flow, data analysis, the no-return evidence), spread over the analysis
threads.

### The gate

At load 10-15 the gate's best of three had come down to 1.6-1.9 s, so it
passed, without much margin when the load neared 16 (where it stopped
judging). Wall time on a shared machine measures the machine as much as the
code, and this one now always carries load 10 or more (a model in training
holds one core and the GPU; other agents' builds come and go). So
`scripts/scale-check.sh` now judges, from its best of three runs:

- **CPU time, at any load: at most 16 s** (`rk-backend-bench` prints the
  process's user and system time when the decompilation arrives). Today's:
  8.6 s on a quiet machine, 11 s at load 10, 12.8 s at load 15; 16 s is
  25% above the last. What fails CI on a busy machine: a change that adds
  work. A change that only moves work onto one thread (as the teardown
  and the no-return evidence above did) shows in wall time far more than
  in CPU time.
- **Wall time, 2 s**, judged only while the load average is under a
  quarter of the cores (8 on this machine), and reported otherwise. That
  is the design's gate, measured where it means something.

Prototype inference (`revkit::infer`, `--infer-prototypes auto` by default
since decomp-quality) runs in the background after the import; the gate
turns it off (`--infer-prototypes off`) so that neither number counts it.
Started right after the import, it overlapped the first decompilation by
a few tens of milliseconds (cmake, load 8: 1.81-1.87 s and 10.9-11.5 s CPU
with it, 1.78-1.84 s and 10.9-11.1 s without).

After merging master at c44baaa (decomp-quality), interleaved at load 9.5
(10 runs each): master 2.33 s and 12.2 s CPU, this branch 1.81 s and
11.0 s CPU, the branch before the merge 1.83 s and 11.3 s.

## Where the time and memory still go

Profiles come from a small `SIGPROF` sampler and a sampling heap profiler
(`LD_PRELOAD`), since `perf` is blocked here (`kernel.perf_event_paranoid`
is 4; `sudo sysctl kernel.perf_event_paranoid=1` would enable it) and
neither valgrind nor heaptrack is installed (apt packages `valgrind`,
`heaptrack`).

**Cold start (cmake, 1.3-2.1 s by load).** The import is mostly decoding:
about 1.0-1.1 s at load 13-15 decoding the flows from 19K seeds on 8
threads (SLEIGH, with the data references along each flow; a third of that
CPU is malloc and free of the p-code's strings), 0.2 s for discovery's
fixpoint, 0.2-0.3 s for data analysis and then the listing beside the
decompiler's inputs, and 0.1-0.2 s loading and staging. More threads help
the decoding on a free machine (16 threads: about a third less), at 35 MB a
SLEIGH engine.

**Whole-program decompilation** is bounded by its budget, not by the
program: workers run the decompiler, a guard keeps the parent and workers
within the budget while runs are in flight, a worker's memory goes back to
the system when it is recycled, and a step that never returns is killed
at the hard deadline (round 3). What costs time now is the decompiler
itself and the handful of functions that run until their deadline.

**Decompilation** is Ghidra's decompiler itself (heritage, jump-table
recovery, the action pool); revkit's own share is small. Costs are heavy
tailed: cmake's slowest functions take 15 to 40 s each and up to 500K
varnodes; libLLVM has functions that run for over half an hour, which
the 30 s timeout (Ghidra's) now stops.

**Discovery on very large programs.** Chrome's discovery takes 31 rounds
(each round's call targets are new entries); each round re-runs no-return
inference over all entries, about 2 s at 168K functions, and the flows of
the new entries are decoded in parallel waves. Its peak is 4.1 GB: flow
graphs (about 40 bytes per instruction for 18M instructions, held for the
whole fixpoint) and the fact store's copy of the file. A compact flow
representation (most instructions have no or one target, but each carries a
24-byte vector) and dropping flow graphs from memory once a function's walk
is final would bring Chrome under 4 GB.

**The daemon's 3.7 GB on libLLVM**: flow graphs memoized for every function
(0.8 GB), the file in the fact store and in the loaded image (0.3 GB each,
plus the patched copy for a relocated PIE), discovery's tables, every
function's references and default names, and one SLEIGH engine per thread
(35 MB each; idle ones are parked, [memory.md](memory.md#sleigh-engines)). The backend's `memo_budget` (2 GB) evicts memos only to a
project directory; an in-memory project keeps them.
