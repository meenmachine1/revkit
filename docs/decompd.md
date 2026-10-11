# Decompiler workers

Ghidra's C++ decompiler runs in worker processes (`rk-decompd`), never in
the process that owns the facts: the daemon (`rk-daemon`), `rk-lift` and
`rk-infer` hand each decompilation to a worker as a self-contained input
bundle. A crash in the decompiler, a step that never returns or memory a
large run leaves behind costs that one function, not the process; the
failure becomes a fact of its own. `src/decompd` (`revkit::decompd`)
holds the bundle format, the worker pool and the batch driver;
`tools/rk-decompd` is the worker and the repro tool.

Why: the held-out evaluation found a segfault (`Merge::snipReads`) and a
SIGFPE (`SplitDatatype::buildPointers`) inside the vendored decompiler,
and a hang inside one `ActionDeadCode` step on libLLVM `0x34998c0` that no
cooperative check reaches; malloc kept 1.5 GB after a large stopped run
([scale.md](scale.md#bounded-decompilation)). In process, each of those
took the whole daemon or batch run with it.

## Bundles

A bundle (`include/revkit/decompd/bundle.h`) holds everything the
decompiler asks while decompiling one function:

| Part | What |
| --- | --- |
| header | mode (`c_text` for rk-lift, `tokens` for the daemon, `observe` for inference, `param_id` for Ghidra's Decompiler Parameter ID, `signature` for BSim features), language, entry, the image's format, pointer size and blocks |
| memory | the ranges that hold bytes (the file's memory and the loader's patches), and the bytes the decompiler reads, in 1 KiB chunks, as the patches leave them |
| answers | what `lift::FactLookup` says about each address the decompiler looks up (the function starting there, the body containing it, data, external reference, label, block mutability), code labels, types by id (kept encoded; a worker decodes one when the decompiler asks), the function's comments, flow overrides and tracked registers; for `observe`, infer's `SymbolEnv` answers |
| hooks | jump tables discovery recovered, flow overrides and comments besides the lookup's |
| firmware | a raw image's regions with their mutability (volatile MMIO, uninitialized RAM) in the blocks; a Thumb function's context (`FunctionFacts::context`, painted over its body by the worker, and used by the parent's prediction engine for that function); `PCODE_` flow overrides applied to emitted p-code, among the function's overrides |
| options | Ghidra's default naming (`default_names`, labels, extrapop), the address prefix, the decoding context (ARM Thumb) |
| joins | for in-order batch runs only: the join records earlier functions left, laid out first (below) |

Limits (the cooperative timeout and the varnode bound) travel beside the
bundle, not in it. Bundles encode canonically (tables sorted by encoding,
indexes remapped, maps ordered), so equal inputs give equal bytes; the
hash (`b2-` (the format version) and the 128-bit fingerprint of the encoding) is the
decompilation's cache key and names its repro. Typical sizes: cmake's
`main` 62 KB; the tuning corpus averages 14 KB under Ghidra's inputs, 15 KB under
its own and 7.5 KB from the reference list alone (Lua with DWARF, 34 KB);
libLLVM 22.6 KB.

### Assembling one: prediction and misses

The parent can't run the decompiler to learn what it will ask, so it
predicts (`builder.h`): it decodes the body with SLEIGH and lists every
address its p-code names (constants that land in memory, absolute memory
operands, call and branch targets, the pointer stored at each, AArch64 and
RISC-V page-plus-offset pairs), every block start (the printer labels goto
targets), the destinations of a switch table among the constants a
function with a computed jump names, the start of data an address falls
inside, address 0, and flow leaving the body for up to 256 instructions.
It answers those from its own lookup (`LiftBundleBuilder` over any
`lift::FactLookup`: an index over a program's inputs in rk-lift, the
backend's fact-store `QueryLookup` in the daemon) with the closure of the
types the answers reference.

A query the bundle doesn't answer is a **miss**. The worker never calls
back: it answers "nothing" (no symbol, no type; bytes it lacks read as
unreadable, so the decompiler never follows made-up code), carries on, and
reports the miss. The parent then looks the missed keys up. If every true
answer is what the worker assumed, the run stands (it is the run of the
bundle with those answers added, which becomes the bundle); otherwise the
parent decompiles again with them added, up to four runs. A bundle that
still misses after that is reported as unresolved (none so far). Misses
are counted (`rk-lift --stats`: `decompile_miss_queries`,
`decompile_reruns`, by kind in `decompile_miss_kinds`):

| tuning corpus, gates' settings | functions | functions with a miss | runs repeated | queries missed | still missing after 8 runs |
| --- | ---: | ---: | ---: | ---: | ---: |
| Ghidra's inputs | 11,380 | 874 (7.7%) | 226 (2.0%) | 2,687 | 0 |
| reference function list | 11,380 | 3,494 (30.7%) | 248 (2.2%) | 11,794 | 0 |
| revkit's own inputs | 9,876 | 919 (9.3%) | 163 (1.7%) | 3,658 | 0 |
| libLLVM, own inputs (`-j 8`) | 127,008 | 23,548 (18.5%) | 6,946 (5.5%) | 202,805 | 6 |

Most misses are free: an address that holds nothing, which the worker
already assumed. What still costs a rerun is mostly data reached through a
computed pointer (an offset into a table), jump tables the guess misses,
and flow running far past the body (a missed chunk brings the next three).
The six libLLVM functions still missing answers after eight runs (flow
through long chains of chunks) keep the last run's output, which is listed
in `--stats` (`decompile_unresolved_functions`).

### What a bundle can't hold

The decompiler's architecture keeps two kinds of state from one function
to the next, which the in-process decompiler had too:

- **Join records** (multi-register storage). Their addresses order
  variables and so number them (`auVar14`/`auVar15`), and records persist
  for the architecture's life. Batch runs in address order on one worker
  (`rk-lift --in-order -j 1`, the gates' setting, Ghidra's sequence)
  chain them: each bundle carries the records earlier functions made, a
  worker lays out exactly those (rebuilding its architecture if its own
  differ), and output equals one in-process decompiler's. Elsewhere (the
  daemon, `-j N`) a worker's records are whatever its earlier functions
  left, as an in-process instance's were.
- **SLEIGH's decode cache**, flushed before every run so that every byte a
  decompilation decodes is read from (and missed by) its bundle.

Neither changes which facts a decompilation reads.

## Workers

`WorkerPool` (`pool.h`) runs `rk-decompd --worker` processes:

- **Transport:** one `AF_UNIX` stream socketpair per worker, frames of a
  32-bit length, a type and a payload (a request: limits and the encoded
  bundle; a reply: `RunResult` with the mode's payload, the misses, the
  addresses asked, the join records made, timing and the worker's RSS),
  and a pipe for the worker's stderr. Pipes over shared memory: a bundle
  is tens of kilobytes and a decompilation milliseconds to seconds, so
  copying through the kernel costs microseconds (0.3 ms of IPC per
  function on cmake, below); a socket reports end-of-file the moment the
  worker dies and `poll()`s with the deadline; and nothing shared with a
  worker can be left half-written or locked by its crash, as a ring in
  shared memory with a futex could.
- **Workers hold only SLEIGH specs and decompiler state.** A worker keeps
  up to two architectures by arch key (mode, language, image shape,
  naming options, context) and decompiles one bundle at a time; it never
  sees the fact store. The pool prefers an idle worker that last served
  the same key.
- **Started** with `posix_spawn` (no fork of a threaded parent), stdin
  `/dev/null`, every other descriptor closed, under `RLIMIT_AS`
  (`PoolOptions::memory_limit`: 4 GiB by default, half the batch budget
  plus 512 MiB in rk-lift; not under sanitizers). A worker reports its
  decompiler build when it starts; a stale binary is refused. It exits
  within a second of its parent's death (a watchdog on `getppid`, since
  `PR_SET_PDEATHSIG` follows the spawning thread, not the process).
- **Deadlines:** the cooperative timeout (lift::DecompileBudget, checked
  between the decompiler's actions) stays the graceful path; the parent
  kills a worker with SIGKILL at the hard deadline, 1.25 times the timeout
  plus 2 s (30 s: 39.5 s), which covers loops no check reaches. A client
  that cancels (the daemon's request context) kills its worker too.
- **Recycling:** a worker is replaced after `recycle_after` functions
  (5000), when its anonymous memory passes `recycle_rss` (768 MiB; in
  rk-lift a share of the budget, 256 MiB at 8 threads of 4 GiB), and after
  any run stopped over its limits (malloc keeps what such runs free; a new
  process gives it back).
- **Failures:** a worker that dies is classified from its exit status
  (SIGSEGV and SIGBUS: `segv`; SIGFPE: `fpe`; SIGABRT and other signals:
  `abort`; exit status 3, which the worker uses when `new` fails, and a
  SIGKILL not sent by revkit: `oom`) or as `timeout` when the pool killed
  it; a cooperative stop is a `timeout` (deadline) or an `oom` (varnode
  bound). The pool starts another worker for the next request.
- **In process, for gdb only:** `REVKIT_DECOMPILE_IN_PROCESS=1`,
  `rk-lift --decompile-in-process`, `rk-daemon --decompile-in-process`,
  `rk-infer --decompile-in-process` run the same bundles in the calling
  process, where a crash ends it. There is no in-process production mode.

The scheduler of whole-program runs (largest first while the estimated
working sets fit the memory budget; measured memory over the budget
admits only small functions) stays, now counting the workers' anonymous
memory beside the parent's.

## Failures as facts

A failure is `decompile_failure(function, bundle_hash, decompiler_build,
kind, deadline, stderr_tail)` (`decompd::Failure`). `decompiler_build`
is `ghidra-12.1.4+` and a hash of everything under `third_party/ghidra`
(sources and any patch series), computed at configure time, so patching
the decompiler changes it.

- **Daemon:** a failed decompilation is the `decompile.ghidra` memo's
  value, with the bundle it failed on: retried when the facts the bundle
  holds change (its dependencies) or the build changes (part of the
  `decompiler.options` input), never on a timer. A timeout may be retried
  once with a longer deadline on request (`DecompileOptions.escalate`);
  the result then stands for that bundle hash, and another escalation is
  refused ([api.md](api.md)).
- **rk-lift:** the decompile phase ends with a summary by kind and one
  line per function (entry, kind, detail, bundle hash), `--stats` lists
  them, and `--failure-bundles DIR` writes each failed function's bundle.
- **rk-infer:** an observation the decompiler failed on is not ok (the
  function is seen from its callers only); the run ends with the same
  summary. Inference's decompilations also get a 30 s timeout now
  (`infer::Options::timeout_seconds`, not part of its fingerprint).

## The repro tool

```sh
rk-decompd --bundle crash.bundle            # decompile it here; print C (or tokens, or the observation)
rk-decompd --bundle crash.bundle -o out.c --timeout 30 --max-varnodes 1000000
rk-decompd --info crash.bundle -v           # hash, mode, entry, answers, types, chunks, naming
gdb --args rk-decompd --bundle crash.bundle
```

Exit status: 0 decompiled; 1 the decompiler reported an error or stopped
over its limits; 2 bad usage or an unreadable bundle; 4 the bundle lacked
answers the decompiler asked for (listed on stderr). A crash ends the
process with its signal, as it ends a worker. That is what decompiler
patch regression tests run: a bundle per known crash under
`third_party/ghidra`'s tests, expecting exit 0 once patched.

For tests of the failure path, `REVKIT_DECOMPD_FAULT=<kind>@<entry>`
(kind `segv`, `fpe`, `abort`, `hang`, `oom` or `sleep<ms>`) makes a worker
fail that way on one function.

## Signatures (mode `signature`)

Binary diffing's similarity tier (F5, [diff.md](diff.md#signatures-f5))
signs functions with BSim's features. A `signature` worker runs the
function through the decompiler's `normalize` action group (no type
recovery, structuring or merging; `lift::DecompileConfig::action`) with no
printer, then BSim's `GraphSigManager` over the result, as Ghidra's
`SignaturesAt` does. The payload (`decompd::FunctionSignature`,
`signature.h`) is the sorted 32-bit feature vector (`simpleSignature`'s
hashes; the `<call>` records are dropped, the call graph is revkit's), the
unimplemented/bad-data flags, and on request each basic block's features
(`debugSignature`'s attribution: a block's control-flow and copy
features, and the data-flow features of the values its operations define).

- **Settings.** `SigManager::settings` is a process-wide static that only
  `GraphSigManager`'s constructor reads; a session sets it and constructs
  its manager under one lock, so a worker (or several in-process sessions)
  can serve bundles with different settings. Bundles carry them: `0x49`
  (`SIG_COLLAPSE_INDNOISE | SIG_DONOTUSE_CONST`), what BSim's 32- and 64-bit
  weight tables are for and what `default_signature_settings` picks for
  32/64-bit languages; `0x4d` (sizes collapsed too) for the size-free
  table, which a diff of a 32-bit against a 64-bit program needs on both
  sides. (`docs/diff/design.md` says `lshweights_64.xml` is `0x4d`; the
  file says `0x49`.)
- **Bundles under the signature profile** (`inputs::SignatureProfile`,
  `src/inputs/profile.h`): function starts and bodies, imports by name with
  their library prototypes, analysis's no-return set (not the debug info's
  `DW_AT_noreturn`), call fixups, decoding context, flow overrides, tracked
  registers and memory blocks (the read-only ranges loads fold from); no
  user or debug-info names, prototypes, types, locals, comments, data or
  labels. The profile's id, the settings and the block flag travel in
  `Bundle::extra`, so they are part of the bundle hash. Renaming, retyping
  or commenting anything changes no signature bundle; a debug build and its
  stripped twin give the same bundles (Lua, x86-64: 704 of 704 functions,
  the `rk_lift_signatures` test; RISC-V differs where the debug build's
  `__global_pointer$` gives `gp`).
- **Bounds and failures** as for any mode: the cooperative timeout
  (`DecompileBudget`, installed in `normalize`), the varnode bound (also
  `GraphSigManager::setMaxVarnode`), the hard deadline, recycling. A
  failure is the signature's value (`FunctionSignature::failure`, the
  bundle hash), memoized like a decompilation's.
- **Drivers.** `decompd::sign_function` (one function: profile, prediction,
  bundle, misses filled), `signature_functions` (a program, largest first,
  results by entry, the same for any thread count), `rk-lift --signatures
  FILE` (JSON), and the daemon's `diff.signature` query
  ([diff.md](diff.md#signatures-f5)). No decompiler patch was needed.

Cost (x86-64, i9-14900F, `rk-lift --analyze --signatures`, functions with
a body):

| | functions | worker time per function | wall, 1 worker | wall, 8 workers | throughput at 8 | full decompile, 8 workers |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Lua 5.4 (gcc -O2) | 704 | 2.8 ms | 2.2 s | 0.89 s | 790 /s | 1.20 s |
| zlib 1.3 (gcc -O2) | 148 | 3.5 ms | 0.61 s | 0.23 s | 630 /s | 0.50 s |
| libLLVM 20 (stripped .so) | 126,606 | 12.8 ms | | 478 s | 265 /s | 1,957 s |

libLLVM (`rk-lift --analyze --no-instructions -j 8 --signatures`, 624 s
with discovery and assembly): 126,597 signed, 9 failed (8 timeouts at the
30 s cooperative deadline or the 39.5 s hard one, one over the varnode
bound), 402 imports skipped; 15.1M features (120 per function, 60 MB as
u32s). Peak PSS 6.3 GiB, parent 2.5 and workers 3.9: the signature batch
has no memory guard of its own yet (the decompile batch's scheduler keeps
that program under 4 GiB). The parent's bundle assembly is half the
cost (1,920 s summed over 8 threads against 1,624 s in workers).

A signature costs about 75% of a decompilation in the worker (Lua: 2.8
against 3.9 ms per function with a body), as Ghidra's measurement found
(80%); bundles are smaller (no types or symbols beyond imports).

## Daemon and UI

The daemon assembles a bundle in `decompile.ghidra` through the query
context, so what it reads are the decompilation's dependencies, as
before; what the worker reports it asked is the run's `touched` set for
subscribers' invalidation. Workers are shared by every program
(`--decompilers N`, default 2); the import warms one (and the prediction
SLEIGH engine) beside the listing. `REVKIT_TIMING=1` prints each
decompilation's split (bundle, worker, round trip).

The UI shows a failed function's instructions under a banner ("Decompiler
crashed (SIGSEGV)", "Decompiler timed out after 30 s") with **Retry** (a
timeout's escalation) and **Export repro** (downloads the bundle).

## Firmware

Raw images (`rk-lift --raw ... --analyze --decompile`, the daemon's raw
import) decompile through workers like any other: on the ARM firmware
benchmark (`scripts/bench-firmware.sh`, 4,239 functions), every function
decompiles at `-j 8` with output byte-identical to the in-process
decompiler's (master a8eaff3), 178 of them after a rerun, none unresolved.

## Results

See [scale.md](scale.md#round-3-decompiler-workers) for the overhead, the
cold start and libLLVM, and [heldout.md](heldout.md) for the held-out
set.
