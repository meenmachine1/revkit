# Fact store and incremental query engine (Phase 0)

`src/facts/`, namespace `revkit::facts`. This note covers the data model, the
query algorithm, concurrency, storage, measured numbers and open questions.

## Data model

Two layers:

**Assertion log** (`AssertionLog`, `fact.h`). Everything a person, an
importer or an agent says is an append-only `Op`:

| field | meaning |
| --- | --- |
| `seq` | monotonically increasing, assigned at stage time; the local order (arrival in this replica's log) |
| `id`, `stamp` | global identity `OpId{replica, counter}` and hybrid-logical-clock stamp, shared by a transaction's ops; target and dependency are also carried by id ([collab.md](collab.md)) |
| `time_ns` | wall clock, informational only |
| `prov` | `Provenance{kind, id, version}`: `user:alice`, `import:dwarf`, `agent:model@1.2`, `analysis:auto`, `migration` |
| `kind` | `Assert` (key, value) or `Retract` (target seq) |
| `depends_on` | optional seq of an assertion this one only makes sense under |
| `meta` | opaque bytes kept with the op for its author (the API stores the request body and full provenance there) |

A `FactKey` is `{FactKind, Address, sub}` (name, type, comment, function
bounds, flow override, note, type definition, a version-tracking
match: [diff.md](diff.md), a memory-map edit:
[memory-map.md](memory-map.md), and the listing's edits of what bytes are
and of constant or volatile ranges: [listing-edit.md](listing-edit.md)). A `FactValue` is a variant:
`monostate` (absent), integer, string, `Address`, `AddressSet`.

**Rebased spaces** ([memory-map.md](memory-map.md#rebase-setting-the-image-base)):
a live `REBASE` key in a space (its value a `Shift`: a delta and the
space's address size) makes the store present that space's keys, and
their `Address`/`AddressSet` values, moved by the delta (what a
`Relocator` says moves, subs and string values included): the engine's
inputs (`AssertedFact`, the key index, `AssertedOrder`) hold moved keys,
`Transaction::assert_fact` takes moved keys and stores them
image-relative, and a commit that changes a space's shift re-indexes the
space and calls `FactDbOptions::on_rebase` first, inside the commit. The
log, its persisted ops and what replicas exchange hold image-relative
keys only.

Liveness is derived, never stored destructively:

- `retracted(x)` = some live `Retract` targets x;
- a `Retract` is live iff it is not retracted, so undo = append a retraction,
  redo = retract the retraction, chains of any length;
- an `Assert` is live iff not retracted and its `depends_on` (if any) is
  live. Retracting function bounds kills the local names asserted under them;
  undoing that revives them.

Liveness is kept incrementally: each op has a count of live retractions
targeting it, and a flip propagates iteratively (no recursion) through
retraction targets and dependents. Appending returns the exact set of keys
whose effective value may have changed.

The **effective value** of a key is its live assertion with the highest
`(rank(prov.kind), stamp, replica, counter)`, where rank is user > import
= migration > agent > analysis. Losers stay in the log. Recency is the
hybrid logical clock, not wall clock: an op always sorts after every op
its author could see, so skewed clocks cannot reorder causally related
edits; on one replica it is the same order as `seq`. Everything the log
reports (liveness, winners, blame, history) is a function of the set of
ops it holds, which is what lets replicas merge in any order
(`Transaction::merge`, [collab.md](collab.md)).

What falls out of the design:
- `blame(key)` gives the winner with its provenance plus every candidate,
  each marked effective, shadowed, retracted (with the retractions) or
  dependency-dead;
- `history(key)` gives the assertions plus every retraction that touched them;
- `Transaction::revert(by, whose, since)` retracts every op of `whose`,
  including its retractions, as one revision. `agent:model` with no version
  matches all versions. The end state is "as if they had never acted", and
  the revert can itself be undone.

**Derived facts** are outputs of registered queries. Each memo records the
rule name and version, the dependencies it read (with fingerprints), its
confidence (`Certain`/`Likely`/`Uncertain`, set by the rule), and the
revision interval it is valid on. `Snapshot::fact<Q>()` returns all of this
as a `DerivedFact`. Derived facts are a cache: they can be dropped and
recomputed at any time, and are never synced.

`FactDb` feeds the log into the engine as the input `AssertedFact(key) ->
effective value`. Re-asserting an equal value (for example, a user
confirming an import) changes nothing downstream. Program bytes are the
input `MemoryPage(space, page) -> 4 KiB`.

Every commit that appends ops publishes exactly one revision, even when no
effective value changes: the input `LogLength` changes with every append
and nothing reads it. A client can therefore name the revision an edit
landed in (`Transaction::next_revision()`), and `commit(&changed)` reports
the keys whose effective value did change.

The inputs `AssertedKeys(kind, space, bucket)` and `AssertedBuckets(kind,
space)` index the keys with a live value by 64 KiB bucket of their address,
so a rule can ask for "every comment in this function"
(`asserted_keys(ctx, kind, first, last)`) and depend only on the buckets
its range overlaps, not on every address or on every comment in the
program. The derived query `AssertedSpan(kind, space, span)` narrows that
to 256-byte spans (filtered out of the bucket, so it re-runs and cuts off
when the bucket changes): `asserted_at(ctx, kind, address)` and narrow
`asserted_keys` ranges read spans, so a rule that looks at many scattered
addresses (a flow reading the overrides on every instruction it decodes)
only re-runs when a key near one of them comes or goes. A transaction can also stage client-defined inputs
(`Transaction::set<Q>`); those are not persisted, so a client sets them
again after reopening.

Addresses (`address.h`) follow Ghidra: a `SpaceTable` of spaces (const, ram,
register, stack, unique, overlays with a base space), `Address{space,
offset}`, inclusive `AddressRange`s (so the last byte of a 64-bit space can
be represented) and normalized `AddressSet`s.

## Query engine

Salsa-style, but validated by **fingerprints** rather than "changed at"
revisions.

- A query is a struct with `name`, `version`, `Key`, `Value` and
  `static Value compute(QueryContext&, const Key&)`; inputs omit `compute`.
  Keys and values go through `Codec<T>`, a canonical binary encoding.
  Fingerprint = 128-bit MurmurHash3 of the encoding.
- Inputs are MVCC: each key keeps a short list of `(revision, fingerprint,
  value)`. A writer stages `set()`s and `commit()` publishes revision R+1.
  Values whose fingerprint is unchanged are dropped, and if nothing changed
  the revision does not advance.
- A memo stores `value, fp, deps (query id, key, fp)…, [lo, hi]`: the value
  is correct at every revision in `[lo, hi]`.
- `fetch(key, S)`:
  1. A memo whose interval covers S is a **hit**.
  2. Otherwise claim the key, and take the newest memo (from memory or
     storage) and **validate** it: probe each dependency at S in recorded
     order (recursively bringing derived ones up to date) and stop at the
     first fingerprint mismatch. If all match, the value is still right.
     The interval extends to `[lo, S]` when every dependency has been
     constant since before `hi`; otherwise it becomes `[max since, S]`.
  3. Otherwise **execute** `compute`, recording each read (fingerprint and
     the revision since which it has been constant). The new interval is
     `[max since, S]`.
- **Early cutoff** needs no special case: a recomputed value with the same
  fingerprint makes every dependent's check pass. Validation stops at the
  first changed dependency, so stale branches the new computation would not
  take are never evaluated.
- Fingerprint edges keep working after a memo is spilled to disk, reloaded
  by a reader pinned to an older revision, or reloaded in a later session.
  A plain "changed_at" comparison is not sound once readers at several
  revisions compute concurrently.
- **Cycles.** A key being computed is owned by a thread. Re-entering a key
  this thread owns throws `CycleError` with the path. Waiting on another
  thread's key adds an edge to a wait-for graph, and closing a loop throws
  instead of deadlocking. The thread that detected it unwinds, the other
  thread proceeds, re-enters and gets the error too. Edges are cleared when a
  slot is released, and slots carry a generation counter, so stale edges
  cannot create false cycles.
- **Input partitions** (salsa's "durability", by partition). Every input
  key belongs to one of 64 partitions: the assertion index's inputs
  (`AssertedFact`, `AssertedKeys`, `AssertedBuckets`) one per fact kind,
  every other input table one of its own (hashed into the upper 48 bits).
  A commit records, before it publishes the revision, the last revision a
  key of each partition changed; a memo records the partitions it read,
  transitively (the union of its dependencies'). Validating a memo whose
  partitions all held still since it was verified extends its interval
  without probing a single dependency. So a comment, a note or a
  version-tracking Match assertion doesn't revalidate discovery, the
  listing or every function's fingerprints: an accept in a 20,000-function
  diff costs milliseconds ([diff.md](diff.md#performance)). Collisions in
  the upper bits only cost the fast path. Memos loaded from storage start
  with every partition and learn theirs on their first validation.
- **Fixpoint hook.** A rule may catch `CycleError` and return a provisional
  value. The engine marks that result (and anything that read it)
  `Uncertain` and never memoizes it. Proper fixpoint iteration across the
  call graph can replace this point later.

Each query is a separate table. Memos live in 64 sharded hash maps per
table. Dependencies are one encoded blob per memo (about 29 bytes per edge)
rather than a vector of structs.

## Concurrency

- **One writer** (`Engine::Writer` / `FactDb::Transaction`), many readers.
  The writer stages privately, and readers never see staged data. `commit`
  installs new input versions at R+1, then publishes R+1 atomically under
  the pin lock.
- A `Snapshot` pins its revision; input versions and memo intervals needed
  by the oldest pin are kept, older ones are pruned on write or by
  `collect_garbage()`. A snapshot taken before a commit keeps answering for
  its revision, including queries it first computes after the commit.
- Queries for different keys run in parallel (`Snapshot::get_all` on a
  `ThreadPool`). A key is computed by at most one thread at a time; others
  wait on the shard's condition variable.
- **Determinism:** queries are pure functions of inputs at the snapshot's
  revision, results are placed by index, and errors from `parallel_for`
  come from the lowest index. Which memo intervals exist depends on
  scheduling, but values do not. The tests compare outputs across 1, 2, 3,
  8 and 16 threads, before and after edits.
- Reading through a `Snapshot` from inside a query is rejected, since it would
  bypass dependency tracking. `begin_write()` on the thread that already
  holds the writer throws instead of deadlocking.

## Storage

`Storage` is an ordered key-value interface with four tables (meta, log,
bytes, derived), point gets, prefix scans and atomic batched writes.
Snapshot isolation lives in the engine, so the interface stays small.

- `make_memory_storage()`: `std::map` per table.
- `open_lmdb_storage(dir)`: LMDB 0.9.31, built from source with FetchContent
  and pinned by SHA-256. The host also has `liblmdb-dev` 0.9.31; I kept the
  vendored build so nothing needs to be installed and the version is fixed.
  The map size is sparse (64 GiB by default), `MDB_NOTLS` is used for
  thread-pool readers, and `no_sync` is optional for recomputable data.

Layout: the log is keyed by big-endian seq and replayed on open to rebuild
liveness. Bytes are stored in 64 KiB chunks (16 pages), because a lone 4 KiB
value costs two LMDB overflow pages. Derived memos are keyed by `u32 query
id + key` and stored as `rule version, lo, hi, fp, confidence, deps, value`.
The meta table holds the last revision; a reopened store continues past it,
so persisted intervals are never misread as current.

**Spilling.** The engine tracks an estimate of resident memo bytes. Every
reader that finds the cache over budget evicts a slice itself
(backpressure) using second-chance sweeps over shards. Evicted memos are
written to the derived table first, unless storage already holds the same
value and dependency blob. A miss reloads the memo and validates it like
any other. A record from an older rule version, a corrupt record, or one
whose dependencies name an unregistered query is treated as missing and
recomputed.

## Measurements

`rk-factbench` (defaults: 250k functions, about 100 toy instructions each,
20k globals, 500 structs, LMDB with `no_sync`, 1 GiB memo budget, 32
threads). Pipeline: bytes → `toy.decode` (instructions) → `toy.xrefs` →
`toy.summary` (decompiled stand-in reading callee names, global types and
struct layouts). Machine: 32 cores, 31 GiB, NVMe.

| | |
| --- | --- |
| program | 101.8 MB of code, 25.0M instructions, 250k functions, 415k import assertions |
| load (bytes + assertions, durable) | 3.5 s |
| analyze everything (decode, xrefs, summaries) | 4.0 s at 32 threads (6.2M insn/s); 5.6 s at 8; 23.6 s at 1 |
| flush resident memos | 2.7 s |
| reopen (replay log, load bytes) | 2.0 s |
| re-validate all 250k summaries from disk after reopen | 2.6 s, 0 recomputations |
| bytes per instruction fact | 5.7 encoded (record incl. key and deps), 9.4 in LMDB pages, 16 in memory when resident |
| whole LMDB file | 1.24 GB (log 24 MB, bytes 108 MB, derived 1.10 GB of pages for 660 MB encoded) |
| peak anonymous RSS | 1.83 GB (live heap peak 1.57 GB; memo cache capped at 1.02 GB) |
| peak total RSS incl. LMDB mappings | 3.07 GB |

Single assertion changes (commit, then the one view a user is looking at,
then every summary re-read):

| change | commit | one affected view | re-read all 250k | recomputed |
| --- | --- | --- | --- | --- |
| retype struct S7 (offsets move) | 0.11 ms | 0.14 ms | 2.1 s | 1 layout + 5,790 summaries; 0 decode, 0 xrefs |
| rename one function | 0.07 ms | 0.95 ms | 2.0 s | 10 summaries (its callers and itself) |
| nothing | 0.001 ms | 0.003 ms | 3.0 s | 0 |

The full re-read is dominated by reloading and re-validating spilled memos:
the working set (about 1.5 GB of memos) exceeds the 1 GiB budget. Only
exactly the functions that read the changed fact recompute.

**Gate: met.** A 101.8 MB binary with 25M instruction facts peaks at 3.07 GB
total RSS (1.83 GB anonymous) against 4 GB, leaving about 1 GB of headroom.
At a 256 MiB memo budget, peak anonymous RSS is 0.76 GB, at the cost of
more reloading.

## Open questions and known gaps

- **Validation is O(dependency graph) per sweep** when the edit's
  partition was read: re-reading everything after a rename costs about
  2 s here at 32 threads (22.5 s on one thread). Edits in partitions a
  memo never read skip it (input partitions, above); partitions are by
  fact kind, not by address, so a rename still revalidates everything
  that read any name.
- **Re-validation does not refresh spilled intervals,** so a memo evicted
  after being re-validated must be validated again when reloaded (the
  3.0 s "nothing changed" sweep). Rewriting on interval change trades
  writes for reads.
- **Allocator.** glibc retains freed memory, up to about 1.1 GB after the
  reopen phase. jemalloc or mimalloc, or arena-per-table pools, are worth
  measuring before the real decompiler output lands.
- **The log and inputs are fully resident** (about 360 MB for 415k ops plus
  100 MB of bytes). For millions of imported facts, ops should be paged
  from storage and the in-memory index kept to `seq → (key, prov, flags)`.
- **Blame, history and statuses at an earlier revision** take the log
  position that revision ended at (`blame(key, upto)`, `status(seq,
  upto)`): liveness is re-derived from the same rules for the ops up to
  it, memoized per call. The current state stays incremental.
- **Granularity.** Instructions are memoized per function, not per
  instruction, which is what makes 25M facts cheap. Random "what's at this
  address" lookups need an address → function index query; reverse xrefs
  ("who calls X") are not indexed yet and need a sharded aggregate query.
- **Cycles across threads** are detected, but which participant recovers
  through the fixpoint hook depends on scheduling. Real fixpoint iteration
  must make that deterministic.
- **Migration** ranks with import. Arguably a migration should keep the rank
  of what it migrates.
- Rule version bumps invalidate per query, not per changed dependency.
- TSan: the vendored LMDB is compiled without TSan instrumentation, the same
  treatment `tools/sanitizers/tsan.supp` gives system libraries, because its
  reader table is lock-free by design. Races involving revkit code are still
  reported. The tests rely on the tsan preset's `setarch -R` emulator.
- `RevertByProvenance` in the API follows `FactDb::revert`: it retracts
  every op of the matching author, assertions and retractions, live or
  not, so assertions they undid come back and a later redo by someone else
  cannot revive the author's own work.
