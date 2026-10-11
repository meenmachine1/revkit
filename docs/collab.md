# Multi-daemon collaboration

Two or more `rk-daemon`s, on different machines or in different processes,
share a project and converge. This page covers the replication model, the
sync protocol, the merge rules (including structural edits), presence and
the limits.

```sh
rk-daemon --no-auth --open prog                                   # a: imports the binary
rk-daemon --no-auth --grpc 127.0.0.1:50061 --http 127.0.0.1:50062 --peer 127.0.0.1:50051   # b, linked to a
rk-daemon --no-auth --grpc 127.0.0.1:50071 --http 127.0.0.1:50072 --peer 127.0.0.1:50061   # c, linked to b
```

b and c receive the program's record and file from their peer, analyse it
themselves, and from then on an edit made through any daemon (by the UI,
an SDK, an agent) shows up on every other one, with the usual subscription
events. One link replicates both ways; links can form a chain, a star or a
mesh, and ops are relayed along them.

**Authentication.** Off loopback, daemons replicate over TLS with a peer
credential: a token with role `peer` that the daemon being linked to
issued, or a secret the group shares ([security.md](security.md#peers)):

```sh
rk-daemon token create --name daemon-b --role peer --project-dir ~/rk-a > b.token   # on a
rk-daemon --project-dir ~/rk-b --peer 'a.lan:50051,token-file=b.token,fingerprint=3D:67:...'   # on b
```

A peer credential reaches `SyncService` only, and nothing but a peer
credential does. A peer is trusted with data: it can push any op with any
provenance, which replication needs, so give peer credentials only to
daemons you run.

## What replicates

Only the **assertion log**: user, importer and agent edits with their
provenance (`src/facts`, [facts.md](facts.md)). Nothing derived is ever
sent; every daemon recomputes functions, listings, xrefs and
decompilations from the same inputs, which are:

| Input | How it reaches a peer |
| --- | --- |
| Assertions and retractions | replicated ops |
| Debug-info import assertions (`import:dwarf`, `import:pdb`) | replicated ops, made once by the importing daemon |
| A program's record (`NOTE` in the project space: id, file hash, load options, its fact spaces) | a replicated op |
| A program's name, deletion and folder, and the project's folders (`NOTE` keys in the project space, api_minor 37) | replicated ops; concurrent moves that make a cycle are broken the same way everywhere (the cycle's lowest folder id hangs from the root) |
| Call-site signature overrides (`CALL_SIGNATURE` keys, api_minor 53) | replicated ops, like any program edit |
| Project-wide types and type archive settings (`TYPE_DEF` and `NOTE` keys in the project space, api_minor 52; [types.md](types.md#project-types)) | replicated ops, resolved like a program's types (concurrent bindings of one name: the store's precedence) |
| Programs imported from a project archive | replicated ops under the replicas the import made for them ([backend.md](backend.md#project-archives)), then the file like any program's |
| The program's file | fetched once by SHA-256, in 1 MiB chunks, from a peer that has it |
| Analysis inputs (`analysis.program.loaded`, decompiler options) | recomputed from the file and the record |
| A memory-map region's bytes from another file | fetched by sha256 like a program's file; the region reads as uninitialized until they arrive ([memory-map.md](memory-map.md#collaborators)) |

Presence (who is looking where) uses the same channel but is not an
assertion: it is never logged or persisted.

## The replication model

`src/facts` (`fact.h`, `assertion_log.h`, `fact_db.h`).

**Replicas and op ids.** A replica is one copy of a project's log: one
`FactDb`, so one project on one daemon. Its id is a random 64-bit number,
persisted in the store's meta table. Every op gets a global identity
`OpId{replica, counter}`, the counter dense from 1 per replica, and keeps
its local `seq` as its position in this replica's log. Retraction targets
and dependencies are carried by id (`target_id`, `depends_on_id`) and
translated to local seqs on arrival. Logs written before ops had ids
replay as the local replica's ops, numbered in log order.

**Clock.** Each transaction is stamped by a hybrid logical clock: physical
milliseconds in the high bits, a 16-bit logical counter in the low ones,
above every stamp the replica has seen (its own or merged). All ops of one
transaction share the stamp. So an op always sorts after every op its
author could have seen, whatever the wall clocks say; only concurrent ops
are ordered by (roughly) wall time.

**Version vectors.** Because counters are dense and a replica only accepts
an op after its replica's previous op, "what a replica holds" is a map
replica → highest counter. A peer asks for exactly the ops it lacks.

**Merging** (`FactDb::Transaction::merge`). An incoming op is skipped if it
is held, staged or waiting (by id). Otherwise it is staged once its
replica's previous op, its retraction target and its dependency are all
held; until then it waits in the `FactDb`, and staging an op wakes what
waited on it. Staging assigns the next local seq, so the local log is
always a causal order (a retraction or dependent after its target), which
is what the liveness machinery and pinned reads (`blame(key, upto)`)
already assumed.

**State is a function of the op set.** Nothing the log reports depends on
arrival order:
- liveness: `retracted(x)` = some live retraction targets x; a retraction
  is live iff not retracted; an assertion is live iff not retracted and its
  dependency (if any) is live. These follow references only.
- the winner of a key: the live assertion with the highest
  `(rank(provenance), stamp, replica, counter)`, where rank is
  user > import = migration > agent > analysis. Rank first, then recency;
  the replica id breaks ties between equal stamps from different replicas,
  identically everywhere.
- blame: candidates ordered live first, then by rank and the same recency
  order; `retracted_by` and history in `(stamp, replica, counter)` order.

Merging is therefore **idempotent** (held ops are skipped), **commutative
and associative** (the result is determined by the set of held ops, and
waiting only delays an op until its predecessors are in the set). The
property tests (`src/facts/tests/replication_test.cc`) check exactly that:
random histories on 2 to 4 replicas with clocks skewed by up to an hour
(single and batched assertions, dependencies, retractions of anything
including retractions, reverts by provenance, partial exchanges of random
subsets in random orders with duplicates) end, once everyone has
everything, with identical effective values, blame (winner, every
candidate's status and retractions, concurrent losers) and history on
every replica, and on fresh replicas fed the same ops shuffled or
reversed. Mutating the tie-break to use local seqs, or dropping ops that
arrive early, makes them fail.

**Retraction and revert.** Unchanged, and replicated as ordinary ops: undo
appends a retraction, redo retracts the retraction, and
`RevertByProvenance` retracts every op the author made, assertions *and*
retractions, live or not, so what they retracted comes back and the result
reads as if they had never acted. A revert is a set of retractions of the
ops the reverting daemon held when it ran. An op the same author made
concurrently on another daemon (for example, an agent still writing on b
while a reviewer on a reverts it) is not covered and survives the merge;
reverting again after the merge removes it. A predicate retraction ("all of
this author's ops up to stamp t") would cover it but would also let a
revert retract ops nobody reviewing could have seen, so it is not used.

**Concurrent edits are visible.** An assertion records the op it
superseded: the live assertion of its own rank that was the winner on its
replica when it was made. Blame follows that chain from the winner; a live,
shadowed candidate of the winner's rank that isn't in it was made without
its author having seen the winner, or vice versa: a concurrent edit.
`BlameResponse.concurrent_seqs` lists these losers, so a UI can say
"your rename lost to bob's, made at the same time".

## The protocol

`proto/revkit/v1/sync.proto`, served by `rk-daemon` on its gRPC port.

| RPC | What |
| --- | --- |
| `GetSyncState` | per project: replica id, version vector, waiting ops, head, programs missing their file |
| `Pull` (stream) | `PullHello` (the server's replica and vector), the ops the caller's `have` vector lacks in causal order, `CaughtUp`, then, when `live`, every op the server commits afterwards (its own and relayed) and presence; heartbeats every 5 s |
| `Push` | the caller's ops (merged as above and committed as one revision with cause `REPLICATION`), presence entries, or a chunk of a program file; returns the vector after the merge and the programs whose file is missing |
| `FetchProgram` | a chunk of a program's file by SHA-256 |

Ops travel as `ReplicatedOp{id, encoded}`, `encoded` being the fact
store's binary encoding of the op (key, value, provenance, stamp,
references by id, and the API metadata: request body, session, reason).
Peers send `format` (currently 1) and refuse other formats.

**A link** (`revkit::api::PeerLink`, `--peer host:port`) runs, per project
either side has:
- *inbound*: `Pull` from the peer with our vector, `Push` each batch into
  the local backend; fetch the files of programs we have only the record
  of;
- *outbound*: `Pull` from the local backend with the peer's vector (from
  `GetSyncState`), `Push` each batch to the peer, creating the project
  there if needed; send the files it reports missing.

Each loop reconnects with exponential backoff (100 ms to 5 s) and starts
over with a fresh vector exchange, so catching up after being offline,
after a partition or after a restart is the same anti-entropy as the first
sync. A project created on either side is picked up within a second.

**Echo suppression.** A pull stream remembers what its peer holds: its
`have` vector, plus everything sent, plus what that peer pushed (Push names
its replica). Ops relayed from third daemons are sent once per link; any
duplicate that slips through is skipped by the merge.

**Invalidation.** Merged ops commit through the same path as local edits,
so subscribers get a `RevisionEvent` (cause `CHANGE_CAUSE_REPLICATION`)
with `changed_keys` and `invalidated` computed exactly as for an edit made
on this daemon. A merged op's `Assertion.revision` is the local revision
that merged it, so `ListAssertions` and `RevertByProvenance` revision
filters stay meaningful per daemon.

**Programs.** When a merged op is a program record the daemon doesn't have,
the program waits for its file (`missing_programs`); the file arrives in
chunks, is checked against the record's SHA-256 and loaded at the record's
fact spaces with the record's options, exactly the inputs the importing
daemon staged, then analysed. A daemon that loads a peer's program nudges
its own pull streams, so daemons further along a chain fetch it at once.
A persistent daemon that restarts with a record but no file reports it
missing again.

Program ordinals fix a program's fact spaces and must agree everywhere.
They are a hash of the program id and file hash (probing past used ones),
so concurrent imports on two daemons don't collide, and the same file
imported under the same name on two daemons lands in the same spaces and
merges into one program.

## Structural edits

Function bounds and type layouts are edits whose meaning spans more than
one key. Two approaches were possible: advisory locks through the sync
service, or an explicit merge rule. **revkit uses an explicit rule.**

Why not locks: a lock needs a single authority (a lock holder or lease
server), which a partitioned or offline daemon can't reach; it would turn
"keep working while disconnected" into "wait", and a crashed holder needs
lease expiry and fencing to be safe. Locks also don't remove the need for a
rule: ops made before a lock was taken still merge. Since derived facts are
recomputed from effective values, a deterministic rule on effective values
is enough to make every daemon agree, and losing edits stay in history
(shadowed, flagged concurrent) so nothing is lost. Advisory "I'm editing
this function" hints can still be layered on presence later; they would
inform people, not gate writes.

The rules:

1. **Every key is a register, never merged inside.** A function's bounds
   (`FUNCTION_BOUNDS@entry`: the whole body, or "not a function") and a
   type application (`TYPE@addr`) take the winning assertion's whole value.
   Two concurrent bodies for one entry are never unioned or split; one
   wins (rank, then recency), the other is shadowed and reported as
   concurrent.
2. **A transaction wins or loses as a unit.** All ops of one
   `AppendAssertions` batch share a stamp, and a batch has one provenance,
   so against a concurrent batch of the same rank it wins on every key
   both touch, or loses on every one. A multi-key edit (split a function:
   shrink one body and assert another entry; change a layout: define the
   new type and retype its uses) is never torn between two authors on the
   keys both edited (`Replication.TransactionsWinOrLoseAsAUnit`).
3. **Asserted bodies of different entries never overlap.** Concurrent
   bounds edits can leave two asserted bodies covering the same addresses
   (each author extended a different function). Discovery
   (`analysis.functions`, `Discovery::disjoin_asserted_bodies`) gives each
   contested address to the claiming entry closest at or before it, else
   the lowest claiming entry, the same rule it uses for code several
   functions reach; an entry left with nothing falls back to its
   discovered body. The rule reads effective values only, so it gives the
   same functions on every daemon whatever order the edits arrived in
   (`Freestanding86.OverlappingAssertedBodiesAreMadeDisjoint`,
   `CollabTest.ConcurrentFunctionBoundsConverge`).
4. **Dependent edits follow their dependency.** A local-variable rename can
   depend on the bounds assertion it was made under; if that is retracted
   anywhere, the rename is dependency-dead everywhere, and comes back if
   the retraction is undone.
5. **Type layouts are immutable values.** A type definition (`TYPE_DEF`) is
   keyed by the hash of its content, so two people editing `struct foo`
   produce two different types, never one record with a mix of their
   fields; each use site (`TYPE@addr`) then picks one by rule 1, and a
   batch that defines a layout and retypes its uses wins or loses those
   sites as a unit by rule 2. After concurrent layout edits that touched
   different sites, both versions of the struct can be in use at once:
   distinct, coherent types, visible in blame as concurrent, which a user
   resolves by retyping.

What the rules don't do: they don't merge two edits into a third value
(no three-way field merge of struct layouts, no union of bodies), and
they enforce invariants within a key and within a batch, not across
unrelated batches. A local renamed under a storage key that a concurrent
bounds change made disappear stays in the log and simply applies to
nothing.

## Presence

`proto/revkit/v1/presence.proto`. A client (one browser tab, one agent
run) announces itself with `UpdatePresence{client_id, who, program_id,
address, selection, view}` and refreshes it before `expires_at` (TTL 30 s by
default, at most 600 s); `left = true` removes it. The newest entry per
`client_id` (by `sequence`, which the server assigns when the client sends
0) wins on every daemon; an update not newer than the stored one is
ignored, which is also what stops relayed entries from bouncing between
daemons. Daemons relay entries over their pull streams and pushes, and
stream them to subscribers that set `include_presence`;
`ListPresence` returns the live ones. Nothing is persisted. Expiry compares
wall clocks, so daemons' clocks should roughly agree (within the TTL).

## Tests

- `src/facts/tests/replication_test.cc`: op ids and stamps, encoding,
  idempotent and order-free merging, waiting for missing predecessors,
  tie-breaks, rank over recency, causality over clock skew, transaction
  atomicity, revert across replicas (including the author's retractions),
  dependencies, malformed ops, replica id and legacy logs across reopen, and
  the convergence property over 200 random histories.
- `src/backend/tests/collab_test.cc`: daemons in one process, each with a
  gRPC server on loopback, linked by `PeerLink`s:
  `ThreeDaemonsConverge` (a chain; concurrent renames and comments from
  three threads, retractions of other daemons' edits, an agent's
  retraction reverted by provenance on another daemon, a partition with
  conflicting edits and its heal, a late joiner linked to the far end; at
  each step every assertion by id, blame on every edited key, the function
  list and every function's decompiled C are identical),
  `PeersEditsInvalidateSubscribersAndPresenceSpreads`,
  `ConcurrentFunctionBoundsConverge`, and
  `PersistentReplicaRestartsAndCatchesUp`.
- `sdk/python/tests/test_collab.py`: three `rk-daemon` processes with
  `--peer`, a rename and presence across them.
- `CollabTest.AuthenticatedPeersOverTls` and
  `sdk/python/tests/test_auth.py::test_peers_replicate_with_tokens_over_tls`:
  replication with a peer token over TLS with the certificate pinned, and
  none with a non-peer token or over plaintext.

## Limits and known gaps

- **Clocks.** Stamps respect causality, but between concurrent edits a
  daemon whose clock runs ahead wins ties of the same rank, and pulls every
  peer's clock forward with it. There is no bound on accepted skew.
- **Seqs are local.** `seq`, `retracts_seq`, `depends_on_seq` and
  `RetractAssertions` seqs are per daemon; `Assertion.id` is the global
  identity. A client talking to two daemons must not mix their seqs.
- **Reverts** cover the ops the reverting daemon held (see above).
- **Imports.** Import a given program on one daemon, or the same file under
  the same name on several (they merge). Different files imported under
  the same name on partitioned daemons, or (with probability about 1 in
  16384 per pair) different programs whose ordinals hash alike, are not
  reconciled: the peer's program is refused with a warning, and that
  daemon reports nothing missing for it.
- **Malformed ops** (a reference that doesn't match, a bad encoding) are
  rejected; between correct daemons this can't happen, but a rejected op
  blocks its replica's later ops on that daemon.
- **Memory and cost.** The whole log stays resident, nothing is ever
  compacted (replicas never forget ops or replica ids), the waiting buffer
  is in memory and unbounded, and a pull's backlog is encoded under the
  backend's global lock. Each link costs two threads per project, and
  each served pull stream one gRPC handler thread.
- **Membership.** Peers are configured by hand (`--peer`); there is no
  discovery, no removal of a replica, and no per-project selection: a link
  syncs every project either side has.
- **Security.** Peers authenticate with a peer token or a shared secret and
  check each other's certificates, but a peer is trusted with every
  project's data and provenance ([security.md](security.md)); there is no
  per-project replication scope.
- **Persistence.** Two daemons can't open one project directory (the
  second is refused: `DIR/.revkit/lock`);
  each needs its own copy (its own replica).
