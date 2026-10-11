# Binary diffing and version tracking

revkit matches the functions of two programs of one project, shows what
changed, and ports names, comments and prototypes from the program you
analysed (A) to the new one (B). This is milestone M1 of the design in
[diff/design.md](diff/design.md): same-processor version diffs from
fingerprints of the code and the call graph, with no decompiler
involvement. A similarity tier (BSim's F5, milestone M2) plugs into the
matcher's residue step. Inside a matched pair, blocks and instructions
correspond through an instruction map (M3, [Inside a
function](#inside-a-function)); stale detection is still to come.

- [Using it](#using-it): the UI, the Python SDK, the API, `rk-diff`
- [The model](#the-model): sessions, proposals, decisions, ported markup
- [Matching](#matching): fingerprints, tiers, propagation, confidence
- [Results](#results) on the tuning corpus and the held-out set
- [Performance](#performance)
- [For developers](#for-developers): code, queries, the F5 hook, the gate
- [Known gaps](#known-gaps)
- [Signatures (F5)](#signatures-f5): BSim's similarity tier over the residue (M2)
- [Inside a function](#inside-a-function): block and instruction correlation, what changed in a pair (M3)
- [Comparing two functions](#comparing-two-functions): any two functions without a session, variables paired, markup ported either way, manual matching (api_minor 54)

## Using it

### In the UI

1. Import the new version into the project (Ctrl+O) and open it.
2. **Tools: Compare programs…** (the palette, Ctrl+Shift+P): pick A, the
   analysed program, and B, the new one (this tab's program by default).
   The run shows its progress in the Compare view's header (fingerprints,
   then matching); on a 20,000-function program it takes about 2 s.
3. The **Compare** view (Ctrl+9) lists the matched pairs: A's function,
   B's, the tier that matched them, a confidence (coloured: green at or
   above 0.95, the auto-apply threshold; amber from 0.8; red below), a
   structural similarity, the status (proposed, accepted, applied) and
   whether the code changed. Click a column to sort; filter by tier,
   status, change kind, least confidence and name. Hovering a row explains
   its evidence ("the same p-code among the 4 callees of FUN_00401000 /
   main"). *Only in A* and *Only in B* list the unmatched functions with
   their best candidates and why they stayed unmatched (a tie, weak
   candidates, nothing).
4. Selecting a row shows what changed inside the pair: both listings
   aligned line by line, changes highlighted (changed amber, inserted
   green, deleted red, a **new** badge on calls into code only B has),
   **n** / **p** for the next and previous difference; **Space** switches
   to the graph diff (both CFGs, blocks coloured by what changed, matched
   blocks at the same place) and **C** to both decompilations
   ([ui.md](ui.md#compare-version-tracking)). The table's *what changed*
   column says it in a line. In the table, **a** accepts the selected match, **r**
   rejects it (it is never proposed again; the function may find another
   partner), **u** unmatches a decided pair, **m** matches the selected
   function by hand with any function of the other program, **Enter** goes
   to it in this tab's program, ↑/↓ (j/k) move. Each decision is one undo
   step ([Comparing two functions](#manual-matching)).
5. **Apply markup…** ports from A to B: names (only over B's default
   `FUN_` names), comments (function-level ones; every comment of a
   function whose bytes didn't change, at the same offset; in a pair whose
   code changed, each instruction's comment at its partner in the
   instruction map) and prototypes
   (with every type they use, defined in B by hash; names are never
   bound). Choose the threshold (0.95 by default), the policy (*safe*:
   only where B has nothing; *add*: append comments; *replace*: comments
   and prototypes also over values asserted by analysis, agents, imports
   or earlier ports, never over a user's), or only the selected match.
   The dialog previews the counts (a dry run). Applying is one revision.
6. **Undo**: Ctrl+Z (when B is this tab's program) or the toast's Undo
   retracts the whole apply run. The provenance popover (i, or hovering a
   name in the decompiler) says where a ported value came from: "ported
   from default/fw-1.0 @ 401000 · comparison d1a2… · run apply-…".

Sessions are kept in the project (ListDiffSessions); the view opens the
newest one with this program. Edits to either program show up live
(`QUERY_KIND_DIFF_SESSION`); **Re-run** recomputes after edits, and only
what changed is recomputed.

### From Python

```python
from revkit import Client, tier_name

with Client("127.0.0.1:50051", actor="user:alice") as rk:
    s = rk.diff("default", "default/fw-1.0", "default/fw-1.1")   # create, run, wait
    print(s.counts())                                             # matched, auto, unchanged, unmatched
    for m in s.matches(min_confidence=0.95, change_kinds=["modified"], sort="confidence"):
        print(m.a.name, hex(m.b.entry.offset), tier_name(m.tier), m.confidence, m.evidence.detail)
    for u in s.unmatched("a"):
        print(u.function.name, [c.function.name for c in u.candidates])
    s.accept((0x401000, 0x402000))           # pairs of entries (A, B)
    s.reject((0x401100, 0x402200))
    s.set_match(0x401200, 0x402300)          # by hand: replaces the matches either had
    s.unmatch((0x401200, 0x402300))          # undo a decision (api_minor 54)
    s.port(0x401000, 0x402000, items=["variable_names"])   # one function's markup, through the match
    run = s.apply(min_confidence=0.95)       # or s.apply((a, b), items=["names"], policy="add")
    print(run.names, run.comments, run.prototypes, run.run_id)
    s.revert_apply(run.run_id)
```

### Over the API

`DiffService` ([proto](../proto/revkit/v1/diff.proto), api_minor 16,
feature `diff`; inside a pair api_minor 17, feature `diff-detail`;
[api.md](api.md#binary-diffing)). With `rk-daemon
--no-auth`:

```sh
H='Content-Type: application/json'; U=localhost:50052/revkit.v1.DiffService
curl -sS -H "$H" -d '{"projectId":"default","programA":"default/v1","programB":"default/v2","run":true}' $U/CreateDiffSession
curl -sS -H "$H" -d '{"projectId":"default","sessionId":"d…"}' $U/GetDiffStatus
curl -sS -H "$H" -d '{"projectId":"default","sessionId":"d…","filter":{"minConfidence":0.95},"sort":"DIFF_SORT_CONFIDENCE"}' $U/ListMatches
curl -sS -H "$H" -d '{"projectId":"default","sessionId":"d…","minConfidence":0.95}' $U/ApplyMarkup
curl -sS -H "$H" -d '{"projectId":"default","sessionId":"d…","entryA":{"offset":"4198400"},"detail":true}' $U/GetFunctionDiff
```

### `rk-diff`

`build/tools/rk-diff/rk-diff A B` matches two binaries from the command
line (`--changes`: what changed inside every modified pair, to stderr), through the image backend in process (as the daemon serves them),
and writes JSON: every match with its tier, confidence and evidence, the
unmatched functions with candidates, timings. `--raw-a/--raw-b
"lang=…,base=…,entry=…,region=…"` load raw images; `--names-a TRUTH`
asserts A's names and ports them (the evaluation's path); `--bench` times
an accept, a reject and a rename; `--direct` skips the backend (one fact
store and the queries: what the timing targets measure).

## The model

Design: [diff/design.md](diff/design.md), section 4.

| What | How it is stored |
| --- | --- |
| A **session** (two programs, a name, options) | a `NOTE` assertion in the project's space, sub `diff-session`, beside the program records (`q::DiffSessions` lists them) |
| Its **proposals** | derived: `diff.proposals(A, B, options)`, then `diff.matches(session)` with the session's decisions applied. Never assertions, so they follow edits to either program |
| An **accepted** pair | `FACT_KIND_MATCH` at B's entry, sub = the session, value `"0x<A entry> accepted <tier> <confidence>"`, by the user or agent who accepted |
| A **rejected** pair | `FACT_KIND_MATCH` at B's entry, sub `<session>/reject/0x<A entry>`, value `rejected` |
| **Unmatch** of a pair | retractions of its accepted, applied or rejected Match assertions (api_minor 54); retracting them (the response's `seqs`) undoes it |
| An **applied** pair | the same key as an accepted one, value `… applied …`, provenance `migration:diff`, made by the apply run that ported through it |
| **Ported markup** | ordinary `NAME`, `COMMENT`, `TYPE` and `TYPE_DEF` assertions on B: provenance `migration:diff`, version = the session id, session = the apply run id, reason "from <A>@0x… (<tier>, <confidence>); applied by user:alice …"; each `depends_on` its pair's Match assertion; `Assertion.ported_from` records the source program, function and address, the source assertion (seq and id, when A's value was asserted) and the Match |

Consequences, all from the fact store's rules ([facts.md](facts.md)):

- **Undo** of an apply run is `RevertApply{session, run}`, a
  RevertByProvenance over the run: one revision, itself undoable. Ctrl+Z in
  the UI retracts the run's assertions (`ApplyMarkupResponse.seqs`).
- **Retracting a Match** (undo of an accept, `RejectMatches` of an applied
  pair, `SetMatch` replacing it) kills everything ported through it
  (dependency-dead), and undoing that revives it.
- **Precedence**: migration ranks with import, below user. A user's later
  edit in B wins; ports never overwrite a user's value, and names are
  ported only over default names (or an earlier port of the same session).
- **Re-diff is incremental**: the proposals are a function of both
  programs' functions; a rename re-runs that function's fingerprints and
  the matching. Decisions re-run only `diff.matches`, which applies them
  to the cached proposals without re-matching (below).
- **Collab**: sessions and decisions replicate like any assertion;
  proposals are recomputed by each daemon.
- **Stale ports**: each ported assertion records its source assertion's
  seq and id, for `diff.stale` (M3); nothing moves automatically today.

What is ported (`DiffMarkupItem`):

| Item | Where | Over what (policy safe / add / replace) |
| --- | --- | --- |
| Names | the function's entry | B's default (`FUN_`) name, or this session's earlier port; never over a symbol's or anyone's asserted name, whatever the policy |
| Comments | plate, pre and repeatable comments at the entry; for a pair whose masked bytes are equal (`DIFF_CHANGE_KIND_UNCHANGED`) every comment in A's body, at the same offset from the entry | none in B / appended to a non-user comment / replaces a non-user comment |
| Prototypes | `TYPE` at the entry (`h:<hash>` with the type closure as `TYPE_DEF` by hash; a C-text prototype as text) | none in B / none / replaces a non-user prototype |

## Matching

`src/diff` ([features.h](../src/diff/include/revkit/diff/features.h),
[match.h](../src/diff/include/revkit/diff/match.h)). Design section 1.

**Fingerprints** (`diff.features(program, entry)`, a fact-engine query per
function; about 130 bytes each, encoded):

| | Fingerprint | Survives |
| --- | --- | --- |
| F0 | a non-default name: asserted, a symbol or export, an import a stub jumps to | renames only |
| F1 | the bytes, with every field encoding an address outside the function masked (found by encoding the target absolute or relative to the instruction; a whole instruction when the field is bit-packed, as on AArch64 and RISC-V), with each instruction's offset from the entry; imports called by name | code moved, relinked |
| F2 | the raw p-code: opcodes, operand kinds (constant, register, unique, memory) and sizes, constants except addresses (and all constants of an instruction that refers outside the function: AArch64's `add` after `adrp`); imports by name | register renames, address changes |
| F3 | the control-flow graph: BinDiff's MD index (each edge weighted by its ends' breadth-first levels and degrees, with square roots of primes), block, edge and loop counts; and an order-free prime signature of the p-code opcodes with the instruction count | compilers' rescheduling |
| F4 | a bag of references that survive a rebuild: imports called, named functions called, strings read (by content), large constants | almost everything |

Calls (in call-site order), strings and globals (in reference order) are
kept for the neighbourhoods.

F1 and F2 describe **the code, not what it points at**: whether a data
reference's target holds code, a string or other data stays out of them
(an instruction referring outside the function still hashes as its p-code
when no field holds the address). Otherwise a patch that rewrites a data
table (a firmware's asset table) makes every function reading it look
changed, and a firmware that grew or shrank turns a constant like 2000000
into a pointer or back. F4 keeps the references: they are evidence for
matching, not for whether code changed.

**The matcher** (`diff.proposals`): BinDiff-style ordered unique matching,
not a global assignment.

1. **Global tiers**, in order: name, bytes, p-code, shape+refs, shape
   (functions of 8 blocks or more), refs (bags of 3 or more). A hash with
   exactly one unmatched function on each side is a match; a bucket with
   several on either side is left alone.
2. **Propagation**: from every matched pair, four neighbourhoods: the
   unmatched functions each side calls, those calling it, those touching
   the globals the pair touches at the same position, and (independently
   of pairs) those reading one string. Within each, the tiers run again
   (bytes, p-code, shape+refs, shape+opcodes, refs, shape); then the call
   sites of the pair in order (when both sides' sites line up, a free
   callee at the same position); then the most similar pair of the
   neighbourhood, each the other's best by a margin of 0.15 and at least
   0.7 similar (the *neighbour* tier); then a lone remaining pair. A
   round's proposals are decided together: a function proposed with two
   different best partners gets neither. The global tiers run again over
   the residue. Rounds repeat until nothing changes.
3. **The residue** goes to registered similarity tiers (M2; below), whose
   accepted pairs seed another propagation.
4. **Candidates**: each function left unmatched gets up to 16 candidates
   (shared buckets, then the unmatched neighbours of its matched
   neighbours' partners), ranked by the structural similarity; the reason
   is a *tie* (it shares an exact fingerprint with several), *weak*
   (structural candidates only) or *no candidate*.
5. **Address order** (BinDiff's address sequence), last: identical code
   that nothing else tells apart (the same bytes or p-code twice, a copied
   helper) pairs by place. Between two consecutive matched functions, if
   the unmatched functions in between are as many on both sides and the
   same in order, they pair in order (relation `address`, confidence 0.9:
   proposed, never applied unasked). Not without a matched function to
   count from, nor with propagation off.

**Unchanged** (the change kind) says whether the code is the same: equal
bytes at the same address (an in-place patch's untouched functions), or
equal masked bytes (F1) with every call site calling the function that
matches the one it called, so a patch that only retargets a call is a
change.

A tiny function (fewer than 5 instructions) matched by its bytes or p-code
alone, and any structural global match, stays below the auto-apply
threshold unless the call graph agrees (a caller or callee of one matched
to a caller or callee of the other): stubs returning a constant come and
go between versions, unique on each side and yet different functions.

**Decisions** (`diff.matches(session)`): accepted and applied pairs are
seeds that replace the proposals they conflict with; rejected pairs are
dropped; propagation runs again only from the functions that changed and
their neighbourhoods; functions that stay unmatched keep their candidates.
A proposal found through a pair that is later rejected stays proposed.

**Determinism**: tiers run in a fixed order, functions are visited by
entry, a round's proposals are decided together, ties are never broken.
The tests compare encoded results across 1, 2 and 8 threads.

### Confidence

Calibrated on the tuning corpus's version-diff families (a) and (e)
(below): each tier and relation has a confidence per band of the
structural similarity (at least 0.9, 0.8, 0.7, less), set at or below the
precision measured there, and a neighbourhood match is scaled slightly by
its parent pair's.

| Tier (relation) | Confidence |
| --- | --- |
| name, accepted | 1.0 |
| bytes (global) / (neighbourhood, residue) | 0.99 / 0.985 |
| p-code | 0.98 (global), 0.975 |
| shape+refs | 0.96 / 0.93 / 0.85 / 0.8 by similarity band |
| shape | 0.95 / 0.92 / 0.8 / 0.7; among callers 0.9 / 0.85 / 0.7 / 0.6 |
| refs | global 0.95 / 0.93 / 0.8 / 0.7; neighbourhoods 0.93 / 0.9 / 0.75 / 0.65; callers 0.88 / 0.85 / 0.7 / 0.6 |
| call order | 0.96 / 0.96 / 0.92 / 0.85 |
| neighbour | 0.92 / 0.9 / 0.8 / 0.6 |
| lone | 0.93 / 0.93 / 0.8 / 0.7 |
| uncorroborated tiny or structural global matches | at most 0.93 |

## Results

`scripts/diff_eval.py` matches **stripped** binaries and scores against
DWARF names of their debug twins (`rk-debuginfo`; for firmware, each
image's truth file); names occurring twice on a side are left out. A pair
counts toward precision when either function has a truth name, and is
correct when both have the same one; recall's denominator is the names
both sides have among the functions discovery found. Three source-level
renames in Lua (`lua_resetthread` → `lua_closethread`, `luaD_tryfuncTM` →
`tryfuncTM`, `luaK_exp2RK` → `exp2RK`; `corpus/diff-renames.json`) count
as the same function. *Auto* is the matches at or above 0.95, what
ApplyMarkup applies by default; *names* is ported-name accuracy: A gets
its truth names, ApplyMarkup ports them over the auto matches through the
backend, and a port is right iff B's truth has that name.

Families: (a) adjacent source versions, `out/corpus-diff` (zlib 1.2.13 →
1.3 → 1.3.1, Lua 5.4.5 → 5.4.6 → 5.4.7, cJSON 1.7.16 → 1.7.17 → 1.7.18)
on x86-64 gcc -O2, x86-64 clang -O2 and AArch64 gcc -O2; (b) -O0 against
-O2 and (c) gcc against clang, x86-64, each program's newest version,
for information; (e) the firmware corpus, same processor: fwkit -O2
against -Os (Cortex-M3 against Cortex-M4, 68020, MIPS big- against
little-endian, PowerPC, SuperH-4, ESP32, ESP8266) and U-Boot built for
two boards (STM32F429/F746, ColdFire M5208/M5373, Malta big/little
endian, MPC837x/MPC866).

| Family | pairs | common | precision | recall | F1 | auto precision | auto recall | names |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| (a) adjacent versions | 18 | 5,335 | 99.94 | 98.37 | 99.15 | **100.00** | **95.39** | 100.00 (5,069) |
| (a) x86-64 gcc -O2 | 6 | 1,807 | 99.89 | 98.67 | 99.28 | 100.00 | 96.40 | 100.00 |
| (a) x86-64 clang -O2 | 6 | 1,721 | 100.00 | 98.02 | 99.00 | 100.00 | 95.35 | 100.00 |
| (a) AArch64 gcc -O2 | 6 | 1,807 | 99.94 | 98.40 | 99.16 | 100.00 | 94.41 | 100.00 |
| (b) -O0 vs -O2 | 3 | 906 | 86.14 | 41.17 | 55.71 | 88.89 | 0.88 | 80.00 (5) |
| (c) gcc vs clang | 3 | 834 | 94.28 | 71.10 | 81.07 | 97.86 | 16.43 | 98.56 (139) |
| (e) firmware | 11 | 6,022 | 96.84 | 75.87 | 85.08 | 99.73 | 42.39 | 99.72 (2,501) |

**Gate** (`scripts/ci.sh --diff`): family (a)'s auto-applied matches need
precision ≥ 0.99 and recall ≥ 0.90; `corpus/baselines/diff.json` guards
every family's figures (0.5 points of slack).

Family (a) by tier (scored matches, precision): bytes 4,902 (100%, of
which 4,842 global), call order 78 (100%), shape 154 (98.7%), shape+refs
34 (100%), refs 34 (100%), neighbour 24 (100%), name 9 (100%), p-code 8
(100%), lone 8 (87.5%). By size (A's instructions; recall / precision):
under 10, 99.7 / 100; 10-29, 97.3 / 99.9; 30-99, 98.1 / 100; 100 and
more, 99.8 / 99.9. By change kind: unchanged functions (equal masked
bytes, 4,921) are all matched; modified ones (414) 79.0%; of the 14
functions removed and 15 added, 2 and 3 were matched to something.

Family (e) by tier: bytes 1,128 (99.6%), call order 749 (99.6%),
shape+refs 645 (98.9%), p-code 585 (99.8%), neighbour 1,084 (92.2%),
shape 234 (94.0%), refs 158 (89.9%), lone 133 (85.7%). Recall by size:
85.9 (under 10), 76.8, 73.2, 69.4% (100 and more): -O2 against -Os
inlines and reorders, which no fingerprint survives; the larger functions
are where BSim (M2) is meant to help.

**Held-out** (measured once, [heldout.md](heldout.md#binary-diffing-measured-once-diffcore);
bzip2, MuJS, SQLite and Mbed TLS versions): family (a) precision 100.00,
recall 96.94, auto precision **100.00**, auto recall **92.22**, ported
names 100.00 (15 pairs, 10,714 functions); (b) 84.81 / 25.99, (c)
91.94 / 54.77 precision / recall.

## Performance

i9-14900F (32 threads), 8 matcher threads, machine load 9 to 11 during
the runs; "features + matching" is what a run costs once discovery has
run (`rk-diff --direct`; the daemon's import does discovery).

| Pair | functions (A, B) | features | matching | target |
| --- | --- | ---: | ---: | --- |
| python3.12 vs libpython3.12.so | 11,925, 7,514 | 0.53 s | 0.28 s | **0.82 s** (10k functions: < 2 s) |
| ctest vs cpack (CMake 3.28) | 20,885, 19,522 | 1.27 s | 0.25 s | 1.52 s |
| qemu-system-i386 vs -x86_64 | 25,076, 25,093 | 1.08 s | 0.15 s | 1.23 s |
| libLLVM 19.1 vs 20.1 | 118,732, 127,008 | 8.45 s | 4.81 s | **13.3 s** (100k functions: < 30 s) |

Peak RSS of `rk-diff --direct` (discovery included): 1.0 GB for ctest
vs cpack, 5.3 GB for libLLVM. Fingerprints are 123 to 146 bytes per
function encoded (target: ≤ 200).

Interactive decisions, through the backend (`rk-diff --bench`, ctest vs
cpack): an accept commits in 0.06 ms and the next page of the table
(`diff.matches` with the decision applied) takes 51 ms; a reject 0.09 ms
and 53 ms; a rename in B 0.4 ms and 0.42 s (its fingerprints and the
proposals are recomputed); an unchanged table 1 ms. Two things make this
fast: decisions are applied to cached proposals (`refine`), and the fact
engine's **input partitions** ([facts.md](facts.md)): a memo knows which
partitions of inputs it read (assertions by fact kind, other inputs by
table), so after a Match assertion every fingerprint and discovery memo
is valid without probing its dependencies.

## For developers

| Where | What |
| --- | --- |
| `src/diff/features.{h,cc}` | `diff.features`: F0 to F4 for one function |
| `src/diff/code.cc`, `correlate.{h,cc}` | `diff.code` (a function's instruction tokens and blocks), `correlate`, `retarget`, `reference_diff`, `diff.correlation` |
| `src/backend/diff_detail.{h,cc}` | `DiffDetail` and the summary line from a correlation |
| `ui/src/diff/{aligned,graph,decomp,detail}.ts` | the aligned listings, the graph diff, the C side by side |
| `src/diff/match.{h,cc}` | the matcher (`match`, `refine`), `diff.proposals`, `diff.matches`, Match assertion values, the `SimilarityTier` registry |
| `src/analysis` | `CodeReader`: decoding a program's code through a query context (bytes become dependencies) |
| `src/backend/diff_session.{h,cc}` | sessions (`q::DiffSessions`), conversions |
| `src/backend/image_backend.cc` | the DiffService handlers, runs in the background, ApplyMarkup's plan, `QUERY_KIND_DIFF_SESSION` in commits |
| `tools/rk-diff`, `scripts/diff_eval.py` | the command line and the evaluation |
| `corpus/diff.json`, `diff-heldout.json`, `diff-renames.json` | the version corpora and their truth's renames |
| `ui/src/diff/view.ts` | the Compare view and dialogs |
| `sdk/python/revkit/diff.py` | the Python helper |

**The F5 hook.** A similarity tier implements `diff::SimilarityTier`
(`match.h`): `name()` and `score(QueryContext&, const ResidueRequest&)`,
registered with `register_similarity_tier()`. Sessions name the tiers
they run (`DiffOptions.similarity_tiers`, in the proposals' key). After
the exact tiers and propagation reach their fixpoint, the matcher passes
the unmatched functions of both sides with the prefilter's candidates
(shared buckets, neighbours of matched neighbours) and the matched pairs;
the tier returns `ScoredPair{a, b, similarity, confidence, accept}`. Pairs
it accepts (mutual best above its thresholds) that don't conflict seed
another round of propagation (tier `SIMILARITY`, relation `SIMILAR`; the
match's similarity is the tier's, BSim's cosine). Reads through the
context (its signature queries) become the proposals' dependencies, so
the result stays incremental; it must be deterministic. The hook is
called at most twice per run. The backend registers BSim's as `"bsim"`
([Signatures (F5)](#signatures-f5)).

**Evaluation and the gate.**

```sh
scripts/build-corpus.sh --diff                  # -> out/corpus-diff (pinned by corpus/diff-manifest.json)
scripts/ci.sh --diff-only                       # the gate; --diff after the other gates
python3 scripts/diff_eval.py --families a --per-pair     # tuning only: each pair's figures
python3 scripts/diff_eval.py --save-baseline corpus/baselines/diff.json   # after an intended change
```

The firmware family reads `out/firmware-corpus`
([firmware.md](firmware.md)). Held-out: `scripts/build-corpus.sh
--diff-heldout` and `scripts/diff_eval.py --heldout --families a,b,c`,
once, summary rates only ([heldout.md](heldout.md)).

## Known gaps

- **The similarity tier is opt-in** (`DiffOptions.similarity_tiers:
  ["bsim"]`, [Signatures (F5)](#signatures-f5)): without it, functions
  whose code changed beyond the neighbourhood tiers stay unmatched with
  candidates; -O0 against -O2 and gcc against clang (families b, c) are
  where this shows. Its matches are never auto-applied.
- **Instruction comments** of a pair whose code changed go to their
  instruction's partner in the instruction map (api_minor 54); a comment
  on an instruction with no partner (inserted or deleted code) stays.
- **Inside a function**: see [its gaps](#gaps-inside-a-function).
- **No stale detection** (`diff.stale`, M3): ported assertions record
  their source assertion for it.
- **MMIO addresses** aren't in the reference bags: the analysis inputs
  don't mark volatile memory, and RAM globals move between versions.
- **Runs** live in the daemon's memory: after a restart a session shows
  IDLE until run again (reads compute the matches on demand).
- **The table** loads 2,000 rows at a time (Load more), not virtualized.
- **Locals, notes and bookmarks** aren't ported; types are defined by
  hash, never bound to names (by design).
- **Body mismatches** (a function split or merged on one side) aren't
  reported as their own change kind.

## Signatures (F5)

The similarity tier over the residue (design §1 step 3, §2): BSim's
feature vectors, computed by revkit's own decompiler workers and compared
by a C++ port of BSim's comparison.

### Pieces

| What | Where |
| --- | --- |
| Worker mode `signature`: the `normalize` action group, then `GraphSigManager`; sorted u32 features, optional per-block features | `src/decompd/signature.{h,cc}`, [decompd.md](decompd.md#signatures-mode-signature) |
| The signature input profile: what a signature bundle is told (no names, types, prototypes or comments beyond imports' library prototypes; analysis's no-return set) | `src/inputs/profile.{h,cc}` |
| `diff.signature(program, entry[, settings])`, memoized; `diff.signature_inputs` (per-address slices under the profile); `SignatureJob` (background, cancellable) | `src/backend/signatures.{h,cc}` |
| BSim's cosine and significance (`LSHCosineVector`, `WeightFactory`, `IDFLookup`, `calculateSignificance`), weight tables chosen as `GenSignatures.getWeightsFile`, idf re-derivation | `src/diff/lsh.{h,cc}`, `third_party/bsim` |
| The residue matcher: mutual best, thresholds, hints | `src/diff/residue.{h,cc}` |
| `rk-lift --signatures`, `rk-sigdiff stability / derive-idf` | `tools/` |
| Ghidra's reference (fixtures, Ghidra's vectors), the stability study | `scripts/diff-bsim-reference.py`, `scripts/diff-signature-stability.py` |

### Signatures as queries

`diff.signature` reads `analysis.function` (the body), the FLOW_OVERRIDE
assertions in the body, `inputs.image`, `decompiler.options` (the
decompiler build) and `diff.signature_inputs` for every address the
decompiler asked. It never reads names, types, comments or the debug
info's prototypes: a rename, a retype or a comment recomputes no signature
(the backend test checks the rule counters), and a debug build signs as
its stripped twin. It is computed only when asked (lazily: a diff asks for
its residue), or ahead of time by a `SignatureJob` over a snapshot (its own
threads, each run in a worker; `cancel()` stops runs in flight through
`DecompileLimitsScope`, and a cancelled computation throws instead of being
memoized). Values are the same at any thread count and equal to rk-lift's
batch (`decompd::signature_functions`), which the tests check; the
`rk_lift_signatures` test compares `-j 1` and `-j 8` on all of Lua.

Settings: `0x49` for 32- and 64-bit languages (the weights files'), `0x4d`
with `lshweights_nosize.xml` when the two programs' pointer sizes differ
(`weights_for`). Measured on the tuning corpus, `0x4d` everywhere is no
better (top-1 within ±0.7 points per family).

### Comparison: bit-for-bit Ghidra's

`src/diff/lsh.cc` ports the Java (Ghidra 12.1.4, `Generic`'s
`generic.lsh.vector`) with Java's rounding (`-ffp-contract=off`, the same
operation order). `scripts/diff-bsim-reference.py fixtures` runs Ghidra's
Java headlessly on 720 vector pairs (real cJSON vectors, both ISAs, and
synthetic ones: repeats past the tf cap of 64, hashes from the idf table,
`0x80000000`/`0xffffffff`, empty vectors) for each of the four weight
tables; `lsh_test` requires the same IEEE bits for cosine, significance,
dot product, intersection count and self-significance (NaN for two empty
vectors, as in Java). All match. And `rk-sigdiff stability` over Ghidra's
own vectors reproduces the design's table exactly (Lua 78.5% top-1,
205/247 in the 10-29 bucket, ...).

### Stability: revkit's vectors against Ghidra's

The design's measurement (§0) recomputed with revkit's own F5: `rk-lift
--analyze --signatures` on each debug build of the tuning corpus (revkit's
discovery and inputs under the signature profile), compared with the C++
comparison (`scripts/diff-signature-stability.py`). Top-1 is strict (ties
lose) among all of B's functions, from the body alone; names are the truth.

| program pair | common fns | median cos | top-1 revkit | top-1 Ghidra | revkit top-1 by features <10 / 10-29 / 30-99 / ≥100 |
|---|---:|---:|---:|---:|---|
| cjson x86-64 gcc-O0 vs clang-O0 | 123 | 1.00 | 56.9% | 59% | 12/33, 25/55, 30/32, 3/3 |
| cjson x86-64 gcc-O2 vs aarch64 gcc-O2 | 95 | 0.72 | 45.3% | 46% | 4/18, 8/35, 25/36, 6/6 |
| cjson x86-64 gcc-O2 vs clang-O2 | 94 | 0.50 | 41.5% | 44% | 5/19, 9/35, 19/34, 6/6 |
| cjson x86-64 gcc-O0 vs gcc-O2 | 94 | 0.22 | 29.8% | 32% | 5/27, 6/44, 15/21, 2/2 |
| zlib x86-64 gcc-O2 vs riscv64 gcc-O2 | 141 | 0.62 | 75.2% | 73% | 4/20, 25/29, 52/64, 25/28 |
| zlib x86-64 gcc-O2 vs clang-O0 | 141 | 0.49 | 68.8% | 73% | 6/23, 18/29, 48/61, 25/28 |
| lua x86-64 gcc-O2 vs aarch64 clang-O2 | 624 | 0.58 | 77.1% | 78.5% | 51/107, 193/238, 187/226, 50/53 |

By family (functions-weighted top-1; residue = `match_residue` over every
pair with the design's thresholds, mutual best, cosine ≥ 0.35,
significance ≥ 10):

| family | pairs | functions | top-1 revkit | top-1 Ghidra (debug) | top-1 Ghidra (stripped) | residue precision / recall, revkit |
|---|---:|---:|---:|---:|---:|---|
| (b) -O0 vs -O2 | 8 | 503 | 44.3% | 46.1% | 45.9% | 93.1% / 26.6% |
| (c) gcc vs clang | 8 | 697 | 70.1% | 71.5% | 71.6% | 97.7% / 61.7% |
| (d) x86-64 / AArch64 / RISC-V | 15 | 1,189 | 77.2% | 77.8% | 77.3% | 98.0% / 61.6% |
| design table | 7 | 1,312 | 65.9% | 67.3% | 66.3% | 96.4% / 53.5% |
| (e) firmware: fwkit across 7 processors, same -O | 42 | 22,506 | 71.8% | (no Ghidra vectors) | | 97.5% / 51.9% |

(b)-(d) are cJSON and the `features` program over every configuration
pair the corpus has, plus zlib cross-ISA; (e) is fwkit built for
Cortex-M, m68k, MIPS, PowerPC, SH-4 and two Xtensa cores at -O2 and at -Os,
the 21 cross-processor pairs at each level (raw images; DWARF names from
the matching ELF as truth). Per pair, (e) ranges from 56% (m68k vs SH-4,
-Os) to 85% (MIPS vs PowerPC).

**Risk 1 (stripped bundles differ from Ghidra's): measured.** revkit's
vectors equal Ghidra's for 98% of functions on x86-64 and AArch64 against
Ghidra's analysis of the stripped twins (89% without import prototypes:
the gap was imports' library prototypes, which the profile now keeps since
they are a function of the import's name and never churn). Ghidra's debug
info barely moves its own numbers (stripped vs debug within 1 point).
What remains is 0-2 points of top-1 per family, mostly one or two functions
per small pair: revkit's discovery finds a few more functions (more
distractors in B: `.cold` parts), and on RISC-V the debug builds'
`__global_pointer$` gives revkit (and Ghidra's debug analysis) `gp`, which
Ghidra's stripped analysis lacks (one extra feature in every function).
Without import prototypes revkit loses another 1-2 points in (b) and (c).

**idf re-derivation (design §7 M4): no gain.** revkit's hashes hit BSim's
idf table as often as Ghidra's own (Lua: 45.5% of feature occurrences
against 44.5%). Tables re-derived from revkit's tuning vectors
(`derive_idf`: the 1000 hashes in most functions, each given the count
whose weight on BSim's curve is -log2(p)/-log2(p_1000)), evaluated
leave-one-program-out (each program scored with a table from the others;
firmware with a 32-bit table from the U-Boot images, which no pair uses),
move top-1 by -0.3 to +0.6 points and lower residue recall by 2-4 points
(significance shifts; its model was fitted with BSim's table). revkit
keeps BSim's tables.

### The residue matcher

`diff::match_residue(a, b, candidates, hints, weights, options)` is a pure
function over feature vectors: for each function of A its candidates in B
(the prefilter's top-K; or, with no prefilter, every function sharing a
hash) are scored with cosine and significance; a pair is accepted when it
is the strict mutual best (A's best candidate is B and B's best scorer is
A; a tie at the top is never broken by score) and cosine ≥ 0.35 and
significance ≥ 10, or when a hint (a propagation edge) names it and it
clears 0.2 / 0. A hint also breaks a tie between the pairs it names, and
brings in a pair the prefilter missed. Each pair carries its evidence:
both scores, the runner-up on each side (the margin), how many pairs were
scored on each side, and the hint kinds; `scored` lists every function's
best candidates for the UI. Deterministic for any input order.

Over every pair of the families above, F5 alone (every function of A
against all of B) accepts 26-62% of the common functions at 93-98%
precision; by cosine band, 96.2% (0.35-0.5), 97.0% (0.5-0.7), 98.3%
(0.7-0.95) and 99.3% (≥ 0.95), but 95.6% at ≥ 0.95 across -O levels.

### In the matcher

The matcher's residue hook (`SimilarityTier`, `ResidueFn`) calls
`diff::score_residue(request, fetch, weights)`: the residue's vectors
(fetched only for the functions still unmatched after the exact tiers and
propagation), `match_residue` over every pair sharing a hash when the
residue has at most 25M pairs (the prefilter's top-16 candidates above
that), `call_graph_hints` (a matched pair's lone unmatched caller on each
side corroborates their pairing), and `residue_confidence`: per cosine
band, from the precision measured below (0.94, 0.90, 0.85, 0.75; 0.70 for
a hinted pair under 0.35), so F5 alone never reaches the auto-apply
threshold (0.95) and asks for acceptance. Accepted pairs seed another round
of propagation.

- **Daemon:** the backend registers a `"bsim"` tier; a session created
  with `DiffOptions.similarity_tiers: ["bsim"]` reads its residue's
  `diff.signature`s through the query context (in parallel on the engine's
  pool; they become the matches' dependencies, so a re-diff after an edit
  re-signs nothing that didn't change). Programs of different pointer
  sizes are signed with `0x4d` and compared with `lshweights_nosize.xml`.
  `SignatureJob` can sign a program ahead of a diff in the background.
- **CLI:** `rk-diff --similarity bsim A B` signs the residue lazily in
  workers (revkit's own inputs under the signature profile) and matches
  directly; `scripts/diff_eval.py --similarity bsim` scores it.

End to end (`scripts/diff_eval.py --families a,b,c,d,e,f`, stripped
binaries, DWARF truth; precision / recall / F1 in %, auto-applied
precision / recall unchanged by F5 since it is never auto-applied):

| family | pairs | common | without F5 | with F5 | F5's own matches (precision) |
|---|---:|---:|---|---|---|
| (a) adjacent versions | 18 | 5,335 | 99.94 / 98.37 / 99.15 | 99.94 / 98.63 / 99.28 | 14 (100%) |
| (b) gcc -O0 vs -O2 | 3 | 906 | 86.14 / 41.17 / 55.71 | 85.74 / 60.38 / 70.85 | 175 (87.4%) |
| (c) gcc vs clang -O2 | 3 | 834 | 94.28 / 71.10 / 81.07 | 92.31 / 79.14 / 85.22 | 74 (85.1%) |
| (d) x86-64 vs AArch64 | 3 | 906 | 99.50 / 87.20 / 92.94 | 99.52 / 92.49 / 95.88 | 46 (100%) |
| (e) firmware, same processor (O2/Os, two U-Boot boards) | 11 | 6,022 | 96.84 / 75.87 / 85.08 | 94.38 / 87.55 / 90.83 | 752 (84.3%) |
| (f) firmware across processors (fwkit -O2, 21 pairs) | 21 | 10,213 | 94.76 / 46.08 / 62.01 | 94.28 / 76.03 / 84.18 | 2,540 (95.8%) |

The same figures come out of both paths: `rk-diff` through the backend
(DiffService, the `"bsim"` tier over `diff.signature`) and `--direct`
(the batch signer), which is also a check that the daemon's signatures are
the batch's. F5 raises F1 in every family (+15 points in (b), +22 in (f)) at a cost of
up to 2.5 points of precision where the residue is hardest (Os vs O2
firmware, compilers). Its own matches by cosine band, over the residue
(harder than F5 over everything): ≥ 0.95: 98-100%; 0.7-0.95: 88-100%;
0.5-0.7: 82-100%; 0.35-0.5: 72-100%, the low ends in (b), (c) and (e);
`residue_confidence` follows these. Signing the residues of all 59 pairs
took 250 s in all (single pairs: Lua -O0 vs -O2, 28 s, of which one
function, the -O0 interpreter loop, takes 17 s: a decompilation of it
takes 23).

### Cost

Per function about 75% of a decompilation in the worker: Lua 2.8 ms, zlib
3.5 ms; at 8 workers 790 and 630 functions/s; libLLVM (127k functions)
in 478 s at 8 workers (265/s, against 1,957 s for its full decompile),
9 failures, peak 6.3 GiB with the workers ([decompd.md](decompd.md#signatures-mode-signature)).
A vector costs 4 bytes per feature (median about 25-45 features; libLLVM
averages 120).

### Held-out (measured once)

The stability measurement on the held-out programs (bzip2, Mbed TLS, MuJS,
tcc; `diff-signature-stability.py --heldout --families b,c,d`, summary
rates only, nothing tuned on them):

| family | pairs | functions | top-1 | residue precision / recall |
|---|---:|---:|---:|---|
| (b) -O0 vs -O2 | 14 | 4,459 | 30.8% | 91.0% / 13.5% |
| (c) gcc vs clang | 14 | 5,303 | 61.0% | 97.8% / 52.0% |
| (d) x86-64 / AArch64 / RISC-V | 27 | 10,644 | 67.5% | 99.5% / 57.9% |

Larger programs than the tuning set's (more functions in B to confuse a
function with), so top-1 is lower; precision holds.

## Inside a function

Design §3 (M3): which blocks and instructions of a matched pair
correspond, and what changed. `src/diff/correlate.h`.

### The instruction map

`diff.code(program, entry)` (a query per function, memoized) describes
each instruction by two tokens and cuts the function into basic blocks as
`GetFunctionGraph` does (calls don't end blocks, calls to no-return
functions do):

| Token | What it hashes | Equal for |
| --- | --- | --- |
| `kind` | the raw p-code's opcodes with each operand's kind (constant, register, unique, memory) and size; no constants, registers or addresses (F2's tokens without values) | the same instruction with other operands (`#4` / `#9`, another register) |
| `exact` | the bytes with every field that holds an address outside the function or a branch target inside it masked (F1, per instruction), and what external targets are (a function, an import by name); the p-code with its non-address constants where the field isn't byte-aligned (ARM's `bl`) | the same instruction, wherever the code moved |

A data address the bytes don't hold (a register's value analysis knows)
is left out: what analysis infers must not make code compare different.

`correlate(a, b)` ports the idea of Ghidra's
`HashedFunctionAddressCorrelation` to those tokens:

1. **Unique n-grams.** Windows of n consecutive instructions within a
   block, n from 16 down to 1, first on `exact` then on `kind`: a hash
   that occurs exactly once on each side matches its n instructions. Each
   pass extends the matches forward and backward along their blocks while
   the tokens agree.
2. **Blocks** pair one to one by those matches (most first), then the
   entries, then through matched neighbours: a pair's unpaired successors
   (and predecessors) of the same edge kind pair when they are one on each
   side and resemble each other (a third of their kinds in common), or,
   when there are several (a switch's cases), by content unique among them
   and then in order; finally identical blocks nothing else tells apart
   pair in address order. A block split or merged on one side stays with
   the block its matches lead to (a cluster).
3. **Alignment.** Within each cluster, instructions align by LCS (the
   common prefix and suffix first; patience anchors past 4M cells): equal
   `exact` tokens are EQUAL; in the gaps, equal `kind` tokens are CHANGED;
   what's left of a gap pairs in order as CHANGED (one instruction replaced
   by another, `add` by `bl`), the rest is INSERTED (B) or DELETED (A). A
   branch within the function is EQUAL only if it leads to instructions
   that correspond.
4. **Lines.** Corresponding instructions in an order both sides agree on
   (the longest increasing run) share a line; the others are *moved* and
   get lines of their own. Differences (*hunks*) are runs of lines that
   aren't both EQUAL and in place.

Nothing assumes equal addresses: code that moved correlates the same.
Every step is ordered by instruction and block indexes, so the result is
deterministic. `diff.correlation(A, a, B, b)` memoizes it per pair (it
depends only on the two `diff.code` values); a read then applies the
session's matches (`retarget`: an EQUAL call or jump out whose targets
don't match each other becomes CHANGED; a target without a match must be
the same address) and lists the references gained and lost
(`reference_diff`: calls by their match, strings by content, other data by
address, from CHANGED, INSERTED and DELETED instructions only, a reference
both sides make cancelling out).

**Block statuses**: UNCHANGED when every instruction is EQUAL with its
partner in the partner block, both ways; MODIFIED when some instruction
corresponds; ADDED (B) or REMOVED (A) when none does.

**Summary line** (`DiffChangeSummary.text`): the counts, and the
instructions themselves when there are at most three ("1 instruction
changed: sub r0,r0,#0x7 → bl FUN_00000400 (new)", a callee only B has
marked *new*), else the calls gained and lost; blocks added and removed.

### Cost

`rk-diff --changes` on version pairs of the tuning corpus (x86-64 gcc -O2,
i9-14900F, cold: `diff.code` of both functions included): Lua 5.4.6 →
5.4.7, 51 modified pairs, correlation median 0.34 ms, p95 1.4 ms, max 18
ms; the whole `GetFunctionDiff` detail (rows, names, summary) median 1.9
ms, p95 4.9 ms, max 58 ms. zlib 1.3 → 1.3.1: 2 pairs, 0.9 ms. A generated
12,200-instruction function (2,000 blocks, `cc -O0`, 18 constants changed,
5 statements inserted, 3 removed): 50 ms cold (decoding 24,000
instructions), 0.7 ms memoized; the detail travels in 200 to 390 ms as
JSON. A second read of a pair costs only the rows and the summary.

### Tests

`src/diff/tests/correlate_test.cc` builds functions by hand for each kind
of change: identical (moved), an immediate changed, an instruction
replaced, a call inserted, blocks swapped in memory, a block split, a
block removed and another added, identical twin cases of a switch, calls
retargeted with and without matching targets, determinism and the
encodings. `diff_test.cc` correlates real code: two compiled versions of
a program where everything moved (unchanged functions EQUAL everywhere,
the added case INSERTED, the calls gained and lost), and an in-place
patch of the ARM firmware fixture (one instruction of `h2` turned into a
BL to new code written over data: exactly that instruction is CHANGED, in
that function only, and the reference diff names the unmatched callee).
`diff_api_test.cc` checks the API (lines cover every row once, partners
on one line, one-to-one block partners, summaries); the UI's e2e patches
the same firmware in two functions and checks the highlighted rows, the
count, next and previous difference, the graph's colours and the C.

### Gaps inside a function

- **Literal pools**: a constant loaded from a pool the function reads
  (ARM's `ldr r0, =value`) that changed doesn't change the instruction;
  the pool isn't part of the instruction map (data the code reads isn't the
  code, as for the change kinds).
- **Padding** inside a body (NOPs between blocks) counts as instructions:
  a version diff that pads differently shows inserted NOPs.
- **Cross-ISA** pairs correlate by `kind` tokens only, which differ
  between ISAs: expect blocks to pair through the CFG and instructions to
  align positionally.
- There is no stale detection (`diff.stale`).

## Comparing two functions

api_minor 54, feature `function-compare`. Ghidra's Function Comparison
window, on revkit's instruction map: any two functions of a project, in
one program or two, with or without a session, and markup carried from
either to the other.

### Using it

- **UI** ([ui.md](ui.md#compare-two-functions)): Compare with… (a
  function's context menu, the function list's, the palette), or two
  functions marked in the function list; the Listing, Graph and C panes
  of the Compare view show the pair. The C pane's token menu applies a
  variable's name or type, the function's name or signature, a global's
  name or type, a callee's name or signature, or a comment to the other
  side; Apply all carries everything someone set.
- **Python**:

```python
c = rk.compare_functions("default/v1", 0x401136, "default/v2", 0x401146)
print(c.detail.summary.text)                     # "3 changed, 1 inserted; ..."
for v in c.markup.variables:                     # a's and b's CompareVariable
    print(v.a.name, v.b.name, v.evidence)        # "count param_1 parameter 1"
r = rk.port_function_markup("default/v1", 0x401136, "default/v2", 0x401146,
                            items=["name", "signature", ("variable_name", "stack:-0x14")])
print(r.names, r.signatures, r.variable_names, r.seqs)    # retract seqs to undo
s.port(a, b, reverse=True, overwrite=True)       # through a session's match, B to A
```

- **MCP**: `compare_functions`, `port_function_markup`,
  `diff_port_function` (from a match), `diff_set_match`, `diff_unmatch`.

### The API

| RPC | What |
| --- | --- |
| `CompareFunctions{program_a, entry_a, program_b, entry_b, session_id?, markup}` | both summaries and `DiffDetail` as `GetFunctionDiff` gives them; with a session its matches retarget calls and `match` is the pair's; without, calls correspond by address in one program and by unique non-default names across two (and the pair itself, for recursion). With `markup`, `CompareMarkup`: both signatures and whether someone set them, the variables (`CompareVariablePair`: storage key, name, type, kind, parameter index, `named`, `typed` on each side; the evidence and votes), the comments of either side with their place on the other |
| `PortFunctionMarkup{from_*, to_*, items, overwrite, dry_run, session_id?}` | one revision on the target, by the caller (provenance user or agent, not `migration`: it is an explicit edit), each assertion with `ported_from` (source program, function, address, source assertion; the session and the pair's Match when given). Response: counts, `ported` (each item's target, before and after), `warnings`, `seqs` |
| `Unmatch{session, pairs}` | retracts the pairs' accepted, applied or rejected Match assertions in one revision (`seqs`: the retractions) |
| `AcceptMatches`, `RejectMatches`, `SetMatch` | now return `seqs`: every op of the decision's revision, so a client undoes it in one step |

`FunctionMarkupItem.kind` is `NAME`, `SIGNATURE`, `VARIABLE_NAME`,
`VARIABLE_TYPE` (with the source variable's storage key, or every
paired variable), `COMMENT` (an address and kind, or every comment), or
since api_minor 71 (feature `port-globals-callees`) `GLOBAL_NAME`,
`GLOBAL_TYPE`, `CALLEE_NAME` and `CALLEE_SIGNATURE` (a source global's
address or a source callee's entry, or every one that pairs).

**Globals and callees** pair through the instruction map. For each pair
of corresponding instructions, their data references (reads, writes,
pointers, to what isn't a function) pair in operand order when both
instructions have as many, and so do their calls. A source address that
pairs with two different targets is left out. A global's name and its
type (the TYPE assertion someone made, or debug info's), and a callee's
name and its asserted prototype, then port as the function's own do: over
default names and unset types without `overwrite`, with the types they
use defined in the target. `PortFunctionMarkupResponse.globals` and
`callees` count them. Default names on either side are data's
(`DAT_`, `PTR_`, `s_`, ...) as well as functions'. Data references come
from the p-code, direct memory operands included (x86-64's
read-modify-write `add [rip+x],ecx` reads and writes `ram:x`; flow
analysis version 19).
With no items, everything *someone set* on the source goes: its name
unless a default one, its signature unless the decompiler's guess, the
variables that are named (asserted, or debug info's: not `param_1`,
`local_14`, `uVar2`, `pNVar4`, `auStack_28`, `in_RAX`, ...) with their
types, every comment. Without `overwrite` the target keeps its own:
names only go over default names, signatures and types over the
decompiler's guesses, comments where the target has none of that kind. A
name another variable of the target has is refused with a warning. Types
a signature or a variable's type uses are defined in the target by hash
(their closure), as ApplyMarkup does.

### Pairing variables

`PairVariables` (`src/backend/function_compare.{h,cc}`, over the two
decompilations as the API returns them):

1. **Parameters** pair by position.
2. **Votes.** For each pair of corresponding instructions (the instruction
   map's EQUAL and CHANGED pairs), the variables the tokens printed from
   them name, in order, vote pairwise when both sides print as many; for
   each pair of C lines aligned by LCS that read the same with variables
   and default symbols abstracted (and print something from an
   instruction: declarations don't vote), the variables in the same places
   vote. Locals pair with locals, parameters with parameters.
3. **Mutual strict best**, repeatedly over what is left: a tie pairs
   nothing. Deterministic.

A debug build against its stripped twin pairs every parameter and the
locals the decompiler keeps alike; across -O levels the parameters pair
and locals pair only where the code is still alike.

### Manual matching

The Compare view's m (match by hand, `SetMatch`), u (`Unmatch`), a and r,
a row's context menu and the candidates' buttons in *Only in A/B*. A
decision is a revision of Match assertions in B; its `seqs` are what Ctrl+Z
(when B is the tab's program) or the toast's Undo retracts. Unmatching an
applied pair kills what was ported through it (its assertions depend on
the Match).

### Demonstration

`out/corpus` x86-64 builds, through an `rk-daemon` (scripted with the
SDK; names checked against the debug build at the same addresses):

| Pair | functions A / B | matched | names ported | right |
| --- | --- | ---: | ---: | ---: |
| Lua gcc -O2 debug vs stripped | 786 / 786 | 786 (780 at ≥ 0.95, 786 unchanged) | 693 (≥ 0.95) | 693 |
| cJSON gcc -O0 debug vs gcc -O2 stripped, with BSim | 139 / 112 | 42 (17 at ≥ 0.95) | 25 (every match) | 21 |

One function each, `PortFunctionMarkup` with nothing asked (everything
someone set): Lua's `luaH_resize` (the same code): 22 variables paired (4
parameters), its signature, 4 parameter names and 3 types ported with the
124 types they use, 132 assertions in one revision; B's decompilation then
reads `void luaH_resize(lua_State *L,Table *t,uint newasize,uint nhsize)`.
cJSON's `cJSON_ParseWithLengthOpts` (-O0 against -O2: 25 instructions
changed, 92 inserted, 82 deleted): 6 variables paired (the 4 parameters),
its signature and 4 parameter names ported; B reads `cJSON *
cJSON_ParseWithLengthOpts(char *value,size_t buffer_length,char
**return_parse_end,cJSON_bool require_null_terminated)`.

### Tests

`src/backend/tests/function_compare_test.cc` (pairing by hand-built
decompilations: positions, votes, ties, determinism; default names),
`diff_api_test.cc` (`CompareAnyTwoFunctions`,
`PortFunctionMarkupItemsAndEverything`, `PortFunctionMarkupGlobalsAndCallees`,
`ApplyPortsInstructionCommentsByAlignedInstruction`,
`UnmatchAndUndoingDecisions`), `sdk/python/tests/test_diff.py`,
`test_mcp_tools.py`, and the UI's `ui/e2e/compare.ts` (Compare with… from
the function list, the C pane's apply and its Undo, Apply all (with the global the function uses), the
function list's marked pair, m and u in a session's table).

### Gaps

- Two functions at a time; no comparing callees from a call row.
- Globals and callees pair only by references from corresponding
  instructions: one whose reference moved to an inserted instruction
  doesn't pair (the session's ApplyMarkup ports callees that are matches).
- Locals pair only through the decompilations: code the compiler
  rearranged (another -O level) pairs its parameters and few locals.
