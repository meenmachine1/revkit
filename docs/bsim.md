# BSim signature databases

A BSim database is a persistent store of executables' functions and their
BSim feature vectors, for finding functions similar to a given one across
every program ingested: a library you built with symbols, older releases
of a product, a malware family. It is revkit's counterpart of Ghidra's
BSim databases (H2, PostgreSQL, Elasticsearch), as a directory of files
any tool can read: the daemon (`BSimService`), `rk-bsim`, the SDKs.

- [What is stored](#what-is-stored)
- [Vectors and similarity](#vectors-and-similarity)
- [The LSH index](#the-lsh-index)
- [The files](#the-files)
- [rk-bsim](#rk-bsim)
- [In the daemon](#in-the-daemon)
- [Searching](#searching)
- [Evaluation](#evaluation)
- [Differences from Ghidra's BSim](#differences-from-ghidras-bsim)

## What is stored

Per executable (one per binary, keyed by the file's sha256: ingesting
the same file again replaces it): its name, the path it was ingested
from, its language and compiler specification, when and what ingested it
(`rk-bsim`, `daemon:<program id>`), and categories (name → value, as
Ghidra's executable categories: `vendor=acme`, `build=gcc-O2`).

Per function: its name (`FUN_…` names are flagged default, so a search
can leave them out and nobody applies them), entry, prototype as C when
one is known (debug info, the user's, an import's, parameter ID; the
decompiler's own isn't computed for this), body size in bytes, and its
feature vector. Thunks, externals and functions the decompiler failed on
are left out (each ingest reports how many and why).

## Vectors and similarity

A function's features are the 32-bit hashes the decompiler's
`GraphSigManager` emits over its normalized data-flow graph and control
flow (decompd's signature mode; `docs/decompd.md`), under the signature
profile (`docs/diff.md` F5): no names, types or prototypes beyond
imports', so a stripped binary signs as its debug twin and renaming
anything changes no vector. They are bit for bit what Ghidra's BSim
computes for the same function from the same decompiler inputs
(`src/diff/lsh.h`; `lsh_test` checks against vectors Ghidra produced).

Similarity is BSim's cosine of the tf-idf-weighted vectors; confidence is
BSim's significance (the dot product less a penalty for the hashes that
differ, under BSim's model of how hashes flip, appear and vanish between
versions). The weights are the database's template's table:

| template | Ghidra's | settings | for |
| --- | --- | --- | --- |
| `64` | `medium_64` (`lshweights_64.xml`) | 0x49 | 64-bit programs |
| `32` | `medium_32` (`lshweights_32.xml`) | 0x49 | 32-bit programs |
| `nosize` | `medium_nosize` (`lshweights_nosize.xml`) | 0x4d | programs of different pointer sizes |

Every function in a database is signed with its template's settings; an
ingest whose program has another pointer size says so (a `nosize`
database suits a mix).

## The LSH index

Each vector is hashed at ingest into `l` buckets (one per table) of `k`
bits: bit *b* of table *t* is the sign of the weighted vector's
projection on a pseudo-random ±1 hyperplane derived from (seed, *t*, *b*,
feature hash) (SimHash). Two functions of cosine *c* share a table's
bucket with probability (1 − acos(*c*)/π)^*k*: with the defaults (k 10,
l 64) a pair at cosine 0.7 meets in some table with probability 0.97, a
pair at 0.5 with 0.67, unrelated functions (cosine ≈ 0) in about 6% of
cases. A search scores the functions that share a bucket with the query
in any table, exactly (cosine and significance); a database of at most
50,000 functions is scored whole instead (about a microsecond per
function), so low similarities aren't missed.

## The files

```
NAME.rkbsim/
  database.json        format, name, description, template, settings, lsh {k, l, seed}, created
  exe/<sha256>.rkbx    one executable: metadata and functions
  lock                 writers flock it while they write
```

An `.rkbx` is `RKBSIMX\0`, the format version and table count (u32 LE
each), a length-prefixed JSON header (the executable's metadata), then
the functions: name, entry, prototype, size and flags (varints and
length-prefixed strings), the feature count and the sorted features as
deltas (varints), and the `l` buckets (u32 each). A writer writes the
whole file to a temporary name and renames it, so readers see a file
whole or not at all; readers load every executable when they open the
database and pick up others' writes with a reload (the daemon reloads
before each request; only changed files are read again). Files are read
as hostile: every count and length is checked against what remains, and
a damaged file is an error naming it.

## rk-bsim

```sh
rk-bsim create zlib.rkbsim --template 64 --description "zlib releases"
rk-bsim ingest zlib.rkbsim out/zlib-1.3/libz.so out/zlib-1.2.13/libz.so --category vendor=madler
rk-bsim info zlib.rkbsim
rk-bsim list zlib.rkbsim [--json]
rk-bsim functions zlib.rkbsim libz.so --name inflate [--json]
rk-bsim set zlib.rkbsim 1b3d4c1fcbb3 --name zlib-1.3 --category build=gcc-O2
rk-bsim delete zlib.rkbsim zlib-1.3
rk-bsim query zlib.rkbsim mystery.bin [--function inflate|0x401000]... [--min-similarity 0.7] [--max 10] [--json]
```

An executable is named by its sha256, a unique prefix of it (6+ hex
digits) or its unique name. `ingest` imports each file into an in-process
backend, the daemon's (the same discovery, analysis, signatures, names
and prototypes as a project's ingest), with `-j` decompiler workers,
`--lang` to force a language, `--ghidra` for the processor specs
(`docs/ghidra.md`). `query` imports a file the same way and searches the
database for its functions (all, or those `--function` names): the
thresholds and filters below (`--min-similarity`, `--min-confidence`,
`--max`, `--exe`, `--not-exe`, `--name`, `--category`,
`--no-default-names`, `--include-self`), `--exhaustive` or
`--index-only`, `--overview` for counts only, `--json` for scripts.

## In the daemon

`BSimService` (`proto/revkit/v1/bsim.proto`; `api_minor` 69, feature
`bsim`). A project attaches databases (a note, `revkit:bsim.databases`,
so attaching is an undoable, replicated edit); every other call names an
attached one by its id, its path.

| call | does | role |
| --- | --- | --- |
| `CreateBSimDatabase{path \| name, template, description, lsh_k, lsh_l}` | creates and attaches: at `path` (a new directory on the daemon's host), or `bsim/<name>.rkbsim` in a persistent project's directory | edit (admin for a path) |
| `AttachBSimDatabase{path}` / `DetachBSimDatabase{database}` | the project's list; detaching leaves the files | admin / edit |
| `ListBSimDatabases` | the attached ones, sizes, or why one can't be opened (`error`) | view |
| `IngestBSim{database, program_ids, categories, threads}` | signs every function of each program (the work a diff shares: `diff.signature` memos) and stores it as one executable; per program what was stored and left out | edit |
| `ListBSimExecutables{database, filter, language}`, `ListBSimFunctions{database, executable, name_contains, offset, limit}` | what is stored | view |
| `UpdateBSimExecutable{database, executable, name, categories}`, `DeleteBSimExecutables{database, executables}` | rename, categorize, delete | edit |

Python (`Client`): `bsim_databases()`, `create_bsim_database(name, path=,
template=)`, `attach_bsim_database(path)`, `detach_bsim_database(db)`,
`bsim_ingest(db, program_ids, categories=)`, `bsim_executables(db)`,
`bsim_functions(db, exe)`, `update_bsim_executable(db, exe, name=,
categories=)`, `delete_bsim_executables(db, exes)`. TypeScript:
`rk.bsim.*`. MCP: `bsim_databases` (with each database's executables),
`bsim_ingest`.

## Searching

`SearchBSim{database, program_id, functions | all_functions, ...}`
(`api_minor` 72, feature `bsim-search`) signs the program's functions
(the given ones, by entry or by an address inside; or all with a body)
under the database's settings and searches each:

- **Thresholds**: `min_similarity` (cosine; default 0.7, Ghidra's),
  `min_confidence` (significance; default 0), `max_matches` per function
  (default 10).
- **Filters**: `executables` (ids, id prefixes or names: only those),
  `exclude_executables`, `languages` (prefixes), `name_contains`,
  `categories` (all must match), `exclude_default_names` (no `FUN_…`
  matches: nothing to learn from them). The query's own file (by sha256)
  is left out unless `include_self`.
- **Overview** (`overview`): each function's `hit_count` and no matches,
  Ghidra's overview query.
- Each result has the function's feature count and self-significance (how
  much any match can mean: tiny functions say little and match many),
  `hit_count` (before `max_matches`) and the matches, best first:
  executable, function (name, entry, prototype, size), similarity,
  confidence, and `program_id` when the matched file is a program of the
  project (by sha256), for Compare and porting markup.
- Every function of the database is scored while queries × database
  stays near 2·10⁷ pairs (`exhaustive` forces it); beyond, the LSH
  index's candidates (`index_only` forces that).

The UI's **BSim** view (palette "Show BSim"; [ui.md](ui.md#bsim)) and
**Find similar functions (BSim)** in the listing's Function menu, the
decompiler's menu and the function list's menu search the function at
the cursor; All functions and Overview search the program. Python
`Client.bsim_search(db, program_id, functions, ...)` and
`Program.bsim_search(db, ...)`; MCP `bsim_search` (an address, or
`all_functions`) and `bsim_overview`.

## Evaluation

`scripts/bsim-eval.py` measures the whole path (ingest, signing, search)
on the diff corpus (`out/corpus-diff`): a reference database of gcc -O2
debug builds of zlib 1.3.1, Lua 5.4.6 and cJSON 1.7.18 (943 functions),
queried with *stripped* builds that differ by compiler, optimization
level, architecture or version; every query function is searched against
the whole database (the other programs are distractors). The truth is the
name the query's debug twin gives the function at the same entry; counted
are the functions with a non-default name that the reference build also
has. Top-1 is correct when the best match has the true name (strict:
and no other name ties it; tiny functions often have identical vectors).
Precision is over the functions whose top-1 passes the threshold, recall
over all counted.

| query builds | functions | top-1 (strict) | precision / recall @0.5 | @0.7 | @0.9 | @0.7, confidence ≥ 10 |
| --- | ---: | ---: | --- | --- | --- | --- |
| clang -O2 | 852 | 72.9% (69.4%) | 76.9% / 50.1% | 81.5% / 31.6% | 77.4% / 20.1% | 85.2% / 30.5% |
| gcc -O0 | 924 | 60.7% (58.5%) | 80.6% / 32.4% | 78.9% / 17.0% | 70.9% / 10.3% | 84.6% / 16.0% |
| AArch64 gcc -O2 | 924 | 85.6% (81.6%) | 87.4% / 76.8% | 87.0% / 58.1% | 82.9% / 33.0% | 89.5% / 57.3% |
| older version (zlib 1.3, Lua 5.4.5, cJSON 1.7.17) | 932 | 90.1% (85.7%) | 90.1% / 90.1% | 90.1% / 90.0% | 90.1% / 90.0% | 91.7% / 89.1% |

Through the LSH index alone (`--lsh`: `index_only`), precision and recall
at 0.7 and 0.9 are the same, scoring 8.7% of the pairs (340k of 3.9M);
it loses only below 0.7 (top-1 at any similarity: clang -O2 58.9%, gcc
-O0 43.0%, AArch64 80.6%, versions 90.1%), which is why small databases
are scored whole. Ingesting the three references took 6 s; searching every
function of a stripped Lua took 3-23 s (signing included, two decompiler
workers).

What the numbers say: a 0.7 threshold is precise (79-90%) but finds only
the functions a build change leaves nearly intact (17-58% across
compilers and levels, 90% across versions); confidence ≥ 10 trades a
little recall for 4-6 points of precision; ranking (top-1 with no
threshold) is the better tool for a reverse engineer, who confirms a
match side by side. The misses are mostly small functions (identical
vectors, ties) and functions -O2 inlines into others.

**Against Ghidra.** The vectors are Ghidra's (98% of functions identical
on x86-64 and AArch64, the rest within discovery's differences; `docs/
diff.md`, "Stability: revkit's vectors against Ghidra's", which measured
top-1 within 0-2 points of Ghidra's own on these programs) and the
scoring is BSim's bit for bit, so Ghidra's BSim on these pairs is
expected within a couple of points; running Ghidra's own `bsim` tooling
(an H2 database, headless analysis and signing of every build) wasn't
done here.

## Differences from Ghidra's BSim

- Storage is files, not H2/PostgreSQL/Elasticsearch; one writer at a time
  per database (others wait on the lock), any number of readers, no
  server, users or PKI.
- The index is SimHash over the same weighted vectors rather than BSim's
  own LSH layout (`k`, `L` per template); small databases are scored
  whole.
- No function tags, call-graph (child) records, or Ghidra's
  `generatesigs`/`commitsigs` XML: ingest signs and stores in one step.
