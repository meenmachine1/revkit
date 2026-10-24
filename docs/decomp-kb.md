# Decomp knowledge base

Matching decompilation as transferable work: what a finished decomp
knows about each function (its name, its source, the compiler and flags it
matches with) carried to the next game, so each game goes faster than the
last. revkit ingests finished decomp projects into a knowledge base (KB)
and applies it to a new program: an exact match brings the name and the
verbatim source with the compiler and flags it matched with; a match
through a matched caller names the small functions Function ID can't; a
near match brings the closest known function's source as the starting
scratch, with the instruction diff.

`api_minor` 105, feature `decomp-kb`. Code: `src/backend/decomp_kb.{h,cc}`
(the KB's files, the manifest, a function's text in its unit, the
instruction diff), `BuildDecompKb`, `ApplyDecompKb` and the export in
`src/backend/image_backend.cc`, `ui/src/ui/decompkb.ts`.

Not DS-only: the inputs are a project's module programs (any format
revkit loads), its translation units and source files, and a per-function
manifest. The first producer is a ds-decomp project
([nds.md](nds.md)); GBA (agbcc, decomp.me-style projects), N64 (IDO, KMC
GCC, splat projects) and GameCube/Wii (Metrowerks, dtk/decomp-toolkit
projects) fit the same shape: a splitter's config naming units and their
address ranges, objects per unit, and a compiler per unit.

- [What it stores](#what-it-stores)
- [Ingesting a finished decomp](#ingesting-a-finished-decomp)
- [Applying it to a new program](#applying-it-to-a-new-program)
- [Exporting the matches](#exporting-the-matches)
- [The manifest](#the-manifest)
- [Why Function ID alone named almost nothing](#why-function-id-alone-named-almost-nothing)
- [Measured](#measured)
- [The KB on disk](#the-kb-on-disk)
- [Using it](#using-it)
- [Licensing](#licensing)
- [Not done yet](#not-done-yet)

## What it stores

Per function of a finished decomp (`revkit.v1.DecompKbFunction`):

| Field | From | Used for |
|---|---|---|
| game, module, address, size, mode (ARM/Thumb) | the module program | where it was |
| symbol (as the linker spells it: mangled) and name (demangled) | symbols.txt, the program, else the manifest's `name` | the name a match gets |
| `anonymous` | a placeholder name (`func_…`, `FUN_…`) the manifest doesn't replace | a match brings the source, not the name |
| full and specific hash, code units | revkit's Function ID hasher (`fid::hash_program`), short functions too | exact matches |
| `small` | fewer instructions than Function ID's 4 | matched only through a caller |
| calls | each call in the body: its offset from the entry, the callee's symbol and address (another module's too, through the module links) | names through callers |
| instructions | the body as text, addresses as `<addr>` | a near match's diff |
| translation unit, source path, the function's own text | the splitter's units (delinks.txt) or the manifest's `source`, the source tree | the verbatim source, the scratch |
| compiler, flags, status, fuzzy, library, object, variant, relocations, manifest hash | the manifest, else the ingest's defaults | "matches with mwcc-ds/2.0/sp2p2, -O4,p" |
| prototype | the program (asserted, demangled) | shown with a match |

The KB keeps whole files too: each unit's source file, verbatim, under
`sources/<game>/<path>`, and a BSim database of the functions' feature
vectors, `near.rkbsim` ([bsim.md](bsim.md)).

## Ingesting a finished decomp

`ProjectService.BuildDecompKb` over the module programs of a finished
game (`program_ids`, else every program in `folder_id`: imported with
`ImportDsdProject`, their names are the decomp's), into `kb_path`, a
directory on the daemon's host under a `--browse-root`:

1. A new KB takes the language most of the programs have (a DS game's
   ARM9 modules, `ARM:LE:32:v5t`); programs of another language are left
   out with a warning (the ARM7's).
2. Each program's functions are hashed with Function ID's hasher, as
   `CreateFidDatabase` hashes them, with no minimum length: functions under
   4 instructions are kept, marked `small`. Thunks and functions with no
   instructions are left out (`unnamed`).
3. A function's name is its symbol as the linker spells it (an asserted
   name with its `revkit:dsd.symbol` note, else the file's mangled name).
   A placeholder name is replaced by the manifest's `name` when that is a
   real one; else the record is `anonymous`, and kept only when the
   manifest covers it or its text is found (a pipeline's own game, whose
   names don't matter, still contributes its source).
4. Each function is placed in its translation unit: the `delinks.txt`
   unit whose `.text` range holds it (the module program's record names
   the config), or the manifest's `source`. The unit's file is read from
   `source_root` (the dsd project's root by default: the directory above
   `config/`) and copied into the KB once; the function's own text is
   found in it by its name (the qualified name followed by its parameter
   list and a body; comments, strings and preprocessor lines skipped,
   braces balanced; an in-class definition by its last component).
5. The manifest, when given, supplies per function the compiler, flags,
   status and the rest, over the unit's; else `compiler` and `flags` apply
   to every function and a unit's `complete` marks its functions matching.
6. Every function but the small ones is signed into `near.rkbsim` (one
   BSim executable per module, `<game>/<module>`, with categories `game`
   and `module`), unless `skip_near_index`; signing decompiles each
   function (`threads` workers, up to 4 by default).
7. The records go to `functions.jsonl`; ingesting the same game again
   replaces its records and its executables in the near index.

The response counts the records (`functions`), those with their own text
(`with_source`), unit files copied (`units`), `small` ones (`too_short`),
`anonymous` ones, those the manifest covered (`from_manifest`), those
signed (`near_indexed`), what was left out (`unnamed`), and the KB's
`total`.

## Applying it to a new program

`ProjectService.ApplyDecompKb` over a new game's programs (`program_ids`,
else `folder_id`'s: matched together, so calls between modules count).
Each match lists the KB functions it matches (`functions`, named ones
first) with its verdict:

- **exact**: the function's full hash, specific hash and code units are a
  KB function's (4 instructions or more, as Function ID requires). It gets
  the KB function's name (the demangled form, with the linker's spelling
  kept as the address's `revkit:dsd.symbol` note so `ExportDsdSymbols`
  writes the mangled name) and a plate comment `decomp KB: <game>
  <module> <address> <symbol>`, `<unit> (<status>)`, `matches with
  <compiler>, <flags>`; the match carries the function's source text
  (`unit_source` too with `include_unit_source`). Only functions with
  placeholder names (`FUN_`, `func_`, `entry`) are renamed unless
  `overwrite`; an anonymous KB function gives its comment and source, not
  a name.
- **call**: named through a matched caller. A function matched to one KB
  function has its code, so each of its calls sits where the KB
  function's does: the callee there (in its program, or the one linked
  module that has a function there) is what the KB function calls there,
  when the callee's own hashes (short ones included) are that KB
  function's and every matched caller agrees. Repeated from the functions
  it names, so chains of small helpers are named from the top. Applied as
  exact ones, the comment saying "through its caller" (`by_call` counts
  them).
- **ambiguous** exact matches (a hash several KB functions with other
  names share: inline helpers, trivial accessors, a deleting destructor
  identical to the complete one) are settled when a matched caller calls
  one of them where the KB does, when one candidate's calls reach callees
  whose hashes agree and the others' don't, or when every candidate name
  but one is taken by another function of the program; else listed, not
  applied (`ambiguous`).
- **candidate**: the instructions are a KB function's (the full hash), the
  constants differ: a likely source to start from, not applied.
- **near** (`near`): for each function of 4 instructions or more with no
  other match, BSim's closest KB functions (`max_near`, default 1) of at
  least `min_similarity` (default 0.7) from `near.rkbsim`: the KB
  function's source is the starting scratch; the match has the similarity
  and confidence and `diff`, a unified diff of the instructions from the
  KB function's (`-`) to this one's (`+`), addresses as `<addr>`. Not
  applied.

Every edit of a program is one revision (`AppendAssertions` with the
caller's provenance); undo retracts it.

## Exporting the matches

`export_dir` (a directory on the daemon's host, under a `--browse-root`)
receives the matches as files to drop into a decomp project, written
without following any link below it:

- `config/<...>/symbols.txt`: each dsd module's symbols.txt as
  `ExportDsdSymbols` writes it (renames in place, the linker's spelling),
  at its path in the project; `symbols.patch`, the unified diff. The names
  are there once applied (`apply`, in the same call or before).
- `<unit>` (`src/main.cpp`): for each unit with exact or call matches, its
  preprocessor lines (the includes) and each matched function's verbatim
  text, in the KB's address order, under a comment naming the KB and the
  compiler and flags.
- `scratch/<module>/<name>.c`: each near match's KB source, under a
  comment with the KB function, the similarity and the instruction diff.

`exported` lists the files written and counts the units, scratches and
symbols.txt files.

## The manifest

A JSON-lines file, one object per function, as a matching pipeline writes
it per build (revkit reads these fields and ignores others):

```json
{"address": "0x02219604", "compiler": "mwcc-ds/2.0/sp2p2", "flags": "-O4,p -proc arm946e",
 "fuzzy": 100.0, "isa": "arm", "library": "", "masked_sha256": "…", "module": "ov006",
 "name": "_ZN13GameOverScene6UpdateEv", "object": "build/ov006/GameOverScene.o",
 "relocations": [...], "size": 948, "source": "src/06_GameOver/Scene/GameOverScene.cpp",
 "status": "exact", "variant": "base"}
```

| Field | Read as |
|---|---|
| `module`, `address` | the key: the module's name as the program has it, the address as `0x` hex or a number (a line without a valid one is counted and skipped) |
| `name` (or `symbol`) | the linker's spelling; replaces a placeholder name |
| `isa` (or `mode`) | `arm`, `thumb` (lowercased) |
| `compiler`, `flags` | strings (`flags` may be a list, joined with spaces) |
| `status` | `exact`, `matching`, `match`, `ok` → `matching`; `fuzzy`, `nonmatching`, `partial` → `nonmatching`; others (`asm`) as given |
| `fuzzy` | the fuzzy match score, percent |
| `source` | the unit's source path, relative to `source_root` |
| `masked_sha256` (or `masked_hash`) | the pipeline's hash of the function's bytes with its relocation sites masked, kept as `manifest_hash` |
| `library`, `object`, `variant` | kept as given |
| `relocations` | a list (or a count): how many, kept |
| `size` | read; the program's own size is kept |

revkit matches by its own hash, not `masked_sha256`: the pipeline's masks
exactly its relocation sites, revkit's every operand field the
instruction's SLEIGH mask covers, so revkit's also matches code whose
unrelocated constants differ, which the specific hash and the verdict
then tell apart.

## Why Function ID alone named almost nothing

On the DS fixture, Function ID built from the decomp's objects named only
`ThumbChecksum` in the ROM's `main`. Measured, the causes, by effect:

- **Discovery, in a ROM** (most of it): a module's functions that only
  other modules call (main's, called from overlays; the ITCM's) or only
  vtables reach weren't functions at all: the ROM's `main` had two, its
  entry and `ThumbChecksum`. `ImportNdsRom` now asserts a function at each
  address another module calls (ARM or Thumb by the call: `blx` switches),
  repeated as new functions call further. Functions only vtables reach,
  and code a tail call (`b`) reaches before it is a function, are still
  missed in a ROM; a dsd project's symbols.txt (even `dsd init`'s
  placeholders) has them all.
- **Size**: Function ID hashes nothing under 4 instructions, and a DS
  game's runtime helpers, accessors and small methods are 1-3 (`_fadd`,
  `_fsub`, `_fmul` are two, `operator delete` one). The KB hashes them
  anyway but matches one only through a caller, the evidence a short
  function needs.
- **Language**: an ARM ELF object loads as `ARM:LE:32:v8` by default and
  the DS modules as `ARM:LE:32:v5t`; Function ID and the KB match within
  one base language (with the default, nothing matched: 0 names), so
  objects must be imported with `language_id="ARM:LE:32:v5t:default"`.
  The KB is built from the finished game's module programs, already `v5t`.
- **Relocated words hash alike; objects' bodies don't.** A `bl`'s target
  and a literal-pool load's offset are operand fields the SLEIGH mask
  covers, so the full hash masks them in an object and in linked code, a
  scalar at a relocation site is masked in the specific hash too, and pool
  words are data, never hashed: the same function in two linked builds,
  every address moved, hashes the same (game 3 below). But in a
  relocatable object an unrelocated `bl` decodes to its own address (the
  REL addend), and revkit's discovery ends the body there: every function
  of the objects with a call hashes short (`GameOverScene::Update` as 3
  instructions of 31). So the KB is built from the finished game's module
  programs (linked code), not its objects.
- **Thumb**: Thumb functions hash in Thumb (the function's mode) and
  match as ARM ones do. A separate bug made revkit's own instruction reads
  (`GetInstruction`, `ListInstructions`, the KB's instruction text) decode
  ARM code after a `blx` target as Thumb once a pooled SLEIGH engine had
  decoded the `blx` (its context commit runs to the end of the space);
  they now decode from the bytes with the mode the caller gives.

## Measured

The fixture (`tests/data/nds/make_fixture.py`): game 1 is the finished
decomp (`dsd/`, with its source, 18 functions in main, 7 in `ov000`, 2 in
`ov001`, 1 in the ITCM); game 3 is the same source built again with the
same flags, linked in another order with code of its own first so every
address moves, `GameOverScene::Update` changed by one statement, as
`dsd init` would leave it (`game3/`, placeholder names) and as a ROM
(`game3.nds`, no symbols).

| Applied to | Function ID from the objects (v5t) | KB from game 1 |
|---|---|---|
| game 1's ROM | 2 names (`ThumbChecksum`, `_s32_div_f`; 1 before the ROM fix, 0 as v8) | 16 exact, 1 through its caller |
| game 3's ROM | | 15 exact, 1 through its caller |
| game 3 (dsd, placeholders) | | 18 exact, 4 through their callers, 0 ambiguous, 1 near (`GameOverScene::Update`, similarity 0.79): 21 of the 23 functions the KB has names for named right; the 2 left are `operator delete`s nothing calls |

The KB from the objects names 8 of the ROM's functions (the bodies cut at
their first call match nothing else).

## The KB on disk

```
<kb>/kb.json            {"format": "revkit-decomp-kb/1", "name", "language", "games": [...]}
<kb>/functions.jsonl    one DecompKbFunction per line (protobuf JSON, the proto's field names)
<kb>/sources/<game>/<unit path>   each unit's source file, verbatim
<kb>/near.rkbsim/       the BSim near index (bsim.md's files)
```

Plain files, so a KB can be versioned, shared and diffed (`near.rkbsim`
is rebuilt by ingesting again).

## Using it

**UI:** File → Apply decomp knowledge base… ([ui.md](ui.md#decomp-knowledge-base)).
**Python:** `Client.build_decomp_kb(project_id, kb_path, folder_id=...,
manifest_path=..., compiler=..., flags=...)`,
`Client.apply_decomp_kb(project_id, kb_path, folder_id=..., apply=True,
near=True, export_dir=...)`. **MCP:** `build_decomp_kb`,
`apply_decomp_kb`. Both calls need admin (the host's files) and a
`--browse-root`.

```python
g1 = rk.import_dsd_project("default", "/srv/game1/config/usa/arm9/config.yaml", folder_name="game1")
rk.build_decomp_kb("default", "/srv/kb", folder_id=g1.folder.folder_id,
                   manifest_path="/srv/game1/results/manifest.jsonl")
g3 = rk.import_dsd_project("default", "/srv/game3/config/eur/arm9/config.yaml", folder_name="game3")
r = rk.apply_decomp_kb("default", "/srv/kb", folder_id=g3.folder.folder_id, apply=True, near=True,
                       export_dir="/srv/game3-kb")
```

Tests: `src/backend/tests/nds_test.cc` (`DecompKbText`: function text,
the manifest's fields, the diff), `sdk/python/tests/test_decomp_kb.py`
(ingest with a pipeline's manifest; apply to dsd's placeholder names and
to game 3 as a project and a ROM; the export; the near match; MCP),
`sdk/python/tests/test_nds.py` (Function ID from objects), `ui/e2e/nds.ts`.

## Licensing

A KB holds whatever source the user points the ingest at, verbatim. That
source's licence goes with it: a KB built from a decomp with no licence,
or a restrictive one, is the user's to keep private; sharing the KB is
sharing the source. revkit adds nothing and claims nothing over it.

## Not done yet

1. Prototypes and types: apply the KB function's prototype (it has the C
   text; parse it in the new program's profile) and the unit's headers'
   types (C++ class import is the blocker: [nds.md](nds.md#what-revkit-doesnt-do-yet)).
2. Declarations a scratch needs, from the unit's headers, so a scratch
   compiles.
3. Data names through the code: a matched function's literal-pool words
   name the globals they point at, as calls name callees.
4. Objects as a source: apply an object's call relocations (to its
   symbols, or an external block) so its bodies are whole, as Ghidra's ELF
   loader does.
5. Relocation-site masking from the manifest (or an object's
   relocations), to match exactly what the pipeline matches.
6. In a ROM: functions only vtables reach (constructors store the vtable;
   its slots are the methods), and tail-called ones.
7. Other producers: splat (N64), decomp-toolkit (GameCube/Wii), GBA
   projects' configs, through the same manifest.
