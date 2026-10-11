# Ghidra interop

Two-way exchange of a user's work between Ghidra projects and revkit, so
adopting revkit isn't a one-way move:

- **Ghidra → revkit.** `tools/ghidra-interop/ghidra_dump.py` (PyGhidra,
  headless) exports the user's work in a Ghidra program as JSON;
  `revkit-ghidra-import` (Python SDK) appends it to the same binary in
  `rk-daemon` as assertions with provenance `import:ghidra@<Ghidra version>`
  (or `agent:ghidra-ai`).
- **revkit → Ghidra.** `revkit-ghidra-export` writes a program's user and
  agent assertions as JSON; `tools/ghidra-interop/ghidra_apply.py` applies
  them to a Ghidra program in one transaction and leaves each change's
  provenance there.

Both directions use the `revkit-ghidra-interop` JSON format, version 1,
described below.

- [Commands](#commands)
- [Ghidra to revkit](#ghidra-to-revkit)
- [revkit to Ghidra](#revkit-to-ghidra)
- [Types](#types)
- [JSON format](#json-format)
- [Tests](#tests)
- [API changes](#api-changes)
- [Gaps](#gaps)

## Commands

The Ghidra side runs in the PyGhidra virtualenv (`scripts/setup-pyghidra.sh`
prints its python), the revkit side in the SDK's (`docs/api.md`,
`pip install -e sdk/python` installs both commands).

```sh
py=$(scripts/setup-pyghidra.sh)
build/tools/rk-daemon/rk-daemon --project-dir ~/rk &
# With accounts (docs/security.md) the import writes import:ghidra provenance,
# which needs an admin's token; the export reads, so a viewer's will do.
export RK_TOKEN=$(build/tools/rk-daemon/rk-daemon token create --name ghidra-bridge --role admin --project-dir ~/rk)

# Ghidra -> revkit, in two steps or one.
$py tools/ghidra-interop/ghidra_dump.py --project ~/work/proj.gpr --program /prog -o prog.ghidra.json
revkit-ghidra-import prog.ghidra.json --binary path/to/prog        # imports the binary if the daemon lacks it
revkit-ghidra-import --ghidra-project ~/work/proj.gpr --program /prog --binary path/to/prog

# revkit -> Ghidra, in two steps or one. Close the project in the Ghidra GUI first:
# the scripts open it headless (the dump read-only).
revkit-ghidra-export --binary path/to/prog -o prog.revkit.json
$py tools/ghidra-interop/ghidra_apply.py --project ~/work/proj.gpr --program /prog prog.revkit.json
revkit-ghidra-export --binary path/to/prog --ghidra-project ~/work/proj.gpr --program /prog

# Undo an import.
python -c 'from revkit import Client; Client().program("default/prog").revert(kind="import", id="ghidra")'
```

Useful options:

| Command | Option | Effect |
| --- | --- | --- |
| `ghidra_dump.py` | `--no-baseline` | Skip the baseline analysis (below); unsourced items get source `UNKNOWN` |
| `revkit-ghidra-import` | `--sources LIST`, `--all-sources` | Ghidra SourceTypes to import (default `USER_DEFINED,IMPORTED,AI,UNKNOWN`) |
| | `--functions user\|all\|none` | Functions revkit's discovery lacks: the user's (default), all of Ghidra's, none |
| | `--function-bodies` | Pin Ghidra's function bodies, not only the entries |
| | `--prune` | Retract this importer's assertions that are gone from Ghidra |
| | `--c-types` | Retype with C text even when the daemon can define types |
| | `--include-from-revkit` | Also import what revkit-ghidra-export put into Ghidra |
| | `--dry-run`, `--report FILE` | Plan only; write the per-category report |
| `revkit-ghidra-export` | `--provenance user,agent[,import,...]` | Provenance kinds to export (default `user,agent`) |
| `ghidra_apply.py` | `--strict` | Roll back if any change can't be applied |

Both sides check the binary: the import finds the revkit program whose
SHA-256 equals Ghidra's `getExecutableSHA256()` (or takes `--program-id` and
refuses a mismatch without `--force`), and the apply refuses a document for
another binary.

**Image bases.** Every address in the JSON is absolute, with the program's
image base beside it; each side shifts by the difference between the two
bases. Ghidra and revkit both load an ELF PIE at 0x100000 and a PE at its
preferred base, so the difference is normally zero; a program rebased in
Ghidra (Memory Map → Set Image Base) maps back the same way.

## Ghidra to revkit

### What is the user's work

Ghidra records a `SourceType` for symbols, function signatures and
variables: `USER_DEFINED`, `IMPORTED` (loaders, debug info, type
archives), `AI`, `ANALYSIS` and `DEFAULT`. `ANALYSIS` and `DEFAULT` are what
revkit derives itself, so they are skipped by default (`--all-sources`
imports them too); `AI` imports as `agent:ghidra-ai`, the others as
`import:ghidra@<version>`.

Comments, data, types, bookmarks, equates, flow overrides, function
existence and no-return flags have no SourceType in Ghidra, and an analyzed
program has hundreds of each (the corpus's stripped gcc -O0 `features`: 831
comments, 967 data items, 59 flow overrides, 25 types). The exporter therefore **re-analyzes a
baseline**: it writes the program's original file bytes (Ghidra keeps them)
to a temp file, imports and auto-analyzes them in memory with the same
language, and marks each item `ANALYSIS` if the fresh analysis produces it
identically, `USER_DEFINED` otherwise. On the corpus binaries that separates
the scripted edits exactly. It costs one auto-analysis (2 to 4 s for small
binaries, minutes for large ones); `--no-baseline` marks such items
`UNKNOWN`, which the importer takes by default, so everything comes in.
Functions the baseline has and the program doesn't are ones the user
deleted (`removed_functions`).

### Mapping

| Ghidra | revkit assertion | Notes |
| --- | --- | --- |
| Primary symbol name (function, label, global) | `Rename{address}` | Namespaces other than a function's are kept as `ns::name`; non-primary labels are reported and skipped (one name per address) |
| Function signature (when `getSignatureSource()` is selected) | `DefineType` of a function type + `Retype{entry, type_hash}` | Return type, parameters (auto-parameters excluded), varargs, calling convention; C text with `--c-types` |
| Parameter name and type (signature not imported) | `Rename`/`Retype{local: param:N}` | Checked against revkit's decompilation |
| Local variable name and type | `Rename`/`Retype{local: storage_key}` | Stack variables by offset (`stack:-0x14`), register variables by register and first use (`register:EAX@0x...`); no unique match is reported and skipped |
| Comment (plate, pre, post, EOL, repeatable) | `Comment` of the same kind | |
| Defined data | `DefineType` + `Retype{address, type_hash}` | `undefined` data is skipped |
| Named types (struct, union, enum, typedef, function definition) | `DefineType` | Those the user made, and any type an imported item uses ([Types](#types)) |
| Function revkit's discovery lacks | `SetFunctionBounds{entry}` | The user's (baseline), or one the user named or typed; `--function-bodies` adds the body |
| Function the user deleted | `SetFunctionBounds{entry, remove}` | Needs the baseline |
| Flow override | `FlowOverride` of the same kind | |
| Bookmark | `Note{tag: ghidra:bookmark:<type>[:<category>]}` | Not `revkit` bookmarks |
| Equate | `Note{tag: ghidra:equate:<operand>, text: NAME=0x..}` at each reference | |
| No-return flag | `Note{tag: ghidra:noreturn}` | Unless revkit already infers it |

Items revkit already has are not asserted again: a name equal to revkit's
effective name, an `IMPORTED` item on a key revkit's own DWARF or PDB import
set, a value equal to the effective assertion's (another author's), and
what `ghidra_apply.py` put into Ghidra while revkit still has it (below).

### Commits, idempotence, provenance

The import is at most two commits per provenance: function bounds first
(so discovery finds the new functions and their variables can be matched),
then everything else as one atomic `AppendAssertions`, type definitions
first; superseded assertions are retracted in one more.
`validate_only` reports the types' hashes beforehand, so the retypes can name
them in the same request.

Re-running is idempotent. An item whose identical body this importer
(`import:ghidra` of any version, or `agent:ghidra-ai`) already asserted
live on the same key is skipped; a type is skipped if anyone defined its
hash. An item Ghidra changed since is appended (it wins: same rank, later)
and the importer's older assertion on that key is retracted. `--prune`
also retracts this importer's assertions on keys the new export no longer
has. An item whose identical assertion by this importer someone in revkit
retracted (an undo, or a `RevertByProvenance` of the import) is not
asserted again (`--reimport-rejected` overrides). An item the server
rejects (it names it) is reported and dropped, and the rest commits.

The report (stdout, `--report`) counts per category what was appended,
unchanged, already in revkit, from revkit, filtered by source, and lists
each skipped item with the reason.

`import:ghidra` ranks like revkit's other importers: above agents and
analysis, below users. A whole import reverts with
`RevertByProvenance{kind: IMPORT, id: "ghidra"}`, or one run by its
`session`.

## revkit to Ghidra

### What is exported

`revkit-ghidra-export` lists the program's live assertions and keeps the
**effective** ones (each key's winner) whose provenance kind is `user` or
`agent`, except `agent:ghidra-ai`'s. Why not everything:

- `import:dwarf` and `import:pdb` are what Ghidra's own DWARF and PDB
  analyzers produce from the same file;
- `import:ghidra` and `agent:ghidra-ai` came from Ghidra;
- loader names and analysis are what Ghidra derives itself, and pushing
  revkit's would overwrite Ghidra's analysis with a different tool's.

So only people's and agents' edits are new to Ghidra.
`--provenance user,agent,import` widens the selection. Taking winners only
means a user edit shadowed by a later user edit isn't sent, and an agent
edit a user overrode isn't either.

### Applying

`ghidra_apply.py` opens the program writable, applies every change in one
transaction (`revkit-ghidra-export`) and saves. Ghidra's source for a
change is `USER_DEFINED` for `user:`, `AI` for `agent:` and `IMPORTED` for
`import:`.

| Change | Ghidra |
| --- | --- |
| `rename` | Function name, else the primary label (created if needed); an empty name restores the default |
| `rename_local`, `retype_local` | Parameter `N` for `param:N`; the stack or register local with that storage, created if missing |
| `retype` at a function entry | `ApplyFunctionSignatureCmd` with the function type (hash) or `CParserUtils.parseSignature` (C text); the function keeps its name |
| `retype` elsewhere | `DataUtilities.createData`, clearing conflicting data, never code; C text through `DataTypeParser` |
| `comment` | The same kind; `decompiler` comments become `PRE` comments |
| `function` | `CreateFunctionCmd` (disassembling the entry if needed), with the body when given; `remove` deletes it |
| `flow_override` | `Instruction.setFlowOverride` |
| `note` | A `revkit` bookmark, category `note:<tag>`; `ghidra:noreturn` sets the flag |
| `define_type` | The type, in category `/revkit` |

A change that can't be applied (no function at an address, an
unparseable C declaration, ...) is reported and skipped; `--strict` rolls
the transaction back instead.

**Traceability.** Every applied change leaves:

- a bookmark of type `revkit`, category `revkit`, at its address, listing
  the changes there: `user:alice #40 rename -> alice_func; user:alice #41
  comment (eol)`, provenance and assertion `seq`, which `Blame` and
  `GetHistory` in revkit resolve; types get the same text as their
  description;
- an entry in the `revkit.applied` string property map at the address:
  the item and the fingerprint of what Ghidra showed right after applying
  (the name, the comment text, the prototype, the data type, ...).

`ghidra_dump.py` marks an item `from_revkit` while its fingerprint still
matches, and skips `revkit` bookmarks. The importer drops such an item while
revkit still has another author's assertion on its key, so importing
Ghidra's work after an apply doesn't bring revkit's own edits back as
`import:ghidra`; into a revkit project that lacks them (a fresh one) they
import like the rest of the user's work in Ghidra. An item the user changes
in Ghidra afterwards has a new fingerprint and is imported.

## Types

### Ghidra to revkit

Types travel as type references (see the JSON format): named types by their
Ghidra path, structural ones inline. The importer turns each into a
`TypeNode` of a `DefineType` assertion (`api_minor` 4), deduplicated and
referring to each other by `assertion_index`, so recursive structs work.

| Ghidra | revkit type model |
| --- | --- |
| `Structure`, `Union` | struct/union: name, size, fields at their offsets; bitfields as absolute bit offsets (little-endian numbering); explicit minimum alignment; `pack(1)` as packed; not-yet-defined as incomplete |
| `Enum` | enum: name, size, signedness, values |
| `TypeDef` | typedef |
| `FunctionDefinition` | typedef of a function type (revkit's function types are structural) |
| `Pointer`, `Array` | pointer (size kept), array (count) |
| `char` | plain char with the data organization's signedness |
| `schar`, `uchar`, `short`, `int`, `long`, `longlong` and unsigned forms | integers of that C rank |
| `byte`, `word`, `dword`, `int16`, ... | fixed-width integers (`uint16_t`) |
| `wchar_t`, `wchar16`, `wchar32` | `wchar_t`, `char16_t`, `char32_t` |
| `float`, `double`, `longdouble`, `floatN` | float of that kind and size |
| `bool`, `void`, `undefined`/`undefinedN` | bool, void, undefined of N bytes |
| strings and unicode (dynamic) | arrays of char, `char16_t` or `char32_t` of the data's length |
| anything else (`ImageBaseOffset32`, ...) | undefined of its size |

A function signature becomes a function type with the calling convention by
name (`__cdecl`, `__stdcall`, ...; the program's default convention and
`unknown` become revkit's default). Hashed prototypes reach revkit's
decompiler, which uses their parameter names and types.

With a daemon older than `api_minor` 4 (or `--c-types`) retypes carry C
declarations instead (`int parse(struct node *n)`, `char *v[4]`), which
revkit stores as display text.

### revkit to Ghidra

`revkit-ghidra-export` includes, for every hash a change names, the type
and everything it reaches (`GetTypes` with `include_dependencies`, whose
field-level description is new in `api_minor` 4). `ghidra_apply.py` builds
Ghidra types from them: integers by rank and size (`uint`, `ulong`, sized
`AbstractIntegerDataType`s for fixed ones), floats by size, pointers,
arrays, structs (shell first, so self-references work; fields with
`replaceAtOffset`, bitfields with `insertBitFieldAt`), unions, enums,
typedefs and function definitions. A named struct, union, enum or typedef
whose name and shape match a type Ghidra already has (one that came from
Ghidra) is reused; others go into `/revkit`. Qualifiers are dropped
(Ghidra has none).

## JSON format

One JSON object; unknown fields are ignored, so later versions can add
fields. Addresses are hex strings (`"0x101040"`) in the program's default
space; items in other spaces (Ghidra's `EXTERNAL` block, overlays,
`_elfSectionHeaders`) are not exported.

### Common fields

| Field | Meaning |
| --- | --- |
| `format` | `"revkit-ghidra-interop"` |
| `version` | `1`; readers refuse a newer version |
| `direction` | `"ghidra-to-revkit"` or `"revkit-to-ghidra"` |
| `program.sha256` | SHA-256 of the original file |
| `program.image_base` | The base the addresses are relative to |

### Type references

A type reference is one of:

```json
{"ref": "/rt/rt_point"}                                    // a named type in "types"
{"kind": "pointer", "size": 8, "target": <ref>}
{"kind": "array", "count": 4, "element": <ref>}
{"kind": "int" | "uint", "size": 4, "rank": "int"}         // rank: char short int long long_long int128 wchar char8 char16 char32; absent = fixed width
{"kind": "char", "size": 1, "signed": true}
{"kind": "float", "size": 8, "float_kind": "double"}       // half float double long_double float128
{"kind": "bool", "size": 1} | {"kind": "void"} | {"kind": "undefined", "size": 4}
```

### ghidra-to-revkit

```json
{
  "format": "revkit-ghidra-interop", "version": 1, "direction": "ghidra-to-revkit",
  "ghidra": {"version": "12.1.4", "project": "/abs/proj.gpr", "program_path": "/prog"},
  "program": {"name": "prog", "sha256": "...", "md5": "...", "executable_path": "/abs/prog",
              "executable_format": "Executable and Linking Format (ELF)", "language_id": "x86:LE:64:default",
              "compiler_spec_id": "gcc", "image_base": "0x100000", "pointer_size": 8, "big_endian": false,
              "default_calling_convention": "__stdcall", "char_signed": true},
  "baseline": {"analysis_seconds": 3.6, "image_base_delta": 0},
  "symbols": [{"address": "0x105134", "name": "rt_parse_options", "kind": "function", "source": "USER_DEFINED", "primary": true}],
  "functions": [{"entry": "0x105134", "name": "rt_parse_options", "name_source": "USER_DEFINED",
                 "body": [["0x105134", "0x1052f1"]], "signature": "int rt_parse_options(rt_handle p, int count)",
                 "signature_source": "USER_DEFINED", "calling_convention": "__stdcall",
                 "return": <ref>, "params": [{"ordinal": 0, "name": "p", "type": <ref>, "source": "USER_DEFINED",
                                              "auto": false, "storage": "RDI:8"}],
                 "locals": [{"name": "rt_counter", "type": <ref>, "source": "USER_DEFINED", "first_use": "0x105134",
                             "storage": "Stack[-0xc]:4", "stack_offset": -12}],
                 "varargs": false, "no_return": false, "inline": false, "custom_storage": false,
                 "thunk_of": "0x...", "exists_source": "ANALYSIS", "no_return_source": "ANALYSIS"}],
  "removed_functions": [{"entry": "0x104a00", "source": "USER_DEFINED"}],
  "comments": [{"address": "0x105134", "kind": "plate", "text": "...", "source": "USER_DEFINED"}],
  "data": [{"address": "0x109128", "length": 16, "type": <ref>, "source": "USER_DEFINED"}],
  "types": [{"id": "/rt/rt_point", "name": "rt_point", "category": "/rt", "kind": "struct", "size": 16,
             "incomplete": false, "packed": false, "alignment": 8,
             "fields": [{"name": "x", "offset": 0, "type": <ref>, "bit_offset": 0, "bit_size": 0, "comment": "..."}],
             "archive": null, "source": "USER_DEFINED", "description": "..."}],
  "bookmarks": [{"address": "0x105134", "type": "Note", "category": "rt", "comment": "...", "source": "USER_DEFINED"}],
  "flow_overrides": [{"address": "0x101bf8", "kind": "call_return", "source": "USER_DEFINED"}],
  "equates": [{"name": "RT_MAGIC", "value": 23, "source": "USER_DEFINED",
               "references": [{"address": "0x1051a1", "operand": 1}]}],
  "stats": {"symbols": 340, "...": 0, "seconds": {"baseline": 3.6, "export": 0.3}}
}
```

- `source` is Ghidra's SourceType where Ghidra keeps one, else `ANALYSIS`
  or `USER_DEFINED` from the baseline, or `UNKNOWN` without one. Types from
  a data type archive that analysis didn't apply are `IMPORTED`.
- Enum `values` are `[name, value]` pairs; `typedef` types have `target`;
  `function` types have `return`, `params`, `varargs`, `calling_convention`,
  `no_return`; `archive` names the source archive of archive types.
- `from_revkit: true` on an item (and `signature_from_revkit` on a
  function) marks what `ghidra_apply.py` set and Ghidra still shows.
- `removed_functions` is present only with a baseline.

### revkit-to-ghidra

```json
{
  "format": "revkit-ghidra-interop", "version": 1, "direction": "revkit-to-ghidra",
  "revkit": {"program_id": "default/prog", "server": "rk-daemon ...", "revision": 52, "provenance_kinds": ["user", "agent"]},
  "program": {"name": "prog", "sha256": "...", "language_id": "x86:LE:64:default", "image_base": "0x100000", "pointer_size": 8},
  "types": {"<hash>": <TypeDefinition as proto JSON: kind, name, size, rank, pointer, array, composite, enumeration, function, typedef_type, qualified>},
  "changes": [
    {"seq": 40, "revision": 47, "provenance": "user:alice", "session": "...", "reason": "...", "op": "rename", "address": "0x104102", "name": "alice_func"},
    {"op": "rename_local", "function": "0x104102", "storage_key": "stack:-0x158", "name": "alice_tmp"},
    {"op": "retype", "address": "0x104102", "c": "int alice_func(char *s)"},
    {"op": "retype", "address": "0x1092f0", "type_hash": "..."},
    {"op": "retype_local", "function": "0x...", "storage_key": "param:0", "type_hash": "..."},
    {"op": "comment", "address": "0x...", "kind": "eol", "text": "..."},
    {"op": "function", "entry": "0x...", "body": [["0x...", "0x..."]], "remove": false},
    {"op": "flow_override", "address": "0x...", "kind": "branch"},
    {"op": "note", "address": "0x...", "tag": "todo", "text": "..."},
    {"op": "define_type", "type_hash": "..."}
  ]
}
```

Every change has `seq`, `revision` and `provenance` (and `session`,
`reason` when set); changes are in `seq` order.

## Tests

| CTest | What | Time |
| --- | --- | --- |
| `ghidra_interop_mapping` | `tools/ghidra-interop/tests`: type mapping (recursive structs, bitfields, C text), keys, local matching, planning against a stand-in state (sources, rebasing, notes), export of assertions; and a hand-written export imported into `rk-daemon`: one revision, the prototype in the decompiler, provenance and version, idempotence, a rebased export, a changed comment superseding the old one | under 1 s |
| `ghidra_roundtrip` | `tools/ghidra-interop/roundtrip_test.py` on the corpus's stripped gcc -O0 `features` (below) | about 25 s |

The round trip, all headless:

1. imports the binary into a new Ghidra project in a temp dir and
   auto-analyzes it;
2. makes scripted user edits with Ghidra's API: function and global renames,
   an `AI`-sourced rename, comments of all five kinds, a struct, an enum and
   a typedef, a struct applied to data and named, an `int` global, a
   signature using the typedef, a stack local renamed and retyped, a new
   function at a block start inside another, a deleted function, a
   `CALL_RETURN` flow override, a bookmark, an equate and a no-return flag;
3. exports, imports into `rk-daemon` (persistent project dir), and checks
   each edit's key, value and provenance (`import:ghidra@12.1.4`, or
   `agent:ghidra-ai`), the types field by field, and that the decompiler uses
   the signature and the local's name;
4. imports again, and imports an export of the program rebased by 0x100000
   in Ghidra: nothing is appended;
5. edits in revkit as `user:alice` and `agent:claude@test`: a rename, an EOL
   comment, a C prototype, a local, a flow override, a note, a C-text and a
   hashed data retype with a new struct, a new function; exports them;
6. applies the export to the Ghidra project and checks each change in
   Ghidra (names with `USER_DEFINED` and `AI` sources, prototype, local, data
   types, `/revkit/alice_pair`, flow override, note, function) and its
   `revkit` bookmark naming the provenance and `seq`;
7. exports Ghidra's work again and imports it: nothing comes back.

48 checks; about 14 s of Ghidra setup, 9 s for the apply, 25 s in all.
With `--binary out/corpus/pe-x86_64/clang-O0/stripped/features.exe` the same
48 checks pass on a PE (about 80 s: Ghidra's PE analysis is slower). Run it by hand
with `RK_DAEMON=build/tools/rk-daemon/rk-daemon PYTHONPATH=sdk/python
~/.cache/revkit/venv/bin/python tools/ghidra-interop/roundtrip_test.py
--work /tmp/rt` (keeps the Ghidra project, the JSON files and the reports).

## API changes

Additive, `api_minor` 3 → 4 (features `define-types`, `type-details`;
`proto/check.sh` passes against master):

- `AssertionBody.define_type` (`DefineType{TypeNode}`), keyed `TYPE_DEF`
  with `sub` = the content hash; `TypeNode`, `TypeNodeRef`, `TypeNodeField`,
  `TypeNodeParam`; `IntegerRank`, `FloatKind`. A request's define_types are
  interned as one batch (`src/backend/define_type.cc`), and a `Retype` by
  `type_hash` may name a hash defined earlier in the same request.
- `GetTypes` fills `kind`, the `detail` oneof (pointer and array targets,
  fields, enumerators, parameters, typedef targets) and the new `rank`,
  `float_kind`, `complete` and `qualified` (`TYPE_KIND_QUALIFIED`).
- `Field.bit_offset` is documented as the bit within the byte at `offset`.
- SDK: `Program.symbols()` (wraps `ListSymbols`), the `revkit.ghidra`
  package and its two commands.

## Gaps

What doesn't round-trip, and why:

- **No-return flags, bookmarks and equates** have no assertion kind in
  revkit; they arrive as notes (`ghidra:noreturn`, `ghidra:bookmark:...`,
  `ghidra:equate:N`) that nothing in revkit acts on: a `ghidra:noreturn`
  note doesn't make discovery or the decompiler treat the function as
  no-return. `ghidra_apply.py` turns a `ghidra:noreturn` note back into the
  flag, other notes into `revkit` bookmarks.
- **Calling conventions** are kept in the function type and reach
  revkit's decompiler as the compiler spec's prototype model
  ([decompiler-inputs.md](decompiler-inputs.md#calling-conventions)); one
  the spec lacks is the default, with a warning. Custom variable storage
  isn't exported at all.
- **Data types on globals** are stored (`TYPE` = `h:<hash>`) but revkit's
  listing shows data as `undefined` rows and its decompiler only takes
  function prototypes, not global types (backend.md, known gaps). Local
  variable names and types are display overlays in revkit, not decompiler
  inputs.
- **C-text retypes** (`c:`) are display-only in revkit (no C parser), and
  `ghidra_apply.py` parses them with Ghidra's `DataTypeParser`, which knows
  type names (`uint`, `char *`, `struct foo`), not declarators such as
  function pointers or arrays; those are skipped with a reason. Prototypes
  go through `CParserUtils.parseSignature`.
- **One name per address**: Ghidra's non-primary labels are reported and
  skipped. Namespaces flatten to `ns::name` text; labels local to a
  function lose their function namespace.
- **Type details revkit's model lacks**: field comments, type descriptions
  and category paths (revkit types are flat by name), and Ghidra-specific
  types (`ImageBaseOffset32`, ...) that become undefined bytes. Bitfields
  use little-endian bit numbering; big-endian programs are untested. Ghidra
  has no qualifiers, so `const` is dropped on the way back.
- **Locals** map only where revkit's decompilation has a variable with the
  same storage: stack variables by offset, register variables by register
  and first use. Variables the two decompilers split or merge differently
  don't match and are reported. A `stack:`/`register:` local revkit names
  but Ghidra lacks is created in Ghidra with an undefined type of 4 (or the
  register's) bytes.
- **Function bodies** are entries only by default; `--function-bodies` pins
  Ghidra's. Without a baseline, functions Ghidra's analysis found and the
  user's are indistinguishable (`--functions all` takes them all); a
  deleted function is known only with a baseline.
- **Retractions don't propagate to Ghidra.** The export sends live
  winners; undoing an edit in revkit doesn't undo it in Ghidra, and
  retracting an `import:ghidra` assertion doesn't change the Ghidra
  program (the importer only remembers not to assert that value again).
- **The baseline is an approximation.** It reruns the analysis with the
  current options; analyzers the user ran by hand, or a Ghidra version
  change, make their output look like the user's. Ghidra's analysis is not
  fully deterministic either (README of `tools/ghidra-export`).
- `FindTypes` still returns nothing; types are listed through
  `ListAssertions` over `TYPE_DEF` keys.
- Tested on x86-64 ELF (the round trip in CTest) and PE (the same round trip
  by hand); other architectures and big-endian programs use the same code
  but are untested.
