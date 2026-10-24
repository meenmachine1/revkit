# Types, DWARF, PDB and demangling

`src/types` (`revkit::types`) is a program-independent store of C-level
types. `src/debuginfo` (`revkit::debuginfo`) reads DWARF and PDBs into it,
and `tools/rk-debuginfo` (formerly `rk-dwarf`, which remains as a symlink)
turns that into reference-format ground truth. `src/cparse` parses C
headers into it, hash-identical to the debug info's ([cparse.md](cparse.md)).
`src/demangle` wraps LLVM's demangler. Structures are also made from how
code uses a pointer, or from the data in a range
([below](#structures-from-pointer-use)). Types travel between programs as
type archives, a C header plus a JSON sidecar, and are filed in
categories ([below](#type-archives)).

## Type model

A `Type` is one of: `void`; `bool` (size); integer (size, signedness, and
its C rank: plain `char`, `signed`/`unsigned char`, `short`, `int`, `long`,
`long long`, `__int128`, `wchar_t`, `char8/16/32_t`, or `Fixed` for types
with no C spelling); float (size, kind, complex); pointer or C++ reference
(target, size); array (element, count, 0 = unknown/flexible); struct, class
or union (name, size, explicit alignment, packed, complete, and fields with
name, type, bit offset and bitfield width); enum (name, underlying size and
signedness, enumerators); typedef; qualifiers (`const`, `volatile`,
`restrict`, `_Atomic`); function (return type, named parameters, varargs,
calling-convention tag, which the decompiler follows as the compiler
spec's prototype model: [decompiler-inputs.md](decompiler-inputs.md#calling-conventions));
and "undefined of N bytes".

Types refer to each other by `TypeId`. The rank is part of an integer's
identity because `long` and `long long` are different C types even where
they have the same size. Plain `char` records the target's signedness, so
a struct with a `char` member hashes differently on x86-64 (signed) and
AArch64/RISC-V (unsigned).

`print.h` renders C declarations (`int (*fn)(int, int)`,
`char *const p`), full definitions with offsets, and the Ghidra notation of
the reference format (`char * * argv`, `int[8] *`, `_func_int_int *`).

## Identity and interning

Every type has a 128-bit hash: the first 16 bytes of SHA-256 over a
canonical encoding. The encoding is explicit (little-endian lengths and
integers, length-prefixed names), so hashes are the same on every machine
and run; a golden value in `store_test.cc` pins it. The store keeps one copy
per hash.

A type that references only stored types hashes as
`H("revkit-type-v1\0" "N" <fields> "H" <child hash> ...)`, Merkle-style.

Recursive types (`struct node { struct node *next; }`) are built in a
`TypeGraph` with graph-local ids and interned as a batch:

1. **Validate.** Every cycle must pass through a struct/union and through a
   pointer or function edge; otherwise the type is infinite or meaningless
   (`TypeGraph::break_invalid_cycles()` repairs such graphs from bad input).
2. **Minimize** with Moore partition refinement, so that two nodes share a
   class exactly when they denote the same (possibly infinite) type tree.
   This makes `node -> node' -> node` with identical copies hash like the
   two-node cycle.
3. **Hash per strongly connected component**, sinks first. For a member of
   a cyclic component, the encoding is a DFS from that member over its
   component: a node is written inline the first time (`N`) and as a
   back-reference to its visit index after (`B`), and anything outside the
   component as its finished hash (`H`). Children are visited in field
   order, so the DFS order, and therefore the hash, depends only on the
   type, not on how the graph was numbered or which DWARF unit it came from.
4. **Reuse or add.** Classes whose hash exists map to the stored type.

If a new local type references a stored type that is on a cycle, the stored
component is copied into the batch first, so a local type equal to another
member of that cycle is recognized as it.

Cost is linear for acyclic types and O(k·e) for a component with k members
and e edges.

The decompiler knows a struct or union by an id made from its hash
(`inputs::GhidraTypes`: the struct kind's id range with the hash's first 6
bytes; a typedef of one is a copy under the typedef's id, followed back to
it). That is how a decompiled field access names its struct: the backend's
`types.aggregate_ids` maps the ids of every struct and union the program
defines (anonymous ones too) and of the library archive's back to their
hashes, which `CodeToken.parent_type_hash` carries with the field's
`field_offset` (api_minor 38, feature `field-tokens`). Rename Field and
Retype Field in the UI edit the struct by that hash ([ui.md](ui.md)).

## Shared rules and tools

- **Packing** (`revkit/types/packing.h`, `infer_packing`): neither DWARF
  nor CodeView reliably says a struct is packed, so it is inferred (a
  member below its natural alignment, or a size that isn't a multiple of
  it, alignment capped at the address size). The DWARF and PDB importers
  and the C parser all classify with it, so one struct hashes the same
  from any of them.
- **Declarations** (`revkit/types/transform.h`, `resolve_declarations`):
  replaces references to an incomplete struct, union or enum with a
  definition of the same name; the C parser's `link()` uses it across
  translation units, as the DWARF importer resolves declarations for a
  whole binary.
- **Layouts as JSON** (`revkit/types/describe.h`): a named type's size,
  fields (bit offset, width, spelled type) and its hash with and without
  typedefs. `rk-debuginfo --types-json` prints every named type of a
  binary's debug info this way and `rk-cparse --json` of a header, which
  is how the parser's round trip is measured; `--dump KEY` on either
  prints every node a type reaches, to find where two differ.

## Structures from pointer use

Ghidra's **Auto Create Structure** and **Auto Fill in Structure**
(`FillOutStructureHelper`), and **Create Structure** on a listing
selection, as `TypeService.AutoStructure` (`api_minor` 32, feature
`auto-struct`; [api.md](api.md#structures-from-pointer-use)). The RPC
composes the structure and asserts nothing; the client applies it in one
request.

**The accesses** (`infer::pointer_accesses`, `src/infer/accesses.cc`). The
decompiler worker, after a function's decompilation, walks the p-code
from every pointer-sized parameter and local, as `FillOutStructureHelper`
does: through `COPY`, `CAST`, `MULTIEQUAL`, `INDIRECT` and additions of a
constant (`INT_ADD`, `INT_SUB`, `PTRADD` with a constant index, `PTRSUB`),
keeping the offset from the variable's value; at a `LOAD` or `STORE`
whose address that is, it records the offset, the size, and what the
value is: a pointer (typed so, or itself dereferenced), a float (typed so,
or read by a float operation), a signed or unsigned integer, a bool, or
unknown; at a `CALL` whose argument it is, the callee, the parameter
index and that parameter's storage. The lists ride in the decompilation's
memo (`DecompileOutput::accesses`, keyed by the variable's storage key),
and the query **`infer.pointer_accesses`** `((program, function),
storage key)` reads one of them, so they are exactly the decompilation
the user sees, and revalidate with it.

**Into callees.** From the variable, breadth first: where the pointer
plus `delta` is passed to a function of the program (a direct thunk
followed to its target; imports and indirect calls aren't), that
function's parameter in the same register (else at the same position)
is walked too and its accesses count at `offset + delta`, up to
`call_depth` calls (default 1, Ghidra's `maxCallDepth`; at most 4), 64
functions. Ghidra follows only a pointer passed unchanged; a pointer to a
field (`&L->base_ci`) is followed here as well, and marks a field.

**Composing** (`infer::compose_structure`). A field per offset some
access starts at, named `field_0x<offset>`, as wide as the commonest
access there (the widest on a tie), and never into the next field: an
8-byte store over two adjacent 4-byte fields (compilers merge stores)
becomes two fields, the first truncated to `undefinedN`. Its type is a
pointer (`undefined1 *`, Ghidra's `undefined *`) when an access says so
and it has the pointer size, else a float, else the integer the accesses
agree on (`int`, `unsigned long`, … by the program's data model), else
`undefinedN`. The bytes between fields are undefined filler (no field),
negative offsets and offsets past 4 KiB (unless the structure is that
large already) are dropped, and the size is the end of the furthest
access. Packing is classified by the importers' rule, so a structure
with a field below its alignment is `packed`.

**Fill in.** With mode `FILL` the variable must point to a structure (its
asserted type, else the type its decompilation prints): that
structure's fields stay as they are (names, types), new fields go only
where none is (truncated at the next existing one), the size only grows,
and the result keeps its name, so applying it rebinds the name and every
use of it shows the new fields. Nothing new: `unchanged`.

**From a selection.** With a range, a field per data item wholly inside
it (a user's definition by its type, an analysis string as `char[n]`,
UTF-16 and UTF-32 as `char16_t[n]` and `char32_t[n]`, a pointer as
`undefined1 *`); everything else is filler, and the size is the range's.

**Applying it** is one `AppendAssertions`: the response's nodes as
`define_type`s, a `bind_type_name` of the struct (named `astruct`,
`astruct_1`, … the first the program doesn't name, or as asked; a name it
has is `ALREADY_EXISTS`), then a `retype` of the variable to the pointer
(by hash) or, for a range, a `listing_edit` defining the struct at the
start (a Define data may name a type the same request defines). One
revision, one undo, with the client's provenance. As every retype of a
parameter or local, the variable's type is committed to the decompiler,
type-locked as Ghidra commits a variable's type
([decompiler-inputs.md](decompiler-inputs.md#variable-types)), so the
body reads and writes the fields. `lua_settop` in stripped Lua, before and
after Auto create structure on its parameter:

```c
lVar1 = *(long *)(param_1 + 0x10);              // before
puVar1 = param_1->field_0x10;                   // after
if ((lVar5 != 0) && (plVar2 <= *(long **)(param_1 + 0x40))) {
if ((lVar5 != 0) && (plVar2 <= param_1->field_0x40)) {
```

**Inferred structures.** Inference composes structures of its own the
same way, from every function's accesses to one class of passed-on
pointers ([infer.md](infer.md#structures)): `astruct_<n>`, the program's
types since inference published them (provenance
`analysis:infer.prototypes`, category `/inferred`). Its composition keeps
a wide field whole where splitting it at narrower accesses costs more
(`ComposeOptions::keep_wide`); Auto Structure keeps Ghidra's rule (a field
at every access start).

### Editing the preview and chaining (api_minor 56)

With feature `auto-struct-edit` the request carries **edits** to the
composed fields (`AutoStructureFieldEdit`, keyed by offset): a new name (a
C identifier, unique in the structure), a new type (C text, anything
`cparse::parse_declaration` takes over the program's types: `int`,
`char[16]`, `struct hdr *`; a declaration's name, `int count`, names the
field too; or a type's hash), `remove` (the bytes become filler) or `add`
(a field at an offset in filler, inside the structure; it needs a type).
They apply after composing, removes first, then renames and retypes, then
adds, each checked against the fields as they are then. One that doesn't
fit is left out and reported in `field_errors` with its offset: a type
that runs into the next field (`char[12] is 12 bytes: it runs into
field_0x10 at 0x10`), one with no size (an unknown `struct x` is
incomplete), a function type, a bad or duplicate name, no field at the
offset. A field that grows past the end grows the structure. The fields
an edit made or changed say `edited`.

**Chaining** (`AutoStructureRequest.field`, `AutoStructureFieldTarget`):
the structure a struct's field points to, made from what the code reads
and writes through the value the field holds (`param_1->field_0x20->…`).
The decompiler worker records, besides each pointer variable's accesses,
the accesses through every pointer-sized value loaded through it (and
through those, three levels deep), under a path key: `param:0->0x20`,
`param:0->0x20->0x8`. A field target names the outer structure (its
hash), the field's offset and the pointer it is read through
(`base_storage_key`: a variable's key or a path; empty: every variable of
the function that points to the structure, by hash or by name); the
daemon walks `base->0x<offset>` like a variable, call depth included. The
field must be at least pointer-sized (an `undefined8` dereferenced works);
nothing read or written through it is `FAILED_PRECONDITION` ("isn't used
as a pointer here"). The response adds the outer structure's next version
(`outer_index`, `outer_hash`: the same fields, that one retyped to the new
pointer) and `outer_named_key`. Applying it is the nodes, a
`bind_type_name` of the new structure and one of the outer's next version
(no retype): one request, one undo, and the code reads
`param_1->field_0x20->field_0x8`. `FILL` on a field fills the structure it
already points to.

A note from testing it: retyping a parameter of a function whose
prototype nothing gave (no debug info, no inference) locks the prototype
with a `void` return, so code that only computed the return value goes;
functions that store through the pointer keep their body.

### The gate

`tools/rk-infer/auto_struct.py` scores it against debug-info truth: for
every function whose DWARF prototype has a `lua_State *` parameter, it
asks a daemon for a structure from that parameter in the **stripped** Lua
(its register's parameter in the decompilation, inference finished), and
checks every field made from accesses against the true layout's field
starts at any depth (`lua_State` is 200 bytes, 24 fields and 31 starts
with `base_ci`'s and the `StkIdRel` unions'). The design's gate is 95%.

| Lua build | depth | functions scored (with fields) | fields | on a true field start | distinct true starts found |
| --- | ---: | ---: | ---: | ---: | ---: |
| x86-64 gcc -O2 | 0 | 508 (195) | 419 | **99.8%** | 27 / 31 |
| x86-64 gcc -O2 | 1 (default) | 508 (453) | 1458 | **99.9%** | 28 / 31 |
| x86-64 gcc -O2 | 2 | 508 (499) | 2231 | **99.9%** | 28 / 31 |
| AArch64 clang -O2 | 0 | 482 (193) | 468 | **99.8%** | 27 / 31 |
| AArch64 clang -O2 | 1 (default) | 482 (433) | 1426 | **99.3%** | 28 / 31 |

The misses are all at `0xb2`, the upper half of `nCcalls` (0xb0): Lua
counts non-yieldable calls in its high 16 bits (`incnny`, `yieldable`),
and compilers read and write that half alone. Of the 513 (494)
functions, 5 (12) are skipped: no function there in the stripped build,
or no parameter in the register. Names and types aren't gated; a run
takes about 7 s (x86-64) and 9 s (AArch64) for all of them.

```sh
tools/rk-infer/auto_struct.py --binary elf-x86_64/gcc-O2/lua --depth 1   # --json out.json for every field
```

## Type archives

Ghidra keeps types in `.gdt` archives; revkit's archive is text anyone
can read, diff and compile: a **C header** of the types plus a **JSON
sidecar** (design item 7). `TypeService.ExportTypeArchive` (`api_minor`
35, feature `type-archive`; [api.md](api.md#type-archives-and-categories))
writes one for a set of a program's types (named ones, a category, the
ones made in revkit, or all) and every named type they reach; importing
one is the header import (`ParseC`) with the sidecar.

**The header** (`revkit/cparse/archive.h`, `write_archive`) is
self-contained: no `#include`, the definitions in dependency order (what
a struct holds by value and the typedefs it names before it; forward
declarations for structs named earlier, so no prototype declares one),
anonymous structs, unions and enums written inline, a
`_Static_assert(sizeof(...) == N)` per sized type, and a comment giving
the data model. The writer parses its own header for the program's
target and keeps, per struct, the first form that reproduces the type:
C's natural layout, `#pragma pack(1, 2, 4, 8)`, or explicit offsets (a
struct packed to 1 whose gaps are unnamed bitfields, written in a
bitfield's unit type under Microsoft's rules); a packed enum gets
`__attribute__((packed))`. The compiler's own `va_list` is written only
for parsers that lack it (`#if !defined(__GNUC__) ...`, for Ghidra), and
Ghidra's `undefinedN` names as `unsigned char` arrays for compilers
(revkit's parser knows them). What can't be reproduced is a note and a
`source_hash` in the sidecar: C++ types (qualified names, classes,
references) are left out, and one name has one definition per header (a
debug info's second definition of a name is written as the first).

**The sidecar** (`TypeArchiveSidecar` as protobuf JSON) has the format
and version, the header's name and SHA-256, the data model (the cparse
target in full: sizes, alignments, char signedness, bitfield and enum
rules), the provenance (`origin`: the program first exported from), and
per type its key, the hash the header parses to, size, line, category and
form. It is deterministic: the same types, categories, origin and data
model give the same bytes.

**Importing** parses the header for the sidecar's data model (so the
types keep their layouts in a program of another target, with a note),
with none of the program's types in scope (what the archive only
declares stays a declaration), checks every type's hash and the header's
SHA-256, then defines what the program lacks and binds every name it
doesn't already define as the archive does (a library archive's
definition counts as none), files the names under the archive's
categories, all in one revision with provenance `import:archive` whose
version is the archive's origin. Exporting from the importing program
then names the same origin, so **export → import → export is
byte-identical**; importing an archive again finds everything identical
and sends nothing.

**Headers for decompiled C.** Export C and the decomp scratch write their
types with the same writer in two other modes (`cparse::ArchiveOptions`;
`api_minor` 112, [api.md](api.md#queries)): *the decompiler's view*
(`decompiler_view`: a structure's fields as the decompiler was given them,
`types::decompiler_fields`, the same function `inputs::GhidraTypes`
encodes them with, and a byte member `field_0x10` for each byte no field
covers, so the C's names for gaps compile) and *C89* (`Dialect::C89`: no
`_Bool` or `_Static_assert`, `long long` under `__extension__`, int-sized
padding bitfields, enumerators in `int`, no anonymous members or flexible
arrays). Neither is an archive to import back: they write members the
types don't have. Names the including file defines (Ghidra's built-in
`uint`, `undefined4`, `code`) are never written (`provided`).

### The gates

- **Round trip** (`TypeArchiveTest`, backend tests): the corpus's debug
  cJSON, Lua (x86-64 gcc -O2) and zlib (AArch64 clang -O2) export every
  type; ParseC of the archive on the **stripped** twin verifies every
  hash; the import gives the stripped program the debug build's very
  types (same keys, same hashes, so the same layouts) and categories;
  its export is byte for byte the debug build's (header and sidecar);
  a second import sends nothing. A header edited after the export is
  caught (`header_changed`, mismatches). The SDK tests and the UI e2e do
  the same through the clients.
- **Real compilers** (`type_archive_compile`): nine corpus archives
  (x86-64, AArch64 and RISC-V ELF; mingw PE with its PDB) pass
  `clang --target=<target> -fsyntax-only`, 887 `_Static_assert`s of
  sizes included; the backend test compiles its archives too.
- **Every corpus binary** (`rk-debuginfo --archive NAME --target T`):
  every named type of all 27 corpus debug builds reproduces (hash equal)
  and each header compiles with clang for its target.
- **Ghidra** (`type_archive_ghidra`, `tools/ghidra-interop/type_archive_check.py`
  through PyGhidra): Ghidra's own C parser (`CParserUtils`, the
  binary's language and compiler spec) parses the nine archives, and
  every struct, union, enum and typedef it makes is compared with
  revkit's layout: 772 types and 1,975 members, all equal. What Ghidra
  rejects or ignores: a typedef of `wchar_t` (it keeps its own), and, in
  the synthetic layout cases, `aligned(N)` on a struct (any spelling:
  attribute, `__declspec(align)`, `_Alignas`) and packed enums, which
  Ghidra lays out naturally (none in the corpus). `_Static_assert`,
  `#pragma pack`, unnamed bitfields, inline anonymous types and the
  guarded `va_list` are all accepted.

## Library prototypes

Ghidra's **Apply Data Archives** analyzer gives an imported function the
prototype its bundled `.gdt` archives declare for that name
(`generic_clib_64`, `windows_vs12_64`). revkit ships archives of its own,
in its own format (a C header plus the JSON sidecar, [above](#type-archives)),
made at build time from the build host's headers with revkit's C parser
(`api_minor` 50, feature `library-types`):

| Archive | Data model | Made from | Functions | Types |
| --- | --- | --- | ---: | ---: |
| `libc-lp64` | LP64 (`x86_64-linux-gnu`) | glibc headers, `_GNU_SOURCE`, fortified, asm labels | 3690 | 346 |
| `libc-ilp32` | ILP32 (`i386-linux-gnu`) | the same headers | 3688 | 341 |
| `kernel32-llp64`, `-ilp32` | LLP64 / ILP32 (`x86_64-w64-mingw32`, `i686-w64-mingw32`) | mingw-w64 `windows.h`, filtered by `libkernel32.a`'s exports | 1163 / 1130 | 531 / 500 |
| `user32-*` | | `libuser32.a` | 697 / 698 | 335 / 341 |
| `ntdll-*` | | `winternl.h` (`libntdll.a`) | 93 / 84 | 115 / 109 |
| `advapi32-*` | | `libadvapi32.a` | 369 / 358 | 220 / 206 |
| `ws2_32-*` | | `winsock2.h`, `ws2tcpip.h` (`libws2_32.a`) | 122 / 122 | 137 / 136 |
| `msvcrt-*` | | the C runtime's headers (`libmsvcrt.a`, `libucrt.a`, `libucrtbase.a`): Windows' C library | 1357 / 1345 | 107 / 88 |

**Making them** (`tools/rk-typeinfo`, run by the build into
`build/typeinfo`, installed to `share/revkit/typeinfo`): the headers a list
names (`glibc.headers`, `windows.headers`) are parsed for the target with
every prototype kept, system headers' too (`cparse::Options::system_prototypes`;
there the first declaration wins, so glibc's fortified inline `printf`
doesn't replace its declaration), plus a few declarations of revkit's own
for runtime entry points no header declares (`__libc_start_main`,
`__stack_chk_fail`, `__getmainargs`, and glibc's `__isoc99_*scanf`). A
function glibc renames with an asm label (`__REDIRECT`: `strtol` links
as `__isoc23_strtol`) is listed under both names; `noreturn` (the
attribute, `__declspec`, `_Noreturn`) is kept and written as `_Noreturn`.
A Windows DLL's archive keeps the functions whose `__imp_` symbols its
mingw-w64 import library lists (x86's `_name@N` decorations stripped).
The archive writer then lays out every type the prototypes reach and
checks its own header as for any archive: every prototype and type
parses back to the same hash except 7 in user32's (dialog templates under
`#pragma pack(2)` written as an inline anonymous struct), and the
sidecar lists each prototype as `function <name>` with form `prototype`
and its `noreturn`. On 32-bit x86 the calling convention is written
(`HANDLE __stdcall CreateFileA(...)`, `PrintOptions::calling_conventions`).
Two small stand-ins live in the tool's directory: an empty
`gnu/stubs-32.h` (a 64-bit host lacks glibc's 32-bit one) and the vector
types of GCC's `emmintrin.h`, which `winnt.h` includes. Sources and
licences: [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). Without
the headers on the build host the archives are skipped and Ghidra's are
used alone.

**Applying them** (`revkit/inputs/library.h`, the `library_signatures`
step of `inputs::assemble_program`, so rk-lift and the daemon agree): the
archives for the image (`default_library_archives`: `libc-lp64` or
`libc-ilp32` for ELF by address size; for PE the six Windows archives of
its data model) are parsed once per target with the **program's** profile
(its compiler spec's data organization, so a 32-bit ARM program lays the
ILP32 archive's structs out by AAPCS), and an import, an external
function, or a function named like one (`_name` for `name`, a symbol
version or stdcall suffix dropped), whose signature nothing better gave,
gets the prototype: its calling convention where the compiler spec has a
model for it (`__stdcall` on 32-bit Windows), varargs, and no-return.
Ghidra's `.gdt` follows for the names revkit's archives don't declare
(the rest of the Windows API). The rank is Ghidra's: debug info (DWARF,
PDB), the demangler and every assertion (the user's, an agent's) come
first; inference and Decompiler Parameter ID only fill what the library
leaves, so inference no longer guesses `printf`'s parameters.
`GetFunction` shows the prototype with origin `derived:
library:<archive>`; the archives' named types are `types.library`
(`TYPE_SOURCE_LIBRARY`, origin `library:<archive>` per type), revkit's
first and Ghidra's after for names they lack.

Two departures from Ghidra:

- **What the `.gdt` reaches.** It applies by name only to an import, an
  external function or a thunk of one, never to a function the program
  defines. Ghidra's `generic_clib` declares an OpenSSL engine's `_init`,
  so every ELF program's `_init` became `int _init(EVP_PKEY_CTX *ctx)`.
  revkit's own archives declare what their libraries export, so they
  still apply to definitions (a statically linked `memcpy`).
- **The C runtime's own code.** A program's start-up and tear-down
  functions (`_init`, `_fini`, `_start`, `__libc_csu_init`/`fini`,
  `frame_dummy`, `register_tm_clones`, `deregister_tm_clones`,
  `__do_global_dtors_aux`, `_DT_INIT`/`_DT_FINI`, ...;
  `inputs::crt_function`) take no archive prototype at all, in the
  decompiler and in `GetFunction`.

Effects on the C, besides the prototypes: Ghidra's archive leaves the
convention `unknown`, so every import thunk carried "WARNING: Unknown
calling convention -- yet parameter storage is locked". revkit's archives,
and now the `.gdt`'s prototypes too, get the compiler spec's default
convention, so the warning goes. A PDB's procedure without parameters is
`__cdecl` like the others, as Ghidra shows it (`char * __cdecl
cJSON_Version(void)`); it was `unknown`. `exit` and kin are no-return
through the archive too.

On the corpus, with revkit's own inputs, the warning went from 10
functions to 0: the two `_init`s of `lua` and `features` (debug builds)
and eight PDB procedures without parameters in `cjson.exe`. The binaries
were x86-64 ELF `lua`, `zlib` and `features`, AArch64 `cjson`, and PE
`cjson.exe` with and without its PDB.

### Format strings

Ghidra's **Variadic Function Signature Override** analysis: a call to a
varargs function whose format parameter (a pointer to characters named
like a format: glibc's `__format`/`__fmt`, mingw's `_Format`) is a
constant string gets a call-site prototype with exactly the arguments the
format names, and the function is decompiled again with it
(`lift::DecompileConfig::format_strings`; `format_string.hh` reads the
format). printf's conversions with flags, `*` widths and precisions,
lengths (`hh` to `ll`, `j`, `z`, `t`, `L`, Microsoft's `I64`/`I32`/`I`
and wide `%S`/`%C` on PE), glibc's `%m`; scanf's pointers, `*`
suppression and scan sets (functions named `*scanf*`). Positional
arguments (`%1$d`), allocating `%ms` and an unknown conversion leave the
call alone. The string comes from data analysis or the image's bytes
(8-, 16- or 32-bit characters, as the parameter's type says). Only for
revkit's own inputs (rk-lift `--analyze --decompile`, `--no-format-strings`
to leave it out; the daemon's decompilations), never for Ghidra's exported
inputs, whose C must stay identical to Ghidra's. In the decompiled C the
arguments are the format's: `snprintf(local_58,0x20,"k%d",iVar9)` where
the call passed a 64-bit register before (`(ulong)uVar9`), and a string
argument shows as its literal (`"path"` for `&DAT_00106247`).

## C++ classes as `this`

The demangler gives a member function's prototype (docs/demangle.md):
`this` is a pointer to its class, and the class is a declaration of that
name with no layout, so the decompiled C reads `*(int *)(this + 0x14)`.
Where the program defines the class (a C++ header imported with ParseC,
`cplusplus` on: its fields, its `_vptr.<class>` and its size; DefineType;
debug info another module brings), the decompiler now gets that
definition wherever a demangled prototype names the class: the backend's
lookup (`QueryLookup::defined_class`) answers the request for the
declared class's type with the program's definition, under the id the
demangled prototypes use, so `this` of every member function, and class
pointers among their parameters (`Scene::add(Shape *)`), have the fields:

```c
void Shape::move(Shape *this,int param_2,int param_3)
{
  this->x = this->x + param_2;
  this->y = this->y + param_3;
  this->flags = this->flags | 2;
  return;
}
```

A name binds when exactly one complete program type has it (as `class N`
or `struct N`, or in a namespace, `class ns::N`; a BindTypeName binding
of the name wins over the definition it replaced); the decompilations
depend on the program's named types, so importing or editing the header
redoes them. `CxxThisTest.ImportedClassesTypeThis` checks it on the
32-bit ARM fixture's C++ (tests/data/arm32, `shapes.h`).

Left: virtual calls go through the header's `_vptr.Shape`, an `int
(**)(...)` as GCC's own `__vtbl_ptr_type`, so they print as
`(*this->items[i]->_vptr.Shape[2])()`, with neither the method nor its
arguments; vtables from `_ZTV` symbols and from constructors storing the
vtable pointer, typed as a structure of the virtual methods' pointers,
would name them. A class pointer the header's own fields hold and the
demangler's of the same name are two types to the decompiler, so storing
one into the other casts (`this->items[n] = (Shape *)param_2`).

## Project types

A project's types (`api_minor` 52, feature `project-types`): defined once
at project scope, seen by every program of the project, so programs built
from one source tree share a struct and one edit reaches them all.
Ghidra keeps such types in a project data type archive the programs open;
here they are assertions in the project's own space, so they have
provenance, undo, history and blame like a program's.

**Where they live.** `TYPE_DEF` keys in the project's space (space 15) at
address 0, as a program's are in its own: a record per content hash,
`name:<key>` bindings, `category:<key>` paths. Every type query of a
program reads them after its own: `types.closure` and `types.resolved`
find a record by hash in the program, then the project, then the library
archives; `types.names` lists the project's named types the program
doesn't define itself (`NamedTypes::Entry.project`), and the project's
binding of a name the program doesn't bind; `types.resolved` follows the
program's binding of a name, else the project's; `types.categories` and
`types.aggregate_ids` likewise. A program's own definition or binding of
a name therefore wins: the project's is what every program sees unless
one says otherwise.

**Editing them.** `AppendAssertionsRequest.project_scope` keys a
request's `define_type`, `bind_type_name` and `type_category` bodies in
the project's space (only those bodies; the program named lays the types
out for its data model): an edit of a project struct binds the project's
name to the new definition, and every program's prototypes, globals,
variables and decompilations that use the name show it, as a
program-scope `BindTypeName` does for one program. The test
(`ProjectTypesTest.TwoProgramsShareAStructAndAnEditReachesBoth`, and the
SDK's, MCP's and UI's): two programs built with the same `struct point`;
moved to the project from the first; its fields renamed at project scope;
the first program's `gety` and the second's `sumxy` decompile to
`p->py` and `p->px + p->py * 3`.

**Moving and copying.** `TypeService.CopyTypes` in one revision:

- **Move to project** (`COPY_TYPES_MODE_MOVE_TO_PROJECT`): the named
  types' definitions (the program's binding of each, else its one
  definition) and every record they reach are defined at project scope,
  each name bound and filed there as the program filed it, and the
  program's own definitions, binding and filing of the names retracted,
  so the program sees the project's (the same hashes: nothing that uses
  them changes). Library records stay the library's.
- **Copy to program** (`COPY_TYPES_MODE_COPY_TO_PROGRAM`): the project's
  definitions and their records defined in the program and the names
  bound there, so the program's copy wins and changes alone.

The response lists the types and how many records, assertions and
retractions it made, and the revision's `seqs`, whose retraction undoes
it (the UI's undo step).

**Archives for the project.** `AssertionBody.type_archive`
(`TypeArchiveSetting`; a `NOTE` in the project's space at 2^48+1, sub
`revkit:type-archive:<name>`) switches a library archive off or on for
every program (a shipped one by name, Ghidra's `.gdt` as `ghidra`), or
attaches an archive to the project: its header (and sidecar, optional),
whose prototypes apply to every program's functions by name at library
rank after the shipped archives' (an attached archive of a shipped one's
name replaces it), and whose types are every program's library types
(`library.prototypes` reads `types.archive_settings`). Switching an
attached archive off or on keeps its header; `detach` removes it (for a
shipped one, back to on). `TypeService.ListTypeArchives` lists, for a
program, the shipped archives (`applies` to its format and data model),
Ghidra's and the attached ones, each `enabled`, with how many functions
and types it gives the program, its data model and origin (the sidecar's
provenance) and its parse errors for this target.

**Replicated and exported.** Project types and archive settings are ops
of the project's log like any other, so peers replicate them
([collab.md](collab.md)); `.rkproj` archives carry them whichever
programs are exported, and importing one keeps them (into a new project
or merged into an existing one). Revision events carry their keys with
`FactKey.project` and invalidate every program's types (and, for a
binding or an archive setting, prototypes, listings and decompilations).

## Categories

A named type can be filed under a category, a '/'-separated path like
Ghidra's category paths: `SetTypeCategory` asserts `TYPE_DEF`
`category:<named key>` = path (design item 8). The path is the name's,
for every definition of it, and is read by `types.categories`, a query
apart from `types.names` so filing never touches the decompiler. Where
the categories come from:

- **DWARF**: each named type's `DW_AT_decl_file`, through its unit's line
  table header (DWARF 2-5 file names; `.debug_line_str` too), as
  `/<file name>` (`/cJSON.h`, `/stddef.h`), as Ghidra files DWARF types;
- **PDB**: `LF_UDT_SRC_LINE` (and `LF_UDT_MOD_SRC_LINE`, through the
  `/names` stream) for structs, unions and enums, and the typedefs an
  `S_UDT` makes for them;
- **a header import**: the header's name; **an archive's**: its own.

`FindTypes` filters by category and lists the categories with their
counts (the UI's folder tree); a search still spans every category.

## DWARF coverage

- DWARF 2-5, 32- and 64-bit units; compile, partial and (DWARF 5) type
  units, with `DW_FORM_ref_sig8` resolved through the type-unit signatures.
- All DWARF 5 forms plus `DW_FORM_indirect` and the GNU index forms;
  `.debug_str`, `.debug_line_str`, `.debug_str_offsets` (strx),
  `.debug_addr` (addrx), `.debug_rnglists` (incl. rnglistx) and
  `.debug_ranges`; `DW_AT_high_pc` as address or length.
- Types: base, pointer, reference, rvalue reference, const, volatile,
  restrict, atomic, typedef, struct/class/union (members, inheritance as a
  field, `DW_AT_data_member_location` as constant or `DW_OP_plus_uconst`,
  bitfields via `DW_AT_data_bit_offset` or DWARF 2-4 `DW_AT_bit_offset`),
  enum (signedness from the underlying type), arrays (multi-dimensional,
  `DW_AT_count` or bounds), subroutine types, unspecified types.
  Declarations (`struct foo;`) resolve to the binary's definition when it
  has exactly one. Packing is inferred from member offsets.
- Functions: every `DW_TAG_subprogram` with code, through
  `DW_AT_specification` and `DW_AT_abstract_origin` chains; name, qualified
  C++ name, linkage name, entry (`DW_AT_entry_pc` or `DW_AT_low_pc`),
  ranges, prototype, parameter names, external, noreturn, and
  `DW_CC_nocall` (GCC changed the ABI, so the prototype isn't the ABI).
- Variables with a static `DW_OP_addr`/`DW_OP_addrx` location.
- Malformed input never crashes: every read is bounds-checked, recursion is
  bounded or iterative, and a bad unit is reported in `diagnostics` and
  skipped. Tested with handcrafted bad units, truncation, random mutation,
  and a libFuzzer target (`-DREVKIT_FUZZ=ON` with clang;
  `src/debuginfo/fuzz/make_seeds.py` makes seeds from ELF files).

## PDB coverage

`read_pdb()` (`revkit/debuginfo/pdb.h`) reads a PDB's bytes; nothing from
LLVM's PDB libraries is used.

- Container: MSF 7.00 ("big MSF", block sizes 512 to 32768), with the
  stream directory read through the block map and every stream assembled
  from its blocks with bounds checks. PDB 2.00 (small MSF) is refused.
- PDB info stream: version, signature, age, GUID, the named stream map
  and feature codes. `read_pdb_identity()` reads only that and the DBI
  header, and `PdbIdentity::matches()` checks a PE's RSDS GUID and age
  (`loader::Image::codeview`).
- DBI: header (age, machine, symbol record stream), module info (object
  names, symbol streams), section contributions (V60 and V2), the section
  map, and the optional debug header's section headers and OMAP (with the
  original section headers), which turn `section:offset` into an RVA.
- TPI and IPI records, indexed by type index.
- Symbols: the global symbol record stream (`S_PUB32` with demangled
  names, `S_GDATA32`, `S_LDATA32`, `S_UDT`) and each module's C13 symbol
  stream: `S_GPROC32`, `S_LPROC32` and their `_ID` and DPC forms (an
  `_ID` procedure's type comes through the IPI's `LF_FUNC_ID` /
  `LF_MFUNC_ID`), `S_THUNK32`, `S_SEPCODE` (extra ranges), scopes
  (`S_BLOCK32`, `S_WITH32`, `S_INLINESITE`/`2`, `S_END`,
  `S_PROC_ID_END`, `S_INLINESITE_END`), locals and parameters (`S_LOCAL`
  with its first `S_DEFRANGE_*` location, `S_REGREL32`, `S_BPREL32`,
  `S_REGISTER`), data (`S_GDATA32`/`S_LDATA32` in a procedure are
  function-local statics) and `S_COMPILE2`/`S_COMPILE3`.
- Types: the simple types (every integer, character, boolean, real and
  complex kind, `void`, `HRESULT`, and their pointer modes), `LF_POINTER`
  (pointers, references, rvalue references, const/volatile/restrict
  pointers; pointers to members become "undefined"), `LF_MODIFIER`
  (stacked modifiers merge), `LF_ARRAY` (multi-dimensional, unknown
  bound), `LF_STRUCTURE`/`LF_CLASS`/`LF_INTERFACE`/`LF_UNION` with
  `LF_FIELDLIST` (`LF_MEMBER`, `LF_BITFIELD` members, `LF_BCLASS`,
  `LF_INDEX` continuations; static members, nested types and virtual
  bases are skipped; a class's own vtable pointer is a `vftable` field
  pointing to a `<class>_vtbl` struct of the virtual functions it
  introduces, from its methods: [pdb.md](pdb.md#c-classes)), `LF_ENUM`, `LF_PROCEDURE`,
  `LF_MFUNCTION` (`this` first), `LF_ARGLIST` (a trailing `T_NOTYPE` is
  `...`) and `LF_ALIAS`. A forward reference resolves to the PDB's
  definition with the same unique name (or name) when there is exactly
  one. `S_UDT` names that aren't a type's own tag become typedefs
  (`PdbDebugInfo::type_names`).
- Functions: qualified and unqualified name, the public symbol's mangled
  name as `linkage_name`, address (RVA plus `PdbOptions::image_base`),
  length, noreturn, and a prototype whose parameter names come from the
  procedure's own `S_LOCAL` parameter symbols, or, without those (MSVC),
  its first `S_REGREL32`/`S_BPREL32`/`S_REGISTER` symbols. Clang omits
  unused parameters from the PDB; the others are named when their types
  place them in the argument list in exactly one way.
- Malformed input never crashes: an unreadable container or info stream
  raises `PdbError`; anything else is skipped and reported in
  `diagnostics` (capped at 256, and 16 bad records per symbol stream).
  Recursion is replaced by work lists, and chains (modifiers, field list
  continuations, scopes) are bounded.

### One type, either format

The PDB importer maps CodeView so that the same C type hashes the same as
from DWARF: simple types get the integer rank DWARF base types get from
their names (`T_LONG` is `long`, `T_QUAD` is `long long`, `T_RCHAR` is
plain `char`), the "near C" calling convention is the default one,
`<unnamed-tag>`-style names are anonymous, bitfields get absolute bit
offsets, `this` loses the pointer `const` CodeView gives it (as in clang's
DWARF), and packing is inferred by the same rule. The DWARF importer in
turn merges a chain of qualifier DIEs into one node, as CodeView has one
`LF_MODIFIER`. CodeView has no typedefs, so DWARF types compare after
`types::without_typedefs()` (with `name_anonymous_tags`, since clang's
CodeView gives `typedef struct {...} point;` the tag `point`).

Deliberate exceptions, where the PDB says something else or less:

- CodeView flattens an anonymous struct or union member into its parent's
  fields; DWARF keeps the nested type.
- C's `wchar_t` (a typedef of `unsigned short`) is `T_WCHAR`, read as the
  C++ `wchar_t` type.
- Clang leaves unused parameters out of the PDB, so they are unnamed.
- `T_REAL128` is read as a 16-byte `long double` (x86-64 mingw's x87
  format); a real `__float128` would differ from DWARF's.
- CodeView has no explicit alignment (`alignas`) and no SysV calling
  convention on x86-64 (`sysv_abi`), and the importer doesn't model
  virtual bases or vtable pointers, which DWARF records as fields.

On features (-O0, -O2), cJSON, zlib and Lua built with clang 18 for
x86_64-windows-gnu with both `-gcodeview` and `-gdwarf`, 1003 of 1014
function prototypes and all 116 named structs, unions and enums imported
from the PDB are the same `TypeId` as the typedef-resolved DWARF; the 11
others are one C `wchar_t` and ten functions with unused parameters. The
GoogleTest fixtures check this on every build.

## Results

- Fuzzing (clang 18, ASan+UBSan, 8 forks): `dwarf_fuzzer` ran 20 minutes
  (5.2M inputs seeded from the fixtures and corpus binaries) with no
  crashes, hangs or leaks. `demangle_fuzzer` found that LLVM's D demangler
  reads past a non-terminated `string_view`; the wrapper now passes
  NUL-terminated copies, and a 5-minute rerun (41M inputs) was clean.
- On the corpus debug builds (zlib, Lua, cJSON, features; x86-64, AArch64,
  RISC-V; gcc and clang; -O0 and -O2), Ghidra's own prototypes agree with
  the DWARF truth on 98.1% of 3249 functions exactly, 99.2% normalized and
  99.5% by signature (`protonorm.py`); the rest are Ghidra errors (extra
  parameters from GCC's concrete DIEs, AArch64 `va_list *`, one bad
  `long double` return). On the stripped builds, the decompiler's signature
  matches the typedef-resolved truth for 4.5% of functions and has the
  right arity for 86.5%.
- PE (clang for mingw, lld, PDB; features -O0 and -O2, cJSON -O2): against
  the PDB truth (`rk-debuginfo --no-dwarf`, 232 functions), Ghidra's
  prototypes agree 3.9% exactly, 3.9% normalized, 90.1% by signature and
  90.9% by arity. Ghidra's PDB import names no parameters (clang writes
  them as `S_LOCAL` with def ranges, which Ghidra doesn't apply), so
  only parameterless functions match exactly; the signature misses are
  Ghidra errors: it drops `...` from every variadic function, and shows
  the Windows x64 ABI's by-reference `long double` (`float16 *`) instead
  of the declared type. With the images' DWARF for the mingw runtime added
  (the default, 547 functions) the rates are 55.2%, 55.4%, 92.0% and
  96.2%. On the stripped PE builds the decompiler's signature matches the
  PDB truth for 7.8% of functions and has the right arity for 73.7%.
- Fuzzing the PDB reader is deferred to the end of the project. The
  target exists (`pdb_fuzzer`, seeds from `make_pdb_seeds.py` and
  `pdb_seed`); preliminary runs (clang 18, ASan+UBSan, 8 forks, about 26
  minutes and 2.7M inputs in all) found nothing, but that is not the
  planned campaign.

## Known gaps

- Linked images only: no relocation of `.o` files, no split DWARF
  (`.dwo`/`.dwp`, skeleton units), no `.debug_types` (DWARF 4 type units),
  no supplementary files (`DW_FORM_GNU_ref_alt`, `.gnu_debugaltlink`).
  (A stripped ELF's separate debug file, found by build ID or
  `.gnu_debuglink`, is read as its own: [backend.md](backend.md#external-debug-files).)
- Location lists are skipped, not decoded; of `.debug_line` only the
  header's file names are read (for `DW_AT_decl_file`); nothing reads
  `.debug_frame` or `.debug_loclists`.
- Pointer-to-member, Fortran strings/sets and Ada subranges become
  "undefined of N bytes"; C++ templates, virtual bases and vtables are not
  modeled beyond their fields; K&R unprototyped functions print as `(void)`.
- Packing is inferred, not recorded by DWARF, with alignment capped at the
  address size; an explicitly over-aligned or oddly packed struct can be
  misclassified.
- `__float128` and `long double` share a size on some targets and are told
  apart by name only.
- Hashing a large strongly connected component is quadratic in its size.
- PDB: no PDB 2.00 (small MSF) files, no type servers (`LF_TYPESERVER2`)
  or precompiled-header types (`LF_PRECOMP`), no `LF_UNION2` (MSVC 17.x's
  `LF_CLASS2`, `LF_STRUCTURE2` and `LF_INTERFACE2` are read: [pdb.md](pdb.md)), no line numbers (C13 subsections), no
  `S_CONSTANT`, `S_GTHREAD32`/`S_LTHREAD32`, managed or ARM-specific
  symbols, and nothing reads the GSI hash tables (the symbol record stream
  is scanned instead). Functions known only from `S_PUB32` (no procedure
  symbol) are listed in `publics` but not in `functions`. OMAP is
  supported but untested on a real rewritten image. Big-endian or
  non-x86/ARM64 PDBs don't exist.
