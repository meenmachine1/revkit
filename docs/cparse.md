# C headers into types (`revkit::cparse`)

`src/cparse` (`revkit::cparse`) parses C, and the subset of C++ headers use,
into revkit's type model ([types.md](types.md)): structs, unions, enums and
typedefs laid out by the program's data model, function prototypes with
parameter names, integer `#define` constants, and line-numbered
diagnostics. It is how headers are imported into a program, how a
`c_declaration` retype becomes a real type, and what `rk-cparse` runs.

- [Decisions](#decisions)
- [What it parses](#what-it-parses)
- [Targets and layout](#targets-and-layout)
- [Untrusted input](#untrusted-input)
- [In the daemon](#in-the-daemon)
- [In the UI](#in-the-ui)
- [rk-cparse](#rk-cparse) (and `--archive`)
- [Verification](#verification)
- [Known gaps](#known-gaps)

## Decisions

- **Hand-written, no libclang.** A preprocessor and a recursive-descent
  declaration parser (about 6,000 lines). libclang would break the package
  contract (`libc6` and `libstdc++6` only, [packaging.md](packaging.md)),
  needs a target triple where revkit's layout authority is the program's
  compiler spec, answers fragments with unknown types with errors instead
  of placeholders, and is a large C++ dependency parsing untrusted input in
  the daemon. clang is used only as a test oracle (below).
- **Hashes like the debug info's.** A parsed struct must be the same
  `TypeId` as the DWARF or PDB importer makes for it, so an imported header
  is identical to a debug build's types, re-importing changes nothing, and
  conflicts are real differences. Packing is classified by the importers'
  own rule (`types::infer_packing`, moved to `revkit/types/packing.h`),
  plain `char` has the target's signedness, unnamed bitfields are left out
  (compilers record none), function types other than a prototype carry no
  parameter names, and `__builtin_va_list` is the typedef GCC and clang
  record.
- **Pure parse, client-side import.** `TypeService.ParseC` asserts nothing;
  the client defines what it chose with `AppendAssertions` (one request:
  one revision, one undo), as the design consult chose over a server-side
  import.

## What it parses

**Preprocessor** (`preprocessor.cc`, `lexer.cc`): object and function-like
macros with hide sets (Prosser's algorithm), `#`, `##`, `__VA_ARGS__`,
`__VA_OPT__`, GNU `, ## __VA_ARGS__`; `#if`/`#elif` with full integer
arithmetic, `defined`, `__has_include` (resolved through the same file
access as `#include`), `__has_attribute`, `__has_builtin`; `#include` and
`#include_next` with `-I`, built-in and `-isystem` directories, include
guards and `#pragma once`; `#line` and GCC line markers; `#pragma pack`
(`push`/`pop`/`N`, also as `_Pragma` and `__pragma`), `push_macro` and
`pop_macro`, `GCC system_header`; `#error` and `#warning` as diagnostics.

**Built-in headers**, sized from the target (they are written over the
macros the profile predefines, as GCC's are): `stddef.h` (with glibc's
`__need_*` protocol), `stdint.h`, `stdbool.h`, `stdarg.h`, `limits.h`,
`float.h`, `stdalign.h`, `stdnoreturn.h`, `iso646.h`, `stdatomic.h`,
`mm_malloc.h`. With a C library's include directory (`-isystem`), its own
`stdint.h` and `limits.h` are included next, as GCC's do.

**Preprocessed input.** Output of `clang -E -dD` or `cl /E` (it starts
with a line marker) is taken as it is: its `#define`s are kept for the
constants, its text isn't expanded again, its line markers give the
diagnostics' files and lines and mark system headers, and its `#pragma
pack` lines still apply. This is the escape hatch for SDKs the
preprocessor can't handle.

**Declarations** (`parser.cc`): structs and unions (forward declarations,
anonymous members, flexible and zero-length arrays, bitfields), enums
(fixed underlying types), typedefs, prototypes and function definitions
(bodies skipped, K&R definitions too), function pointers and the full
declarator grammar, `const`/`volatile`/`restrict`/`_Atomic`,
`__attribute__((packed, aligned(N), mode(...), vector_size(N), ms_abi,
...))`, `__declspec(align(N))`, `alignas`/`_Alignas`, `[[...]]`, calling
convention keywords (recorded as compilers record them: ignored on x86-64,
kept on i386), `_Static_assert` evaluated (a failure is an error),
`typeof`, `__int128`, `_Float16`..`_Float128`, `_Complex`, AArch64's NEON
and SVE types. Integer constant expressions have C's types and widths,
`sizeof`, `_Alignof`, `offsetof` and casts.

**C++ subset**: namespaces (qualified names `ns::name`), classes with
access specifiers and methods (skipped), static members, constructors and
destructors (skipped), single and multiple inheritance as unnamed base
fields, a vtable pointer for a class with virtual methods, `enum class`
(and its underlying type), references, `using X = T`. Templates and
operators are skipped with a warning.

**Constants**: every object-like macro of the sources' own files (not
system headers) whose expansion is an integer constant expression;
`defines_as_enum` groups each file's into one enum, `<file>_constants`.

**Ghidra's names**: `undefined`, `undefined1` … `undefinedN` are
undefined types of that size unless the sources declare the name, as
revkit and Ghidra print them; the profile predefines `__revkit__`, so a
header (a type archive's) can keep lines for other compilers from it.

**Recovery**: an error skips to the next `;` or the end of the enclosing
block, at file level and inside a struct, and keeps everything else. An
unknown type name becomes `undefined4` (the data model's `int`) with one
error per name; an unknown identifier before a type keyword (an
unexpanded `FOO_API` macro) is ignored with a warning.

**Names from the program.** A name the sources use but don't declare is
looked up in the program's named types (its bound definition, else its
own, else the library archive's), and a struct the sources only declare
is the program's definition when it has one. `link()` does the same
between translation units: a struct one unit only declares becomes the
definition the others agree on (by shape), as the DWARF importer resolves
declarations for a whole binary.

## Targets and layout

A `Profile` is a target: layout rules, compiler dialect and predefined
macros. In the daemon it comes from the program: `cparse::profile_for`
starts from the target its language, compiler spec id and format name and
lays over it the compiler spec's `<data_organization>`, read by
`lift::read_data_organization` with the Element helpers
`ImageArchitecture` uses for the decompiler's core types
(`src/lift/spec_xml.hh`). Where Ghidra's specs disagree with the
platform's ABI the ABI wins and a note says so: AArch64 and RISC-V Linux
have a 16-byte long double and unsigned `char`, which the specs leave at
8 bytes and signed, and RISC-V's size map stops at 8 bytes. A test checks
that the specs give the named targets (`CParseSpec`).

A language with no named target gets C's usual sizes for its address
size, with the compiler spec's data organization over them where it has
one. Microcontrollers (16- and 24-bit addresses: AVR, 8051, Z80, PIC,
MSP430, the address-space languages) get their compilers' model: `int` 2
bytes, `long` 4, `double` 4, pointers of the address size (2, or 3 for
24-bit), alignment at most 2, and none at all on 8-bit cores (8051, Z80,
PIC, 6502, HC08, AVR), as avr-gcc, SDCC, Keil and XC8 lay structs out; a
profile note says so (`ParseCResponse.profile_notes`, shown by the header
import), and a spec's own sizes win (AVR's and MSP430's do). Tested by
`CParseSpec.MicrocontrollerTargets` and, through the daemon on raw AVR and
8051 programs, `ParseCTargets.MicrocontrollerPrograms`.

Named targets: `x86_64-linux-gnu`, `aarch64-linux-gnu`, `riscv64-linux-gnu`,
`x86_64-w64-mingw32`, `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`,
`i386-linux-gnu`, `i686-w64-mingw32`, `i386-pc-windows-msvc`,
`arm-linux-gnueabihf`, `arm-none-eabi`, `riscv32-linux-gnu`,
`powerpc-linux-gnu`, `mips-linux-gnu`, `mipsel-linux-gnu`. A PE's program
gets the MSVC target (Ghidra's `windows` compiler spec); a mingw-built one
should be parsed with `profile: "x86_64-w64-mingw32"` (16-byte long
double, GCC's enums).

Layout: GCC's rules (a bitfield moves to the next unit of its type's
alignment only when it would span more units than its type; named
bitfields' types count toward alignment; AAPCS's zero-width bitfields
align the struct; `packed`, member `aligned`, `#pragma pack`) and
Microsoft's (a run of bitfields of one size shares a unit; a different
size starts a new one; mingw's GCC and clang keep that unit aligned in a
packed struct, Microsoft's compiler doesn't); enums unsigned unless
negative and 8 bytes when a value needs it (GCC), always `int` (MSVC);
GCC vectors aligned to their size up to the target's limit.

## Untrusted input

The daemon parses headers its callers send. Every resource is bounded
(`cparse::Limits`, a parse that hits one stops with what it has and
`limit_hit`): 64 MiB of source text, 4,096 files, include depth 64,
20 million tokens of macro expansion, 50 million tokens read, nesting of
200 (declarators, expressions, braces, `#if`, macro arguments, namespaces),
2 million types, 1,000 diagnostics, 20 s. Recursion is bounded by the
same nesting limit. Files are read only through a `FileSystem`: the
daemon's is `host_file_system(--browse-root dirs)`, which canonicalizes
every path (so neither `..` nor a symlink leaves a root) and refuses what
isn't under one; every `#include` and `__has_include` resolves through it.
Without a file system (pasted text) no file is read except the built-in
headers.

`cparse_fuzzer` (`-DREVKIT_FUZZ=ON` with clang, ASan and UBSan) takes a
flags byte (target, C++, constants as enums, a second linked unit) and up
to three files that may include each other; `src/cparse/fuzz/make_seeds.py`
makes seeds from headers and `cparse.dict` is its dictionary.

## In the daemon

**`TypeService.ParseC`** (`api_minor` 25, feature `parse-c`;
[api.md](api.md#parsing-c)). Sources are text, or paths on the daemon's
host under `--browse-root` (as are `include_dirs`); host paths need admin,
pasted text needs viewer. The response has every type the named types,
prototypes and constant enums need that the program lacks, as
DefineType-ready `TypeNode`s whose references are indices into the list
(or hashes of the program's types), each node's hash, the named types with
the program's definition of each name (`existing_hash`: equal is
identical, empty is new, different is a conflict, also listed with
`same_layout`), constants, prototypes, diagnostics and the target used.
The SDKs' `import_header` defines the chosen nodes and binds their names
in one request with provenance `import:header`, the file as its version
and a session of its own, so `RevertByProvenance` on that session undoes
it.

**Types by hash.** A type name `__revkit_type_<hash>` is the program's
type with that hash itself (`ProgramTypes::lookup`; an anonymous struct or
union so named, alone in a member declaration, is an anonymous member),
so C can name an exact type the program has, as no spelling can when two
definitions share a name. A struct written with its fields' types by hash
parses to its own hash (`ParseCTest.TypesByHash`). The response also gives
each node's C spelling (`displays`), each named type's definition
(`c_definition`) and each diagnostic's line (`source_line`), for previews.

**`c_declaration` retypes** (`parse_c.cc`, `ParseRetype`): the text is
parsed as one declaration against the program's types (a prototype for a
function's entry, keeping its parameter names); the retype's value is the
type's hash, and the types it reaches that the program lacks are defined
by the same request (their `TYPE_DEF` assertions follow the request's in
the response). The decompiler then uses it like any hashed prototype or
data type. Text that doesn't parse is stored as text, as all of it was
before; old `c:` facts read as before.

**Bound names reach debug-info variables.** `BindTypeName` already reached
asserted and debug-info prototypes; the types the decompiler gets for
debug-info globals and locals now go through `types.resolved` too
(`own_inputs.cc`: a variable whose debug-info type reaches a rebound name
is given the bound definition; a stack local keeps its slot's size, so an
edit that resizes its type leaves that local alone). The import records
locals' types so their names can be rebound (`debug_import.cc`), and
`LocalFacts` carries its debug-info type's hash (`source_type`; the
`inputs.*` rule versions were bumped).

On Lua's headers (`lua.h`, `lauxlib.h`, `lualib.h`, `lstate.h`, `lobject.h`,
`lparser.h`, `llex.h`, `lcode.h`) into the stripped `lua`: ParseC 0.14 s
(405 nodes, 107 named types, 240 prototypes), the import 17 ms as one
revision of 315 assertions, the first decompilation after it 46 ms.

## In the UI

The web UI ([ui.md](ui.md#types-editor-and-header-import)) uses ParseC for
everything about types, and computes no layout itself:

- **Import header…**: a header pasted, uploaded or on the daemon's host,
  with include folders, defines and the target; the response's named types
  are previewed as new, replacing (both definitions) or identical, with a
  policy each (import, skip, rename), the diagnostics with their lines,
  the constants' enums and the prototypes naming functions; the import is
  `headerImportPlan`'s bodies (plus retypes by hash) in one
  `AppendAssertions` with provenance `import:header`.
- **The type editor**: the draft is C (`ui/src/data/cgen.ts`), the fields
  it didn't change by hash, edited ones through `__typeof__`, plus a probe
  struct per field (`struct { char c; T x; }`: `x`'s offset is `T`'s
  alignment, the size less it is `T`'s size). Natural layouts are C's
  rules (with `packed`, `#pragma pack` and `aligned`); explicit ones are a
  packed struct whose gaps are unnamed bitfields, which compilers, and so
  the parser, don't record as fields, after which the importers' packing
  rule decides `packed`. This is the design's "ParseC of the edited C";
  no `LayoutType` RPC was needed.
- **Edit in C**, member declarations typed where a field's type goes,
  "Paste C…", enum values as C expressions, and retypes (checked as they
  are typed; definitions before the declaration are defined with it).

## rk-cparse

```sh
rk-cparse cJSON.h                              # C definitions, prototypes, constants
rk-cparse --json --target aarch64-linux-gnu -I include foo.h
rk-cparse --language ARM:LE:32:v8 --compiler default fw.h   # the target from Ghidra's spec
rk-cparse --units --system -isystem /usr/include a.c b.c    # translation units, linked
rk-cparse --dump "struct foo" foo.h            # every node it reaches, for diffs
rk-cparse --archive foo foo.h                  # the named types as a type archive's header
```

`--json` gives each named type's layout (size, fields with bit offsets
and widths) and its hash with and without typedefs, the same shape
`rk-debuginfo --types-json` gives for a binary's DWARF or PDB. Exit status
1 when a source had errors.

## Verification

**Round trip** (`scripts/cparse_roundtrip.py`, a CI gate with
`corpus/baselines/cparse-roundtrip.json`): each corpus program's own
sources (`corpus/src/features/*.c`; cJSON, zlib and Lua from the cached
tarballs: every `.c` file with its headers, function bodies skipped,
linked as units) are parsed under the data model of every corpus binary
built from them, with the C library headers that binary was compiled
against (copied out of the corpus image, `scripts/cparse-sysroots.sh`:
Debian trixie's glibc for each architecture, mingw-w64), and every named
struct, union, enum and typedef the binary's debug info describes is
compared: size and each field's name, bit offset and width, and the
`TypeId` after `types::without_typedefs(name_anonymous_tags)`, the form the
PDB importer is held to.

| Data model | Binaries | Structs and unions | Layout | Hash | Hash with typedefs | Enums | Typedefs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| x86-64 SysV (LP64) | 11 | 158 (87 distinct) | 100% | 100% | 100% | 13, 100% | 352, 100% |
| AArch64 (LP64) | 7 | 135 (87) | 100% | 100% | 100% | 12, 100% | 274, 100% |
| RISC-V 64 (LP64) | 6 | 69 (27) | 100% | 100% | 100% | 8, 100% | 163, 100% |
| x86-64 PE (LLP64, Microsoft bitfields; PDB) | 3 | 35 (21) | 100% | 100% | n/a | 2, 100% | 33, 100% |

No exceptions: every type the debug info describes is parsed and every
one is identical, system types (glibc's `FILE`, `struct timespec`, the
`va_list` tags) included. The typedef-preserving hash is 100% too on the
ELF models; for structs it is meaningless against a PDB (CodeView has no
typedefs). Two things the comparison accounts for: clang's CodeView names
`typedef struct {...} t;` `struct t` (compared with the typedef's
struct), and GCC on AArch64 records `va_list` without the
`__builtin_va_list` typedef clang has (98% of AArch64 typedefs keep their
typedef-preserving hash, all of them the flat one).

**Against clang** (`src/cparse/tests/clang_oracle.py`, CTest
`cparse_clang_oracle` with `-DREVKIT_WITH_CLANG=ON`; clang is never
linked or shipped): the layout cases in `tests/data/layouts.h` (bitfields
of every kind, packing, pragma pack, alignment, anonymous members,
vectors, enums, flexible arrays) on 15 targets, 810 records, agree with
clang's `-fdump-record-layouts` field by field, except where clang's own
headers differ from GCC's, which revkit follows (i386's `max_align_t`,
MIPS's `__BIGGEST_ALIGNMENT__`). The host's glibc headers (80 of them,
`stdio.h` to `sys/epoll.h` and `linux/input.h`): 198 records, all equal.

**Fuzzing**: `cparse_fuzzer`, clang 18 with ASan and UBSan, 8 forks, two
10-minute runs from 120 seeds (corpus headers and sources): 190,000
inputs of up to 32 KB, then, on the final code with single declarations
too, 205,000 of up to 8 KB; no crashes, timeouts, leaks or OOMs. A first
short run had found a use after free (a parameter's type read after
adding a type moved the graph's nodes); fixed, with a regression test.

**Tests**: `revkit_cparse_test` (layout, preprocessor, passthrough,
constants, C++, recovery on truncated input, macro bombs, recursive
includes, deep nesting, byte and time limits, include roots with `..`,
absolute paths and symlinks), `revkit_cparse_spec_test` (profiles from
Ghidra's specs), `ParseCTest` in the backend tests (the acceptance test
below, DefineType round trip of the nodes, conflicts, host file rules,
bound names reaching debug-info variables), and the SDKs' tests.

The acceptance test (`ParseCTest.HeaderImportRetypeAndUndo`): cJSON.h is
parsed for the stripped cJSON and imported as one revision; retyping
`cJSON_GetStringValue` (found at the same address in the debug build) to
`char *cJSON_GetStringValue(const cJSON * const item)` makes its
decompilation read `item->valuestring`; reverting the retype's and the
import's sessions gives back the decompilation from before, and no name
is bound.

## Known gaps

- No `#embed`, digraphs or trigraphs; `__has_builtin` knows the `va_*` and
  `offsetof` builtins only; `typeof` of an expression handles variables,
  members, dereferences and casts.
- Pointers to members, templates and operators aren't modeled (skipped
  with a warning); bitfields in classes with virtual bases follow C.
- Microsoft's zero-width bitfield rule is simplified (it ends a run).
- A PE program gets the MSVC target unless the request names one.
- Define-data at addresses is the listing's Define data
  ([listing-edit.md](listing-edit.md)): its `c_declaration` goes through
  this parser. Structures from pointer use and from a listing selection
  (phase 3) are `TypeService.AutoStructure`
  ([types.md](types.md#structures-from-pointer-use)), which lays out
  nothing with C's rules: its fields are at the offsets the code uses.
  Type archives (a header the parser reads back to the same hashes) and
  categories are phase 4 ([types.md](types.md#type-archives)).
- An explicit layout (the editor's) is written with unnamed bitfields as
  its gaps: under Microsoft's bitfield rules a run of bitfields takes its
  whole storage unit, so a field placed inside one can't be expressed and
  is reported where the target's rules put it.
