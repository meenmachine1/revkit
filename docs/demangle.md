# Demangled names and prototypes

C++ compilers (and Rust's and D's) spell a function's scope and parameter
types into its symbol: `_ZN3geo5Shape5scaleEd` is `geo::Shape::scale(double)`.
Since `api_minor` 40 (feature `demangle`) revkit's **demangler analysis**
names every symbol of an ELF, PE (exports, imports, PDB-less symbols) or raw
image by its demangled name, as Ghidra's Demangler GNU and Demangler
Microsoft analyzers do, and gives each function the prototype its mangled
signature says, where nothing better (debug info, the user) says one.

- [What a user sees](#what-a-user-sees)
- [Names](#names)
- [Prototypes](#prototypes)
- [How it fits the fact store](#how-it-fits-the-fact-store)
- [API, SDKs and MCP](#api-sdks-and-mcp)
- [The gate](#the-gate)
- [Known gaps](#known-gaps)

## What a user sees

- **Function list, symbol search, listing, decompiler**: `geo::Shape::scale`,
  `std::vector<int,std::allocator<int>>::push_back`, `geo::Shape::vtable`,
  not the mangled symbols. The function list's tooltip and the palette show
  the other spellings, and a search finds either: typing `_ZN3geo5Shape` in
  the palette (or `name_contains` in `ListFunctions`, `ListSymbols`) finds
  `geo::Shape::scale` and says it matched the mangled name.
- **Prototypes**: `undefined geo::Shape::scale(geo::Shape *this, double param_2)`
  in the function list and the listing's signature line, and the
  decompiler prints `void geo::Shape::scale(Shape *this,double param_2)` with
  `this` typed, so field accesses read `this + 0x10`.
- **The decompiler** names a callee as Ghidra's does, in its namespaces and
  minimally qualified from where it is used: `geo::Shape::make(...)` from
  `main`, `scale(this, f)` from another `geo::Shape` method.
- **A setting** chooses the spelling every view shows (palette, "Names:"):
  - *demangled, short* (the default; Ghidra's "use short names": the
    qualified name without parameters, also the decompiler's),
  - *demangled, full signatures* (`geo::Shape::scale(double)`),
  - *mangled* (`_ZN3geo5Shape5scaleEd`, as the file spells it).
  It is per browser (`localStorage` `rk.names`); a rename shows as itself.

## Names

`revkit::demangle::parse` (`src/demangle/structured.cc`) walks LLVM's
demangler ASTs (Itanium and Microsoft; Rust and D through LLVM's string
demanglers), so the analysis knows a name's scope, base name, parameters,
member status and calling convention instead of re-parsing the demangler's
text. Names LLVM's Itanium parser can't read (some template expressions in
libstdc++, such as `std::__relocate_a_1<int,int>`) fall back to the C++
runtime's demangler (`abi::__cxa_demangle`, GNU libiberty's in libstdc++),
for the name only. The analysis keeps Ghidra's conventions:

| Mangled | Name |
| --- | --- |
| a function | its qualified name without parameters or return type: `util::clamp<int>`, `geo::Shape::~Shape`, `operator_new` |
| a local entity | inside its function's name: `f::{lambda(int)#1}::operator()` |
| `vtable for X`, `typeinfo for X`, `VTT for X`, `guard variable for X` | `X::vtable`, `X::typeinfo`, `X::VTT`, `X::guard` |
| a thunk (`non-virtual thunk to X::f(int)`) | the function it adjusts for: `X::f` |
| a GCC clone (`.isra.0`, `.cold`) | with its suffix: `helper.isra.0` |
| an ABI tag (`describe[abi:cxx11]`) | without it: `describe` |

Every name is one token: no space after a template argument's comma, and
other spaces as `_` (`std::map<int,unsigned_int>`, `operator_new`), as
Ghidra's `SymbolUtilities` makes them, so the listing and the decompiler
print the same text.

Analysis (discovery, no-return detection, call fixups, pointer names
`PTR_<symbol>_<addr>`) still reads the names as the file spells them: the
demangled name is a display and decompiler name, applied after.

## Prototypes

A function whose name says its signature gets a prototype written as C
that `revkit::cparse` reads for the program's target
(`src/inputs/demangled.cc`, one translation unit for the whole program):

- **parameters** with the mangled types: builtins in the target's C
  spelling (`bool` as `_Bool`, `wchar_t` by the target's size), references
  as pointers, classes as declared (incomplete) structs of their qualified
  names, arrays and functions decayed to pointers, function pointers as
  such, varargs;
- **`this`** (`geo::Shape *this`, `const` for a const member) first for a
  member function. Itanium names say so for constructors, destructors and
  const or ref-qualified functions; Microsoft names always say. Otherwise
  a function in a scope the program's symbols show is a class (it has a
  constructor, a destructor, a const member, a vtable, typeinfo; or its
  name has template arguments) is taken for a member, as Ghidra's
  `DemangledFunction.isThisCall` does, but not a two-operand operator or a
  function in `std`. That `this` is a **guess**: where inference
  ([infer.md](infer.md)) counts the mangled parameters alone (no extra
  integer register), the function is a static member and the guess goes
  (`refine_demangled_this`; the function list, the decompiler and rk-lift
  alike), as Ghidra drops it when its own parameter count matches;
- **the return type** where the mangling has one (templates, Microsoft
  names), else unknown: the decompiler is told Ghidra's `undefined`
  unlocked return and decides it; destructors return `void`;
- **the calling convention** of a Microsoft name (`__thiscall`,
  `__stdcall`, `__fastcall`, ...) where the compiler spec has a model for
  it, else the default.

No prototype where the C would be wrong: a class (or, in an Itanium name,
anything that may be one) passed by value, a member pointer, a vector type,
a clone (GCC drops and splits a clone's parameters).

**Precedence.** The demangled prototype ranks as an import: the user's
prototype and the debug info's (DWARF and PDB, which are import
assertions) win over it; an agent's, a script's or a plugin's assertion
doesn't replace it; inference and Decompiler Parameter ID apply only to
functions without one.

## How it fits the fact store

Names and prototypes from mangled symbols are **derived facts**, like the
loader's other names ([backend.md](backend.md#loader-derived-names-derived-facts-not-assertions)),
not `import:` assertions: a pure function of the file, free in the log
(libLLVM has over 50,000 mangled exports), and recomputed by a rule version
bump, so existing projects get them on open with nothing to migrate.

| Rule | What changed |
| --- | --- |
| `functions.table` 3, `names.loader` 4, `names.default` 5 | `Func`/`Label` carry the demangled name and the mangled one (`mangled`) |
| `symbols.effective` 6 | the demangled name, and `type_rank`: the rank of the assertion that gave the type (TYPE keys keep `AssertedOrder` now) |
| `analysis.demangler.scopes` | the program's class scopes |
| `analysis.demangler` (per function) | the prototype's display, its `this` guess and parameter kinds |
| `inputs.static` 5, `inputs.program` 13, `inputs.function` 7, `inputs.address` 11, `decompile.ghidra` 12 (bundle version 4) | `revkit::inputs` names functions, labels and data in their namespaces and applies the prototypes (`lift::FunctionFacts::demangled`, `this_guessed`) |

The decompiler's lookups (`QueryLookup::with_overlay`) lay assertions over
it by rank: a TYPE assertion below import rank leaves a demangled
signature in place, a rename replaces the whole qualified name (its
namespaces go too).

## API, SDKs and MCP

| Where | What |
| --- | --- |
| `DemangledName` (common.proto) | `mangled` (as the file spells it) and `full` (the demangler's output, parameters included) |
| `Function.demangled`, `Symbol.demangled`, `Label.demangled`, `ListingToken.demangled` (SYMBOL), `ListingHeader.demangled` (label and signature lines), `CodeToken.demangled` (FUNCTION_NAME, GLOBAL_VARIABLE) | set where the shown name is the demangled default, not a rename |
| `ListFunctions.name_contains`, `ListSymbols.name_contains`, `name_equals` | match the mangled spelling too |
| `Function.prototype_origin`, `name_origin` | `derived: analysis.demangler` |
| Python | `Program.demangled(addr)`, `Program.mangled_name(addr)`; `revkit.script.mangled_name(addr)`, `demangled_signature(addr)` |
| TypeScript | `showName(name, demangled, form)`, `showNameIn`, `DEMANGLE_FEATURE` (`sdk/ts/src/names.ts`) |
| MCP | `list_functions` items have `mangled`; `decompile` lists the demangled names it shows (`demangled`: name, mangled, signature, address); `search_symbols` finds either spelling |
| rk-lift | on by default in `--analyze --decompile`; `--no-own demangle` leaves it out |

## The gate

`scripts/demangle_gate.py` (in `scripts/ci.sh`'s corpus gates) builds
`corpus/cxx` (a C++ shared library with namespaces, classes, virtual,
const and static members, overloads, operators, templates, references,
function pointers, enums and the standard library, and an executable
calling it) with the host's compilers, debug and stripped, decompiles each
stripped build with `rk-lift --analyze --decompile` with the analysis
("after") and without it (`--no-own demangle`, "before"), and compares
parameter counts (`this` included) with the debug build's DWARF. It fails
unless every build names all its mangled functions demangled and gets at
least as many counts right as before.

On 2026-10-08 (gcc 13, clang 18, aarch64 gcc 13, mingw-w64 gcc 13):

| Build | Mangled functions named demangled | Mangled names left in the C | Parameter counts right |
| --- | --- | --- | --- |
| elf-x86_64 gcc -O2 `libshapes.so` | 0 → 115 of 115 | 250 → 0 | 58 → 59 of 76 |
| elf-x86_64 gcc -O0 `libshapes.so` | 0 → 766 of 766 | 1542 → 0 | 323 → 333 of 391 |
| elf-x86_64 clang -O2 `libshapes.so` | 0 → 115 of 115 | 229 → 0 | 73 → 75 of 77 |
| elf-aarch64 gcc -O2 `libshapes.so` | 0 → 115 of 115 | 243 → 0 | 58 → 59 of 76 |
| pe-x86_64 mingw -O2 `shapes.dll` | 0 → 72 of 72 | 100 → 0 | 131 → 137 of 168 |
| the executables (imports only) | 0 → 122 of 122 | 381 → 0 | |
| **total** | **0 → 1305 of 1305** | | **643 → 663 of 788** |

Most of what stays wrong is the truth's own: DWARF gives destructors an
artificial `__in_chrg` parameter the ABI doesn't pass, and leaves a
template's expanded parameter pack out. The C corpus's decompiled-C gates
(`rk-decomp`, `rk-decomp-refonly`, `rk-decomp-own`) are unchanged: its
programs are C.

`src/demangle/tests/demangle_test.cc` (the structured parse),
`src/inputs/tests/demangled_test.cc` (prototypes, `this`, the batch,
Microsoft), `src/backend/tests/demangle_test.cc` (the API: names, search,
prototype rank, listing, rename), `sdk/python/tests/test_demangle.py` (SDK,
script, MCP) and `ui/e2e/demangle.ts` (the function list, palette, header
rows, decompiler and the setting) test it.

## Known gaps

- Microsoft-mangled programs are covered by unit tests only: there is no
  MSVC toolchain on the gate's host, and a stripped MSVC image has no
  symbols but its exports.
- An Itanium static member function in a class keeps a guessed `this` until
  inference runs (in the daemon, in the background; rk-lift waits for it),
  and keeps it where inference's count is wrong.
- Classes are opaque: a prototype names `geo::Shape *` but the struct has no
  fields until someone defines it (or debug info does). A class by value
  gives no prototype at all.
- A PLT stub named after a demangled import keeps the demangled name when
  the import's target is renamed (stubs are named by analysis, as before).
- Swift names aren't demangled (a Mach-O's Swift types are read by their descriptors, [macho.md](macho.md#objective-c-and-swift), but their mangled symbols stay as they are).
