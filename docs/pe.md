# Windows programs: MSVC RTTI, PE structures, PDB

What revkit knows about a PE beyond its loader (`src/loader/pe.cc`): the
C++ classes MSVC's run-time type information names, their vftables and
virtual methods (Ghidra's RTTI analyzer and the class recovery its
scripts do), and the PE's own structures, exception data, TLS callbacks
and Control Flow Guard tables (Ghidra's PE loader markup and its Windows
PE analyzers). The code is `src/msvc` (`revkit::msvc`, a pure function of
the loaded image) and `src/backend/msvc_import.{h,cc}` (its results as
assertions).

- [What a user sees](#what-a-user-sees)
- [MSVC RTTI and vftables](#msvc-rtti-and-vftables)
- [Virtual methods' this](#virtual-methods-this)
- [PE structures and exception data](#pe-structures-and-exception-data)
- [How it fits the fact store](#how-it-fits-the-fact-store)
- [API, SDKs, MCP and the UI](#api-sdks-mcp-and-the-ui)
- [Tests](#tests)
- [Known gaps](#known-gaps)

## What a user sees

On a stripped program built by MSVC (or clang-cl) with `/GR`:

- **Classes**: the **Class hierarchy** view (palette: "Show class
  hierarchy"; feature `msvc-rtti`) lists every class a TypeDescriptor
  names, as a tree of derived classes under their bases, and for the
  selected class its bases (direct or not, virtual or at which offset),
  derived classes, vftables with their functions and the struct `this`
  points to.
- **The listing**: TypeDescriptors, CompleteObjectLocators, hierarchy
  descriptors, base class arrays and descriptors as typed data, named as
  Ghidra names them (`geo::Rect::RTTI_Type_Descriptor`,
  `geo::Rect::RTTI_Complete_Object_Locator`, ...); each vftable typed as a
  struct of function pointers (`geo::Rect::vftable`, and
  `geo::Rect::vftable_for_Named` for a secondary base's), the slot before
  it as `vftable_meta_ptr`, and `type_info::vftable`.
- **Functions**: every vftable entry is a function, named
  `geo::Rect::vfunc1` (the class that declares it and its slot) unless
  the file or the debug info names it.
- **The decompiler**: a virtual method's `this` is a pointer to its class's
  struct, whose first field is `vftable` (a pointer to the class's vftable
  struct) and which is as large as the methods reach through `this`, so a
  method reads

  ```c
  int geo::Shape::vfunc2(Shape *this,int param_2)
  {
    undefined8 uVar1;

    uVar1 = (*this->vftable->vfunc1)(this);
    return (int)uVar1 * param_2 + *(int *)&this->field_0x8;
  }
  ```

  32-bit methods are `__thiscall`.

## MSVC RTTI and vftables

`msvc::scan_rtti` follows Ghidra's RTTI analyzer
(`RttiAnalyzer`, `RttiUtil`), over every initialized, non-executable block:

1. **TypeDescriptors**: a `.?AV` or `.?AU` name (printable, ending in
   `@@`) two pointers into a pointer-aligned record whose `spare` is 0 and
   whose `pVFTable` is 0 or mapped. The name is demangled by
   `revkit::demangle` (`geo::Rect`, `std::vector<int,std::allocator<int>>`).
2. **CompleteObjectLocators**: a 4-aligned record with signature 1
   (64-bit: offsets relative to the image base, and `pSelf` pointing back)
   or 0 (32-bit: absolute pointers) whose TypeDescriptor was found and
   whose ClassHierarchyDescriptor's first base is the class itself.
3. **Hierarchies**: each class's descriptor (from its locators, else from
   a base class descriptor that points to one), its BaseClassArray and
   BaseClassDescriptors (`numContainedBases`, the PMD, attributes); the
   array is a preorder walk, so its subtree sizes give direct bases.
4. **vftables**: every pointer-sized slot that holds a locator's address
   starts a table after it; its entries are the pointers to executable
   memory that follow, up to the next table's slot.

A table belongs to the subobject at its locator's offset: the class
itself at 0, else the first non-virtual base at that offset in the array,
else the only virtual base (`vftable_for_<base>`; a class with one table
names it `vftable` whatever its offset).

**Which class a function belongs to.** A function in several tables
(inherited, or shared) is named after the most derived class every table's
class derives from (`Shape::scale`, in `Rect`'s and `Box<int>`'s tables,
is `geo::Shape::vfunc2` though `Shape`, abstract, has no table), with its
slot. Its `this` is the most derived class every table's subobject is at
offset 0 of: `Rect::name`, in `Rect`'s and `Square`'s tables for `Named`,
takes a `geo::Named *`, which is what the caller passes. A function in
tables of unrelated classes (`_purecall`, folded identical code) gets no
name and no `this`.

**Class structs.** Each class `this` or a table needs gets a struct of its
name (`struct geo::Rect`, `class` for `.?AV`) with `vftable` as field 0,
a pointer to `geo::Rect_vftable` (a struct with one function pointer per
slot, named after the entry's name or `vfuncN`; a class without a table of
its own gets the slots every table of its subobjects shares). The function
pointers are `undefined8 (*)(geo::Rect *this, ...)`, `__thiscall` on
32-bit images, so a call through one passes `this` and lets the decompiler
find the other arguments. The struct's size: at least a pointer, as far
as the class's methods load or store through `this` (a walk of each
method's first 400 instructions' p-code, both ways at branches, that
tracks registers holding `this` plus a constant through copies and adds,
and keeps only callee-saved ones across calls), and each non-virtual
base's struct at its offset. Fields past the vftable pointer are gaps the
decompiler names `field_0x18`.

Where the PDB defines the class, its struct is `this`'s type instead
(the PDB's prototypes win anyway, below).

## Virtual methods' this

The analysis asserts a prototype for each virtual method,
`undefined8 geo::Rect::vfunc1(geo::Rect *this, ...)`, at **analysis
rank**. An analysis-rank prototype is not a locked signature: the
decompiler's lookup (`QueryLookup::apply_this`, `src/backend/own_inputs.cc`)
uses it only to type `this`:

- where another source locked the prototype (inference, Decompiler
  Parameter ID), its first parameter becomes `this` (a float first
  parameter is left alone); on 32-bit, a prototype in another convention
  gets `this` in front, as `__thiscall`;
- where nothing did, the function's own decompilation runs twice, as a
  parameter retype does ([decompiler-inputs.md](decompiler-inputs.md#variable-types)):
  the parameters the first run found are committed with the first typed,
  when it is in `this`'s register (RCX, ECX under `__thiscall`, x0), and
  the return stays the decompiler's; callers see the prototype unlocked,
  in its convention.

Every other source outranks it: a user's or an agent's prototype, the
debug info's (DWARF and PDB are import assertions), a demangled one.

## PE structures and exception data

`src/msvc/pe_markup.cc` reads the headers from the image's Headers block
and each directory by address, every table bounded (a damaged image gets
less markup), with Ghidra's structure names:

| What | Typed as | Named | Functions made |
| --- | --- | --- | --- |
| headers | `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS32/64` (file and optional header with the 16 `IMAGE_DATA_DIRECTORY`s), `IMAGE_SECTION_HEADER[n]` | `IMAGE_DOS_HEADER` | |
| exports | `IMAGE_EXPORT_DIRECTORY`, the address, name and ordinal arrays, the names | | |
| imports | `IMAGE_IMPORT_DESCRIPTOR[n+1]`, each lookup table, `IMAGE_IMPORT_BY_NAME` entries, the DLL names (the IAT stays the loader's: its slots are the imports) | | |
| resources | the `IMAGE_RESOURCE_DIRECTORY` tree, its entries, name strings and `IMAGE_RESOURCE_DATA_ENTRY` leaves | | |
| debug | `IMAGE_DEBUG_DIRECTORY[n]`, the CodeView `CV_INFO_PDB70` record | | |
| base relocations | each `IMAGE_BASE_RELOCATION` block and its entries | | |
| TLS | `IMAGE_TLS_DIRECTORY32/64`, the callback array | `_tls_used`, `__tls_callbacks`, `tls_callback_N` | each callback |
| load config | `IMAGE_LOAD_CONFIG_DIRECTORY32/64` as far as its `Size` says | `_load_config_used`, `__security_cookie`, `__guard_check_icall_fptr`, `__guard_dispatch_icall_fptr`, `__guard_fids_table`, `__safe_se_handler_table` | each Control Flow Guard target (its RVAs, with the stride `GuardFlags` gives) and each SafeSEH handler (32-bit) |
| x64 exception data | `_IMAGE_RUNTIME_FUNCTION_ENTRY[n]` (`__pdata`), each `UNWIND_INFO` with its codes, handler and chained entry; a `__C_specific_handler` scope table (`C_SCOPE_TABLE_ENTRY[n]`) where the handler's data is one | `Filter@<addr>`, `__except_<addr>` | each language handler, each filter |
| MSVC C++ EH (`__CxxFrameHandler3`) | `FuncInfo`, `UnwindMapEntry[]`, `TryBlockMapEntry[]`, `HandlerType[]`, `IPtoStateMapEntry[]`, the catches' TypeDescriptors | `FuncInfo_<addr>`, `Unwind@<addr>`, `Catch@<addr>`, `Catch_All@<addr>` | each unwind funclet and catch handler; on 32-bit the `__ehhandler$` thunk |

The function starts `.pdata` gives (x64, ARM64) were already discovery's
seeds (the loader's `function_ranges`); the guard table, SafeSEH table,
TLS callbacks and EH funclets add theirs as `FUNCTION_BOUNDS` assertions.
A FuncInfo is found from the language handler's data on x64 (its RVA,
checked by FuncInfo's magic number) and, on 32-bit, from each function's
`mov eax, FuncInfo; jmp __CxxFrameHandler3` thunk. A scope table is
recognized by its shape (a count, then entries whose ranges and targets
are inside the function and whose filters are code or 1), so it doesn't
depend on the handler's name. The headers, directories and exception
tables are `analysis:pe` assertions; the C++ EH data, like RTTI,
`analysis:msvc`. The import warning sums them up ("analysis:pe: 1 pe
headers, 22 guard cf functions, ...").

## How it fits the fact store

Unlike the loader's names ([backend.md](backend.md#loader-derived-names-derived-facts-not-assertions)),
the markup is **assertions**, staged in the import's revision with
provenance `analysis:msvc`, as a user's edits would make them:

| Fact | What |
| --- | --- |
| `TYPE_DEF` | the RTTI structures' types, the class structs and vftable structs, and what they reach |
| `CODE_UNIT` (`data`) | each structure and vftable, as Define data marks one ([listing-edit.md](listing-edit.md)) |
| `NAME` | the structures, vftables, `type_info::vftable`, virtual methods (where no symbol or debug info names the address) |
| `FUNCTION_BOUNDS` | a seed at each vftable entry |
| `TYPE` | the virtual methods' prototypes (above) |

(and the same kinds, `analysis:pe`, for the PE structures above). So they rank below everything else, show their origin (blame:
`analysis:msvc`), and one `RevertByProvenance` of `analysis:msvc` takes
the analysis back (the functions only a vftable reached are gone with it:
discovery doesn't follow data pointers). Analysis runs at import
(`ImageBackendOptions::import_pe_analysis`, on by default; the import's
warnings say what it found: "analysis:msvc: 8 rtti classes, 12 typed
this, 7 vftables, 12 virtual functions"); a project imported before it
doesn't have it. The hierarchy itself is a derived query, `msvc.classes`
(the scan over the program's image), which `GetClassHierarchy` reads with
the names the program gives the tables and functions now.

`GhidraTypes` now tells the decompiler a function pointer type's
`__thiscall` (`model="__thiscall"`, as Java encodes a function
definition's calling convention); other conventions stay `unknown`, as
the debug info's always were.

## API, SDKs, MCP and the UI

| Where | What |
| --- | --- |
| `QueryService.GetClassHierarchy` (`api_minor` 45, feature `msvc-rtti`) | `RttiClass`: name, mangled name, struct or class, TypeDescriptor and hierarchy addresses and attributes, `bases` (`RttiBase`: direct, virtual, offset, vbtable offset and index, attributes, depth), `derived`, `vftables` (`RttiVftable`: address, effective name, subobject offset and class, locator, `functions` with slot, entry and effective name), `type_name` and `type_hash` of the struct `this` points to; `name_contains` filters. A viewer may call it |
| Python | `Program.classes(name_contains="")` |
| MCP | `list_classes(program_id, name_contains, limit)` |
| UI | the Class hierarchy view (`ui/src/ui/classes.ts`) |
| `GetServerInfo` | `api_minor` 46, feature `pe-analysis`: the PE markup at import |

## Tests

The fixture is `tests/data/msvc/classes.cc` (with `runtime.cc`, the
CRT's stand-ins: type_info's vftable, the C++ exception runtime's entry
points, the security cookie, the load config and TLS), built at test time
by `tests/data/msvc/build.sh` with clang in cl mode (`--driver-mode=cl
--target=x86_64-pc-windows-msvc` and `i686-pc-windows-msvc`, `/GR /EHsc
/GS /O1 /guard:cf,nochecks`) and `lld-link /nodefaultlib`, debug (with
its PDB) and stripped; no Windows SDK or CRT is needed, and tests skip
without clang or lld-link. It has single, multiple and virtual
inheritance, an abstract base, a template, virtual calls through `this`,
try/catch, `__try`/`__except` (x64), a `/GS` cookie check and a TLS
callback; calls go through a volatile index so nothing is devirtualized.

- `src/msvc/tests/msvc_test.cc`, both architectures, against the linker
  map: every class's TypeDescriptor, Square's hierarchy (bases, depths,
  direct bases, the `Named` offset), the virtual base, every vftable's
  address, class, subobject and entries, and the markup's names, types
  and functions.
- `src/backend/tests/msvc_test.cc`, both architectures, through the API:
  names, origins and prototypes in the function list; the decompiled C of
  `Rect::area` (`Rect *this`, `this->field_0x18`, `__thiscall` on i686)
  and of `Shape::scale` (`(*this->vftable->vfunc1)(this)`); the RTTI
  structures in `ListData`; `GetClassHierarchy` (bases, derived classes,
  tables, function names, the filter); a user's rename and prototype win,
  a revert of `analysis:msvc` takes it back, and with the PDB its names
  and prototypes win.
- PE structures (`MarksUpPeStructures`, both architectures): the DOS and
  NT headers and the section table, the load config and
  `__security_cookie`, guard table targets, the TLS callback
  (`tls_callback_0`), `guarded()`'s FuncInfo and its two catch handlers
  (`Catch@`, `Catch_All@`), and on x64 `.pdata`, the UNWIND_INFOs and
  `filtered()`'s scope table; through the API
  (`PeStructuresExceptionDataAndTls`): the headers in `ListData` with
  their `analysis:pe` origin, `__security_cookie` in the decompiled `/GS`
  check, the TLS callback and catch handlers as functions, every `.pdata`
  start a function.
- `sdk/python/tests/test_msvc.py`: `Program.classes()` and MCP
  `list_classes`; `ui/e2e/classes.ts`: the view's tree, details, links and
  filter, and a function's decompilation from it.

What the fixture leaves untested: MSVC's own CRT and its EH4 compressed
tables (`__CxxFrameHandler4`, which clang doesn't emit and this doesn't
read), `/GS` and EH as cl.exe lays them out, x86 SafeSEH tables (lld-link
wants objects marked SafeSEH-compatible; the code reads them but no test
makes one), resources (the fixture has none), and real programs' size
(the scans were not measured on a large MSVC binary).

## Known gaps

- Classes a binary has no RTTI for (`/GR-`) aren't found; constructors
  aren't recognized, so a class struct's size is what its virtual methods
  reach, not the object's.
- A class with several vftables gets one struct with one vftable pointer
  (the primary table's); secondary tables have their own structs, which no
  class field points to.
- Virtual bases' layout (vbtables) isn't modelled.
- A project imported before this analysis doesn't get it (no re-run on
  open yet).
- `__CxxFrameHandler4` (EH4) data, ES type lists, throw infos
  (`_ThrowInfo`, catchable types) and ARM64 exception data aren't typed;
  x86 `_except_handler3/4` scope tables aren't read.
- Large tables cost one assertion per item: a binary with 100,000
  `.pdata` entries gets that many UNWIND_INFO marks (at most 131,072).
