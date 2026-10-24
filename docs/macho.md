# Mach-O

revkit loads Mach-O files (macOS, iOS, watchOS and tvOS programs, dylibs,
bundles and object files) as Ghidra's "Mac OS X Mach-O" loader does: thin
32- and 64-bit files of either byte order, and a slice of a universal
(fat) file. Analysis then runs as it does for ELF. The loader is
`src/loader/macho.cc` (`revkit::loader::parse_macho`); `parse()` and
`load_file()` pick it by the magic number.

- [What a user sees](#what-a-user-sees)
- [Universal files and slices](#universal-files-and-slices)
- [Memory blocks](#memory-blocks)
- [Symbols, exports and the entry point](#symbols-exports-and-the-entry-point)
- [Imports, stubs and fixups](#imports-stubs-and-fixups)
- [The language](#the-language)
- [Libraries](#libraries)
- [Objective-C and Swift](#objective-c-and-swift)
- [Load-command facts](#load-command-facts)
- [API, SDKs, MCP and the UI](#api-sdks-mcp-and-the-ui)
- [Tests](#tests)
- [Known gaps](#known-gaps)

## What a user sees

On a program built for macOS on Apple silicon:

- **Functions** are named by the symbol table (`_main`, `_add`, the
  Objective-C methods' `-[Point sum]`), else by the export trie, and found
  from the entry point, those symbols, `LC_FUNCTION_STARTS` and the stubs;
  a stripped file keeps its function starts and exports.
- **Stubs** (`__TEXT,__stubs`) are thunks named after what they import,
  `_printf` and `_puts`, as Ghidra names them; a call to one decompiles as
  `_printf("hello %d\n",...)`, with the C library's prototype (`_printf`
  is `printf`: library prototypes and no-return names match without the
  leading underscore, as Ghidra's do).
- **Pointer slots** (`__got`, `__la_symbol_ptr`) hold what dyld binds them
  to: each undefined symbol has a label in an `EXTERNAL` block after the
  image, and the slots point there (`PTR__printf_100004008`).
- **Data**: `__cstring` strings and pointers as the data analysis finds
  them; pointer sections' entries are pointers, as Ghidra's loader marks
  them; chained-fixup pointers read as their targets.
- **Program summary**: the CPU (`arm64`), file type, UUID, platform and
  minimum OS, SDK, the dylibs and rpaths, a universal file's slices, the
  code signature and whether the file is encrypted.
- **Objective-C**: every method is a function named as clang names it
  (`-[Point sum]`, `+[Base alloc]`, `-[Point(Extra) diff]`), stripped or
  not, with the prototype its type encoding gives and `self` a pointer to
  the class's struct, whose fields are its ivars; a message send shows its
  selector:

  ```c
  int -[Point sum](Point *self,SEL _cmd)

  {
    int iVar1;

    iVar1 = _objc_msgSend(self,"x");
    return self->y + iVar1;
  }
  ```

  The runtime's structures are typed and named (`_OBJC_CLASS_$_Point`,
  `__OBJC_CLASS_RO_$_Point`, `__OBJC_$_INSTANCE_METHODS_Point`, ...), and
  `ListObjcClasses` lists the classes, their methods, ivars, properties,
  protocols and categories.

## Universal files and slices

A universal file (`FAT_MAGIC`, `FAT_MAGIC_64`) holds one Mach-O per CPU.
revkit loads one slice per program:

- **The default**: the first `arm64` or `arm64e` slice, else the first
  `x86_64` one, else the first (`loader::macho_default_slice`). Ghidra
  instead offers every slice in its import dialog and makes the user pick.
- **Another**: `ImportOptions.macho_slice` names it by its arch, as `lipo`
  names CPUs (`arm64`, `arm64e`, `x86_64`, `x86_64h`, `i386`, `armv7`,
  `armv7s`, `arm64_32`, `ppc`), or by index (`#1`). A slice the file
  doesn't have fails with the ones it has.
- **The same file again**: `ImportProgramRequest.program_file` re-imports a
  program's stored file, so another slice of a universal program is one
  call (the UI's **Import x86_64** button).

The program keeps the whole file (its SHA-256 is the file's); offsets in
`Section`s and `Region`s are file offsets, the slice's offset included. A
Java class file shares `0xcafebabe`: a universal header with no slices or
more than 64, or slices outside the file or without a Mach-O magic, is
not a Mach-O.

## Memory blocks

As `MachoProgramBuilder.processMemoryBlocks` lays them out:

- A block per segment (`LC_SEGMENT`, `LC_SEGMENT_64`) with its file bytes,
  then the rest of its `vmsize` uninitialized, with the segment's initial
  protection; `__PAGEZERO` is not mapped.
- Each section with a size splits its segment's blocks and names the part
  it covers (`__text`, `__stubs`, `__cstring`, `__got`, `__data`, ...);
  what is left keeps the segment's name (`__TEXT` for the header and load
  commands before `__text`). A zero-fill section past the file bytes is
  uninitialized; one inside them (lld pads `__DATA` to a page) stays
  initialized, as Ghidra leaves it.
- Section permissions are Ghidra's (`Section.isWrite`, `isExecute`): all
  readable; writable outside `__TEXT`, `__TEXT_EXEC` and `__PRELINK_TEXT`
  except `__const`, and `__got*` always; executable for `__text`,
  `__TEXT_EXEC` and sections with instructions (`S_ATTR_PURE_INSTRUCTIONS`,
  `S_ATTR_SOME_INSTRUCTIONS`).
- A section outside every segment gets a block of its own; one that
  overlaps another block, a segment that wraps or overlaps another, and a
  segment with file bytes but no memory size (Ghidra's overlay) are left
  out with a warning.

The image base is the lowest segment with file bytes (the header's,
`__TEXT`'s: 0x100000000 for a 64-bit executable). `LoadOptions::image_base`
(`ImportOptions.image_base`, and `SetImageBase` after import) moves every
address, symbol, export, fixup target and function start by the same
amount.

`Section::segment` is the section's segment; `type` its `S_*` type,
`flags` the whole flags word, `info` `reserved1` (the first indirect
symbol of a pointer or stub section) and `entsize` `reserved2` (a stub's
size).

## Symbols, exports and the entry point

- **Symbols** (`LC_SYMTAB`'s nlist): `N_SECT` entries are defined symbols,
  functions in a section of code and data otherwise (`__mh_execute_header`,
  in `__TEXT`'s executable header part, is data); external
  ones are global (weak with `N_WEAK_DEF` or `N_WEAK_REF`), the rest
  local. Undefined external ones (`N_UNDF`) are imports, or common symbols
  when `n_value` is a size. Debugging entries (`N_STAB`) and `N_ABS`,
  `N_INDR` and `N_PBUD` entries are skipped. An ARM symbol with
  `N_ARM_THUMB_DEF` has bit 0 set, as ELF's Thumb symbols do, and its
  function decodes as Thumb up to the next function start.
- **Exports**: the export trie of `LC_DYLD_EXPORTS_TRIE` (or
  `LC_DYLD_INFO`'s), names and addresses from `__TEXT`'s address;
  re-exports are listed with a `forwarder` of `library:name`; absolute
  exports keep their value. An export no symbol names is a symbol too
  (`SymbolSource::macho_export`). Exports in code are function symbols;
  data exports and `__mh_execute_header` seed nothing.
- **The entry point**: `LC_MAIN`'s offset from `__TEXT`, else the PC of
  `LC_UNIXTHREAD` (or `LC_THREAD`) for x86, x86-64, ARM, AArch64 and
  PowerPC, Ghidra's priority.
- **Function starts** (`LC_FUNCTION_STARTS`) seed discovery
  (`kSeedFunctionStarts`), as Ghidra's Mach-O Function Starts analyzer
  makes functions there; **data in code** (`LC_DATA_IN_CODE`) is data to
  discovery and the decompiler, as ARM's `$d` mapping symbols are in ELF.

## Imports, stubs and fixups

Mach-O has no relocation sections in a linked file: dyld binds and rebases
by `LC_DYLD_INFO` opcodes, by chained fixups (`LC_DYLD_CHAINED_FIXUPS`),
or for old files by the indirect symbol table. All of them become
`Image::relocations`, as ELF's dynamic relocations are:

| Source | Relocation | `type` (name) |
| --- | --- | --- |
| bind opcodes, weak binds | `glob_dat` with the symbol and addend | 1-3 (`BIND_TYPE_POINTER`, `..._TEXT_ABSOLUTE32`, `..._TEXT_PCREL32`) |
| lazy bind opcodes | `jump_slot` | as binds |
| rebase opcodes | `relative`, `target` the stored pointer (moved by a rebase) | 0x11-0x13 (`REBASE_TYPE_POINTER`, ...) |
| chained fixups: binds | `glob_dat`, the import's addend plus the pointer's | 0x8800 + the pointer format (`DYLD_CHAINED_PTR_64`, `DYLD_CHAINED_PTR_ARM64E_USERLAND`, ...) |
| chained fixups: rebases | `relative`, `target` decoded (offset formats from the header; arm64e's high byte kept) | as above |
| threaded binds (arm64e before chained fixups) | as chained `DYLD_CHAINED_PTR_ARM64E` | 0x8801 |
| indirect symbol table slots no bind covers | `glob_dat` (non-lazy) or `jump_slot` (lazy) | 0x20 (`INDIRECT_SYMBOL`) |

Each bind is also an `Import` (its slot as `iat_address`, its dylib from
the library ordinal). Chained-fixup pointer formats 1-13 are decoded
(arm64e userland and kernel, 64-bit, 64-bit offset, 32-bit with its
non-pointer bias, the cache and firmware formats); `DYLD_CHAINED_PTR_START_MULTI`
pages are followed. Compressed chained-import names (`symbols_format` 1)
are not read.

What analysis does with them, as for ELF:

- Every bound slot is an **import slot** named after its symbol, and every
  stub section (`S_SYMBOL_STUBS`) a PLT of its stub size, so each stub is
  a function discovery finds and names after the slot it jumps through.
  `MachoInfo::stub_names` keeps the indirect symbol table's name of each
  stub, which Ghidra's `processStubs` names the thunk; it is the slot's
  import, so the two agree.
- The decompiler sees the slots as dyld leaves them
  (`inputs::relocation_patches`): a bind holds its symbol's address in the
  `EXTERNAL` block (Ghidra's `processUndefinedSymbols`: every undefined
  symbol of the symbol table, in its order, 0x100 bytes apart from the
  first 4 KiB boundary past the last block; then a pointer-sized slot for
  each chained bind of a name the table lacks), or the image's own
  definition of the name (weak and flat-namespace binds), plus a chained
  bind's addend (an opcode bind's addend is dropped, as Ghidra drops it).
  A lazy pointer, rebased to its stub helper and bound, holds the bind.
  Rebased pointers hold their targets, in the analysis's bytes too.
- `EXTERNAL` entries are labels, not functions, since nlist doesn't say
  what a symbol is; a stub's jump into the block is `CALL_RETURN`, as an
  ELF PLT stub's is.

## The language

`guess_language` follows Ghidra 12.1.4's `Mac OS X Mach-O` opinions
(`MachoLoader` queries them with the CPU type, and for ARM the subtype):

| CPU | Language | Compiler |
| --- | --- | --- |
| x86 (7) | `x86:LE:32:default` | `gcc` |
| x86-64 (0x1000007) | `x86:LE:64:default` | `gcc`; `swift` with Swift sections |
| arm64, arm64e (0x100000c) | `AARCH64:LE:64:AppleSilicon` | `default`; `swift` or `golang` with their sections |
| arm64_32 (0x200000c) | `AARCH64:LE:32:ilp32` | `default` |
| ARM (12), subtypes all, v7, v7f, v7s, v7k, v8 | `ARM:LE:32:v8` | `default` |
| ARM v4T, v6 | `ARM:LE:32:v4t`, `ARM:LE:32:v6` | `default` |
| PowerPC, PowerPC 64 | `PowerPC:BE:32:default`, `PowerPC:BE:64:default` | `default` |
| SPARC (14) | `sparc:BE:32:default` | `default` |

Swift is told by a section named `__swift*`, `swift*` or `.sw5*`, Go by
one containing `gopclntab` or `go_buildinfo` (`SwiftUtils.isSwift`,
`GoRttiMapper.hasGolangSections`). Ghidra has no opinion for ARM v5,
XScale and the M profiles; revkit takes `ARM:LE:32:v5t` for the first two,
`ARM:LE:32:Cortex` for v6-M, v7-M and v7E-M and `ARM:LE:32:v8-m` for
v8-M.

## Libraries

`Image::needed` is every dylib load command's install name in order
(`LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`, `LC_REEXPORT_DYLIB`,
`LC_LAZY_LOAD_DYLIB`, `LC_LOAD_UPWARD_DYLIB`), `soname` the file's own
(`LC_ID_DYLIB`), `runpath` its `LC_RPATH`s. In the program-libraries
feature ([api.md](api.md#libraries)):

- A needed library is the project program named as its file
  (`@rpath/libgreet.dylib` is `libgreet.dylib`), else one whose install
  name is it.
- An import resolves in the dylib it names (the two-level namespace), else,
  for what an umbrella only re-exports, in the program's other libraries
  in load order. Exports are a library's export trie.
- `import_libraries` first expands `@executable_path`, `@loader_path` and
  `@rpath` install names as dyld does (the loading image's rpaths, then
  its loaders', up to the main executable; `api_minor` 100, so an app's
  `@rpath/Foo.framework/Foo` is found in its `Frameworks/`:
  [apple-apps.md](apple-apps.md#libraries-in-a-bundle)), then looks for
  each by its file name in the search paths, the program's directory and
  its rpaths (`@loader_path` and `@executable_path` as that directory);
  inside a library root an absolute install name (`/usr/lib/libc++.1.dylib`)
  is tried as it is first. A universal library loads its slice of the
  program's CPU type and subtype.

## Objective-C and Swift

`src/objc` (`revkit::objc`) reads the Objective-C 2 runtime's metadata as
Ghidra's Objective-C Type Metadata analyzer does (`Objc2TypeMetadata`),
and Swift's type descriptors as its Swift Type Metadata analyzer does,
from the loaded image: pointers as dyld leaves them (a chained rebase at
its target, a bind as its symbol: a superclass in another image is the
name `_OBJC_CLASS_$_NSObject` names).

- **What is read**: `__objc_classlist` (and `__objc_nlclslist`): each
  `class_t`, its `class_ro_t` (flags, instance size, name, methods,
  protocols, ivars, properties), its metaclass's (the class methods) and
  its superclass; method lists of pointers or of 32-bit relative offsets
  (`method_list_t`'s small-list flag, whose names go through a selector
  reference); `ivar_t`s with their offset variables' values; properties;
  `__objc_catlist`'s categories (of local or external classes);
  `__objc_protolist`'s protocols (required and optional methods);
  `__objc_selrefs`, `__objc_classrefs`, `__objc_superrefs`,
  `__objc_protorefs`; `__objc_imageinfo`. Every read is bounded.
- **Swift**: `__swift5_types`' context descriptors (direct and indirect):
  each struct's, class's and enum's name and module, its metadata
  accessor, its field names (`__swift5_fieldmd`), and a non-generic class's
  vtable implementations (following rea's reader, MIT;
  THIRD_PARTY_NOTICES.md). Swift names aren't demangled.

What a program gets (`objc::markup`, asserted at import as the PE
analysis is, [pe.md](pe.md#how-it-fits-the-fact-store)):

| Fact | Provenance | What |
| --- | --- | --- |
| `CODE_UNIT` (data), `TYPE_DEF` | `analysis:objc` | `class_t`, `class_ro_t`, `method_list_t` with its `method_t` or `method_small_t` entries, `ivar_list_t`/`ivar_t`, `property_list_t`/`property_t`, `protocol_list_t`, `protocol_t`, `category_t`, `objc_image_info`, the lists' pointer arrays, selector references as `char *`, ivar offsets as integers, and the names and type strings they point to as strings |
| `NAME` | `analysis:objc` | the structures, as clang's symbols name them (`_OBJC_CLASS_$_Point`, `_OBJC_METACLASS_$_Point`, `__OBJC_CLASS_RO_$_Point`, `__OBJC_$_INSTANCE_METHODS_Point`, `__OBJC_$_CATEGORY_Point_$_Extra`, `__OBJC_PROTOCOL_$_Named`, `_OBJC_IVAR_$_Point.y`, ...), and the methods' functions (`-[Point sum]`) where no symbol names them |
| `FUNCTION_BOUNDS` | `analysis:objc` | a function at each method's implementation |
| `TYPE` | `import:objc` | each method's prototype from its type encoding: `void -[Point setX:](struct Point *self, SEL _cmd, int)`, `id +[Base alloc](Class self, SEL _cmd)`; an instance method's `self` points to the class's struct (`isa`, then each ivar at its offset, typed by its encoding or as bytes) |
| `NAME`, `FUNCTION_BOUNDS` | `analysis:swift` | `Mod.S nominal type descriptor`, `type metadata accessor for Mod.S`, a function at each vtable entry |

Ghidra applies the prototypes at analysis rank; revkit stages them as
import assertions (as the debug info's are) so they apply whole. Ghidra
names a method `sum` in a class namespace `Point`; revkit uses
Objective-C's own spelling, the one the symbol table has. As Ghidra's
analyzer makes them, the loader makes `__objc_data`, `__objc_classrefs`,
`__objc_msgrefs`, `__objc_selrefs`, `__objc_superrefs` and
`__objc_protorefs` read-only, so a selector reference folds to its string;
revkit adds `__objc_ivar`, so an ivar's offset folds and `self->y` reads
as a field. The import's warnings sum it up (`analysis:objc: 1 objc
categories, 2 objc classes, 7 objc methods, 1 objc protocols, 3 objc
selector refs`; `import:objc: 7 prototypes`), and a revert of
`analysis:objc` takes it back.

## Load-command facts

`Image::macho` (`MachoInfo`) holds what the header and load commands say:
CPU type and subtype and the arch name, file type, header flags, the
slices, `LC_UUID` (also `Image::build_id`, lower-case hex), the platform,
minimum OS and SDK of `LC_BUILD_VERSION` (else `LC_VERSION_MIN_*`),
`LC_SOURCE_VERSION`, the dylinker, dylibs with their kind and versions,
rpaths, the segments, whether the file is code-signed (`LC_CODE_SIGNATURE`)
and where the signature is, and `LC_ENCRYPTION_INFO(_64)`. The signature's
contents (CodeDirectories, entitlements, requirements, the signer's
certificates; read, not verified) are the program summary's
`code_signature` ([apple-apps.md](apple-apps.md#code-signatures)).
An encrypted file (a nonzero `cryptid`, or a segment with
`SG_PROTECTED_VERSION_1`) loads with a warning saying so; its encrypted
range reads as the file has it, and nothing tries to decrypt it.

## API, SDKs, MCP and the UI

| Where | What |
| --- | --- |
| `ImportOptions.macho_slice` (`api_minor` 90, feature `macho`) | the slice to load: an arch name or `#N` |
| `ImportProgramRequest.program_file` | import a program's stored file again (another slice) |
| `ProgramInfo.macho_slice`, `macho_slices` | the slice a program is and the file's slices (empty for a thin file) |
| `ProgramSummary.macho` (`MachoSummary`) | arch, CPU type and subtype, file type, UUID, platform, minimum OS, SDK, source version, install name, dylinker, dylibs (`MachoDylib`: name, kind, versions), rpaths, slices (`MachoSlice`) and which this is, code signature (`code_signature`, `api_minor` 100: [apple-apps.md](apple-apps.md#code-signatures)), encryption and its range, how dyld fixes it up (`fixups`: `chained`, `opcodes`), header flags; `ProgramSummary.build_id` the UUID |
| `ListRelocations` | `format` `macho`, the fixups above with their names |
| Python | `Client.import_program(..., macho_slice=, program_file=)`; `Program.macho()` |
| MCP | `import_program(macho_slice)`; `program_summary` has a `macho` object |
| `QueryService.ListObjcClasses` (`api_minor` 91, feature `objc`) | the classes by name (`ObjcClass`: address, metaclass, superclass, instance size, root, Swift, methods with selector, type encoding, implementation, category and the function's current name, ivars with offsets, properties, protocols, categories; a class only categories here extend is `external`), protocols (`ObjcProtocol`, optional methods marked) and Swift types (`SwiftType`: name, module, kind, descriptor, accessor, fields, vtable); `name_contains` filters |
| Python | `Program.objc_classes(name_contains="")` |
| MCP | `list_objc_classes(program_id, name_contains, limit, offset)` |
| UI | the Open dialog (below) |

The Open dialog's import of a universal file loads its default slice and
says which, with **Import x86_64** (the first other slice) in its toast; a
universal program's details say which slice it is of the file's
(`arm64 (of x86_64, arm64)`) with an **Import** button for each other
one.

## Tests

The fixtures are `tests/data/macho` (C sources, an Objective-C one with a
root class of its own, and hand-written `libSystem.tbd` and `libobjc.tbd`
text stubs), built at test time by `build.sh` with clang, `ld64.lld`
(`-platform_version`, with and without `-fixup_chains`) and `llvm-lipo`:
no Apple SDK or binary is used. lld links x86-64, arm64 and arm64_32;
ARMv7 and i386 are object files (lld links neither). The tests check the
loader against what `llvm-nm` and `llvm-objdump` say of the same files;
without the tools they skip.

- `src/loader/tests/macho_test.cc`: every fixture's symbols at llvm-nm's
  addresses and every fixup llvm-objdump lists, of the right kind with its
  symbol, dylib or target (dyld-info opcodes and chained fixups, x86-64,
  arm64 and arm64_32); blocks, permissions, stubs, exports, function
  starts and metadata; the universal file's slices (the default, by name,
  by index, a missing one), its bytes the thin file's; object files
  (Thumb symbols, 32-bit); a rebase; a dylib and a program that links it
  by `@rpath`; Objective-C sections. Hand-built files for what lld doesn't
  write: arm64e chained fixups (authenticated and plain rebases and binds,
  a high byte, an addend), `LC_ENCRYPTION_INFO_64`, a minimal file's
  blocks, malformed headers and load commands (rejected), and bad
  linkedit data (warnings).
- `src/backend/tests/macho_test.cc`, through the API: functions and the
  stubs named on x86-64 and arm64, opcodes and chained, and `_main`
  decompiling to calls of `_printf` and `_puts`; the summary and the
  relocation table; the universal file's default slice, the other by
  `program_file`, a missing one; a dylib imported with its program and
  the imports resolved to it.
- `sdk/python/tests/test_macho.py`: the slices and `Program.macho()`, and
  MCP's `import_program` and `program_summary`.
- `src/objc/tests/objc_test.cc`: `objc.m` built for arm64 (dyld info
  and chained fixups) and x86-64: classes, metaclasses, superclasses,
  methods at their symbols' addresses, ivars at their offset variables'
  values, properties, the protocol, the category and the references; the
  markup's names at clang's symbols' addresses, the prototypes; a
  hand-built image for a relative method list and Swift descriptors (a
  struct with a field, a class with a vtable).
- `src/backend/tests/macho_test.cc` (`ObjectiveCMetadataNamesTypesAndListsMethods`):
  `objc.m` stripped of its local symbols, through the API: the methods
  named from the metadata, their prototypes, `self->y` and the selectors
  in the decompiled C, `ListObjcClasses` and its filter.
- `sdk/python/tests/test_macho.py`: `Program.objc_classes()` and MCP's
  `list_objc_classes`.
- `ui/e2e/macho.ts`: the Open dialog's slice detail and Import x86_64.
- `src/objc/fuzz/objc_fuzzer.cc`: the readers over what the loader makes
  of any input.
- `src/loader/fuzz/fuzz_macho.cc` (libFuzzer; docs/development.md):
  thin and universal files, a slice by name or index, rebased or not.

## Known gaps

- **Objective-C**: Objective-C 1 (`__OBJC` segment) isn't read; a
  message send isn't resolved to its implementation (calls stay
  `_objc_msgSend(self,"x")`); the classes aren't in the Class hierarchy
  view (`ListObjcClasses` and MCP have them); a dyld cache's optimized
  selectors aren't read (no dyld cache loader).
- **Swift**: names aren't demangled; generic types' and resilient
  classes' vtables, protocol conformances (`__swift5_proto`) and
  associated types aren't read; nothing is typed from Swift metadata.
- **DWARF**: a Mach-O's `__DWARF` sections and `.dSYM` bundles aren't read.
- Ghidra's **markup** of the header and load commands as structures, the
  `__program_vars` structure and the `ABSOLUTE` block of `N_ABS` symbols
  aren't made; Ghidra's import dialog choice of slice is the default here.
- **Object files** load their sections at their addresses, but their
  section relocations aren't applied.
- **dyld shared caches**, kernel collections (`MH_FILESET`), prelinked
  kernels and kext bundles aren't loaded as Ghidra's dedicated loaders
  load them; `vmsize` 0 segments (Ghidra's overlays) are left out.
- The emulator and the debugger don't run Mach-O programs.
