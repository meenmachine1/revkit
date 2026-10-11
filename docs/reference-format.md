# Reference output format (version 1)

Ghidra's exporter (`tools/ghidra-export`) and revkit's own tools write this
JSON so `tools/refdiff` can compare them. One file per binary.

Rules:
- Addresses are lowercase hex strings with `0x` prefix, in the default code
  space unless a `space` field says otherwise: `"0x401000"`.
- Arrays are sorted: memory by `start`, functions by `entry`,
  instructions by `addr`. Object keys are written sorted.
- Fields a producer can't fill are omitted, never `null` (except `out` below).
- Output must be byte-identical across runs for the same input.
- Files are named `<binary.path>.json` (or `.json.gz`), mirroring the corpus
  tree, e.g. `out/ref/elf-x86_64/gcc-O2/debug/features.json`.
- Canonical layout (what `tools/refdiff/refformat.py` `dumps()` writes, and
  recommended for any producer): sorted keys, ASCII with `\u` escapes, one
  top-level key per line, and each element of `memory`, `functions` and
  `instructions` on its own compact line. Consumers must not depend on the
  layout; `refdiff` parses JSON.

```json
{
  "format_version": 1,
  "producer": "ghidra-12.1.4" | "revkit-<git sha>",
  "binary": {
    "path": "x86_64/gcc-O2/hello",
    "sha256": "<hex>",
    "language": "x86:LE:64:default",
    "compiler": "gcc",
    "image_base": "0x400000"
  },
  "memory": [
    { "name": ".text", "start": "0x401000", "end": "0x401fff", "perms": "r-x" }
  ],
  "functions": [
    {
      "entry": "0x401136",
      "name": "main",
      "body": [["0x401136", "0x40118a"]],
      "prototype": "int main(int argc, char * * argv)",
      "decompiled_c": "int main(int argc,char **argv)\n{\n..."
    }
  ],
  "instructions": [
    {
      "addr": "0x401136",
      "len": 4,
      "mnemonic": "ENDBR64",
      "text": "ENDBR64",
      "pcode": [
        { "op": "INT_ADD",
          "out": ["register", "0x20", 8],
          "in":  [["register", "0x20", 8], ["const", "0x8", 8]] }
      ]
    }
  ]
}
```

- `binary.path` is the binary's path relative to the corpus root (as in the
  corpus manifest). `language` is the SLEIGH language ID and `compiler` the
  compiler spec ID Ghidra chose (`gcc`, `clangwindows`, `windows`, ...).
- `memory` lists the blocks in loaded address spaces (Ghidra's
  `MemoryBlock.isLoaded()`, overlays excluded), so non-loaded ELF sections
  such as `.comment`, `.debug_*` and `_elfSectionHeaders` are not listed.
  Blocks Ghidra synthesizes are listed: `EXTERNAL` (ELF import stubs),
  `tdb` (PE thread data block), and processor blocks such as RISC-V `csr`.
  `end` is inclusive. A block outside the default code space carries
  `"space": "<name>"` (e.g. `csreg`) and is matched by (space, start).
  revkit (`rk-lift`) lists only blocks backed by the file: ELF allocated
  sections plus `segment_N.K` fragments for loaded bytes no section covers
  (all-zero fragments up to 0xff bytes dropped, as Ghidra does), and PE
  `Headers` plus sections sized max(VirtualSize, SizeOfRawData). It does not
  synthesize `EXTERNAL`, `tdb` or processor blocks, so those are expected
  differences.
- `functions` are the program's non-external functions after auto-analysis,
  thunks (PLT stubs) included. `name` is unqualified (no namespace).
  `prototype` is Ghidra's `Function.getPrototypeString(false, false)`: no
  calling convention, pointer stars space-separated (`char * * argv`).
- `decompiled_c` is `DecompiledFunction.getC()` from a `DecompInterface` with
  `DecompileOptions.grabFromProgram(program)` and simplification style
  `decompile`. It is omitted for functions the decompiler fails on.
- `body` ranges are inclusive `[first, last]` byte addresses.
- `thumb` (rk-lift `--analyze` only, ARM): `true` on a function discovery
  found to be Thumb code; its body's instructions decode as Thumb.
- `instructions` covers every instruction inside any function body, once each
  even where bodies overlap. `mnemonic` and `text` are Ghidra's
  `getMnemonicString()` and `toString()` (no symbol substitution).
- `pcode` is the instruction's raw SLEIGH p-code with no flow overrides
  applied (Java `Instruction.getPcode(false)`).
- A varnode is `[space_name, offset_hex, size]`. Space names are SLEIGH's
  (`ram`, `register`, `unique`, `const`, `stack`).
- Offsets are unsigned. A `const` offset is masked to its size
  (`["const", "0xfffffffd", 4]`, never a sign-extended 64-bit value); other
  offsets are masked to 64 bits.
- Input 0 of `LOAD` and `STORE` names an address space; its numeric value is
  implementation-specific (Java space ID vs. C++ `AddrSpace*`), so it is
  written with the pseudo-space `space` and the space's name in the offset
  slot: `["space", "ram", 8]`. The size is the one Java's SLEIGH emits:
  the template's (8) for LOAD/STORE written in the spec, and 4 for the
  LOAD/STORE SLEIGH synthesizes for a dynamic operand such as an x86 memory
  operand (Java `PcodeEmit` hard-codes 4 there; C++ uses `sizeof(AddrSpace*)`
  and revkit rewrites it to 4).
  `CALLOTHER`'s input 0 stays a plain `const` user-op index.
- `out` is `null` for ops with no output.
- `unique` offsets can legitimately differ between SLEIGH implementations;
  `refdiff` renumbers them per instruction in order of first appearance
  before comparing: ops in order, and within an op the output first, then
  inputs left to right. Varnodes with the same offset get the same number.

## Debug-info ground truth (`tools/rk-debuginfo`)

`rk-debuginfo` (also installed as `rk-dwarf`, its old name) writes the same
format from a binary's debug info: `binary` and `functions` only (no
`memory`, `instructions` or `decompiled_c`). For ELF that is DWARF. For PE
it is the CodeView PDB the image was linked with, plus any DWARF in the
image (mingw links its runtime's DWARF into the PE), the PDB winning where
both describe a function; `--no-dwarf` and `--no-pdb` pick one.

- The PDB is `--pdb`, or else the first of: the path in the debug
  directory's CodeView record as written, that file name beside the
  binary, and `<name>.pdb` beside the binary, whose GUID and age match the
  image's RSDS record (NB10: signature and age). A mismatched PDB is
  skipped with a warning (`--pdb` uses it anyway, with a warning).
- Addresses are rebased the way Ghidra loads the file (position-independent
  ELF at `0x100000`, 32-bit at `0x10000`; PE at its `ImageBase`), so
  entries line up with Ghidra's export; `--file-base` keeps link-time
  addresses. `language` and `compiler` are the IDs Ghidra picks for the
  machine (`clangwindows` for a PE whose PDB names clang as its compiler).
- PDB functions are the procedure symbols (`S_GPROC32`, `S_LPROC32`, ...)
  at their section:offset, with `body` the procedure's length (plus any
  `S_SEPCODE` blocks). `name` is the unqualified procedure name and
  `prototype` its type with the procedure's own parameter names; CodeView
  has no typedefs, so a PDB prototype names underlying types
  (`ulonglong n`, not `size_t n`), and parameters the compiler left out of
  the PDB print as `param_N`.
- One function per DWARF subprogram with code in an executable section, at
  `DW_AT_low_pc` (or `DW_AT_entry_pc`). `name` is `DW_AT_name`, unqualified;
  GCC clones (`foo.isra.0`) carry the original's name.
- `body` is the DWARF ranges, made inclusive. They cover alignment padding
  between a function's blocks, which Ghidra leaves out of its bodies, so
  `bodies` agreement with Ghidra is not meaningful on optimized builds.
- `prototype` renders the DWARF types in the notation above: what
  `getPrototypeString(false, false)` prints when Ghidra imports the same
  DWARF. That means no qualifiers and no `struct`/`union`/`enum` keywords,
  Ghidra's integer names (`uint`, `ulong`, `uchar`, `longlong`, ...,
  `longdouble`), `T[N]` for arrays, anonymous function types as
  `_func_<ret>_<params>` (`_func_void_int_ptr_void_ptr *`), unnamed
  parameters as `param_N`, and `(void)` for an empty list. Typedef names are
  kept; `--resolve-typedefs` prints underlying types instead, which is the
  truth to score stripped-binary output against (nothing can recover
  `uint32_t` from code).
- `prototype` is omitted when the subprogram has `DW_AT_calling_convention`
  `DW_CC_nocall`: the compiler changed its parameters (IPA-SRA and similar),
  so the declared prototype is not its ABI.

## Comparing prototypes

A raw string comparison mixes notation with substance: Ghidra spells a DWARF
base type by its own name when it has one (`ulong`) but by the DWARF name
when it doesn't (clang's `unsigned long`), and shows a struct returned in
memory as a hidden parameter. Before comparing, both sides are normalized
(reference implementation: `normalize()` in `tools/rk-debuginfo/protonorm.py`):

1. Tokenize; rejoin with one space between tokens, none after `(` or `[` or
   before `)`, `]`, `,` or `[`, and one after `,`. Stars stay separate
   tokens: `char **argv` and `char * * argv` both become `char * * argv`.
2. Drop `const`, `volatile`, `restrict`, `_Atomic` and the keywords
   `struct`, `union`, `enum`, `class`.
3. Spell C integer and float types with Ghidra's names: `unsigned int` and
   `unsigned` → `uint`; `long int` → `long`; `unsigned long` and
   `long unsigned int` → `ulong`; `short int` → `short`; `unsigned short`,
   `short unsigned int` → `ushort`; `signed char` → `char`; `unsigned char`
   → `uchar`; `long long` → `longlong`; `unsigned long long` → `ulonglong`;
   `long double` → `longdouble`; `_Bool` → `bool`. Ghidra's names for
   types from a PDB, and for long double on Windows, map the same way:
   `long64` → `longlong`, `ulong64` → `ulonglong`, `schar` → `char`,
   `float10` and `float16` → `longdouble`, and an anonymous function type's
   calling convention is dropped (`_func___cdecl_int_int` →
   `_func_int_int`).
4. If the first parameter is `T * __return_storage_ptr__`, remove it, and
   if the return type is `T *` or `void`, make it `T`.
5. `()` is `(void)`.

Three levels of agreement, each over the functions that have a truth
prototype (a function missing on the other side counts as a mismatch):

- **normalized**: normalized prototypes equal, parameter names included.
- **signature**: also ignoring the function name and parameter names (the
  last identifier of each parameter); this is the one to gate on, since a
  stripped binary has no names to recover.
- **arity**: same parameter count, varargs, and void/non-void return.

For a stripped binary, Ghidra's `prototype` is `undefined FUN_...()` (its
analysis doesn't commit the decompiler's signature), so compare the
signature line of `decompiled_c` instead (`protonorm.py --decompiled`).

Differences that survive normalization are real disagreements, e.g.
AArch64 `va_list` parameters (Ghidra shows the by-reference copy as
`va_list *`), extra parameters Ghidra takes from GCC's concrete
out-of-line DIEs, and, from a PDB, variadic functions without their `...`
and Windows x64's by-reference `long double` parameters.

`protonorm.py` also prints an **exact** rate (the raw strings equal), so
four levels in all.
