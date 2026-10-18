# Go programs: function names, source lines and the calling convention

A Go binary keeps a table of every Go function, the **pclntab**: its entry,
its end, its name, and for each instruction its source file and line. The
runtime needs it for stack traces and the garbage collector, so `strip` and
`go build -ldflags="-s -w"` leave it in. revkit reads it at import and
names the functions from it, as Ghidra's Golang Symbols analyzer does, and
gives a Go program Ghidra's golang compiler spec, so the decompiler reads
Go's register arguments. Since `api_minor` 93 (feature `go-pclntab`).

What a stripped Go program looked like before, and now (a 1.7 MB
`ls`-like test program, Go 1.27, linux/amd64, `-ldflags="-s -w"`):

| | Functions | `FUN_` | Named as the symbol table names them |
| --- | --- | --- | --- |
| before | 841 | 839 | 0 of 2032 |
| now | 2032 | 1 | 2031 of 2032 (the one left is `runtime.etext`, not a function) |

The build info (Go version, modules, settings) is
[build-info.md](build-info.md); this is the code.

- [Where the table is](#where-the-table-is)
- [The layouts](#the-layouts)
- [What import asserts](#what-import-asserts)
- [Names](#names)
- [The golang compiler spec](#the-golang-compiler-spec)
- [API, SDK, MCP and UI](#api-sdk-mcp-and-ui)
- [Measurements](#measurements)
- [Limits and refusals](#limits-and-refusals)
- [Tests and fuzzing](#tests-and-fuzzing)
- [Not done yet](#not-done-yet)

## Where the table is

`revkit::loader::read_go_pclntab` (`src/loader/gopclntab.cc`,
`revkit/loader/gopclntab.hh`) looks, in order:

| Where | Found by |
| --- | --- |
| ELF `.gopclntab`; `.data.rel.ro.gopclntab` in a PIE before Go 1.18 | `section` |
| Mach-O `__TEXT,__gopclntab` | `section` |
| the `runtime.pcheader` (Go 1.16+) or `runtime.pclntab` symbol | `symbol` |
| its magic, at 4-byte aligned addresses of file-backed memory: a PE (Go's linker names no section for it), an ELF without section headers | `scan` |

A scanned header must have the image's pointer size; each candidate (at
most 32) is decoded whole, its entries must be in executable memory, and
the one a **moduledata** points to wins. The moduledata
(`runtime.firstmoduledata`) is the runtime's record of the module: revkit
finds it as a pointer-sized word in writable data holding the table's
address (Go 1.16+: its `pcHeader` field; before, its `pclntable` slice),
checks that the next field points where the header says (the function-name
table, or before 1.16 the function table), and reads its `minpc`, `maxpc`
and `text`. A pointer is read as the file stores it: a RELATIVE relocation
or a Mach-O rebase at its slot gives its target, and a rebased image moves
it with the image (as the build-info reader does).

From Go 1.18 a function's entry is an offset from the text start. The
header has a `textStart` field, but Go's linker now writes 0 there
("unused"), so revkit takes the moduledata's `text`, then the header's
field when it isn't 0, then the `runtime.text` symbol, then the `.text`
(`__text`) section. The moduledata's `minpc` must be the first function's
entry, or the summary says so.

## The layouts

Four layouts, in both byte orders and both pointer sizes (Go's magics read
differently in the other byte order, which says the order):

| Magic | Layout | Go | Entries | `_func` |
| --- | --- | --- | --- | --- |
| `0xfffffffb` | 1.2 | 1.2 to 1.15 | pointers; one table, file names through a file table of offsets | entry pointer, then 32-bit fields |
| `0xfffffffa` | 1.16 | 1.16, 1.17 | pointers; the header gives offsets to the name, compilation-unit, file, pc-value and function tables | adds `cuOffset` |
| `0xfffffff0` | 1.18 | 1.18, 1.19 | 32-bit offsets from the text start | entry offset |
| `0xfffffff1` | 1.20 | 1.20 and later | as 1.18 | adds `startLine` |

For each function revkit reads its entry, its end (the next entry), its
name, `funcID` and `flag` (1.16+), and if asked its source file and line:
the file is the pcfile table's value at the entry (through the
compilation unit's file list from 1.16, the file table before), the line
is `startLine` (the `func` line) from 1.20, else the pcln table's value at
the entry, which Go gives the function's prologue (the `func` line too).
The format is Go's own (`runtime/symtab.go`, `runtime/runtime2.go`,
`debug/gosym`); how a stripped binary's table is found follows Ghidra's
`GoPcHeader` and `GoModuledata` (THIRD_PARTY_NOTICES.md).

## What import asserts

At import (`src/backend/go_import.cc`, with the PE and Objective-C passes:
`ImageBackendOptions::import_pe_analysis`), a Go program's table becomes
assertions with provenance **`analysis:go`**, ranked below every other
provenance:

| Fact | What |
| --- | --- |
| `FUNCTION_BOUNDS` | a function at every entry (a seed: flow analysis finds the body) |
| `NAME` | Go's name ([below](#names)), only where the file's symbols, exports and the debug info name nothing |
| `COMMENT` (plate) | `Go source: /src/hello/main.go:15`, and `Go name: <Go's spelling>` when the name had to change (Ghidra's `Golang source:` plate comment) |
| `NO_RETURN` | Go's runtime functions that never return: Ghidra's `GolangFunctionsThatDoNotReturn` (`runtime.throw`, `runtime.gopanic`, `runtime.abort`, the `goPanicIndex` family...) and Go 1.25's `runtime.panicBounds`, `panicExtend`, `panicBounds64/32/32X` |

`go:buildid` (the build ID string at the start of the text, which the
table lists) is skipped, as Ghidra skips it. A user's rename, the debug
info's names (DWARF of an unstripped build) and an agent's all win;
reverting `analysis:go` takes the whole pass back. The import's warnings
summarize it: `analysis:go: 2031 functions, 2031 names, 35 no return
functions, 2029 source lines; pclntab 1.20 layout`.

The source location is a plate comment because revkit has no line-number
facts yet (DWARF's `.debug_line` is read only for file names); the
listing and the decompiler show it above the function.

## Names

A function keeps Go's own spelling, the one stack traces, `go tool nm`,
pprof and Ghidra print: `main.main`, `fmt.Fprintf`, `main.(*T).Method`,
`main.T.String`, `example.com/dep.Greeting`, `main.main.func1`,
`slices.Sort[...]` (Go 1.21+ writes generic instantiations so), `type:.eq.main.T`.
`revkit::loader::go_display_name` makes it one revkit name (no whitespace,
at most 256 bytes): an old toolchain's middle dot (`·`) and division slash
as `.` and `/`, whitespace as `_` (Ghidra's `replaceInvalidChars`: a Go
1.18-1.20 shape name such as `sync.(*Pool[go.shape.interface {}]).Get`
becomes `..._{}...`), and in a name still too long, each generic argument
list as `[...]`, then the rest cut.

Go names don't use `::`, so the demangler leaves them alone, and the
symbol tree (`ListSymbolTree`) puts a Go program's functions in
namespaces by **package path**, as Ghidra's symbol tree does:
`Namespaces/example.com/dep/Greeting`, `Namespaces/main/(*T).Method`. The
package is what comes before the first `.` after the last `/` that isn't
inside a receiver or generic arguments; `go:` and `type:` names, and cgo's
C names, stay whole. A program is Go's when it has the golang compiler
spec, a pclntab section or Go build info.

## The golang compiler spec

Ghidra ships compiler specs for Go: `x86-64-golang.cspec` and
`AARCH64_golang.cspec`, whose default prototype is Go's register ABI
(ABIInternal: integer arguments in RAX, RBX, RCX, RDI, RSI, R8-R11 on
amd64, X0-X15 on arm64, results the same, the closure context in RDX and
the goroutine in R14 kept), and `x86-32-golang.cspec` (abi0: everything on
the stack). Ghidra's opinions choose them for a Go binary (`x86.opinion`:
PE i386 and amd64, ELF x86-64; `AARCH64.opinion`: ELF and Mach-O arm64).
revkit's `guess_language` does too, where the default prototype is how
that Go passes arguments:

| Target | golang spec |
| --- | --- |
| amd64 (ELF, PE, Mach-O) | Go 1.17 and later (the register ABI's first release on amd64) |
| arm64 (ELF, PE, Mach-O) | Go 1.18 and later |
| i386 | every Go (abi0) |
| others (ppc64, riscv64, ...) | none in Ghidra |

The Go version is the build info's; without build info, a pclntab section
in the 1.18 or 1.20 layout says at least 1.18 (the 1.16 layout, Go 1.16 or
1.17, keeps the platform's spec). Mach-O x86-64 gets it although Ghidra's
opinion file has no entry for it (the ABI is the same). A Go before the
register ABI keeps the platform's spec: Ghidra applies the golang spec and
then switches each function to `abi0`, which revkit's prototypes can't do
yet. A user can still choose either with `SetProgramLanguage`.

The golang specs' data organization has an 8-byte `int` (Go's `int`) on
amd64 and arm64 and an 8-byte `long` on i386. revkit's decompiler inputs
now take the C types' sizes from those specs (`inputs::data_org`), and the
decompiler's core types keep a 4-byte integer as `sdword`/`dword` where no
C type has 4 bytes, as Ghidra's `SignedDWordDataType`; other specs are
unchanged.

What it changes, for `func total(es []Entry) (n int64)` (Go 1.17, symbols
kept, no DWARF):

```c
// before (gcc spec)
long main.total(void)
{
  long in_RAX; long lVar1; long lVar2; long unaff_RBX;
  if (unaff_RBX < 1) { lVar2 = 0; }
  ...  lVar2 = lVar2 + *(long *)(in_RAX + 0x10); ... in_RAX = in_RAX + 0x20;

// now (golang spec): the slice's pointer and length are the parameters
int main.total(int param_1,int param_2)
{
  ...
  if (param_2 < 1) { iVar2 = 0; }
  ...  iVar2 = iVar2 + *(int *)(param_1 + 0x10); ... param_1 = param_1 + 0x20;
```

and a call reads `os.OpenFile(name,len,0,0)` with its register arguments
instead of no arguments.

## API, SDK, MCP and UI

- `QueryService.GetBuildInfo` returns `go_pclntab` (`GoPclntab`): the
  `layout` (`"1.2"`, `"1.16"`, `"1.18"`, `"1.20"`), its `address`,
  `pointer_size`, `quantum` (1 on x86, 4 on ARM64 and the RISCs),
  `big_endian`, `text_start` (1.18 and 1.20 layouts), `function_count` and
  `functions_read`, `file_count`, the `moduledata` when found, `found_by`
  (`section`, `symbol`, `scan`) and `warnings`. A table that is there but
  doesn't decode is a line in the response's `warnings`.
- Python: `Program.build_info().go_pclntab`; MCP `build_info` has a
  `go_pclntab` summary. The functions, names, comments and no-return marks
  come through the usual reads (`functions()`, `comments("plate")`,
  `symbol_tree()`); their provenance is `analysis:go`.
- The UI's **Build info…** has a Function table line (`2031 functions, 288
  files · pclntab 1.20 layout at 0x4c6348 (section)`), and a Go section
  with only that line for a Go binary without build info.

## Measurements

The `ls`-like program above (flags, a directory walk, sorting, a method,
a closure, generics), built with Go 1.27 and Go 1.17 for each target,
imported into revkit before and after this change. "Named right" counts
the unstripped build's `go tool nm` text symbols whose address now has a
function of that name (`.abi0` suffixes and Mach-O's `_` aside; nm prints
generic shapes with spaces where revkit has `_`, counted as right).

| Binary (stripped unless noted) | Functions before → after | `FUN_` before → after | Named right after | Spec after |
| --- | --- | --- | --- | --- |
| Go 1.27 linux/amd64 | 841 → 2032 | 839 → 1 | 2031 / 2032 | golang |
| Go 1.27 linux/amd64, symbols kept | 2031 → 2033 | 1 → 1 | (the symbols) | golang |
| Go 1.27 linux/amd64 PIE | 842 → 2033 | 840 → 2 | 2031 / 2032 | golang |
| Go 1.27 linux/arm64 | 837 → 1988 | 827 → 0 | 1988 / 1989 | golang |
| Go 1.27 linux/386 | 967 → 2086 | 948 → 28 | (2058 named) | golang |
| Go 1.27 windows/amd64 (PE, found by scan) | 1947 → 2143 | 1945 → 1 | 2142 / 2144 | golang |
| Go 1.27 darwin/amd64 (Mach-O) | 866 → 2115 | 808 → 1 | 2058 / 2060 | golang |
| Go 1.27 darwin/arm64 (Mach-O) | 866 → 2077 | 797 → 0 | 2018 / 2020 | golang |
| Go 1.17 linux/amd64 | 589 → 1584 | 587 → 22 | 1562 / 1563 | golang |
| Go 1.17 linux/amd64 PIE | 590 → 1585 | 588 → 23 | 1562 / 1563 | golang |
| Go 1.17 linux/arm64 | 2 → 1516 | 1 → 23 | 1493 / 1494 | default (abi0) |
| Go 1.17 windows/amd64 (PE) | 582 → 1632 | 580 → 26 | 1606 / 1608 | golang |
| `gh` 2.45 (Go 1.22, 45 MB, stripped, cgo) | 640 → 30697 | 577 → 144 | (30490 named) | golang |

The `FUN_` left are call targets inside other functions: the entry points
into the middle of `runtime.duffzero` and `runtime.duffcopy` that Go's
compiler calls (all 28 on 386, 21 of 22 on Go 1.17 amd64; Ghidra's "Fixup
Duff Functions" handles them, revkit leaves them as flow finds them), and
in `gh` also the C code cgo linked after the Go text (48), which the
pclntab doesn't list. Importing `gh` took 9.7 s (0.9 s before, when
discovery found almost nothing). The 1.2 layout is checked
against Go's own test table (`pcln115.gz`, Go 1.15): `main.main` at
`0x105c280`, `/tmp/hello.go:3`, as `debug/gosym`'s test expects; the 1.18
layout against synthetic tables only (no Go 1.18 or 1.19 toolchain or
binary here).

## Limits and refusals

The file is hostile input. A table that is absent gives nothing (and says
nothing about the language); one that is there and doesn't decode is a
warning.

- Refused: a header whose pad bytes aren't 0, a quantum other than 1, 2 or
  4, a pointer size other than 4 or 8, a header or a table offset past the
  data, no functions, more than 4M functions, a function table past the
  data or not sorted, and a table in which no function decodes.
- Skipped, with a warning (`3 of 2031 functions didn't decode (function
  7: no name)`): a function whose `_func` or name is outside the table.
- Bounded: a table spans at most 1 GiB; a name or file name at most 4096
  bytes; the names and files read at most 256 MiB in all (functions can
  share one long name), after which the rest of the table is left; the
  magic scan reads at most 1 GiB and decodes at most 32 candidates.

## Tests and fuzzing

- `src/loader/tests/gopclntab_test.cc`: synthetic tables in all four
  layouts, little and big endian, 4- and 8-byte pointers, quantum 1 and 4;
  the text start from the moduledata, the header, the text section;
  relocated pointers; every refusal and a skipped function; a table found
  in its section, by its magic in an ELF without section headers past a
  decoy no moduledata points to, and not scanned for in an ELF with
  sections; display names and the no-return list; the golang spec choice
  for each target and version. Then Go's `pcln115.gz` from the installed
  Go, and real builds at test time: the current Go as ELF, PIE, arm64, 386,
  PE and Mach-O amd64 and arm64, stripped, checked function by function
  against the unstripped build's table and `go tool nm`; with `$RK_GO_OLD`
  (Go 1.17) ELF, PIE, PE and arm64 the same way.
- `src/backend/tests/go_test.cc`: a stripped ELF through the API (names
  and their `analysis:go` provenance, the plate comment, `runtime.throw`
  no-return, the golang spec and a method's register parameters in the
  decompiler, the symbol tree's packages, `GetBuildInfo`'s summary), a
  user's rename and the symbol table's names winning, a stripped PE found
  by its magic, and a C program untouched.
- `sdk/python/tests/test_build_info.py` (the SDK and MCP) and
  `ui/e2e/buildinfo.ts` (the dialog's Function table line).
- Fuzzer `go_pclntab_fuzzer` (`src/loader/fuzz`; `-DREVKIT_FUZZ=ON`): the
  table parser over the input (with and without lines, a wrapping text
  start, a pointer function that moves every pointer), and an ELF, PE or
  Mach-O read whole (`read_go_pclntab`, `guess_language`), seeded with the
  synthetic tables and images (`RK_FUZZ_SEEDS=<dir>` makes the loader
  test write them), the first 60 KB of real 1.20 and 1.16 tables and
  `pcln115`. First run: 4 minutes, `-rss_limit_mb=2048`, `-max_len=65536`:
  206,129 executions (855 a second, peak RSS 516 MB), nothing found.

## Not done yet

- **Go strings.** Go's strings are a pointer and a length, not
  NUL-terminated, and the linker packs their bytes together, so the
  decompiler shows a one-byte `"/"` as the whole run of strings after it
  (`/* TRUNCATED STRING LITERAL */`). Ghidra's Golang Strings analyzer
  marks the `{ptr, len}` headers in data and the string bytes they point
  to, and finds the lengths code passes beside a string's address. The
  next step: string headers in `.data`, `.noptrdata` and `.rodata` whose
  pointer is in read-only data and whose length the bytes there hold as
  UTF-8, typed as a `GoString` struct, their bytes as `char[len]`; then
  the code side.
- **Runtime types** (`typelinks`, `rtype`, itabs, Ghidra's Go type
  archives and `GoTypeManager`): the moduledata found here has the
  `types`/`typelinks` fields to start from; each Go version lays `rtype`
  out differently, so it is its own piece of work.
- **Function signatures.** Ghidra gives Go functions their parameters from
  the runtime type of methods and its snapshot JSON of the standard
  library (`typeinfo/golang/*.json`), and fixes a DWARF prototype's
  storage so a `string` or a struct argument takes the registers Go's ABI
  gives it (`GoFunctionFixup`). revkit's DWARF prototypes for Go use the
  spec's storage, which puts an aggregate on the stack; and a Go older
  than the register ABI keeps the platform's spec, as above.
- **Duff's device.** `runtime.duffzero` and `duffcopy` entry points as
  their own functions (Ghidra's `Fixup Duff Functions`).
- **Line numbers** beyond each function's first line: the pcln table has
  every instruction's line; revkit has no line facts to put them in yet.
- Multiple text sections (a text over 256 MB on ARM and PowerPC), the
  dyld shared cache's Go, and plugins and shared libraries
  (`-buildmode=shared`) with more than one moduledata.
