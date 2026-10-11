# Decompiler parity (Phase 2 gate, Phase 3 own inputs)

> Given Ghidra's function bounds, symbols and types, ≥95% of corpus
> functions produce structurally identical C (same AST modulo whitespace);
> whole-corpus decompilation ≥3× faster wall-clock than `analyzeHeadless`
> on the same machine.

**Result: 11380 of 11380 corpus functions (100%) produce structurally
identical C, and the same tokens including comments. The corpus decompiles
in about 4.5 s, against about 58 s for `analyzeHeadless` (13×) and about
12 s for Ghidra's decompilation phase alone (2.6×).**
Details, method and caveats below.

## The harness

```sh
# Ghidra side, once (also done by scripts/phase0.sh): references and the
# decompiler inputs from the same analysis session.
py=$(scripts/setup-pyghidra.sh)
$py tools/ghidra-export/ghidra_export.py --corpus out/corpus --out out/ref --inputs-out out/ghidra-db

# revkit side: decompile every binary in process, compare.
scripts/decompile-corpus.sh --inputs out/ghidra-db --in-order -P 16       # -> out/revkit-decomp
python3 tools/refdiff/refdiff.py out/ref out/revkit-decomp --only c_tokens,c_ast,c_alpha --by-group --group-depth 2

# One binary:
build/tools/rk-lift/rk-lift --decompile --no-instructions --inputs out/ghidra-db/elf-x86_64/gcc-O2/debug/zlib.json \
    --in-order -j 1 -o zlib.json out/corpus/elf-x86_64/gcc-O2/debug/zlib
```

| Piece | What |
| --- | --- |
| `tools/ghidra-export/ghidra_dbexport.py` (or `ghidra_export.py --inputs-out`) | Exports what Ghidra's Java side tells its decompiler: [decompiler-inputs.md](decompiler-inputs.md) |
| `rk-lift --decompile` | Decompiles every function in process. `--inputs` takes Ghidra's inputs and function list; `--functions-from` takes only a reference file's function list; `-j` threads; `--in-order` keeps address order |
| `src/lift/decompile.{hh,cc}` | `InputDecompiler` (one `ImageArchitecture` answering the decompiler's queries from the inputs) and `decompile_functions` (one per thread) |
| `scripts/decompile-corpus.sh` | Runs rk-lift over the corpus, `-P` binaries at once |
| `tools/refdiff` `c_tokens`, `c_ast`, `c_alpha` | Token-level comparison of decompiled C ([refdiff README](../tools/refdiff/README.md)) |
| `scripts/ci.sh` | Gates `c_*` rates against `corpus/baselines/rk-decomp.json` (Ghidra inputs), `rk-decomp-refonly.json` (reference function list only) and `rk-decomp-own.json` (revkit's own inputs, common functions) |
| `scripts/decomp-ablation.py` | Removes one kind of Ghidra fact at a time and measures the loss |
| `scripts/ghidra-headless-timing.py`, `tools/ghidra-export/ghidra_decompile_timing.py` | Ghidra timings on the same machine |

### Comparison

`c_ast` compares token sequences without comments: two token sequences
are equal exactly when the C parses to the same syntax tree, so this is
"same AST modulo whitespace". Line wrapping and indentation never matter.
`c_tokens` keeps comments (warnings, plate and pre comments) and compares
them word by word; it is stricter. `c_alpha` additionally renames local
variables and parameters by order of use; it is a looser secondary measure
that forgives naming only. A function both sides fail to decompile (one:
Lua `0x107b70` on AArch64, "Overlapping input varnodes") counts as
agreement.

## Results

### Under Ghidra's inputs (the gate)

Every group is at 100% on all three measures:

| arch / toolchain | functions | `c_ast` | `c_tokens` |
| --- | ---: | ---: | ---: |
| elf-aarch64/clang-O0 | 336 | 100% | 100% |
| elf-aarch64/clang-O2 | 2254 | 100% | 100% |
| elf-aarch64/gcc-O0 | 340 | 100% | 100% |
| elf-aarch64/gcc-O2 | 500 | 100% | 100% |
| elf-riscv64/clang-O0 | 324 | 100% | 100% |
| elf-riscv64/clang-O2 | 456 | 100% | 100% |
| elf-riscv64/gcc-O0 | 332 | 100% | 100% |
| elf-riscv64/gcc-O2 | 618 | 100% | 100% |
| elf-x86_64/clang-O0 | 1094 | 100% | 100% |
| elf-x86_64/clang-O2 | 456 | 100% | 100% |
| elf-x86_64/gcc-O0 | 642 | 100% | 100% |
| elf-x86_64/gcc-O2 | 2626 | 100% | 100% |
| pe-x86_64/clang-O0 | 506 | 100% | 100% |
| pe-x86_64/clang-O2 | 896 | 100% | 100% |
| **total** | **11380** | **100%** | **100%** |

That needs `--in-order` (each binary's functions in address order on one
decompiler instance, as `DecompInterface` does): the decompiler numbers
`join` storage (multi-register values) in first-use order and keeps that
numbering for the life of the architecture, so a function's variable
numbering depends on which functions were decompiled before it. With
threads inside a binary (`-j 8`), 11379 of 11380 match: one AArch64 Lua
function swaps `auVar14` and `auVar15`.

Ghidra's auto-analysis is not fully deterministic either: in about one run
of three, RISC-V zlib's `main` gets a tracked `gp` value. The reference and
the inputs must therefore come from the same Ghidra session, which
`ghidra_export.py --inputs-out` and `scripts/phase0.sh` ensure.
`ghidra_dbexport.py --with-c` also records Ghidra's own C from its session
for such comparisons.

### From the reference's function list only

With only the reference's function entries, names and bodies, plus what
revkit's loader knows (`--functions-from`, Ghidra's default names
synthesized), 14.3% of functions match (`c_ast`), 19.2% ignoring variable
names. The decompiler is the same; the difference is everything Ghidra's
analysis and type import add. Per group (`c_tokens`, `c_ast`, `c_alpha`):

| arch / toolchain | `c_tokens` | `c_ast` | `c_alpha` |
| --- | ---: | ---: | ---: |
| elf-aarch64/clang-O0 | 11.6% | 12.8% | 29.8% |
| elf-aarch64/clang-O2 | 14.0% | 14.6% | 16.9% |
| elf-aarch64/gcc-O0 | 17.1% | 18.2% | 27.7% |
| elf-aarch64/gcc-O2 | 16.8% | 18.6% | 19.8% |
| elf-riscv64/clang-O0 | 12.0% | 13.3% | 29.9% |
| elf-riscv64/clang-O2 | 14.9% | 16.5% | 16.7% |
| elf-riscv64/gcc-O0 | 16.3% | 17.5% | 28.9% |
| elf-riscv64/gcc-O2 | 17.0% | 18.0% | 18.3% |
| elf-x86_64/clang-O0 | 11.4% | 12.3% | 25.7% |
| elf-x86_64/clang-O2 | 14.7% | 16.2% | 18.0% |
| elf-x86_64/gcc-O0 | 16.4% | 17.5% | 24.8% |
| elf-x86_64/gcc-O2 | 14.5% | 15.0% | 17.3% |
| pe-x86_64/clang-O0 | 6.9% | 7.1% | 15.4% |
| pe-x86_64/clang-O2 | 5.1% | 7.7% | 8.8% |

## What each kind of input is worth

`scripts/decomp-ablation.py` starts from Ghidra's full inputs (100%) and
removes one kind of fact at a time. The loss is how many functions depend
on it; it ranks what revkit must produce itself before it can match Ghidra
without Ghidra.

| Input removed | Functions that stop matching | Example (Ghidra / revkit without it) | Who can supply it |
| --- | ---: | --- | --- |
| Function signatures (parameters, return types, calling conventions) | 7592 | `void * memcpy(void *...` / `void memcpy(void)` | Mostly inherent today: DWARF prototypes (debug builds), Ghidra's type archives for imports, conventions its analysis assigns. revkit's DWARF and PDB readers could supply the first |
| Local variables (stack analysis, DWARF locals) | 2703 | `int local_58;` / `int iStack_58;` | Inherent: Ghidra's stack analysis; DWARF locals fixable |
| Data symbols and types | 2276 | `(*(code *)(undefined *)0x0)()` / `(*(code *)0x0)()` | Mostly inherent (data, string and pointer analysis); ELF symbols and DWARF globals fixable |
| Labels (which code addresses Ghidra has references to) | 2144 | `goto LAB_00106f74` / `goto code_r0x00106f74` | Inherent (reference analysis); revkit synthesizes `LAB_` for every target, which is close |
| Relocated bytes (GOT and IAT contents, `RELATIVE` pointers) | 1642 | `memcpy(__dest,__src...` / `(void *)(...` | Fixable on revkit's side: the loader applying relocations and laying out `EXTERNAL` as Ghidra does |
| Flow overrides (`CALL_RETURN` on PLT jumps) | 1548 | `abort();` / `abort(); return;` | Fixable on revkit's side: mark PLT stubs |
| Tracked registers (RISC-V `gp`, PE `GS_OFFSET`) | 686 | `gp = &__global_pointer$;` missing | Fixable on revkit's side: loader context from `__global_pointer$` and the PE thread block |
| Non-returning functions | 583 | `abort();` / `abort(); return;` | Largely fixable (Ghidra's list of known non-returning names); propagation needs analysis |
| Import slots (PE IAT external references) | 394 | `SetUnhandledExceptionFilter(...)` / `(*(code *)...)()` | Fixable on revkit's side: the loader already knows the imports |
| Namespaces (DWARF static locals) | 76 | `run_floats::coef` / `coef` | Fixable with DWARF |
| Comments | 12 | a pre comment keeps `} else { if` from becoming `} else if` | Inherent (Ghidra's DWARF and loader notes) |
| Synthesized memory (PE thread block) | 6 | `StackBase` / `*(void **)...` | Fixable on revkit's side |
| Ghidra's memory map | 0 | | revkit's loader blocks agree |

So of what the decompiler is told, revkit's integration now reproduces
everything; what revkit's own components would need to produce, to reach
Ghidra's output without Ghidra, is led by signatures, locals and data
symbols (analysis and type import), then relocations, PLT overrides,
tracked registers, non-returning functions and imports, which are loader
work.

## What revkit fixed on its side

Under identical inputs, these differences were revkit's (or the C++
decompiler's defaults where Ghidra's Java side differs), and are fixed in
`src/lift`. Rates are `c_ast` over the corpus when each was found.

| Difference | Fix |
| --- | --- |
| Core types named `undefined`/`uint4` rather than Ghidra's (`undefined1`, `uint3`, `longdouble`, `wchar16`, ...); variable prefixes (`auVar`) follow | `ImageArchitecture::buildCoreTypes` declares PcodeDataTypeManager's list, ids included, from the compiler spec's data organization |
| `1LL` instead of `1L` on Windows | Java omits data-organization fields equal to its defaults, so Ghidra's decompiler never learns that `long` is 4 bytes on LLP64; mirrored (`ImageTypeFactory::java_long_size`) |
| `main.cold` instead of `main_cold` | `DecompileResults` runs `IllegalCharCppTransformer` over function, variable, type, field and label tokens; the printer does the same |
| Warnings after plate comments in the header | Java's comments reach the decompiler when the printer first asks, after analysis added its warnings; comments are added then |
| `in_RSI` instead of `in_register_00000034`, `extraout_q0` instead of `extraout_var` | Java names storage only after a register that starts there (`RegisterManager.getRegister(addr, size)`); SLEIGH also accepts a containing register |
| `"\xfeff"` instead of `&DAT_001071f1`; `""` arrays; strings running past their data | `JavaStringManager`: defined strings' own values, else US-ASCII/UTF-16/UTF-32 to a terminator, rejected on a replacement character, terminator appended as `DecompileProcess` does |
| `_frm` instead of `frm` (RISC-V CSRs) | Java answers a hole where a register starts, so the decompiler names it after the register |
| `UNK_00105dc8` instead of `UNK_ram_00105dc8`; `abort` instead of `<EXTERNAL>_abort` | Ghidra's dynamic names carry the space name where it shows; code labels are namespace-prefixed |
| Undefined bytes in read-only memory as raw constants instead of `&UNK_...` | Java sends a dynamically named symbol for undefined bytes that aren't plain writable memory |
| A type's warning (`Enum "SectionFlags"`) in every function | Types are fetched when first needed and dropped after each function, as Java flushes the decompiler |
| Whole functions lost to unreadable bytes (`EXTERNAL` placeholders) | Unreadable bytes decode as a bad instruction (`halt_baddata`), as when Java has no instruction to send |
| Symbols from earlier functions leaking into later ones | `ImageScope::reset()` after every function (Java's `flushNative`) |
| Duplicate scope ids for functions without a Ghidra id | Ids that can't collide with the decompiler's temporary functions (jump-table recovery) |
| Variable numbering (`auVar14`/`auVar15`) | `--in-order`: see above |

Progression on the corpus: 79.5% (zlib, names and options only) → 99.46%
(inputs with lazy types, namespaces, external references) → 99.99% (spaces,
registers, strings) → 100% (in order).

## From revkit's own inputs (Phase 3)

`rk-lift --analyze --decompile` decompiles with nothing from Ghidra but the
decompiler and its language files: functions from `revkit::analysis`
discovery, and every fact Ghidra's Java side would have put in its database
assembled by `src/inputs` (`revkit::inputs`) from revkit's loader,
discovery and debug-info readers. The image backend's `decompile.ghidra`
uses the same assembly (below), so the UI and SDK show this output.

```sh
scripts/decompile-corpus.sh --inputs own --out build/corpus-out/revkit-decomp-own --in-order
python3 tools/refdiff/refdiff.py out/ref build/corpus-out/revkit-decomp-own \
  --common-functions --only functions,c_tokens,c_ast,c_alpha --by-group --group-depth 2 --by-variant
# what one kind of fact is worth: --own-facts KINDS (only those), --no-own KIND
# the inputs as JSON, for scripts/compare-inputs.py: --dump-inputs
```

C is compared on the functions both sides have (matched by entry,
`--common-functions`); `functions` is the overlap of the function sets
themselves, reported apart. The CI gate is `corpus/baselines/rk-decomp-own.json`.

> **Since phase7/decomp-quality, identity with Ghidra is a regression guard,
> not the goal.** The goal is C closer to the original source than Ghidra's
> ([decomp-quality.md](decomp-quality.md)), and revkit now departs from
> Ghidra where that wins there: on stripped 64-bit programs `rk-lift`
> locks revkit::infer's prototypes (`--no-infer-prototypes` turns it off),
> and in raw firmware images strings and literal-pool constants are
> constants ([firmware.md](firmware.md#constants-in-a-writable-image)).
> With those, the tuning corpus's own-input `c_ast` is **55.5%** (debug
> builds 89.2% as before, stripped builds 21.4%, were 95.5%), and the gate's
> baseline was lowered to match:
>
> | group | `functions` | `c_tokens` | `c_ast` | `c_alpha` |
> | --- | ---: | ---: | ---: | ---: |
> | elf-aarch64/clang-O0 | 82.1% | 52.2% | 64.1% | 64.1% |
> | elf-aarch64/clang-O2 | 86.8% | 37.3% | 54.9% | 55.1% |
> | elf-aarch64/gcc-O0 | 81.8% | 63.3% | 63.7% | 63.7% |
> | elf-aarch64/gcc-O2 | 78.8% | 47.5% | 63.7% | 64.2% |
> | elf-riscv64/clang-O0 | 81.6% | 49.3% | 52.3% | 52.3% |
> | elf-riscv64/clang-O2 | 78.7% | 32.6% | 50.8% | 51.7% |
> | elf-riscv64/gcc-O0 | 80.8% | 50.0% | 52.2% | 53.0% |
> | elf-riscv64/gcc-O2 | 79.7% | 37.1% | 47.4% | 47.4% |
> | elf-x86_64/clang-O0 | 84.6% | 57.6% | 60.4% | 60.5% |
> | elf-x86_64/clang-O2 | 78.5% | 44.4% | 65.6% | 66.5% |
> | elf-x86_64/gcc-O0 | 83.8% | 58.9% | 62.6% | 62.6% |
> | elf-x86_64/gcc-O2 | 87.4% | 39.5% | 54.1% | 54.6% |
> | pe-x86_64/clang-O0 | 96.6% | 42.7% | 49.6% | 50.2% |
> | pe-x86_64/clang-O2 | 95.7% | 34.7% | 50.2% | 51.1% |
> | **debug builds** | 86.2% | 65.7% | 89.2% | 89.9% |
> | **stripped builds** | 85.3% | 20.6% | 21.4% | 21.6% |
> | **all** | 85.7% | 43.3% | **55.5%** | 55.9% |
>
> The tables below are the state before that (92.3%), kept for the
> history of the parity work; `--no-infer-prototypes` reproduces them.

| group | `functions` | `c_tokens` | `c_ast` | `c_alpha` |
| --- | ---: | ---: | ---: | ---: |
| elf-aarch64/clang-O0 | 82.1% | 84.8% | 96.7% | 96.7% |
| elf-aarch64/clang-O2 | 86.8% | 76.4% | 94.0% | 94.6% |
| elf-aarch64/gcc-O0 | 81.8% | 96.0% | 96.4% | 96.4% |
| elf-aarch64/gcc-O2 | 78.8% | 79.2% | 95.4% | 95.9% |
| elf-riscv64/clang-O0 | 81.6% | 91.0% | 94.0% | 94.4% |
| elf-riscv64/clang-O2 | 78.7% | 73.5% | 91.7% | 93.1% |
| elf-riscv64/gcc-O0 | 80.8% | 90.7% | 93.0% | 94.4% |
| elf-riscv64/gcc-O2 | 79.7% | 78.6% | 88.9% | 89.3% |
| elf-x86_64/clang-O0 | 84.6% | 94.6% | 97.4% | 97.6% |
| elf-x86_64/clang-O2 | 78.5% | 74.9% | 96.1% | 96.9% |
| elf-x86_64/gcc-O0 | 83.8% | 94.2% | 98.0% | 98.0% |
| elf-x86_64/gcc-O2 | 87.4% | 78.6% | 93.1% | 93.7% |
| pe-x86_64/clang-O0 | 96.6% | 73.9% | 80.8% | 83.4% |
| pe-x86_64/clang-O2 | 95.7% | 57.6% | 80.6% | 83.0% |
| **debug builds** | 86.2% | 65.7% | 89.2% | 89.9% |
| **stripped builds** | 85.3% | 93.3% | 95.5% | 96.5% |
| **all** | 85.7% | 79.4% | **92.3%** | 93.2% |

Data analysis ([data-analysis.md](data-analysis.md)) took this from 78.2%
(PE 46.9%) to 90.1% (PE 65.3%), and Ghidra's Decompiler Parameter ID
([param-id.md](param-id.md)) to 92.3% (PE 80.7%); the steps are in the
second table below.
The PDB rows use `--pdb-signatures ghidra`, rk-lift's default (Ghidra's
PDB applicator's `__cdecl` and `param_N`); with the PDB's own names
(`full`, the daemon's) the corpus is at 88.5%.

### What each fix added

Cumulative, in the order they landed (`--own-facts` with each kind added to
the ones before; rates on the 9812 common functions):

| facts given | `c_ast` debug | `c_ast` stripped | `c_tokens` debug | `c_tokens` stripped | `c_ast` all |
| --- | ---: | ---: | ---: | ---: | ---: |
| discovery's functions only | 1.5% | 27.0% | 1.5% | 26.5% | 14.2% |
| + relocations (`EXTERNAL` block, GOT, `RELATIVE`) | 2.5% | 28.4% | 2.2% | 27.3% | 15.4% |
| + `CALL_RETURN` on import stubs and shared returns | 3.1% | 33.9% | 2.8% | 32.8% | 18.4% |
| + discovery's no-return functions | 3.6% | 34.5% | 2.9% | 33.0% | 19.0% |
| + PE import slots as external references | 3.8% | 34.6% | 3.1% | 33.2% | 19.1% |
| + tracked registers (RISC-V `gp`, PE `GS_OFFSET`, thread block) | 3.8% | 34.6% | 3.1% | 33.1% | 19.1% |
| + `LAB_` only where code is referred to | 4.0% | 34.8% | 3.3% | 33.4% | 19.3% |
| + loader data symbols (ELF objects, pointer slots `PTR_`) | 5.1% | 38.4% | 4.2% | 37.0% | 21.7% |
| + DWARF and PDB (names, prototypes, globals, types, namespaces, locals) | 47.3% | 38.4% | 32.7% | 37.0% | 42.9% |
| + library prototypes from Ghidra's type archives | 72.2% | 59.6% | 54.2% | 58.3% | 65.9% |
| + stack variables (Ghidra's Stack analyzer) | **81.8%** | **74.4%** | **61.1%** | **73.2%** | **78.2%** |

Then data analysis ([data-analysis.md](data-analysis.md)), each step on
the one before (`c_ast` on the same 9812 functions; PE is the two
`pe-x86_64` groups together):

| added | `c_ast` all | `c_ast` PE |
| --- | ---: | ---: |
| (the above) | 78.2% | 46.9% |
| + accessed data (`undefinedN`), referenced strings and pointers, the string search, Ghidra's pointer names | 83.6% | 47.3% |
| + memory operands in the code space (x86-64 RIP-relative accesses), `.got` markup, debug variables over loader data | 85.2% | 52.9% |
| + constants carried along the flow, written read-only data not constant | 85.3% | 52.9% |
| + switch case labels (`switchD_..._caseD_n`) | 86.1% | 53.5% |
| + no-return as Ghidra's database has it (names, call-site evidence, thunks; not discovery's inference) | 88.5% | 53.5% |
| + PDB prototypes as Ghidra applies them (`__cdecl`, `param_N`) | 89.9% | 63.8% |
| + PDB public symbols naming what nothing else named | 90.1% | 65.3% |
| + Ghidra's Decompiler Parameter ID (where Ghidra runs it: PE below 2 MiB; [param-id.md](param-id.md)) | **92.3%** | **80.7%** |

Tracked registers change little on their own here because their effect on
RISC-V and PE shows mostly through data and signatures added later; with
everything on, taking Ghidra's tracked values instead gains only 13
functions (below). `c_tokens` counts comments and `c_ast` doesn't: debug
builds' gap between the two is largely Ghidra's `Unresolved local var`
comments for DWARF locals it can't place, which land at other statements
than revkit's.

### The remaining gap

`scripts/decomp-ablation.py --own` starts from revkit's inputs
(`--dump-inputs`) and replaces one kind with Ghidra's (out/ghidra-db) at a
time: the gain is what revkit's version of that kind still costs.

| Kind replaced by Ghidra's | Gain before data analysis | before parameter ID | Gain now | What Ghidra has that revkit doesn't |
| --- | ---: | ---: | ---: | --- |
| Signatures of the program's own functions | +182 | +68 | **-147** | done: of those, the ones Ghidra's Decompiler Parameter ID committed gain +207 before ([param-id.md](param-id.md)) and **-8** now; the rest (debug info) -139 both times: PDB type details (`ulong64`, `_func___cdecl_...` function types, varargs, `long double` passed by reference) fit revkit's other facts worse than revkit's own |
| Code labels | +71 | +22 | +22 | labels of other kinds (a referenced address 0, case labels Ghidra's switch analysis skipped) |
| Flow overrides | +13 | +20 | +20 | |
| Tracked registers | +13 | +13 | +19 | values Ghidra's constant propagation sets beyond the entry (inherent) |
| Non-returning functions | +31 | +15 | +15 | evidence in Ghidra's incremental order |
| Data symbols and types | **+715** | +20 | +13 | DWARF anonymous string variables (`anon_var.dwarf_...`), PE header structures, `switchdataD_` tables |
| Signatures of imported functions | +15 | +22 | +10 | archive prototypes for names revkit's lookup misses (C++ and versioned names) |
| Function names | +17 | +2 | +10 | |
| Comments | +7 | +9 | +9 | loader and DWARF notes |
| Namespaces, relocated bytes, memory | 0 | 0 | 0 | done |
| Local variables | -77 | -78 | -60 | done: Ghidra's locals fit revkit's other facts worse than revkit's own |
| External references | -71 | -71 | -71 | done: likewise, against revkit's `PTR_` data and import names |

All kinds swapped at once give 100% by construction, so the rest of the
92.3% → 100% is interaction between kinds. PE (80.7%) is still behind
ELF (94.3%): its stripped builds are now at 86-89% (55-59% before the
parameter ID), its debug builds (73-76%) lose most to how Ghidra's PDB
applicator types things. The function sets themselves differ by about 14%
in debug and stripped builds alike (`functions`); discovery's side of that
is `rk-lift-analyze.json`'s gate.

### In the image backend

The backend decompiles through the same assembly, as fact-store queries
(`src/backend/own_inputs.h`): `inputs.program` runs
`inputs::assemble_program` over discovery's results and the debug info the
program read at load (the same `inputs::read_debug_info` the import
assertions now come from); `inputs.function` runs
`inputs::assemble_function` (stack variables, flow overrides, code labels)
over one function's flow; `inputs.address` and `inputs.type` slice the
program's facts per address and per type. Each decompiler instance is a
`lift::InputDecompiler` whose `FactLookup` is a `QueryLookup` over those
queries, with the project's assertions laid over them (renames; prototypes
and data types other than the debug info's own). So a decompilation depends
on exactly the slices it reads, and an edit re-decompiles only the
functions that read what changed, as before (the fact-store invalidation
tests pass unchanged, except that RISC-V `run_vm` now folds its
one-destination switch as Ghidra's output does). Differences from rk-lift:
token output via the backend's own printer (no `IllegalCharCppTransformer`
pass), and a function's stack variables are given only for the function
being decompiled (the decompiler doesn't use a callee's).

Ghidra's Decompiler Parameter ID runs there too, as the queries
`analysis.param_id_plan`, `analysis.param_id_deps` and `analysis.param_id`
([param-id.md](param-id.md)), computed in the background after the import
and after each edit and published per function (`param_id.published`) as
results arrive: the first decompilation never waits for it, and a
function whose committed signature changes re-decompiles its callers and
nothing else. The `QueryLookup` lays the commits over functions nothing
asserts and no debug info or archive types, after revkit::infer's
prototype where inference is on.

## Speed

Same machine (Intel i9-14900F, 8 performance and 16 efficiency cores,
32 threads, 31 GB), corpus of 54 binaries and 11380 functions, the Release
(RelWithDebInfo) build. Other jobs shared the machine (load average 3-17
during runs), so every number is a range over repeated runs.

| What | Wall clock |
| --- | ---: |
| Ghidra `analyzeHeadless`, 10 processes (import, auto-analysis, decompile every function; `scripts/ghidra-headless-timing.py`) | 56.1-60.6 s |
| Ghidra decompilation alone, 10 workers starting together after analysis (`ghidra_decompile_timing.py`) | 11.5-12.0 s |
| revkit, exact (`decompile-corpus.sh --in-order -P 16`: load, read inputs, decompile; 100% `c_ast`) | 3.5-5.5 s, typically about 4.5 s |
| revkit, threads within binaries (`-P 16 -j 2` or `-P 8 -j 4`; 99.99%) | 3.7-3.8 s |

- **Against `analyzeHeadless`** (the gate's comparison): about 13×.
  `analyzeHeadless` must analyze to decompile; revkit gets the analysis
  results from Ghidra's export, per the gate's premise.
- **Decompilation alone**: about 2.6× in exact mode, 3.2× with threads
  within binaries. Ghidra's decompile phases add up to 85-109 s (each
  binary through one `DecompInterface`, as the reference export does);
  revkit's processes use 44-58 s of CPU for the same work, a little over 2×
  less. The rest of the wall-clock gap comes from scheduling: each side is
  bounded by its slowest binary (Lua on x86-64: 7.6 s in Ghidra, 2.6 s for
  revkit on a performance core and 3.4-4.6 s on the efficiency cores it
  often lands on).
- revkit's floor for a binary is its slowest function: `luaV_execute`
  takes 1.15 s on its own.
- Where revkit's time goes (Lua, one thread): almost all in the
  decompiler's own analysis; answering its queries (encoding and decoding
  symbols) costs about 0.2 s of 2.7 s, data types next to nothing since they
  are kept between functions, printing 0.04 s, and an architecture's setup
  (mostly the `.sla` decode) 60 ms.
- The reference export's 70 s (10 workers) also walked every instruction
  and its p-code through JPype, so it isn't a decompilation timing.

## In decompiler workers

Since the decompiler moved to worker processes ([decompd.md](decompd.md)),
every gate decompiles from self-contained bundles in `rk-decompd`. Against
the in-process decompiler it replaced (master at 23aeb0f), on the tuning
corpus with the gates' settings (`--in-order -j 1`, join records chained):

| configuration | functions byte-identical |
| --- | ---: |
| Ghidra's inputs (Phase 2 gate) | 11,380 of 11,380 |
| reference function list only | 11,380 of 11,380 |
| revkit's own inputs | 9,874 of 9,876 |

The two that differ are one function, `run_varargs` in PE clang-O0
`features.exe` (debug and stripped): its third vararg prints as
`0x4004000000000000` in one run and as `0` beside `SUB84(...)` in another
depending on nothing but the heap. The in-process decompiler gives a
third variant under `GLIBC_TUNABLES=glibc.malloc.tcache_count=0`, with
identical inputs, lookups and bytes, so Ghidra's decompiler orders
something by pointer there. It is the decompiler fork's to fix; the gates
don't move (the function differs from Ghidra's C either way).

## Vendored code

The decompiler is a fork: pristine Ghidra 12.1.4 plus an ordered patch
series applied at build time ([third_party/ghidra/README.md](../third_party/ghidra/README.md)).
No patch was needed for parity. Patch 0004 keeps a LOAD or STORE whose
constant address range would run past the top of `ram` instead of failing
the function (firmware with a read-only image, [firmware.md](firmware.md));
it changes only functions that failed. The others are defensive fixes for
crashes Ghidra's own decompiler has too (each turns a segfault or SIGFPE
into a `LowlevelError`, so the function fails and the rest of the binary
decompiles; [UPSTREAM.md](../third_party/ghidra/UPSTREAM.md)); they change
no output that existed before. Patches that would help parity, none
applied:

- **Join numbering independent of history.** `Architecture::findAddJoin`
  hands out `join` space offsets in first-use order and never forgets
  them, so decompiling a function after others can number its variables
  differently. Resetting join records in `clearAnalysis` (a few lines in
  `architecture.cc`) would make every function independent of order and
  allow threads within a binary with exact output, but would then differ
  from Ghidra's own process, which keeps them; it only makes sense applied
  to both.
- **`TokenSplit::countbase` per emitter.** `EmitPrettyPrint` numbers
  tokens from a static counter, so concurrent pretty-printers race; revkit
  prints under its exclusive lock. Making the counter a member of
  `EmitPrettyPrint` (`prettyprint.hh/.cc`) would let printing run in
  parallel.
- **UBSan reports** in `printc.cc:1822` (a `TypeUnicode` cast to
  `TypeChar`) and `address.hh:599` (shift of a negative value) are
  Ghidra's own and harmless in practice.

The `1L`/`1LL` difference is a Ghidra bug on the Java side
(`DataOrganizationImpl.encode` omits a 4-byte `long`); revkit reproduces it
for parity.

## Notes

- Debug builds' DWARF reaches the decompiler only through Ghidra's
  inputs here; revkit's own DWARF reader (`src/debuginfo`) does not yet feed
  the decompiler.
- `rk-lift --decompile` without `--inputs` or `--functions-from`
  decompiles the image's own symbols, with Ghidra's default names
  synthesized.
- The image backend (`src/backend`) shares `ImageArchitecture`, so it now
  also gets Ghidra's core type names, Java register naming, bad data for
  unreadable bytes and the lock-free `.sla` load. Its own symbol handling is
  unchanged (the resolving scope is off unless resolvers are set).
