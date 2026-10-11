# Firmware: raw images and firmware-grade discovery

revkit loads flat binaries (firmware, ROM dumps) the way Ghidra's Raw Binary
loader does, and finds their functions with its own analysis: from the
processor's exception vectors, through literal pools, ARM/Thumb
interworking, jump tables and pointer tables, to Ghidra's function-start
patterns and an aggressive code finder for what nothing reaches. Ghidra is
used only to score the result (`scripts/bench-firmware.sh` on the user's
ARM camera firmware, `scripts/ci.sh --firmware` on a multi-processor
corpus, [below](#other-processors)); nothing from it is an input.

![Importing a raw Cortex-M firmware image with a header: revkit detects the processor, the load address, the 0x200-byte header and the RAM and peripheral regions; Reset comes from the vector table; its startup code initializes RAM and the peripherals; a hover previews a callee, which then opens as a graph](images/firmware-demo.gif)

## Loading a raw image

```sh
# rk-lift: header skipped, the image at 0 (rwx), two MMIO regions.
build/tools/rk-lift/rk-lift --raw --lang ARM:LE:32:v4t:default --raw-offset 0x200 \
    --region periph:c0000000:300000 --region sysctrl:d0000000:1000:rw-:volatile \
    --analyze --decompile -o out.json firmware.bin
# rk-decomp, one function, the same layout
build/tools/rk-decomp/rk-decomp --file firmware.bin --lang ARM:LE:32:v4t:default \
    --raw-offset 0x200 --region sysctrl:d0000000:1000 --addr 0x16a70
```

| Flag (rk-lift, rk-decomp) | `ImportOptions` (API, [api.md](api.md#queries)) | Meaning |
| --- | --- | --- |
| `--raw` | `format: "raw"` | load as a flat binary; needs a language |
| `--lang` | `language_id`, `compiler_spec_id` | `proc:endian:size:variant[:compiler]` |
| `--base` | `has_image_base`, `image_base` | the image's address (default 0) |
| `--raw-offset` | `raw_offset` | file bytes before the image (a header) |
| `--raw-length` | `raw_length` | bytes loaded (default: to the end) |
| `--raw-perms` | `raw_permissions` | the image's permissions, default `rwx` as Ghidra's loader |
| `--raw-entry` | `entry_point` | an entry point (the processor's own are added anyway) |
| `--region name:start:size[:perms][:init\|uninit\|volatile]` | `regions` | RAM, MMIO: default `rw-`, uninitialized |

Regions can also be added, changed or removed after import, from the UI's
Memory Map view, the SDKs or MCP, including another file's bytes at an
address (a second flash dump, a bootloader): [memory-map.md](memory-map.md).
Adding a firmware's RAM and MMIO afterwards gives the same analysis and C
as declaring them here.

`loader::parse_raw` builds the image (`src/loader/raw.cc`); the backend keeps
the layout in the program's record (`ProgramSource::raw`), so a persistent
project reopens identically. The web UI's Open dialog has a "Raw binary"
section, and a file the daemon can't load as ELF or PE opens it.

Memory semantics, as in Ghidra: an uninitialized region has no contents and
is never folded; a `volatile` region (MMIO) is never folded or merged; the
image is read/write/execute by default, so reads of it are not constant.
With a read-only image, the decompiler folds reads of it; patch 0004
(`third_party/ghidra`) keeps a fold that would address past the top of
memory (a pointer slot holding 0xffffffff, as erased flash reads) from
failing the function: the access stays a pointer access.

### Constants in a writable image

A raw image is read/write/execute, so nothing in it is constant to the
decompiler: it prints a string only from read-only memory
(`PrintC::pushPtrCharConstant`) and folds only read-only words, and
Ghidra's C of a firmware shows no source string at all and reads every
constant through its literal pool (`FUN_0801d298(DAT_0800013c, ...)`).
revkit departs from that (`inputs::add_analyzed_values`, raw images only):
data no code writes (`analysis::DataItem::written`, anywhere inside the
item) is constant when it is

- a string in the image (initialized, executable, not I/O): the C shows
  `"[%8lu] %-6s %s\n"`;
- a literal-pool word (`DataItem::literal`: inside a flow's
  `FlowGraph::literals`) holding a string's or a function's address, or a
  number outside memory (a mask, a division's magic multiplier): the C
  shows the string, calls the function directly (SuperH's `jsr @rN`) and
  divides by 1000 instead of multiplying by `DAT_400d0360`.

A pool word holding any other address stays a read through the pool, as
in Ghidra: with an address in RAM or in a peripheral region constant, the
decompiler forwards a store there to the loads after it (a register polled
after a write becomes an infinite loop wherever the region isn't declared
volatile), and in an image at a low address small numbers (sizes, counts)
would read as pointers into it. Against the original source this wins on
every processor ([decomp-quality.md](decomp-quality.md)); against Ghidra's
own C it costs identity (the C `ast` column below, and the baselines).

## Discovery

What `src/analysis` adds, all as fact-engine queries (`analysis.flow`,
`analysis.functions`), deterministic for any number of threads:

| Mechanism | Where | Ghidra's counterpart |
| --- | --- | --- |
| Processor entry points (`<default_symbols>` with `entry`, ARM's vectors) | `describe`, `lift::processor_symbols` | "Apply Processor Defined Labels" |
| Vectors held as pointers (`type="code_ptr"`: Cortex-M, MSP430, 6502, the 68HC families, V850): the slot is data and the code it points to is a function named after the vector. Cortex-M's table, which the spec puts at 0, is read at the image's start when the image is loaded at its flash address (an STM32's 0x08000000), and its external interrupts past the spec's `IRQ` are followed too (`IRQ1`, `IRQ2`, ...) | `describe` | Ghidra applies them only at the spec's own addresses |
| Computed jumps and calls resolved from literal pools and the program counter (`ldr pc, [pc, #n]`, `ldr r0, =f; bx r0`), calls past them clobbering memory and `lr` | `resolve_computed` | ARM constant propagation (`ArmAnalyzer`) |
| `mov lr, pc` before a jump makes it a call; a jump to the unchanged link register (`mov pc, lr`, `pop {pc}` after a push of `lr`) is a return | `resolve_computed` | `LRset` context, `ArmAnalyzer`'s return override |
| ARM/Thumb interworking: `BX`/`BLX` targets take the instruction set the `TB` register says; Thumb flows are keyed by the tagged address and decode with a Thumb engine; `kFunctionThumb`, `FunctionInfo::flow_key()` | `Flow`, `Decoder` | TMode context at BX/BLX targets |
| ARM conditional execution: conditional jumps and returns fall through, and a conditional `ldrls pc, [...]` / `addls pc, pc, ...` is its own jump-table guard; table words are data | `classify`, `recover_jump_table` | ARM switch analysis |
| Switch helpers: a call to code that, instead of returning, goes on where a table at its return address says (gcc's `__gnu_thumb1_case_uqi`/`sqi`/`uhi`/`shi`/`si` for Thumb-1, ARM's `switch8`). A callee qualifies by its shape (a few straight-line instructions ending in a computed jump made from the link register it was called with); the call site proves it by recovering the table through the helper's own instructions, as any jump table is probed. The call becomes a computed jump to the cases, the table data, and the helper stays a called function (`FlowGraph::case_calls`), named by Ghidra's labelled start patterns (`funcstart label=`, `label_patterns`) | `CaseHelper`, `Flow`, `Discovery::find_labels` | ARM switch patterns (Function Start Pre Search), call fixups, Decompiler Switch Analysis |
| Words loaded from code (literal pools) are data, and the code addresses among them candidate functions | `FlowGraph::literals`, `code_pointers` | constant references |
| Ghidra's function-start patterns (`Ghidra/Processors/*/data/patterns`, Apache 2.0, read from the install) in code nothing reached, with their `after`, `validcode`, `contiguous` and alignment conditions; code pointers (literal pools, runs of three or more pointers in data) count as the data references `after="ptr"` / `"defined"` accept; a "possible" start that another function's code falls into is dropped | `search_starts` | Function Start Search |
| Code that isn't a function: at gap starts, a plausible subroutine that calls a known function or new code; its calls make functions, its literal pools data | `find_code` | ARM Aggressive Instruction Finder |
| Constants code loads that point into code nothing reached: a function where the code there is a valid subroutine (every decoded flow ends in a return, a computed jump or known code; not a string, pointer data or a mask) | `search_starts` | Reference analyzer (`OperandReferenceAnalyzer`, `PseudoDisassembler.checkValidSubroutine`) |
| Code the code finder found that something calls becomes a function; code it finds that begins by saving the return address is a (possible) function; where a gap's start gives nothing, the first place further in that saves the return address and calls a known function | `Discovery::run`, `find_code`, `saves_return_address` | |
| Fill (more than 16 instructions of one repeated byte), text, bytes as random as compressed data and zeroed words are not code; an unproven candidate must be credible code | `starts_fill`, `Discovery::credible` | |
| Far jumps: gcc's Thumb-1 `bl` to a place in the same function (a branch reaches 2 KiB). Code that returns from a stack frame it didn't make (the first path to a return takes the return address off the stack as it found it; through further far jumps, three deep) is the rest of a function: a call to it that returns from exactly the frame the caller's prologue made is a jump (`FlowGraph::far_jumps`, `BRANCH` to the decompiler), and as a candidate it isn't credible | `FrameFragment`, `pops_callers_frame`, `prologue_frame` | none (Ghidra makes each far jump's target a function) |
| Shrink-wrapped prologues (`cbz r0, out; push {r4, lr}`): a prologue a few instructions into a gap, after a forward early exit that tests what the function was given, starts where the gap does. The guard is at most 16 bytes of instructions, delay slots not counted (32 bytes in all), so MIPS's several early exits, each a branch and its slot (`beqz a0, out; nop; lw v1, 4(a0); beqz v1, out; nop`), reach a prologue 20 or more bytes in | `guards_prologue` | |
| A computed jump the first path to it resolved to one address, because the index was a constant there (an out-of-range value clamped to a case on the way in: `cmp r0, #3; bls 1f; movs r0, #0; 1: lsls r0, #1; add pc, r0`), is probed again along each other path into its straight run; a table of two or more destinations found there (through the guard) makes it the switch | `Flow` (`reprobe_shared_jump`) | ARM switch analysis |
| What the search found inside a literal pool known code loads, or inside an instruction of code it didn't find, is dropped | `Discovery::run` | |
| A conditional branch to a function elsewhere is a tail call (ARM's `beq other_function`): a possible start counts as inside a function only when reached between its own instructions (or, conditionally, right after them) | `Walk::inner` | |
| An ARM exception vector table inside the image (an application after its boot loader: `b reset` and seven `ldr pc, [pc, #n]`) gives its reset code | `search_starts` | |
| Tables of pointers in data (an ELF's: names and handlers, three or more code pointers in a run of pointers) give candidates checked as a valid subroutine | `search_starts` | Create Address Tables |
| No-return inference over all of it (an infinite loop like `b .` is no-return) | `infer_no_return` | Non-Returning Functions |
| A fallback when all of the above finds nothing at all: routines called from two or more places, then code that calls them ([below](#discovery-without-seeds-or-patterns)) | `find_called`, `find_code` | Aggressive Instruction Finder (off by default) |

The search runs for raw images and stripped ARM ELFs (no static symbol
table's functions; `ProgramInfo::search`): other ELF and PE programs have
symbols, exports and unwind tables, and their gates are unchanged. An ARM
ELF's lazy PLT is cut into stubs by its size and jump slots (binutils: a
20-byte header and 12- or 16-byte stubs; lld: 32 and 16), not by
`sh_entsize`, which is an instruction's. Interworking applies to every ARM program. The computed-flow
resolution applies to every ARM program and to raw images on every
processor (SuperH `jsr @rN` after a literal load, `bsrf`/`braf`, MIPS
`jalr`, PowerPC `bctrl`, Xtensa `callx8`), as Ghidra's constant
propagation resolves them; a resolved jump back before the function's
entry is a tail call (SuperH's `braf` after an epilogue). In ELF and PE
programs elsewhere Ghidra leaves such jumps alone (the held-out set showed
bodies moving on x86-64 when they were resolved there too). Literal-pool
loads include memory operands of any p-code op (SuperH's
`mov.l @(disp,pc)` lifts to a COPY from `ram`).

To the decompiler: on ARM every function gets its instruction set (`TMode`)
over its body and over the code of other functions its flow runs or jumps
into (`FunctionFacts::context`, `context_reach`, from `FunctionInfo::reach`),
after the context there is set back to the language's and the image's: what
decoding other code left (SLEIGH's `globalset` at `BL`/`BLX` targets, as
data read as code has them; an IT block's state) doesn't reach it, so a
function's C doesn't depend on what was decompiled before it;
a function named as the compiler spec's call fixups name their targets
(`<callfixup><target name=...>`: the switch helpers above, get_pc thunks)
gets that fixup (`FunctionFacts::call_fixup`, as Ghidra's Call-Fixup
Installer sets it), so a call to a switch helper decompiles to the
`switch`, and the call itself is overridden `CALL_RETURN` so the table
behind it isn't read as code; resolved computed flows become flow overrides
applied to the p-code as it is emitted (`PCODE_RETURN`, `PCODE_CALL`,
`PCODE_CALL_RETURN`), as Java's `PcodeOverride` applies them, which also
works on conditional instructions `Funcdata::overrideFlow` refuses; ASCII
strings outside code become string data (`s_<text>_<address>`); ARM
functions get stack locals. Data comes from the same data analysis as
for ELF and PE ([data-analysis.md](data-analysis.md): `analysis.data`
from each flow's `data_refs`), which runs on raw images over their
blocks: `undefinedN` where code accesses memory at a constant address,
strings, and pointers at referenced addresses (literal-pool words holding
an address: `PTR_<target>_<address>`; not on ARM, as in Ghidra); data in
a volatile region (MMIO) is volatile. Constants are carried through
big-endian registers too (MIPS, PowerPC, 68k read a register's low part
at a higher offset), and no-return evidence counts a call that falls into
the caller's literal pool as falling into data (SuperH).

### Discovery without seeds or patterns

A raw image can have nothing to start from: a 6502 blob loaded at 0 has
its vectors at 0xfffa-0xffff, outside it; an 8051 or Z80 routine library
loaded where no vector is; a processor Ghidra has no start patterns for
(6502, Z80, 8051). Discovery then found no functions and no instructions:
the only search left, `find_code`, looks at the first few places of each
gap, at even addresses, with rules tuned for 32-bit code.

When seeds and every search above have found nothing at all, discovery
falls back, once, to a code finder of its own. It corresponds to Ghidra's
generic Aggressive Instruction Finder (`AggressiveInstructionFinderAnalyzer`,
a prototype analyzer that is off by default; revkit's ARM `find_code`
follows the ARM one), but runs only as this fallback, and an image where
discovery finds anything gets exactly what it got before:

1. **Routines called from more than one place** (`detail::find_called`):
   every place an instruction can start (the language's instruction
   alignment: every byte on the 6502, Z80 and 8051, every word on AVR) is
   decoded, and direct calls are grouped by target. A target is kept
   where two or more calls to it, not overlapping, each sit in code (not
   in text, fill or bytes as random as compressed data, and their flow on
   from the call decodes as a valid subroutine's does), the bytes around
   them differ (a table of records holding a call opcode repeats them),
   three or more aren't evenly spaced a few bytes apart (records with a
   field that counts), and the target is a valid subroutine (as Ghidra's
   `checkValidSubroutine`) that isn't text, fill or random bytes. Where
   two disagree (one starts inside an instruction of the other's flow),
   the one called more often stays. They are possible functions: the
   candidates the start patterns' "possible" starts are.
2. **Then the usual rounds**, with `find_code` given rules for 8- and
   16-bit code: every byte a possible start on byte-coded processors; a
   piece of one instruction allowed (a lone `rts` a branch reaches); a
   first instruction that stores a byte register is not filler (`sta
   $d020`); a call to where no code is adds nothing (data's `rst 38h`);
   and running into a known function's entry is not code (a table before
   it, decoded: on these processors nearly every byte decodes). What it
   finds is a possible function where calls push the return address
   (code nothing calls is where the program starts), not orphan code.

Precision comes first. Data, text and random bytes give no functions; on
hand-assembled programs (a table, eight routines, a main loop, text) for
the 6502, Z80, 8051 and AVR with no entry point, master found nothing and
the fallback finds exactly the nine functions, none in the table or text,
and all nine decompile (`RawFirmware.BlobsWithoutEntryPoints`,
`RawFirmware.BlobsOfDataTextAndRandomBytesHaveNoCode`). A routine only
one call reaches is found through its caller; one nothing calls (an
interrupt handler whose vector is outside the image) is not, and a
routine that only falls into another (hand-written assembly's shared
tails) is left out rather than risk tables decoded as code.

The synthetic firmware in `src/analysis/tests/fixtures/armfw` (vectors,
a reset handler, ARM and Thumb code, an ARM jump table, a pointer table,
an unreferenced function, MMIO, a read-only 0xffffffff slot) is built at
test time with clang and ld.lld: `Firmware.*` (inputs tests), `RawImport.*`
(backend) and `rk_lift_raw_arm` (CTest) run on it. `RawFirmware.*`
(analysis tests) is a SuperH-4 image written out by hand: a call through a
literal-pool register and a task function only a pointer reaches.

## Scoring on a real firmware

`scripts/bench-firmware.sh [--fetch] [--headless] [name]` scores revkit on a
firmware image against Ghidra, from files kept outside the repository
(`$RK_FW_BENCH`, default `~/revkit-bench`; it skips when they are missing, and isn't part
of CI). `--fetch` reads the user's Ghidra through the ghidra-mcp plugin's
HTTP server, read-only (function list, disassembly, decompiled C);
`--headless` runs Ghidra's default analysis of the same image (PyGhidra, a
throwaway program) for a second function list and for C when the user's
Ghidra can't decompile. Decompiled C is compared on 200 functions both
sides have, stratified by Ghidra's size: `ast` and `alpha` as refdiff has
them, and two structural levels, since Ghidra's C carries the user's names
and types: **shape** (identifiers, casts and declarations abstracted) and
**flow** (the control-flow skeleton).

On a 2 MB ARMv4T camera firmware (Ghidra 12.1.4 with the user's analysis:
4,184 functions):

| | before (master, firmware wrapped in an ELF) | after |
| --- | ---: | ---: |
| functions found | 115 | 4,239 |
| recall of the user's Ghidra functions | 2.7% | **98.0%** |
| precision | 100% | 96.7% |
| recall of Ghidra's default analysis (4,084) | | 98.8% |
| Ghidra's default analysis vs the user's | | recall 95.4%, precision 97.8% |
| instructions both decode (of Ghidra's 203,810 in functions) | | 198,376 (97.3%); revkit only 10,914, Ghidra only 5,434 |
| decompiled C, sample of 200, structurally equal (shape / flow) | 3.0% / 3.5% (8 decompiled) | **80.5% / 87.5%** |
| decompiled C, identical tokens (ast / alpha) | 0% / 0% | 21.5% / 22.5% |
| time (discovery; discovery and all 4,239 functions decompiled, 8 threads) | | 3 s; 13 to 21 s (Ghidra headless, analysis only: 65 s) |

The user's Ghidra could not decompile during the measurement ("Decompilation
did not complete" for every function), so C was compared with Ghidra's
default analysis of the same image and memory map.

Where they still differ (200-function sample): Ghidra's function bodies run
on through tail jumps into code revkit makes a function of (16: revkit
calls `FUN_x` and returns where Ghidra goes on; revkit infers no-return for
`b .` loops Ghidra treats as returning, as in an assert's halt), data types
and struct fields from Ghidra's type propagation and parameter analysis
(13), loops shaped differently after those (3), four functions revkit
doesn't start where Ghidra does (functions only a user's or a pattern's
judgement separates), and three other expression or flow differences. revkit's 139 functions Ghidra doesn't have are mostly
calls from code Ghidra never decoded (switch cases it didn't recover, code
after a call it thinks never returns) and tail-jumped prologues; Ghidra's
84 revkit lacks are mostly user-created functions and starts only Ghidra's
own orphan code reaches.

## A second ARM firmware: Thumb-1 and Thumb-2, compressed data

`scripts/bench-firmware.sh --headless <name>` on a 1.3 MB raw ARMv7 image
(an IoT module's flash: a boot loader and an application, mostly Thumb, a
few ARM routines and veneers, compressed data), against Ghidra 12.1.4's
default analysis of the same image (4,258 functions):

| | before | after |
| --- | ---: | ---: |
| recall of Ghidra's functions | 98.2% | **99.3%** |
| functions | 5,979 | 6,725 |
| precision against Ghidra | 70.0% | 62.9% |
| Ghidra's instructions revkit doesn't decode | 9,599 | **207** |
| decompiled functions halting on bad data (Ghidra: 24) | 149 | **24** |
| C, 200-function sample: ast / alpha / shape / flow | 73.5 / 88.5 / 92.0 / 94.0% | **76.5 / 92.0 / 96.0 / 97.5%** |

Precision against Ghidra falls because revkit decodes about 45% more of the
image than Ghidra does, and finds the functions there. Of the 2,497
functions Ghidra lacks, 2,451 start in bytes Ghidra leaves undecoded,
2,484 start right after an unconditional transfer or undecoded bytes,
2,220 begin with a prologue that saves the return address, and of their
13,840 calls 84.5% land exactly on the entry of a function Ghidra has
(random bytes would almost never hit one): code Ghidra's default analysis
leaves alone (its aggressive instruction finder is off by default), not
data. The other way round, the functions Ghidra has and revkit doesn't
are mostly the targets of far jumps (Ghidra makes each a function; they
return from their caller's frame) and the halves of ARM/Thumb veneers to
code outside the image, which both decompile to `halt_baddata`.

The ARM camera firmware above, against the user's Ghidra: recall 98.2% ->
99.1%, precision 95.5% -> 93.1% (162 new functions, 117 of them prologues
in code master didn't decode; 97% of their calls land on the user's
functions), C 70.0 / 72.5 / 82.5 / 87.5% -> 71.5 / 74.0 / 84.0 / 88.5%,
`halt_baddata` 2 -> 0.

### Stripped ARM ELFs

The same benchmark takes ELF inputs (empty raw arguments: both tools load
the file themselves). On four stripped ARM programs from an embedded
Linux root filesystem (one of them PIE; ARM and Thumb-2):

| program size | Ghidra's functions | recall | precision | Ghidra-only instructions | `halt_baddata` revkit / Ghidra |
| --- | ---: | ---: | ---: | ---: | --- |
| 1.0 MB (ARM, musl, PIE) | 2,132 | 97.2% | 75.5% | 3,428 | 106 / 385 |
| 145 KB (mostly Thumb-2) | 440 | 100% | 83.3% | 10 | 3 / 89 |
| 105 KB (ARM and Thumb-2) | 367 | 98.1% | 91.1% | 963 | 1 / 202 |
| 6 KB | 25 | 100% | 92.6% | 0 | 18 / 19 |

Before this work revkit found 9% of the 105 KB program's functions and 81%
of the 145 KB one's (only what the entry point and exports reach). Most of the
functions revkit has beyond Ghidra's are code Ghidra decodes but makes no
function of (stack-probing prologues: `mov r12, #0x1000; push`), PLT stubs
and code reached only through tables in data. The decompiled C differs
from Ghidra's mostly in types: Ghidra types calls to libc from its data
type archives (`iVar1 = printf(...)`, `0x0` for pointers), which revkit
doesn't yet; control flow agrees on 80 to 98% of the sample.

## Other processors

Only ARM had been measured until the firmware corpus (`corpus/firmware`,
[corpus/README.md](../corpus/README.md#firmware-corpus)): 36 raw images
for twelve processor families, built from source in Docker (pinned image
digest, pinned sources and sha256s, a committed manifest; binaries are
never committed), each a flat image (the ELF's loaded segments at their
load addresses, `objcopy -O binary`'s layout) with its load address and
entry, kept beside its ELF (DWARF) and a truth file (DWARF functions,
symbol-table functions, `DW_AT_noreturn` functions). The first six
families (23 images) are 32-bit processors with one memory space; the
second six (13 images) add the microcontrollers that need
[address spaces and word addressing](processors.md), and RISC-V 32 and
SPARC.

| processor (Ghidra language) | images (raw size) |
| --- | --- |
| MIPS32 BE and LE (`MIPS:BE/LE:32:default`) | U-Boot 2025.01 malta, maltael (294, 296 KB); fwkit -O2 BE (241 KB), -Os LE (204 KB) |
| PowerPC 32 BE (`PowerPC:BE:32:default`) | U-Boot MPC837XERDB (e300, 404 KB), MCR3000 (MPC866, 851 KB); fwkit -O2, -Os (238, 184 KB) |
| SuperH-4 LE (`SuperH4:LE:32:default`) | U-Boot r2dplus (283 KB); fwkit -O2, -Os (177, 157 KB) |
| 68000 family (`68000:BE:32:Coldfire`, `68000:BE:32:default`) | U-Boot M5208EVBE, M5373EVB (ColdFire, 259, 349 KB); fwkit 68020 -O2, -Os (191, 164 KB) |
| ARM Cortex-M, Thumb-2 only (`ARM:LE:32:Cortex`) | U-Boot stm32f429-discovery, stm32f746-disco (148, 333 KB); fwkit Cortex-M3 -O2, Cortex-M4 -Os (140, 122 KB) |
| Xtensa (`Xtensa:LE:32:default`) | fwkit ESP32 (LX6, windowed ABI: `entry`/`callx8`/`retw`) -O2, -Os (156, 140 KB); ESP8266 (L106, CALL0 ABI) -O2, -Os (174, 159 KB) |
| AVR (`avr8:LE:16:default`, compiler `gcc`) | grbl 1.1h for the ATmega328P, -Os (31 KB); mcukit -O2, -Os (10, 5 KB) |
| 8051 (`8051:BE:16:default`) | mcukit, SDCC large model, speed and size (9 KB each) |
| MSP430 and MSP430X (`TI_MSP430:LE:16:default`, `TI_MSP430X:LE:32:default`) | mcukit on the MSP430G2553 -O2, -Os (16 KB each, flash at 0xc000); fwkit on MSP430X, large model, -Os (274 KB) |
| Z80 (`z80:LE:16:default`) | mcukit, SDCC, size (6 KB) |
| RISC-V 32 (`RISCV:LE:32:default`, compiler `gcc`) | fwkit RV32IMAC, machine mode, -O2, -Os (183, 159 KB) |
| SPARC V8 (`sparc:BE:32:default`) | fwkit with a trap table and window traps, -O2, -Os (228, 196 KB) |

fwkit (`corpus/firmware/src/fwkit`) is a small RTOS firmware: FreeRTOS
11.1 (the kernel's own ARM_CM3 port on Cortex-M, a portable C port
elsewhere), lwIP 2.2 (DHCP, DNS, SNTP, MQTT, UDP and TCP services on a
memory-mapped MAC), littlefs 2.10 on a RAM disk, Monocypher 4.0.2,
heatshrink and mpaland/printf, with a shell whose commands are a table of
function pointers, and per-processor startup code (vectors, reset,
interrupt entry). mcukit (`corpus/firmware/src/mcukit`) is a bare-metal
firmware for the processors fwkit doesn't fit: a superloop scheduler, UART
ring buffers, a shell dispatched through a table, a framed protocol state
machine, CRC tables in code memory, PID arithmetic and settings with a
checksum, with a board layer per microcontroller. grbl is the real one: the
CNC controller as it ships for the Arduino Uno. Compilers: Debian trixie's
cross gcc 14.2 (MIPS, PowerPC, SuperH, m68k, arm-none-eabi, xtensa-lx106,
riscv64-unknown-elf, sparc64 with its 32-bit libgcc), Espressif's
crosstool-NG esp-14.2.0 for the ESP32, avr-gcc 14.2 with avr-libc, TI's
msp430-gcc 9.3.1.11 (a pinned download) and SDCC 4.5.0, whose truth comes
from its `.cdb` debug records and the map file.

**Method.** `tools/ghidra-export/ghidra_export.py --firmware-corpus`
imports each image with Ghidra's Raw Binary loader at its load address,
adds the same RAM and MMIO regions (uninitialized; MMIO volatile; in the
space the manifest names, as the 8051's external RAM in `EXTMEM`) and the
entry point, runs Ghidra's default auto-analysis and exports the
reference (functions, instructions, decompiled C) to `out/firmware-ref`.
`scripts/firmware_score.py` runs `rk-lift --raw --lang --base --raw-entry
--region ... --analyze --decompile` (decompiler workers) with the same
layout and compares, pooled per processor: recall and precision of
Ghidra's function entries; recall of the DWARF functions for each tool,
and the share of each tool's functions that DWARF or the symbol table has
(truth precision); instructions both decode, revkit only, Ghidra only;
and decompiled C on every function both have and both decompile:
identical tokens (`ast`), with locals renamed (`alpha`), and the
structural `shape` and `flow` of the ARM benchmark. `shape*` also counts
as the same a function whose C differs because the two disagree about a
callee returning, where DWARF (`DW_AT_noreturn`) says revkit is right:
Ghidra's evidence-based no-return analysis misses `fw_panic` and
`fw_assert_failed` on Xtensa, for instance, and keeps decoding past them.

```sh
scripts/build-firmware-corpus.sh                    # -> out/firmware-corpus, checks the manifest
py=$(scripts/setup-pyghidra.sh)
$py tools/ghidra-export/ghidra_export.py --firmware-corpus out/firmware-corpus --out out/firmware-ref -j 6 --heap 4g
scripts/ci.sh --firmware-only                       # or --firmware after the other gates
```

### The first six families

Results (23 images; before: master at fe4f8ad, after: this branch merged
with master's data analysis, decompiler workers):

| processor | Ghidra's functions | recall vs Ghidra | precision vs Ghidra | DWARF recall (Ghidra's) | truth precision (Ghidra's) | instructions both / revkit only / Ghidra only | C ast / alpha | C shape | shape* | flow |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| Cortex-M | 2,749 | 95.2 -> **98.1%** | 91.6 -> 85.9% | 74.6 -> **81.4%** (71.8%) | 99.2% (99.9%) | 149,788 / 20,980 / 1,792 | 38.5 -> **72.2** / 89.9% | 95.5 -> 95.5% | 97.8% | 97.4 -> 97.6% |
| 68000/ColdFire | 1,733 | 91.2 -> **96.7%** | 97.7 -> 95.1% | 46.5 -> **50.9%** (49.1%) | 94.5% (92.7%) | 126,349 / 3,552 / 2,227 | 54.2 -> **69.7** / 85.6% | 81.7 -> **90.9%** | 94.7% | 93.9 -> 95.4% |
| MIPS | 2,943 | 93.3 -> **96.4%** | 99.2 -> 98.7% | 77.9 -> **81.1%** (82.9%) | 97.2% (96.9%) | 181,948 / 1,340 / 1,402 | 43.8 -> **61.2** / 75.6% | 78.1 -> **84.9%** | 91.0% | 92.1 -> 93.4% |
| PowerPC | 4,090 | 98.3 -> **98.9%** | 96.0 -> 96.0% | 89.3 -> **89.9%** (90.3%) | 94.6% (97.9%) | 248,792 / 793 / 3,009 | 53.0 -> **65.7** / 81.6% | 88.9 -> **92.9%** | 94.5% | 96.1 -> 96.8% |
| SuperH-4 | 1,894 | 0.6 -> **92.0%** | 100 -> 89.5% | 0.3 -> **75.4%** (73.2%) | 99.5% (99.5%) | 157,598 / 15,593 / 10,998 | 36.9 / 48.9% | 64.4% | 64.4% | 99.6% |
| Xtensa | 2,491 | 98.6 -> **99.9%** | 99.3 -> 97.0% | 94.6 -> **98.0%** (95.3%) | 99.5% (99.6%) | 189,980 / 7,735 / 361 | 29.5 -> **62.9** / 72.0% | 65.6 -> **82.4%** | 99.6% | 86.9 -> 92.6% |

(Before, SuperH found 11 functions: every call there goes through a
register loaded from a literal pool, which only ARM resolved; its C
numbers then covered those 11: 54.5% ast, 81.8% shape.) Precision against Ghidra drops where
revkit now finds functions Ghidra doesn't: the DWARF recall and truth
precision columns show they are real (Cortex-M U-Boot: 79% of the DWARF
functions against Ghidra's 67%).

What changed, all generic: computed calls and jumps resolved on raw images
for every processor (SuperH, and the MIPS, PowerPC and Xtensa calls
through registers); pointers to code from literal pools checked as Ghidra
checks a subroutine (SuperH's task functions and callbacks); called code
the code finder had found promoted to functions (SuperH U-Boot); an
undecodable call target no longer found again every round (U-Boot on
MPC8xx ran out of rounds and threw); and the decompiler given the data
Ghidra's analysis would have typed (pointer pools, accessed data, volatile
MMIO; now master's data analysis, extended to raw images and big-endian
registers). The ARM camera firmware stays at 98.2% recall of the user's
Ghidra functions; precision 95.5% (was 96.7%: the new functions are code
only pointers reach); decompiled C of the 200-function sample: 70.0%
identical tokens (was 21.5%), 82.5% shape (was 80.5%), 87.5% flow.

Since then (branch phase7/decomp-quality), three changes moved the C
further, two of them deliberately away from Ghidra's: addresses kept in
callee-saved registers across calls type the accesses after them
(PowerPC 65.7 -> 71.0%, MIPS 61.2 -> 62.3% identical to Ghidra), and then
strings and literal-pool constants became constants (above). Identity with
Ghidra's C is now (`c_ast` / `c_alpha` / `c_shape` / `c_flow`):

| processor | before | after |
| --- | --- | --- |
| Cortex-M | 72.2 / 89.9 / 95.5 / 97.6% | 52.0 / 61.9 / 64.2 / 92.6% |
| 68000/ColdFire | 69.7 / 85.6 / 90.9 / 95.4% | 55.8 / 69.9 / 73.3 / 95.4% |
| MIPS | 61.2 / 75.6 / 84.9 / 93.4% | 47.9 / 58.1 / 63.0 / 93.4% |
| PowerPC | 65.7 / 81.6 / 92.9 / 96.8% | 65.1 / 83.1 / 86.8 / 96.8% |
| SuperH-4 | 36.9 / 48.9 / 64.4 / 99.6% | 17.7 / 18.0 / 18.9 / 81.8% |
| Xtensa | 62.9 / 72.0 / 82.4 / 92.6% | 43.1 / 47.6 / 50.3 / 91.2% |

and against the original source revkit's C now wins on every processor,
per function and per metric ([decomp-quality.md](decomp-quality.md)):
the composite (functions where revkit wins more metrics than it loses
against the reverse) is 709/1906/67 on Cortex-M, 296/723/19 on 68000,
303/2219/218 on MIPS, 402/3483/55 on PowerPC, 1216/422/72 on SuperH and
862/1534/83 on Xtensa (W/T/L; master: 215/2437/30, 89/926/23,
189/2291/260, 195/3345/400, 167/1268/275, 473/1880/126). Function
discovery and the listing are unchanged (the table above). On the user's
camera firmware the C has 3,221 string literals (1 before) and no
decompiler failures.

Where they still differ:

- **SuperH C** (64% shape): Ghidra passes arguments to calls through
  literal-pool registers that revkit's decompiler leaves without, and it
  shows some of those calls direct and others indirect in a way the code
  alone doesn't explain. It isn't Ghidra's Decompiler Parameter ID: that
  analyzer is off by default except on small PEs, and every function of
  Ghidra's firmware databases has the default prototype (`undefined
  FUN_x()`); forcing revkit's reproduction of it on (`rk-lift --param-id
  on`) takes C `ast` from 72/70/61/66/37/63% (Cortex-M, 68000, MIPS,
  PowerPC, SuperH, Xtensa) down to 22/38/22/20/33/26%, every committed
  signature differing from Ghidra's unlocked ones ([param-id.md](param-id.md)).
  On SuperH fwkit -O2, 6 indirect calls differ in having arguments at all
  (a constant function pointer passed in r4 that revkit's decompiler doesn't
  take as an argument), and 4 functions in how the slot they call through is
  typed (`(*DAT_x)()` against `(*(code *)PTR_FUN_x)()`): data, not
  signatures. SuperH U-Boot
  (position-independent, `bsrf` calls) still lacks 15% of Ghidra's
  functions, reached from code revkit hasn't decoded.
- **Xtensa and MIPS C**: most differences are callees that never return
  (`fw_panic`, `fw_assert_failed`, `board_reset`), which DWARF confirms
  but Ghidra's evidence-based analysis misses on these images, and
  revkit, now telling the decompiler what Ghidra's evidence says, finds
  differently (`shape*`); then return values Ghidra's decompiler reads
  where revkit's doesn't (`x = f()` where revkit's callee returns nothing
  known; not committed signatures, which Ghidra's firmware databases don't
  have) and stack locals' names on MIPS (`local_res8` against
  `uStackX_8`).
- **PowerPC**: Ghidra's function-start patterns make gcc's shrink-wrapped
  prologues (a `stwu r1` after an early exit) into functions, and so does
  revkit's pattern search: 3% of revkit's functions there are such
  fragments (truth precision 94.6% against Ghidra's 97.9%).
- **68000**: both tools find only about half of the DWARF functions:
  neither reaches most of ColdFire U-Boot (26% of its DWARF functions),
  whose code is entered through tables of function pointers in data
  (U-Boot's init sequences, driver and command lists), which neither
  follows.

### The second six families

Results (13 images: AVR, 8051, MSP430 and MSP430X, Z80, RISC-V 32, SPARC;
there is no "before": AVR and the 8051 could not be loaded at all until
programs had [address spaces](processors.md)):

| processor | Ghidra's functions | revkit's | recall vs Ghidra | precision vs Ghidra | DWARF recall (Ghidra's) | truth precision (Ghidra's) | instructions both / revkit only / Ghidra only | C ast / alpha | C shape | shape* | flow |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| AVR | 281 | 256 | 83.3% | 91.4% | 68.1% (79.2%) | 75.4% (79.4%) | 8,123 / 479 / 7,215 | 64.4% / 64.4% | 76.4% | 76.4% | 82.8% |
| 8051 | 46 | 44 | 91.3% | 95.5% | 29.1% (29.1%) | 81.8% (78.3%) | 1,688 / 46 / 0 | 61.9% / 61.9% | 90.5% | 90.5% | 90.5% |
| MSP430 / MSP430X | 323 | 565 | 99.1% | 56.6% | **68.9%** (38.7%) | 97.7% (96.0%) | 63,032 / 17,036 / 271 | 75.0% / 76.2% | 91.6% | 91.6% | 99.1% |
| Z80 | 32 | 33 | 84.4% | 81.8% | 38.9% (33.3%) | 78.8% (65.6%) | 435 / 90 / 28 | 48.1% / 48.1% | 70.4% | 70.4% | 100.0% |
| RISC-V 32 | 1,134 | 1,145 | 99.1% | 98.2% | 86.7% (85.9%) | 98.1% (98.1%) | 94,685 / 961 / 1,177 | 69.8% / 70.0% | 74.8% | 90.5% | 90.3% |
| SPARC V8 | 1,205 | 1,191 | 98.3% | 99.5% | 91.2% (92.4%) | 99.6% (99.7%) | 88,554 / 175 / 311 | 66.1% / 76.5% | 89.8% | 89.9% | 98.9% |

The columns are the first table's; "truth" for SDCC's images (8051, Z80)
is its `.cdb` debug records and map file in place of DWARF. The mcukit
images are small (20 to 45 functions each), so one function there is two
to five points; grbl, the fwkit images and the pooled rows are the ones to
read. `corpus/baselines/firmware-<arch>.json` holds each row, and
`scripts/ci.sh --firmware` fails when a rate drops.

What it took, beyond loading them: AVR's `Z` put together from `R30` and
`R31` (avr-gcc's switch tables), SPARC's `call` with a `restore` in its
delay slot as a tail call (recall of Ghidra's functions 64% to 98%),
MSP430X images without ELF headers below the flash, integer types named by
the compiler spec's sizes (a 2-byte integer is `int` where `int` has two
bytes: MSP430 C `ast` 6% to 75%, AVR 43% to 55%), and the processor spec's
labels as names for the decompiler (`PCON`, `SREG`, the 8051's register
banks: 8051 `ast` 29% to 62%, AVR 55% to 64%).

Where they differ:

- **AVR** is the weakest: revkit's functions hold 53% of the instructions
  Ghidra's do, and it finds 83% of Ghidra's functions (grbl: 48% and
  79.5%). Discovery does not follow the context a skip instruction
  (`cpse`, `sbrc`, `sbrs`, `sbic`, `sbis`) sets for the next one, so the
  code after a skipped `rjmp`, `jmp` or `ret` is lost unless something
  else reaches it: 137 places in grbl
  ([known-issues.md](known-issues.md#discovery-loses-the-code-after-a-skipped-jump-on-avr)).
  The functions that are found decompile like Ghidra's (shape 76%).
- **MSP430X**: revkit finds 513 functions on fwkit where Ghidra finds 286,
  and all 228 of the extra ones are in the DWARF (truth precision 97.7%):
  67 that no call or jump names (task entries and callbacks, found through
  the constants and pointers that hold their addresses) and 161 that
  those call. Ghidra's default analysis of this image decodes none of
  them. That is what precision against Ghidra (56.6%) measures here. 190
  DWARF functions are found by neither.
- **8051 and Z80**: both tools find about a third of SDCC's functions, and
  nearly the same third: mcukit's tasks, shell commands and protocol
  handlers are called through tables of 16-bit code addresses in code
  memory, which neither follows on these processors. On the 8051 revkit
  keeps `main` in the startup code that jumps to it, where Ghidra makes it
  a function behind a thunk; on the Z80 Ghidra has functions at five
  restart and NMI vectors (0x20 to 0x38, 0x66) that revkit does not, and
  revkit finds five of SDCC's functions that Ghidra does not.
- **RISC-V 32**: the differences in C are callees that never return
  (`fw_panic`, `fw_assert_failed`), as on Xtensa and MIPS: 74.8% shape,
  90.5% counting those where DWARF says revkit is right. Names carry the
  space (`FUN_ram_20000000`) in both tools, since the language has a
  second space for control registers.
- **SPARC**: function sets agree to 98 to 99% both ways; C differs mostly
  in the names of locals (66.1% identical tokens, 76.5% with locals
  renamed).

## Known gaps

- The search is for raw images and stripped ARM ELFs; on other ELF and PE
  programs it is off.
- The fallback for images with nothing to start from runs only when
  discovery finds nothing at all: an image whose vectors or entry reach a
  little code and leave the rest unreached gets no help from it.
- A shrink-wrapped prologue after more than 16 bytes of early exits
  (delay slots aside) isn't recognised: the function stays orphan code
  unless something calls it. Exits that return in line (`bnez a0, 1f;
  nop; jr ra; li v0, 0; 1: addiu sp, ...`) aren't guards either: the start
  pattern after the return makes the prologue a function of its own.
- A switch whose guarded path reaches its jump more than eight
  instructions before it (the probe walks the joining path's straight run
  that far) keeps the first path's single target.
- On AVR, discovery loses the code after a skipped jump (above), and on
  Harvard microcontrollers function pointers in code memory are not
  followed ([processors.md](processors.md#known-gaps)).
- Thumb functions get no stack locals (they'd need a Thumb engine there).
- Strings are ASCII only (no UTF-16) and found by a simple rule (five
  printable characters, mostly alphanumeric, NUL-terminated), not Ghidra's
  n-gram model.
- Prototype inference (`src/infer`) has no 32-bit convention, so callees'
  parameter counts come from the decompiler alone: tried as tables, it
  typed too many integers as pointers (an int and a pointer are the same
  size), and a raw ARM image mixing ARM and Thumb would also need
  discovery's Thumb ranges in the inference decompiler
  ([decomp-quality.md](decomp-quality.md#what-was-tried-and-left-out)).
