# Processors

revkit takes its processors from Ghidra's SLEIGH: every language of the
install (`ListLanguages`, `rk-sweep --list`) loads, lifts to p-code, and
goes through discovery, the decompiler and the emulator. This page says how
processors with several memory spaces or word-addressed code are modelled,
how microcontroller firmware is loaded, what is measured on which
processor, and what the sweep over every language shows. How well revkit
analyses firmware, against Ghidra and DWARF, is in
[firmware.md](firmware.md#other-processors).

## Address spaces and word addressing

Most processors have one memory space, addressed in bytes. Three things
differ on small microcontrollers, and Ghidra's languages model all three:

- **Several memory spaces** (Harvard machines). AVR has `code` (flash) and
  `mem` (the register file, I/O and SRAM); the 8051 has `CODE`, `INTMEM`,
  `SFR` and `EXTMEM`; PIC has `CODE` and `DATA`. The same number is a
  different place in each.
- **Word-addressed code.** AVR's and PIC's code spaces count 2-byte words:
  Ghidra shows `code:003a` for the instruction at byte 0x74.
- **Registers in memory.** AVR's `R0`-`R31` are the first 32 bytes of `mem`.

revkit keeps every address as one 64-bit **key** (`src/loader`,
`image.hh`). In the language's default space, where code is, the key is the
byte offset. A block in another memory space is keyed at that space's base
plus its byte offset; the base is the space's SLEIGH index shifted left by
40 bits, so a language's keys are the same however an image was loaded,
and no key of one space is another's on processors whose spaces are at most
40 bits wide. (Images of 64-bit languages keep a single space.) A
word-addressed space is keyed by byte offset too, as SLEIGH's addresses
and Ghidra's `Address.getOffset()` are; only names and display count
words.

| | AVR example | key |
| --- | --- | --- |
| code, word address `code:003a` | flash byte 0x74 | `0x74` |
| data, `mem:0100` (first SRAM byte) | `mem` is SLEIGH space 3 | `0x30000000100` |
| register `R24` | `mem:0018` | a register to the analysis, not memory |

What follows from the model:

- **Loaders** lay out the language's spaces and the blocks its processor
  spec creates in every program (`<default_memory_blocks>`: AVR's
  `regalias`, `iospace` and `mem`; the 8051's register banks, `INTMEM` and
  `SFR`), and put the spec's labels on mapped memory as weak data symbols
  (`PORTB`, `SP`: Ghidra's "Apply Processor Defined Labels"), which name
  that memory in the listing and in decompiled C.
  `lift::initialize` installs the provider that reads them from the
  install, so every tool and the daemon get the same layout.
- **The lifter** serves any keyed space to SLEIGH and to the decompiler;
  registers report their space.
- **Analysis** reads p-code in other spaces at its keys, treats registers
  mapped into memory as registers, and counts `LOAD`/`STORE` pointers and
  computed targets in their space's units (AVR's `icall` jumps to the word
  address in `Z`).
- **Names** are Ghidra's: `FUN_code_003a`, `DAT_mem_0100`, with the
  space's name and its offset in the space's units, padded to its size.
  A language with a second space that images don't use still qualifies
  names (RISC-V's `csreg`: `FUN_ram_20000000`).
- **The API** (`api_minor` 26, feature `address-spaces`) lists the spaces
  in `ProgramSummary.spaces` with each one's `key_base` and `word_size`;
  addresses in responses are keys, and requests may name a space instead
  ([api.md](api.md#queries)). **The UI** shows `code:003a` and `mem:0100`,
  takes them in Go To and the URL, and has a space switch
  ([ui.md](ui.md#address-spaces-harvard-and-word-addressed-processors)).

## Loading microcontroller firmware

```sh
# Intel HEX or Motorola S-records, told apart by content: a block per run of records
build/tools/rk-lift/rk-lift --raw --lang avr8:LE:16:default:gcc --analyze --decompile -o out.json firmware.hex
# A flat 8051 image with external RAM and memory-mapped I/O in EXTMEM
build/tools/rk-lift/rk-lift --raw --lang 8051:BE:16:default --analyze \
    --region xram:0:ff00:rw-:space=EXTMEM --region xio:ff00:100:rw-:volatile:space=EXTMEM -o out.json fw.bin
# A data dump loaded in another space
build/tools/rk-lift/rk-lift --raw --lang 8051:BE:16:default --raw-space EXTMEM -o out.json xdata.bin
# An AVR ELF (avr-gcc): language from the header, SRAM moved from 0x800000 into mem
build/tools/rk-lift/rk-lift --analyze -o out.json firmware.elf
```

| What | Flag (`rk-lift`, `rk-decomp`) | `ImportOptions` |
| --- | --- | --- |
| The file is Intel HEX, S-records or binary (default: by content) | `--raw-format ihex\|srec\|binary\|detect` | `raw_format` |
| The space the image goes in (default: the code space) | `--raw-space NAME` | `raw_space` |
| A region in another space | `--region name:start:size[:perms][:init\|uninit\|volatile]:space=NAME` | `MemoryRegion.space` |

`--base`, `--raw-entry` and region starts are byte offsets in their space
(a word address times the word size). A HEX or S-record file gives its own
addresses, and its start address as the entry unless one is given. The
other raw options are in [firmware.md](firmware.md#loading-a-raw-image).
ELF files get their language from the header as Ghidra's `.opinion` files
map it (AVR, MSP430, SPARC, 68k, SuperH, Xtensa, PA-RISC, TriCore, V850,
Hexagon, LoongArch besides the earlier ones).

The processor's entry points (the reset and interrupt vectors its spec
names) start discovery, as on every raw image; `Discovery` in
[firmware.md](firmware.md#discovery) has the rest. Two things were added
for these processors: a register read whole after it was written in pieces
is put together from the pieces (AVR's `Z` after `R30` and `R31`: avr-gcc's
switch tables through `__tablejump2__`), and an instruction that calls and
then returns under a condition its own p-code settles is a call or a tail
call (SPARC's `call` with a `restore` in the delay slot).

## What is measured where

| Level | Processors | How |
| --- | --- | --- |
| Scored against Ghidra and DWARF, gated in CI | ARM (v4T, Cortex-M), MIPS, PowerPC, SuperH-4, 68000/ColdFire, Xtensa, AVR, 8051, MSP430 and MSP430X, Z80, RISC-V 32, SPARC | the firmware corpus, `scripts/ci.sh --firmware` ([firmware.md](firmware.md#other-processors)) |
| Scored against Ghidra, gated in CI | x86, x86-64, AArch64, RISC-V 64 (ELF and PE programs) | the tuning and held-out corpora, `scripts/ci.sh` ([decomp-parity.md](decomp-parity.md), [heldout.md](heldout.md)) |
| Discovery and decompilation checked against debug records | AVR, 8051, MSP430, Z80 | CTest `mcu_fixtures` (`scripts/mcu_fixtures_test.py`: at least a set number of functions and a set share of the DWARF or SDCC functions found on the corpus's mcukit images; skipped without the corpus or its Docker image) |
| Smoke-tested end to end | every language of the install | the sweep below; CTest `processor_sweep_sampled` runs 16 of them |

## The sweep

`scripts/processor_sweep.py` runs `tools/rk-sweep` on every language, each
in a child process with a timeout (120 s unless `--timeout` says
otherwise), so a crash or a hang is one language's result and not the end
of the sweep:

```sh
scripts/processor_sweep.py -j 8 --write-doc docs/processors.md   # every language; rewrites the table below
scripts/processor_sweep.py --only 'avr8:*' --json out.json       # some of them
build/tools/rk-sweep/rk-sweep --lang PIC-16:LE:16:PIC-16F         # one, a JSON line per stage
```

- **loads**: the raw loader lays the image out with the language's memory
  spaces and processor-spec blocks.
- **lifts**: SLEIGH decodes it linearly; the figure is the share of the
  bytes in decoded instructions.
- **discovers**: discovery runs from the first instruction that decodes;
  the figure is the functions found.
- **decompiles**: the decompiler decompiles that function.
- **emulates**: the p-code emulator runs up to 16 steps from it; the figure
  is the steps run.

The image is the first 64 KB of a firmware-corpus image where the corpus
has one for the language (the **sample** column), else 4 KB of random bytes
seeded by the language id. On random bytes most of what decodes is noise,
so these columns say that the pipeline works on the language, not how
well: "no" is an error the tool reported, with the reason under notes, and
an emulator that stops before 16 steps has usually run into unmapped
memory or bytes that don't decode. Deprecated languages are marked *dep*.

The sweep takes about ten seconds with 8 jobs. On 189 languages nothing
crashes or hangs, and every language loads and lifts. What it reports as
"no":

- **Discovery, 2**: `DATA:BE:64:default` and `DATA:LE:64:default` have no
  instructions, so nothing decodes and the later stages don't run.
- **Decompilation, 16**: those two, the thirteen Dalvik languages and
  `JVM:BE:32:default`, whose p-code needs injections that Ghidra's Java
  side computes ("Missing dynamic inject"); revkit has no counterpart.
- **Emulation, 6**: those two, and the four TriCore languages, whose
  register space is larger than the emulator's register file allows.

What the first full sweeps found, all fixed:

- **A crash in SLEIGH on ten languages** (six ARM v7 and v8 variants,
  `JVM:BE:32:default`, `NDS32:LE/BE:32:default`, `V850:LE:32:v850e3v5`):
  an instruction whose tree of constructors is larger than the fixed pool
  the parser builds it in (a long `VLDM` register list in random bytes)
  wrote past the pool. Patch 0005 of the fork makes it a decode failure
  ([UPSTREAM.md](../third_party/ghidra/UPSTREAM.md)).
- **ARM v4 and v5** have the `TB` register but no `TMode` context variable
  (no Thumb): describing the program painted a context that wasn't there.
- **V850's compiler spec** names a register in another case than the
  language defines it (`ctbp`, `CTBP`); Java's register map holds each
  name in lower and upper case too, and now so does revkit's.
- **Language ids with a space** (`x86:LE:16:Real Mode`) broke the list the
  sweep script reads.
- **RISC-V discovery took minutes**: a far tail call (`auipc t1` /
  `jr lo(t1)`) is a computed jump, and jump-table recovery probed it with
  1024 values of every register and stack slot the code before it read,
  from every split point, only to find one destination each time. A jump
  whose outcome is settled with the candidate unknown is now rejected
  after one run: 141 s to 1.6 s on the corpus's 190 KB RV32 image, with
  the same functions and instructions on every corpus image.

<!-- sweep:begin (generated by scripts/processor_sweep.py --write-doc; edit the script, not this section) -->

Totals (189 languages, 15 on a firmware-corpus sample):

| stage | yes | no | CRASH | HANG |
| --- | ---: | ---: | ---: | ---: |
| load | 189 | 0 | 0 | 0 |
| lift | 189 | 0 | 0 | 0 |
| discover | 187 | 2 | 0 | 0 |
| decompile | 173 | 16 | 0 | 0 |
| emulate | 183 | 6 | 0 | 0 |

| language | processor | loads | lifts | discovers | decompiles | emulates | sample | notes |
| --- | --- | --- | ---: | ---: | --- | ---: | --- | --- |
| `6502:LE:16:default` | 6502 | yes | 76% | 1 | yes | 1 | random | emulator stops: unmapped (fetch from unmapped memory at 0x7fef) |
| `65C02:LE:16:default` | 65C02 | yes | 90% | 1 | yes | 1 | random | emulator stops: unmapped (read of 1 bytes at 0xbcda (unmapped)) |
| `68000:BE:32:Coldfire` | 68000 | yes | 100% | 101 | yes | 10 | m68k/uboot-M5208EVBE | emulator stops: unmapped (write of 4 bytes at 0x80003ff8 (unmapped)) |
| `68000:BE:32:CPU32` | 68000 | yes | 79% | 1 | yes | no | random | emulator stops: unmapped (read of 2 bytes at 0xffffa059 (unmapped)) |
| `68000:BE:32:default` | 68000 | yes | 100% | 305 | yes | 2 | m68k/fwkit-m68k-O2 | emulator stops: unmapped (write of 4 bytes at 0x8ffffc (unmapped)) |
| `68000:BE:32:MC68020` | 68000 | yes | 82% | 1 | yes | no | random | emulator stops: divide_by_zero (division by zero) |
| `68000:BE:32:MC68030` | 68000 | yes | 81% | 1 | yes | 1 | random | emulator stops: unmapped (read of 1 bytes at 0xffffffff (unmapped)) |
| `6805:BE:16:default` | 6805 | yes | 89% | 1 | yes | 3 | random | emulator stops: unmapped (read of 1 bytes at 0x16f9 (unmapped)) |
| `6809:BE:16:default` | 6809 | yes | 92% | 1 | yes | 3 | random | emulator stops: decode (no instruction decodes at 0x7) |
| `80251:BE:24:default` | 80251 | yes | 100% | 1 | yes | 5 | random | spaces RAM SFR BITS; emulator stops: unmapped (fetch from unmapped memory at 0xff0000) |
| `80390:BE:24:default` | 80390 | yes | 100% | 1 | yes | 1 | random | spaces CODE INTMEM EXTMEM SFR BITS; emulator stops: unmapped (fetch from unmapped memory at 0x13875) |
| `8048:LE:16:default` | 8048 | yes | 92% | 2 | yes | 5 | random | spaces CODE INTMEM EXTMEM PORT; emulator stops: decode (no instruction decodes at 0x7) |
| `8051:BE:16:default` | 8051 | yes | 100% | 22 | yes | 16 | mcs51/mcukit-8051-O2 | spaces RAM CODE INTMEM EXTMEM SFR BITS |
| `8051:BE:24:cip-51` | 8051 | yes | 100% | 39 | yes | 16 | random | spaces RAM CODE INTMEM EXTMEM SFR BITS IFLASH XRAM |
| `8051:BE:24:mx51` | 8051 | yes | 100% | 56 | yes | 16 | random | spaces RAM SFR ESFR BITS EBITS |
| `8085:LE:16:default` | 8085 | yes | 97% | 1 | yes | 14 | random | spaces ram io; emulator stops: unmapped (read of 1 bytes at 0xecd3 (unmapped)) |
| `AARCH64:BE:32:ilp32` | AARCH64 | yes | 40% | 1 | yes | 1 | random | emulator stops: decode (no instruction decodes at 0x8) |
| `AARCH64:BE:64:v8A` | AARCH64 | yes | 36% | 1 | yes | no | random | emulator stops: unmapped (write of 8 bytes at 0xfffffffffffffe48 (unmapped)) |
| `AARCH64:LE:32:ilp32` | AARCH64 | yes | 36% | 1 | yes | 1 | random | emulator stops: unmapped (fetch from unmapped memory at 0x83bf78) |
| `AARCH64:LE:64:AppleSilicon` | AARCH64 | yes | 34% | 1 | yes | 2 | random | emulator stops: decode (no instruction decodes at 0x8) |
| `AARCH64:LE:64:v8A` | AARCH64 | yes | 36% | 1 | yes | no | random | emulator stops: unmapped (read of 4 bytes at 0xfffffffffff8e388 (unmapped)) |
| `ARM:BE:32:Cortex` | ARM | yes | 96% | 18 | yes | no | random | emulator stops: unmapped (write of 4 bytes at 0xfffffffc (unmapped)) |
| `ARM:BE:32:v4` | ARM | yes | 87% | 5 | yes | 6 | random | emulator stops: decode (no instruction decodes at 0x1c) |
| `ARM:BE:32:v4t` | ARM | yes | 87% | 5 | yes | 6 | random | emulator stops: decode (no instruction decodes at 0x18) |
| `ARM:BE:32:v5` | ARM | yes | 89% | 6 | yes | 1 | random | emulator stops: unmapped (fetch from unmapped memory at 0xe07760) |
| `ARM:BE:32:v5t` | ARM | yes | 88% | 6 | yes | 5 | random | emulator stops: decode (no instruction decodes at 0x18) |
| `ARM:BE:32:v6` | ARM | yes | 89% | 8 | yes | 6 | random | emulator stops: userop (CALLOTHER coprocessor_loadlong has no handler (ldcl p2,cr14,) |
| `ARM:BE:32:v7` | ARM | yes | 90% | 5 | yes | 1 | random | emulator stops: decode (no instruction decodes at 0x4) |
| `ARM:BE:32:v8` | ARM | yes | 89% | 8 | yes | 3 | random | emulator stops: unmapped (read of 4 bytes at 0xfffffffc (unmapped)) |
| `ARM:BE:32:v8-m` | ARM | yes | 95% | 17 | yes | 3 | random | emulator stops: unmapped (read of 1 bytes at 0xef663d46 (unmapped)) |
| `ARM:BE:32:v8T` | ARM | yes | 95% | 6 | yes | 4 | random | emulator stops: decode (no instruction decodes at 0x8) |
| `ARM:LE:32:Cortex` | ARM | yes | 100% | 410 | yes | no | cortexm/fwkit-cortexm3-O2 | emulator stops: unmapped (write of 4 bytes at 0xfffffffc (unmapped)) |
| `ARM:LE:32:v4` | ARM | yes | 86% | 5 | yes | 1 | random | emulator stops: userop (CALLOTHER coprocessor_loadlong has no handler (ldclgt p10,cr) |
| `ARM:LE:32:v4t` | ARM | yes | 86% | 6 | yes | 1 | random | emulator stops: decode (no instruction decodes at 0x6) |
| `ARM:LE:32:v5` | ARM | yes | 86% | 6 | yes | no | random | emulator stops: userop (CALLOTHER coprocessor_loadlong has no handler (ldclvc p9,cr3) |
| `ARM:LE:32:v5t` | ARM | yes | 89% | 5 | yes | 1 | random | emulator stops: decode (no instruction decodes at 0x4) |
| `ARM:LE:32:v6` | ARM | yes | 89% | 7 | yes | 3 | random | emulator stops: decode (no instruction decodes at 0xc) |
| `ARM:LE:32:v7` | ARM | yes | 91% | 7 | yes | 1 | random | emulator stops: decode (no instruction decodes at 0x6) |
| `ARM:LE:32:v8` | ARM | yes | 90% | 7 | yes | no | random | emulator stops: userop (CALLOTHER software_interrupt has no handler (swipl 0x216bf7)) |
| `ARM:LE:32:v8-m` | ARM | yes | 94% | 15 | yes | 1 | random | emulator stops: unmapped (fetch from unmapped memory at 0xfffffe14) |
| `ARM:LE:32:v8T` | ARM | yes | 96% | 8 | yes | 9 | random | emulator stops: unmapped (write of 4 bytes at 0xfffffffc (unmapped)) |
| `ARM:LEBE:32:v7LEInstruction` | ARM | yes | 90% | 8 | yes | 1 | random | emulator stops: unmapped (fetch from unmapped memory at 0x314c0d80) |
| `ARM:LEBE:32:v8LEInstruction` | ARM | yes | 90% | 7 | yes | 1 | random | emulator stops: unmapped (fetch from unmapped memory at 0x13e04f0) |
| `avr32:BE:32:default` | AVR32 | yes | 93% | 1 | yes | 7 | random | emulator stops: unmapped (read of 1 bytes at 0xffffffff (unmapped)) |
| `avr8:LE:16:atmega256` | AVR8 | yes | 98% | 67 | yes | 2 | random | spaces code/2 mem codebyte; emulator stops: unmapped (fetch from unmapped memory at 0xfff122) |
| `avr8:LE:16:default` | AVR8 | yes | 100% | 170 | yes | 16 | avr/grbl-atmega328p-Os | spaces code/2 mem codebyte |
| `avr8:LE:16:extended` *dep* | AVR8 | yes | 98% | 20 | yes | 7 | random | spaces code/2 mem codebyte; emulator stops: unmapped (fetch from unmapped memory at 0xfff62e) |
| `avr8:LE:24:xmega` | AVR8 | yes | 98% | 147 | yes | 16 | random | spaces code/2 mem codebyte |
| `BPF:LE:32:default` | BPF | yes | 94% | 1 | yes | 5 | random | spaces ram packet mem; emulator stops: decode (no instruction decodes at 0xf8) |
| `CP1600:BE:16:default` | CP1600 | yes | 100% | 1 | yes | 2 | random | spaces ram/2; emulator stops: unmapped (write of 2 bytes at 0x7646 (unmapped)) |
| `CR16C:LE:16:default` | CR16C | yes | 100% | 1 | yes | no | random | emulator stops: unmapped (read of 1 bytes at 0x7c061 (unmapped)) |
| `Dalvik:LE:32:default` *dep* | Dalvik | yes | 95% | 1 | no | no | random | decompile: Missing dynamic inject; emulator stops: unimplemented (p-code op CPOOLREF (iput_char v5,[v2:0x8b89])) |
| `Dalvik:LE:32:DEX_Android10` | Dalvik | yes | 99% | 1 | no | no | random | decompile: Missing dynamic inject; emulator stops: unimplemented (p-code op CPOOLREF (iput_boolean v11,[v13:0x2ce])) |
| `Dalvik:LE:32:DEX_Android11` | Dalvik | yes | 99% | 1 | no | 2 | random | decompile: Missing dynamic inject; emulator stops: divide_by_zero (division by zero) |
| `Dalvik:LE:32:DEX_Android12` | Dalvik | yes | 100% | 1 | no | 3 | random | decompile: Missing dynamic inject; emulator stops: userop (CALLOTHER filledNewArrayRange has no handler (filled_new_arr) |
| `Dalvik:LE:32:DEX_Android13` | Dalvik | yes | 99% | 1 | no | 4 | random | decompile: Missing dynamic inject; emulator stops: unimplemented (p-code op CPOOLREF (iget_short v10,[v6:0x1189])) |
| `Dalvik:LE:32:DEX_Base` | Dalvik | yes | 95% | 1 | no | 2 | random | decompile: Missing dynamic inject; emulator stops: userop (CALLOTHER moveRangeToIV has no handler (invoke_static_range ) |
| `Dalvik:LE:32:DEX_KitKat` | Dalvik | yes | 99% | 1 | no | 3 | random | decompile: Missing dynamic inject; emulator stops: unimplemented (p-code op CPOOLREF (sput_byte v130,0x24c3)) |
| `Dalvik:LE:32:DEX_Lollipop` | Dalvik | yes | 99% | 1 | no | 4 | random | decompile: Missing dynamic inject; emulator stops: unimplemented (p-code op CPOOLREF (const_class v181,0xc4c8)) |
| `Dalvik:LE:32:DEX_Nougat` | Dalvik | yes | 99% | 1 | no | no | random | decompile: Missing dynamic inject; emulator stops: divide_by_zero (division by zero) |
| `Dalvik:LE:32:DEX_Oreo` | Dalvik | yes | 99% | 1 | no | 1 | random | decompile: Missing dynamic inject; emulator stops: unimplemented (p-code op CPOOLREF (iput_short v4,[v9:0xfead])) |
| `Dalvik:LE:32:DEX_Pie` | Dalvik | yes | 99% | 1 | no | 2 | random | decompile: Missing dynamic inject; emulator stops: divide_by_zero (division by zero) |
| `Dalvik:LE:32:Marshmallow` | Dalvik | yes | 100% | 1 | no | 2 | random | decompile: Missing dynamic inject; emulator stops: unimplemented (p-code op CPOOLREF (invoke_super 0xf89e,v2,v13,v10,v8,v9)) |
| `Dalvik:LE:32:ODEX_KitKat` | Dalvik | yes | 99% | 1 | no | 10 | random | decompile: Missing dynamic inject; emulator stops: userop (CALLOTHER getInstanceFieldQuick has no handler (iget_wide_qu) |
| `DATA:BE:64:default` | DATA | yes | 0% | no | - | - | random | discover: nothing decodes |
| `DATA:LE:64:default` | DATA | yes | 0% | no | - | - | random | discover: nothing decodes |
| `dsPIC30F:LE:24:default` | dsPIC30F | yes | 83% | 1 | yes | 1 | random | spaces ram rom/2; emulator stops: decode (no instruction decodes at 0x4) |
| `dsPIC33C:LE:24:default` | dsPIC33C | yes | 82% | 1 | yes | 6 | random | spaces ram rom/2; emulator stops: decode (no instruction decodes at 0x18) |
| `dsPIC33E:LE:24:default` | dsPIC33E | yes | 82% | 1 | yes | 1 | random | spaces ram rom/2; emulator stops: decode (no instruction decodes at 0x8) |
| `dsPIC33F:LE:24:default` | dsPIC33F | yes | 82% | 1 | yes | 7 | random | spaces ram rom/2; emulator stops: decode (no instruction decodes at 0x1e) |
| `eBPF:BE:64:default` | eBPF | yes | 68% | 1 | yes | 2 | random | spaces ram syscall; emulator stops: decode (no instruction decodes at 0x15) |
| `eBPF:LE:64:default` | eBPF | yes | 71% | 1 | yes | 1 | random | spaces ram syscall; emulator stops: decode (no instruction decodes at 0x9) |
| `H6309:BE:16:default` | H6309 | yes | 93% | 1 | yes | 2 | random | emulator stops: unmapped (read of 2 bytes at 0xad74 (unmapped)) |
| `HC-12:BE:16:default` | HC-12 | yes | 99% | 1 | yes | no | random | emulator stops: unmapped (read of 1 bytes at 0xc23c (unmapped)) |
| `HC05:BE:16:default` | HC05 | yes | 90% | 1 | yes | 7 | random | emulator stops: decode (no instruction decodes at 0x6c) |
| `HC05:BE:16:M68HC05TB` | HC05 | yes | 89% | 1 | yes | 1 | random | emulator stops: unmapped (fetch from unmapped memory at 0xffa5) |
| `HC08:BE:16:default` | HC08 | yes | 99% | 1 | yes | 13 | random | emulator stops: unmapped (write of 2 bytes at 0xfffe (unmapped)) |
| `HC08:BE:16:MC68HC908QY4` | HC08 | yes | 99% | 2 | yes | 2 | random | emulator stops: unmapped (fetch from unmapped memory at 0xff8c) |
| `HCS-12:BE:24:default` | HCS-12 | yes | 100% | 1 | yes | no | random | emulator stops: userop (CALLOTHER segment has no handler (PULX)) |
| `HCS-12X:BE:24:default` | HCS-12X | yes | 100% | 2 | yes | no | random | emulator stops: userop (CALLOTHER segment has no handler (STY 0xc, PC)) |
| `HCS08:BE:16:default` | HCS08 | yes | 99% | 5 | yes | no | random | emulator stops: unmapped (read of 1 bytes at 0x7130 (unmapped)) |
| `HCS08:BE:16:MC9S08GB60` | HCS08 | yes | 100% | 4 | yes | 2 | random | emulator stops: unmapped (read of 1 bytes at 0xca80 (unmapped)) |
| `HCS12:BE:24:default` *dep* | HCS-12X | yes | 100% | 1 | yes | 2 | random | emulator stops: userop (CALLOTHER backgroundDebugMode has no handler (BGND)) |
| `Hexagon:LE:32:default` | Hexagon | yes | 57% | 1 | yes | 3 | random | emulator stops: decode (no instruction decodes at 0x10) |
| `JVM:BE:32:default` | JVM | yes | 85% | 1 | no | no | random | spaces ram constantPool localVariableArray parameterSpace; decompile: Missing dynamic inject; emulator stops: unmapped (write of 4 bytes at 0xfffffffc (unmapped)) |
| `Loongarch:LE:32:ilp32d` | Loongarch | yes | 28% | 1 | yes | 1 | random | spaces ram iocsr; emulator stops: unmapped (fetch from unmapped memory at 0x12428) |
| `Loongarch:LE:32:ilp32f` | Loongarch | yes | 29% | 1 | yes | 2 | random | spaces ram iocsr; emulator stops: decode (no instruction decodes at 0xc) |
| `Loongarch:LE:64:lp64d` | Loongarch | yes | 34% | 1 | yes | 1 | random | spaces ram iocsr; emulator stops: unmapped (read of 8 bytes at 0x300c (unmapped)) |
| `Loongarch:LE:64:lp64f` | Loongarch | yes | 35% | 1 | yes | no | random | spaces ram iocsr; emulator stops: unmapped (write of 4 bytes at 0xffffffffffffadc8 (unmapped)) |
| `M16C/60:LE:16:default` | M16C/60 | yes | 99% | 1 | yes | 1 | random | emulator stops: unmapped (read of 1 bytes at 0xffde (unmapped)) |
| `M16C/80:LE:16:default` | M16C/80 | yes | 98% | 1 | yes | 5 | random | emulator stops: unmapped (read of 1 bytes at 0xb56040 (unmapped)) |
| `M8C:BE:16:default` | M8C | yes | 100% | 39 | yes | 11 | random | spaces CODE RAM BANK0 BANK1; emulator stops: userop (CALLOTHER syscall has no handler (SSC)) |
| `MCS96:LE:16:default` | MCS96 | yes | 86% | 1 | yes | 2 | random | emulator stops: unmapped (fetch from unmapped memory at 0xfed9) |
| `MIPS:BE:32:16e` | MIPS | yes | 80% | 1 | yes | 2 | random | emulator stops: decode (no instruction decodes at 0x6) |
| `MIPS:BE:32:default` | MIPS | yes | 77% | 253 | yes | 16 | mips/fwkit-mips-O2 |  |
| `MIPS:BE:32:micro` | MIPS | yes | 71% | 1 | yes | 2 | random | emulator stops: decode (no instruction decodes at 0xc) |
| `MIPS:BE:32:R6` | MIPS | yes | 69% | 1 | yes | 1 | random | emulator stops: decode (no instruction decodes at 0x4) |
| `MIPS:BE:64:16e` | MIPS | yes | 80% | 1 | yes | 3 | random | emulator stops: decode (no instruction decodes at 0x6) |
| `MIPS:BE:64:64-32addr` | MIPS | yes | 82% | 1 | yes | no | random | emulator stops: unmapped (write of 8 bytes at 0x784a (unmapped)) |
| `MIPS:BE:64:64-32R6addr` | MIPS | yes | 82% | 1 | yes | no | random | emulator stops: unmapped (write of 1 bytes at 0xffffdc08 (unmapped)) |
| `MIPS:BE:64:default` | MIPS | yes | 81% | 1 | yes | no | random | emulator stops: unmapped (read of 8 bytes at 0xffffffffffffb5ee (unmapped)) |
| `MIPS:BE:64:micro` | MIPS | yes | 79% | 1 | yes | no | random | emulator stops: unmapped (read of 2 bytes at 0x24f1 (unmapped)) |
| `MIPS:BE:64:micro64-32addr` | MIPS | yes | 80% | 1 | yes | 1 | random | emulator stops: decode (no instruction decodes at 0xc) |
| `MIPS:BE:64:R6` | MIPS | yes | 80% | 1 | yes | no | random | emulator stops: unmapped (write of 8 bytes at 0x420e (unmapped)) |
| `MIPS:LE:32:16e` | MIPS | yes | 78% | 1 | yes | 1 | random | emulator stops: unmapped (fetch from unmapped memory at 0xfffffc6a) |
| `MIPS:LE:32:default` | MIPS | yes | 78% | 259 | yes | 16 | mips/fwkit-mipsel-Os |  |
| `MIPS:LE:32:micro` | MIPS | yes | 70% | 1 | yes | 1 | random | emulator stops: unmapped (write of 8 bytes at 0x344c (unmapped)) |
| `MIPS:LE:32:R6` | MIPS | yes | 70% | 1 | yes | no | random | emulator stops: unmapped (write of 8 bytes at 0xffffdad2 (unmapped)) |
| `MIPS:LE:64:16e` | MIPS | yes | 79% | 1 | yes | 2 | random | emulator stops: unmapped (fetch from unmapped memory at 0x974ccb4) |
| `MIPS:LE:64:64-32addr` | MIPS | yes | 82% | 1 | yes | no | random | emulator stops: unmapped (read of 4 bytes at 0x77f8 (unmapped)) |
| `MIPS:LE:64:64-32R6addr` | MIPS | yes | 81% | 1 | yes | 1 | random | emulator stops: unmapped (read of 8 bytes at 0xffffde50 (unmapped)) |
| `MIPS:LE:64:default` | MIPS | yes | 82% | 1 | yes | no | random | emulator stops: unmapped (read of 8 bytes at 0x17e0 (unmapped)) |
| `MIPS:LE:64:micro` | MIPS | yes | 82% | 1 | yes | no | random | emulator stops: unmapped (read of 8 bytes at 0x347b (unmapped)) |
| `MIPS:LE:64:micro64-32addr` | MIPS | yes | 81% | 1 | yes | no | random | emulator stops: unmapped (read of 8 bytes at 0xffff86bf (unmapped)) |
| `MIPS:LE:64:R6` | MIPS | yes | 80% | 1 | yes | no | random | emulator stops: unmapped (write of 8 bytes at 0x5367 (unmapped)) |
| `NDS32:BE:32:default` | NDS32 | yes | 82% | 1 | yes | 2 | random | spaces ram csreg/4; emulator stops: decode (no instruction decodes at 0x8) |
| `NDS32:LE:32:default` | NDS32 | yes | 82% | 1 | yes | 1 | random | spaces ram csreg/4; emulator stops: unmapped (read of 2 bytes at 0xffffa986 (unmapped)) |
| `pa-risc:BE:32:default` | PA-RISC | yes | 56% | 1 | yes | 2 | random | emulator stops: unmapped (read of 1 bytes at 0xfffff010 (unmapped)) |
| `PIC-12:LE:16:PIC-12C5xx` | PIC-12 | yes | 98% | 1 | yes | 2 | random | spaces CODE/2 DATA HWSTACK/2; emulator stops: unimplemented (no p-code semantics for MOVF 0x19,w) |
| `PIC-16:LE:16:PIC-16` | PIC-16 | yes | 92% | 2 | yes | 4 | random | spaces CODE/2 DATA HWSTACK/2; emulator stops: unimplemented (no p-code semantics for INCF 0x7a,w) |
| `PIC-16:LE:16:PIC-16C5x` | PIC-16 | yes | 98% | 1 | yes | 7 | random | spaces CODE/2 DATA HWSTACK/2; emulator stops: unimplemented (no p-code semantics for RLF PORTB,f) |
| `PIC-16:LE:16:PIC-16F` | PIC-16 | yes | 99% | 2 | yes | 2 | random | spaces CODE/2 DATA HWSTACK/2; emulator stops: unmapped (fetch from unmapped memory at 0x14cf) |
| `PIC-17:LE:16:PIC-17C7xx` | PIC-17 | yes | 96% | 3 | yes | 8 | random | spaces CODE/2 DATA HWSTACK; emulator stops: unmapped (fetch from unmapped memory at 0x30a6) |
| `PIC-18:LE:24:PIC-18` | PIC-18 | yes | 92% | 2 | yes | 14 | random | spaces CODE DATA HWSTACK; emulator stops: unmapped (fetch from unmapped memory at 0x15e122) |
| `PIC-24E:LE:24:default` | PIC-24 | yes | 80% | 1 | yes | 6 | random | spaces ram rom/2; emulator stops: unmapped (fetch from unmapped memory at 0xfd46) |
| `PIC-24F:LE:24:default` | PIC-24 | yes | 77% | 1 | yes | 1 | random | spaces ram rom/2; emulator stops: decode (no instruction decodes at 0x8) |
| `PIC-24H:LE:24:default` | PIC-24 | yes | 77% | 1 | yes | 1 | random | spaces ram rom/2; emulator stops: decode (no instruction decodes at 0x4) |
| `PowerPC:BE:32:4xx` | PowerPC | yes | 80% | 1 | yes | 1 | random | emulator stops: decode (no instruction decodes at 0x4) |
| `PowerPC:BE:32:default` | PowerPC | yes | 97% | 239 | yes | 2 | ppc/fwkit-ppc-O2 | emulator stops: userop (CALLOTHER instructionSynchronize has no handler (isync)) |
| `PowerPC:BE:32:e500` | PowerPC | yes | 84% | 1 | yes | no | random | emulator stops: unmapped (read of 4 bytes at 0x5c7c (unmapped)) |
| `PowerPC:BE:32:e500mc` | PowerPC | yes | 80% | 1 | yes | no | random | emulator stops: unmapped (write of 8 bytes at 0x6765 (unmapped)) |
| `PowerPC:BE:32:MPC8270` | PowerPC | yes | 81% | 1 | yes | no | random | emulator stops: unmapped (write of 4 bytes at 0xffffb64b (unmapped)) |
| `PowerPC:BE:32:QUICC` | PowerPC | yes | 81% | 1 | yes | 1 | random | emulator stops: unmapped (read of 4 bytes at 0x481b (unmapped)) |
| `PowerPC:BE:64:64-32addr` | PowerPC | yes | 84% | 1 | yes | 1 | random | emulator stops: decode (no instruction decodes at 0x4) |
| `PowerPC:BE:64:A2-32addr` | PowerPC | yes | 90% | 1 | yes | no | random | emulator stops: unmapped (read of 2 bytes at 0x7cbc (unmapped)) |
| `PowerPC:BE:64:A2ALT` | PowerPC | yes | 88% | 1 | yes | no | random | emulator stops: unmapped (read of 4 bytes at 0x78ce (unmapped)) |
| `PowerPC:BE:64:A2ALT-32addr` | PowerPC | yes | 88% | 1 | yes | no | random | emulator stops: unmapped (read of 4 bytes at 0x2845 (unmapped)) |
| `PowerPC:BE:64:default` | PowerPC | yes | 84% | 1 | yes | no | random | emulator stops: unmapped (write of 4 bytes at 0x2bb7 (unmapped)) |
| `PowerPC:BE:64:VLE-32addr` | PowerPC | yes | 88% | 1 | yes | 1 | random | emulator stops: unmapped (read of 4 bytes at 0xffffa48f (unmapped)) |
| `PowerPC:BE:64:VLEALT-32addr` | PowerPC | yes | 88% | 1 | yes | 2 | random | emulator stops: decode (no instruction decodes at 0x8) |
| `PowerPC:LE:32:4xx` | PowerPC | yes | 80% | 1 | yes | no | random | emulator stops: unmapped (read of 1 bytes at 0x5acd (unmapped)) |
| `PowerPC:LE:32:default` | PowerPC | yes | 80% | 1 | yes | no | random | emulator stops: unmapped (write of 8 bytes at 0x5f1e (unmapped)) |
| `PowerPC:LE:32:e500` | PowerPC | yes | 84% | 1 | yes | 1 | random | emulator stops: unmapped (read of 4 bytes at 0x63ff (unmapped)) |
| `PowerPC:LE:32:e500mc` | PowerPC | yes | 84% | 1 | yes | 1 | random | emulator stops: decode (no instruction decodes at 0xc) |
| `PowerPC:LE:32:QUICC` | PowerPC | yes | 80% | 1 | yes | 1 | random | emulator stops: unmapped (fetch from unmapped memory at 0x1b55ce4) |
| `PowerPC:LE:64:64-32addr` | PowerPC | yes | 84% | 1 | yes | no | random | emulator stops: unmapped (read of 2 bytes at 0x4d8d (unmapped)) |
| `PowerPC:LE:64:A2-32addr` | PowerPC | yes | 87% | 1 | yes | 1 | random | emulator stops: decode (no instruction decodes at 0x4) |
| `PowerPC:LE:64:A2ALT` | PowerPC | yes | 88% | 1 | yes | 1 | random | emulator stops: unmapped (read of 4 bytes at 0x5962 (unmapped)) |
| `PowerPC:LE:64:A2ALT-32addr` | PowerPC | yes | 89% | 1 | yes | no | random | emulator stops: unmapped (write of 4 bytes at 0x19a7 (unmapped)) |
| `PowerPC:LE:64:default` | PowerPC | yes | 83% | 1 | yes | no | random | emulator stops: unmapped (write of 8 bytes at 0xffffffffffff812c (unmapped)) |
| `RISCV:LE:32:AndeStar_v5` | RISCV | yes | 80% | 2 | yes | 6 | random | spaces ram csreg/4 ExecTable; emulator stops: decode (no instruction decodes at 0x1f0) |
| `RISCV:LE:32:default` | RISCV | yes | 100% | 293 | yes | 16 | riscv32/fwkit-rv32-O2 | spaces ram csreg/4 |
| `RISCV:LE:32:RV32G` *dep* | RISCV | yes | 82% | 1 | yes | 1 | random | spaces ram csreg/4; emulator stops: decode (no instruction decodes at 0x37e) |
| `RISCV:LE:32:RV32GC` *dep* | RISCV | yes | 83% | 2 | yes | 3 | random | spaces ram csreg/4; emulator stops: decode (no instruction decodes at 0x2ea) |
| `RISCV:LE:32:RV32I` *dep* | RISCV | yes | 83% | 1 | yes | 1 | random | spaces ram csreg/4; emulator stops: decode (no instruction decodes at 0x2) |
| `RISCV:LE:32:RV32IC` *dep* | RISCV | yes | 83% | 1 | yes | 2 | random | spaces ram csreg/4; emulator stops: unmapped (fetch from unmapped memory at 0xfffffffc) |
| `RISCV:LE:32:RV32IMC` *dep* | RISCV | yes | 83% | 1 | yes | 1 | random | spaces ram csreg/4; emulator stops: decode (no instruction decodes at 0x2) |
| `RISCV:LE:64:default` | RISCV | yes | 86% | 1 | yes | 2 | random | spaces ram csreg/8; emulator stops: unimplemented (no p-code semantics for vsrl.vx v24,v23,sp ,v0.t) |
| `RISCV:LE:64:RV64G` *dep* | RISCV | yes | 85% | 1 | yes | 3 | random | spaces ram csreg/8; emulator stops: decode (no instruction decodes at 0x6) |
| `RISCV:LE:64:RV64GC` *dep* | RISCV | yes | 85% | 1 | yes | 2 | random | spaces ram csreg/8; emulator stops: decode (no instruction decodes at 0x4) |
| `RISCV:LE:64:RV64I` *dep* | RISCV | yes | 87% | 1 | yes | 1 | random | spaces ram csreg/8; emulator stops: decode (no instruction decodes at 0x2) |
| `RISCV:LE:64:RV64IC` *dep* | RISCV | yes | 84% | 1 | yes | 4 | random | spaces ram csreg/8; emulator stops: decode (no instruction decodes at 0xe) |
| `sparc:BE:32:default` | Sparc | yes | 77% | 264 | yes | 16 | sparc/fwkit-sparc-O2 |  |
| `sparc:BE:64:default` | Sparc | yes | 64% | 1 | yes | 1 | random | emulator stops: decode (no instruction decodes at 0x4) |
| `SuperH4:BE:32:default` | SuperH4 | yes | 79% | 1 | yes | 3 | random | emulator stops: decode (no instruction decodes at 0x6) |
| `SuperH4:LE:32:default` | SuperH4 | yes | 78% | 243 | yes | 10 | sh4/fwkit-sh4-O2 | emulator stops: unmapped (write of 4 bytes at 0x8c0ffffc (unmapped)) |
| `SuperH:BE:32:SH-1` | SuperH | yes | 79% | 1 | yes | 5 | random | emulator stops: decode (no instruction decodes at 0xa) |
| `SuperH:BE:32:SH-2` | SuperH | yes | 80% | 1 | yes | 2 | random | emulator stops: decode (no instruction decodes at 0x4) |
| `SuperH:BE:32:SH-2A` | SuperH | yes | 85% | 1 | yes | 1 | random | emulator stops: unmapped (write of 1 bytes at 0xe7cc947 (unmapped)) |
| `TI_MSP430:LE:16:default` | TI_MSP430 | yes | 41% | 21 | yes | 1 | msp430/mcukit-msp430-O2 | emulator stops: unmapped (write of 2 bytes at 0x120 (unmapped)) |
| `TI_MSP430X:LE:32:default` | TI_MSP430X | yes | 100% | 247 | yes | no | msp430/fwkit-msp430x-Os | emulator stops: unmapped (write of 2 bytes at 0x15c (unmapped)) |
| `tricore:LE:32:default` | tricore | yes | 68% | 1 | yes | no | random | emulate: register space of tricore:LE:32:default:default is too large |
| `tricore:LE:32:tc172x` | tricore | yes | 66% | 1 | yes | no | random | emulate: register space of tricore:LE:32:tc172x:default is too large |
| `tricore:LE:32:tc176x` | tricore | yes | 68% | 1 | yes | no | random | emulate: register space of tricore:LE:32:tc176x:default is too large |
| `tricore:LE:32:tc29x` | tricore | yes | 66% | 1 | yes | no | random | emulate: register space of tricore:LE:32:tc29x:default is too large |
| `V850:LE:32:default` | V850 | yes | 99% | 4 | yes | 1 | random | spaces ram sysreg; emulator stops: unmapped (write of 4 bytes at 0xffffee96 (unmapped)) |
| `V850:LE:32:v850e3v5` | V850 | yes | 100% | 4 | yes | 1 | random | spaces ram sysreg; emulator stops: divide_by_zero (division by zero) |
| `x86:LE:16:Protected Mode` | x86 | yes | 99% | 1 | yes | no | random | emulator stops: userop (CALLOTHER swi has no handler (INT3)) |
| `x86:LE:16:Real Mode` | x86 | yes | 99% | 1 | yes | no | random | emulator stops: userop (CALLOTHER segment has no handler (POP BX)) |
| `x86:LE:32:default` | x86 | yes | 99% | 1 | yes | 2 | random | emulator stops: decode (no instruction decodes at 0x4) |
| `x86:LE:32:System Management Mode` | x86 | yes | 99% | 1 | yes | 1 | random | emulator stops: unmapped (fetch from unmapped memory at 0xffffff9c) |
| `x86:LE:64:compat32` | x86 | yes | 99% | 1 | yes | 3 | random | emulator stops: unmapped (write of 1 bytes at 0xfdfbc8b5 (unmapped)) |
| `x86:LE:64:default` | x86 | yes | 96% | 1 | yes | no | random | emulator stops: userop (CALLOTHER swi has no handler (INT1)) |
| `Xtensa:BE:32:default` | Xtensa | yes | 88% | 1 | yes | no | random | emulator stops: userop (CALLOTHER flix has no handler (FLIX 0x9a28a)) |
| `Xtensa:LE:32:default` | Xtensa | yes | 98% | 374 | yes | 1 | xtensa/fwkit-esp32-O2 | emulator stops: userop (CALLOTHER wsr has no handler (wsr a0,WindowBase)) |
| `z180:LE:16:default` | Z180 | yes | 99% | 6 | yes | 8 | random | spaces ram io; emulator stops: unmapped (write of 2 bytes at 0xfffe (unmapped)) |
| `z182:LE:16:default` | Z180 | yes | 99% | 6 | yes | 12 | random | spaces ram io; emulator stops: unmapped (fetch from unmapped memory at 0x4bd0) |
| `z80:LE:16:default` | Z80 | yes | 100% | 33 | yes | 2 | z80/mcukit-z80-Os | spaces ram io; emulator stops: unmapped (write of 2 bytes at 0xfffe (unmapped)) |
| `z8401x:LE:16:default` | Z80 | yes | 99% | 5 | yes | 1 | random | spaces ram io; emulator stops: unmapped (fetch from unmapped memory at 0xffac) |

<!-- sweep:end -->

## Known gaps

- **Context that one instruction sets for the next is not followed in
  discovery.** AVR's skip instructions (`cpse`, `sbrc`, `sbrs`, `sbic`,
  `sbis`) set a context bit for the instruction after them, which then
  begins with a conditional branch over itself. Discovery decodes each
  instruction from its bytes and the painted context alone, so where the
  skipped instruction is an unconditional `rjmp`, `jmp` or `ret`, the code
  after it is only found if something else reaches it. The listing, which
  decodes linearly, and the decompiler apply the context. This is most of
  what revkit lacks on the AVR images ([firmware.md](firmware.md#other-processors)).
- **Function pointers in code memory are not followed on Harvard
  machines.** Tables of 16-bit code addresses (task and command tables) in
  flash are found on ARM-style images as runs of pointers in data; on AVR,
  the 8051 and the Z80 neither revkit nor Ghidra reaches the functions
  only such tables name.
- **Types from debug information assume a 4-byte `int`.** The decompiler's
  own integer names follow the compiler spec (a 2-byte integer is `int` on
  AVR and MSP430, as in Ghidra), but DWARF base types of an ELF for such a
  processor are still mapped with fixed sizes.
- **Spaces need 64-bit room.** Keys put a space's base above bit 40, so
  images of 64-bit languages keep one space.
- **Dalvik and JVM don't decompile, TriCore doesn't emulate** (above).
- Paged and banked memory (8051 code banking, PIC's page select as an
  address space of its own) is loaded as the language lays it out; there
  is no overlay or bank-switching model.
