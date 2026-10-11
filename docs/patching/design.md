# Patching in revkit: assembler, patch model, export

Recommendation for adding an assembler, instruction and byte patches, and
export of a patched binary to revkit (C++20, vendored Ghidra 12.1.4 SLEIGH).
Measurements below were taken on this host on 2026-10-05; scripts and raw
output are in this directory (`ghidra-bench/`, `fw-lift.json`, `cm3-lift.json`).

## 1. Assembler: port Ghidra's SLEIGH-inverting assembler to C++ (option a, with d's oracle)

**Recommendation: (a), hardened with (d)'s idea.** Build one generic
assembler over the vendored SLEIGH: invert the constructors loaded from the
`.sla`, solve operand fields, and keep only candidates that revkit's own
disassembler decodes back to the same parse tree. Do not take LLVM MC as the
primary assembler, and do not bind to it at all in the first milestones.
Keystone is GPL-2 and out.

### What Ghidra's assembler is

- `ghidra.app.plugin.assembler` (SoftwareModeling): 116 Java files,
  17.5k lines, **8.3k non-comment lines**; the Patch Instruction UI
  (`ghidra.app.plugin.core.assembler`, Base) is another 2.1k lines.
- Pipeline: `AbstractSleighAssemblerBuilder` walks every `SubtableSymbol`'s
  decision tree (`(DisjointPattern, Constructor)` pairs) and turns each
  constructor's *print pieces* into a production of a context-free grammar
  (operands become terminals: numeric, varnode-list string maps, name maps,
  or non-terminals for subtables). `AssemblyParser` builds an **LALR(1)**
  table and parses with branching on conflicts (ambiguity is kept, all parse
  trees are resolved). `AbstractAssemblyTreeResolver` resolves each tree
  bottom-up: `AssemblyPatternBlock`s (mask/value bit vectors for instruction
  and context) are combined, operand values are solved by
  `RecursiveDescentSolver` over the `PatternExpression` tree (`MaskedLong`
  arithmetic; solvers for `+ - * << >> & | ^ ~` with constant partners,
  `inst_start`/`inst_next` by *backfill* once the length is known), context
  changes (`ContextOp`) are solved backwards, `globalset` paths are found on
  an `AssemblyContextGraph` (Dijkstra over context states), and finally
  **`filterByDisassembly`** re-parses the candidate bytes with the SLEIGH
  disassembler and drops any whose construct-state tree differs. That last
  step is exactly option (d)'s verification; Ghidra already does it.
- Known holes, from the code: `inst_next2` "not really supported";
  non-invertible expressions (division, non-constant multiplication, shift by
  an unknown) are `SolverException`s; the recursion path for context
  (`resolveRootRecursion`) is "only correct for the `instruction` table".
  Ghidra ships an **`assemblyRating`** per language: only **33 of 181**
  languages are rated (29 PLATINUM: ARM v7, AARCH64 v8A, MIPS, PowerPC,
  SuperH4, 68000, sparc, avr8, avr32, pa-risc, MSP430X; 4 GOLD: x86 32/64,
  dsPIC30F). The other 148 pop an "untested" warning in Ghidra.

### Measured (Ghidra 12.1.4 headless, `AsmBench.java`: every 5th instruction of the auto-analysed program, 3000 per language, `resolveLine` at the instruction's address with the program's context)

| language | program | grammar build | exact encoding found | other encoding only | failures | µs / line |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| ARM:LE:32:v4t | a vendor ARM v4t firmware (raw, with a header) | 167 ms | 2924 / 3000 (97.5%) | 76 (2.5%): ARM modified immediates the toolchain rotated non-canonically (`mov r1,#0x800`, `subs r12,r0,#0x2700`) | 0 | 405 |
| ARM:LE:32:v8 (Cortex-M3 ELF, Thumb-2) | fwkit -O2 | 2.1 s | 2986 / 3000 (99.5%) | 0 | 14: conditional instructions inside IT blocks (`mov.eq r0,#0x0`) | **11,866** |
| MIPS:BE:32 | fwkit -O2 | 824 ms | 2299 / 3000 | 0 | 701, all delay-slot `_`-prefixed mnemonics (bench artefact: strip `_`) | 568 |
| PowerPC:BE:32:e500 | fwkit -O2 | 881 ms | 3000 / 3000 | 0 | 0 | 910 |
| SuperH4:LE:32 | fwkit -O2 | 80 ms | 2533 / 3000 | 0 | 467, all delay-slot `_` (same artefact) | 380 |
| 68000:BE:32:Coldfire | fwkit -O2 | 431 ms | 3000 / 3000 | 0 | 0 | 632 |
| Xtensa:LE:32 (ESP32) | fwkit -O2 | 101 ms | 2866 / 3000 (95.5%) | 0 | 134, all `movi.n` (the solver can't invert its split, sign-folded immediate field) | 218 |
| x86:LE:64 | lua (gcc -O2) | **9.8 s** | 2996 / 3000 | 4 (multi-byte `NOP` forms) | 0 | 1,973 |
| AARCH64:LE:64:v8A | cjson (gcc -O2) | 6.5 s | 885 / 885 (whole program) | 0 | 0 | 1,579 |

Take-aways: the approach is complete where the spec is regular (PowerPC,
68000, AArch64 100%; x86-64 99.9%; ARM 97.5% with the rest being
alternative encodings of the same instruction), its failures are specific
and diagnosable (Xtensa `movi.n`, Thumb IT blocks), it needs the
**program's context at the address** (Thumb, IT-block state, MIPS16, x86
operand size), and it is slow on big grammars: x86-64 takes 9.8 s and
AArch64 6.5 s to build the LALR tables (Ghidra caches the built assembler
per session, not on disk), and Thumb-2 costs 12 ms per line because every
ambiguity branches. For an interactive patch dialog that is fine; for a round-trip CI
gate over a corpus it needs the C++ port to be an order of magnitude faster
(no streams-of-objects, bit vectors not `byte[]`, memoized sub-resolutions).

### Why not LLVM MC (b), and why not a hybrid now (c)

- **Coverage**: LLVM 18 on this host has 21 targets built. Mapping Ghidra's
  processors to them covers **103 of 181 language ids (57%)**, 12 of those on
  experimental targets (M68k, MSP430, Xtensa, AVR). Uncovered: SuperH (the
  user's corpus has SH4), PIC, 8051, Z80, 6502, 68HC, TriCore, V850, NDS32,
  PA-RISC, CR16, Dalvik, and more: 78 languages.
- **Syntax fidelity** (measured on a vendor ARM v4t firmware, ARM v4t, 3000 unique
  Ghidra-printed lines fed to `llvm-mc -triple=armv4t`): 84.2% accepted raw;
  95.6% after four normalizations (`{r4 r5 lr}` → commas, `cpy` → `mov`,
  `bl 0xADDR` and `ldr r0,[0xADDR]` rewritten as offsets). Rejected after
  that: `adr rX,0xADDR` (needs a label), and Ghidra's condition-before-S
  order `subcss` where UAL wants `subshs`. Thumb-2 (Cortex-M3 fwkit, 3000
  lines): 97% accepted among non-PC-relative lines; the rejects are IT-block
  forms (`mov.eq`, `sub.ls`) that UAL expresses as a separate `it` instruction
  plus a conditional mnemonic, so an LLVM path would have to know the IT
  state at the address, which only SLEIGH context tracks. **23.5% of Thumb
  lines are PC-relative** (`bl`, `cbz`, `adr`, literal loads) and need an
  address-to-offset rewrite layer before LLVM sees them.
- **Byte fidelity** where accepted: ARM 1811 / 1854 identical (97.7%); the
  43 differences are the same non-canonical rotated immediates; Thumb-2 2224
  / 2226.
- So LLVM would be a second syntax (GNU/UAL) on half the languages, behind a
  per-processor rewrite layer, pulling in ~100 MB of libLLVM. It cannot be the
  oracle (the oracle must be *our* disassembler), and it does not remove the
  need for the SLEIGH assembler. Rejected for now; revisit as an optional
  "GNU syntax" input filter if users ask for it.

### Why not a pure search assembler (d)

Blind enumeration of 32-bit encodings is 4·10⁹ decodes per instruction. What
makes search tractable is enumerating *constructors* and solving *fields*,
which is Ghidra's design. The verifiable part of (d), decode-and-compare, is
kept as the mandatory last stage, and it also gives the test oracle: a
candidate is accepted iff `Lifter::lift(addr, bytes)` with the context at
`addr` yields the same text and the same constructor tree.

### Ready to reuse in the vendored C++ (`third_party/ghidra/decompiler`)

- `.sla` loading: `Sleigh`/`SleighBase` (`symtab`, `findSymbol`), so the
  assembler works from the compiled `.sla`, as the disassembler does.
- `Constructor` (`getPattern()` → `TokenPattern`, `getNumOperands`,
  `getOperand`, `context` changes as `ContextOp`/`ContextCommit`);
  `SubtableSymbol` → `DecisionNode` holding the `(DisjointPattern*,
  Constructor*)` list; `DisjointPattern`/`InstructionPattern`/
  `ContextPattern`/`CombinePattern` → `PatternBlock` (mask/value words):
  these are `AssemblyPatternBlock`'s source data.
- `PatternExpression` tree (`TokenField`, `ContextField`, `OperandValue`,
  `ConstantValue`, `Start/End/Next2InstructionValue`, binary and unary
  expressions) with `minValue`/`maxValue`: what the solver inverts.
- `OperandSymbol::getDefiningSymbol()`: `VarnodeListSymbol`, `NameSymbol`,
  `ValueMapSymbol`, `SubtableSymbol`: the terminal kinds of the grammar.
- `ContextDatabase`/`ContextCache` and revkit's `Lifter::set_context`: the
  context at an address (TMode, ITMode) for `resolveLine`.
- `ParserContext`/`ConstructState` from `Sleigh::resolve`: the tree the
  oracle compares.
- Three members are private and need one-line accessor patches in the
  series: `Constructor::printpiece`, `DecisionNode::list`, and
  `SubtableSymbol`'s decision node. They are `0006-SLEIGH-expose-...` to `0008`.

### Design of the port (what to do differently)

1. **Grammar from print pieces**, as Ghidra, built once per language and
   cached on disk next to the `.sla` (the x86 grammar has ~5.5k constructors;
   ARM 2k; AArch64 1.2k).
2. **Parser**: a memoized GLR/Earley-style parser over the token stream
   rather than LALR(1)-with-branching. It gives the same set of parse trees,
   has no table-build step, and produces the *expected-token set at the
   cursor* for free, which is the completion list in the UI.
3. **Resolution** as Ghidra's: pattern blocks, recursive-descent solver with
   backfill for `inst_next`, context solving. Port the solver test cases.
4. **Selection**: all candidates that survive the oracle, ranked by
   (a) instruction length, (b) **Hamming distance to the bytes currently at
   the address**. For an immediate change this keeps the toolchain's
   rotation and every other bit, so the diff shows only what the user meant.
   It also answers the 2.5% "other encoding" cases above.
5. **Speed targets**: < 100 ms grammar load from cache, < 1 ms per line on
   ARM/Thumb, < 5 ms on x86. The CI gate needs ~10⁵ lines per language.

Effort: 6–9k lines of C++ with tests; roughly the size of `src/diff`.

## 2. Patch model in the fact store

**Byte patches are assertions.** New `FactKind::Patch` (`PATCH@addr`,
`sub = ""`), value = the new bytes (a string), one assertion per contiguous
range. The op's `meta` holds what the API needs to render it: the original
bytes, the assembly text as typed (instruction patches), the canonical text
re-disassembled, the context used, the number of alternative encodings, and
the usual provenance. The value stays bytes-only so precedence (user > import
> agent > analysis), blame, history, undo (`Retract`), redo and
`RevertByProvenance` all work unchanged, and collab replicates patches like
every other op.

**Reads.** Add a derived query `bytes.effective(PageKey)` = `MemoryPage` with
every live `PATCH` key overlapping the page laid over it (found through
`AssertedSpan(Patch, …)`, winners by the store's rank). Overlapping patches
compose by precedence then recency, which is also what blame shows. Every
consumer that decodes bytes reads this query instead of `MemoryPage`. Today
`analysis/decode.cc` and the plugin host go through the engine, but five
readers go straight to `loader::Image::memory` and would miss patches:
`analysis/program.cc` (2 sites), `analysis/data_program.cc`,
`backend/program.cc:534`, `inputs/assemble.cc:412` (the decompiler's image),
`emu/state.cc` (the emulator). Routing them through `bytes.effective` is the
first task of M1; the lifter already has the `lift(address, bytes)` overload
for callers that own their bytes.

**Invalidation** falls out: a patch changes the page's fingerprint, so the
flows that decoded it, the listing pages, xrefs, the function's
decompilation and the diff fingerprints recompute, and nothing else does
(`Patch` is its own input partition, so memos that never read bytes nor
patches are not revalidated). A patch at a function entry can change
discovery; that is correct and already how `FLOW_OVERRIDE` behaves.

**Instruction patches** store both: bytes as the value (authoritative),
text in `meta`. The listing never trusts the stored text; it shows the
re-disassembly, so a patch that no longer decodes (someone patched a byte
of it later) shows up as such.

**Shorter replacements** (x86): pad with the language's NOP, assembled by
the same assembler, as a second `PATCH` in the same transaction; the dialog
shows the padding.

**Space for new code.** A derived query `space.candidates(program)` ranks
regions: runs of erase-state bytes (0xFF/0x00) past the last defined item in
a block, alignment padding between functions, and **data with no
references** (the user's debug-string case) sorted by size, each with its
current contents and xref count. A multi-instruction patch is one
transaction: `PATCH` per instruction (two-pass within the block for forward
labels; symbol names resolve through `symbols.effective`), plus a
`FUNCTION_BOUNDS` entry at the cave so discovery decodes it and a `NAME`.
Overwriting something with references warns; the user accepts.

**Diff.** The patched program and the original are the same fact-store
program under two *views*: `bytes.effective` reads a view flag in its key
(`patched`, `original` = `MemoryPage` alone). `diff.*` already takes a
program key; give it `(program, view)`. The matcher's bytes tier then pairs
everything, `Unchanged` (equal bytes at the same address) marks every
untouched function, and the modified ones are exactly the patched functions
with the existing side-by-side view. No copy of the program, no second
import; the "original" costs nothing until opened.

## 3. Export

`Export(program, format, fixups, verify)` is a pure function of the file's
bytes and the live patches. For each patch, map address → file offset
through the loader's regions (`Region.file_offset/file_size`; ELF segments,
PE sections, the raw image's `raw_offset`). A patch outside file-backed
bytes (bss, synthesized memory, MMIO, a declared RAM region) is an error that
names the patch; no silent drop. The raw header is preserved because the file
is the base and the image starts at `raw_offset`. PE: recompute the optional
header CheckSum (fixed algorithm) built in. ELF: nothing to fix.

**Fixups**: a new plugin kind `fixup` (`rk_fixup(file) -> file`, WASM, with
manifest magic/format filters) plus one built-in: *checksum*, driven by a
spec stored as a `NOTE` assertion on the program: `{algorithm, range,
field offset and width, endianness}` or `{algorithm, range, filename
pattern}`.

**Detector: yes, ship it, and make it broader than CRC32.** On a vendor
firmware no header word matches any CRC32 variant over any natural range,
but the filename suffix is the **32-bit sum of all bytes of the whole file**
(verified on two releases). So the helper tries
additive sums (8/16/32-bit words, both endians), Fletcher/Adler, CRC-16
(CCITT, Modbus, XMODEM), CRC-32 (IEEE, bzip2, MPEG-2, POSIX, JAMCRC, C,
reflected and not) over candidate ranges (whole file, image after the
header, each minus the field itself, minus trailing 0xFF/0x00 padding,
header-declared lengths) against every
16/32-bit header word and a user-supplied value (the filename suffix). A hit
becomes the spec; the export dialog shows the evidence ("sum32 over
0..EOF == filename suffix"). The exporter can also produce the output name
from a template (e.g. `NAME_{SUM:08X}.bin`).

**Verification**: re-load the exported bytes with the program's
`ImportOptions` as a temporary program and diff its memory against the
patched view: every mapped byte identical, every fixup field recomputed from
the output matches. The report lists the changed ranges. Export fails
closed if the reload differs.

## 4. UI

- **Patch instruction** (Ctrl+Shift+G): the row's text becomes an inline
  editor. A debounced `Assemble{address, text}` call returns candidate
  encodings (bytes, length, Hamming distance), errors with column positions,
  and the parser's expected tokens at the cursor for completion (mnemonics,
  register names from the varnode lists, `#`, `[`). Candidates are listed
  under the row with their bytes; Enter commits the highlighted one as a
  `PATCH` assertion with the typed text in `meta`. Immediates: clicking a
  `scalar` token (the listing already has typed tokens) opens a value field
  and re-assembles the same text with the value substituted, so the common
  "change a constant" patch never requires typing assembly.
- **Bytes editor**: a hex pane for the selection with original and patched
  columns; typing hex or ASCII stages one `PATCH` per contiguous run.
- **Patched rows**: gutter mark and highlighted byte column in the listing;
  hover shows original bytes and text plus blame; the graph colors blocks
  that contain patches; the decompiler shows a bar "n patches in this
  function".
- **Patches panel**: `ListAssertions(kind=PATCH)`: address, old → new
  text, author, revision, with Revert (retraction), Revert mine
  (`RevertByProvenance`), jump, and the original/patched diff.
- **Export dialog**: format, fixups with the detector's evidence and a
  "detect" button, filename template, verify on; the result shows the
  verification report and the written path.

## 5. Tests and gates

- **Round-trip corpus per language**: for every instruction the discovery
  found in the corpus binaries (`out/corpus`: x86-64, AArch64, RISC-V;
  `out/firmware-corpus`: Cortex-M, MIPS, PowerPC, SuperH4, 68000, Xtensa;
  locally the user's ARM v4t firmware), assemble the printed text at its
  address with its context and classify: *exact* (an encoding equals the
  original bytes), *equivalent* (re-disassembles to the same text, different
  bytes), *failed* (with the parser/solver stage). Also fuzz the languages
  with no binaries: decode random bytes, assemble what decodes. Report per
  language and per constructor (which of the N constructors were exercised),
  and time per line.
- **Gate** (`scripts/ci.sh --asm`): ARM, Thumb-2, AArch64, x86-64, MIPS,
  PowerPC ≥ 99% exact+equivalent, exact ≥ 95%; every language's figures in a
  baseline file with 0.5 points of slack, as `corpus/baselines/diff.json`
  does. Per-line time budget 1 ms (x86 5 ms).
- **Export**: patch, export, reload, byte-compare for raw/ELF/PE; checksum
  fixup tests on synthetic headers for every algorithm; the firmware sum
  rule as a local bench (`bench-firmware.sh` style, the files are not
  committed).
- **Store semantics**: undo/redo of a patch restores the decode; two
  overlapping patches by different ranks; revert by provenance; collab merge
  in both orders; diff original vs patched marks exactly the patched
  functions.

## 6. Milestones and risks

**M1 (first value, 4–6 weeks)**: `PATCH` kind, `bytes.effective`, every
reader routed through it, listing marks, hex editor and immediate edit,
the SLEIGH assembler with ARM/Thumb passing the gate, inline patch dialog,
raw export with the checksum detector and sum/CRC fixups, reload
verification. The user can redo today's hand patches (immediates, `add` →
`bl`, code over the debug string) and ship a file whose name checksum is
right.

**M2**: the corpus gate across all corpus languages, x86-64 and AArch64
quality, ELF/PE export with PE checksum, patches panel, code caves and
multi-instruction blocks with labels, original-vs-patched diff view.

**M3**: WASM fixup plugins, SDK/agent API for patches, collab tests,
grammar cache, optional GNU-syntax input filter.

**Risks**: (1) solver incompleteness on irregular specs (division, variable
shifts; Ghidra's own ratings show x86 at GOLD and 148 languages untested):
mitigated by the oracle and per-language baselines, not by promising
everything. (2) Context: Thumb/IT, MIPS16, x86 modes must come from the
program at the address and the IT case is unsolved even in Ghidra (14 of
3000). (3) Performance of ambiguous grammars (Thumb-2 12 ms/line in Java). (4)
Untracked byte readers silently showing the original: the audit above is
the fix, and a test that patches a byte in every subsystem's path. (5)
Non-canonical encodings in old toolchains (2.5% in a vendor firmware):
handled by the nearest-bytes selector. (6) Three accessor patches to the
vendored SLEIGH: tiny, but keep them in the series with repros.
