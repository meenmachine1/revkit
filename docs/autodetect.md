# Auto-detection: processor, load address and header offset

For a binary with no header that says what it is (raw firmware, a dump),
revkit suggests what the raw import options ask for: the language (processor,
byte order, variant and mode), the load address, the offset of the image
within the file, and extra memory regions. Each suggestion comes with its
evidence, a confidence and alternatives, and the user can override any of it.

**Status:** in implementation (phases in section 8). The library
(`src/detect/`, `rk-lift --detect`) answers processor, base and offset;
the daemon serves it as `ProjectService.DetectRawLayout` (`api_minor` 23,
feature `raw-detect`, with progress and cancellation), the Python and
TypeScript SDKs and the MCP server call it, and the UI's Open dialog
suggests the raw options from it (section 7). Calibration (section 5) and
storing the accepted suggestion with the import are still to do.

**Provenance:** the design is clean-room, from first principles and
experiments with revkit's own decoders and discovery on labelled test data.
It takes nothing from existing detectors' code or methods; in particular it
has no byte n-gram classifier. Ghidra has no such detection, and is not an
input.

Two additions made after the design was written:

- **The headline metric is the false-confident rate:** how often an answer
  given at high confidence is wrong. Top-1 accuracy comes second.
- **Position-independent code:** when the code has too few absolute
  constants to vote on (AArch64 `adrp`, RISC-V `auipc`, x86-64), say "any
  base works; conventional X suggested" at low confidence, and don't guess.

Test data other than what revkit builds itself stays outside the repository
(`scripts/bench-detect.sh`, paths from the environment); the docs carry
aggregate numbers only.

## 0. What the experiments showed

| Question | Measurement | Consequence |
|---|---|---|
| Does "it decodes" identify the ISA? | No. On wrong-ISA code: x86 0.97, Z80/8051 1.00, Thumb 0.88-0.99, ARM 0.87-0.96 of bytes decode. True ISA: 0.95-1.00. | Decode validity is a filter only. |
| Does one control-flow statistic do it? | Short jumps landing on instruction starts, minus a byte-shuffled null: 10/18 top-1 (four misses were my harness only counting `ram`-space targets). | No single cheap signal, and a shuffled null is the wrong null for fixed-width ISAs. |
| Does revkit's own discovery separate ISAs? | Yes, where start patterns exist. `--analyze` body coverage: true ISA 0.35-1.00 (x86 0.62, AArch64 0.35, RISC-V 0.67, SPARC 0.77, Xtensa 0.73, 68k 1.00, AVR 0.71); wrong ISA or endianness 0 functions on all 23 wrong pairings of three kit images, in 0.0-0.1 s. | Discovery yield is the deciding signal for those families. |
| Where does that fail? | Z80 "discovers" 0.39-0.92 coverage on 8 of 16 foreign corpora, taking up to 165 s on 32 KB. On true 8051/MSP430/6502 chunks, and on the SuperH (0.00) and PPC (0.08) chunks, it finds almost nothing. | Needs a budget, a per-language chance baseline, and pattern-free seeds. |
| Do unknown ISAs get refused? | Alpha, VAX, Blackfin: every language ≤0.05 coverage. HP-PA: Z80 0.77. | Refusal works once dense 8-bit ISAs are discounted. |
| Variants? | Often exact ties: ColdFire U-Boot identical under 68040/68020/ColdFire/CPU32; PPC default = e500 = 4xx; Cortex = v8T = v8-m. Separable: v4t on Thumb-2 0.34 vs 0.47; RV64 image under RV32 0.10 vs 0.49; x86-64 on 32-bit BIOS 0 vs 0.37. RV32 image under RV64 ties. | Variants need an instruction census and "smallest sufficient", with honest tie groups. |
| Base from pointers vs strings? | Raw aligned words minus string offsets: true base is the top peak in 10/16 kit images, 2-9x over runner-up. Failures: MIPS and PPC top peaks `0x24810000` / `0x38600000` are `addiu` / `li` instruction words; SH4 U-Boot's top peak `0xfffbc004` is a wrapped (negative) delta, i.e. offsets rather than absolute pointers. | Pointers must be constants the lifter materialises, not raw words. Several coherent peaks are normal. |
| Base from discovery yield? | MIPS: 864 functions at the true base vs 327 at 0. PPC: 1485 vs 1482. Cortex-M: 529 vs 510. | Verifies base only on absolute-call ISAs. |
| Wrapper magic? | `u-boot-sam460.bin` starts with uImage magic but its header CRC fails (stored `552d426f`, computed `203c9708`). Its last word is a PPC branch `4bfff004`; `bios.bin` has `EA` far-jump at end-16. | Validate wrappers by checksum; add "top-aligned" base candidates. |

Byte-column entropy at stride 4 and 2 is a free prior: ARMel
5.91/4.32/4.61/3.45, ARMeb mirrored, MIPSeb 3.86/6.00/3.47/5.90; x86, Z80,
8051, VAX flat.

## 1. Pipeline

Each stage emits hypotheses with evidence into one `Hypothesis{segments,
language, mode map, delta, base, offset, regions, score, evidence[]}` beam;
later stages can demote earlier choices.

1. **Container** (file → payloads). Intel HEX and S-record (reuse the
   in-flight loaders), uImage, TRX, UEFI FV, compression magics. Accept only
   if a checksum or length validates; otherwise keep it as a weak hint. A
   validated wrapper's load address is strong but overridable evidence.
2. **Segment map** (payload → typed extents). 4 KB windows classed as padding,
   high-entropy, text or code-like, plus the stride profile. Compressed
   extents are excluded from scoring and reported as regions.
3. **Processor family** (code-like extents → ranked family, endianness,
   width). Section 2.
4. **Mode and variant** (top families → language id plus mode map).
5. **Delta and base** (language plus image → `delta = base − offset`). Section
   3.
6. **Offset and regions**. Section 4.
7. **Verify**: budgeted discovery on the top 3 full hypotheses. Feedback: a
   base that raises absolute-call closure re-ranks languages; a language that
   wins only one extent splits the file into segments.

## 2. Processor identification

**Decision: decoder-driven, three tiers, with a small calibrated ranker over
decoder-derived features.** Rejected:
- A byte-statistics classifier on labelled data: it can't name variants or
  modes, gives no readable evidence, and the only labelled corpus is
  third-party and can't be committed.
- Decode-rate alone: measured useless.
- Full discovery on all languages: Z80 cost and false acceptance.

**Tier 0, priors (ms).** Stride profile orders candidates and proposes
endianness. File larger than the language's address space is a demotion. Never
a hard exclusion.

**Tier 1, sweep kernel.** New code on `Lifter::measure` and
`Lifter::lift_pcode(address, bytes)`, over about 16 windows of 4 KB from
code-like extents. One configuration per distinct `.sla` times decode mode:
135 `.sla` cover the 180 ids, and TMode, MIPS16, microMIPS and VLE are context
modes. Features per configuration:
- valid-byte fraction and resync rate;
- direct jumps landing on instruction starts vs into instruction middles;
- returns followed by padding or a call target;
- unimplemented and `CALLOTHER` rate;
- stack bracket from p-code: SP −k … SP +k … `RETURN`, with SP taken from the
  cspec; this is the prologue/epilogue idiom derived from the language's own
  semantics;
- call-target fan-in.

Each feature is normalised by the same language's value at wrong alignment and
on other extents, not by shuffled bytes. A logistic ranker over about 12
features gives the score. Cost: 64 KB decodes in under 0.2 s through rk-lift
including startup and JSON, so all 150 configurations fit in about 2 s on 8
threads in-process.

**Tier 2, budgeted discovery on the top 8.** Run `analysis` discovery
(`Discovery::run`, `search_starts`, `find_code`, `valid_subroutine` in
`src/analysis/search.cc`) under a hard instruction budget. Add pattern-free
seeds: Tier 1 call targets with fan-in ≥2. Score is coverage and call closure,
discounted by the language's chance acceptance measured on the non-code
extents of the same file.

**Variants.** Group languages by family. Decode the discovered code under each
sibling; instructions valid in A and invalid in B are the census. Choose the
smallest variant that decodes everything, and report ties as a group with a
documented default. Structural tie-breakers:
- Cortex-M: word 0 is a RAM-like SP and following words are odd in-image
  addresses.
- ARM vs Thumb: a per-region mode map from interworking flow
  (`ProgramInfo::isa_context`), reported as a mix, not a file-level choice.
- 16/32/64-bit x86, MIPS32/64, RV32/64: census of width-only instructions.

**None of these.** Refuse when the best Tier 2 score is below the calibrated
threshold, when under about 2 KB of code exists, or when the top two families
are within the margin. Example: `npcm8xx_bootrom.bin`, 672 bytes, ARMv7 0.387
vs AArch64 0.369. Report "unknown processor" with the closest three.

## 3. Base address

**Decision: delta voting over lifter-materialised pointers, plus structural
anchors, verified by closure.** Rejected: raw word scanning as the main source
(fails on split-immediate ISAs, measured) and brute-force rebasing with
discovery (insensitive on PC-relative ISAs, measured).

- **Pointers**: constants from flows (`data_refs`, `FlowGraph::literals`,
  `Evaluator` hi/lo pairs via `resolve_computed`) and runs of three or more
  pointer-like words in non-code. Words inside decoded code are excluded.
- **Targets**: string starts (`src/analysis/strings.cc`,
  `ngram_valid_string`), function starts from base-independent discovery, and
  jump-table entries.
- **Vote**: histogram of pointer − target file offset, counting each pointer
  and target once and collapsing arithmetic runs. I saw off-by-4/8 artefact
  peaks on Cortex-M from stride-4 tables. Significance is against a Poisson
  null from pointer density.
- **Anchors**: `lift::processor_symbols` entries, the Cortex-M vector table,
  reset vector at end of file (base = 2^N − size), validated wrapper fields.
- **Verification**: absolute-call closure where the ISA has it; agreement
  between PC-relative and absolute references to the same target.

Handling:
- **Several regions or RAM-copied code**: a second peak supported by a
  contiguous file extent becomes a second region with its own base.
- **Relative-offset peaks**: a wrapped delta whose implied image would
  straddle the top of the address space is labelled "relative offsets", not a
  base.
- **High bases**: all arithmetic is modulo the address width.
- **Sparse pointers**: fall back to anchors, else say "base undetermined; code
  is position-independent, analysis is largely unaffected".

**Precision**: exact to the byte, since votes are exact. Accept when two
independent target classes agree, or one class leads by ≥3x.

## 4. Header offset and regions, jointly with base

Voting determines only `delta = base − offset`; that is the quantity analysis
needs. Split it with:
- the code-start boundary from the segment map;
- the vector-table position;
- header self-description: a field equal to payload length, entry, delta, or a
  CRC of the remainder;
- a round-base prior.

So a 0x200 header at base 0 shows as delta = −0x200, and the split falls out.
Regions: materialised store and load addresses outside the image cluster into
suggested `ram` (written) and `mmio` (volatile) regions, emitted as
`RawRegion`s for `loader::parse_raw` ([Memory regions](#memory-regions) has
how).

## 5. Confidence

- Scores are isotonic-calibrated on the dev split into high, medium and low
  bands, per answer: processor, variant, base, offset.
- Evidence is plain sentences from the features, e.g. "1,220 strings; 140
  pointers land on string starts at base 0xbe000000, next best 54".
- Always return the top 3 alternatives.
- Refuse per answer, not all-or-nothing.

## 6. Evaluation

- **Metrics**: family+endianness top-1 and top-3; exact language id, or
  membership in the reported tie group; mode-map byte accuracy; base exact and
  within the reported delta; offset exact; refusal precision and recall on
  unknown ISAs; calibration error; time.
- **Train/dev**: only data revkit builds: `corpus/firmware` (23 images)
  rebuilt at alternative link addresses, with synthetic headers, padding and
  concatenation, plus `corpus/` ELF `.text` extractions. Wrong-language
  decodes give the negatives.
- **External dev**: half of the labelled ISA chunks, split by ISA name hash.
  Use them for family scoring and negatives only: they are unlinked (ARM call
  targets were 2% in range), so no base or linkage metrics.
- **Held-out**, run once per phase, summary rates only, under the
  `docs/heldout.md` policy: the other half of the chunks, `seed/qemu`
  (stripped ELFs give exact truth), `curated_samples.csv`, stripped Linux ARM
  ELFs, and the user's private images.
- **CI**: extend `scripts/ci.sh --firmware` with a detect gate on the kit:
  family+endianness 23/23, language-or-tie-group ≥22, base ≥21, a time
  ceiling, baselines in `corpus/baselines/detect-*.json`. In-repo fixtures are
  generated at test time: `src/analysis/tests/fixtures/armfw` plus header and
  offset variants. External sets go through `scripts/bench-detect.sh` with the
  path from an env var, skipped when absent, output under `build/`, nothing
  committed.

## 7. Integration

- **Library**: `src/detect/`, namespace `revkit::detect`, over loader, lift
  and analysis. Not a fact-store query: no program exists yet and hypotheses
  are transient images. Tier 2 uses a private `facts::Engine` per hypothesis;
  the accepted suggestion and its evidence are stored with the import
  (`ProgramSource::raw`, IMPORT provenance).
- **API** (done; [api.md](api.md#raw-layout-detection)):
  `ProjectService.DetectRawLayout(path or upload, hints, detect_id)`
  returning up to three `RawLayoutSuggestion{ImportOptions options;
  per-answer confidence; evidence[]; tie_group; language_pinned;
  region_details}` (each region with its kind, confidence and evidence), the
  refusal with its closest guesses, and the segment map
  (`src/backend/raw_detect.{h,cc}`). Progress (`GetRawDetectProgress`) and
  cancellation (`CancelRawDetect`, or a gRPC caller going away) follow the
  `GetImportProgress` pattern: per caller, kept five minutes. The library
  reports progress and is stopped through `detect::Options::progress` and
  `cancel`, called between stages and candidates. Hints: a language (only
  its processor is tried, and the suggestion covering it names it) or a
  processor. Limits: import's role (admin of the project), paths up to
  1 GiB, uploads within `max_request_bytes`, two detections at a time
  with eight queued. Not yet: the accepted suggestion and its evidence
  stored with the import.
- **SDKs** (done): Python `Client.detect_raw_layout` (progress callback,
  cancel event) and `import_program(options=...)`; TypeScript
  `detectRawLayout` (polls, aborts through `CancelRawDetect`); MCP
  `detect_raw_layout` (read-only; agents are told to rely on high
  confidence only and ask the user about the rest).
- **CLI**: `rk-lift --detect` prints JSON; `--lang auto`, `--base auto`,
  `--raw-offset auto` apply only at high confidence, else exit non-zero with
  alternatives.
- **Open dialog** (done; `ui/src/ui/open.ts`, `rawdetect.ts`;
  [ui.md](ui.md)): a file that isn't ELF or PE, or a raw import without a
  language, runs detection. Suggestions fill the raw fields as editable
  values with confidence chips, a "why" expander and an alternatives menu
  (tie group and other suggestions); each region a row with its own chip
  and evidence, pre-filled into the regions box; values the user typed stay; a
  refusal shows its reason and the guesses, none applied; progress on the
  import bar, and Skip detection. Nothing is imported automatically, at
  any confidence: the user chooses Import as raw.
- **Budget**: quick ≤3 s for ≤4 MB on 8 threads (tiers 0-1, anchors); full ≤30
  s (Tier 2, delta, verify); deterministic at any thread count; hard
  per-hypothesis instruction budget.

## 8. Phases (one agent each)

| Phase | Content | Gate | Size |
|---|---|---|---|
| P0 | Harness, truth format, splits, generated fixtures, `bench-detect.sh` | Baseline report runs, repo clean of external data | ~0.8k lines |
| P1 | Container, segment map, Tier 0/1 kernel, `rk-lift --detect` | Family+endianness: kit 23/23, external dev ≥85%, quick ≤3 s | ~2.5k |
| P2 | Tier 2 budget and chance discount, pattern-free seeds, variants and modes | Tie-group accuracy ≥90% dev; unknown-ISA refusal ≥90%; no hypothesis over budget | ~1.8k |
| P3 | Delta voting, anchors, offset split, regions | Base ≥21/23 kit; synthetic header variants ≥90% exact | ~2k |
| P4 | Calibration, RPC, Open dialog | UI test; calibration error ≤0.1 on dev | ~1.5k |
| P5 | Held-out run once, docs | Numbers published, no tuning afterwards | ~0.3k |

**Risks**
- Dense 8-bit ISAs accept anything; the chance-discount design is untested.
- Pattern-less languages have low Tier 2 recall.
- Loader limits found while testing: a 16-bit language can't load a file over
  64 KB or x86 real mode at 0xE0000; `ARM:LE:32:v4` fails with "Non-existent
  context variable: TMode"; AVR is word-addressed. Detection may name a
  language the loader can't load yet, and should say so.
- Wrong-language discovery has no time bound today (165 s on 32 KB), which
  also exposes the daemon.
- Compressed-majority images leave little code to score.

**Open questions**
- Should a detected-but-tied variant default to the newest or the smallest?
- Should banked 8051/HCS12 images be in scope for base detection?
- Is 30 s acceptable for the full pass in the Open dialog?
- May calibration weights trained on revkit-built data ship in the repo? I
  assume yes.

## Measuring it

Detection is scored on files whose answers are known, by scripts that only
see what the detector prints (`rk-lift --detect FILE`, a JSON report:
`scripts/detect_score.py` documents it).

- **The kit** (`scripts/detect_cases.py`, from `out/firmware-corpus`): every
  image as built, with a vendor header before it (one with length and
  checksum fields, one that says nothing), with fill after it, and with
  compressed data after it; plus files that are no program (random,
  compressed, text, fill, a table), which must be refused; near misses
  (code of a processor derived from a kit image's, which must not get a
  confident answer); and images built with clang from mcukit's sources:
  position-independent AArch64 and RISC-V, and Thumb code with no vector
  table ([Related processors](#related-processors-position-independent-bases-and-arm-variants)).
  137 cases, built where they are used.
- **External files** (`scripts/bench-detect.sh`): a manifest outside the
  repository lists real firmware and labelled code with what is known of
  each (`scripts/detect_external.py`). Code cut out of programs counts for
  the processor only (it has no layout); half of it, by name, is held out,
  as are all whole images, for a final run (`docs/heldout.md`).

The scorer reports, per group: the family, byte order and size right (top-1
and top-3), the language right or in the reported tie group, the base
exact, the image landing where it should (base minus offset), the offset
exact, refusals of what is no program, time, and **confident-wrong**: any
answer given at high confidence that is wrong. `--baseline` fails on any
rate below a saved one.

## Related processors, position-independent bases and ARM variants

A one-time held-out run (aggregate only) showed three weaknesses, fixed
here with the held-out set left untouched since; tuning used only the kit
and the dev split.

**Related processors.** Two samples of processors revkit has no language
for got a related one at high confidence: their code decodes and its
branches land, since a derived processor keeps its parent's branches. The
rest of its instruction set doesn't fit, and that is now checked for the
answer (`Fit`, `src/detect/fit.cc`) on the code control flow vouches for
(`Features::reached`: where relative branches and calls land on an
instruction, and the instructions after up to the next transfer):

- *Cut runs*: reached runs ending in bytes the language can't decode. Real
  code: at most 0.6% (kit, and every high answer of the dev split);
  derived processors' code 0.7-28%. From 2% (and 10 runs) the answer is at
  most medium; from 10% (and 50 runs) it is refused as unknown.
- *Rare mnemonics*: the share of reached instructions whose mnemonic is
  under 1 in 1000 of real code of the language (`profiles.inc`, generated
  by `scripts/detect_profiles.py` from the reached code of the kit, the
  clang-built images and the corpus's -O2 programs: ARM Thumb, 68000, MIPS,
  PowerPC, SuperH4, Xtensa 32-bit; AArch64, RISC-V, x86 64-bit). Real code
  compiled elsewhere (the dev split's chunks, leaving a codebase out of the
  kit's profile): at most 10%; derived processors' 24-66%. From 20% the
  answer is at most medium.

The evidence says "decodes like MIPS, but 37% of the code control flow
reaches uses instructions real MIPS code rarely has (36% of the same bytes
shuffled, under 10% of real code)". The kit's near misses
(`detect_cases.py`: a fixed permutation of MIPS, PowerPC and SuperH major
opcodes, the transfers' kept) were 6 of 11 at high confidence before, none
now.

**Position-independent bases.** Where code makes its addresses from the
program counter, the base comes from data:

- Pointer tables now keep running over small fields (a structure's other
  members, a relocation's type: under 0x10000, at most two in a row) and
  are read to the file's end; so `R_*_RELATIVE` tables left in a
  position-independent image vote with their addends.
- adrp's page made the trace take AArch64 addresses for absolute: what
  moves with the code is now tested by moving it 64 KiB, not 1 KiB. (This
  had placed a position-independent image at 0, at medium confidence.)
- Half addresses (movw before movt, lui or lis before the low half) are no
  longer pointers; they voted for a spurious base on Thumb-2 code.
- What follows an unconditional jump (a tail call) is a function start
  candidate, as what follows a return was.
- Code that relocates itself compares where it runs with where it was
  linked (an address made from the program counter against a constant,
  `Trace::anchors`); one that agrees with the votes makes the base high
  confidence. Alone they don't place an image: code also compares where it
  is with where a copy ends (SH-4 U-Boot's two such comparisons are 8 KiB
  off).
- Where the variant's address size differs from the candidate the sweep
  chose (RV32 standing for RV64), the image is placed again with the
  variant's pointers.

Conventional bases (OpenSBI's 0x80000000 and the like) are not guessed.

**ARM variants.** Ghidra's v4t decodes a Thumb-2 instruction's halves as
two Thumb instructions, so bytes decoded don't tell Thumb-2 from Thumb, and
the variants were ranked by how much shuffled data they decode, which in
Thumb doesn't follow the architecture. Now ARM variants rank by version
(v4t < v5t < v6 < v7 < v8), and in Thumb a census of the reached code
counts Thumb-2: 32-bit instructions other than bl/blx, IT and cbz/cbnz.
At least half the rate of the shuffled bytes means Thumb-2 (Thumb-2 code:
19-31% against 9-10%; Thumb code: 0%), which v4t and v5t lack; and v7
comes before Ghidra's v6, which has ARMv6T2's Thumb-2 though of the ARMv6
cores only the ARM1156T2 does. Cortex-M images with their vector table stay
`Cortex`.

**Numbers.** Kit, the 115 cases it had: unchanged (family 115, language
115, variant 105, base 109, offset 112, confident-wrong 0). The 22 new: near
misses 11/11 unconfident (6 high before); position-independent 4/4 base,
language and variant (before: base at 0 or undetermined); Thumb 2/2
variant (v6 for both before) and base. Dev split (43): refusals of
no-decoder processors 24/24 (23 before: VAX had been MCS96 at medium),
family 18/19 and answered 11/19 as before, confident-wrong 0, the six right
high answers still high (ARMhf now v7, was v6).

## Permissive instruction sets, 8-bit code, RV32 and aliased images

A second held-out corpus of public firmware (36 families, 478 images,
split by name hash: a dev half tuned on, a test half scored once by the
lead) showed, on its first run: PIC-17 as the top answer for a fifth of
the images, of which it had none; 8-bit families mostly wrong or refused;
RV32 code answered RV64 with high confidence; images seen through two
buses placed at the data bus's address; load addresses right for a third;
and detections running into the 300 s timeout. Changes, each from what the
instruction sets do (the test half untouched):

- **Fill isn't code.** Runs of 8 or more bytes of one value are skipped by
  the sweep. PIC-17 decodes 0xffff as a return; a return followed by fill
  was evidence against shuffled bytes, which have no runs. That was the
  shuffled baseline's blind spot: it models random bytes, not structure.
- **Permissive instruction sets are judged off their alignment.** A
  candidate whose instructions are aligned (2 or 4 bytes) is also swept a
  byte (or a halfword) along, and what it finds there is taken off its
  evidence, kind by kind. Another processor's byte-oriented code and its
  data keep their structure off the alignment; the candidate's own code
  doesn't. PIC-17 makes calls and jumps of a quarter of all words (pointer
  tables into RAM, an 8-bit processor's instruction idioms), and shuffled
  bytes can't show that.
- **Absolute jumps say something whatever the base.** Two absolute jumps
  in a row, in code, lie about as far from their targets (target − place is
  base − offset, give or take a function); by chance they agree as often
  as random addresses do. Runs of absolute transfers (address tables,
  vectors spread out with fill) don't count, nor two jumps to one target
  (another processor's idiom repeated nearby). This is its own kind of
  evidence: 8-bit code had little else (Z80's `jp`, the 8085's every jump,
  6502 `jmp`).
- **Jumps within a page.** PIC's GOTO and CALL hold 11 (PIC16) or 9
  (PIC12) bits and a page register the rest, which p-code makes a computed
  jump: PIC16 code showed no transfers at all. The p-code is evaluated with
  every register all zeros and all ones; a target whose low 8 or more bits
  agree is a jump within the page the instruction is in, and votes on those
  bits for the base.
- **Code mixed with data.** Each kind of evidence assumed the windows were
  code; an 8-bit game is mostly graphics, and its real branches came out as
  evidence against. Each kind now takes the best of its full, half and
  quarter rate beyond chance, less log 3 for the choice.
- **Subset processors.** Code that uses nothing of a larger instruction
  set is the smaller's: the 8085 (8080) in Z80 and Z180 answers, the 6502
  in 65C02, the 6809 in HD6309, HC08 and 6805 in HCS08, HC12 in HCS12, the
  8051 in 80251 and DS80C390. They join the variant choice, which takes the
  least capable that decodes the code as fully.
- **RV32 or RV64 from the stack.** The two share the 32-bit instructions
  but for a few, and each decodes most of the other's compressed ones
  (RV32's `c.jal` is RV64's `c.addiw`, its `c.flwsp` RV64's `c.ldsp`).
  Functions save registers in slots of the register size: `c.sdsp` and
  `c.ldsp` against `c.swsp` and `c.lwsp` in the code control flow reaches
  (at least 20, one kind twice the other) decide.
- **Aliased images.** Where strings and function starts both stand out at
  different differences, the image is mapped twice (the ESP chips'
  instruction and data buses): strings are named at the data bus's
  address, functions at the instruction bus's. The base is the functions',
  at most medium, and the evidence names the other.
- **Two kinds agreeing.** Strings and function starts both ahead (each
  twice its runner-up, 12 together) at one difference place the image, at
  medium: small and 8-bit programs name few of either.
- **Function ends.** A conditional return (Z80's `ret nz`) or a predicated
  jump ends no function; an unconditional absolute jump does.
- **Refused answers keep their layout.** A refused processor's best guess
  still gets its variant, base, offset and regions, at most medium
  confidence: the user may know the processor.
- **The timeouts** were a loop: a RAM cluster below the region floor had a
  wrapped size, and rounding it up to a power of two doubled past 2^63 to
  zero. Such a cluster now makes no region, and the rounding stops.

**Numbers, dev half** (215 images; load and offset over the 209 with a
known layout; 8-bit: 6502, 6805, 6809, 8048, 8051, 8085, Z80, HC08, HC12,
PIC-12/16/18, MCS96, M8C, AVR8 and CP1600):

| | first run | now |
|---|---|---|
| family, top-1 | 144 | 188 |
| family, top-3 | 181 | 194 |
| load address (base − offset) | 74 | 105 |
| offset | 125 | 167 |
| confident-wrong | 3 | 1 |
| errors (timeouts) | 4 | 0 |
| PIC-17 the top answer | 43 | 0 |

| group | images | family | top-3 | load | offset |
|---|---|---|---|---|---|
| 8-bit | 87 | 35 → 68 | 63 → 73 | 7 → 22 | 32 → 64 |
| 16-bit (MSP430, M16C, PIC24, x86 boot code) | 17 | 11 → 14 | 14 → 14 | 4 → 7 | 11 → 14 |
| 32 and 64-bit | 111 | 98 → 106 | 104 → 107 | 63 → 76 | 82 → 89 |

The confident-wrong left is a base: an image whose truth is its physical
load address while its code names its link address. The kit is unchanged
or better (base 115 → 116, offset 118 → 119, regions found 69 → 70 of 70,
confident-wrong 0); its time per case went from about 5 s to 6 s (p50),
the second sweep of aligned candidates.

Still weak: banked 8-bit images larger than the address space (no one
base fits); MCS96 and 8048 (few, small samples); 16-bit x86 boot sectors
(under 300 instructions); and processors whose foreign structure another
candidate reads as branches (a narrow word's zero top bits are short
forward branches to the 68000).

## Memory regions

A raw image's code uses memory beyond its own bytes: RAM (uninitialized,
read and written) and devices' registers (MMIO, volatile). Detection
suggests both next to the processor, base and offset, as `--region`
strings (`ram:20000000:40000`, `mmio:40010000:1000:rw-:volatile`) with a
kind, a confidence and evidence each (`Suggestion::region_details`,
`RegionSuggestion`; `region_details` in `rk-lift --detect`'s JSON).
`Suggestion::regions` lists the RAM and MMIO ones, ready to apply; a
cluster that can't be classified is shown (kind `unknown`, low
confidence) but not listed there.

**Provenance:** the design is from a clean-room design consult (first
principles and measurements on the corpus with revkit's own trace), with
no other tool's region or base-finding code as an input.

### What it is inferred from

`Sweeper::trace()` decodes the code-like part of the file, follows
constants through straight-line code and literal pools, and records for
region inference (`Trace::memory`, `stack_values`, `back_jumps`,
`setups`):

- **Loads and stores at addresses the code names**, with width, direction,
  the stored constant when known, the instruction's place, and the
  constant the address was made from by adding a small offset (its
  *base*: a device's register block, a structure).
- **Constants put in the stack pointer**, and on Cortex-M the vector
  table's word 0 (when word 1 is an odd address in the image). Startup
  code near either end of the image counts: padding-classed stretches
  there (vectors spread out with fill) are traced too
  (`startup_windows`). The top of RAM, exactly.
- **The startup copy and clear**: where control leaves straight-line code
  (a call, a jump), the constants registers hold. A destination outside the
  image, a source in it, and a length (memcpy's arguments) or an end (a copy
  loop's) such that the copy takes the image's last bytes is the copy of
  initial data to the start of RAM; a clear (a zero and a range) starting
  where it ends is `.bss`. The start of RAM, exactly.
- **Short loops** (a jump back at most 32 bytes): a load in one that stores
  nothing is polling.

`memory_facts` turns these into per-address uses at the detected base
(only outside the image), and `regions()` (`src/detect/regions.cc`) into
regions:

1. **Filter and fold.** Accesses below 64 KiB, or in the top 64 KiB unless
   reached from a round base there, are small numbers, not addresses
   (32-bit spaces); misaligned ones, ones made from all-printable words,
   and one instruction moving more than two words (`stmw`, `ldm`) are bytes
   or block moves, not variables or registers. Aliases fold: Cortex-M
   bit-band words to their word, MIPS kseg0/kseg1 and SH-4 P1/P2 by
   physical address (the image's own alias is dropped and said).
2. **Architectural maps**, priors and boundaries only: Cortex-M's fixed map
   (code, SRAM, peripheral, external RAM and device, private peripheral
   bus, vendor), when the vector table says Cortex-M; MIPS32 kseg windows;
   SH-4 P0-P4; the ESP chips' data and instruction buses for Xtensa.
   PowerPC and 68k have none. Accesses in a code window make no region.
3. **Clusters**: accesses within 64 KiB of each other in one window. Kept
   with three addresses used from three 256-byte stretches of the code, or
   eight addresses by eight instructions, or an anchor (the stack, the
   startup copy).
4. **The stack's top** joins the nearest cluster below it in its window
   (within 64 KiB; or within 16 MiB if that cluster is RAM by its own
   evidence or the window is RAM's), never across the image or into a
   device; alone it makes RAM of its own when it's the only candidate.
5. **Classification.** RAM: the stack or the startup copy (decisive), or
   40+ addresses of several widths. MMIO: a register block (a few bases,
   each with its registers within a page above it, 70% words or all
   bytes), stores of constants (half of the stores or more), polling, or a
   device window. In a RAM window only a register block written with
   constants or polled is a device (RAM is written with constants, and
   volatile variables are polled). Else unknown.
6. **Sizes.** MMIO: the hull in 4 KiB pages; clusters of one window with
   nothing else between, within 16 MiB, one block. RAM: from its lowest
   address (or the copy's destination) down to 64 KiB, up to the stack and
   every access, to a size RAM comes in (a power of two, or one and a half),
   short of the next region, the image and the window's end. The evidence
   says which rounding applied. In address spaces under 32 bits the gap,
   the pages and the 16 MiB scale with the space (a 64 KiB space: 256
   bytes). No region covers the image where it will load: at its base, or
   at 0 where the base is unknown (where an import without one puts it);
   one that does is cut to the side with more of its accesses, or dropped.
   Nor does one span over a quarter of the space (bar RAM the stack or a
   startup copy places): scattered accesses are no one memory. (A 6502
   code sample with its base unknown had been given `mmio:0:10000`, all of
   its space, which the import then refused over the image at 0.)
7. **Confidence.** High: two kinds of evidence agree (RAM: the stack, the
   copy, many variables; not in a device window. MMIO: two of register
   block, constants, polling, device window, from ten accesses or more).
   Medium: one. Unknown is low. Without a base, at most medium. The
   evidence ends with the reason ("high: 2 kinds of evidence agree",
   "medium: where the image loads is unknown").

Small processors' specs declare their I/O registers volatile
(`lift::processor_volatile_ranges`: avr8, 8051, PIC, MSP430, HCS08...);
they are in other spaces than the image's, and analysis knows them
already: the evidence says so instead of a region.

### Truth and numbers

`scripts/detect_cases.py` carries each image's regions into `cases.json`:
the manifest's (fwkit: its linker script and board), plus
`corpus/firmware/regions-truth.json`, which names a source per entry:
Cortex-M's System Control Space (fwkit's fault handler and the FreeRTOS
port use it; the manifest omits it), and for U-Boot, whose regions the
corpus doesn't list, windows of the boards' memory maps from the chips'
and boards' manuals (`regions_partial`), scored for found and false only.
`scripts/detect_score.py` reports per true region found (a suggestion of
the kind overlaps it), start covered, RAM's last word covered (where the
stack starts), size within 2x; windows found; false regions per kind
(overlapping no true region or window of the kind); and region
confident-wrong (a false region at high confidence), which counts in
confident-wrong.

The kit (120 cases; 70 with exact truth, from 14 fwkit images, and 45 with
board windows, from 9 U-Boot images):

| | RAM | MMIO |
|---|---|---|
| exact truth: found, start, size within 2x | 69/70 | 69/70 |
| RAM's last word covered | 69/70 | |
| board windows found (U-Boot) | 35/45 | 40/45 |
| false | 0 | 0 |
| confident-wrong | 0 | 0 |

Per processor, exact truth found for every fwkit case of Cortex-M, 68k,
MIPS, PowerPC and Xtensa; the one SH-4 miss is a case whose processor is
refused (no suggestion). Of the U-Boot windows: Malta finds its GT-64120
and PCI windows, the ColdFire and STM32 boards their SRAM from the stack;
the MPC837x and r2d+ boards keep their first stack in cache or set it
where the trace doesn't follow, so no RAM, and SH-4's U-Boot has no base.

Instructions read as words: data decoded as code holds loads from the
program counter that land in code, and the word they read is an
instruction (ARM's `mov r0, #0` is 0xe3a00000, a `blx` 0xfa0fa000): an
address at the top of the space. The trace marks words read as literals
from code that a branch lands in and runs through (`Trace::code_words`;
not a word also read from a pool past a return), and an address made only
from them is left out, with evidence saying how many. The kit's region
numbers are unchanged.

Limits: variables reached only through a register the trace can't follow
(U-Boot's `gd`, relocated code) are invisible; a device in the top 64 KiB
reached without a round base is missed; RAM a program copies its code to
is not yet a region of its own.

**Next (not done):** a full pass over budgeted discovery, once Tier 2
lands: load the image with the complement of the image mapped as two
uninitialized probe regions (`parse_raw` accepts them), so
`FlowGraph::data_refs` keeps accesses outside the image
(`Consts::memory()` requires `is_mapped`), and merge them into the trace's
accesses: bases kept across branches and calls, and function-level loops.
And an analysis-equivalence metric: `--analyze` under suggested and true
regions, comparing functions and data references.

## Files to build on

- `src/analysis/search.cc`: `Discovery::run`, `search_starts`, `find_code`,
  `valid_subroutine`.
- `src/lift/include/revkit/lift/lifter.hh`: `Lifter::measure`,
  `Lifter::lift_pcode(address, bytes)`.
- `src/loader/raw.cc`: `RawOptions`, `RawRegion`, `parse_raw`.
- `proto/revkit/v1/project.proto`: `ImportOptions`, the import progress
  pattern.
- `scripts/firmware_score.py` and `corpus/firmware`: the kit and its truth.

### Second held-out set: the test half (2026-10-08)

Scored once, after the dev-half work above landed (master 8d7b00c), on the
263 cases of the second held-out corpus's test half, which no tuning run
opened. The first run is master a51a6a3 on the same cases, judged by the
same scorer. Before the dev-half work, the lead had seen aggregate failure
patterns over the whole corpus (the PIC-17 answers, RV32 answered as RV64,
ESP alias bases), so the half is held out from tuning, not from those
summaries.

| | first run | after |
| --- | --- | --- |
| family, top-1 | 180/261 | 221/261 |
| family, top-3 | 214/261 | 236/261 |
| load address | 99/252 | 146/252 |
| offset | 156/252 | 194/252 |
| confident and wrong | 9 | 3 |
| errors (timeouts) | 2 | 0 |
| 8-bit group: family | 34/93 | 68/93 |
| 8-bit group: load address | 8/91 | 33/91 |

PIC-17 is no longer anyone's top answer (it was for 88 of the corpus's 478
cases). The three confident and wrong answers left are bases: an MSP430X
image placed at a 64 KiB boundary, an ESP RISC-V ROM at its data-bus alias,
and a PIC32 image at its kernel-segment alias (a case whose truth is marked
uncertain). The test half is now spent.
