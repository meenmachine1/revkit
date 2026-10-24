# Upstream notes

Each patch in `patches/` is written to be offered to Ghidra
(NationalSecurityAgency/ghidra) as it is: its commit message is the
description, its repro is the savefile in `repro/`, and the version is the
pristine release, Ghidra 12.1.4. Ghidra's own decompiler fails the same
way on every crash below (its export of the held-out corpus reports
"Decompiler process died" on those functions), so none of them is
revkit-specific. **Nothing has been submitted yet.**

To submit one: `fork.sh unpack` gives a git history in Ghidra's layout, so
`git format-patch`/cherry-pick onto upstream `master` (or attach the patch);
open an issue with the description and the repro XML (upstream replays it
with `decomp_dbg`: `restore`, `load function`, `decompile`). Record the
issue or PR here, and drop the patch from the series once a release
carries the fix.

| Patch | Kind | Status |
| --- | --- | --- |
| [0001](patches/0001-Decompiler-fail-cleanly-when-an-INDIRECT-s-effect-op.patch) `Merge::snipReads` / `trimOpOutput` on a dead INDIRECT effect op | defensive | not submitted |
| [0002](patches/0002-Decompiler-fail-cleanly-when-a-bitfield-pull-s-readi.patch) `BitFieldPullTransform::apply` on a dead read op | defensive | not submitted |
| [0003](patches/0003-Decompiler-fail-cleanly-instead-of-dividing-by-zero-.patch) `SplitDatatype::buildPointers` divides by a zero size | defensive | not submitted |
| [0004](patches/0004-Decompiler-leave-a-LOAD-or-STORE-whose-constant-addr.patch) `RuleLoadVarnode` / `RuleStoreVarnode` on a constant address range that would wrap | algorithmic (only functions that failed change) | not submitted |
| [0005](patches/0005-SLEIGH-fail-cleanly-when-an-instruction-nests-more-o.patch) `ParserContext::allocateOperand` past the fixed pool of constructor states | defensive | not submitted |
| [0006](patches/0006-SLEIGH-expose-a-Constructor-s-print-pieces-and-conte.patch) `Constructor` print pieces and context changes, `ContextOp`/`ContextCommit` fields | accessors (no behaviour change) | not submitted |
| [0007](patches/0007-SLEIGH-expose-the-decision-tree-s-constructor-patter.patch) `SubtableSymbol`'s decision tree, `DecisionNode` pairs and children | accessors (no behaviour change) | not submitted |
| [0008](patches/0008-SLEIGH-expose-operand-fields-and-attached-symbol-tab.patch) `TokenField`/`ContextField` layout, `OperandValue` index, name/value/varnode tables | accessors (no behaviour change) | not submitted |
| [0011](patches/0011-SLEIGH-expose-a-decision-node-s-field.patch) `DecisionNode` field (context or instruction bits, start, size) | accessors (no behaviour change) | not submitted |
| [0012](patches/0012-Decompiler-an-option-to-type-a-loaded-value-by-its-i.patch) option `extensiontypes`: a LOAD typed by its instruction's sign or zero extension | option, off by default | not submitted |
| [0013](patches/0013-Decompiler-an-option-to-print-comparisons-with-the-c.patch) option `encodedcompare`: comparisons with the constant on the right, and the constant the instruction encodes | option, off by default | not submitted |
| [0014](patches/0014-Decompiler-an-option-to-fold-a-signed-flag-test-of-a.patch) option `flagcompare`: `RuleFlagResultCompare`, a decrement's signed flag test as one comparison | option, off by default | not submitted |
| [0015](patches/0015-Decompiler-an-option-to-print-only-C-a-compiler-acce.patch) option `compilablec`: lvalues for unnamed bytes, statements after labels, pointer/integer casts | option, off by default | not submitted |
| (none) `jsR_run` never finishes: `RulePtrArith`/`RulePtrsubUndo` cycle | issue only | not submitted |

## 0001: segfault in `Merge::snipReads` (via `Funcdata::opInsertAfter`)

- **Fails:** SIGSEGV in `Funcdata::opInsertAfter` (`funcdata_op.cc`)
  from `Merge::snipReads` (`merge.cc:472`), in `ActionMergeRequired`.
- **Cause:** the INDIRECT's effect op is dead. A 16-byte `movaps` STORE
  to the stack became a COPY (`RuleStoreVarnode`), keeping its INDIRECTs;
  `RuleSplitCopy` (cleanup pool) splits the COPY and destroys it, and no
  `RuleIndirectCollapse` runs after the cleanup pool to drop the INDIRECTs.
  `snipReads` then inserts after the dead op, whose parent block is null.
- **Patch:** throw `LowlevelError` when the effect op is dead, in
  `snipReads` and the same pattern in `trimOpOutput`.
- **Better fix, for upstream to judge:** have `SplitDatatype::splitCopy`
  keep the original COPY object as one of the pieces when it is an
  INDIRECT source, as `splitStore` already does for STOREs ("Preserve
  original STORE object, so that INDIRECT references are still valid").
- **Seen on:** Mbed TLS 3.6.2 self-test, x86-64 gcc -O2 debug,
  `mbedtls_aria_self_test`.
- **Repro:** `repro/0001-mbedtls_aria_self_test.xml` (Ghidra's debug
  capture, 50 KB).

## 0002: segfault in `BitFieldPullTransform::applyRecord`

- **Fails:** SIGSEGV in `Varnode::eraseDescend` from
  `Funcdata::opSetInput` in `BitFieldPullTransform::applyRecord`
  (`bitfield.cc:1450`), under `RuleBitFieldIn`.
- **Cause:** an earlier `PullRecord`'s `applyRecord` destroyed (via
  `opDestroyRecursive`) the INT_AND that a later record reads.
  `getSlot` on the dead op doesn't find the varnode and returns
  `numInput()`; `opSetInput` reads past the inputs.
- **Patch:** in `apply()`, throw `LowlevelError` when a record's `readOp`
  is dead.
- **Better fix, for upstream to judge:** skip such a record (the read it
  would rewrite no longer exists), or don't let one record's cleanup
  destroy ops other records still name.
- **Seen on:** tcc 0.9.27 `struct_decl` (bitfield structs from DWARF/PDB),
  debug builds for x86-64 clang -O2, AArch64 gcc -O2 and Windows x86-64
  clang -O2.
- **Repro:** `repro/0002-struct_decl-{x86_64,aarch64,pe}.xml`.

## 0003: SIGFPE in `SplitDatatype::buildPointers`

- **Fails:** SIGFPE (`curOff % tmpType->getSize()`, `subflow.cc:2631`)
  under `RuleSplitStore` (also reachable from `RuleSplitLoad`).
- **Cause:** `RootPointer::backUpPointer` accepts a pointer to any struct
  as the root, including an incomplete struct of size 0 (`<type
  size="0" metatype="struct">` still decodes, "the old way to indicate an
  incomplete structure"). `buildPointers` then takes size 0 as an array
  stride. An array of zero-size elements divides by zero a few lines on.
- **Patch:** throw `LowlevelError` before either division.
- **Better fix, for upstream to judge:** don't back up to a pointer to a
  zero-size type in `backUpPointer`, so the split proceeds from the last
  sized pointer.
- **Seen when** a client (revkit's prototype inference) passed an opaque
  library struct (`struct __jmp_buf_tag *`) as an incomplete size-0
  struct. Ghidra's Java side never sends size 0 (an empty structure is
  encoded with size 1), so through Ghidra this needs a savefile or
  another client. (revkit keeps sending size 0: giving such structs
  size 1 changed its inference results.)
- **Repro:** `repro/0003-storeopaque.xml` (10 KB, made with the console;
  its header comment says how): `add rdi,0x18; mov qword [rdi],0; ret`.

## Not patched: `jsR_run` never finishes (timeout only)

- **Fails:** MuJS 1.3.5 `jsR_run` (the bytecode interpreter), x86-64
  clang -O2 debug, at 0x145930: the decompiler runs until killed, at
  constant memory (Ghidra times out too).
- **Cause:** an oscillation in the `mainloop` action group:
  `RulePtrArith` turns an INT_ADD (at 0x147baf) into PTRADD/PTRSUB and
  `RulePtrsubUndo` undoes it, so every pass changes something and
  `mainloop` (repeat until no change) never ends. More than 1500 passes in
  60 s.
- **Why no bound:** a cap on `rule_repeatapply` passes would be the
  defensive patch, but no cap is both safe and useful. On the corpus,
  `mainloop` normally ends within 17 passes (tuning corpus: 14), yet one
  held-out function (Mbed TLS RISC-V gcc -O2 stripped, 0x1135d6, also
  decompiled through its thunk at 0x116f3c) cycles the same rules, plus
  `RulePushPtr`, for 124,968 passes (about 10 s) and then finishes; Ghidra
  decompiles it too. A cap below that breaks it; a cap above it lets
  `jsR_run` run for over an hour. So a deadline contains this one:
  revkit's in-process `DecompileBudget` (`rk-lift --timeout 30` stops
  `jsR_run` after 30 s and decompiles the other 704 functions of the
  binary), and the out-of-process worker's deadline.
- **Repro:** `repro/hang-jsR_run.xml` (Ghidra's debug capture; no `.expect`,
  so not a CTest: it runs until killed).
- **To report:** an issue with the repro and the rule pair.

## 0004: "Trying to construct memory range beyond end of address space"

- **Fails:** the function doesn't decompile: `LowlevelError` from
  `AddrSpaceManager::constructWrappingAddress` (`translate.cc`) via
  `Funcdata::newVarnodeOut` (`funcdata_varnode.cc:113`) in
  `RuleStoreVarnode::applyOp` (and the same through `newVarnode` in
  `RuleLoadVarnode`).
- **Cause:** a LOAD or STORE through a constant pointer becomes a COPY of
  a varnode at that address; within size bytes of the top of `ram` (which
  doesn't allow wrapped ranges) that varnode can't exist. The constant
  comes from folding a read-only pointer slot holding 0xffffffff (erased
  flash in firmware).
- **Patch:** both rules leave the LOAD or STORE alone in exactly that case
  (the range isn't valid in a heritaged space without wrapping), so the
  function decompiles with the access through the pointer. Only functions
  that failed before change.
- **Seen on:** an ARM v4t camera firmware loaded raw with its image
  read-only (six functions); the repro is a synthetic image
  (`src/analysis/tests/fixtures/armfw`, `poke_bad_slot`), captured with
  `ghidra_debug_xml.py --raw ARM:LE:32:v4t --read-only`; Ghidra 12.1.4's
  own decompiler fails the same way on it.
- **Repro:** `repro/0004-store-wraps.xml` (6 KB).

## 0005: SLEIGH writes past its parser state on deeply nested non-code bytes

- **Fails:** the process crashes (SIGSEGV, or silent heap or stack
  corruption) in `ParserContext::allocateOperand` (`context.hh`) via
  `Sleigh::resolve` (`sleigh.cc`) while disassembling: from
  `Sleigh::instructionLength`, `oneInstruction`, `printAssembly`.
- **Cause:** every `ParserContext` holds a fixed pool of 75 `ConstructState`s
  of 20 operands (`DisassemblyCache` initializes them with
  `initialize(75,20,...)`), and `ParserWalker` a 32-entry breadcrumb path.
  `allocateOperand` indexes both without a bound. Bytes that are not code
  can decode through a constructor tree deeper than that, and so can a
  register list the language decodes by recursion: ARM v7/v8 `VLDM`/`VSTM`
  with more than about 24 single-precision registers needs 77 states.
- **Patch:** throw `BadDataError` when the pool, the path or the operand
  slots would overflow, as the parser already does for an instruction
  longer than 16 bytes. The caller treats the bytes as undecodable. Only
  inputs that crashed before change.
- **Better fix, for upstream to judge:** size the pool from the language
  (the SLEIGH compiler knows the deepest tree) or grow it, so that the
  valid long lists decode as the Java SLEIGH decodes them.
- **Seen on:** compressed data inside a raw ARMv7 firmware image
  (`ARM:LE:32:v7`), during function-start search; and the processor sweep
  (`scripts/processor_sweep.py`), every language over random bytes:
  `ARM:LE:32:v8` and five other ARM v7/v8 variants, `JVM:BE:32:default`,
  `NDS32:LE/BE:32:default`, `V850:LE:32:v850e3v5`. Ghidra 12.1.4.
- **Repro:** the instruction word `0x0d6d6a3e` decoded as `ARM:LE:32:v7`:
  `Lift.ArmBytesNestingTooDeepAreBadData` (`src/lift/tests/lift_test.cc`);
  and `repro/0005-deeplist.xml` (12 KB, written with the console:
  `1c 9a ab 4c`, `vldmiami r11!,{s19 ...}`, then `bx lr`), which decompiles
  to `halt_baddata()`.
- **To report:** an issue with the word and the language.

## 0006, 0007, 0008: read access to SLEIGH's tables for an assembler

- **Need:** revkit's SLEIGH-inverting assembler (`src/asm`,
  [docs/patching.md](../../docs/patching.md)) builds its grammar and
  solves operands from a loaded `.sla`, as Ghidra's Java assembler does
  from Java's SLEIGH classes, which expose all of this. In C++ the data is
  private: a constructor's display pieces and context operations (0006),
  the decision tree's (pattern, constructor) pairs, which are the only
  place a loaded `.sla` keeps constructor patterns (0007), and token and
  context field layouts, the operand an `OperandValue` names, and the
  tables attached to fields (0008). `TokenField::genPattern` can't stand in
  for the layout: a decoded `TokenField` has no `Token`.
- **Patches:** read-only accessors only; nothing else changes.
- **Repro:** no decompiler savefile (nothing fails without them): the
  assembler's tests (`src/asm/tests`) and its round-trip gate
  (`scripts/asm_roundtrip.py`) are what need them.
- **To offer upstream:** as one change "expose SLEIGH tables to C++
  clients", with the assembler as the motivating user.

## 0009: SLEIGH reads a dead walker when a delay-slot instruction is unimplemented

- **Fails:** the process crashes (SIGSEGV) in `Address::printRaw` via the
  `UnimplError` handler of `Sleigh::oneInstruction` (`sleigh.cc`), or the
  error's text is garbage.
- **Cause:** `SleighBuilder::delaySlot` points the builder's walker at a
  `ParserWalker` on its own stack while it builds the delay-slot
  instruction, and restores it only on the normal path. When that build
  throws `UnimplError`, the handler asks the builder for its current walker
  and gets the one whose frame has unwound.
- **Patch:** restore the walker (and the unique offset) before rethrowing.
  `SleighBuilder::appendCrossBuild` has the same shape (a walker on its
  stack for the instruction it weaves in) and gets the same fix, though no
  input was seen to reach it. Only inputs that read freed stack before
  change.
- **Seen on:** Thumb code swept as SPARC while detecting a raw image's
  processor; Ghidra 12.1.4.
- **Repro:** the words `38b510b3 a1b1144c` decoded as `sparc:BE:32:default`
  at 0x3a10 (an annulled branch with an unimplemented instruction in its
  delay slot): `Lift.UnimplementedDelaySlotIsUnimplemented`
  (`src/lift/tests/lift_test.cc`), which fails under ASan without the
  patch. It is a disassembly crash, so it has no decompiler savefile.
- **To report:** an issue with the words and the language.


## 0010: SLEIGH reads an operand handle that was never set

- **Fails:** the process crashes (SIGSEGV) in
  `SleighBuilder::generateLocation` (`sleigh.cc`), building p-code for
  microMIPS `bc2f` or `bc2t` (`MIPS:LE:32:micro` and the other microMIPS
  languages, `ISA_MODE` 1).
- **Cause:** two things meet.
  - **Spec:** the constructor uses an operand for its value
    (`getCopCondition(2:1, COP2CC)`, `mipsmicro.sinc`), but `COP2CC`'s
    constructors export nothing (`COP2CC: is mic_cc=0 {}`). They exist for
    display only.
  - **Engine:** `Sleigh::resolveHandles` sets an operand's handle only when
    its constructor exports, and `ParserContext` reuses its pool of
    `ConstructState`s, so the handle holds whatever an earlier instruction
    left there, or uninitialized memory. `ConstTpl::fixSpace` returns that
    space pointer and the builder dereferences it.
- **Patch:** clear a state's handle when it is allocated (and the root's
  when the state is reset). Throw `UnimplError` where a varnode's space
  would come from a handle that was never set. Such instructions are
  unimplemented; nothing else changes.
- **Spec fix (not applied; revkit uses the install's compiled specs):**
  `COP2CC` should export its value, e.g.
  `COP2CC: is mic_cc=0 { export 0:1; }` and
  `COP2CC: val", " is mic_cc [ val = mic_cc << 0; ] { export *[const]:1 val; }`.
- **Seen on:** SuperH code swept as microMIPS while detecting a raw
  image's processor; Ghidra 12.1.4.
- **Repro:** the words `8c42 00a0` decoded as `MIPS:LE:32:micro` with
  `ISA_MODE` 1 at 0x1000: `Lift.OperandThatExportsNothingIsUnimplemented`
  (`src/lift/tests/lift_test.cc`).
- **To report:** two issues: the spec, and the engine's unchecked handle.

## 0011: read access to a decision node's field, for Function ID

- **Need:** revkit's Function ID ([docs/fid.md](../../docs/fid.md)) hashes
  instructions with the masks Ghidra's Java disassembler reports
  (`SleighDebugLogger`): each `DecisionNode` on the way to a constructor
  adds the bits it decides on. The C++ node keeps its field private.
- **Patch:** `DecisionNode::isContextDecision`, `getStartBit`, `getBitSize`;
  read-only accessors, nothing else changes.
- **Repro:** none (nothing fails without it); `fid_hash_test` covers the
  masks against Ghidra's.

## 0012-0015: the source-shape options

Each adds an option, off by default, so Ghidra's output is unchanged
unless it is set; their commit messages say what each shows, why, and the
patch. revkit turns them on for its own inputs
([docs/decompiler-inputs.md](../../docs/decompiler-inputs.md#source-shape)),
measured against the original source in
[docs/decomp-quality.md](../../docs/decomp-quality.md#source-shape-2026-10-21).

- **Need:** a matching decompilation (C rewritten until it compiles to the
  same bytes, here a Nintendo DS game built with Metrowerks CodeWarrior)
  hand-fixed the same things in bulk: load signedness that doesn't follow
  `ldrh`/`ldrsh`, comparison constants shifted by one (`x < 1` for the
  instruction's `x <= 0`), byte-count loop guards as two tests, and C a
  compiler rejects (`x._0_2_`, a label ending a block, pointer/integer
  conversions without a cast).
- **Options** (console `option <name> <value>`, `OptionDatabase`):
  `extensiontypes on|words|off`, `encodedcompare on|right|off`,
  `flagcompare on|off`, `compilablec on|off`. Their element ids are 291-294,
  above `ELEM_UNKNOWN` (290): upstream would renumber them.
- **Repro:** `repro/0012-extensiontypes.xml`, `0013-encodedcompare.xml`,
  `0014-flagcompare.xml`, `0015-compilablec.xml`, datatests that decompile
  with the option off and on (ARMv5TE and x86-64 code).
- **To report:** one issue proposing the options together, with the
  matching-decompilation motive; `flagcompare` assumes no overflow at the
  decrement, which upstream may want as a warning instead.

