# EVM contracts

revkit loads Ethereum Virtual Machine bytecode, lifts it with a SLEIGH
processor of its own and decompiles it: a contract's runtime code or its
creation code (the constructor), as a binary file or as the hex text solc
and block explorers print. The dispatcher's functions are named by
selector, JUMPDESTs are labelled, and the targets of computed jumps come
from a stack analysis, so the decompiler sees the contract's control flow
(`api_minor` 99, feature `evm`).

- [Importing](#importing)
- [What the import finds](#what-the-import-finds)
- [The processor](#the-processor)
- [What the decompiler shows](#what-the-decompiler-shows)
- [Measured](#measured)
- [Known gaps](#known-gaps)

## Importing

```python
pid = rk.import_program("default", path="erc20.hex").program.program_id   # hex text: 0x6080604052...
s = rk.program(pid).summary().evm                  # creation?, functions, jump counts
```

A file is EVM bytecode when it starts as solc's contracts do, with the
free-memory pointer set up: `PUSH1 0x80 PUSH1 0x40 MSTORE` (`6080604052`;
`6060604052` before solc 0.4.22), as bytes or as hex digits after an
optional `0x` (whitespace between byte pairs is allowed). Such a file
imports by itself when no format or language is asked for; format `evm`
(`ImportOptions.format`, MCP `import_program`'s `format`) imports one that
starts some other way, such as Vyper's. File system listings name it
content kind `evm` ([filesystems.md](filesystems.md#content-kinds)).

The program is a raw image of the language `EVM:BE:32:default`, format
`evm`:

| Block | At | What |
| --- | --- | --- |
| `runtime` | 0 | the runtime code: the file, or the slice creation code returns |
| `init` | `0x100000` | creation code, when the file is creation code |

Creation code is recognised by what it does: a `CODECOPY` of a constant
offset and size into memory, then a `RETURN` of that memory with the same
size, found by running the constructor on an abstract stack (below). The
copied slice is the runtime, laid out at 0; the creation code keeps its
own segment, since its jumps are offsets in itself. The raw options are
stored with the program, so it loads again the same way; the hex text is
decoded by the raw loader's `hexbytes` container (`raw_format`
`"hexbytes"`, which any raw import may use).

## What the import finds

`revkit::evm` (`src/evm`) reads the code and the backend stages what it
finds as `analysis:evm` assertions, which a person's or an agent's edits
outrank and `RevertByProvenance` takes back as a whole
(`src/backend/evm_import.cc`):

- **Functions.** The runtime's entry is `dispatcher` (or `runtime` with
  no dispatcher), the creation code's `constructor`. The dispatcher's
  comparisons, `PUSH4 <selector> EQ PUSHn <tag> JUMPI` (after `DUP1`, or
  with `DUP2` between as via-IR code has it), give a function at each tag,
  named `func_0x<selector>` (`func_0xa9059cbb`), or by a short built-in
  table of well-known signatures (ERC-20, ERC-2612, ERC-721, ERC-165,
  Ownable, Pausable: 33 entries, checked against keccak256 in
  `sdk/python/tests/test_evm.py`): `transfer`, with a plate comment
  `transfer(address,uint256) (ERC-20)` and the selector. A name from the
  table is a guess (the selector is the usual one's), and evidence says so
  (tier `guessed` in `program_summary`'s evidence).
- **JUMPDESTs** are labelled `tag_<offset>`, as solc's assembly names
  jump targets, and marked as code (Disassemble here), so discovery decodes
  all of the code and data analysis takes no `PUSH32` immediate for a
  string. JUMPDEST bytes inside `PUSH` data and in solc's CBOR metadata
  trailer don't count; the metadata gets a plate comment.
- **Jump targets.** The stack analysis runs the code from each entry with
  an abstract stack of the constants `PUSH` and `PC` put there, moved by
  `DUP`, `SWAP` and `POP` (anything else computed is unknown), one state per
  distinct stack at each JUMPDEST, within a budget (64 states per JUMPDEST,
  200,000 in all). That follows return addresses: an internal function
  call pushes its return tag, jumps, and the function's last `JUMP` returns
  to whatever is under its results. Each computed jump's targets become
  computed-jump references, which discovery follows and the decompiler
  takes as the jump's table (one target: a branch; several: a switch).
- **The summary.** `ProgramSummary.evm` (`EvmSummary`): whether the file
  is creation code and where its runtime is, the dispatcher's functions
  with selector, entry, name and the table's signature, and the jumps:
  `jumps`, `direct_jumps` (folded by the processor, below),
  `resolved_jumps` (direct and computed with every target known),
  `unresolved_jumps` (a target not a constant on some path),
  `unreached_jumps`, `jumpdests`, `budget`, and the metadata's place. MCP's
  `program_summary` shows it as `evm`, and an unresolved jump is an
  `indirect_jump` unknown in its evidence ([api.md](api.md#result-evidence));
  `get_function` and `decompile` list each function's.

## The processor

`processors/EVM` is revkit's own SLEIGH spec, compiled at build time by
`rk-sleigh`, the SLEIGH compiler built from the vendored decompiler fork
(no Java; [processors.md](processors.md#revkits-own-processors)).
`evm.slaspec` is generated by `processors/EVM/gen_slaspec.py`, which says
the model in its header:

- **Spaces.** Code is `ram` (4-byte addresses). The operand stack is
  `opstack`, below `SP`, in 32-byte slots, as Ghidra's JVM models its
  operand stack: the decompiler turns pushes and pops back into
  expressions. Memory (`MLOAD`, `MSTORE`) is `mem`, so `mload(0x40)`, the
  free-memory pointer, is the global `auMem00000040`.
- **256-bit words.** Values are 32-byte varnodes. Ghidra's decompiler
  folds constants and tracks known-zero bits in 64 bits only, so folding
  any operation that moves bits across bit 64 would be wrong for 256-bit
  values. Those are CALLOTHERs named as Yul names the instruction: `shr`,
  `shl`, `sar`, `mul`, `div`, `sdiv`, `mod`, `smod`, `exp`, `addmod`,
  `mulmod`, `signextend`, `byte`. `ADD`, `SUB`, `AND`, `OR`, `XOR`, `NOT`
  and the comparisons stay p-code, which is sound because no constant is
  wider than 64 bits: `PUSH1` to `PUSH8` push their value, `PUSH9` and up
  push `u256(limb, ...)` in 4-byte limbs, most significant first.
- **Long pushes.** The SLEIGH engine decodes at most 16 bytes per
  instruction, so `PUSH16` to `PUSH32` decode as their opcode alone, take
  their limbs as loads from the (read-only) code, which the decompiler
  folds to constants, and branch past their immediate. The listing shows
  the immediate as bytes after the instruction.
- **Folded jumps.** `PUSHn tag; JUMP` and `PUSHn tag; JUMPI` (`n` up to 4)
  are one instruction each, a direct branch, the way
  [bytecode-lifting.md](bytecode-lifting.md#what-sleigh-can-express-with-tricks)
  folds instruction pairs: most of a contract's jumps need no analysis at
  all. A jump adds its own segment (`address & 0xfff00000`) to the tag, so
  creation code's tags stay in its segment.
- **The rest.** Environment and storage instructions are CALLOTHERs
  (`calldataload`, `caller`, `sload`, `sstore`, `keccak256`, `log3`,
  `evm_call` (`call` is a SLEIGH keyword), `staticcall`, ...); `STOP`,
  `RETURN` (`evm_return`), `REVERT`, `INVALID` and `SELFDESTRUCT` end the run
  with a CALLOTHER and a return. Unassigned opcodes decode as `INVALID`.
  The compiler spec gives a contract's code no parameters and no result.

No community spec was ported. The one found, `adelapie/ghidra-evm` (and its
fork `pbwaffles/ghidra-evm`; AGPL-3.0, for Ghidra 9.1.2 with a Java
loader), notes that its `PUSH32` doesn't decompile correctly because of the
64-bit limit; revkit's model is designed around that limit instead.

## What the decompiler shows

OpenZeppelin's ERC-20 `transfer`, from the compiled contract (the address
checks and the event, abridged):

```c
void transfer(void)
{
  ...
  auVar6 = calldataload((undefined1  [32])0x4);
  auVar3 = shl((undefined1  [32])0xa0,(undefined1  [32])0x1);
  if (auVar6 == (auVar6 & auVar3 - (undefined1  [32])0x1)) {
    auVar5 = calldataload((undefined1  [32])0x24);
    auVar4 = caller();
    ...
        auMem00000000 = auVar4 & auVar3 - (undefined1  [32])0x1;
        auMem00000020 = (undefined1  [32])0x0;
        auVar3 = keccak256((undefined1  [32])0x0,(undefined1  [32])0x40);
        aauStack_140[0] = sload(auVar3);
        if (auVar5 <= aauStack_140[0]) {
          ...
          sstore(auVar3,aauStack_140[0] - auVar5);
          ...
          sstore(auVar3,auVar5 + auVar7);
          ...
          auVar3 = u256(0xddf252ad,0x1be2c89b,0x69c2b068,0xfc378daa,0x952ba7f1,0x63c4a116,0x28f55a4d,0xf523b3ef);
          log3(auMem00000040,(auVar8 + (undefined1  [32])0x20) - auMem00000040,auVar3,...);
          evm_return(auMem00000040,(auVar5 + (undefined1  [32])0x20) - auMem00000040);
          return;
        }
        ...
        auVar6 = u256(0x45524332,0x303a2074,0x72616e73,0x66657220,0x616d6f75,0x6e742065,0x78636565,0x64732062);
```

The balance mapping's slot (`keccak256` of the owner and slot 0), the
check, the two `sstore`s, the `Transfer` event's topic and the revert
string ("ERC20: transfer amount exceeds b...") are all there. The types
print as `undefined1 [32]` with casts on constants: Ghidra has no 256-bit
integer type.

## Measured

On OpenZeppelin Contracts 4.9.6's compiled `ERC20` and `ERC721`
(`tests/data/evm`, MIT), through the daemon (2026-10-18):

| File | Jumps | Direct | Resolved | Unresolved | Functions | Decompiled |
| --- | --- | --- | --- | --- | --- | --- |
| ERC-20 creation | 134 | 115 | 134 | 0 | 13 (11 by selector, all in the table) | 13, 0.9 s |
| ERC-20 runtime | 98 | 83 | 98 | 0 | 12 | 12, 0.7 s |
| ERC-721 creation | 231 | 194 | 230 | 1 | 15 | 15, 3.6 s |
| ERC-721 runtime | 195 | 162 | 194 | 1 | 14 | 14, 3.0 s |

No decompilation fails or reports bad instruction data. The one jump the
stack analysis leaves open in ERC-721 returns through a value it doesn't
track (anything computed is unknown to it).

Tests: `revkit_evm_tests` (detection, disassembly, the stack analysis,
the runtime in creation code, the dispatcher, the counts above),
`EvmImport.*` in `revkit_backend_tests` (import, summary, functions,
decompiling the dispatcher and `transfer`), `RawHex.HexText`,
`ContainerBytecode.ClassesDexWasmAndOthers` (the content kind) and
`sdk/python/tests/test_evm.py` (the SDK, MCP, and the signature table
against keccak256). solc isn't installed on the build host and isn't
fetched, so the contracts are committed compiled output rather than
compiled at test time.

## Known gaps

- **Internal functions aren't functions.** Solidity's internal calls are
  jumps with a pushed return address, so a public function's decompilation
  holds the internal ones it reaches inline, and a shared helper (ABI
  decoding, the revert-with-string tail) appears in each caller. Recognising
  the call-and-return pattern as calls, as heimdall and Panoramix do,
  would give each its own function.
- **Types.** Words print as `undefined1 [32]`; a 256-bit integer type, and
  `address` for values masked to 160 bits, need the decompiler's type
  factory to have them.
- **The stack analysis tracks pushed constants only**, so a jump to a
  computed value (rare in solc's output) stays unresolved; it says so in
  the summary and in `get_function`'s unknowns. Its budget may cut very
  large contracts short (`EvmSummary.budget`).
- **Names beyond the table**: the table has 33 well-known signatures, no
  database of selectors is downloaded; a contract's ABI isn't read either.
- **Storage layout**: slots are numbers (`sload(0x2)`); naming them needs
  the compiler's storage layout or inference.
- **No emulation**: the emulator computes in 64 bits, so EVM programs
  don't run in it.
