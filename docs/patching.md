# Patching

Change a program's bytes in revkit: assemble an instruction where it
stands, edit bytes, see every view follow, undo, and export a file that
loads and passes the vendor's checksum. The design and the measurements
behind it are in [patching/design.md](patching/design.md).

## Using it

**In the UI** (feature `patch`):

- **Patch instruction: Ctrl+Shift+G** (Ghidra's key; palette: *Patch
  instruction (assemble)…*). The selected row becomes an editor holding
  the instruction as the listing prints it. Type: it is assembled as you
  type at that address, with the processor mode there (Thumb or ARM, x86
  operand size and so on). The list under it shows the encodings found,
  shortest first; among equal lengths, the one closest to the current bytes
  (or the toolchain's canonical form, when the current bytes are one).
  The current encoding is marked. An error says why nothing encodes ("a
  relative operand can't reach its target", "an operand's value can't be
  encoded here") or, for a syntax error, where it is (a caret) and what
  could come there. **Tab** (or Ctrl+Space) completes the mnemonic or
  operand at the cursor, **↑/↓** choose an encoding, **Enter** writes it,
  **Esc** cancels. *Pad with NOPs* fills the rest of a longer instruction
  with the language's NOPs. *Thumb* (ARM) assembles Thumb code where the
  listing decodes ARM. Labels and function names resolve:
  `bl FUN_000a0000`, `CALL twice`.
- **Patch bytes: Ctrl+Shift+H** (*Patch bytes of the selection…*): the
  selection's bytes as hex (or ASCII text), written as one patch of the
  changed span.
- Patched rows have an orange mark in the gutter, a tint, and the changed
  bytes underlined, in the listing and the graph (a patched block gets an
  orange border). The decompiler, the emulator, the debugger's static view,
  xrefs and Compare all read the bytes as patched.
- **Ctrl+Z** undoes a patch like any edit (the provenance popover and
  `RevertByProvenance` work too).
- **Patches** view (palette: *Show patches*; a side-dock tab): each patch
  with its address (click to go there), what it was and is now, the
  function, the bytes, who and when; **Revert** one or all. *Revert the
  patch here* reverts from the listing.
- **Export…** (palette: *Export the patched program (checksum fixups)…*):
  the whole file with its header (raw, ELF, PE) or only the loaded image,
  fixups, and a file name template. **Detect** takes a file name with the
  checksum in it (`FW_202401011200_1234ABCD.bin`) or a value (`0x…`)
  and finds the rule (see [the detector](#the-checksum-detector)); **Use**
  adds it and its name template. **Export** downloads the file after the
  daemon verified it; **Save settings** stores them with the program (an
  assertion: shared, undoable).
- **Compare with original** (with feature `diff`): the file as imported is
  opened as `<name> (original)` once, and the Compare view shows it against
  the patched program: the patched functions are the modified ones.

**From Python** ([sdk/python/revkit/patching.py](../sdk/python/revkit/patching.py)):

```python
from revkit import Client
from revkit.patching import name_sum

with Client("127.0.0.1:50051", actor="user:alice") as rk:
    fw = rk.program("default/firmware.bin")
    fw.patch_instruction(0x8010, "cmp r0,#0x9")
    fw.patch_instruction(0x20040, "bl 0xa0000")
    hit = fw.detect_checksum(file_name="FW_202401011200_1234ABCD.bin").hits[0]
    out = fw.export(name_sum("sum32", template=hit.file_name_template))
    open(out.file_name, "wb").write(out.data)
```

**For agents** (the MCP server, [api.md](api.md#mcp-server-revkitmcp_server)):
`assemble` (the encodings, or the error and what was expected; writes
nothing), `patch_instruction`, `patch_bytes`, `list_patches`,
`revert_patch`, `detect_checksum` and `export_patched`. An agent's patch
carries its provenance and stated reason like its other edits, so a
reviewer can list or revert a run's patches.

**Command line**: `rk-asm --lang ARM:LE:32:v4t --addr 0x20040 'bl 0xa0000'`
prints the encodings; `--complete`, `--dump` (the grammar), `--roundtrip
BINARY` (every instruction disassembled and assembled back) are for
debugging the assembler.

## How it works

### Patches are facts

A patch is an assertion: `FACT_KIND_PATCH` at its first address, the value
the new bytes (1 to 256: `facts::kMaxPatchBytes`). It has provenance,
history, blame, undo, `RevertByProvenance` and replication like every
other fact. The op's `meta` holds what was typed. Where patches overlap,
the later one wins: `AssertedOrder` (the store's rank, then stamp,
replica and counter) orders a Patch key's live winners, and a patch keeps
its place when retracted and replayed.

Every byte reader goes through derived queries in `src/facts`:

- `patch.page(page)`: whether a Patch key starts in the 4 KiB page or in
  the 255 bytes before it, so may overlap it. The gate: a reader looks at
  a page's spans only where this is true.
- `patch.span(space, offset >> 8)`: the live patches starting in one
  256-byte span, with their order.
- `bytes.effective(page)`: the loader's 4 KiB page with the patches over it
  laid on (`patches_overlapping`, `apply_patches`).

The readers that used to read `loader::Image::memory` directly now read the
bytes as patched: flows and decoding (`analysis/decode.cc`: its
`ByteReader` reads the loader's pages, their gates, and the patch spans
it covers on gated pages only),
the program description's stub scan (`analysis/program.cc`), data analysis
(`analysis/data_program.cc`), the backend's listing and instructions
(`backend/program.cc`, `PatchedBytes`), the decompiler's image
(`inputs::Program::read`, `decompd` chunks through `RunLookup::chunk`), and
the emulator and debugger (`emu::Options::patches`). After a commit that
patched bytes, the loader's description of the program (PE import stubs,
GOT values) is computed again and set in a revision of its own only when
it changed (`Redescribe`).

Invalidation is the engine's: a patch changes `patch.span` of its spans, so
only what read those bytes recomputes. A program without patches (nearly
all of them) reads one `patch.page` per page read, as cheap as a filter
over an empty bucket, and no span: no per-span memos or dependencies (two
memos per 256 bytes read, 1,500 on lua; about 4% of bash's import,
measured in one process against the same build reading no patches). The
price is the first patch near a page, which opens its gate and so re-runs
that page's readers once; from then on the gate holds still and a patch
re-runs only the readers of its spans
(`APatchAfterImportRedecodesOnlyNearIt` in
`src/analysis/tests/analysis_test.cc`). Retracting the last patch near a
page closes the gate again. Measured on x86-64 (six functions a page
apart, `PatchPrecision` in `src/backend/tests/patch_api_test.cc`): one
flow, the patched function's and its caller's decompilation.
`QUERY_KIND_PATCHES` tells clients the patch list changed.

### The assembler (`src/asm`)

An inverse of SLEIGH over the vendored engine (accessor patches 0006–0008
in `third_party/ghidra/patches`), the same approach as Ghidra's
`ghidra.app.plugin.assembler`, written for C++:

1. **Grammar.** Each table's constructors become productions from their
   print pieces: literals, operand slots, sub-tables, and terminals for
   numbers (any base, signed, by value), register names (from the
   language's register lists, attached names and value maps). Built once
   per language (milliseconds) and shared.
2. **Parse.** An Earley parser over characters with terminals matching
   spans, memoized; every parse tree is kept (ambiguity is the point:
   `mov r0,#1` has several constructors).
3. **Solve.** Each tree is generated forwards (continuation passing) into
   pattern blocks: byte masks and values for the instruction's tokens and
   the context. Operand expressions are solved for their fields (addition,
   shifts, masks, catenation part by part, circular rotations over all
   amounts, `inst_next` backfilled once the length is known); context
   changes the constructors make are solved backwards; prefixes come from
   Ghidra's root recursion (x86 `0x66`, REX, ARM's condition check),
   searched by depth.
4. **Verify.** Each candidate is decoded by the real SLEIGH decoder
   (`lift::SleighDecoder`) at the address with the context, and kept only
   if it decodes to the same constructor tree and to the same text (numbers
   compared by value, labels by symbol). Nothing the disassembler wouldn't
   print back is offered.
5. **Rank.** Shortest first; then, when the current bytes are the canonical
   encoding of the current text, canonical first (the toolchain's
   `cmp r0,#0x9` is `e3500009`, not the 2-bit-closer `e3500124`), else the
   fewest bits changed.

Errors come from the parser (column, expected terminals) or the deepest
reason the solver saw. Completion runs the parser to the cursor and lists
the terminals that can come next.

**Round-trip gate** (`scripts/asm_roundtrip.py`, `scripts/ci.sh --asm`):
every instruction of corpus binaries disassembled and assembled at its
address with its context; *exact* means the original bytes are among the
candidates, *ok* that every candidate decodes to the same text. Baselines
per language in `corpus/baselines/asm.json`; the gate fails on a drop.
Times are per line with `rk-asm` on a loaded 32-thread machine:

| Language | Lines | Exact | OK | Median µs | p95 µs |
| --- | ---: | ---: | ---: | ---: | ---: |
| ARM:LE:32:v4t ARM | 6567 | 100% | 100% | 94 | 180 |
| ARM:LE:32:v4t Thumb | 6247 | 100% | 100% | 99 | 110 |
| ARM:LE:32:v7 ARM | 6521 | 100% | 100% | 229 | 319 |
| ARM:LE:32:v7 Thumb | 6224 | 100% | 100% | 214 | 270 |
| ARM:LE:32:Cortex Thumb | 25794 | 100% | 100% | 200 | 276 |
| AARCH64:LE:64:v8A | 30675 | 100% | 100% | 322 | 537 |
| x86:LE:64:default | 50568 | 99.66% | 100% | 776 | 1607 |
| MIPS:BE:32:default | 12715 | 100% | 100% | 164 | 207 |
| MIPS:LE:32:default | 13392 | 100% | 100% | 131 | 213 |
| PowerPC:BE:32:default | 24975 | 100% | 100% | 136 | 155 |
| RISCV:LE:64:default | 27745 | 100% | 100% | 131 | 220 |
| SuperH4:LE:32:default | 18551 | 100% | 100% | 50 | 94 |
| Xtensa:LE:32:default | 24705 | 100% | 100% | 64 | 72 |
| 68000:BE:32:default | 12360 | 100% | 100% | 76 | 212 |
| 68000:BE:32:Coldfire | 14923 | 100% | 100% | 104 | 276 |

x86's misses are encodings no assembler picks for the printed text
(multi-byte NOPs, redundant prefixes): every candidate decodes back to the
same instruction. A local run over a 2 MiB ARM v4t vendor firmware
(42 087 lines) was 100% exact at 62 µs a line.

### Export (`src/patch`)

`ExportProgram` starts from the imported file's bytes and writes each live
patch at its file offset, through the loader's regions (ELF segments, PE
sections, a raw import's offset): a raw file's header stays as it was. A
patch outside file-backed bytes (`.bss`, a declared RAM region) is an error
naming it. `EXPORT_FORMAT_IMAGE` writes only the loaded image (raw
imports).

Fixups run in order: checksum fields, then the PE CheckSum, then the file
name. A checksum fixup (`ChecksumSpec`) is an algorithm over `[start,
end)` of the output (`end` 0: the end of the file; negative: back from it;
`skip_padding`: trailing 0xFF/0x00 left out), written into a field (offset,
width, endianness; the field itself counts as zero while summing) or into
the file name. Algorithms: sums (8, 16, 32 bits; 16- and 32-bit words in
either endianness; negated), XOR-8, Fletcher-16/32, Adler-32, CRC-16
(CCITT-FALSE, XMODEM, KERMIT, MODBUS, ARC), CRC-32 (IEEE, BZIP2, MPEG-2,
POSIX, JAMCRC, CRC-32C) and the PE CheckSum. The file name template takes
`{NAME}` (the original's name without its extension), `{EXT}` (with its
dot) and `{SUM}` with printf-like width and case (`{SUM:08X}`).

Every export is verified (unless `skip_verify`): the output is loaded again
with the program's import options and every mapped byte compared with the
patched program; each fixup is recomputed from the output and compared.
The response lists the changes (file offset, length, address, what), the
fixups applied and the verification. With `host_path` the daemon writes
the file on its host (admin only); otherwise the bytes come back.

Settings (format, fixups, template) are stored with the program as a
`NOTE` assertion tagged `patch.export` (`SetExportSettings`), so they are
shared and undoable.

### The checksum detector

`DetectChecksum` tries every algorithm over candidate ranges of the file
(the whole file, after the raw header, without trailing padding, header
declared lengths, each without a field's bytes) against each 16- and
32-bit header word and against a value the user gives: hex digits, or a
file name whose hex run is the checksum. Hits come simplest first, with
evidence in words and, for a file name, its template: on a vendor
firmware named `FW_202401011200_1234ABCD.bin` it finds `sum32 over
0x0..EOF = 0x1234ABCD, the file name's "1234ABCD"` and the template
`FW_202401011200_{SUM:08X}.bin` after 192 candidates.

### API

`PatchService` (`api_minor` 27, features `patch`, `assemble`,
`export-fixups`; see [api.md](api.md#patching)). Roles: assembling,
listing, detecting and exporting to the caller need viewer; patching,
reverting, saving settings and opening the original need editor;
exporting to a path on the daemon's host needs admin, like importing from
one.

## Known gaps

- **Patch commit cost on large raw firmware.** A patch re-runs only the
  flows that decode near it, but function discovery is one whole-program
  fixpoint whose early rounds' search reads most of a raw image, so on a
  2 MiB ARM firmware a patch commit takes about as long as discovery (≈10
  s), where an ELF's is milliseconds. Incremental discovery is the fix
  (src/analysis).
- **No code-cave helper yet**: `space.candidates` from the design (padding,
  unreferenced data such as a debug string) isn't built; patch the cave's
  bytes or instructions one by one, then a `FUNCTION_BOUNDS` there.
- **One instruction per editor**: multi-line assembly with forward labels
  is not built.
- **WASM fixup plugins** (custom checksums) are not built; the built-in
  algorithms and the PE CheckSum are.
- The original for Compare is a second program imported from the stored
  file bytes (the design's zero-copy view flag on `bytes.effective` is not
  built).
- Mach-O export is not supported (no Mach-O loader).
