# Nintendo DS games

revkit loads a Nintendo DS game as one program per module, from a
[ds-decomp](https://github.com/AetiasHax/ds-decomp) ("dsd") project or
from a `.nds` ROM image, names what one module calls in another from that
module's program, and writes the names back to the dsd project. It is
meant as a front end to an existing matching-decompilation pipeline:
analyse, name and decompile in revkit, build and match with dsd, mwccarm
and objdiff.

`api_minor` 103, feature `nds`; the memory map, the name conflicts and
the fixes a matching-decompilation run needed are `api_minor` 104
([below](#memory-map), [Imported twice](#imported-twice), [What a matching
run needed](#what-a-matching-run-needed)). Code: `src/nds` (the formats, no
dependencies), `src/backend/nds_import.cc` (the plan of programs),
`src/backend/image_backend.cc` (the RPCs), `src/backend/own_inputs.cc`
(names across modules in the decompiler), `ui/src/ui/nds.ts`.

- [What a game becomes](#what-a-game-becomes)
- [Importing a ds-decomp project](#importing-a-ds-decomp-project)
- [Memory map](#memory-map)
- [Imported twice](#imported-twice)
- [Modules across programs](#modules-across-programs)
- [Writing names back](#writing-names-back)
- [From revkit to a scratch](#from-revkit-to-a-scratch)
- [Importing a ROM](#importing-a-rom)
- [What a matching run needed](#what-a-matching-run-needed)
- [What revkit doesn't do yet](#what-revkit-doesnt-do-yet)
- [Reusing a finished decomp](#reusing-a-finished-decomp)
- [Decompiling mwcc C++: what's missing, ranked](#decompiling-mwcc-c-whats-missing-ranked)
- [Formats and their sources](#formats-and-their-sources)
- [Test fixtures](#test-fixtures)

## What a game becomes

A DS game is several programs that share an address space: the ARM9's
`main` (loaded at 0x02000000 on retail games), the autoload blocks the
ARM9 copies out at start-up (ITCM at 0x01FF8000, DTCM at 0x027E0000 and
sometimes others), the ARM9 overlays (loaded on demand, several sharing
one address range), and the ARM7's program and its overlays.

Ghidra puts overlays in overlay spaces of one program; revkit has none
([ghidra-feature-survey.md](ghidra-feature-survey.md), "Overlay blocks /
overlay spaces"). Instead each module is its own raw program at its load
address, in one folder per game:

| Module | Program | Language |
|---|---|---|
| `main` | `main` | `ARM:LE:32:v5t` (ARM946E-S is ARMv5TE; Ghidra's v5t covers its instructions) |
| ITCM, DTCM, other autoloads | `itcm`, `dtcm`, `autoload_N` | `ARM:LE:32:v5t` |
| ARM9 overlay N | `ovNNN` (`ov006`) | `ARM:LE:32:v5t` |
| ARM7 | `arm7` | `ARM:LE:32:v4t` (ARM7TDMI) |
| ARM7 overlay N | `arm7_ovNNN` | `ARM:LE:32:v4t` |

Program names are the module names; a second game in the same project gets
`main-2` and so on (each in its own folder).

## Importing a ds-decomp project

**UI:** File → Import ds-decomp project… (the daemon's host browser:
choose `config/<version>/arm9/config.yaml`). **Python:**
`Client.import_dsd_project(project_id, config_path)`. **MCP:**
`import_dsd_project`. **API:** `ProjectService.ImportDsdProject`. The
daemon needs `--browse-root` over the project, and the call needs admin (it
reads the host's files); every file it reads must be under a browse root.

What it reads:

- **`config.yaml`** (dsd's): `main_module`, `autoloads` (`kind: Itcm`,
  `Dtcm`, or `!Unknown N`), `overlays` (`id`, `signed`), each with its
  `delinks`, `symbols` and `relocations` files, relative to the config.
- **The extract** its `rom_config` names (ds-rom's layout, as `dsd rom
  extract` writes it): `arm9/arm9.bin` and `arm9.yaml` (`base_address`,
  `entry_function`, `bss_start`/`bss_end`), `itcm`/`dtcm` with their
  `base_address`, the overlays' `overlays.yaml` (`base_address`,
  `code_size`, `bss_size`, `file_name`), and `arm7_bin` with `arm7.yaml`.
  The extract's binaries are already decompressed and the autoloads split
  out. Without an extract, each module's `object` (the binary dsd builds)
  is loaded at its `delinks.txt`'s lowest address instead.
- **`delinks.txt`**: the module's sections (`.text start:0x.. end:0x..
  kind:code align:32`, kinds `code`, `rodata`, `data`, `bss`) become its
  memory blocks, named as dsd names them (`.text` r-x, `.rodata` r--,
  `.data` rw-, `.bss` rw- uninitialized; empty ones such as a `.ctor`
  with start = end are left out). Each translation unit (a `path:` line
  with indented `complete`, `categories:` and sections) becomes a plate
  comment at its first section's start, `import:dsd`:
  `dsd: src/06_GameOver/Scene/GameOverScene.cpp (complete)` and its
  ranges.
- **`symbols.txt`**: every symbol becomes part of the program's symbol
  table, as an ELF's would be (`loader::RawOptions::symbols`, kept with
  the program's raw layout so a reopened project has them): a
  `function(arm|thumb,size=..)` is a function symbol with its size (a
  Thumb one odd, so its body is decoded as Thumb), `data(..)` and `bss`
  data symbols with the size their kind implies, `label(..)` a label;
  `local` and `weak` are the binding. Functions are then seeded and named
  from them and mangled names are demangled as an ELF's are: `_ZN13GameOverSceneC1Ev`
  shows as `GameOverScene::GameOverScene` with the prototype the mangled
  name gives (`this` typed), and the mangled spelling stays the symbol's
  (`DemangledName.mangled`). revkit's own analysis then finds the bodies,
  the references and anything the symbols don't list.
- **`relocs.txt`**: which other modules each module refers to, for the
  links (next section). In-module references are revkit's own analysis's.

The kinds and attributes read are dsd's whole syntax; those seen in a
real, complete project (bakubrawlers, 2026-10) are `function(arm,size=..)`,
`function(thumb,size=..)`, `data(any)`, `bss`, `label(arm)`, `local`, `weak`;
relocations `arm_call`, `arm_call_thumb`, `arm_branch`, `load` (with `add:`),
`link_time_const(ARM9_CTOR_START)`; modules `main`, `itcm`, `dtcm`,
`overlay(N)` and `overlays(0,1,…)` (a call from main whose target overlay
dsd can't tell); delinks kinds `code`, `rodata`, `data`, `bss` and `complete`
units. The parsers also take `data(byte|short|word[N])`, `data(byte[])`,
`bss(size=..)`, `function(..,unknown)`, `ambiguous`, `thumb_call`,
`thumb_call_arm`, `overlay_id`, `module:none`, `module:autoload(N)` and
`categories:`. A line that doesn't parse is reported with its number
(`NdsModuleImport.warnings`) and skipped.

dsd covers the ARM9 only; the ARM7 and its overlays come from the extract,
with no symbols (`skip_arm7` leaves them out). `modules` imports only the
modules named.

The response (`ImportDsdProjectResponse`) has the folder and, per module,
its program, address, size, `.bss` size, the counts of symbols, functions
(Thumb ones), data symbols, relocations (those naming another module, and
the ambiguous ones), sections and units, its links, and warnings.

## Memory map

Besides its own sections, every module program maps the DS's memory that
its code reads and writes as hardware, as volatile, uninitialized
read/write blocks (`loader::platform_regions`, presets `nds-arm9` and
`nds-arm7`), so the decompiler reads them each time: a loop polling
`VCOUNT` stays a loop that reads it, a wait on the SDK's VBlank counter
doesn't become `do {} while (true)`, and the read that saves `IME` before
interrupts are turned off is kept.

| Block | ARM9 | ARM7 | What it is (GBATEK, "DS Memory Maps") |
|---|---|---|---|
| `main_shared` | 0x027FF000–0x027FFFFF | the same | the end of main memory (through its 0x027xxxxx mirror) both CPUs and the SDK's start-up code share: the cartridge header copy at 0x027FFE00, the VBlank counter, IPC words |
| `shared_wram` | 0x03000000–0x03FFFFFF | 0x03000000–0x037FFFFF | the shared WRAM window (16 or 32 KiB given to the CPU, mirrored; programs use the mirror at 0x037F8000); the ARM7's own WRAM above it is not volatile |
| `io` | 0x04000000–0x04FFFFFF | the same | the I/O ports (the ARM7's wireless ports at 0x04800000 included) |

Each block is cut around every module of the same CPU (a block of the
program's own at an address would hide a sibling module there from the
links): an autoload or the ARM7 placed in shared WRAM keeps its addresses,
and the block is split around it (`shared_wram`, `shared_wram_1`). The
memory map shows them, and they can be edited like any block
([memory-map.md](memory-map.md)).

The same presets map a raw image's I/O when a module is imported on its
own, the way a run did before the DS import existed (`main.bin` as a raw
program at 0x02000000): `ImportOptions.memory_preset` `"nds-arm9"` or
`"nds-arm7"` (Python `import_program(..., memory_preset="nds-arm9")`),
cut around the image and the regions given.

## Imported twice

A program's id is `<project>/<name>`, and a game's folder is named after
the game, so importing a game (or a module) again meets its own name.
`on_conflict` (`NameConflict`; `ImportProgramRequest`,
`ImportDsdProjectRequest`, `ImportNdsRomRequest`; Python
`on_conflict="keep_both" | "replace" | "refuse"`) says what happens:

- **keep both** (the default, as before): a folder `game (2)` beside the
  first and programs `main-2` and so on; the response says whose name it
  was (`folder_taken_by`, `ImportProgramResponse.name_taken_by`) and a
  warning names it.
- **replace**: the folder's programs are deleted (`DeleteProgram`, so
  undoable) and the modules are imported into the same folder, each shown
  with its module's name (`RenameProgram`: a deleted program keeps its id,
  so the new ids are `main-2` and so on; `replaced_program_ids` lists the
  old ones, and the links point at the new programs).
- **refuse**: `ALREADY_EXISTS`, nothing imported.

## Modules across programs

An overlay calls `main` and the autoloads all the time, and `main` calls
into the loaded overlay. Each program records which module programs it is
linked to: a NOTE on its record, sub `revkit:program.dsd` (reserved like
the program's name and folder), with where it came from (`source dsd|nds`,
`config` or `rom`, `module`, `symbols`, `cpu`) and one `link <module>
<program id>` line per linked module. Every ARM9 module is linked to `main`
and the autoloads, the ARM7's to the ARM7, and a module to each overlay its
`relocs.txt` names alone (`module:overlay(N)`); never to one an ambiguous
`module:overlays(...)` names.

Library linking (`LinkProgramLibrary`, [api.md](api.md#libraries)) doesn't
fit: it resolves imports by name through import slots and exports, and a
DS module calls absolute addresses. The links are this new kind of
cross-program reference instead, by address:

- **The decompiler**: where a function's code refers to an address no
  block of its program holds, the decompiler's lookups ask the linked
  modules; when exactly one maps the address, that program's facts there
  are used as that program's own decompilations see them (its renames,
  its demangled or asserted prototypes, its data's types), with the type
  definitions they reach (`own_inputs.cc`, `QueryLookup::linked`). A call
  from `ov000` reads `SceneBase::Update((SceneBase *)this)` instead of
  `func_0x020000d8()`, and a load reads `kRetryItems` instead of
  `uRam020001dc`. Each lookup is a dependency of the decompilation, so a
  rename in `main` redoes the overlay's decompilations that call it.
- **The listing**: an operand or a data value pointing there shows the
  linked module's name, with `ListingToken.target_program_id` saying which
  program; the UI opens that program there when it is followed.
- **Ambiguity**: two linked modules mapping the address (two overlays
  sharing it) name it in neither; the address shows as it is.

Not yet: references back (main's function listing the overlays that call
it), the call graph across modules, and the decompiler pane's follow into
another program (the listing's works).

## Writing names back

**UI:** File → Export ds-decomp symbols… (a diff per module, Copy patch,
Write files). **Python:** `Client.export_dsd_symbols(project_id,
write=False)`. **MCP:** `export_dsd_symbols`. **API:**
`ProjectService.ExportDsdSymbols`.

For each module program (`program_ids`, else every one in `folder_id`,
else the project's) it reads the module's `symbols.txt` (the path recorded
at import) and compares it with the program:

- **A listed symbol whose name changed in revkit is renamed in place**:
  only the name is replaced; the kind, address, `local`/`weak`, comment
  and every other line stay as they were, so the diff is the rename.
- **The mangled-name rule.** revkit shows a mangled symbol's demangled
  name. A function whose name is still the file's (not renamed) keeps the
  listed spelling. A rename to exactly the listed name's demangled form
  (`GameOverScene::Update` for `_ZN13GameOverScene6UpdateEv`, short or
  with its parameters) also keeps the listed spelling: it names the same
  symbol. Any other name is written as typed. revkit doesn't mangle: type
  the mangled name (`_ZN13GameOverScene4DrawEi`) to get one in
  `symbols.txt`, or a plain name for a C function.
- **New symbols** are added in address order (at the end when the file
  isn't sorted): functions revkit has that dsd doesn't list, when they
  have a name of their own (not revkit's `FUN_…` or dsd's `func_…`
  placeholders), as `function(arm|thumb,size=..)` with the size up to the
  next function or the block's end (a dsd function's size takes in its
  literal pool); named data as `data(any)`, named addresses in `.bss` as
  `bss`, and names inside a function as `label(arm|thumb)`.
- **Names dsd can't read back** (spaces, `//`, unbalanced parentheses) are
  skipped with the reason.

The response has each module's unified diff (`diff`), all of them in one
`patch` (absolute paths: `patch -p0 < file` applies it), and the changes.
With `write` each changed file is copied to `symbols.txt.bak-<UTC time>`
beside it (`-1`, `-2`... when that name is taken), then replaced (written
to a temporary file and renamed). Writing needs admin and the files under
a `--browse-root`. The export reads and writes each `symbols.txt` the
import read through its directory opened below the browse root, never
following a link (one swapped in after the import is refused), as a
regular file of at most the import's limit; the backup and the temporary
file are created new (`O_EXCL`), so a link planted at their names is
never followed. A module's name must be printable ASCII without spaces
(bug scrub part 3).

## From revkit to a scratch

**UI:** the decompiler's right-click menu (and Edit), Copy as decomp
scratch. **Python:** `Program.decomp_scratch(function)`. **MCP:**
`decomp_scratch`. **API:** `QueryService.ExportDecompScratch`.

One function as the start of a matching attempt, in the shape of a
bakubrawlers-style probe file:

```c
// PROBE: _ZN13GameOverScene6UpdateEv ov000 0x0210008c
/* GameOverScene::Update from default/ov000, decompiled by revkit ... */
/* Ghidra's built-in type names ... */  typedef unsigned int undefined4; ...
/* Types */      the named types its tokens and variables use, and what they reach
/* Callees */    void SceneBase::Update(SceneBase *this); /* main */
                 float Lerp(float a, float b, float t); /* main */
/* Globals */    extern undefined1 kRetryItems[16]; /* 0x020001d4 */
void GameOverScene::Update(GameOverScene *this) { ... }
```

`context` (the declarations) and `source` (the PROBE line and the
function) split it for a decomp.me scratch. The PROBE line names the
symbol as the file spells it (mangled; the user's name after a rename),
the module and the address. A callee's prototype is the asserted or
demangled one, else its own decompilation's. It is a starting point: the
C is Ghidra's, with Ghidra's type names and `::` in names, not source
mwcc compiles.

**The C's shape.** By default revkit's C follows what the instructions
encode where it can without guessing the compiler: `ldrh`/`ldrsh`
signedness, comparisons with the constant on the right, `subs; bgt` loop
guards as one test, bitfields as fields, `ldrb`/`ldrsb` too
([decompiler-inputs.md](decompiler-inputs.md#source-shape)). CodeWarrior
keeps the source's comparison constants, so for a matching project set
each module's program to

```python
prog.set_decompiler_settings(comparison_form="encoded", compilable_c=True)
```

(`x <= 0` where the instruction has `cmp r0,#0; ble`, and C a compiler
takes as is: no `x._0_2_`, no label ending a block, casts on
pointer/integer conversions). Scratches, `Decompile` and `ExportC` follow
the setting.

**The C++ in it.** `this` is typed (from the mangled name); its class is
an empty placeholder (`this + 0x14`) until the program defines it: import
the game's C++ headers (ParseC with `cplusplus`) and every member function
of a class they declare prints `this->field`
([types.md](types.md#c-classes-as-this)). Without headers, inference types
the class's word parameters elsewhere as its own structures (`astruct_<n>`),
but not `this` of a demangled prototype.

**Interworking and the runtime.** Thumb functions decode as Thumb from
their odd symbols; `blx` and `bl` across modes (`arm_call_thumb`) reach
them; a call into another module through a linked program names it. A
mwcc soft-float or division helper (`_fmul`, `_fdiv`, `_s32_div_f`) named
in `symbols.txt` keeps its name; since api_minor 103 a raw image's `_name`
no longer takes a library archive's `name` (`_fdiv` had been given C23's
`float fdiv(double, double)`, which garbled every call with `CONCAT44`).
Their prototypes are then what their own decompilation finds (two words
in, one out): the float types come only from a prototype someone gives.

## Importing a ROM

**UI:** File → Import DS ROM…. **Python:** `Client.import_nds_rom(project_id,
path=...)` (or `content=`, `program_file=`). **MCP:** `import_nds_rom`.
**API:** `ProjectService.ImportNdsRom`. For users without dsd: the same
programs from the ROM itself, with no symbols.

- **The header** (GBATEK, "DS Cartridge Header"): title, game code, the
  ARM9's and ARM7's ROM offset, entry, RAM address and size, the FNT and
  FAT, the ARM9 and ARM7 overlay tables. It is taken when its CRC-16 over
  0x000-0x15D holds or the logo's checksum does.
- **The ARM9's module parameters** (NitroSDK's `_start_ModuleParams`):
  found through the ARM9 footer (the 12 bytes after the ARM9 in the ROM:
  the `0xDEC00621` nitrocode, the parameters' offset) or by the nitrocode
  words `0x2106C0DE`, `0xDEC00621` that end them. They give the autoload
  list, where the autoload data starts, main's `.bss`, and the compressed
  static end.
- **BLZ**: when the compressed static end is set, the ARM9 up to it is
  decompressed backwards from its 8-byte footer (compressed length,
  footer length, how much longer the output is); the part before the
  compressed area is stored as is. The decompressed module's parameters
  are cleared to "not compressed", as the SDK's start-up code leaves them.
- **Autoloads**: each list entry (12 bytes: address, size, `.bss` size; or
  16 with the static initializers, told apart by the sizes adding up to the
  autoload data) is cut off the ARM9 into its module: `itcm` at
  0x01FF8000, `dtcm` at 0x027E0000 (or 0x027C0000, 0x023C0000, 0x02FE0000),
  `autoload_N` otherwise. `main` keeps the bytes before the autoload data.
- **Overlays**: 32-byte entries (id, RAM address, RAM size, `.bss` size,
  static initializer start and end, file id, and the last word's
  compressed size in bits 0-23, compressed flag bit 24, authenticated bit
  25); each overlay's bytes are its FAT file's, BLZ-decompressed when
  flagged.
- **ARM7**: its program and overlays the same way, as `ARM:LE:32:v4t`.

Each module is one block over its bytes (read/write/execute) plus a
`.bss` block and the [memory map](#memory-map)'s, with the entry point
where the header gives one. A ROM has
no symbols, so after the modules are analysed the import asserts a
function (Disassemble here, a function: ARM, or Thumb after a `blx`) at
each address one module calls in another, the only one of its links that
maps it, a few rounds as new functions call further: main's functions
only overlays call, the ITCM's. Functions only vtables reach are still
missed. Programs
record `container_path` `nds://game.nds!/ov006`. The secure area (the
ARM9's first 2 KiB) is expected decrypted, as dumps are; an encrypted one
reads as noise.

**As a file system.** A `.nds` file (and a NARC archive) also opens in
the file system browser (File → Open file system…, `OpenFileSystem`;
formats `nds` and `narc`, [filesystems.md](filesystems.md#formats)), laid
out as ds-rom extracts it: `header.bin`, `arm9.bin` (BLZ-decompressed,
with its language and load address, so Import imports it as a raw
program), `arm7.bin`, `y9.bin`/`y7.bin`, `overlay/overlay_NNNN.bin`
(decompressed when flagged), `banner.bin`, and NitroFS under `files/`. A
file that is LZ10, LZ11, Huffman or RLE data throughout shows
decompressed (codecs `nds-lz`, `nds-blz`), and a NARC inside opens as a
directory (`files/data/pack.narc!/`).

## What a matching run needed

A private matching-decompilation run on a retail game (revkit 0.1.3, the
modules loaded as raw programs and ds-decomp's symbols asserted through
the SDK; [known-issues.md](known-issues.md) has what is still open) hit
these, fixed in `api_minor` 104:

- **Calls cut off after a call that returns.** The decompiler's inputs
  take Ghidra's no-return evidence (`analysis.no_return_evidence`): a
  target called three times where what follows the call isn't code that
  continues (the next function's entry, a literal pool, bytes that don't
  decode) is marked non-returning, and every call to it becomes `call;
  return;`. Two things made that wrong. The evidence judged targets the
  program has no code for (an overlay calling `main`, which only a linked
  program maps): those now always return here, unless the program that
  has them says otherwise (a linked module's function brings its own
  no-return flag). And `SetNoReturn(false)` cleared the callee's flag but
  not the evidence, so the decompiler stopped warning "Subroutine does not
  return" and still ended the caller after the call: the user's word is
  now over the evidence, so the flow after the call comes back. A
  `SetNoReturn` on a Thumb function now reaches discovery too (its flow
  key is the tagged entry when nothing else marks the code Thumb, as for
  a function only a BLX found).
- **Thumb entries through the SDK.** `SetFunctionBounds` keeps the
  function's instruction set when the entry is untagged (a Thumb function
  stays Thumb; its key is the tagged entry, or the plain one where
  symbols already mark the code Thumb) and takes
  `instruction_set` to choose one; the check for an instruction at the
  entry decodes in that set (it decoded ARM, so a Thumb entry whose bytes
  aren't an ARM instruction was refused "no instruction at entry"). Bounds
  after a Disassemble in the same request take the Disassemble's
  instruction set.
- **Assertion batches.** A refused batch names every refused body and why
  (`assertions[i]: ...; assertions[j]: ...`), and `skip_invalid` commits
  the others in one revision with the refused ones in
  `AppendAssertionsResponse.refused` ([api.md](api.md#assertions-provenance-blame)).
- **Stores that only grow.** `rk-daemon compact <dir>` and
  `ProjectService.CompactProject` rewrite a project's store without its
  free pages after dropping stale memos (and every memo, or those beyond a
  size, as asked); `--cache-limit-mb` bounds the stored memos as projects
  open ([backend.md](backend.md#compaction)).
- **Daemon memory with Parameter ID**: [memory.md](memory.md#many-programs-and-parameter-id).

## What revkit doesn't do yet

- No mangling: a new C++ name must be typed mangled to reach `symbols.txt`.
- No class layouts or vtables recovered from mwcc code itself (no RTTI in
  these games): a class's layout comes from an imported header
  ([types.md](types.md#c-classes-as-this)); inference runs on 32-bit ARM
  ([infer.md](infer.md#32-bit-processors)) but doesn't type a demangled
  `this`.
- dsd's `load` relocations aren't applied as typed pointers (literal
  pools and vtables read as words), and `data(word[4])` isn't typed as an
  array.
- No references back across modules, no cross-module call graph.
- No relocs.txt or delinks.txt export: only symbols.txt is written.

## Reusing a finished decomp

Games 1 and 2 are finished matching decomps; game 3 starts from nothing
but its ROM. Three things carry over, from cheapest to richest:

**1. Function ID from the decomp's objects.** A finished decomp's build
directory has an object per translation unit (`build/<ver>/src/**/*.o`:
mwcc's ARM ELF relocatable objects, with symbols). Import them, build a
Function ID database, and run it on game 3's modules:

```python
objs = [rk.import_program("default", path=str(o), name="g1-" + o.stem,
                          language_id="ARM:LE:32:v5t:default").program.program_id
        for o in Path("bakubrawlers/build/usa/src").rglob("*.o")]
rk.create_fid_database("/srv/kb/bakubrawlers.rkfid", objs, "bakubrawlers", version="usa", attach="project")
for m in rk.import_dsd_project("default", "/srv/game3/config/eur/arm9/config.yaml").modules:
    rk.program(m.program.program_id).run_fid()   # names what matches; fid_matches() lists it
```

- **The language.** ELF objects load as `ARM:LE:32:v8` by default, the
  DS modules as `ARM:LE:32:v5t`; Function ID matches within one base
  language, so import the objects with `language_id="ARM:LE:32:v5t"` (an
  explicit language overrides the ELF's).
- **Relocations.** revkit records an object's relocations but doesn't
  apply them: a `bl` in a `.o` decodes to its own address (the REL addend),
  so an object's call graph is empty and its decompilation calls itself.
  The hashes don't mind (every operand field is masked by the
  instruction's SLEIGH mask in the full hash, scalars at relocation sites
  in the specific hash too, literal-pool words aren't hashed), but
  discovery ends an object's function at its first call, so only
  functions without calls hash as the linked code does. Measured on the
  fixture: Function ID from the objects names 2 of the ROM's functions
  (`ThumbChecksum`, `_s32_div_f`); the decomp knowledge base, built from
  the finished game's module programs, names most of them
  ([decomp-kb.md](decomp-kb.md#measured)).
- **What a match gives**: the name (demangled as the objects' symbols are),
  a plate comment naming the library, and a match list to review
  (`fid_matches`, Analyze → Function ID… in the UI). Names only.
- **Untested here: mwcc's own objects.** The tests use clang's objects as a
  stand-in. mwcc's section layout, its symbol and relocation choices (it
  relocation types and sections may differ from clang's; unverified.
- **Why it names so little**: the language, functions under 4
  instructions, the objects' cut bodies, and (in a ROM) functions nothing
  in their own module calls: [decomp-kb.md](decomp-kb.md#why-function-id-alone-named-almost-nothing).

**2. BSim from the decomp's programs.** BSim compares decompiled
functions' features, so it finds what changed a little (another
constant, a reordered branch): ingest the finished game's module programs
(not its objects: unrelocated calls make poor features) and search game 3's
functions against them (`bsim_ingest`, `bsim_search`, `bsim_apply` with
the name, or the name and signature). Untested on ARM32 beyond the
template choice; expect it to work as on AArch64, with the caveats of
[bsim.md](bsim.md).

**3. The decomp knowledge base** ([decomp-kb.md](decomp-kb.md); `api_minor`
105, feature `decomp-kb`): the names together with each function's
verbatim source, its translation unit and the compiler and flags it
matches with, from the finished games' module programs, delinks.txt,
source tree and a matching pipeline's manifest; applied to a new game by
hash, through matched callers (the small helpers) and by BSim (a near
match's source as the scratch, with the instruction diff); exported as
symbols.txt changes and the matched sources in their units. File → Apply
decomp knowledge base… in the UI.

**C++ headers.** revkit's C header import (`ParseC`, C++ mode for `.hpp`)
reads classes' fields, single and multiple inheritance (each base an
unnamed leading field), `enum class`, namespaces and `extern "C"`; it
skips member functions, constructors, operators and templates, and lays
out a class with virtual methods with a `_vptr` pointer (no vtable type).
Measured on a real decomp's 107 `include/**/*.hpp` (with its SDK headers on
the include path): all parse without errors, 4,551 named types (class
`SceneBase` laid out as `_vptr.SceneBase`, `mFinished`, `mContext`, 12
bytes). What fails is the binding: importing the fixture's `game.h` into
the overlay's program leaves `GameOverScene::Update`'s decompilation
unchanged (`*(undefined4 *)(this + 0x14)`): the demangler's `this` type is
its own placeholder class, not the imported class of the same name. That
binding is item 1 below.

## Decompiling mwcc C++: what's missing, ranked

What revkit's ARM32 analysis and decompiler lack for CodeWarrior-built DS
C++ (no RTTI, no exceptions, Itanium mangling), from the fixture's output
and a real decomp's headers, ranked by how much of a decompilation it
spoils and what it costs. A follow-up builds these in order.

| # | Gap | What it does to the C today | What to build | Effort |
|---|---|---|---|---|
| 1 | **Class layouts.** `this` is typed from the mangled name (`GameOverScene *this`) but the class is an empty placeholder | every member access is pointer arithmetic: `*(undefined4 *)(this + 0x14) = uVar1`, `pGVar2 = this + 0x14` | (a) C++ class import from the decomp's headers: cparse already lays out fields, bases and a `_vptr` and skips methods; bind the parsed class to the demangler's placeholder of the same qualified name (types by name across the program), so `this->fade` prints. (b) Inferred structures for `this` (below) when there are no headers | M (a), with 2 |
| 2 | **Inference off on 32-bit ARM.** `--infer-prototypes auto` covers x86-64, AArch64 and RISC-V 64 ([infer.md](infer.md)); ARM32 gets Ghidra's parameter ID at best | callees without an asserted or demangled prototype show `undefined4 f(undefined4,...)` from their own decompilation; no inferred structures for `this`, so (1b) has nothing | Enable inference on `ARM:LE:32:*` (AAPCS: r0-r3, the stack, r0/r0:r1 returns, soft float in core registers), measure against source like the other targets ([decomp-quality.md](decomp-quality.md)), then structures from pointer use for `this` | M |
| 3 | **Vtables and virtual calls without RTTI.** No RTTI in these games: the MSVC RTTI path ([pe.md](pe.md)) doesn't apply. Constructors store `&_ZTV<class> + 8` into `*this` (the fixture: `*puVar1 = &DAT_021001c0`) | a vtable is undefined words (`DAT_021001c0`); a virtual call is `(**(code **)(*(int *)this + 8))(this)` | Itanium vtables from symbols (`_ZTV…` names in symbols.txt: the slots after the offset-to-top and the null typeinfo word are the class's virtual methods in order) and, without symbols, from constructors (a store of a constant pointer into `[r0]` whose target is a run of function pointers in .data/.rodata). Make a vtable struct per class (slot names from the methods' names), type `_vptr`, so a virtual call prints `this->_vptr->Update(this)`; class hierarchy from constructors calling base constructors and vtables sharing slots (MSVC's `GetClassHierarchy` view) | M-L |
| 4 | **Literal pools and data kinds.** dsd's `load` relocations aren't used: pool words and vtable slots read as `undefined4`; `data(word[4])` is undefined bytes | `kRetryItems._8_4_` instead of `kRetryItems[2]`; pools aren't pointers in the listing | At import, `load` relocs in data sections as typed pointers (CODE_UNIT data marks, as the PE markup asserts data), symbols.txt's `data(byte|short|word[N])` as integer arrays | S |
| 5 | **mwcc's runtime helpers.** `_fadd`, `_fsub`, `_fmul`, `_fdiv`, the double forms, `_f2d`/`_d2f`, `_fflt`/`_ffix`, `_s32_div_f`/`_u32_div_f` (quotient in r0, remainder in r1), the 64-bit `_ll_*` | calls show the helpers' names (since api_minor 100 no wrong library prototype), with undefined word types; the float math is invisible as floats | A shipped library archive "mwcc-arm" with their prototypes, applied to raw ARM images with an importer's symbols; a calling-convention override for the r0:r1 division helpers; then let the decompiler print them as operators (a call fixup per helper, as Ghidra's `__aeabi_*` handling would) | S-M |
| 6 | **Static initialization.** `__sinit_<file>` functions and the `.ctor` lists register globals' destructors through `__register_global_object` | globals constructed in `__sinit_` are untyped `DAT_`s; destructor registrations are opaque calls | Read `.ctor` (delinks' section, the overlay table's static-initializer range, `ARM9_CTOR_START`), name and type the global each registration names, link `__sinit_` to its unit | S-M |
| 7 | **References back across modules.** Calls from overlays into main are named, but main's functions don't list their overlay callers, and the call graph stops at the module | "who calls this?" misses every overlay | A cross-program xref index from the module links (each linker's references into a linked program's ranges), in GetXrefs and the call graph | M |
| 8 | **The decompiler pane's follow across programs.** The listing's works (`target_program_id`); the decompiler's tokens carry the address only | following a call into main from an overlay's C goes nowhere | `CodeToken.target_program_id`, filled from the linked lookup | S |
| 9 | **Interworking at the edges.** Thumb from symbols, `blx`/`bl` between modes and ARMv5's `bx lr` work; ARMv4T (the ARM7) calls Thumb through `bx rN` veneers (`_call_via_rN`) | a veneer is a function of its own; its callers call it, not the target | Recognise `bx rN` veneers as thunks to the register's value at each call (the register value analysis has the `mov rN, #target`/pool load) | S |
| 10 | **Mangling.** A new C++ name has to be typed mangled to reach symbols.txt | names written back as typed (`GameOverScene::Draw` isn't a linker symbol) | An Itanium mangler for a name plus its prototype (the class, the parameters' types), used by the export when the name has a C++ prototype | M |

The first three decide whether decompiled mwcc C++ reads like the
source; 4-6 are cheap and remove most of the remaining noise.

## Formats and their sources

| Format | Source | Licence | revkit |
|---|---|---|---|
| dsd's config.yaml, symbols.txt, relocs.txt, delinks.txt | ds-decomp's `lib/src/config/*.rs` (read for the syntax) and a real project's files | MIT | `src/nds/dsd.cc`, `yaml.cc`, written anew |
| ds-rom's extract config | ds-rom's `lib/src/rom/config.rs`, `rom.rs` (read for the field names) | MIT | `parse_rom_extract` |
| .nds header, overlay table, FNT/FAT, NitroFS | GBATEK (problemkaputt.de/gbatek.htm) | public documentation | `src/nds/rom.cc` |
| module parameters, autoload list, ARM9 footer | GBATEK; cross-checked with ds-rom's `raw/build_info.rs`, `raw/autoload_info.rs` | MIT | `rom.cc` |
| BLZ, LZ10, LZ11, Huffman, RLE | GBATEK ("BIOS Decompression Functions") | public documentation | `src/nds/compress.cc` |
| NARC | GBATEK ("NitroARC") | public documentation | `rom.cc` |

No code is copied from ds-decomp, ds-rom, ndstool (GPL) or any game.

## Test fixtures

`tests/data/nds/make_fixture.py` builds them at test time with clang and
ld.lld (the tests skip without them): a little C++ game (`game.h`,
`main.cpp`, `itcm.cpp`, `ov000.cpp`, `ov001.cpp`, `arm7.c`) with classes,
virtual methods, a constructor that stores its vtable, a Thumb function,
mwcc-named soft-float and division helpers, ITCM code and DTCM data,
linked at the DS's addresses, then:

- `game.nds`: header with a valid CRC (no Nintendo logo), a
  BLZ-compressed ARM9 with module parameters, footer and the two autoloads,
  an overlay table with a compressed and a plain overlay sharing
  0x02100000, an ARM7, and NitroFS (`/data/msg.lz` LZ10,
  `/data/huff.bin` Huffman, `/data/pack.narc` a NARC, `/data/sub/tiles.lz11`
  LZ11, `/data/sub/rle.bin` RLE), every compressor the script's own;
- `dsd/`: a ds-decomp project (config, symbols, relocs and delinks from
  the linked ELFs, one function renamed to dsd's placeholder) and its
  extract;
- `objs/*.o`: the relocatable objects, as a decomp's build directory has
  them;
- `dsd3/`: the same project with dsd's placeholder names;
- "game 3": the same source and flags built again, linked in another
  order with code of its own first (every address moves) and
  `GameOverScene::Update` changed by one statement, as a ROM
  (`game3.nds`) and as `dsd init` would leave it (`game3/`, placeholder
  names; `game3-named/` with the names, for the tests);
- `expect.json`: what the tests compare with.

Tests: `src/nds/tests/nds_test.cc` (the formats, the export, the
compressions against the fixture, the ROM), `src/backend/tests/nds_test.cc`
(import, reopen, links in the decompiler, export, refusals),
`sdk/python/tests/test_nds.py` (SDK and MCP),
`sdk/python/tests/test_decomp_kb.py` (the decomp knowledge base),
`ui/e2e/nds.ts`.
