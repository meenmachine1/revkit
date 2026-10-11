# The memory map after import

Every program has a memory map: the blocks its loader made (an ELF's or a
PE's sections, a raw image's block and the regions declared at import),
each with its range, permissions, whether it is initialized or volatile,
and where its bytes come from. Since `api_minor` 24 (feature
`memory-map`) the map can be edited after import, as Ghidra's **Window →
Memory Map** and **File → Add To Program** edit it:

- **add a region**: uninitialized RAM, zero-filled memory, memory-mapped
  I/O (volatile), or **bytes from another file** at an address (a second
  flash dump, a bootloader, a RAM dump), from an offset in that file and
  for a length;
- **change a region the user added**: its name, start, size, permissions,
  initialized and volatile flags (never its bytes);
- **change one of the image's own blocks**: its name, permissions and
  volatile flag, as Ghidra allows (never its range or bytes);
- **remove** a region the user added, or revert an image block's edits.

Each edit is an assertion with provenance, blame, undo and redo, shared
live with collaborators like any other edit, and analysis, the listing,
references, data, the decompiler and the emulator follow it. Before this,
extra memory could only be declared at import (`rk-lift --region`,
`ImportOptions.regions`, the Open dialog's regions), and changing it meant
importing again.

- [Using it](#using-it)
- [Design](#design)
- [What an edit recomputes](#what-an-edit-recomputes)
- [Collaborators](#collaborators)
- [Rebase: setting the image base](#rebase-setting-the-image-base)
- [Known gaps](#known-gaps)

## Using it

**UI.** The **Memory map** view (`Ctrl+Shift+M`, or "Show memory map" in
the palette; a main-area tab) lists the blocks in address order: name,
start, end, size, permissions, initialized, volatile, source (`image @<file
offset>`, `<file> @<offset>`, `zero-filled`, `none`) and who added or last
edited it (`loader` for the image's own). **Add region…** (`a` in the
table; palette "Memory map: add a region" and "Memory map: add bytes from a
file") opens a form for every kind; bytes from a file are uploaded from
this computer or chosen on the daemon's host (with `--browse-root`, the
same browser rules as importing). The pencil (`e`, `F2`) changes a region
or an image block, the cross (`Delete`) removes a region, ↺ reverts an
image block's edits. The daemon's checks show in the form, which stays
open ("region low [0x80, 0x17f] overlaps block ram [0x0, 0xff]"). Every
change is on the tab's undo stack (`Ctrl+Z`), and every tab and client
reloads (the edit's event invalidates the program). Clicking a row goes to
its start in the listing.

**Python** (`revkit.Program`):

```python
prog = rk.program("default/fw.bin")
ram = prog.add_memory_region("sram", 0x20000000, 0x1000)                 # uninitialized RAM, rw-
prog.add_memory_region("uart", 0x40011000, 0x400, volatile=True)          # MMIO
prog.add_memory_region("boot", 0x100000, perms="r-x", path="/data/boot.bin")   # Add To Program (admin)
prog.add_memory_region("cal", 0x80000, perms="r--", content=data, file_offset=0x10, length=0x100)
prog.update_memory_region(ram.region_id, volatile=True)                   # fields left None keep their values
prog.update_memory_region(0x0, name="flash", perms="r-x")                 # an image block, by its start
prog.remove_memory_region(ram.region_id)
prog.retract(ram.assertion.seq)                                           # undo any of them
for b in prog.memory_map(): print(b.name, hex(b.range.first.offset), b.source)
```

**MCP**: `memory_map`, `add_memory_region`, `update_memory_region`,
`remove_memory_region` (and `undo_changes` with the seq they return).
**TypeScript**: `rk.projects.addMemoryRegion`, `updateMemoryRegion`,
`removeMemoryRegion`, `rk.queries.getMemoryMap`
(`sdk/ts/test/memory.ts`).

**API** ([api.md](api.md#queries), "Memory map"):

| RPC | Role | Does |
| --- | --- | --- |
| `QueryService.GetMemoryMap` | viewer | `blocks` (the effective map) and `rejected` (regions it can't place); each `MemoryBlock` has `is_volatile`, `region_id`, `edited`, `source` and `origin` |
| `ProjectService.AddMemoryRegion` | editor; **admin** to read a host `path` | a `MemoryRegion` (name, start, size, permissions, `initialized`, `is_volatile`), and for bytes from a file `path` or `content`, `file_name`, `file_offset`, `length`; `validate_only` |
| `ProjectService.UpdateMemoryRegion` | editor | a user region by `region_id`, or an image block by `block_start` |
| `ProjectService.RemoveMemoryRegion` | editor | the same |

Each returns the `Assertion` it made: `RetractAssertions` on its seq
undoes it. Overlaps and wrapping are `INVALID_ARGUMENT` with the raw
loader's wording; an unknown region is `NOT_FOUND`; removing an image
block that has no edits is `FAILED_PRECONDITION`. `AppendAssertions`
refuses `memory_region` bodies. Bytes from a file follow `ImportProgram`'s
rules: a host path needs admin (any path the daemon can read, as an import
by path; the UI offers the `--browse-root` browser), uploads are bounded
by the daemon's message size, files by 4 GiB.

## Design

### Where edits live

A memory-map edit is a `MEMORY_REGION` assertion (`facts::FactKind`
10, `FACT_KIND_MEMORY_REGION`) in the program's space at address 0:

| `sub` | Value (`src/analysis/include/revkit/analysis/memory.h`) |
| --- | --- |
| `region:<id>` | a region the user added (`RegionSpec`: name, start, size, permissions, initialized, volatile, and for bytes from a file where they are staged, their length and sha256, the file's name and offset); the id is the daemon's, random |
| `block:<hex start>` | an edit to one of the image's blocks (`BlockEdit`: name, permissions, volatile) |

The value `""` removes the region or reverts the block's edits, so a
removal is an assertion too (blame shows who removed what), and undo is a
retraction as for every edit. Changing a region asserts its whole new
state on the same key. The op's body (`AssertionBody.memory_region`,
`MemoryRegionEdit`) says what the edit did, for history and events.

A region's bytes from another file are not in the log: they are written to
the fact store's bytes (persisted with the project, like the program's own
file), in the program's file space above the file, at a 4 GiB slot chosen
by their sha256 (equal bytes share one copy). The assertion records where
(`RegionBytes`), so removing, undoing and redoing never move bytes, and a
replica stages arriving bytes where the assertion says ([below](#collaborators)).

### How analysis sees them: the map is a query

The fundamental question was whether memory can be an assertion-backed
derived query without a full re-load. The options:

1. **Re-load on every edit.** Rebuild the image with the regions, and stage
   new inputs (ProgramInfo, DataProgramInfo, image bytes, the program
   record) in the edit's transaction, as an import does. Analysis is
   untouched, but the inputs stop being a function of the log: every
   operation that changes which edits are live (undo, redo, a revert by
   provenance, a collaborator's merged ops, a reopen) needs its own
   re-stage hook, two of them can't share one revision, and a missed path
   leaves stale memory with no error.
2. **A derived query over the assertions** (chosen). `analysis.memory`
   computes the effective map from the loader's blocks and the
   `MEMORY_REGION` keys (read through the key index, so it depends on
   exactly those keys). The two inputs analysis read the memory from,
   `analysis.program` (ProgramInfo) and `analysis.data_program`
   (DataProgramInfo), become derived queries over it, and the loader's
   views move to new inputs, `analysis.program.loaded` and
   `analysis.data_program.loaded`, which `stage_image` sets. Every log
   operation is then right by construction: the store re-derives liveness,
   the map follows, and what reads it revalidates.
3. **Per-region inputs** (an input per region that a commit hook keeps
   in step) has option 1's problem with fewer moving parts, and no gain.

Option 2 keeps analysis incremental: queries recompute only where the
map's value changed, and the fact engine's early cutoff stops them where
their results don't (below). It also costs nothing for programs without
edits: `analysis.program` and `analysis.data_program` keep their names and
return the loaded values unchanged, with the same fingerprints, so every
memo that read the old inputs validates against the queries (persistent
projects reopen without recomputing). New fields are encoded only when
set for the same reason (`ProgramInfo::sources` behind a flag bit,
`DataBlock::is_volatile` as a flag bit).

What the map changes, for analysis (`src/analysis/memory.cc`):

- `ProgramInfo::mapped` gains the regions (constants pointing into them
  are references: pointers into new RAM become data references);
  `ProgramInfo::code` is the executable, initialized blocks of the map (a
  region from a file with `x` is code discovery decodes; an image block
  made non-executable is no longer code);
- `ProgramInfo::sources` says where an added region's bytes are: zeros,
  or the staged file bytes. Every reader of program bytes in analysis
  (`detail::ByteReader`: flows, jump tables, data analysis, strings,
  `CodeReader` for diffing and plugins' code) lays them over the program's
  pages; an uninitialized region has no bytes, so nothing reads it as
  known;
- `DataProgramInfo::blocks` are the map's: data analysis lays data down in
  added RAM (`DAT_` labels where code refers), searches a file's bytes for
  strings, and volatile blocks stay volatile.

**Conflicts.** A region that overlaps a block, or wraps, is refused when
asserted. Undo and concurrent edits can still make two live regions
overlap (undoing the removal of a region whose place another one took
since; two collaborators adding regions at once). The map then keeps
regions in a deterministic order, by start, then id (every replica agrees),
and reports the others in `GetMemoryMapResponse.rejected` with the reason;
they are not mapped until moved or removed. The UI lists them as "not
mapped".

### How the image backend sees them: a variant of the program

The listing, references, the decompiler, the emulator and the debugger
read memory through the backend's `Program` (a `loader::Image`, SLEIGH
engines over it, and a decompiler pool), not through fact-store pages.
`Program::WithMemory(map)` builds a variant of the loaded program with the
map laid over a copy of its image: the image blocks renamed or with new
permissions and volatile flags, the user's regions as blocks, and their
memory (a `loader::Memory` region can now take its bytes from a buffer of
its own: `Memory::add(region, bytes)`). It shares the language, the debug
info, the decompiler workers and the per-program bookkeeping with the
loaded program; it has its own SLEIGH engines and decompiler architecture.
Variants are cached by the map's encoding (the last four), so a map is
built once. The image's part is `analysis::image_with_memory`
(`src/analysis/memory.cc`), which prototype inference uses too (below).
An image block's edited permissions reach its memory: where the block is a
whole loaded region (raw images) the region takes them, and where it is
part of one (an ELF section inside its segment) the region is split at the
block's bounds, each piece keeping its bytes (`loader::Memory::set_perms`
over a range), so the emulator and the debugger map the section with its
own permissions and the rest of the segment with the segment's
(`EmulatorApi.AnEditedSectionsPermissionsReachTheEmulator`).

**Prototype inference** (`src/infer`, [infer.md](infer.md)) reads the
image through `infer.image.effective`: the staged image as is for a
program without edits (the same value, so nothing recomputes), else the
image with the map laid over it and a decompiler pool over that, its
identity naming the map. Its rules (the call graph's code-pointer tables,
each observation's decompilation, the ABI and data organization) follow
an edit, and the daemon runs inference again after one (memoized rounds
recompute where the map changed what they read). A constant a function
returns becomes a pointer once a region maps its address
(`FactStoreTest.InferenceReadsTheMemoryMap`).

`EffectiveProgram(ctx or snapshot, program)` reads the program's source and
`analysis.memory` and returns the variant: every backend rule that reads
memory through the program goes through it (`names.loader`,
`listing.code`, `xrefs.function`, `names.default`, `listing.rows`,
`listing.page`, `symbols.effective`, `inputs.static`, `inputs.program`,
`inputs.function`, `decompile.ghidra`, parameter ID, BSim signatures), so
each depends on the map. Their rule versions went up so that memos computed
before (which don't carry that dependency) are recomputed once, except
`decompile.ghidra`, whose memos depend on `inputs.image`, which changes
with any edit that changes memory (the decompiler's blocks are in it). The
API's views (`GetListing`, `ReadMemory`, `GetProgramSummary`, `Decompile`)
take the variant at their snapshot's revision; emulator and debugger
sessions take the one at head when they start. Rules that only need the
program's identity (the library's types, header lines) read the source
alone, so an edit doesn't revalidate them.

So, on the hand-assembled ARM firmware of `MemoryMapTest`
(`src/backend/tests/memory_map_test.cc`), whose code reads RAM, a constant
in another file and calls into a third, before and after:

```c
// read_ram, before                     // after "sram" at 0x20000000 (uninitialized RAM)
undefined4 FUN_00000040(void)           undefined4 FUN_00000040(void)
{                                       {
  return uRam20000000;                    return DAT_20000000;
}                                       }
// read_const, before                   // after "consts" at 0x80000, r--, from a file holding 0x12345678
  return uRam00080000;                    return 0x12345678;
                                        // the same region made volatile
                                          uVar1 = DAT_00080000;
                                          return uVar1;
```

`GetXrefs` to 0x20000000 goes from none to the literal-pool load, and the
call to 0x100000 becomes a function (`FUN_00100000`, `return 7;`) once
the bootloader's bytes are added there; undoing each takes it back. On the
firmware corpus ([firmware.md](firmware.md#other-processors)), importing
an image bare and adding its RAM and MMIO regions afterwards gives the
same functions, data, references into the regions and decompiled C as
declaring them at import (Cortex-M fwkit -O2: 523 functions, 2,173 data
items, 66 of 66 sampled functions' C identical; likewise MIPS fwkit -O2,
Xtensa ESP32 fwkit -O2 and PowerPC U-Boot MCR3000).

## What an edit recomputes

ProgramInfo is read by every flow, so any edit that changes it (a region
added or removed, a block's permissions) runs discovery's flows again and
its fixpoint once; their results are compared by fingerprint, and what
didn't change cuts off there: functions, references, rows and data are
recomputed but their unchanged values stop invalidation, and per-function
queries of unaffected functions validate. Every decompilation runs again
when next read, since the decompiler's memory blocks are part of each
one's inputs (as in Ghidra, where a memory map change re-analyzes).
`MemoryMapTest.AnEditRerunsDiscoveryOnce` counts it on the 11-function
firmware: one `analysis.memory`, one `analysis.functions`, 11 flows, 5 of
11 `analysis.function` slices, one listing and one `names.default`, and
each decompilation once. The edit's RPC warms discovery, references and
the listing at the new revision before it answers (as an import does):
0.2 s on Lua (786 functions, 1.2 MB), about 1 s per region on a 140 KB
Cortex-M firmware, where the firmware search runs again. An edit that
leaves ProgramInfo as it was (an image block's name or volatile flag)
doesn't run discovery again: ProgramInfo cuts off, and only the
decompiler's inputs and what reads them follow.

Subscribers get the program in `invalidate_all_programs` and a `MEMORY`
invalidation: every view reloads, as after an import.

## Collaborators

`MEMORY_REGION` assertions replicate like every other op. A region's
bytes from another file travel the way a program's file does: a daemon
holding an assertion whose bytes it lacks lists them in its sync state's
`missing_programs` (by sha256 and size, with the region's program id), a
peer serves them through `FetchProgram`, and the chunks arrive in `Push`.
Until they do, the region is mapped but uninitialized
(`MemoryBlock.source.missing`); when they arrive they are staged where the
assertion says, in one revision that invalidates the program.
`CollabTest.MemoryMapEditsReplicateWithTheirBytes` checks it with two
daemons.

**Address spaces and patches.** A region may be in another memory space
the program has (`MemoryRegion.space`: an 8051's `EXTMEM`, AVR's data
memory): its start is an offset there, keyed as the program's other
addresses in that space are (`AddressSpaceInfo.key_base`), and it may not
leave the space. Patches (`PatchService`, [patching.md](patching.md)) lay
over an added region's bytes as over the image's: the file's bytes, then
the patch, in analysis, the listing, the decompiler and plugins.
**Analyzer plugins** see the effective map (`plugins.program_info`) and
read added regions' bytes (`MemoryMapTest.RegionsInAnotherMemorySpace`,
`PatchesLayOverARegionsBytes`).

## Rebase: setting the image base

A program's **image base** can be changed after import (Ghidra's
**Set Image Base**; `api_minor` 42, feature `rebase`): the whole program
moves by the difference, its functions, symbols and every fact the users
and tools recorded about it (names, comments, types, listing edits,
patches, notes, memory regions, references, function bounds, flow
overrides), and the history of those edits with them. Raw images are the
main use: their base was detected or guessed at import, and a wrong guess
must be fixable after hours of work without losing it.

**UI.** The Memory map view's **Set image base…** (palette "Memory map:
set image base") asks for the new base, showing where the program is and
where it was imported, and checks it with the daemon before it moves
(`validate_only`). It is one edit on the tab's undo stack: `Ctrl+Z` moves
the program back. Every tab and client reloads; the cursor and the
back/forward history move with the program.

**Python**: `prog.set_image_base(0x08000000)`, `prog.image_base()`,
`prog.import_image_base()`, `prog.retract(r.assertion.seq)` to move it
back; in scripts `set_image_base(base)` and `image_base()`
(`revkit.script`; it commits at once, after any buffered edits).
**MCP**: `set_image_base` (and `undo_changes`); `program_summary` shows
`image_base` and `import_image_base`. **TypeScript**:
`rk.projects.setImageBase({programId, imageBase})`, `REBASE_FEATURE`.

**API**: `ProjectService.SetImageBase{program_id, image_base,
validate_only}` (an editor's edit) returns the `Assertion` (a
`FACT_KIND_REBASE` key at address 0 with an `ImageBaseBody`: the new,
previous and import bases), `image_base`, `previous_image_base` and
`import_image_base`. A base the image's blocks wouldn't fit at (wrapping
the default space's addresses) is `INVALID_ARGUMENT`; a program a loader
plugin laid out is `FAILED_PRECONDITION`. `ProgramSummary.image_base` is
where the program is now, `import_image_base` where it was imported.
`AppendAssertions` refuses `image_base` bodies. Subscribers get the
program in `invalidate_all_programs` with a `MEMORY` invalidation, as
after a memory-map edit.

### Design: facts are image-relative, the base is a fact

There were two ways to keep the facts with the code when the code moves:

1. **Store facts by image-relative offset** (chosen). Every key and
   address in the log is relative to a fixed origin, and the current base
   is a fact of its own; what a reader sees is the stored offset plus the
   base.
2. **Record a rebase fact that maps old addresses to new on read**, with
   facts stored at the absolute addresses of their time. Rejected: an
   op's meaning would depend on whether it was made before or after each
   rebase, and with collaborators "before" is undecidable (two peers'
   concurrent ops straddle a rebase in stamp order but not in what their
   authors saw); undoing a rebase would have to map back the edits made
   after it; and every read would replay the chain of rebases.

With (1) the mapping is one number per program, decided by the liveness
of one assertion, so undo, redo, a revert, a collaborator's merge and a
reopen are right by construction, as for the memory map
([above](#how-analysis-sees-them-the-map-is-a-query)).

**The origin is the import base.** A program's keys are the addresses its
facts had at import, which is what every existing project already holds:
nothing migrates. The rebase is a `REBASE` assertion
(`facts::FactKind::Rebase`, `FACT_KIND_REBASE`) in the program's space at
address 0 whose value is the **delta**, the new base minus the import
base (two's complement, wrapping in 64 bits). Setting the base again
asserts the key again (setting it back to the import base asserts 0), so
the latest assertion wins and undoing it returns to the one before; it
replicates, blames and reverts like any edit, and `AppendAssertions`
refuses it (only `SetImageBase` makes one).

**The fact store presents the moved addresses** (`src/facts/fact_db.cc`).
It keeps each program space's delta (the live `REBASE` value) and indexes
every key at its effective address: the stored address plus the delta,
for the kinds that are addresses (all but `TYPE_DEF`, `MEMORY_REGION`
and `REBASE`), in the space's default memory (keys below 2^40: AVR's data
memory and the 8051's `EXTMEM` don't move, as Ghidra moves only the
default space), and `Address` and `AddressSet` values the same way
(function bodies). `AssertedFact`, the key index (buckets, spans) and
`AssertedOrder` hold effective keys, so **every query reads effective
addresses and none changed**. A commit that changes a space's delta
re-indexes that space's keys in the same revision: their old effective
keys read as absent, their new ones as their values, and everything
derived from them recomputes (as after a re-import: every key moved).
`Transaction::assert_fact` takes an effective key and value and stores
them image-relative (minus the delta at head); `merge` takes ops as
stored, since peers send the log's own encoding. The log itself
(`AssertionLog`, its persisted ops, `ops_since`, archives) only ever
holds image-relative keys.

**The API translates what it reads from the log**
(`src/backend/image_backend.cc`): ops' keys and values (history,
`ListAssertions`, blame, events, the key filter of a revert) get the
delta at the read's revision added, and so do the request bodies an op's
meta keeps for display, which are stored image-relative: every `Address`
in the default space of an `AssertionBody`, found by reflection, so a
rename's target, a function's body, a patch's address and a memory
region's start all move. A key in a request (blame, `ListAssertions`
filters, raw `FactKey`s) is effective and has the delta subtracted.

**The program reloads at the new base.** The decompiler, the listing and
data analysis read the program's image and its bytes (`program.source`,
the pages in the program's space), which an import stages. When a commit
changes a space's delta, whatever made it (the `SetImageBase` RPC, an
undo, a redo, a revert, ops merged from a peer), the fact store calls the
backend back inside the same commit (`FactDbOptions::on_rebase`), and the
backend loads the program as an import at the new base would
(`Program::Options::image_base`, or a raw image's `base`; a PIE's
RELATIVE relocations applied for the new base, `relocate.cc`) and stages
what an import stages: the program source, discovery's and data
analysis's loaded views, the plugins' and inference's inputs, and the
image's bytes at the new addresses. One revision holds both, so no reader
sees moved facts over an unmoved program. On reopen the store indexes
with the deltas its log gives and the backend loads each program at its
effective base; the pages are those last staged (persisted with the
commit).

**What else follows the delta.** A memory region the user added keeps its
start image-relative in its value (`analysis.memory` adds the delta), and
`block:<start>` edits name an image block by its import-time start. A
raw image's import-time regions move with it, as Ghidra moves every block
of the default space. A PIE's relocated pointers follow; a PE's are not
re-applied (an import at that base doesn't apply them either), and a
non-PIE's code keeps its absolute addresses, so rebasing one is for
matching another tool's addresses, as in Ghidra.

**Costs.** A rebase re-indexes the program's keys (proportional to the
facts recorded about it), re-stages its pages, and every derived fact
about the program recomputes when next read, as after an import. Its
background passes (inference, Decompiler Parameter ID) run again, their
published prototypes cleared in the rebase's commit (they named functions
where they were).

**Checks.** `src/facts/tests/rebase_test.cc`: keys read moved and stored
image-relative, values and the key index moved, a later rebase replacing
an earlier and undo returning to it, keys landing where others left, the
callback staging in the rebase's own commit, replicas merging a rebase and
the edits made after it (and one made before a peer saw it), and a reopen.
`src/backend/tests/rebase_test.cc` is the gate: the corpus's `cjson`
(gcc -O2, with its DWARF) with a user's work (renames, a struct from C and
a prototype using it, plate and end-of-line comments, a patch, a listing
edit, a memory region from another file's bytes, an image block's edit, a
note, an undone rename), moved by +0x10000: the function list (entries,
names, prototypes), the listing around fifteen functions (header rows,
labels, operands, comments), their decompiled C, every op of the history
and every effective assertion (keys and request bodies), the memory map
and the first bytes of each block (a PIE's relocated pointers moved) all
read as before at the shifted addresses; an edit made there goes back
with the program; moving back by `SetImageBase` and by undo gives exactly
what was there; it persists across a reopen; and the case it is for, an
ARM firmware imported at 0x10000 instead of 0 (no function found), moved
to 0 with its rename and plate comment: its vectors and functions are
found. `sdk/python/tests/test_rebase.py` (the SDK, a script, MCP),
`sdk/ts/test/memory.ts` and `ui/e2e/memory.ts` (the dialog, page B
following, `Ctrl+Z`) check the rest.

## Known gaps

- **Rebase.** A diff session's matches name the other program's entries in
  their values and subs: rebasing one side leaves them naming the other's
  old addresses until matched again. A PE's base relocations aren't
  re-applied (as at import), nor are a non-PIE's absolute addresses: a
  rebase there is for matching another tool's addresses. Every region of
  the default space moves with the image (as in Ghidra), memory-mapped I/O
  declared at import too: update it if it shouldn't. Memos computed before
  a rebase stay in the store until evicted.

- Region names are free text (no `/` or control characters), unlike
  Ghidra's block-name rules; overlays are not offered.
- The UI's address column width is chosen at load from the image's highest
  address, so a region above it widens nothing until a reload.
- The Open dialog still takes import-time regions as text lines; the
  region editor (`ui/src/ui/regionform.ts`) is standalone and could
  replace them.
