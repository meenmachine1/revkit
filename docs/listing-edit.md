# Editing what bytes are, from the listing

Ghidra's Clear Code Bytes (`C`), Disassemble (`D`) and the Data menu,
in revkit: every edit is an assertion with provenance and undo, and
discovery, data analysis and the decompiler read the assertions as
inputs, so they recompute only where an edit changes something.

## Design

Two new fact kinds, both **ordered** like `PATCH` (`fact.order`): where
edits overlap, each byte goes to the live edit of the highest precedence,
then the most recent.

**`CODE_UNIT@start`** says what the bytes from `start` are
(`ListingEdit` in the API; `analysis::UnitMark` in `src/analysis/units.h`):

| `sub` | edit | value |
| --- | --- | --- |
| `clear:<hex length>` | **Clear**: undefined bytes | the length |
| `code` | **Disassemble here**: code starts here, in ARM or Thumb (or as the context says), optionally a function | the mode and the function flag |
| `data` | **Define data**: a typed item (integer, pointer, float, string, struct, array of any of them) | the element type's hash and C name, the count, the string layout, its size, and its layout when defined (fields, pointer offsets; a later binding of the type's name lays it out again, below) |

`analysis.units` paints the live marks in order. A byte belongs to the
newest mark covering it; a data mark is *alive* only while it owns all its
bytes (a newer Clear, Disassemble or data over part of it kills it, as
Ghidra clears conflicting data). Bytes owned by a Clear or a dead data mark
are **cleared**: undefined, whatever analysis thought.

- **Discovery** (`analysis.flow`, `analysis.functions`) reads the map:
  nothing starts in cleared or data bytes (no seed, call target, search
  find or asserted entry, like `fn-remove`'s not-a-function, but for
  code), and a flow stops where it reaches them. A `code` mark is an entry
  that isn't a function (the firmware search's orphan code: walked, shown,
  its calls make functions) unless it has the function flag, or something
  calls it. Its flow is *forced*: it decodes outside executable blocks and
  through cleared bytes older than the mark, so Disassemble here undoes a
  Clear along the flow it follows; it still stops at live data and at
  anything newer.
- **Data analysis** (`analysis.data`) lays the alive data marks down first,
  as `kDataUser` items with their type, and treats every marked byte as an
  obstacle: its steps never define data in cleared bytes.
- **The listing** shows each user item as a typed data row (and a row per
  field or element when expanded), laid out by its type as the program's
  names bind it now; **references** come from its pointers (and from the
  pointers analysis lays down); **names** follow Ghidra (`DAT_`, `s_`, `PTR_`).
- **The decompiler** sees the item as a global of that type: the item is in
  the program's data, and `symbols.effective` gives its address the
  mark's type hash, which the lookup lays over the data as it lays a
  Retype (a `TYPE` assertion still wins).

**`MUTABILITY@start`** (`sub` = hex length) marks a range constant,
volatile or writable (`normal`), or back to what the memory map says
(`default`). `analysis.mutability` paints them like code units, and
`inputs.address` lays the result over the data and the block it reports,
so the decompiler folds reads of constant data (and never folds volatile
ones), per range rather than per block.

Both kinds go through `AppendAssertions` (bodies `listing_edit` and
`mutability`), so they share undo, blame, history, revert by provenance,
collaboration and the change events every other edit has.

- [Using it](#using-it)
- [How each edit steers analysis](#how-each-edit-steers-analysis)
- [Data settings](#data-settings)
- [What an edit recomputes](#what-an-edit-recomputes)
- [Known gaps](#known-gaps)

## Using it

**UI** ([ui.md](ui.md#listing-edits-clear-disassemble-data)). In the listing, Ghidra's keys
where they don't clash with revkit's:

| Key | Does |
| --- | --- |
| `d` | Disassemble here (as the context says; "as ARM" and "as Thumb" in the menu where a program has both) |
| `c` | Clear the selected rows, or the row at the cursor |
| `b` | Define a byte at the cursor; again: word, dword, qword (Ghidra's cycle) |
| `'` | char |
| `"` | a NUL-terminated string |
| `[` | an array of what is at the cursor (or a byte), with a count (default: what fills the selection) |
| `t` | any type, through the type chooser Set type uses |
| `p` | a pointer of the program's pointer size |
| `+` / `-` | expand or collapse a struct or array (also the marker left of its type) |
| `Shift+B` | show or hide the bytes column (was `b`, which Ghidra's data cycle takes) |

The listing's right-click menu has all of them, a Data group (integers,
floats, strings in UTF-8, UTF-16 and Pascal, pointer, array, choose a
type, constant, volatile, writable, back to the memory map's say) and a
"Recently used" group of the types last defined; the palette has them
too. Every action is one step on the tab's undo stack, shows in the
provenance popup (`i`), and reaches every tab and collaborator live.

**API.** `AppendAssertions` with the bodies above (no new RPCs, so
every role that may edit may make them); undo is `RetractAssertions` on
the seqs the response returns (a Define data that parsed a new type also
returns its `TYPE_DEF`s). Refused with `INVALID_ARGUMENT`: an address
outside memory, an empty length, a type the parser can't read or that
has no size, a function type, data running past its block or larger than
16 MiB, a terminated string with no NUL within 64 KiB, an instruction set
on a language that has one. Data may be defined in uninitialized
memory (`.bss`; its values show as `??`), except a string whose length
its bytes would say.

**Python** (`revkit.Program`, and buffered in `revkit.script`):

```python
prog = rk.program("default/prog")
r = prog.define_data(prog.symbol("config"), "struct conf")       # any C type, or a Ghidra name: "dword"
prog.define_data(0x404000, string="utf16")                         # layout="terminated" (default), "fixed", "pascal", "pascal16"
prog.define_data(0x404100, "uint32_t", count=16)                   # an array
prog.clear_code(entry, length=0x40)                                # Clear Code Bytes
prog.disassemble(entry, isa="thumb", function=True)                # Disassemble here (and make a function)
prog.set_mutability(0x404200, 4, "constant")                       # or "volatile", "normal", "default"
prog.retract(*[a.seq for a in r.assertions])                       # undo
```

**MCP**: `define_data`, `clear_code`, `disassemble_here` (the read tool
`disassemble` shows rows) and `set_mutability`, each returning the seqs
for `undo_changes`. **TypeScript**: `listingEdit.clearCode`,
`disassemble`, `defineData`, `setMutability` build the bodies.

## How each edit steers analysis

**Clear.** `analysis.units.code` lists the cleared bytes within code;
`analysis.functions` drops seeds, call targets, search finds and
asserted entries that start in them (as it drops an asserted
not-a-function), so a cleared function is gone though its callers still
call it, and `analysis.flow` stops where an instruction would start in
them or reach into them. Data analysis takes them for obstacles, so the
bytes stay undefined rather than becoming analysis's strings or `DAT_`
labels. Names, comments and types asserted there stay, as in Ghidra.

**Disassemble here.** The mark is an entry of the discovery fixpoint:
an orphan (code, walked for its calls and shown, never a function's
boundary) unless its function flag makes it an asserted entry, and
promoted to a function when something calls it. Its flow is forced: it
decodes outside executable memory, and through bytes whose mark is
older than it (a Clear, a data item it killed), but never through a live
data item or a newer mark. So Clear then Disassemble here gives the code
back along the flow it follows, and undoing either gives back the state
before it. In ARM, the mark's instruction set picks its flow key (a
Thumb entry is the tagged key, as for interworking).

**Define data.** The server resolves the type (a hash, a Ghidra builtin
name, or C the program's types and the library archive's resolve) and
takes, with the mark, what analysis and the listing need: the item's
type and size, its element's C name and value format, its fields (depth
first, nested structs and short arrays) and the offsets of its pointers.
`analysis.data` lays the item down first as a `kDataUser` item (strings
with their text, a lone pointer with its value, anything else
`defined`), follows its pointers as references (their targets get
labels, strings or pointers as analysis's references do), and never
lays analysis data over it. `xrefs.static` has a `DATA_POINTER`
reference from each pointer slot (and from each pointer analysis or the
loader laid down, where it holds a mapped address, as Ghidra's pointer
data does); `names.default` names the item as
analysis names data (`DAT_`, `s_`, `PTR_`); `symbols.effective` gives
its address the item's type hash, which the decompiler's lookup lays over
the data as it lays a Retype (a `TYPE` assertion at the address wins).
`listing.rows` gives the item one row, and when expanded one per field
or array element (at most 4,096), which `GetListing` returns as DATA
rows with `data_field`, `data_parent` and `data_depth`; toggling is the
same definition asserted again with `collapsed` flipped.

**When the type's name is bound again.** Types by hash never change, but
a `BindTypeName` makes another definition the program's one for a name
([types.md](types.md)), and the decompiler's uses follow it
(`types.resolved`). The listing does too: `listing.user_data` lays out
again each item whose element type reaches a name bound to another
definition (`types.resolved` differs from `types.closure`), from the bound
definition: its fields, their C types, value formats and pointers, and the
references those pointers make. `listing.rows`, `xrefs.static` and
`names.default` read the items through it, and a binding's change event
invalidates the program's listing and references, so the rows follow live
and undoing the binding gives the old ones back. The item's extent and
stride stay the mark's (its length and element size): the extent is what
discovery, data analysis and the other edits' liveness go by, and a type
edit moving it would clear or uncover bytes nobody edited. A field (or a
pointer) of the new definition that runs past the element is left out;
defining the item again takes the new size.

**Constants.** `analysis.mutability` paints the `MUTABILITY` marks,
`inputs.mutability` reads one address of it, and `inputs.address` lays
it over the block's mutability and the data's there: constant reads fold
to the bytes' value, volatile ones are kept and never forwarded,
`normal` stops a read-only block's folding, `default` cancels older
edits over its range.

## Data settings

Ghidra's *Data > Settings* and *Default Settings* (`api_minor` 84,
feature `data-settings`): how a defined datum displays, per item, per
struct field, or for every item of a type. A `SetDataSettings` body
carries a `DataSettings`:

| Setting | Values | Applies to |
| --- | --- | --- |
| `format` | hex (`2ah`), decimal (`42`), octal (`52o`), binary (`101010b`), char (`'*'`, the bytes most significant first) | integers, chars, bools, enums, undefined bytes, array elements |
| `signedness` | signed, unsigned | integers |
| `endian` | little, big (default: the program's) | integers, floats, pointers, UTF-16 and UTF-32 strings |
| `padding` | padded (leading zeros to the width), unpadded | hex, octal, binary |
| `charset` | US-ASCII, ISO-8859-1, windows-1252, UTF-8, UTF-16 (in `endian`), UTF-16LE, UTF-16BE, UTF-32, UTF-32LE, UTF-32BE | strings (defined or data analysis's), char arrays |
| `termination` | at the first NUL, every character (NULs as `\0`) | strings, char arrays |
| `pointer_kind` | absolute, image-base offset (an RVA), relative to the pointer | pointers (defined or data analysis's) |
| `pointer_mask`, `pointer_shift` | the stored value's bits, then a left shift (negative: right), before the kind | pointers |

Mutability, Ghidra's other data setting, is `SetMutability` over the
item's bytes; the UI's dialog asserts both in one step.

(With this, a string's or char array's bytes that aren't UTF-8 show as
`\xNN` whatever its settings: they used to reach clients as invalid UTF-8,
which protobuf clients refuse to read.)

**Stored apart from the definition.** A data definition's `CODE_UNIT`
mark is untouched: settings are `NOTE` keys with reserved tags, so every
data definition made before them reads exactly as it did, and with no
settings a row shows exactly as before.

| Key | Settings of |
| --- | --- |
| `NOTE@item`, tag `revkit:data-settings` | the item: its row and, for an array, each element's |
| `NOTE@item`, tag `revkit:data-settings:<field>` | a struct field's row (`field` is its `data_field` path, `hdr.magic`) |
| `NOTE@0`, tag `revkit:data-type-settings:<type>` | every row of the type (its `data_settings_type`: the element's C type, or `string`, `unicode`, `unicode32`, `pointer`, `undefinedN` for data analysis's rows) |

The value is text (`format=decimal;sign=signed`); an empty one removes
them. Each setting a row's own settings leave unset comes from its type's
defaults, then from how the type shows. A daemon from before this feature
opens such a project and imports its archive (`NOTE` is a fact kind it
knows; it reads the settings as notes, which only its next-note
navigation sees), and shows the rows as it always did. `Note` bodies
can't use the reserved tags, and next-note navigation skips them.

**What follows them.** `listing.page` reads the settings of its rows'
items (and the type defaults) as inputs, so the listing, listing search
and copy show the values as set, and an edit re-renders only the pages
of the item (a type's defaults: every page). Settings stay when the data
is cleared or defined again, as comments do, and apply to whatever data
row starts there; analysis's own data takes them too. Rebasing moves an
item's settings with it; a type's stay the type's. Only the display
changes: the definition's extent, references (a pointer's reference is
still its absolute target), the decompiler and data analysis don't.

**Using it.** The listing's Data menu has *Settings…*: a form with
"This item" or "Every `<type>`", the settings that apply to the row's
kind, and the item's mutability ([ui.md](ui.md#data-settings)). Python:

```python
prog.set_data_settings(prog.symbol("threshold"), format="decimal", signed=True)
prog.set_data_settings(cfg, "hdr.magic", format="hex", padding="padded")   # a struct field
prog.set_data_settings(banner, charset="ISO-8859-1", termination="all")
prog.set_data_settings(rva_slot, pointer="image-base")
prog.set_type_data_settings("uint32_t", format="decimal")                 # every uint32_t
prog.set_data_settings(prog.symbol("threshold"))                          # none: removed
```

MCP `set_data_settings` (an address and field, or `type_name`), and the
TypeScript builder `setDataSettings(address | { address, field } |
{ typeName }, options)`.

## Clear Flow and Repair

Ghidra's *Clear Flow and Repair* (`api_minor` 83, feature `clear-flow`):
`QueryService.PlanClearFlow` plans it and a client asserts the plan as
ClearCode edits in one `AppendAssertions`, so it is one revision and one
undo step, with the user's provenance like any other edit. The plan:

1. The flow from the instruction: fallthrough, branches, jumps and the
   targets of recovered jump tables, in the flow graphs of the functions
   that hold it; with `follow_calls`, also into the functions it calls.
2. Less what other code reaches: from the entry of every other function
   with code in that span (and of every callee something outside the flow
   calls), the flow that doesn't pass through the start. Those
   instructions stay code: that is the repair, since flows into the
   cleared code from outside keep what they reach.
3. The rest, merged into ranges where they touch, are the ClearCode
   edits; the functions whose entries are in them go (`functions`).

Since a ClearCode edit lets nothing start in its bytes, code that flowed
into the start before stops there afterwards, the way Ghidra's repair
leaves the start cleared. The listing's *Clear flow and repair* (the
right-click menu and the palette), the SDK's `Program.plan_clear_flow()`
and `clear_flow()`, and MCP `clear_flow` (with `dry_run`) use it.

## Fallthrough overrides

Ghidra's *Set Fallthrough* and *Clear Fallthrough* (`api_minor` 85,
feature `fallthrough-override`): a `SetFallthrough` assertion says where
control goes on after an instruction, instead of the next one, or that it
doesn't go on ([api.md](api.md#fallthrough-overrides)). It steers
discovery like the edits above: `analysis.flow` reads `FALLTHROUGH` keys
through the key index's spans, so only the flows that decode the
instruction run again, then the fixpoint, and the rows, references and
decompilations that read them. The bytes it skips (inline data after a
call) stay out of the body and show as undefined, ready for Data. The
listing marks the instruction (`⤷ fallthrough: <address>` or `⤷ no
fallthrough`, after the operands, with a flow arrow to the address),
and its menu has *Set fallthrough…* and *Clear fallthrough*
([ui.md](ui.md#fallthrough-overrides)).

## What an edit recomputes

An edit changes `analysis.units` (all the program's marks, a cheap
program-wide paint). `analysis.units.code` cuts off unless the marks
within code changed, so a data definition in `.data` doesn't run
discovery again. Flows read `analysis.units.bucket` for the 64 KiB
buckets they decode in, which cut off except where the edit is; the
fixpoint and the flows that saw the edit run again, then data analysis,
names, rows and what read them, as for a function-bounds edit. A
mutability edit re-runs `inputs.mutability` per address read and cuts
off except over its range; decompilations that read there run again.
Subscribers get the discovery effects (functions, rows rebuilt with
their row windows, references, labels) plus the edit's own range.

## Known gaps

- A data definition keeps the extent it was made with: a rebound name's
  fields follow ([above](#how-each-edit-steers-analysis)), but a larger or
  smaller definition doesn't grow or shrink the item until it is defined
  again.
- An ARM mark over code the program's context paints Thumb decodes as
  Thumb (the context wins).
- Clear doesn't take away names, comments or types asserted in the
  bytes; Ghidra's "Clear With Options" isn't offered.
- Data settings are display only: a pointer shown as an image-base offset
  or masked still makes its reference to the absolute value analysis
  read, and the decompiler, the Data view (`ListData`) and hover cards
  show values as their types do. Charsets beyond the ten listed
  (Shift-JIS, EBCDIC, other code pages) aren't offered. Ghidra's
  per-instance settings on a nested struct's array elements are kept per
  field path, not per element.
