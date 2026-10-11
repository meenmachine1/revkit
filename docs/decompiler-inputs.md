# Decompiler inputs (version 1)

What Ghidra's Java side tells its decompiler about a program, besides the
bytes and the processor and compiler specs. `tools/ghidra-export/ghidra_dbexport.py`
(or `ghidra_export.py --inputs-out`) writes it from an auto-analyzed program;
`rk-lift --decompile --inputs` reads it (`tools/rk-lift/inputs_json.cc` into
`revkit::lift::DecompilerInputs`, `src/lift/include/revkit/lift/decomp_inputs.hh`).
[decomp-parity.md](decomp-parity.md) explains how revkit uses it.

During a decompilation the decompiler asks the Java side
(`DecompileCallback`) about addresses, names, types, comments and register
values; Java answers from the program database that analysis built. This
format holds the facts those answers are computed from, so revkit can give
the same answers in process. revkit applies the decompiler-facing rules
itself (which symbols are locked, how parameters map to storage, when an
address is a hole), following Ghidra's Java encoders, so the same code can
later serve facts from revkit's own store.

One JSON file per binary, mirroring the corpus tree like the reference
format. Addresses are `"0x..."` strings in the default (code/data) space
unless a `space` field names another (RISC-V `csreg`). Fields that don't
apply are omitted.

## Top level

| Key | What |
| --- | --- |
| `format` | `"revkit-decompiler-inputs"` |
| `format_version` | `1` |
| `producer` | `"ghidra-12.1.4"` |
| `binary` | `path`, `sha256`, `language`, `compiler`, `image_base` as in the reference format; `default_convention` (the compiler spec's default prototype name); `address_prefix`: what Ghidra puts before the address in dynamic names (`"ram_"` on RISC-V, where the space name shows: `UNK_ram_00105dc8`; else `""`) |
| `memory` | Ghidra's memory blocks: `name`, `start`, `end` (inclusive), `perms` (`"rwx"` style), `initialized`, `loaded`, `volatile`, `external` (the ELF `EXTERNAL` block), `space` |
| `patches` | Bytes the loader changed, as they read after loading: `{addr, bytes (hex), type, symbol}` per relocation (GOT slots pointing into `EXTERNAL`, `RELATIVE` pointers) |
| `synthesized_memory` | `{addr, bytes}` for initialized blocks no file backs (a PE's thread data block `tdb`, whose `Self` field the decompiler reads) |
| `functions` | Every function in memory (thunks and `EXTERNAL` placeholders included), sorted by entry; see below |
| `data` | Defined data, and undefined bytes that carry a symbol; see below |
| `external_refs` | Pointer data with an external reference (PE import slots): `{addr, label, id, function}` where `function` is the external function, in the same form as `functions` |
| `labels` | Global symbols outside function bodies at addresses with no data (code outside functions, or no memory): `{addr, name, space}` |
| `code_labels` | The primary symbol at addresses inside function bodies, default (`LAB_...`) ones included: `{addr, name}`, namespace-prefixed as `getCodeLabel` sends it (`switchD_001060ad_caseD_1`) |
| `comments` | Comments in function bodies: `{addr, kind: eol\|pre\|post\|plate, text}` |
| `tracked` | Register values the program context holds at each function entry (`getTrackedRegisters`): `{entry: [[space, offset, size, value], ...]}` (x86 `DF`, PE `GS_OFFSET`, RISC-V `gp`) |
| `flow_overrides` | Instructions with a flow override: `{addr, kind}` with kind `BRANCH`, `CALL`, `CALL_RETURN` (ELF PLT jumps), `RETURN` |
| `types` | Every named data type referenced above, in the decompiler's encoding (below) |

## Functions

| Field | What |
| --- | --- |
| `entry`, `name`, `body` | As in the reference format (`body` ranges inclusive) |
| `id` | Ghidra's function id (the id of its local scope) |
| `label` | The namespace-prefixed name `getCodeLabel` gives at the entry, when it differs from `name` (`<EXTERNAL>_abort`) |
| `namespace` | `[[id, name], ...]` from below the global namespace down, when not global (libraries count as global) |
| `signature_source` | `DEFAULT`, `ANALYSIS`, `IMPORTED` or `USER_DEFINED`. Anything but `DEFAULT` locks parameter and return types |
| `convention` | `Function.getCallingConventionName()`: a prototype model name, or `"unknown"` |
| `has_this` | The model passes `this` |
| `extrapop` | Stack bytes a call removes, as `FunctionPrototype.grabFromFunction` computes it, or `"unknown"` |
| `call_fixup`, `call_fixup_noreturn` | Call-fixup injection name, and whether it doesn't fall through |
| `context`, `context_reach` | Context variables painted over the body before it is decoded (`{"TMode": 1}` for a Thumb function, `0` for an ARM one), and ranges outside the body they cover too: code of other functions this one's flow runs or jumps into. Before that the context over those ranges is set back to the language's and the image's, so what decoding other functions set there (`globalset`) is gone: Ghidra's decompiler takes the context from the program database, where only the function's own disassembly set it |
| `varargs`, `inline`, `noreturn`, `custom_storage` | Flags |
| `thunk_of` | The thunked function's entry, or its name if external |
| `return` | `type` (type reference), `default` (Ghidra's `undefined` DEFAULT type), `storage` (varnodes, `null` if invalid), `void_storage`, `size` |
| `params` | `{name, valid, storage, stack, type, auto, id}`: `storage` is a list of `[space, offset, size]` varnodes, `type` a reference sized to the storage, `auto` `THIS` or `RETURN_STORAGE_PTR` for auto-parameters |
| `locals` | `{name, undefined, first_use, storage or hash, type, float, type_size, size, id}`: `undefined` when the type is `undefinedN` (not type-locked); `first_use` the offset from the entry where a register variable starts; `hash` for dynamic storage. An empty `name` (revkit's [variable types](#variable-types) only) isn't name-locked |
| `decompiled_c` | Only with `--with-c`: Ghidra's own C from the same analysis session |

## Data

`{addr, space, name, length, type, mutability, id, namespace, dynamic, string}`.
`type` is a reference sized to `length`. `mutability` is `normal`,
`constant` or `volatile`, from the data's settings or else its block
(`MappedEntry.getMutabilityOfAddress`). `dynamic` marks a default name
(`DAT_...`, `s_hello_00104010`) rather than a symbol in the database.
`string` is the value Java's `getStringData` returns for defined string
data (`StringDataInstance`), when the data is a string.

## Types

Each type is an element of the decompiler's encoding (what
`PcodeDataTypeManager.encodeType` and `encodeTypeRef` produce) written as
JSON: `[tag, {attributes}, [children]]`, children omitted when empty, an
attribute `content` for element text. Numbers and booleans keep their JSON
types; ids above 2^63 are plain JSON integers. For example
`["def", {"id": 360287970189639684, "name": "uLong"}, [["type", {"id": 13835058055282163910, "metatype": "uint", "name": "ulong", "size": 8}]]]`.
References inside functions and data use the same form (`typeref` for
named types, inline `type` elements for pointers, arrays and integers).
`types` holds the full definitions of every named type reachable from
them, so revkit can answer the decompiler's `getDataType` queries.

## How revkit answers from it

`InputDecompiler` (`src/lift/decompile.cc`) follows `DecompileCallback`:

- `getMappedSymbols(addr)`: an import slot gives an external reference; an
  address within 8 bytes of a function's entry gives the function (with
  parameter names locked only for the function being decompiled), elsewhere
  in a body a read-only hole; an address where a register starts, a hole
  (the decompiler uses the register's name); defined data or a labelled
  undefined byte, a data symbol; other undefined bytes in read-only or
  volatile memory, a dynamic `UNK_` symbol; anything else, a hole.
- `getCodeLabel`, `getExternalRef`, `getDataType`, `getComments`,
  `getStringData`, `getTrackedRegisters`: from `code_labels`/`labels`,
  `external_refs`, `types`, `comments`, `data[].string` or raw bytes
  (US-ASCII, UTF-16, UTF-32), `tracked`.
- Each answer is encoded as Java's `HighFunction`, `LocalSymbolMap`,
  `FunctionPrototype`, `HighCodeSymbol`, `HighLabelSymbol` and
  `HighExternalSymbol` encoders would, and decoded by the decompiler's own
  decoders. Everything is forgotten after each function, as
  `DecompInterface` flushes the decompiler process.

## Calling conventions

An asserted prototype (Set signature, a `DefineType` function type applied
by `Retype`, a debug-info prototype whose types were rebound) reaches the
decompiler with its type's calling convention (`types::FunctionType.cc`)
as the compiler spec's prototype model, as Ghidra's Java side commits a
function's calling convention: `__cdecl`, `__stdcall`, `__fastcall`,
`__thiscall`, `__vectorcall`, `__pascal`, `__regcall`, and `MSABI` for
`ms_abi` on a System V target (x86-64-gcc.cspec's name).
`QueryLookup::with_overlay` (`src/backend/own_inputs.cc`) checks the name
against the spec's `<prototype>` and `<modelalias>` names
(`lift::prototype_models`); the model is locked, assigns the parameters'
storage and gives the stack cleanup (`extrapop`) that callers see. A
convention the spec has no model for (`__stdcall` in x86gcc.cspec, a
32-bit ELF) is the default model, with a warning on the function's
output. No convention is the default model, as before. A prototype whose return
is Ghidra's DEFAULT type, `undefined` (C reads it as the 1-byte undefined
type), leaves the return to the decompiler, unlocked, as Ghidra's Edit
Function does; any other return, `void` included, is locked.

On 32-bit Windows (x86win.cspec) the default is `__stdcall`: `__fastcall`
moves the first two parameters to ECX and EDX, and a callee that pops its
arguments (`ret 8`) declared `__cdecl` leaves its callers' stacks wrong.

## Variable types

A parameter or local the user typed (a `Retype` whose target is the
variable, by the storage key its decompilation gives it: `TYPE@entry` with
`sub = local:<key>`, by hash) is committed to the decompiler as Ghidra's
`HighFunctionDBUtil.updateDBVariable` commits one, type-locked, so the
decompiler propagates the type through the body: field accesses
(`param_1->field_0x10`), typed loads and stores, array indexing.
`symbols.variable_types` (`src/backend/queries.cc`) reads a function's
asserted variable types and the storage each key names;
`QueryLookup::commit_variable_types` (`src/backend/own_inputs.cc`) lays
them over the function's facts:

- **`param:N`**: parameter *N* of the prototype gets the type, locked with
  the rest of the prototype; a type of another size has the convention
  assign every parameter's storage again (unless the storage is custom).
  Callers see it as part of the prototype. Where nothing locked the
  prototype (no debug info, asserted prototype, inferred one or Decompiler
  Parameter ID commit yet), the function is decompiled twice: the first
  run's parameters are committed in their storage as `undefinedN`, the
  return left unlocked (Java's `commitParamsToDatabase` without data
  types, which Ghidra's retype action does first), and the second run has
  them and the type. Its callers then see the prototype unlocked. Only
  the inputs are locked: the output stays the decompiler's, in the
  spec's default convention (until 2026-10 the return became a locked
  `void` and the code computing the return value went; tested by
  `AutoStructTest.ATypedParameterLeavesTheReturnToTheDecompiler`).
- **`stack:<offset>`**: a local at that stack offset, as wide as the type.
  Undefined locals of the stack analysis it overlaps are dropped (Java
  clears conflicting ones); a typed one it would overlap (debug info's)
  wins, and the retype stays display only.
- **`register:<name>@<pc>`** (or a register's offset): a local in that
  register from its first use at `pc` (the decompiler's map entry's use
  point), the register named or, for a type of another size, the part of
  it (or the register around it) as wide as the type.
- **`unique:<offset>@<pc>`**, a temporary: mapped by the hash of its
  p-code (`DynamicHash`, Java's dynamic storage), which only a
  decompilation knows (`DecompileOutput::dynamic`, from the Converter), so
  it is decompiled twice, the first run for the hash.
- Keys made unique with `#n` and `name:` keys name no storage: display
  only.

A local without an asserted name is sent unnamed and not name-locked, so
the decompiler names it as it would have (`paVar1` once typed, as Ghidra
renames an uncommitted variable); Java always sends a name. Each key stays
the variable's key after the commit, so its rename, type and auto-struct
fill-in keep finding it. The asserted type's spelling is still printed in
the declaration (`RetypeDeclarations`), and a C-text retype the parser
can't read stays display only. The analyzer's own decompilations
(Decompiler Parameter ID) see none of this: in Ghidra they ran before the
user's edits.

## Equates

An equate or a conversion the user set on a scalar (`OperandDisplay`,
an `EQUATE` assertion: [api.md](api.md#equates-and-user-references))
reaches the decompiler as Ghidra's Java side sends one
(`LocalSymbolMap.grabEquates`): an `EquateSymbol` in the local scope of
the function being decompiled, mapped to a constant varnode by its dynamic
hash, which the vendored decompiler attaches as it does a Java equate
(`Funcdata`'s dynamic symbol mapping) and prints in place of the value
(`PrintC::pushEquate`), or in the conversion's format.

- `decompile.inputs` (`src/backend/queries.cc`) reads the function's
  `EQUATE` keys into `DecompileInputs::equates` (`lift::EquateFacts`:
  the instruction, the value, a name or a format, the hash of a
  decompiler constant no operand holds), which reach the worker through
  the bundle (`RunHooks::equates`).
- `InputDecompiler::place_equates` (`src/lift/decompile.cc`) places each
  as Java's `DynamicHash.calcConstantHash` does: it decodes the
  instruction with the decompiler's own SLEIGH translator, and for every
  constant input of its p-code holding the value (zero- or sign-extended:
  `matchWithPossibleExtension`) computes the level-0 hash of that constant
  and the op reading it (`DynamicHash(op, slot)`), one symbol per distinct
  hash. A decompiler constant named by `constant_hash` gets that hash.
- `encode_function_symbol` writes them in the function's `<localdb>` as
  `HighFunction.encode` writes `EquateSymbol`s: `<equatesymbol cat="1">`
  with the `<value>`, name-locked for a name, with a `format` attribute
  (`hex`, `dec`, `oct`, `bin`, `char`) and no name for a conversion,
  then the `<hash>` and the instruction as the use point.
- The decompiler has no float conversion: `FLOAT` is sent as an equate
  whose name is the formatted value. Signed and unsigned decimal are both
  `dec`; the constant's type decides the sign, as in Ghidra.
- The printer's CONSTANT tokens carry the constant's own dynamic hash
  (`CodeToken.constant_hash`, `DynamicHash::uniqueHash` on the varnode),
  which a Convert or Set Equate on a decompiler token sends when no operand
  of the instruction holds the constant, and `display_set` when an
  `EquateSymbol` printed them.

## User references

A user reference (`UserReference`, a `REFERENCE` assertion) reaches the
decompiler where Ghidra's would:

- **Computed calls.** The primary (or only) user call reference
  (`CALL`, `COMPUTED_CALL`) of a computed call in the function is a call
  override (`DecompileInputs::call_targets`, `RunHooks::call_targets`):
  `Override::insertIndirectOverride` before the analysis, so the
  `CALLIND` becomes a direct call to the target with its prototype, as
  Ghidra's `CALL_OVERRIDE_UNCONDITIONAL` reference makes it. The bundle
  answers for the target's function up front.
- **Computed jumps.** A computed jump with user `COMPUTED_JUMP` references
  has its table installed (`DecompileInputs::forced_tables`,
  `RunHooks::forced_tables`): the targets discovery follows (the table it
  recovered and the user's), given with `JumpTable::setOverride` whether
  or not the decompiler recovers a table itself, as Ghidra's
  `SwitchOverride` script installs the computed jump references as a
  jump table override.
- **Discovery.** A call reference's target is a function, so callers see
  its name and prototype ([api.md](api.md#equates-and-user-references)).

## No return

Whether a function returns, as the user says (`SetNoReturn`, a
`NO_RETURN` assertion at its entry; Ghidra's Set No-Return and Edit
Function's No Return), overrides analysis's no-return inference both
ways:

- `analysis.functions` (Discovery) takes the user's no-return functions
  as known ones before inference (a call to one ends its caller's flow;
  `NoReturnReason::user`), and the user's returning ones are never
  inferred no-return (their callers' flow goes on after the call);
  `analysis.flow` (`detail::named_no_return`) and `analysis.thunk` read
  the mark per call, so bodies, the listing's flow arrows and xrefs
  follow.
- The decompiler's no-return set (`inputs.sets`) is analysis's, so a
  caller's decompilation ends at the call (no dead fallthrough code), and
  the function's own `noreturn` flag is the mark
  (`QueryLookup::with_overlay`).
- Retracted, analysis has its say again. Invalidation: the function list,
  the function, its listing and decompilation, and its callers'.

## Call-site signature overrides

A call's signature override (`CallSignatureOverride`, a `CALL_SIGNATURE`
assertion at the call; [api.md](api.md#call-site-signature-overrides))
reaches the decompiler as Ghidra's per-call-site prototype does (Java's
`HighFunction` sends a `protooverride` for a call with an override
symbol):

- `decompile.inputs` lists the function body's overrides
  (`DecompileInputs::call_signatures`: call -> the function type's hash);
  the run's lookup (`QueryLookup::call_prototype`) makes each a prototype
  as an asserted function prototype is made (`prototype_from`: its calling
  convention's model where the compiler spec has one, the return and
  parameter types and names, varargs; dynamic storage), its types joining
  the run's overlay types.
- The bundle carries them (`LiftFacts::hook_call_protos`, bundle version
  5) with their types, and the worker's `RunHooks::call_protos` become
  `PrototypePieces` (types decoded as the prototype's storage is assigned)
  and a `FuncProto` per call, given with `Override::insertProtoOverride`
  before every analysis of the function, so `FlowInfo::setupCallSpecs`
  copies it into the call's `FuncCallSpecs`: input, output and model
  locked.
- A format string's call-site prototype (`DecompileConfig::format_strings`)
  is never given for a call with the user's.
