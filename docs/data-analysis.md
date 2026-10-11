# Data analysis

Ghidra's analyzers define data in a program before its decompiler runs:
strings, pointers, the sized `undefinedN` of every global code touches,
switch labels, and functions found not to return. The decompiler's output
depends on all of it (`"text"` against `&DAT_00104010`, `DAT_x` against
`_DAT_x`, `goto switchD_..._caseD_3` against `goto LAB_...`, `abort();`
against `abort(); return;`). revkit's data analysis produces the same facts
from revkit's own discovery, as fact-engine queries, so that decompiling
from revkit's own inputs (`rk-lift --analyze --decompile`, the daemon)
matches Ghidra's C; [decomp-parity.md](decomp-parity.md#from-revkits-own-inputs-phase-3)
measures it. The signatures Ghidra's Decompiler Parameter ID analyzer
commits for a program's own functions (after these analyzers, on small
PEs) are in [param-id.md](param-id.md).

| Query (src/analysis) | What | Reads |
| --- | --- | --- |
| `analysis.data_program` (input) | what the loader knows about memory that discovery doesn't need: blocks and permissions, base relocations (PE `.reloc`, ELF relocations) and whether the program is relocatable, ranges the loader marks up (PE headers, exception table, import slots, relocated slots), `.got` entries, ELF object symbols | set at import (`stage_image`) and on reopen |
| `analysis.flow` (`FlowGraph::data_refs`) | each flow's data references: loads and stores at constant addresses with their sizes, addresses computed into registers or stored, from constants carried along the flow while it decodes | the flow's own decode |
| `analysis.data` | the program's data, laid down in Ghidra's analyzer order (below) | `analysis.functions`, every flow, the bytes, `analysis.data_program` |
| `analysis.no_return_evidence` | the functions Ghidra's evidence marks non-returning | `analysis.functions`, every flow, bytes after calls |

All are deterministic functions of what they read. An edit that changes
discovery re-runs the flows it changed (their references come with them)
and then the program-wide queries, whose values usually come out the same,
so what reads them validates by fingerprint. The image backend reads them
in `inputs.program`, `inputs.sets`, `names.default` and `listing.rows`.

## The steps

`analysis.data` follows the analyzers' priorities, each step only over what
the earlier ones left undefined: instructions and loader markup are
obstacles, and `undefinedN` data is "undefined stuff" later steps replace,
as Ghidra clears it (`DataUtilities.isUndefinedRange`).

1. **Accesses** (`ConstantPropagationAnalyzer`,
   `ConstantPropagationContextEvaluator.createData`, priority
   REFERENCE_ANALYSIS - 4): an `undefinedN` of the access size (1 to 8)
   where code loads or stores at a constant address. Constants are carried
   depth first along each flow as `SymbolicPropogator.flowConstants` goes
   (fallthrough first, branch targets with the values at the branch, each
   instruction with the first path's values, registers cleared at calls),
   so x86-64 RIP-relative operands (code-space varnodes in SLEIGH's p-code,
   not LOAD/STORE), AArch64 `adrp`/`add`/`ldr` and RISC-V `auipc`/`addi`
   all resolve; a value loaded from a constant address is read from the
   bytes, as the analyzer trusts initialized memory.
2. **References** (`OperandReferenceAnalyzer`, then
   `DataOperandReferenceAnalyzer` for references from data), per
   referenced address in order of the referring instruction: an ASCII
   string (printable, tab, CR, LF, at least 5 characters to a NUL, none of
   it referenced inside), a UTF-16 string (at least 4 characters, not much
   shorter than the one 8 bytes before), or a pointer (not below 4096, to
   mapped memory, not offcut into a code unit or into a function's middle,
   at a relocated location when the program is relocatable; never on ARM).
   A pointer's target is a reference in turn, and so are the loader's
   relocated slots and `.got` entries.
3. **String search** (`StringsAnalyzer`, after data type propagation): over
   every loaded, initialized and accessible block, NUL-terminated ASCII
   and, by the wide character size, UTF-16 (PE) or UTF-32 (ELF) runs of at
   least 5 characters (`MinLengthCharSequenceMatcher`, a matcher per
   character width and offset), scored by Ghidra's string n-gram model
   (`NGramUtils`: lower-cased, trimmed, runs of spaces collapsed, trigram
   log-probabilities against a threshold per length) from
   `Ghidra/Features/Base/data/stringngrams/StringModel.sng` in the Ghidra
   install, read once per process; a string ending where an equal-typed one
   ends may consume it, and zero bytes pad a string to 4-byte alignment
   within its block. Each matcher runs on its own over the engine's pool;
   found strings are offered in Ghidra's order.
4. **Labels**: referenced addresses still undefined, which Ghidra's
   references give a dynamic `DAT_` label.

The user's edits come first ([listing-edit.md](listing-edit.md)): a
data item defined from the listing is laid down before step 1 (`kDataUser`,
with its type, and its pointers' targets join step 2's references), and
bytes a Clear or a data definition owns are obstacles no step defines
data in.

Data that code writes to in read-only memory keeps normal mutability
(`MappedEntry.getMutabilityOfAddress`), so the decompiler doesn't fold it
to a constant.

## Names and types

`revkit::inputs` (`src/inputs/data.cc`) turns the items into the
decompiler's data facts as Ghidra's database has them:

| Item | Name | Type |
| --- | --- | --- |
| string | `s_<label>_<address>`: `StringDataInstance.makeStringLabel`, up to 32 displayable characters, runs of others as one `_` | `char[n]`, with the string value |
| UTF-16 / UTF-32 | `u_<label>_<address>` | `wchar_t[n]` where the wide character has that size, else `wchar16`/`wchar32` |
| pointer | `PTR_<target>_<address>` (`PointerDataType.getLabelString`): a symbol's name whole, a default label without its address (`PTR_FUN_`, `PTR_s_hello_`, `PTR_LAB_`, `PTR_DAT_`), `PTR_PTR_` beyond two levels, `PTR_LOOP_` for a cycle, `PTR_` alone for an unmapped value; where the space shows in default names (RISC-V `FUN_ram_...`) the target's name stays whole | pointer to undefined |
| access | `DAT_<address>` | `undefinedN` |

An ELF object symbol keeps its name and takes a string's type; data inside
a DWARF or PDB variable is dropped (relocated pointer slots included), as
Ghidra lays the debug info's variables over the loader's markup. The same
pointer naming now names the relocated slots.

## Switch labels

Where revkit's references decide the code labels (own inputs), the
decompiler names a target of the function's own recovered jump tables as
`DecompilerSwitchAnalysisCmd.labelSwitch` does: the first case going there
is `switchD_<jump>::caseD_<value>` (the value as Ghidra's `Integer` prints
it), the case without a label or with the decompiler's default value is
`switchD_<jump>::default`, and `getCodeLabel` joins them with `_`. The
decompiler's run decides them, so in-process and worker output agree, and
under Ghidra's own inputs (which already carry them) nothing changes.

## No-return

Discovery's own no-return functions (known names, and those no path
returns from) stop its bodies where Ghidra's flow would. The decompiler is
told what Ghidra's database holds instead: the known names,
`analysis.no_return_evidence`, and thunks of either.
`FindNoReturnFunctionsAnalyzer`'s evidence is a call whose fallthrough
runs into the next function, bytes that don't decode, an instruction over a
function's entry, or (x86) an `INT3`; three such calls, or every path
through the target ending in a call to a non-returning function (a call to
a function found here still has its fallthrough, as in Ghidra before the
analyzer clears it), make the target non-returning, in two passes. Ghidra
never marks `_start` and the like, which discovery's inference does.

## In the listing

The daemon's listing gives each data item one `LISTING_ROW_KIND_DATA` row
(no API change): `data_type` (`string`, `unicode`, `pointer`,
`undefined4`), a TYPE token with Ghidra's mnemonic (`ds`, `addr`,
`undefined4`), then a DATA_VALUE (the quoted string, the value in hex) or a
SYMBOL token naming the pointer's target; `names.default` gives the item's
address its name, so labels, operands and header rows show `s_...` and
`PTR_...` like the decompiler.

## PDB prototypes

Ghidra's PDB applicator gives a near-C procedure the convention `__cdecl`
(`unknown` without parameters) and doesn't apply the PDB's parameter
names. `inputs::Options::pdb_signatures` scopes that quirk to the PDB
prototype step: `ghidra` (rk-lift's default, what the parity measurement
compares) or `full`, the PDB's own names and the default convention,
which the daemon uses so users see what the PDB says
(`rk-lift --pdb-signatures full` measures it). Nothing else depends on the
option. Revisit it if Ghidra starts applying PDB parameter names.

## Cost

On cmake (11.8 MB, the cold-start gate's binary), `analysis.data` takes
about 110 ms of the backend's import (string search 65 ms, steps 1 and 2
about 25 ms) and the references come from the flows' own decode; the first
decompilation of `main` still arrives within the gate.

## Not done

- PE structures Ghidra's loader types (`IMAGE_DOS_HEADER`,
  `_IMAGE_RUNTIME_FUNCTION_ENTRY`, `UNWIND_INFO`, the load config, TLS),
  RTTI and `__security_cookie` are typed and named by the image
  backend's import ([pe.md](pe.md)), as analysis assertions, not by these
  queries: rk-lift's own inputs don't have them.
- Switch tables' `switchdataD_` data and the `uint` entries Ghidra lays
  over relative tables.
- Address tables (`OperandReferenceAnalyzer`'s PE pointer arrays).
- DWARF anonymous string variables (`anon_var.dwarf_<offset>`): the
  debug-info reader skips unnamed variables.
