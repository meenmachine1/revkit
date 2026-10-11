# Function ID

Function ID names statically linked library functions in a program by
hashing each function and looking the hash up in databases of known
libraries, as Ghidra's Function ID does. revkit computes **Ghidra's hash bit
for bit**, so it reads **Ghidra's own databases** (the `.fidbf` files Ghidra
ships for the Microsoft C/C++ runtimes, Visual Studio 2012 to 2019 and
older, x86 and x64) as well as its own `.rkfid` files, which `rk-fid
create` and `CreateFidDatabase` make from programs with symbols.

| Piece | Where |
| --- | --- |
| Hash, databases, matching, building databases | `src/fid` (`revkit::fid`) |
| The per-instruction masks and operands the hash reads | `src/lift/fid_insn.cc` (`SleighDecoder::fid`), SLEIGH patch 0011 |
| The analyzer, attachments, results, apply and reject | `src/backend/fid.cc`, `src/backend/image_backend.cc` |
| Command line | `tools/rk-fid` |
| Ghidra as the yardstick | `tools/ghidra-export/ghidra_fid.py`, `ghidra_fid_create.py` |
| Gates | `scripts/fid-gate.py`, `scripts/fid-crosscheck.py` |
| UI | the Function ID window (`ui/src/ui/fid.ts`, [ui.md](ui.md#function-id)) |

## Hashing

Ghidra's `FidService` hashes a function with `MessageDigestFidHasher`
over the instructions of its body in address order
(`FunctionBodyFunctionExtentGenerator`), with two 64-bit FNV-1a digests:

- the **full hash**: each instruction's bytes with every operand's value
  bits masked out, plus, per operand, a sum of what its objects are
  (registers by their offset in the register space, a placeholder for
  scalars and addresses);
- the **specific hash**: the same, but with small constants (and whole
  constant operands that aren't addresses) mixed in; the number of them is
  the **specific extra** (at most 127).

The **code units** are the instructions less the calls among them. A
function of fewer than 4 instructions hashes to nothing. x86's NOP forms
(`X86InstructionSkipper`'s patterns) are skipped. A scalar whose operand
bits a relocation touches (`hasRelocation`) is a placeholder.

The masks are what Ghidra's Java disassembler reports
(`InstructionPrototype.getInstructionMask` and `getOperandValueMask`), which
`SleighDebugLogger` computes by re-resolving the instruction and recording,
for every constructor in the parse tree, the instruction bits each decision
node read and the instruction pattern that matched; an operand's mask is the
token fields its value comes from. `SleighDecoder::fid` replays that resolve
over the C++ engine's parse tree, context changes included, with the same
quirk the hashes depend on: a decision node's field that doesn't start in
the node's first byte is recorded in it, because normalizing Java's
`PatternBlock(0, mask, value)` moves the leading zero bytes into an offset
`InstructionBitPattern` ignores. Patch 0011 exposes the decision node's
field to the C++ side; nothing else in the engine changes.

What the hash also reads from Ghidra's analysis, revkit takes from its own:

| Ghidra | revkit |
| --- | --- |
| The function's body | discovery's, going on after calls to functions only discovery infers never return (Ghidra's bodies stop only after its own evidence: `NoReturnEvidence`); a thunk is no-return only through its target |
| A call (`FlowType.isCall`, flow overrides) | the instruction's p-code flow, plus Ghidra's `CALL_RETURN` override: a jump to another function's entry, a computed jump through an import's pointer |
| A scalar operand typed as an address (a memory reference on it) | the flow's constant-propagation references (`FlowGraph::data_refs`; an address computed into a register only on x86), and outside ELF Ghidra's Scalar Operand References rule (a value past the first page, not a mask, in memory, not inside a function past its entry) |
| The relocation table | ELF relocations, PE base relocations (`.reloc`) |

Agreement with Ghidra (`ghidra_fid.py --no-fid-analyzer` against
`rk-fid hash`, every function both find):

| Program | Same hash quad |
| --- | --- |
| zlib, ELF x86-64, gcc -O2 / clang -O0 | 133/133, 163/163 |
| cJSON, ELF x86-64, gcc -O0 | 120/120 |
| Lua, ELF x86-64, gcc -O2 | 666/671 (5: bodies) |
| zlib, ELF AArch64, clang -O2 | 155/156 (the PLT header) |
| cJSON, PE x64 (mingw), clang -O2 | 192/194 |
| Ghidra's `sleigh.exe` (MSVC, x64) | 2074/2090 |

`src/fid/tests/data/ghidra_hashes.json` holds Ghidra's hashes for three of
these corpus binaries; `revkit_fid_tests` checks them.

## Databases

**Ghidra's `.fidbf`** is a raw Ghidra database (`LocalBufferFile` holding a
`DBHandle`): a header block, then 16 KiB buffers; buffer 0 holds the
database parameters, the first naming the master table's B-tree, whose
records name each table's schema and root. revkit reads the five tables
Function ID uses (Functions, Libraries, Strings, Superior and Inferior
relations) whole into memory, skipping the index tables, and refuses
anything that doesn't check out: magic, block size, buffer ids, node types,
key counts against the buffer, record and string offsets, cycles in a
B-tree, chained buffers' lengths, the schemas and the schema version (6).
The `.fidb` files Ghidra's Populate writes are *packed* databases;
`ghidra_fid_create.py --raw` (or `FidDB.saveRawDatabaseFile`) writes the
raw form revkit reads.

**revkit's `.rkfid`** holds the same model, little-endian: the magic
`RKFID\0\1\0`; a count and the libraries (id, family, version, variant,
creator, language, compiler, language version and minor); a count and the
functions (id, code units, full hash, specific extra, specific hash,
library id, name, entry, source path, flags); then the superior and the
inferior relation keys, each a count and sorted 64-bit keys. Strings are a
32-bit length and UTF-8 bytes. Every count is checked against the bytes
left.

Relations are Ghidra's: a caller's id times the FNV prime, xor a callee's
full hash (superior), and the reverse (inferior).

`fuzz_fid_db` (`-DREVKIT_FUZZ=ON`) fuzzes both readers.

## Matching

`revkit::fid::search` is `FidProgramSeeker`: for each function with a
hash, the database functions with its full hash are scored: its code units
(at least 24 for an auto-pass function), plus 0.67 per specific constant
when the specific hash matches too, plus the code units of its callees the
database says it calls (superior relations) and of its callers that call
it (inferior relations; not counted past 500 callers). Callees and callers
count once per full hash. A score under 14.6 is no match; auto-fail,
force-specific and force-relation flags apply. The best scores are kept,
ties included.

Naming is `ApplyFidEntriesCommand` and `MatchNameAnalysis`: one name (up to
leading underscores) names the function; several names with one base name
(demangled, the first template argument list emptied, a special member's
class kept) name it with that base; several base names, when the best
score reaches 30, name it `FID_conflict:<first>`; otherwise nothing. The
plate comment says which ("Library Function - Single Match", the names,
"Library: Visual Studio 2019 Release").

## In the daemon

The analyzer `function-id` runs in the background after a PE or ELF
import, when an attached database is for the program's language
(`rk-daemon --function-id off` turns it off), and again on
`StartAnalysis(["function-id"])`. Its job shows on `GetAnalysisStatus`
(hashing, matching) and `CancelAnalysis` stops it.

Its names are **ANALYSIS assertions** with provenance id `fid:<database>`
(and the reason: verdict, score, library), with Ghidra's plate comment, in
one revision. It names only functions whose name is still discovery's
default (`FUN_…`) or its own: never over a symbol, an export, the
demangler, DWARF, a PDB, a user or an agent. A later run retracts the names
it no longer makes (a database detached).

Databases in force for a program: Ghidra's shipped ones (`builtin:<name>`,
found under the daemon's Ghidra root, attached unless detached), the
caller's (USER scope, kept in `<project dir>/.fid-users`), and the
project's (PROJECT scope, a project note replicated with it). Attaching a
file or creating one reads or writes the daemon's host, so it needs the
admin role, as importing by path does.

`ListFidMatches` returns the last run's results (not persisted: a reopened
project runs again): each match's candidates with their scores, the name
Function ID proposes and its status: APPLIED (its name is the program's),
KEPT (a better-ranked name stays), UNAPPLIED (names that differ, scoring
low), REJECTED, ACCEPTED (someone applied a candidate). `ApplyFidMatch`
asserts a candidate's name as the caller; `RejectFidMatch` retracts the
Function ID name and plate and records the entry (a program note
`revkit:fid.rejected`) so runs leave it alone. `CreateFidDatabase` writes a
`.rkfid` from programs of the project, with the names they have.

## Creating databases

```sh
rk-fid create --name zlib --version 1.3.1 --variant gcc-O2 -o zlib.rkfid minigzip-debug example-debug
rk-fid match stripped-program --db zlib.rkfid [--json]
rk-fid info zlib.rkfid
```

A program's functions with a name that isn't a default one are added
(names from its symbols or its debug info); thunks, functions under 4
instructions and duplicates (the same hash, name and callees) are not.
Callees in the library are relations; calls to names the library defines
elsewhere (another program, a duplicate) relate by name at the end; names
in `--common` (Ghidra's common symbols file) relate nothing. All programs
must be of one language.

## Gates

**MSVC CRT.** The brief's gate builds a statically linked MSVC program
with `clang-cl` and `lld-link` and scores the vs2019 database's names
against its PDB. This host has no Windows CRT or SDK (no xwin sysroot, no
`libcmt.lib`), so it doesn't run. Instead `scripts/fid-crosscheck.py`
compares revkit's names with Ghidra's on the same shipped databases, on
MSVC-built programs that ship with Ghidra (its native `decompile.exe`,
`sleigh.exe` and `pdb.exe`, x64; the GhidraClass exercises, x86):

| Program | Ghidra names | revkit names | Same | Agreement |
| --- | --- | --- | --- | --- |
| decompile.exe (x64) | 230 | 221 | 221 | 0.961 |
| sleigh.exe (x64) | 238 | 231 | 231 | 0.971 |
| pdb.exe (x64) | 14 | 14 | 14 | 1.000 |
| WinHelloCPP.exe (x86) | 231 | 144 | 144 | 0.623 |
| WallaceSrc.exe (x86) | 34 | 14 | 14 | 0.412 |

Every name revkit gives is Ghidra's: the disagreements are functions
revkit doesn't name. On x64 they are a few functions whose bodies differ
(6 and 3 on decompile.exe). On the 32-bit programs they are functions
revkit's discovery doesn't make (81 of 87 on WinHelloCPP): it has no linear
sweep or function-start search on PE programs, so functions only reached
through pointers (window procedures, CRT initializer tables) are missing,
and Function ID can only name the functions there are.

**ELF.** `scripts/fid-gate.py` builds zlib 1.3.1 and Lua 5.4.7 (the
corpus's pinned tarballs) with the host's gcc into static libraries, a
database from one program linking each (minigzip, lua) and a stripped
other program linking it too (example, luac), with the truth from its
debug build:

| Library | Precision | Recall (of the library's functions the database has) |
| --- | --- | --- |
| zlib | 1.000 (100/100) | 0.851 of 114 |
| Lua | 1.000 (449/449) | 0.972 of 459 |

With `--ghidra`, Ghidra populates a database from the same program and
searches the same stripped program with it, and revkit matches with that
database read natively: agreement 0.991 (zlib) and 0.996 (Lua) of the
functions either names (revkit on Ghidra's database: precision 1.000,
recall 0.851 and 0.965); Ghidra's recall is 0.860 and 0.967. The misses
are small functions under the threshold, the same for both; the 3
disagreements are a callee only Ghidra's constant propagation finds
(zcalloc through a function pointer) and two bodies.

## Not done

- Ghidra's FidDebug views, the "always apply FID labels" option and
  bookmarks (the plate comment and the results table stand in).
- Packed `.fidb` files are not read; save them raw first.
- `FidService` in the Ghidra compat shim is Unsupported (see
  [scripting.md](scripting.md)); scripts use `Program.fid_matches()` and
  the `Client` database calls.
