# PDBs: loading one, symbol servers, C++ classes

How revkit reads a PE's PDB is in [types.md](types.md#pdb-coverage)
(`src/debuginfo/pdb.cc`, `pdb_types.cc`) and how its facts become
`import:pdb` assertions at import in [backend.md](backend.md#debug-info).
This page covers what came with `api_minor` 49 (feature `pdb-load`):
loading a PDB into a program that is already open (Ghidra's Load PDB
File), finding it on a symbol path (`_NT_SYMBOL_PATH`, local stores,
symbol servers, `.pd_` files), MSVC 17.x's class records, and C++
classes' vtable pointers.

- [Load PDB](#load-pdb)
- [Symbol servers](#symbol-servers)
- [C++ classes](#c-classes)
- [API, SDKs, MCP and the UI](#api-sdks-mcp-and-the-ui)
- [Tests](#tests)
- [Known gaps](#known-gaps)

## Load PDB

At import the PDB is looked up where the CodeView record says, beside the
binary and as `<stem>.pdb`, and used only when its GUID and age are the
image's. **Load PDB** (`ProjectService.LoadPdb`) does it later, from:

- a **path** on the daemon's host (an admin's call, like ImportProgram's
  paths),
- an **upload** (`UploadChunk`'s `upload_id`),
- the **symbol path**: the PDB the program's CodeView record names, looked
  up as below.

The PDB's identity is checked against the image's CodeView record. A PDB
of another build (another GUID or age), or any PDB for a program without
a CodeView record (a stripped link), is refused with
`FAILED_PRECONDITION` and a message naming both identities, unless
`force` is set: then it is loaded with a warning ("another build's PDB
...: its addresses may not match the program"), Ghidra's "ignore age and
GUID".

What it applies is what the import applies (`ReadPdbBytes`,
`src/backend/debug_import.cc`): function and global names, prototypes
and global types as `TYPE` = `h:<hash>`, and the type records they reach,
as `import:pdb` assertions with the caller's session, plus a note on the
image base (`revkit:pdb`) naming the file, in one revision. So the PDB's
names and prototypes win over the analysis's, the demangler's and an
agent's, and lose to the user's; the RTTI analysis's classes keep their
place and the PDB's class structs are what its prototypes' `this` points
to. The response lists the assertions' seqs: `RetractAssertions` on them
(Ctrl+Z in the UI) takes the load back.

## Symbol servers

`src/backend/symbol_server.{h,cc}`. The daemon's **symbol path** uses
`_NT_SYMBOL_PATH`'s syntax:

| Entry | Means |
| --- | --- |
| `srv*<cache>*https://msdl.microsoft.com/download/symbols` | a symbol server, its downloads kept in `<cache>` (a store) |
| `srv*https://server/path` | a server, its downloads in the default cache |
| `srv*<dir>`, `cache*<dir>` | a local symbol store |
| `symsrv*symsrv.dll*...` | as `srv*...` |
| `<dir>` | a plain directory (`<dir>/<name>`), or a store |

Entries are separated by `;`. A PDB is looked up by its file name (the
CodeView record's, any directory dropped; a name with a separator or
`..` is refused) and its key, the GUID as 32 upper-case hex digits
(`Data1`, `Data2`, `Data3` as numbers, then `Data4`'s bytes) followed by
the age in hex: `<store>/<name>/<key>/<name>`, or the compressed
`<store>/<name>/<key>/<name minus its last character>_` (a `.pd_`). Every
local entry is tried first, in order; then each server: its cache, then,
if downloads are allowed, `GET <url>/<name>/<key>/<name>` and the `.pd_`
(redirects followed, 60 s timeouts, at most 2 GiB). A file is used only
when its identity matches; a download is written into the cache
atomically and found there next time. Every place tried is reported
(`LoadPdbResponse.search_log`).

A **`.pd_`** is a Microsoft cabinet holding the PDB: stored or MSZIP
folders are expanded (`ExpandCabinet`, zlib's inflate with each block's
32 KiB history); LZX and Quantum cabinets are refused with a message.

**Settings.** `rk-daemon --symbol-path <path>`, `--symbol-cache <dir>`
(where a server entry without its own cache downloads; default
`<project_dir>/.revkit/symbols`) and `--symbol-downloads`.
`ProjectService.GetSymbolSettings` and `SetSymbolSettings` (the admin
role's) read and change them while the daemon runs; with a project
directory they are kept in `<project_dir>/.revkit/symbols.json` and used
at the next start unless flags are given. **Downloads are off by
default**: the daemon contacts a server only after an admin turned them
on (`--symbol-downloads` or `SetSymbolSettings`), see
[security.md](security.md#symbol-servers). The same settings carry an
ELF's debug file directories and debuginfod servers (`api_minor` 86,
[backend.md](backend.md#external-debug-files)); an older client's
`SetSymbolSettings` clears those, the Python SDK's keeps them.

## C++ classes

`src/debuginfo/pdb_types.cc`:

- **`LF_CLASS2`, `LF_STRUCTURE2`, `LF_INTERFACE2`** (`0x1608`, `0x1609`,
  `0x160b`, written by MSVC 17.x): 32-bit properties, the field list,
  derived list and vshape, then the member count and the size as numerics
  and the names (Ghidra's `Class19MsType` layout). They are read as their
  older kinds.
- **Vtable pointers**: a class with an `LF_VFUNCTAB` (its own vtable
  pointer; MSVC puts it at offset 0) gets a field `vftable` at offset 0,
  a pointer to a struct `<class>_vtbl` whose fields are the virtual
  functions the class introduces (`LF_ONEMETHOD`, and `LF_METHOD`'s
  `LF_METHODLIST` overloads, with the introducing-virtual property), at
  their vtable offsets, typed as pointers to their method types. Slots a
  base introduced are gaps (a derived class shares its primary base's
  pointer, as a field of its base). So a virtual call through a PDB
  class reads `b->vftable->get(b)`, and the RTTI analysis
  ([pe.md](pe.md)) types `this` with the PDB's class where the PDB has
  it.

## API, SDKs, MCP and the UI

| Where | What |
| --- | --- |
| `ProjectService.LoadPdb` (`api_minor` 49, feature `pdb-load`; admin) | `path`, `upload_id` or `symbol_path`; `force`; response: `pdb_file`, `exact`, `source` (`file`, `upload`, `store <dir>`, `server <url>`, `cache <dir>`, `directory <dir>`), counts, `warnings`, `search_log`, `assertion_seqs` |
| `ProjectService.GetSymbolSettings`, `SetSymbolSettings` (admin) | `SymbolSettings`: `symbol_path`, `downloads`, `cache_dir` |
| Python | `Program.load_pdb(path=None, *, local_file=None, symbol_path=False, force=False)`, `Client.symbol_settings()`, `Client.set_symbol_settings(path, downloads=False, cache_dir="")` |
| MCP | `load_pdb(program_id, path="", from_symbol_path=False, force=False)` |
| UI | palette "Load PDB…" (a path, or empty for the symbol path; "Load it even if it is another build's"), one undo step; "Symbol path and servers…" |

## Tests

- `src/backend/tests/symbol_server_test.cc`: the path syntax, store keys,
  cabinets (MSZIP over several blocks, stored, LZX refused), finding the
  fixture's PDB (tests/data/msvc, built by clang-cl and lld-link) in a
  store as a `.pd_` and in a flat directory, another age refused, a name
  with directories refused; and downloads from a local `httplib` server on
  a test port (54700-54799): nothing is asked while downloads are off,
  then the `.pdb` is asked, the `.pd_` fetched and expanded into the
  cache, and the next lookup reads the cache without asking.
- `src/backend/tests/msvc_test.cc` `LoadPdbOnAnOpenProgram`, both
  architectures: the debug build moved away from its PDB loads it by
  path (exact; names, prototypes from `import:pdb`, a virtual call
  through the PDB's class reads `b->vftable->get`), the stripped build
  refuses it without `force` and takes it with a warning, the symbol path
  finds it in a local store, a non-PDB is refused.
- `src/debuginfo/tests/pdb_malformed_test.cc`
  `Structure2AndVirtualFunctions`: a synthetic `LF_STRUCTURE2` with
  `LF_VFUNCTAB`, an `LF_ONEMETHOD` and an `LF_METHOD` list.
- `sdk/python/tests/test_msvc.py`: `load_pdb` forced, undone by its seqs,
  the settings, MCP `load_pdb`; `ui/e2e/classes.ts`: the Load PDB dialog,
  its refusal, force, and Ctrl+Z.

Untested: HTTPS servers (the client is the same, with OpenSSL; no test
talks TLS), redirects, the real msdl.microsoft.com (never contacted by a
test), LZX `.pd_` files (not supported), and `LF_CLASS2` from a real
MSVC 17 PDB (clang doesn't write it; the test is synthetic).

## Known gaps

- Only names, prototypes, globals and types apply: a PDB loaded after
  import doesn't give the decompiler its stack variables (the program's
  debug info is read at load), as the import's PDB does.
- LZX- and Quantum-compressed `.pd_` files, `file.ptr` redirections and
  symbol server proxies aren't supported.
- Virtual bases' vbtable pointers, methods that aren't virtual and static
  members stay out of the class structs.
