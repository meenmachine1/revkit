# Investigating a binary with revkit

You are working through revkit's MCP tools: a reverse-engineering server
(disassembler, decompiler, analysis, debugger) that a person may be using at
the same time in its web UI. Every edit you make is recorded as yours, with
the reason you give, and can be undone. This guide is the workflow; call
`about` for the daemon's version, its features and who your edits are
recorded as.

## 1. Find or bring in the program

- `list_programs`: the projects and their programs. Every program tool
  takes a `program_id` from it (`default/ls`).
- `import_program(project_id, path)` imports a file on the daemon's host
  (an admin token when the daemon has accounts). For an archive, firmware
  package or file system image, `open_filesystem` then `list_filesystem`
  and `import_from_filesystem`. Raw firmware with no headers:
  `detect_raw_layout` suggests the processor, base and entry, then
  `import_program` with `language_id`, `image_base` and `format="raw"`.
- `analysis_status` says when analysis has finished; the reads work before
  that, on what is known so far.

## 2. Get your bearings

- `program_summary`: language, image base, entry points, memory blocks,
  function count. `overview`: where code, data, undefined bytes and
  high-entropy (packed or encrypted) regions are.
- `build_info`: for a Go binary, the Go version, its modules and build
  settings; for a Rust binary, its crates and rustc.
- Bytecode (a .NET assembly, DEX or APK, jar or `.class`, `.pyc`, a Lua
  chunk, a wasm module, a JavaScript bundle), as a program or a file inside
  an open file system: `decompile_external` runs the dedicated decompiler
  (ILSpy, jadx, Vineflower, pycdc, unluac, wasm-decompile, webcrack) and
  gives its source; `read_provider_output` reads the other files of a
  tree. `list_providers` says which are installed.
- `list_libraries` and `list_relocations` for what it links against;
  `symbol_tree` for imports, exports, classes and namespaces.

## 3. Find what matters

- `list_functions` (filters: named or unnamed, thunks; paged),
  `search_symbols`, `get_function`.
- Strings first, usually: `list_strings`, `search_strings` (a substring or a
  regular expression), then `xrefs` to the string to reach the code using
  it.
- `search_text` (the listing), `search_memory` (bytes with wildcards,
  strings, numbers), `search_scalars` (constants: magic numbers, error
  codes), `search_decompiled` (the C).
- `find_next` steps to the next function, label, data, undefined bytes or
  note. `preview` shows what is at an address; `describe_value` spells a
  constant and names what it points at.

## 4. Read

- `decompile` (paged by line; with the variables and their storage),
  `disassemble` (paged by row), `function_graph`, `instruction`.
- `xrefs`, `callers`, `callees` to move through the call graph.
- `slice_decompiled`: where a variable's value comes from (backward) or
  flows to (forward) inside a function; `trace_value` follows it across
  calls (into callees' returns and parameters, out to callers' arguments
  and uses) and says where it lost track (indirect calls, imports,
  memory).
- `get_type`, `find_types`, `find_type_uses` (where a struct or one field is
  read and written).

Addresses are hex strings (`"0x401040"`, or `"401040"`), a symbol name
(`"main"`, a demangled C++ name), or a Go To expression (`"main+0x10"`,
`"file:0x200"`). Long results come a page at a time: a result with
`"truncated": true` says in `"more"` how to get the next page.

## 5. Record what you learn

Each edit takes a short, specific `reason` (what you saw that justifies
it): "calls fopen on its argument and parses key=value lines", not
"renamed".

- `rename` (functions, labels, globals), `rename_variable` and
  `retype_variable` (from `decompile`'s variables).
- `retype`: a global's type or a function's prototype, as C
  (`"int parse_config(const char *path, struct config *out)"`).
- New types: `parse_c` checks C declarations, `import_header` makes them
  the program's; `auto_structure` builds a struct from how a pointer is
  used; `rename_field` and `retype_field` fix one field.
- `set_comment`, `add_note`, `set_equate` (name a constant),
  `override_call_signature` (one call's prototype: a varargs call).
- Where analysis got code wrong: `create_function`, `clear_code`,
  `disassemble_here`, `define_data`, `set_no_return`, `add_reference`.

Then search again and decompile the callers: names and types propagate,
and the next function reads better for them. Work outward from what you
have named.

## 6. Review and undo

- `list_my_changes`: your edits in this session, with seqs and reasons.
- `undo_changes(seqs, reason)` retracts some; `revert_my_changes` the whole
  session. `blame` shows who set what at an address.
- A person's edit outranks yours: a write that comes back `SHADOWED` lost
  to theirs, and you should not fight it.

## 7. Compare and recognise

- `bsim_search` finds functions similar to one (or to all) in attached
  BSim databases, from other builds or libraries; `bsim_apply` takes a
  match's name and signature. `fid_matches` lists library functions
  Function ID recognised.
- `compare_programs` matches two versions of a program; `diff_matches`,
  `diff_unmatched` and `diff_function` show what changed;
  `port_function_markup` carries your names, types and comments to the new
  version. `compare_functions` compares any two functions.

## 8. Run it (when that helps)

`emu_start` emulates a function or a firmware image; `emu_call` calls one
function with arguments; `debug_start` launches or attaches a debugger.
Use them to confirm what a routine computes, not as a first step.

## Good habits

- Read before you write: decompile the function and look at its callers
  before naming it.
- Prefer names that say what a function does (`parse_config_line`) over
  how (`loop_over_string`). Keep the program's existing conventions.
- Small steps with reasons beat a large unexplained rewrite: the person
  reviewing your work sees each edit and why.
- Say what you are unsure of in a comment or a note rather than encoding a
  guess in a name.
