# Scripting

revkit scripts are ordinary Python 3.10+ files that drive the daemon
through the public API, the way Ghidra scripts drive a Ghidra program.
They run headless (`rk-script`) and from the UI, where the daemon runs
them in a host process for you (`ScriptService`). This page is the design
as built, the API, the commands, the daemon's script service and the
safety statement.

- [What a script looks like](#what-a-script-looks-like)
- [Safety: a script is full Python with your rights](#safety)
- [The design](#the-design)
- [The script API (`revkit.script`)](#the-script-api)
- [Edits, provenance and precedence](#edits-provenance-and-precedence)
- [Prompts, output and the host interface](#prompts-output-and-the-host-interface)
- [`rk-script`](#rk-script)
- [The daemon's script service](#the-daemons-script-service)
- [The console](#the-console)
- [Libraries: what `import` finds](#libraries)
- [Editor completion](#editor-completion)
- [Metadata](#metadata)
- [Batch RPCs](#batch-rpcs)
- [Starter scripts](#starter-scripts)
- [Running Ghidra scripts](#running-ghidra-scripts)
- [Performance](#performance)
- [Tests](#tests)
- [Next phases and known gaps](#next-phases-and-known-gaps)

## What a script looks like

```python
# @category Analysis/Naming
# @description Names small unnamed functions that only return a constant
# @arg max_size:int=8 Largest function to look at
from revkit.script import *          # optional: rk-script defines these names already

for f in current_program.functions():
    monitor.check_cancelled()
    if f.name.startswith("FUN_") and f.size <= args["max_size"]:
        d = decompile(f)
        if "return" in d.text and d.text.count(";") == 1:
            rename(f, f"ret_const_{f.entry.offset:x}")
            print("named", hex(f.entry.offset))
```

```sh
rk-script run ret_const.py --daemon 127.0.0.1:50051 --program default/bash
rk-script run ret_const.py --import /usr/bin/bash --arg max_size=16       # a throwaway daemon
```

Every edit the run made is one revision with provenance
`script:ret_const@<sha12>` and the run's id as its session: one undo, and
`revert(session=<run id>)` (or the UI's history) takes the whole run back.

## Safety

**A script is full Python on the machine that runs it, with the rights of
whoever runs it.** It can read and write files, open network connections,
start processes, and do anything the daemon lets its credentials do (with
an editor's token: edit every program it can see). There is no sandbox and
none is pretended. Run scripts you would run as a shell script: read a
script before running it, and treat a script from someone else like any
other program from them.

What revkit does guarantee:

- Scripts reach the daemon only through the public API, with the caller's
  token: roles, project lists and provenance stamping apply as to any
  client ([security.md](security.md)). A viewer's script can't edit; a
  script can't claim to be someone else (`on_behalf_of` naming another
  identity is refused).
- Every edit is recorded with the script's name and hash and the person who
  ran it, so a run can be reviewed (`ListAssertions` by session or by
  `on_behalf_of`) and reverted as a whole.
- `rk-script` runs each program's scripts in a separate host process, so a
  crash, `sys.exit` or a hung script costs that run, not the daemon or other
  runs.

- When the daemon runs a script for you (the UI, `ScriptService`), it runs
  as the **daemon's** user, with a run token that acts as you and dies
  with the run. That is a shell as the daemon's user, so the daemon runs
  scripts only for the role `--scripts-host-role` names: editor and admin
  by default when every listener is on loopback, **nobody** when it listens
  beyond loopback until an admin turns it on. A viewer runs scripts (and
  the console) only where an admin chose `--scripts-host-role viewer`,
  and then read-only: the run token is a viewer's, so its edits are
  refused, but it is still Python as the daemon's user.
- A per-user or per-project script runs only once you have **seen and
  confirmed its exact text**: the first run of an unseen hash, or of text
  someone changed since your last confirmed run or save, shows its source
  and SHA-256 first. Shipped scripts are trusted like the daemon.

Untrusted automation belongs in WebAssembly plugins
([plugins.md](plugins.md)): sandboxed, deterministic, memoized analyzers
and commands. A script that proves useful can graduate into one. Details:
[security.md](security.md#roles).

## The design

Decided in a design consult (2026-10-07), from measurements on a scratch
daemon (`/usr/bin/bash`, 2,578 functions) and a survey of the 336 scripts
Ghidra 12.1.4 ships:

- **Out-of-process CPython over gRPC.** A loopback unary call costs
  0.13-0.32 ms; listing all functions 16 ms; a decompilation 59 ms
  sequential and 0.4 ms memo-warm. Transport is not the bottleneck, the
  decompiler is, so an in-process interpreter would buy nothing visible.
  Out of process, a crash costs one run, the user's venv (angr, z3,
  unicorn, capstone, numpy) just works, and the same file runs headless
  and from the UI. Rejected: embedded CPython (the GIL in a multi-threaded
  daemon, crashes take the daemon, a bundled Python fighting the user's
  packages); Python in WebAssembly or Pyodide (no native wheels, slower,
  and the wasm sandbox exists for untrusted, deterministic analyzers, not
  trusted automation); JavaScript scripts (not in v1).
- **A flat API on the SDK** (`revkit.script`), Ghidra's `FlatProgramAPI`
  in spirit: context names, reads, buffered edits, prompts, a monitor.
- **One run, one revision.** Edits are buffered and committed as one
  `AppendAssertions` at the end, so a run is one undo and one revert.
- **Script provenance ranks with agents** (`PROVENANCE_KIND_SCRIPT`), so a
  person's edit made after a run survives running the script again; the
  server stamps who ran it in `Provenance.on_behalf_of`.
- **Batch RPCs** where per-item calls would cost: `DecompileMany`,
  `FindBytes`, `ListInstructions`. Everything else scripts need is
  already a batch (`ListFunctions`, `ListSymbols`, ranged `GetXrefs`,
  `ListData`, `GetListing`).
- **Determinism is not promised** for scripts (they read files and the
  network). What is replayable is their output: one assertion batch with
  provenance, diffable with `ListAssertions` and revertable.

## The script API

`revkit.script` (`sdk/python/revkit/script/__init__.py`). `rk-script`
defines every name below in the script's globals; `from revkit.script
import *` makes them known to an editor too (outside a run, the context
names raise).

**Context**

| Name | What |
| --- | --- |
| `current_program` | a `revkit.Program` (every SDK read and write is there) |
| `current_address` | int or None (`--address`, or the UI's cursor) |
| `current_function` | the `Function` containing `current_address`, or None |
| `current_selection` | `(first, last)` or None (`--selection A:B`) |
| `args` | `--arg` values, typed by the script's `@arg` lines, with their defaults |
| `script` | its `ScriptMeta` (name, description, args, `sha12`) |
| `run_id`, `client` | the run's id (its provenance session), the `revkit.Client` |
| `monitor` | progress and cancellation (below) |

**Reads** (each takes an int, an `Address`, a `Function` or a symbol name
where an address is expected): `functions(name_contains="")`,
`function_at(a)`, `function_containing(a)`, `symbol_at(a)`, `to_addr(x)`,
`decompile(f, text=True)`, `decompile_many(funcs=None, text=True,
parallelism=0)` (all functions when None; results in completion order),
`read_bytes(a, n)`, `find_bytes("48 8b ?? 05" | bytes, mask=None, first=,
last=, max_results=, alignment=, executable_only=)`, `strings(text_contains,
min_length=)`, `instructions(first, last | function=, pcode=True)`,
`xrefs_to(a)`, `xrefs_from(a)`, `equates()` (the Equates table as
committed: `{name: Equate(name, value, references, enum_type_hash,
member)}`), `enums_with_value(v, program_only=False)`;
`image_base()`; `preview(a)` (what a hover card shows at `a`: a function's signature and first lines of C, else the listing's rows; docs/ui.md "Hover cards"); `mangled_name(a)` and
`demangled_signature(a)`, a demangled name's other spellings
(`api_minor` 40, [demangle.md](demangle.md); `symbol_at` gives the
demangled name, and `to_addr` takes either).

**Searches** (feature `search`, [api.md](api.md#search); cancelled with
the run's monitor): `search_memory(query, format="hex" | "string" |
"decimal" | "float" | "double" | "binary" | "regex", **options)`,
`search_text(query, fields=, regex=, case_sensitive=, whole_word=)`,
`search_scalars(min, max | value=, instructions=, data=)` and
`search_decompiled(query, functions=None)` (every function when None;
the monitor shows functions done of all). Each returns the match
messages; the options are `Program.search_*`'s ([api.md](api.md#python-sdk-sdkpython)).

```python
for m in search_text("parse_config", fields=["labels", "operands"], whole_word=True):
    print(hex(m.address.offset), m.text)
for m in search_scalars(value=0x5f3759df):
    note(m.address.offset, "fast inverse square root", tag="crypto")
```

Function ID ([fid.md](fid.md)): `fid_matches()` (the last run's matches on
the current program: entry, the name Function ID gives, status,
candidates with scores), `run_fid()` (runs it again, returns the matches),
`apply_fid(entry, name="")` and `reject_fid(entry)` (not buffered: each
commits at once, after what is buffered).

New on `revkit.Program` for everyone (not only scripts):
`strings()`, `data(*categories)`, `instructions(...)`, `find_bytes(...)`,
`decompile_many(...)`; and `byte_pattern()` and `describe_provenance()` in
`revkit`.

**Edits** (buffered; see below; `set_image_base(base)` isn't: it moves the
program at once, after committing what is buffered,
[memory-map.md](memory-map.md#rebase-setting-the-image-base)): `rename(a, name)`, `rename_local(f,
storage_key, name)`, `retype(a, c_declaration | type_hash=)`,
`retype_local(f, storage_key, c)`, `comment(a, text, kind="eol")`,
`set_function(entry, body=())`, `remove_function(entry)`,
`flow_override(a, kind)`, `note(a, text, tag="")`, `define_type(c_source,
keys=None)` (parses C for the program and defines and binds its types with
the run's edits), and from the listing (docs/listing-edit.md):
`define_data(a, type=None, count=0, string=None, layout=None,
collapsed=None, type_hash=None)` (a C type or a builtin such as `"dword"`,
an array of `count`, or a `"utf8"`/`"utf16"`/`"utf32"` string laid out
`"terminated"`, `"fixed"`, `"pascal"` or `"pascal16"`), `clear(a,
length=1)`, `disassemble(a, isa=None, function=False)` (`isa` `"arm"` or
`"thumb"`), `set_mutability(a, length, "constant" | "volatile" | "normal" |
"default")`; structures (docs/types.md, "Structures from pointer use"):
`auto_create_structure(f, storage_key, call_depth=None, name="")` (a
structure from the variable's use, bound by name, the variable retyped to
it), `auto_fill_structure(f, storage_key, call_depth=None)` and
`create_structure(first, last, name="")` (from the data in the range,
defined there), each returning the structure's name (two in one run get
two names, though neither is committed yet); project types
([types.md](types.md#project-types)): `move_types_to_project(keys)` and
`copy_types_to_program(keys)` (at once, not with the run's edits),
`type_archives()` and `set_type_archive_enabled(name, enabled)` (with the
run's edits); equates and user references
(docs/api.md, "Equates and user references"): `convert(a, value, format,
operand=None, apply_to=None)` (Ghidra's Convert: `"hex"`, `"signed"`,
`"unsigned"`, `"octal"`, `"binary"`, `"char"`, `"float"`, `"default"`),
`set_equate(a, value, name, operand=None, apply_to=None)` (`apply_to`
`"function"` or `"program"`), `set_enum_equate(a, value, enum, member)`,
`clear_display(a, value)`, `rename_equate(old, new)` and
`remove_equate(name)` (every operand that shows it, as committed),
`add_reference(from_, to, type="data", operand=None, primary=False)`
(`"data"`, `"read"`, `"write"`, `"call"`, `"jump"`, `"computed_call"`,
`"computed_jump"`), `remove_reference(from_, to, operand=None)` and
`set_primary_reference(from_, to, primary=True)`; then
`commit(reason="")`, `pending_edits()`, `revert(session="")`.

The same edits are on `revkit.Program` for everyone, each one
`AppendAssertions` (undo: retract its seqs): `convert`, `set_equate`,
`set_enum_equate`, `clear_display`, `equates()`, `rename_equate`,
`remove_equate`, `enums_with_value`, `add_reference`, `remove_reference`,
`set_primary_reference`; the bodies are `revkit.operand_display_body` and
`revkit.reference_body`, and `revkit.fold_equates` folds `ListAssertions`
(kind EQUATE) into the Equates table.

**The project** (`api_minor` 37): `current_project` (the program's
project id), `project_programs(project="")` (each with `folder_path`),
`folders(project="")`, and, applied at once rather than buffered, each one
revision with the run's provenance: `create_folder(path, parents=True)`
(returns its id), `rename_folder(folder, name)`, `move_to_folder(folder,
programs=(), folders=())`, `delete_folder(folder)` (folders by path or
id); `export_project(path, programs=(), folders=(),
annotations_only=False)` writes a `.rkproj` archive
([backend.md](backend.md#project-archives)).

**Prompts**: `ask_string`, `ask_int`, `ask_float`, `ask_address` (hex,
decimal, `401000h` or a symbol), `ask_yes_no`, `ask_choice`, `ask_choices`,
`ask_file`, `ask_values({"name": default, ...})`. Each takes the prompt's
`name` (what `--arg name=value` answers), a message and a default.

**Monitor**: `monitor.set_max(n)`, `increment(by=1)` (also checks for
cancellation), `set_progress(v)`, `message(text)`, `check_cancelled()`
(raises `Cancelled`), `is_cancelled`; Ghidra's spellings (`setMaximum`,
`checkCancelled`, ...) work too. Progress reaches the host at most ten
times a second.

**Output**: `print` goes to the run's console (stdout headless); `log(...)`
to its log (stderr). A failure's traceback starts at the script's own frame
and names its file and line (`RunResult.error_file`, `error_line`), which is
what the UI will link to.

`revkit.script.run_script(path, client=, program_id=, args=, host=,
context=)` runs a script in the current process and returns a `RunResult`
(status `ok`, `error` or `cancelled`, the error and traceback, the
revisions committed, the assertion count, the edits discarded, the time).

## Edits, provenance and precedence

- **Buffered, validated, one revision.** Each edit call appends to the
  run's buffer with the script line that made it. When the script ends
  normally (also through `sys.exit(0)`), the buffer is sent once with
  `validate_only`; a refused edit fails the run with `script.py:12: rename
  0x401000 to '': assertions[3]: ...` and nothing lands. Then the same
  request commits: one revision. `commit(reason=)` flushes early, for a
  script that works in stages (each commit is a revision).
- **Failures commit nothing.** A script that raises, exits non-zero, or
  is cancelled discards what it had buffered (`RunResult.discarded`);
  what earlier `commit()` calls landed stays.
- **Provenance**: kind `script` (`PROVENANCE_KIND_SCRIPT = 7`), id the
  script's name (its `@name`, else the file's stem), version the first 12
  hex digits of the source's SHA-256, session the run id, tool
  `script:<name>@<sha12>`, reason the script's `@description` unless
  `--reason` says otherwise.
- **Who ran it**: `Provenance.on_behalf_of` (api_minor 29). With
  authentication the server stamps the caller ("user:alice",
  "agent:ci-bot") and refuses any other value; clients send it empty. Any
  editor may write `script:<name>` provenance, since the person is recorded
  beside it. Admins writing importer provenance (`import:ghidra`) get
  `on_behalf_of` stamped too. Without authentication (`--no-auth`) the
  client's text is kept: `rk-script` sends the client's actor, else
  `user:<login name>`.
- **Precedence**: `user > import = migration > agent = plugin = script >
  analysis`, later winning among equals. A script's rename loses to any
  person's edit, whenever it was made; re-running a bulk-rename script
  never undoes your manual fixes. Rejected: running scripts as `user:`
  provenance, where a re-run would shadow the user's own later fixes.
- **Blame and filters**: blame candidates and `FactOrigin`s carry the full
  provenance; the UI's badge reads "alice via script:fix-names"
  (`ui/src/data/format.ts` `provBadge`). `ProvenanceFilter.on_behalf_of`
  narrows `ListAssertions` and `RevertByProvenance` to what someone's
  scripts did (`prog.assertions(on_behalf_of="user:alice")`).
- **Reverting a run**: `prog.revert(session=run_id)`
  (`RevertByProvenance` with the session filter), or `revert()` inside a
  script for its own committed edits. Like every revert it is one
  revision and itself undoable.

## Prompts, output and the host interface

A run talks to a **host** (`revkit/script/host.py`) through four calls:
`output(text, stream)`, `progress(current, maximum, message)`,
`ask(prompt)` and `cancelled()`, plus lifecycle `event`s (start, result,
error). Two hosts ship:

- `HeadlessHost` (`rk-script`): output to the terminal (prefixed by the
  program when several run); a prompt is answered by `--arg name=value`,
  then by stdin when it is a terminal (or `--stdin`: one answer per line,
  `a,b` for several choices), then by the prompt's default, and otherwise
  the run **fails at once**: `int prompt 'limit' (Limit) has no answer:
  pass --arg limit=VALUE`.
- `StreamHost`: JSON lines both ways, which the daemon's script service
  speaks to its host processes. Out: `{"type": "start" | "output" |
  "progress" | "prompt" | "result" | "error", ...}`; a prompt carries
  `id`, `kind`, `name`, `message`, `default`, `choices`; the result has the
  committed `seqs`. In: `{"type": "answer", "id": N, "value": ...}` (or
  `"cancelled": true`), `{"type": "cancel"}` and `{"type": "context",
  "address": "0x...", "selection": [first, last] | null}`, which moves
  `current_address`, `current_function` and `current_selection` while the
  script runs. With `background=True` (the worker's) a thread reads them
  as they come. `python -m revkit.script.worker --stream` runs a script
  under it; there SIGTERM cancels at once (a sleep or a blocking call is
  interrupted), except during a commit, which finishes first.

Output reaches the host a line at a time (`print(..., flush=True)` sends a
partial line).

## rk-script

```
rk-script run S.py [--daemon host:port | --throwaway] [--project-dir D] [--import FILE... | --program ID...]
                   [--pre P.py] [--post Q.py] [-j N] [--arg k=v] [--json]
                   [--address A] [--selection A:B] [--context JSON] [--decompilers N] [--progress] [--stdin]
                   [--token T] [--fingerprint F | --ca PEM] [--actor user:NAME] [--reason TEXT] [--listen-port P]
                   [--script-arg V]... [--compat auto|ghidra|off] [--lib DIR]...
rk-script info S.py
rk-script list [DIR...] [--json]
rk-script setup [--dir D] [--python P] [--wheel W] [--with PACKAGE]... [--force] [--dry-run]
```

- **Where**: `--daemon` (default `$RK_GRPC`), with `--token` /
  `$RK_TOKEN` and `--fingerprint` / `--ca` for an authenticated daemon
  ([security.md](security.md#clients)); or `--throwaway`, a daemon of its
  own (`revkit.Daemon`, `--no-auth` on free loopback ports; the default
  when only `--import` is given) with `--decompilers` workers (default
  `max(2, -j)`) and, with `--project-dir D`, a persistent project: imports
  (matched by SHA-256) and decompilations are reused by the next run.
- **Ghidra scripts**: `--script-arg` gives a Ghidra script its arguments
  (`getScriptArgs()`, which answer its `ask*` calls in order) and
  `--compat` says whether it is one ([below](#running-ghidra-scripts)).
- **What**: `--program ID` names programs on the daemon; `--import FILE`
  imports into `--project` (default `default`), reusing a program with the
  same file. Scripts are paths or shipped names (`rk-script run
  batch_decompile`).
- **Per program**: the `--pre` scripts, then waiting for analysis
  (`GetAnalysisStatus` idle, `--analysis-timeout`), then the script, then
  the `--post` scripts, each in turn in one host process (`python -m
  revkit.script.worker`), each its own run and revision; a failing phase
  stops that program's later phases. `-j N` programs at a time.
- **Exit status**: 0 when every run succeeded, 1 when one failed, 2 for a
  usage error, 3 when cancelled (SIGINT/SIGTERM: the host cancels the
  monitor; a second signal interrupts). With `--json`, one object per
  program on stdout (`program_id`, `input`, `status`, `exit_code`,
  `seconds`, `revisions`, `assertions`, `error`, and `runs`: each phase's
  `RunResult`), and the scripts' output goes to stderr, for CI.
- **setup**: makes the Python environment the daemon runs scripts with,
  `~/.local/share/revkit/pyenv` (`$XDG_DATA_HOME`), which `rk-daemon` looks
  for: a venv from this Python (`--python`) with the revkit SDK (`--wheel`,
  default the wheel in `share/revkit/python` beside `rk-daemon`, else
  `share/revkit/sdk`'s, else this source tree) and whatever your scripts
  import (`--with angr --with z3-solver`). Run again to update the SDK: it
  reinstalls the SDK itself even when the version string is the same
  (`pip install --force-reinstall --no-deps`, so an older build of the
  same version is replaced and the dependencies are left alone); `--force`
  makes the environment anew.

**From the packages.** The `.deb` and the bundle ship the SDK as a wheel
in `share/revkit/python/` and `bin/rk-script`
(`packaging/linux/rk-script`), a shell wrapper that runs the SDK's
`rk-script` from that environment. On a fresh machine its first run (any
command, or `rk-script setup`) makes the environment from the wheel:
`python3 -m venv` (Python 3.10 or newer with its venv module: on Debian
and Ubuntu `python3` and `python3-venv`, which the package recommends but
doesn't require; the daemon, the CLIs and the web UI need no Python), then
`pip install` of the wheel, whose dependencies (`grpcio`, `protobuf`) pip
fetches from PyPI or the index it is configured with. A package upgrade
brings a newer wheel; the wrapper's next run installs it. `rk-script
setup` takes the SDK's options (`--with`, `--force`, `--dry-run`, `--dir`,
`--python`); `$REVKIT_PYENV` names another environment. The Script
Manager's **Set up Python** does the same through the daemon
(`SetupScriptPython`, below), so the desktop app needs no terminal.

## The daemon's script service

`ScriptService` (`proto/revkit/v1/script.proto`, `src/api/script_service.cc`;
`api_minor` 31, feature `scripts-host`; the RPCs in
[api.md](api.md#scripts-the-daemon-runs)) is how the UI, and any client,
runs scripts without a Python of its own.

- **Libraries.** `ListScripts` reads three directories and parses each
  script's metadata (the same tags as `meta.py`, in C++): **shipped**
  (`share/revkit/scripts`, installed with the packages from
  `sdk/python/revkit/scripts`; in a source build, that directory),
  **per-user** (`~/.config/revkit/scripts`, `$XDG_CONFIG_HOME`, or
  `rk-daemon --scripts-dir`) and **per-project**
  (`<project-dir>/<project>/scripts`, with `--project-dir`; it travels with
  the project directory). Scripts are named by id: `shipped/x.py`,
  `user/x.py`, `project/<project>/x.py`. `SaveScript` writes per-user and
  per-project scripts (never shipped ones), refusing to overwrite text
  changed since it was read.
- **A run.** `RunScript` starts `python -m revkit.script.worker --stream
  --no-analysis-wait` for the program, the script, the `--arg`s and the
  UI's context, in its own process group with the daemon's environment
  plus `RK_TOKEN` (a run token) and, over TLS, `RK_TLS_FINGERPRINT`. It
  connects back to the daemon's gRPC listener (`127.0.0.1` for a wildcard
  bind). The host's JSON lines become the stream: `started`, `output`,
  `progress`, `prompt`, then `result` (the committed `revisions` and
  assertion `seqs`) or `error` (the message, the traceback with the
  script's path shown as its id, and the `script_id` and `line` it failed
  at). A host that dies without a result (a crash, `os._exit`, SIGKILL) is
  an error naming its exit status; its stderr is in the output.
- **Run tokens.** The daemon mints a token for each run through its
  credential store (`Store::mint_run_token`): in memory only, acting as the
  caller (kind, name, role, projects; re-checked against the account or
  API token on every use) and revoked when the run ends. The script's edits
  therefore pass the same authorization and stamping as the caller's own:
  `script:<name>@<sha12>`, `on_behalf_of` the caller, the run id as the
  session. A script the daemon runs can't start scripts. Without
  authentication (`--no-auth`) there is no token and `on_behalf_of` is the
  daemon's login name, as for `rk-script`.
- **Prompts** arrive as `prompt` messages and are answered with
  `AnswerPrompt` (a dismissed prompt cancels the run); `--arg`s
  (`RunScriptRequest.args`) answer prompts of their name without asking.
- **Cancel.** `CancelScript`, or the client going away: the host gets a
  cancel message and SIGTERM (the script ends at once, committing
  nothing it had buffered), and SIGKILL to its process group 2 s later if
  it is still there.
- **Context.** `UpdateContext` sends the UI's cursor and selection to a
  running script; its `current_address`, `current_function` and
  `current_selection` follow.
- **Who may run scripts.** `rk-daemon --scripts-host-role
  off|viewer|editor|admin`; by default editor (and admin) when every
  listener is on loopback and off otherwise. `ListScripts.host_enabled`
  and `host_disabled_reason` tell the UI. A viewer never saves scripts,
  and runs them (and the console) only under `viewer`, read-only: the
  host gets `--read-only` (edits fail at once, "this run is read-only")
  and a viewer's run token (the daemon refuses an edit that goes around
  the buffer).
- **Libraries.** The host imports from the per-user library, then the
  project's ([below](#libraries)): the daemon passes both as `--lib`.
- **Trust.** A per-user or per-project script runs only after its caller
  confirmed its exact text: `RunScript` answers `trust_required` (the
  source, the hash, `unseen` or `changed` with the hash confirmed before)
  until it is called with `confirm_sha256` equal to the script's SHA-256.
  The pin is kept per caller and script in `~/.config/revkit/trusted-scripts`
  (mode 0600); saving a script pins it for the saver only, so a project
  script someone else changed asks you again. Shipped scripts are trusted.
- **Python.** `--script-python`, else the first of `$REVKIT_PYTHON`,
  `~/.local/share/revkit/pyenv/bin/python` and `python3` whose revkit SDK
  is this daemon's (in a source build, also with the tree's `sdk/python`
  on `PYTHONPATH`): it imports `revkit.script.worker` and
  `revkit.script.console`, and its `revkit.script.SCRIPT_API` is at least
  the daemon's (`kScriptSdkApi` in `script_service.cc`; raised together
  when the daemon starts relying on something new in the SDK). When none
  can, `ListScripts.python_problem` and `RunScript`'s
  `FAILED_PRECONDITION` (the console's too) say what was tried and how to
  set one up (`rk-script setup`, or the Script Manager's **Set up
  Python**). A Python with an **older SDK** (an environment made before
  the console existed, which pip left alone because the version string
  hadn't changed) is passed over, and when it is the only one the problem
  says so: "the revkit SDK in <python> is older than this daemon … Set up
  Python (or run `rk-script setup`) to update it". The Script Manager's
  banner and the Python console then offer **Set up Python**. A found
  Python is kept; a failed search is repeated at most every 5 s, so
  setting one up needs no restart.
- **Setting Python up.** `SetupScriptPython` (`api_minor` 33, feature
  `scripts-setup`) makes `~/.local/share/revkit/pyenv` as `rk-script
  setup` does: `python3 -m venv` (`--script-setup-python` names another
  base Python), `pip install --upgrade` of the SDK beside the daemon
  (`share/revkit/python`'s wheel; in a source build, `sdk/python`), then
  `pip install --force-reinstall --no-deps` of the SDK alone (pip keeps an
  installed SDK with the same version string even when it is an older
  build; its dependencies are left as they are), then the daemon's SDK
  check, each command's output streamed as it runs, then the
  result; the daemon looks for its Python again at once. For callers who
  may run scripts, one at a time; refused when `--script-python` names
  the Python. Errors say what to do (install `python3-venv`, reach PyPI
  or a mirror via `PIP_INDEX_URL`).
- **Limits.** 8 runs at once (`RESOURCE_EXHAUSTED` beyond), a script file
  of at most 1 MiB, 8 MiB of output per run (then a truncation note), the
  last 200 runs in `ListScriptRuns`.

The UI ([ui.md](ui.md#scripts)) puts it together: the Script Manager,
palette and key entries, `@context` scripts in the listing's and
decompiler's right-click menus, the output panel, prompts as dialogs, the
trust dialog, the editor, and each run as one undo step
(`Edits.record(label, result.seqs)`).

The Python client has the same calls (`Client.list_scripts`,
`run_script(...).wait(answers)`, `save_script`, `script_runs`), the
TypeScript SDK `runScript(rk, request, handlers)`, and the MCP server
`list_scripts` and `run_script` ([api.md](api.md)).

## The console

The Python console is a REPL bound to one program, which the daemon runs
for you as it runs scripts (`api_minor` 43, feature `script-console`;
`RunScript{interactive: true}`, [api.md](api.md#scripts-the-daemon-runs)).
The UI's **Window: Python** view is its front end
([ui.md](ui.md#python-console)); `Client.console(program)` and the
TypeScript `consoleRun` are the clients' ([api.md](api.md)).

```python
>>> f = current_function
>>> f.name, f.size
('main', 183)
>>> for x in xrefs_to(f):
...     print(hex(x.from_address.offset), x.from_function_name)
...
0x1040 _start
>>> rename(f, "entry_main")          # one statement: one revision, one undo
```

- **One live host per user and program.** The first statement (or an
  empty one, which only opens it) starts `python -m revkit.script.console`
  with a run token acting as you, as for a script; later statements go to
  the same process, so the namespace (variables, imports, functions you
  defined) persists between them and between pages of yours on that
  program. A host that died (a crash, `os._exit`) is started again by the
  next statement (`started.console_started`; the namespace is new);
  `exit()` and **Restart** (`CancelScript` with the console's run id) end
  it on purpose. One idle for `rk-daemon --console-idle-timeout` seconds
  (default 1800; 0: never) is closed and its token revoked. At most 16
  consoles at once on a daemon; one statement at a time per console.
- **Names.** `revkit.script`'s, as a script has them, with
  `current_address`, `current_function` and `current_selection`
  following the cursor (`UpdateContext` with the console's run id; each
  statement also carries the cursor). `ghidra_names` binds Ghidra's too,
  as Ghidra's Python console does: `currentProgram`, `currentAddress`,
  `currentSelection`, `getFunctionAt`, `toAddr`, ... (the compat layer,
  [below](#running-ghidra-scripts)); turning it off removes them.
  `input()` asks through the UI's prompt (the console's stdin is its
  protocol), as `ask_*` do.
- **Input as Python's REPL takes it** (`code`/`codeop` rules): a statement
  runs; an open block or an unclosed bracket answers `more` and runs
  nothing, and the UI sends the lines again with the next one; an empty
  last line ends a block; a paste of several statements runs at once.
  Each top-level expression echoes its value (`sys.displayhook`).
  Tracebacks start at the console's own lines (`<console 7>`, with the
  source shown), not the host's.
- **Edits, one statement at a time.** A statement's edits are buffered
  and committed when it ends, as one revision: provenance kind `script`,
  id `console`, version the first 12 hex digits of the statement's
  SHA-256, the console's run id as the session, `on_behalf_of` you. The
  UI makes its `seqs` one undo step. A statement that raises, or is
  interrupted, commits nothing it had buffered (`discarded`); `commit()`
  inside one commits early, as in a script. A viewer's console
  (`--scripts-host-role viewer`) is read-only: reads work, edits fail at
  once, and the daemon would refuse them anyway.
- **Ctrl+C** is `CancelScript{run_id, interrupt: true}`: SIGINT to the
  host, a `KeyboardInterrupt` in the statement (`status: interrupted`),
  never in the middle of a commit; the console stays. Closing the
  `RunScript` call (a page going away) interrupts too, and a statement
  that ignores it with nobody waiting is ended with its console 10 s
  later.
- **Completion.** `CompleteConsole{program_id, text}` answers from the
  console's live namespace, even while a statement runs: with jedi when
  the host's Python has it (`pip install jedi` into the scripts' Python),
  else the standard library's rlcompleter (attribute chains are
  evaluated, as rlcompleter does; properties are never called to describe
  a completion). Each completion has its kind, its signature without
  annotations (`rename(addr, name)`) and its docstring's first line, which
  the UI also shows as signature help on `(`.
- **History.** The daemon keeps each caller's statements, the last 1,000
  (an open block isn't one until it ends), in
  `~/.config/revkit/console-history/<caller>-<hash>.json` (mode 0600; the
  daemon's user's `$XDG_CONFIG_HOME`), and sends them with `started`: the
  history follows you between browsers and the desktop app.

The host speaks the stream host's JSON lines plus `exec` (a statement:
`{"type": "exec", "id", "source", "context", "ghidra"}` answered by
`done`), `complete` (answered by `completions`) and `quit`; it says
`ready` (its Python and completion engine) when it starts
(`revkit/script/console.py`).

## Libraries

Scripts import Python modules of your own: `import mylib` finds
`mylib.py` (or a `mylib/` package) in, in order:

1. the **per-user library**, `~/.config/revkit/scripts`
   (`$XDG_CONFIG_HOME/revkit/scripts`; the daemon's `--scripts-dir`);
2. the **project's library**, `<project-dir>/<project>/scripts`, for the
   program's project (a daemon with `--project-dir`; `rk-script` with
   `--project-dir`);
3. `rk-script --lib DIR`, each in turn;
4. the script's own directory, when it is none of these (a script run
   from anywhere with `rk-script` imports its neighbours).

They go on `sys.path` **after Python's standard library and before
installed packages**: a library can't shadow `json` or `re`, and a module
of yours wins over an installed package of the same name. The same order
holds for scripts the daemon runs, `rk-script`, and the console (which
imports what the libraries hold when a statement asks: `import mylib`,
then `importlib.reload(mylib)` after you change it, since the console's
process lives on). The Script Manager doesn't list files whose name starts
with `_`, so `_helpers.py` is a library and not a script; the shipped
starters share code that way (`revkit/scripts/_signatures.py`).

## Editor completion

The Script Manager's editor completes the script API without asking the
daemon, from a static index generated from the SDK: `python -m
revkit.script.completion_index` reads `revkit.script.__all__` (with each
function's signature and docstring), the members of what the context
names are (`revkit.Program` for `current_program`, `Client`, `Monitor`,
the `Function` fields) and the compat layer's Ghidra names (the flat API,
`currentProgram`'s `Program`, `Address`), and writes
`ui/src/scripts/script-api.json` (format `revkit-script-api/1`, about
90 KB, loaded by the editor on first use). `sdk/python/generate.sh` runs
it with the protobuf stubs, and `tests/test_completion_index.py` fails
when the committed file isn't what the SDK gives now. Signatures leave
out annotations, which differ between Python versions and crowd a
tooltip. Typing `(` after a function the index knows shows its signature
with the current argument in bold ([ui.md](ui.md#scripts)).

## Metadata

`revkit/script/meta.py` reads the comment block at the top of a script
(the first line of code ends it), the tags Ghidra scripts use plus typed
arguments; the daemon's `ListScripts` reads the same tags
(`ParseScriptMetadata` in `src/api/script_service.cc`).

| Tag | Meaning |
| --- | --- |
| `@category A/B` | where it is listed |
| `@description text` | what it does (repeat the tag to continue); the provenance reason |
| `@menupath A.B` | where the Script Manager and the palette show it |
| `@keybinding ctrl shift R` | a key that runs it in the UI |
| `@context program\|function\|address\|selection` | what it applies to: `function`, `selection` and `address` scripts are in the listing's and decompiler's right-click menus |
| `@arg name[:type][[a\|b]][=default] description` | an argument: `str`, `int`, `float`, `bool`, `address`, `file`, `choice`; `--arg name=value` sets it, and answers an `ask_*` of that name |
| `@name n` | the provenance id, if not the file's stem |

Unknown tags are kept (`ScriptMeta.extra`); malformed ones are listed in
`errors` (`rk-script info` exits 1).

## Batch RPCs

`api_minor` 29, feature `script-batch` ([api.md](api.md)); policies in
`src/api/auth_policy.cc` (viewer of the project, as the per-item reads).

- **`QueryService.DecompileMany`** (server-streaming): `functions` or
  `all`, `DecompileOptions` (`include_text`, `timeout_ms`), `parallelism`
  (default the daemon's decompiler workers plus one, at most 64), and
  `ReadOptions`. The daemon resolves one snapshot and holds it for the
  whole call (a pinned revision it no longer keeps fails at once with
  `REVISION_EXPIRED`; the Python SDK then reruns at head), orders the
  functions it served before first (they are probably memoized), and runs
  `parallelism` threads each taking the next function through the memoized
  `Decompile` query, so results arrive in completion order. Each
  `DecompileManyResponse` has `index`, `total`, `entry`, `function` or
  `failure` (as `Decompile`) or `error` (no function there),
  `served_before`, `function_ms` and `elapsed_ms`. A client that goes away
  stops the work not started.
- **`QueryService.FindBytes`**: `pattern` (1-256 bytes), `mask`, `range`,
  `alignment`, `executable_only`, `max_results` (default 1000, at most
  100,000; `truncated` says there were more). Searched over the memory
  map's initialized blocks as patched, in 1 MiB chunks, with `memchr` on
  the first fully-masked byte. On `/usr/bin/bash`: 3 ms for 1,779
  matches of a 3-byte pattern.
- **`QueryService.ListInstructions`** (server-streaming): the instructions
  in a `range` or a `function`'s body, each an `InstructionDetail` as
  `GetInstruction` returns it (tokens, operands with references, flow,
  p-code unless `omit_pcode`), 256 per message, `limit` and `truncated`.
  All 228,850 instructions of bash without p-code: 1.7 s. (The plugin
  ABI's `FunctionCode` blobs were considered and not used: their
  consumers are wasm guests, and the protobuf message is what every
  client already reads.)

## Starter scripts

Shipped in `sdk/python/revkit/scripts/` (`rk-script list`), each with
metadata and a test in `sdk/python/tests/test_starter_scripts.py`:

| Script | What |
| --- | --- |
| `rename_by_strings` | names `FUN_` functions after the identifier a string they use starts with ("parse_config: missing value") |
| `find_crypto_constants` | AES S-boxes, SHA-1/2, MD5, CRC-32/32C, Blowfish and ChaCha constants by `FindBytes`, in the program's byte order; a `crypto` note at each, naming its users |
| `decrypt_strings` | emulates each caller of a decryption function (`EmulatorService`, call mode, a breakpoint per call), reads the buffer after the call and comments the call site |
| `export_functions` | functions (entry, name, size, prototype, callers, references, optionally the C through `DecompileMany`) to JSON or CSV |
| `batch_decompile` | `DecompileMany` over every (or named) function with a timing report: rate, p50/p90/p99/max, slowest, failures by kind |
| `xref_report` | references to a symbol or address grouped by function, with the referring instruction |
| `create_functions_at_call_targets` | a function at every direct call target in executable memory that no function starts at |
| `find_format_string_sinks` | calls to printf-family functions (and `_chk` variants) whose format argument isn't a string literal, from the decompiled callers' tokens |
| `comment_syscalls` | comments `syscall`/`int 0x80`/`svc` with the call's name from the number loaded just before (Linux x86-64, x86, AArch64, ARM) |
| `list_unreferenced_data` | defined data with no references (strings, pointers, typed globals) |
| `tag_functions_by_complexity` | asks which measure (`ask_choice`: size, instructions or callers), measures every function with progress, and puts a `complexity:` plate comment on the top tenth (or those over `threshold`) |
| `summarize_function` | `@context function`: the function at the cursor's size, instructions, callers and callees as its plate comment |
| `export_call_graph` | the call graph as Graphviz DOT or JSON: the whole program, or what a root function reaches to a depth, with or without imports (one ranged `GetXrefs` for every call) |
| `apply_header` | applies a C header: defines its types (committed first), then gives every function, imports included, whose name a prototype declares that prototype; `dry_run` reports |
| `name_wrappers` | names small `FUN_` functions that only call (or tail-jump to) one named function `<callee>_wrapper` (`__printf_chk` counts as `printf`) |
| `find_dangerous_calls` | calls to easy-to-misuse functions (`gets`, `strcpy`, `sprintf`, `system`, `popen`, `exec*`, `mktemp`, ... and their `__*_chk` forms, or a list you give), by caller, each with a `dangerous-call` note |
| `export_strings` | strings with their addresses and the functions that use them, to JSON or CSV |
| `search_instructions` | instructions whose text ("mnemonic operands") matches a regular expression, in the selection or every executable block; optionally a `search` note on each |
| `dump_memory` | `@context selection`: the selection's (or a range's) bytes as patched, raw, as a hex dump, or as a C array |
| `export_function_signatures` | a signature of every named function (SHA-256 of its instructions with every address operand masked) to JSON |
| `apply_function_signatures` | names `FUN_` functions whose signature matches exactly one function of such a file (and one here), optionally with its prototype: a small Function ID across builds |
| `list_notes` | the program's notes by tag (crypto constants, dangerous calls, search hits, ...), Ghidra's Bookmarks as a report, optionally to JSON |

## Running Ghidra scripts

`revkit.ghidra.compat` runs Python scripts written for Ghidra (its
`GhidraScript` and `FlatProgramAPI`) on revkit. It is a bounded subset over
`revkit.script`, labelled "compat" on purpose: what scripts commonly use
works, everything else fails at once with an `Unsupported` error that names
the Ghidra API and what to use in revkit instead. revkit's own API
(`revkit.script`, above) is what new scripts should use, and it gets
features first.

### How a script is run

`rk-script` and the daemon's script service (so the Script Manager too) look
at a script before running it. It is a Ghidra script when it imports
`ghidra.*` or says `@runtime Jython` or `@runtime PyGhidra`, or, if it
doesn't import `revkit`, when it uses `currentProgram` or `currentAddress`
or calls Ghidra's flat API (`println(`, `toAddr(`, `getFunctionAt(`,
`askString(`, ...). `--compat ghidra|off` (rk-script) overrides the guess.
Such a script runs with:

- GhidraScript's names defined: `currentProgram`, `currentAddress`,
  `currentLocation`, `currentSelection`, `currentHighlight` (None),
  `monitor`, `state`, and every `GhidraScript`/`FlatProgramAPI` method as a
  function (`println`, `toAddr`, `getFunctionAt`, `askString`,
  `createLabel`, ...). The UI's cursor and selection follow into a running
  script as they do for revkit scripts. revkit's own names (`rename`,
  `decompile_many`, `current_program`, ...) are there as well, for scripts
  that mix the two.
- `ghidra.*` imports answered by the shim while it runs:
  `from ghidra.program.model.listing import Function`,
  `from ghidra.program.model.symbol.SourceType import *` and Jython's
  `import ghidra.program.model.data.StringDataType as StringDataType`. A
  Ghidra class the shim doesn't have imports as a placeholder that raises
  `Unsupported` when used, so an import the script never uses costs
  nothing. `java.*`, `javax.*`, `docking.*` and `jpype` import the same way:
  there is no JVM.
- Its metadata read as Ghidra writes it: the comment lines before the tags
  are the description, `# @category: Examples` takes the colon, and the
  `## ###` licence block is skipped (in `rk-script info` and `ListScripts`).

```sh
rk-script run MakeFunctionsScript.py --program default/bash --script-arg "55 48 89 e5"
rk-script run FindTextScript.py --program default/bash --address main --arg "Text Search=parse"
rk-script run anything.py --compat ghidra      # or off: never treat it as a Ghidra script
```

**Prompts.** `askString`, `askInt`, `askLong`, `askDouble`, `askYesNo`,
`askChoice`, `askChoices`, `askAddress`, `askFile`, `askDirectory` and
`askBytes` take their answers as Ghidra's headless mode does: from the
script's arguments in order (`--script-arg`, repeatable; `getScriptArgs()`
returns them), then from `--arg TITLE=VALUE` (the prompt's title is its
name), then from the UI's dialog or the terminal, then the default; with
none of these a headless run fails naming the prompt.

**Python 3 only.** Ghidra's Jython scripts are Python 2: make each `print`
statement a call (`print "x", y` becomes `print("x", y)`), `long(...)`
becomes `int(...)` and `except E, e:` becomes `except E as e:`, and drop
`import exceptions`.
A script that fails to compile for this reason says so in its error.
PyGhidra scripts are Python 3 already, but use Java classes through JPype
where Ghidra's API takes them (`jpype.JArray(jpype.JByte)(10)`): those fail
with `Unsupported`; the shim takes Python lists and `bytes` where Ghidra
takes `byte[]`, and returns signed byte lists (`bytes(b)` gives the raw
bytes) where Ghidra returns one.

### What it covers

- **`currentProgram`**: `getName`, `getLanguage` (`getLanguageID`,
  `getProcessor`, `isBigEndian`), `getCompilerSpec` (`getCompilerSpecID`,
  `getDataOrganization`), `getAddressFactory` (`getAddress("0x...")`,
  `getDefaultAddressSpace`), `getMinAddress`, `getMaxAddress`,
  `getImageBase`, `getExecutableSHA256`, `getDefaultPointerSize`,
  `startTransaction`/`endTransaction` (a commit; a rollback is
  `Unsupported`), and its managers:
- **`getFunctionManager()`**: `getFunctions(forward)` and `(start | set,
  forward)`, `getFunctionsNoStubs`, `getFunctionAt`,
  `getFunctionContaining`, `getFunctionCount`, `isInFunction`,
  `removeFunction`, `createFunction`. A **`Function`** has its name
  (`setName`), entry, body, plate and repeatable comments, prototype
  string, calling convention, thunk and no-return flags, callers and
  callees (`getCallingFunctions`, `getCalledFunctions`), and parameters and
  locals from the decompiler (`getParameters`, `getLocalVariables`; a
  `Variable` renames and retypes its decompiler variable).
- **`getSymbolTable()`**: `getSymbolAt`, `getPrimarySymbol`, `getSymbols`
  (by address, name, or set and type), `getSymbolIterator`,
  `getPrimarySymbolIterator`, `getDefinedSymbols`, `getAllSymbols`,
  `getGlobalSymbols`, `getSymbol(reference)`, `createLabel`,
  `getExternalEntryPointIterator`. A **`Symbol`** has its name
  (`setName`), address, `SymbolType`, `SourceType` and references.
- **`getRelocationTable()`** (feature `relocation-table`): `getRelocations`
  (all, at an address, or in a set), `hasRelocation`,
  `getRelocationAddressAfter`, `getSize`, `isRelocatable`. A
  **`Relocation`** has its address, type, symbol name, bytes, values (the
  addend) and status, always `UNKNOWN`: revkit applies relocations to no
  bytes except the RELATIVE ones a rebase moves.
- **`getListing()`**: instructions (`getInstructionAt`,
  `getInstructionContaining`, `getInstructionAfter`/`Before`,
  `getInstructions(forward | set | start)`), data (`getDataAt`,
  `getDefinedDataAt`, `getDataContaining`, `getDataAfter`/`Before`,
  `getDefinedData`, `getData` with undefined bytes), code units
  (`getCodeUnitAt`, `getCodeUnitContaining`, `getCodeUnits`), comments
  (`getComment`, `setComment`, `getCommentAddressIterator`),
  `getFunctions`, `clearCodeUnits`, `createData`. An **`Instruction`** has
  Ghidra's operand text (`getDefaultOperandRepresentation`), operand
  objects (`getOpObjects`: `Register`, `Scalar` with its decoded width,
  `Address`), `getOperandType`, `getOperandReferences`, `getFlowType`,
  `getFlows`, `getFallThrough`, `getFallFrom`, `getPcode`, and
  `getInputObjects`/`getResultObjects` from its p-code. A **`Data`** has its
  type, mnemonic, value (a string, a `Scalar` or an `Address`) and
  Ghidra's value text.
- **`getMemory()`** (also an address set of the blocks): `getBlocks`,
  `getBlock`, `getByte`/`getShort`/`getInt`/`getLong`, `getBytes`,
  `findBytes` (forward and back, with masks; one `SearchMemory` call
  either way), `getExecuteSet`,
  `getLoadedAndInitializedAddressSet`, `locateAddressesForFileOffset`, and
  `setByte`/`setBytes`/`setInt`: patches (below).
- **`getReferenceManager()`**: `getReferencesTo`, `getReferencesFrom`,
  `getReferenceCountTo`, `hasReferencesTo`, `getFlowReferencesFrom`,
  `getReferenceSourceIterator`, `getReferenceDestinationIterator`; and
  user references (from instructions; `RefType` `DATA`, `READ`, `WRITE`,
  `UNCONDITIONAL_CALL`, `UNCONDITIONAL_JUMP`, `COMPUTED_CALL`,
  `COMPUTED_JUMP` and their conditional forms): `addMemoryReference(from,
  to, type, source, opIndex)`, `delete(ref)` (the user's, or analysis's:
  it leaves xrefs), `setPrimary(ref, primary)`, `updateRefType`,
  `removeAllReferencesFrom`, `removeAllReferencesTo`. A **`Reference`**
  has its addresses, `RefType`, operand index, source and `isPrimary`.
- **`getEquateTable()`**: the program's equates (folded from its EQUATE
  assertions): `getEquate(name)`, `getEquate(addr, opIndex, value)`,
  `getEquates()`, `getEquates(addr[, opIndex])`, `getEquates(value)`,
  `getEquateAddresses`, `createEquate(name, value)` (kept by the run until
  `addReference` uses it), `removeEquate(name)`, `deleteAddressRange`. An
  **`Equate`** has `getName`, `getValue`, `getDisplayValue`,
  `getReferenceCount`, `getReferences` (`EquateReference`: `getAddress`,
  `getOpIndex`, `getDynamicHashValue`), `addReference(addr, opIndex)`,
  `removeReference(addr, opIndex)`, `renameEquate(name)` (every operand),
  `isEnumBased` and `getEnumUUID` (the enum's type hash). Equates name
  instruction operands; revkit has no data equates.
- **`getDataTypeManager()`**: `getDataType("/int")` for Ghidra's builtin
  types (`int`, `dword`, `char`, `pointer`, `string`, `unicode`, ...) and
  the program's named types (`FindTypes`); `CParser(dtm).parse(c)` then
  `addDataType` defines types from C (`ParseC`). The builtin classes
  (`IntegerDataType`, `StringDataType`, `PointerDataType(t)`,
  `ArrayDataType(t, n, size)`, ...) work with `createData` and
  `isinstance`.
- **Values**: `Address` (`getOffset`, `add`, `subtract`, `next`,
  `compareTo`, Ghidra's text "00101139"), `AddressSet` (`add`, `delete`,
  `contains`, `union`, `intersect`, `subtract`, `getAddresses`,
  `getAddressRanges`, ...), `Register`, `Scalar`, `SourceType`,
  `SymbolType`, `RefType`/`FlowType`, `CommentType` (and `CodeUnit`'s
  comment numbers), `OperandType`.
- **Flat functions**: the reads above unqualified (`getFirstFunction`,
  `getFunctionAfter`, `getInstructionAfter`, `getFirstData`,
  `getDataAfter`, `getSymbolAt`, `getReferencesTo`, `getBytes`, `getInt`,
  ...), `toAddr`, `find(text)` (plate comments, pre-comments, labels,
  then mnemonics, in Ghidra's order, through `SearchText`),
  `find(start, bytes)`, `findBytes(start, regex[, limit, alignment])` (a
  regular expression over the bytes, as Ghidra's, run by `SearchMemory`
  with RE2 on the daemon; one RE2 can't run, with backreferences or
  lookaround, is matched with Python's `re` over the bytes read instead),
  `findStrings`, `createLabel`, `setEOLComment`,
  `setPlateComment`, `setPreComment`, `setPostComment`,
  `setRepeatableComment` and their getters, `createFunction`,
  `removeFunction`, `disassemble`, `clearListing`, `createData`,
  `createByte`/`createWord`/`createDWord`/`createQWord`/`createAsciiString`
  and the like, `removeData`, `setByte`/`setBytes`,
  `createEquate(instruction, opIndex, name)`, `getEquate`, `getEquates`,
  `removeEquate`, `removeEquates`, `createMemoryReference(instruction,
  opIndex, to, type)`, `addInstructionXref`, `removeReference`,
  `setReferencePrimary`, `getScriptName`,
  `getScriptArgs`, `isRunningHeadless`, `println`, `printf` (Java's format
  conversions, `%t` dates included), `printerr`, `popup`, `goTo`.
- **`monitor`** (`isCancelled`, `checkCancelled`, `setMessage`,
  `initialize`, `setMaximum`, `incrementProgress`, ... on the run's
  monitor) and **`state`** (`getCurrentProgram`, `getCurrentAddress`,
  `getCurrentSelection`, environment variables).
- **The decompiler**: `DecompInterface` (`openProgram`, `setOptions`,
  `decompileFunction(f, timeout, monitor)`) gives `DecompileResults` with
  `getDecompiledFunction().getC()` (the daemon's C) and `getHighFunction()`:
  `getLocalSymbolMap()` (the decompilation's parameters and locals as
  `HighSymbol`s, renamed and retyped with
  `HighFunctionDBUtil.updateDBVariable`) and `getPcodeOps()`, the *raw*
  p-code of the function's instructions, each varnode tied to its
  decompiler variable where the decompilation's varnode table maps it.
  Ghidra's high p-code (after the decompiler's simplification) isn't
  exposed, so op counts differ from Ghidra's, and def-use walks
  (`Varnode.getDef`) are `Unsupported`. `FlatDecompilerAPI.decompile(f)`
  works too. The simplification style and toggles are accepted and
  ignored.
- **Helpers**: `ghidra.util.Msg` (to the run's log), `SymbolUtilities`,
  `SystemUtilities.isInHeadlessMode`, `TaskMonitor.DUMMY`, Ghidra's common
  exceptions, `FlatProgramAPI(currentProgram)`.

Anything a shim object lacks raises `Unsupported` naming it
("Function.setNoReturn: give the prototype as C: retype(entry,
'__attribute__((noreturn)) void f(void)')"). `Unsupported` is a
`NotImplementedError` and an `AttributeError`, so `hasattr` probes answer
no.

### How it differs from Ghidra

- **Edits are the run's script edits.** They carry the run's `script:`
  provenance and session like any revkit script's, so a run is reverted as
  a whole and blame names the script and who ran it. Names and comments
  are visible to the script at once; a structural edit (a function made or
  removed, disassembly, data defined or cleared) is committed before the
  script's next read, so the script sees it, as in Ghidra. A run without
  structural edits is one revision; with them, a revision per batch, all
  in the run's session (one undo step in the UI).
- **Precedence.** A script's edits rank with agents' and plugins': below a
  person's and an import's (`user > import > script`). A Ghidra script that
  renames a symbol a person named, or an import named, doesn't change it in
  revkit; in Ghidra it would.
- **One name per address.** `createLabel` on an address with a name
  renames it (revkit has no secondary labels); namespaces are global.
- **Memory writes are patches.** `setByte`, `setBytes`, `Memory.setInt` and
  `MemoryBlock.putBytes` become `PatchService` patches when the run ends
  (or before a structural commit), with the run's provenance, so reverting
  the run takes them back.
- **The program model is revkit's.** References come from revkit's
  analysis (and the user's: `addMemoryReference`): there are none from the ELF headers, `.dynamic`, `.init_array`
  or `.fini_array`, which Ghidra's loader marks up, and none from code
  outside functions. Ghidra's ELF `EXTERNAL` pseudo block and its
  functions don't exist. Locals are the decompiler's, not a stack frame's.
- **Headless.** `popup` goes to the run's log (as Ghidra's headless
  `Msg.info`), `goTo` answers whether the address is in the program, and
  `isRunningHeadless()` is true under `rk-script`.

### Unsupported APIs

Each raises `Unsupported("<API>: <what to use>")`; a missing method of a
shim class names the class and method and uses its family's line.

| Ghidra API | Use instead |
| --- | --- |
| `state.getTool` | revkit scripts run without a Ghidra tool; the UI's cursor and selection are currentAddress and currentSelection |
| `getState().getTool` | revkit scripts run without a Ghidra tool; the UI's cursor and selection are currentAddress and currentSelection |
| `getService` | no tool services in revkit scripts; the daemon's API is current_program and client (revkit.script) |
| `createTableChooserDialog` | no table dialogs yet; print rows, or write JSON/CSV (export_functions starter script) |
| `TableChooserDialog` | no table dialogs yet; print rows, or write JSON/CSV (export_functions starter script) |
| `show` | no result tables yet; print the addresses |
| `createSelection` | no tool selection to set; print or return the addresses |
| `setCurrentSelection` | no tool selection to set; print or return the addresses |
| `createHighlight` | no highlights; print the addresses |
| `setCurrentHighlight` | no highlights; print the addresses |
| `setBackgroundColor` | no listing colors; use note(addr, text, tag) to mark places |
| `clearBackgroundColor` | no listing colors; use note(addr, text, tag) to mark places |
| `openProgram` | the run has one program; revkit.Client(...).program(id) opens others |
| `closeProgram` | the run has one program; revkit.Client(...).program(id) opens others |
| `importFile` | import with rk-script --import FILE, or revkit.Client.import_program |
| `importFileAsBinary` | import with revkit.Client.import_program(..., options=raw) |
| `saveProgram` | revkit saves every edit as it commits; nothing to save |
| `askProgram` | the run has one program; rk-script --program ID picks it |
| `askDomainFile` | no Ghidra project files; rk-script --program ID picks the program |
| `askProjectFolder` | no Ghidra project folders; revkit projects are directories (Client.projects()) |
| `askLanguage` | the language comes with the program (currentProgram.getLanguage()) |
| `askValues` | ask each value: askString/askInt/askChoice, or revkit.script.ask_values({...}) |
| `askPassword` | read secrets from the environment (os.environ) |
| `runScript` | chain scripts with rk-script --pre P.py / --post Q.py, or import a Python module |
| `runCommand` | run the command's revkit equivalent (rename, comment, set_function, define_data, ...) |
| `analyzeAll` | current_program.analyze() (the daemon's analysis jobs), or wait for analysis_status().idle |
| `analyzeChanges` | current_program.analyze() (the daemon's analysis jobs) |
| `setAnalysisOption` | analysis options are rk-daemon flags and AnalysisService requests, not per-program options |
| `getCurrentAnalysisOptionsAndValues` | analysis options are rk-daemon flags and AnalysisService requests |
| `resetAnalysisOptions` | analysis options are rk-daemon flags and AnalysisService requests |
| `openDataTypeArchive` | parse a C header instead: current_program.parse_c / define_type(c_source) |
| `getProgramFile` | the imported file is on the daemon's host; current_program.export() writes it with patches |
| `goToHome` | no tool navigation in revkit scripts |
| `setToolStatusMessage` | print the message |
| `getBookmarkManager` | revkit has notes: note(addr, text, tag) and current_program.assertions() |
| `createBookmark` | revkit has notes: note(addr, text, tag) |
| `getBookmarks` | revkit has notes: current_program.assertions() (note bodies) |
| `removeBookmark` | retract the note's assertion (current_program.retract(seq)) |
| `addExternalReference` | revkit has no external references; imports are thunks named after their targets |
| `addStackReference` | revkit has no stack references; locals come from the decompiler |
| `addRegisterReference` | revkit has no register references |
| `addOffsetMemReference` | revkit has memory references only: addMemoryReference(from, to, type, source, opIndex) |
| `createExternalReference` | revkit has no external references; imports are thunks named after their targets |
| `createStackReference` | revkit has no stack references; locals come from the decompiler |
| `addEntryPoint` | entry points come from the loader; set_function(addr) makes a function there |
| `removeEntryPoint` | entry points come from the loader |
| `createMemoryBlock` | current_program.add_memory_region(name, start, size, ...) |
| `removeMemoryBlock` | current_program.remove_memory_region(region) |
| `Memory.split` | the memory map's regions: current_program.add_memory_region / update_memory_region |
| `Memory.join` | the memory map's regions: current_program.update_memory_region |
| `Memory.createInitializedBlock` | current_program.add_memory_region(name, start, size, initialized=True) |
| `Memory.createUninitializedBlock` | current_program.add_memory_region(name, start, size) |
| `MemoryBlock.setName` | current_program.update_memory_region(start, name=...) |
| `MemoryBlock.setRead` | current_program.update_memory_region(start, perms='r--') |
| `MemoryBlock.setWrite` | current_program.update_memory_region(start, perms='rw-') |
| `MemoryBlock.setExecute` | current_program.update_memory_region(start, perms='r-x') |
| `MemoryBlock.setVolatile` | current_program.update_memory_region(start, volatile=True) |
| `MemoryBlock.getSourceInfos` | the block's source: current_program.memory_map() (MemoryBlock.source) |
| `getNamespace` | revkit names are global: one name per address |
| `createNamespace` | revkit names are global: one name per address |
| `createClass` | revkit names are global; describe classes with C types (define_type) |
| `Symbol.setNamespace` | revkit names are global: one name per address |
| `Symbol.delete` | rename the address instead (rename(addr, name)); a derived name can't be deleted |
| `removeSymbol` | rename the address instead (rename(addr, name)); a derived name can't be deleted |
| `getExternalManager` | revkit has no external locations; imports are thunks named after their targets |
| `Function.setReturnType` | give the prototype as C: retype(entry, 'int f(char *s)') |
| `Function.updateFunction` | give the prototype as C: retype(entry, 'int f(char *s)') |
| `Function.replaceParameters` | give the prototype as C: retype(entry, 'int f(char *s)') |
| `Function.addParameter` | give the prototype as C: retype(entry, 'int f(char *s)') |
| `Function.insertParameter` | give the prototype as C: retype(entry, 'int f(char *s)') |
| `Function.removeParameter` | give the prototype as C: retype(entry, 'int f(char *s)') |
| `Function.setCallingConvention` | give the prototype as C with its convention: retype(entry, 'int __stdcall f(int)') |
| `Function.setNoReturn` | give the prototype as C: retype(entry, '__attribute__((noreturn)) void f(void)') |
| `Function.setCustomVariableStorage` | revkit keeps the decompiler's storage; rename_local/retype_local name and type it |
| `Function.addLocalVariable` | locals come from the decompiler; rename_local/retype_local name and type them |
| `Function.removeVariable` | locals come from the decompiler |
| `Function.getStackFrame` | locals come from the decompiler: DecompInterface ... getHighFunction().getLocalSymbolMap() |
| `Function.setBody` | set_function(entry, body=[(first, last), ...]) |
| `Function.setThunkedFunction` | revkit finds thunks itself |
| `Function.setInline` | no inline flag in revkit |
| `Function.addTag` | use note(entry, text, tag) |
| `Function.getTags` | notes: current_program.assertions() (note bodies) |
| `Data.getComponent` | data components: current_program.listing() rows (data_field, data_parent) |
| `Data.getComponentAt` | data components: current_program.listing() rows (data_field, data_parent) |
| `Instruction.getPrototype` | the decoded instruction: current_program.instruction(addr) (tokens, operands, p-code) |
| `Instruction.getInstructionContext` | processor context is not exposed to scripts |
| `Instruction.setFallThrough` | flow_override(addr, kind) |
| `Instruction.setFlowOverride` | flow_override(addr, kind) |
| `Program.getProgramContext` | processor context is not exposed to scripts |
| `Program.getDomainFile` | no Ghidra project files; current_program.summary().info names the program |
| `Program.getChanges` | current_program.assertions() lists what changed |
| `Program.getSourceFileManager` | no source-file mapping in revkit |
| `Program.getUsrPropertyManager` | use notes: note(addr, text, tag) |
| `Program.getTreeManager` | no program trees (fragments) in revkit |
| `Program.getRegister` | register names: Varnode.register_name in instruction and decompiler results |
| `Program.endTransaction(rollback)` | edits are buffered until the run ends; raise an exception to discard them |
| `Language.getRegisters` | register names: Varnode.register_name in instruction and decompiler results |
| `Language.getProgramCounter` | register names: Varnode.register_name in instruction and decompiler results |
| `DataTypeManager.addDataType` | define_type(c_source) (or CParser(dtm).parse(c) then addDataType) |
| `DataTypeManager.resolve` | define_type(c_source) |
| `DataTypeManager.remove` | retract the type's assertion |
| `DataTypeManager.createCategory` | revkit types have no categories |
| `DataTypeManager.getCategory` | revkit types have no categories |
| `DataTypeManager.getRootCategory` | revkit types have no categories |
| `DataTypeManager.getAllStructures` | current_program.find_types() (kind STRUCT) |
| `BasicBlockModel` | the function's blocks: current_program GetFunctionGraph (QueryService) |
| `SimpleBlockModel` | the function's blocks: current_program GetFunctionGraph (QueryService) |
| `PartitionCodeSubModel` | the function's blocks: current_program GetFunctionGraph (QueryService) |
| `IsolatedEntrySubModel` | the function's blocks: current_program GetFunctionGraph (QueryService) |
| `CodeBlockModel` | the function's blocks: current_program GetFunctionGraph (QueryService) |
| `CyclomaticComplexity` | edges - blocks + 2 from GetFunctionGraph (QueryService) |
| `SearchBaseExtended` | operand masks need the instruction's encoding: search_memory(bits, format='binary') with x for masked bits |
| `InstructionSearchApi` | operand masks need the instruction's encoding: search_memory(bits, format='binary') with x for masked bits |
| `AutoAnalysisManager` | current_program.analyze() (the daemon's analysis jobs) |
| `ParallelDecompiler` | decompile_many(funcs) decompiles on the daemon's workers (revkit.script) |
| `DecompilerCallback` | decompile_many(funcs) decompiles on the daemon's workers (revkit.script) |
| `DecompilerUtils` | DecompInterface().decompileFunction(f, timeout, monitor), with the daemon's options |
| `DecompileResults.getCCodeMarkup` | the decompiler's tokens: decompile(f).lines (CodeLine/CodeToken, with addresses and variables) |
| `HighFunction.getBasicBlocks` | the function's blocks: GetFunctionGraph (QueryService) |
| `HighFunction.getGlobalSymbolMap` | globals: decompile(f).variables (kind GLOBAL) |
| `HighFunction.getVarnodes` | decompile(f).varnodes (each varnode and its variable) |
| `HighFunctionDBUtil.commitParamsToDatabase` | give the prototype as C: retype(entry, 'int f(char *s)') |
| `HighFunctionDBUtil.commitLocalNamesToDatabase` | rename_local(f, storage_key, name) per variable |
| `Varnode.getDef` | def-use chains are not exposed; decompile(f).varnodes maps varnodes to variables |
| `Varnode.getDescendants` | def-use chains are not exposed; decompile(f).varnodes maps varnodes to variables |
| `PcodeBlockBasic` | the function's blocks: GetFunctionGraph (QueryService) |
| `DataGatheringParams` | read the bytes and instructions around entries yourself: getBytes, getInstructionAt |
| `FunctionBitPatternInfo` | read the bytes and instructions around entries yourself: getBytes, getInstructionAt |
| `CompoundCmd` | call the edits directly (Symbol.setName, createLabel, setEOLComment, ...): a run is already one undo step |
| `RenameLabelCmd` | Symbol.setName(name, source) or createLabel(addr, name, True) |
| `AddLabelCmd` | createLabel(addr, name, True) |
| `SetCommentCmd` | setEOLComment / setPlateComment / setPreComment / setPostComment |
| `CreateFunctionCmd` | createFunction(addr, name) |
| `DisassembleCommand` | disassemble(addr) |
| `ClearCmd` | clearListing(start, end) |
| `AlignmentDataType` | revkit has no alignment data type; createData(addr, ArrayDataType(ByteDataType(), n, 1)) |
| `PseudoDisassembler` | decode with current_program.instruction(addr) (any address, without disassembling it) |
| `EmulatorHelper` | revkit's emulator: current_program.emulate(...) (EmulatorService) |
| `PcodeEmulator` | revkit's emulator: current_program.emulate(...) (EmulatorService) |
| `DebuggerTraceManagerService` | revkit's debugger: current_program.debug(...) (DebuggerService) |
| `VTSession` | program diffing: client.diff(project, program_a, program_b) (DiffService) |
| `BSim` | program diffing: client.diff(project, program_a, program_b) (DiffService) |
| `FidService` | revkit has Function ID (Ghidra's hashes and `.fidbf` databases), with its own API: `revkit.script.fid_matches()`, `run_fid()`, `apply_fid()`, `reject_fid()`, `Program.fid_matches()` ([fid.md](fid.md)) |
| `java` | Java classes aren't available: revkit runs scripts in CPython; use Python's standard library |
| `javax` | no Swing: print, or use askString/askChoice for input |
| `docking` | no Ghidra GUI: print, or use askString/askChoice for input |
| `jpype` | no JVM: revkit runs scripts in CPython |

### The corpus: 30 of Ghidra's scripts

`sdk/python/tests/ghidra_corpus` keeps 30 of the scripts Ghidra 12.1.4
ships (`scripts/`): 24 that use the flat API and 6 that use what revkit
doesn't have, from `Features/Base`, `Decompiler`, `BytePatterns` and
`PyGhidra`, the bundled Jython scripts and Ghidra's class labs. The Java
ones are ported to Python 3 line by line with their Ghidra API calls as
they were (Java library calls become Python's: `Gson` the `json` module,
`Thread.sleep` `time.sleep`, a `Calendar` the epoch milliseconds Java's
formatter takes as well); the Jython ones only got their `print`
statements made calls. Each file keeps Ghidra's Apache-2.0 licence header
with a note of the change.

`run.py` runs each scenario (`corpus.json`: the script, its arguments, the
cursor and selection, a setup, what is compared) under the shim, and the
*same file* in Ghidra through PyGhidra (`ghidra_reference.py`: the program
imported and analyzed once, each scenario in a transaction rolled back
afterwards), on two programs: the SDK fixture (`tests/fixtures/
script_target.c`, `cc -O1`) and the corpus program
`elf-x86_64/gcc-O0/debug/features` (pinned by `corpus/manifest.json`). It
compares the output, the log messages, and the comments, names, functions,
bytes and files the script changed. Only the memory both programs have is
compared: Ghidra's ELF loader adds an `EXTERNAL` pseudo block (a function
per import) and non-loaded `.symtab`-like spaces that revkit doesn't have.
Ghidra's results are kept in `expected/<sha256 of the binary>.json`.

```sh
sdk/python/tests/ghidra_corpus/run.py --programs fixture,features --ghidra live     # needs scripts/setup-pyghidra.sh
sdk/python/tests/ghidra_corpus/run.py --record      # a live run, kept as the expected results
```

**Gate: met.** On each program at least 20 of the 30 run and agree with
Ghidra, and the rest fail with `Unsupported` naming the API, or differ
for a reason in revkit's program model (not the shim) that `corpus.json`
states:

- **Fixture: 21 agree, 6 Unsupported, 3 differ by the program model.**
- **features: 20 agree, 6 Unsupported, 4 differ by the program model.**

| Script | From | Compared | Fixture | features |
| --- | --- | --- | --- | --- |
| HelloWorldScript | Features/Base | output | agrees | agrees |
| HelloWorldPopupScript | Features/Base | output, messages | agrees | agrees |
| Lab4Script | docs/GhidraClass | output | agrees | agrees |
| Lab5Script | docs/GhidraClass | output, comments | agrees | agrees |
| AddCommentToProgramScript | Features/Base | output, comments | agrees | agrees |
| ConvertDotToDashInAutoAnalysisLabels | Features/Base | output, names | agrees | agrees |
| FormatExampleScript | Features/Base | output | agrees | agrees |
| IterateInstructionsScript | Features/Base | output | differs* | differs* |
| IterateFunctionsScript | Features/Base | output | agrees | agrees |
| IterateFunctionsByAddressScript | Features/Base | output | agrees | agrees |
| FindTextScript | Features/Base | output | agrees | agrees |
| ExportFunctionInfoScript | Features/Base | output, file | agrees | agrees |
| PrintFunctionCallTreesScript | Features/Base | output | agrees | agrees |
| ReportPercentDisassembled | Features/Base | output, messages | differs* | differs* |
| FindAndReplaceCommentScript | Features/Base | output, comments | agrees | agrees |
| RemoveSymbolQuotesScript | Features/Base | output, names | agrees | agrees |
| DeleteFunctionDefaultPlatesScript | Features/Base | output, comments | agrees | agrees |
| AutoRenameSimpleLabels | Features/Base | output (sorted), names, comments | agrees | agrees |
| ClearOrphanFunctions | Features/Base | output, functions, comments | differs* | differs* |
| CreateFunctionsFromSelection | Features/Base | output, functions | agrees | agrees |
| MakeFunctionsScript | Features/Base | output, functions | agrees | agrees |
| XorMemoryScript | Features/Base | output, bytes | agrees | agrees |
| RecursiveStringFinder | Features/Base (Jython) | output | agrees | differs* |
| LocateMemoryAddressesForFileOffset | Features/Base (Jython) | output, comments | agrees | agrees |
| CallAnotherScript | Features/Base | `runScript` | Unsupported | Unsupported |
| SelectFunctionsScript | Features/Base | `createSelection` | Unsupported | Unsupported |
| ComputeCyclomaticComplexity | Features/Base | `ghidra.program.util.CyclomaticComplexity` | Unsupported | Unsupported |
| PyGhidraBasics | Features/PyGhidra | `java.util.LinkedList` | Unsupported | Unsupported |
| GraphASTScript | Features/Decompiler | `state.getTool` | Unsupported | Unsupported |
| DumpFunctionBitPatternInfoForCurrentFunctionScript | Features/BytePatterns | `ghidra.bitpatterns.info.DataGatheringParams` | Unsupported | Unsupported |

\* differs because of revkit's program model, not the shim:
`IterateInstructionsScript` and `ReportPercentDisassembled`: revkit's
analysis doesn't disassemble the `.plt`'s lazy-binding code that only the
GOT reaches (the `PUSH n; JMP .plt` stubs; every other instruction's text
agrees, and 84.1% against 90.3% of the fixture's executable bytes are
instructions, 98.4% against 99.7% of features'). `ClearOrphanFunctions`:
revkit has no references from the ELF headers, `.dynamic`, `.init_array`
and `.fini_array` (Ghidra's loader marks them up), and its references come
from code inside functions, so removing `_start` also removes its
reference to `main`; revkit removes 7 functions, Ghidra none.
`RecursiveStringFinder` on features: Ghidra's analysis also references a
string from the `MOV RDI,RAX` that passes `LEA`'s pointer on (constant
propagation), so its tree lists those strings twice.

Choices the comparison records (in `corpus.json`): the two
`IterateFunctions` scripts' final counts aren't compared (Ghidra's include
the 8 functions of its `EXTERNAL` block; every function listed is);
`AutoRenameSimpleLabels`'s lines are compared sorted (`getAllSymbols` walks
Ghidra's database order and revkit's address order); `FormatExampleScript`
compares its dates' shape, not their digits; `RecursiveStringFinder`'s
`print(type(...))` lines (a Java class name in Ghidra) are left out. The
setups run as an agent (`agent:corpus`), which a script's edits outrank as
a later equal, as a Ghidra script may change anything; `MakeFunctionsScript`
runs without removing a function first, because revkit makes a function at
a function symbol once its code is disassembled (Ghidra doesn't), so the
script's own `createFunction` found it made. On features,
`RemoveSymbolQuotesScript` renames symbols from the ELF symbol table,
because names from the DWARF import outrank a script's edits.

Two more scripts run as extras, outside the 30: `CountSymbolsScript` and
`IterateDataScript` list every symbol and every defined data item, which
compares the ELF loaders more than the shim: Ghidra marks up the ELF
headers, `.dynamic` and `.eh_frame` with labels and data (`__DT_*`,
`fde_*`, `Elf64_Ehdr`) revkit's loader doesn't make. Both differ on both
programs.

The corpus found and fixed, in the shim: Ghidra's operand text (addresses
as `0x00101016`, not symbol names) and operand objects (a scalar that
names an address is a `Scalar` of its decoded width, which needed
`ListingToken.scalar_bits` and `value`, `api_minor` 34, feature
`token-scalars`); `getDefaultOperandRepresentation` of a missing operand
(`<UNSUPPORTED>`); headless `popup`; thunks (a dynamic name; a
call-terminator jump); comments on bytes inside a folded listing row of
undefined bytes (the listing doesn't show them; the shim reads them from
the fact store); memory patches among the run's commits; and
`ghidra.app.util.cparser.C` (a package with a capitalized name).

## Performance

The design's gate: a decompile loop over cmake's 19,409 functions
(`corpus/large/manifest.json`) under 4 minutes at `-j 8` through
`DecompileMany`.

**Met: 82.7 s.** Measured 2026-10-07 on the 32-core, 31 GiB machine while
another agent's sanitizer CI ran beside it (load average 12.0 at the start,
12.4 at the end; available memory 15-18 GiB throughout, the run itself
using about 2-3 GiB):

```sh
rk-script run batch_decompile --throwaway --import /usr/bin/cmake -j 8 --arg out=report.json --json
```

| | |
| --- | --- |
| functions | 19,409, every one decompiled; 1 `TIMEOUT` failure (`FUN_003a7c80`, 30.6 s, the server's 30 s deadline), no errors |
| `DecompileMany` wall time | 82.7 s (234.6 functions/s), first result after 57 ms |
| per function | p50 3.0 ms, p90 32.3 ms, p99 496 ms, max 30.6 s; 727 s of decompiler time in all, so the 8 workers (9 in flight) were busy throughout |
| whole `rk-script` run | 88.9 s, with the throwaway daemon's start and the import (about 6 s) |

Again after merging background prototype inference (master `f5a41cc`,
`rk-daemon --infer-prototypes auto` by default), load 14-15: `DecompileMany`
86.6 s (224 functions/s, p50 3.7 ms, p99 511 ms, no failures), minimum
available memory 10 GiB. The whole `rk-script` run took 552 s, because it
waits for analysis to be idle before the script, and the inference job on
cmake took about 7.5 minutes of that; `--analysis-timeout 0` runs the script
at once (decompilations then don't yet see the inferred prototypes). On
the branch as landed (master `ed4d6f7` merged), load 9.5-18.6:
`DecompileMany` 88.5 s (219 functions/s, p50 3.6 ms, p99 499 ms, one
timeout), minimum available memory 14 GiB; earlier runs under load 16-24
took up to 99.5 s.

The loop is bound by the decompiler: the five slowest functions take 15-31 s
each. Decompilations are memoized: in the same daemon, functions already
decompiled come first and cost no decompiler time (200 of bash's functions
again: 10 ms, against 170 ms the first time).

## Tests

- `sdk/python/tests/test_scripting.py`: one revision per run with the
  provenance above, `revert(session)` restoring the head, a person's later
  edit surviving a re-run, refused edits naming the script line with
  nothing landing, exceptions, `sys.exit` and cancellation committing
  nothing, tracebacks trimmed to the script, staged commits, context,
  prompts (`--arg`, stdin, defaults, failing fast, bad choices), the
  JSON-lines stream host, metadata, `rk-script` over two programs with
  `-j 2`, `--pre`, `--json` and exit statuses, a throwaway daemon with a
  persistent project, and, with authentication, `on_behalf_of` stamped as
  `user:alice` and a forged one refused.
- `sdk/python/tests/test_starter_scripts.py`: each starter on the
  compiled fixture `tests/fixtures/script_target.c` (the signatures
  exported from the plain build name the stripped build's functions).
- `sdk/python/tests/test_console.py` (`python_sdk`): the console's host
  in process and as a process over its protocol: statements, blocks
  needing their empty line, a paste, expression echo, tracebacks from the
  console's own lines, `KeyboardInterrupt` by SIGINT with the namespace
  kept, `input()` as a prompt, `exit()`, a refused commit, a read-only
  console, rlcompleter's (and, when installed, jedi's) completions and
  signatures without calling properties, Ghidra's names on and off, a
  statement's edits as one revision with provenance `console`; and the
  libraries' order and place on `sys.path`, with `rk-script` importing
  from the per-user library, then the project's, then the script's
  directory.
- `sdk/python/tests/test_script_console.py` (`python_sdk`): the daemon's
  interactive `RunScript` on an authenticated daemon with
  `--scripts-host-role viewer`: one host per caller and program keeping
  its namespace, another user's apart, the history per caller (mode
  0600), a statement as one revision with script provenance `console` on
  behalf of the caller and its undo, `CompleteConsole`, interrupt and a
  busy console, prompts and `input()`, `UpdateContext`, a host that dies
  started again, `exit()` and Close, the idle timeout, Ghidra's names, a
  viewer's console reading and refused an edit (also around the buffer),
  and a default daemon refusing a viewer a console.
- `sdk/python/tests/test_completion_index.py`: the editor's index is
  current and covers the API and Ghidra's names.
- `sdk/python/tests/test_ghidra_compat.py` (`python_sdk`): the Ghidra
  shim on the fixture: detection, Ghidra's metadata conventions, Python 2
  errors, reads (functions, addresses and sets, instructions and their
  operand text, data, memory, `findBytes`, references, symbols), edits as
  one revision with script provenance, structural edits the script sees,
  memory writes as the run's patches, the decompiler (`getC`, the local
  symbol map, p-code, `updateDBVariable`), `CParser` and `createData`,
  prompts from script arguments and `--arg`, `Unsupported` naming the API
  and its replacement (and every table entry documented here), and
  `rk-script` with `--script-arg` and `--compat`; then the 30 corpus
  scripts, compared with Ghidra's recorded results when the fixture built
  here is the one recorded (the gate), else checked to run or fail with
  the named API.
- `ghidra_compat_corpus` (ctest, `LABELS ghidra`): the corpus live
  against Ghidra through PyGhidra on the fixture and, when
  `scripts/build-corpus.sh` built it, features; skipped without the
  PyGhidra venv.
- `src/api/tests/script_service_test.cc`: the daemon's metadata parser
  reads Ghidra's conventions too.
- `src/backend/tests/image_backend_test.cc`
  `ImageBackendTest.ScriptBatchReads`: `DecompileMany` (every function
  once at one revision, a pinned earlier revision, a missing entry, refused
  options, a client going away), `FindBytes` (exact, masked, truncated,
  ranges) and `ListInstructions` (a body with p-code, `omit_pcode`,
  `limit`, a range).
- `src/api/tests/auth_test.cc` `AuthPolicyUnit.StampingRules` (script
  provenance stamping) and `EveryMethodHasAPolicy`;
  `src/facts/tests/address_test.cc` (the kind's rank and encoding).
- `sdk/ts/test/scripting.ts` (`ts_sdk_scripting`): the TypeScript helpers
  over Connect.
- `sdk/python/tests/test_script_service.py` (`python_sdk`): the daemon's
  service on an authenticated TLS daemon: the libraries and metadata, a run
  streaming output and progress, prompts round-tripping (choice, int,
  choices; `--arg`; a dismissed prompt cancelling), cancel ending a run in
  under 1 s and one that ignores SIGTERM in under 2.6 s, the context
  following `UpdateContext`, one revision with script provenance and
  `on_behalf_of` `user:alice` and the run token dead afterwards, tracebacks
  naming `user/broken.py` line 3, a viewer refused, trust (unseen, changed,
  a stale confirmation refused, saving pinning it for the saver only),
  `SaveScript`, a daemon with scripts off, one with no Python, the MCP
  tools, `rk-script setup --dry-run`, and `SetupScriptPython` with stand-in
  Pythons (the steps streamed, the environment found at once, a missing
  venv module's error, refused under `--script-python`).
- `src/api/tests/script_service_test.cc` (`revkit_api_tests`): the C++
  metadata parser, scripts off beyond loopback by default, the Python
  search's hint, what Set up Python installs (`FindScriptSdk`), trust pins
  and run tokens.
- `sdk/ts/test/scripts.ts` (`ts_sdk_scripts`) and `ui/e2e/scripts.ts`
  (`ui_e2e`): see [ui.md](ui.md#scripts).

## Next phases and known gaps

1. **Core: done.**
2. **Daemon and UI: done** (this page and [ui.md](ui.md#scripts)):
   `ScriptService` with host processes, run tokens, streams, prompts,
   cancel and context; per-project libraries, trust confirmation and
   Python discovery with `rk-script setup` (from phase 4); the Script
   Manager, output panel, palette, key and context-menu entries, the
   editor and one undo step per run.
3. **Ghidra compatibility: done** ([above](#running-ghidra-scripts)):
   `revkit.ghidra.compat`, the `GhidraScript`/`FlatProgramAPI` subset
   Ghidra's bundled scripts use, failing with `Unsupported` naming the API
   and its revkit replacement for the rest; 30 of Ghidra's scripts as a
   corpus compared with Ghidra itself.
4. **Polish: mostly done.** The console ([above](#the-console):
   `RunScript{interactive}`, `CompleteConsole`, Ctrl+C, history, Ghidra's
   names, read-only for viewers), completion and signature help in the
   editor from an index generated from the SDK, per-user and per-project
   libraries for `import`, and ten more starter scripts (22 in all). Left:
   python-build-standalone in the desktop bundle.

Known gaps: the daemon's script hosts start a process per run (about
0.1-0.2 s; no warm pool); a running script reads no console input (its
`input()` is a prompt); a console's namespace is lost when its host
restarts or idles out; completion in the editor knows only the names the
index has, not the script's own variables; a run outlives the logout of the session
that started it (its token is tied to the account) until it ends; `define_type` types can be used by a
retype only after `commit()`; `decrypt_strings` handles register calling
conventions only; `DecompileMany` keeps the snapshot it started at for the
whole call, which keeps that revision's memos alive while it runs.
