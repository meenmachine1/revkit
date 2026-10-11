# Plugins

First-party loaders and analyzers are C++ (`src/loader`, `src/analysis`).
Third-party **loaders**, **analyzers**, **commands** and **peripherals**
are WebAssembly modules that `rk-daemon` runs in a sandbox (`src/plugins`,
`revkit::plugins`, on [wasmtime](https://wasmtime.dev)), or separate
programs over the public API ([api.md](api.md)). A plugin can't crash or
corrupt the daemon, read files, or use the network; analyzer plugins are
fact-engine queries, memoized and invalidated like built-in rules;
peripheral plugins are devices of an emulated machine
([firmware-emulation.md](firmware-emulation.md#peripheral-plugins)).

```sh
cmake --preset default && cmake --build --preset default        # builds build/plugins/*.wasm too
build/tools/rk-daemon/rk-daemon --plugin-dir build/plugins --open prog
```

```python
from revkit import Client
with Client("127.0.0.1:50051", actor="user:alice") as rk:
    prog = rk.program("default/prog")
    print([p.name for p in rk.plugins()])
    for f in prog.plugin_facts("string-refs").facts:
        print(hex(f.address.offset), f.text, f.origin.derived.rule)       # plugin:string-refs@1.0.0
    prog.run_command("rename-regex", {"pattern": "^FUN_0*", "replace": "sub_"})
    prog.revert(kind="plugin", id="rename-regex")
```

- [Plugin kinds](#plugin-kinds)
- [The interface decision: core WebAssembly, not WIT](#the-interface-decision)
- [Sandbox and capabilities](#sandbox-and-capabilities)
- [Interface version 1](#interface-version-1)
- [Analyzers as queries](#analyzers-as-queries)
- [Loaders](#loaders) and [commands](#commands)
- [Writing a plugin](#writing-a-plugin)
- [Versioning rules](#versioning-rules)
- [Daemon, API and SDKs](#daemon-api-and-sdks)
- [Build impact](#build-impact)
- [Known gaps](#known-gaps)

## Plugin kinds

| Kind | Input | Output | Runs | Example |
| --- | --- | --- | --- | --- |
| analyzer | a scope: the program, or one function | facts at addresses: labels, comments, data types, notes | as the query `plugins.analyze`, on demand (`GetPluginFacts`), memoized | `crc32-tables` (program), `string-refs` (per function) |
| loader | the file's bytes | language, blocks, entry point, symbols | at import, for files the built-in loaders reject (by magic), or when `ImportOptions.format` names it; again when a persisted project reopens | `rkraw-loader` |
| command | arguments (strings) | edits: renames, comments, function entries, notes | on `RunCommand`; its edits go through `AppendAssertions` | `rename-regex` |
| peripheral | register reads and writes, ticks, input, interrupt inputs | register values, interrupt lines, output bytes | as a device of a machine (`"kind": "plugin:NAME"` in its description), one live instance per emulation session | `tick-timer` |

Analyzers and commands pull the facts they need through host imports
(program info, memory, functions, instructions with p-code, names); a
loader only gets its file. A peripheral sees the emulated machine (its
clock, its interrupt lines, the session's output, and its memory with a
grant) and no program facts.

## The interface decision

**Version 1 is a documented core-WebAssembly ABI with explicit versioning,
not a WIT world.** wasmtime 49's C API does have the component model
(`wasmtime/component/*.h`), and I read it with this in mind. It falls short
in three ways that matter here:

- **Values are dynamically typed trees.** A call takes and returns
  `wasmtime_component_val_t`, and a `list<u8>` is a vector of those values,
  one 40-byte tagged union per byte. Analyzers move memory and code around
  by the megabyte, so a 1 MiB read would cost a 40 MiB value tree on each
  side. There is no generator for typed host bindings in C or C++, which is
  what the Rust embedding has (`bindgen!`).
- **Guests need more tools than clang.** A component comes from
  `wit-bindgen` plus `wasm-tools component new`, or from Rust's
  `wasm32-wasip2`, whose standard library imports WASI interfaces this host
  refuses to provide. Under the core ABI, clang 18 and wasm-ld (both
  installed here) build a plugin with one command, and so does any language
  that targets `wasm32-unknown-unknown`.
- **Interface checking is no stronger in practice.** The component model
  checks types structurally at instantiation. The core ABI checks the
  manifest's interface version, the module's `rk_abi_version()`, every
  import's module, name and signature, and the required exports, all at
  load. Within a major version, size-prefixed records give
  forward-compatible extension.

So the cost of WIT today is a 40x copy on the hot path and a Rust toolchain
for plugin authors, with no gain in safety. The ABI is shaped so it can
move later (records, lists, strings, one function per fact): a
`revkit:plugin@2` WIT world can mirror it once the C API grows typed
lifting, or a thin adapter component can wrap v1 modules.

## Sandbox and capabilities

Each guarantee comes with a test, in `src/plugins/tests/sandbox_test.cc`
unless noted.

| Guarantee | How | Test |
| --- | --- | --- |
| A plugin can't hang the daemon | **Fuel**: each call starts with a budget (default 2·10⁹, about one per wasm instruction; the manifest may ask for up to 2·10¹⁰). Host imports charge fuel too (1000 per call plus 1 per 8 bytes), so looping on imports runs out as well. Running out traps deterministically, at the same point every time. A **wall-clock backstop** (epoch interruption: a host thread advances the epoch every 10 ms; default 30 s) catches anything fuel misses | `AnInfiniteLoopRunsOutOfFuel`, `HostCallsCostFuelToo`, `WallClockBackstopStopsWhatFuelAllows` |
| A plugin can't exhaust memory | A per-store limiter caps linear memory (default 64 MiB, at most 1 GiB): `memory.grow` past it returns -1. Initial memory over the cap is rejected at load. One memory, a few tables | `MemoryIsCappedAndGrowthPastItFails`, `InitialMemoryOverTheCapIsRejectedAtLoad` |
| A plugin can't crash or corrupt the daemon | It runs in wasmtime's sandbox. Every guest pointer and length a host import receives is bounds-checked against the guest's memory. Results are decoded with checked readers: lists can't claim more items than bytes, text is bounded UTF-8, kinds are known. Traps (unreachable, out-of-bounds access, division by zero, stack overflow) are failed calls. Signals-based traps are off, so wasmtime installs no process-wide signal handler: every trap is an explicit check. Exceptions from fact reads (a query cycle, say) are carried across the wasm frames and rethrown after the instance is gone | `TrapsAreFailedCalls`, `MalformedOutputIsRejected`, `ExceptionsFromFactsReachTheCaller`, `ConcurrentCalls` |
| No ambient authority | The only imports are `revkit:plugin/v1` functions, and the linker defines only those the plugin's granted capabilities cover. No WASI: no files, sockets, clocks, random numbers, environment or arguments. A module importing anything else is rejected at load, with a message saying why | `NoAmbientAuthority` |
| Reading the binary needs a grant | Capability `file` (raw bytes of the binary under analysis) is never granted by default: `rk-daemon --plugin-grant NAME=file` | `NoAmbientAuthority` |
| Determinism (analyzers) | A fresh store and instance per call, so no state survives between calls; no clock or randomness imports; fuel instead of time; NaN canonicalization; no threads, shared memory or relaxed SIMD. Same inputs, same facts, same fuel | `EveryCallStartsFresh`, `AnInfiniteLoopRunsOutOfFuel` (same fuel twice), `Analyzers.AreDeterministic` (two hosts, two stores) |
| Interface version mismatch | Manifest `interface` and `rk_abi_version()` must both be 1, and the kind's entry point must be exported | `InterfaceVersionMismatchIsRejected` |
| A bad plugin doesn't stop the others | `--plugin-dir` loads each module on its own; rejected ones are listed with their error | `RejectedPluginsInADirectoryDontStopTheOthers`, `ListPlugins` |

**Capabilities** (manifest `capabilities`):

| Capability | Imports | Granted |
| --- | --- | --- |
| (none) | `log`, `fail`, `set_output`, `take`, `program_info` | always |
| `memory` | `memory_read`: the program's mapped, initialized bytes | by default |
| `code` | `functions`, `function_code`, `symbol_name` | by default |
| `file` | `file_size`, `file_read`: the raw file under analysis | only with `--plugin-grant NAME=file` |
| `irq` (peripherals) | `irq_set`: the plugin's interrupt outputs | by default |
| `output` (peripherals) | `output`: bytes for the session's output | by default |
| `bus` (peripherals) | `bus_read`, `bus_write`: the emulated machine's memory (DMA) | only with `--plugin-grant NAME=bus` |

A plugin must request what it imports, and must be granted what it
requests. Otherwise it is rejected at load. Loaders take no capabilities:
their input is the file. Peripherals can't import the fact imports
(`program_info`, `memory_read`, `functions`, …) and the other kinds can't
import the peripheral ones; either is rejected at load
(`PeripheralPlugins.ImportsFollowTheGrants`).

**Peripherals keep their instance.** The other kinds get a fresh store and
instance per call. A peripheral is instantiated once per emulation
session and lives until it ends: its globals are the device's state
(`PeripheralPlugins.StateCarriesFromCallToCall`). Each call into it
(a register access, a tick, input) still has its own fuel (50,000,000
unless the manifest asks for another amount) and the wall-clock backstop.
A call that fails stops the emulation run with the reason (stop kind
`hook`) and leaves the instance dead for the rest of the session; the
daemon and other sessions go on
(`PeripheralPlugins.AFailingPluginStopsTheRunNotTheHost`). With the
machine's clock in instructions, a peripheral plugin is as deterministic
as a built-in peripheral.

**Failures.** A call that fails reports one of `plugin error` (non-zero
return or `fail()`), `trap`, `out of fuel`, `out of memory` (`fail("out
of memory")`, which the SDK's allocator uses, or a trap with memory within
1 MiB of the cap), `timeout` and `bad output`. Through the API,
`RunCommand` maps exhausted budgets to `RESOURCE_EXHAUSTED` and everything
else to `FAILED_PRECONDITION`. `GetPluginFacts` lists failed runs in
`errors` and still returns the other plugins' facts.

## Interface version 1

### Exports

| Export | Signature | |
| --- | --- | --- |
| `memory` | memory | linear memory, at most the cap |
| `rk_abi_version` | `() -> i32` | must return 1 |
| `rk_alloc` | `(size: i32) -> i32` | a buffer for the host to write the input into |
| `rk_analyze` / `rk_load` / `rk_command` | `(ptr: i32, len: i32) -> i32` | the kind's entry point: 0 on success |

The host calls `rk_alloc(len)`, copies the input there and calls the entry
point. A plugin hands back its result with `set_output`. Every call runs in
a fresh instance, so a bump allocator that never frees is fine.

A peripheral (interface minor 1) has no single entry point. It exports
`rk_peripheral_buffer` (a static buffer of at least 4,096 bytes for the
host's input), `rk_peripheral_init`, `rk_peripheral_read` and
`rk_peripheral_write`, and optionally `rk_peripheral_tick`,
`rk_peripheral_input`, `rk_peripheral_irq_in` and `rk_peripheral_reset`
([signatures](firmware-emulation.md#peripheral-plugins)). Its instance
lives for the session, so it must not allocate per call.

### Imports (module `revkit:plugin/v1`)

| Import | Signature | Capability | |
| --- | --- | --- | --- |
| `log` | `(ptr, len)` | | a line for the daemon's log and the result (at most 200 lines of 1 KiB) |
| `fail` | `(ptr, len)` | | ends the call now with this message (a plugin error) |
| `set_output` | `(ptr, len)` | | the result blob (at most 64 MiB); a later call replaces it |
| `take` | `(dst) -> i32` | | copies the blob the last fact import staged to `dst`; returns its length |
| `program_info` | `() -> i32` | | stages a ProgramInfo; returns its length |
| `memory_read` | `(addr: i64, dst, len) -> i32` | memory | copies mapped, initialized bytes at addr until a gap (at most 16 MiB); returns the count |
| `functions` | `() -> i32` | code | stages `list<Function>` |
| `function_code` | `(entry: i64) -> i32` | code | stages a FunctionCode, or returns -1 when no function starts there |
| `symbol_name` | `(addr: i64) -> i32` | code | stages the effective name (UTF-8, not a record); 0 when there is none |
| `file_size` | `() -> i64` | file | |
| `file_read` | `(offset: i64, dst, len) -> i32` | file | |
| `now` | `() -> i64` | (peripherals) | the machine's clock, in ticks |
| `schedule` | `(at: i64)` | (peripherals) | calls `rk_peripheral_tick` when the clock reaches `at` (replacing an earlier request); negative cancels |
| `irq_set` | `(line: i32, level: i32)` | irq | drives interrupt output `line` (an index into the manifest's `peripheral.outputs`) |
| `output` | `(ptr, len)` | output | bytes for the session's output, as a UART transmits |
| `bus_read`, `bus_write` | `(addr: i64, ptr, len) -> i32` | bus | the emulated machine's memory, at most 1 MiB a call |

`ptr`, `len` and `dst` are `i32`s. A fact import stages its blob in the host;
the plugin allocates that many bytes and calls `take`.

### Blobs

Little-endian. `u8`/`u32`/`u64` are fixed width; `str` is a `u32` length
then bytes; `list<T>` is a `u32` count then items; a **record** is a `u32`
size then its fields. A reader reads the fields it knows and skips to the
record's end, so a newer host or plugin can append fields.

```
ProgramInfo   = record { str language; str compiler; u8 pointer_size; u8 big_endian;
                         u8 has_entry; u64 entry; u64 file_size;
                         list<record { str name; u64 start; u64 size; u8 perms; u8 initialized }> blocks }
                perms: 1 read, 2 write, 4 execute
Function      = record { u64 entry; str name; u32 flags; list<{ u64 first; u64 last }> body }
                flags: 1 no-return, 2 thunk, 4 discovered (not a seed), 8 asserted entry
FunctionCode  = record { u64 entry; list<Insn> insns }
Insn          = record { u64 address; u32 length; str mnemonic; str text; list<PcodeOp> pcode }
PcodeOp       = record { str opcode; u8 has_output; [Varnode output]; list<Varnode> inputs }
Varnode       = record { str space; u64 offset; u32 size }
                opcode: Ghidra's names (COPY, INT_ADD, CALL, ...); space: ram, register, const, unique, ...

AnalyzeRequest = record { u8 scope; u64 address }          scope: 0 program, 1 function (address = entry)
AnalyzeResult  = list<record { u8 kind; u64 address; str text; str sub }>
                 kind: 1 label, 2 comment (sub: eol | pre | post | plate), 3 data type (a C type), 4 note (sub: tag)
LoadResult     = record { str language; str compiler; u8 has_entry; u64 entry;
                          list<record { str name; u64 start; u64 size; u64 file_offset; u64 file_size; u8 perms }> blocks;
                          list<record { str name; u64 address; u64 size; u8 is_function }> symbols }
CommandRequest = record { str program_id; list<record { str key; str value }> args }
CommandResult  = list<record { u8 op; u64 address; str text; str sub }>
                 op: 1 rename (text), 2 comment (text, sub = kind), 3 function entry, 4 note (text, sub = tag)
```

The host validates results: text at most 4 KiB (64 bytes for `sub`), UTF-8;
at most 10⁶ facts or 10⁵ edits; loader blocks non-empty, non-wrapping,
inside the file, at most 4096; the language a Ghidra id
(`proc:endian:size:variant`, optionally `:compiler`).

## Analyzers as queries

`plugins.analyze(plugin@version, module fingerprint, program, scope)` is a
fact-engine query (`src/plugins/include/revkit/plugins/queries.h`). A
function-scope analyzer has one key per discovered function. Every fact
import the plugin calls is answered through the query's context, so the
memo records exactly what the plugin read:

| Import | Reads | Through |
| --- | --- | --- |
| `program_info` | `plugins.program` (memory map, set at import), `analysis.program` | `plugins.program_info` |
| `memory_read` | each 4 KiB page it read | `page` |
| `file_read` | the file's pages it read | `page` |
| `functions` | `analysis.functions`, the NAME at each entry | `plugins.functions` |
| `function_code` | `analysis.function` there, the pages of its body | `plugins.code` (memoized decode) |
| `symbol_name` | NAME assertions at the address (256-byte span), `analysis.function` | `plugins.name` |

A patched byte re-runs exactly the analyzers that read its page; a rename
re-runs exactly those that asked for that name, or for the function list.
Measured in `src/plugins/tests/analyzer_test.cc` on a compiled fixture:
patching a string re-runs `string-refs` for the one function that
references it, and `crc32-tables` (which scans everything), and nothing
else. Renaming a function re-runs `string-refs` for that function only; it
read its own name to decide whether to suggest a label. Retracting the
rename brings the suggestion back. Through the backend
(`backend_test.cc`), `QueryCounters` shows one `plugins.analyze`
execution after a rename.

- **Rule tags.** Each fact is served with `origin.derived.rule =
  "plugin:<name>@<version>"`. The engine-level rule is `plugins.analyze`,
  and the key carries the module's fingerprint, so a rebuilt module (even
  one keeping its version) never reuses another module's memos.
- **Failures are results.** Out of fuel, out of memory, a trap and bad
  output are deterministic, so they are memoized like any value (as
  `Uncertain`) and listed in `GetPluginFactsResponse.errors`. A timeout,
  or a module not loaded in this process, is an exception: nothing is
  memoized and the next read tries again.
- **Persistence.** With `--project-dir`, analyzer memos are spilled and
  reloaded like built-in ones, keyed by module fingerprint.

## Loaders

At import, the built-in ELF and PE loaders go first. If they reject the
file, the first loader plugin (by name) whose manifest magic matches it
runs. `ImportOptions.format` can name one outright (`"rkraw-loader"` or
`"plugin:rkraw-loader"`). The plugin's blocks become file-backed regions,
and the rest of a block reads as zero. Its entry point and function
symbols are discovery seeds, and its other symbols are labels. Function
discovery, the listing, xrefs and the decompiler then work as for ELF. The
program's format is `plugin:<name>@<version>`, which is also the import's
provenance id.

The program record keeps the loader's `name@version`. A persisted project
reloads the program with the loader of that name. A newer version is used
if that's what is installed, and the program's derived facts then
recompute. Without the plugin, the program is skipped with a message and
the rest of the project opens. `ALoaderPluginImportsACustomFormat` and
`ALoaderPluginReopensItsPrograms` (`backend_test.cc`) cover this, and so
does `test_loader_plugin_imports_a_custom_format` (Python SDK).

## Commands

`RunCommand(program, plugin, args)` runs the command at head with a
`StoreFacts<Snapshot>`, so it reads the same facts an analyzer would, and
names are effective ones. Arguments are checked against the manifest
(unknown or missing required ones are `INVALID_ARGUMENT`). The plugin's
edits become one `AppendAssertionsRequest`, with the same validation,
precedence, single revision and subscription events as any edit:

- **Provenance.** By default the edits are `plugin:<name>@<version>`
  (`PROVENANCE_KIND_PLUGIN`, which ranks with agents), keeping the caller's
  session, reason and tool. When the caller is an agent, they are the
  agent's (`agent:claude@...`), with `tool = plugin:<name>@<version>`. So
  a person's edit outranks a plugin's, blame names the plugin, and
  `RevertByProvenance{kind: PLUGIN, id: name}`, or the agent's session,
  undoes the run.
- **`dry_run`** validates and returns the assertions without committing;
  `expected_head_revision` gives optimistic concurrency.

`CommandEditsCarryPluginProvenanceAndRevert`,
`AnAgentRunningACommandKeepsItsProvenance` and `CommandErrorsAreReported`
(`backend_test.cc`) cover this, and so do `test_command_provenance_and_revert`
and `test_agent_runs_a_command_as_itself` (Python).

## Writing a plugin

The C SDK (`sdk/plugins/c/revkit_plugin.{h,c}`) is freestanding: no libc,
and clang's wasm32 target with wasm-ld is all it needs. It provides
`memcpy`/`memset`, a bump allocator, string and buffer helpers, decoders
for every fact blob (`rk_get_program`, `rk_get_functions`,
`rk_get_function_code`, `rk_get_symbol_name`, `rk_read_memory`) and
encoders for results (`rk_emit_fact`, `rk_emit_edit`, `rk_load_*`).

```c
#include "revkit_plugin.h"

static int analyze(const rk_analyze_request *req, rk_list_out *facts) {
  rk_code code;
  if (!rk_get_function_code(req->address, &code)) return 0;
  if (code.ninsns > 1000)
    rk_emit_fact(facts, RK_FACT_COMMENT, req->address, rk_s("a very long function"), rk_s("plate"));
  return 0;
}
RK_ANALYZER(analyze)
```

```json
{"name": "long-functions", "version": "0.1.0", "kind": "analyzer", "interface": 1,
 "capabilities": ["code"], "analyzer": {"scope": "function"}}
```

```sh
clang --target=wasm32 -O2 -ffreestanding -nostdlib -Isdk/plugins/c -Wl,--no-entry \
      -o plugins/long-functions.wasm long_functions.c sdk/plugins/c/revkit_plugin.c
cp long-functions.json plugins/   # NAME.json beside NAME.wasm
rk-daemon --plugin-dir plugins --open prog
```

Any language with a `wasm32-unknown-unknown` target works if it exports and
imports what [Interface version 1](#interface-version-1) lists. The CMake
build compiles the examples into `build/plugins/` when clang can target
wasm32, and otherwise skips them (and their tests) with a message.

**Manifest** (`NAME.json`; unknown fields are errors):

| Field | |
| --- | --- |
| `name` | `[a-z0-9][a-z0-9._-]*`, at most 64 characters; unique per daemon |
| `version` | semantic version |
| `kind` | `analyzer`, `loader`, `command` or `peripheral` |
| `interface` | 1 |
| `description` | |
| `capabilities` | `memory`, `code`, `file`; for peripherals `irq`, `output`, `bus` |
| `analyzer.scope` | `program` (default) or `function` |
| `loader.magic`, `loader.offset` | hex bytes the file has at offset; required for loaders |
| `command.args` | `[{"name", "description", "required"}]` |
| `peripheral.outputs`, `peripheral.inputs`, `peripheral.size` | interrupt output names (default `["irq"]`), the number of interrupt inputs (controllers; default 0), and the register block's size when the machine gives none (default 0x1000) |
| `limits.fuel`, `limits.memory_mb` | requests, capped by the host's maximum (2·10¹⁰, 1 GiB) |

**Examples** (`sdk/plugins/examples/`):

- `crc32-tables` (analyzer, program, `memory`) scans initialized memory
  for 256-entry CRC-32 tables: reflected 0xEDB88320 and MSB-first
  0x04C11DB7, in either byte order. It labels each table `crc32_table`,
  types it `uint32_t[256]` and adds a plate comment.
- `string-refs` (analyzer, function, `memory` + `code`) finds constants in
  a function's p-code that point at C strings in non-executable memory. It
  comments each referencing instruction with the string and suggests a
  `str_...` label for functions still named `FUN_...`.
- `rkraw-loader` (loader) reads RKRAW, a raw-with-header format: a
  language id, blocks, an entry point and symbols
  ([its README](../sdk/plugins/examples/rkraw-loader/README.md)). Every
  field is bounds-checked.
- `rename-regex` (command, `code`) renames functions by a regular
  expression (`pattern`, `replace` with `\1`/`$1`, optional `limit`). It
  uses a small backtracking engine in the plugin (classes, groups,
  alternation, `* + ? {m,n}`, anchors) with a step limit.
- `tick-timer` (peripheral, `irq` + `output`) is a periodic timer with an
  interrupt and a transmit register: control, period, value, status
  (write 1 to clear), a byte to the output, and a count. `"period"` in
  its machine entry sets the period at reset. A bare-metal program on a
  Versatile/PB machine takes its interrupts through the VIC
  (`PeripheralPlugins.TickTimerInterruptsAProgram`).

## Versioning rules

- **Interface major** (`revkit:plugin/v1`, manifest `interface`,
  `rk_abi_version()`): a host serves exactly the majors it implements,
  only 1 today. A breaking change (a changed signature or field order, a
  removed import, new semantics) is a new major with a new import module
  name (`revkit:plugin/v2`). A host may serve several majors side by side;
  plugins built for v1 keep loading as long as v1 is served.
- **Within a major**, these are allowed: new imports (a v1 plugin that
  doesn't import them is unaffected; one that does fails to load on an
  older host with "doesn't have"), fields appended to records (readers
  skip unknown trailing fields), new fact kinds or edit ops (an older host
  rejects a result that uses them as bad output), new capabilities, and
  new optional manifest fields. Everything else is forbidden: reordering or
  retyping fields, changing what a field means, changing a signature.
  `abi::kInterfaceMinor` counts the additions.
- **Plugin versions** are the author's semver. `name@version` is the rule
  of an analyzer's facts and the provenance version of a command's edits.
  Memos are keyed by module fingerprint, so even an unchanged version
  string can't serve stale facts.
- **API.** `PluginService`, `PROVENANCE_KIND_PLUGIN` and
  `ImportOptions.format` naming a loader plugin are additive in
  `revkit.v1`: `api_minor` 6, feature `plugins` (4 is ghidra-interop's DefineType,
  5 collab's sync and presence; both were assigned while this was written). Other branches may bump
  `api_minor` too. When they merge, each additive change takes the next
  number, and clients should test the feature string, not the number
  ([api.md](api.md#versioning-and-compatibility)). Peripheral plugins
  are interface minor 1 (new exports, imports and capabilities, all
  additive) and, in the API, `PLUGIN_KIND_PERIPHERAL` and
  `ListPeripheralKinds`: `api_minor` 20, feature `peripheral-plugins`.

## Daemon, API and SDKs

```sh
rk-daemon --plugin-dir DIR [--plugin-dir DIR2] [--plugin-grant NAME=file] [--plugin-grant NAME=bus]
# Plugins and their grants are chosen by whoever starts the daemon; over the
# API, RunCommand needs the editor role; an agent token's run is recorded as
# agent:<token name>, anyone else's as plugin:<name>@<version> with the
# caller's session (docs/security.md).
```

Plugins load at startup, before persisted projects reopen, since loader
plugins may be needed then. Each loaded plugin is logged with its kind and
granted capabilities, and each rejected one with its error.

`PluginService` (`proto/revkit/v1/plugin.proto`; feature `plugins`):

| RPC | |
| --- | --- |
| `ListPlugins` | every plugin found: name, version, kind, interface, capabilities, args, magic, limits, fingerprint, and for peripherals their interrupt outputs, inputs and size; rejected ones with `loaded = false` and `error` |
| `RunCommand` | runs a command (see [Commands](#commands)); returns the assertions, the plugin's log and fuel used |
| `GetPluginFacts` | facts from the named analyzers (default all), optionally only in an address range, each with `origin.derived.rule`; failed runs in `errors` |

`ListAnalyzers` also lists analyzer plugins as `plugin:<name>@<version>`.
With analyzer plugins loaded, a revision that changes what they read (a
function name, function bounds, a flow override) carries
`QUERY_KIND_PLUGIN_FACTS` for the program (`api_minor` 11, feature
`plugin-facts-invalidation`), so a client showing their facts refetches
then and only then. The web UI shows analyzer facts as annotations on the
listing rows in view (`⚙ string-refs: "hello"`) and lists command plugins
in its command palette, asking for their arguments; their edits are one
undo step ([ui.md](ui.md)).
Python: `Client.plugins()`, `Program.run_command(plugin, args, dry_run=,
reason=)`, `Program.plugin_facts(*plugins, first=, last=)`,
`Client.import_program(..., format=)`, `revert(kind="plugin", ...)`, and a
`ResourceExhausted` error. TypeScript: `createRevkit(t).plugins`.

Peripheral plugins are used through `EmulatorService` and `DebugService`,
not `PluginService`: a machine description names one as `plugin:NAME`,
and `ListPeripheralKinds` lists them beside the built-in kinds (feature
`peripheral-plugins`, when the daemon has plugins and wasmtime).
`rk-emu --machine board.json --plugin-dir DIR [--plugin-grant NAME=bus]`
loads them without a daemon.

## Build impact

- **wasmtime 49.0.2** comes as its prebuilt C API release for Linux
  x86-64: a 16 MB download, pinned by SHA-256 and unpacked once per build
  directory, with nothing to compile. Building it from source would need
  a Rust toolchain and several CPU-minutes per build directory (default,
  asan, tsan). It is the artifact wasmtime publishes for embedders.
  `-DREVKIT_PLUGINS=OFF`, or another platform, builds the host without a
  runtime: loading a plugin then fails with a message, and the tests that
  need one skip.
- **Linking** the static `libwasmtime.a` (a 71 MB archive) adds 25 MB of
  code to `rk-daemon` (text 8.1 MB → 33.2 MB; the file, with debug info,
  goes from 171 to 207 MB), and the same to each test binary that links
  it. Linking `rk-daemon` takes 0.5 s longer (3.2 s → 3.7 s).
- **Examples** compile in well under a second each with clang 18.
- **Runtime.** Compiling a plugin at load takes milliseconds (Cranelift,
  on the loading thread). A call that does nothing costs 30 to 40 µs (a
  fresh store and instance). On stripped Lua (786 functions, 32 cores
  shared with other builds at load 40 to 60):
  - `string-refs` over every function takes 1.5 s cold through
    `GetPluginFacts`. Nearly all of that is decoding 20 MB of instructions
    and p-code into `plugins.code` blobs (0.5 to 1.25 s on 8 threads),
    which every analyzer shares. The 786 wasm calls take 40 to 120 ms on
    8 threads (220M fuel in all). Warm, it's 6 to 9 ms: all memo hits.
  - `crc32-tables` takes 5 ms, and the `rename-regex` dry run
    (697 renames) 10 ms.

**Sanitizers.** wasmtime is Rust and uninstrumented, like the system gRPC.
`scripts/ci.sh --asan --tsan` passes with one narrow TSan exclusion.

- **Signal handlers.** The host turns off signals-based traps, so wasmtime
  installs none. With them on, TSan reports wasmtime's trap handler
  allocating inside a signal handler, and ASan and wasmtime would both
  want SIGSEGV.
- **The TSan exclusion.** Guest memory is mapped from a copy-on-write image
  with raw syscalls TSan never sees. When a new instance's memory lands
  where a finished one's was, on another thread, TSan reports the host's
  copies into the two as a race (`Sandbox.ConcurrentCalls` found it). A
  guest's memory belongs to one store, used by one thread at a time, so
  those copies can't race. They all go through `src/plugins/guest_copy.cc`,
  two byte loops built without TSan instrumentation under the tsan preset
  (and kept from becoming calls to the intercepted `memcpy`). Every other
  access, the host's state included, stays checked. `AnnotateNewMemory`
  would be the narrower tool, but it is a no-op in GCC 13's libtsan.

## Known gaps

- **Plugin facts aren't merged into the listing or the decompiler.** They
  are served by `GetPluginFacts`, with rules. Accepting one is a command or
  an edit (an agent can turn a label suggestion into a rename). The UI
  doesn't show them yet, and its command palette doesn't list commands.
- **Subscriptions** have no `QueryKind` for plugin facts. A client caching
  them should refetch per revision, which is cheap: unchanged results are
  memo hits.
- **Names**: `symbol_name` and `functions` give asserted and discovered
  function names, not loader labels (`names.default`, which is the
  backend's).
- **Fuel calibration**: fuel counts wasm instructions, not time, and host
  imports are charged a flat estimate. The wall-clock backstop covers the
  rest.
- **Loader plugins** describe only blocks, entry and symbols. There are no
  relocations, imports or exports, and no debug info.
- **No component-model interface** yet (see [the decision](#the-interface-decision)),
  no async plugins, and no plugin-to-plugin calls.
- **Hot reload**: plugins load at startup only.
- **Peripherals**: an instance's state is not saved with a trace or
  restored by time travel, and there is no way to inspect it beyond the
  one-line state every device reports (the plugin's calls and fuel).
- **Collaboration** ([collab.md](collab.md)): a command's edits replicate
  like any assertion (op ids, HLC stamps; `PROVENANCE_KIND_PLUGIN` ranks
  with agents across replicas, `Replication.PluginsRankWithAgentsAcrossReplicas`).
  Plugins themselves don't: each daemon serves analyzer facts only for
  the plugins it loaded, and a peer needs the loader plugin to load a
  program another daemon imported with one. A daemon from before this
  change rejects ops with the plugin kind as malformed.
