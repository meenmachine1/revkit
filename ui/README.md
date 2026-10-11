# revkit UI

The first-party UI: a TypeScript web app that runs in a browser tab or in a
Tauri shell and talks to `rk-daemon` only through the public API
(`proto/revkit/v1`, via the generated client in `sdk/ts`) over Connect.
There is no Tauri IPC and no private endpoint: anything the UI does, a
script or an agent can do too. Design notes are in
[`../docs/ui.md`](../docs/ui.md), frame-time results in
[`bench/RESULTS.md`](bench/RESULTS.md).

## Run it

Needs Node 22+ (24 is used here). No global installs.

```sh
(cd sdk/ts && npm ci)                       # the UI compiles the SDK sources
cd ui && npm ci && npm run build             # tsc + vite -> ui/dist
build/tools/rk-daemon/rk-daemon user add me --role admin   # once (or run the daemon with --no-auth)
build/tools/rk-daemon/rk-daemon --open prog  # from the repo root
# open http://revkit.localhost:50052 and sign in
```

**Signing in** ([../docs/security.md](../docs/security.md)). Against a
daemon with accounts the UI shows a login page; the daemon keeps the
session in an HttpOnly cookie, so a reload keeps it, and the page sends the
session's CSRF token with every call. The toolbar shows `user:<account>`
(the name the daemon records on your edits) and a Log out button (also
"Log out" in the command palette). A `--no-auth` daemon skips all this and
the toolbar's name is yours to choose, as before.

`rk-daemon` serves `ui/dist` on its HTTP port by default (`--web-root dir`
or `$REVKIT_WEB_ROOT` to serve another build, `--no-web-root` for none).
With one program loaded the UI opens it; otherwise it shows the open dialog,
which can also import a file (uploaded bytes) or a path on the daemon's host.
The dialog's **Project** menu switches projects (opening a closed one, or
creating one); each program has a menu (right-click, `⋯`, the menu key or
`Shift+F10`) to open, rename (`F2`) or delete it (`Delete`, after asking).
Deleting is soft: the toast's Undo, or **Show deleted** and a click,
restores it (daemon feature `program-management`). The palette has "Switch
project…", "Rename this program…" and "Delete this program…".

**Development:** `npm run dev` serves on http://localhost:5173 with hot
reload and proxies the API to `RK_DAEMON_URL` (default
`http://127.0.0.1:50052`), so there is no CORS to configure.

**Tauri shell** (`tauri/src-tauri`, no Tauri CLI needed; needs Rust and
`libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libsoup-3.0-dev`,
`libjavascriptcoregtk-4.1-dev`, `librsvg2-dev`):

```sh
npm run build && (cd tauri/src-tauri && cargo build --release)   # embeds dist/
build/tools/rk-daemon/rk-daemon --open prog --allow-origin tauri://localhost
ui/tauri/src-tauri/target/release/revkit-shell
```

The shell loads its bundled copy and points it at `REVKIT_DAEMON`, which
is why the daemon must allow the `tauri://localhost` origin. Without
`REVKIT_DAEMON` it starts its own `rk-daemon` (`REVKIT_DAEMON_BIN`, the one
a packaged app carries, or `rk-daemon` beside it or on `PATH`) with an
account and a token it hands to the page, and falls back to
`http://127.0.0.1:50052` when there is none; the packaged desktop app
(`scripts/package.sh --desktop`) is described in
[`../docs/packaging.md`](../docs/packaging.md#desktop-app). `REVKIT_UI_URL=http://127.0.0.1:50052/` loads
the daemon's copy instead (same origin, no flag needed). With accounts, the
bundled copy (another origin, so no cookie) signs in for a bearer token and
keeps it in `localStorage`; plaintext on loopback is allowed, so the
default URL works. A TLS daemon's certificate must be trusted by WebKitGTK,
or load the daemon's own copy with `REVKIT_UI_URL=https://...`.

### URL parameters

| Param | Default | Meaning |
|---|---|---|
| `program` | the only one | Program id to open (`default/prog`); the hash is the address (`#1055d0`) |
| `api` | same origin | Daemon base URL |
| `user` | `local` (or the saved name) | Name recorded as `user:<name>` on edits |
| `theme` | system / saved | `dark` or `light` |
| `dpr` | `auto` | `auto` (fall back to 1 when redraws are too slow), `native`, or a number |
| `format` | `binary` | Connect encoding: `binary` (application/proto) or `json` |
| `headers` | `1` (saved) | `0`: labels in a column instead of header rows (also older daemons) |
| `arrows` | `1` (saved) | `0`: no flow arrows |
| `fnpage` | 200 | Functions per page in the functions panel |
| `render`, `hold`, `page`, `pages` | `direct`, 150, 256, 96 | Listing painter, stale-hold ms, rows per page, cached pages |
| `autobench`, `sink`, `only` | | Run the benchmark scenarios on load and POST them to `bench/sink.ts` |

## Using it

Functions and notes on the left, then two groups of tabbed views: the
**main area** (listing, graph) and the **side** (decompiler, calls, data,
types). Drag a tab to the other group, or use the palette's "Move … to
the side"; the layout and the side's width are remembered ("Reset view
layout" restores them). One selection links the views: selecting an
instruction decompiles its function, highlights the C it produced and the
instruction in the graph; clicking C or the graph selects the instruction.
The status bar shows the subscription state, the revision, the location,
and a warning when the listing renders below the display's pixel ratio.

- **Functions** (left, `Ctrl+1` filters): every function, paged from the
  daemon, with its signature (the user's or an agent's prototype in their
  colour, debug info's, else what parameter ID committed: `rk-daemon
  --param-id on` for ELF, where Ghidra's default leaves it off), size and
  references to it. The bar under the filter sorts by name, address, size
  or references (click again to reverse); **Show** lists only named or
  unnamed (`FUN_`) functions, thunks (`⇢`), functions without thunks, or
  the ones the decompiler failed on (`⚠`). Sorting and filtering run in
  the daemon (feature `function-list-filters`), so they scale.
- **Graph** (`Ctrl+4`, or `Space` from the listing): the current
  function's basic blocks and edges (green: conditional taken, red: not
  taken, blue: jump, purple: switch case, grey: fallthrough), laid out
  with ELK. Drag to pan, wheel to zoom (around the pointer), `0` fits,
  `1` is actual size, arrows pan. Click an instruction to select it
  everywhere; double-click (or `Enter` on) a call to follow it. Switch
  edges are labelled with their cases (`case 3`, from the decompiler's
  case labels). The minimap (`m`, or **Map**) shows the whole function and
  the viewport while it doesn't fit; click or drag it to move there. `c`
  collapses the selected block to its first instruction; `Shift+C` groups
  it with the blocks it dominates (a loop, an if's arm) into one node, and
  again expands it; `Shift+E` (**Expand all**) undoes all of that. The
  right-click menu has the same. On MIPS and other delay-slot machines a
  branch's delay slot stays in the branch's block.
- **Calls** (`Ctrl+5`): what the current function calls and what calls
  it, expandable level by level (recursion marked). Click goes to the
  function (`Alt`+click: the call site); double-click makes it the root.
- **Data** (`Ctrl+6`): the program's strings (address, string, references),
  or all defined data, pointers, typed globals or accessed `undefinedN`;
  filter by text; click goes there.
- **Types** (`Ctrl+7`): the program's types (debug info, defined types)
  and the library archive's as a category tree: source, kind, then initial
  letter for kinds with many types and namespace (`std::`); branches load
  as they open (`→` opens, `←` closes or goes up, `Enter` shows a type),
  and only the rows in view are drawn. A search lists matches flat, best
  first. Each type is shown field by field.
  **Edit** a struct, union, enum or typedef or create one (New…): fields
  at explicit offsets (insert at an offset into undefined filler, delete
  leaving filler, grow and shrink, bitfields at `byte:bit`) or in C's
  layout (natural, packed, `#pragma pack(N)`, `aligned(N)`), any C type
  (function pointers too) or member declarations, a flexible array, enum
  values as C expressions; the daemon lays it out as you edit
  (`TypeService.ParseC`). **Edit in C** edits the definition as text.
  **Save** defines the new version and binds the name to it, so every use
  (prototypes, variables, globals, other types) shows the edit, in every
  tab; `Ctrl+Z` undoes it. **Duplicate…** and **Rename…** make a new
  definition (rename also retracts the old name's binding). **Import
  header…** parses a C header (pasted, uploaded or on the daemon's host)
  and previews what it adds, replaces or already has, with its
  diagnostics; the import is one undo step ([docs/ui.md](../docs/ui.md#types-editor-and-header-import)). **Apply** /
  **Apply \*** retype the selected variable, parameter or global to the
  type or a pointer to it; with a function selected, its return type (a
  prototype by hash, so the decompiler uses it).
- **Plugins**: analyzer plugins' facts show at the end of their listing
  rows (`⚙ string-refs: "hello"`), and for the current function at the end
  of its instructions in the graph and of the C lines printed from them; command plugins are in the palette
  ("Run plugin rename-regex…", asking for their arguments), and their edits
  are one undo step ("Show the last plugin command's edits" lists them).

The listing reads like Ghidra's: plate comments, a function's signature,
its label and pre-comments are lines of their own above the instruction
(numbered by the daemon, so scrolling and jumps stay exact), and a gutter
draws flow arrows for the jumps in view. A jump whose other end is out of
view is drawn to the edge; clicking any arrow follows it. Rows with notes
have a marker; an overridden flow shows `⤷ flow: …` in the comment column. Other people (and agents) viewing the program show up as a
name tag on their row and in the status bar ("1 other here"), when the
daemon has presence.

| Key | Where | Does |
|---|---|---|
| `Ctrl+K`, `g` | anywhere | Go to an address (`401000`, `0x401000`), a function or label (by substring), or `#row` |
| `Ctrl+Shift+P`, `F1` | anywhere | Command palette (every command with its shortcut) |
| `Alt+←` / `Alt+→`, mouse back/forward | anywhere | History |
| `Ctrl+1` … `7` | anywhere | Functions filter, listing, decompiler, graph, calls, data, types |
| `Ctrl+Shift+M` | anywhere | Memory map: the program's blocks; add RAM, I/O or another file's bytes, change or remove a region (`a`, `e`, `Delete` in its table) |
| `Space` | listing, graph | Toggle the listing and the graph |
| `Ctrl+O` | anywhere | Open or import a program |
| `↑ ↓ PgUp PgDn`, `Ctrl+Home/End` | listing | Move the selection |
| `← → ↑ ↓` | decompiler | Walk the names and constants (the listing follows) |
| `Enter`, double-click | listing, decompiler | Follow the reference under the selection |
| `n`, `F2` | listing, decompiler | Rename: the selected symbol operand, label or function in the listing (an instruction without a label gets one); the selected function, global, parameter or local in the decompiler |
| `;` | listing, decompiler | Comment: end-of-line in the listing (on a plate or pre-comment line, that comment), pre-comment (shown in both) in the decompiler; the palette sets plate, pre, post and end-of-line comments |
| `y` | listing, decompiler | Set a type as a C declaration: a function's prototype (signature line, function name, or nothing selected in the decompiler), a parameter or local (decompiler), a global (its row or a reference to it). The daemon parses it (`ParseC`) as it is entered, so an error keeps the dialog open; definitions may come first (`struct ctr { int n; }; struct ctr *`), defined and applied in one step. Against a daemon without `parse-c`, a declaration that names a type of the program is applied by hash and others are C text checked with `validate_only` |
| `f` / `Shift+F` | listing, decompiler | Create a function at the selected instruction / remove the function containing it (asks first) |
| `o` | listing | Flow override on the selected instruction (branch, call, call + return, return, none) |
| `Shift+N` | listing, decompiler | Add or edit a note (tag and text) at the selection; empty text clears it. The notes panel lists them; click one to go there |
| `x` | listing, decompiler | References to the selected thing; the xref marker (◂n) in the listing does the same |
| `i`, or hover | listing, decompiler | Provenance badge: who or what named, typed, commented or overrode it (`user:alice`, `agent:claude@…`, `derived · loader.symbols`), when, why, competing values, and **Undo** (a retraction) |
| `Ctrl+Z` / `Ctrl+Shift+Z` | anywhere | Undo / redo this tab's edits (retract / retract the retraction) |
| `b` | listing | Show or hide the bytes column |
| `0` `1` `+` `-` `m` | graph | Fit, actual size, zoom, minimap |
| `c` / `Shift+C` / `Shift+E` | graph | Collapse a block / group it with what it dominates / expand everything |
| `←` `→` `Home` `End` | a view's tabs | The tab groups are one Tab stop each; arrows switch views |
| `F2`, `Delete`, `Shift+F10` | open dialog | Rename, delete, or the menu of the selected program |

Every key is also a command in the palette (`Ctrl+Shift+P`), listed with
its key. Text meets WCAG AA contrast (4.5:1) in both themes, on the
background and on selected rows, the canvas listing and graph included;
`e2e/a11y.ts` checks names, roles and contrast in eight states of each
theme, and runs axe-core as well when it is installed
(`RK_AXE=<axe.min.js>`).

Names and prototypes asserted by a user are blue in the listing, functions
panel and decompiler (dotted underline), names asserted by an agent purple.
Every edit is an assertion with `user:<name>` provenance, undoable, and
shows up live in every view, tab and client, with a toast naming who made
it.

## How it works

| Path | What |
|---|---|
| `src/api/client.ts` | The `revkit.v1` client (`@revkit/api` = `sdk/ts`) over Connect, and the user's provenance (`user:<name>`, session per tab, tool `rk-web/0.1`) |
| `src/data/listingSource.ts` | `GetListing` row windows (scrolling) and address windows (jumps), with header rows, mapped to the transport-neutral row model in `types.ts` |
| `src/data/rowCache.ts` | Paged LRU, prefetch, request limiting, revision-aware invalidation by address range, renumbering from the events' row windows |
| `src/data/live.ts` | The tab's one `Subscribe` stream: resume from the last revision, resync on `resync_required` |
| `src/data/edits.ts` | Rename, retype, comment, function bounds, flow override and note as `AppendAssertions` (and `validate_only` checks); undo/redo as `RetractAssertions` |
| `src/listing/` | Canvas view (scroll model, input, hit testing, flow arrows), layout (header rows), painters, theme, DPR fallback probe (`gpu.ts`) |
| `src/decomp/pane.ts` | CodeMirror view of `Decompile`'s token stream, token ↔ address mapping both ways |
| `src/ui/` | Functions panel (paged), notes panel, palette, open dialog, xrefs, provenance popover, dialogs |
| `src/graph/` | Function graph: canvas view (`cfg.ts`), ELK layout in a worker (`elk.ts`) |
| `src/ui/dock.ts` | The two tab groups and the remembered layout |
| `src/ui/vlist.ts` | Virtualized rows (only the rows in view in the DOM): references, notes, the call graph; the functions, data and types lists do the same with their own paging |
| `src/ui/calls.ts`, `data.ts`, `types.ts` | Call graph, defined data, types browser and editor |
| `src/ui/memmap.ts`, `regionform.ts` | Memory map view; the region editor (every kind of region, standalone) |
| `src/data/cgen.ts` | The type editor's drafts as C for `ParseC` (unchanged types by hash, a probe per field), its layout and diagnostics, and what saving asserts |
| `src/ui/headerimport.ts`, `hostfiles.ts` | Import header… (preview, policies, one-revision import) and the daemon-host file browser |
| `src/data/ctype.ts` | C type spellings and prototypes as `DefineType` nodes, for daemons without `parse-c` |
| `src/data/plugins.ts` | Plugin facts for the rows in view, command plugins |
| `src/app.ts` | Wiring: selection, history, edits, invalidation |
| `e2e/` | End-to-end test against a real daemon |
| `bench/` | Frame-time benchmark: Playwright runner, Tauri autobench, report |

API used, per feature:

| Feature | RPCs |
|---|---|
| Open, import | `MetaService.GetServerInfo`, `ProjectService.ListProjects`, `ListPrograms`, `ImportProgram` (content or path), `GetProgramSummary` |
| Functions panel | `QueryService.ListFunctions` by position (`offset`, 200 per page, pinned to one revision), `name_contains` for the filter, a `range` count for the current function's position |
| Listing | `QueryService.GetListing` with `header_rows` (rows window, 256-row pages; address window with `rows_before` for jumps); rows carry `flow`, `flow_targets` and `flow_override` for the arrows |
| Decompiler | `QueryService.Decompile` (tokens with addresses, variables with storage keys) |
| Go to symbol | `QueryService.ListSymbols` (`name_equals`, `name_contains`), added for the UI |
| Xrefs | `QueryService.GetXrefs` (direction `TO`) |
| Edits, undo | `AssertionService.AppendAssertions` (rename, retype, comment, function bounds, flow override, note; `validate_only` for the retype dialog), `RetractAssertions` |
| Notes panel | `AssertionService.ListAssertions` (kind `NOTE`, effective) |
| Memory map | `QueryService.GetMemoryMap`; `ProjectService.AddMemoryRegion` (content or path), `UpdateMemoryRegion`, `RemoveMemoryRegion`, `ListHostFiles` (feature `memory-map`) |
| Status bar function name | `QueryService.GetFunction`, when no loaded page lists it |
| Provenance | `AssertionService.Blame` (plus the `FactOrigin` on listing labels and decompiler variables, for coloring) |
| Live updates | `SubscriptionService.Subscribe` (with `include_presence` for collaborators' cursors) |
| Presence | `PresenceService.UpdatePresence` |
| Graph | `QueryService.GetFunctionGraph` |
| Calls | `QueryService.GetXrefs` (`CALL` references to the entry, from the body), `GetFunction` (the body) |
| Data | `QueryService.ListData` (by `offset`, pinned to one revision) |
| Types | `QueryService.FindTypes` (by source), `GetTypes`; `AppendAssertions` with `DefineType` + `BindTypeName` (edit), `DefineType` + `Retype` by hash (apply) |
| Plugins | `PluginService.ListPlugins`, `GetPluginFacts` (the rows in view), `RunCommand` |

**Invalidation.** Each `RevisionEvent` names what changed. `LISTING`
ranges mark the cached listing pages holding those addresses stale (an unset
range marks all of them); stale pages keep drawing until the refetch lands.
When rows came or went (code defined, a label, a plate or pre-comment line),
the entry carries the row windows before and after (`header_rows`, or
`rows` without header rows): cached rows move to their new numbers, the
view keeps its place and selection, and responses computed before the
change are mapped the same way when they land. Only a change no window
describes (a different `total_rows`) drops the cache and re-anchors at the
selected address. A page or decompilation computed before the newest
invalidation that touches it is refetched rather than kept, so a response
that raced an edit doesn't stick. `DECOMPILE` reloads the shown function in
place (scroll and selection kept), `FUNCTION_LIST` reloads the functions
panel's pages in view, a changed `NOTE` key the notes panel.

**Rendering fallback.** WebKitGTK without GPU compositing can't redraw a
full-window canvas at DPR 2 within a frame (bench/RESULTS.md). Shortly
after startup the page times idle frames and then 36 frames of real listing
redraws. When the redraws miss vsync at DPR > 1 it renders the canvas at
DPR 1 (upscaled nearest-neighbour) and says so in the status bar (`DPR 1 ·
software rendering`, measurements in the tooltip). It times the redraws
again at DPR 1 and, should that be clearly slower (more than 10 %), goes
back to the native ratio and only warns (`software rendering · N
ms/frame`). On WebKitGTK under Xvfb the gain is small, because the engine's
floor is painting the whole window at device scale (bench/RESULTS.md).
`?dpr=native` disables this, `?dpr=1` forces DPR 1, and the palette
toggles it.

## Tests

`e2e/run.ts` compiles a small C program, starts `rk-daemon --backend
image` on it serving the bundle, and drives headless Chrome through open,
navigation (palette by symbol and address, back/forward, functions panel,
xrefs), decompiler ↔ listing sync, renames of a function and a parameter,
comments, the provenance badge, the same changes appearing in a second
page, undo by `Ctrl+Z` and from the badge (checked in the log as
retractions), header rows (signature, label, plate and pre-comment lines,
renumbered live in both pages with the selection kept), flow arrows and
following one out of view, retype of a prototype (with the daemon's
validation error), a parameter and a global, creating and removing a
function, a flow override, a note, each page seeing the other's cursor
(presence), the paged functions panel, import by
upload, and the DPR 1 fallback. Every v1.1 edit is checked in the second
page and undone there too. Phase 5 adds: the graph (checksum's blocks and
typed edges, the loop's back edge, clicking an instruction selects it in
the listing and C, the listing selection shows in the graph, double-click
follows a call), the call graph (main's callees, expanding twice, checksum's
callers, click to go), the strings window (references, filter, click),
types (a struct created, used in a prototype by hash, edited so `p->b`
becomes `p->count` in both pages' C, the binding's provenance, three
undos), plugins from `sdk/plugins/examples` (string-refs annotations on
main's rows; rename-regex run from the palette, its `plugin:` provenance,
its edits listed and undone in both pages) and a view moved to the side,
remembered after a reload. The daemon gets `--plugin-dir` from
`RK_PLUGIN_DIR` (CTest passes the build's example plugins); without it
the plugin check is skipped.

```sh
cd ui && RK_DAEMON=../build/tools/rk-daemon/rk-daemon e2e/run.sh   # typecheck, build to a temp dir, run
```

CTest runs it as `ui_e2e` (about ten minutes, in parts) when Node, `ui/node_modules` and a
browser are present: `REVKIT_UI_BROWSER` is a Chrome binary (default
`/usr/bin/google-chrome`) or `chromium` for Playwright's own
(`npx playwright install chromium`). It is excluded under the tsan preset,
like `python_sdk`.

The whole run needs more than 6 GB (its daemons load many processor
specifications and programs, and Chrome holds every page), so `e2e/run.sh`
(and CTest's `ui_e2e`) runs it in five parts one after another, each with
the two setup checks and each in its own memory-capped scope when
`systemd-run --user` works (`RK_E2E_MEMORY_MAX`, default `6G`; `none` runs
them without one; `RK_E2E_SLICE=revkit-work.slice` puts them in a slice
whose cap other work shares). A part is an `RK_E2E_ONLY=<regex>` run: only the checks
whose names it matches, and no module (`e2e/<module>.ts`) none of whose
checks match, its setup included. Set `RK_E2E_ONLY` yourself for one
filtered run instead. A new module's checks fall into the last part unless
its names match an earlier one's. Its daemons run with `--memo-budget 384`
(MiB of derived facts kept per project).

## Benchmarks

See [`bench/RESULTS.md`](bench/RESULTS.md).

```sh
rk-daemon --no-auth --open ~/dev/revkit/out/corpus/elf-x86_64/gcc-O2/debug/lua --allow-origin tauri://localhost
npx tsx bench/run.ts --engines chrome,chrome-uncapped,chrome-gpu,chrome-gpu-uncapped --dpr 1,2 \
  --out bench/raw/daemon-host-chrome.json --host host
docker run --rm --network host --ipc host --user $(id -u):$(id -g) -e HOME=/tmp -e IN_DOCKER=1 \
  -v $PWD/..:/repo -w /repo/ui mcr.microsoft.com/playwright:v1.63.0-noble \
  node_modules/.bin/tsx bench/run.ts --engines chromium,chromium-uncapped,webkit,firefox --dpr 1,2 \
  --out bench/raw/daemon-docker.json --host docker
(cd tauri/src-tauri && cargo build --release) && bench/tauri-all.sh   # WebKitGTK under Xvfb
bench/report-all.sh            # bench/results.json + bench/raw/tables-main.md
```

The runner opens the page with `dpr=native`, so the fallback doesn't
change what is measured; `bench/tauri-all.sh` runs the shell both ways.

`bench/graph.ts` generates a function of about 2,000 basic blocks, serves
it and times `GetFunctionGraph`, the layout and frames while the graph is
panned and zoomed (`RK_DAEMON=… npx tsx bench/graph.ts`).

`bench/scale-smoke.ts` times what the functions panel and the header-rows
listing ask of a large program (pages by offset, the filter, the
current-function position, a rename's commit), then loads the UI in host
Chrome and scrolls the panel; bench/RESULTS.md has libLLVM's numbers.
