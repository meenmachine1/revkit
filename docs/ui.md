# UI: web front end

Status: UI v1.1 (branch `phase3/ui-next`), on the real daemon and API:
v1 plus every edit the API supports, Ghidra-style header rows, flow arrows
and a paged functions panel. Phase 5 (branch `phase5/product`) adds the
views a reverse engineer expects from Ghidra: a function graph, a call
graph, defined strings and data, a types browser and editor, plugin
results, and docked, remembered views (below, "Phase 5"). Types made,
edited and imported from C headers, laid out by the daemon, filed in
folders and carried between programs as type archives: "Types: editor and
header import". Code and usage in
[`ui/README.md`](../ui/README.md); frame times in `ui/bench/RESULTS.md`. The phase-0 spike that chose this stack is
summarized below ("Decision under test", "What the spike showed").

## Decision under test (phase 0)

The first-party UI is a TypeScript web app that runs unchanged in a Tauri
shell and in a plain browser tab, and reaches the daemon over a
browser-native transport (Connect or gRPC-web), never Tauri IPC. The spike
asked whether that stack can draw the listing, the view with the hardest
performance budget, at a **median frame time under 16 ms on a
10M-instruction program in Chromium and WebKit**. If both engines missed,
the decision would be revisited.

**Result: the decision stands, with one Linux caveat.** Chromium (software
and GPU), Playwright's WebKit and Firefox hold 60 fps in every scenario at
device scale 1 and 2. Uncapped Chromium needs 0.8 to 4.6 ms per frame in
software and 0.5 to 2.1 ms on the GPU. The exception is the WebKitGTK that
Tauri uses on Linux when it has no GPU compositing. It passes at scale 1
but runs at 50 to 54 fps (18 to 20 ms frames) at scale 2, and at 24 fps
when the machine is busy. A flat full-canvas fill alone takes 17 ms per
frame there, so the limit is the engine's CPU paint path, not the listing.
WebKitGTK's GPU path on a real display couldn't be measured from this
headless host (see RESULTS.md, "What wasn't measured").

## Architecture (v1, v1.1)

```
 rk-daemon (gRPC services; Connect/gRPC-web gateway; serves ui/dist)
      │  revkit.v1 over Connect (binary protobuf over fetch / streaming fetch)
      ▼
 sdk/ts client ── DaemonListing ── RowCache ── ListingView (canvas)
                  Live (Subscribe) ──┬──► invalidation ─► RowCache, decompile cache, functions panel
                  Edits (assertions) ┘
                  Decompile ──────────────────► DecompilerPane (CodeMirror)
      ▲
 Tauri shell (window only) or a browser tab
```

- **One API.** The UI uses only `revkit.v1` through the generated
  TypeScript client (`sdk/ts`, aliased as `@revkit/api`); the spike's
  `revkit.ui.v1` protocol and mock daemon are gone. `src/data/` is the only
  code that sees listing protobufs; the canvas view sees a transport-neutral
  row model.
- **Listing rows** are the daemon's (`GetListing`): one row per instruction,
  data item or coalesced undefined run, densely numbered, with
  `total_rows`. Since v1.1 the UI asks for `header_rows`: the daemon also
  numbers the display lines above each code unit (plate comment lines, a
  function's signature, its label, pre-comment lines) as rows of kind
  `HEADER`, so the client never inserts lines into the numbering. Row
  windows page the scroll; address windows with `rows_before` serve jumps,
  and the anchor row is the code unit containing the address (its header
  lines count toward `rows_before`). Against a daemon without the feature,
  labels sit in a column of the row they name, as in v1.
- **Renumbering.** A label, a plate or pre-comment, a function entry or
  code (un)defined adds or removes rows. The event's `LISTING` entries say
  where, as row windows before and after (`header_rows` /
  `previous_header_rows`); the row cache moves what it holds, maps late
  responses the same way, and the view keeps its scroll position and
  selection (re-selecting the code unit by address when its own rows
  changed). Nothing outside the windows is refetched.
- **Flow arrows.** Listing rows carry the instruction's flow after any
  override and its static targets (plus jump-table cases). The view draws
  the jumps whose source or target is in view, or that pass through it,
  finding sources up to 600 rows away in the cache, in lanes assigned
  shortest first; a jump to a row out of view is drawn to that edge, and
  clicking an arrow follows it.
- **Decompiler-first.** Selecting anything decompiles its function.
  `Decompile` tokens carry the instruction address they were printed from,
  so listing → C marks exactly those tokens, and C → listing selects the
  token's instruction and highlights the rest of its line's instructions.
  Variables carry storage keys, which is what a local rename targets.
- **Edits are assertions.** Rename (function, label, global, parameter,
  local, struct field), retype (prototype, parameter, local, global; a C declaration the
  daemon checks with `validate_only` before the dialog closes), comments of
  every kind, function bounds (create, remove), flow overrides and notes go
  through `AppendAssertions` with `user:<name>` provenance, a per-tab
  session and `tool: rk-web/0.1`. Undo appends a retraction; redo retracts
  the retraction. Nothing is updated optimistically: the subscription event
  for the commit refreshes every view, in this tab and every other client,
  the same way. Notes are listed from `ListAssertions` and reloaded when an
  event changes a `NOTE` key.
- **Presence.** With the daemon's `presence` feature, each tab publishes
  its cursor (`UpdatePresence`, refreshed every 15 s, removed on leaving)
  and streams everyone else's on its one `Subscribe`
  (`include_presence`); collaborators' rows get a name tag in their color
  and the status bar says who else is in the program.
- **Functions panel at scale.** The panel fetches 200-function pages of
  `ListFunctions` by position (`offset`) as they scroll into view, pinned to
  one revision, so opening a 300,000-function library costs one page; the
  filter is the daemon's `name_contains`, and the current function's
  position is a `range` count. A `FUNCTION_LIST` invalidation reloads the
  pages in view at head.
- **Invalidation.** One `Subscribe` stream per tab, resumed from the last
  revision. `LISTING` ranges mark the pages holding those addresses stale
  (visible stale pages keep drawing until refetched), `DECOMPILE` reloads
  the shown function in place, `FUNCTION_LIST` reloads the functions panel.
  Results computed at a revision older than an invalidation that covers
  them are refetched, so responses that race an edit don't stick. Row
  shifts need no new API: an unset `LISTING` range means numbering may have
  changed, a different `total_rows` re-anchors the view at the selected
  address.
- **Provenance** comes from `Blame` (value, winning assertion or
  derivation, competing candidates); the `FactOrigin`s already on listing
  labels and decompiler variables color user and agent names without extra
  calls.
- **Rendering fallback.** The page times idle frames and real listing
  redraws after startup. When redraws miss vsync at DPR > 1 it renders the
  canvas at DPR 1 and says so in the status bar, unless DPR 1 measures
  clearly slower, in which case it stays at the native ratio and only warns
  (see "What the spike showed", point 4). On WebKitGTK under Xvfb DPR 1
  gains about 1 ms per frame: the floor is the engine painting the whole
  window at device scale, not the canvas (bench/RESULTS.md).
- **Serving.** `rk-daemon` serves `ui/dist` by default, so browser mode is
  `rk-daemon --open prog` plus http://revkit.localhost:50052. The Tauri shell
  embeds the same bundle and reaches the daemon over HTTP.
- **Signing in** ([security.md](security.md#clients)). Against a daemon
  with accounts, `main.ts` asks `WhoAmI` before anything else and shows the
  login page (`ui/login.ts`) when there is no session. Same origin, the
  session lives in the daemon's HttpOnly cookie and `api/client.ts` adds
  the CSRF token to every call; another origin (Tauri) keeps a bearer
  token. The toolbar shows the account and Log out; edits send empty
  provenance kind and id, which the daemon stamps, and collaborators'
  cursors are named by the daemon.

### API added for the UI

- `QueryService.ListSymbols` (api_minor 2, feature `symbols`): functions
  and labels by exact or substring name, kind and range. Go-to-symbol and
  the palette need labels and globals, which `ListFunctions` doesn't cover.
- v1.1 (api_minor 7), all additive:
  - `GetListingRequest.header_rows`, `LISTING_ROW_KIND_HEADER`,
    `ListingRow.header` (feature `listing-header-rows`): header lines as
    rows the daemon numbers; `InvalidatedQuery.header_rows` /
    `previous_header_rows` give that numbering's windows.
  - `ListingRow.flow`, `flow_targets`, `flow_override`,
    `flow_override_origin` (feature `listing-flow`), for arrows and the
    override marker; `data_type` also carries a global's asserted type.
  - `ListFunctionsRequest.offset` (feature `function-list-offset`): random
    access for a virtualized list.
- For the type editor and the header import (api_minor 25, feature
  `parse-c`, with `TypeService.ParseC`): a type name `__revkit_type_<hash>`
  is the program's type with that hash (an anonymous struct or union so
  named is an anonymous member), `ParseCResponse.displays` (each node's C
  spelling), `ParseCNamedType.c_definition` and
  `ParseCDiagnostic.source_line` ([api.md](api.md#parsing-c)).

## Phase 5: product views

- **Docked views.** The listing, graph, decompiler, calls, data and types
  views are tabs in two groups (main and side, `src/ui/dock.ts`); a tab
  moves to the other group by drag or from the palette, and the
  placement, the active tabs and the side's width are remembered. Hidden
  views do no work: the graph, calls and data load when shown (and when
  the selection moves while they are shown), and an invalidation that
  reaches a hidden view only marks it stale. `Ctrl+1`…`9` show the views
  (and `Ctrl+Shift+S` the Script Manager),
  `Space` toggles the listing and the graph in place; every palette
  command shows the key that runs it. Tabs that don't fit their group
  scroll (the mouse wheel scrolls them sideways, the active tab is kept in
  view) and a **»** button at the strip's end lists every view of the
  group. The side never takes more than the window less 600 px (at least
  240 px), whatever width it was dragged to, so the listing keeps room in a
  narrow window. **Search results** is a view that comes and goes: it
  has no tab until a search (or *Show search results*) opens it. It closes
  with the × on its tab or in its head, a middle-click on the tab, Delete
  on the focused tab, Escape in its table, or by closing its last result
  set. Closing it shows the tab that was active before, and it stays
  closed across reloads (`rk.layout` remembers closed views). Clicking a
  tab half out of the strip scrolls the strip just enough to show it.
- **Function graph** (`src/graph/`). `GetFunctionGraph` (added for it)
  returns the function's basic blocks with their instructions as listing
  rows and typed edges; the daemon computes blocks from the listing's
  flow (after overrides) and the recovered jump tables, so the graph,
  the listing's arrows and the decompiler agree. ELK's layered algorithm
  (elkjs, EPL-2.0) runs in a web worker; the canvas draws only what is in
  view, edges as one path per color, and switches to boxes with a bar per
  line below 6 px per line. On a 1,999-block function every frame lands
  on vsync with all blocks on screen (`ui/bench/RESULTS.md`, "Phase 5").
  A refetch after an edit reuses the layout when the blocks and edges
  didn't change.
- **Emulator** (`src/emu/panel.ts`, its own DOM, styles and keys) over
  `EmulatorService` ([emulator.md](emulator.md)): a dockable view (the side
  by default, `Ctrl+8`), sessions started by "Emulate from here",
  breakpoints from the listing's gutter (`ListingView.onGutterClick`,
  `emuMarks`), the pc marked in the listing, the graph (`CfgView.pc`) and
  the decompiler (`DecompilerPane.setPc`). Session state stays in the
  daemon's session, never in assertions.
- **Debugger** (`src/debug/panel.ts`) over `DebugService`, in the
  Emulator's place when the daemon has feature `debugger` (same view, keys
  and gutter breakpoints): a target picker (Emulator; gdb remote
  `host:port` and Launch locally with feature `debugger-live`), Pause for a
  running target, a timeline scrubber that shows a recorded snapshot's
  registers, memory (stale bytes dimmed, unrecorded ones `??`) and pc mark
  (Now returns), threads (click to select) and modules with the address
  mapping. Breakpoints are program addresses, so they land on a PIE's
  runtime addresses too. With feature `firmware-emulation` the picker has
  **Emulator (machine…)** ([firmware-emulation.md](firmware-emulation.md)):
  a machine saved with the program, one derived from it (Derive), or a
  description edited in place and saved; such a session marks the
  exceptions the CPU took under the scrubber (click one for its
  snapshot), has a UART input line and a "Break on exceptions" box.
  With feature `debugger-stack` a **Stack** box lists the stop's (or the
  scrubbed snapshot's) call stack, `#1 main+0x2c  0x1012c6`, each frame
  with how it was found (CFI, entry, frame pointer, link register; a
  stack scan's guesses in italics); clicking a frame moves the listing
  and decompiler to its pc and shows its unwound registers, outlined
  ([debugger.md](debugger.md#call-stack)).
  With feature `debugger-values`, while a session is stopped, the hover
  cards also show values ([debugger.md](debugger.md#expressions)). A
  decompiler variable's card shows its typed value, read through its
  storage in the innermost frame of its function. A listing register's
  card shows its value in the selected frame, and a memory operand's card
  shows the address and what is there.
  With `debugger-watches` the view also has a **Watches** box. Add an
  expression by typing it there, or with **Debugger ▸ Add watch…** on a
  variable or register (a decompiler variable is evaluated in its
  function's frame). Each watch shows its typed value and type, a mark
  when it changed since the previous stop, and a struct's fields on a
  click. Watches are kept per program in this browser.
  With `debugger-disassembly` the view also has a **Disassembly** box
  for target memory the listing doesn't hold. It follows the pc when the
  pc leaves the program, and shows a library frame clicked in the Stack,
  an address or expression typed into it, or one given with **Debugger ▸
  Disassemble runtime memory…**. Rows in the program open in the listing,
  and branch targets disassemble on a click.
  With `debugger-copy`, **Debugger ▸ Copy runtime memory into the
  program…** copies a range, or the mapped region holding an address. It
  can make a new memory block at the runtime address, patches over the
  program's own bytes (only the bytes that differ), or a new program. A
  block or patches are one undo step.
  With `debugger-conditions` the view has a **Breakpoints** table. It
  shows each breakpoint's enabled checkbox, address, condition and ignore
  count (⚠ when the condition failed), and hits. Double-click a row, or
  use **Debugger ▸ Breakpoint condition…**, to set the condition and
  ignore count. A run passes over hits whose condition doesn't hold
  ([debugger.md](debugger.md#breakpoints)).
  With `debugger-rewind` an emulator session has **Back** (Shift+F7) and,
  on a scrubbed snapshot, **Resume from here**. Both go back and continue
  from that point, and the later snapshots are dropped or kept as a trace
  ([debugger.md](debugger.md#rewind)).
  With `debugger-emulate-from`, **Emulate** starts an emulator on the
  current stop's (or the scrubbed snapshot's) registers and memory. Memory
  is read from the target when first touched, and the target isn't
  changed. Closing the emulator returns to the target
  ([debugger.md](debugger.md#emulating-from-a-stop)).
- **Call graph** from `GetXrefs` (no new API): `CALL` references to the
  entry (callers, by their containing function) and from the body
  (callees), a level at a time.
- **Defined data** from `ListData` (added for it): a virtualized table
  paged by position, strings by default.
- **Types.** `FindTypes` (implemented on the image backend, with library
  archive types) and `GetTypes` feed a browser; the editor saves a new
  definition and a `BindTypeName` (added for it) in one request, which
  makes it the program's definition of its name, so its uses in
  prototypes, variables, globals and other types follow, in every tab; the
  decision and its alternatives (re-pointing every use, or none) are in
  [api.md](api.md#assertions-provenance-blame) ("Editing a type"). Since
  `api_minor` 25 the daemon parses and lays out every type the editor
  saves ([Types: editor and header import](#types-editor-and-header-import));
  before it, field types were C spellings the UI turned into `DefineType`
  nodes (`src/data/ctype.ts`, still used against older daemons).
- **Plugins.** Analyzer facts for the rows in view (`GetPluginFacts` over
  the visible range, from the containing function's entry) are drawn at
  the end of their rows with the plugin's name, refetched on
  `QUERY_KIND_PLUGIN_FACTS` (added for it); command plugins are palette
  entries that ask for their arguments, and the assertions `RunCommand`
  returns are one undo step of the tab.

## Phase 7: daily-use polish

Branch `phase7/ui-polish`; checks in `ui/e2e/polish.ts` (screenshots with
`RK_SHOTS=<dir>`).

- **Programs and projects** (API 19, feature `program-management`). The
  Open dialog has a project switcher (opens a closed project, creates
  one) and a menu per program (right-click, `⋯`, the menu key,
  `Shift+F10`): open, rename (`F2`), delete (`Delete`, confirmed). A
  delete is soft, an assertion on the program's record: the toast's Undo
  and **Show deleted** (now `⋯` → Show deleted programs) restore it by retracting it; nothing is purged
  ([api.md](api.md#queries), "Program management", has the decision).
  Every tab follows a rename or deletion of its program (`PROGRAM`
  invalidations).
- **Import progress** (API 22, feature `import-progress`;
  `src/ui/importprogress.ts`). While `ImportProgram` runs, the Open
  dialog's bottom right shows a bar and a line saying what the daemon is
  doing: "Reading cmake (11.3 MB)", "Loading cmake: sections and
  symbols", "Reading DWARF debug info (21.2 MB)", "Disassembling: 8,491
  functions", "Searching for function starts: 9,346 found", "Finding
  strings and pointers", "Saving to the project", then "Imported fw.bin:
  11,061 functions" in green for a moment before the program opens. The
  dialog sends a random `import_id` and polls `GetImportProgress` every
  250 ms, one request at a time, while the import call is in flight; the
  bar eases between polls (a 0.3 s transition) and is indeterminate (a
  sliding segment; static under `prefers-reduced-motion`) until the
  daemon has a fraction: while a file uploads, or before the import has
  started. Polling stops when the import answers, fails (the error shows
  as before and the bar hides) or the dialog closes. Older daemons (no
  feature) get the "Importing…" line alone. Accessibility: the bar is a
  `role="progressbar"` with `aria-valuenow` and an `aria-valuetext` of
  the percentage and the line; a polite live region announces each phase
  (not every count). The desktop app works the same way: it is another
  origin with a bearer token, which the poll sends like every call
  (checked in the Tauri shell under Xvfb, WebKitGTK, against its own
  daemon with accounts). How the fraction is computed and what each phase
  costs: [api.md](api.md#import-progress). `ui/e2e/run.ts` imports a
  scaled-up firmware (armfw with 8,000 bulk functions) through the dialog
  and checks the bar shows a phase with a function count, never goes
  back and ends at 100% (screenshot `import-progress.png` with
  `RK_SHOTS`).
- **Raw layout detection** (API 23, feature `raw-detect`;
  `src/ui/rawdetect.ts`, [autodetect.md](autodetect.md),
  [api.md](api.md#raw-layout-detection)). In the order a user meets it:
  - **The picked file.** Under the path, from the moment a file is picked
    (upload, drop, Browse, a typed path) until another replaces it: its
    name, its path on the daemon's host or "uploaded", and its size (an
    upload's at once, a browsed file's from the listing, a typed path's
    from its folder's listing or once detection has read it). The status
    lines, the suggestion's summary and a refusal name it too.
  - **One way to say "raw".** There is no raw mode to tick: every pick is
    first imported as ELF or PE, and the raw options' own **Import as
    raw** (shown with them) imports the picked file, or the typed path,
    as raw; with neither, it asks for a file with the system chooser. A
    file the daemon can't load as ELF or PE opens the options (with
    detection, below) and stays picked: Enter on its path again imports
    it as raw, while any other file is tried as ELF or PE first.
  - **When it runs.** If the daemon says a picked file is neither ELF nor
    PE, the dialog opens the raw options and runs `DetectRawLayout` on
    the same file instead of asking for a language. It also runs when
    the user chooses Import as raw with no language typed, and on
    **Suggest from the file**, which
    sends a language the user typed as a hint (only its processor's
    languages are tried, and the suggestion that covers it names it).
  - **While it runs.** The import bar shows the detection: "Trying 76
    languages: 43 done", then "Working out the load address…", a
    fraction that never goes back, and "Detected in 1.7 s" at the end.
    **Skip detection** beside it stops it on the daemon
    (`CancelRawDetect`); so do closing the dialog, starting an import and
    picking another file.
  - **A suggestion.** The best one fills the language, load address,
    header offset and regions as ordinary, editable values (a dashed
    border while they are detection's). Under each field: confidence
    chips (processor and variant for the language; high green, medium
    amber, low red; the tooltip says what the level means), "undetermined"
    for a load address detection couldn't work out, and a **why**
    expander with the daemon's evidence sentences. A line above the
    fields summarises it, with a strip showing what the file looks like
    (code, text, padding, compressed). The language's **Alternatives**
    menu lists the languages the same evidence fits (the tie group: the
    variant is the open question) and the other suggestions; picking one
    replaces the language and the values still detection's.
  - **Regions.** The regions box is filled with the RAM and MMIO
    regions detection suggests, and under it each detected region is a
    row: a checkbox (whether its line is in the box), the region as an
    editable line, a chip with its kind and confidence ("RAM medium") and
    its own evidence. Ticking, unticking or editing a row changes its
    line in the box, which stays what is imported; memory of unknown kind
    starts unticked. Above the rows, **High confidence only** ticks the
    high-confidence regions and unticks the rest, **Select all** and
    **Select none** tick or untick them all (the box's other lines stay),
    with a count of those ticked.
  - **Overlaps.** The ticked regions are checked, as they change, against
    the image's range (load address to load address + file size − header,
    or the length when set; in the image's space; not for Intel HEX or
    S-records, whose records place them) and each other. One that
    overlaps has an inline error on its row ("overlaps the image
    (0x0–0x1a49)", ranges inclusive), a **Clip** to what lies outside (two
    lines when it spans the image) and **Untick**; a line typed in the box
    is listed under the rows with Clip and **Remove**. Import as raw with
    an overlap left isn't sent: the status says so and focus goes to the
    first fix. (The raw loader's own message names both blocks too:
    "region mmio (0x0–0xffff) overlaps the image block ram (0x0–0x1a49)".)
  - **The user's values stay.** A field the user typed in is marked
    "edited" and is never overwritten by a later suggestion or
    alternative; **Use …** puts the suggestion back. Picking another file
    forgets what detection said of the last one (its values go, typed
    ones stay), and the next file is tried as ELF or PE first.
  - **A refusal** (compressed or encrypted, text or fill, no known
    processor, too small) is a box with the reason in words, the
    daemon's sentence and the reason code, then the closest guesses with
    their confidence and evidence, none applied; **Use** on one fills the
    fields from it. With nothing filled, Import as raw asks for a
    language.
  - **Nothing is imported** until the user chooses Import as raw, at any
    confidence; the import then uses what the fields say.
  Older daemons (no feature) keep the previous behaviour: the raw options
  open with a hint to fill them in. Keys typed in the raw fields are now
  the fields' (Delete used to reach the program list and ask to delete
  the open program). `ui/e2e/detect.ts` covers generated ARM firmware
  (armfw with 300 functions: suggested, evidence, alternatives, edits
  that stay, the confirmed import's language), random bytes (refused,
  nothing filled), armfw's 1 KB image (guesses applied only when picked),
  a typed language as the hint, skipping, an ELF after a refusal, and the
  dialog's names and AA contrast in both themes, with an overlap marked
  too; and the picked file shown at the pick, during detection and with
  the suggestions (and replaced by the next pick), the single Import as
  raw shown with the raw options (no checkbox), the region tools by
  mouse and keyboard, and an overlapping region marked, not sent, clipped
  and unticked (screenshots `raw-detect.png`, `raw-detect-refused.png`, `raw-region-overlap.png`
  with `RK_SHOTS`).
- **Functions** (feature `function-list-filters`): each row has the
  signature (asserted, debug info's, or parameter ID's), size and
  references; sorts by name, address, size and references, either way;
  Show filters named, unnamed, thunks, without thunks and decompiler
  failures, all in the daemon.
- **Graph**: switch edges carry their cases (from the decompiler's case
  labels); a minimap while the function doesn't fit; blocks collapse
  (`c`) and group with the blocks they dominate (`Shift+C`); MIPS delay
  slots stay in their branch's block (the daemon's `GetFunctionGraph`).
- **Types** (feature `find-types-tree`): a category tree, source, kind,
  initial letter for big kinds, `::` namespace, loaded as branches open
  (`FindTypes` `name_prefix`, `summary_only`) and virtualized; with
  feature `type-archive`, by folder (the types' categories) instead.
- **Plugin facts** in the graph and the decompiler, for the current
  function's body.
- **Large tables**: the references dialog, notes and the call graph draw
  only the rows in view (`src/ui/vlist.ts`), like the functions, data and
  types lists, and page through every reference.
- **File chooser**: made on demand, timed, with the live stream paused
  while it is open, and a diagnostics dialog; findings and the experiment
  for the affected machine in [known-issues.md](known-issues.md).
- **Keyboard and accessibility**: every key is a palette command with its
  key; tab groups are single Tab stops; colours meet WCAG AA in both
  themes (canvas included); `ui/e2e/a11y.ts` checks names, roles and
  contrast offline in ten states per theme (the type editor and the
  header import among them), with axe-core when installed (0 problems
  with axe-core 4.14, 2026-10-05).

## Phase 9: UI polish

Branch `phase9/uipolish`; checks in `ui/e2e/uipolish.ts`. An audit of
every view, menu and dialog at 1440×900 and 1024×680 in both themes, then
fixes, made shared where several places had their own version:

- **Focus.** Modal dialogs keep the keyboard: Tab past the last control
  comes back to the first, Shift+Tab before the first goes to the last,
  and focus that lands behind the dialog (a click on the toolbar, Tab out
  of the window and back) returns to it (`src/ui/focustrap.ts`; a
  dialog's own Tab, a type completion, still wins). A palette command that
  opens a menu or a popover (Navigation history…, Patch instruction…)
  keeps the focus there instead of the palette handing it back to the
  view; the Open dialog's program list takes the focus.
- **The palette** lists each command once: *Show comparison*, the second
  *Show patches* and *Window: Python* are gone (*Show compare*,
  *Show patches* and *Show Python (the console)* remain), and *Show
  defined strings* no longer claims `Ctrl+6` (*Show data*'s key). Script
  and plugin commands carry their description as a dimmed detail rather
  than in the title; command titles are set in the UI font, symbols in
  the code font; view names keep their capitals (*Show function ID*,
  *Move Python to the main area*); the program and project commands sit
  with the File menu's (*File: Open or import program…*, *File: Switch
  project…*, *File: Rename this program…*, *File: Delete this program…*).
- **View heads** stay one line: the title and buttons keep their size, the
  text between them (counts, a function's name) shortens with an
  ellipsis, and a head too crowded for a narrow side scrolls. The graph
  diff's head looks like the others'.
- **Buttons that have nothing to act on are disabled**: Compare's Re-run
  and Apply markup without a comparison, Patches' Revert all without
  patches, Equates' Rename and Remove and Function ID's Apply and Reject
  without a selection, the search results' Copy CSV, Make selection and
  Close (and no empty result-set picker) before a search.
- **Empty and loading states** ("No equates", "No matches", "No notes",
  "No comparison yet", "Loading…" before the Equates, Function ID and
  Patches views have loaded) share one style, and in a list they are a
  disabled option, so screen readers hear a list with one entry.
- **Right-click menus** use the short form of a command's title (*Rename*,
  *Set type…*, *Copy special…*); the palette's explanation in parentheses
  is the item's tooltip.
- **Fonts**: drop-downs (All tiers, Strings, Program) are set in the UI
  font, like buttons; text filters stay in the code font.
- **Narrow windows**: the side is bounded (see "Docked views"), a listing
  too narrow for the mnemonic and the start of the operands beside the
  bytes hides the bytes column until it is wide again (`Shift+B` still
  shows them; the preference is kept), the main group's content no longer
  draws over the side, the toolbar's Go to field
  shrinks before the program's name does, the type editor's packing and
  alignment wrap, Compare's filters wrap, the graph diff's buttons stay
  reachable, and the graph's minimap shrinks with its view. The memory
  map's rows are as tall as the other tables' (its row buttons had the
  toolbar's icon size). A dialog taller than a short window scrolls
  inside it instead of running off the bottom.
- **Stale views**: the Calls view's root follows a rename of its function
  (and the undo).
- **Colours**: the patch editor and the Patches view use theme tokens
  (`--patch`, `--patch-bg`, `--border-soft`), so the light theme gets
  its darker orange; links (`a`, `.link`) use the accent colour.

### Edit function

**Edit function** (feature `parse-c`; the conventions with
`calling-conventions`, api_minor 58; `src/ui/editfunction.ts`) is
Ghidra's Edit Function dialog: the function's C signature on top and
its fields below, each kept in step with the other as either is edited.
The fields: the name, the return type (empty or `undefined`: the
decompiler decides it, unlocked, as Ghidra's undefined return; a return
nothing asserted starts so, and `void` says it returns nothing), the
**calling convention** (a
dropdown of the compiler spec's prototype models and aliases from
`QueryService.ListCallingConventions`: "default (__stdcall)", "unknown",
then `__stdcall`, `__cdecl`, `__fastcall`, `__thiscall`, … on 32-bit
Windows; a model C can't spell is listed but can't be chosen), the
**parameters** (type and name cells with the type chooser's names; add,
remove, move up and down) and **varargs**. "default" and "unknown" both
leave the convention out of the C, which the decompiler reads as the
spec's default, as Ghidra decompiles them. The daemon checks the C as it
changes (an unknown type, a convention the spec lacks) and its error
shows under the signature; Apply (or `Ctrl+Enter`) sets the prototype, and
renames the function when its name changed, in one request: one undo
step. The decompiler shows the new convention (`__fastcall` on x86-32
moves the first two parameters to ECX and EDX; a `__cdecl` caller
cleans the stack). It opens with `F` at a function's entry in the
listing or on its name or signature line in the decompiler (Ghidra's
keymap; `Alt+P` in IDA's; elsewhere `F` creates a function), from the
listing's **Function ▸** menu, the decompiler's right-click menu, the
function list's menu and the palette. **No return** (feature
`no-return`) is checked when the function doesn't return, by analysis or
by the user's word; changed, Apply asserts it (`SetNoReturn`) in the
same request. Not offered: **Inline** (revkit has no such fact) and the
parameters' storage (assigned by the decompiler, not reported before it
runs).

**Set no return** and **Clear no return** (Ghidra's Set No-Return; no
key in Ghidra's keymap) are in the listing's **Function ▸** menu, the
decompiler's right-click menu (on a called function's name, that function; elsewhere the function shown), the function
list's menu (whichever applies to the row) and the palette: calls to the
function end their caller's flow there, so callers' bodies, listing flow
and decompilations lose the dead fallthrough; Clear says it returns,
even where analysis decided it doesn't. One undo step each.

### Copying from the decompiler

The decompiler's C selects and copies like text: a drag, Shift+click, a
double click on a word and a triple click on a line select (drawn in both
themes); `Ctrl+C` copies the selection, or the selected token when nothing
is selected; `Ctrl+A` selects the function; Escape drops the selection.
A plain click still selects a token (on release, when the pointer didn't
move) and syncs the listing; a double click on a function or global name
still follows it; the arrow keys still walk the tokens. The right-click
menu starts with **Copy** and **Copy function** (the whole C). The
listing is a canvas: drag, Shift+click or Shift+arrows select rows and
`Ctrl+C` copies them as shown; Copy special (`Ctrl+Shift+C`) has the other
formats.

### Slices

With the daemon's `decompile-slices` (`api_minor` 57; [api.md](api.md#slices)),
the decompiler's right-click menu has Ghidra's **Highlight ▸**: **Def-use**
(the value's definition and its uses), **Forward slice** (every value
computed from it), **Backward slice** (every value it is computed from),
**Forward operator slice** and **Backward operator slice** (the operations
those run through), and **Clear**; the palette has them as *Highlight …*.
They act on the token clicked: a variable, a parameter, a constant, or an
operator, a call's name or `return` (its result going forward, its
operands going backward).

- The slice's tokens are tinted in the C (`.cm-slice`, both themes) and
  the instructions its ops belong to in the listing (a tint and a bar in
  the gutter, `ListingView.sliceMarks`), so a backward slice from a
  `return` shows its operands in the C and the instructions computing them.
- **Next and previous** highlighted token: Ghidra's `Ctrl+.` and `Ctrl+,`
  (in every keymap; the palette's *Highlight: next/previous*) move the
  cursor through them, the listing following.
- **Escape** clears it (after a text selection), as does decompiling
  another function or the same one again after an edit.
- A toast says how many tokens and instructions it covers.

`src/app.ts` `sliceCommands`, `slice`; `src/decomp/pane.ts`
`setSlice`, `sliceStep`, `clearSlice`. Tests: `ui_e2e` (`e2e/slices.ts`): a
backward slice from `second`'s `return` highlights exactly its operands
(`param_1`, `1`) in the C and marks the listing, next and previous walk
them and Escape clears both; def-use of a local in `checksum` marks only
its prints; a forward operator slice from a parameter marks operations and
instructions. Screenshots `slice-*.png` with `RK_SHOTS`. The daemon's
side is `SliceTest` (`revkit_backend_tests`) and `tests/test_slices.py`
(`python_sdk`, the SDK and the MCP tool).

### Keymap presets

revkit's keys follow one of three tools: **Ghidra** (the default), **IDA
Pro** or **Binary Ninja**. Choose in **File → Preferences…** or with the
palette's *Keymap: Ghidra*, *Keymap: IDA Pro* and *Keymap: Binary Ninja*;
the choice is kept per viewer (`localStorage`, `rk.keymap`). Menus, the
palette, right-click menus, the toolbar's and the tabs' tooltips show the
active preset's keys, and *Help: Keyboard shortcuts* (also in Preferences)
is a cheat sheet of every active binding with a filter.

The table is `src/ui/keymap.ts`, and the page's key handler
(`App.onKey`, `dispatchKey`) asks it what a key means. A plain key (no
Ctrl or Alt) acts only in the listing, the decompiler or the graph and
never in a text field; Ctrl and Alt keys that act anywhere (back and
forward, the searches) also work from a text field, except Ctrl+Enter,
which a field keeps. A view's own keys come first: the decompiler's Escape
drops its text selection before IDA's Escape goes back, and the listing's
Escape drops a row selection first. `Ctrl+K` and `Ctrl+P` (go to),
`Ctrl+Shift+P` and `F1` (commands), `Ctrl+O` (open), `Ctrl+Alt` next and
previous by kind, `Ctrl+C`/`Ctrl+A` in the decompiler and the debugger's
`F7`/`F8`/`F9` are the same in every preset, as are the graph's and
Compare's keys inside those views.

Every binding in the IDA and Binary Ninja columns is one of the tool's
documented defaults; Ghidra's are from Ghidra 12.1.4's sources
(`Ghidra/Features/Base` and `Decompiler`, `KeyBindingData`). An action a
tool has no documented default for keeps revkit's key (marked *revkit*),
unless the preset gives that key to something else (then it has none: use
the palette or the menu). Sources: Hex-Rays' IDA shortcut reference
(docs.hex-rays.com, *Shortcuts*, IDA 9.x) and *IDA Pro cheat sheet* for
C/D/A/U and F5; Binary Ninja's user guide (docs.binary.ninja, *Default
Hotkeys*, the Windows/Linux keys).

| revkit action | Ghidra (default) | IDA Pro | Binary Ninja |
|---|---|---|---|
| Go to address or symbol | `G` (`Ctrl+K` everywhere) | `G` | `G` |
| Back | `Alt+←` | `Esc` (`Alt+←` revkit) | `Esc`, `Ctrl+[` (`Alt+←` revkit) |
| Forward | `Alt+→` | `Ctrl+Enter` (`Alt+→` revkit) | `Ctrl+]` (`Alt+→` revkit) |
| Rename | `L` (`N`, `F2` revkit) | `N` | `N` |
| Set type | `Ctrl+L` (`Y` revkit) | `Y` | `Y` |
| Set comment | `;` | `;` and `:` (Shift+;) | `;` |
| References to (xrefs) | `Ctrl+Shift+F` (`X` revkit) | `X` | `X` |
| Create function | `F` | `P` | `P` |
| Edit function | `F` at a function's entry or on its name or signature (Create function's key) | `Alt+P` | none (`P` creates) |
| Remove function | `Shift+F` revkit | `Shift+F` revkit | `Shift+F` revkit |
| Listing: disassemble (make code) | `D` | `C` | none |
| Listing: clear (undefine) | `C` | `U` | `U` |
| Listing: cycle byte, word, dword, qword | `B` | `D` | `D` |
| Listing: string | `Shift+'` revkit | `A` | `A` |
| Listing: char | `'` | `'` revkit | `R` |
| Listing: pointer | `P` | none | `O` |
| Listing: byte, word, dword, qword | — | — | `1`, `2`, `4`, `8` |
| Listing: array | `[` | `[` revkit | `[` revkit |
| Listing: choose data type | `T` | `T` revkit | none (`Y` sets a type) |
| Decompiler (show) | `Ctrl+E` (`Ctrl+3` revkit) | `F5` (`Ctrl+3`) | `Ctrl+3` revkit |
| Switch listing ⇄ decompiler | — | `Tab` | `Tab`, `F5` |
| Listing ⇄ graph | `Space` revkit | `Space` revkit | `Space` |
| Search memory (bytes, strings) | `S` (`Ctrl+Shift+E` revkit) | `Alt+B` | `S`, `Ctrl+Shift+E` revkit |
| Search program text | `Ctrl+F` | `Alt+T` | `Ctrl+Shift+F` revkit |
| Search scalars | — | `Alt+I` | — |
| Repeat search (next) | `F3` | `Ctrl+T` (`F3` revkit) | `F3` revkit |
| Repeat search backward | `Shift+F3` | none | `Shift+F3` revkit |
| Add note (bookmark) | `Ctrl+D` (`Shift+N` revkit) | `Alt+M` (mark position) | `Shift+N` revkit |
| Undo / redo | `Ctrl+Z` / `Ctrl+Shift+Z` | `Ctrl+Z` / `Ctrl+Shift+Z` | `Ctrl+Z` / `Ctrl+Shift+Z` revkit |
| Debugger: toggle breakpoint | — | `F2` | — |
| Functions (focus the filter) | `Ctrl+1` | `Shift+F3` (`Ctrl+1`) | `Ctrl+1` |
| Data (strings) view | `Ctrl+6` | `Shift+F12` (`Ctrl+6`) | `Ctrl+6` |
| Types view | `Ctrl+7` | `Ctrl+7` | `T` (`Ctrl+7`) |
| Bytes view | — | — | `H` |
| Patch instruction | `Ctrl+Shift+G` | `Ctrl+Shift+G` | `E` (`Ctrl+Shift+G`) |
| Next / previous highlighted token (slices) | `Ctrl+.` / `Ctrl+,` | `Ctrl+.` / `Ctrl+,` revkit | `Ctrl+.` / `Ctrl+,` revkit |
| Flow override | `O` revkit | `O` revkit | none (`O` is pointer) |
| Equate | `Shift+E` | `Shift+E` revkit | `Shift+E` revkit |
| Add reference | `Shift+R` | `Shift+R` revkit | `Shift+R` revkit |
| Auto create structure | `Shift+[` | `Shift+[` revkit | `Shift+[` revkit |
| Provenance | `I` revkit | `I` revkit | `I` revkit |

The other actions (views by `Ctrl+2`…`Ctrl+9`, Copy special, Patch bytes,
the memory map, scripts) keep revkit's keys in every preset.

**Left on revkit's key, or none, on purpose:**

- IDA's `;` is a *repeatable* comment and `:` a regular one; revkit has no
  repeatable comments, so both open Set comment. IDA's anterior and
  posterior lines (`Ins`, `Shift+Ins` or `Alt+Q`/`Alt+A`, depending on the
  version) aren't bound: the sources disagree.
- IDA's `Ctrl+M` (jump to a mark) and `Ctrl+Shift+M` (bookmarks window):
  revkit has no notes list to jump through, and `Ctrl+Shift+M` is the
  memory map. Binary Ninja's numbered bookmarks (`Ctrl+Alt+1`…`0`, then
  `Ctrl+1`…`0`) aren't bound: revkit's notes aren't numbered and
  `Ctrl+1`…`9` are its views.
- IDA's `M` (enum member) and `*` (array): one source each, not bound;
  `Shift+E` (Set equate, which also offers enum members) and `[` stay.
- Binary Ninja's Find (`Ctrl+F` on most installs) isn't in its documented
  default list, so its searches keep revkit's keys. It has no documented
  make-code key, so Disassemble has none there (`D` cycles data widths).
- Ghidra's `Delete` (remove a function at its entry) isn't bound: revkit's
  Remove function acts on the function around the cursor, and `Shift+F`
  asks first. Ghidra's `Y` (the last data type used) and `F` on data
  (float cycle) aren't revkit actions.

**Browser-reserved and conflicting keys.** In a browser the page gets
these only if the browser lets it; the desktop app gets all of them.

- `Ctrl+T` (IDA's search next) opens a tab in Chrome and Firefox, which
  never give it to the page: use `F3`.
- `Ctrl+F` (Ghidra's text search) replaces the browser's find in page while
  the page has the focus; the listing is a canvas, which the browser's find
  can't search anyway.
- `Ctrl+D` (Ghidra's bookmark) and `Ctrl+E` (Ghidra's decompiler) are the
  browser's bookmark and search-bar keys; Chrome and Firefox let the page
  take them, and revkit does while it has the focus.
- `Ctrl+L` (Ghidra's set type) is the browser's address bar key; the page
  takes it, but only when the focus is in the listing, the decompiler or
  the graph (not in a text field).
- `Alt+T` and `Alt+B` (IDA) are Firefox's Tools and Bookmarks menu keys
  on Linux and Windows; revkit takes them while the page has the focus,
  but a browser that keeps them opens its menu instead (not checked in
  Firefox: the tests run Chrome).
- `Tab` (IDA, Binary Ninja) switches the listing and the decompiler
  instead of moving the focus, but only in those views; the toolbar, the
  panels and dialogs Tab as usual, and `Ctrl+1`/`Ctrl+2`/`Ctrl+3` move the
  focus to the functions, the listing and the decompiler.
- `Esc` (IDA, Binary Ninja: back) leaves full screen in a browser before
  the page sees it.

Tests: `ui_unit` (`test/keymap.ts`: chords from key events, labels, no
key bound twice in a preset, the presets' key bindings) and `ui_e2e`
(`e2e/keymap.ts`): Ghidra by default (`L` renames in the listing and the
decompiler, `Ctrl+L` sets a type, `Ctrl+Shift+F` lists references, the
palette's and the tooltip's keys); IDA Pro from the palette (`L` does
nothing, `N` renames, `Tab` to the decompiler and back, `G` then `Esc`
goes back, `Y` sets a type and `Ctrl+L` doesn't, the palette, the Search
menu, the tooltips and the cheat sheet show IDA's keys, kept after a
reload); Binary Ninja from File → Preferences (`Ctrl+[` goes back).
Screenshots `keymap-*.png` with `RK_SHOTS`.

### The main window

The chrome follows the same pattern as the Open dialog (phase 9; the
mockup was a project window over a dark workspace): one accent, 1 px
borders, room in the bars and headers, none taken from the code rows
(the listing's and decompiler's line heights are unchanged).

- **Top bar** (`#toolbar`): the wordmark; the menus **File**, **Edit**,
  **View**, **Navigate**, **Analyze** and **Search** (with the
  feature); Back, Forward and History; a centred command field "Go to
  address, symbol, or command…" with its `Ctrl K` chip (the palette:
  addresses and symbols, `>` for commands); Undo, Redo, the user, Log out
  and the command list on the right. Edit, Navigate and Analyze list the
  palette's commands by id (`EDIT_MENU`, `NAV_MENU`, `ANALYZE_MENU` in
  `app.ts`; `menu-cmd-<id>` test ids), with the active keymap's keys and
  disabled where the palette would refuse them; a command a daemon lacks
  is left out. View lists every view (a check on the ones shown; it opens
  a closed one), then the layout, Data, the theme, Preferences and the
  shortcuts. Under 900 px the menus fold into one **☰** button with each
  menu as a submenu; under 640 px Back, Forward, Undo, Redo and the user
  go too (their keys still work).
- **Context row** (`#context`): the project (its folder icon and name; a
  click opens the Open dialog on the project switcher), the program's
  folders and the program (`#program`; a click opens the Open dialog,
  as `Ctrl+O` does), and **Import binary…** on the right (the Open
  dialog straight in its import section, into the folder of the program
  this tab shows).
- **Panel headers** (`.panel-head`): one height (34 px), the title in the
  UI font at 13 px, not small capitals; Functions reads "Functions (14)"
  with the count dimmed beside it. The functions filter has a search
  glass and the UI font; Name / Address / Size / Refs is a header row, the
  sorted one bold with its arrow in the accent.
- **Tab bars** (`.dock-bar`): 34 px, 13 px labels, the active tab in the
  text colour with a 2 px accent underline (accent text while its group
  has the focus).
- **Status bar** (`#statusbar`): 28 px, segments with a rule between
  them: the daemon chip, the live dot, the revision, the address, the
  function, and on the right the row and the key hints; empty segments
  take no room.
- **Colours.** Dark: the code panes `#10141b`, the chrome `#151a22`,
  borders `#252c37`, one blue accent `#4f9dff`; light is the same layers
  in daylight (white panes, `#f5f7fa` chrome, `#d6dce4` borders, accent
  `#0a66d6`). Both keep AA contrast for dim text, on the selection too
  (the accessibility check). The listing canvas's theme
  (`src/listing/theme.ts`) and the overview bar use the same background.

Tests: `ui_e2e` (`e2e/uipolish.ts`): the menus hold the commands (Edit:
undo, rename, retype, comment; View: listing, decompiler, graph, reset
layout, theme; Navigate: go to, back, forward, references; Analyze:
auto-create structure, compare); View → Graph shows the graph; Navigate
→ Go to opens the palette; the context row names the project and the
program; Import binary… opens the import section; the project crumb
focuses the project switcher; an 820 px window keeps the program's name
and the toolbar in the window, the menus behind ☰. Screenshots
`81-polish-chrome.png`, `82-polish-820.png` with `RK_SHOTS`.

### Opening programs

The Open dialog (`Ctrl+O`, File → Open…, and the dialog a fresh start
shows when the daemon has several programs or none; `src/ui/open.ts`,
the columns' text in `src/data/programs.ts`) is laid out as a project
window:

- **Title row**: "Open program" and a close `×` (none when no program is
  open yet: a fresh start can't be dismissed, and has no Cancel either).
- **Toolbar**: the **Project** switcher (each project with its program
  count; a closed one is opened, **New project…** creates one), **New
  folder** (in the folder picked) and `⋯`: **Show deleted programs** (a
  check), **New project…**, **Export project…** and **Import project…**.
- **Breadcrumb**: the project, then the folders down to the one picked (the
  row picked, or the folder of the program picked), each a button that
  picks that folder (the project's root: nothing picked) and a drop target
  for a dragged program or folder; on the right "N programs" ("1 of N
  programs" while searching, "· N deleted" with the trash shown).
- **Search** ("Search programs by name, architecture, format or
  folder…"): every word typed must be in the name, the architecture (as
  shown or as the language id), the format or the folder path. The tree
  becomes the flat list of matches, each with its folder beside the name.
  A letter typed while the list has the focus goes to the search; ↑↓,
  PgUp/PgDn and Enter still move and open from the search field; Escape
  clears it, and a second Escape closes the dialog.
- **The table.** Column headers **Name**, **Architecture**, **Imported**
  and **Status** sort (a click; again reverses; remembered in
  `revkit.open.sort`); folders come first, by name, and each folder's
  programs are sorted within it. Name has a file or folder icon (a folder's
  caret opens and closes it). Architecture is the language id as people
  read it: `x86:LE:64:default` is "x86 · 64-bit · LE", `ARM:LE:32:v4t` is
  "ARM · 32-bit · LE (v4T)" (the raw id is the cell's title and in the
  details). Imported is "just now", "6 min ago", "3 hours ago" under a
  day, else "Oct 7, 2026" (the time in its title). The daemon keeps no
  per-program "modified" time, so the column is the import's. Status is
  a dot and a word from `GetAnalysisStatus` (cheap: no program is loaded
  for it; at most 200 programs, six at a time): **Ready**, **Analyzing
  42%** or **Analyzing…** (a running job, or the background analyzers:
  parameter ID, inference, Function ID; polled every 2 s while any is
  busy), **Error** (the last job failed; its message in the title), **Open
  here** (the program this tab shows), **Deleted**. `⋯` at the row's end
  (shown on hover and on the row picked) is the row's menu: Open,
  Rename… (F2), Move to…, Copy SHA-256, Delete… (Del), Export program…;
  a folder's has Expand/Collapse, New folder…, Rename…, Move to…, Delete,
  Export folder…; a right-click on the empty space under the rows or on
  the breadcrumb's project is the project's (New folder…, Export
  project…, Import project…).
- **Picking and opening.** A click picks a row; a double click, Enter or
  **Open program ↵** opens the program (on a deleted one the button says
  **Restore**, and a double click or Enter restores it). The button is
  disabled until a program is picked. ↑↓, PgUp/PgDn, Home/End move;
  →/← open and close folders (← on a program goes to its folder).
- **Details** of the row picked, in two columns: Format ("ELF", "PE",
  "Raw binary"), Fingerprint (the SHA-256's first 12 hex digits; a click
  copies all of it, the title shows it), Language (the raw id), Location
  (project / folders), Compiler (the compiler specification), Imported
  (date and time), Size (the file's), Status, and From (the path inside
  a container, for a program imported from a file system), plus Deleted
  with **Restore**. Compiler and Size are `ProgramInfo.compiler_spec_id`
  and `file_size` (added for this; older daemons leave them out, and so
  does the panel). A folder shows its path and contents; nothing picked,
  the project's name, program count and database path. The function count
  is left out: it would load each program picked.
- **Footer**: **Import binary…** with "Add a binary to this project" (or
  "to /libs": the folder picked) on the left; "Double-click a program to
  open it", **Cancel** and **Open program ↵** on the right.
- **Import binary…** swaps the table for the import section, headed
  "Import into default / libs": a drop zone (a file dropped anywhere on
  the dialog imports, from either view) with **Choose file…** (the upload:
  the system file chooser) and **Browse daemon host…** (the daemon's
  files under `--browse-root`, listed below it: ↑↓ Enter, Backspace for
  the parent; a click on a file imports it), **Path on the daemon host**
  with **Import** (or Enter), the file picked, and **Raw binary
  (firmware)…** with its options and detection, as before. The status
  line and the import's progress bar sit under it. **Back to programs**
  (the same footer button) or Escape returns to the table; the crumb and
  search are hidden meanwhile.
- **Narrow windows.** The dialog is a size container: under 760 px the
  Imported column and the open hint go, under 560 px Architecture too and
  the details are one column.
- **Keyboard and focus.** The dialog keeps the focus trap of every modal
  (Tab cycles inside it) and the resizable grips (the table, or the import
  section, is what grows: `data-grow` on `.od-main`).

Tests: `ui_e2e` (`e2e/opendialog.ts`): the columns and the count; a
folder picked disables Open program and shows its details and crumb; a
program picked enables it, with its format, language, short fingerprint
(full in the title), compiler, size and "x86 · 64-bit · LE"; Open here and
Ready; searching "x86 64" lists both programs flat with the folder beside
one; sorting by name both ways and by date; searching by folder ("1 of N
programs"), no match, Escape clearing it; letters typed on the list going
to the search and Enter opening the match; a click only picking, a double
click opening, and Open program opening. `test/programs.ts` (ui_unit):
the architecture text, formats, dates, sizes, the sort and the search.
`e2e/projects.ts`, `e2e/polish.ts`, `e2e/detect.ts`, `e2e/filesystems.ts`
and `e2e/run.ts` go through Import binary… to the import section, and
the trash through `⋯` → Show deleted programs.

**Universal Mach-O files** (feature `macho`, api_minor 90;
[macho.md](macho.md#universal-files-and-slices)). Importing one loads
its default slice (arm64, else x86_64); the toast says which and offers
**Import x86_64** (the file's first other slice). A universal program's
details have a **Slice** line, `arm64 (of x86_64, arm64)`, with an
**Import** button per other slice: the program's stored file imported
again with that slice (`ImportProgram.program_file`), into the same
folder. Tests: `e2e/macho.ts` (the Slice line, Import x86_64, the new
program's language and line).

**.NET assemblies** (feature `dotnet`, api_minor 94;
[api.md](api.md#net-assemblies)). Importing an IL-only assembly toasts
that it was imported without code analysis (its code is IL, not machine
code), and its details have a **.NET** line: `IL-only .NET assembly,
metadata v4.0.30319, runtime 2.5; imported without code analysis (its code
is IL)`. A mixed-mode assembly's line says so, and its native code is
analysed.

**Packed executables** (feature `packed-executables`, api_minor 96;
[filesystems.md](filesystems.md#packed-executables)). Importing a program
packed with its scripts (PyInstaller, pkg, nexe, a Node single executable,
Bun) toasts what it carries with **Open as file system**, and its details
have a **Packed** line with the same button: the file browser on the
program's stored file, its scripts as `.pyc` or JavaScript files to
browse, extract or hand to a decompiler. Importing a bytecode file
itself (a `.pyc`, a class file) says what it is instead of offering raw
options.

### Changing the language

**Analyze → Change language (which processor variant fits the code)…**
(feature `set-language`). The dialog shows the program's language, then a
table of every variant of its processor in its byte order, in each mode
(ARM and Thumb, say), compared on the program's own code: the share of
bytes decoded (with a bar), invalid and unimplemented instructions, what
control flow reaches, and reached runs cut short. Auto-detection's pick is
marked **detection's pick** and listed first, with its reasons below the
table (Thumb-2 use, a Cortex-M vector table); the current language is
marked **current**. Click a row (or Enter) to choose it, or pick any
language of the processor (the other byte order) and a compiler spec from
the lists below; **Switch** changes the language in place: the same bytes
at the same addresses, every name, comment and type kept, analysis run
again. While it runs, the dialog shows the import's progress bar (the
phase, functions found, a percentage); it takes about as long as the
import's analysis, and the views keep showing the program as it was until
it is done. It is one undo step (Ctrl+Z, or the toast's Undo);
**Imported language** goes back to the language of the import. A language
that lays memory out differently is greyed out: import the file again in
it.

### Libraries

`api_minor` 70, feature `program-libraries` ([api.md](api.md#libraries);
`src/ui/libraries.ts`).

- **Importing them.** The Open dialog's import section has **Also import
  the libraries it needs** (remembered), with an optional field of more
  library directories on the daemon host (`:` separated). The program and
  the libraries it needs that the project lacks (found beside it, on its
  runpath, on those directories, then the host's `/lib` and `/usr/lib` for a
  file on the daemon host; two levels deep) are imported into the folder
  picked; a toast names the libraries imported and those found nowhere. A
  file inside a root file system extracted under `--browse-root` finds its
  libraries in that root instead of the host's (api_minor 79; the toast
  names the root). The File System browser's batch import has the same
  option for a container's programs.
- **Where an import goes.** In the functions list, an import thunk's second
  line reads `→ libc.so.6!strlen` (in the accent) instead of its signature;
  a click opens the library program at that function. **Navigate → Go to
  library function** does the same for the function at the cursor, and the
  thunk's **References** dialog heads its list with "Imported: goes to
  libc.so.6!strlen" (a click opens it).
- **References back from a library** (feature `library-importers`,
  api_minor 81). In a library program, the **References** dialog of a
  function it exports (Ctrl+Shift+F) also lists, above its own references,
  **From programs that import it**: each call of the import in another
  program (`call prog!main+0x1c`), or the import's thunk when nothing
  calls it; a click opens that program there.
- **Analyze → Libraries…** (the palette's "Libraries…"): the program's
  libraries, its own first then theirs (indented, with who needs them), each
  with how it resolved (**linked**, **by name**, **by soname**, **not in
  project**), the program it is (a click opens it), how many imports go
  there, **Link…** (choose the program it is, or "Find it by name") and,
  for one not in the project, **Import…** (the Open dialog's import section
  with the libraries option on). Below, **Imports (N, M resolved)**: each
  import and `library!function`, a click opens it there. Its soname and
  build ID head the list.
- **The Open dialog's details** have a **Libraries** line for the picked
  program (`libmylib.so · libc.so.6 (not in project)`) with **Libraries…**,
  in the Status line's place (the table's Status column has it).
- **The debugger** names a library frame and the pc from the library
  program, and offers **Open libmylib.so at lib_add** (a new tab that then
  follows the pc while it is in the library), as
  [debugger.md](debugger.md#libraries) describes.

Tests: `ui_e2e` (`e2e/libraries.ts`): a program and a shared library built
without libc, imported from the Open dialog with the libraries option; the
thunk's `→ libmylib.so!lib_add` and its References' target; Analyze → Libraries… (by name, two imports,
`lib_twice` resolved); the Open dialog's Libraries line; the thunk's target
opening `libmylib.so` at `lib_add`, whose References list `prog2!_start`'s
call and open it there; under gdbserver, a stop in `lib_add` offering
**Open libmylib.so at lib_add**, the tab it opens marking the pc there and
following it to `lib_twice`, and the mark gone when the session closes.
Screenshots `libraries-*.png` with `RK_SHOTS`.

### Tracing a value across calls

`api_minor` 89, feature `value-trace` ([api.md](api.md#tracing-a-value-across-calls);
`src/ui/trace.ts`).

Right-click a variable, constant or operator in the decompiler: **Trace
value across calls ▸ Where it comes from…** or **Where it goes…** (the
palette's "Trace value across calls: …"). The dialog lists:

- **Calls crossed**: each argument passed to a parameter and each returned
  value taken by a call (`combine → scale: x → v (argument)`); a click goes
  to the call.
- **Each function reached**, the start first, with how far it is (the
  start, a callee n down, a caller n up) and the C lines the traced value
  touches; a click opens the function there.
- **Couldn't follow**: indirect calls, imports, memory, functions nothing
  calls directly, limits, each with the value and the instruction.

The start function's traced tokens are highlighted in the decompiler as a
slice is (Esc clears).

Tests: `ui_e2e` (`e2e/trace.ts`): a program built with `-g`; from
combine's `x`, Where it goes… lists scale, pick and main and not other,
the call into scale, the indirect call and main's missing callers,
highlights `x`, and a line in scale opens scale.

### Build info

`api_minor` 88, feature `build-info` ([build-info.md](build-info.md);
`src/ui/buildinfo.ts`).

- **Analyze → Build info…** (the palette's "Build info (Go modules, Rust
  crates, toolchain)…"): what the file says built it. For Go: the Go
  version, the main module, the package, the target (`GOOS/GOARCH`), the
  VCS revision and time (and "modified"), the layout and the header's
  address, and (`api_minor` 93, feature `go-pclntab`; [go.md](go.md)) the
  **Function table** its functions were named from (`2031 functions, 288
  files · pclntab 1.20 layout at 0x4c6348 (section)`; a Go binary without
  build info shows only this); **Build settings** (each `build` line: `-ldflags`, `-tags`,
  `CGO_ENABLED`, ...) and **Dependencies** (module, version, what replaced
  it, sum); **Copy** copies the module text as `go version -m` prints it.
  For Rust: the root crate, the rustc version and commit, and **Crates**
  (name, version, source, what it depends on; build dependencies marked).
  The filter narrows both tables (any case). A file with none says so; a
  blob that didn't decode shows why.
- **The Open dialog's details** have a **Built with** line for a program
  that has build metadata (`Go go1.22.3 · 14 modules`, `Rust · 52 crates
  (rustc 1.79.0)`) with **Build info…**; nothing for one without.

Tests: `ui_e2e` (`e2e/buildinfo.ts`, when Go is installed): a Go program
built with a dependency replaced by a local directory; the dialog's
version, main module, settings and the replaced dependency, the filter,
and the Open dialog's Built with line and its button.

### Resizable dialogs

Every modal dialog can be resized: the Open dialog (`Ctrl+O`, and the one
a fresh start shows when the daemon has several programs or none), the
palette, the type chooser, the header import, Compare's, the script
editor, the file system browser, About and the rest. One shared piece
does it (`src/ui/dialogsize.ts`, installed once by `main.ts`): it watches
`#overlays` for a `.backdrop` holding a `.modal`, so a new dialog gets it
without code of its own. The sign-in page is not a dialog and doesn't.

- **Grips.** A corner grip at the bottom right (drawn as two diagonal
  lines) and invisible right, left and bottom edges (the pointer shows the
  resize cursor over them). They sit in the backdrop beside the dialog, so
  they stay put when the dialog's content scrolls. The dialog stays
  centered: the edge under the pointer follows it, so the dialog grows
  twice as much as the pointer moves sideways.
- **What grows.** Width is the dialog's. Height goes to the part that
  scrolls (the program list, a table, a tree, a log, a text area: the
  element marked `data-grow`, else the dialog's largest scrolling
  element, preferring lists and tables), so the list gets taller and the
  buttons stay below it; content reflows to the width.
- **Bounds.** At least 280 px wide and 60 px of list; at most the window
  (8 px margins) and the dialog's own maximum height. A size kept from a
  bigger window is shrunk to fit this one, and a window resize keeps the
  dialog inside.
- **Kept per dialog, per viewer**: `localStorage` `rk.dialog:<name>` (the
  dialog's `data-testid`, else its label); a double click on the corner
  grip forgets it and gives the usual size back.
- **Not yet.** No keyboard resizing; the grips are pointer only (the
  usual size fits a 1024×680 window).

Tests: `ui_e2e` (`e2e/dialogsize.ts`): the Open dialog dragged by its
corner 80 px right and down is 160 px wider with 80 px more list, its top
unchanged; dragged far, it stops at the window; after a reload `Ctrl+O`
opens it at the size it had; a double click on the grip gives the usual
size back and forgets it; the palette and About have the grip too.
Screenshots `dialog-open-before.png`, `dialog-open-resized.png` with
`RK_SHOTS`.

## Types: editor and header import

With a daemon that parses C (`api_minor` 25, feature `parse-c`;
[cparse.md](cparse.md)) the types view makes, edits and imports types,
and never lays one out itself: every offset, size, alignment and packing
it shows is the daemon's, for the program's target.

**Import header…** (the button by New…, or the palette's "Import C
header…"; `src/ui/headerimport.ts`):

1. The header: pasted, uploaded (Upload file…, the system chooser
   `filepick.ts` uses), or a file on the daemon's host (Daemon host…, a
   browser of `ListHostFiles`, `src/ui/hostfiles.ts`; the daemon needs
   `--browse-root`, and host files need admin). Include folders (`-I`, on
   the daemon's host; Add folder… browses for one), defines (`FOO=1 BAR
   -UBAZ`) and the target (the program's own, from its compiler spec, or a
   named one such as `x86_64-w64-mingw32`) are shown and editable; options:
   `#define` constants as one enum per file (on by default), C++, and
   retyping functions from the header's prototypes (off by default).
2. **Parse** shows the target used and a preview: the types the header
   declares in three buckets, **new**, **replaces the program's** (same
   name, another layout or members: both C definitions side by side,
   and whether only names or member types differ) and **identical**
   (nothing to do); `<file>_constants` enums with their count; with the
   retype option, the prototypes that name a function of the program, each
   with a box. Each type has a policy: import (replace), skip or rename
   (a name to import it under). The diagnostics are listed below; clicking
   one shows its line, with the lines around it for pasted or uploaded
   text, and the message at its column.
3. **Import** defines what the chosen types need and binds their names, and
   retypes the chosen functions by hash, in one `AppendAssertions`
   (headerImportPlan in `sdk/ts`) with provenance `import:header`, the
   file as its version and a session of its own (under the tab's, so the
   tab doesn't toast its own import): one revision, one undo step, live in
   every tab and for collaborators. Signed in without the admin role, the
   daemon stamps the user instead of `import:header`. A user's own edit of
   a type outranks an import (user > import), so importing a header later
   doesn't override it at the use sites. With categories (api_minor 35)
   the imported types are filed under the header's name.

**The editor** (Edit, or New…; `src/ui/types.ts`, `src/data/cgen.ts`).
The draft is C: fields it didn't change are written by hash
(`__revkit_type_<hash>`, so they keep their exact types), edited ones as
typed (through `__typeof__`), and a probe struct per field measures its
type's size and alignment. ParseC lays it out as the user edits (a
change, debounced) and reports errors at each field's line, under the
field; the status line says the target, size, alignment and whether it is
packed, and "no changes" when the draft is the program's definition
already. Saving defines the laid-out nodes and binds the name: one
revision, one undo, user provenance.

- **Packing**: *explicit offsets* (structs from the program and debug
  info open this way, as Ghidra's unpacked editing): fields stay where
  they are, the bytes between them are rows of undefined filler; *natural*
  (C's rules for the field order: the target's alignments, bitfield model
  and padding; new types start this way), `__attribute__((packed))`, or
  `#pragma pack(N)`. **Alignment**: natural or `aligned(N)`. An explicit
  layout is written as a packed struct with the filler as unnamed
  bitfields; the daemon decides whether it is packed by the rule the
  debug-info importers share, and a field the target's bitfield rules
  can't put where it was asked (Microsoft's storage units) is flagged.
- **Insert at offset…**: a field at a byte offset; in filler it takes those
  bytes (past the end, the struct grows and the gap is filler); over
  fields, they and everything after them move up by its size. A filler
  row's + puts an `undefinedN` there. **Delete** (✕) leaves filler in an
  explicit layout. **Size** grows (filler at the end) or shrinks, but not
  below the last field's end.
- **Bitfields**: the width column, and in an explicit layout the offset
  as `byte:bit` (`0x4:3`).
- **Flexible array**: the last field's `[]` box (`type name[]`).
- **Types**: any C spelling, function pointers included
  (`void (*)(int)`). Member declarations typed where a type goes
  (`int (*open)(const char *path, int flags)`, `int a; char *b;`) become
  fields, names and all; **Paste C…** adds a block of them.
- **Enums**: values are C constant expressions (`1 << 4`, `RED + 2`;
  empty is the previous plus one) the daemon evaluates and shows; a size
  (C's rules, or 1, 2, 4 or 8 bytes) and signedness; move up and down,
  sort by value; a name used twice is flagged.
- **C tab** ("Edit in C" on a type, or the tab in the editor): the type's
  C definition as text, with line numbers. Saving parses it with the
  program's named types in scope and saves every type it declares that is
  new or changed, as one revision; parse errors stay in the editor, marked
  in the gutter at their lines and listed (click to select the line). A
  draft with field edits opens there as readable C; C's rules then place
  its fields.
- **Duplicate…**: a copy under another name (a new type). **Rename…**: the
  definition under the new name, bound, and the old name's binding
  retracted, one undo step (two revisions). Uses by name follow the old
  name's previous binding (a debug-info type of that name, or none). Uses
  by hash (another type's field, a prototype or variable retyped to it)
  keep the definition they name, still printed with the old name, and
  that definition stays listed under it, unbound; renaming a type from
  debug info therefore leaves the debug info's definition as the old
  name's.

**Structures from pointer use and from a selection** (feature
`auto-struct`, [types.md](types.md#structures-from-pointer-use);
`src/ui/autostruct.ts`). Right-click a parameter or local in the
decompiler: **Auto create structure** (also `Shift+[`, as in Ghidra) and
**Auto fill in structure** (for a variable that points to a structure
already). In the listing, select the bytes or data items and right-click
**Create structure from selection**. Each opens a preview the daemon
composes (`TypeService.AutoStructure`): the fields by offset with their
size, type and name, whether each is new, kept (filling in) or from data,
the undefined filler between them, and how many accesses in how many
functions it came from; the name (the daemon's `astruct_N` until one is
typed) and, for a variable, how many calls deep to follow the pointer
(this function only, 1, the default, to 4) recompose it. **Apply** (or
Enter) defines the structure, binds its name and retypes the variable to
a pointer to it (or defines the structure at the selection's start) in
one `AppendAssertions`: one undo step ("Create struct astruct from
param_1"), live in every tab; a fill in with nothing to add can't be
applied. As with any retype of a parameter or local, the declaration
shows the new type; the body is the decompiler's.

With feature `auto-struct-edit` (api_minor 56) the preview's fields are
editable before Apply: a field's **type** (any C type; the type chooser's
names complete it) and **name** are cells, **×** removes a field (its
bytes become filler; **↶** keeps it after all) and **+** on a filler row
adds a field there. A cell commits on Enter, Tab or leaving it (Enter
never applies there); the daemon recomposes with the edits (debounced)
and an edit that doesn't fit is shown under its row ("char[12] is 12
bytes: it runs into field_0x10 at 0x10") while Apply waits for it to be
fixed or dropped. The edits stay across a change of the name or the call
depth. **Ctrl+Enter** applies from anywhere in the dialog. **Open in
Types editor after apply** (remembered per browser) shows the new
structure in the Types view for bigger edits. **Chaining:** right-click a
struct field token (`param_1->field_0x20`) for Auto create structure
(`Shift+[`) or Auto fill in structure: the field is taken as a pointer,
the structure is made from what the code reads through it (the tokens
before the field say which pointer: `param_1`, or
`param_1->field_0x20` for the next level), and Apply defines it and
points the outer structure's field to it, one undo step:
`param_1->field_0x20->field_0x8`.

**Struct fields in the decompiler** (feature `field-tokens`, api_minor
38). A field token (`L->top`, `param_1->field_0x4`) names its struct by
hash and its offset (`CodeToken.parent_type_hash`, `field_offset`).
Right-click one: **Rename field…** and **Retype field…** take the place of
Rename and Set type (`n`/`F2` and `y` on a selected field do the same).
Each makes the struct's next version with that one field changed, laid out
by the daemon as the editor's Save does (other fields stay where they
are), and binds the struct's name to it: one `AppendAssertions`, one undo
step ("Rename field astruct.field_0x4 → count"), shown in every use of the
struct in every tab. A field whose struct the daemon couldn't name, or a
struct with no name of its own (an anonymous member's, a typedef of an
anonymous struct), says so rather than editing; it is edited in Types,
through the type that holds it.

**Rename on what can't be renamed.** In the decompiler, Rename acts on the
selected token: a function, global, parameter, local or field. A token
that names nothing (a keyword, a constant, an operator, a type in the
body) says "Nothing to rename here" and never renames the function, as it
did before. With no token selected, or on a token of the signature line,
Rename is the function's, as on the listing's header and signature rows.

**Folders, archives** (feature `type-archive`, api_minor 35;
[types.md](types.md#type-archives)). The tree is by folder (the **Group**
select keeps the kind tree, remembered): the program's types under their
categories, which the debug info gives (the header that declared each
type), a header import gives (the header's name) and an archive's import
keeps, those with none at the top, and the library archive by kind.
Folders load their types as they open, a page at a time; a small
program's open by themselves. **Drag** a type onto a folder (the top
included) or use **Move to category…** on the shown type (a path such as
`/net/http`; folders are made as needed) to file it there: one undo step,
live in every tab. A search lists matches from every folder.

- **Export archive…**: the shown type (and what it references), a folder
  and its subfolders, the types made, edited or imported in revkit, or all
  of the program's; the daemon writes the header and the sidecar and both
  download (`<name>.h`, `<name>.json`); notes list what the header can't
  reproduce. Exporting what an archive imported gives the same files.
- **Import archive…** (also in the palette): the header import's dialog
  for an archive: both files uploaded together (or pasted), parsed for the
  sidecar's data model and checked against its hashes ("N of N types match
  the sidecar's hashes"; mismatches, or a header edited since, are named
  and block the import), the same preview (new, replacing, identical, a
  policy each); Import defines and binds them and files them under the
  archive's categories in one undo step, with provenance `import:archive`
  and the archive's origin.

**Project types and archives** (feature `project-types`, api_minor 52;
[types.md](types.md#project-types)). The tree has a **Project types**
branch: the project's types, which every program of the project sees
(the Program source includes them; the Project source shows them alone);
a project type's origin line starts with "project". On a program's
type, **Move to project** makes it the project's (one undo step, live in
every tab of every program); on a project type, **Copy to program**
gives this program its own copy. Editing a project type (the editor, Edit
in C, Rename Field, Retype Field) edits it for every program. The
**Archives** button opens a section listing the type archives whose
prototypes the project applies to imports by name: revkit's library
archives for this program (libc, the Windows API), Ghidra's, and those
attached to the project, each with a switch (on or off for every program,
one undo step), how many functions and types it gives the program, and
where it came from; **Attach archive…** uploads a header (and its
sidecar), **Detach** removes an attached one.

**C wherever a type is asked for.** The retype dialog (`y`) checks the
declaration with ParseC as it is entered (as a type name, or a
declaration with a name), and takes definitions before it: `struct ctr {
int n; }; struct ctr` defines and binds `struct ctr` and retypes to it in
one request. Apply and the return type of a function go through ParseC
too; `src/data/ctype.ts` is kept only for daemons without `parse-c`, and
guesses no alignments.

## Memory map

With the daemon's `memory-map` feature (`api_minor` 24,
[memory-map.md](memory-map.md)), the **Memory map** view
(`src/ui/memmap.ts`, `Ctrl+Shift+M`, a main-area tab; "Show memory map"
in the palette) is Ghidra's Window → Memory Map: a table of the program's
blocks in address order (name, start, end, size, permissions,
initialized, volatile, where the bytes come from, and who added or last
edited it: `loader` for the image's own, colored like other provenance).
Against an older daemon it lists the blocks without editing.

- **Add region…** (`a` in the table; palette "Memory map: add a region"
  and "Memory map: add bytes from a file") opens the region editor
  (`src/ui/regionform.ts`): the kind (uninitialized RAM, zero-filled,
  memory-mapped I/O, bytes from a file), name, start and size in hex,
  read/write/execute, volatile; for bytes from a file, **Upload…** (the
  timed file chooser, `src/ui/filepick.ts`) or **Daemon host…**
  (`src/ui/hostfiles.ts`, the daemon-host browser the header import uses,
  when the daemon has `host-files`), an offset and a
  length. The daemon's error (an overlap names the block) shows under the
  fields and the form stays open.
- The pencil (`e`, `F2`) changes a region (everything but its bytes) or
  an image block (its name, permissions and volatile flag; start and size
  are fixed); the cross (`Delete`) removes a region; ↺ reverts an image
  block's edits. Regions the map can't place (after an undo or concurrent
  edits) are listed struck through, "not mapped", with the reason.
- Each change goes on the tab's undo stack (`Ctrl+Z`, and the toast's
  Undo); its revision's event invalidates the whole program, so every view
  here and in other tabs and clients reloads (the listing, functions,
  decompiler, graph, data). `Enter` or a click goes to a block's start.

**Set image base…** (API 42, feature `rebase`; palette "Memory map: set
image base") moves the whole program, with everything recorded about it,
to another base ([memory-map.md](memory-map.md#rebase-setting-the-image-base)):
a dialog shows where the program is and where it was imported, checks the
new base with the daemon (`validate_only`, so a base the image wouldn't
fit at is said in the dialog), and commits one edit on the undo stack
(`Ctrl+Z` moves it back). The cursor and the back/forward history move
with the program.

The region editor is a standalone component;
the Open dialog's raw regions (a text area) could adopt the editor.
`ui/e2e/memory.ts` (run by `e2e/run.ts`) imports a hand-assembled ARM
firmware and adds RAM (its read becomes `DAT_20000000`), a refused
overlap, a bootloader's bytes from the daemon's host (its function
appears), a volatile edit, an image block's rename and revert, and a
removal undone with `Ctrl+Z`, followed live in a second page
(screenshots `memory-map.png` and `memory-map-form.png` with `RK_SHOTS`),
and Set image base moving the program (a rename with it) and `Ctrl+Z`
moving it back.

## Compare (version tracking)

With the daemon's `diff` feature ([diff.md](diff.md)), **Tools: Compare
programs…** in the palette picks the analysed program (A) and the new one
(B, this tab's by default) and runs a DiffService session; the **Compare**
view (`src/diff/view.ts`, Ctrl+9, a main-area tab) shows the run's phase
and progress, then the match table: A's and B's functions, tier,
confidence (coloured: green at or above the 0.95 auto-apply threshold,
amber from 0.8, red below), similarity, status and change, sortable by
clicking a column and filtered by tier, status, change kind, least
confidence and name; the functions only one side has, with their
candidates, and **what changed** in each modified pair, in a line
(`SummarizeFunctionDiffs`, loaded after the table: "1 instruction changed:
sub r0,r0,#0x7 → bl FUN_00000400 (new)"; the full text on hover).
**a** accepts and **r** rejects the selected match, **Enter** goes to it.

**Manual matching** (feature `function-compare`, api_minor 54): **m**
matches the selected function by hand with one picked from the other
program (a picker by name, the candidates first; `SetMatch`), **u**
unmatches a decided pair (accepted, applied or rejected: `Unmatch`, so the
matcher's proposal applies again, and anything ported through the match
goes with it). In *Only in A* / *Only in B* each candidate is a button
that matches the row with it. Right-clicking a row gives the same actions
(Accept, Reject, Unmatch, Match with…, Go to). Each decision is one undo
step: Ctrl+Z when B is this tab's program (the decision's ops, returned by
the daemon, are retracted), or the toast's Undo.

### Compare two functions

Any two functions of the project, in one program or two, with no session
(feature `function-compare`; `CompareFunctions`): **Compare with…** in a
function's context menu (the listing, the decompiler, the palette's
"Compare function with…") or a row of the function list picks the other
function (any program, by name), and the Compare view shows the pair in
the same Listing, Graph and C panes, without the table: the header names
both (**Swap**, **Close** goes back to the session). In the function list,
**Ctrl+click** marks up to two functions and the context menu's "Compare
the marked" opens them. Calls correspond within one program by address,
across two by name (no default names), so a call to `strcmp` on both sides
is equal.

**Token-level apply** in the C pane: the daemon pairs the two
decompilations' variables (parameters by position, locals by the
instructions and C lines that print them) and the header counts them; a
variable named differently on the other side is underlined. Right-click a
token: a variable's **Apply name** or **Apply type** to the other side,
the function name's **Apply name** and **Apply signature**, a comment's
**Apply this comment** (or a line's comments), **Apply all** (only what
the other side lacks: default names and the decompiler's guesses) and
**Apply all, replacing**. **Apply all A → B** and **Apply all B → A** in the
pane's header do the same for a whole side. Each apply is one revision by
you (`PortFunctionMarkup`, provenance user, each assertion recording where
it came from in `ported_from`) and one undo step: Ctrl+Z when the target
is this tab's program, else the toast's Undo. A single token's apply
replaces what the other side has; a name another variable of the target
already has is refused with a warning.

**Inside the selected pair** (feature `diff-detail`; `GetFunctionDiff`
with `detail`, cached per pair until the session is invalidated, and
memoized by the daemon, so reopening a pair is instant), the lower half
shows one of three panes, chosen by the segmented buttons (remembered;
**Space** toggles the listing and the graph):

- **Listing** (`src/diff/aligned.ts`): both functions' instructions
  aligned by the instruction map, in one virtualized scroll container (so
  the sides can't drift apart, and a 20,000-line function scrolls like a
  short one). Corresponding instructions share a line, a hatched gap marks
  the side that has nothing; changed rows are amber with the differing
  tokens emphasised (an LCS over the two rows' tokens), inserted rows (B)
  green, deleted rows (A) red, rows that moved out of order blue, equal
  rows dimmed; a thin rule separates basic blocks. A call into a function
  that only B has carries a **new** badge. The header counts the
  differences (runs of lines that aren't equal: "1/3 differences · 2
  changed, 1 inserted") with ↑/↓; **n** / **p** go to the next and
  previous difference anywhere in the view (the table, the listing, the
  graph), wrapping around; a pair opens at its first difference. The
  palette has "Compare: next/previous difference" too. (`n` is rename and
  `F8` the debugger's step elsewhere; the Compare view owns its keys.)
- **Graph** (`src/diff/graph.ts`, the *graph diff*): both CFGs from the
  detail's blocks, edges and block map. **Side by side** is the default:
  ELK lays out the *union* of the two graphs once (a matched pair of
  blocks is one node sized for either side, a block only one side has a
  node of its own), and each side draws the nodes and edges it has, with
  pan and zoom shared, so a matched block sits at exactly the same place
  in both panes and an added or removed block leaves a hole on the other
  side. Unchanged blocks are neutral, modified amber, added green, removed
  red (a coloured header band and tint); edges both sides have are
  neutral, A's alone red, B's alone green. **Merged** (the button or
  **m**) draws the union as one graph with each node tagged A, B or A+B
  and a modified pair's lines interleaved (− red, + green). Side by side
  is the default because each pane stays one program's real code, read
  like the function graph, while the shared layout still lines the pairs
  up; merged is more compact but no node reads as either program. Clicking
  a block selects its partner and scrolls the listing to it. Drawing is
  culled with a bar-per-line level of detail like the function graph:
  on a 2,000-block pair, layout 0.47 s (merged 1.0 s) in ELK's worker and
  frames under 3 ms uncapped (bench/RESULTS.md, `bench/diffgraph.ts`).
- **C** (`src/diff/decomp.ts`): both functions decompiled side by side,
  lines aligned by LCS over their text (variables and default names
  abstracted), a line
  amber, green or red when a token on it was printed from a changed,
  inserted or deleted instruction (tokens carry instruction addresses).
  Clicking a line selects its instruction in the listing.

The dockable **Graph diff** view (`diffgraph`, Ctrl+Shift+9, at the side
by default) is the same graph diff, following the pair selected in
Compare, so the listing and the graph can be seen at once. **Apply markup…**
chooses items (names, comments, prototypes), threshold, policy and scope
with a live dry-run preview, and applies as one revision, undone by
Ctrl+Z (when B is this tab's program: the run's assertions are an undo
step) or the toast's Undo (RevertApply). The provenance popover says where
a ported value came from. `QUERY_KIND_DIFF_SESSION` invalidations reload
the table when shown.

## Patching

With the daemon's `patch` feature ([patching.md](patching.md)),
`src/patch/patch.ts`:

- **Ctrl+Shift+G** (Ghidra's Patch Instruction) turns the selected row into
  an inline editor over the listing, holding the listing's text. Each
  keystroke assembles (`PatchService.Assemble`, debounced 120 ms) and the
  list shows the encodings (bytes, size, "current" or bits changed); a
  syntax error shows a caret under the column and what was expected; while
  a mnemonic is typed, or on Tab / Ctrl+Space, the list shows completions
  (Tab inserts). Enter writes the highlighted encoding
  (`PatchInstruction` with its bytes), recorded as an undo step; options:
  pad with NOPs, Thumb (ARM programs). Neither key was bound before;
  Ctrl+Shift+P (commands) and Ctrl+Shift+Z (redo) are unaffected, and the
  browser has no default for either.
- **Ctrl+Shift+H** (Ghidra's Patch Data) edits the selection's bytes as hex
  or ASCII in a dialog; Ctrl+Enter writes the changed span (`PatchBytes`).
- Rows with `ListingRow.patched` get the theme's `patchedRow` tint, a
  `patchMark` bar at the gutter's edge, and their changed bytes (against
  `original_bytes`) underlined; the graph tints patched lines and outlines
  their blocks.
- The **Patches** view (side dock) lists `ListPatches` (reloaded on
  `QUERY_KIND_PATCHES`): address (goes there), was → now, function, bytes,
  who; Revert per patch, Revert all, Export…, Compare with original.
- **Export** dialog: format, the fixups (checksum over a range into the
  file name or a field, PE CheckSum), Detect from a file name or value
  (hits with their evidence; Use adds the spec and its template), the file
  name template, Save settings, Export (downloads the verified bytes and
  shows the verification).
- **Compare with original**: `OpenOriginal`, then a DiffService session
  "original vs patched" shown in the Compare view
  (`DiffView.openSession`).
- Palette: *Patch instruction (assemble)…*, *Patch bytes of the
  selection…*, *Show patches*, *Export the patched program (checksum
  fixups)…*, *Revert the patch here*, *Compare with original*.

The e2e (`e2e/run.ts`, "patching") patches an immediate in the listing,
undoes and redoes it, assembles a call by name, checks page B, reverts
from the Patches view, exports with a 32-bit sum in the file name
(checking the downloaded bytes, the sum and the name) and opens Compare
with original.

## Listing edits (Clear, Disassemble, Data)

With the daemon's `listing-edit` feature (API 30;
[listing-edit.md](listing-edit.md)), the listing edits what bytes are, as
Ghidra's Clear Code Bytes, Disassemble and Data menu do
(`src/ui/listingedit.ts`). Every action is one `AppendAssertions` call
(`listing_edit` or `mutability` bodies, `src/data/edits.ts`), so one undo
step on the tab's stack with a label ("Clear 12 bytes at 0x401000",
"Define dword at 0x404010"), blame in the provenance popover and live
updates in every page; nothing changes on screen until the subscription's
`LISTING` invalidation refetches the rows.

| Key (listing) | Action |
| --- | --- |
| `d` | Disassemble here: code starts at the cursor (as the context says) |
| `c` | Clear: the selected rows' bytes (or the code unit at the cursor; on a field row, its whole item) become undefined; functions starting there go |
| `b` | Cycle: the item at the cursor becomes a byte, and each press the next of word, dword, qword (a row that isn't one of them starts at byte) |
| `'` | char |
| `"` | string (UTF-8, up to its terminator) |
| `[` | array: asks `type[count]`, the element type being the cursor's defined item (else `byte`) and the count filling the selection (or the row: an undefined run) |
| `t` | choose a type: Set type's chooser (C types, Ghidra's `byte word dword qword sbyte … char float double pointer`, the program's structs, unions, enums and typedefs); `type[n]` is an array |
| `p` | pointer (the program's pointer size) |
| `+` (or `=`), `-` | expand or collapse the data item at the cursor (or the item of the field row at the cursor) |
| `Shift+B` | show or hide the bytes column (was `b`) |

**The clash.** `b` toggled the bytes column; Ghidra's `B` is the data
cycle, so the cycle takes `b` and the bytes column moves to `Shift+B`
(palette: *Show/Hide bytes column*). Against a daemon without the feature
the editing keys only say so (a toast). `c` is the graph's collapse key in
the graph view (its canvas handles it first), and every editing key acts
only while the listing has the focus, so the graph and the decompiler keep
theirs. Space stays the listing/graph switch, which is why expand and
collapse are `+` and `-` (Ghidra's toggle on a data item's `+`).

A **selection** longer than one item, defined with a fixed-size type
(byte … pointer, a chosen type), asks first: an array that fills the
selection (`dword[8]`), or one item. A string over a selection asks for a
fixed length (the selection's characters) or up to the terminator. Data is
defined, and code disassembled, at the code unit at the cursor, or at the
start of a selection of several rows; on a field or element row the UI
refuses (clear the item first, or change its type in the Types view), as
the daemon would otherwise drop the whole item under a newer edit.

**Menus.** The listing's right-click menu has a listing-edit group after
the function edits: *Disassemble here*, *Disassemble and create function*,
*Disassemble as ARM* and *as Thumb* (ARM languages other than Cortex-M,
where both instruction sets exist), *Clear code bytes*, *Clear flow and
repair* (feature `clear-flow`, `api_minor` 83: the code only the flow from
the instruction at the cursor reaches, in one undo step; a toast says how
many instructions went and how many other code keeps;
[listing-edit.md](listing-edit.md#clear-flow-and-repair)), a **Data** submenu
(cycle, byte, word, dword, qword, char, string, UTF-16 string, Pascal
string, float, double, pointer, array…, choose type…, then constant,
volatile, writable (normal) and the memory map's default for the
selection), a **Recently used** submenu (the last five definitions, newest
first, kept per browser in `rk.recentData`; picking one defines it at the
cursor as it was, arrays with their count) and *expand* / *collapse* on an
item with fields. `src/ui/menu.ts` gained submenus for this (→, Enter, a
click or hovering opens one; ← or Escape goes back). Every action is also
in the palette (*Disassemble here*, *Clear code bytes*, *Clear flow and
repair*, *Data: …*), with its key. `ui/e2e/run.ts` ("clear flow: …")
checks Clear flow and repair and its undo.

### Fallthrough overrides

With the daemon's `fallthrough-override` feature (`api_minor` 85;
[api.md](api.md#fallthrough-overrides)), the listing's right-click menu
has, after *Clear flow and repair*, Ghidra's *Set fallthrough…* (on an
instruction) and *Clear fallthrough* (on one with an override); both are
in the palette too. *Set fallthrough…* asks for the address control goes
on at after the instruction (an address, `space:offset` or a symbol; it
starts at the current fallthrough), empty for none, and writes one
`SetFallthrough` assertion (`Edits.fallthroughBody`): one undo step, "Set
fallthrough to 0x401010 at 0x401000". An overridden instruction shows `⤷
fallthrough: <address>` (or `⤷ no fallthrough`) in the override colour
after its operands, and the listing draws a flow arrow from it to the
address (Ghidra's fallthrough arrow); `i` on the mark shows who set it,
and the references view names the reference `fallthrough`.
`ui/e2e/listingedit.ts` ("listing edit: the menu's Set fallthrough… …")
checks setting, clearing and undoing it on two pages.

**Data rows.** A data row shows its type and its value (or the symbol a
pointer points at; analysis's data rows now show their values too). A
defined item with fields or elements (`data_components` > 0) has a
disclosure marker before its type, `+` collapsed and `−` expanded; a click
on it toggles. Expanded, the daemon sends a row per field or element right
after the item (`data_field` "magic", "[3]", `data_parent`, `data_depth`),
drawn indented by depth with the field's name before its type. Expanding or
collapsing asserts the item's definition again (read from `Blame` on
`CODE_UNIT` / `data` at the item) with `collapsed` flipped, so it is an
undo step and every page follows. Arrays come collapsed, structs expanded,
as the daemon's default.

**Provenance.** A row's `unit_origin` (who cleared, disassembled or
defined it) and `mutability_origin` show in the popover: `i` on a row
lists its usual fact (name, comment…) and below it the listing edit and
the mutability edit, each with its history and *Undo (retract)*; hovering
a data row's type or a field shows the listing edit. Their keys are found
from the winning assertion's seq (`ListAssertions` by kind up to the
row), since a Clear's or a mutability edit's key holds its length. A row
under a mutability edit has a badge after its value: `[const]`,
`[volatile]` or `[writable]`.

The e2e (`e2e/listingedit.ts`) selects `twice`'s rows and presses `c`
(the function leaves the list, the bytes are undefined, page B follows),
`d` disassembles it again, the menu's *Disassemble and create function*
brings the function back, and undo restores it; on printf's format string
(data needs bytes: the daemon refuses uninitialized memory such as
`.bss`), `b` defines a byte and cycles it to a word, `'` a char, `[` a
`byte[4]` that `+` expands and its marker collapses, `i` names user:e2e,
`Shift+B` toggles the bytes column; `"` makes it a string again, the Data
submenu marks it constant (`i` shows the mutability) and the Recently used
submenu redefines it; Ctrl+Z undoes every step.

## Data settings

With the daemon's `data-settings` feature (API 84;
[listing-edit.md](listing-edit.md#data-settings)), the Data submenu (and
the palette's *Data: settings…*) has **Settings…** on a data row: Ghidra's
Data Settings and Default Settings in one form (`src/ui/datasettings.ts`).
*Apply to* chooses this item (on a struct field's row, that field; on an
array's element, the array) or *Every `<type>`*, the type's default
settings (the row's `data_settings_type`: `uint32_t`, `string`,
`pointer`, `undefined4`). The form offers what applies to the row's
value: for integers the format (hex, decimal, octal, binary, char),
signedness and padding; the byte order for anything but a struct; for
strings and char arrays the charset (US-ASCII, ISO-8859-1, windows-1252,
UTF-8, UTF-16, UTF-32 and their LE and BE forms) and termination (at the
first NUL, or every character); for pointers absolute, image-base offset
or relative, with a mask and shift; and on an item its mutability
(constant, volatile, writable, as the memory map says). Each starts at
the row's own setting ("Default" when unset), and a line under them names
the type's defaults the item falls back to. *Save* asserts the settings
(and the mutability) in one `AppendAssertions`, one undo step ("Data
settings of dword at 0x404010"); *All default* removes them. The row
shows the new value once the subscription refetches it, in every page.

The e2e (`e2e/listingedit.ts`, "data settings: …") makes a word of
printf's format string, sets it to decimal (page B follows), sets every
word's default to binary under it (the row stays decimal: its own wins),
then *All default* shows the type's binary, and Ctrl+Z undoes every step.

## Equates and references

With the daemon's `equates` and `user-references` features (API 39), the
listing and the decompiler show a scalar as the user says and the user
adds and deletes references, as Ghidra's Convert, Set Equate and
References menus do (`src/ui/equates.ts`, `src/ui/references.ts`). Every
action is one `AppendAssertions` call (`operand_display` or `reference`
bodies, `src/data/edits.ts`), so one undo step on the tab's stack ("Set
equate GK_LETTER = 0x41 at 0x10116d in the function"; an *apply to* that
touches many operands is still one step), blame in the provenance popover
(`i` on the operand: the equate or conversion, or the primary reference's
assertion) and live updates in every page.

| Key | Action |
| --- | --- |
| `E` (Shift+e) | Set equate on the scalar operand at the cursor (the row's only scalar, or a choice), or on the decompiler's selected constant |
| `R` (Shift+r) | Add reference from the instruction at the cursor (listing) |

Neither key was bound. **Set equate** is Ghidra's SetEquateDialog: a name
field whose dropdown (the type chooser's) lists the equates that already
have the scalar's value and the enum members of that value
(`FindTypes{enum_value}`, the program's enums first, then the
libraries'), picking a member asserts the enum member rather than a plain
name; *Apply to* this operand, matching scalars in the function, or in the
program. The daemon's refusal (one name has one value) shows in the dialog,
which stays open. A decompiler constant is sent with its instruction,
value and `constant_hash`.

**Menus.** On a scalar operand (right-click it; the click picks the
operand) and on a decompiler constant, the right-click menu has a
**Convert** submenu, each item previewing the value (Hex, Signed decimal,
Unsigned decimal, Octal, Binary, Char, Float for 32- and 64-bit scalars,
and Default to clear), *Set equate…* and *Remove equate*. The listing's
**References** submenu has *Add reference from here…* (to an address or a
symbol, with symbols dropping down; the type, Ghidra's RefTypes; the
operand at the cursor or the instruction; primary), *Delete a reference
from here…* and *Set the primary reference…* (each picks one of the
instruction's references) and *Show the References window*. Every action
is in the palette too (*Convert scalar to …*, *Set equate…*, *Add
reference from here…*).

**Windows.** **Equates** (side dock) folds the effective EQUATE
assertions whose display is a name (there is no equates RPC): name, value,
uses; selecting one lists its uses (a click goes there; Enter goes to the
first); *Rename…* and *Remove* act on every use as one edit. **References**
(side dock) follows the code unit at the cursor: its references from and
to it (`GetXrefs` BOTH) with the type, operand, primary (★) and source
(the user's name for an asserted reference, else analysis), *Set primary*
and *Delete* per row and *Add…*. Delete asserts `remove` at the
reference's key, which also takes analysis's references from → to out of
xrefs; Set primary asserts the reference as the user's (its type from the
xref's kind) and demotes the operand's other primary user references in
the same edit, as Ghidra keeps one. Both windows reload on the
subscription's events. The xrefs dialog (`x`) badges a user's reference
with who made it.

The e2e (`e2e/equates.ts`, on `grade()` of the test program: `cmp edi,
0x41`, `add eax, 0x41` and a call through a function pointer) converts
0x41 to Char from the listing's menu ('A' in the listing and the C, page B
too; `i` names user:e2e); defines an enum and presses `E` on the
decompiler's constant, picks the suggested member and applies it to the
function (both operands, both views, both pages); the Equates window lists
it with 2 uses, goes to one, renames it everywhere, refuses the name for
0x3 in the dialog and removes it; `R` adds a primary computed call to
`twice` (the C calls `twice`, the References window and the xrefs say
user:e2e), a second reference is made primary from the window, and an
analysis jump reference is deleted from the References submenu; Ctrl+Z
undoes every step.

## Byte viewer, navigation and the overview

With the daemon's `byte-viewer`, `find-next` and `overview` features (API
44; [api.md](api.md#byte-viewer-overview-and-navigation)), Ghidra's Bytes
window, its next/previous actions, address expressions, the overview
bars, Copy Special and a few of its optional listing fields. Checks in
`e2e/byteview.ts` (screenshots `byte-viewer.png`, `overview.png` and
`listing-fields.png` with `RK_SHOTS`); the expression evaluator and Copy
Special's formats have unit tests (`test/unit.ts`, CTest `ui_unit`).

- **The Bytes view** (`src/bytes/viewer.ts`; a side-dock tab, palette *Show bytes*;
  Ghidra has no key for it either): an address column, hex, and ASCII, and from its
  **Columns** menu octal, binary, UTF-16 (in the program's byte order) and
  signed integers of the group's size. **Bytes a line: auto** (the
  default: the most of 32, 16, 8 or 4 that fit the pane's width with the
  columns shown, so the 520 px side panel doesn't scroll sideways; the
  menu says what it chose, "auto (8) / line", and it follows the pane as
  it is resized or the columns change) **or 8, 16 or 32**, in **groups of
  1, 2, 4 or 8** (a group is never wider than the line; all remembered per
  browser, as are the columns).
  Lines run over the memory blocks and skip the gaps between them; bytes
  outside every block are blank, uninitialized ones `??`. Each byte is
  tinted by what the listing makes of it (code, data; undefined bytes
  dim), the cursor's code unit is underlined, and patched bytes are tinted
  orange with an underline and say what the file had in their tooltip.
  `GetByteView` supplies a screenful and one either side; an edit's
  `LISTING` invalidation refetches what is shown.
- **Synced both ways.** The listing's cursor (and so the decompiler's,
  which drives it) moves the viewer's cursor to the code unit, unless the
  viewer's cursor is already inside it; a multi-row selection in the
  listing selects its bytes here. A click on a byte moves the listing to
  the code unit holding it; Shift+click, a drag or Shift+arrows select a
  range of bytes, which selects the rows over it in the listing (the
  viewer keeps its own byte-exact range). Arrows, Page Up/Down and
  Home/End move the cursor; the wheel scrolls. **Follow** off pins the view
  where it is (a snapshot), and Ctrl+C in it copies the selected bytes as
  hex.
- **Edit** (off by default, as in Ghidra; with feature `patch`): typing
  hex digits over the hex column, or characters over the ASCII column (Tab
  switches; the cursor's box says which), changes the byte at the cursor
  and moves on; Backspace steps back. Typed bytes show in italics until
  they are written: after a quarter second of no typing (or Enter, leaving
  the view, or Edit off) they go out as one `PatchBytes` per contiguous
  run, and every write of an **edit session** (Edit on to Edit off) is one
  undo step ("Edit 3 bytes at 0x…": `Edits.recordSession`), however many
  writes it took. Uninitialized memory can't be edited (the daemon would
  refuse too). The listing, the decompiler and other tabs follow from the
  subscription as for any patch.
- **Next and previous** (`QueryService.FindNext`): Ghidra's keys,
  `Ctrl+Alt+I` instruction, `D` data, `U` undefined, `L` label, `F`
  function, `V` a different byte value, `B` a note (Ghidra's bookmarks),
  with Shift for previous, and `Ctrl+Alt+↓` / `↑` for the kind used last;
  every one is a palette entry (*Go to next instruction*, …). Instruction,
  data and undefined go by runs: the next instruction is the first one
  after the run of instructions the cursor is in. From the byte viewer
  (when it has the focus) they start at its cursor. "No next label" when
  there is none. (Ctrl+Alt+arrows may be taken by the desktop on some
  Linux setups; the letters and the palette always work.)
- **Go To expressions** (`src/data/expr.ts`) in the palette
  (`Ctrl+K`, `g`): `main+0x10`, `checksum - 8`, `0x1000 + 4*3`,
  `(sym - 8) / 2`, `file:0x200` (a file offset, through the memory map's
  file offsets), `mem:0x100` (a space). Numbers are hex, as Ghidra's and
  as the listing shows addresses (`0x` optional, `h` suffix allowed);
  a name of only hex letters (`add`) is the symbol when one exists, else a
  number; names are looked up exactly (`ns::f` included). The result is
  one "Go to …" item with the expression (and the file offset) beside it;
  an error is an item saying what is wrong ("no symbol \"nosuch\"").
  **Wildcards** (`FUN_*`, `str?cpy`, `*alloc*`) list every matching symbol
  (functions and labels, from `ListSymbols` by the longest literal part,
  then matched here), up to 200.
- **History**: the toolbar's **▾** beside Back and Forward lists the
  places you went (forward ones above, back ones below, newest first, with
  the function and offset when known); choosing one goes there and keeps
  the rest as back and forward history. Also *Navigation history…* in the
  palette.
- **Overview bars** (`src/listing/overview.ts`): two thin bars right of
  the listing's scrollbar, over every memory block in address order (each
  in proportion to its size, a rule between blocks): one coloured by kind
  (code, data, undefined, external, uninitialized), one by entropy (cool
  for low, hot for high). A line marks the cursor; a click or a drag goes
  there; the tooltip names the block, the kinds' shares and the entropy.
  `GetOverview` is asked for about one slice per device pixel of height,
  again after edits (debounced) and when the bars grow. Hidden from the
  Fields menu or the palette (remembered).
- **Copy Special** (`Ctrl+Shift+C`, palette, the listing's right-click
  menu; `src/data/copyformats.ts`): the listing's selection (or the code
  unit at the cursor), or the byte viewer's when it has the focus, as a
  hex string, spaced hex bytes, a C array, Python bytes, Base64, an
  address list (the selected rows, or the code units in the viewer's
  range), or the listing's text as shown. Up to 1 MiB; uninitialized bytes
  copy as zeros, with a warning. (A browser may keep `Ctrl+Shift+C` for
  its developer tools; the desktop app and the palette don't.)
- **Fields menu** (top right of the listing's column header): the bytes
  column, then **File offset** (where the code unit's bytes are in the
  imported file, from the memory map), **Function offset** (`main+0x1c`),
  **P-code** (each instruction's raw p-code, `⟨ RAX = INT_ADD RAX, 0x8 ;
  … ⟩`, after its operands, from `ListInstructions` for the rows in view)
  and **References on labels** (`XREF[3]: 401020(c), 401088(j), …` after a
  label row's name: the first three referrers with Ghidra's one-letter
  kinds, from `GetXrefs`; an address there is a token, so double-click
  follows it); and the overview bars. Remembered per browser. P-code sits
  on the instruction's own line, not on lines under it as in Ghidra: rows
  are one line each in the daemon's numbering (a p-code numbering would
  need every instruction lifted to count rows). The XREF list is on header
  label rows (the default); with labels in a column (no header rows) the
  count stays as before.

## Scripts

With feature `scripts-host` (`api_minor` 31; [scripting.md](scripting.md)
for the service, its safety defaults and the script API), the daemon runs
Python scripts for the page; `src/scripts/` is the UI for it.

- **Script Manager** (`src/scripts/manager.ts`, a dock tab, the side by
  default, **Ctrl+Shift+S**; `Ctrl+9` is Compare's): every script
  `ListScripts` returns (shipped, the daemon user's
  `~/.config/revkit/scripts`, the project's `scripts/`) in a tree by
  `@category`, with a search box (Enter runs the first match). A script's
  details show its description, `@context`, `@arg`s, id and hash, with
  **Run**, **Edit** (or *View source* for a shipped one) and **Bind key**.
  A banner says when the daemon won't run scripts for this page
  (`host_disabled_reason`: a non-loopback daemon without
  `--scripts-host-role`, a viewer) or has no Python that can import
  `revkit`, or only one whose SDK is older than the daemon
  (`python_problem`, with the setup hint; the Python console shows the
  same message and its own **Set up Python**). With no Python, or a
  stale SDK, the banner's **Set up Python** makes or updates one in a click (`SetupScriptPython`,
  as `rk-script setup` does: `~/.local/share/revkit/pyenv` from the SDK
  the daemon ships): its steps show in the output panel as they run, then
  the scripts are listed again and the banner goes (or the error stays,
  saying what to install).
- **Everywhere.** Every script is a palette command ("Run script
  <name>", its description dimmed beside it; the filter matches either); its `@keybinding` (`normalizeKeybinding`:
  "ctrl shift R" is Ctrl+Shift+R) or a key bound in the manager (kept per
  browser, `localStorage` `rk.scriptKeys`; an empty binding removes the
  script's own) runs it, after the built-in keys; `@context function`,
  `selection` and `address` scripts are at the end of the listing's and
  the decompiler's right-click menus when there is a function at the
  cursor, a selection of several rows, or an address. A run gets the
  cursor (`current_address`, so `current_function`) and the selection;
  while it runs, moving the cursor sends `UpdateContext`.
- **Output panel** (in the manager): the console (stdout, stderr in the
  warning colour), a progress bar (indeterminate without a maximum) with
  the monitor's message, **Cancel** (`CancelScript`: the host is
  cancelled, then killed 2 s later), the status and time, and for a
  failure its message, a link to the script's line in the editor and the
  traceback (the daemon writes file paths as script ids).
- **Prompts** use the standard dialogs: `ask_string`, `ask_int`,
  `ask_float` (checked as numbers), `ask_address` (the cursor by
  default), `ask_file` in `ask`; `ask_yes_no` and `ask_choice` in
  `choose` (the default marked); `ask_choices` in a check-box list.
  Escape answers "cancelled", which cancels the run.
- **Trust.** A per-user or project script the user hasn't confirmed at
  this hash (a first run, or a change since their last run or save) shows
  its id, full SHA-256 and source before anything runs; **Run it** pins
  the hash (the daemon keeps the pins), so it isn't asked again until the
  text changes. Shipped scripts are trusted like the daemon.
- **Undo.** A run's committed assertions (`ScriptResult.seqs`) are one
  entry on the tab's undo stack (`Edits.record`), so Ctrl+Z takes back the
  whole run, in every page; the views refresh from the subscription as for
  any edit, and the page doesn't toast its own runs' revisions. **Recent
  runs** (`ListScriptRuns` and this page's own) each have **Revert this
  run**: `RevertByProvenance` on the run's session, itself one undo step.
  "Scripts: revert a recent run…" in the palette picks one.
- **Editor** (`src/scripts/editor.ts`): CodeMirror with a small Python
  stream mode (`src/scripts/python.ts`: keywords, builtins and the flat
  API's names, strings, numbers, comments, decorators), line numbers,
  history and indentation (`@codemirror/commands`), for per-user and
  project scripts. **Save** (Ctrl+S) is `SaveScript` with the hash last
  read, so someone else's change in between is refused rather than
  overwritten; **Save and run** (Ctrl+Enter). "New…" in the manager starts
  a script in your library or the project's from a template. Shipped
  scripts open read-only with **Copy to my scripts**. **Completion**
  (`src/scripts/assist.ts`, `@codemirror/autocomplete`) offers the
  `revkit.script` names, the members of what they are (`current_program.`,
  `monitor.`, `client.`, `currentProgram.`) and Ghidra's flat API
  (`getFunctionAt`, `currentProgram`, ...; first in a script that looks
  like a Ghidra one), each with its signature and the first paragraph of
  its docstring, from a static index (`src/scripts/script-api.json`,
  loaded on first use) that `sdk/python/generate.sh` builds from the SDK's
  own signatures and docstrings (`python -m revkit.script.completion_index`;
  a test fails when it drifts). Typing `(` after a known function shows its
  **signature** above the call, the argument being typed in bold, until
  its `)` (Escape closes it, then the dialog).
- **Tests**: `ui/e2e/console.ts` (the editor completing `decompile_m`,
  `current_program.functi` and `getFunctionA`, and the signature on `(`;
  the console: below) and `ui/e2e/scripts.ts` (the manager's tree and search, a starter
  from the palette answering its `ask_choice` with progress, one revision
  with script provenance seen live in a second page and undone with one
  Ctrl+Z, a per-user script's trust dialog then Cancel within 2 s and no
  question the second time, an `@context function` script from the
  right-click menu, Revert this run and its undo, and on a daemon with no
  Python, **Set up Python** in one click with stand-in Pythons: the steps
  in the output panel, then the banner gone); `sdk/ts/test/scripts.ts`
  (`ts_sdk_scripts`: the helpers, ListScripts, trust declined and
  confirmed, a prompt, progress, output, provenance, a failure's line).

## Python console

With feature `script-console` (`api_minor` 43; [scripting.md](scripting.md#the-console)
for the daemon's side), **Show Python (the console)** in the palette opens a dockable **Python** view (`src/scripts/console.ts`, the
side by default): a REPL bound to this program, run by the daemon in a live
host of yours (one per user and program, kept while you work, so names you
define stay).

- **Names.** `current_program`, `current_address`, `current_function` and
  `current_selection` follow the cursor and the listing's selection
  (`UpdateContext` as you move, and each statement carries them too), and
  every `revkit.script` name is there (`functions()`, `decompile(f)`,
  `rename(a, name)`, `find_bytes(...)`, ...). **Ghidra names** (a check box,
  kept per browser) binds Ghidra's as its Python console does:
  `currentProgram`, `currentAddress`, `currentSelection`, `getFunctionAt`,
  `toAddr`, `monitor`, ... (`revkit.ghidra.compat`).
- **Input.** Enter runs what is typed; an open block (`for ...:`, a
  `def`, an unclosed bracket) continues on the next line with the `...`
  prompt and its indentation, and an empty line ends it, as in Python's
  REPL. Shift+Enter adds a line; a paste of several statements runs at
  once. Expressions echo their value. Up and Down walk the **history**
  (the daemon keeps it per user, the last 1,000 statements; Up on the
  first line, Down on the last). **Tab** completes from the console's live
  namespace (`CompleteConsole`: jedi when the host's Python has it, else
  rlcompleter), so `current_program.fu`, a variable you defined or a
  module you imported complete; `(` shows the callee's signature. Ctrl+L
  clears the output.
- **Ctrl+C** (or **Interrupt**) raises `KeyboardInterrupt` in the running
  statement; the console and its names stay. With nothing running, Ctrl+C
  drops the input (with a selection it copies). Enter pressed while a
  statement runs runs the input after it. `input()` and the `ask_*`
  prompts use the standard dialogs; Escape interrupts the statement.
- **Edits.** A statement's edits are one revision with provenance
  `script:console@<hash of the statement>` and the console as its session,
  so each is **one Ctrl+Z**, in every page; the console notes how many
  edits it made. A statement that raises commits nothing it had buffered.
- **Restart** ends the host (the next statement starts a new one, with an
  empty namespace; so does `exit()`), and so does the daemon after the
  console sits idle (`--console-idle-timeout`, 30 minutes by default); a
  host that died (`os._exit`, a crash) is started again at the next
  statement, and the console says the namespace is new. **Clear** empties
  the output.
- **Read-only.** A viewer (on a daemon whose `--scripts-host-role` is
  `viewer`) gets a console that reads; its edits fail at once ("this
  console is read-only"), and the run token is a viewer's, so the daemon
  refuses them too. The header shows **read-only**. Where the daemon
  doesn't run Python for you, the view says why.
- **Tests**: `ui/e2e/console.ts` (`ui_e2e`): a statement and a block at
  the console, `current_function` following the cursor, Tab completion of
  a name defined there and of `decompile_many` with its signature on `(`,
  the history on Up, a console edit as one revision with script provenance
  `console` undone with one Ctrl+Z, Ctrl+C interrupting `while True:
  pass` with the namespace kept, a viewer signed in to a TLS daemon
  with `--scripts-host-role viewer` reading but refused an edit, and a
  daemon whose script Python has an older SDK: the console says so with
  **Set up Python**, as does the Script Manager. The stale-SDK search and
  the forced reinstall are `ScriptHost.AnOlderSdkSaysToUpdateIt`
  (`revkit_api_tests`) and `test_stale_sdk_says_to_update_it`
  (`python_sdk`).

## Address spaces (Harvard and word-addressed processors)

With the daemon's `address-spaces` feature, a program whose language has
several memory spaces or word-addressed code (AVR, the 8051, PIC: see
[processors.md](processors.md)) shows addresses as Ghidra does: the
space and its offset in the space's addressable units, `code:003a` for
AVR's flash byte 0x74, `mem:0100` for its SRAM (`src/data/format.ts`,
`fmtAddr`, from `ProgramSummary.spaces`). The listing's address column,
the functions, data, xrefs, calls and notes panels and the status bar use
it; the status bar's tooltip notes the unit ("code counts 2-byte words
(byte offset 0x74)"). Go To (Ctrl+K) and the URL take `space:offset` in
the same units, and a bare offset is in the code space's units; typing a
space's name offers its first block. The status bar's space switch jumps
between the spaces that have memory. The Open dialog's raw section takes
the space the image goes in and its format (detected, binary, Intel HEX,
S-records); regions take `:space=NAME`. Programs with one byte-addressed
space look as before.

## Demangled names

API 40, feature `demangle` ([demangle.md](demangle.md)). The daemon names
mangled symbols by their demangled names (`geo::Shape::scale`) and sends
their other spellings (`DemangledName`) wherever it shows one; the UI
spells them as the **names setting** says (`src/data/names.ts`, over the
TypeScript SDK's `showName`): the palette's "Names: demangled, short"
(the default, Ghidra's "use short names"), "Names: demangled, full
signatures" and "Names: mangled (as the file spells them)", kept per
browser (`rk.names`). The function list (names, prototypes; its tooltip
shows the other spellings), the listing (labels, SYMBOL operands, header
rows' labels and signature lines), the decompiler (FUNCTION_NAME and
GLOBAL_VARIABLE tokens) and the palette's symbol search follow it, and a
change redraws each. A search by either spelling finds a function; the
palette says when the match was the mangled name ("mangled
_ZN3geo5Shape5scaleEd"). A rename shows as itself in every setting.
`e2e/demangle.ts` checks it on a stripped C++ library.

## Hover cards

API 47, feature `hover` (no new calls: the cards read with `GetFunction`,
`Decompile`, `GetListing`, `GetTypes`, `ListSymbols` and `GetMemoryMap`).
Resting the pointer on something in the listing or the decompiler for
450 ms shows a **hover card** (`src/ui/hover.ts`, in the provenance
popover's frame, `src/ui/provenance.ts`), as Ghidra's tooltips do:

| Under the pointer | The card |
| --- | --- |
| a reference: a call's or jump's target, an address or symbol operand, a data item's pointer, a callee or a global in the C | a function: its signature (in the names setting's spelling) and its first lines of C (the signature, the brace and the first statements after the local declarations, as Ghidra's decompiler preview; the listing's rows when it doesn't decompile); anything else: the listing's first 8 rows there |
| a function's name (its label, its own name in the C) | its signature |
| a variable or parameter in the C | its declaration and its type's definition: through pointers, arrays, typedefs and qualifiers to a struct's or union's layout (offset, type, name, size of each member) or an enum's values |
| a type name in the C, a data item's or a member's type (or name) in the listing | the same definition |
| a field in the C (`p->second`) | its struct's layout with the member marked |
| a scalar operand or a constant in the C | hex, decimal (unsigned, and signed when different), as a C character constant when every byte prints (`'A'`, `'ELF'`), and, when it is an address, the symbol there and its memory block |

Below the previews, the **provenance badge**'s sections (who named or
typed it, the history, Undo) for whatever has a fact, as hovering showed
before; `i` still shows the badge alone for the selection. The card never
takes the focus (the listing or the decompiler keeps the keyboard), is at
most 60% of the window tall and scrolls (its wheel doesn't scroll the view
under it), stays while the pointer moves onto it (to scroll it, select
text or press Undo), and closes on Escape, on leaving it, or when the
pointer rests on something else. Each section fills in as its read
returns, so a slow decompilation doesn't hold up the rest. The TypeScript
SDK's `preview`, `previewLines` and `scalarText` (`sdk/ts/src/preview.ts`),
Python's `Program.preview`, `Program.describe_scalar`, `scalar_text` and
`preview_lines` (and `preview` in `revkit.script`) and MCP's `preview` and
`describe_value` give clients the same. Hovering on the way to something else doesn't take a card being shown away: a
new one replaces it, and a hide scheduled for the old one is cancelled.
`src/backend/tests/hover_test.cc` pins the reads the cards make (a
callee's prototype and first lines, a struct global's type by hash and its
layout, a struct parameter's type found by its spelling, since the
decompiler's `TypeRef` has no hash there, a field token's struct and
offset, a scalar's symbol and block), and `e2e/hover.ts` checks a call's
target, a scalar in both views, a callee's card with its provenance, the
focus, the scroll bounds, Escape, and a struct parameter, its type and a
field showing the struct's layout.
## Class hierarchy

With feature `msvc-rtti` ([pe.md](pe.md)) a **Class hierarchy** view
(palette: "Show class hierarchy"; side dock by default) lists the C++
classes MSVC RTTI names in the program (`ui/src/ui/classes.ts`, one
`GetClassHierarchy` call): a tree of derived classes under their bases (a
class with several bases shows under each), or, with a filter, the
matching classes flat. The selected class shows its TypeDescriptor and
hierarchy addresses, the struct `this` points to (a link to it in Types),
its bases (indented by depth, virtual or at which offset; a link selects
the base), derived classes and vftables with each slot's function: a click
goes to the address. It reloads when names change. `ui/e2e/classes.ts`
checks it on the clang-cl fixture (docs/pe.md, "Tests").

## Load debug file

With the daemon's `debug-files` feature (API 86;
[backend.md](backend.md#external-debug-files)) the Analyze menu (and the
palette) has **Load debug file…** (`src/ui/debugfiles.ts`): a path to a
debug file on the daemon's host, or empty to look the program's up by its
build ID and `.gnu_debuglink` (beside the binary, the configured
directories, `/usr/lib/debug`, the cache, then the debuginfod servers when
they are on), and "Load it even if it is another build's". A refusal (not
an ELF with DWARF, another build's, nothing found and where it looked)
stays in the dialog; a load is one step on the tab's undo stack, with a
toast saying what it brought and Undo. **Debug file directories and
debuginfod…** edits the settings: the directories (separated by `;`), the
servers (space-separated), "Fetch from debuginfod servers" (off by
default: network access) and "Allow plain http:// servers". The daemon's
`DEBUGINFOD_URLS` shows in the hint as a suggestion, never filled in. Both
are an admin's. The e2e (`e2e/debugfiles.ts`) builds a program with `-g`,
strips it, refuses the stripped binary as its own debug file, loads the
real one (the function is named), undoes it, and saves a directory with
fetching left off.

## Function ID

With feature `function-id` ([fid.md](fid.md), `api_minor` 51) a **Function
ID** view (palette: "Show Function ID"; side dock by default;
`ui/src/ui/fid.ts`) shows the last run's matches (`ListFidMatches`): a
row per function with a match, its address, the name it has now, the name
Function ID gives (or how many names when they differ), the score, the
status (applied, kept: a better-ranked name stays, not applied, rejected,
accepted) and the library, with a filter by name or library. The selected
match shows its candidates (name, score, library, database; the score's
parts in the tooltip) and Ghidra's plate comment.

- **Run** runs the analyzer again (`StartAnalysis function-id`) and
  reloads when the daemon is idle.
- **Apply** (Enter, or a click on a candidate) names the function as the
  match (`ApplyFidMatch`): the user's edit, one undo step.
- **Reject** (Delete) takes Function ID's name and plate off and keeps
  later runs away from the function (`RejectFidMatch`).
- **Databases…** lists Ghidra's builtin databases, yours and the
  project's, with their libraries and whether each is for this program's
  language; a check box attaches or detaches one (yours, or the project's
  for a project database), **Attach a file…** attaches a `.fidbf` or
  `.rkfid` on the daemon's host to the project.

The view reloads when names change. `ui/e2e/fid.ts` checks it on a small
static library built at test time: named, reject, apply, databases.

## BSim

With feature `bsim` ([bsim.md](bsim.md), `api_minor` 69; searching:
`bsim-search`, 72; applying: `bsim-apply`, 76) a **BSim** view (palette "Show BSim"; side dock;
`ui/src/ui/bsim.ts`) searches a BSim database for functions like this
program's. The head picks the database (the project's attached ones; the
last one used is remembered), **Databases…** creates one in the project
by name, attaches one at a host path (admin) or detaches one (`-name`),
and **Ingest** adds this program to the database (replacing an earlier
ingest of the same file).

- **This function** searches the function at the cursor (also **Find
  similar functions (BSim)** in the listing's Function menu, the
  decompiler's menu, on a called function's name that function, and the
  function list's menu); **All functions** lists every function with
  matches, best first; **Overview** counts each function's matches (a
  double click searches it).
- Options: similarity and confidence at least (0.7 and 0 by default),
  matches per function, **named only** (no `FUN_…` matches), and a filter
  that is an executable when one has that name or id, else a function
  name.
- Each match row: similarity, confidence, the match's name (its prototype
  in the tooltip) and executable. A double click or Enter on a match whose
  file is a program of the project opens the two side by side in
  **Compare**; `g` goes to the searched function.
- **Applying** (feature `bsim-apply`, `api_minor` 76;
  [bsim.md](bsim.md#applying-matches)): **Apply name**, **Apply
  signature** (the name and a skeleton signature: the types this program
  lacks become empty placeholder structures) and **Apply signature and
  types** in the bar and a match row's context menu apply the selected
  hits to their functions; the menu's *Replacing the function's own* does
  it over names and signatures someone set. A click selects a hit, Ctrl
  (Cmd) and a click adds or removes one, Shift and a click a range, Ctrl+A
  each function's best. One apply is one edit: the toast's **Undo** or
  Ctrl+Z takes back every function it changed. Each applied row shows
  what became of it (✓ applied, = unchanged, – skipped, ✗ failed; the
  reason in its tooltip) and its function's new name.

`ui/e2e/bsim.ts` checks it on builds compiled at test time: a match from
the function list's menu, Compare, All functions and the Overview; on a
stripped build, Apply name on one hit and the toast's Undo, then Ctrl+A
and Apply signature in one step, undone with the tab's undo.

## Comments

With feature `comment-table` (`api_minor` 77) a **Comments** view
(View menu, or the palette's "Comments"; `ui/src/ui/comments.ts`) is
Ghidra's comment window: every comment of the program
(`QueryService.ListComments`) in address order, one row per comment, with
the address, the kind (EOL, Pre, Post, Plate, Repeatable, Decompiler), the
function and offset it is in (or the address's label), and the text
coloured by who wrote it. A kind filter and a text filter
(case-insensitive) narrow it; the rows are virtualized and paged at one
revision, so a program with many comments scrolls smoothly. A click or
Enter goes to the comment in the listing; a double-click or Shift+Enter
opens the comment dialog for that kind. The view reloads when a comment
changes anywhere (an edit, an undo, another user). `ui/e2e/run.ts`
("comment table: …", in part A1 after the comment checks) checks it.

## Symbol tree

With feature `symbol-tree` (`api_minor` 82) a **Symbol tree** view (View
menu, or the palette's "Symbol tree"; `ui/src/ui/symtree.ts`) is Ghidra's
symbol tree, read a level at a time (`QueryService.ListSymbolTree`):
**Imports** by library (`<EXTERNAL>` when the file doesn't say which, as
for ELF), **Exports**, **Functions** and **Labels** by name, **Classes**
(the scopes the demangler finds classes, and MSVC RTTI's) with their
members, and **Namespaces** from qualified names (`geo::util::clamp`),
nested. Each folder shows its size; a level loads 500 nodes at a time
("more…" for the rest). The filter narrows every expanded level by name,
in any case. A click or Enter on a symbol goes there; on a folder,
library, namespace or class it expands or collapses (Right and Left too).
The tree reloads when a name or a function's bounds change, so a rename to
`ns::name` moves the symbol into that namespace. `ui/e2e/run.ts`
("symbol tree: …") checks it.

## Export C

With feature `export-c` (`api_minor` 80) **File: Export C/C++…** (the
palette, the Edit menu and the decompiler's menu; `ui/src/ui/exportc.ts`)
is Ghidra's C/C++ exporter: the function at the cursor or every function,
decompiled (`QueryService.ExportC`) into one `.c` in address order, each
under a `/* name @ address */` line, and with **a header** (on by
default) a `.h` the `.c` includes: Ghidra's built-in type names
(`undefined4`, `uint`, `code`, ...), the program's types as a type archive
writes them, a typedef of each struct, union and enum tag, and each
function's prototype (one whose function-pointer type C can't name is a
comment). A progress bar counts the functions while they decompile; then
both files download. A function the decompiler fails on is a comment
saying why. The name defaults to the program's. `ui/e2e/run.ts`
("export c: …") checks it.

## Relocations

With feature `relocation-table` (`api_minor` 78) a **Relocations** view
(View menu, or the palette's "Relocations"; `ui/src/ui/relocations.ts`)
is Ghidra's relocation table: the relocations the file carries
(`QueryService.ListRelocations`) in address order: ELF dynamic and object
relocations (RELA, REL and RELR), and a PE's base relocations from its
`.reloc` directory. Each row has the address patched, the type's name
(`R_X86_64_JUMP_SLOT`, `IMAGE_REL_BASED_DIR64`; `type N` for a machine
revkit has no names for), the symbol or, for a relocation that points
into the program (RELATIVE, IRELATIVE, PE), the function or label it
points at, the addend and the bytes there. A text filter matches the
symbol or the type name. A click or Enter goes to the address; a
double-click or Shift+Enter goes to the target. revkit applies no
relocation to the bytes except the RELATIVE ones a rebase moves, so the
bytes are the file's. `ui/e2e/run.ts` ("relocations: …") checks it.

## Register values

With feature `register-values` (`api_minor` 87;
[api.md](api.md#register-values)) the UI has Ghidra's Set Register
Values and its register manager (`ui/src/ui/regvalues.ts`):

- **Set register value…** and **Clear register value…** (the listing's
  right-click menu ▸ Function, and the palette) open one dialog: the
  register (typed, with the language's registers to choose from), the
  value (`0x418ff0`, `418ff0h` or decimal), the range, and **No value here
  (clear)**. The range is the listing's selection when it spans rows,
  else the body of the function at the cursor (several ranges when the
  body has several), else the code unit there; with one range its From
  and To can be edited. Enter applies it as one undo step
  ("Set gp = 0x418ff0 over bump", Ctrl+Z), and every page's listing and
  decompiler follow: `gp`-relative loads become their globals.
- **The Register values view** (View menu, the palette, or Function ▸
  Register values) lists every range by register, then address: the
  register, first and last address, value and who set it ("analysis
  (mips-gp)" for the loader's `_gp`, else the assertion's author,
  coloured as names are). A register filter narrows it; **Set…** opens the
  dialog. A click or Enter goes to the range's start; a double-click opens
  the dialog on that range; Delete clears it (no value there, one undo
  step). It reloads when a register value changes anywhere.
- **In the listing** the row where a range starts and a function's entry
  row end with `assume gp = 0x38180` (the override colour; hovering shows
  who set it, or analysis's rule), and an operand that reaches a global
  through the register shows it as Ghidra does: `lw at,-0x7fe0(gp)=>counter`.

`ui/e2e/regvalues.ts` ("register values: …") checks it on a MIPS program
built with small data (screenshots `regvalues-view.png`,
`regvalues-dialog.png`).

## Project tree and archives

API 37, features `project-folders` and `project-archive`
([api.md](api.md), "Folders" and "Project archives"; the archive format
is in [backend.md](backend.md#project-archives)). `src/ui/open.ts` (the
tree), `src/ui/archive.ts` (the archive dialogs), `sdk/ts/src/projects.ts`
(the helpers both use); checks in `e2e/projects.ts`.

- **The tree.** The Open dialog (the project window, Ctrl+O; its layout
  is in "Opening programs" above) lists the project as a tree, as
  Ghidra's project window does: folders first, then programs, a program
  inside its folder; the breadcrumb above it stands for the root.
  Folders expand and collapse with their caret, a double click, Enter, →
  and ← (← on a program or a closed folder goes to the folder above);
  which are closed is remembered per project. The list is a `role="tree"` whose rows are
  `treeitem`s with `aria-level`, `aria-expanded` on folders and
  `aria-selected` on the row picked; ↑↓ move as before.
- **Organizing.** A folder's menu (right-click, `⋯`, the menu key,
  Shift+F10) has New folder…, Rename… (F2), Move to… (a chooser of every
  folder but the one moved and those below it), Delete (Del; only an
  empty folder: move or delete what is in it first) and Export folder…;
  the root's has New folder…, Export project… and Import project…; a
  program's adds Move to… and Export program… to Open, Rename and Delete.
  Programs and folders also drag onto a folder or a breadcrumb segment,
  the project's root among them (the target is outlined; a folder can't
  go into itself). **New folder** in the dialog's toolbar makes one in the
  folder picked. Each edit's toast has
  **Undo**, which retracts its assertions by project, as the server keeps
  folders as assertions (a move of several items is one undo). After an
  edit the tree is read again; edits from other tabs or daemons show the
  next time it is read.
- **Importing into a folder.** The import section's "Import into default
  / libs / json" (and the footer's "Add a binary to /libs/json") names
  where an import goes: the folder picked, or the folder of the program
  picked, when Import binary… was pressed. After `ImportProgram` the new
  program is moved there.
- **File → Export project…** (the toolbar's **File** menu, the palette's
  "File: Export project…", the dialog's `⋯`, or a folder's or
  program's menu): the whole project, the folder or program picked, as one
  `.rkproj`; **Annotations only** leaves the programs' files out (each is
  found again by its SHA-256 on import). The archive streams from the
  daemon (the status counts the bytes) and is saved as a download.
- **File → Import project…**: pick a `.rkproj` (the system file chooser);
  it is uploaded in 4 MiB pieces and inspected first. The dialog lists its
  programs, their folders and where each binary is: in the archive, found
  in this project, added, or **missing**. For a missing one, **Add
  binary…** takes a file (checked against the SHA-256 in the page before it
  is uploaded) or **Skip the programs whose binary is missing** leaves
  them out; Import stays disabled until one or the other. It goes into
  **a new project** (named; the archive's name by default) or **this
  project**, under the folder picked, as new programs (a name already in
  that folder gets " (2)"). The daemon's warnings show as toasts; from the
  File menu the first program imported opens, from the Open dialog the
  project it went into is listed.
- **Desktop app.** The same dialogs. A download (an archive, an exported
  program) asks where to save with the desktop's native save dialog (the
  Tauri shell's `on_download`, GTK's file chooser on Linux; cancelling it
  cancels the download); opening a file is the webview's own file input,
  which is native too.
- **Older daemons.** Without `project-folders` the Open dialog is the
  flat list it was, with no New folder or Move to…; without
  `project-archive` the File menu's archive items are disabled and the
  dialog's `⋯` has no archive items.
- **Not yet.** The tree doesn't follow other clients' folder edits live
  (`QUERY_KIND_PROJECT_TREE` events) while the dialog is open; several
  rows can't be picked at once for one move; an archive is collected in
  the page before it is saved, so a multi-gigabyte one needs that much
  memory in the browser.

## File system browser

API 48, feature `filesystems` ([filesystems.md](filesystems.md)).
`src/ui/filesystem.ts` (the browser, Info and batch import),
`sdk/ts/src/filesystems.ts` (the session helpers); checks in
`e2e/filesystems.ts`.

- **Opening.** File → Open file system… (the toolbar's File menu, or the
  palette's "File: Open file system…") asks where from: a file on this
  computer (the system file chooser; sent to the daemon), a file or folder
  on the daemon host (the host browser; needs `--browse-root`), or the
  open program's stored file (a raw firmware image holding a file system).
  In the Open dialog, a file that starts like an archive or an image (a
  zip, a tar, a squashfs, ...), or one the loaders refuse that the daemon
  opens as a container, gets **Open as file system** instead of raw
  detection (which stays a button away).
- **The tree.** Name, size (a directory's entry count), type (`file ·
  gzip` for a file holding a container), permissions, and what each file
  is: `ELF 32-bit LE ARM executable · ARM:LE:32`, a nested container's
  format, text, data, bytecode (`Python 3.12 bytecode (magic 3531)`).
  Scripts and bytecode carry a small badge with their content kind
  (`pyc:3.12`, `lua:5.4`, `js-source`; api_minor 95,
  [filesystems.md](filesystems.md#content-kinds)). A packed executable is
  a program (bold) that expands like a container: its PyInstaller
  archive, pkg file system or SEA blob opens in place (api_minor 96).
  Programs are bold; unreadable members (encrypted, an
  unsupported method) say why in red; a name that was normalized (a
  traversal) has a `renamed` badge. Directories and container files expand
  with a click on ▸, → or a double click: a container opens in place, its
  root under it, to any depth. The bottom line shows the active row's
  session path (`/pkg/data.tar.gz!/data.tar!/usr/bin/tool`).
- **Selecting.** Click picks one row, Ctrl+click adds or removes,
  Shift+click and Shift+↑↓ pick a range, Space toggles; ← goes to the
  folder above; Enter expands or shows Info.
- **The menu** (right-click, the context-menu key, Shift+F10):
  **Import** (the selected files, as programs; one file is imported
  whatever it is), **Import programs below…**, **Open as file system**
  (a container file), **Extract to daemon host…** (a folder chosen in the
  host browser; admin, under `--browse-root`), **Info…** (the container
  path, what it is, size, owner, times, a link's target, the load address
  a firmware header names, SHA-256/SHA-1/MD5 for files up to 256 MiB (a
  button computes them for larger ones), and the first 32 bytes), and
  **Copy container path**. The head's buttons do the same for the
  selection. On bytecode (a jar, an APK, a DEX, a `.class`, a `.pyc`, a
  Lua chunk, a wasm module, a .NET assembly, a `.js`), **Decompile with
  jadx…** and the other external decompilers that take it ([below](#external-decompilers)).
- **Import programs below…** (batch): the selected folders and containers,
  or everything. Options: subfolders, look inside archives and images
  found, raw detection on other data (slow), recreate the folders in the
  project, analyze, also import the libraries they need from this file
  system (feature `library-roots`, api_minor 79:
  [filesystems.md](filesystems.md#libraries-of-imported-programs)), at
  most N programs (100), into a project folder. The preview lists every file with what it is and whether it would be
  imported (and why not), and updates with the options; **Import N
  programs** runs it. The status (and a toast with **Open** for the first
  program) says how many were imported, skipped and failed, and the
  libraries brought with them and those not in the file system.
- **Importing** opens nothing by itself: the toast's **Open <name>**
  opens the program. Each records its container path, which the program's
  `ProgramInfo.container_path` keeps.
- **Closing** the browser (Close, Escape, the backdrop) closes the session.
- **Older daemons.** Without `filesystems` the File menu's item is
  disabled and the Open dialog never offers it.
- **Not yet.** A directory shows at most 2,000 entries; no text or hex
  preview pane (Info shows the first bytes); drag and drop from the tree
  into the project window.

## External decompilers

API 92, feature `external-decompilers` ([providers.md](providers.md)).
`src/ui/external.ts` (the pane's bar, the dialog, the source view),
`src/ui/sourcehl.ts` (the highlighting); checks in `e2e/providers.ts`.

- **The decompiler pane, for bytecode.** When the program's file is
  bytecode (a .NET assembly, a DEX, a jar, ...; `ListProviders` with the
  program says so), a bar under the pane's title names what it is (".NET
  assembly") and switches the pane between the external decompiler's
  source (the default when one is installed: ILSpy's C# here, which Ghidra's
  x86 view of the IL can't approach) and Ghidra's C. The source view has
  the provider (any of those that take the input, with its version; those
  not installed are disabled, the reason in their tooltip), the output's
  files (a tree's: the main file first, which is the largest in the
  provider's language), **Run again** (a fresh run instead of the cached
  result) and a status line (the version, the file count, "cached" or the
  seconds it took; on a failure what happened and the last line of the
  tool's stderr; its tooltip has the input's SHA-256 and the sandbox). The
  code is read-only with line numbers and selection, highlighted in the
  theme's token colours: C#, Java, Kotlin, JavaScript, wasm-decompile's
  pseudo-code (one C-like tokenizer with each language's keywords), Python,
  Lua and XML (an ILSpy project's `.csproj`). The first view runs the
  provider (seconds; the result is cached by the daemon after that). With
  no provider installed, the bar says which would take it and why it isn't
  available, and the pane stays on the C.
- **The file system browser's Decompile with …** opens a dialog: the
  provider and its status as above, the output's files on the left with a
  filter, and the selected file on the right (binary files say so). Closing
  it (Close, Escape, the backdrop) keeps the result in the daemon's cache.
- **Not yet.** No settings dialog (the API, the SDK and `rk-daemon
  --provider` set the tools' paths); no link from a line of the source to
  the listing; no search across a tree's files.

## Daemon status

The status bar's first item, bottom left, is the daemon's chip
(`ui/src/ui/daemon.ts`), in the browser and in the desktop app:

- **connected** (green): `rk-daemon 0.1.0 · <project>`;
- **busy…** (amber, pulsing): the daemon is there, but a check (4 s)
  went unanswered: a long job, such as analyzing a program again in a new
  language, holds the browser's few connections to it. The page stays
  usable, and what it asks for arrives when the daemon is done. A minute of
  unanswered checks is **disconnected**; a refused connection is at once;
- **connecting** (amber, pulsing): the first call, or a Reconnect;
- **disconnected** (red), with a button beside it: **Reconnect** in a
  browser, **Start daemon** in the desktop app when its daemon has stopped;
- **restarting** (amber, pulsing): after **Restart daemon…** (below),
  until the new daemon answers.

Clicking it opens a popover: the server version, the API (`v1.36`), the
uptime, the address the page talks to and the project. The page learns the
state from `GetServerInfo` (at load, every 15 s while connected and every
3 s while not) and from the subscription stream: a dropped stream checks
at once, so a killed daemon shows red within a second or two.

**When the daemon goes away in a browser**, the page stays: what it has
loaded (listing pages, the decompilation, panels) stays on screen and
usable read-only, a toast says so, and calls fail with "the daemon is
disconnected; the page is read-only until it is back" instead of "Failed to
fetch" (`api/client.ts`). The popover shows **Reconnect** and the command
that starts the daemon again, with a **Copy** button:

- the daemon's own command line, from `GetServerInfo.launch_args`
  (`api_minor` 36, feature `daemon-info`), which the daemon tells admins
  only (with `--no-auth` every caller is one); the page keeps it per
  daemon address, so it is known after a reload too;
- `systemctl --user start revkit-daemon.service` when the daemon was
  socket activated (with the socket enabled, Reconnect alone starts it:
  [packaging.md](packaging.md#start-the-daemon-on-first-use-systemd-socket-activation));
- otherwise `rk-daemon --http <host:port>` and a note that the other flags
  aren't known here.

When it answers again, the chip turns green, the stream reconnects at once
(`Live.kick`, not after its backoff) and resyncs if the daemon's revisions
moved. A page that couldn't reach the daemon at load (the desktop app,
`?api=`) reloads instead.

**In the desktop app** (Tauri), the popover also has **Start daemon**,
**Stop**, **Restart** and **Show daemon log** (the log's last 256 KB in a
dialog), through the shell's `daemon_*` commands (`main.rs`; the only Tauri
IPC the UI uses, granted to the bundled page only: [security.md](security.md#the-desktop-apps-daemon-controls)).
The app still starts its daemon at launch. If the daemon dies, the chip
turns red with **Start daemon**, and the popover says how it ended
(`signal: 9 (SIGKILL)`, `exit status: 1`) above the log's last 20 lines.
Stop sends SIGTERM (SIGKILL after 10 s); Start and Restart ask for the
same HTTP port and reuse the token the app made at launch, so the page
carries on; if the port is taken, the daemon takes another and the page
follows it. A daemon the app didn't start (`REVKIT_DAEMON`) shows the
chip without the controls.

Tests: `ui_e2e` (`e2e/daemon.ts`) runs a daemon of its own on a fixed port
in 53900–53999: the chip connected and green with the version and project
and the popover's details; the daemon killed (SIGKILL), the chip red, the
listing's rows still there, a call's message, the start command with every
flag the daemon ran with and the clipboard holding it; Reconnect while
it's down (still red), then a new daemon on the same port and Reconnect
(green, the stream live, calls working). The shell's helpers and the
start/stop cycle on a stand-in daemon are `cargo test` in
`ui/tauri/src-tauri` (port file, log tail, SIGTERM, how it ended); the
controls themselves were checked by hand under Xvfb (kill → red with the
log and Start daemon → green on the same port; Restart; Stop; Show daemon
log).

### Restart daemon

**In a browser** too, the popover of a green chip has **Restart daemon…**
for an admin (with `--no-auth` the anonymous caller is one, on loopback
only), when the daemon can restart itself (`MetaService.RestartDaemon`,
`api_minor` 55, feature `daemon-restart`). In the desktop app the
popover keeps the app's own Restart, which restarts the daemon it started.

1. **Confirm.** A dry run (`dry_run`) tells the page how the daemon will
   restart and how many update streams are open; the dialog says how many
   *other* connections the restart drops (the streams less this page's
   own: other tabs and windows, agents following changes), with the names
   of the others on this program from presence, or that none is
   connected. Clients without a stream (a one-off SDK call, an MCP server
   between calls) aren't counted: the daemon can't see them.
2. **Restart.** The daemon answers, then (after 300 ms) shuts down as for
   SIGTERM: the HTTP gateway closes, open streams end, gRPC finishes its
   calls, the peers stop, and the backend is destroyed (projects saved,
   decompiler workers and script hosts stopped). Then it **re-executes
   itself** in the same process (same PID, so a supervisor or the desktop
   app keeps tracking it) with the same argv and environment, the binary
   at the path it started from (a rebuilt or upgraded `rk-daemon` takes
   effect); descriptors other than stdin, stdout and stderr close on exec,
   so the ports and the project lock are free for the new image. If the
   exec fails, the daemon logs why and exits 1. **Under systemd socket
   activation** it exits 0 instead, and systemd, which keeps the socket,
   starts it again on the next connection
   ([packaging.md](packaging.md#start-the-daemon-on-first-use-systemd-socket-activation)).
   The daemon logs an audit line: who, from which address, the reason
   ("from the web UI (alice)") and the streams it ended.
3. **Reconnect.** The chip shows **restarting…** (amber); calls fail with
   "the daemon is restarting"; the page asks the daemon twice a second and
   takes only an answer from a daemon that started after the request.
   Then, if the daemon serves the page (same origin) and its bundle
   changed (Vite's hashed script and stylesheet names in `/`), the page
   reloads to the new UI; otherwise the chip turns green, a toast says
   "Daemon restarted", and the stream reconnects at once and resyncs.
   Not back within 90 s: red, with Reconnect.

With `--http 127.0.0.1:0` (a port the system picks) the restarted daemon
gets another port and the page can't follow; give a fixed port.

Tests: `daemon_restart` (`tools/rk-daemon/restart_test.py`): a dry run
restarts nothing; a restart brings the same PID back on the same port
with a fresh uptime, the same command line and an audit line; a viewer
is refused (403) and an anonymous caller too (401) with accounts on;
under socket activation the daemon says `exit`, exits 0 and the socket
stays open. `revkit_api_tests` (`AuthTest.RestartDaemonIsForAdminsOnly`:
anonymous, viewer, editor, token and peer refused, the feature listed,
the dry run counting an open stream, the hook called once;
`AuthServer.RestartNeedsTheDaemonsHook`). `ui_e2e` (`e2e/daemon.ts`):
Restart daemon… with a second tab open (the confirmation says 1 other
connection), the chip restarting then green and live on the same daemon
process and port, no reload, the other tab back too. Screenshot
`daemon-restart-confirm.png` with `RK_SHOTS`.

## Search

Ghidra's four searches over the daemon's (`api_minor` 41, feature
`search`; [api.md](api.md#search)), in `src/ui/search.ts`; checks in
`ui/e2e/search.ts` (screenshots `search-*.png` with `RK_SHOTS`).

- **Opening them.** `S` (Ghidra's key) or `Ctrl+Shift+E` opens Search
  Memory, `Ctrl+F` (Ghidra's) Search Program Text, in the default keymap
  (the others: "Keymap presets"); the toolbar's **Search** menu
  has all four (Memory…, Program text…, Scalars…, Decompiled code…),
  Repeat search (`F3`), Repeat search backward (`Shift+F3`) and Show
  search results; the palette has them as "Search: …". The toolbar's menu
  and `S` appear only with the feature.
- **The dialogs** float at the top right and leave the listing usable, as
  Ghidra's aren't modal: the cursor can move while one is open, and
  Next starts from wherever it is. Enter is Next, Shift+Enter Previous,
  Ctrl+Enter Search All, Esc closes (the focus goes back to the listing);
  the line at the bottom says what was found, where, and the bytes the
  daemon searched for ("found at 001011df · e8 7c fe ff ff (bytes e8 ?? ??
  ?? ??)"), "Wrapped around", "Not found after …", or the daemon's error
  (a bad hex digit, a regex RE2 refuses). Each dialog keeps what was typed
  (per browser). A match inside an instruction selects the instruction;
  the next search goes on from the match, not the instruction's start.
  - *Memory*: what to search for and its format (Hex, String, Decimal,
    Float, Double, Binary, Regular expression, each with a hint and an
    example); for strings the encoding (ASCII, UTF-8, UTF-16), Case
    sensitive (off by default) and Escape sequences; for decimals the size
    (1, 2, 4, 8 bytes) and Unsigned; for numbers and UTF-16 the byte order
    (the program's, little, big). Where: the entire program or the
    selection; code units (instructions, defined data, undefined; all by
    default), executable blocks only, an alignment; Wrap around (on); a
    limit for Search All (10,000).
  - *Program text*: Regular expression, Case sensitive, Whole word, and
    the fields (Functions, Comments, Labels, Mnemonics, Operands, Data
    mnemonics, Data values; all by default), matched against the listing
    as shown, so a rename counts.
  - *Scalars*: a value (4096, 0x1000, -1), a range (either end open) or
    every scalar, in instructions, defined data or both.
  - *Decompiled code*: every function, those in the selection, or the
    current one; Enter searches all.
- **F3 and Shift+F3** repeat the last search after the dialog closes
  (from the cursor, forward or back); after a decompiled-code search they
  step through its results (the next row, opened). With no search yet, F3
  opens Search Memory.
- **The results** go to a dockable **Search results** view (the side
  group by default; drag it like any tab). It keeps the last ten result
  sets (a picker in its header; Close drops one) and shows, while a search
  streams, a progress bar with "searching 3,145,728 of 11,785,757 bytes ·
  26%" (code units for text and scalars, functions for decompiled code)
  and **Cancel**. Columns: memory (Address, Label, Match, Code unit,
  Function), program text (Address, Field, Text with the match marked,
  Label, Function), scalars (Address, Value in hex, Decimal, Bits,
  Instruction / data, Function), decompiled code (Function, Line, Text with
  the match marked, Address). A click on a header sorts by it (again: the
  other way; `aria-sort`); the filter keeps rows any of whose cells
  contains the text; **Copy CSV** copies the rows shown with a header
  (Ctrl+C in the table too); a click (or Enter) goes to the row's address
  in the listing, or opens the decompiler at the line with the match
  marked; Shift+click and Ctrl+click choose several rows, Ctrl+A all.
  **Make selection** makes the chosen rows' addresses (every row shown
  when none or one is chosen: a memory match's bytes, a code unit's
  address, a decompiled line's address) the listing's selection: a set of
  ranges drawn as selected, which the next click or keyboard selection in
  the listing replaces, and which the searches' "Selection" scope
  searches. Edits that take one range (Clear, Create structure, scripts'
  `current_selection`) still use the rows selected in the listing. Every
  hit of the result set shown is marked in the listing's gutter (orange).
  The table draws only the rows in view, so 100,000 results scroll like
  ten.

## Find uses

Ghidra's Find Uses of on a data type or a field (`api_minor` 53, feature
`type-uses`; [api.md](api.md#find-uses-of-a-type-or-field)), in
`src/app.ts` (`findUses`) and `src/ui/search.ts` (`Search.findUses`);
checks in `ui/e2e/callsite.ts` (screenshot `find-uses-field.png` with
`RK_SHOTS`).

- **From the decompiler.** Right-click a struct field (`p->count`): **Find
  uses of field** and **Find uses of type (struct or union)** follow Rename
  field and Retype field. On a type's name (a declaration's `struct node`,
  a cast), **Find uses of type**. The palette has both ("Find uses of
  …"); they are enabled only where the token names one of the program's
  structs or unions.
- **From the Types window.** A struct's or union's detail has **Find
  uses** beside Apply, and each field row a **Uses** button.
- **The results** go to the Search results view as a set titled "Uses of
  node" or "Uses of node.count", streaming with the progress bar
  ("searching 120 of 412 functions · 29%") and **Cancel**: every
  function's decompilation is read on the daemon, the ones decompiled
  before at once. Columns: Function, Line, Use (read, write, read/write,
  address of, or type for a declaration or cast), Code (the C line with the
  token marked), Address. The table sorts, filters, copies as CSV and
  makes a selection as for the searches; a click (or Enter, or F3) opens
  the decompiler at the line with the use marked.

## Signature overrides

Ghidra's Override Signature, Edit Signature Override and Remove Signature
Override on a call (`api_minor` 53, feature `call-signature-override`;
[api.md](api.md#call-site-signature-overrides)), in `src/app.ts`; checks
in `ui/e2e/callsite.ts` (screenshot `signature-override.png`).

- **Where.** On a call: the called function's name in the decompiler, or
  the call instruction's row in the listing (a direct or a computed
  call). The right-click menus and the palette have **Override signature
  (this call)…**, and once the call has one **Edit signature override…**
  and **Remove signature override**.
- **The dialog** asks for the prototype as C, prefilled with the override
  or the callee's prototype (`int printf(char *fmt, ...)`): for a varargs
  call, write the arguments this call passes (`int printf(char *fmt, int
  n, char *s)`); for a computed call, its target's prototype. Saving is
  one undo step ("Signature override at 00101234", Ctrl+Z); the
  decompilation updates in every page.
- **Shown.** The call's listing row ends with `⤷ signature: int
  printf(char * fmt, int n, char * s)` (the override color; `i` on it
  shows who set it), and the hover card of the call's name in the
  decompiler starts with a "signature override (this call)" section.

## Phase-0 spike architecture

The spike talked to a mock daemon over its own `revkit.ui.v1` protocol
(display-line rows with header and label lines, `GetRowsAround` with an
anchor row, generation-stamped `WatchChanges`). The canvas view, row cache,
scroll model and painters carried over to v1 unchanged in substance.

## What the spike showed

1. **Canvas text rendering isn't the bottleneck.** JS time per frame is
   0.2 to 0.7 ms in Chromium and WebKit, about 1.3 ms in Firefox and 2 to
   3 ms in WebKitGTK on the CPU. The cost is getting a full-viewport canvas
   to the screen. On the GPU that is nearly free (Chrome GPU uncapped:
   0.5 ms frames at scale 2). In software it scales with pixel count:
   Chromium takes 2.2 to 4.6 ms at scale 2, and WebKitGTK takes 17 ms for a
   flat fill at scale 2.
2. **Caching glyphs or rows doesn't help.** A static glyph atlas is 2 to 4×
   slower than `fillText` in Chromium, and a per-row bitmap cache costs about
   the same overall; neither changes the WebKitGTK result. `direct` stays
   the default. See RESULTS.md for the side-by-side.
3. **Data latency, not rendering, limits the scrollbar drag.** Sweeping 11M
   rows in 4 s needs new rows every frame. With the hold policy no frame is
   ever blank, but 9 to 93 % of frames show content one frame behind the
   thumb, depending on how well one-frame-ahead prediction works and how
   fast the engine delivers fetch results. That's the right trade for a
   scrollbar and unnoticeable in use. A real daemon with a slower row path
   would show more lag, never jank: with 25 ms of injected latency, scrolls
   and flings still never drew a blank row.
4. **Linux without GPU compositing is the risk.** Tauri apps commonly ship
   with `WEBKIT_DISABLE_DMABUF_RENDERER=1` or
   `WEBKIT_DISABLE_COMPOSITING_MODE=1` to dodge driver bugs; under Xvfb
   WebKitGTK chose the same non-composited CPU path on its own. On a HiDPI
   screen that path spends the whole 60 fps budget on a full-window canvas
   update before drawing anything, so it can't hold 60 fps.

## Recommendations from the spike, and what v1 did

- Keep the decision: web UI, Connect transport, canvas listing. Make the
  row-paged API (above, and `ui/README.md`) the daemon's listing contract,
  including dense row numbering and a generation-stamped change stream that
  can say "rows from N on shifted".
- Before committing to Tauri on Linux, run `bench/tauri.sh` on real Linux
  desktops with working GPU drivers (`NO_XVFB=1 DISP=:0`), Intel, AMD and
  NVIDIA, at scale 2. If WebKitGTK's GPU path also misses, ship the Linux
  build as the browser-tab mode (or a Chromium-based shell) and keep Tauri
  for macOS and Windows, where it uses WKWebView and WebView2.
- Detect software rendering at startup (`webkit://gpu` equivalents aren't
  scriptable, but a 30-frame flat-fill probe is) and fall back to rendering
  the listing at DPR 1 with a CSS upscale, or warn.
- Keep the listing on one canvas with its own scroll model. Don't use
  DOM rows or native scrolling for row counts in the millions: element
  height limits (~33M px in Chromium) are exceeded at about 1.8M rows of
  18 px.
- Move fetch and decode to a worker only if profiles show main-thread
  stalls from it; at 0.5 ms per 256-row page it didn't matter here.
- Watch font loading: the canvas measures glyphs once, so the webfont must
  be loaded before the first measurement (`document.fonts.load`). Bundle the
  font so all engines lay out identically.

What v1 did with these: the decision stands (web UI, Connect, canvas
listing); the daemon's listing contract is row-paged with dense numbering;
software rendering is detected with a redraw probe and handled at DPR 1;
fetch and decode stay on the main thread; the webfont is bundled and
loaded before measuring. Running `bench/tauri.sh` on real Linux desktops
with GPU drivers is still open.

## Known gaps (v1.1)

- **Listing.** No data definitions (the backend has none yet), so data
  shows as 16-byte undefined rows (a global's asserted type replaces
  `undefined[n]` on its row). No post-comment or local-variable lines
  (post-comments stay in the comment column). Arrows for jumps whose
  source is more than 600 rows away from the view are drawn only from a
  visible source. Labels and comments in the middle of a coalesced data
  row aren't shown (as in v1).
- **Retype.** Since api_minor 25 the daemon parses a C declaration
  ([cparse.md](cparse.md)) into a hashed type that reaches the decompiler
  (prototypes and globals); the dialog checks it with `ParseC` first, so a
  typo is caught there. The UI shows the declaration as typed in the
  decompiler's header and the listing's signature line (a retype with
  definitions before it goes by hash, and shows as the decompiler prints
  the type). Asserted parameter and local types are committed to the
  decompiler, so the body follows them (field accesses, typed loads and
  stores; [decompiler-inputs.md](decompiler-inputs.md#variable-types)).
  Since phase 5 the UI spells declarations that name a program type as
  `DefineType` nodes and retypes by hash, so those prototypes reach the
  decompiler; plain C text still doesn't (no C parser in the daemon).
- **Header rows** cost a whole-program pass on the daemon whenever a name
  or plate/pre-comment changes anywhere (`listing.headers`), about
  proportional to functions plus labels; fine for libLLVM-sized programs,
  see bench/RESULTS.md.
- **Navigation.** History is per tab and in memory. Symbol search is by
  substring (no fuzzy matching; wildcards and expressions since API 44);
  the palette ranks functions from the loaded list and asks `ListSymbols`
  for labels.
- **Decompiler.** Arrow keys walk tokens, but there is no text caret; no inline
  rename editing (a dialog asks); no type or prototype display beyond the
  code.
- **Scale.** The functions filter is a daemon-side substring scan per
  keystroke (debounced), in address order: no prefix-first ranking.
- **Rendering fallback** is decided once, shortly after load; moving the
  window to another monitor re-measures nothing (it does re-read the
  device pixel ratio).

### Known gaps (Compare)

- The aligned listing shows instructions only (no data rows inside the
  function, no header rows); the C pane aligns lines by text, not by the
  instruction map, so a statement the decompiler reorders shows as two.
- The graph diff's union layout is computed per pair and mode (no reuse
  across pairs); edges carry no kind colours (taken, fall-through), only
  their diff status.
- The table loads 2,000 rows at a time; sessions can't be renamed or
  deleted from the UI.
- Two functions compare two at a time (Ghidra's window takes several);
  after a port the Listing pane keeps its labels until the pair is opened
  again (the C pane and the header refresh).

### Known gaps (phase 5)

- **Graph.** Layout of a 2,000-block function takes about a second
  (shown with a message); edges leaving the function (tail jumps) are
  only the source block's `exit` mark. Switch labels come from the
  decompiler, so a function it fails on has none, and a default reached
  through the bounds check (a conditional edge) isn't labelled. Grouping
  is by dominance only (no free selection of blocks), and folds are kept
  per function for the tab's life, not saved.
- **Types.** The folder tree files the program's types only; the
  library archive's are by kind (its `.gdt` category paths aren't kept).
  In the kind tree, names starting with neither a letter, `_` nor a digit
  are only found by searching. A drag moves one type at a time (no
  multi-select), and folders exist only while a type is in one (no empty
  folders). The editor has no undo inside an unsaved
  edit, and no drag reordering (buttons move fields, in natural layouts).
  Its C tab is a plain text area (no highlighting or completion), and
  readable C of a draft loses an explicit layout's filler. The header
  import's preview names a constant enum's constants by count only, and
  an anonymous struct pasted where a field's type goes can't be written
  back as text (paste it in the C tab). Renaming leaves the old
  definition listed under its old name while uses by hash name it. An
  edit reaches asserted and
  debug-info prototypes, debug-info globals and locals in the decompiler
  (since api_minor 25) and every display. A search lists its first 500
  matches (the tree pages 500 at a time with "Load more").
- **Plugins.** Analyzer facts are fetched for the listing rows in view
  and for the current function's body (graph, decompiler); in C a fact
  sits on the first line printed from its instruction, or from the next
  instruction within 32 bytes (an argument's load goes with its call).
  `DATA_TYPE` facts are shown, not applied. Commands' arguments are free
  text.
- **Calls** lists direct and indirect call references the daemon knows;
  calls through pointers it didn't resolve are missing, as in the xrefs.

### Right-click menus and the type chooser

- **Menus** (right-click, the toolbar's File, Search, History and Fields,
  `⋯` buttons) stay inside the window: one taller than it scrolls, and a
  label too long for it is shortened with an ellipsis. Toggles (the
  listing's Fields, the byte viewer's columns, a group's » menu) keep a
  check-mark column so their labels line up. A menu whose items are all
  disabled (the History of a fresh page) still takes the focus, so
  Escape closes it.

- **Right-click** in the listing or the decompiler (or the context-menu
  key) selects what is under the pointer (keeping a selection it falls
  inside) and shows the actions that apply there, grouped, with their keys.
  **The listing's** keeps the most used at the top and the rest in
  submenus, as Ghidra's does (about 20 entries instead of 29): Follow,
  References to, Go to; Rename, Set type, Set comment; then **Comments ▸**
  (plate, pre, post, end-of-line, note), Disassemble and Clear (feature
  `listing-edit`, see "Listing edits"), **Data ▸** (cycle, the types and
  strings, array, choose type, mutability, **Recently used ▸**, expand or
  collapse, create structure from selection), **Function ▸** (create,
  remove, flow override, call-site signature overrides, compare with…),
  **References ▸**, Convert ▸ and Set equate on a scalar, **Patch ▸**
  (instruction, bytes, revert here), **Copy ▸** (rows, Copy special),
  **Debugger ▸** (emulate, breakpoint); provenance, graph; undo and redo.
  A submenu with nothing that applies is left out. The keyboard works in
  them (→ or Enter opens one with the focus on its first item, ← or Escape
  goes back). **The decompiler's** is one level: copy; follow,
  references, go to; rename, set type (on a struct field, rename field and
  retype field), comments, note; find uses; signature overrides;
  structures; equates; emulate, breakpoint; compare; provenance, graph;
  undo and redo. The listing's canvas no longer gets the browser's own
  menu ("Save image as…").
- **Set type** for a variable, a parameter or a global is a type chooser,
  as Ghidra's: a field with a dropdown of the types whose name holds what is
  typed (C's types, `<stdint.h>`, `undefinedN`, and the program's and its
  libraries' structs, unions, enums and typedefs, with kind, size and
  source), best matches first; ↑↓ and Tab or Enter take one, keeping what
  was typed around the name (`const`, `*`, `[n]`); with nothing typed, the
  types set last. "Browse types…" opens the Types view. Any C declaration
  still works. A function's prototype stays a multi-line C field.
