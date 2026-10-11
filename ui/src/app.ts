// The application: one program per tab, a functions panel, the canvas
// listing and the decompiler pane, linked through one selection. Everything
// it knows comes from the public revkit.v1 API; edits are assertions, and
// every view (here, in other tabs, other clients) updates from the
// subscription stream.

import { create } from "@bufbuild/protobuf";
import {
  ChangeCause,
  EmulatorRunMode,
  CommentKind,
  FactKind,
  FlowKind,
  FlowOverrideKind,
  InstructionSet,
  QueryKind,
  Role,
  CodeTokenKind,
  DecompileFailureKind,
  SymbolKind,
  VariableKind,
  ParseCSeverity,
  NavigationKind,
  Endianness,
  ByteKind,
  XrefDirection,
  SliceKind,
  AutoStructureMode,
  AutoStructureRequestSchema,
  autoStructureBodies,
  headerImportPlan,
  type AssertionBody,
  type DecompileFailure,
  type DecompiledFunction,
  type CallingConvention,
  type Variable,
  type ProgramSummary,
  type RevisionEvent,
  type ResolvedImport,
  type Revkit,
  type TypeDefinition,
} from "@revkit/api";
import { SESSION, session, setUserName, userName, userProvenance } from "./api/client";
import { Edits, type RenameTarget } from "./data/edits";
import { addressSpaces, errText, fmtAddr, hex, originClass, parseAddress, provText, setAddressSpaces, spaceOf, spaceUnitNote } from "./data/format";
import { DaemonListing } from "./data/listingSource";
import { Live, type LiveState } from "./data/live";
import type { DaemonStatus } from "./ui/daemon";
import { RowCache } from "./data/rowCache";
import { HeaderKind, RowKind, TokenKind, type ListingRow, type RowShift } from "./data/types";
import type { TokSpan } from "./decomp/pane";
import { DecompilerPane } from "./decomp/pane";
import { EmulatorPanel } from "./emu/panel";
import { DebuggerPanel, type RunName } from "./debug/panel";
import { dprMode, measureFrames, needsFallback } from "./listing/gpu";
import { layoutRow, makeColumns, type Columns } from "./listing/layout";
import { makePainter } from "./listing/painters";
import { DARK, LIGHT } from "./listing/theme";
import { ListingView, PAD_X, type Hit } from "./listing/view";
import { ask, askFields, askMore, choose, toast, type Suggestion } from "./ui/dialogs";
import { $, h, prefs, typing } from "./ui/dom";
import { NAME_FORMS, matchedSpelling, nameForm, onNameForm, setNameForm, showName } from "./data/names";
import { showMenu, showMenuAt, type MenuItem } from "./ui/menu";
import { PROJECT_ARCHIVE_FEATURE, exportProjectDialog, importProjectDialog } from "./ui/archive";
import { FunctionsPanel } from "./ui/functions";
import { CfgView } from "./graph/cfg";
import { CallsView } from "./ui/calls";
import { DataView } from "./ui/data";
import { MemoryMapView } from "./ui/memmap";
import { Dock, type GroupName } from "./ui/dock";
import { TypesView } from "./ui/types";
import { PluginFacts } from "./data/plugins";
import { spell, spellPrototype } from "./data/ctype";
import { annotationAt, setAnnotations } from "./listing/layout";
import { ByteViewer } from "./bytes/viewer";
import { OverviewBars } from "./listing/overview";
import { FIELD_MENU, NO_FIELDS, XREF_LETTER, bumpFields, dropFieldValues, hasPcode, pcodeText, setFieldSources, setPcode, setXrefs, xrefsAt, type FieldFlags } from "./listing/fields";
import { ExprError, evaluateText, globLiteral, globToRegExp, isExpression, isGlob } from "./data/expr";
import { COPY_FORMATS, formatAddresses, formatBytes, type CopyFormat } from "./data/copyformats";

/** "Decompiler crashed (SIGSEGV)", "Decompiler timed out after 30 s", ... */
function failureText(f: DecompileFailure): string {
  switch (f.kind) {
    case DecompileFailureKind.TIMEOUT:
      return `Decompiler timed out${f.deadlineMs ? ` after ${(f.deadlineMs / 1000).toFixed(f.deadlineMs < 10_000 ? 1 : 0)} s` : ""}${f.escalated ? " (with the longer deadline)" : ""}`;
    case DecompileFailureKind.OOM:
      return "Decompiler ran out of memory";
    default:
      return `Decompiler crashed (${f.detail || "unknown signal"})`;
  }
}
import { NotesPanel } from "./ui/notes";
import { Collaborators } from "./ui/presence";
import { deleteProgram, renameProgram, showOpenDialog, undoProgramEdit } from "./ui/open";
import { LIBRARIES_FEATURE, importMap, importTarget, showLibrariesDialog } from "./ui/libraries";
import { LANGUAGE_FEATURE, showLanguageDialog } from "./ui/language";
import { FILESYSTEMS_FEATURE, openFileSystemDialog } from "./ui/filesystem";
import { showPickerDiagnostics } from "./ui/pickdiag";
import { Palette, type Command, type Item } from "./ui/palette";
import { showAbout } from "./ui/about";
import { showPreferences, showShortcuts } from "./ui/preferences";
import { ProvenancePopover, listingEditText, type FactRef, type HoverSubject } from "./ui/provenance";
import { HoverPreviews, type Preview } from "./ui/hover";
import { DATA_KINDS, ListingEditor, MUTABILITY_CHOICES } from "./ui/listingedit";
import { Keymap, PRESETS, chordWhileTyping, eventChord, type PresetId } from "./ui/keymap";
import { previewStructure } from "./ui/autostruct";
import { DiffGraphView } from "./diff/graph";
import { DiffView } from "./diff/view";
import { PatchEditor, PatchesView, exportDialog, patchBytesDialog, type PatchHost } from "./patch/patch";
import { showXrefs } from "./ui/xrefs";
import { ClassesView } from "./ui/classes";
import { FidView } from "./ui/fid";
import { BsimView } from "./ui/bsim";
import { loadPdb, symbolSettings, type PdbHost } from "./ui/pdb";
import { EquateEditor, EquatesView, FORMATS, floatable, formatScalar, type EquateHost, type ScalarTarget } from "./ui/equates";
import { ReferenceEditor, ReferencesView, type ReferenceHost } from "./ui/references";
import { cToDraft, editFunction, type FunctionDraft } from "./ui/editfunction";
import { PythonConsole } from "./scripts/console";
import { Scripts } from "./scripts/manager";
import { Search, type SearchKind } from "./ui/search";

export const FONT = '"JetBrains Mono", monospace';

type PaneName = "functions" | "listing" | "decomp" | "graph" | "calls" | "strings" | "types" | "diff" | "patches" | "memory" | "scripts" | "equates" | "refs" | "search" | "python" | "bytes" | "fid" | "bsim";

/** Where each view goes until the user moves it. */
// The toolbar's menus: palette commands by id ("-" starts a group; ids a daemon lacks are left out).
const EDIT_MENU = ["undo", "redo", "-", "rename", "retype", "comment", "comment-plate", "comment-pre", "comment-post", "comment-eol", "note", "-", "fn-edit", "fn-create", "fn-remove", "flow", "-", "copy-special", "decomp-copy-all", "-", "patch-insn", "patch-bytes", "patch-revert-here", "patch-export", "-", "preferences"];
const NAV_MENU = ["goto", "back", "forward", "history", "-", "follow", "follow-import", "xrefs", "functions", "-", "nav-repeat-next", "nav-repeat-prev", "-", "toggle-decomp", "toggle-graph"];
const ANALYZE_MENU = ["xrefs", "prov", "libraries", "-", "auto-struct", "auto-fill", "struct-from-selection", "type-new", "type-import", "-", "load-pdb", "symbol-settings", "-", "memory-add", "memory-rebase", "language", "-", "emulate", "dbg-launch", "dbg-connect", "-", "compare", "fn-compare", "patch-compare", "-", "bsim-similar", "bsim-ingest"];
/** A command's title in a menu: without the "File: " or "Tools: " prefix the palette uses. */
function menuLabel(title: string): string {
  return title.replace(/^(File|Tools|Help): /, "");
}

const DEFAULT_PLACES: Record<string, GroupName> = { listing: "main", graph: "main", decomp: "side", calls: "side", strings: "side", types: "side", emu: "side", diff: "main", diffgraph: "side", patches: "side", memory: "main", scripts: "side", equates: "side", refs: "side", searchresults: "side", python: "side", bytes: "side", classes: "side", fid: "side", bsim: "side" };

/** The views, their titles and shortcuts (tabs, palette, keys). */
const VIEWS: { id: string; title: string; keys: string; closable?: boolean }[] = [
  { id: "listing", title: "Listing", keys: "Ctrl+2" },
  { id: "graph", title: "Graph", keys: "Ctrl+4" },
  { id: "decomp", title: "Decompiler", keys: "Ctrl+3" },
  { id: "calls", title: "Calls", keys: "Ctrl+5" },
  { id: "strings", title: "Data", keys: "Ctrl+6" },
  { id: "types", title: "Types", keys: "Ctrl+7" },
  // Ghidra's Window → Memory Map (docs/memory-map.md); editable with feature memory-map.
  { id: "memory", title: "Memory map", keys: "Ctrl+Shift+M" },
];
/** The emulator's view, when the daemon has one (feature emulator); the
 * Debugger (feature debugger) takes its place. */
/** Types set last (for the type chooser), newest first; per browser. */
function recentTypes(): string[] {
  try {
    return JSON.parse(localStorage.getItem("revkit.recentTypes") ?? "[]") as string[];
  } catch {
    return [];
  }
}
function rememberType(t: string) {
  if (!t || t.includes("{") || t.includes("\n")) return;
  try {
    localStorage.setItem("revkit.recentTypes", JSON.stringify([t, ...recentTypes().filter((x) => x !== t)].slice(0, 8)));
  } catch {
    /* no storage: no recent list */
  }
}

const EMU_VIEW = { id: "emu", title: "Emulator", keys: "Ctrl+8" };
const DEBUG_VIEW = { id: "emu", title: "Debugger", keys: "Ctrl+8" };
/** Version tracking against another program (feature diff). */
const DIFF_VIEW = { id: "diff", title: "Compare", keys: "Ctrl+9" };
/** Both graphs of the pair selected in Compare (feature diff-detail). */
const DIFF_GRAPH_VIEW = { id: "diffgraph", title: "Graph diff", keys: "Ctrl+Shift+9" };
/** The program's patches (feature patch). */
const PATCHES_VIEW = { id: "patches", title: "Patches", keys: "" };
/** The program's equates (feature equates). */
const EQUATES_VIEW = { id: "equates", title: "Equates", keys: "" };
/** C++ classes from MSVC RTTI (feature msvc-rtti; docs/pe.md). */
const CLASSES_VIEW = { id: "classes", title: "Class hierarchy", keys: "" };
/** Function ID's matches (feature function-id; docs/fid.md). */
const FID_VIEW = { id: "fid", title: "Function ID", keys: "" };
/** BSim databases: similar functions across programs (feature bsim; docs/bsim.md). */
const BSIM_VIEW = { id: "bsim", title: "BSim", keys: "" };
/** The references from and to the code unit at the cursor (feature user-references). */
const REFS_VIEW = { id: "refs", title: "References", keys: "" };
/** Scripts the daemon runs (feature scripts-host; docs/scripting.md). */
const SCRIPTS_VIEW = { id: "scripts", title: "Scripts", keys: "Ctrl+Shift+S" };
/** The byte viewer, Ghidra's Bytes window (feature byte-viewer). */
const BYTES_VIEW = { id: "bytes", title: "Bytes", keys: "" };

/** Next/previous by kind (feature find-next): Ghidra's Ctrl+Alt keys, by KeyboardEvent.code. */
const NAV_KINDS: { code: string; key: string; kind: NavigationKind; name: string }[] = [
  { code: "KeyI", key: "I", kind: NavigationKind.INSTRUCTION, name: "instruction" },
  { code: "KeyD", key: "D", kind: NavigationKind.DATA, name: "data" },
  { code: "KeyU", key: "U", kind: NavigationKind.UNDEFINED, name: "undefined" },
  { code: "KeyL", key: "L", kind: NavigationKind.LABEL, name: "label" },
  { code: "KeyF", key: "F", kind: NavigationKind.FUNCTION, name: "function" },
  { code: "KeyV", key: "V", kind: NavigationKind.DIFFERENT_BYTE, name: "different byte value" },
  { code: "KeyB", key: "B", kind: NavigationKind.NOTE, name: "note (bookmark)" },
];
/** The searches' results table (feature search; docs/ui.md "Search"). */
const SEARCH_VIEW = { id: "searchresults", title: "Search results", keys: "", closable: true };
/** A view's title inside a command ("Show function ID", "Move Python to the side"): lower case but for acronyms and names. */
function viewNoun(title: string): string {
  return title.split(" ").map((w) => (w === w.toUpperCase() || w === "Python" ? w : w.toLowerCase())).join(" ");
}
/** The Python console (feature script-console; docs/ui.md, "Python console"). */
const PYTHON_VIEW = { id: "python", title: "Python", keys: "" };

interface RenameSpec {
  target: RenameTarget;
  current: string;
  what: string;
}

interface RetypeSpec {
  target: RenameTarget;
  /** FactKey for blame (the current value). */
  key: { address: bigint; sub: string };
  what: string;
  prototype: boolean;
  /** What to start from when nothing is asserted (the decompiler's). */
  fallback: string;
}

const COMMENT_KINDS: Record<string, { kind: CommentKind; label: string }> = {
  eol: { kind: CommentKind.EOL, label: "End-of-line comment" },
  pre: { kind: CommentKind.PRE, label: "Pre-comment (above the instruction, and in the decompiler)" },
  post: { kind: CommentKind.POST, label: "Post-comment" },
  plate: { kind: CommentKind.PLATE, label: "Plate comment (a block above, and in the decompiler)" },
};

const FLOW_CHOICES: { kind: FlowOverrideKind; label: string; detail: string }[] = [
  { kind: FlowOverrideKind.BRANCH, label: "Branch", detail: "a call is a jump within the function" },
  { kind: FlowOverrideKind.CALL, label: "Call", detail: "a jump is a call" },
  { kind: FlowOverrideKind.CALL_RETURN, label: "Call + return", detail: "a tail call" },
  { kind: FlowOverrideKind.RETURN, label: "Return", detail: "treat as a return" },
  { kind: FlowOverrideKind.NONE, label: "None", detail: "no override (cancels one)" },
];

function roleName(r: Role): string {
  return r === Role.ADMIN ? "admin" : r === Role.EDITOR ? "editor" : r === Role.VIEWER ? "viewer" : "no role";
}

export interface AppOptions {
  rk: Revkit;
  programId: string;
  params: URLSearchParams;
  dark: boolean;
  features: string[];
  /** Signed in to a daemon with authentication: how to sign out. */
  logout?: () => void;
  /** The daemon status chip (ui/daemon.ts): told the project and the stream's state. */
  daemon?: DaemonStatus;
}

export class App {
  readonly rk: Revkit;
  readonly programId: string;
  projectId = "";
  summary!: ProgramSummary;
  addrWidth = 8;
  cols!: Columns;
  source!: DaemonListing;
  cache!: RowCache;
  view!: ListingView;
  pane!: DecompilerPane;
  functions!: FunctionsPanel;
  notes!: NotesPanel;
  /** Collaborators' cursors (feature presence), else null. */
  collab: Collaborators | null = null;
  /** The debugger panel (feature debugger), else the emulator panel
   * (feature emulator), else null. */
  emu: DebuggerPanel | EmulatorPanel | null = null;
  private emuMarks = { pc: null as bigint | null, breakpoints: new Set<bigint>() };
  palette!: Palette;
  prov!: ProvenancePopover;
  edits!: Edits;
  /** Clear, Disassemble here, Define data, mutability (feature listing-edit). */
  listingEdit!: ListingEditor;
  live!: Live;
  dock!: Dock;
  graph!: CfgView;
  calls!: CallsView;
  data!: DataView;
  memmap!: MemoryMapView;
  types!: TypesView;
  plugins!: PluginFacts;
  /** Plugin facts over the shown function's body, for the graph and the decompiler. */
  fnFacts!: PluginFacts;
  /** The Compare view (feature diff), else null. */
  diff: DiffView | null = null;
  /** The dockable Graph diff (feature diff-detail): follows Compare's pair. */
  diffGraph: DiffGraphView | null = null;
  /** Patching (feature patch): the inline editor and the Patches view, else null. */
  patchEditor: PatchEditor | null = null;
  patches: PatchesView | null = null;
  /** Equates (feature equates): Convert, Set Equate and the Equates window, else null. */
  equateEdit: EquateEditor | null = null;
  equates: EquatesView | null = null;
  /** The class hierarchy (feature msvc-rtti), else null. */
  classes: ClassesView | null = null;
  /** Function ID's matches (feature function-id), else null. */
  fid: FidView | null = null;
  /** BSim's searches (feature bsim), else null. */
  bsim: BsimView | null = null;
  /** User references (feature user-references): Add, Delete, Set primary and the References window, else null. */
  refEdit: ReferenceEditor | null = null;
  refs: ReferencesView | null = null;
  /** Scripts (feature scripts-host): the Script Manager, its runs and output, else null. */
  scripts: Scripts | null = null;
  /** The byte viewer (feature byte-viewer), else null. */
  bytes: ByteViewer | null = null;
  /** The overview bars beside the listing's scrollbar (feature overview), else null. */
  overview: OverviewBars | null = null;
  /** The listing's optional fields (the Fields menu). */
  fields: FieldFlags = { ...NO_FIELDS };
  /** The memory blocks (for file offsets and the byte viewer), refreshed on MEMORY invalidations. */
  blocks: { first: bigint; last: bigint; name: string; initialized: boolean; fileOffset: bigint | null }[] = [];
  /** The last Copy Special (tests). */
  lastCopy: { format: string; text: string } | null = null;
  /** The kind Ctrl+Alt+↑/↓ repeat (the last next/previous used). */
  private navKind: NavigationKind = NavigationKind.FUNCTION;
  private fieldsTimer = 0;
  private pcodeWant = "";
  private xrefsPending = new Set<bigint>();
  private fnNamePending = new Set<bigint>();
  /** The Python console (feature script-console), else null. */
  console: PythonConsole | null = null;
  /** The searches (feature search): dialogs, results, F3; else null. */
  search: Search | null = null;
  /** The decompilation being loaded (loadDecompile), to wait for. */
  private decompLoading: Promise<void> | null = null;
  private graphReload = 0;
  private dataReload = 0;
  private memoryReload = 0;
  private callsReload = 0;
  private dark: boolean;
  private params: URLSearchParams;
  private features: Set<string>;

  private back: bigint[] = [];
  private fwd: bigint[] = [];
  private active: PaneName = "listing";
  /** The keymap preset's bindings (ui/keymap.ts; Preferences, "Keymap: …"). */
  readonly keymap = new Keymap();

  private decompEntry: bigint | null = null;
  private decompFn: DecompiledFunction | null = null;
  private decompSeq = 0;
  private decompCache = new Map<bigint, DecompiledFunction>();
  /** Functions the decompiler failed on (a crash, a timeout), as last reported. */
  private decompFailures = new Map<bigint, DecompileFailure>();
  /** Per function: the newest revision that invalidated its decompilation. */
  private decompStaleAt = new Map<bigint, bigint>();
  private fnReload = 0;
  private notesReload = 0;
  private location: bigint | null = null;
  /** The function containing the location (its entry), as the listing's row says. */
  private locFunc: bigint | null = null;
  /** Import thunks (by entry) and where they go (feature program-libraries). */
  private imports = new Map<bigint, ResolvedImport>();
  /** Rows are numbered with header rows (labels, signatures, plate/pre-comments). */
  headerRows = false;
  /** Function names by entry, from GetFunction, for the status bar. */
  private fnNames = new Map<bigint, string>();
  /** The bytes column as the user set it (Shift+B, Fields); a narrow listing hides it meanwhile. */
  private bytesPref = true;
  private narrowListing = false;
  /** Function entries spread over the program (the benchmark's jump targets). */
  jumpTargets: bigint[] = [];
  liveState: LiveState = "connecting";
  /** Set when the canvas renders below the device pixel ratio. */
  renderNote = "";
  /** The redraw probe's median frame interval at the native ratio (0 = not run). */
  probeMs = 0;
  /** The idle frame interval the probe compared against. */
  probeIdleMs = 0;
  /** The probe at DPR 1, when the native ratio was too slow (0 = not run). */
  probeLowMs = 0;
  /** Settles once the render scale is chosen (the probe has run or was skipped). */
  renderScaleChosen: Promise<void> = Promise.resolve();

  constructor(o: AppOptions) {
    this.rk = o.rk;
    this.programId = o.programId;
    this.params = o.params;
    this.dark = o.dark;
    this.features = new Set(o.features);
    this.logout = o.logout;
    this.daemon = o.daemon;
  }

  private daemon?: DaemonStatus;

  /** Set when signed in (the daemon requires authentication). */
  private logout?: () => void;

  // ---------------------------------------------------------------- setup --

  async start() {
    const { summary, snapshot } = await this.rk.projects.getProgramSummary({ programId: this.programId });
    if (!summary) throw new Error("no program summary");
    this.summary = summary;
    this.projectId = summary.info?.projectId ?? this.programId.split("/")[0];
    this.daemon?.setProject(this.projectId);
    setAddressSpaces(summary.spaces);
    let maxAddr = 0n;
    for (const b of summary.memory) if (b.range?.last && b.range.last.offset > maxAddr) maxAddr = b.range.last.offset;
    this.addrWidth = Math.max(8, maxAddr.toString(16).length);
    // Programs with several memory spaces show space:offset (code:003a),
    // and the status bar switches between the spaces.
    if (addressSpaces().length) {
      this.addrWidth = 0;
      for (const b of summary.memory)
        for (const a of [b.range?.first?.offset, b.range?.last?.offset])
          if (a !== undefined) this.addrWidth = Math.max(this.addrWidth, fmtAddr(a).length);
      const sel = $("st-space") as HTMLSelectElement;
      sel.replaceChildren();
      for (const sp of addressSpaces()) {
        const first = this.firstBlockIn(sp.name);
        if (first === null) continue;
        const o = document.createElement("option");
        o.value = sp.name;
        o.textContent = sp.wordSize > 1 ? `${sp.name} (${sp.wordSize}-byte words)` : sp.name;
        sel.append(o);
      }
      sel.hidden = sel.options.length < 2;
      sel.onchange = () => {
        const a = this.firstBlockIn(sel.value);
        if (a !== null) void this.navigate(a);
      };
    }
    document.title = `${summary.info?.name ?? this.programId} · revkit`;
    $("program").textContent = summary.info?.name ?? this.programId;
    $("program").title = `${this.programId} · ${summary.language?.languageId ?? ""} · ${summary.functionCount.toLocaleString()} functions · ${summary.instructionCount.toLocaleString()} instructions (Ctrl+O to open another)`;
    this.paintContext(summary.info?.folderPath ?? "");

    // Views in two tab groups; placed before anything measures itself.
    this.dock = new Dock($("dock-main"), $("dock-side"), document.querySelector<HTMLElement>(".splitter[data-split=dock-side]"));
    if (this.features.has("debugger")) this.makeDebugger();
    else if (this.features.has("emulator")) this.makeEmulator();
    this.dock.setup(
      this.views().map((v) => ({ ...v, keys: this.k(`view-${v.id}`), el: v.id === "emu" ? this.emu!.el : $(v.id), onShow: () => this.onViewShown(v.id) })),
      DEFAULT_PLACES,
    );

    this.headerRows = this.features.has("listing-header-rows") && (this.params.get("headers") ?? prefs.get("rk.headers")) !== "0";
    try {
      this.fields = { ...NO_FIELDS, ...(JSON.parse(prefs.get("rk.fields") ?? "{}") as Partial<FieldFlags>) };
    } catch {
      this.fields = { ...NO_FIELDS };
    }
    this.setBlocks(summary.memory);
    this.bytesPref = prefs.get("rk.bytes") !== "0";
    this.cols = makeColumns(this.addrWidth, this.bytesPref, this.headerRows, this.fields);
    this.source = new DaemonListing(this.rk, this.programId, this.addrWidth, this.headerRows);
    this.cache = new RowCache(this.source, {
      pageSize: Number(this.params.get("page") ?? 256),
      capacity: Number(this.params.get("pages") ?? 96),
    });
    // Total rows for the scrollbar, plus the first page.
    const first = await this.source.rows(0, this.cache.pageSize);
    this.cache.rowCount = first.totalRows;
    this.cache.insert(first.startRow, first.rows, first.revision, first.totalRows);
    this.cache.onRowCount = () => this.reanchor();

    const canvas = $("listing-canvas") as HTMLCanvasElement;
    this.view = new ListingView({
      canvas,
      cache: this.cache,
      source: this.source,
      painter: makePainter(this.params.get("render")),
      theme: this.dark ? DARK : LIGHT,
      columns: this.cols,
      fontFamily: FONT,
      fontSize: 13,
      rowHeight: 18,
    });
    if (this.params.has("hold")) this.view.holdMs = Number(this.params.get("hold"));
    setFieldSources({ fileOffset: (a) => this.fileOffsetOf(a), fnName: (e) => this.fnName(e) });
    if (this.features.has("overview")) {
      this.overview = new OverviewBars({ rk: this.rk, programId: this.programId, navigate: (a) => void this.navigate(a, { focus: "listing" }) });
      this.overview.dark = this.dark;
      this.overview.el.hidden = prefs.get("rk.overview") === "0";
      canvas.parentElement!.append(this.overview.el);
      this.view.resize();
      this.overview.reload(0);
    }
    this.view.arrows = (this.params.get("arrows") ?? prefs.get("rk.arrows")) !== "0";
    this.paintColumnHeader();

    this.pane = new DecompilerPane($("cm"));
    $("decomp-retry").addEventListener("click", () => void this.retryDecompile());
    $("decomp-repro").addEventListener("click", () => void this.exportRepro());
    this.pane.showMessage("// Select an instruction to decompile its function.");
    this.functions = new FunctionsPanel($("fnpanel"), this.rk, this.programId, this.addrWidth, this.features);
    // Demangled names as the setting spells them (names.ts): every view
    // draws its names again.
    onNameForm(() => void this.renameShown());
    this.notes = new NotesPanel($("notes"), this.rk, this.programId, this.addrWidth);
    this.prov = new ProvenancePopover(this.rk, this.programId);
    this.prov.previews = new HoverPreviews({
      rk: this.rk,
      programId: this.programId,
      rowsAround: async (address, rows) => (await this.source.rowsAround(address, 0, rows)).rows,
      rowText: (r) => this.view.rowText(r),
      debugValue: (item, frame) => (this.emu instanceof DebuggerPanel ? this.emu.evaluate([item], frame) : Promise.resolve(null)),
    });
    this.edits = new Edits(this.rk, this.programId);
    this.listingEdit = new ListingEditor({
      rk: this.rk,
      programId: this.programId,
      edits: this.edits,
      view: this.view,
      cache: this.cache,
      pointerSize: summary.language?.pointerSize || 8,
      armThumb: this.armThumb(),
      settle: (rev) => this.live.waitFor(rev),
      undo: () => void this.redoOrUndo("undo"),
      typeSuggestions: (t) => this.typeSuggestions(t),
    });
    this.palette = new Palette(() => this.commands(), (q, s) => this.searchItems(q, s));
    this.setupViews();

    this.wire();
    void this.functions.load().catch((e) => toast(`Functions: ${errText(e)}`, { kind: "error" }));
    void this.notes.load();
    void this.loadJumpTargets();

    if (this.emu) this.wireEmulator();

    if (this.features.has("presence")) {
      const c = new Collaborators(this.rk, this.projectId, this.programId);
      c.onChange = () => this.showCollaborators();
      this.collab = c;
      // Restart daemon… names the others it would drop.
      if (this.daemon) this.daemon.others = () => [...c.cursors.values()].map((x) => x.name);
    }
    this.live = new Live(
      this.rk,
      this.projectId,
      this.programId,
      {
        onRevision: (ev) => this.onRevision(ev),
        onResync: (head) => this.resync(head),
        onState: (s, head) => this.setLive(s, head),
        onPresence: (p) => this.collab?.update(p),
      },
      snapshot?.revision ?? 0n,
      this.collab !== null,
    );

    // Initial location: the URL's #address, else main, else the entry point.
    const fromHash = parseAddress(location.hash.slice(1));
    let start = fromHash;
    if (start === null) start = await this.findSymbol("main");
    if (start === null) start = summary.entryPoints[0]?.address?.offset ?? null;
    if (start !== null) await this.view.goTo(start, { align: "third" });
    else this.view.scrollToRow(0);
    canvas.focus();
    this.setupResize();
    this.renderScaleChosen = this.chooseRenderScale();
  }

  /** The emulator view (feature emulator): a dockable panel, made before the
   * dock is set up; its marks are wired once the listing exists (wireEmulator). */
  private makeEmulator() {
    this.emu = new EmulatorPanel(
      this.rk,
      this.programId,
      {
        showPc: (pc) => {
          this.emuMarks.pc = pc;
          this.pane.setPc(pc);
          this.graph.pc = pc;
          this.graph.invalidate();
          if (pc !== null) {
            void this.view.goTo(pc, { align: "center" });
            if (this.dock.isVisible("graph")) this.graph.select(pc);
          }
          this.view.invalidate();
        },
        marksChanged: () => this.view.invalidate(),
        show: () => this.showView("emu"),
        notify: (text, error) => toast(text, { kind: error ? "error" : "info" }),
      },
      this.addrWidth,
    );
    this.emuMarks.breakpoints = this.emu.breakpoints;
  }

  /** The debugger view (feature debugger): the emulator's place, with live
   * targets (feature debugger-live) and the recorded timeline. */
  private makeDebugger() {
    this.emu = new DebuggerPanel(
      this.rk,
      this.programId,
      {
        showPc: (pc) => this.showEmuPc(pc),
        marksChanged: () => this.view.invalidate(),
        show: () => this.showView("emu"),
        notify: (text, error) => toast(text, { kind: error ? "error" : "info" }),
        selection: () => this.location,
        showFrame: (pc) => void this.navigate(pc, { focus: "listing" }),
      },
      this.addrWidth,
      this.features.has("debugger-live"),
      this.features.has("firmware-emulation"),
      this.features.has("debugger-stack"),
      this.features.has("debugger-values"),
      this.features.has("debugger-disassembly"),
      this.features.has("debugger-copy"),
      this.features.has("debugger-conditions"),
      this.features.has("debugger-emulate-from"),
    );
    this.emuMarks.breakpoints = this.emu.breakpoints;
  }

  private showEmuPc(pc: bigint | null) {
    this.emuMarks.pc = pc;
    this.pane.setPc(pc);
    this.graph.pc = pc;
    this.graph.invalidate();
    if (pc !== null) {
      void this.view.goTo(pc, { align: "center" });
      if (this.dock.isVisible("graph")) this.graph.select(pc);
    }
    this.view.invalidate();
  }

  /** Step, over, out or continue in whichever panel there is. */
  private emuRun(name: RunName) {
    const e = this.emu;
    if (e instanceof DebuggerPanel) return void e.run(name);
    if (e) {
      const modes = { into: EmulatorRunMode.STEP_INTO, over: EmulatorRunMode.STEP_OVER, out: EmulatorRunMode.STEP_OUT, run: EmulatorRunMode.RUN };
      void e.run(modes[name]);
    }
  }

  /** Gutter breakpoints and the pc mark in the listing. */
  private wireEmulator() {
    const emu = this.emu!;
    this.view.emuMarks = this.emuMarks;
    this.view.onGutterClick = (row) => void emu.toggleBreakpoint(row.address);
  }

  /** The views this daemon supports, in tab order. */
  private views() {
    const views = this.emu ? [...VIEWS, this.emu instanceof DebuggerPanel ? DEBUG_VIEW : EMU_VIEW] : [...VIEWS];
    if (this.features.has("diff")) views.push(DIFF_VIEW);
    if (this.features.has("diff-detail")) views.push(DIFF_GRAPH_VIEW);
    if (this.features.has("patch")) views.push(PATCHES_VIEW);
    if (this.features.has("equates")) views.push(EQUATES_VIEW);
    if (this.features.has("user-references")) views.push(REFS_VIEW);
    if (this.features.has("scripts-host")) views.push(SCRIPTS_VIEW);
    if (this.features.has("byte-viewer")) views.push(BYTES_VIEW);
    if (this.features.has("search")) views.push(SEARCH_VIEW);
    if (this.features.has("script-console") && this.features.has("scripts-host")) views.push(PYTHON_VIEW);
    if (this.features.has("msvc-rtti")) views.push(CLASSES_VIEW);
    if (this.features.has("function-id")) views.push(FID_VIEW);
    if (this.features.has("bsim")) views.push(BSIM_VIEW);
    return views;
  }

  /** Shows the debugger's target picker set to `kind`. */
  private debugTarget(kind: "launch" | "remote") {
    if (!(this.emu instanceof DebuggerPanel)) return;
    this.showView("emu");
    const sel = this.emu.el.querySelector<HTMLSelectElement>("[data-testid=dbg-target]")!;
    sel.value = kind;
    sel.dispatchEvent(new Event("change"));
    if (kind === "remote") this.emu.el.querySelector<HTMLInputElement>("[data-testid=dbg-target-input]")!.focus();
    else void this.emu.connect();
  }

  /** Starts emulating at the selection (a call into it; a process at the entry point). */
  private async emulateHere() {
    if (!this.emu) return toast("This daemon has no emulator", { kind: "error" });
    const addr = this.location;
    if (addr === null) return toast("Select an instruction to emulate from", { kind: "error" });
    await this.emu.start(addr);
  }

  /** Function entries spread over the program, for the benchmark's random jumps. */
  private async loadJumpTargets() {
    try {
      const first = await this.rk.queries.listFunctions({ programId: this.programId, page: { pageSize: 2000 } });
      const total = Number(first.page?.totalCount ?? 0n);
      const out = first.functions.map((f) => f.entry!.offset);
      if (total > out.length && this.features.has("function-list-offset")) {
        for (let k = 1; k < 10; k++) {
          const r = await this.rk.queries.listFunctions({ programId: this.programId, offset: BigInt(Math.floor((total * k) / 10)), page: { pageSize: 500 } });
          out.push(...r.functions.map((f) => f.entry!.offset));
        }
      }
      this.jumpTargets = out;
    } catch {
      /* the benchmark reports it */
    }
  }

  private paintColumnHeader() {
    const hdr = $("colhdr");
    const cw = this.view.charWidth;
    const c = this.cols;
    const cols: [number, string][] = [
      [c.addr, "Address"],
      ...(c.fields.fileOffset ? ([[c.fileOff, "File off"]] as [number, string][]) : []),
      ...(c.fields.fnOffset ? ([[c.fnOff, "Function offset"]] as [number, string][]) : []),
      ...(c.showBytes ? ([[c.bytes, "Bytes"]] as [number, string][]) : []),
      [c.xref, "Refs"],
      ...(c.labelWidth > 0 ? ([[c.label, "Label"]] as [number, string][]) : []),
      [c.mnem, "Instruction"],
      [c.comment, "Comment"],
    ];
    hdr.replaceChildren(...cols.map(([col, label]) => h("span", { style: `left:${PAD_X + col * cw}px` }, label)));
  }

  private setupResize() {
    const canvas = this.view.canvas;
    new ResizeObserver(() => {
      this.view.resize();
      this.fitListingColumns();
    }).observe(canvas);
    const watchDpr = () => {
      const mq = matchMedia(`(resolution: ${window.devicePixelRatio}dppx)`);
      mq.addEventListener(
        "change",
        () => {
          this.view.resize();
          watchDpr();
        },
        { once: true },
      );
    };
    watchDpr();
    // Splitters: drag to resize the side panes; widths persist.
    for (const sp of document.querySelectorAll<HTMLElement>(".splitter")) {
      const target = $(sp.dataset.split!);
      const key = `rk.w.${sp.dataset.split}`;
      const saved = Number(prefs.get(key));
      if (saved > 120) target.style.width = `${saved}px`;
      sp.addEventListener("pointerdown", (e) => {
        e.preventDefault();
        sp.setPointerCapture(e.pointerId);
        sp.classList.add("dragging");
        const x0 = e.clientX;
        const w0 = target.getBoundingClientRect().width;
        const sign = sp.dataset.split === "dock-side" ? -1 : 1;
        const move = (m: PointerEvent) => {
          const w = Math.max(160, Math.min(innerWidth * 0.6, w0 + sign * (m.clientX - x0)));
          target.style.width = `${w}px`;
        };
        const up = () => {
          sp.classList.remove("dragging");
          sp.removeEventListener("pointermove", move);
          sp.removeEventListener("pointerup", up);
          prefs.set(key, String(Math.round(target.getBoundingClientRect().width)));
        };
        sp.addEventListener("pointermove", move);
        sp.addEventListener("pointerup", up);
      });
    }
  }

  /**
   * Rendering fallback: when a full listing redraw at the native device
   * pixel ratio misses the frame budget (WebKitGTK without GPU
   * compositing), draw the canvas at DPR 1 and say so. ?dpr=1 forces it,
   * ?dpr=native disables the check.
   */
  private async chooseRenderScale() {
    const mode = dprMode(this.params.get("dpr"));
    const native = window.devicePixelRatio || 1;
    if (typeof mode === "number") {
      if (mode !== native) this.setRenderScale(mode, `Rendering the listing at DPR ${mode} (forced by ?dpr=${mode}); the display is at ${native}.`, true);
      return;
    }
    if (mode === "native" || native <= 1) return;
    await new Promise((r) => setTimeout(r, 600));
    if (document.visibilityState !== "visible") return;
    const idle = await measureFrames(() => {}, 24, 4);
    const ms = await measureFrames(() => this.view.render());
    this.probeMs = ms;
    this.probeIdleMs = idle;
    document.body.dataset.probeMs = ms.toFixed(1);
    if (!needsFallback(ms, idle, native)) return;
    // Too slow at the native ratio: render at DPR 1. Where the cost is the
    // compositor painting the whole window at device scale (WebKitGTK on
    // the CPU), that gains little, so check it doesn't cost more either:
    // if it is clearly slower, go back and only warn.
    this.view.dprOverride = 1;
    this.view.resize();
    const at1 = await measureFrames(() => this.view.render());
    this.probeLowMs = at1;
    const facts = `a full listing redraw takes ${ms.toFixed(1)} ms per frame at DPR ${native} and ${at1.toFixed(1)} ms at DPR 1 (idle frames ${idle.toFixed(1)} ms)`;
    if (at1 <= ms * 1.1) {
      this.setRenderScale(1, `No GPU compositing: ${facts}, so the listing renders at DPR 1 and is upscaled. Pass ?dpr=native to override.`);
      return;
    }
    this.view.dprOverride = null;
    this.view.resize();
    this.renderNote = `No GPU compositing: ${facts}. DPR 1 is slower on this engine, so the listing stays at DPR ${native}. GPU compositing, or a browser tab, restores 60 fps.`;
    const el = $("st-render");
    el.hidden = false;
    el.textContent = `software rendering · ${Math.round(ms)} ms/frame`;
    el.title = this.renderNote;
    document.body.dataset.renderDpr = String(native);
  }

  setRenderScale(dpr: number, why: string, forced = false) {
    this.view.dprOverride = dpr;
    this.view.resize();
    this.renderNote = why;
    const el = $("st-render");
    el.hidden = false;
    el.textContent = `DPR ${dpr} · ${forced ? "forced" : "software rendering"}`;
    el.title = why;
    document.body.dataset.renderDpr = String(dpr);
  }

  // --------------------------------------------------------------- wiring --

  private wire() {
    const v = this.view;
    v.onSelect = (row) => this.onListingSelect(row);
    v.onFollow = (t) => void this.navigate(t);
    v.onXrefs = (row) => void this.xrefsFor(row.address, row.label || hex(row.address));
    v.onNotice = (text) => toast(text);
    v.onArrow = (t) => void this.navigate(t);
    v.onDisclosure = (row) => {
      if (this.features.has("listing-edit")) void this.listingEdit.toggle(row);
    };
    v.noteAddrs = this.notes.addresses;
    this.notes.onOpen = (n) => void this.navigate(n.address, { focus: "listing" });
    this.notes.onChange = () => {
      v.noteAddrs = this.notes.addresses;
      v.invalidate();
    };
    v.onHover = (hit, x, y) => this.prov.hover(hit ? this.hoverForHit(hit) : null, x, y);
    v.onContextMenu = (x, y) => this.contextMenu("listing", x, y);
    v.onStatus = (first, total) => {
      const t = `row ${first.toLocaleString()} / ${total.toLocaleString()}`;
      const el = $("st-rows");
      if (el.textContent !== t) el.textContent = t;
      this.wantPluginFacts();
      this.wantFields();
    };
    this.pane.onSelectAddress = (addr) => void this.onDecompSelect(addr);
    this.pane.onFollow = (t) => void this.navigate(t);
    this.pane.onHover = (s, x, y) => this.prov.hover(s ? this.hoverForSpan(s) : null, x, y);
    this.pane.onContextMenu = (x, y) => this.contextMenu("decomp", x, y);
    // The slice went from the C (Escape, another function): the listing's marks too.
    this.pane.onSliceCleared = () => {
      this.view.sliceMarks = null;
      this.view.invalidate();
    };
    this.functions.onOpen = (entry) => void this.navigate(entry, { focus: "listing" });
    this.functions.onExternal = (entry) => this.followImport(entry);
    if (this.features.has(LIBRARIES_FEATURE)) void this.loadImports();
    this.functions.onContext = (row, marked, x, y) => this.functionMenu(row, marked, x, y);
    this.functions.onLoaded = () => {
      // Names may have changed under the status bar.
      const row = this.view.selectedRowData();
      if (this.location !== null) this.setLocation(this.location, row && row.address === this.location ? row : undefined);
    };
    this.prov.onUndo = async (seq, label) => {
      try {
        const r = await this.edits.retract([seq], `Undo ${label}`);
        toast(`Retracted ${label}`, { action: { label: "Restore", run: () => void this.redoOrUndo("undo") } });
        await this.live.waitFor(r.revision);
      } catch (e) {
        toast(errText(e), { kind: "error" });
      }
    };
    this.edits.onChange = () => this.updateButtons();
    // An edit can change which function the selection is in (function
    // bounds, flow overrides): follow it when the selected row is refetched.
    this.cache.onUpdate(() => this.followSelection());
    this.view.onReselect = () => this.followSelection();

    for (const [id, el] of [
      ["functions", $("functions")],
      ["listing", $("listing")],
      ["decomp", $("decomp")],
    ] as const)
      el.addEventListener("focusin", () => (this.active = id));

    $("program").onclick = () => this.openProgram();
    $("project-crumb").onclick = () => this.openProgram(true);
    $("import-binary").onclick = () => this.openProgram(false, true);
    $("file").onclick = () => showMenuAt($("file"), this.fileItems(), "File");
    $("editmenu").onclick = () => showMenuAt($("editmenu"), this.commandMenu(EDIT_MENU), "Edit");
    $("viewmenu").onclick = () => showMenuAt($("viewmenu"), this.viewMenuItems(), "View");
    $("navmenu").onclick = () => showMenuAt($("navmenu"), this.commandMenu(NAV_MENU), "Navigate");
    $("analyzemenu").onclick = () => showMenuAt($("analyzemenu"), this.commandMenu(ANALYZE_MENU), "Analyze");
    $("allmenu").onclick = () =>
      showMenuAt($("allmenu"), [
        { label: "File", testid: "all-menu-file", submenu: this.fileItems() },
        { label: "Edit", testid: "all-menu-edit", submenu: this.commandMenu(EDIT_MENU) },
        { label: "View", testid: "all-menu-view", submenu: this.viewMenuItems() },
        { label: "Navigate", testid: "all-menu-nav", submenu: this.commandMenu(NAV_MENU) },
        { label: "Analyze", testid: "all-menu-analyze", submenu: this.commandMenu(ANALYZE_MENU) },
        ...(this.search ? [{ label: "Search", testid: "all-menu-search", submenu: this.searchMenuItems() }] : []),
      ], "Menus");
    const searchMenu = $("searchmenu");
    searchMenu.hidden = !this.search;
    searchMenu.onclick = () => showMenuAt(searchMenu, this.searchMenuItems(), "Search");
    $("back").onclick = () => void this.goBack();
    $("forward").onclick = () => void this.goForward();
    $("history").onclick = () => showMenuAt($("history"), this.historyItems(), "History");
    $("fields").onclick = () => showMenuAt($("fields"), this.fieldItems(), "Fields");
    $("search").onclick = () => this.palette.open("");
    $("help").onclick = () => this.palette.open(">");
    $("undo").onclick = () => void this.redoOrUndo("undo");
    $("redo").onclick = () => void this.redoOrUndo("redo");
    if (session.identity) {
      // Signed in: the name is the daemon's, not ours to change.
      const who = session.identity;
      $("user").textContent = `user:${who.name}`;
      $("user").title = `Signed in as ${who.name} (${roleName(who.role)}); the daemon records your edits as user:${who.name}`;
      $("user").onclick = () => this.palette.open(">log out");
      const out = $("logout");
      out.hidden = false;
      out.onclick = () => this.logout?.();
    } else {
      $("user").onclick = () => void this.changeUser();
      $("user").textContent = `user:${userName()}`;
    }
    window.addEventListener("keydown", (e) => this.onKey(e));
    this.keymap.onChange = () => this.applyKeymap();
    this.applyKeymap();
    // Mouse back/forward buttons.
    window.addEventListener("mouseup", (e) => {
      if (e.button === 3) void this.goBack();
      else if (e.button === 4) void this.goForward();
    });
    window.addEventListener("hashchange", () => {
      const a = parseAddress(location.hash.slice(1));
      if (a !== null && a !== this.location) void this.navigate(a);
    });
  }

  private onKey(e: KeyboardEvent) {
    const mod = e.ctrlKey || e.metaKey;
    const k = e.key;
    if (mod && !e.shiftKey && !e.altKey && (k === "k" || k === "p")) return this.consume(e, () => this.palette.open(""));
    if ((mod && e.shiftKey && (k === "P" || k === "p")) || k === "F1") return this.consume(e, () => this.palette.open(">"));
    if (mod && !e.shiftKey && !e.altKey && k === "o") return this.consume(e, () => this.openProgram());
    // Next/previous by kind (Ghidra's Ctrl+Alt keys; Shift goes back), and
    // Ctrl+Alt+↓/↑ for the kind used last.
    if (e.ctrlKey && e.altKey && !e.metaKey && !typing() && !document.querySelector(".backdrop")) {
      const nk = NAV_KINDS.find((n) => n.code === e.code);
      if (nk && this.features.has("find-next")) return this.consume(e, () => void this.findNext(nk.kind, e.shiftKey));
      if ((k === "ArrowDown" || k === "ArrowUp") && this.features.has("find-next")) return this.consume(e, () => void this.findNext(this.navKind, k === "ArrowUp"));
    }
    if (document.querySelector(".backdrop")) {
      // A modal owns the keyboard; Alt+← must not take the browser back a page.
      if (e.altKey && (k === "ArrowLeft" || k === "ArrowRight")) e.preventDefault();
      return;
    }
    if (k === "Escape" && this.prov.isOpen) return this.prov.hide();
    if (this.emu?.active && !typing() && (k === "F7" || k === "F8" || k === "F9")) return this.consume(e, () => this.emu!.handleKey(e));
    // The active keymap preset's bindings (ui/keymap.ts).
    if (this.dispatchKey(e)) return;
    if (k === "Escape") return;
    if (typing()) return;
    // Scripts' keys (their @keybinding, or one bound in the Script Manager).
    if ((mod || e.altKey || /^F\d+$/.test(k)) && this.scripts?.handleKey(e)) return;
    if (mod || e.altKey) return;
    if (!this.inCodeView()) return;
    this.scripts?.handleKey(e);
  }

  /** The listing, the decompiler or the graph has the focus (not a panel's list). */
  private inCodeView(): boolean {
    const a = this.active;
    return !(a === "functions" || a === "strings" || a === "types" || a === "calls" || a === "diff" || a === "patches" || a === "memory" || a === "scripts" || a === "equates" || a === "refs" || a === "search" || a === "python" || a === "bytes" || a === "fid" || a === "bsim");
  }

  /**
   * Runs the action the active keymap binds the key to, if one applies
   * where the focus is. A plain key (no Ctrl or Alt) acts only in the
   * listing, the decompiler or the graph and never in a text field; a key
   * the focused view handled already (the decompiler's Escape dropping its
   * selection) is left alone. True when an action ran.
   */
  private dispatchKey(e: KeyboardEvent): boolean {
    if (e.defaultPrevented) return false;
    const chord = eventChord(e);
    const ids = this.keymap.actions(chord);
    if (!ids.length) return false;
    const plain = !/^(Ctrl|Alt)\+/.test(chord) && !/^(Shift\+)?F\d+$/.test(chord);
    const isTyping = typing();
    const acts = this.keyActions();
    for (const id of ids) {
      const a = acts[id];
      if (!a) continue;
      if (isTyping && (a.scope !== "any" || !chordWhileTyping(chord))) continue;
      const scope = plain && (a.scope === "any" || a.scope === "app") ? "code" : a.scope;
      if (scope === "code" && !this.inCodeView()) continue;
      if (scope === "listing" && this.active !== "listing") continue;
      if (a.when && !a.when()) continue;
      this.consume(e, a.run);
      return true;
    }
    return false;
  }

  /**
   * What each action a key can be bound to does (ui/keymap.ts names them;
   * the palette's commands share the ids). `scope`: "any" works from a text
   * field too (Ctrl and Alt keys only), "app" anywhere else, "code" in the
   * listing, decompiler or graph, "listing" in the listing only. `when`:
   * the key falls through to the next action bound to it (or the browser)
   * unless it holds.
   */
  private keyActions(): Record<string, { scope: "any" | "app" | "code" | "listing"; when?: () => boolean; run: () => void }> {
    const le = this.listingEdit;
    const edit = (act: () => void) => () => {
      if (!this.features.has("listing-edit")) return toast("This daemon can't edit the listing (Clear, Disassemble, Data: feature listing-edit)", { kind: "error" });
      act();
    };
    const view = (id: string, has = true) => ({ scope: "app" as const, when: () => has, run: () => this.showView(id) });
    const search = this.search;
    return {
      goto: { scope: "code", run: () => this.palette.open("") },
      back: { scope: "any", run: () => void this.goBack() },
      forward: { scope: "any", run: () => void this.goForward() },
      rename: { scope: "code", run: () => void this.rename() },
      retype: { scope: "code", run: () => void this.retype() },
      comment: { scope: "code", run: () => void this.comment() },
      xrefs: { scope: "code", run: () => void this.xrefs() },
      follow: { scope: "code", when: () => this.active === "decomp", run: () => this.followFromDecomp() },
      "fn-edit": { scope: "code", when: () => this.features.has("parse-c") && this.editFunctionTarget(false) !== null, run: () => void this.editFunctionAt(this.editFunctionTarget(false)!) },
      // Create function; at a function's entry (or on its name or signature
      // in the decompiler) Edit Function, as Ghidra's F.
      "fn-create": {
        scope: "code",
        run: () => {
          const at = this.features.has("parse-c") ? this.editFunctionTarget(true) : null;
          if (at !== null) void this.editFunctionAt(at);
          else void this.createFunction();
        },
      },
      "fn-remove": { scope: "code", run: () => void this.removeFunction() },
      flow: { scope: "code", run: () => void this.flowOverride() },
      note: { scope: "code", run: () => void this.addNote() },
      prov: { scope: "code", run: () => void this.showProvenanceForSelection() },
      bytes: { scope: "code", run: () => this.toggleBytes() },
      // Ghidra's Set Equate, on a scalar operand or a decompiler constant.
      "eq-set": { scope: "code", run: () => void this.setEquate() },
      // Ghidra's References > Add, from the instruction at the cursor.
      "ref-add": { scope: "code", when: () => this.active === "listing", run: () => void this.addReference() },
      // Shift+[ (Ghidra's Auto Create Structure), on a decompiler variable.
      "auto-struct": { scope: "code", when: () => this.autoStructTarget() !== null, run: () => void this.autoStructure(false) },
      "toggle-graph": { scope: "code", when: () => this.active === "listing" || this.active === "graph", run: () => this.toggleGraph() },
      "toggle-decomp": { scope: "code", run: () => this.showView(this.active === "decomp" ? "listing" : "decomp") },
      undo: { scope: "app", run: () => void this.redoOrUndo("undo") },
      redo: { scope: "app", run: () => void this.redoOrUndo("redo") },
      "search-memory": { scope: "any", when: () => !!search, run: () => search!.open("memory") },
      "search-text": { scope: "any", when: () => !!search, run: () => search!.open("text") },
      "search-scalars": { scope: "any", when: () => !!search, run: () => search!.open("scalars") },
      "search-next": { scope: "any", when: () => !!search, run: () => void search!.repeat(false) },
      "search-prev": { scope: "any", when: () => !!search, run: () => void search!.repeat(true) },
      "copy-special": { scope: "app", run: () => void this.copySpecial() },
      "patch-insn": { scope: "app", when: () => this.patchEditor !== null, run: () => this.patchInstruction() },
      "patch-bytes": { scope: "app", when: () => this.patchEditor !== null, run: () => void this.patchBytes() },
      "slice-next": { scope: "code", when: () => this.pane.slice !== null, run: () => void this.pane.sliceStep(1) },
      "slice-prev": { scope: "code", when: () => this.pane.slice !== null, run: () => void this.pane.sliceStep(-1) },
      "emu-break": { scope: "code", when: () => this.emu !== null && this.location !== null, run: () => void this.emu?.toggleBreakpoint(this.location!) },
      functions: { scope: "app", run: () => this.functions.focusFilter() },
      "view-listing": view("listing"),
      "view-decomp": view("decomp"),
      "view-graph": view("graph"),
      "view-calls": view("calls"),
      "view-strings": view("strings"),
      "view-types": view("types"),
      "view-memory": view("memory"),
      "view-emu": view("emu", !!this.emu),
      "view-diff": view("diff", !!this.diff),
      "view-diffgraph": view("diffgraph", !!this.diffGraph),
      "view-scripts": view("scripts", !!this.scripts),
      "view-bytes": view("bytes", !!this.bytes),
      "le-disasm": { scope: "listing", run: edit(() => void le.disassemble()) },
      "le-clear": { scope: "listing", run: edit(() => void le.clear()) },
      "le-cycle": { scope: "listing", run: edit(() => void le.cycle()) },
      ...Object.fromEntries(DATA_KINDS.map((d) => [`le-data-${d.id}`, { scope: "listing" as const, run: edit(() => void le.defineKind(d.id)) }])),
      "le-array": { scope: "listing", run: edit(() => void le.array()) },
      "le-type": { scope: "listing", run: edit(() => void le.chooseType()) },
      "le-expand": { scope: "listing", run: edit(() => void le.toggle(undefined, true)) },
      "le-collapse": { scope: "listing", run: edit(() => void le.toggle(undefined, false)) },
    };
  }

  /** ARM with Thumb (not Cortex-M, which is Thumb only): Disassemble offers both. */
  private armThumb(): boolean {
    const id = this.summary.language?.languageId ?? "";
    return id.startsWith("ARM:") && !/cortex/i.test(id);
  }

  /** An action's keys in the active keymap, for menus and the palette. */
  private k(action: string): string | undefined {
    return this.keymap.label(action);
  }

  /** The keymap changed (or the page started): tooltips and tabs show its keys. */
  private applyKeymap() {
    const tip = (id: string, what: string, action: string) => {
      const keys = this.k(action);
      $(id).title = keys ? `${what} (${keys})` : what;
    };
    tip("back", "Back", "back");
    tip("forward", "Forward", "forward");
    tip("undo", "Undo", "undo");
    tip("redo", "Redo", "redo");
    this.dock.setKeys((id) => this.k(`view-${id}`));
    this.notes.setAddKeys(this.k("note") ?? "");
    // The status bar's reminder: the first key of each.
    const first = (id: string) => this.k(id)?.split(" / ")[0];
    const hint = (id: string, what: string) => (first(id) ? `${first(id)} ${what}` : null);
    const data = [first("le-disasm"), first("le-clear"), first("le-cycle")].filter(Boolean).join(" ");
    const hints = [hint("rename", "rename"), hint("retype", "type"), hint("comment", "comment"), hint("xrefs", "xrefs"), data ? `${data} code/data` : null, hint("toggle-graph", "graph"), hint("toggle-decomp", "decompiler"), "Ctrl+2–9 views", "F1 commands"];
    const el = document.querySelector<HTMLElement>("#statusbar .hints");
    if (el) el.textContent = hints.filter(Boolean).join(" · ");
    document.body.dataset.keymap = this.keymap.preset;
  }

  private setKeymap(id: PresetId) {
    this.keymap.set(id);
    toast(`Keymap: ${this.keymap.name}`);
  }

  private showPreferences() {
    showPreferences({ keymap: this.keymap, showShortcuts: () => this.showShortcuts() });
  }

  private showShortcuts() {
    const titles = new Map<string, string>();
    for (const c of this.commands()) if (!titles.has(c.id)) titles.set(c.id, c.title);
    // Keys whose commands are named for the view, or have no palette entry.
    titles.set("follow", "Follow reference (the decompiler)");
    for (const [id, t] of [["view-emu", "Show the emulator or debugger"], ["view-diff", "Show Compare"], ["view-diffgraph", "Show the graph diff"], ["view-scripts", "Show scripts"], ["view-bytes", "Show bytes"]])
      if (!titles.has(id)) titles.set(id, t);
    showShortcuts(this.keymap, titles);
  }

  private consume(e: KeyboardEvent, fn: () => void) {
    e.preventDefault();
    e.stopPropagation();
    fn();
  }

  // ------------------------------------------------------------ selection --

  /** The selected row was refetched or reselected: if it is now in another
   * function, show that one. */
  private followSelection() {
    const row = this.view.selectedRowData();
    if (!row || row.address !== this.location || row.kind === RowKind.Header) return;
    if (row.func !== this.decompEntry && !(row.func === null && this.decompEntry === null)) {
      this.setLocation(row.address, row);
      void this.showDecompileFor(row);
    }
  }

  private onListingSelect(row: ListingRow) {
    this.view.syncAddrs = null;
    this.setLocation(row.address, row);
    void this.showDecompileFor(row);
  }

  /** C -> listing: select the instruction, highlight the clicked line's. */
  private async onDecompSelect(addr: bigint) {
    this.view.syncAddrs = this.pane.lineAddresses(this.pane.selected);
    const row = await this.view.goTo(addr, { notify: false, align: "center" });
    if (row < 0) return;
    const r = this.cache.get(row);
    this.setLocation(addr, r);
  }

  /** A function's name for the status bar: from the panel's pages, the
   * decompiler, or GetFunction (cached until the function list changes). */
  private fnName(entry: bigint): string | undefined {
    const n = this.functions.nameAt(entry) ?? (this.decompFn?.entry?.offset === entry ? this.decompFn.name : undefined) ?? this.fnNames.get(entry);
    if (n !== undefined) return n;
    if (this.fnNamePending.has(entry)) return undefined;
    this.fnNamePending.add(entry);
    void this.rk.queries.getFunction({ programId: this.programId, address: { offset: entry } }).then(
      (r) => {
        this.fnNamePending.delete(entry);
        if (!r.function) return;
        this.fnNames.set(entry, r.function.name);
        if (this.fields.fnOffset) {
          bumpFields();
          this.view.invalidate();
        }
        const row = this.view.selectedRowData();
        if (this.location !== null && row?.func === entry) this.setLocation(this.location, row);
      },
      () => this.fnNamePending.delete(entry),
    );
    return undefined;
  }

  /** Collaborators' cursors: listing markers and the status bar. */
  private showCollaborators() {
    const c = this.collab;
    if (!c) return;
    this.view.cursors = c.byAddress();
    this.view.invalidate();
    const el = $("st-collab");
    const n = c.cursors.size;
    el.hidden = n === 0;
    el.textContent = n === 1 ? "1 other here" : `${n} others here`;
    el.title = [...c.cursors.values()].map((x) => `${x.name}${x.address !== null ? ` at ${hex(x.address)}` : ""}${x.view ? ` (${x.view})` : ""}`).join("\n");
  }

  private setLocation(addr: bigint, row?: ListingRow) {
    this.location = addr;
    this.collab?.moved(addr, this.active === "decomp" ? "decompiler" : "listing");
    const fnName = row?.func !== null && row?.func !== undefined ? this.fnName(row.func) : undefined;
    $("st-loc").textContent = fmtAddr(addr, this.addrWidth) + (row?.block ? `  ${row.block}` : "");
    $("st-loc").title = spaceUnitNote(addr);
    const sel = $("st-space") as HTMLSelectElement;
    if (!sel.hidden) sel.value = spaceOf(addr)?.name ?? sel.value;
    $("st-fn").textContent = fnName && row?.func !== null && row?.func !== undefined ? `${fnName}${addr > row.func ? `+0x${hex(addr - row.func)}` : ""}` : "";
    this.functions.setCurrent(row?.func ?? null);
    this.locFunc = row?.func ?? null;
    const h = `#${fmtAddr(addr)}`;
    if (location.hash !== h) history.replaceState(null, "", h);
    if (this.graph) this.syncViews(addr, row);
    this.overview?.setCursor(addr);
    if (this.bytes && row && row.kind !== RowKind.Header) {
      this.bytes.setVisible(this.dock.isVisible("bytes"));
      this.bytes.followListing(row.address, row.length, this.listingSelection());
    }
    this.refs?.follow(row && row.kind !== RowKind.Header ? row.address : addr, this.dock?.isVisible("refs") ?? false);
    if (this.scripts?.running) this.scripts.contextMoved();
    if (this.console?.runId) this.console.contextMoved();
  }

  private async showDecompileFor(row: ListingRow) {
    const entry = row.func;
    if (entry === null) {
      this.decompSeq++;
      this.decompEntry = null;
      this.decompFn = null;
      $("decomp-name").textContent = "";
      this.showFailure(null);
      this.pane.showMessage(row.kind === RowKind.Instruction ? `// 0x${hex(row.address)} is not inside a known function.` : `// No code at 0x${hex(row.address)}.`);
      return;
    }
    if (entry !== this.decompEntry) await this.loadDecompile(entry);
    this.pane.highlightAddress(row.address);
  }

  private async loadDecompile(entry: bigint, refresh = false, escalate = false) {
    const p = this.loadDecompileNow(entry, refresh, escalate);
    this.decompLoading = p;
    try {
      await p;
    } finally {
      if (this.decompLoading === p) this.decompLoading = null;
    }
  }

  private async loadDecompileNow(entry: bigint, refresh: boolean, escalate: boolean) {
    const seq = ++this.decompSeq;
    this.decompEntry = entry;
    const nameEl = $("decomp-name");
    let fn = refresh ? undefined : this.decompCache.get(entry);
    if (!fn) {
      nameEl.textContent = `${this.fnName(entry) ?? hex(entry)} · ${escalate ? "retrying with a longer deadline" : "decompiling"}…`;
      let rev = 0n;
      try {
        const r = await this.rk.queries.decompile({
          programId: this.programId,
          function: { offset: entry },
          options: escalate ? { escalate: true } : undefined,
        });
        fn = r.function;
        rev = r.snapshot?.revision ?? 0n;
        if (r.failure) this.decompFailures.set(entry, r.failure);
        else this.decompFailures.delete(entry);
      } catch (e) {
        if (seq !== this.decompSeq) return;
        this.decompFn = null;
        nameEl.textContent = this.fnName(entry) ?? hex(entry);
        this.showFailure(null);
        this.pane.showMessage(`// Decompiler error for 0x${hex(entry)}:\n// ${errText(e).replace(/\n/g, "\n// ")}`);
        return;
      }
      if (!fn) return;
      // Computed before an edit that invalidated it (the event overtook the
      // response): show it, but don't keep it, and fetch again.
      if (rev < (this.decompStaleAt.get(entry) ?? 0n)) {
        if (seq === this.decompSeq) queueMicrotask(() => void this.loadDecompile(entry, true));
      } else {
        this.decompCache.set(entry, fn);
        if (this.decompCache.size > 64) this.decompCache.delete(this.decompCache.keys().next().value!);
      }
    }
    if (seq !== this.decompSeq) return;
    const failure = this.decompFailures.get(entry);
    this.showFailure(failure ?? null);
    if (failure) {
      // No C: the function's instructions instead, under the banner.
      this.decompFn = null;
      nameEl.textContent = fn.name;
      $("decomp-sig").textContent = "";
      const text = await this.disassembly(entry);
      if (seq !== this.decompSeq) return;
      this.pane.showMessage(`// ${failureText(failure)}: the function's instructions.\n\n${text}`);
      if (this.location !== null) this.pane.highlightAddress(this.location);
      return;
    }
    if (seq !== this.decompSeq) return;
    this.decompFn = fn;
    nameEl.textContent = fn.name;
    nameEl.title = fn.prototype?.cDeclaration ?? fn.name;
    // The effective prototype: an asserted C declaration isn't parsed, so
    // the decompiler's own signature line can't show it; this does.
    const sig = $("decomp-sig");
    const proto = fn.prototype;
    const asserted = proto?.origin?.source.case === "asserted";
    sig.textContent = asserted ? proto!.cDeclaration : "";
    sig.className = `decomp-sig mono o-${originClass(proto?.origin)}`;
    sig.title = asserted ? `Prototype set by ${provText(proto!.origin!.source.case === "asserted" ? proto!.origin!.source.value.provenance : undefined)}` : "";
    this.pane.setFunction(fn);
    if (this.location !== null) this.pane.highlightAddress(this.location);
    this.decompiledShown(fn);
  }

  /** The banner over the decompiler pane for a failed decompilation. */
  private showFailure(f: DecompileFailure | null) {
    const banner = $("decomp-failure");
    banner.hidden = f === null;
    if (!f) return;
    banner.classList.toggle("timeout", f.kind === DecompileFailureKind.TIMEOUT);
    $("decomp-failure-text").textContent = failureText(f);
    banner.title = `${f.detail}\nbundle ${f.bundleHash}\ndecompiler ${f.decompilerBuild}` + (f.stderrTail ? `\n\n${f.stderrTail.slice(-600)}` : "");
    const retry = $("decomp-retry") as HTMLButtonElement;
    retry.textContent = f.canEscalate ? "Retry with a longer deadline" : "Retry";
    retry.title = f.canEscalate
      ? "Decompile again once, with four times the deadline"
      : "Decompile again (the result is the same until the function's inputs or the decompiler change)";
  }

  private async retryDecompile() {
    const entry = this.decompEntry;
    if (entry === null) return;
    const f = this.decompFailures.get(entry);
    this.decompCache.delete(entry);
    await this.loadDecompile(entry, true, f?.canEscalate ?? false);
  }

  /** Downloads the failed decompilation's input bundle. */
  private async exportRepro() {
    const entry = this.decompEntry;
    if (entry === null) return;
    try {
      const r = await this.rk.queries.decompile({ programId: this.programId, function: { offset: entry }, options: { includeBundle: true } });
      const bytes = r.failure?.bundle;
      if (!bytes || bytes.length === 0) {
        toast("No bundle: the decompilation didn't fail this time.");
        return;
      }
      const url = URL.createObjectURL(new Blob([new Uint8Array(bytes)], { type: "application/octet-stream" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `${this.programId.replace(/[^A-Za-z0-9._-]+/g, "_")}-${hex(entry)}.bundle`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    } catch (e) {
      toast(`Export failed: ${errText(e)}`);
    }
  }

  /** The function's instructions as text, from the listing. */
  private async disassembly(entry: bigint): Promise<string> {
    try {
      const around = await this.source.rowsAround(entry, 0, 2000);
      const lines: string[] = [];
      for (const row of around.rows) {
        if (row.kind !== RowKind.Instruction) continue;
        if (row.func !== entry) {
          if (lines.length) break;
          continue;
        }
        lines.push(`${row.addrText}  ${row.mnemonic.padEnd(8)} ${row.operands.map((o) => o.text).join("")}`);
      }
      return lines.length ? lines.join("\n") : "// (no instructions)";
    } catch (e) {
      return `// (no listing: ${errText(e)})`;
    }
  }

  // ----------------------------------------------------------- navigation --

  /** Goes to an address, recording the current one in the back history. */
  async navigate(addr: bigint, opts: { focus?: PaneName } = {}) {
    const cur = this.view.selectedAddress();
    if (cur !== null && cur !== addr) {
      this.back.push(cur);
      if (this.back.length > 200) this.back.shift();
      this.fwd = [];
    }
    this.updateButtons();
    await this.view.goTo(addr, { align: "third" });
    if (opts.focus === "listing") this.view.canvas.focus({ preventScroll: true });
  }

  async goBack() {
    const a = this.back.pop();
    if (a === undefined) return;
    const cur = this.view.selectedAddress();
    if (cur !== null) this.fwd.push(cur);
    this.updateButtons();
    await this.view.goTo(a, { align: "third" });
  }

  async goForward() {
    const a = this.fwd.pop();
    if (a === undefined) return;
    const cur = this.view.selectedAddress();
    if (cur !== null) this.back.push(cur);
    this.updateButtons();
    await this.view.goTo(a, { align: "third" });
  }

  private updateButtons() {
    ($("back") as HTMLButtonElement).disabled = !this.back.length;
    ($("forward") as HTMLButtonElement).disabled = !this.fwd.length;
    const u = $("undo") as HTMLButtonElement;
    const r = $("redo") as HTMLButtonElement;
    u.disabled = !this.edits?.canUndo;
    r.disabled = !this.edits?.canRedo;
    u.title = this.edits?.canUndo ? `Undo ${this.edits.undoLabel} (Ctrl+Z)` : "Undo (Ctrl+Z)";
    r.title = this.edits?.canRedo ? `Redo ${this.edits.redoLabel} (Ctrl+Shift+Z)` : "Redo (Ctrl+Shift+Z)";
  }

  /** Row numbering changed (total rows differ): stay on the same address. */
  private reanchor() {
    const a = this.location;
    if (a !== null) void this.view.goTo(a, { notify: false });
  }

  private followFromDecomp() {
    const s = this.pane.selected;
    if (s?.tok.target) void this.navigate(s.tok.target.offset);
  }

  // ----------------------------------------- history, next/previous by kind --

  /** The history dropdown: forward locations (furthest first), here, then back (newest first). */
  private historyItems(): MenuItem[] {
    const cur = this.view.selectedAddress();
    const list = [...this.back, ...(cur !== null ? [cur] : []), ...[...this.fwd].reverse()];
    const here = this.back.length;
    const items: MenuItem[] = [];
    for (let j = list.length - 1; j >= 0; j--) {
      const a = list[j];
      const where = this.describeAddress(a);
      items.push({
        label: `${j === here ? "• " : j > here ? "→ " : "← "}${fmtAddr(a, this.addrWidth)}${where ? `  ${where}` : ""}`,
        testid: `history-${j}`,
        disabled: j === here,
        run: () => void this.goToHistory(list, j),
      });
    }
    if (!items.length) items.push({ label: "No history yet", disabled: true });
    return items;
  }

  /** Jumps to entry `j` of the history list (back + here + forward), keeping the rest as back and forward. */
  private async goToHistory(list: bigint[], j: number) {
    this.back = list.slice(0, j);
    this.fwd = list.slice(j + 1).reverse();
    this.updateButtons();
    await this.view.goTo(list[j], { align: "third" });
  }

  /** "main+0x1c" or a label, from the rows in the cache (empty when not loaded). */
  private describeAddress(a: bigint): string {
    const i = this.cache.findCached(a);
    const r = i >= 0 ? this.cache.get(i) : undefined;
    if (!r) return "";
    if (r.func !== null) {
      const n = this.fnName(r.func);
      if (n) return a === r.func ? n : `${n}+0x${hex(a - r.func)}`;
    }
    return r.label;
  }

  /** Next (or previous) place of a kind from the cursor (the byte viewer's when it has the focus). */
  async findNext(kind: NavigationKind, backward: boolean) {
    this.navKind = kind;
    const name = NAV_KINDS.find((n) => n.kind === kind)?.name ?? "place";
    const from = this.active === "bytes" && this.bytes?.cursor != null ? this.bytes.cursor : this.location;
    if (from === null) return;
    try {
      const r = await this.rk.queries.findNext({ programId: this.programId, from: { offset: from }, kind, backward });
      if (!r.found || !r.address) return toast(`No ${backward ? "previous" : "next"} ${name}`);
      const focus = this.active === "bytes" ? undefined : "listing";
      await this.navigate(r.address.offset, focus ? { focus } : {});
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  private navCommands(): Command[] {
    if (!this.features.has("find-next")) return [];
    const out: Command[] = [];
    for (const back of [false, true])
      for (const n of NAV_KINDS)
        out.push({
          id: `nav-${back ? "prev" : "next"}-${n.code.slice(3).toLowerCase()}`,
          title: `Go to ${back ? "previous" : "next"} ${n.name}`,
          keys: `Ctrl+Alt+${back ? "Shift+" : ""}${n.key}`,
          enabled: () => this.location !== null,
          run: () => void this.findNext(n.kind, back),
        });
    out.push({ id: "nav-repeat-next", title: "Go to next (the kind used last)", keys: "Ctrl+Alt+↓", enabled: () => this.location !== null, run: () => void this.findNext(this.navKind, false) });
    out.push({ id: "nav-repeat-prev", title: "Go to previous (the kind used last)", keys: "Ctrl+Alt+↑", enabled: () => this.location !== null, run: () => void this.findNext(this.navKind, true) });
    return out;
  }

  // ------------------------------------------------- memory blocks, offsets --

  private setBlocks(list: { name: string; range?: { first?: { offset: bigint }; last?: { offset: bigint } }; initialized: boolean; hasFileOffset: boolean; fileOffset: bigint }[]) {
    const next = list
      .filter((b) => b.range?.first && b.range.last)
      .map((b) => ({ first: b.range!.first!.offset, last: b.range!.last!.offset, name: b.name, initialized: b.initialized, fileOffset: b.hasFileOffset ? b.fileOffset : null }))
      .sort((x, y) => (x.first < y.first ? -1 : x.first > y.first ? 1 : 0));
    // In place: the byte viewer holds this array.
    this.blocks.splice(0, this.blocks.length, ...next);
  }

  private async refreshBlocks() {
    try {
      const r = await this.rk.queries.getMemoryMap({ programId: this.programId });
      this.setBlocks(r.blocks);
      bumpFields();
      this.view.invalidate();
      this.bytes?.invalidate();
      this.overview?.reload(0);
    } catch {
      /* keep the last map */
    }
  }

  /** The offset in the imported file of an address, or null (not from the file). */
  fileOffsetOf(a: bigint): bigint | null {
    for (const b of this.blocks) if (a >= b.first && a <= b.last) return b.fileOffset === null ? null : b.fileOffset + (a - b.first);
    return null;
  }

  /** The address a file offset loaded to, or null. */
  private addressOfFileOffset(o: bigint): bigint | null {
    for (const b of this.blocks) if (b.fileOffset !== null && b.initialized && o >= b.fileOffset && o <= b.fileOffset + (b.last - b.first)) return b.first + (o - b.fileOffset);
    return null;
  }

  /** The listing's multi-row selection as addresses (inclusive), or null for one row. */
  private listingSelection(): [bigint, bigint] | null {
    const [lo, hi] = this.view.selectionRange();
    if (lo < 0 || lo === hi) return null;
    let first: bigint | null = null;
    let last: bigint | null = null;
    for (let i = lo; i <= hi; i++) {
      const r = this.cache.get(i);
      if (!r || r.kind === RowKind.Header) continue;
      if (first === null) first = r.address;
      last = r.address + BigInt(Math.max(1, r.length)) - 1n;
    }
    return first !== null && last !== null ? [first, last] : null;
  }

  // ------------------------------------------------------------ the fields --

  private fieldItems(): MenuItem[] {
    return [
      { label: "Bytes", checked: this.cols.showBytes, keys: this.k("bytes"), testid: "field-bytes", run: () => this.toggleBytes() },
      ...FIELD_MENU.map((f) => ({ label: f.label, checked: this.fields[f.id], testid: `field-${f.id}`, run: () => this.setField(f.id, !this.fields[f.id]) })),
      ...(this.overview ? [{ label: "Overview bars (code, data; entropy)", checked: !this.overview.el.hidden, testid: "field-overview", separator: true, run: () => this.toggleOverview() }] : []),
    ];
  }

  setField(id: keyof FieldFlags, value: boolean) {
    this.fields[id] = value;
    prefs.set("rk.fields", JSON.stringify(this.fields));
    this.cols = makeColumns(this.addrWidth, this.cols.showBytes, this.headerRows, this.fields);
    this.view.setColumns(this.cols);
    this.paintColumnHeader();
    this.pcodeWant = "";
    this.wantFields();
  }

  toggleOverview() {
    if (!this.overview) return;
    this.overview.el.hidden = !this.overview.el.hidden;
    prefs.set("rk.overview", this.overview.el.hidden ? "0" : "1");
    this.view.resize();
    if (!this.overview.el.hidden) this.overview.reload(0);
  }

  /** Fetches what the optional fields need for the rows in view (p-code, references). */
  private wantFields() {
    if (!this.fields.pcode && !this.fields.xrefList) return;
    clearTimeout(this.fieldsTimer);
    this.fieldsTimer = window.setTimeout(() => void this.fetchFields(), 60);
  }

  private async fetchFields() {
    const first = Math.floor(this.view.topRow);
    const rows: ListingRow[] = [];
    for (let i = first; i <= first + this.view.viewportRows + 1; i++) {
      const r = this.cache.get(i);
      if (r) rows.push(r);
    }
    if (this.fields.pcode) {
      const insns = rows.filter((r) => r.kind === RowKind.Instruction && !hasPcode(r.address));
      if (insns.length) {
        const lo = insns[0].address;
        const hi = insns[insns.length - 1].address;
        const key = `${lo}-${hi}`;
        if (key !== this.pcodeWant) {
          this.pcodeWant = key;
          try {
            const got: [bigint, string][] = [];
            for await (const r of this.rk.queries.listInstructions({ programId: this.programId, scope: { case: "range", value: { first: { offset: lo }, last: { offset: hi } } }, limit: 600 }))
              for (const d of r.instructions) got.push([d.address?.offset ?? 0n, pcodeText(d.pcode)]);
            setPcode(got);
            this.view.invalidate();
          } catch {
            this.pcodeWant = "";
          }
        }
      }
    }
    if (this.fields.xrefList) {
      const labels = rows.filter((r) => r.kind === RowKind.Header && r.header?.kind === HeaderKind.Label && r.xrefCount > 0 && !xrefsAt(r.address) && !this.xrefsPending.has(r.address));
      await Promise.all(
        labels.map(async (r) => {
          this.xrefsPending.add(r.address);
          try {
            const x = await this.rk.queries.getXrefs({ programId: this.programId, location: { case: "address", value: { offset: r.address } }, direction: XrefDirection.TO, page: { pageSize: 3 } });
            setXrefs(r.address, { count: r.xrefCount, from: x.xrefs.map((e) => ({ address: e.fromAddress?.offset ?? 0n, kind: XREF_LETTER[e.kind] ?? "?" })) });
          } catch {
            /* shown as the count alone */
          } finally {
            this.xrefsPending.delete(r.address);
          }
        }),
      );
      if (labels.length) this.view.invalidate();
    }
  }

  // ------------------------------------------------------------ copy special --

  /** The selection Copy Special copies: the byte viewer's when it has the focus, else the listing's (or the code unit at the cursor). */
  private copyRange(): { lo: bigint; hi: bigint; from: "bytes" | "listing" } | null {
    if (this.active === "bytes" && this.bytes) {
      const r = this.bytes.selectedRange();
      return r ? { lo: r[0], hi: r[1], from: "bytes" } : null;
    }
    const sel = this.listingSelection();
    if (sel) return { lo: sel[0], hi: sel[1], from: "listing" };
    const row = this.view.selectedRowData();
    if (!row || row.kind === RowKind.Header) return null;
    return { lo: row.address, hi: row.address + BigInt(Math.max(1, row.length)) - 1n, from: "listing" };
  }

  /** Ghidra's Copy Special: the selection's bytes as hex, C, Python or Base64, its addresses, or the listing's text. */
  async copySpecial(format?: CopyFormat) {
    const range = this.copyRange();
    if (!range) return toast("Select something to copy first (the listing's rows, or bytes in the byte viewer)");
    const choices = COPY_FORMATS.filter((f) => f.id !== "listing" || range.from === "listing");
    const fmt = format ?? (await choose("Copy special", choices.map((f) => ({ label: f.label, detail: f.detail, value: f.id }))));
    if (!fmt) return;
    const n = range.hi - range.lo + 1n;
    const MAX = 1n << 20n;
    let text: string;
    try {
      if (fmt === "listing") {
        const t = this.view.selectionText();
        if (t === null) return toast("Some selected rows aren't loaded yet; copy again in a moment");
        text = t;
      } else if (fmt === "addresses" && range.from === "listing") {
        const [lo, hi] = this.view.selectionRange();
        const addrs: bigint[] = [];
        for (let i = lo; i <= hi; i++) {
          const r = this.cache.get(i);
          if (r && r.kind !== RowKind.Header && addrs.at(-1) !== r.address) addrs.push(r.address);
        }
        text = formatAddresses(addrs);
      } else {
        if (n > MAX) return toast(`The selection is ${n.toLocaleString()} bytes; Copy Special takes up to 1 MiB`, { kind: "error" });
        const bytes = new Uint8Array(Number(n));
        const starts: bigint[] = [];
        let uninit = false;
        for (let at = range.lo; at <= range.hi; at += 65536n) {
          const len = Number(range.hi - at + 1n < 65536n ? range.hi - at + 1n : 65536n);
          const r = await this.rk.queries.getByteView({ programId: this.programId, address: { offset: at }, length: len });
          bytes.set(r.data.subarray(0, len), Number(at - range.lo));
          for (const run of r.runs) {
            const s = run.start?.offset ?? 0n;
            if (run.kind === ByteKind.UNINITIALIZED) uninit = true;
            if (s >= range.lo && s <= range.hi && run.kind !== ByteKind.UNINITIALIZED && starts.at(-1) !== s) starts.push(s);
          }
        }
        if (fmt === "addresses") text = formatAddresses(starts);
        else {
          text = formatBytes(fmt, bytes, `data_${hex(range.lo)}`);
          if (uninit) toast("Part of the selection is uninitialized: copied as zeros");
        }
      }
    } catch (e) {
      return toast(errText(e), { kind: "error" });
    }
    this.lastCopy = { format: fmt, text };
    const label = COPY_FORMATS.find((f) => f.id === fmt)?.label ?? fmt;
    try {
      await navigator.clipboard.writeText(text);
      toast(`Copied ${label.toLowerCase()} (${fmt === "listing" || fmt === "addresses" ? `${text.split("\n").filter(Boolean).length} lines` : `${n.toLocaleString()} bytes`})`);
    } catch {
      toast("Can't reach the clipboard here", { kind: "error" });
    }
  }

  // ------------------------------------------------------------- symbols --

  private async findSymbol(name: string): Promise<bigint | null> {
    if (!this.features.has("symbols")) {
      const r = await this.rk.queries.listFunctions({ programId: this.programId, nameContains: name, page: { pageSize: 50 } });
      return r.functions.find((f) => f.name === name)?.entry?.offset ?? null;
    }
    const r = await this.rk.queries.listSymbols({ programId: this.programId, nameEquals: name, page: { pageSize: 2 } });
    return r.symbols[0]?.address?.offset ?? null;
  }

  /** The first memory block's start in a space (by name), or null. */
  private firstBlockIn(space: string): bigint | null {
    let first: bigint | null = null;
    for (const b of this.summary.memory) {
      const a = b.range?.first?.offset;
      if (a === undefined || spaceOf(a)?.name !== space) continue;
      if (first === null || a < first) first = a;
    }
    return first;
  }

  private async searchItems(q: string, signal: AbortSignal): Promise<Item[]> {
    const items: Item[] = [];
    // Address spaces: "mem:" (or the name) jumps to the space's first block.
    for (const sp of addressSpaces()) {
      const name = sp.name.toLowerCase();
      const t = q.toLowerCase();
      if (q && t !== name && t !== name + ":") continue;
      const first = this.firstBlockIn(sp.name);
      if (first === null) continue;
      items.push({
        label: `Space ${sp.name}`,
        detail: sp.wordSize > 1 ? `${sp.wordSize}-byte words · ${fmtAddr(first)}` : fmtAddr(first),
        badge: "addr",
        run: () => void this.navigate(first),
      });
    }
    if (!q) {
      for (const a of this.back.slice(-8).reverse())
        items.push({ label: fmtAddr(a, this.addrWidth), detail: "recent", badge: "addr", run: () => void this.navigate(a) });
      return items;
    }
    if (q.startsWith("#") && /^#\d+$/.test(q)) {
      const row = Number(q.slice(1));
      items.push({ label: `Row ${row.toLocaleString()}`, badge: "addr", run: () => this.view.scrollToRow(row, "third") });
      return items;
    }
    // Wildcards in names (FUN_*): every symbol that matches, from the daemon.
    if (isGlob(q)) return this.globItems(q, signal);
    // Expressions (main+0x10, 0x1000 + 4*3, file:0x200): evaluated here, names looked up exactly.
    if (isExpression(q)) {
      await new Promise((r) => setTimeout(r, 60));
      if (signal.aborted) return items;
      try {
        const v = await evaluateText(q, {
          symbol: (n) => this.findSymbol(n),
          fileOffset: (o) => this.addressOfFileOffset(o),
          isSpace: (n) => addressSpaces().some((sp) => sp.name.toLowerCase() === n.toLowerCase()),
          spaceAddress: (n, o) => parseAddress(`${n}:${o.toString(16)}`),
        });
        const off = this.fileOffsetOf(v);
        items.push({ label: `Go to ${fmtAddr(v, this.addrWidth)}`, badge: "expr", detail: `${q.trim()}${off !== null && !/^file:/i.test(q.trim()) ? ` · file offset 0x${hex(off)}` : ""}`, run: () => void this.navigate(v) });
      } catch (e) {
        if (signal.aborted) return items;
        items.push({ label: e instanceof ExprError ? e.message : errText(e), badge: "error", detail: "Go to expression", run: () => {} });
      }
      return items;
    }
    const a = parseAddress(q);
    if (a !== null) items.push({ label: `Go to ${fmtAddr(a, this.addrWidth)}`, badge: "addr", detail: spaceUnitNote(a) || "address", run: () => void this.navigate(a) });
    const lower = q.toLowerCase();
    // Functions first, ranked exact > prefix > substring: the daemon's
    // name filter (the panel holds only the pages in view).
    const seen = new Set<bigint>();
    try {
      const r = await this.rk.queries.listFunctions({ programId: this.programId, nameContains: q, page: { pageSize: 200 } }, { signal });
      const fnMatches = r.functions
        .map((f) => ({ f, i: f.name.toLowerCase().indexOf(lower) }))
        .sort((x, y) => Number(y.f.name === q) - Number(x.f.name === q) || Number(y.i === 0) - Number(x.i === 0) || x.f.name.length - y.f.name.length)
        .slice(0, 30);
      for (const { f } of fnMatches) {
        const entry = f.entry!.offset;
        seen.add(entry);
        items.push({ label: showName(f.name, f.demangled), detail: matchedSpelling(f.name, f.demangled, lower) + fmtAddr(entry, this.addrWidth), badge: "fn", run: () => void this.navigate(entry) });
      }
    } catch (e) {
      if (signal.aborted) return items;
      throw e;
    }
    if (this.features.has("symbols") && q.length >= 2) {
      // The server's answer is current even when the local function list
      // is a moment behind an edit; it adds labels and globals too.
      await new Promise((r) => setTimeout(r, 90));
      if (signal.aborted) return items;
      const r = await this.rk.queries.listSymbols({ programId: this.programId, nameContains: q, page: { pageSize: 100 } }, { signal });
      const rank = (n: string) => (n === q ? 0 : n.toLowerCase().startsWith(lower) ? 1 : 2);
      const found = r.symbols
        .filter((s) => s.address && !seen.has(s.address.offset))
        .sort((x, y) => rank(x.name) - rank(y.name) || Number(y.kind === SymbolKind.FUNCTION) - Number(x.kind === SymbolKind.FUNCTION) || x.name.length - y.name.length)
        .slice(0, 40);
      for (const s of found) {
        const addr = s.address!.offset;
        const fn = s.kind === SymbolKind.FUNCTION;
        items.push({ label: showName(s.name, s.demangled), detail: matchedSpelling(s.name, s.demangled, lower) + fmtAddr(addr, this.addrWidth), badge: fn ? "fn" : "label", run: () => void this.navigate(addr) });
      }
    }
    return items;
  }

  /** Symbols whose names match a wildcard pattern (`*` any run, `?` one character), best first. */
  private async globItems(q: string, signal: AbortSignal): Promise<Item[]> {
    const re = globToRegExp(q);
    const lit = globLiteral(q);
    await new Promise((r) => setTimeout(r, 90));
    if (signal.aborted) return [];
    const found: { name: string; addr: bigint; fn: boolean }[] = [];
    if (this.features.has("symbols")) {
      const r = await this.rk.queries.listSymbols({ programId: this.programId, nameContains: lit, page: { pageSize: 5000 } }, { signal });
      for (const s of r.symbols) if (s.address && re.test(s.name)) found.push({ name: s.name, addr: s.address.offset, fn: s.kind === SymbolKind.FUNCTION });
    } else {
      const r = await this.rk.queries.listFunctions({ programId: this.programId, nameContains: lit, page: { pageSize: 5000 } }, { signal });
      for (const f of r.functions) if (f.entry && re.test(f.name)) found.push({ name: f.name, addr: f.entry.offset, fn: true });
    }
    const items: Item[] = found.slice(0, 200).map((f) => ({ label: f.name, detail: fmtAddr(f.addr, this.addrWidth), badge: f.fn ? "fn" : "label", run: () => void this.navigate(f.addr) }));
    if (!items.length) items.push({ label: `No symbol matches ${q.trim()}`, badge: "glob", run: () => {} });
    else if (found.length > items.length) items.push({ label: `${found.length - items.length} more match ${q.trim()}`, badge: "glob", run: () => {} });
    return items;
  }

  // ---------------------------------------------------------------- edits --

  private renameSpec(): RenameSpec | null {
    if (this.active === "decomp") {
      const s = this.pane.selected;
      const fn = this.decompFn;
      // A token that names nothing (a keyword, a constant, a type, a field
      // the daemon can't place) is nothing to rename, never the function;
      // nothing selected, or a token of the signature line, is the
      // function, as the listing's header and signature rows are.
      if (s && !this.pane.nameable(s) && !this.onSignatureLine(s)) return null;
      if (s && this.pane.nameable(s) && fn) {
        const v = this.pane.variable(s);
        if (v && v.kind !== VariableKind.GLOBAL) {
          return {
            target: { case: "local", function: fn.entry!.offset, storageKey: v.storageKey },
            current: v.name,
            what: v.kind === VariableKind.PARAMETER ? "parameter" : "local variable",
          };
        }
        const addr = s.tok.target?.offset ?? v?.address?.offset;
        if (addr !== undefined) return { target: { case: "address", address: addr }, current: s.tok.text, what: s.tok.kind === CodeTokenKind.FUNCTION_NAME ? "function" : "global" };
      }
      if (fn?.entry) return { target: { case: "address", address: fn.entry.offset }, current: fn.name, what: "function" };
      return null;
    }
    const row = this.view.selectedRowData();
    if (!row) return null;
    const hit = this.view.selectedHit;
    if (hit?.kind === "token" && hit.target !== undefined && hit.data === row) {
      return { target: { case: "address", address: hit.target }, current: hit.key, what: "symbol" };
    }
    // Any line of a code unit (its label, signature or comment rows too)
    // names its address.
    const label = row.label || (row.kind === RowKind.Header ? (this.fnName(row.address) ?? "") : "");
    if (label) return { target: { case: "address", address: row.address }, current: label, what: row.functionEntry ? "function" : "label" };
    return { target: { case: "address", address: row.address }, current: "", what: "label" };
  }

  /** The decompiled function's signature line (its name's first line, the declaration): a token there means the function. */
  private onSignatureLine(s: TokSpan): boolean {
    const entry = this.decompFn?.entry?.offset;
    if (entry === undefined) return false;
    const decl = this.pane.spans.find((t) => t.tok.kind === CodeTokenKind.FUNCTION_NAME && t.tok.target?.offset === entry);
    return !!decl && decl.line === s.line;
  }

  /** The decompiler's selected struct field (a FIELD token; feature field-tokens), for Rename Field and Retype Field. */
  private selectedField(): { hash: string; offset: bigint; name: string } | null {
    if (this.active !== "decomp" || !this.features.has("field-tokens")) return null;
    return this.pane.field(this.pane.selected) ?? null;
  }

  // ------------------------------------------------ find uses (type-uses) --

  /** The struct (or union) a decompiler token is about: a FIELD token's
   * parent, or a TYPE token naming one (feature type-uses). */
  private selectedStruct(): { hash: string; name: string } | null {
    if (this.active !== "decomp" || !this.features.has("type-uses")) return null;
    const s = this.pane.selected;
    if (!s) return null;
    if (s.tok.kind === CodeTokenKind.FIELD && s.tok.parentTypeHash) return { hash: s.tok.parentTypeHash, name: "" };
    if (s.tok.kind === CodeTokenKind.TYPE && s.tok.typeHash) return { hash: s.tok.typeHash, name: s.tok.text };
    return null;
  }

  private async typeName(hash: string): Promise<string> {
    try {
      const t = (await this.rk.queries.getTypes({ programId: this.programId, hashes: [hash] })).types.find((x) => x.hash === hash);
      if (t) return t.name || t.display;
    } catch {
      /* the hash, shortened */
    }
    return hash.slice(0, 8);
  }

  /**
   * Find Uses of a struct or union, or of one of its fields (feature
   * type-uses; Ghidra's Find Uses of): every function's decompiled C is
   * read on the daemon (cached decompilations first), the uses stream into
   * the search results table with progress and Cancel, and a row opens the
   * decompiler at the use.
   */
  async findUses(hash: string, field?: { offset: bigint; name: string }, typeName?: string) {
    if (!this.features.has("type-uses")) return toast("Finding uses needs a daemon with feature type-uses (api_minor 53)", { kind: "error" });
    if (!this.search) return toast("Finding uses needs a daemon with feature search", { kind: "error" });
    const name = typeName || (await this.typeName(hash));
    await this.search.findUses(hash, field ? `${name}.${field.name}` : name, field);
  }

  // ------------------------------ call-site signature overrides (feature) --

  /** The call the selection is on (feature call-signature-override): a
   * call's FUNCTION_NAME token in the decompiler, or a call instruction's
   * row in the listing; its address, callee and current override. */
  private selectedCall(): { address: bigint; callee: string; current: string; target?: bigint } | null {
    if (!this.features.has("call-signature-override")) return null;
    if (this.active === "decomp") {
      const s = this.pane.selected;
      const entry = this.decompFn?.entry?.offset;
      if (!s || s.tok.kind !== CodeTokenKind.FUNCTION_NAME || !s.tok.address || s.tok.address.offset === entry || this.onSignatureLine(s)) return null;
      return { address: s.tok.address.offset, callee: s.tok.text, current: s.tok.callSignature, target: s.tok.target?.offset };
    }
    const row = this.view.selectedRowData();
    if (!row || row.kind !== RowKind.Instruction || (row.flow !== FlowKind.CALL && row.flow !== FlowKind.INDIRECT_CALL)) return null;
    const target = row.flowTargets.length === 1 ? row.flowTargets[0] : undefined;
    return { address: row.address, callee: target !== undefined ? (this.fnName(target) ?? "") : "", current: row.callSignature, target };
  }

  /**
   * Override Signature / Edit Signature Override (Ghidra's, on a call): the
   * prototype this call alone uses, as C (prefilled with the override or the
   * callee's prototype); one undo step; the decompiler shows the call with
   * the arguments it names.
   */
  async overrideCallSignature() {
    const c = this.selectedCall();
    if (!c) return toast("Select a call (its name in the decompiler, or the call instruction in the listing) first");
    let current = c.current;
    if (!current && c.target !== undefined) {
      try {
        current = (await this.rk.queries.getFunction({ programId: this.programId, address: { offset: c.target } })).function?.prototype ?? "";
      } catch {
        /* the dialog starts empty */
      }
    }
    const where = `${c.callee ? `${c.callee} ` : ""}at ${hex(c.address)}`;
    const value = await ask({
      title: `${c.current ? "Edit signature override" : "Override signature"}: call ${where}`,
      value: current,
      placeholder: "int printf(char *fmt, int n, char *s)",
      hint: "The prototype this call alone uses (its arguments and return), as C: for a varargs call, name the arguments it passes · Enter to save · Esc to cancel",
      validate: (v) => (v.trim() && !/\)\s*;?\s*$/.test(v.trim()) ? "A function prototype: ret name(params)" : null),
    });
    if (value === null || !value.trim() || value.trim() === c.current) return;
    await this.applyCallSignature(c.address, value.trim().replace(/;\s*$/, ""), `Signature override at ${hex(c.address)}`);
  }

  /** Remove Signature Override: the call takes its callee's prototype again. */
  async removeCallSignature() {
    const c = this.selectedCall();
    if (!c?.current) return toast("Select a call with a signature override first");
    await this.applyCallSignature(c.address, "", `Removed the signature override at ${hex(c.address)}`);
  }

  private async applyCallSignature(call: bigint, prototype: string, label: string) {
    try {
      const r = await this.edits.callSignature(call, prototype, label);
      toast(label, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
      await this.live.waitFor(r.revision);
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  /** Why a field can't be edited here (null: it can). */
  private fieldBlocked(f: { hash: string; name: string }): string | null {
    if (!this.features.has("parse-c")) return "Editing a struct needs a daemon that parses C (api_minor 25, feature parse-c)";
    if (!f.hash) return `Can't edit ${f.name}: its struct isn't one of the program's types`;
    return null;
  }

  /**
   * Rename Field: the struct's next version with the field renamed, bound
   * to the struct's name (one undo step), as saving it in the type editor
   * does; every use of the struct shows it.
   */
  async renameField() {
    const f = this.selectedField();
    if (!f) return toast("Select a struct field in the decompiler first");
    const blocked = this.fieldBlocked(f);
    if (blocked) return toast(blocked, { kind: "error" });
    const name = await ask({
      title: `Rename field ${f.name}`,
      value: f.name,
      placeholder: "field name",
      hint: "Renames the field in its struct (a new version of the struct, bound to its name) · Enter to save · Esc to cancel",
      validate: (v) => (/^[A-Za-z_]\w*$/.test(v.trim()) ? null : "A C name: letters, digits, _"),
    });
    if (name === null || name.trim() === f.name) return;
    await this.editField(f, { name: name.trim() }, `Renamed field ${f.name} → ${name.trim()}`);
  }

  /** Retype Field: as Rename Field, with the field's type changed (any C type spelling). */
  async retypeField() {
    const f = this.selectedField();
    if (!f) return toast("Select a struct field in the decompiler first");
    const blocked = this.fieldBlocked(f);
    if (blocked) return toast(blocked, { kind: "error" });
    let current = "";
    try {
      const t = (await this.rk.queries.getTypes({ programId: this.programId, hashes: [f.hash], includeDependencies: true })).types;
      const parent = t.find((x) => x.hash === f.hash);
      const fd = parent?.detail.case === "composite" ? parent.detail.value.fields.find((x) => x.name === f.name && x.offset === f.offset) : undefined;
      current = (fd && t.find((x) => x.hash === fd.typeHash)?.display) ?? "";
    } catch {
      /* the dialog starts empty */
    }
    const value = await ask({
      title: `Set the type of field ${f.name}`,
      value: current,
      placeholder: "const uint8_t *",
      suggest: (v) => this.typeSuggestions(v),
      browse: { label: "Browse types…", run: () => this.showView("types") },
      hint: "Type a name: matching types drop down (↑↓, Tab or Enter takes one) · any C type · the struct keeps its other fields where they are · Enter to save · Esc to cancel",
    });
    if (value === null || !value.trim() || value.trim() === current) return;
    rememberType(value.trim());
    await this.editField(f, { type: value.trim() }, `Field ${f.name}: ${value.trim()}`);
  }

  private async editField(f: { hash: string; offset: bigint; name: string }, change: { name?: string; type?: string }, done: string) {
    try {
      const r = await this.types.editField(f.hash, f.offset, f.name, change);
      toast(done, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
      await this.live.waitFor(r.revision);
    } catch (e) {
      toast(`${change.name !== undefined ? "Rename field" : "Set field type"} failed: ${errText(e)}`, { kind: "error" });
    }
  }

  /** What a retype applies to: the selected variable, global or function. */
  private retypeSpec(): RetypeSpec | null {
    const fnSpec = (entry: bigint, name: string): RetypeSpec => ({
      target: { case: "address", address: entry },
      key: { address: entry, sub: "" },
      what: `function ${name}`,
      prototype: true,
      fallback: this.decompFn?.entry?.offset === entry ? (this.decompFn.prototype?.cDeclaration ?? "") : "",
    });
    if (this.active === "decomp") {
      const s = this.pane.selected;
      const fn = this.decompFn;
      if (!fn?.entry) return null;
      const v = s ? this.pane.variable(s) : undefined;
      if (v && v.kind !== VariableKind.GLOBAL) {
        return {
          target: { case: "local", function: fn.entry.offset, storageKey: v.storageKey },
          key: { address: fn.entry.offset, sub: `local:${v.storageKey}` },
          what: `${v.kind === VariableKind.PARAMETER ? "parameter" : "local"} ${v.name}`,
          prototype: false,
          fallback: v.type?.display ?? "",
        };
      }
      if (s?.tok.kind === CodeTokenKind.FUNCTION_NAME && s.tok.target) return fnSpec(s.tok.target.offset, s.tok.text);
      const g = s?.tok.target?.offset ?? v?.address?.offset;
      if (g !== undefined && s) return { target: { case: "address", address: g }, key: { address: g, sub: "" }, what: `global ${s.tok.text}`, prototype: false, fallback: v?.type?.display ?? "" };
      return fnSpec(fn.entry.offset, fn.name);
    }
    const row = this.view.selectedRowData();
    if (!row) return null;
    const hit = this.view.selectedHit && this.view.selectedHit.data === row ? this.view.selectedHit : null;
    const addr = hit?.kind === "token" && hit.target !== undefined ? hit.target : row.address;
    const isFn = addr === row.address ? row.functionEntry : row.func === addr;
    if (isFn || (addr === row.address && row.header?.kind === HeaderKind.Signature)) return fnSpec(addr, this.fnName(addr) ?? hex(addr));
    const name = hit?.kind === "token" ? hit.key : row.label || hex(addr);
    return { target: { case: "address", address: addr }, key: { address: addr, sub: "" }, what: `global ${name}`, prototype: false, fallback: addr === row.address ? row.dataType : "" };
  }

  /**
   * What Auto create / fill in structure applies to (feature auto-struct):
   * the decompiler's selected parameter or local, or (feature
   * auto-struct-edit) a struct field token, treated as a pointer (chained
   * structures: param_1->field_0x20 becomes a pointer to a new structure).
   */
  private autoStructTarget():
    | { kind: "variable"; fn: bigint; fnName: string; key: string; name: string }
    | { kind: "field"; fn: bigint; fnName: string; hash: string; offset: bigint; name: string; base: string; what: string }
    | null {
    if (!this.features.has("auto-struct") || this.active !== "decomp") return null;
    const s = this.pane.selected;
    const fn = this.decompFn;
    if (!fn?.entry || !s) return null;
    const v = this.pane.variable(s);
    if (v && v.kind !== VariableKind.GLOBAL) return { kind: "variable", fn: fn.entry.offset, fnName: fn.name, key: v.storageKey, name: v.name };
    const f = this.pane.field(s);
    if (f && f.hash && this.features.has("auto-struct-edit")) {
      const base = this.fieldBase(s);
      return { kind: "field", fn: fn.entry.offset, fnName: fn.name, hash: f.hash, offset: f.offset, name: f.name, base: base?.key ?? "", what: `${base?.text ?? "…"}->${f.name}` };
    }
    return null;
  }

  /** The variable or variable->field->… chain a field token is read through ("param:0->0x20"), from the tokens before it. */
  private fieldBase(s: TokSpan): { key: string; text: string } | null {
    const spans = this.pane.spans;
    const i = spans.indexOf(s);
    const prev = (j: number) => {
      for (let k = j - 1; k >= 0; k--) if (spans[k].line === s.line && spans[k].tok.text.trim()) return k;
      return -1;
    };
    const arrow = prev(i);
    if (arrow < 0 || spans[arrow].tok.text.trim() !== "->") return null;
    const b = prev(arrow);
    if (b < 0) return null;
    const v = this.pane.variable(spans[b]);
    if (v && v.kind !== VariableKind.GLOBAL) return { key: v.storageKey, text: v.name };
    const inner = this.pane.field(spans[b]);
    if (!inner) return null;
    const up = this.fieldBase(spans[b]);
    return up ? { key: `${up.key}->0x${inner.offset.toString(16)}`, text: `${up.text}->${inner.name}` } : null;
  }

  /**
   * Ghidra's Auto Create Structure (and with `fill`, Auto Fill in
   * Structure) on the selected variable or struct field: the daemon
   * composes it from the loads, stores and the calls the pointer is passed
   * to; the preview shows the fields and edits them; Apply defines it,
   * binds its name and retypes the variable (or the outer structure's
   * field) in one undo step.
   */
  async autoStructure(fill: boolean) {
    const t = this.autoStructTarget();
    if (!t) return toast("Select a parameter, a local or a struct field in the decompiler first");
    const what = t.kind === "variable" ? t.name : t.what;
    const request =
      t.kind === "variable"
        ? create(AutoStructureRequestSchema, {
            programId: this.programId,
            source: { case: "variable", value: { function: { offset: t.fn }, storageKey: t.key } },
            mode: fill ? AutoStructureMode.FILL : AutoStructureMode.CREATE,
            callDepth: 1,
          })
        : create(AutoStructureRequestSchema, {
            programId: this.programId,
            source: { case: "field", value: { function: { offset: t.fn }, structHash: t.hash, offset: t.offset, baseStorageKey: t.base } },
            mode: fill ? AutoStructureMode.FILL : AutoStructureMode.CREATE,
            callDepth: 1,
          });
    const got = await previewStructure({
      rk: this.rk,
      title: `${fill ? "Auto fill in structure" : "Auto create structure"} for ${what} in ${t.fnName}`,
      request,
      named: !fill,
      depth: true,
      editable: this.features.has("auto-struct-edit"),
      suggest: (v) => this.typeSuggestions(v),
    });
    if (!got) return;
    const made = got.made;
    try {
      const label = `${fill ? "Fill in" : "Create"} struct ${made.name} from ${what}`;
      const bodies = t.kind === "variable" ? autoStructureBodies(made, { function: t.fn, storageKey: t.key }) : autoStructureBodies(made, { field: true });
      const r = await this.edits.bodies(label, bodies);
      toast(`${fill ? "Filled in" : "Created"} struct ${made.name} (${made.fields.length} field${made.fields.length === 1 ? "" : "s"}): ${what} is a struct ${made.name} *`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
      await this.live.waitFor(r.revision);
      if (got.openTypes) this.openTypeNamed(made.name);
    } catch (e) {
      toast(`${fill ? "Auto fill in" : "Auto create"} structure failed: ${errText(e)}`, { kind: "error" });
    }
  }

  private openTypeNamed(name: string) {
    if (!name) return;
    this.showView("types");
    void this.types.showNamed(name);
  }

  /**
   * The function Edit Function applies to: in the decompiler, the one shown
   * (with `entryOnly`, only on its name or its signature line); in the
   * listing, the one at the cursor (with `entryOnly`, only at its entry).
   */
  private editFunctionTarget(entryOnly: boolean): bigint | null {
    if (this.active === "decomp") {
      const fn = this.decompFn?.entry?.offset;
      if (fn === undefined) return null;
      if (!entryOnly) return fn;
      const s = this.pane.selected;
      if (!s) return null;
      if (s.tok.kind === CodeTokenKind.FUNCTION_NAME && s.tok.target?.offset === fn) return fn;
      return this.onSignatureLine(s) ? fn : null;
    }
    if (this.active !== "listing") return null;
    const row = this.view.selectedRowData();
    if (!row || row.func === null || row.func === undefined) return null;
    if (!entryOnly) return row.func;
    return row.address === row.func ? row.func : null;
  }

  /** Set/Clear no return's function: in the decompiler a called function's
   * name under the cursor, else the function shown; in the listing the
   * function containing the row. */
  private noReturnTarget(): bigint | null {
    if (this.active === "decomp") {
      const t = this.pane.selected?.tok;
      if (t?.kind === CodeTokenKind.FUNCTION_NAME && t.target?.offset !== undefined) return t.target.offset;
    }
    return this.editFunctionTarget(false);
  }

  /** BSim's query function: a called function's name under the decompiler's cursor, else the function shown or containing the listing's row. */
  private bsimTarget(): { entry: bigint; name: string } | null {
    const e = this.noReturnTarget();
    if (e === null) return null;
    return { entry: e, name: this.fnName(e) ?? `0x${e.toString(16)}` };
  }

  /** Find similar functions (BSim): the BSim view, searching the function at the cursor. */
  async findSimilar(entry?: bigint) {
    if (!this.bsim) return toast("This daemon has no BSim databases (feature bsim)", { kind: "error" });
    const t = entry !== undefined ? { entry, name: this.fnName(entry) ?? "" } : this.bsimTarget();
    if (!t) return toast("Put the cursor in a function first", { kind: "error" });
    this.showView("bsim");
    await this.bsim.loadDatabases();
    await this.bsim.search("function", t.entry);
  }

  async bsimIngest() {
    if (!this.bsim) return;
    this.showView("bsim");
    await this.bsim.loadDatabases();
    await this.bsim.ingest();
  }

  /** Whether a function doesn't return, when this page knows (the decompiled one); undefined otherwise. */
  private knownNoReturn(entry: bigint): boolean | undefined {
    return this.decompFn?.entry?.offset === entry ? (this.decompFn.prototype?.noReturn ?? false) : undefined;
  }

  /** Ghidra's Set No-Return / Clear (feature no-return): one edit, undoable. */
  async setNoReturn(entry: bigint, noReturn: boolean) {
    const name = this.fnName(entry) ?? hex(entry);
    try {
      const r = await this.edits.bodies(`${noReturn ? "Set" : "Clear"} no return on ${name}`, [Edits.noReturnBody(entry, noReturn)]);
      toast(`${name} ${noReturn ? "doesn't return: calls to it end there" : "returns"}`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
      await this.live.waitFor(r.revision);
    } catch (e) {
      toast(`${noReturn ? "Set" : "Clear"} no return failed: ${errText(e)}`, { kind: "error" });
    }
  }

  private callingConventions: Promise<{ conventions: CallingConvention[]; defaultName: string }> | null = null;

  /**
   * Edit Function (Ghidra's): the signature as C over its fields (name,
   * return type, calling convention from the compiler spec, parameters,
   * varargs); Apply sets the prototype (and the name) in one undo step.
   */
  async editFunctionAt(entry: bigint) {
    if (!this.features.has("parse-c")) return toast("Edit function needs a daemon that parses C (feature parse-c)", { kind: "error" });
    let fn: DecompiledFunction | undefined;
    try {
      fn = this.decompFn?.entry?.offset === entry ? this.decompFn : (await this.rk.queries.decompile({ programId: this.programId, function: { offset: entry } })).function;
    } catch (e) {
      return toast(`Edit function: ${errText(e)}`, { kind: "error" });
    }
    if (!fn) return toast("No function there", { kind: "error" });
    if (this.features.has("calling-conventions"))
      this.callingConventions ??= this.rk.queries.listCallingConventions({ programId: this.programId }).then(
        (r) => ({ conventions: r.conventions, defaultName: r.defaultName }),
        () => ({ conventions: [], defaultName: "" }),
      );
    const cc = this.callingConventions ? await this.callingConventions : { conventions: [] as CallingConvention[], defaultName: "" };
    const proto = fn.prototype;
    const name = this.fnName(entry) ?? fn.name;
    // The fields from the decompiler's prototype; its declaration says whether a convention was chosen.
    const declared = cToDraft(proto?.cDeclaration ?? "", cc.conventions);
    const vars = fn.variables;
    const params = (proto?.parameterIndices ?? []).map((i) => vars[i]).filter((v): v is Variable => !!v).map((v) => ({ name: v.name, type: v.type?.display || "undefined4" }));
    // A return nothing asserted is the decompiler's own guess: left undefined
    // (unlocked), so applying the dialog doesn't lock it.
    const locked = !!proto?.origin && ["user", "agent", "import"].includes(originClass(proto.origin));
    const initial: FunctionDraft = {
      name,
      ret: locked ? proto?.returnType?.display || declared?.ret || "void" : "",
      convention: declared?.convention ?? "",
      params: params.length || !declared ? params : declared.params,
      varargs: proto?.varargs ?? declared?.varargs ?? false,
    };
    if (this.features.has("no-return")) initial.noReturn = proto?.noReturn ?? false;
    const target: RenameTarget = { case: "address", address: entry };
    await editFunction({
      title: `Edit function ${name}`,
      initial,
      conventions: cc.conventions,
      defaultName: cc.defaultName,
      suggest: (v) => this.typeSuggestions(v),
      check: async (c) => {
        const r = await this.parseRetype(c, true).catch((e) => ({ error: errText(e) }));
        return "error" in r ? r.error : null;
      },
      apply: async (draft, c) => {
        const r = await this.parseRetype(c, true).catch((e) => ({ error: errText(e) }));
        if ("error" in r) return r.error;
        const bodies = [
          ...(draft.name !== name ? [Edits.renameBody(target, draft.name)] : []),
          ...(draft.noReturn !== undefined && draft.noReturn !== initial.noReturn ? [Edits.noReturnBody(entry, draft.noReturn)] : []),
          ...(r.definitions ? [...r.bodies, Edits.retypeHashBody(target, r.hash)] : [Edits.retypeBody(target, r.declaration)]),
        ];
        try {
          const res = await this.edits.bodies(`Edit function ${draft.name}`, bodies);
          toast(`${draft.name}: ${c}`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
          await this.live.waitFor(res.revision);
          return null;
        } catch (e) {
          return errText(e);
        }
      },
    });
  }

  /** Create Structure on a listing selection: fields from the data defined in it, defined at its start. */
  async structureFromSelection() {
    const sel = this.listingEdit.range();
    if (!sel) return toast("Select the bytes or data items to make a structure of", { kind: "error" });
    const last = sel.start + sel.length - 1n;
    const got = await previewStructure({
      rk: this.rk,
      title: `Create structure from ${hex(sel.start)}..${hex(last)} (${sel.length} bytes)`,
      request: create(AutoStructureRequestSchema, {
        programId: this.programId,
        source: { case: "range", value: { first: { offset: sel.start }, last: { offset: last } } },
        mode: AutoStructureMode.CREATE,
      }),
      named: true,
      depth: false,
      editable: this.features.has("auto-struct-edit"),
      suggest: (v) => this.typeSuggestions(v),
    });
    if (!got) return;
    const made = got.made;
    try {
      const r = await this.edits.bodies(`Create struct ${made.name} at ${hex(sel.start)}`, autoStructureBodies(made, { at: sel.start }));
      toast(`Created struct ${made.name} at ${hex(sel.start)}`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
      await this.live.waitFor(r.revision);
      if (got.openTypes) this.openTypeNamed(made.name);
    } catch (e) {
      toast(`Create structure failed: ${errText(e)}`, { kind: "error" });
    }
  }

  /** y: set a type (C declaration) on a variable, global or prototype. */
  async retype() {
    if (this.selectedField()) return this.retypeField();
    const spec = this.retypeSpec();
    if (!spec) return toast("Select a function, variable or global first");
    let current = "";
    try {
      const b = await this.rk.assertions.blame({ key: { programId: this.programId, kind: FactKind.TYPE, address: { offset: spec.key.address }, sub: spec.key.sub } });
      current = b.valueText;
    } catch {
      /* nothing asserted */
    }
    const parseC = this.features.has("parse-c");
    const value = await ask({
      title: `Set the ${spec.prototype ? "prototype" : "type"} of ${spec.what}`,
      value: current || spec.fallback,
      placeholder: spec.prototype ? "int name(char *s, int n)" : "const uint8_t *",
      // A variable's or a global's type: a single line with a dropdown of
      // the types that match what is typed (Ghidra's data type chooser);
      // a prototype: C text, possibly with definitions, over several lines.
      multiline: parseC && spec.prototype,
      suggest: spec.prototype ? undefined : (v) => this.typeSuggestions(v),
      browse: spec.prototype ? undefined : { label: "Browse types…", run: () => this.showView("types") },
      hint: spec.prototype && parseC
        ? "A C declaration, parsed by the daemon; definitions may come first (struct p { int x; }; struct p *) · Enter to save · Shift+Enter for a new line · Esc to cancel"
        : spec.prototype
          ? "A C declaration, checked by the daemon · Enter to save · Esc to cancel"
          : "Type a name: matching types drop down (↑↓, Tab or Enter takes one) · add * or [n] for a pointer or an array · any C declaration works · Enter to save · Esc to cancel",
      check: async (v) => {
        if (!parseC) return this.edits.check(Edits.retypeBody(spec.target, v.trim()));
        const r = await this.parseRetype(v, spec.prototype).catch((e) => ({ error: errText(e) }));
        return "error" in r ? r.error : null;
      },
    });
    if (value === null || value.trim() === current) return;
    rememberType(value.trim());
    if (parseC) {
      // Definitions before the declaration: defined, bound and applied by
      // hash in one request (one undo). A declaration alone goes as C text,
      // which the daemon parses the same way and shows as typed.
      const r = await this.parseRetype(value, spec.prototype).catch((e) => ({ error: errText(e) }));
      if ("error" in r) return toast(`Set type failed: ${r.error}`, { kind: "error" });
      try {
        const label = `Set ${spec.prototype ? "prototype" : "type"} of ${spec.what}`;
        const res = r.definitions
          ? await this.edits.bodies(label, [...r.bodies, Edits.retypeHashBody(spec.target, r.hash)])
          : await this.edits.retype(spec.target, r.declaration, label);
        toast(`${spec.what}: ${r.declaration}`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
        await this.live.waitFor(res.revision);
      } catch (e) {
        toast(`Set type failed: ${errText(e)}`, { kind: "error" });
      }
      return;
    }
    try {
      // A spelling of a named type of the program ("struct point *") is
      // applied by hash, so the decompiler and every display know it and
      // follow its edits; other declarations are C text.
      if (spec.prototype) {
        const p = await spellPrototype(value.trim(), this.typeContext()).catch(() => null);
        if (p?.usesNamed) {
          const bodies = p.nodes.map(Edits.defineTypeBody);
          const hash = (await this.edits.validate(bodies))[p.index]?.sub;
          if (hash) {
            const r = await this.edits.bodies(`Set prototype of ${spec.what}`, [...bodies, Edits.retypeHashBody(spec.target, hash)]);
            toast(`${spec.what}: ${value.trim()}`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
            await this.live.waitFor(r.revision);
            return;
          }
        }
      } else {
        const s = await spell(value.trim(), this.typeContext()).catch(() => null);
        if (s?.usesNamed) {
          const rev = await this.retypeByHash(spec.target, value.trim(), `Set type of ${spec.what}`);
          if (rev !== null) {
            toast(`${spec.what}: ${value.trim()}`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
            await this.live.waitFor(rev);
            return;
          }
        }
      }
      const r = await this.edits.retype(spec.target, value.trim(), `Set type of ${spec.what}`);
      toast(`${spec.what}: ${value.trim()}`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
      await this.live.waitFor(r.revision);
    } catch (e) {
      toast(`Set type failed: ${errText(e)}`, { kind: "error" });
    }
  }

  /**
   * The type chooser's dropdown for what is typed: the C types and the
   * program's and its libraries' named types whose name holds the typed
   * name, the best matches first, each keeping what was typed around the
   * name (const, *, [n]). Nothing typed: the types used last, then the
   * common ones.
   */
  private async typeSuggestions(text: string): Promise<Suggestion[]> {
    const m = /^(\s*(?:(?:const|volatile)\s+)*)((?:(?:struct|union|enum)\s+)?[A-Za-z_][\w:]*(?:\s+(?:int|long|short|char))*)?(.*)$/s.exec(text) ?? ["", "", "", text];
    const quals = m[1] ?? "";
    const base = (m[2] ?? "").trim();
    const suffix = m[3] ?? "";
    const q = base.replace(/^(struct|union|enum)\s+/, "").toLowerCase();
    const ptr = (this.summary.language?.pointerSize || 8) * 8;
    const builtins: [string, string][] = [
      ["void", "void"], ["bool", "1 byte"], ["char", "1 byte"], ["signed char", "1 byte"], ["unsigned char", "1 byte"],
      ["short", "2 bytes"], ["unsigned short", "2 bytes"], ["int", "4 bytes"], ["unsigned int", "4 bytes"],
      ["long", ptr === 64 ? "8 bytes" : "4 bytes"], ["unsigned long", ptr === 64 ? "8 bytes" : "4 bytes"],
      ["long long", "8 bytes"], ["unsigned long long", "8 bytes"], ["float", "4 bytes"], ["double", "8 bytes"],
      ["int8_t", "1 byte"], ["uint8_t", "1 byte"], ["int16_t", "2 bytes"], ["uint16_t", "2 bytes"],
      ["int32_t", "4 bytes"], ["uint32_t", "4 bytes"], ["int64_t", "8 bytes"], ["uint64_t", "8 bytes"],
      ["size_t", `${ptr / 8} bytes`], ["intptr_t", `${ptr / 8} bytes`], ["uintptr_t", `${ptr / 8} bytes`],
      ["undefined1", "1 byte"], ["undefined2", "2 bytes"], ["undefined4", "4 bytes"], ["undefined8", "8 bytes"],
    ];
    const out: (Suggestion & { rank: number })[] = [];
    const seen = new Set<string>();
    const add = (name: string, detail: string, rank: number) => {
      if (seen.has(name)) return;
      seen.add(name);
      out.push({ label: name, detail, insert: `${quals}${name}${suffix}`, rank });
    };
    const score = (name: string) => {
      const n = name.toLowerCase().replace(/^(struct|union|enum)\s+/, "");
      return n === q ? 0 : n.startsWith(q) ? 1 : n.includes(q) ? 2 : -1;
    };
    if (!q) {
      for (const t of recentTypes()) add(t, "used recently", -1);
      for (const [n, d] of builtins.slice(0, 15)) add(n, `C · ${d}`, 3);
    } else {
      for (const [n, d] of builtins) {
        const r = score(n);
        if (r >= 0) add(n, `C · ${d}`, r + 0.5);
      }
      try {
        const r = await this.rk.queries.findTypes({ programId: this.programId, nameContains: q, summaryOnly: true, page: { pageSize: 60 } });
        const kinds: Record<number, string> = { 9: "struct", 10: "union", 11: "enum", 12: "function", 13: "typedef" };
        for (const t of r.types) {
          if (t.superseded || !kinds[t.kind] || !t.name) continue;
          const spelling = t.kind === 9 || t.kind === 10 || t.kind === 11 ? (t.display && /^(struct|union|enum) /.test(t.display) ? t.display : `${kinds[t.kind]} ${t.name}`) : t.name;
          const from = t.origin?.source.case === "derived" ? "library" : "program";
          const rk = score(spelling);
          add(spelling, `${kinds[t.kind]} · ${t.size} byte${t.size === 1n ? "" : "s"} · ${from}`, (rk < 0 ? 2 : rk) + (from === "library" ? 0.25 : 0));
        }
      } catch {
        /* the C types alone */
      }
    }
    return out.sort((a, b) => a.rank - b.rank || a.label.length - b.label.length || a.label.localeCompare(b.label)).slice(0, 40);
  }

  /**
   * A retype's text, parsed by the daemon (ParseC): its last declaration is
   * the type (or the prototype); declarations before it are types to
   * define with it ("struct p { int x; }; struct p *"). The error, or what
   * to define (the definitions, and the type's own nodes the program lacks)
   * and the hash to retype to.
   */
  private async parseRetype(text: string, prototype: boolean): Promise<{ error: string } | { bodies: AssertionBody[]; hash: string; declaration: string; definitions: boolean }> {
    const src = text.trim().replace(/;\s*$/, "");
    if (!src) return { error: "The declaration is empty" };
    // The last top-level ';' or '}' ends the definitions.
    let depth = 0, cut = -1;
    for (let i = 0; i < src.length; i++) {
      const c = src[i];
      if (c === "{" || c === "(" || c === "[") depth++;
      else if (c === "}" || c === ")" || c === "]") depth--;
      if (depth === 0 && c === ";") cut = i + 1;
    }
    const defs = cut > 0 ? src.slice(0, cut) : "";
    const last = src.slice(cut > 0 ? cut : 0).trim();
    if (!last) return { error: "The last declaration is the type: nothing follows the definitions" };
    const head = defs ? `${defs}\n` : "";
    const lines = head.split("\n").length - 1;
    // As a type name, and as a declaration with a name: whichever reads.
    const sources = prototype
      ? [{ kind: { case: "text" as const, value: `${head}${last};\n` }, name: "retype.h" }]
      : [
          { kind: { case: "text" as const, value: `${head}typedef __typeof__(${last}) __rk_retype_t;\n` }, name: "retype.h" },
          { kind: { case: "text" as const, value: `typedef ${last};\n` }, name: "retype-decl.h" },
        ];
    const parsed = await this.rk.types.parseC({ programId: this.programId, sources, options: { prototypes: prototype } });
    const errs = (file: string) => parsed.diagnostics.filter((d) => d.file === file && d.severity === ParseCSeverity.ERROR);
    const first = errs("retype.h")[0];
    let hash = "", root: number | null = null;
    if (prototype) {
      if (first) return { error: first.line > lines ? first.text : `line ${first.line}: ${first.text}` };
      const p = parsed.prototypes.at(-1);
      if (!p) return { error: "Not a prototype (int name(char *s))" };
      hash = p.hash;
      root = p.index;
    } else {
      const pick = (key: string) => {
        const n = parsed.named.find((x) => x.key === key);
        const t = n ? parsed.nodes[n.index]?.target?.kind : undefined;
        if (!t) return false;
        if (t.case === "hash") hash = t.value;
        else if (t.case === "assertionIndex") {
          hash = parsed.hashes[t.value];
          root = t.value;
        }
        return !!hash;
      };
      if (first || !pick("typedef __rk_retype_t")) {
        const declared = parsed.named.filter((x) => x.file === "retype-decl.h" && x.key.startsWith("typedef "));
        if (first?.line && first.line <= lines) return { error: `line ${first.line}: ${first.text}` };
        if (errs("retype-decl.h").length || declared.length !== 1 || !pick(declared[0].key)) return { error: first?.text ?? "Not a type (const uint8_t *, struct point *, void (*)(int))" };
      }
    }
    const mine = defs ? parsed.named.filter((n) => !n.system && n.file === "retype.h" && n.line <= lines && n.existingHash !== n.hash) : [];
    const plan = headerImportPlan(parsed, { keys: mine.map((n) => n.key), roots: root === null ? [] : [root] });
    return { bodies: plan.bodies, hash, declaration: last, definitions: !!defs };
  }

  /** The code unit a function, flow or note edit applies to. */
  private codeUnit(): ListingRow | null {
    if (this.active === "decomp") {
      const s = this.pane.selected;
      const a = (s ? this.pane.addressOf(s) : null) ?? this.location;
      const row = this.view.selectedRowData();
      return row && a !== null && row.address === a ? row : null;
    }
    return this.view.selectedRowData() ?? null;
  }

  /** f: a function starts at the selected instruction (analysis finds its body). */
  async createFunction() {
    const row = this.codeUnit();
    if (!row) return toast("Select an instruction first");
    if (row.functionEntry) return toast(`A function already starts at ${hex(row.address)}`);
    try {
      const r = await this.edits.functionBounds(row.address, false, `Create function at ${hex(row.address)}`);
      toast(`Function created at ${hex(row.address)}`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
      await this.live.waitFor(r.revision);
      this.decompCache.delete(row.address);
    } catch (e) {
      toast(`Create function failed: ${errText(e)}`, { kind: "error" });
    }
  }

  /** Shift+F: no function starts at the entry of the selected one. */
  async removeFunction() {
    const row = this.codeUnit();
    const entry = row?.func ?? (row?.functionEntry ? row.address : null);
    if (!row || entry === null || entry === undefined) return toast("Not inside a function");
    const name = this.fnName(entry) ?? hex(entry);
    const ok = await choose(`Remove function ${name} at ${hex(entry)}?`, [
      { label: `Remove ${name}`, detail: "its code joins whatever reaches it; undo restores it", value: true },
      { label: "Cancel", value: false },
    ]);
    if (!ok) return;
    try {
      const r = await this.edits.functionBounds(entry, true, `Remove function ${name}`);
      toast(`Removed function ${name}`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
      await this.live.waitFor(r.revision);
    } catch (e) {
      toast(`Remove function failed: ${errText(e)}`, { kind: "error" });
    }
  }

  /** o: override the selected instruction's flow. */
  async flowOverride() {
    const row = this.codeUnit();
    if (!row || row.kind !== RowKind.Instruction) return toast("Select an instruction first");
    const kind = await choose(
      `Flow override at ${hex(row.address)} (${row.mnemonic})`,
      FLOW_CHOICES.map((c) => ({ label: c.label, detail: c.detail, value: c.kind, current: row.flowOverride === c.kind })),
    );
    if (kind === null || kind === row.flowOverride) return;
    const label = FLOW_CHOICES.find((c) => c.kind === kind)!.label;
    try {
      const r = await this.edits.flowOverride(row.address, kind, `Flow override ${label} at ${hex(row.address)}`);
      toast(`Flow at ${hex(row.address)}: ${label}`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
      await this.live.waitFor(r.revision);
    } catch (e) {
      toast(`Flow override failed: ${errText(e)}`, { kind: "error" });
    }
  }

  /** Shift+N: a note (tag and text) at the selection; empty text clears it. */
  async addNote() {
    const addr = this.codeUnit()?.address ?? this.location;
    if (addr === null) return toast("Select an address first");
    const existing = this.notes.at(addr)[0];
    const r = await askMore({
      title: `Note at ${hex(addr)}`,
      value: existing?.text ?? "",
      multiline: true,
      placeholder: "what you found, a hypothesis, a todo (empty clears it)",
      extra: { label: "Tag", value: existing?.tag ?? "note", placeholder: "note" },
    });
    if (r === null) return;
    const tag = r.extra.trim() || "note";
    if (existing && existing.tag === tag && existing.text === r.value) return;
    try {
      const res = await this.edits.note(addr, tag, r.value);
      toast(r.value ? `Note ${tag} saved` : `Note ${tag} cleared`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
      await this.live.waitFor(res.revision);
    } catch (e) {
      toast(`Note failed: ${errText(e)}`, { kind: "error" });
    }
  }

  async rename() {
    if (this.selectedField()) return this.renameField();
    const spec = this.renameSpec();
    if (!spec) return toast("Nothing to rename here");
    const where = spec.target.case === "address" ? ` at ${hex(spec.target.address)}` : "";
    const name = await ask({
      title: `Rename ${spec.what}${spec.current ? ` ${spec.current}` : ""}${where}`,
      value: spec.current,
      placeholder: "new name (empty restores the default)",
      validate: (v) => (/\s/.test(v.trim()) ? "Names can't contain spaces" : null),
    });
    if (name === null || name.trim() === spec.current) return;
    try {
      const r = await this.edits.rename(spec.target, name.trim(), `Rename ${spec.current || spec.what} → ${name.trim() || "(default)"}`);
      toast(name.trim() ? `Renamed ${spec.current || spec.what} → ${name.trim()}` : `Restored the default name`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
      await this.live.waitFor(r.revision);
    } catch (e) {
      toast(`Rename failed: ${errText(e)}`, { kind: "error" });
    }
  }

  private commentSpec(sub?: string): { address: bigint; kind: CommentKind; sub: string } | null {
    if (this.active === "decomp") {
      const s = this.pane.selected;
      const addr = (s ? this.pane.addressOf(s) : null) ?? this.location;
      sub ??= "pre";
      return addr === null ? null : { address: addr, kind: COMMENT_KINDS[sub].kind, sub };
    }
    const row = this.view.selectedRowData();
    if (!row) return null;
    // A plate or pre-comment line edits that comment.
    sub ??= row.header?.kind === HeaderKind.Plate ? "plate" : row.header?.kind === HeaderKind.Pre ? "pre" : "eol";
    return { address: row.address, kind: COMMENT_KINDS[sub].kind, sub };
  }

  async comment(sub?: string) {
    const spec = this.commentSpec(sub);
    if (!spec) return toast("Select an instruction first");
    let current = "";
    try {
      const b = await this.rk.assertions.blame({ key: { programId: this.programId, kind: FactKind.COMMENT, address: { offset: spec.address }, sub: spec.sub } });
      current = b.valueText;
    } catch {
      /* no comment yet */
    }
    const label = COMMENT_KINDS[spec.sub].label;
    const text = await ask({ title: `${label} at ${hex(spec.address)}`, value: current, multiline: true, placeholder: "empty deletes the comment" });
    if (text === null || text === current) return;
    try {
      const r = await this.edits.comment(spec.address, spec.kind, text);
      toast(text ? "Comment saved" : "Comment deleted", { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
      await this.live.waitFor(r.revision);
    } catch (e) {
      toast(`Comment failed: ${errText(e)}`, { kind: "error" });
    }
  }

  async redoOrUndo(which: "undo" | "redo") {
    try {
      const r = which === "undo" ? await this.edits.undo() : await this.edits.redo();
      if (!r) return toast(which === "undo" ? "Nothing to undo" : "Nothing to redo");
      toast(`${which === "undo" ? "Undid" : "Redid"}: ${r.label}`);
      await this.live.waitFor(r.result.revision);
    } catch (e) {
      toast(`${which === "undo" ? "Undo" : "Redo"} failed: ${errText(e)}`, { kind: "error" });
    }
  }

  // ---------------------------------------------------------- xrefs, info --

  private async xrefs() {
    if (this.active === "decomp") {
      const s = this.pane.selected;
      if (s?.tok.target) return this.xrefsFor(s.tok.target.offset, s.tok.text);
      const v = this.pane.variable(s);
      if (v?.address) return this.xrefsFor(v.address.offset, v.name);
      if (this.decompFn?.entry) return this.xrefsFor(this.decompFn.entry.offset, this.decompFn.name);
      return;
    }
    const row = this.view.selectedRowData();
    if (!row) return;
    const hit = this.view.selectedHit;
    if (hit?.kind === "token" && hit.target !== undefined && hit.data === row) return this.xrefsFor(hit.target, hit.key);
    return this.xrefsFor(row.address, row.label || hex(row.address));
  }

  private xrefsFor(address: bigint, name: string) {
    const imp = this.importHere(address);
    const external = imp?.resolved ? { text: importTarget(imp), open: () => this.followImport(address) } : undefined;
    return showXrefs(this.rk, this.programId, address, name, this.addrWidth, (a) => void this.navigate(a), external);
  }

  private factForHit(hit: Hit): FactRef | null {
    const r = hit.data;
    if (hit.kind === "label") return { kind: FactKind.NAME, address: r.address, label: `${r.functionEntry ? "function" : "label"} ${r.label}` };
    if (hit.kind === "token" && hit.op !== undefined) {
      // An operand shown as an equate or a conversion, or as a primary user reference's target.
      const o = r.operands[hit.op];
      const d = o?.displayOrigin?.source;
      if (d?.case === "asserted") return { kind: FactKind.EQUATE, address: r.address, seq: d.value.seq, label: `display of ${o.text} at ${hex(r.address)}` };
      const ref = o?.referenceOrigin?.source;
      if (ref?.case === "asserted") return { kind: FactKind.REFERENCE, address: r.address, seq: ref.value.seq, label: `reference to ${o.text} from ${hex(r.address)}` };
    }
    if (hit.kind === "token" && hit.target !== undefined) return { kind: FactKind.NAME, address: hit.target, label: `symbol ${hit.key}` };
    if (hit.kind === "signature") return { kind: FactKind.TYPE, address: r.address, label: `prototype of ${this.fnName(r.address) ?? hex(r.address)}` };
    if (hit.kind === "type" || hit.kind === "field" || hit.kind === "disclosure") return this.unitFact(r) ?? { kind: FactKind.TYPE, address: r.address, label: `type of ${r.label || hex(r.address)}` };
    if (hit.kind === "mutability") return this.mutabilityFact(r);
    if (hit.kind === "override") return { kind: FactKind.FLOW_OVERRIDE, address: r.address, label: `flow override at ${hex(r.address)}` };
    if (hit.kind === "callsig") return { kind: FactKind.CALL_SIGNATURE, address: r.address, label: `signature override at ${hex(r.address)}` };
    if (hit.kind === "plugin") {
      const facts = this.plugins.facts.filter((f) => f.address?.offset === r.address);
      return {
        kind: FactKind.UNSPECIFIED,
        address: r.address,
        sub: "plugin",
        label: `plugin facts at ${hex(r.address)}`,
        derived: facts.map((f) => ({ rule: f.origin?.source.case === "derived" ? f.origin.source.value.rule : "plugin", text: `${["", "label", "comment", "data type", "note"][f.kind] ?? "fact"}: ${f.text}` })),
      };
    }
    if (hit.kind === "comment") {
      const sub = r.header?.kind === HeaderKind.Plate ? "plate" : r.header?.kind === HeaderKind.Pre ? "pre" : r.eol ? "eol" : r.commentSub;
      return { kind: FactKind.COMMENT, address: r.address, sub, label: `${sub} comment at ${hex(r.address)}` };
    }
    return null;
  }

  /** The listing edit (Clear, Disassemble here, Define data) that says what a row is, if any. */
  private unitFact(r: ListingRow): FactRef | null {
    const o = r.unitOrigin?.source;
    if (o?.case !== "asserted") return null;
    const what = r.kind === RowKind.Data ? `data ${r.dataType}` : r.kind === RowKind.Instruction ? "code" : "undefined bytes";
    return { kind: FactKind.CODE_UNIT, address: r.address, seq: o.value.seq, label: `listing edit: ${what} at ${hex(r.address)}` };
  }

  /** The mutability edit over a row, if any. */
  private mutabilityFact(r: ListingRow): FactRef | null {
    const o = r.mutabilityOrigin?.source;
    if (o?.case !== "asserted") return null;
    return { kind: FactKind.MUTABILITY, address: r.address, seq: o.value.seq, label: `mutability at ${hex(r.address)}` };
  }

  /** Debugger ▸ Add watch: what is selected as a watch expression (a
   * decompiler variable in its function's frame, a listing register, a
   * labelled data item, else the address as an int), confirmed in a prompt. */
  private async watchHere() {
    if (!(this.emu instanceof DebuggerPanel)) return;
    let guess = "";
    let fn: bigint | undefined;
    if (this.active === "decomp" && this.pane.selected) {
      const s = this.pane.selected;
      const v = this.pane.variable(s);
      if (v) {
        guess = v.name;
        if (v.kind !== VariableKind.GLOBAL) fn = this.decompFn?.entry?.offset;
      } else if (/^[A-Za-z_]\w*$/.test(s.tok.text)) guess = s.tok.text;
    } else {
      const row = this.view.selectedRowData();
      const hit = this.view.selectedHit && row && this.view.selectedHit.data === row ? this.view.selectedHit : null;
      const o = hit?.op !== undefined ? row?.operands[hit.op] : undefined;
      if (o?.kind === TokenKind.Register) guess = `$${o.text.trim()}`;
      else if (row?.label && row.dataType) guess = row.label;
      else if (row) {
        const slide = this.emu.state?.mapping?.known ? this.emu.state.mapping.slide : 0n;
        guess = `*(${row.dataType && /^[\w ]+$/.test(row.dataType) ? row.dataType : "int"} *)0x${(row.address + slide).toString(16)}`;
      }
    }
    const expr = await ask({ title: "Watch expression", value: guess, placeholder: "$RAX, *(int *)($RBP - 0x14), ctx->len" });
    if (expr?.trim()) this.emu.addWatch(expr.trim(), expr.trim() === guess ? fn : undefined);
  }

  /** Debugger ▸ Disassemble runtime memory: an address or expression (the
   * selection's runtime address by default), in the Debugger view. */
  private async disassembleRuntime() {
    if (!(this.emu instanceof DebuggerPanel)) return;
    const slide = this.emu.state?.mapping?.known ? this.emu.state.mapping.slide : 0n;
    const guess = this.location !== null ? `0x${(this.location + slide).toString(16)}` : "";
    const expr = await ask({ title: "Disassemble runtime memory at", value: guess, placeholder: "a runtime address or expression: $RIP, 0x7ffff7c2a1ca, *(void **)$RSP" });
    if (expr?.trim()) await this.emu.disassembleExpr(expr.trim());
  }

  /** Debugger ▸ Copy runtime memory into the program: a range (or the
   * target region holding an address) as a new block, as patches, or as a
   * new program; one undo step. */
  private async copyRuntimeMemory() {
    if (!(this.emu instanceof DebuggerPanel)) return;
    const emu = this.emu;
    const slide = emu.state?.mapping?.known ? emu.state.mapping.slide : 0n;
    const first = emu.disasm[0]?.location?.address?.offset;
    const guess = this.location !== null ? `0x${(this.location + slide).toString(16)}` : first !== undefined ? `0x${first.toString(16)}` : "";
    const f = await askFields("Copy runtime memory into the program", [
      { name: "address", label: "Runtime address or expression", value: guess, required: true, placeholder: "0x7ffff7c28000, $RSP, *(void **)$RDI" },
      { name: "length", label: "Length in bytes (empty: the whole mapped region)", placeholder: "0x1000, or empty for the region" },
      { name: "name", label: "Block or program name (optional)", placeholder: "default: the region's name and the address" },
    ]);
    if (!f) return;
    type Mode = "block" | "patch" | "program";
    const mode = await choose<Mode>("Copy it as", [
      { label: "A new memory block", detail: "at its runtime address: a library, the heap, code unpacked outside the program", value: "block" },
      { label: "Patches over the program", detail: "only the bytes that differ: code unpacked or decrypted in place", value: "patch" },
      { label: "A new program", detail: "a raw program in the project, in this program's language, based at the address", value: "program" },
    ]);
    if (!mode) return;
    let length = 0n;
    if (f.length?.trim()) {
      try {
        length = BigInt(/^0x/i.test(f.length.trim()) || /^\d+$/.test(f.length.trim()) ? f.length.trim() : `0x${f.length.trim()}`);
      } catch {
        return void toast(`Not a length: ${f.length}`, { kind: "error" });
      }
    }
    const r = await emu.copyMemory(f.address.trim(), length, mode, f.name?.trim() ?? "");
    if (!r) return;
    const what = `${r.length} bytes from 0x${r.address.toString(16)}`;
    if (mode === "program") {
      toast(`Copied ${what} into a new program, ${r.program?.name ?? ""}`);
      return;
    }
    if (mode === "patch" && r.changed === 0n) return void toast(`The program already has these ${what}: nothing to patch`);
    this.edits.record(mode === "patch" ? `Copy ${r.changed} changed bytes from runtime memory` : `Copy ${what} into a block`, r.seqs);
    toast(mode === "patch" ? `Patched ${r.changed} bytes that differed (${what})` : `Copied ${what} into block ${r.block?.name ?? ""}`);
    await this.live.waitFor(r.revision);
    if (mode === "block") void this.navigate(r.programAddress);
  }

  /** A debug session can give values now (feature debugger-values, a session, not running). */
  private debugValues(): boolean {
    return this.emu instanceof DebuggerPanel && this.emu.values && this.emu.active && !this.emu.running;
  }

  /** A listing hit's hover card (ui/hover.ts): a reference's target, a
   * scalar, a data item's type, a function's signature; then who set it. */
  private hoverForHit(hit: Hit): HoverSubject | null {
    const r = hit.data;
    const previews: Preview[] = [];
    if (hit.kind === "token") {
      const o = hit.op !== undefined ? r.operands[hit.op] : undefined;
      // While a debug session is stopped: the register's value, the memory operand's.
      if (o && this.debugValues()) {
        if (o.kind === TokenKind.Register)
          previews.push({ kind: "value", item: { case: "expression", value: `$${o.text.trim()}` }, label: `register ${o.text.trim()}`, frame: (this.emu as DebuggerPanel).frame });
        const memory = o.operandIndex !== undefined && r.operands.some((x) => x.operandIndex === o.operandIndex && x.text.includes("["));
        if (memory) previews.push({ kind: "value", item: { case: "operand", value: { address: { offset: r.address }, operand: o.operandIndex! } }, label: "memory operand" });
      }
      if (hit.target !== undefined) previews.push({ kind: "target", address: hit.target });
      else if (o?.value !== undefined) previews.push({ kind: "scalar", value: o.value, bits: o.bits ?? 64 });
    } else if (hit.kind === "label" && r.functionEntry) previews.push({ kind: "target", address: r.address, signatureOnly: true });
    else if (hit.kind === "callsig" && r.callSignature) previews.push({ kind: "callsig", text: r.callSignature });
    else if ((hit.kind === "type" || hit.kind === "field") && r.dataTypeHash) previews.push({ kind: "type", hash: r.dataTypeHash, declared: r.dataType, label: `type of ${r.label || r.dataField || hex(r.address)}` });
    return { key: `l:${r.address}:${hit.kind}:${hit.col}`, previews, fact: this.factForHit(hit) };
  }

  /** A decompiler token's hover card: a callee's signature and first lines,
   * a global's listing rows, a variable's, a type's or a field's
   * definition, a constant's spellings; then who set it. */
  private hoverForSpan(s: TokSpan): HoverSubject | null {
    const t = s.tok;
    const previews: Preview[] = [];
    const v = this.pane.variable(s);
    const fnEntry = this.decompFn?.entry?.offset;
    if (t.kind === CodeTokenKind.FUNCTION_NAME && t.callSignature) previews.push({ kind: "callsig", text: t.callSignature });
    if (t.kind === CodeTokenKind.FUNCTION_NAME && t.target) previews.push({ kind: "target", address: t.target.offset, signatureOnly: t.target.offset === fnEntry });
    else if (t.kind === CodeTokenKind.GLOBAL_VARIABLE && t.target) previews.push({ kind: "target", address: t.target.offset });
    // While a debug session is stopped: the variable's value through its storage.
    if (v && fnEntry !== undefined && this.debugValues() && (t.kind === CodeTokenKind.LOCAL_VARIABLE || t.kind === CodeTokenKind.PARAMETER || t.kind === CodeTokenKind.GLOBAL_VARIABLE))
      previews.push({
        kind: "value",
        item: { case: "variable", value: { function: { offset: fnEntry }, storage: v.storage, type: v.type, name: v.name, address: v.address } },
        label: `value of ${v.name}`,
      });
    if ((t.kind === CodeTokenKind.LOCAL_VARIABLE || t.kind === CodeTokenKind.PARAMETER || t.kind === CodeTokenKind.GLOBAL_VARIABLE) && v?.type && (v.type.hash || v.type.display))
      previews.push({ kind: "type", hash: v.type.hash, declared: `${v.type.display} ${v.name}`, label: `${v.kind === VariableKind.PARAMETER ? "parameter" : v.kind === VariableKind.GLOBAL ? "global" : "local"} ${v.name}` });
    if (t.kind === CodeTokenKind.TYPE) previews.push({ kind: "type", hash: t.typeHash, declared: t.text, label: "type" });
    const f = this.pane.field(s);
    if (f?.hash) previews.push({ kind: "type", hash: f.hash, field: f.offset, label: `field ${f.name} at +0x${f.offset.toString(16)}` });
    if (t.kind === CodeTokenKind.CONSTANT && t.value !== undefined) {
      const vn = t.varnodeIndices.map((i) => this.decompFn?.varnodes[i]?.varnode?.size ?? 0).find((n) => n > 0);
      previews.push({ kind: "scalar", value: t.value, bits: vn ? vn * 8 : 64 });
    }
    return { key: `d:${fnEntry}:${s.line}:${s.from}`, previews, fact: this.factForSpan(s) };
  }

  private factForSpan(s: TokSpan): FactRef | null {
    const fn = this.decompFn;
    const v = this.pane.variable(s);
    if (v && fn?.entry && v.kind !== VariableKind.GLOBAL) return { kind: FactKind.NAME, address: fn.entry.offset, sub: `local:${v.storageKey}`, label: `${v.kind === VariableKind.PARAMETER ? "parameter" : "local"} ${v.name}` };
    const addr = s.tok.target?.offset ?? v?.address?.offset;
    if (addr !== undefined) return { kind: FactKind.NAME, address: addr, label: `${s.tok.kind === CodeTokenKind.FUNCTION_NAME ? "function" : "global"} ${s.tok.text}` };
    return null;
  }

  /** i: the provenance badge for what is selected, placed next to it. */
  private async showProvenanceForSelection() {
    if (this.active === "decomp") {
      const s = this.pane.selected;
      const f = s ? this.factForSpan(s) : null;
      if (!s || !f) return toast("Select a name in the decompiler first");
      const c = this.pane.view.coordsAtPos(s.from);
      return this.prov.show(f, c?.left ?? 200, (c?.bottom ?? 200) + 4);
    }
    const row = this.view.selectedRowData();
    if (!row) return;
    const hit = this.view.selectedHit && this.view.selectedHit.data === row ? this.view.selectedHit : null;
    const headerHit = row.header ? layoutRow(row, this.cols).hot.find((h) => h.kind !== "xref") : undefined;
    const f: FactRef | null =
      (hit && this.factForHit(hit)) ??
      (headerHit ? this.factForHit({ ...headerHit, row: this.view.selectedRow, data: row }) : null) ??
      (row.label
        ? { kind: FactKind.NAME, address: row.address, label: `${row.functionEntry ? "function" : "label"} ${row.label}` }
        : row.flowOverride
          ? { kind: FactKind.FLOW_OVERRIDE, address: row.address, label: `flow override at ${hex(row.address)}` }
          : row.dataType && !row.unitOrigin
            ? { kind: FactKind.TYPE, address: row.address, label: `type at ${hex(row.address)}` }
            : row.comment
              ? { kind: FactKind.COMMENT, address: row.address, sub: row.eol ? "eol" : row.commentSub, label: `comment at ${hex(row.address)}` }
              : null);
    // What the row is and its mutability, when edits say so (listing-edit).
    const more = [this.unitFact(row), this.mutabilityFact(row)].filter((x): x is FactRef => x !== null && !(f && x.kind === f.kind));
    const first = f ?? more.shift();
    if (!first) return toast("Nothing named here");
    const rect = this.view.canvas.getBoundingClientRect();
    const y = rect.top + this.view.selectedRow * this.view.rowH - this.view.scrollY + this.view.rowH + 4;
    return this.prov.show(first, rect.left + PAD_X + this.cols.label * this.view.charWidth, y, more);
  }

  // --------------------------------------------------------- live updates --

  private setLive(s: LiveState, head: bigint) {
    this.liveState = s;
    const el = $("st-live");
    el.className = `st-live ${s}`;
    el.querySelector("span")!.textContent = s;
    $("st-rev").textContent = `rev ${head}`;
    document.body.dataset.live = s;
    document.body.dataset.revision = String(head);
    this.daemon?.noteStream(s);
  }

  private onRevision(ev: RevisionEvent) {
    const rev = ev.revision;
    if (ev.invalidateAllPrograms.includes(this.programId)) return this.resync(rev);
    let listing = false;
    let fnList = false;
    let types = false;
    let xrefs = false;
    let pluginFacts = false;
    const decomp = new Set<bigint>();
    // Renumbered rows first (the windows of the numbering this tab reads),
    // so the range invalidations below find the rows where they now are.
    const shifts: RowShift[] = [];
    for (const q of ev.invalidated) {
      if (q.programId !== this.programId || q.kind !== QueryKind.LISTING) continue;
      const w = this.headerRows ? q.headerRows : q.rows;
      const p = this.headerRows ? q.previousHeaderRows : q.previousRows;
      if (w && p) shifts.push({ prevFirst: Number(p.firstRow), prevCount: p.rowCount, first: Number(w.firstRow), count: w.rowCount });
    }
    if (shifts.length) this.cache.applyShift(rev, shifts);
    for (const q of ev.invalidated) {
      if (q.programId !== this.programId) continue;
      switch (q.kind) {
        case QueryKind.LISTING:
          listing = true;
          if (q.range?.first && q.range.last) this.cache.invalidateRange(q.range.first.offset, q.range.last.offset, rev);
          else this.cache.invalidateAll(rev);
          break;
        case QueryKind.FUNCTION_LIST:
        case QueryKind.FUNCTION:
          fnList = true;
          break;
        case QueryKind.DIFF_SESSION:
          this.diff?.invalidate(q.diffSessionId);
          break;
        case QueryKind.DECOMPILE:
          if (q.address) decomp.add(q.address.offset);
          break;
        case QueryKind.TYPES:
          types = true;
          break;
        case QueryKind.XREFS:
          xrefs = true;
          break;
        case QueryKind.PLUGIN_FACTS:
          pluginFacts = true;
          break;
        case QueryKind.PROGRAM:
          void this.programChanged();
          break;
        case QueryKind.MEMORY:
          this.reloadMemory();
          void this.refreshBlocks();
          break;
      }
    }
    // The other views: the graph of the function shown, data, calls, types.
    const g = this.graph.entry;
    if (g !== null && (listing || fnList || decomp.has(g))) {
      clearTimeout(this.graphReload);
      this.graphReload = window.setTimeout(() => {
        if (this.graph.entry === null) return;
        if (this.dock.isVisible("graph")) void this.graph.load(this.graph.entry, true).then(() => this.graph.select(this.location, false));
        else this.graph.clear();
      }, 150);
    }
    const typedGlobal = ev.changedKeys.some((k) => k.programId === this.programId && k.kind === FactKind.TYPE && !k.sub);
    if (listing || fnList || typedGlobal || types) {
      clearTimeout(this.dataReload);
      this.dataReload = window.setTimeout(() => (this.dock.isVisible("strings") ? void this.data.load() : this.data.markStale()), 200);
    }
    if (fnList || xrefs) {
      clearTimeout(this.callsReload);
      this.callsReload = window.setTimeout(() => void this.calls.refresh(), 200);
    }
    if (types) void this.types.refresh();
    if (pluginFacts) {
      this.plugins.invalidate();
      this.wantPluginFacts();
      this.fnFacts.invalidate();
      if (this.decompEntry !== null) void this.wantFunctionFacts(this.decompEntry);
    }
    this.patches?.onRevision(ev, this.dock.isVisible("patches"));
    this.equates?.onRevision(ev, this.dock.isVisible("equates"));
    this.refs?.onRevision(ev, this.dock.isVisible("refs"));
    if (listing || xrefs) {
      // Fields fetched for the rows in view: dropped and asked for again.
      dropFieldValues({ pcode: listing, xrefs: true });
      this.pcodeWant = "";
      this.wantFields();
    }
    if (listing) {
      this.overview?.reload();
      if (this.bytes) {
        this.bytes.setVisible(this.dock.isVisible("bytes"));
        this.bytes.invalidate();
      }
    }
    if (listing) this.view.invalidate();
    if (fnList) {
      this.fnRanges.clear();
      this.fnNames.clear();
      this.functions.forgetNames();
      this.reloadFunctions();
      // Function and vftable names show in the class hierarchy.
      if (this.classes) this.dock.isVisible("classes") ? void this.classes.load() : this.classes.markStale();
      // Names show in Function ID's matches (and its runs rename).
      if (this.fid) this.dock.isVisible("fid") ? void this.fid.load() : this.fid.markStale();
    }
    if (ev.changedKeys.some((k) => k.programId === this.programId && k.kind === FactKind.NOTE)) this.reloadNotes();
    for (const a of decomp) {
      this.decompCache.delete(a);
      this.decompStaleAt.set(a, rev);
    }
    if (this.decompEntry !== null && decomp.has(this.decompEntry)) void this.loadDecompile(this.decompEntry, true);
    // This tab's own edits (a header import has a session of its own under the tab's).
    if (!(ev.provenance?.session ?? "").startsWith(SESSION) && !this.scripts?.ownRuns.has(ev.provenance?.session ?? "") && (ev.cause === ChangeCause.ASSERTION || ev.cause === ChangeCause.RETRACTION)) {
      const n = ev.assertionSeqs.length;
      const what = ev.cause === ChangeCause.RETRACTION ? `retracted ${n} assertion${n === 1 ? "" : "s"}` : this.describe(ev);
      toast(`${provText(ev.provenance)} ${what}`, { kind: "remote" });
    }
    document.body.dataset.revision = String(rev);
  }

  private describe(ev: RevisionEvent): string {
    const a = ev.assertions[0]?.body?.kind;
    const where = (t: { kind: { case?: string; value?: unknown } } | undefined) =>
      t?.kind.case === "local" ? "a variable" : hex(t?.kind.value && typeof t.kind.value === "object" && "offset" in t.kind.value ? (t.kind.value as { offset: bigint }).offset : 0n);
    if (ev.assertions.length === 1)
      switch (a?.case) {
        case "rename":
          return `renamed ${where(a.value.target)} to ${a.value.name || "(default)"}`;
        case "comment":
          return `commented ${hex(a.value.address?.offset ?? 0n)}`;
        case "retype":
          return `set the type of ${where(a.value.target)} to ${a.value.type?.kind.case === "cDeclaration" ? a.value.type.kind.value : "a type"}`;
        case "functionBounds":
          return `${a.value.remove ? "removed the function at" : "created a function at"} ${hex(a.value.entry?.offset ?? 0n)}`;
        case "flowOverride":
          return `overrode the flow at ${hex(a.value.address?.offset ?? 0n)}`;
        case "note":
          return `${a.value.text ? "noted" : "cleared a note at"} ${hex(a.value.address?.offset ?? 0n)}`;
        case "memoryRegion":
          return a.value.removed ? "removed a memory region" : `${a.value.regionId ? "set" : "edited"} memory region ${a.value.name} at ${hex(a.value.start)}`;
        case "listingEdit":
        case "mutability":
          return `${listingEditText(ev.assertions[0].body)} at ${hex(a.value.address?.offset ?? 0n)}`;
        case "operandDisplay":
        case "reference":
          return `${listingEditText(ev.assertions[0].body)}`;
      }
    return `made ${ev.assertionSeqs.length} edit${ev.assertionSeqs.length === 1 ? "" : "s"}`;
  }

  /** The memory map changed: reload it where it is shown, else when next shown. */
  private reloadMemory() {
    clearTimeout(this.memoryReload);
    this.memoryReload = window.setTimeout(() => (this.dock.isVisible("memory") ? void this.memmap.load() : this.memmap.markStale()), 100);
  }

  private reloadFunctions() {
    clearTimeout(this.fnReload);
    this.fnReload = window.setTimeout(() => void this.functions.load().catch(() => {}), 120);
  }

  private reloadNotes() {
    clearTimeout(this.notesReload);
    this.notesReload = window.setTimeout(() => void this.notes.load(), 60);
  }

  private resync(head: bigint) {
    this.cache.invalidateAll(head);
    if (this.graph.entry !== null && this.dock.isVisible("graph")) void this.graph.load(this.graph.entry, true);
    this.data.markStale();
    this.reloadMemory();
    void this.types.refresh();
    void this.calls.refresh();
    this.plugins.invalidate();
    this.decompCache.clear();
    if (this.decompEntry !== null) this.decompStaleAt.set(this.decompEntry, head);
    if (this.decompEntry !== null) void this.loadDecompile(this.decompEntry, true);
    this.reloadFunctions();
    this.reloadNotes();
    if (this.equates) this.dock.isVisible("equates") ? void this.equates.load() : this.equates.markStale();
    if (this.classes) this.dock.isVisible("classes") ? void this.classes.load() : this.classes.markStale();
    if (this.fid) this.dock.isVisible("fid") ? void this.fid.load() : this.fid.markStale();
    if (this.refs) this.dock.isVisible("refs") ? void this.refs.load() : this.refs.markStale();
  }

  // ---------------------------------------------------------------- views --

  private setupViews() {
    const theme = this.dark ? DARK : LIGHT;
    this.graph = new CfgView($("graph"), this.rk, this.programId, this.addrWidth, theme, FONT);
    this.graph.onSelect = (addr) => void this.selectFrom("graph", addr);
    this.graph.onFollow = (addr) => void this.navigate(addr);
    this.calls = new CallsView($("calls"), this.rk, this.programId, this.addrWidth);
    this.calls.onOpen = (addr) => void this.navigate(addr);
    this.data = new DataView($("strings"), this.rk, this.programId, this.addrWidth);
    this.data.onOpen = (addr) => void this.navigate(addr);
    this.memmap = new MemoryMapView($("memory"), {
      rk: this.rk,
      programId: this.programId,
      addrWidth: this.addrWidth,
      editable: this.features.has("memory-map"),
      hostFiles: this.features.has("host-files"),
      navigate: (addr) => void this.navigate(addr, { focus: "listing" }),
      recordUndo: (label, seqs) => this.edits.record(label, seqs),
      undo: () => void this.redoOrUndo("undo"),
      settle: (rev) => this.live.waitFor(rev),
      pause: () => this.live.pause(),
      rebase: this.features.has("rebase"),
      // The cursor and the history move with the program (docs/memory-map.md, "Rebase").
      rebased: (from, to) => this.moveBase(to - from),
    });
    this.types = new TypesView($("types"), {
      rk: this.rk,
      programId: this.programId,
      edits: this.edits,
      parseC: this.features.has("parse-c"),
      archives: this.features.has("type-archive"),
      projectTypes: this.features.has("project-types"),
      apply: (def, pointer) => this.applyType(def, pointer),
      settle: (rev) => this.live.waitFor(rev),
      findUses: this.features.has("type-uses") ? (hash, name, field) => void this.findUses(hash, field, name) : undefined,
    });
    if (this.features.has("diff")) {
      this.diff = new DiffView($("diff"), {
        rk: this.rk,
        projectId: this.projectId,
        programId: this.programId,
        addrWidth: this.addrWidth,
        edits: this.edits,
        navigate: (addr) => void this.navigate(addr),
        settle: (rev) => this.live.waitFor(rev),
        theme: () => (this.dark ? DARK : LIGHT),
        font: FONT,
        detail: this.features.has("diff-detail"),
        compare: this.features.has("function-compare"),
        onPair: (pd, message) => {
          if (this.diffGraph && this.dock.isVisible("diffgraph")) void this.diffGraph.set(pd, message);
        },
      });
      $("diff").addEventListener("focusin", () => (this.active = "diff"));
      if (this.features.has("diff-detail")) {
        this.diffGraph = new DiffGraphView(theme, FONT, "Graph diff");
        $("diffgraph").append(this.diffGraph.el);
        this.diffGraph.onSelectBlock = (side, block) => {
          this.diff?.revealBlock(side, block);
        };
        $("diffgraph").addEventListener("focusin", () => (this.active = "diff"));
      }
    }
    if (this.features.has("patch")) {
      const host = this.patchHost();
      this.patchEditor = new PatchEditor(host);
      this.patches = new PatchesView($("patches"), host);
      $("patches").addEventListener("focusin", () => (this.active = "patches"));
    }
    if (this.features.has("equates")) {
      const host = this.equateHost();
      this.equateEdit = new EquateEditor(host);
      this.equates = new EquatesView($("equates"), host);
      $("equates").addEventListener("focusin", () => (this.active = "equates"));
    }
    if (this.features.has("msvc-rtti")) {
      this.classes = new ClassesView($("classes"), {
        rk: this.rk,
        programId: this.programId,
        addrWidth: this.addrWidth,
        navigate: (a) => void this.navigate(a, { focus: "listing" }),
        showType: (name) => {
          this.showView("types");
          void this.types.showNamed(name);
        },
      });
    }
    if (this.features.has("function-id")) {
      this.fid = new FidView($("fid"), {
        rk: this.rk,
        programId: this.programId,
        projectId: this.projectId,
        addrWidth: this.addrWidth,
        navigate: (a) => void this.navigate(a, { focus: "listing" }),
        settle: (rev) => this.live.waitFor(rev),
        undo: () => void this.redoOrUndo("undo"),
      });
      $("fid").addEventListener("focusin", () => (this.active = "fid"));
    }
    if (this.features.has("bsim")) {
      this.bsim = new BsimView($("bsim"), {
        rk: this.rk,
        programId: this.programId,
        projectId: this.projectId,
        addrWidth: this.addrWidth,
        features: this.features,
        currentFunction: () => this.bsimTarget(),
        navigate: (a) => void this.navigate(a, { focus: "listing" }),
        compare: (a, b) => {
          if (!this.diff || !this.features.has("function-compare")) return toast("This daemon can't compare two functions (feature function-compare)", { kind: "error" });
          this.showView("diff");
          void this.diff.openFunctions(a, b);
        },
      });
      $("bsim").addEventListener("focusin", () => (this.active = "bsim"));
    }
    if (this.features.has("user-references")) {
      const host = this.referenceHost();
      this.refEdit = new ReferenceEditor(host);
      this.refs = new ReferencesView($("refs"), host, this.refEdit, () => this.referenceOperand());
      $("refs").addEventListener("focusin", () => (this.active = "refs"));
    }
    if (this.features.has("scripts-host")) {
      this.scripts = new Scripts($("scripts"), {
        rk: this.rk,
        programId: this.programId,
        projectId: this.projectId,
        location: () => this.location,
        currentFunction: () => (this.active === "decomp" ? this.decompEntry : (this.view.selectedRowData()?.func ?? null)),
        selection: () => this.selectedRange(),
        recordUndo: (label, seqs) => this.edits.record(label, seqs),
        settle: (rev) => this.live.waitFor(rev),
        show: () => this.dock.show("scripts"),
      });
      $("scripts").addEventListener("focusin", () => (this.active = "scripts"));
      // Palette commands and keys need the list before the view is shown.
      void this.scripts.load();
      if (this.features.has("script-console")) {
        const scripts = this.scripts;
        this.console = new PythonConsole($("python"), {
          rk: this.rk,
          programId: this.programId,
          location: () => this.location,
          selection: () => this.selectedRange(),
          recordUndo: (label, seqs) => this.edits.record(label, seqs),
          settle: (rev) => this.live.waitFor(rev),
          hostStatus: () => scripts.hostStatus(),
          setupPython: async () => {
            await scripts.setupPython();
            return !scripts.pythonProblem;
          },
          own: (runId) => scripts.ownRuns.add(runId),
          show: () => this.dock.show("python"),
        });
        $("python").addEventListener("focusin", () => (this.active = "python"));
      }
    }
    if (this.features.has("byte-viewer")) {
      this.bytes = new ByteViewer({
        rk: this.rk,
        programId: this.programId,
        addrWidth: this.addrWidth,
        edits: this.edits,
        bigEndian: this.summary.language?.endianness === Endianness.BIG,
        blocks: this.blocks,
        canPatch: this.features.has("patch"),
        select: (a) => void this.view.goTo(a, { align: "third" }),
        selectRange: (lo, hi) => void this.view.selectAddressRange(lo, hi),
        settle: (rev) => this.live.waitFor(rev),
      });
      $("bytes").append(this.bytes.el);
      $("bytes").addEventListener("focusin", () => (this.active = "bytes"));
    }
    if (this.features.has("search")) {
      this.search = new Search($("searchresults"), {
        rk: this.rk,
        programId: this.programId,
        addrWidth: this.addrWidth,
        location: () => this.location,
        selection: () => this.selectionRanges(),
        currentFunction: () => (this.active === "decomp" ? this.decompEntry : (this.view.selectedRowData()?.func ?? this.decompEntry)),
        navigate: (addr) => this.navigate(addr),
        openDecompiled: (entry, line, from, to, address) => this.openDecompiledLine(entry, line, from, to, address),
        select: (ranges) => {
          this.view.rangeSelection = ranges;
          this.view.invalidate();
        },
        markHits: (addrs) => {
          this.view.searchMarks = addrs;
          this.view.invalidate();
        },
        showResults: () => this.dock.show("searchresults"),
        closeResults: () => {
          this.dock.close("searchresults");
          this.view.canvas.focus({ preventScroll: true });
        },
        focusListing: () => this.view.canvas.focus({ preventScroll: true }),
      });
      $("searchresults").addEventListener("focusin", () => (this.active = "search"));
    }
    this.plugins = new PluginFacts(this.rk, this.programId);
    this.plugins.onChange = () => {
      setAnnotations(this.plugins.byAddress);
      this.view.invalidate();
    };
    if (this.features.has("plugins")) void this.plugins.loadPlugins().then(() => this.wantPluginFacts());
    this.fnFacts = new PluginFacts(this.rk, this.programId);
    this.fnFacts.onChange = () => {
      this.graph.setAnnotations(this.fnFacts.byAddress);
      this.pane.setAnnotations(this.fnFacts.byAddress);
    };
    for (const [id, name] of [
      ["graph", "graph"],
      ["calls", "calls"],
      ["strings", "strings"],
      ["types", "types"],
      ["memory", "memory"],
    ] as const)
      $(id).addEventListener("focusin", () => (this.active = name));
  }

  /** A view's tab was chosen: bring it up to date with the selection. */
  private onViewShown(id: string) {
    const row = this.view?.selectedRowData();
    switch (id) {
      case "listing":
        this.view?.resize();
        break;
      case "graph":
        if (row?.func != null) void this.graph.load(row.func).then(() => this.graph.select(this.location));
        else this.graph.resize();
        break;
      case "calls":
        if (row?.func != null) void this.calls.setRoot(row.func, this.fnName(row.func) ?? hex(row.func));
        break;
      case "strings":
        this.data?.ensureLoaded();
        break;
      case "types":
        this.types?.ensureLoaded();
        break;
      case "memory":
        this.memmap?.ensureLoaded();
        break;
      case "diff":
        void this.diff?.ensureLoaded();
        break;
      case "diffgraph":
        void this.diff?.ensureLoaded().then(() => this.diffGraph?.set(this.diff?.shownPair() ?? null)).then(() => this.diffGraph?.resize());
        break;
      case "patches":
        this.patches?.ensureLoaded();
        break;
      case "classes":
        this.classes?.ensureLoaded();
        break;
      case "fid":
        this.fid?.ensureLoaded();
        break;
      case "bsim":
        this.bsim?.ensureLoaded();
        break;
      case "equates":
        this.equates?.ensureLoaded();
        break;
      case "refs":
        this.refs?.follow(this.location, true);
        this.refs?.ensureLoaded();
        break;
      case "scripts":
        this.scripts?.ensureLoaded();
        break;
      case "bytes":
        if (this.bytes) {
          this.bytes.setVisible(true);
          if (row && row.kind !== RowKind.Header) this.bytes.followListing(row.address, row.length, this.listingSelection());
        }
        break;
      case "python":
        this.console?.focus();
        break;
    }
  }

  // -------------------------------------------------------------- patching --

  private patchHost(): PatchHost {
    return {
      rk: this.rk,
      programId: this.programId,
      addrWidth: this.addrWidth,
      edits: this.edits,
      settle: (rev) => this.live.waitFor(rev),
      navigate: (addr) => void this.navigate(addr),
      isaToggle: (this.summary.language?.languageId ?? "").startsWith("ARM:"),
      compareWithOriginal: this.features.has("diff") ? () => this.compareWithOriginal() : undefined,
    };
  }

  /** The selected row's client rectangle (where the inline editor goes). */
  private rowRect(): { left: number; top: number; width: number } | null {
    const i = this.view.selectedRow;
    if (i < 0) return null;
    const c = this.view.canvas.getBoundingClientRect();
    return { left: c.left + PAD_X + Math.max(0, this.cols.mnem - 2) * this.view.charWidth, top: c.top + i * this.view.rowH - this.view.scrollY, width: c.width };
  }

  /** Ctrl+Shift+G: the selected instruction becomes an editor (assembled as typed). */
  patchInstruction() {
    const row = this.view.selectedRowData();
    if (!this.patchEditor || !row || row.kind === RowKind.Header) return toast("Select an instruction (or data) to patch", { kind: "error" });
    const text = row.kind === RowKind.Instruction ? `${row.mnemonic}${row.operands.length ? " " + row.operands.map((t) => t.text).join("") : ""}` : "";
    const at = this.rowRect();
    if (!at) return;
    this.patchEditor.open(row.address, text, at);
  }

  /** Ctrl+Shift+H: the selection's bytes in a hex editor. */
  async patchBytes() {
    const [a, b] = this.view.selectionRange();
    const first = this.cache.get(a);
    const last = this.cache.get(b);
    if (!first || !last) return toast("Select the bytes to patch", { kind: "error" });
    const end = last.address + BigInt(Math.max(1, last.length));
    await patchBytesDialog(this.patchHost(), first.address, Number(end - first.address));
  }

  private async revertPatchHere() {
    const row = this.view.selectedRowData();
    if (!row) return;
    try {
      const last = row.address + BigInt(Math.max(1, row.length) - 1);
      const r = await this.rk.patch.revertPatches({ programId: this.programId, range: { first: { offset: row.address }, last: { offset: last } }, provenance: userProvenance("revert patch") });
      this.edits.record(`Revert patch at 0x${hex(row.address)}`, r.seqs);
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  /** Compare with…: the function at the cursor (or `entry`) against any function of the project (feature function-compare). */
  async compareFunctionWith(entry?: bigint, name?: string) {
    if (!this.diff || !this.features.has("function-compare")) return toast("This daemon can't compare two functions (feature function-compare)", { kind: "error" });
    const e = entry ?? (this.active === "decomp" ? this.decompEntry : (this.view.selectedRowData()?.func ?? this.decompEntry));
    if (e === null || e === undefined) return toast("Put the cursor in a function first", { kind: "error" });
    const n = name ?? this.functions.nameAt(e) ?? (this.decompFn?.entry?.offset === e ? this.decompFn.name : undefined) ?? this.fnNames.get(e) ?? `0x${e.toString(16)}`;
    this.showView("diff");
    await this.diff.compareWith({ programId: this.programId, entry: e, name: n });
  }

  /** Two functions of this program side by side (the function list's marked pair). */
  async compareFunctions(a: { entry: bigint; name: string }, b: { entry: bigint; name: string }) {
    if (!this.diff || !this.features.has("function-compare")) return toast("This daemon can't compare two functions (feature function-compare)", { kind: "error" });
    this.showView("diff");
    await this.diff.openFunctions({ programId: this.programId, ...a }, { programId: this.programId, ...b });
  }

  /** The function list's context menu: open, compare with…, the marked pair. */
  private functionMenu(row: { entry: bigint; name: string; noReturn?: boolean }, marked: { entry: bigint; name: string }[], x: number, y: number) {
    const can = this.diff !== null && this.features.has("function-compare");
    const others = marked.filter((m) => m.entry !== row.entry);
    const items: MenuItem[] = [
      { label: "Go to", keys: "Enter", testid: "fn-menu-open", run: () => void this.navigate(row.entry, { focus: "listing" }) },
      { label: "Edit function…", keys: this.k("fn-edit"), disabled: !this.features.has("parse-c"), testid: "fn-menu-edit", run: () => void this.editFunctionAt(row.entry) },
      ...(this.bsim && this.features.has("bsim-search")
        ? [{ label: "Find similar functions (BSim)", testid: "fn-menu-bsim", run: () => void this.findSimilar(row.entry) }]
        : []),
      ...(this.features.has("no-return")
        ? [
            row.noReturn
              ? { label: "Clear no return (it returns)", testid: "fn-menu-no-return-clear", run: () => void this.setNoReturn(row.entry, false) }
              : { label: "Set no return (calls to it end there)", testid: "fn-menu-no-return-set", run: () => void this.setNoReturn(row.entry, true) },
          ]
        : []),
      { label: "Compare with…", separator: true, disabled: !can, testid: "fn-menu-compare", run: () => void this.compareFunctionWith(row.entry, row.name) },
    ];
    if (marked.length === 2 && marked.some((m) => m.entry === row.entry))
      items.push({ label: `Compare the marked: ${marked[0].name} (A) with ${marked[1].name} (B)`, disabled: !can, testid: "fn-menu-compare-marked", run: () => void this.compareFunctions(marked[0], marked[1]) });
    else if (others.length)
      items.push({ label: `Compare ${others.at(-1)!.name} (A) with ${row.name} (B)`, disabled: !can, testid: "fn-menu-compare-marked", run: () => void this.compareFunctions(others.at(-1)!, row) });
    const on = marked.some((m) => m.entry === row.entry);
    items.push({ label: on ? "Unmark" : "Mark for comparison", keys: "Ctrl+click", testid: "fn-menu-mark", run: () => this.functions.toggleMark(row.entry, row.name) });
    showMenu(items, x, y, "Function actions");
  }

  /** The program as imported (PatchService.OpenOriginal) against this one, in the Compare view. */
  async compareWithOriginal() {
    if (!this.diff) return toast("This daemon has no Compare (feature diff)", { kind: "error" });
    try {
      toast("Loading the original program…");
      const o = await this.rk.patch.openOriginal({ programId: this.programId, provenance: userProvenance("compare with original") });
      const s = await this.rk.diff.createDiffSession({
        projectId: this.projectId,
        programA: o.programId,
        programB: this.programId,
        name: "original vs patched",
        run: true,
        provenance: userProvenance("compare with original"),
      });
      this.showView("diff");
      if (s.session) await this.diff.openSession(s.session.sessionId);
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  // ------------------------------------------------- equates, references --

  private pdbHost(): PdbHost {
    return {
      rk: this.rk,
      programId: this.programId,
      settle: (rev) => this.live.waitFor(rev),
      recordUndo: (label, seqs) => this.edits.record(label, seqs),
      undo: () => void this.redoOrUndo("undo"),
    };
  }

  private equateHost(): EquateHost {
    return {
      rk: this.rk,
      programId: this.programId,
      edits: this.edits,
      addrWidth: this.addrWidth,
      settle: (rev) => this.live.waitFor(rev),
      undo: () => void this.redoOrUndo("undo"),
      navigate: (addr) => void this.navigate(addr, { focus: "listing" }),
    };
  }

  private referenceHost(): ReferenceHost {
    return {
      ...this.equateHost(),
      resolve: async (text) => {
        const t = text.trim();
        if (!t) return null;
        return parseAddress(t) ?? (await this.findSymbol(t));
      },
    };
  }

  /** The operand (index into row.operands) the listing's selected token is, if any. */
  private selectedOperand(row: ListingRow): number | undefined {
    const hit = this.view.selectedHit;
    if (hit?.kind !== "token" || hit.data.address !== row.address) return undefined;
    return layoutRow(row, this.cols).hot.find((x) => x.kind === "token" && x.col === hit.col)?.op;
  }

  /** A listing row's scalar operands (with their values). */
  private rowScalars(row: ListingRow): ScalarTarget[] {
    if (row.kind !== RowKind.Instruction) return [];
    return row.operands
      .filter((o) => o.kind === TokenKind.Immediate && o.value !== undefined)
      .map((o) => ({ address: row.address, operandIndex: o.operandIndex, value: BigInt.asUintN(64, o.value!), bits: o.bits ?? 0, text: o.text, displayed: !!o.displayOrigin, where: "listing" as const }));
  }

  /**
   * The scalar Convert and Set Equate act on: the decompiler's selected
   * constant, or the listing's selected scalar operand (the row's only
   * scalar when no operand is selected).
   */
  scalarTarget(): ScalarTarget | null {
    if (this.active === "decomp") {
      const t = this.pane.selected?.tok;
      if (!t || t.kind !== CodeTokenKind.CONSTANT || t.value === undefined || !t.address) return null;
      const vn = t.varnodeIndices.length ? this.decompFn?.varnodes[t.varnodeIndices[0]]?.varnode : undefined;
      return { address: t.address.offset, value: t.value, constantHash: t.constantHash, bits: vn ? vn.size * 8 : 0, text: t.text, displayed: t.displaySet, where: "decomp" };
    }
    const row = this.view.selectedRowData();
    if (!row) return null;
    const all = this.rowScalars(row);
    const op = this.selectedOperand(row);
    if (op !== undefined) {
      const o = row.operands[op];
      if (o?.kind !== TokenKind.Immediate || o.value === undefined) return null;
      return all.find((s) => s.operandIndex === o.operandIndex && s.text === o.text) ?? null;
    }
    return all.length === 1 ? all[0] : null;
  }

  /** The scalar at the cursor, or one picked from the row's when it has several. */
  private async pickScalar(): Promise<ScalarTarget | null> {
    const t = this.scalarTarget();
    if (t) return t;
    if (this.active !== "decomp") {
      const row = this.view.selectedRowData();
      const all = row ? this.rowScalars(row) : [];
      if (all.length > 1) return choose("Which scalar?", all.map((s) => ({ label: s.text, detail: s.operandIndex !== undefined ? `operand ${s.operandIndex}` : "", value: s })));
    }
    toast(this.active === "decomp" ? "Select a constant in the decompiler first" : "Select an instruction with a scalar operand (or click the scalar)");
    return null;
  }

  /** E: Set Equate on the scalar at the cursor (listing or decompiler). */
  async setEquate() {
    if (!this.equateEdit) return toast("This daemon has no equates (feature equates)", { kind: "error" });
    const t = await this.pickScalar();
    if (t) await this.equateEdit.setEquate(t);
  }

  /** The cursor's operand for Add reference (unset: the instruction), and the row's operands. */
  private referenceOperand(): { operand: number | undefined; operands: { index: number; text: string }[] } {
    const row = this.view.selectedRowData();
    if (!row || row.kind === RowKind.Header) return { operand: undefined, operands: [] };
    const byIndex = new Map<number, string>();
    for (const o of row.operands) if (o.operandIndex !== undefined) byIndex.set(o.operandIndex, (byIndex.get(o.operandIndex) ?? "") + o.text);
    const operands = [...byIndex].map(([index, text]) => ({ index, text: text.trim() }));
    const op = this.selectedOperand(row);
    const operand = op !== undefined ? row.operands[op]?.operandIndex : operands.length === 1 ? operands[0].index : undefined;
    return { operand, operands };
  }

  /** R: Add reference from the code unit at the cursor. */
  async addReference() {
    if (!this.refEdit) return toast("This daemon has no user references (feature user-references)", { kind: "error" });
    const row = this.view.selectedRowData();
    if (!row || row.kind === RowKind.Header) return toast("Select an instruction in the listing first");
    const o = this.referenceOperand();
    await this.refEdit.add(row.address, o.operand, o.operands);
  }

  /** The Convert submenu, Set equate and Remove equate (feature equates), on a scalar. */
  private equateMenu(all: Map<string, Command>): MenuItem[] {
    const t = this.equateEdit ? this.scalarTarget() : null;
    if (!t) return [];
    const m = (id: string, label?: string) => this.menuItem(all, id, label);
    const convert: MenuItem[] = [
      ...FORMATS.filter((f) => f.id !== "float" || floatable(t)).map((f) => {
        const shown = formatScalar(t.value, t.bits, f.format);
        return { label: shown ? `${f.label}: ${shown}` : f.label, testid: `ctx-conv-${f.id}`, run: () => void this.equateEdit!.convert(t, f.format) };
      }),
      { label: "Default (as disassembled)", testid: "ctx-conv-default", separator: true, disabled: !t.displayed, run: () => void this.equateEdit!.convert(t, null) },
    ];
    return [{ label: "Convert", testid: "ctx-convert", submenu: convert }, m("eq-set", "Set equate…"), m("eq-remove", "Remove equate")].filter((x): x is MenuItem => x !== null);
  }

  /** The References submenu (feature user-references), in the listing. */
  private referenceMenu(all: Map<string, Command>): MenuItem[] {
    if (!this.refEdit || this.location === null) return [];
    const m = (id: string, label?: string) => this.menuItem(all, id, label);
    const sub = [m("ref-add", "Add reference from here…"), m("ref-delete", "Delete a reference from here…"), m("ref-primary", "Set the primary reference…"), m("view-refs", "Show the References window")].filter((x): x is MenuItem => x !== null);
    return sub.length ? [{ label: "References", testid: "ctx-refs", submenu: sub }] : [];
  }

  /** Convert, Set equate, the Equates window; Add, Delete and Set primary references, the References window. */
  private equateReferenceCommands(): Command[] {
    const eq = () => this.equateEdit !== null;
    const scalar = () => (eq() ? this.scalarTarget() : null);
    const rowScalar = () => {
      const r = this.view.selectedRowData();
      return !!r && this.rowScalars(r).length > 0;
    };
    const refs = () => this.refEdit !== null && this.active === "listing" && this.location !== null;
    const here = () => this.view.selectedRowData()?.address ?? this.location!;
    return [
      { id: "eq-set", title: "Set equate (a name or an enum member for the scalar)…", keys: this.k("eq-set"), enabled: () => eq() && (this.active === "decomp" ? scalar() !== null : rowScalar()), run: () => void this.setEquate() },
      { id: "eq-remove", title: "Remove equate (show the scalar as disassembled)", enabled: () => !!scalar()?.displayed, run: () => { const t = scalar(); if (t) void this.equateEdit!.remove(t); } },
      ...FORMATS.map((f) => ({
        id: `conv-${f.id}`,
        title: `Convert scalar to ${f.label.toLowerCase()}`,
        enabled: () => { const t = scalar(); return !!t && (f.id !== "float" || floatable(t)); },
        run: () => { const t = scalar(); if (t) void this.equateEdit!.convert(t, f.format); },
      })),
      { id: "conv-default", title: "Convert scalar back to its default display", enabled: () => !!scalar()?.displayed, run: () => { const t = scalar(); if (t) void this.equateEdit!.convert(t, null); } },
      { id: "ref-add", title: "Add reference from here…", keys: this.k("ref-add"), enabled: refs, run: () => void this.addReference() },
      { id: "ref-delete", title: "Delete a reference from here…", enabled: refs, run: () => void this.refEdit!.pick(here(), "delete") },
      { id: "ref-primary", title: "Set the primary reference from here…", enabled: refs, run: () => void this.refEdit!.pick(here(), "primary") },
    ];
  }

  /** Shows a view and focuses it. */
  showView(id: string) {
    this.dock.show(id);
    switch (id) {
      case "listing":
        this.view.canvas.focus();
        break;
      case "decomp":
        this.pane.focus();
        break;
      case "graph":
        this.graph.canvas.focus({ preventScroll: true });
        break;
      case "calls":
        this.calls.focus();
        break;
      case "strings":
        this.data.focusFilter();
        break;
      case "types":
        this.types.focusFilter();
        break;
      case "memory":
        this.memmap.focus();
        break;
      case "diff":
        this.diff?.focus();
        break;
      case "diffgraph":
        this.diffGraph?.el.querySelector<HTMLCanvasElement>("canvas")?.focus({ preventScroll: true });
        break;
      case "searchresults":
        this.search?.results.focus();
        break;
      case "equates":
        this.equates?.focus();
        break;
      case "classes":
        this.classes?.focus();
        break;
      case "fid":
        this.fid?.focus();
        break;
      case "bsim":
        this.bsim?.focus();
        break;
      case "bytes":
        this.bytes?.focus();
        break;
    }
  }

  /** Space: the listing or the graph, whichever isn't shown (in the same place). */
  private toggleGraph() {
    // Side by side (in different groups), Space moves the focus between them.
    const together = this.dock.groupOf("graph") === this.dock.groupOf("listing");
    if (!together) this.showView(this.active === "graph" ? "listing" : "graph");
    else if (this.dock.isVisible("graph")) this.showView("listing");
    else this.showView("graph");
  }

  /** The selection moved (listing, decompiler): the graph and the calls follow. */
  private syncViews(addr: bigint, row?: ListingRow) {
    const fn = row?.func ?? null;
    if (this.dock.isVisible("graph")) {
      if (fn === null) {
        if (row && row.kind !== RowKind.Header) this.graph.clear(`0x${hex(addr)} is not in a function.`);
      } else if (fn !== this.graph.entry) void this.graph.load(fn).then(() => this.graph.select(this.location));
      else this.graph.select(addr);
    } else if (fn !== null && fn === this.graph.entry) this.graph.select(addr, false);
    if (this.dock.isVisible("calls") && fn !== null) void this.calls.setRoot(fn, this.fnName(fn) ?? hex(fn));
  }

  /** An instruction was picked in the graph: select it in the listing (and so the decompiler). */
  private async selectFrom(_from: "graph", addr: bigint) {
    const row = await this.view.goTo(addr, { align: "center" });
    if (row < 0) return;
  }

  private wantPluginFacts() {
    if (!this.plugins?.analyzers.length) return;
    const first = Math.floor(this.view.topRow);
    let lo: bigint | null = null, hi: bigint | null = null;
    for (let i = first; i <= first + this.view.viewportRows; i++) {
      const r = this.cache.get(i);
      if (!r) continue;
      const a = r.func !== null && r.func < r.address ? r.func : r.address;
      if (lo === null || a < lo) lo = a;
      const end = r.address + BigInt(Math.max(1, r.length)) - 1n;
      if (hi === null || end > hi) hi = end;
    }
    if (lo !== null && hi !== null) this.plugins.want(lo, hi);
  }

  /** Retypes the selection to a named type, or a pointer to it. */
  async applyType(def: TypeDefinition, pointer: boolean) {
    const spec = this.retypeSpec();
    if (!spec) return toast("Select a variable, parameter, global or function (in the listing or the decompiler) first");
    if (spec.prototype) return this.applyReturnType(spec, def, pointer);
    try {
      const spelled = `${def.display}${pointer ? " *" : ""}`;
      const r = await this.retypeByHash(spec.target, spelled, `Set type of ${spec.what} to ${spelled}`);
      if (!r) return toast(`Can't spell ${spelled}`, { kind: "error" });
      toast(`${spec.what}: ${spelled}`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
      await this.live.waitFor(r);
    } catch (e) {
      toast(`Apply type failed: ${errText(e)}`, { kind: "error" });
    }
  }

  /** A function selected: the type becomes its return type (the rest of its prototype as the decompiler has it). */
  private async applyReturnType(spec: RetypeSpec, def: TypeDefinition, pointer: boolean) {
    const entry = spec.key.address;
    try {
      const fn = this.decompFn?.entry?.offset === entry ? this.decompFn : (await this.rk.queries.decompile({ programId: this.programId, function: { offset: entry } })).function;
      const proto = fn?.prototype;
      if (!fn || !proto) return toast("No prototype to change: the function doesn't decompile", { kind: "error" });
      const params = proto.parameterIndices.map((i) => fn.variables[i]).map((v) => `${v?.type?.display ?? "undefined8"} ${v?.name ?? ""}`.trim());
      if (proto.varargs) params.push("...");
      const ret = `${def.display}${pointer ? " *" : ""}`;
      const decl = `${ret} ${fn.name}(${params.length ? params.join(", ") : "void"})`;
      if (this.features.has("parse-c")) {
        const r = await this.parseRetype(decl, true);
        if ("error" in r) return toast(`Can't define ${decl}: ${r.error}`, { kind: "error" });
        const res = await this.edits.bodies(`Set return type of ${fn.name} to ${ret}`, [...r.bodies, Edits.retypeHashBody(spec.target, r.hash)]);
        toast(`${fn.name} returns ${ret}`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
        await this.live.waitFor(res.revision);
        return;
      }
      const p = await spellPrototype(decl, this.typeContext());
      const bodies = p.nodes.map(Edits.defineTypeBody);
      const hash = (await this.edits.validate(bodies))[p.index]?.sub;
      if (!hash) return toast(`Can't define ${decl}`, { kind: "error" });
      const r = await this.edits.bodies(`Set return type of ${fn.name} to ${ret}`, [...bodies, Edits.retypeHashBody(spec.target, hash)]);
      toast(`${fn.name} returns ${ret}`, { action: { label: "Undo", run: () => void this.redoOrUndo("undo") } });
      await this.live.waitFor(r.revision);
    } catch (e) {
      toast(`Set return type failed: ${errText(e)}`, { kind: "error" });
    }
  }

  /**
   * Retypes to a spelled type by hash (DefineType for any pointer or array
   * around it, in the same request). Resolves to the revision, or null when
   * the spelling names no type of the program.
   */
  private async retypeByHash(target: RenameTarget, spelling: string, label: string): Promise<bigint | null> {
    if (this.features.has("parse-c")) {
      const r = await this.parseRetype(spelling, false);
      if ("error" in r) return null;
      return (await this.edits.bodies(label, [...r.bodies, Edits.retypeHashBody(target, r.hash)])).revision;
    }
    const s = await spell(spelling, this.typeContext()).catch(() => null);
    if (!s) return null;
    let hash: string;
    const bodies = s.nodes.map(Edits.defineTypeBody);
    if ("hash" in s.ref) hash = s.ref.hash;
    else {
      const keys = await this.edits.validate(bodies);
      hash = keys[s.ref.index]?.sub ?? "";
      if (!hash) return null;
    }
    const r = await this.edits.bodies(label, [...bodies, Edits.retypeHashBody(target, hash)]);
    return r.revision;
  }

  private typeContext() {
    const lang = this.summary.language;
    return {
      pointerSize: lang?.pointerSize || 8,
      charSigned: /^(x86|8086)/i.test(lang?.processor || lang?.languageId || "x86"),
      named: async (kind: "struct" | "union" | "enum" | "", name: string) => {
        const r = await this.rk.queries.findTypes({ programId: this.programId, nameContains: name, page: { pageSize: 100 } });
        const want = kind === "struct" ? 9 : kind === "union" ? 10 : kind === "enum" ? 11 : 0;
        const exact = r.types.filter((t) => t.name === name && !t.superseded && (!want || t.kind === want)).sort((x, y) => Number(x.origin?.source.case === "derived") - Number(y.origin?.source.case === "derived"));
        return exact.find((t) => t.kind === 13 && t.origin?.source.case !== "derived") ?? exact[0] ?? null;
      },
    };
  }

  /** The listing's selection as addresses [first, last], when it spans more than one row. */
  /** The listing's selection as address ranges: the range selection made
   * from search results, else the rows selected; empty when there is none. */
  private selectionRanges(): [bigint, bigint][] {
    if (this.view.rangeSelection?.length) return this.view.rangeSelection;
    const r = this.selectedRange();
    return r ? [r] : [];
  }

  /** A decompiled-code search result: the function in the decompiler, at the line, the match marked. */
  private async openDecompiledLine(entry: bigint, line: number, from: number, to: number, address: bigint | null) {
    await this.navigate(address ?? entry);
    if (this.decompLoading) await this.decompLoading;
    if (this.decompFn?.entry?.offset !== entry) await this.loadDecompile(entry);
    if (this.decompFn?.entry?.offset !== entry) return;
    this.dock.show("decomp");
    this.pane.revealLine(line, from, to);
  }

  /** The toolbar's Search menu (feature search). */
  private searchMenuItems(): MenuItem[] {
    const s = this.search!;
    const open = (k: SearchKind) => () => s.open(k);
    return [
      { label: "Memory…", keys: this.k("search-memory"), testid: "menu-search-memory", run: open("memory") },
      { label: "Program text…", keys: this.k("search-text"), testid: "menu-search-text", run: open("text") },
      { label: "Scalars…", keys: this.k("search-scalars"), testid: "menu-search-scalars", run: open("scalars") },
      { label: "Decompiled code…", testid: "menu-search-decompiled", run: open("decompiled") },
      { label: "Repeat search", keys: this.k("search-next"), separator: true, disabled: s.last === null, testid: "menu-search-next", run: () => void s.repeat(false) },
      { label: "Repeat search backward", keys: this.k("search-prev"), disabled: s.last === null, testid: "menu-search-prev", run: () => void s.repeat(true) },
      { label: "Show search results", testid: "menu-search-results", run: () => this.showView("searchresults") },
    ];
  }

  private selectedRange(): [bigint, bigint] | null {
    const [lo, hi] = this.view.selectionRange();
    if (lo < 0 || hi <= lo) return null;
    const a = this.cache.get(lo), b = this.cache.get(hi);
    if (!a || !b) return null;
    return [a.address, b.address + BigInt(Math.max(1, b.length) - 1)];
  }

  /** Runs a command plugin with arguments asked for; its edits are undoable here. */
  private async runPlugin(name: string) {
    const p = this.plugins.commands.find((x) => x.name === name);
    if (!p) return toast(`No command plugin ${name}`, { kind: "error" });
    const args = await askFields(
      `Run ${p.name}@${p.version}${p.description ? ` — ${p.description}` : ""}`,
      p.args.map((a) => ({ name: a.name, label: a.name, placeholder: a.description, required: a.required })),
    );
    if (args === null) return;
    try {
      const r = await this.rk.plugins.runCommand({ programId: this.programId, plugin: p.name, args, provenance: userProvenance(`palette: ${p.name}`) });
      const n = r.assertions.length;
      if (!n) return toast(`${p.name}: no edits${r.log.length ? ` (${r.log.at(-1)})` : ""}`);
      this.edits.record(`${p.name} (${n} edit${n === 1 ? "" : "s"})`, r.assertions.map((a) => a.seq));
      this.lastPluginRun = r.assertions;
      toast(`${p.name} made ${n} edit${n === 1 ? "" : "s"} as plugin:${p.name}@${p.version}`, {
        action: { label: "Show", run: () => void this.showPluginEdits() },
        ms: 8000,
      });
      await this.live.waitFor(r.snapshot?.revision ?? 0n);
    } catch (e) {
      toast(`${p.name} failed: ${errText(e)}`, { kind: "error" });
    }
  }

  private lastPluginRun: import("@revkit/api").Assertion[] = [];

  /** The last plugin command's edits; picking one goes there. */
  private async showPluginEdits() {
    const items = this.lastPluginRun;
    if (!items.length) return toast("No plugin edits yet");
    const describe = (a: import("@revkit/api").Assertion) => {
      const b = a.body?.kind;
      switch (b?.case) {
        case "rename":
          return `rename → ${b.value.name}`;
        case "comment":
          return `comment: ${b.value.text}`;
        case "functionBounds":
          return "function entry";
        case "note":
          return `note ${b.value.tag}: ${b.value.text}`;
        default:
          return b?.case ?? "edit";
      }
    };
    const addr = await choose(
      `Edits by ${provText(items[0].provenance)} · Ctrl+Z undoes them`,
      items.map((a) => ({ label: describe(a), detail: hex(a.key?.address?.offset ?? 0n, this.addrWidth), value: a.key?.address?.offset ?? 0n })),
    );
    if (addr !== null) await this.navigate(addr);
  }

  // ------------------------------------------------------------- commands --

  /** The program moved by `delta` (Set image base): the cursor and the
   * back/forward history move with it. */
  private moveBase(delta: bigint) {
    const mask = (1n << 64n) - 1n;
    const move = (a: bigint) => (a + delta) & mask;
    this.back = this.back.map(move);
    this.fwd = this.fwd.map(move);
    if (this.location !== null) {
      const from = this.location;
      const to = move(from);
      // Once the views have the moved program: the cursor where it was in it.
      setTimeout(() => {
        void this.navigate(to).then(() => {
          if (this.back[this.back.length - 1] === from) this.back.pop();
        });
      }, 0);
    }
  }

  /** The names setting changed (names.ts): the listing, the function list
   * and the decompiler draw their names again. */
  private async renameShown() {
    this.pane.rerender();
    void this.functions.load(true);
    this.cache.clear();
    const first = await this.source.rows(0, this.cache.pageSize);
    this.cache.rowCount = first.totalRows;
    this.cache.insert(first.startRow, first.rows, first.revision, first.totalRows);
    if (this.location !== null) await this.view.goTo(this.location, { align: "third" });
    toast(`Names: ${NAME_FORMS.find((n) => n.form === nameForm())?.label ?? nameForm()}`);
  }

  /** Switches between header rows and labels in a column (one numbering
   * or the other; the cache starts over at the current address). */
  private async setHeaderRows(on: boolean) {
    if (on && !this.features.has("listing-header-rows")) return toast("This daemon has no header rows (feature listing-header-rows)");
    this.headerRows = on;
    prefs.set("rk.headers", on ? "1" : "0");
    this.source.headerRows = on;
    this.cols = makeColumns(this.addrWidth, this.cols.showBytes, on, this.fields);
    this.view.setColumns(this.cols);
    this.paintColumnHeader();
    this.cache.clear();
    const first = await this.source.rows(0, this.cache.pageSize);
    this.cache.rowCount = first.totalRows;
    this.cache.insert(first.startRow, first.rows, first.revision, first.totalRows);
    if (this.location !== null) await this.view.goTo(this.location, { align: "third" });
  }

  private toggleBytes() {
    this.bytesPref = !this.cols.showBytes;
    this.cols = makeColumns(this.addrWidth, this.bytesPref, this.headerRows, this.fields);
    prefs.set("rk.bytes", this.cols.showBytes ? "1" : "0");
    this.view.setColumns(this.cols);
    this.paintColumnHeader();
  }

  /**
   * A listing too narrow for the mnemonic and the start of the operands
   * next to the bytes (a narrow window, a wide side) hides the bytes column
   * until it is wide again; Shift+B still shows them. The preference
   * (rk.bytes) is unchanged.
   */
  private fitListingColumns() {
    const w = this.view.canvas.clientWidth;
    if (!w) return;
    // The optional fields are a choice, not counted: only the base layout's room.
    const withBytes = makeColumns(this.addrWidth, true, this.headerRows);
    const narrow = w < PAD_X + (withBytes.ops + 12) * this.view.charWidth;
    if (narrow === this.narrowListing) return;
    this.narrowListing = narrow;
    const want = this.bytesPref && !narrow;
    if (want === this.cols.showBytes) return;
    this.cols = makeColumns(this.addrWidth, want, this.headerRows, this.fields);
    this.view.setColumns(this.cols);
    this.paintColumnHeader();
  }

  private toggleTheme() {
    this.dark = !this.dark;
    document.documentElement.dataset.theme = this.dark ? "dark" : "light";
    this.view.setTheme(this.dark ? DARK : LIGHT);
    if (this.overview) {
      this.overview.dark = this.dark;
      this.overview.draw();
    }
    this.graph.setTheme(this.dark ? DARK : LIGHT);
    this.diff?.graph.setTheme(this.dark ? DARK : LIGHT);
    this.diffGraph?.setTheme(this.dark ? DARK : LIGHT);
    prefs.set("rk.theme", this.dark ? "dark" : "light");
  }

  private async changeUser() {
    const v = await ask({ title: "Your name, recorded as user:<name> on every edit", value: userName(), validate: (s) => (/^[\w.@-]+$/.test(s.trim()) ? null : "Letters, digits, . @ _ - only") });
    if (v === null) return;
    setUserName(v.trim());
    $("user").textContent = `user:${userName()}`;
  }

  /** The toolbar's File menu. */
  private fileItems(): MenuItem[] {
    const archives = this.features.has(PROJECT_ARCHIVE_FEATURE);
    const why = archives ? undefined : true;
    return [
      { label: "Open program…", keys: "Ctrl+O", testid: "file-open", run: () => this.openProgram() },
      { label: "Preferences…", testid: "file-preferences", run: () => this.showPreferences() },
      { label: "Open file system…", disabled: this.features.has(FILESYSTEMS_FEATURE) ? undefined : true, testid: "file-open-filesystem", run: () => void this.openFileSystem() },
      { label: "Import project…", separator: true, disabled: why, testid: "file-import-project", run: () => void this.importProject() },
      { label: "Export project…", disabled: why, testid: "file-export-project", run: () => void this.exportProject() },
    ];
  }

  /** File → Open file system…: a container from this computer, the daemon host or this program (filesystem.ts). */
  private async openFileSystem() {
    await openFileSystemDialog({
      rk: this.rk,
      projectId: this.projectId || this.programId.split("/")[0],
      features: this.features,
      currentProgram: this.programId ? { programId: this.programId, name: $("program").textContent ?? this.programId } : undefined,
      pauseStreams: () => this.live.pause(),
      onOpenProgram: (id) => {
        const u = new URL(location.href);
        u.searchParams.set("program", id);
        u.hash = "";
        location.href = u.toString();
      },
    });
  }

  /** File → Export project…: the project, or this program (archive.ts). */
  private async exportProject() {
    await exportProjectDialog(this.rk, {
      projectId: this.projectId || this.programId.split("/")[0],
      programs: this.programId ? [{ programId: this.programId, name: $("program").textContent ?? this.programId }] : [],
    });
  }

  /** File → Import project…: into a new project or this one; opens the first program imported. */
  private async importProject() {
    await importProjectDialog(this.rk, {
      projectId: this.projectId || this.programId.split("/")[0],
      pauseStreams: () => this.live.pause(),
      onImported: (_project, first) => {
        if (!first) return;
        const u = new URL(location.href);
        u.searchParams.set("program", first);
        u.hash = "";
        location.href = u.toString();
      },
    });
  }

  /** The context row: the project, the program's folder, the program (the name is set by start and renames). */
  private paintContext(folderPath: string) {
    const pid = this.projectId || this.programId.split("/")[0];
    $("project-name").textContent = pid;
    const folder = $("folder-crumb");
    const parts = folderPath.split("/").filter(Boolean);
    folder.hidden = !parts.length;
    folder.replaceChildren(...parts.flatMap((p) => [h("span", { class: "ctx-folder-name" }, p), h("span", { class: "ctx-sep", "aria-hidden": "true" }, "/")]));
    // The project's display name, when it differs from its id.
    void this.rk.projects.listProjects({}).then(({ projects }) => {
      const p = projects.find((x) => x.projectId === pid);
      if (p?.name) $("project-name").textContent = p.name;
      $("project-crumb").title = `Project ${p?.name ?? pid}${p ? ` · ${p.programCount} program${p.programCount === 1 ? "" : "s"}` : ""}: switch or create one`;
    }).catch(() => {});
  }

  /** A menu of palette commands by id ("-" starts a group); those this daemon lacks are left out. */
  private commandMenu(ids: string[]): MenuItem[] {
    const byId = new Map(this.commands().map((c) => [c.id, c]));
    const items: MenuItem[] = [];
    let sep = false;
    for (const id of ids) {
      if (id === "-") {
        sep = items.length > 0;
        continue;
      }
      const c = byId.get(id);
      if (!c) continue;
      const on = c.enabled ? c.enabled() : true;
      items.push({ label: menuLabel(c.title), keys: c.keys, disabled: !on || undefined, separator: sep || undefined, testid: `menu-cmd-${id}`, title: c.detail, run: () => void c.run() });
      sep = false;
    }
    return items;
  }

  /** View: each view (shown or reopened), then the layout and the theme. */
  private viewMenuItems(): MenuItem[] {
    const views = this.dock.viewList();
    return [
      ...views.map((v) => ({ label: v.title, keys: this.k(`view-${v.id}`), checked: v.visible, testid: `menu-view-${v.id}`, run: () => this.showView(v.id) })),
      ...this.commandMenu(["-", "toggle-decomp", "toggle-graph", "layout-reset", "-", "strings", "defined-data", "-", "theme", "preferences", "shortcuts"]),
    ];
  }

  /** Where the program's import thunks go (feature program-libraries): the functions list shows it. */
  private async loadImports() {
    try {
      this.imports = await importMap(this.rk, this.programId);
    } catch {
      return;
    }
    const shown = new Map<bigint, string>();
    for (const [entry, i] of this.imports) if (i.resolved || i.library) shown.set(entry, importTarget(i));
    this.functions.setExternals(shown);
  }

  /** The import thunk at (or containing) the location, if it is one. */
  private importHere(entry?: bigint | null): ResolvedImport | undefined {
    const at = entry ?? this.locFunc ?? this.location;
    return at === null ? undefined : this.imports.get(at);
  }

  /** Go to library function: the library program, at the function the import resolves to. */
  private followImport(entry?: bigint | null) {
    const i = this.importHere(entry);
    if (!i) return toast("Not an import thunk here", { kind: "error" });
    if (!i.resolved) return toast(`${i.name}: ${i.library ? `${i.library} is not in the project` : "no library program exports it"} (Analyze → Libraries…)`, { kind: "error" });
    this.openProgramAt(i.programId, i.address?.offset);
  }

  /** Opens another program of the project, at an address. */
  openProgramAt(programId: string, address?: bigint) {
    const u = new URL(location.href);
    u.searchParams.set("program", programId);
    u.hash = address !== undefined ? `#${address.toString(16)}` : "";
    location.href = u.toString();
  }

  private showLanguage() {
    void showLanguageDialog(this.rk, {
      programId: this.programId,
      programName: $("program").textContent ?? this.programId,
      recordUndo: (label, seqs) => this.edits.record(label, seqs),
      undo: () => void this.redoOrUndo("undo"),
      settle: (rev) => this.live.waitFor(rev),
    });
  }

  private showLibraries() {
    showLibrariesDialog(this.rk, {
      programId: this.programId,
      programName: $("program").textContent ?? this.programId,
      openProgram: (id, address) => this.openProgramAt(id, address),
      importLibraries: () => this.openProgram(false, true),
    });
  }

  openProgram(focusProjects = false, startImport = false) {
    showOpenDialog(this.rk, {
      current: this.programId,
      features: this.features,
      focusProjects,
      startImport,
      pauseStreams: () => this.live.pause(),
      onOpen: (id, address) => this.openProgramAt(id, address),
    });
  }

  /** The right-click menu of the listing or the decompiler: the palette's
   *  commands that act on what is selected there, in groups, with their keys. */
  // ------------------------------------------------------------ slices --

  /** Highlight ▸ Def-use and the slices (feature decompile-slices), on the decompiler's token. */
  private sliceCommands(): Command[] {
    const on = () => this.features.has("decompile-slices") && this.active === "decomp" && this.pane.selected !== null;
    const has = () => this.pane.slice !== null;
    const kinds: [string, SliceKind, string][] = [
      ["slice-def-use", SliceKind.DEF_USE, "Highlight def-use (the value's definition and uses)"],
      ["slice-forward", SliceKind.FORWARD, "Highlight forward slice (every value computed from it)"],
      ["slice-backward", SliceKind.BACKWARD, "Highlight backward slice (every value it is computed from)"],
      ["slice-forward-ops", SliceKind.FORWARD_OPS, "Highlight forward operator slice (the operations; marks the listing's instructions)"],
      ["slice-backward-ops", SliceKind.BACKWARD_OPS, "Highlight backward operator slice (the operations; marks the listing's instructions)"],
    ];
    return [
      ...kinds.map(([id, kind, title]) => ({ id, title, keys: this.k(id), enabled: on, run: () => void this.slice(kind) })),
      { id: "slice-next", title: "Highlight: next highlighted token", keys: this.k("slice-next"), enabled: has, run: () => void this.pane.sliceStep(1) },
      { id: "slice-prev", title: "Highlight: previous highlighted token", keys: this.k("slice-prev"), enabled: has, run: () => void this.pane.sliceStep(-1) },
      { id: "slice-clear", title: "Highlight: clear", keys: "Esc", enabled: has, run: () => this.pane.clearSlice() },
    ];
  }

  /** Asks the daemon for a slice from the selected token and highlights it here and in the listing. */
  private async slice(kind: SliceKind) {
    const fn = this.pane.fn;
    const sel = this.pane.selected;
    const pos = sel ? this.pane.tokenPosition(sel) : null;
    if (!fn?.entry || !pos) return void toast("Click a variable, constant or operator in the decompiler first");
    const what = kind === SliceKind.DEF_USE ? "Def-use" : kind === SliceKind.FORWARD ? "Forward slice" : kind === SliceKind.BACKWARD ? "Backward slice" : kind === SliceKind.FORWARD_OPS ? "Forward operator slice" : "Backward operator slice";
    try {
      const r = await this.rk.queries.sliceDecompiled({ programId: this.programId, function: { offset: fn.entry.offset }, kind, from: { case: "token", value: pos } });
      if (this.pane.fn !== fn) return; // decompiled again meanwhile
      const label = `${what} of ${r.start}`;
      this.pane.setSlice(r.tokens, label);
      this.view.sliceMarks = new Set(r.addresses.map((a) => a.offset));
      this.view.invalidate();
      const keys = this.k("slice-next");
      toast(`${label}: ${r.tokens.length} token${r.tokens.length === 1 ? "" : "s"}, ${r.addresses.length} instruction${r.addresses.length === 1 ? "" : "s"}${keys ? ` · ${keys} next` : ""} · Esc clears`);
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  private contextMenu(where: "listing" | "decomp", x: number, y: number) {
    this.prov.hover(null, 0, 0);
    this.active = where;
    const all = new Map(this.commands().map((c) => [c.id, c]));
    if (where === "listing") return this.listingContextMenu(all, x, y);
    // The decompiler's.
    const groups: (string[] | MenuItem[])[] = [
      ["decomp-copy", "decomp-copy-all"],
      ["follow", "xrefs", "goto"],
      // On a struct field: its own Rename and Retype (the struct's next version).
      this.selectedField() ? ["rename-field", "retype-field", "comment", "comment-plate", "note"] : ["rename", "retype", "comment", "comment-plate", "note"],
      ["find-uses-field", "find-uses-type"],
      this.sliceMenu(all),
      ["callsig-override", "callsig-edit", "callsig-remove"],
      ["auto-struct", "auto-fill"],
      this.equateMenu(all),
      ["emulate", "emu-break", "dbg-watch"],
      ["fn-edit", "no-return-set", "no-return-clear", "fn-compare", "bsim-similar"],
      ["prov", "toggle-graph"],
      ["undo", "redo"],
    ];
    const items: MenuItem[] = [];
    let sep = false;
    for (const group of groups) {
      const entries = group.map((g) => (typeof g === "string" ? this.menuItem(all, g) : g)).filter((m): m is MenuItem => m !== null);
      if (!entries.length) continue;
      for (const [i, m] of entries.entries()) items.push({ ...m, separator: sep && i === 0 });
      sep = true;
    }
    // Scripts that apply here (@context function, selection, address).
    for (const [i, it] of (this.scripts?.contextItems() ?? []).entries()) items.push({ ...it, separator: sep && i === 0 });
    showMenu(items, x, y, "Decompiler actions");
  }

  /**
   * The listing's right-click menu, grouped as Ghidra's: the most used
   * actions at the top (Follow, References to, Go to, Rename, Set type,
   * Set comment; Disassemble and Clear), the rest in submenus (Comments,
   * Data, Function, References, Convert, Patch, Copy, Debugger), then
   * provenance, the graph and undo. A submenu with nothing that applies is
   * left out.
   */
  private listingContextMenu(all: Map<string, Command>, x: number, y: number) {
    const m = (id: string, label?: string) => this.menuItem(all, id, label);
    const present = (xs: (MenuItem | null)[]) => xs.filter((i): i is MenuItem => i !== null);
    const sub = (label: string, testid: string, items: (MenuItem | null)[]): MenuItem | null => {
      const list = present(items);
      return list.length ? { label, testid, submenu: list } : null;
    };
    const edit = this.listingEditMenu(all);
    const editItem = (testid: string) => edit.find((i) => i.testid === testid) ?? null;
    const dataSub = editItem("ctx-le-data")?.submenu ?? [];
    const recent = editItem("ctx-le-recent");
    const top = edit.filter((i) => ["ctx-le-disasm", "ctx-le-disasm-fn", "ctx-le-disasm-arm", "ctx-le-disasm-thumb", "ctx-le-clear"].includes(i.testid ?? ""));
    const expand = edit.filter((i) => ["ctx-le-expand", "ctx-le-collapse"].includes(i.testid ?? ""));
    const refs = this.referenceMenu(all)[0]?.submenu ?? [];
    const groups: (MenuItem | null)[][] = [
      [m("follow"), m("xrefs"), m("goto")],
      [m("rename"), m("retype"), m("comment")],
      [
        sub("Comments", "ctx-comments", [m("comment-plate"), m("comment-pre"), m("comment-post"), m("comment-eol"), m("note")]),
        ...top,
        sub("Data", "ctx-data", [...dataSub, ...(recent ? [{ ...recent, separator: true }] : []), ...expand, m("struct-from-selection", "Create structure from selection…")]),
        sub("Function", "ctx-function", [m("fn-edit"), m("no-return-set"), m("no-return-clear"), m("fn-create"), m("fn-remove"), m("flow"), m("callsig-override"), m("callsig-edit"), m("callsig-remove"), m("fn-compare"), m("bsim-similar")]),
        sub("References", "ctx-refs", refs),
        ...this.equateMenu(all),
        sub("Patch", "ctx-patch", [m("patch-insn"), m("patch-bytes"), m("patch-revert-here")]),
        sub("Copy", "ctx-copy", [m("copy-rows", "Copy rows"), m("copy-special")]),
        sub("Debugger", "ctx-debugger", [m("emulate"), m("emu-break"), m("dbg-bp-edit", "Breakpoint condition…"), m("dbg-watch", "Add watch…"), m("dbg-disasm", "Disassemble runtime memory…"), m("dbg-copy", "Copy runtime memory into the program…")]),
      ],
      [m("prov"), m("toggle-graph")],
      [m("undo"), m("redo")],
    ];
    const items: MenuItem[] = [];
    let sep = false;
    for (const group of groups) {
      const entries = present(group);
      if (!entries.length) continue;
      for (const [i, it] of entries.entries()) items.push({ ...it, separator: sep && i === 0 });
      sep = true;
    }
    // Scripts that apply here (@context function, selection, address).
    for (const [i, it] of (this.scripts?.contextItems() ?? []).entries()) items.push({ ...it, separator: sep && i === 0 });
    showMenu(items, x, y, "Listing actions");
  }

  private copyToClipboard(text: string, done: string) {
    if (!text) return;
    void navigator.clipboard.writeText(text).then(
      () => toast(done),
      () => toast("Can't reach the clipboard; select the text and press Ctrl+C", { kind: "error" }),
    );
  }

  /** The decompiler's Highlight ▸ (def-use and the slices), as Ghidra's. */
  private sliceMenu(all: Map<string, Command>): MenuItem[] {
    const m = (id: string, label: string) => this.menuItem(all, id, label);
    const items = [
      m("slice-def-use", "Def-use"),
      m("slice-forward", "Forward slice"),
      m("slice-backward", "Backward slice"),
      m("slice-forward-ops", "Forward operator slice"),
      m("slice-backward-ops", "Backward operator slice"),
      m("slice-clear", "Clear"),
    ].filter((x): x is MenuItem => x !== null);
    return items.length ? [{ label: "Highlight", testid: "ctx-highlight", submenu: items }] : [];
  }

  /** A command as a menu item (null when it doesn't apply now). */
  private menuItem(all: Map<string, Command>, id: string, label?: string): MenuItem | null {
    const c = all.get(id);
    if (!c || !(c.enabled?.() ?? true)) return null;
    // A menu is read in context: the palette's explanation in parentheses
    // ("Rename (function, label, variable, field)") becomes the tooltip.
    const short = label ?? c.title.replace(/ \([^)]*\)/, "");
    return { label: short, title: short !== c.title ? c.title : undefined, keys: c.keys, testid: `ctx-${c.id}`, run: () => void c.run() };
  }

  /**
   * The listing-edit group (feature listing-edit): Disassemble (as ARM or
   * Thumb where both exist, with a function), Clear, the Data submenu
   * (types, strings, array, choose type, mutability), the recently used
   * definitions, and expand or collapse on a data item with fields.
   */
  private listingEditMenu(all: Map<string, Command>): MenuItem[] {
    if (!this.features.has("listing-edit") || this.location === null) return [];
    const m = (id: string, label?: string) => this.menuItem(all, id, label);
    const data: MenuItem[] = [
      m("le-cycle", "Cycle byte, word, dword, qword"),
      ...DATA_KINDS.map((k) => m(`le-data-${k.id}`, k.label)),
      m("le-array", "Array…"),
      m("le-type", "Choose type…"),
      ...MUTABILITY_CHOICES.map((c, i) => {
        const it = m(`le-mut-${c.id}`, c.label);
        return it && i === 0 ? { ...it, separator: true } : it;
      }),
    ].filter((x): x is MenuItem => x !== null);
    const recent = this.listingEdit.recent().map((d, i) => m(`le-recent-${i}`, d.label)).filter((x): x is MenuItem => x !== null);
    return [
      m("le-disasm"),
      m("le-disasm-fn"),
      m("le-disasm-arm"),
      m("le-disasm-thumb"),
      m("le-clear"),
      { label: "Data", testid: "ctx-le-data", submenu: data },
      recent.length ? { label: "Recently used", testid: "ctx-le-recent", submenu: recent } : null,
      m("le-expand", "Expand fields or elements"),
      m("le-collapse", "Collapse"),
    ].filter((x): x is MenuItem => x !== null);
  }

  /** Clear, Disassemble here, the Data menu and mutability (feature listing-edit). */
  private listingEditCommands(): Command[] {
    const le = this.listingEdit;
    const on = () => this.features.has("listing-edit") && this.location !== null;
    const item = () => (on() ? le.expandable() : null);
    return [
      { id: "le-disasm", title: "Disassemble here", keys: this.k("le-disasm"), enabled: on, run: () => void le.disassemble() },
      { id: "le-disasm-fn", title: "Disassemble and create function", enabled: on, run: () => void le.disassemble(InstructionSet.UNSPECIFIED, true) },
      { id: "le-disasm-arm", title: "Disassemble as ARM", enabled: () => on() && this.armThumb(), run: () => void le.disassemble(InstructionSet.ARM) },
      { id: "le-disasm-thumb", title: "Disassemble as Thumb", enabled: () => on() && this.armThumb(), run: () => void le.disassemble(InstructionSet.THUMB) },
      { id: "le-clear", title: "Clear code bytes (the selection)", keys: this.k("le-clear"), enabled: on, run: () => void le.clear() },
      { id: "le-cycle", title: "Data: cycle byte, word, dword, qword", keys: this.k("le-cycle"), enabled: on, run: () => void le.cycle() },
      ...DATA_KINDS.map((k) => ({ id: `le-data-${k.id}`, title: `Data: ${k.label}`, keys: this.k(`le-data-${k.id}`), enabled: on, run: () => void le.defineKind(k.id) })),
      { id: "le-array", title: "Data: array…", keys: this.k("le-array"), enabled: on, run: () => void le.array() },
      { id: "le-type", title: "Data: choose type…", keys: this.k("le-type"), enabled: on, run: () => void le.chooseType() },
      ...MUTABILITY_CHOICES.map((c) => ({ id: `le-mut-${c.id}`, title: `Data: ${c.label.charAt(0).toLowerCase()}${c.label.slice(1)}`, enabled: on, run: () => void le.mutability(c.m) })),
      ...le.recent().map((d, i) => ({ id: `le-recent-${i}`, title: `Data: recently used: ${d.label}`, enabled: on, run: () => void le.defineRecent(d) })),
      { id: "le-expand", title: "Data: expand the item's fields or elements", keys: this.k("le-expand"), enabled: () => !!item()?.dataCollapsed, run: () => void le.toggle(undefined, true) },
      { id: "le-collapse", title: "Data: collapse the item", keys: this.k("le-collapse"), enabled: () => { const it = item(); return !!it && !it.dataCollapsed; }, run: () => void le.toggle(undefined, false) },
    ];
  }

  private commands(): Command[] {
    return [
      { id: "goto", title: "Go to address or symbol", keys: this.k("goto"), run: () => this.palette.open("") },
      { id: "back", title: "Navigate back", keys: this.k("back"), enabled: () => this.back.length > 0, run: () => void this.goBack() },
      { id: "forward", title: "Navigate forward", keys: this.k("forward"), enabled: () => this.fwd.length > 0, run: () => void this.goForward() },
      { id: "rename", title: "Rename (function, label, variable, field)", keys: this.k("rename"), run: () => void this.rename() },
      { id: "rename-field", title: "Rename field…", keys: this.k("rename"), enabled: () => this.selectedField() !== null, run: () => void this.renameField() },
      { id: "retype-field", title: "Retype field…", keys: this.k("retype"), enabled: () => this.selectedField() !== null, run: () => void this.retypeField() },
      {
        id: "find-uses-field",
        title: "Find uses of field",
        enabled: () => this.features.has("type-uses") && !!this.selectedField()?.hash,
        run: () => { const f = this.selectedField(); if (f?.hash) void this.findUses(f.hash, { offset: f.offset, name: f.name }); },
      },
      {
        id: "find-uses-type",
        title: "Find uses of type (struct or union)",
        enabled: () => this.selectedStruct() !== null,
        run: () => { const t = this.selectedStruct(); if (t) void this.findUses(t.hash, undefined, t.name); },
      },
      ...this.sliceCommands(),
      { id: "callsig-override", title: "Override signature (this call)…", enabled: () => { const c = this.selectedCall(); return !!c && !c.current; }, run: () => void this.overrideCallSignature() },
      { id: "callsig-edit", title: "Edit signature override…", enabled: () => !!this.selectedCall()?.current, run: () => void this.overrideCallSignature() },
      { id: "callsig-remove", title: "Remove signature override", enabled: () => !!this.selectedCall()?.current, run: () => void this.removeCallSignature() },
      { id: "comment", title: "Set comment", keys: this.k("comment"), run: () => void this.comment() },
      { id: "comment-plate", title: "Set plate comment…", run: () => void this.comment("plate") },
      { id: "comment-pre", title: "Set pre-comment…", run: () => void this.comment("pre") },
      { id: "comment-post", title: "Set post-comment…", run: () => void this.comment("post") },
      { id: "comment-eol", title: "Set end-of-line comment…", run: () => void this.comment("eol") },
      { id: "retype", title: "Set type (variable, global, function prototype)…", keys: this.k("retype"), run: () => void this.retype() },
      { id: "auto-struct", title: "Auto create structure (from the variable's or the field's use)…", keys: this.k("auto-struct"), enabled: () => this.autoStructTarget() !== null, run: () => void this.autoStructure(false) },
      { id: "auto-fill", title: "Auto fill in structure (the one the variable or the field points to)…", enabled: () => this.autoStructTarget() !== null, run: () => void this.autoStructure(true) },
      { id: "struct-from-selection", title: "Create structure from selection…", enabled: () => this.features.has("auto-struct") && this.active === "listing" && this.listingEdit.range() !== null, run: () => void this.structureFromSelection() },
      { id: "fn-edit", title: "Edit function (signature, calling convention, parameters)…", keys: this.k("fn-edit") ?? (this.k("fn-create") ? `${this.k("fn-create")} at the entry` : undefined), enabled: () => this.features.has("parse-c") && this.editFunctionTarget(false) !== null, run: () => void this.editFunctionAt(this.editFunctionTarget(false)!) },
      {
        id: "no-return-set",
        title: "Set no return (calls to the function end their caller's flow)",
        enabled: () => this.features.has("no-return") && this.noReturnTarget() !== null && this.knownNoReturn(this.noReturnTarget()!) !== true,
        run: () => void this.setNoReturn(this.noReturnTarget()!, true),
      },
      {
        id: "no-return-clear",
        title: "Clear no return (the function returns)",
        enabled: () => this.features.has("no-return") && this.noReturnTarget() !== null && this.knownNoReturn(this.noReturnTarget()!) !== false,
        run: () => void this.setNoReturn(this.noReturnTarget()!, false),
      },
      { id: "fn-create", title: "Create function here", keys: this.k("fn-create"), run: () => void this.createFunction() },
      { id: "fn-remove", title: "Remove function…", keys: this.k("fn-remove"), run: () => void this.removeFunction() },
      { id: "flow", title: "Set flow override…", keys: this.k("flow"), run: () => void this.flowOverride() },
      { id: "note", title: "Add or edit note…", keys: this.k("note"), run: () => void this.addNote() },
      ...this.listingEditCommands(),
      ...this.equateReferenceCommands(),
      { id: "headers", title: this.headerRows ? "Show labels in a column (no header rows)" : "Show header rows (labels, signatures, plate comments)", enabled: () => this.features.has("listing-header-rows"), run: () => void this.setHeaderRows(!this.headerRows) },
      {
        id: "arrows",
        title: this.view.arrows ? "Hide flow arrows" : "Show flow arrows",
        run: () => {
          this.view.arrows = !this.view.arrows;
          prefs.set("rk.arrows", this.view.arrows ? "1" : "0");
          this.view.invalidate();
        },
      },
      { id: "xrefs", title: "Show references to…", keys: this.k("xrefs"), run: () => void this.xrefs() },
      { id: "emulate", title: "Emulate from here", enabled: () => this.emu !== null, run: () => void this.emulateHere() },
      { id: "emu-into", title: "Debugger: step into", keys: "F7", enabled: () => !!this.emu?.active, run: () => this.emuRun("into") },
      { id: "emu-over", title: "Debugger: step over", keys: "F8", enabled: () => !!this.emu?.active, run: () => this.emuRun("over") },
      { id: "emu-out", title: "Debugger: step out", keys: "Shift+F8", enabled: () => !!this.emu?.active, run: () => this.emuRun("out") },
      { id: "emu-run", title: "Debugger: continue", keys: "F9", enabled: () => !!this.emu?.active, run: () => this.emuRun("run") },
      { id: "emu-break", title: "Debugger: toggle breakpoint here", keys: this.k("emu-break"), enabled: () => this.emu !== null && this.location !== null, run: () => void this.emu?.toggleBreakpoint(this.location!) },
      { id: "dbg-disasm", title: "Debugger: disassemble runtime memory…", enabled: () => this.emu instanceof DebuggerPanel && this.emu.disassembly && this.emu.active, run: () => void this.disassembleRuntime() },
      { id: "dbg-copy", title: "Debugger: copy runtime memory into the program…", enabled: () => this.emu instanceof DebuggerPanel && this.emu.copy && this.emu.active && !this.emu.running, run: () => void this.copyRuntimeMemory() },
      { id: "dbg-bp-edit", title: "Debugger: breakpoint condition here…", enabled: () => this.emu instanceof DebuggerPanel && this.emu.conditions && this.location !== null, run: () => void (this.emu as DebuggerPanel).editBreakpoint(this.location!) },
      { id: "dbg-watch", title: "Debugger: add watch…", enabled: () => this.emu instanceof DebuggerPanel && this.emu.values, run: () => void this.watchHere() },
      { id: "emu-close", title: "Debugger: close session", enabled: () => !!this.emu?.active, run: () => void this.emu?.close() },
      { id: "dbg-launch", title: "Debugger: launch the program", enabled: () => this.emu instanceof DebuggerPanel && this.features.has("debugger-live"), run: () => void this.debugTarget("launch") },
      { id: "dbg-connect", title: "Debugger: connect to a gdb remote stub", enabled: () => this.emu instanceof DebuggerPanel && this.features.has("debugger-live"), run: () => void this.debugTarget("remote") },
      { id: "dbg-pause", title: "Debugger: pause", enabled: () => this.emu instanceof DebuggerPanel && this.emu.running, run: () => void (this.emu as DebuggerPanel).interrupt() },
      { id: "dbg-clear", title: "Debugger: clear breakpoints", enabled: () => this.emu instanceof DebuggerPanel, run: () => void (this.emu as DebuggerPanel).clearBreakpoints() },
      { id: "prov", title: "Show provenance (who named this)", keys: this.k("prov"), run: () => void this.showProvenanceForSelection() },
      { id: "undo", title: `Undo${this.edits.undoLabel ? ": " + this.edits.undoLabel : ""}`, keys: this.k("undo"), enabled: () => this.edits.canUndo, run: () => void this.redoOrUndo("undo") },
      { id: "redo", title: `Redo${this.edits.redoLabel ? ": " + this.edits.redoLabel : ""}`, keys: this.k("redo"), enabled: () => this.edits.canRedo, run: () => void this.redoOrUndo("redo") },
      { id: "follow", title: "Follow reference", keys: this.k("follow"), run: () => (this.active === "decomp" ? this.followFromDecomp() : (() => { const t = this.view.followTarget(); if (t !== undefined) void this.navigate(t); })()) },
      { id: "functions", title: "Focus functions filter", keys: this.k("functions"), run: () => this.functions.focusFilter() },
      ...(this.search
        ? [
            { id: "search-memory", title: "Search: memory (hex, strings, numbers, regex)…", keys: this.k("search-memory"), run: () => this.search!.open("memory") },
            { id: "search-text", title: "Search: program text (labels, comments, instructions, data)…", keys: this.k("search-text"), run: () => this.search!.open("text") },
            { id: "search-scalars", title: "Search: scalars (a value or a range)…", keys: this.k("search-scalars"), run: () => this.search!.open("scalars") },
            { id: "search-decompiled", title: "Search: decompiled code…", run: () => this.search!.open("decompiled") },
            { id: "search-next", title: "Search: repeat (next)", keys: this.k("search-next"), enabled: () => this.search!.last !== null, run: () => void this.search!.repeat(false) },
            { id: "search-prev", title: "Search: repeat backward (previous)", keys: this.k("search-prev"), enabled: () => this.search!.last !== null, run: () => void this.search!.repeat(true) },
          ]
        : []),
      ...this.views().map((v) => ({ id: `view-${v.id}`, title: `Show ${viewNoun(v.title)}${v.id === "strings" ? " (strings, defined data)" : v.id === "calls" ? " (call graph)" : v.id === "graph" ? " (function graph)" : v.id === "refs" ? " (from and to the code unit at the cursor)" : v.id === "python" ? " (the console)" : ""}`, keys: this.k(`view-${v.id}`), run: () => this.showView(v.id) })),
      { id: "toggle-decomp", title: "Switch between the listing and the decompiler", keys: this.k("toggle-decomp"), run: () => this.showView(this.active === "decomp" ? "listing" : "decomp") },
      { id: "toggle-graph", title: "Toggle listing / graph", keys: this.k("toggle-graph"), run: () => this.toggleGraph() },
      ...this.views().map((v) => ({
        id: `move-${v.id}`,
        title: `Move ${viewNoun(v.title)} to the ${this.dock.groupOf(v.id) === "main" ? "side" : "main area"}`,
        run: () => this.dock.move(v.id),
      })),
      { id: "layout-reset", title: "Reset view layout", run: () => this.dock.reset(DEFAULT_PLACES) },
      { id: "strings", title: "Show defined strings", run: () => { this.data.setCategory(0); this.showView("strings"); } },
      { id: "defined-data", title: "Show all defined data", run: () => { this.data.setCategory(1); this.showView("strings"); } },
      { id: "project-export", title: "File: Export project…", enabled: () => this.features.has(PROJECT_ARCHIVE_FEATURE), run: () => void this.exportProject() },
      { id: "open-filesystem", title: "File: Open file system…", enabled: () => this.features.has(FILESYSTEMS_FEATURE), run: () => void this.openFileSystem() },
      { id: "project-import", title: "File: Import project…", enabled: () => this.features.has(PROJECT_ARCHIVE_FEATURE), run: () => void this.importProject() },
      { id: "type-new", title: "New struct…", run: () => { this.showView("types"); this.types.newType("struct"); } },
      { id: "type-import", title: "Import C header…", enabled: () => this.features.has("parse-c"), run: () => { this.showView("types"); this.types.importHeader(); } },
      { id: "type-archive-import", title: "Import type archive…", enabled: () => this.features.has("type-archive"), run: () => { this.showView("types"); this.types.importArchive(); } },
      { id: "type-archive-export", title: "Export type archive…", enabled: () => this.features.has("type-archive"), run: () => { this.showView("types"); this.types.exportArchive(); } },
      { id: "load-pdb", title: "Load PDB…", enabled: () => this.features.has("pdb-load"), run: () => void loadPdb(this.pdbHost()) },
      { id: "symbol-settings", title: "Symbol path and servers…", enabled: () => this.features.has("pdb-load"), run: () => void symbolSettings(this.pdbHost()) },
      { id: "memory-add", title: "Memory map: add a region (RAM, I/O)…", enabled: () => this.features.has("memory-map"), run: () => { this.showView("memory"); void this.memmap.add(); } },
      { id: "memory-add-file", title: "Memory map: add bytes from a file (Add To Program)…", enabled: () => this.features.has("memory-map"), run: () => { this.showView("memory"); void this.memmap.add("file"); } },
      { id: "memory-rebase", title: "Memory map: set image base (move the program)…", enabled: () => this.features.has("rebase"), run: () => { this.showView("memory"); void this.memmap.setImageBase(); } },
      ...this.plugins.commands.map((p) => ({ id: `plugin-${p.name}`, title: `Run plugin ${p.name}…`, detail: p.description || undefined, run: () => void this.runPlugin(p.name) })),
      ...(this.scripts?.commands() ?? []),
      { id: "python-restart", title: "Python: restart the console", enabled: () => this.console !== null, run: () => { this.showView("python"); void this.console!.restart(); } },
      { id: "plugin-edits", title: "Show the last plugin command's edits", enabled: () => this.lastPluginRun.length > 0, run: () => void this.showPluginEdits() },
      { id: "bytes", title: this.cols.showBytes ? "Hide bytes column" : "Show bytes column", keys: this.k("bytes"), run: () => this.toggleBytes() },
      ...FIELD_MENU.map((f) => ({ id: `field-${f.id}`, title: `Fields: ${this.fields[f.id] ? "hide" : "show"} ${f.label.charAt(0).toLowerCase()}${f.label.slice(1)}`, run: () => this.setField(f.id, !this.fields[f.id]) })),
      { id: "overview", title: `${this.overview?.el.hidden === false ? "Hide" : "Show"} the overview bars (code, data, undefined, external; entropy)`, enabled: () => this.overview !== null, run: () => this.toggleOverview() },
      { id: "copy-special", title: "Copy special (bytes as hex, C, Python, Base64; addresses; listing text)…", keys: this.k("copy-special"), run: () => void this.copySpecial() },
      { id: "history", title: "Navigation history…", run: () => showMenuAt($("history"), this.historyItems(), "History") },
      { id: "bytes-edit", title: this.bytes?.editing ? "Byte viewer: stop editing" : "Byte viewer: edit bytes (type hex or characters; patches)", enabled: () => this.bytes !== null && this.features.has("patch"), run: () => { this.showView("bytes"); this.bytes!.setEditing(!this.bytes!.editing); } },
      ...this.navCommands(),
      ...NAME_FORMS.map(({ form, label }) => ({
        id: `names-${form}`,
        title: `Names: ${label}`,
        enabled: () => nameForm() !== form,
        run: () => setNameForm(form),
      })),
      { id: "preferences", title: "Preferences… (keymap)", run: () => this.showPreferences() },
      ...PRESETS.map((p) => ({ id: `keymap-${p.id}`, title: `Keymap: ${p.name}${p.id === "ghidra" ? " (default)" : ""}`, enabled: () => this.keymap.preset !== p.id, run: () => this.setKeymap(p.id) })),
      { id: "shortcuts", title: "Help: Keyboard shortcuts (the active keymap's)", run: () => this.showShortcuts() },
      { id: "theme", title: `Switch to ${this.dark ? "light" : "dark"} theme`, run: () => this.toggleTheme() },
      { id: "about", title: "About revkit (versions, licenses)", run: () => void showAbout(this.rk) },
      ...(session.identity
        ? [{ id: "logout", title: `Log out (signed in as ${session.identity.name})`, run: () => this.logout?.() }]
        : [{ id: "user", title: `Change user name (now user:${userName()})`, run: () => void this.changeUser() }]),
      { id: "open", title: "File: Open or import program…", keys: "Ctrl+O", run: () => this.openProgram() },
      ...this.programCommands(),
      ...this.keyedCommands(),
      { id: "libraries", title: "Libraries (shared libraries and the programs they are)…", enabled: () => this.features.has(LIBRARIES_FEATURE), run: () => this.showLibraries() },
      { id: "language", title: "Change language (which processor variant fits the code)…", enabled: () => this.features.has(LANGUAGE_FEATURE), run: () => this.showLanguage() },
      { id: "follow-import", title: "Go to library function (the import's program)", enabled: () => this.importHere()?.resolved === true, run: () => this.followImport() },
      { id: "compare", title: "Tools: Compare programs (version tracking)…", enabled: () => this.diff !== null, run: () => { this.showView("diff"); void this.diff!.compare(); } },
      {
        id: "bsim-similar",
        title: "Find similar functions (BSim)",
        enabled: () => this.bsim !== null && this.features.has("bsim-search") && this.bsimTarget() !== null,
        run: () => void this.findSimilar(),
      },
      { id: "bsim-ingest", title: "Ingest this program into a BSim database", enabled: () => this.bsim !== null, run: () => void this.bsimIngest() },
      { id: "fn-compare", title: "Compare function with…", enabled: () => this.diff !== null && this.features.has("function-compare"), run: () => void this.compareFunctionWith() },
      { id: "compare-apply", title: "Compare: apply markup to the new program…", enabled: () => this.diff !== null, run: () => { this.showView("diff"); void this.diff!.applyDialog(); } },
      { id: "compare-accept", title: "Compare: accept the selected match", keys: "a", enabled: () => !!this.diff?.selectedMatch(), run: () => void this.diff!.accept() },
      { id: "compare-reject", title: "Compare: reject the selected match", keys: "r", enabled: () => !!this.diff?.selectedMatch(), run: () => void this.diff!.reject() },
      { id: "compare-next", title: "Compare: next difference", keys: "n (in Compare)", enabled: () => !!this.diff?.selectedMatch(), run: () => { this.showView("diff"); this.diff!.goDiff(1); } },
      { id: "compare-prev", title: "Compare: previous difference", keys: "p (in Compare)", enabled: () => !!this.diff?.selectedMatch(), run: () => { this.showView("diff"); this.diff!.goDiff(-1); } },
      { id: "compare-graph", title: "Compare: show the graph diff of the selected pair", keys: "Space (in Compare)", enabled: () => this.diffGraph !== null, run: () => { this.showView("diff"); this.diff!.setLower("graph"); } },
      { id: "compare-listing", title: "Compare: show both listings aligned", enabled: () => this.diffGraph !== null, run: () => { this.showView("diff"); this.diff!.setLower("listing"); } },
      { id: "compare-c", title: "Compare: show both functions decompiled", enabled: () => this.diffGraph !== null, run: () => { this.showView("diff"); this.diff!.setLower("c"); } },
      { id: "patch-insn", title: "Patch instruction (assemble)…", keys: this.k("patch-insn"), enabled: () => this.patchEditor !== null && this.location !== null, run: () => this.patchInstruction() },
      { id: "patch-bytes", title: "Patch bytes of the selection…", keys: this.k("patch-bytes"), enabled: () => this.patchEditor !== null && this.location !== null, run: () => void this.patchBytes() },
      { id: "patch-export", title: "Export the patched program (checksum fixups)…", enabled: () => this.patches !== null, run: () => void exportDialog(this.patchHost()) },
      { id: "patch-revert-here", title: "Revert the patch here", enabled: () => this.patches !== null && !!this.view.selectedRowData()?.patched, run: () => void this.revertPatchHere() },
      { id: "patch-compare", title: "Compare with original (patched vs as imported)", enabled: () => this.patches !== null && this.diff !== null, run: () => void this.compareWithOriginal() },
      {
        id: "dpr",
        title: this.view.dprOverride === null ? "Render listing at DPR 1 (software rendering)" : "Render listing at native DPR",
        run: () => {
          if (this.view.dprOverride === null) this.setRenderScale(1, "Set from the command palette.", true);
          else {
            this.view.dprOverride = null;
            this.view.resize();
            $("st-render").hidden = true;
          }
        },
      },
    ];
  }

  // ------------------------------------------- the shown function's extras --

  /** A function's C is shown: the graph's case labels, and its plugin facts. */
  private decompiledShown(fn: DecompiledFunction) {
    this.graph.setDecompiled(fn);
    const entry = fn.entry?.offset;
    if (entry !== undefined) void this.wantFunctionFacts(entry);
  }

  private fnRanges = new Map<bigint, [bigint, bigint]>();

  /** Analyzer plugins' facts over a function's body (graph, decompiler). */
  private async wantFunctionFacts(entry: bigint) {
    this.fnFacts.analyzers = this.plugins.analyzers;
    if (!this.fnFacts.analyzers.length) return;
    let range = this.fnRanges.get(entry);
    if (!range) {
      try {
        const r = await this.rk.queries.getFunction({ programId: this.programId, address: { offset: entry } });
        let lo = entry, hi = entry;
        for (const b of r.function?.body ?? []) {
          if (b.first && b.first.offset < lo) lo = b.first.offset;
          if (b.last && b.last.offset > hi) hi = b.last.offset;
        }
        range = [lo, hi];
        this.fnRanges.set(entry, range);
        if (this.fnRanges.size > 256) this.fnRanges.delete(this.fnRanges.keys().next().value!);
      } catch {
        return;
      }
    }
    this.fnFacts.want(range[0], range[1]);
  }

  // ---------------------------------------- the rest of the keys, by name --

  /** Keys that only had a key: every one is in the palette too, with that key. */
  private keyedCommands(): Command[] {
    const graph = (run: () => void) => () => {
      this.showView("graph");
      run();
    };
    return [
      { id: "commands", title: "Show all commands", keys: "Ctrl+Shift+P / F1", run: () => this.palette.open(">") },
      {
        id: "decomp-copy",
        title: "Copy (the decompiler's selected text, or the token)",
        keys: "Ctrl+C",
        enabled: () => this.active === "decomp" && this.pane.copyText() !== null,
        run: () => this.copyToClipboard(this.pane.copyText() ?? "", "Copied"),
      },
      { id: "decomp-copy-all", title: "Copy function (the decompiled C)", enabled: () => !!this.pane.fn, run: () => this.copyToClipboard(this.pane.text, "Copied the function's C") },
      { id: "decomp-select-all", title: "Select all (the decompiled C)", keys: "Ctrl+A", enabled: () => !!this.pane.fn, run: () => { this.showView("decomp"); this.pane.selectText(0, this.pane.text.length); } },
      {
        id: "copy-rows",
        title: "Copy the selected listing rows",
        keys: "Ctrl+C",
        run: () => {
          const text = this.view.selectionText();
          if (text === null) return toast("Select rows in the listing first (drag, Shift+click or Shift+arrows)");
          void navigator.clipboard.writeText(text).then(
            () => toast("Copied the selected rows"),
            () => toast("Can't reach the clipboard; press Ctrl+C in the listing", { kind: "error" }),
          );
        },
      },
      { id: "graph-fit", title: "Graph: fit the whole function", keys: "0", run: graph(() => this.graph.fit()) },
      { id: "graph-1to1", title: "Graph: actual size", keys: "1", run: graph(() => this.graph.zoomTo(1)) },
      { id: "graph-in", title: "Graph: zoom in", keys: "+ (in the graph)", run: graph(() => this.graph.zoomTo(this.graph.scale * 1.25)) },
      { id: "graph-out", title: "Graph: zoom out", keys: "- (in the graph)", run: graph(() => this.graph.zoomTo(this.graph.scale / 1.25)) },
      { id: "graph-map", title: `Graph: ${this.graph.showMinimap ? "hide" : "show"} the minimap`, keys: "m", run: graph(() => this.graph.toggleMinimap()) },
      { id: "graph-collapse", title: "Graph: collapse or expand the selected block", keys: "c (in the graph)", enabled: () => this.location !== null, run: graph(() => this.graph.foldSelected(false)) },
      { id: "graph-group", title: "Graph: group the selected block with the blocks it dominates", keys: "Shift+C (in the graph)", enabled: () => this.location !== null, run: graph(() => this.graph.foldSelected(true)) },
      { id: "graph-expand", title: "Graph: expand all blocks and groups", keys: "Shift+E", run: graph(() => this.graph.expandAll()) },
      { id: "fn-sort", title: "Functions: sort by size (again: by references, name, address)", run: () => this.functions.cycleSort() },
    ];
  }

  // ------------------------------------------------- program management --

  /** Rename, delete and switch project (feature program-management). */
  private programCommands(): Command[] {
    const manage = this.features.has("program-management");
    return [
      { id: "project-switch", title: "File: Switch project…", run: () => this.openProgram(true) },
      { id: "program-rename", title: "File: Rename this program…", enabled: () => manage, run: () => void this.renameThisProgram() },
      { id: "program-delete", title: "File: Delete this program…", enabled: () => manage, run: () => void this.deleteThisProgram() },
      { id: "picker-diagnostics", title: "Diagnostics: time the system file chooser…", run: () => showPickerDiagnostics(() => this.live.pause()) },
    ];
  }

  private async thisProgram() {
    const r = await this.rk.projects.listPrograms({ projectId: this.projectId, includeDeleted: true });
    return r.programs.find((p) => p.programId === this.programId) ?? null;
  }

  private async renameThisProgram() {
    try {
      const p = await this.thisProgram();
      if (p) await renameProgram(this.rk, p);
    } catch (e) {
      toast(`Rename failed: ${errText(e)}`, { kind: "error" });
    }
  }

  private async deleteThisProgram() {
    try {
      const p = await this.thisProgram();
      if (p && (await deleteProgram(this.rk, p, this.programId))) this.openProgram();
    } catch (e) {
      toast(`Delete failed: ${errText(e)}`, { kind: "error" });
    }
  }

  /** This program was renamed, deleted or restored (here or anywhere). */
  private async programChanged() {
    let p;
    try {
      p = await this.thisProgram();
    } catch {
      return;
    }
    if (!p) return;
    document.title = `${p.name}${p.deleted ? " (deleted)" : ""} · revkit`;
    $("program").textContent = p.name;
    $("program").classList.toggle("deleted", p.deleted);
    if (p.deleted && !document.querySelector("[data-testid=open-dialog]")) {
      const seq = p.deletedOrigin?.source.case === "asserted" ? p.deletedOrigin.source.value.seq : 0n;
      const who = p.deletedOrigin?.source.case === "asserted" ? provText(p.deletedOrigin.source.value.provenance) : "someone";
      toast(`${who} deleted this program; it stays readable here until you leave`, {
        kind: "remote",
        ms: 12000,
        ...(seq ? { action: { label: "Restore", run: () => void undoProgramEdit(this.rk, this.programId, seq, "delete") } } : {}),
      });
    }
  }

  /** Visible rows, summarized (tests). */
  visibleRows() {
    const first = Math.floor(this.view.topRow);
    const out = [];
    for (let i = first; i <= first + this.view.viewportRows + 1; i++) {
      const r = this.cache.get(i);
      if (!r) continue;
      out.push({
        row: i,
        address: hex(r.address),
        kind: r.kind,
        header: r.header ? { kind: r.header.kind, text: r.header.text } : null,
        label: r.label,
        mnemonic: r.mnemonic,
        comment: r.comment,
        dataType: r.dataType,
        flow: r.flow,
        flowOverride: r.flowOverride,
        callSignature: r.callSignature,
        targets: r.flowTargets.map((t) => hex(t)),
        func: r.func === null ? null : hex(r.func),
        entry: r.functionEntry,
        annot: annotationAt(r.address) ?? "",
        operands: r.operands.map((t) => t.text).join(""),
        bytes: r.bytesText,
        patched: r.patched,
        length: r.length,
        dataField: r.dataField,
        dataDepth: r.dataDepth,
        dataComponents: r.dataComponents,
        dataCollapsed: r.dataCollapsed,
        unit: r.unitOrigin?.source.case === "asserted" ? provText(r.unitOrigin.source.value.provenance) : "",
        mutability: r.mutability,
        xrefCount: r.xrefCount,
        // The row as drawn (optional fields included).
        text: layoutRow(r, this.cols).runs.map((x) => x.text).join(" "),
      });
    }
    return out;
  }

  /** Where a row's plugin annotation is drawn, in client coordinates (tests). */
  annotationPoint(address: bigint): { x: number; y: number } | null {
    const first = Math.floor(this.view.topRow);
    const rect = this.view.canvas.getBoundingClientRect();
    for (let i = first; i <= first + this.view.viewportRows; i++) {
      const r = this.cache.get(i);
      if (!r || r.address !== address || r.kind === RowKind.Header) continue;
      const span = layoutRow(r, this.cols).hot.find((x) => x.kind === "plugin");
      if (!span) return null;
      return { x: rect.left + PAD_X + (span.col + 2) * this.view.charWidth, y: rect.top + i * this.view.rowH - this.view.scrollY + this.view.rowH / 2 };
    }
    return null;
  }

  /** Where a data item's disclosure marker (+/−) is drawn, in client coordinates (tests). */
  disclosurePoint(address: bigint): { x: number; y: number } | null {
    const first = Math.floor(this.view.topRow);
    const rect = this.view.canvas.getBoundingClientRect();
    for (let i = first; i <= first + this.view.viewportRows; i++) {
      const r = this.cache.get(i);
      if (!r || r.address !== address || r.kind !== RowKind.Data || r.dataField) continue;
      const span = layoutRow(r, this.cols).hot.find((x) => x.kind === "disclosure");
      if (!span) return null;
      return { x: rect.left + PAD_X + (span.col + 0.5) * this.view.charWidth, y: rect.top + i * this.view.rowH - this.view.scrollY + this.view.rowH / 2 };
    }
    return null;
  }

  /** Where an operand token (by its text) of the code unit at `address` is drawn, in client coordinates (tests). */
  operandPoint(address: bigint, text: string): { x: number; y: number } | null {
    const first = Math.floor(this.view.topRow);
    const rect = this.view.canvas.getBoundingClientRect();
    for (let i = first; i <= first + this.view.viewportRows; i++) {
      const r = this.cache.get(i);
      if (!r || r.address !== address || r.kind === RowKind.Header || r.dataField) continue;
      const span = layoutRow(r, this.cols).hot.find((x) => x.kind === "token" && x.key === text);
      if (!span) return null;
      return { x: rect.left + PAD_X + (span.col + span.len / 2) * this.view.charWidth, y: rect.top + i * this.view.rowH - this.view.scrollY + this.view.rowH / 2 };
    }
    return null;
  }

  /** The byte viewer's state (tests). */
  byteState() {
    return this.bytes?.state() ?? null;
  }

  /** The overview bars' slices and the cursor's place on them (tests). */
  overviewState() {
    return this.overview ? { ...this.overview.state(), hidden: this.overview.el.hidden } : null;
  }

  /** The flow arrows drawn in the last frame (tests). */
  arrows() {
    const top = this.view.canvas.getBoundingClientRect();
    return this.view.lastArrows.map((a) => ({ from: a.from, to: a.to, target: hex(a.target), offscreen: a.offscreen, conditional: a.conditional, x: top.left + a.x, y: top.top + (a.y0 + a.y1) / 2 }));
  }

  /** State for tests and the benchmark. */
  snapshot() {
    const row = this.view.selectedRowData();
    return {
      address: this.location === null ? null : hex(this.location),
      label: row?.label ?? null,
      comment: row?.comment ?? null,
      rowKind: row?.kind ?? null,
      selectedRow: this.view.selectedRow,
      selection: this.view.selectionRange(),
      totalRows: this.cache.rowCount,
      headerRows: this.headerRows,
      functionCount: this.functions.totalCount,
      notes: this.notes.notes.map((n) => ({ address: hex(n.address), tag: n.tag, text: n.text, who: n.who })),
      collaborators: this.collab ? [...this.collab.cursors.values()].map((c) => ({ name: c.name, address: c.address === null ? null : hex(c.address), view: c.view })) : [],
      decompSig: $("decomp-sig").textContent ?? "",
      func: row?.func === null || row?.func === undefined ? null : hex(row.func),
      decompName: this.decompFn?.name ?? null,
      decompText: this.pane.view.state.doc.toString(),
      decompSelected: this.pane.selected?.tok.text ?? null,
      live: this.liveState,
      revision: String(this.live?.head ?? 0n),
      renderDpr: this.view.renderDpr,
      back: this.back.length,
      forward: this.fwd.length,
      active: this.active,
      keymap: this.keymap.preset,
      slice: this.pane.slice ? { label: this.pane.slice.label, tokens: this.pane.slice.spans.map((s) => s.tok.text), selected: this.pane.selected?.tok.text ?? null } : null,
      sliceMarks: [...(this.view.sliceMarks ?? [])].map((a) => hex(a)),
      views: this.views().filter((v) => this.dock.isVisible(v.id)).map((v) => v.id),
      search: this.search?.state() ?? null,
      foundLine: this.pane.foundLine,
      rangeSelection: (this.view.rangeSelection ?? []).map(([a, b]) => [hex(a), hex(b)]),
      searchMarks: this.view.searchMarks?.size ?? 0,
      emu: this.emu
        ? {
            active: this.emu.active,
            busy: this.emu.busy,
            pc: this.emu.pc === null ? null : hex(this.emu.pc),
            stop: (document.querySelector("[data-testid=emu-status]") as HTMLElement | null)?.dataset.kind ?? null,
            breakpoints: [...this.emu.breakpoints].map((b) => hex(b)),
            changed: [...document.querySelectorAll("#emu .emu-reg.changed")].map((e) => (e as HTMLElement).dataset.reg ?? ""),
            steps: String(this.emu.state?.steps ?? 0n),
            frames: this.emu instanceof DebuggerPanel ? this.emu.frames.map((f) => ({ function: f.function, how: f.how, address: f.pc?.programAddress ? hex(f.pc.programAddress.offset) : null })) : [],
            frame: this.emu instanceof DebuggerPanel ? this.emu.frame : 0,
            bps: this.emu instanceof DebuggerPanel ? this.emu.bpList.map((b) => ({ id: b.id, address: b.location?.programAddress ? hex(b.location.programAddress.offset) : null, condition: b.condition, ignore: b.ignoreCount, disabled: b.disabled, hits: String(b.hits), error: b.conditionError, inserted: b.inserted })) : [],
            disasm: this.emu instanceof DebuggerPanel ? this.emu.disasm.map((i) => ({ address: hex(i.location?.address?.offset ?? 0n), program: i.location?.programAddress ? hex(i.location.programAddress.offset) : null, text: `${i.mnemonic} ${i.operands}`.trim(), pc: i.pc, symbol: i.symbol })) : [],
            watches: this.emu instanceof DebuggerPanel ? this.emu.watches.map((w, i) => ({ expr: w.expr, ...(this.emu as DebuggerPanel).watchValues[i] })) : [],
            ...(this.emu instanceof DebuggerPanel
              ? {
                  target: this.emu.session?.targetKind ?? null,
                  running: this.emu.running,
                  snapshot: this.emu.shown === null ? null : String(this.emu.shown),
                  first: String(this.emu.first),
                  last: String(this.emu.last),
                  historical: this.emu.historical,
                  rewindable: !!this.emu.state?.rewindable,
                  parent: this.emu.parent?.session.targetKind ?? null,
                  threads: this.emu.threads.length,
                  modules: this.emu.modules,
                  slide: String(this.emu.state?.mapping?.slide ?? 0n),
                  mapped: this.emu.state?.mapping?.known ?? false,
                  machine: this.emu.session?.machine?.cpu ?? null,
                  events: this.emu.events.map((e) => e.kind),
                  eventSnapshots: this.emu.events.map((e) => String(e.index)),
                }
              : {}),
          }
        : null,
    };
  }
}
