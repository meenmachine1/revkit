// Open dialog: pick a program the daemon already has, or import one, either
// by uploading the file's bytes (ImportProgram.content, works for remote
// daemons) or by a path on the daemon's host, typed or picked in the
// in-app browser (ListHostFiles; needs rk-daemon --browse-root). The
// browser doesn't use the native file chooser, which on some desktops is
// slow to open.
//
// The file picked (uploaded, dropped, browsed or typed) is shown under the
// path, with where it is and its size, until another replaces it.
//
// "Raw binary" imports a file as flat firmware (ImportOptions format "raw",
// feature "raw-import"): language, load address, a header to skip, and
// extra memory regions (RAM, MMIO). Any pick is first imported as ELF or
// PE; a file the daemon can't load so opens those options and stays
// picked, and the section's Import as raw imports it (or, with nothing
// picked, asks for a file) as raw. There is no raw mode to tick. The
// language field suggests every language the daemon has (ListLanguages,
// feature "languages"), searchable by id, processor or description.
// Before a raw import, the ticked regions are checked against the image's
// range and each other: one that overlaps is marked on its row, with Clip
// and Untick, and the import isn't sent.
//
// Import progress (feature "import-progress"): while ImportProgram runs, a
// bar at the bottom right says what the daemon is doing and how far it has
// got (importprogress.ts); older daemons get the "Importing…" line alone.
//
// Raw layout detection (feature "raw-detect", api_minor 23; rawdetect.ts):
// when the picked file isn't ELF or PE, or the user chose a raw import
// without a language, the daemon's DetectRawLayout suggests the language,
// load address, header offset and regions. They fill the raw fields as
// editable values, each with a confidence chip and a "why" expander, the
// language with an alternatives menu (the other suggestions and the
// languages the evidence can't tell apart). A refusal shows its reason and
// the closest guesses, none applied. Values the user typed stay theirs.
// The bar shows the detection's progress, Skip detection stops it, and
// nothing is imported until the user chooses Import as raw.
//
// The layout (docs/ui.md, "Opening programs"): a title row; a toolbar with
// the project switcher, New folder and ⋯ (Show deleted programs, New
// project…, the archives); the breadcrumb of the folder picked with the
// program count; a search field (name, architecture, format, folder; a
// letter typed on the list goes there); the programs as a table with
// sortable columns (Name, Architecture as "ARM · 32-bit · LE (v4T)",
// Imported, Status from GetAnalysisStatus: Ready, Analyzing, Error, Open
// here); the picked program's details (format, language, compiler, size,
// fingerprint to copy, folder, container); and a footer: Import binary…
// on the left, Cancel and Open program on the right. A click picks a row;
// a double click or Enter opens it. Import binary… swaps the table for the
// import section: Choose file… (upload), Browse daemon host…, a host path,
// and the raw binary options; Esc or Back to programs returns.
//
// Projects and programs (feature "program-management"): a project switcher
// (every project the daemon knows; a closed one is opened, a new one
// created), and per program a context menu (right-click, the menu key,
// Shift+F10 or its ⋯ button): open, rename (F2), move, copy the SHA-256,
// delete (Delete, asks first; a soft delete the toast's Undo or the trash
// restores: ⋯ → Show deleted programs, then Enter or Restore).
//
// Folders (feature "project-folders", api_minor 37): the program list is
// the project's tree, folders first. Folders expand and collapse (their
// caret, a double click, Enter, → and ←; remembered per project), programs
// and folders drag onto a folder or a breadcrumb segment (the project's
// root among them), and the menu (right-click, ⋯, the menu key,
// Shift+F10) has New folder, Rename (F2), Move to…, Delete (an empty
// folder) and Export. An import goes into the folder picked (the row
// picked, or the folder of the program picked). Every edit's toast has
// Undo (RetractAssertions by project). Older daemons: the flat list.
//
// Project archives (feature "project-archive"): Export project… and
// Import project… in the toolbar's ⋯ menu (archive.ts).
//
// Universal Mach-O files (feature "macho", api_minor 90): the import loads
// the default slice (arm64, else x86_64) and its toast offers the file's
// other slices; a slice's details say which it is of the file's slices,
// with an Import button for each other one (ImportProgram.program_file:
// the stored file again, ImportOptions.macho_slice).

import { create } from "@bufbuild/protobuf";
import {
  AnalysisState, Endianness, ImportOptionsSchema, MemoryRegionSchema, RAW_DETECT_FEATURE, confidenceName, detectRawLayout, type AvailableLanguage,
  type DetectRawLayoutResponse, type MemoryRegion, type ProgramInfo, type ProjectInfo, type Revkit,
} from "@revkit/api";
import { Code, ConnectError } from "@connectrpc/connect";
import {
  PROJECT_ARCHIVE_FEATURE, PROJECT_FOLDERS_FEATURE, buildProjectTree, folderWithin, undoFolderEdit, walkFolders, type FolderNode,
} from "@revkit/api";
import { exportProjectDialog, importProjectDialog } from "./archive";
import { userProvenance } from "../api/client";
import { errText, provText } from "../data/format";
import { archText, compareFolders, comparePrograms, dateText, dateTimeText, formatText, matchesQuery, sizeText, type Sort, type SortKey } from "../data/programs";
import { icon } from "./icons";
import { LIBRARIES_FEATURE, librariesSummary, showLibrariesDialog } from "./libraries";
import { BUILD_INFO_FEATURE, buildInfoSummary, showBuildInfoDialog } from "./buildinfo";
import { APPLE_BUNDLES_FEATURE, showCodeSignatureDialog, signatureSummary } from "./apple";
import { ask, choose, toast } from "./dialogs";
import { h, overlayRoot, prefs, typing } from "./dom";
import { showMenu, showMenuAt, type MenuItem } from "./menu";
import { pickFile } from "./filepick";
import { FILESYSTEMS_FEATURE, showFileSystemBrowser } from "./filesystem";
import { looksLikeContainer, openFileSystem, type FileSystemSession } from "@revkit/api";
import { IMPORT_PROGRESS_FEATURE, ImportProgressView, followImport, newImportId } from "./importprogress";
import {
  RegionRows, SuggestedField, detectProgress, type Overlap, fieldSuggestions, languageOf, refusalBox, refusalTitle, segmentStrip, shortLanguage, summary,
} from "./rawdetect";

export interface OpenOptions {
  /** No program is open yet: the dialog can't be dismissed. */
  required?: boolean;
  onOpen: (programId: string, address?: bigint) => void;
  /** The program this tab shows, if any (deleting it is called out). */
  current?: string;
  /** The daemon's features (program-management enables rename and delete). */
  features?: Set<string> | string[];
  /** Start with the project switcher focused. */
  focusProjects?: boolean;
  /** Start in the import section (the context row's Import binary…). */
  startImport?: boolean;
  /** Pauses the tab's live streams while the system file chooser is open; returns the resume. */
  pauseStreams?: () => () => void;
}

const LAST_PROJECT = "revkit.open.project";

/** Ticked regions the loader would refuse: the import isn't sent. */
class OverlapError extends Error {}

/** A file to import: uploaded bytes or a path on the daemon's host; `size` once known. */
type FileReq = { path?: string; content?: Uint8Array; name?: string; size?: number };

/** A region line's [start, end) in a space ("" the code space). */
type Span = { start: bigint; end: bigint; space: string };

/** A file the loader will likely read as Intel HEX or S-records (its name, or its first bytes). */
function looksLikeText(req: FileReq): boolean {
  if (req.content) {
    const head = req.content.subarray(0, 64);
    return head.length > 0 && (head[0] === 0x3a || head[0] === 0x53) && head.every((b) => b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f));
  }
  return /\.(hex|ihex|ihx|srec|s19|s28|s37|mot)$/i.test(req.path ?? "");
}

const hexs = (v: bigint) => "0x" + v.toString(16);

/** `line` (name:start:size:...) cut to what lies outside `by`: none, one or two lines (the second named name_2). */
export function clipRegion(line: string, r: Span, by: Span): string[] {
  const parts = line.trim().split(":");
  const pieces: [bigint, bigint][] = [];
  if (r.start < by.start) pieces.push([r.start, r.end < by.start ? r.end : by.start]);
  if (r.end > by.end) pieces.push([r.start > by.end ? r.start : by.end, r.end]);
  return pieces.map(([a, b], i) => [i ? `${parts[0]}_2` : parts[0], a.toString(16), (b - a).toString(16), ...parts.slice(3)].join(":"));
}

/**
 * Which of `lines` (ticked regions, in order) the raw loader would refuse:
 * each against the image (`image`, null: none or not known) and the lines
 * before it, in the same space. `exact`: the image's end is known (else
 * only its first byte is, and nothing is offered to clip to).
 */
export function regionOverlaps(lines: string[], image: Span | null, exact: boolean): Map<string, Overlap> {
  const out = new Map<string, Overlap>();
  const taken: { what: string; span: Span; clip: boolean }[] = [];
  const range = (x: Span, known: boolean) => (known ? `${hexs(x.start)}–${hexs(x.end - 1n)}` : `from ${hexs(x.start)}`);
  if (image && image.end > image.start) taken.push({ what: "the image", span: image, clip: exact });
  for (const line of lines) {
    let r: MemoryRegion;
    try {
      r = parseRegion(line);
    } catch {
      continue; // the import says what is wrong with it
    }
    const span = { start: r.start, end: r.start + r.size, space: r.space };
    const hit = taken.find((t) => t.span.space === span.space && t.span.start < span.end && span.start < t.span.end);
    if (hit) {
      const known = hit.what !== "the image" || exact;
      out.set(line, { message: `overlaps ${hit.what} (${range(hit.span, known)})`, clipped: hit.clip ? clipRegion(line, span, hit.span) : [] });
    } else {
      taken.push({ what: `region ${r.name}`, span, clip: true });
    }
  }
  return out;
}

/** Renames a program, asking for the name; resolves to the new name, or null. */
export async function renameProgram(rk: Revkit, p: ProgramInfo): Promise<string | null> {
  const name = await ask({
    title: `Rename program ${p.name}`,
    value: p.name,
    hint: "Enter to rename · empty restores the imported name · Esc to cancel",
    validate: (v) => (/[\/\x00-\x1f\x7f]/.test(v) ? "No / or control characters" : v.length > 200 ? "At most 200 characters" : null),
  });
  if (name === null || name === p.name) return null;
  const r = await rk.projects.renameProgram({ programId: p.programId, name: name.trim(), provenance: userProvenance(`rename program ${p.programId}`) });
  const seq = r.assertion?.seq;
  toast(`Renamed ${p.name} to ${r.program?.name ?? name}`, seq ? { action: { label: "Undo", run: () => void undoProgramEdit(rk, p.programId, seq, "rename") } } : {});
  return r.program?.name ?? name;
}

/** Deletes a program after asking; resolves true when deleted. */
export async function deleteProgram(rk: Revkit, p: ProgramInfo, current?: string): Promise<boolean> {
  const here = p.programId === current;
  const ok = await choose(
    `Delete ${p.name}?${here ? " It is open in this tab." : ""}`,
    [
      { label: `Delete ${p.name}`, detail: "hidden from the project; Undo or the trash restores it", value: true },
      { label: "Cancel", value: false, current: true },
    ],
    "The program's data is kept until a purge · ↑↓ Enter · Esc cancels",
  );
  if (!ok) return false;
  const r = await rk.projects.deleteProgram({ programId: p.programId, provenance: userProvenance(`delete program ${p.programId}`) });
  const seq = r.assertion?.seq;
  toast(`Deleted ${p.name}`, { ms: 8000, ...(seq ? { action: { label: "Undo", run: () => void undoProgramEdit(rk, p.programId, seq, "delete") } } : {}) });
  return true;
}

/** Retracts a rename or deletion (the trash's Restore, the toasts' Undo). */
export async function undoProgramEdit(rk: Revkit, programId: string, seq: bigint, what: "rename" | "delete") {
  try {
    await rk.assertions.retractAssertions({ programId, seqs: [seq], provenance: userProvenance(`undo ${what} of ${programId}`) });
    toast(what === "delete" ? `Restored ${programId}` : `Rename of ${programId} undone`);
  } catch (e) {
    toast(errText(e), { kind: "error" });
  }
}

/** "name:start:size[:perms][:init|uninit|volatile]", numbers in hex: a
 * region as rk-lift --region spells it. Throws on a malformed line. */
export function parseRegion(line: string): MemoryRegion {
  const parts = line.trim().split(":");
  if (parts.length < 3 || parts.length > 6 || !parts[0]) throw new Error(`region "${line}": name:start:size[:perms][:init|uninit|volatile][:space=NAME]`);
  const num = (t: string) => {
    if (!/^(0x)?[0-9a-f]+$/i.test(t)) throw new Error(`region "${line}": "${t}" is not hex`);
    return BigInt(t.toLowerCase().startsWith("0x") ? t : "0x" + t);
  };
  const r = create(MemoryRegionSchema, { name: parts[0], start: num(parts[1]), size: num(parts[2]), read: true, write: true });
  for (const f of parts.slice(3)) {
    if (f === "init") r.initialized = true;
    else if (f === "uninit") r.initialized = false;
    else if (f === "volatile") r.isVolatile = true;
    else if (f.startsWith("space=") && f.length > 6) r.space = f.slice(6);
    else if (/^[r-][w-][x-]$/.test(f)) [r.read, r.write, r.execute] = [f[0] === "r", f[1] === "w", f[2] === "x"];
    else throw new Error(`region "${line}": unknown "${f}"`);
  }
  if (!r.size) throw new Error(`region "${line}": empty`);
  return r;
}

// Suggested when the daemon can't list its languages (before api_minor 15).
const RAW_LANGUAGES = [
  "ARM:LE:32:v4t", "ARM:LE:32:v5t", "ARM:LE:32:v7", "ARM:LE:32:Cortex", "ARM:BE:32:v7", "AARCH64:LE:64:v8A",
  "MIPS:BE:32:default", "MIPS:LE:32:default", "PowerPC:BE:32:default", "x86:LE:32:default", "RISCV:LE:32:default",
];

/** How long the import's last progress may take before the program opens anyway. */
const FINAL_PROGRESS_MS = 1500;

export function showOpenDialog(rk: Revkit, o: OpenOptions) {
  const restore = document.activeElement as HTMLElement | null;
  const manage = new Set(o.features ?? []).has("program-management");
  const foldersOn = new Set(o.features ?? []).has(PROJECT_FOLDERS_FEATURE);
  const archivesOn = new Set(o.features ?? []).has(PROJECT_ARCHIVE_FEATURE);
  const tracked = new Set(o.features ?? []).has(IMPORT_PROGRESS_FEATURE);
  const detects = new Set(o.features ?? []).has(RAW_DETECT_FEATURE);
  const fsOn = new Set(o.features ?? []).has(FILESYSTEMS_FEATURE);
  const libsOn = new Set(o.features ?? []).has(LIBRARIES_FEATURE);
  const buildInfoOn = new Set(o.features ?? []).has(BUILD_INFO_FEATURE);
  // A Mach-O's code signature in a line (api_minor 100, feature "apple-bundles").
  const appleOn = new Set(o.features ?? []).has(APPLE_BUNDLES_FEATURE);
  // A universal Mach-O's slices (feature "macho", api_minor 90): the one
  // imported, the others a click away (ImportProgram.program_file).
  const machoOn = new Set(o.features ?? []).has("macho");
  const progress = new ImportProgressView();
  let stopFollowing: (() => void) | undefined;
  let importing = false;
  let closed = false;
  const list = h("div", { class: "open-list od-list", role: foldersOn ? "tree" : "listbox", "aria-label": "Programs", "data-testid": "open-list" });
  const status = h("div", { class: "open-status", "aria-live": "polite" });
  const path = h("input", { class: "path-input", placeholder: "/path/on/daemon/host/binary", "aria-label": "Path of a binary on the daemon's host", spellcheck: "false", "data-testid": "open-path" });
  // The file to import, from its pick until another replaces it.
  const fileLabel = (req: FileReq) => req.name ?? req.path?.split("/").pop() ?? "the file";
  const pickedName = h("span", { class: "open-picked-name", "data-testid": "open-picked-name" });
  const pickedWhere = h("span", { class: "dim mono open-picked-where", "data-testid": "open-picked-where" });
  const pickedSize = h("span", { class: "dim", "data-testid": "open-picked-size" });
  const picked = h(
    "div",
    { class: "open-picked", hidden: true, role: "group", "aria-label": "The file to import", "data-testid": "open-picked" },
    h("span", { class: "dim" }, "File"),
    pickedName,
    pickedWhere,
    pickedSize,
  );
  let shownFile: FileReq | undefined;
  const sizeOf = (req: FileReq) => req.content?.length ?? req.size;
  const showPicked = (req?: FileReq) => {
    shownFile = req;
    picked.hidden = !req;
    if (req) {
      pickedName.textContent = fileLabel(req);
      pickedWhere.textContent = req.content ? "uploaded" : (req.path ?? "");
      pickedWhere.title = req.content ? "Its bytes are sent to the daemon" : "A path on the daemon's host";
      const n = sizeOf(req);
      pickedSize.textContent = n === undefined ? "size not known yet" : `${size(BigInt(n))}${n >= 1024 ? ` (${n.toLocaleString("en-US")} bytes)` : ""}`;
      picked.dataset.name = fileLabel(req);
    }
    regionRows.refresh();
  };
  // A path's size from its folder's listing (needs rk-daemon --browse-root;
  // without it the size stays unknown until detection reads the file).
  const knowSize = async (req: FileReq) => {
    if (sizeOf(req) !== undefined || !req.path) return;
    const at = req.path.lastIndexOf("/");
    try {
      const r = await rk.projects.listHostFiles({ path: at > 0 ? req.path.slice(0, at) : "/" });
      const e = r.entries.find((x) => !x.directory && (x.path === req.path || x.name === req.path!.slice(at + 1)));
      if (!e || req.size !== undefined) return;
      req.size = Number(e.size);
      if (sameFile(req, shownFile)) showPicked(req);
    } catch {
      /* not browsable: unknown it stays */
    }
  };
  // Raw binary options.
  const field = (placeholder: string, testid: string, value = "") =>
    h("input", { class: "path-input", placeholder, "aria-label": placeholder, spellcheck: "false", "data-testid": testid, value }) as HTMLInputElement;
  const rawLang = field("language, e.g. ARM:LE:32:v4t", "raw-language");
  rawLang.setAttribute("list", "raw-languages");
  const langList = h("datalist", { id: "raw-languages" }, ...RAW_LANGUAGES.map((l) => h("option", { value: l })));
  const langInfo = h("div", { class: "raw-lang-info dim", "data-testid": "raw-language-info" });
  let languages = new Map<string, AvailableLanguage>();
  const describeLanguage = () => {
    const id = rawLang.value.trim();
    const l = languages.get(id.split(":").slice(0, 4).join(":"));
    if (l) {
      const endian = l.endianness === Endianness.BIG ? "big-endian" : "little-endian";
      const desc = l.description || l.processor;
      const facts = [/endian/i.test(desc) ? "" : endian, desc.includes(`${l.addressSize}`) ? "" : `${l.addressSize}-bit`];
      langInfo.textContent = [desc, facts.filter(Boolean).join(", "), `compilers: ${l.compilerSpecIds.join(", ")}`]
        .filter(Boolean).join(" · ");
    } else if (id && languages.size) {
      langInfo.textContent = `No language "${id}" on this daemon. Type a processor name to search its ${languages.size} languages.`;
    } else {
      langInfo.textContent = languages.size ? `${languages.size} languages: type a processor name (MIPS, 68000, Xtensa, 8051…) to search.` : "";
    }
  };
  rawLang.addEventListener("input", describeLanguage);
  const loadLanguages = async () => {
    try {
      const r = await rk.projects.listLanguages({});
      languages = new Map(r.languages.map((l) => [l.languageId, l]));
      langList.replaceChildren(...r.languages.map((l) =>
        h("option", { value: l.languageId, label: `${l.processor} · ${l.description}` })));
    } catch {
      // An older daemon: keep the short list.
    }
    describeLanguage();
  };
  const rawBase = field("load address (hex), default 0", "raw-base");
  const rawOffset = field("header bytes to skip (hex), default 0", "raw-offset");
  const rawLength = field("bytes to load (hex), default to the end", "raw-length");
  const rawPerms = field("image permissions, default rwx", "raw-perms");
  // Harvard MCUs: the space the image goes in (empty: code; EXTMEM for an
  // 8051 data dump), and the container (Intel HEX, S-records).
  const rawSpace = field("memory space, default the code space (e.g. EXTMEM)", "raw-space");
  const rawFormat = h(
    "select",
    { class: "path-input", "data-testid": "raw-format", title: "What the file holds", "aria-label": "File format" },
    h("option", { value: "" }, "format: detect (binary, Intel HEX, S-records)"),
    h("option", { value: "binary" }, "binary"),
    h("option", { value: "ihex" }, "Intel HEX"),
    h("option", { value: "srec" }, "Motorola S-records"),
  ) as HTMLSelectElement;
  const rawRegions = h("textarea", {
    class: "path-input raw-regions",
    rows: "3",
    spellcheck: "false",
    "data-testid": "raw-regions",
    "aria-label": "Memory regions, one per line: name:start:size[:perms][:init|uninit|volatile][:space=NAME]",
    placeholder: "regions, one per line: name:start:size[:perms][:init|uninit|volatile][:space=NAME]\nperiph:c0000000:300000:rw-",
  }) as HTMLTextAreaElement;
  for (const el of [rawLang, rawBase, rawOffset, rawLength, rawPerms, rawSpace, rawFormat, rawRegions])
    el.addEventListener("keydown", (e) => e.stopPropagation());
  // Detection's suggestions on the fields it answers (rawdetect.ts).
  const sameHex = (a: string, b: string) => {
    const n = (t: string) => (/^(0x)?[0-9a-f]+$/i.test(t.trim()) ? BigInt(t.trim().toLowerCase().startsWith("0x") ? t.trim() : "0x" + t.trim()) : t.trim());
    return n(a) === n(b);
  };
  const sameLines = (a: string, b: string) => {
    const n = (t: string) => t.split("\n").map((l) => l.trim()).filter(Boolean).join("\n");
    return n(a) === n(b);
  };
  const sLang = new SuggestedField(rawLang, "language", "language", (a, b) => shortLanguage(a.trim()) === shortLanguage(b.trim()));
  const sBase = new SuggestedField(rawBase, "base", "load address", sameHex);
  const sOffset = new SuggestedField(rawOffset, "offset", "header offset", sameHex);
  const sRegions = new SuggestedField(rawRegions, "regions", "regions", sameLines, true);
  const suggested = [sLang, sBase, sOffset, sRegions];
  // Each detected region with its own confidence and evidence, under the box.
  const regionRows = new RegionRows(rawRegions);
  // The image's range as the loader will lay it (a binary at the load
  // address, from the header on, to the length or the file's end). A HEX or
  // S-record file's addresses are its records': nothing to check here.
  const imageSpan = (): { span: Span; exact: boolean } | null => {
    const req = pending ?? (path.value.trim() ? { path: path.value.trim() } : undefined);
    if (!req) return null;
    const fmt = rawFormat.value;
    if (fmt === "ihex" || fmt === "srec") return null;
    if (!fmt && looksLikeText(req)) return null;
    let start: bigint, offset: bigint, length: bigint | undefined;
    try {
      start = rawBase.value.trim() ? hex(rawBase.value, "load address") : 0n;
      offset = rawOffset.value.trim() ? hex(rawOffset.value, "header") : 0n;
      length = rawLength.value.trim() ? hex(rawLength.value, "length") : undefined;
    } catch {
      return null;
    }
    const space = rawSpace.value.trim();
    const n = sizeOf(req);
    if (length === undefined) {
      if (n === undefined) return { span: { start, end: start + 1n, space }, exact: false };
      length = BigInt(n) > offset ? BigInt(n) - offset : 0n;
    }
    return length ? { span: { start, end: start + length, space }, exact: true } : null;
  };
  regionRows.checker = (lines) => {
    const img = imageSpan();
    return regionOverlaps(lines, img?.span ?? null, !!img?.exact);
  };
  // What detection said of the file: a summary or the refusal, and the file's map.
  const detectView = h("div", { class: "raw-detect", "data-testid": "raw-detect-view", hidden: true });
  const rawBox = h(
    "details",
    { class: "raw-options", "data-testid": "raw-options" },
    h("summary", {}, "Raw binary (firmware)…"),
  ) as HTMLDetailsElement;
  // The fields' grid; a <details> itself doesn't lay out as one everywhere.
  const rawGrid = h(
    "div",
    { class: "raw-grid" },
    detectView,
    langList,
    sLang.el, sBase.el, langInfo, sOffset.el, rawLength, rawPerms, rawSpace, rawFormat, sRegions.el, regionRows.el, regionRows.problems,
  );
  rawBox.append(rawGrid);
  for (const el of [rawBase, rawOffset, rawLength, rawSpace]) el.addEventListener("input", () => regionRows.refresh());
  rawFormat.addEventListener("change", () => regionRows.refresh());
  let languagesAsked = false;
  rawBox.addEventListener("toggle", () => {
    if (!rawBox.open || languagesAsked) return;
    languagesAsked = true;
    void loadLanguages();
  });
  // What the user picked last, to import again as raw.
  let pending: FileReq | undefined;
  // The one way to import as raw: the picked file, else the typed path,
  // else a file the system chooser picks now.
  const rawImportBtn = h("button", {
    class: "btn",
    "data-testid": "raw-import",
    title: "Import the picked file as a raw binary with the options above (with nothing picked, choose a file first)",
    onclick: () => {
      if (pending) void doImport(pending, true);
      else if (path.value.trim()) void doImport({ path: path.value.trim() }, true);
      else void importFile(true);
    },
    text: "Import as raw",
  });
  // Detection again, on demand: for the picked file, with the user's own
  // language (if any) as a hint that narrows the search.
  const rawDetectBtn = h("button", {
    class: "btn",
    type: "button",
    hidden: !detects,
    "data-testid": "raw-detect",
    title: "Suggest the language, load address, header and regions from the file's bytes (a language you typed narrows the search)",
    onclick: () => {
      const req = pending ?? (path.value.trim() ? { path: path.value.trim() } : undefined);
      if (req) void runDetection(req);
      else busy("Pick a file first (Choose file…, Browse daemon host…, or a path).", "hint");
    },
    text: "Suggest from the file",
  });
  rawGrid.append(h("div", { class: "raw-actions" }, rawImportBtn, rawDetectBtn));
  const hex = (t: string, what: string) => {
    t = t.trim();
    if (!/^(0x)?[0-9a-f]+$/i.test(t)) throw new Error(`${what}: "${t}" is not hex`);
    return BigInt(t.toLowerCase().startsWith("0x") ? t : "0x" + t);
  };
  // --- raw layout detection ---
  let detectCtl: AbortController | undefined;
  let detectedFor: FileReq | undefined;
  let detection: DetectRawLayoutResponse | undefined;
  let chosen = -1;
  // The file known not to be ELF or PE, or detected on the user's say:
  // picking it again (Enter on its path) imports it as raw. Any other file
  // is tried as ELF or PE first.
  let rawFor: FileReq | undefined;
  const sameFile = (a?: FileReq, b?: FileReq) => !!a && !!b && a.path === b.path && a.content === b.content;
  const fsBtn = h("button", { class: "btn small primary", type: "button", hidden: true, "data-testid": "open-as-filesystem", title: "Browse what is inside and import from it", text: "Open as file system" });
  const skipBtn = h("button", {
    class: "btn small",
    type: "button",
    hidden: true,
    "data-testid": "raw-detect-skip",
    title: "Stop detecting and set the raw binary options yourself",
    text: "Skip detection",
  });
  const stopDetection = () => {
    const c = detectCtl;
    detectCtl = undefined;
    skipBtn.hidden = true;
    c?.abort();
  };
  skipBtn.addEventListener("click", () => {
    if (!detectCtl) return;
    stopDetection();
    progress.hide();
    rawBox.dataset.detect = "skipped";
    busy(`Detection of ${fileLabel(detectedFor ?? {})} skipped. Set the raw binary options and choose Import as raw.`, "hint");
    rawLang.focus();
  });
  // Forgets what detection said; values the user typed stay.
  const forgetDetection = () => {
    stopDetection();
    detection = undefined;
    detectedFor = undefined;
    chosen = -1;
    for (const f of suggested) f.clear();
    regionRows.clear();
    sLang.onAlternatives = undefined;
    detectView.replaceChildren();
    detectView.hidden = true;
    delete rawBox.dataset.detect;
  };
  // Puts suggestion `i` on the fields: the language always when the user
  // chose it (`chosenByUser`), the rest where the user hasn't typed a value.
  const applySuggestion = (i: number, chosenByUser: boolean, language?: string) => {
    const s = detection?.suggestions[i];
    if (!s) return;
    chosen = i;
    const f = fieldSuggestions(s, language);
    sLang.onAlternatives = (anchor) => showMenuAt(anchor, alternatives(), "Other languages detection considered");
    sLang.suggest(f.language, chosenByUser);
    sBase.suggest(f.base);
    sOffset.suggest(f.offset);
    sRegions.suggest(f.regions);
    regionRows.show(s.regionDetails);
    describeLanguage();
  };
  const alternatives = (): MenuItem[] => {
    const r = detection;
    if (!r) return [];
    const items: MenuItem[] = [];
    const current = r.suggestions[chosen];
    const here = shortLanguage(rawLang.value.trim());
    if (current) {
      // The languages the same evidence fits: the variant is the open question.
      for (const t of [languageOf(current), ...current.tieGroup.map((l) => shortLanguage(l))]) {
        if (t === here) continue;
        items.push({
          label: `${t} · same evidence`,
          testid: "raw-alt-tie",
          run: () => applySuggestion(chosen, true, t),
        });
      }
    }
    r.suggestions.forEach((s, j) => {
      if (j === chosen) return;
      items.push({
        label: `${languageOf(s)} · processor ${confidenceName(s.processorConfidence) || "low"}${r.refusal ? " (a guess)" : ""}`,
        testid: "raw-alt-suggestion",
        run: () => applySuggestion(j, true),
      });
    });
    if (!items.length) items.push({ label: "No other language fits", disabled: true, run: () => {} });
    return items;
  };
  const showDetection = (req: FileReq, r: DetectRawLayoutResponse) => {
    detection = r;
    if (r.fileSize && req.size === undefined) {
      req.size = Number(r.fileSize);
      if (sameFile(req, shownFile)) showPicked(req);
    }
    const strip = segmentStrip(r);
    const label = fileLabel(req);
    if (r.refusal || !r.suggestions.length) {
      // Nothing applied: the reason, and the closest guesses to use if the user wants.
      for (const f of suggested) f.clear();
      regionRows.clear();
      const reason = r.refusal ? refusalTitle(r.refusal.reason) : "Nothing to suggest";
      detectView.replaceChildren(
        refusalBox(r, label, (i) => {
          applySuggestion(i, true);
          rawLang.focus();
        }),
        ...(strip ? [strip] : []),
      );
      rawBox.dataset.detect = "refused";
      busy(`${label}: not detected. ${reason}. Set the raw binary options yourself${r.suggestions.length ? ", or use one of the closest guesses" : ""}.`, "hint");
    } else {
      applySuggestion(0, false);
      const n = r.suggestions.length - 1;
      detectView.replaceChildren(
        h(
          "div",
          { class: "raw-detected", "data-testid": "raw-detected" },
          h("span", {}, `Suggested from ${label}'s bytes: ${summary(r.suggestions[0])}.`),
          h("span", { class: "dim" }, ` ${n ? `${n} other suggestion${n === 1 ? "" : "s"} under Alternatives. ` : ""}Edit anything, then choose Import as raw.`),
        ),
        ...(strip ? [strip] : []),
      );
      rawBox.dataset.detect = "suggested";
      busy(`Suggested raw options for ${label}: check them below and choose Import as raw.`, "hint");
    }
    detectView.hidden = false;
  };
  // Runs detection on the file `req` names; nothing is imported.
  const runDetection = async (req: FileReq) => {
    if (!detects || importing) return;
    forgetDetection();
    const ctl = new AbortController();
    detectCtl = ctl;
    detectedFor = req;
    rawFor = req;
    pending = req;
    showPicked(req);
    void knowSize(req);
    rawBox.open = true;
    rawBox.dataset.detect = "running";
    const label = fileLabel(req);
    busy(`Detecting ${label}'s processor, load address and header…`);
    status.title = req.path ?? "";
    skipBtn.hidden = false;
    progress.start(req.content ? `Uploading ${label} (${size(BigInt(req.content.length))})` : "Starting detection", "Detection progress");
    // A language the user typed narrows the search to its processor.
    const hint = sLang.own ? rawLang.value.trim() : "";
    if (!project) await projectsReady;
    if (detectCtl !== ctl || closed) return;
    try {
      const r = await detectRawLayout(
        rk,
        {
          projectId: project,
          source: req.content ? { case: "content", value: req.content } : { case: "path", value: req.path! },
          ...(hint ? { hints: { languageId: hint } } : {}),
        },
        { signal: ctl.signal, onProgress: (p) => detectCtl === ctl && progress.show(detectProgress(p)) },
      );
      if (detectCtl !== ctl || closed) return;
      showDetection(req, r);
      // A refusal ends the bar without the green of an answer.
      if (r.refusal) progress.show({ text: `Not detected: ${refusalTitle(r.refusal.reason)}`, fraction: 1, phase: "DONE", announce: "Not detected", done: true, error: true });
      else progress.finish(`Detected in ${r.elapsedSeconds.toFixed(1)} s`);
      rawLang.focus();
    } catch (e) {
      if (detectCtl !== ctl || closed) return;
      progress.hide();
      rawBox.dataset.detect = e instanceof ConnectError && e.code === Code.Canceled ? "skipped" : "failed";
      busy(`Detection failed: ${errText(e)}. Set the raw binary options yourself.`, true);
    } finally {
      if (detectCtl === ctl) {
        detectCtl = undefined;
        skipBtn.hidden = true;
      }
    }
  };
  // Another slice of a universal Mach-O already imported: its stored file
  // again, with the slice named (ImportProgram.program_file).
  const importSlice = async (into: string, p: ProgramInfo, arch: string) => {
    try {
      const r = await rk.projects.importProgram({
        projectId: into,
        source: { case: "programFile", value: p.programId },
        provenance: userProvenance(`import the ${arch} slice of ${p.name}`),
        options: create(ImportOptionsSchema, { machoSlice: arch, analyze: true }),
        ...(foldersOn && p.folderId ? { folderId: p.folderId } : {}),
      });
      toast(`Imported ${r.program?.name ?? arch}`);
      if (!closed && into === project) void loadPrograms(r.program ? `p:${r.program.programId}` : undefined);
    } catch (e) {
      toast(`The ${arch} slice wasn't imported: ${errText(e)}`, { kind: "error" });
    }
  };
  const rawOptions = (raw: boolean) => {
    if (!raw) return undefined;
    const language = rawLang.value.trim();
    if (!language) throw new Error("a raw binary needs a language (e.g. ARM:LE:32:v4t)");
    const parts = language.split(":");
    const regions = rawRegions.value.split("\n").filter((l) => l.trim()).map(parseRegion);
    const perms = rawPerms.value.trim();
    if (perms && !/^[r-][w-][x-]$/.test(perms)) throw new Error(`permissions: "${perms}" is not like rwx or r-x`);
    return create(ImportOptionsSchema, {
      format: "raw",
      languageId: parts.slice(0, 4).join(":"),
      compilerSpecId: parts[4] ?? "",
      hasImageBase: !!rawBase.value.trim(),
      imageBase: rawBase.value.trim() ? hex(rawBase.value, "load address") : 0n,
      rawOffset: rawOffset.value.trim() ? hex(rawOffset.value, "header") : 0n,
      rawLength: rawLength.value.trim() ? hex(rawLength.value, "length") : 0n,
      rawPermissions: perms,
      rawSpace: rawSpace.value.trim(),
      rawFormat: rawFormat.value,
      regions,
    });
  };
  let project = prefs.get(LAST_PROJECT) ?? "";
  // The first listing of the projects (which picks `project` when none was remembered).
  let projectsReady: Promise<void> = Promise.resolve();
  const projectInfos = new Map<string, ProjectInfo>();
  const projectName = () => projectInfos.get(project)?.name || project;
  let showDeleted = false;
  const projectSel = h("select", { class: "open-project od-select", "aria-label": "Project", "data-testid": "open-project", title: "Project (each one fact database)" }) as HTMLSelectElement;

  // --- the view: the programs (a table) or the import section ---
  let view: "programs" | "import" = "programs";
  // Sorting (remembered), and the search.
  const SORT_KEY = "revkit.open.sort";
  let sort: Sort = { key: "name", dir: 1 };
  try {
    const s = JSON.parse(prefs.get(SORT_KEY) ?? "null") as Sort | null;
    if (s && ["name", "arch", "date", "status"].includes(s.key) && (s.dir === 1 || s.dir === -1)) sort = s;
  } catch {
    /* the default */
  }
  let query = "";
  const search = h("input", {
    class: "od-search-input",
    type: "search",
    placeholder: "Search programs by name, architecture, format or folder…",
    "aria-label": "Search programs",
    spellcheck: "false",
    autocomplete: "off",
    "data-testid": "open-search",
  }) as HTMLInputElement;
  search.addEventListener("input", () => {
    query = search.value.trim();
    const key = rows[active]?.dataset.key;
    render();
    showPrograms(key);
  });
  // The program rows (the tree's, or the search's matches) and the one picked (-1: none, the root).
  let rows: HTMLElement[] = [];
  let active = 0;
  let programView: HTMLElement[] = [h("div", { class: "od-empty dim", role: "none" }, "Loading…")];
  // The daemon host's files, in the import section.
  let browsing = false;
  let hostRows: HTMLElement[] = [];
  let hostActive = 0;
  let parentDir = "";
  const LAST_DIR = "revkit.open.lastDir";

  const close = () => {
    closed = true;
    clearTimeout(statusTimer);
    dropFileSystem();
    stopDetection();
    stopFollowing?.();
    backdrop.remove();
    document.removeEventListener("keydown", onDocKey, true);
    restore?.focus({ preventScroll: true });
  };
  const open = (id: string, address?: bigint) => {
    closed = true;
    clearTimeout(statusTimer);
    stopDetection();
    stopFollowing?.();
    backdrop.remove();
    document.removeEventListener("keydown", onDocKey, true);
    o.onOpen(id, address);
  };
  // Progress, guidance (what to do next) or an error.
  const busy = (text: string, kind: boolean | "hint" = false) => {
    status.textContent = text;
    status.removeAttribute("title");
    status.className = "open-status" + (kind === "hint" ? " hint" : kind ? " error" : "");
  };
  // A container (zip, tar, squashfs, ...): "Open as file system" browses
  // it (filesystem.ts), its session opened here already.
  let fsSession: FileSystemSession | undefined;
  const dropFileSystem = () => {
    fsBtn.hidden = true;
    void fsSession?.close();
    fsSession = undefined;
  };
  const offerFileSystem = async (req: FileReq): Promise<boolean> => {
    if (!fsOn) return false;
    if (!project) await projectsReady;
    let s: FileSystemSession;
    try {
      s = await openFileSystem(rk, project, req.content ? { file: req.content, name: req.name ?? "upload" } : { hostPath: req.path! });
    } catch {
      return false;
    }
    dropFileSystem();
    fsSession = s;
    fsBtn.hidden = false;
    busy(`${fileLabel(req)} is a ${s.root?.description ?? "container"}: open it as a file system to browse it and import what is inside.`, "hint");
    fsBtn.focus();
    return true;
  };
  // A program's file carrying a packer's archive (api_minor 96, ProgramInfo.payload_format): browse it.
  const payloadNames: Record<string, string> = {
    pyinstaller: "PyInstaller archive", "node-sea": "Node.js single executable blob", pkg: "pkg file system", nexe: "nexe resources",
    bun: "Bun module graph", zip: "appended zip", "lua-chunks": "Lua chunks",
  };
  const payloadText = (f: string) => payloadNames[f] ?? f;
  const openPayload = async (projectId: string, programId: string) => {
    try {
      const s = await openFileSystem(rk, projectId, { programId });
      showFileSystemBrowser({ rk, projectId, features: new Set(o.features ?? []), pauseStreams: o.pauseStreams, onOpenProgram: (id, address) => open(id, address) }, s);
    } catch (e) {
      toast(`Could not open it as a file system: ${errText(e)}`, { kind: "error" });
    }
  };
  fsBtn.addEventListener("click", () => {
    const s = fsSession;
    if (!s) return;
    fsSession = undefined;
    fsBtn.hidden = true;
    showFileSystemBrowser({ rk, projectId: s.projectId, features: new Set(o.features ?? []), pauseStreams: o.pauseStreams, onOpenProgram: (id, address) => open(id, address) }, s);
  });
  // Where an import goes: the folder picked in the tree when the import section opened.
  let importInto: { folderId: string; path: string } | null = null;
  // Imports `req`: as ELF or PE, unless `raw` (Import as raw) or it is the
  // file already known not to be one.
  const doImport = async (req: FileReq, raw = false) => {
    if (importing) return;
    if (view !== "import") setView("import");
    dropFileSystem();
    // Another file: what detection said of the last one no longer applies.
    if (detectedFor && !sameFile(req, detectedFor)) forgetDetection();
    pending = req;
    showPicked(req);
    void knowSize(req);
    const asRaw = raw || sameFile(req, rawFor);
    if (asRaw) rawFor = req;
    // Bytes that start like an archive or image: offered as a file system, not imported.
    if (!asRaw && req.content && looksLikeContainer(req.content.subarray(0, 40000)) && (await offerFileSystem(req))) return;
    // Raw chosen without a language: suggest one (and the rest) first.
    if (detects && asRaw && !rawLang.value.trim()) {
      if (!sameFile(req, detectedFor)) return void runDetection(req);
      if (detectCtl) return busy("Detection is still running: wait for its suggestions, or Skip detection and type a language.", "hint");
    }
    stopDetection();
    const label = fileLabel(req);
    busy(`Importing ${label}…`);
    status.title = req.path ?? "";
    importing = true;
    // With the feature, a random id to follow the import by.
    const importId = tracked ? newImportId() : "";
    // A file picked before the projects are listed goes to the project chosen then.
    if (!project) await projectsReady;
    const into = project;
    const dest = importInto;
    try {
      const raw = rawOptions(asRaw);
      // Nothing the loader would refuse for an overlap is sent.
      if (raw) {
        await knowSize(req);
        const n = regionRows.refresh();
        if (n) throw new OverlapError(`${label} not imported: ${n === 1 ? "a region overlaps" : `${n} regions overlap`} the image or another region. Clip or untick ${n === 1 ? "it" : "them"} (marked under the regions).`);
      }
      // Also import the libraries it needs (feature program-libraries).
      const libs = libsOn && libsBox.checked;
      const options = libs ? (raw ?? create(ImportOptionsSchema, {})) : raw;
      if (libs && options) {
        options.importLibraries = true;
        options.librarySearchPaths = libsPaths.value.split(/[:\n]/).map((x) => x.trim()).filter(Boolean);
      }
      if (importId) {
        progress.start(req.content ? `Uploading ${label} (${size(BigInt(req.content.length))})` : "Starting the import");
        stopFollowing = followImport(rk, into, importId, progress);
      }
      const r = await rk.projects.importProgram({
        projectId: into,
        source: req.content ? { case: "content", value: req.content } : { case: "path", value: req.path! },
        name: req.name ?? "",
        provenance: userProvenance(),
        importId,
        // The daemon puts it (and its libraries) in the folder (api_minor 70).
        ...(libsOn && foldersOn && dest?.folderId && into === project ? { folderId: dest.folderId } : {}),
        ...(options ? { options } : {}),
      });
      const id = r.program?.programId;
      if (!id) throw new Error("import returned no program");
      if (machoOn && r.program && r.program.machoSlices.length > 1) {
        const others = r.program.machoSlices.filter((a) => a !== r.program!.machoSlice);
        toast(`Universal binary: imported its ${r.program.machoSlice} slice; it also has ${others.join(", ")}`, {
          ms: 12000,
          action: { label: `Import ${others[0]}`, run: () => void importSlice(into, r.program!, others[0]) },
        });
      }
      // A packed executable: its scripts are a file system away (api_minor 96).
      if (fsOn && r.program?.payloadFormat) {
        const pid = r.program.programId;
        toast(`${r.program.name} carries a ${payloadText(r.program.payloadFormat)}: open it as a file system to see the scripts and files packed in it.`, {
          ms: 12000,
          action: { label: "Open as file system", run: () => void openPayload(into, pid) },
        });
      }
      // An IL-only .NET assembly is imported without code analysis (api_minor 94).
      if (r.program?.dotnet?.codeAnalysisSkipped)
        toast(`${r.program.dotnet.description}: imported without code analysis, as its code is IL, not machine code. Its C# comes from the ILSpy external decompiler (docs/providers.md).`, { ms: 12000 });
      if (r.libraries.length || r.librariesNotFound.length)
        toast(
          [r.libraries.length ? `Imported ${r.libraries.length} librar${r.libraries.length === 1 ? "y" : "ies"} with it (${r.libraries.map((x) => x.name).join(", ")})` : "",
            r.librariesNotFound.length ? `not found: ${r.librariesNotFound.map((x) => x.name).join(", ")}` : "",
            // The extracted root file system they were looked for in (api_minor 79).
            r.libraryRoot ? `looked for in ${r.libraryRoot}` : ""].filter(Boolean).join("; "),
          { ms: 8000 },
        );
      // Into the folder picked in the tree (older daemons: moved here).
      if (foldersOn && dest?.folderId && into === project && !libsOn) {
        try {
          await rk.projects.moveToFolder({ projectId: into, folderId: dest.folderId, programIds: [id], provenance: userProvenance(`import into ${dest.path}`) });
        } catch (e) {
          toast(`Imported, but not moved into ${dest.path}: ${errText(e)}`, { kind: "error" });
        }
      }
      stopFollowing?.();
      if (importId && !closed) {
        // The bar full, with what was found, for a moment before the program opens.
        progress.finish(`Imported ${r.program?.name ?? label}`);
        busy(`Imported ${r.program?.name ?? label}; opening it…`);
        // What was found, for the bar: briefly. Nothing waits on an answer
        // that may not come (the browser's six connections to the daemon
        // all held by other tabs' streams and calls, a daemon too busy to
        // answer); the program is imported either way (docs/known-issues.md).
        try {
          const last = await rk.projects.getImportProgress({ projectId: into, importId }, { timeoutMs: FINAL_PROGRESS_MS });
          if (last.done && !last.error) progress.update(last);
        } catch {
          /* the program is imported either way */
        }
        await new Promise((resolve) => setTimeout(resolve, 400));
        if (closed) return;
      }
      open(id);
    } catch (e) {
      stopFollowing?.();
      progress.hide();
      const text = errText(e);
      // Not ELF or PE (or a loader plugin's): offer the raw options.
      const notElfOrPe = !asRaw && /unrecognised file format|no Ghidra language/i.test(text);
      if (notElfOrPe && (await offerFileSystem(req))) {
        // A container: browse it instead (detection stays a button away).
      } else if (notElfOrPe && detects) {
        // Suggest the raw options from the file's bytes; the user confirms.
        importing = false;
        void runDetection(req);
        busy(`${label} isn't ELF or PE. Detecting its processor, load address and header…`);
      } else if (notElfOrPe) {
        rawFor = req;
        rawBox.open = true;
        busy(`${label} isn't ELF or PE. Set the raw binary options below and choose Import as raw.`, "hint");
        rawLang.focus();
      } else if (e instanceof OverlapError) {
        rawBox.open = true;
        busy(text, true);
        regionRows.focusProblem();
      } else {
        busy(text, true);
      }
    } finally {
      importing = false;
      stopFollowing = undefined;
    }
  };
  // The system file chooser, asked for when the button is pressed (no file
  // <input> waits in the page), timed: when it is slow to appear, say how
  // to avoid it (filepick.ts, docs/known-issues.md).
  const importFile = async (raw = false) => {
    busy("Waiting for the system file chooser…");
    const { file: f, timing } = await pickFile({ pause: o.pauseStreams });
    const slow = timing.shownMs !== null && timing.shownMs > 2000;
    if (!f) {
      busy(
        timing.error
          ? `The file chooser failed: ${timing.error}`
          : slow
            ? `The system file chooser took ${(timing.shownMs! / 1000).toFixed(1)} s to open. Dropping a file here or Browse daemon host… avoids it; Diagnostics in the command palette times the alternatives.`
            : "",
        timing.error ? true : slow ? "hint" : false,
      );
      return;
    }
    await doImport({ content: new Uint8Array(await f.arrayBuffer()), name: f.name.replace(/[^\w.+-]/g, "_") }, raw);
    if (slow) toast(`The system file chooser took ${(timing.shownMs! / 1000).toFixed(1)} s to open; drag and drop or Browse daemon host… avoid it.`, { ms: 8000 });
  };
  // A path typed now is the file the raw buttons mean, not the last one picked.
  path.addEventListener("input", () => {
    pending = undefined;
    const t = path.value.trim();
    showPicked(t ? { path: t } : undefined);
  });
  path.addEventListener("keydown", (e) => {
    e.stopPropagation();
    if (e.key === "Enter" && path.value.trim()) void doImport({ path: path.value.trim() });
    if (e.key === "Escape") setView("programs");
  });

  // --- the header: the title, then the project, New folder and ⋯ ---
  const closeBtn = h("button", { class: "od-close icon-btn", type: "button", "aria-label": "Close", title: "Close (Esc)", "data-testid": "open-close", hidden: !!o.required, onclick: () => close() }, icon("close"));
  const newFolderBtn = h(
    "button",
    {
      class: "btn od-tool open-new-folder",
      type: "button",
      "data-testid": "open-new-folder",
      hidden: !foldersOn,
      title: "New folder in the folder picked (or the root)",
      onclick: () => void doNewFolder(selectedFolder()?.folderId ?? ""),
    },
    icon("folder-plus"),
    h("span", {}, "New folder"),
  );
  const toggleDeleted = () => {
    showDeleted = !showDeleted;
    void loadPrograms(rows[active]?.dataset.key);
  };
  const overflowBtn = h(
    "button",
    { class: "btn od-tool od-icon-only", type: "button", "aria-label": "More project actions", title: "Show deleted programs, project archives, a new project", "aria-haspopup": "menu", "data-testid": "open-overflow" },
    icon("more"),
  );
  overflowBtn.addEventListener("click", () =>
    showMenuAt(overflowBtn, [
      ...(manage ? [{ label: "Show deleted programs", checked: showDeleted, testid: "menu-show-deleted", title: "List the programs deleted from this project, to restore them", run: toggleDeleted }] : []),
      { label: "New project…", testid: "menu-new-project", separator: manage, run: () => void newProject() },
      ...(archivesOn
        ? [
            { label: "Export project…", separator: true, testid: "menu-export-project", run: () => void doExport() },
            { label: "Import project…", testid: "menu-import-project", run: () => void doImportProject() },
          ]
        : []),
    ], "Project actions"));
  const projectBox = h("label", { class: "od-project" }, h("span", { class: "od-label" }, "Project"), h("span", { class: "od-select-wrap" }, projectSel, icon("chevron-down", "od-select-caret")));

  // --- the breadcrumb: the folder picked, and how many programs ---
  const crumbs = h("nav", { class: "od-crumbs", "aria-label": "Folder", "data-testid": "open-crumbs" });
  const countEl = h("span", { class: "od-count", "data-testid": "open-count" });
  const paintCrumbs = () => {
    const f = selectedFolder();
    const segs: HTMLElement[] = [];
    const rootBtn = h(
      "button",
      { class: "od-crumb od-crumb-root", type: "button", "data-testid": "open-root", title: `The project's root${foldersOn ? ": drop here to move out of a folder" : ""}`, onclick: () => pickFolder("") },
      icon("folder"),
      h("span", {}, projectName() || "Project"),
    );
    if (foldersOn) {
      dropTarget(rootBtn, "");
      rootBtn.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        const n = folderNodes.get("");
        if (n) showMenu(folderMenu(n), e.clientX, e.clientY, "Actions for the project");
      });
    }
    segs.push(rootBtn, h("span", { class: "od-crumb-sep", "aria-hidden": "true" }, "/"));
    if (f?.folderId) {
      // Each folder from the root down to the one picked.
      const chain: FolderNode[] = [];
      for (let n = folderNodes.get(f.folderId); n && n.folderId; n = folderNodes.get(n.folder?.parentId ?? "")) chain.unshift(n);
      for (const n of chain) {
        const b = h("button", { class: "od-crumb", type: "button", "data-testid": "open-crumb", title: n.path, onclick: () => pickFolder(n.folderId) }, n.name);
        dropTarget(b, n.folderId);
        segs.push(b, h("span", { class: "od-crumb-sep", "aria-hidden": "true" }, "/"));
      }
    }
    crumbs.replaceChildren(...segs);
    const total = lastLive.length;
    const shown = rows.filter((r) => r.dataset.kind === "program" && !r.classList.contains("deleted")).length;
    countEl.textContent = query
      ? `${shown} of ${total} program${total === 1 ? "" : "s"}`
      : `${total} program${total === 1 ? "" : "s"}${lastGone.length ? ` · ${lastGone.length} deleted` : ""}`;
  };
  /** Picks a folder's row ("" the root: nothing picked), from the breadcrumb. */
  const pickFolder = (id: string) => {
    if (query) {
      search.value = "";
      query = "";
      render();
    }
    if (id && collapsed.size) {
      // Its parents open, so its row is there.
      for (let n = folderNodes.get(folderNodes.get(id)?.folder?.parentId ?? ""); n && n.folderId; n = folderNodes.get(n.folder?.parentId ?? "")) collapsed.delete(n.folderId);
      prefs.set(collapsedKey(), JSON.stringify([...collapsed]));
      render();
    }
    showPrograms(id ? `f:${id}` : undefined);
    if (!id) {
      active = -1;
      paint();
    }
    list.focus({ preventScroll: true });
  };

  // --- the table: sortable column headers over the rows ---
  const sortBtns = new Map<SortKey, HTMLElement>();
  const th = (key: SortKey, label: string, cls: string) => {
    const b = h("button", { class: `od-th ${cls}`, type: "button", "data-testid": `open-sort-${key}`, onclick: () => setSort(key) }, h("span", {}, label), h("span", { class: "od-sort", "aria-hidden": "true" }));
    sortBtns.set(key, b);
    return b;
  };
  const thead = h("div", { class: "od-thead" }, th("name", "Name", "od-c-name"), th("arch", "Architecture", "od-c-arch"), th("date", "Imported", "od-c-date"), th("status", "Status", "od-c-status"), h("span", { class: "od-c-more" }));
  const paintSort = () => {
    for (const [k, b] of sortBtns) {
      const on = k === sort.key;
      b.classList.toggle("on", on);
      b.dataset.dir = on ? (sort.dir === 1 ? "asc" : "desc") : "";
      (b.lastElementChild as HTMLElement).textContent = on ? (sort.dir === 1 ? "▲" : "▼") : "";
      const name = (b.firstElementChild as HTMLElement).textContent;
      b.title = on ? `Sorted by ${name?.toLowerCase()}, ${sort.dir === 1 ? "ascending" : "descending"}: click to reverse` : `Sort by ${name?.toLowerCase()}`;
    }
  };
  const setSort = (key: SortKey) => {
    sort = sort.key === key ? { key, dir: sort.dir === 1 ? -1 : 1 } : { key, dir: key === "date" ? -1 : 1 };
    prefs.set(SORT_KEY, JSON.stringify(sort));
    paintSort();
    const k = rows[active]?.dataset.key;
    render();
    showPrograms(k);
  };
  paintSort();
  list.addEventListener("contextmenu", (e) => {
    // The empty space under the rows: the root's menu.
    if (e.target !== list && !(e.target as HTMLElement).classList.contains("od-empty")) return;
    const n = folderNodes.get("");
    if (!n || !foldersOn) return;
    e.preventDefault();
    showMenu(folderMenu(n), e.clientX, e.clientY, "Actions for the project");
  });
  list.addEventListener("click", (e) => {
    if (e.target === list && foldersOn) {
      active = -1;
      paint();
    }
  });
  const table = h("div", { class: "od-table" }, thead, list);

  // --- the import section: upload, the daemon host's files, a path, raw ---
  const intoLabel = h("span", { class: "od-into", "data-testid": "open-into" });
  const uploadBtn = h("button", { class: "btn primary", type: "button", "data-testid": "open-import", onclick: () => void importFile() }, icon("upload"), h("span", {}, "Choose file…"));
  const browseLabel = h("span", {}, "Browse daemon host…");
  const browseBtn = h("button", { class: "btn", type: "button", "data-testid": "open-browse", onclick: () => (browsing ? hideHost() : void browse()) }, icon("server"), browseLabel);
  const hostCrumb = h("div", { class: "od-host-path dim mono" });
  const hostList = h("div", { class: "od-host-list", role: "listbox", "aria-label": "Files on the daemon host", tabindex: "0", "data-testid": "open-host-list" });
  const hostPanel = h("div", { class: "od-host", hidden: true, "data-testid": "open-host" }, hostCrumb, hostList);
  const pathGo = h("button", {
    class: "btn",
    type: "button",
    "data-testid": "open-path-go",
    title: "Import the file at this path on the daemon's host",
    onclick: () => (path.value.trim() ? void doImport({ path: path.value.trim() }) : path.focus()),
    text: "Import",
  });
  path.id = "od-path";
  // Also import the libraries it needs (feature program-libraries), from these directories too.
  const libsBox = h("input", { type: "checkbox", "data-testid": "open-import-libraries" }) as HTMLInputElement;
  const libsPaths = h("input", {
    class: "path-input",
    placeholder: "more library directories on the daemon host, : separated (optional)",
    "aria-label": "Library search paths",
    spellcheck: "false",
    "data-testid": "open-library-paths",
    hidden: true,
  }) as HTMLInputElement;
  libsPaths.addEventListener("keydown", (e) => e.stopPropagation());
  try {
    libsBox.checked = prefs.get("revkit.open.libraries") === "1";
  } catch {
    /* default off */
  }
  libsPaths.hidden = !libsBox.checked;
  libsBox.addEventListener("change", () => {
    libsPaths.hidden = !libsBox.checked;
    prefs.set("revkit.open.libraries", libsBox.checked ? "1" : "0");
  });
  const libsRow = h(
    "div",
    { class: "od-libs", hidden: !libsOn },
    h("label", { class: "od-check", title: "The shared libraries it needs (ELF DT_NEEDED, PE import DLLs) that the project lacks: beside the file, on its runpath, on these directories, then the host's /lib and /usr/lib for a file on the daemon host (for a file inside an extracted root file system under --browse-root, that root's /lib, /usr/lib and ld.so.conf directories instead); two levels deep" }, libsBox, h("span", {}, "Also import the libraries it needs")),
    libsPaths,
  );
  const importView = h(
    "div",
    { class: "od-import", hidden: true, "data-testid": "open-import-view" },
    h("div", { class: "od-import-head" }, h("span", { class: "dim" }, "Import into"), intoLabel),
    h(
      "div",
      { class: "od-drop" },
      icon("upload", "od-drop-icon"),
      h("div", { class: "od-drop-text" }, h("strong", {}, "Drop a binary anywhere on this dialog"), h("span", { class: "dim" }, "ELF, PE, Mach-O, firmware images, archives and file system images")),
      h("div", { class: "od-drop-actions" }, uploadBtn, browseBtn),
    ),
    hostPanel,
    h("div", { class: "od-pathrow" }, h("label", { class: "od-label", for: "od-path" }, "Path on the daemon host"), h("div", { class: "od-pathline" }, path, pathGo)),
    libsRow,
    picked,
    rawBox,
  );
  const main = h("div", { class: "od-main", "data-grow": "" }, table, importView);

  // --- the details of what is picked ---
  const details = h("section", { class: "od-details", "aria-label": "Details", "data-testid": "open-details" });

  // --- the footer ---
  const importLabel = h("span", {}, "Import binary…");
  const importIcon = h("span", { class: "od-import-icon" }, icon("upload"));
  const importBtn = h("button", { class: "btn od-import-btn", type: "button", "data-testid": "open-import-binary", onclick: () => setView(view === "import" ? "programs" : "import") }, importIcon, importLabel);
  const importHint = h("span", { class: "od-hint od-hint-import" }, "Add a binary to this project");
  const openHint = h("span", { class: "od-hint od-hint-open" }, "Double-click a program to open it");
  const cancelBtn = h("button", { class: "btn", type: "button", "data-testid": "open-cancel", hidden: !!o.required, onclick: () => close(), text: "Cancel" });
  const goLabel = h("span", {}, "Open program");
  const goBtn = h("button", { class: "btn primary od-go", type: "button", "data-testid": "open-go", disabled: true, onclick: () => activate() }, goLabel, icon("enter", "od-go-key"));

  const box = h(
    "div",
    { class: "modal open od", role: "dialog", "aria-modal": "true", "aria-label": "Open program", "data-testid": "open-dialog", "data-view": "programs" },
    h("div", { class: "od-titlebar" }, h("h2", { class: "modal-title od-title" }, "Open program"), closeBtn),
    h("div", { class: "od-toolbar" }, projectBox, newFolderBtn, overflowBtn),
    h("div", { class: "od-crumbrow" }, crumbs, countEl),
    h("label", { class: "od-search" }, icon("search"), search),
    main,
    h("div", { class: "open-foot" }, status, fsBtn, skipBtn, progress.el),
    details,
    h("div", { class: "od-foot" }, h("div", { class: "od-foot-l" }, importBtn, importHint), h("div", { class: "od-foot-r" }, openHint, cancelBtn, goBtn)),
  );
  const backdrop = h("div", { class: "backdrop" }, box);
  backdrop.addEventListener("mousedown", (e) => {
    if (e.target === backdrop && !o.required) close();
  });
  backdrop.addEventListener("dragover", (e) => {
    if (!e.dataTransfer?.types.includes("Files")) return;
    e.preventDefault();
    box.classList.add("drop");
  });
  backdrop.addEventListener("dragleave", (e) => {
    if (!e.relatedTarget || !box.contains(e.relatedTarget as Node)) box.classList.remove("drop");
  });
  backdrop.addEventListener("drop", async (e) => {
    if (!e.dataTransfer?.types.includes("Files")) return;
    e.preventDefault();
    box.classList.remove("drop");
    const f = e.dataTransfer?.files?.[0];
    if (f) await doImport({ content: new Uint8Array(await f.arrayBuffer()), name: f.name.replace(/[^\w.+-]/g, "_") });
  });

  /** Shows the programs or the import section. */
  const setView = (v: "programs" | "import") => {
    if (v === "import") importInto = selectedFolder();
    view = v;
    box.dataset.view = v;
    table.hidden = v !== "programs";
    importView.hidden = v !== "import";
    details.hidden = v !== "programs";
    importHint.hidden = openHint.hidden = goBtn.hidden = v !== "programs";
    importIcon.replaceChildren(icon(v === "import" ? "back" : "upload"));
    importLabel.textContent = v === "import" ? "Back to programs" : "Import binary…";
    importBtn.title = v === "import" ? "Back to the project's programs (Esc)" : "Upload a file, pick one on the daemon host or type its path; raw firmware too";
    if (v === "import") {
      const into = importInto;
      intoLabel.textContent = `${projectName()}${into && into.folderId ? ` / ${into.path.replace(/^\//, "").split("/").join(" / ")}` : " /"}`;
      intoLabel.title = into?.path ?? "/";
      uploadBtn.focus();
    } else {
      list.focus({ preventScroll: true });
    }
    paint();
  };

  /** Opens the program picked (or restores it from the trash); a folder opens or closes. */
  const activate = () => {
    const row = rows[active];
    if (!row) return;
    if (row.dataset.kind === "program") {
      const p = programs.get(row.dataset.id ?? "");
      if (!p) return;
      if (p.deleted) void doRestore(p);
      else open(p.programId);
    } else if (row.dataset.kind === "folder") {
      toggleFolder(row.dataset.id ?? "");
    }
  };

  const paint = () => {
    rows.forEach((r, i) => {
      r.classList.toggle("active", i === active);
      r.setAttribute("aria-selected", String(i === active));
    });
    if (view === "programs") rows[active]?.scrollIntoView({ block: "nearest" });
    hostRows.forEach((r, i) => {
      r.classList.toggle("active", i === hostActive);
      r.setAttribute("aria-selected", String(i === hostActive));
    });
    if (browsing && view === "import") hostRows[hostActive]?.scrollIntoView({ block: "nearest" });
    paintCrumbs();
    paintDetails();
    const row = rows[active];
    const p = row?.dataset.kind === "program" ? programs.get(row.dataset.id ?? "") : undefined;
    goBtn.disabled = !p;
    goLabel.textContent = p?.deleted ? "Restore" : "Open program";
    goBtn.title = p ? (p.deleted ? `Restore ${p.name} (Enter)` : `Open ${p.name} (Enter)`) : "Pick a program to open";
    const f = foldersOn ? selectedFolder() : null;
    importHint.textContent = f?.folderId ? `Add a binary to ${f.path}` : "Add a binary to this project";
  };

  const size = (n: bigint) => sizeText(Number(n));
  /** Back to the programs from the daemon host's files. */
  const hideHost = () => {
    browsing = false;
    browseLabel.textContent = "Browse daemon host…";
    hostPanel.hidden = true;
    hostRows = [];
    paint();
  };
  /** Rows of the programs into the table, `keep` picked again if it is still there. */
  const showPrograms = (keep?: string) => {
    rows = programRows;
    const at = keep ? rows.findIndex((r) => r.dataset.key === keep) : -1;
    // The first program rather than a folder.
    active = at >= 0 ? at : rows.length ? Math.max(0, rows.findIndex((r) => r.dataset.kind === "program")) : -1;
    list.replaceChildren(...programView);
    paint();
  };
  const browse = async (dir?: string) => {
    browsing = true;
    browseLabel.textContent = "Hide host files";
    hostPanel.hidden = false;
    if (dir === undefined) {
      try {
        dir = localStorage.getItem(LAST_DIR) ?? "";
      } catch {
        dir = "";
      }
    }
    hostList.replaceChildren(h("div", { class: "od-empty dim", role: "none" }, "Loading…"));
    let r;
    const t0 = performance.now();
    try {
      r = await rk.projects.listHostFiles({ path: dir });
    } catch (e) {
      // A remembered directory that's gone or now outside the roots: start over.
      if (dir) return browse("");
      hostList.replaceChildren(h("div", { class: "od-empty error", role: "none" }, `Can't browse the daemon host: ${errText(e)}`));
      hostRows = [];
      return;
    }
    if (!browsing) return;
    try {
      localStorage.setItem(LAST_DIR, r.path);
    } catch {
      /* private window: just don't remember */
    }
    parentDir = r.parent;
    const items: HTMLElement[] = [];
    if (r.parent)
      items.push(
        h("div", { class: "open-row browse-row dir", role: "option", onclick: () => void browse(r.parent) },
          h("span", { class: "od-c-name" }, icon("back", "od-icon"), h("span", { class: "open-name" }, "..")), h("span", { class: "dim" }, "parent folder"), h("span")),
      );
    for (const e of r.entries)
      items.push(
        h(
          "div",
          {
            class: "open-row browse-row" + (e.directory ? " dir" : ""),
            role: "option",
            title: e.path,
            "data-testid": "browse-entry",
            onclick: () => (e.directory ? void browse(e.path) : void doImport({ path: e.path, name: e.name.replace(/[^\w.+-]/g, "_"), size: Number(e.size) })),
          },
          h("span", { class: "od-c-name" }, icon(e.directory ? "folder" : "file", "od-icon"), h("span", { class: "open-name" }, e.name)),
          h("span", { class: "dim" }, e.directory ? "folder" : size(e.size)),
          h("span", { class: "dim" }, e.modified ? dateText(Number(e.modified.seconds) * 1000) : ""),
        ),
      );
    if (r.truncated) items.push(h("div", { class: "od-empty dim", role: "none" }, "More files than can be listed; type the path below instead."));
    // How long the daemon took (a slow browse over a VPN is round trips; docs/known-issues.md).
    const ms = performance.now() - t0;
    hostCrumb.title = `${r.path}\n${r.entries.length} entries listed in ${ms.toFixed(0)} ms`;
    hostCrumb.dataset.ms = ms.toFixed(0);
    hostCrumb.replaceChildren(h("span", { class: "od-host-dir" }, r.path), h("span", { class: "browse-ms" }, ` · ${r.entries.length} in ${ms < 1000 ? `${ms.toFixed(0)} ms` : `${(ms / 1000).toFixed(1)} s`}`));
    hostList.replaceChildren(...(items.length ? items : [h("div", { class: "od-empty dim", role: "none" }, "Empty folder.")]));
    hostRows = items.filter((x) => x.classList.contains("open-row"));
    hostActive = 0;
    paint();
  };
  const printable = (e: KeyboardEvent) => e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey;
  const onDocKey = (e: KeyboardEvent) => {
    // A dialog or menu over this one (rename, confirm) owns the keyboard.
    if (overlayRoot().lastElementChild !== backdrop) return;
    const at = document.activeElement as HTMLElement | null;
    // The import section: Escape goes back to the programs; the arrows and Enter walk the daemon host's files.
    if (view === "import") {
      if (e.key === "Escape") return keyDone(e, () => setView("programs"));
      if (box.contains(at) && typing()) return;
      if ((e.key === "Enter" || e.key === " ") && at && box.contains(at) && at.matches("button, summary, input[type=checkbox], select")) return;
      if (!browsing || !hostRows.length) return;
      if (e.key === "ArrowDown") return keyDone(e, () => (hostActive = Math.min(hostRows.length - 1, hostActive + 1)));
      if (e.key === "ArrowUp") return keyDone(e, () => (hostActive = Math.max(0, hostActive - 1)));
      if (e.key === "Enter") return keyDone(e, () => hostRows[hostActive]?.click());
      if (e.key === "Backspace" && parentDir) return keyDone(e, () => void browse(parentDir));
      return;
    }
    // The search field: the arrows, Enter and Escape are the list's; the rest edits it.
    if (at === search) {
      if (e.key === "Escape") {
        if (search.value) return keyDone(e, () => {
          search.value = "";
          search.dispatchEvent(new Event("input"));
        });
        if (!o.required) close();
        return;
      }
      if (!["ArrowDown", "ArrowUp", "Enter", "PageDown", "PageUp"].includes(e.key)) return;
    } else if (at === projectSel || (box.contains(at) && typing())) {
      // In another field (the project) keys edit it.
      if (e.key === "Escape" && !o.required) close();
      return;
    } else {
      // Enter and Space on the dialog's own buttons press them; they aren't the list's.
      if ((e.key === "Enter" || e.key === " ") && at && box.contains(at) && at !== list && at.matches("button, summary, input[type=checkbox], select")) return;
      // Type to filter: a letter goes to the search.
      if (printable(e) && e.key !== " ") {
        e.preventDefault();
        e.stopPropagation();
        search.focus();
        search.value += e.key;
        search.dispatchEvent(new Event("input"));
        return;
      }
    }
    const row = rows[active];
    const info = row?.dataset.kind === "program" ? programs.get(row.dataset.id ?? "") : undefined;
    const node = row && row.dataset.kind === "folder" ? folderNodes.get(row.dataset.id ?? "") : undefined;
    const menuKey = e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey);
    if (at !== search && info && manage && (e.key === "F2" || e.key === "Delete" || menuKey)) {
      e.preventDefault();
      e.stopPropagation();
      if (e.key === "F2") void doRename(info);
      else if (e.key === "Delete") void doDelete(info);
      else showMenuAt(row, menuFor(info), `Actions for ${info.name}`);
      return;
    }
    if (at !== search && !row && foldersOn && menuKey) {
      const n = folderNodes.get("");
      if (n) return keyDone(e, () => showMenuAt(crumbs, folderMenu(n), "Actions for the project"));
    }
    if (node && at !== search) {
      if (menuKey || e.key === "F2" || e.key === "Delete") {
        e.preventDefault();
        e.stopPropagation();
        if (e.key === "F2") void doRenameFolder(node);
        else if (e.key === "Delete") void doDeleteFolder(node);
        else showMenuAt(row, folderMenu(node), `Actions for ${node.path}`);
        return;
      }
      const isOpen = !collapsed.has(node.folderId);
      if (e.key === "ArrowRight" && !isOpen) return keyDone(e, () => toggleFolder(node.folderId));
      if (e.key === "ArrowLeft" && isOpen) return keyDone(e, () => toggleFolder(node.folderId));
    }
    if (e.key === "ArrowLeft" && foldersOn && row && at !== search) {
      // To the folder above.
      const parent = row.dataset.parent;
      const up = parent ? rows.findIndex((r) => r.dataset.kind === "folder" && r.dataset.id === parent) : -1;
      if (up >= 0 && up !== active) return keyDone(e, () => (active = up));
    }
    const last = rows.length - 1;
    if (e.key === "Escape" && !o.required) close();
    else if (e.key === "Escape") return;
    else if (e.key === "ArrowDown") active = Math.min(last, active + 1);
    else if (e.key === "ArrowUp") active = Math.max(0, active - 1);
    else if (e.key === "PageDown") active = Math.min(last, Math.max(0, active) + 10);
    else if (e.key === "PageUp") active = Math.max(0, active - 10);
    else if (e.key === "Home" && at !== search) active = Math.min(0, last);
    else if (e.key === "End" && at !== search) active = last;
    else if (e.key === "Enter") activate();
    else return;
    e.preventDefault();
    e.stopPropagation();
    paint();
  };
  const keyDone = (e: KeyboardEvent, run: () => void) => {
    e.preventDefault();
    e.stopPropagation();
    run();
    paint();
  };
  document.addEventListener("keydown", onDocKey, true);
  overlayRoot().append(backdrop);

  // --- projects and programs ---
  const programs = new Map<string, ProgramInfo>();
  const doRename = async (p: ProgramInfo) => {
    try {
      if ((await renameProgram(rk, p)) !== null) await loadProjects();
    } catch (e) {
      busy(`Rename failed: ${errText(e)}`, true);
    }
  };
  const doDelete = async (p: ProgramInfo) => {
    try {
      if (await deleteProgram(rk, p, o.current)) await loadProjects();
    } catch (e) {
      busy(`Delete failed: ${errText(e)}`, true);
    }
  };
  const doRestore = async (p: ProgramInfo) => {
    const seq = p.deletedOrigin?.source.case === "asserted" ? p.deletedOrigin.source.value.seq : 0n;
    if (!seq) return busy(`Can't restore ${p.name}: no deletion to undo`, true);
    await undoProgramEdit(rk, p.programId, seq, "delete");
    await loadProjects();
  };
  const copySha = async (p: ProgramInfo) => {
    try {
      await navigator.clipboard.writeText(p.sha256);
      toast(`Copied the SHA-256 of ${p.name}`);
    } catch {
      // No clipboard (an insecure origin): the full value to copy by hand.
      void ask({ title: `SHA-256 of ${p.name}`, value: p.sha256, hint: "Ctrl+C to copy · Esc to close" });
    }
  };
  const menuFor = (p: ProgramInfo): MenuItem[] =>
    p.deleted
      ? [{ label: "Restore", keys: "Enter", testid: "menu-restore", run: () => void doRestore(p) }]
      : [
          { label: "Open", keys: "Enter", run: () => open(p.programId) },
          { label: "Rename…", keys: "F2", disabled: !manage, run: () => void doRename(p) },
          ...(foldersOn ? [{ label: "Move to…", testid: "menu-move-program", run: () => void doMoveTo({ programIds: [p.programId] }) }] : []),
          { label: "Copy SHA-256", testid: "menu-copy-sha", run: () => void copySha(p) },
          { label: "Delete…", keys: "Del", danger: true, disabled: !manage, run: () => void doDelete(p) },
          ...(archivesOn ? [{ label: "Export program…", separator: true, testid: "menu-export-program", run: () => void doExport({ program: p }) }] : []),
        ];

  // --- the status column (GetAnalysisStatus: cheap, no program is loaded for it) ---
  type Status = { kind: "ready" | "busy" | "error" | "here" | "deleted" | "unknown"; text: string; detail?: string };
  const statuses = new Map<string, Status>();
  const STATUS_RANK: Record<Status["kind"], number> = { here: 0, busy: 1, error: 2, ready: 3, unknown: 4, deleted: 5 };
  let statusTimer: ReturnType<typeof setTimeout> | undefined;
  const statusOf = (p: ProgramInfo): Status => {
    if (p.deleted) {
      const who = p.deletedOrigin?.source.case === "asserted" ? provText(p.deletedOrigin.source.value.provenance) : "";
      return { kind: "deleted", text: "Deleted", detail: `Deleted${who ? ` by ${who}` : ""}: Enter or Restore brings it back` };
    }
    const s = statuses.get(p.programId);
    if (s && (s.kind === "busy" || s.kind === "error")) return s;
    if (p.programId === o.current) return { kind: "here", text: "Open here", detail: "Open in this tab" };
    return s ?? { kind: "unknown", text: "" };
  };
  const statusCell = (p: ProgramInfo) => {
    const s = statusOf(p);
    return h(
      "span",
      { class: `od-c-status od-st-${s.kind}`, "data-status": s.kind, title: s.detail ?? s.text },
      h("span", { class: "od-dot", "aria-hidden": "true" }),
      h("span", { class: "od-st-text" }, s.text),
    );
  };
  const refreshStatuses = async () => {
    clearTimeout(statusTimer);
    const forProject = project;
    const ids = lastLive.slice(0, 200).map((p) => p.programId);
    let analyzing = false;
    let next = 0;
    const one = async () => {
      while (next < ids.length) {
        const id = ids[next++];
        try {
          const r = await rk.analysis.getAnalysisStatus({ programId: id });
          const job = r.jobs[0];
          let s: Status;
          if (job && (job.state === AnalysisState.RUNNING || job.state === AnalysisState.QUEUED)) {
            const pct = job.progress >= 0 ? ` ${Math.round(job.progress * 100)}%` : "";
            s = { kind: "busy", text: `Analyzing${pct || "…"}`, detail: `Analyzing${job.phase ? `: ${job.phase}` : "…"}` };
          } else if (!r.idle) {
            s = { kind: "busy", text: "Analyzing…", detail: "Analyzing in the background (parameters, types, Function ID)" };
          } else if (job && job.state === AnalysisState.FAILED) {
            s = { kind: "error", text: "Error", detail: `Analysis failed${job.message ? `: ${job.message}` : ""}` };
          } else {
            s = { kind: "ready", text: "Ready", detail: "Ready: analysis finished" };
          }
          analyzing ||= s.kind === "busy";
          statuses.set(id, s);
        } catch {
          statuses.delete(id);
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(6, ids.length) }, one));
    if (closed || forProject !== project) return;
    for (const r of programRows) {
      const p = r.dataset.kind === "program" ? programs.get(r.dataset.id ?? "") : undefined;
      const cell = r.querySelector(".od-c-status");
      if (p && cell) cell.replaceWith(statusCell(p));
    }
    paintDetails();
    if (analyzing) statusTimer = setTimeout(() => void refreshStatuses(), 2000);
  };

  // --- the details panel ---
  const detail = (label: string, value: Node | string, opts: { mono?: boolean; wide?: boolean; testid?: string; title?: string } = {}) => [
    h("dt", { class: opts.wide ? "od-wide-dt" : "" }, label),
    h("dd", { class: (opts.mono ? "mono " : "") + (opts.wide ? "od-wide" : ""), "data-testid": opts.testid, title: opts.title ?? (typeof value === "string" ? value : undefined) }, value),
  ];
  // Each program's libraries in a line (ListProgramLibraries), once asked.
  const libSummaries = new Map<string, string>();
  const loadLibSummary = async (id: string) => {
    libSummaries.set(id, "…");
    try {
      libSummaries.set(id, librariesSummary(await rk.projects.listProgramLibraries({ programId: id })));
    } catch (e) {
      libSummaries.set(id, errText(e));
    }
    if (!closed) paintDetails();
  };
  // Each program's build info in a line (GetBuildInfo), once asked.
  const buildSummaries = new Map<string, string>();
  const loadBuildSummary = async (id: string) => {
    buildSummaries.set(id, "…");
    try {
      buildSummaries.set(id, buildInfoSummary(await rk.queries.getBuildInfo({ programId: id })));
    } catch (e) {
      buildSummaries.set(id, errText(e));
    }
    if (!closed) paintDetails();
  };
  // Each Mach-O's code signature in a line (GetProgramSummary), once asked.
  const signatureSummaries = new Map<string, string>();
  const loadSignatureSummary = async (id: string) => {
    signatureSummaries.set(id, "…");
    try {
      const m = (await rk.projects.getProgramSummary({ programId: id })).summary?.macho;
      signatureSummaries.set(id, m?.codeSignature ? signatureSummary(m.codeSignature) : "not signed");
    } catch (e) {
      signatureSummaries.set(id, errText(e));
    }
    if (!closed) paintDetails();
  };
  const paintDetails = () => {
    if (view !== "programs") return;
    const row = rows[active];
    const kind = row?.dataset.kind;
    const p = kind === "program" ? programs.get(row!.dataset.id ?? "") : undefined;
    const n = kind === "folder" ? folderNodes.get(row!.dataset.id ?? "") : undefined;
    const items: HTMLElement[] = [];
    let title = "Project";
    if (p) {
      title = "Program details";
      const where = `${projectName()}${p.folderPath && p.folderPath !== "/" ? ` / ${p.folderPath.replace(/^\//, "").split("/").join(" / ")}` : ""}`;
      const sha = h(
        "button",
        { class: "od-copy mono", type: "button", "data-testid": "open-copy-sha", title: `SHA-256 ${p.sha256}\nClick to copy`, onclick: () => void copySha(p) },
        h("span", {}, p.sha256.slice(0, 12)),
        icon("copy"),
      );
      const st = statusOf(p);
      items.push(
        ...detail("Format", formatText(p.format), { testid: "open-detail-format" }),
        ...detail("Fingerprint", sha, { title: p.sha256 }),
        ...detail("Language", p.languageId, { mono: true, testid: "open-detail-language" }),
        ...detail("Location", where, { testid: "open-detail-location" }),
      );
      if (p.compilerSpecId) items.push(...detail("Compiler", p.compilerSpecId, { mono: true, testid: "open-detail-compiler" }));
      items.push(...detail("Imported", dateTimeText(Number(p.importedAt?.seconds ?? 0n) * 1000) || "—", { testid: "open-detail-imported" }));
      if (p.fileSize) items.push(...detail("Size", `${sizeText(Number(p.fileSize))}${p.fileSize >= 1024n ? ` (${Number(p.fileSize).toLocaleString("en-US")} bytes)` : ""}`, { testid: "open-detail-size" }));
      // Status is the table's column (its detail in the cell's title); with libraries their line takes its place.
      if (st.text && !libsOn) items.push(...detail("Status", st.detail ?? st.text, { testid: "open-detail-status" }));
      if (p.containerPath) items.push(...detail("From", p.containerPath, { mono: true, wide: true, testid: "open-detail-container" }));
      if (p.machoSlices.length > 1) {
        // A universal Mach-O: this slice, and the others to import.
        const others = p.machoSlices.filter((a) => a !== p.machoSlice);
        const line = h("span", { class: "od-libs-line" }, h("span", { class: "mono" }, `${p.machoSlice} (of ${p.machoSlices.join(", ")})`));
        if (machoOn && !p.deleted)
          for (const a of others)
            line.append(h("button", { class: "btn small", type: "button", "data-testid": `open-import-slice-${a}`, title: `Import the file's ${a} slice as another program`, onclick: () => void importSlice(project, p, a), text: `Import ${a}` }));
        items.push(...detail("Slice", line, { testid: "open-detail-slice" }));
      }
      // A packer's archive in the file (api_minor 96).
      if (p.payloadFormat) {
        const line = h("span", { class: "od-libs-line" }, h("span", {}, payloadText(p.payloadFormat)));
        if (fsOn && !p.deleted)
          line.append(h("button", { class: "btn small", type: "button", "data-testid": "open-payload", title: "Browse what is packed in it, and import or extract it", onclick: () => void openPayload(project, p.programId), text: "Open as file system" }));
        items.push(...detail("Packed", line, { testid: "open-detail-packed" }));
      }
      // A .NET assembly (api_minor 94): what its CLR header says, and that IL isn't analysed as machine code.
      if (p.dotnet)
        items.push(
          ...detail(".NET", p.dotnet.description + (p.dotnet.codeAnalysisSkipped ? "; imported without code analysis (its code is IL)" : ""), {
            testid: "open-detail-dotnet",
          }),
        );
      if (libsOn && !p.deleted) {
        const known = libSummaries.get(p.programId);
        const text = h("span", { class: "od-libs-text" }, known ?? "…");
        if (known === undefined) void loadLibSummary(p.programId);
        const btn = h("button", {
          class: "btn small",
          type: "button",
          "data-testid": "open-libraries",
          title: "Its shared libraries, the programs they are, and where its imports go",
          onclick: () =>
            showLibrariesDialog(rk, {
              programId: p.programId,
              programName: p.name,
              openProgram: (id, address) => open(id, address),
              importLibraries: () => {
                libsBox.checked = true;
                libsPaths.hidden = false;
                setView("import");
              },
            }),
          text: "Libraries…",
        });
        items.push(...detail("Libraries", h("span", { class: "od-libs-line" }, text, btn), { testid: "open-detail-libraries" }));
      }
      // A Mach-O's code signature: read, not verified.
      if (appleOn && !p.deleted && p.format === "macho") {
        const known = signatureSummaries.get(p.programId);
        if (known === undefined) void loadSignatureSummary(p.programId);
        const btn = h("button", { class: "btn small", type: "button", "data-testid": "open-signature", title: "Its code signature and entitlements, as the file says (not verified)", onclick: () => void showCodeSignatureDialog(rk, { programId: p.programId, programName: p.name }), text: "Signature…" });
        items.push(...detail("Signed", h("span", { class: "od-libs-line" }, h("span", { class: "od-libs-text" }, known ?? "…"), btn), { testid: "open-detail-signature" }));
      }
      // Go's or Rust's build metadata, when the file has some (nothing shown otherwise).
      const known = buildInfoOn && !p.deleted ? buildSummaries.get(p.programId) : "none";
      if (known === undefined) void loadBuildSummary(p.programId);
      else if (known !== "none" && known !== "…") {
        const btn = h("button", { class: "btn small", type: "button", "data-testid": "open-build-info", title: "Go modules, Rust crates and the toolchain, as the file says", onclick: () => showBuildInfoDialog(rk, { programId: p.programId, programName: p.name }), text: "Build info…" });
        items.push(...detail("Built with", h("span", { class: "od-libs-line" }, h("span", { class: "od-libs-text" }, known), btn), { testid: "open-detail-build" }));
      }
      if (p.deleted) {
        const restoreBtn = h("button", { class: "btn small", type: "button", "data-testid": "open-restore", onclick: () => void doRestore(p), text: "Restore" });
        items.push(...detail("Deleted", h("span", { class: "od-deleted" }, h("span", {}, st.detail?.split(":")[0] ?? "Deleted"), restoreBtn), { wide: true }));
      }
    } else if (n) {
      title = "Folder details";
      items.push(
        ...detail("Path", n.path, { mono: true }),
        ...detail("Contains", `${n.programs.length} program${n.programs.length === 1 ? "" : "s"}, ${n.folders.length} folder${n.folders.length === 1 ? "" : "s"}`),
        ...detail("Project", projectName()),
        ...detail("Folder ID", n.folderId, { mono: true }),
      );
    } else {
      const info = projectInfos.get(project);
      title = "Project";
      items.push(
        ...detail("Name", projectName()),
        ...detail("Programs", `${lastLive.length}${lastGone.length ? ` (and ${lastGone.length} deleted)` : ""}`),
      );
      if (info?.path) items.push(...detail("Database", info.path, { mono: true, wide: true }));
      if (!lastLive.length) items.push(...detail("Start", "Import binary… below adds one, or drop a file on this dialog", { wide: true }));
    }
    details.replaceChildren(h("div", { class: "od-details-title" }, title), h("dl", { class: "od-fields" }, ...items));
    details.dataset.kind = p ? "program" : n ? "folder" : "project";
  };

  const programRow = (p: ProgramInfo, level: number, parent: string | undefined, flat: boolean) => {
    // For the mouse; the keyboard has F2, Delete, the menu key and Shift+F10
    // (a button inside an option would be nested interactive content).
    const more = h(
      "span",
      { class: "od-c-more open-more", title: "Actions (right-click, F2 rename, Delete, Shift+F10)", "aria-hidden": "true", "data-testid": "open-row-menu", hidden: !manage && !foldersOn && !archivesOn },
      icon("more"),
    );
    more.addEventListener("click", (e) => {
      e.stopPropagation();
      active = rows.indexOf(row);
      paint();
      showMenuAt(more, menuFor(p), `Actions for ${p.name}`);
    });
    const inTree = foldersOn;
    const imported = Number(p.importedAt?.seconds ?? 0n) * 1000;
    const row = h(
      "div",
      {
        class: "open-row od-row" + (p.deleted ? " deleted" : "") + (p.programId === o.current ? " current" : ""),
        role: inTree ? "treeitem" : "option",
        ...(inTree ? { "aria-level": String(level) } : {}),
        "data-id": p.programId,
        "data-key": `p:${p.programId}`,
        "data-kind": "program",
        ...(parent !== undefined ? { "data-parent": parent } : {}),
        "data-testid": "open-row",
        title: p.programId + (p.folderPath && p.folderPath !== "/" ? ` in ${p.folderPath}` : ""),
        onclick: () => {
          active = rows.indexOf(row);
          paint();
        },
        ondblclick: () => (p.deleted ? void doRestore(p) : open(p.programId)),
      },
      h(
        "span",
        { class: "od-c-name" },
        h("span", { class: "od-indent", style: `width:${(level - 1) * 18 + (foldersOn && !flat ? 18 : 0)}px` }),
        icon("file", "od-icon"),
        h("span", { class: "open-name" }, p.name),
        flat && p.folderPath && p.folderPath !== "/" ? h("span", { class: "od-where" }, p.folderPath) : null,
      ),
      h("span", { class: "od-c-arch", title: p.languageId }, archText(p.languageId)),
      h("span", { class: "od-c-date", title: dateTimeText(imported) }, dateText(imported)),
      statusCell(p),
      more,
    );
    row.addEventListener("contextmenu", (e) => {
      if (!manage && !foldersOn && !archivesOn) return;
      e.preventDefault();
      active = rows.indexOf(row);
      paint();
      showMenu(menuFor(p), e.clientX, e.clientY, `Actions for ${p.name}`);
    });
    if (foldersOn && !p.deleted) draggable(row, { programIds: [p.programId] });
    return row;
  };
  // --- the tree (feature "project-folders") ---
  const folderNodes = new Map<string, FolderNode>();
  let tree: FolderNode | undefined;
  let lastLive: ProgramInfo[] = [];
  let lastGone: ProgramInfo[] = [];
  let programRows: HTMLElement[] = [];
  const collapsedKey = () => `revkit.open.collapsed.${project}`;
  let collapsed = new Set<string>();
  const loadCollapsed = () => {
    try {
      collapsed = new Set(JSON.parse(prefs.get(collapsedKey()) ?? "[]") as string[]);
    } catch {
      collapsed = new Set();
    }
  };
  const toggleFolder = (id: string, open?: boolean) => {
    if (!id) return;
    const now = !collapsed.has(id);
    if (open === now) return;
    if (now) collapsed.add(id);
    else collapsed.delete(id);
    prefs.set(collapsedKey(), JSON.stringify([...collapsed]));
    const key = rows[active]?.dataset.key;
    render();
    showPrograms(key);
  };
  /** The folder an import, a new folder or an export means: the row picked, or the folder of the program picked. */
  const selectedFolder = (): { folderId: string; path: string } | null => {
    if (!foldersOn || !tree) return null;
    const row = rows[active];
    if (!row) return { folderId: "", path: "/" };
    const id = row.dataset.kind === "program" ? (row.dataset.parent ?? programs.get(row.dataset.id ?? "")?.folderId ?? "") : (row.dataset.id ?? "");
    const n = folderNodes.get(id);
    return n ? { folderId: n.folderId, path: n.path } : { folderId: "", path: "/" };
  };
  const selectedPrograms = (): ProgramInfo[] => {
    const row = rows[active];
    const p = row?.dataset.kind === "program" ? programs.get(row.dataset.id ?? "") : undefined;
    return p && !p.deleted ? [p] : [];
  };
  const reload = async (keep?: string) => {
    await loadPrograms(keep);
  };
  // Undo for a folder edit's toast: its assertions, retracted by project.
  const undoAction = (seqs: bigint[], what: string) =>
    seqs.length
      ? {
          action: {
            label: "Undo",
            run: () =>
              void (async () => {
                try {
                  await undoFolderEdit(rk, project, seqs, userProvenance(`undo ${what}`));
                  toast(`Undone: ${what}`);
                  await reload(rows[active]?.dataset.key);
                } catch (e) {
                  toast(errText(e), { kind: "error" });
                }
              })(),
          },
        }
      : {};
  const nameRule = (v: string) =>
    !v.trim() ? "A name, please" : /[\/\x00-\x1f\x7f]/.test(v) ? "No / or control characters" : v.trim() === "." || v.trim() === ".." ? "Not . or .." : v.length > 200 ? "At most 200 characters" : null;
  const doNewFolder = async (parent: string) => {
    const where = folderNodes.get(parent)?.path ?? "/";
    const name = await ask({ title: `New folder in ${where}`, placeholder: "folder name", hint: "Enter to create · Esc to cancel", validate: nameRule });
    if (name === null) return;
    try {
      const r = await rk.projects.createFolder({ projectId: project, parentId: parent, name: name.trim(), provenance: userProvenance(`new folder ${name.trim()}`) });
      if (parent) collapsed.delete(parent);
      toast(`Created ${r.folder?.path ?? name}`, undoAction(r.assertion ? [r.assertion.seq] : [], `create ${r.folder?.path ?? name}`));
      await reload(r.folder ? `f:${r.folder.folderId}` : undefined);
    } catch (e) {
      busy(`Can't create the folder: ${errText(e)}`, true);
    }
  };
  const doRenameFolder = async (n: FolderNode) => {
    if (!n.folderId) return;
    const name = await ask({ title: `Rename folder ${n.path}`, value: n.name, hint: "Enter to rename · Esc to cancel", validate: nameRule });
    if (name === null || name.trim() === n.name) return;
    try {
      const r = await rk.projects.renameFolder({ projectId: project, folderId: n.folderId, name: name.trim(), provenance: userProvenance(`rename folder ${n.path}`) });
      toast(`Renamed ${n.path} to ${r.folder?.path ?? name}`, undoAction(r.assertion ? [r.assertion.seq] : [], `rename of ${n.path}`));
      await reload(`f:${n.folderId}`);
    } catch (e) {
      busy(`Can't rename ${n.path}: ${errText(e)}`, true);
    }
  };
  const doDeleteFolder = async (n: FolderNode) => {
    if (!n.folderId) return;
    if (n.folders.length || n.programs.length) return busy(`${n.path} isn't empty: move or delete what is in it first.`, "hint");
    try {
      const r = await rk.projects.deleteFolder({ projectId: project, folderId: n.folderId, provenance: userProvenance(`delete folder ${n.path}`) });
      toast(`Deleted ${n.path}`, { ms: 8000, ...undoAction(r.assertion ? [r.assertion.seq] : [], `delete ${n.path}`) });
      const parent = folderNodes.get(n.folderId)?.folder?.parentId ?? "";
      await reload(parent ? `f:${parent}` : undefined);
    } catch (e) {
      busy(`Can't delete ${n.path}: ${errText(e)}`, true);
    }
  };
  const doMove = async (dest: string, items: { programIds?: string[]; folderIds?: string[] }) => {
    const label = items.programIds?.length ? programs.get(items.programIds[0])?.name ?? "the program" : folderNodes.get(items.folderIds?.[0] ?? "")?.path ?? "the folder";
    const to = folderNodes.get(dest)?.path ?? "/";
    try {
      const r = await rk.projects.moveToFolder({
        projectId: project, folderId: dest, programIds: items.programIds ?? [], folderIds: items.folderIds ?? [], provenance: userProvenance(`move ${label} to ${to}`),
      });
      if (dest) collapsed.delete(dest);
      if (dest) prefs.set(collapsedKey(), JSON.stringify([...collapsed]));
      if (r.assertions.length) toast(`Moved ${label} to ${to}`, undoAction(r.assertions.map((a) => a.seq), `move of ${label}`));
      await reload(items.programIds?.length ? `p:${items.programIds[0]}` : `f:${items.folderIds?.[0]}`);
    } catch (e) {
      busy(`Can't move ${label}: ${errText(e)}`, true);
    }
  };
  /** Move to…: a folder chooser (not the moved folder or below it). */
  const doMoveTo = async (items: { programIds?: string[]; folderIds?: string[] }) => {
    if (!tree) return;
    const moving = items.folderIds?.[0];
    const targets = walkFolders(tree, true).filter((n) => !moving || !folderWithin(tree!, n.folderId, moving));
    const here = moving ? folderNodes.get(moving)?.folder?.parentId ?? "" : programs.get(items.programIds?.[0] ?? "")?.folderId ?? "";
    const dest = await choose(
      "Move to folder",
      targets.map((n) => ({ label: n.folderId ? n.path : "/ (the project's root)", value: n.folderId, current: n.folderId === here })),
      "↑↓ select · Enter move · Esc cancel",
    );
    if (dest === null || dest === here) return;
    await doMove(dest, items);
  };
  const doExport = async (scope?: { folder?: FolderNode; program?: ProgramInfo }) => {
    const f = scope?.folder ?? (scope?.program ? undefined : (() => {
      const s = selectedFolder();
      return s?.folderId ? folderNodes.get(s.folderId) : undefined;
    })());
    const progs = scope?.program ? [scope.program] : scope?.folder ? [] : selectedPrograms();
    await exportProjectDialog(rk, {
      projectId: project,
      projectName: projectName(),
      programs: progs.map((p) => ({ programId: p.programId, name: p.name })),
      folder: f ? { folderId: f.folderId, path: f.path } : undefined,
    });
  };
  const doImportProject = async () => {
    const f = selectedFolder();
    await importProjectDialog(rk, {
      projectId: project,
      folder: f ?? undefined,
      pauseStreams: o.pauseStreams,
      onImported: async (pid, first) => {
        if (pid !== project) {
          project = pid;
          prefs.set(LAST_PROJECT, project);
        }
        await loadProjects();
        if (first) busy(`Imported. Pick a program to open it.`, "hint");
      },
    });
  };
  const folderMenu = (n: FolderNode): MenuItem[] => {
    const root = n.folderId === "";
    const items: MenuItem[] = [];
    if (!root) items.push({ label: collapsed.has(n.folderId) ? "Expand" : "Collapse", keys: "Enter", run: () => toggleFolder(n.folderId) });
    items.push({ label: "New folder…", testid: "menu-new-folder", run: () => void doNewFolder(n.folderId) });
    if (!root) {
      items.push(
        { label: "Rename…", keys: "F2", testid: "menu-rename-folder", run: () => void doRenameFolder(n) },
        { label: "Move to…", testid: "menu-move-folder", run: () => void doMoveTo({ folderIds: [n.folderId] }) },
        { label: "Delete", keys: "Del", danger: true, disabled: n.folders.length > 0 || n.programs.length > 0, testid: "menu-delete-folder", run: () => void doDeleteFolder(n) },
      );
    }
    if (archivesOn) {
      items.push({ label: root ? "Export project…" : "Export folder…", separator: true, testid: "menu-export", run: () => void doExport(root ? {} : { folder: n }) });
      if (root) items.push({ label: "Import project…", testid: "menu-import-project", run: () => void doImportProject() });
    }
    return items;
  };
  // Drag and drop inside the tree (a type of our own, so a file dropped on
  // the dialog still imports).
  const DRAG = "application/x-revkit-tree";
  const draggable = (row: HTMLElement, item: { programIds?: string[]; folderIds?: string[] }) => {
    row.draggable = true;
    row.addEventListener("dragstart", (e) => {
      e.dataTransfer?.setData(DRAG, JSON.stringify(item));
      if (e.dataTransfer) e.dataTransfer.effectAllowed = "move";
      row.classList.add("dragging");
    });
    row.addEventListener("dragend", () => row.classList.remove("dragging"));
  };
  const dropTarget = (row: HTMLElement, folderId: string) => {
    row.addEventListener("dragover", (e) => {
      if (!e.dataTransfer?.types.includes(DRAG)) return;
      e.preventDefault();
      e.stopPropagation();
      e.dataTransfer.dropEffect = "move";
      row.classList.add("drop-target");
    });
    row.addEventListener("dragleave", () => row.classList.remove("drop-target"));
    row.addEventListener("drop", (e) => {
      if (!e.dataTransfer?.types.includes(DRAG)) return;
      e.preventDefault();
      e.stopPropagation();
      row.classList.remove("drop-target");
      try {
        const item = JSON.parse(e.dataTransfer.getData(DRAG)) as { programIds?: string[]; folderIds?: string[] };
        const moving = item.folderIds?.[0];
        if (moving && tree && folderWithin(tree, folderId, moving)) return busy("A folder can't go into itself or a folder below it.", "hint");
        void doMove(folderId, item);
      } catch {
        /* not ours */
      }
    });
  };
  const folderRow = (n: FolderNode, level: number) => {
    const isOpen = !collapsed.has(n.folderId);
    const caret = h("span", { class: "od-caret" + (isOpen ? " open" : ""), "aria-hidden": "true" }, icon("chevron"));
    caret.addEventListener("click", (e) => {
      e.stopPropagation();
      active = rows.indexOf(row);
      toggleFolder(n.folderId);
    });
    caret.addEventListener("dblclick", (e) => e.stopPropagation());
    const more = h("span", { class: "od-c-more open-more", title: "Actions (right-click, F2 rename, Delete, Shift+F10)", "aria-hidden": "true", "data-testid": "open-folder-menu" }, icon("more"));
    const count = n.programs.length + n.folders.length;
    const row = h(
      "div",
      {
        class: "open-row od-row open-folder",
        role: "treeitem",
        "aria-level": String(level),
        "aria-expanded": String(isOpen),
        "data-kind": "folder",
        "data-id": n.folderId,
        "data-key": `f:${n.folderId}`,
        "data-parent": n.folder?.parentId ?? "",
        "data-path": n.path,
        "data-testid": "open-folder",
        title: n.path,
        onclick: () => {
          active = rows.indexOf(row);
          paint();
        },
        ondblclick: () => toggleFolder(n.folderId),
      },
      h("span", { class: "od-c-name" }, h("span", { class: "od-indent", style: `width:${(level - 1) * 18}px` }), caret, icon(isOpen ? "folder-open" : "folder", "od-icon od-folder-icon"), h("span", { class: "open-name" }, n.name)),
      h("span", { class: "od-c-arch dim" }, count ? `${count} item${count === 1 ? "" : "s"}` : "empty"),
      h("span", { class: "od-c-date" }),
      h("span", { class: "od-c-status" }),
      more,
    );
    more.addEventListener("click", (e) => {
      e.stopPropagation();
      active = rows.indexOf(row);
      paint();
      showMenuAt(more, folderMenu(n), `Actions for ${n.path}`);
    });
    row.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      active = rows.indexOf(row);
      paint();
      showMenu(folderMenu(n), e.clientX, e.clientY, `Actions for ${n.path}`);
    });
    draggable(row, { folderIds: [n.folderId] });
    dropTarget(row, n.folderId);
    return row;
  };
  const sortInfo = (p: ProgramInfo) => ({
    name: p.name,
    languageId: p.languageId,
    format: p.format,
    folderPath: p.folderPath,
    importedMs: Number(p.importedAt?.seconds ?? 0n) * 1000,
    status: String(STATUS_RANK[statusOf(p).kind]),
  });
  const sorted = (ps: ProgramInfo[]) => [...ps].sort((a, b) => comparePrograms(sortInfo(a), sortInfo(b), sort));
  // The rows: the tree (folders first, each level sorted), or the search's matches flat.
  const render = () => {
    const items: HTMLElement[] = [];
    if (query) {
      for (const p of sorted(lastLive.filter((x) => matchesQuery(sortInfo(x), query)))) items.push(programRow(p, 1, p.folderId, true));
    } else if (tree) {
      const walk = (n: FolderNode, level: number) => {
        for (const f of [...n.folders].sort((a, b) => compareFolders(a.name, b.name, sort))) {
          items.push(folderRow(f, level));
          if (!collapsed.has(f.folderId)) walk(f, level + 1);
        }
        for (const p of sorted(n.programs)) items.push(programRow(p, level, n.folderId, false));
      };
      walk(tree, 1);
    } else {
      items.push(...sorted(lastLive).map((p) => programRow(p, 1, undefined, false)));
    }
    const gone = sorted(query ? lastGone.filter((x) => matchesQuery(sortInfo(x), query)) : lastGone).map((p) => programRow(p, 1, undefined, true));
    programRows = [...items, ...gone];
    const empty = (text: string, hint?: string) =>
      h("div", { class: "od-empty", role: "none" }, h("div", { class: "od-empty-title" }, text), hint ? h("div", { class: "dim" }, hint) : null);
    programView = [...items, ...(gone.length ? [h("div", { class: "open-section", role: "none" }, `Deleted (${gone.length})`)] : []), ...gone];
    if (!items.length) {
      const e = query
        ? empty(`No programs match “${query}”.`, "Search looks at names, architectures, formats and folders. Esc clears it.")
        : lastLive.length || tree?.folders.length
          ? empty("This folder is empty.")
          : empty(showDeleted ? "Nothing deleted, and no programs yet." : "No programs yet.", "Import binary… below adds one, or drop a file anywhere on this dialog.");
      programView.unshift(e);
    }
    if (tree && !lastLive.length && tree.folders.length && !query) programView.push(h("div", { class: "od-empty dim", role: "none" }, "No programs yet. Import one below."));
  };
  const loadPrograms = async (keep?: string) => {
    try {
      const r = await rk.projects.listPrograms({ projectId: project, includeDeleted: showDeleted });
      programs.clear();
      for (const p of r.programs) programs.set(p.programId, p);
      lastLive = r.programs.filter((p) => !p.deleted);
      lastGone = r.programs.filter((p) => p.deleted);
      loadCollapsed();
      tree = foldersOn ? buildProjectTree({ folders: r.folders, programs: lastLive }) : undefined;
      folderNodes.clear();
      if (tree) for (const n of walkFolders(tree, true)) folderNodes.set(n.folderId, n);
      render();
      showPrograms(keep);
      void refreshStatuses();
    } catch (e) {
      programView = [h("div", { class: "od-empty error", role: "none" }, `Can't list ${project}'s programs: ${errText(e)}`)];
      programRows = [];
      showPrograms();
    }
  };
  const NEW_PROJECT = "\u0000new";
  const loadProjects = async () => {
    try {
      const { projects } = await rk.projects.listProjects({});
      projectInfos.clear();
      for (const p of projects) projectInfos.set(p.projectId, p);
      if (!projects.some((p) => p.projectId === project)) project = projects.find((p) => p.open)?.projectId ?? projects[0]?.projectId ?? "default";
      projectSel.replaceChildren(
        ...projects.map((p) =>
          h("option", { value: p.projectId, selected: p.projectId === project }, `${p.name}${p.name !== p.projectId ? ` (${p.projectId})` : ""} · ${p.programCount} program${p.programCount === 1 ? "" : "s"}${p.open ? "" : " · closed"}`),
        ),
        h("option", { value: NEW_PROJECT }, "New project…"),
      );
      projectSel.value = project;
    } catch (e) {
      programView = [h("div", { class: "od-empty error", role: "none" }, `Can't reach the daemon: ${errText(e)}`)];
      programRows = [];
      showPrograms();
      return;
    }
    await loadPrograms(rows[active]?.dataset.key);
  };
  const switchTo = async (id: string) => {
    project = id;
    prefs.set(LAST_PROJECT, project);
    statuses.clear();
    if (query) {
      search.value = "";
      query = "";
    }
    busy("");
    await loadProjects();
  };
  const newProject = async () => {
    const name = await ask({ title: "New project", placeholder: "name (a fact database on the daemon)", validate: (v) => (/^[\w.-]+$/.test(v.trim()) ? null : "Letters, digits, . _ - only") });
    if (name === null) return;
    try {
      const r = await rk.projects.openProject({ target: { case: "path", value: name.trim() }, createIfMissing: true, name: name.trim() });
      await switchTo(r.project?.projectId ?? project);
    } catch (e) {
      busy(`Can't create the project: ${errText(e)}`, true);
    }
  };
  projectSel.addEventListener("change", async () => {
    if (projectSel.value === NEW_PROJECT) {
      projectSel.value = project;
      return void newProject();
    }
    const id = projectSel.value;
    try {
      await rk.projects.openProject({ target: { case: "projectId", value: id } });
    } catch (e) {
      projectSel.value = project;
      return busy(`Can't open ${id}: ${errText(e)}`, true);
    }
    await switchTo(id);
  });
  // The program list takes the focus (arrows, Enter, type to search; the keys work wherever it is).
  list.tabIndex = 0;
  showPrograms();
  if (o.focusProjects) projectSel.focus();
  else list.focus({ preventScroll: true });
  projectsReady = loadProjects().catch(() => {});
  if (o.startImport) {
    setView("import");
    // Into the folder of the program this tab shows, once the tree is read.
    void projectsReady.then(() => {
      if (closed || view !== "import" || importing) return;
      const at = o.current ? rows.findIndex((r) => r.dataset.kind === "program" && r.dataset.id === o.current) : -1;
      if (at >= 0) active = at;
      setView("import");
    });
  }
}
