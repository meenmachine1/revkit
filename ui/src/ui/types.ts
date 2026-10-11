// Types: the program's named types (FindTypes: debug info, DefineType
// assertions) with a search, each shown field by field (GetTypes), and an
// editor for structs, unions, enums and typedefs. Saving defines the new
// version and binds the name to it (DefineType + BindTypeName, one
// request with user provenance), so every use of the type (prototypes,
// globals, variables, other types) shows the edit, in every tab, and one
// undo restores the previous version. "Apply" retypes the selected
// variable, parameter, global or return value to the type (or a pointer to
// it).
//
// The editor never lays a type out itself: the draft is C (data/cgen.ts)
// the daemon parses and lays out for the program's target (ParseC), as the
// user edits. Structs keep explicit offsets (Ghidra's unpacked editing:
// insert at an offset, delete leaving undefined filler, grow and shrink,
// bitfields at byte:bit) or follow C's rules (natural, packed, pack(N)),
// with an alignment; a field's type is any C spelling (function pointers
// too) or member declarations, which become fields. "Edit in C" edits the
// definition as text. Duplicate and rename make new definitions (rename
// also retracts the old name's binding). "Import header…" opens the
// header import (headerimport.ts).
//
// Without a search the list is a category tree (feature find-types-tree):
// by source (the program's own types: debug info and defined ones; the
// library archive's), then kind, then, for kinds with many types, initial
// letter, then namespace ("std::"). Branches load when opened, a page at a
// time (FindTypes name_prefix, summary_only), and the list draws only the
// rows in view, so a library of thousands of types stays fast. A search
// lists matches flat, best first.
//
// With a daemon that files types in categories (feature "type-archive"),
// the tree is by folder (the default; "Kinds" is the tree above): the
// program's types under their categories (debug info files them under the
// header that declared them, a header import under the header's name),
// those with none at the top, the library archive by kind. Dragging a type
// onto a folder, or "Move to category…", files it there (SetTypeCategory,
// one undo step). "Export archive…" and "Import archive…" carry types
// between programs as a C header plus a JSON sidecar (typearchive.ts,
// headerimport.ts).
//
// With project-wide types (feature "project-types", docs/types.md#project-types)
// the tree has the project's types too, which every program of the project
// sees: "Move to project" makes a program's type the project's (one undo
// step), "Copy to program" gives this program its own copy, and editing a
// project type edits it for every program. The Archives section lists the
// type archives whose prototypes the project applies to imports (revkit's
// library archives, Ghidra's, attached ones), each switched on or off, and
// attaches or detaches archives.

import { AssertionOp, AssertionStatus, CopyTypesMode, FactKind, ParseCSeverity, TypeArchiveKind, TypeKind, TypeSource, headerImportPlan, normalizeCategory, typeArchiveBody, typeCategoryBodies, type TypeArchiveInfo, type TypeDefinition, type Revkit } from "@revkit/api";
import { byOffset, extent, keyOf, layout, measure, parseMembers, parseText, readable, saveBodies, type Draft, type DraftKind, type FieldDraft, type Layout, type LineNote, type Packing } from "../data/cgen";
import { Edits } from "../data/edits";
import { errText, originClass, originText } from "../data/format";
import { h, prefs } from "./dom";
import { ask, askFields, toast } from "./dialogs";
import { headerImportDialog, openHeaderImport } from "./headerimport";
import { exportArchiveDialog, openExportArchive } from "./typearchive";

const PAGE = 500;
const ROW_H = 22;
/** Kinds with more types than this are split by initial letter. */
const BUCKET_OVER = 300;
/** Kinds of the program's own with at most this many open by themselves. */
const AUTO_OPEN = 200;
const BUCKETS = [..."ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789"];
/** The drag's data: a named type's key ("struct cJSON"). */
const DRAG_TYPE = "application/x-revkit-type";

/** A branch of the category tree. */
interface TNode {
  key: string;
  label: string;
  source: TypeSource;
  kind?: TypeKind;
  prefix?: string;
  /** Types under it (null: not counted yet). */
  count: number | null;
  /** A folder of the program's types: its category ("" the top), its types loaded. */
  category?: string;
  loaded?: boolean;
  /** Loaded leaves (kinds and letters) and sub-branches (sources, kinds with letters, namespaces). */
  types: TypeDefinition[];
  children: TNode[] | null;
  loading: boolean;
  /** More types than loaded (a page at a time), and where the next page starts. */
  more: boolean;
  token?: string;
}

/** A row of the list: a branch, a type, or a "load more" / message line. */
interface TRow {
  depth: number;
  node?: TNode;
  type?: TypeDefinition;
  more?: TNode;
  text?: string;
}

/** A named type's key ("struct cJSON", "typedef cJSON"). */
function keyOfType(t: TypeDefinition): string {
  return `${KIND_LABEL[t.kind] ?? "typedef"} ${t.name}`;
}

/** replaceChildren, skipping absent children. */
function fill(el: HTMLElement, ...kids: (Node | string | null | undefined | false)[]) {
  el.replaceChildren(...kids.filter((k): k is Node | string => !!k));
}

/** A field as the editor adds one (its size is measured by the daemon). */
function newField(name: string, type: string, offset: number): FieldDraft {
  return { name, type, hash: "", shown: "", offset, bitOffset: 0, bitSize: 0, flex: false, size: -1, align: -1 };
}

/** "16", "0x10" (null when it isn't a number). */
function parseNum(s: string): number | null {
  const t = s.trim();
  const n = /^0x[0-9a-f]+$/i.test(t) ? parseInt(t, 16) : /^\d+$/.test(t) ? Number(t) : NaN;
  return Number.isFinite(n) ? n : null;
}

/** "0x4", "4:3" (byte:bit) as a position. */
function parsePos(s: string): { byte: number; bit: number } | null {
  const [b, bit = "0"] = s.split(":");
  const byte = parseNum(b), x = parseNum(bit);
  if (byte === null || x === null || x > 7) return null;
  return { byte, bit: x };
}

const KIND_LABEL: Record<number, string> = {
  [TypeKind.STRUCT]: "struct",
  [TypeKind.UNION]: "union",
  [TypeKind.ENUM]: "enum",
  [TypeKind.TYPEDEF]: "typedef",
};

export interface TypesHost {
  rk: Revkit;
  programId: string;
  edits: Edits;
  /** The daemon parses C (api_minor 25, feature parse-c): the editor and the header import need it. */
  parseC: boolean;
  /** Categories and type archives (api_minor 35, feature type-archive). */
  archives?: boolean;
  /** Project-wide types and the archives section (api_minor 52, feature project-types). */
  projectTypes?: boolean;
  /** Retypes the current selection to `hash` (a pointer to it with `pointer`). */
  apply: (def: TypeDefinition, pointer: boolean) => Promise<void>;
  /** Waits until this tab has seen a revision (the edit's own event). */
  settle: (revision: bigint) => Promise<void>;
  /** Find Uses of a struct or union, or one field (feature type-uses): the search results table. */
  findUses?: (hash: string, name: string, field?: { offset: bigint; name: string }) => void;
}

export class TypesView {
  private list: HTMLElement;
  private filter: HTMLInputElement;
  private kind: HTMLSelectElement;
  private superseded: HTMLInputElement;
  private source: HTMLSelectElement;
  private count: HTMLElement;
  /** The Archives section (feature project-types): shown or not, and its list. */
  private archivesEl: HTMLElement;
  private archivesOpen = false;
  private archiveList: TypeArchiveInfo[] = [];
  private detail: HTMLElement;
  private types: TypeDefinition[] = [];
  private total = 0;
  /** The tree (no search) or the matches (a search), as list rows. */
  private rows: TRow[] = [];
  private roots: TNode[] = [];
  /** Branches open (by key), and the ones the user closed (they stay closed on refresh). */
  private open = new Set<string>(["src:1"]);
  private closed = new Set<string>();
  private spacer: HTMLElement;
  private rowsEl: HTMLElement;
  private tree = false;
  /** Find-types-tree features (name_prefix, summary_only). */
  treeable = true;
  /** The tree by folder (categories) or by kind. */
  private group: "folders" | "kinds" = "kinds";
  private groupSel: HTMLSelectElement;
  /** A type is being dragged (to a folder). */
  private dragging = false;
  private active = -1;
  private seq = 0;
  private timer = 0;
  private loaded = false;
  /** The type shown on the right (by name, so an edit keeps it shown). */
  private shown: TypeDefinition | null = null;
  private deps = new Map<string, TypeDefinition>();
  private draft: Draft | null = null;
  /** The editor's tab, the C tab's text (and what it started as), its diagnostics. */
  private tab: "fields" | "c" = "fields";
  private cText = "";
  private cBase = "";
  private notes: LineNote[] = [];
  private dirty = false;
  private renaming = false;
  /** The daemon's latest layout of the draft. */
  private layout: Layout | null = null;
  private error = "";
  private busy = false;

  constructor(
    root: HTMLElement,
    private host: TypesHost,
  ) {
    this.filter = h("input", { class: "filter", placeholder: "Search types by name", spellcheck: "false", "aria-label": "Search types", "data-testid": "types-filter" });
    this.kind = h(
      "select",
      { class: "filter select", "aria-label": "Kind" },
      h("option", { value: "0" }, "All kinds"),
      ...[TypeKind.STRUCT, TypeKind.UNION, TypeKind.ENUM, TypeKind.TYPEDEF].map((k) => h("option", { value: String(k) }, KIND_LABEL[k])),
    );
    this.superseded = h("input", { type: "checkbox", title: "Also list versions an edit replaced" });
    this.source = h(
      "select",
      { class: "filter select", "aria-label": "Source", "data-testid": "types-source", title: "Program: debug info and defined types · Library: the type archive applied to the imports" },
      h("option", { value: String(TypeSource.PROGRAM), title: "The program's types (with the project's, which every program sees)" }, "Program"),
      h("option", { value: String(TypeSource.LIBRARY) }, "Library"),
      host.projectTypes ? h("option", { value: String(TypeSource.PROJECT) }, "Project") : null,
      h("option", { value: "0" }, "All"),
    );
    this.count = h("span", { class: "dim count", "data-testid": "types-count" });
    this.group = host.archives && (prefs.get("rk.types.group") ?? "folders") === "folders" ? "folders" : "kinds";
    this.groupSel = h(
      "select",
      { class: "filter select", "aria-label": "Group the tree", "data-testid": "types-group", title: "Folders: the program's types by category · Kinds: by source, kind and initial letter", hidden: !host.archives },
      h("option", { value: "folders" }, "Folders"),
      h("option", { value: "kinds" }, "Kinds"),
    );
    this.groupSel.value = this.group;
    this.groupSel.addEventListener("change", () => this.setGroup(this.groupSel.value as "folders" | "kinds"));
    const newSel = h(
      "select",
      { class: "filter select", "aria-label": "New type", "data-testid": "types-new" },
      h("option", { value: "" }, "New…"),
      ...(["struct", "union", "enum", "typedef"] as DraftKind[]).map((k) => h("option", { value: k }, k)),
    );
    newSel.addEventListener("change", () => {
      const k = newSel.value as DraftKind;
      newSel.value = "";
      if (k) this.newType(k);
    });
    this.spacer = h("div", { class: "fn-spacer" });
    this.rowsEl = h("div", { class: "fn-rows" });
    this.list = h("div", { class: "types-list", tabindex: "0", role: "tree", "aria-label": "Types", "data-testid": "types-list" }, this.spacer, this.rowsEl);
    this.list.addEventListener("scroll", () => this.paintRows());
    new ResizeObserver(() => this.paintRows()).observe(this.list);
    this.detail = h("div", { class: "types-detail", "data-testid": "types-detail" });
    this.archivesEl = h("div", { class: "types-archives", "data-testid": "types-archives", hidden: true });
    root.append(
      h("div", { class: "panel-head view-head" }, h("span", { class: "panel-title" }, "Types"), this.count),
      h(
        "div",
        { class: "fn-filter types-filters" },
        this.filter,
        this.source,
        this.kind,
        h("label", { class: "dim small-label" }, this.superseded, "history"),
        newSel,
        h("button", { class: "btn small", "data-testid": "types-import", disabled: !host.parseC, title: host.parseC ? "Parse a C header and import its types (one undo step)" : "Needs a daemon that parses C (api_minor 25, feature parse-c)", onclick: () => this.importHeader() }, "Import header…"),
        host.archives ? this.groupSel : null,
        host.archives ? h("button", { class: "btn small", "data-testid": "types-import-archive", title: "Import a type archive: a header and its JSON sidecar (one undo step)", onclick: () => this.importArchive() }, "Import archive…") : null,
        host.archives ? h("button", { class: "btn small", "data-testid": "types-export-archive", title: "Export types as a type archive: a C header and a JSON sidecar of hashes, categories and the data model", onclick: () => this.exportArchive() }, "Export archive…") : null,
        host.projectTypes ? h("button", { class: "btn small", "data-testid": "types-archives-toggle", title: "The type archives whose prototypes the project applies to imports: on or off, attach and detach", onclick: () => void this.toggleArchives() }, "Archives") : null,
      ),
      this.archivesEl,
      h("div", { class: "types-split" }, this.list, this.detail),
    );
    const reload = () => {
      clearTimeout(this.timer);
      this.timer = window.setTimeout(() => void this.load(), 150);
    };
    this.filter.addEventListener("input", reload);
    this.kind.addEventListener("change", () => void this.load());
    this.source.addEventListener("change", () => void this.load());
    this.superseded.addEventListener("change", () => void this.load());
    this.filter.addEventListener("keydown", (e) => this.onListKey(e));
    this.list.addEventListener("keydown", (e) => this.onListKey(e));
    // Drag a type onto a folder: filed there.
    this.list.addEventListener("dragstart", (e) => {
      const el = (e.target as HTMLElement).closest<HTMLElement>("[data-type-key]");
      if (!el || !e.dataTransfer) return;
      e.dataTransfer.setData(DRAG_TYPE, el.dataset.typeKey!);
      e.dataTransfer.effectAllowed = "move";
      // The rows stay as they are while dragging (a repaint would drop the drag's source).
      this.dragging = true;
    });
    this.list.addEventListener("dragend", () => {
      this.dragging = false;
      this.paintRows();
    });
    const folderAt = (e: DragEvent) => {
      if (!e.dataTransfer?.types.includes(DRAG_TYPE)) return null;
      return (e.target as HTMLElement).closest<HTMLElement>("[data-category]");
    };
    this.list.addEventListener("dragover", (e) => {
      const f = folderAt(e);
      if (!f) return;
      e.preventDefault();
      e.dataTransfer!.dropEffect = "move";
      for (const x of this.list.querySelectorAll(".drop-target")) if (x !== f) x.classList.remove("drop-target");
      f.classList.add("drop-target");
    });
    this.list.addEventListener("dragleave", (e) => (e.target as HTMLElement).closest?.("[data-category]")?.classList.remove("drop-target"));
    this.list.addEventListener("drop", (e) => {
      const f = folderAt(e);
      if (!f) return;
      e.preventDefault();
      f.classList.remove("drop-target");
      void this.moveToCategory([e.dataTransfer!.getData(DRAG_TYPE)], f.dataset.category ?? "");
    });
    this.list.addEventListener("click", (e) => {
      const el = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (!el?.draggable) return;
      this.list.focus({ preventScroll: true });
      this.activate(Number(el.dataset.i), true);
    });
    this.list.addEventListener("mousedown", (e) => {
      const el = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (!el) return;
      // A type that can be dragged: picked on click, so a drag can start
      // from the row as it is (picking repaints the rows).
      if (el.draggable) return;
      e.preventDefault();
      this.list.focus({ preventScroll: true });
      this.activate(Number(el.dataset.i), true);
    });
    this.paintDetail();
  }

  /** Opens the header import; what it imports is shown here afterwards. */
  importHeader() {
    return openHeaderImport({
      rk: this.host.rk,
      programId: this.host.programId,
      edits: this.host.edits,
      settle: this.host.settle,
      imported: (keys) => {
        const first = keys.find((k) => !k.endsWith("_constants")) ?? keys[0];
        if (first) void this.showAfterSave(first.split(" ")[0], first.split(" ").slice(1).join(" "));
      },
    });
  }

  /** Opens the header import for a type archive (a header and its sidecar). */
  importArchive() {
    return openHeaderImport({
      rk: this.host.rk,
      programId: this.host.programId,
      edits: this.host.edits,
      settle: this.host.settle,
      archive: true,
      imported: (keys) => {
        const first = keys[0];
        if (first) void this.showAfterSave(first.split(" ")[0], first.split(" ").slice(1).join(" "));
      },
    });
  }

  /** Opens Export archive… for the shown type, the active folder, or all. */
  exportArchive() {
    const r = this.rows[this.active];
    const folder = r?.node?.category ?? (this.shown ? this.shown.category || "/" : undefined);
    return openExportArchive({ rk: this.host.rk, programId: this.host.programId, shownKey: this.shown && !this.shown.superseded ? keyOfType(this.shown) : undefined, folder: folder === "" ? "/" : folder });
  }

  /** Files named types under a category ("" or "/": the top), as one undo step. */
  async moveToCategory(keys: string[], path: string) {
    const to = normalizeCategory(path.trim());
    if (to === null) return toast(`"${path}" isn't a category: a path such as /net/http`, { kind: "error" });
    try {
      const r = await this.host.edits.bodies(`Move ${keys.length === 1 ? keys[0] : `${keys.length} types`} to ${to || "/"}`, typeCategoryBodies(keys, to));
      await this.host.settle(r.revision);
      toast(`Moved ${keys.length === 1 ? keys[0] : `${keys.length} types`} to ${to || "/"}`, { action: { label: "Undo", run: () => void this.host.edits.undo().catch((e) => toast(errText(e), { kind: "error" })) } });
      if (to) this.open.add(`cat:${to}`);
      await this.refresh();
    } catch (e) {
      toast(`Move: ${errText(e)}`, { kind: "error" });
    }
  }

  /** Move to project / Copy to program for the shown type (one undo step). */
  async copyShown(mode: CopyTypesMode) {
    const t = this.shown;
    if (!t) return;
    const key = keyOfType(t);
    const what = mode === CopyTypesMode.MOVE_TO_PROJECT ? `Move ${key} to the project` : `Copy ${key} to the program`;
    try {
      const r = await this.host.edits.copyTypes(what, [key], mode);
      await this.host.settle(r.revision);
      toast(mode === CopyTypesMode.MOVE_TO_PROJECT ? `${key} is the project's: every program sees it` : `${key} copied into the program`,
        { action: { label: "Undo", run: () => void this.host.edits.undo().catch((e) => toast(errText(e), { kind: "error" })) } });
      if (mode === CopyTypesMode.MOVE_TO_PROJECT) this.open.add(`src:${TypeSource.PROJECT}`);
      await this.refresh();
      const [kind, ...rest] = key.split(" ");
      await this.showAfterSave(kind as DraftKind, rest.join(" "));
    } catch (e) {
      toast(`${what}: ${errText(e)}`, { kind: "error" });
    }
  }

  /** Shows or hides the Archives section. */
  async toggleArchives() {
    this.archivesOpen = !this.archivesOpen;
    this.archivesEl.hidden = !this.archivesOpen;
    if (this.archivesOpen) await this.loadArchives();
  }

  /** The type archives of the project, for this program (ListTypeArchives). */
  private async loadArchives() {
    if (!this.archivesOpen) return;
    try {
      this.archiveList = (await this.host.rk.types.listTypeArchives({ programId: this.host.programId })).archives;
    } catch (e) {
      fill(this.archivesEl, h("div", { class: "error" }, `Archives: ${errText(e)}`));
      return;
    }
    this.paintArchives();
  }

  private paintArchives() {
    const kind = (a: TypeArchiveInfo) => (a.kind === TypeArchiveKind.SHIPPED ? "revkit" : a.kind === TypeArchiveKind.GHIDRA ? "Ghidra" : "attached");
    const rows = this.archiveList
      .filter((a) => a.applies || a.kind === TypeArchiveKind.ATTACHED || !a.enabled)
      .map((a) => {
        const box = h("input", { type: "checkbox", "data-testid": `archive-enabled-${a.name}`, title: a.enabled ? "On: its prototypes apply to imports by name (turn off for every program of the project)" : "Off for the project" });
        box.checked = a.enabled;
        box.addEventListener("change", () => void this.setArchive(a.name, box.checked));
        return h(
          "tr",
          { "data-testid": "archive-row" },
          h("td", {}, box),
          h("td", { class: "mono" }, a.name),
          h("td", {}, h("span", { class: "badge b-kind" }, kind(a))),
          h("td", { class: "dim" }, a.kind === TypeArchiveKind.GHIDRA ? a.origin : `${a.functions.toLocaleString()} functions · ${a.types.toLocaleString()} types`),
          h("td", { class: "dim small-label", title: a.dataModel }, a.kind === TypeArchiveKind.GHIDRA ? "" : a.origin),
          h("td", {}, a.kind === TypeArchiveKind.ATTACHED ? h("button", { class: "btn small", "data-testid": `archive-detach-${a.name}`, onclick: () => void this.detachArchive(a.name) }, "Detach") : null,
            a.diagnostics.length ? h("span", { class: "error", title: a.diagnostics.join("\n") }, ` ${a.diagnostics.length} errors`) : null),
        );
      });
    const pick = h("input", { type: "file", accept: ".h,.json", multiple: true, hidden: true, "data-testid": "archive-attach-file" }) as HTMLInputElement;
    pick.addEventListener("change", () => void this.attachFiles(Array.from(pick.files ?? [])));
    fill(
      this.archivesEl,
      h("div", { class: "panel-head" }, h("span", { class: "panel-title" }, "Archives"),
        h("span", { class: "dim" }, "Prototypes for imports by name, for every program of the project"),
        h("span", { class: "spacer" }),
        h("button", { class: "btn small", "data-testid": "archive-attach", title: "Attach a type archive (a header, and its JSON sidecar if any) to the project", onclick: () => pick.click() }, "Attach archive…"),
        pick),
      h("table", { class: "types-table" }, ...rows),
    );
  }

  private async setArchive(name: string, enabled: boolean) {
    try {
      const r = await this.host.edits.bodies(`Archive ${name} ${enabled ? "on" : "off"}`, [typeArchiveBody({ name, enabled })]);
      await this.host.settle(r.revision);
      toast(`${name} ${enabled ? "on" : "off"} for the project`, { action: { label: "Undo", run: () => void this.host.edits.undo().catch((e) => toast(errText(e), { kind: "error" })) } });
    } catch (e) {
      toast(`Archive ${name}: ${errText(e)}`, { kind: "error" });
    }
    await this.loadArchives();
    await this.refresh();
  }

  /** Attaches the chosen header (and its sidecar, if chosen too). */
  private async attachFiles(files: File[]) {
    const header = files.find((f) => f.name.endsWith(".h"));
    if (!header) return toast("Attach archive: choose its header (.h), and its sidecar (.json) if it has one", { kind: "error" });
    const sidecar = files.find((f) => f.name.endsWith(".json"));
    const name = header.name.replace(/\.h$/, "").replace(/[^A-Za-z0-9_.-]/g, "_").slice(0, 64);
    try {
      const r = await this.host.edits.bodies(`Attach archive ${name}`, [typeArchiveBody({ name, enabled: true, header: await header.text(), sidecar: sidecar ? await sidecar.text() : "" })]);
      await this.host.settle(r.revision);
      toast(`Attached ${name}: its prototypes apply to every program of the project`, { action: { label: "Undo", run: () => void this.host.edits.undo().catch((e) => toast(errText(e), { kind: "error" })) } });
    } catch (e) {
      toast(`Attach ${name}: ${errText(e)}`, { kind: "error" });
    }
    await this.loadArchives();
    await this.refresh();
  }

  private async detachArchive(name: string) {
    try {
      const r = await this.host.edits.bodies(`Detach archive ${name}`, [typeArchiveBody({ name, detach: true })]);
      await this.host.settle(r.revision);
    } catch (e) {
      toast(`Detach ${name}: ${errText(e)}`, { kind: "error" });
    }
    await this.loadArchives();
    await this.refresh();
  }

  /** Asks for the shown type's category. */
  async moveShown() {
    const t = this.shown;
    if (!t) return;
    const to = await ask({
      title: `Move ${keyOfType(t)} to category`,
      value: t.category || "/",
      hint: "A folder path such as /net/http (/ is the top); folders are made as needed",
      validate: (v) => (normalizeCategory(v.trim()) === null ? "A path from /, such as /net/http" : null),
    });
    if (to !== null) await this.moveToCategory([keyOfType(t)], to);
  }

  /** The tree by folder or by kind (remembered). */
  setGroup(g: "folders" | "kinds") {
    if (!this.host.archives) g = "kinds";
    this.group = g;
    this.groupSel.value = g;
    prefs.set("rk.types.group", g);
    if (this.loaded) void this.load();
  }

  ensureLoaded() {
    if (!this.loaded) void this.load();
  }

  focusFilter() {
    this.filter.focus();
    this.filter.select();
  }

  /** The program's types changed (a TYPES invalidation): list them again, keep the one shown (by name). */
  async refresh() {
    if (this.archivesOpen) void this.loadArchives();
    if (!this.loaded) return;
    await this.load(true);
  }

  private async load(keep = false): Promise<void> {
    this.loaded = true;
    const tree = this.treeable && !this.filter.value.trim() && !this.superseded.checked;
    if (tree) return this.loadTree(keep);
    this.tree = false;
    const seq = ++this.seq;
    const k = Number(this.kind.value);
    try {
      const src = Number(this.source.value);
      // "Program": the program's own and the project's (every program's) types.
      const sources = src === TypeSource.PROGRAM && this.host.projectTypes ? [TypeSource.PROGRAM, TypeSource.PROJECT] : src ? [src] : [];
      const r = await this.host.rk.queries.findTypes({ programId: this.host.programId, nameContains: this.filter.value.trim(), kinds: k ? [k] : [], sources, includeSuperseded: this.superseded.checked, page: { pageSize: PAGE } });
      if (seq !== this.seq) return;
      // Exact names first, then prefixes, then the rest (each by name, as the daemon sorts).
      const q = this.filter.value.trim().toLowerCase();
      const rank = (t: TypeDefinition) => (!q ? 0 : t.name.toLowerCase() === q ? 0 : t.name.toLowerCase().startsWith(q) ? 1 : 2);
      this.types = r.types.map((t, i) => ({ t, i })).sort((x, y) => rank(x.t) - rank(y.t) || x.i - y.i).map((x) => x.t);
      this.total = Number(r.page?.totalCount ?? BigInt(r.types.length));
      this.count.textContent = `${this.total.toLocaleString()} ${this.total === 1 ? "type" : "types"}${this.total > this.types.length ? ` (first ${this.types.length})` : ""}`;
    } catch (e) {
      if (seq !== this.seq) return;
      this.types = [];
      this.count.textContent = errText(e);
    }
    this.rows = this.types.map((t) => ({ depth: 0, type: t }));
    this.paintList();
    if (keep && this.shown) {
      // The edited type, or the definition its name is bound to now.
      const same = this.types.find((t) => t.hash === this.shown!.hash && !t.superseded) ?? this.types.find((t) => t.name === this.shown!.name && t.kind === this.shown!.kind && !t.superseded);
      if (same) await this.show(same);
      else if (!this.draft) await this.show(this.shown);
    }
  }

  // ---------------------------------------------------------------- tree --

  private sources(): TypeSource[] {
    const src = Number(this.source.value);
    if (src === TypeSource.PROGRAM && this.host.projectTypes) return [TypeSource.PROGRAM, TypeSource.PROJECT];
    return src ? [src as TypeSource] : this.host.projectTypes ? [TypeSource.PROGRAM, TypeSource.PROJECT, TypeSource.LIBRARY] : [TypeSource.PROGRAM, TypeSource.LIBRARY];
  }

  private kinds(): TypeKind[] {
    const k = Number(this.kind.value);
    return k ? [k as TypeKind] : [TypeKind.STRUCT, TypeKind.UNION, TypeKind.ENUM, TypeKind.TYPEDEF];
  }

  /** One page of a branch's types (summaries), after `token` for the next page. */
  private async find(src: TypeSource, kind: TypeKind | undefined, prefix: string, pageSize: number, token = "") {
    const r = await this.host.rk.queries.findTypes({
      programId: this.host.programId,
      kinds: kind ? [kind] : this.kinds(),
      sources: [src],
      namePrefix: prefix,
      summaryOnly: true,
      page: { pageSize, pageToken: token },
    });
    return { types: r.types, total: Number(r.page?.totalCount ?? BigInt(r.types.length)), token: r.page?.nextPageToken ?? "" };
  }

  /** The program's folders (FindTypes categories) as branches under one root. */
  private async folderRoot(): Promise<TNode> {
    const r = await this.host.rk.queries.findTypes({ programId: this.host.programId, sources: [TypeSource.PROGRAM], kinds: this.kinds(), includeCategories: true, summaryOnly: true, page: { pageSize: 1 } });
    const root: TNode = { key: "cat:/", label: "Program types", source: TypeSource.PROGRAM, category: "", count: Number(r.page?.totalCount ?? 0n), types: [], children: [], loading: false, more: false };
    const byPath = new Map<string, TNode>([["", root]]);
    const direct = new Map<string, number>();
    const node = (path: string): TNode => {
      const have = byPath.get(path);
      if (have) return have;
      const at = path.lastIndexOf("/");
      const parent = node(path.slice(0, at));
      const n: TNode = { key: `cat:${path}`, label: path.slice(at + 1), source: TypeSource.PROGRAM, category: path, count: 0, types: [], children: [], loading: false, more: false };
      parent.children!.push(n);
      byPath.set(path, n);
      return n;
    };
    for (const c of r.categories) {
      const path = c.path === "/" ? "" : c.path;
      node(path);
      direct.set(path, c.types);
    }
    // Each folder counts its types and its subfolders'; subfolders by name.
    const total = (n: TNode): number => {
      n.children!.sort((a, b) => a.label.localeCompare(b.label));
      n.count = (direct.get(n.category!) ?? 0) + n.children!.reduce((x, c) => x + total(c), 0);
      return n.count;
    };
    total(root);
    return root;
  }

  /** The tree's roots and their kinds' counts; opened branches load again (refresh). */
  private async loadTree(keep: boolean): Promise<void> {
    if (this.group === "folders") return this.loadFolders(keep);
    const seq = ++this.seq;
    this.tree = true;
    const roots: TNode[] = this.sources().map((src) => ({
      key: `src:${src}`,
      label: src === TypeSource.PROGRAM ? "Program types" : src === TypeSource.PROJECT ? "Project types" : "Library archives",
      source: src,
      count: null,
      types: [],
      children: this.kinds().map((k) => ({ key: `src:${src}/k:${k}`, label: KIND_LABEL[k] + "s", source: src, kind: k, count: null, types: [], children: null, loading: false, more: false })),
      loading: false,
      more: false,
    }));
    try {
      await Promise.all(
        roots.flatMap((r) =>
          r.children!.map(async (k) => {
            const x = await this.find(r.source, k.kind, "", 1);
            k.count = x.total;
            if (r.source === TypeSource.LIBRARY && !this.host.projectTypes && x.types[0]?.origin?.source.case === "derived") r.label = `Library: ${x.types[0].origin.source.value.rule.replace(/^library:/, "")}`;
          }),
        ),
      );
    } catch (e) {
      if (seq !== this.seq) return;
      // A daemon without name_prefix / summary_only: the flat list.
      this.treeable = false;
      this.count.textContent = errText(e);
      return this.load(keep);
    }
    if (seq !== this.seq) return;
    for (const r of roots) {
      r.count = r.children!.reduce((n, k) => n + (k.count ?? 0), 0);
      r.children = r.children!.filter((k) => k.count);
      // The program's small kinds open by themselves.
      if (r.source === TypeSource.PROGRAM) for (const k of r.children) if ((k.count ?? 0) <= AUTO_OPEN && !this.closed.has(k.key)) this.open.add(k.key);
    }
    this.roots = roots;
    this.total = roots.reduce((n, r) => n + (r.count ?? 0), 0);
    this.count.textContent = `${this.total.toLocaleString()} ${this.total === 1 ? "type" : "types"}`;
    // Opened branches load again, top down.
    const reopen = async (nodes: TNode[]) => {
      for (const n of nodes) {
        if (!this.open.has(n.key)) continue;
        await this.expand(n, false);
        if (seq !== this.seq) return;
        if (n.children) await reopen(n.children);
      }
    };
    await reopen(roots);
    if (seq !== this.seq) return;
    this.flatten();
    if (keep && this.shown && !this.draft) {
      const same = this.types.find((t) => t.name === this.shown!.name && t.kind === this.shown!.kind && !t.superseded);
      await this.show(same ?? this.shown);
    }
  }

  /** The folder tree: the program's types by category, the library by kind. */
  private async loadFolders(keep: boolean): Promise<void> {
    const seq = ++this.seq;
    this.tree = true;
    const roots: TNode[] = [];
    try {
      if (this.sources().includes(TypeSource.PROGRAM)) roots.push(await this.folderRoot());
      if (this.sources().includes(TypeSource.PROJECT)) {
        // The project's types (every program sees them), by kind.
        const proj: TNode = { key: `src:${TypeSource.PROJECT}`, label: "Project types", source: TypeSource.PROJECT, count: null, types: [], loading: false, more: false,
          children: this.kinds().map((k) => ({ key: `src:${TypeSource.PROJECT}/k:${k}`, label: KIND_LABEL[k] + "s", source: TypeSource.PROJECT, kind: k, count: null, types: [], children: null, loading: false, more: false })) };
        await Promise.all(proj.children!.map(async (k) => {
          k.count = (await this.find(TypeSource.PROJECT, k.kind, "", 1)).total;
        }));
        proj.children = proj.children!.filter((k) => k.count);
        proj.count = proj.children.reduce((n, k) => n + (k.count ?? 0), 0);
        if (proj.count) {
          if (!this.closed.has(proj.key)) this.open.add(proj.key);
          roots.push(proj);
        }
      }
      if (this.sources().includes(TypeSource.LIBRARY)) {
        const lib: TNode = { key: `src:${TypeSource.LIBRARY}`, label: "Library archives", source: TypeSource.LIBRARY, count: null, types: [], loading: false, more: false,
          children: this.kinds().map((k) => ({ key: `src:${TypeSource.LIBRARY}/k:${k}`, label: KIND_LABEL[k] + "s", source: TypeSource.LIBRARY, kind: k, count: null, types: [], children: null, loading: false, more: false })) };
        await Promise.all(lib.children!.map(async (k) => {
          const x = await this.find(TypeSource.LIBRARY, k.kind, "", 1);
          k.count = x.total;
          if (!this.host.projectTypes && x.types[0]?.origin?.source.case === "derived") lib.label = `Library: ${x.types[0].origin.source.value.rule.replace(/^library:/, "")}`;
        }));
        lib.children = lib.children!.filter((k) => k.count);
        lib.count = lib.children.reduce((n, k) => n + (k.count ?? 0), 0);
        if (lib.count) roots.push(lib);
      }
    } catch (e) {
      if (seq !== this.seq) return;
      this.group = "kinds";
      this.count.textContent = errText(e);
      return this.loadTree(keep);
    }
    if (seq !== this.seq) return;
    // A small program's folders open by themselves.
    const program = roots.find((r) => r.category !== undefined);
    if (program && !this.closed.has(program.key)) this.open.add(program.key);
    if (program && (program.count ?? 0) <= AUTO_OPEN) {
      const all = (n: TNode) => {
        if (!this.closed.has(n.key)) this.open.add(n.key);
        n.children?.forEach(all);
      };
      all(program);
    }
    this.roots = roots;
    this.total = roots.reduce((n, r) => n + (r.count ?? 0), 0);
    this.count.textContent = `${this.total.toLocaleString()} ${this.total === 1 ? "type" : "types"}`;
    const reopen = async (nodes: TNode[]) => {
      for (const n of nodes) {
        if (!this.open.has(n.key)) continue;
        await this.expand(n, false);
        if (seq !== this.seq) return;
        if (n.children) await reopen(n.children);
      }
    };
    await reopen(roots);
    if (seq !== this.seq) return;
    this.flatten();
    if (keep && this.shown && !this.draft) {
      const same = this.types.find((t) => t.name === this.shown!.name && t.kind === this.shown!.kind && !t.superseded);
      await this.show(same ?? this.shown);
    }
  }

  /** A folder's own types, a page at a time. */
  private async expandFolder(n: TNode, paint: boolean, more: boolean) {
    if (n.loading || (!more && n.loaded)) return;
    n.loading = true;
    if (paint) this.flatten();
    try {
      const r = await this.host.rk.queries.findTypes({
        programId: this.host.programId,
        sources: [TypeSource.PROGRAM],
        kinds: this.kinds(),
        category: n.category || "/",
        categoryExact: true,
        summaryOnly: true,
        page: { pageSize: PAGE, pageToken: more ? (n.token ?? "") : "" },
      });
      n.types = more ? [...n.types, ...r.types] : r.types;
      n.token = r.page?.nextPageToken ?? "";
      n.more = !!n.token && n.types.length < Number(r.page?.totalCount ?? 0n);
      n.loaded = true;
    } catch (e) {
      toast(`Types: ${errText(e)}`, { kind: "error" });
    } finally {
      n.loading = false;
    }
    if (paint) this.flatten();
  }

  /** Loads a branch's types or sub-branches (once; `more` adds a page). */
  private async expand(n: TNode, paint = true, more = false) {
    if (n.category !== undefined) return this.expandFolder(n, paint, more);
    if (n.kind === undefined && n.children) return; // a source: its kinds are there
    if (n.loading || (!more && (n.types.length || n.children))) return;
    n.loading = true;
    if (paint) this.flatten();
    try {
      if (n.kind !== undefined && n.prefix === undefined && (n.count ?? 0) > BUCKET_OVER) {
        // Too many: by initial letter, counted (empty letters left out).
        const counts = await Promise.all(BUCKETS.map((b) => this.find(n.source, n.kind, b, 1).then((x) => x.total)));
        n.children = BUCKETS.map((b, i) => ({ key: `${n.key}/p:${b}`, label: b, source: n.source, kind: n.kind, prefix: b, count: counts[i], types: [], children: null, loading: false, more: false })).filter((c) => c.count);
        const rest = (n.count ?? 0) - counts.reduce((a, b) => a + b, 0);
        if (rest > 0) n.children.push({ key: `${n.key}/p:other`, label: `${rest} other (search to find them)`, source: n.source, kind: n.kind, prefix: "\u0000", count: null, types: [], children: [], loading: false, more: false });
      } else if (n.kind !== undefined) {
        const r = await this.find(n.source, n.kind, n.prefix ?? "", PAGE, more ? (n.token ?? "") : "");
        n.types = more ? [...n.types, ...r.types] : r.types;
        n.token = r.token;
        n.more = !!r.token && n.types.length < r.total;
        n.count ??= r.total;
      }
    } catch (e) {
      toast(`Types: ${errText(e)}`, { kind: "error" });
    } finally {
      n.loading = false;
    }
    if (paint) this.flatten();
  }

  /** Opens or closes a branch. */
  private toggle(n: TNode, open?: boolean) {
    const now = open ?? !this.open.has(n.key);
    if (now) {
      this.open.add(n.key);
      this.closed.delete(n.key);
      this.flatten();
      void this.expand(n);
    } else {
      this.open.delete(n.key);
      this.closed.add(n.key);
      this.flatten();
    }
  }

  /** The tree as rows (open branches' children under them), namespaces grouped. */
  private flatten() {
    const rows: TRow[] = [];
    const leaves: TypeDefinition[] = [];
    const typeRows = (n: TNode, depth: number) => {
      // Names with a namespace ("std::vector") under their namespace.
      const ns = new Map<string, TypeDefinition[]>();
      const plain: TypeDefinition[] = [];
      for (const t of n.types) {
        const at = t.name.indexOf("::");
        if (at > 0) {
          const key = t.name.slice(0, at);
          ns.set(key, [...(ns.get(key) ?? []), t]);
        } else plain.push(t);
      }
      for (const [name, list] of ns) {
        const key = `${n.key}/ns:${name}`;
        const sub: TNode = { key, label: `${name}::`, source: n.source, kind: n.kind, count: list.length, types: list, children: null, loading: false, more: false };
        if (list.length === 1) {
          plain.push(list[0]);
          continue;
        }
        rows.push({ depth, node: sub });
        if (this.open.has(key)) for (const t of list) {
          rows.push({ depth: depth + 1, type: t });
          leaves.push(t);
        }
      }
      for (const t of plain.sort((a, b) => a.name.localeCompare(b.name))) {
        rows.push({ depth, type: t });
        leaves.push(t);
      }
      if (n.more) rows.push({ depth, more: n });
    };
    const walk = (nodes: TNode[], depth: number) => {
      for (const n of nodes) {
        rows.push({ depth, node: n });
        if (!this.open.has(n.key)) continue;
        if (n.loading && !n.types.length && !n.children?.length) rows.push({ depth: depth + 1, text: "Loading…" });
        if (n.children) walk(n.children, depth + 1);
        if (n.types.length) typeRows(n, depth + 1);
      }
    };
    walk(this.roots, 0);
    if (!rows.length) rows.push({ depth: 0, text: "No named types" });
    this.rows = rows;
    this.types = leaves;
    this.paintList();
  }

  private paintList() {
    this.list.dataset.mode = this.tree ? "tree" : "flat";
    this.spacer.style.height = `${this.rows.length * ROW_H}px`;
    if (this.active >= this.rows.length) this.active = this.rows.length - 1;
    this.paintRows();
  }

  /** Only the rows in view are in the DOM. */
  private paintRows() {
    if (this.dragging) return;
    const top = this.list.scrollTop;
    const height = this.list.clientHeight || 600;
    const first = Math.max(0, Math.floor(top / ROW_H) - 4);
    const last = Math.min(this.rows.length, Math.ceil((top + height) / ROW_H) + 4);
    const frag = document.createDocumentFragment();
    for (let i = first; i < last; i++) {
      const r = this.rows[i];
      const style = `top:${i * ROW_H}px;padding-left:${10 + r.depth * 14}px`;
      const active = i === this.active ? " active" : "";
      if (r.node) {
        const open = this.open.has(r.node.key);
        const folder = r.node.category !== undefined ? { "data-category": r.node.category || "/", title: r.node.category ? `${r.node.category}: drop a type here to file it here` : "The program's types; those with no category are at the top (drop a type here to take it out of its folder)" } : {};
        frag.append(
          h(
            "div",
            { class: "types-row types-branch" + (r.node.category !== undefined ? " types-folder" : "") + active, "data-i": i, style, role: "treeitem", "aria-level": r.depth + 1, "aria-expanded": String(open), "data-key": r.node.key, "data-testid": "types-branch", ...folder },
            h("span", { class: "types-twisty", "aria-hidden": "true" }, open ? "▾" : "▸"),
            h("span", { class: "types-name" }, r.node.label),
            h("span", { class: "fn-addr" }, r.node.loading ? "…" : r.node.count === null ? "" : r.node.count.toLocaleString()),
          ),
        );
      } else if (r.type) {
        const t = r.type;
        frag.append(
          h(
            "div",
            {
              class: "types-row" + active + (t.superseded ? " superseded" : "") + (this.shown?.hash === t.hash ? " shown" : ""),
              "data-i": i,
              style,
              role: "treeitem",
              "aria-level": r.depth + 1,
              "aria-selected": String(this.shown?.hash === t.hash),
              title: `${t.display} · ${Number(t.size)} bytes · ${originText(t.origin)}${t.category ? ` · ${t.category}` : ""}${t.superseded ? " · superseded by an edit" : ""}`,
              ...(this.host.archives && !t.superseded && t.origin?.source.case !== "derived" ? { draggable: "true", "data-type-key": keyOfType(t) } : {}),
            },
            h("span", { class: "badge b-kind" }, KIND_LABEL[t.kind] ?? "type"),
            h("span", { class: `types-name o-${originClass(t.origin)}` }, t.name),
            h("span", { class: "fn-addr" }, `${Number(t.size)}`),
          ),
        );
      } else if (r.more) {
        frag.append(h("div", { class: "types-row types-more dim" + active, "data-i": i, style, role: "treeitem", "aria-level": r.depth + 1, "data-testid": "types-more" }, `Load more… (${r.more.types.length.toLocaleString()} of ${(r.more.count ?? 0).toLocaleString()})`));
      } else {
        frag.append(h("div", { class: "types-row dim" + active, "data-i": i, style, role: "treeitem", "aria-level": r.depth + 1, "aria-disabled": "true" }, r.text ?? ""));
      }
    }
    this.rowsEl.replaceChildren(frag);
    if (!this.rows.length) this.rowsEl.append(h("div", { class: "notes-empty dim", role: "treeitem", "aria-disabled": "true" }, this.filter.value ? "No types match" : "No named types"));
  }

  private scrollToRow(i: number) {
    const top = i * ROW_H;
    if (top < this.list.scrollTop) this.list.scrollTop = top;
    else if (top + ROW_H > this.list.scrollTop + this.list.clientHeight) this.list.scrollTop = top + ROW_H - this.list.clientHeight;
  }

  /** A row was clicked or Enter pressed: open a type, toggle a branch, load more. */
  private activate(i: number, click = false) {
    const r = this.rows[i];
    if (!r) return;
    this.active = i;
    if (r.node) this.toggle(r.node);
    else if (r.more) void this.expand(r.more, true, true);
    else if (r.type) this.pick(r.type);
    else this.paintRows();
    if (!click) this.scrollToRow(i);
  }

  private pick(t: TypeDefinition) {
    if (this.draft && !confirm("Discard the unsaved edit?")) return;
    this.draft = null;
    this.paintRows();
    void this.show(t);
  }

  /** Shows a type by name (tests, and Go to type). */
  async showNamed(name: string) {
    this.filter.value = name;
    await this.load();
    const i = this.rows.findIndex((r) => r.type?.name === name && !r.type.superseded);
    if (i >= 0) {
      this.active = i;
      this.paintList();
      await this.show(this.rows[i].type!);
    }
  }

  private showSeq = 0;

  private async show(t: TypeDefinition) {
    // Lists hold summaries (summary_only): the type is shown once its full
    // definition is here.
    const seq = ++this.showSeq;
    this.error = "";
    let full = t;
    try {
      const r = await this.host.rk.queries.getTypes({ programId: this.host.programId, hashes: [t.hash], includeDependencies: true });
      for (const d of r.types) this.deps.set(d.hash, d);
      full = r.types.find((d) => d.hash === t.hash) ?? t;
      // The category is the name's (FindTypes), not the definition's (GetTypes).
      if (t.category && !full.category) full.category = t.category;
    } catch (e) {
      this.error = errText(e);
    }
    if (seq !== this.showSeq) return;
    this.shown = full;
    this.paintDetail();
    this.paintRows();
  }

  private disp(hash: string): string {
    return this.deps.get(hash)?.display ?? hash.slice(0, 8);
  }

  // --------------------------------------------------------------- editing --

  private fieldOf(f: { name: string; typeHash: string; offset: bigint; bitOffset: number; bitSize: number }): FieldDraft {
    const ft = this.deps.get(f.typeHash);
    // A flexible array member: its element, as `type name[]`.
    if (ft?.detail.case === "array" && ft.detail.value.count === 0n) {
      const el = ft.detail.value.elementHash;
      const et = this.deps.get(el);
      return { name: f.name, type: this.disp(el), hash: el, shown: this.disp(el), offset: Number(f.offset), bitOffset: f.bitOffset, bitSize: f.bitSize, flex: true, size: Number(et?.size ?? 0n), align: et?.alignment || 1 };
    }
    return { name: f.name, type: this.disp(f.typeHash), hash: f.typeHash, shown: this.disp(f.typeHash), offset: Number(f.offset), bitOffset: f.bitOffset, bitSize: f.bitSize, flex: false, size: ft ? Number(ft.size) : -1, align: ft?.alignment || -1 };
  }

  private draftOf(t: TypeDefinition): Draft {
    const kind = (KIND_LABEL[t.kind] ?? "struct") as DraftKind;
    const d: Draft = { kind, name: t.name, size: Number(t.size), packing: kind === "struct" ? "explicit" : "natural", align: 0, fields: [], values: [], enumSize: 0, enumSigned: false, target: "", targetHash: "", targetShown: "", from: t.hash, fromName: t.name };
    if (t.detail.case === "composite") {
      d.fields = t.detail.value.fields.map((f) => this.fieldOf(f));
      // An alignment above what the fields ask for was an explicit one.
      const natural = d.fields.reduce((m, f) => Math.max(m, f.align), 1);
      if (!t.detail.value.packed && t.alignment > natural) d.align = t.alignment;
    } else if (t.detail.case === "enumeration") {
      d.values = t.detail.value.values.map((v) => ({ name: v.name, value: String(v.value) }));
      d.enumSize = Number(t.size) || 4;
      d.enumSigned = this.deps.get(t.detail.value.underlyingHash)?.kind === TypeKind.INT || t.detail.value.values.some((v) => v.value < 0n);
    } else if (t.detail.case === "typedefType") {
      d.targetHash = t.detail.value.targetHash;
      d.target = d.targetShown = this.disp(d.targetHash);
    }
    return d;
  }

  /** Edits the shown type, on its fields or in C. */
  edit(tab: "fields" | "c" = "fields") {
    if (!this.shown || !this.canEdit()) return;
    this.draft = this.draftOf(this.shown);
    this.tab = tab;
    this.cText = this.shown.kind === TypeKind.ENUM ? readable(this.draft) : this.shown.cDefinition;
    this.cBase = this.cText;
    this.notes = [];
    this.dirty = false;
    this.error = "";
    this.renaming = false;
    this.paintDetail();
    this.relayout(0);
  }

  newType(kind: DraftKind) {
    if (!this.canEdit()) return toast("Editing types needs a daemon that parses C (api_minor 25, feature parse-c)", { kind: "error" });
    if (this.draft && !confirm("Discard the unsaved edit?")) return;
    this.shown = null;
    const d: Draft = { kind, name: "", size: 0, packing: "natural", align: 0, fields: [], values: [], enumSize: 0, enumSigned: false, target: "int", targetHash: "", targetShown: "", from: "", fromName: "" };
    if (kind === "struct" || kind === "union") d.fields.push(newField("field_0", "int", 0));
    if (kind === "enum") d.values.push({ name: "VALUE_0", value: "0" });
    this.draft = d;
    this.tab = "fields";
    this.cText = this.cBase = "";
    this.notes = [];
    this.dirty = true;
    this.error = "";
    this.renaming = false;
    this.layout = null;
    this.paintDetail();
    this.detail.querySelector<HTMLInputElement>("[data-testid=type-name]")?.focus();
  }

  /** A copy of the shown type under a new name (a new type). */
  async duplicate(name?: string) {
    const t = this.shown;
    if (!t || !this.canEdit()) return;
    const to = name ?? (await ask({ title: `Duplicate ${KIND_LABEL[t.kind] ?? ""} ${t.name} as`, value: `${t.name}_copy`, validate: (v) => (/^[A-Za-z_]\w*$/.test(v.trim()) ? null : "A C name: letters, digits, _") }));
    if (!to) return;
    const d = this.draftOf(t);
    d.name = to.trim();
    d.from = "";
    d.fromName = "";
    this.draft = d;
    this.tab = "fields";
    this.dirty = true;
    this.renaming = false;
    await this.save();
  }

  /**
   * Renames the shown type: its definition under the new name, bound, and
   * the old name's binding retracted (one undo step). Uses by hash (a
   * prototype, another type's field) keep the definition they name, shown
   * by its old name; uses by name follow the old name's previous binding.
   */
  async rename(name?: string) {
    const t = this.shown;
    if (!t || !this.canEdit()) return;
    const to = name ?? (await ask({ title: `Rename ${KIND_LABEL[t.kind] ?? ""} ${t.name} to`, value: t.name, validate: (v) => (/^[A-Za-z_]\w*$/.test(v.trim()) ? null : "A C name: letters, digits, _") }));
    if (!to || to.trim() === t.name) return;
    const d = this.draftOf(t);
    d.name = to.trim();
    this.draft = d;
    this.tab = "fields";
    this.dirty = true;
    this.renaming = true;
    await this.save();
  }

  private canEdit(): boolean {
    return this.host.parseC;
  }

  /**
   * A field of a struct or union, by its parent's hash and offset (a
   * decompiler FIELD token: feature field-tokens), with its name or type
   * changed: the parent's next version, laid out by the daemon and bound to
   * its name, one undo step, as saving it in the editor does (Rename Field,
   * Retype Field). `name` is the field's name as the decompiler printed it,
   * which tells a union's members (all at offset 0) apart. Resolves to the
   * revision and what was done; throws with a message the user can read.
   */
  async editField(hash: string, offset: bigint, name: string, change: { name?: string; type?: string }): Promise<{ revision: bigint; label: string }> {
    if (!this.canEdit()) throw new Error("editing types needs a daemon that parses C (api_minor 25, feature parse-c)");
    const r = await this.host.rk.queries.getTypes({ programId: this.host.programId, hashes: [hash], includeDependencies: true });
    for (const d of r.types) this.deps.set(d.hash, d);
    const t = r.types.find((d) => d.hash === hash);
    if (!t) throw new Error(`the program doesn't know the type ${hash.slice(0, 12)}`);
    const kind = KIND_LABEL[t.kind] ?? "type";
    if (t.detail.case !== "composite") throw new Error(`${t.display || t.name} is not a struct or union`);
    if (!t.name) throw new Error(`the field's ${kind} has no name of its own (an anonymous member or a typedef's): edit the type that holds it in Types`);
    const d = this.draftOf(t);
    const at = d.fields.filter((f) => f.offset === Number(offset) && !f.bitSize);
    const f = at.find((x) => x.name === name) ?? (at.length === 1 ? at[0] : undefined);
    if (!f) throw new Error(`${kind} ${t.name} has no field ${name} at 0x${offset.toString(16)}`);
    let label: string;
    if (change.name !== undefined) {
      const to = change.name.trim();
      if (!/^[A-Za-z_]\w*$/.test(to)) throw new Error("a field name is a C name: letters, digits, _");
      if (to !== f.name && d.fields.some((x) => x !== f && x.name === to)) throw new Error(`${kind} ${t.name} already has a field ${to}`);
      label = `Rename field ${t.name}.${f.name} → ${to}`;
      f.name = to;
    } else {
      const to = (change.type ?? "").trim();
      if (!to) throw new Error("the field's type is empty");
      label = `Set type of field ${t.name}.${f.name} to ${to}`;
      f.type = to;
      f.size = -1;
      f.align = -1;
    }
    const l = await layout(this.host.rk, this.host.programId, d);
    if (!l.ok) throw new Error(l.errors[0] ?? f.problem ?? d.fields.find((x) => x.problem)?.problem ?? "the C has errors");
    if (l.identical) throw new Error(`no change to ${kind} ${t.name}`);
    const res = t.project ? await this.host.edits.projectBodies(label, saveBodies(l)) : await this.host.edits.bodies(label, saveBodies(l));
    return { revision: res.revision, label };
  }

  /** Lays the draft out on the daemon after `ms` (edits come in bursts). */
  private relayout(ms = 200) {
    clearTimeout(this.layoutTimer);
    this.layoutTimer = window.setTimeout(() => void this.runLayout(), ms);
  }

  private layoutSeq = 0;
  private layoutTimer = 0;

  private runLayout(): Promise<Layout | null> {
    const d = this.draft;
    if (!d || this.tab !== "fields") return Promise.resolve(null);
    if (!/^[A-Za-z_]\w*$/.test(d.name)) {
      this.layout = null;
      this.paintStatus();
      return Promise.resolve(null);
    }
    const seq = ++this.layoutSeq;
    const run = layout(this.host.rk, this.host.programId, d)
      .then((l) => {
        if (seq !== this.layoutSeq || this.draft !== d) return l;
        this.layout = l;
        this.error = "";
        this.paintDetail();
        return l;
      })
      .catch((e) => {
        if (seq === this.layoutSeq && this.draft === d) {
          this.layout = null;
          this.error = errText(e);
          this.paintDetail();
        }
        return null;
      });
    return run;
  }

  /** The draft changed: mark it, and lay it out again. */
  private changed(repaint = true, ms = 200) {
    this.dirty = true;
    if (repaint) this.paintDetail();
    this.relayout(ms);
  }

  private async save() {
    const d = this.draft;
    if (!d || this.busy) return;
    if (this.tab === "c") return this.saveC();
    if (!/^[A-Za-z_]\w*$/.test(d.name)) {
      this.error = "The type needs a name (letters, digits, _)";
      return this.paintDetail();
    }
    this.busy = true;
    this.error = "";
    this.paintDetail();
    try {
      clearTimeout(this.layoutTimer);
      const l = await this.runLayout();
      if (!l) throw new Error(this.error || "the daemon couldn't lay the type out");
      if (!l.ok) throw new Error(l.errors[0] ?? d.fields.find((f) => f.problem)?.problem ?? d.values.find((v) => v.problem)?.problem ?? "the C has errors");
      const renamed = !!d.from && d.fromName !== d.name;
      if (l.identical && !renamed) {
        this.draft = null;
        toast(d.from ? `No changes to ${d.kind} ${d.name}` : `${d.kind} ${d.name} is already the program's`);
        this.busy = false;
        if (this.shown) await this.show(this.shown);
        return this.paintDetail();
      }
      const bodies = saveBodies(l);
      const verb = renamed ? "Rename" : d.from ? "Edit" : "Create";
      const label = renamed ? `Rename ${d.kind} ${d.fromName} to ${d.name}` : `${verb} ${d.kind} ${d.name}`;
      let r;
      if (renamed) {
        // The old name's binding goes: its uses by name fall back to what it was before.
        const b = await this.host.rk.assertions.blame({ key: { programId: this.host.programId, kind: FactKind.TYPE_DEF, sub: `name:${keyOf(d.kind, d.fromName)}` } });
        const live = b.candidates.filter((c) => c.op === AssertionOp.ASSERT && (c.status === AssertionStatus.EFFECTIVE || c.status === AssertionStatus.SHADOWED)).map((c) => c.seq);
        r = await this.host.edits.bodiesAndRetract(label, bodies, live);
      } else r = this.shown?.project && d.from ? await this.host.edits.projectBodies(label, bodies) : await this.host.edits.bodies(label, bodies);
      this.draft = null;
      this.renaming = false;
      toast(renamed ? `Renamed ${d.kind} ${d.fromName} to ${d.name}` : `${verb === "Edit" ? "Saved" : "Created"} ${d.kind} ${d.name}`, { action: { label: "Undo", run: () => void this.host.edits.undo().catch((e) => toast(errText(e), { kind: "error" })) } });
      await this.host.settle(r.revision);
      await this.showAfterSave(d.kind, d.name);
    } catch (e) {
      this.error = errText(e).replace(/^assertions\[\d+\]:\s*/, "");
    } finally {
      this.busy = false;
    }
    this.paintDetail();
  }

  /** Saves the C tab: every type the C declares that is new or changed, one revision. */
  private async saveC() {
    const d = this.draft;
    if (!d || this.busy) return;
    this.busy = true;
    this.error = "";
    this.notes = [];
    this.paintDetail();
    try {
      const parsed = await parseText(this.host.rk, this.host.programId, this.cText, "edit.h");
      this.notes = parsed.diagnostics.filter((x) => x.severity !== ParseCSeverity.NOTE).map((x) => ({ line: x.line, text: x.text, error: x.severity === ParseCSeverity.ERROR }));
      if (parsed.errors) throw new Error(`The C has ${parsed.errors} error${parsed.errors === 1 ? "" : "s"}; the first at line ${this.notes.find((n) => n.error)?.line ?? "?"}`);
      const mine = parsed.named.filter((n) => !n.system);
      if (!mine.length) throw new Error("The C declares no struct, union, enum or typedef");
      const changed = mine.filter((n) => n.existingHash !== n.hash);
      if (!changed.length) {
        this.draft = null;
        toast("No changes");
        this.busy = false;
        if (this.shown) await this.show(this.shown);
        return this.paintDetail();
      }
      const bodies = headerImportPlan(parsed, { keys: changed.map((n) => n.key) }).bodies;
      const main = changed.find((n) => n.key === keyOf(d.kind, d.name)) ?? changed[0];
      const label = changed.length === 1 ? `Edit ${main.key} in C` : `Edit ${changed.length} types in C`;
      const r = this.shown?.project ? await this.host.edits.projectBodies(label, bodies) : await this.host.edits.bodies(label, bodies);
      this.draft = null;
      toast(changed.length === 1 ? `Saved ${main.key}` : `Saved ${changed.map((n) => n.key).join(", ")}`, { action: { label: "Undo", run: () => void this.host.edits.undo().catch((e) => toast(errText(e), { kind: "error" })) } });
      await this.host.settle(r.revision);
      const [kind, ...rest] = main.key.split(" ");
      await this.showAfterSave(kind as DraftKind, rest.join(" "));
    } catch (e) {
      this.error = errText(e);
    } finally {
      this.busy = false;
    }
    this.paintDetail();
  }

  private async showAfterSave(kind: string, name: string) {
    this.filter.value = this.filter.value && !name.toLowerCase().includes(this.filter.value.toLowerCase()) ? "" : this.filter.value;
    await this.load();
    const want = (t: TypeDefinition) => t.name === name && KIND_LABEL[t.kind] === kind && !t.superseded;
    const shown = this.types.find(want) ?? (await this.host.rk.queries.findTypes({ programId: this.host.programId, nameContains: name, page: { pageSize: 50 } })).types.find(want);
    if (shown) await this.show(shown);
  }

  private cancel() {
    clearTimeout(this.layoutTimer);
    this.layoutSeq++;
    this.draft = null;
    this.error = "";
    this.notes = [];
    this.renaming = false;
    this.paintDetail();
  }

  /** Switches the editor between its fields and its C. */
  private switchTab(tab: "fields" | "c") {
    const d = this.draft;
    if (!d || tab === this.tab) return;
    if (tab === "c") {
      this.cText = this.dirty || !this.shown ? readable(d) : this.cBase || readable(d);
      this.cBase = this.cText;
      this.notes = [];
    } else if (this.cText !== this.cBase && !confirm("Discard the edits to the C?")) return;
    this.tab = tab;
    this.error = "";
    this.paintDetail();
    if (tab === "fields") this.relayout(0);
  }

  /** Fills in measured sizes for fields from a paste (hash types need their display). */
  private async describeFields(fields: FieldDraft[]) {
    const want = fields.filter((f) => f.hash && !f.type).map((f) => f.hash);
    if (want.length) {
      const r = await this.host.rk.queries.getTypes({ programId: this.host.programId, hashes: [...new Set(want)], includeDependencies: true });
      for (const t of r.types) this.deps.set(t.hash, t);
      for (const f of fields)
        if (f.hash && !f.type) {
          f.type = f.shown = this.disp(f.hash);
          const t = this.deps.get(f.hash);
          if (t) f.size = Number(t.size);
        }
    }
  }

  /**
   * Member declarations typed or pasted where a field's type goes
   * ("void (*cb)(int)", "int a; char *s;"): they become fields, at `at`
   * (replacing the field there when `replace`). False when the text is a
   * type spelling, not declarations.
   */
  private async pasteFields(text: string, at: number, replace: boolean): Promise<boolean> {
    const d = this.draft;
    if (!d) return false;
    const r = await parseMembers(this.host.rk, this.host.programId, text, d.kind === "union");
    if (!r || !r.fields.length) {
      if (r?.errors.length && !replace) this.error = `Paste: ${r.errors[0]}`;
      return false;
    }
    await this.describeFields(r.fields);
    if (d.kind === "struct" && d.packing === "explicit") {
      // After the field before them, at their alignment, in their own order.
      const probe = { ...d, fields: r.fields };
      await measure(this.host.rk, this.host.programId, probe);
      const before = byOffset(d.fields.filter((_, i) => !(replace && i === at)));
      const prev = replace ? d.fields[at] : null;
      let base = prev ? prev.offset : before.reduce((m, f) => Math.max(m, Math.ceil((extent(f)?.end ?? f.offset * 8) / 8)), 0);
      const align = r.fields.reduce((m, f) => Math.max(m, f.align), 1);
      base = Math.ceil(base / align) * align;
      for (const f of r.fields) f.offset += base;
      const end = r.fields.reduce((m, f) => Math.max(m, f.offset + Math.max(0, f.size)), 0);
      d.size = Math.max(d.size, end);
    }
    d.fields.splice(replace ? at : at, replace ? 1 : 0, ...r.fields);
    this.error = "";
    return true;
  }

  /** A field's type was typed: declarations become fields, a spelling stays (the layout checks it). */
  private async typeCommitted(i: number) {
    const d = this.draft;
    const f = d?.fields[i];
    if (!d || !f) return;
    const text = f.type.trim();
    // Declarations ("void (*cb)(int)", "int a; char *s;") become fields; a
    // type spelling declares none and stays (the layout checks it).
    if (text && f.type !== f.shown && (await this.pasteFields(text, i, true))) return this.changed();
    f.hash = f.type === f.shown ? f.hash : "";
    f.size = f.hash ? f.size : -1;
    this.changed();
  }

  /** Inserts a field at a byte offset: in a gap it takes the gap's bytes; over fields, they move up to make room. */
  async insertAt(offset: number, type = "undefined4", name = "") {
    const d = this.draft;
    if (!d || d.kind !== "struct") return;
    const f = newField(name || `field_0x${offset.toString(16)}`, type, offset);
    f.size = -1;
    if (d.packing !== "explicit") {
      // Natural layouts: before the first field at or past the offset.
      const i = d.fields.findIndex((x) => x.offset >= offset);
      d.fields.splice(i < 0 ? d.fields.length : i, 0, f);
      return this.changed();
    }
    await measure(this.host.rk, this.host.programId, { ...d, fields: [f] });
    const size = Math.max(0, f.size);
    const start = offset * 8, end = start + size * 8;
    const inside = d.fields.find((x) => {
      const e = extent(x);
      return e && e.start < start && e.end > start;
    });
    if (inside) {
      this.error = `0x${offset.toString(16)} is inside ${inside.name || "a field"}: delete it, or insert at its offset`;
      return this.paintDetail();
    }
    const hit = d.fields.some((x) => {
      const e = extent(x);
      return e && e.start < end && e.end > start;
    });
    // Over fields: they (and everything after them) move up to make room.
    if (hit) for (const x of d.fields) if (x.offset * 8 + x.bitOffset >= start) x.offset += size;
    d.fields.push(f);
    d.fields = byOffset(d.fields);
    const last = d.fields.reduce((m, x) => Math.max(m, Math.ceil((extent(x)?.end ?? 0) / 8)), 0);
    d.size = Math.max(d.size, last);
    this.changed();
  }

  /** Deletes a field: an explicit layout keeps the others where they are (its bytes become filler). */
  deleteField(i: number) {
    const d = this.draft;
    if (!d) return;
    d.fields.splice(i, 1);
    this.changed();
  }

  /** Resizes an explicit struct: it can't cut a field off. */
  private resize(n: number) {
    const d = this.draft;
    if (!d) return;
    const end = d.fields.reduce((m, f) => Math.max(m, Math.ceil((extent(f)?.end ?? 0) / 8)), 0);
    if (n < end) {
      this.error = `Fields reach 0x${end.toString(16)}: delete or move them before shrinking below that`;
      return this.paintDetail();
    }
    d.size = n;
    this.error = "";
    this.changed();
  }

  // -------------------------------------------------------------- drawing --

  private paintDetail() {
    const d = this.draft;
    const t = this.shown;
    if (d) return this.paintEditor(d);
    if (!t) {
      fill(this.detail, h("div", { class: "notes-empty dim" }, "Pick a type to see its fields, or create one."), this.error ? h("div", { class: "error" }, this.error) : null);
      return;
    }
    const rows: HTMLElement[] = [];
    const uses = this.host.findUses && t.detail.case === "composite" ? this.host.findUses : null;
    if (t.detail.case === "composite") {
      rows.push(h("tr", { class: "dim" }, h("th", {}, "Offset"), h("th", {}, "Size"), h("th", {}, "Type"), h("th", {}, "Name"), h("th", {}, "Bits"), uses ? h("th", {}) : null));
      for (const f of t.detail.value.fields) {
        const ft = this.deps.get(f.typeHash);
        const field = { offset: f.offset, name: f.name };
        rows.push(
          h(
            "tr",
            { "data-testid": "type-field" },
            h("td", { class: "mono" }, `0x${Number(f.offset).toString(16)}${f.bitSize ? `:${f.bitOffset}` : ""}`),
            h("td", { class: "mono" }, String(Number(ft?.size ?? 0n))),
            h("td", { class: "mono k-ty" }, this.disp(f.typeHash)),
            h("td", { class: "mono" }, f.name || "(anonymous)"),
            h("td", { class: "mono dim" }, f.bitSize ? `${f.bitSize} bit${f.bitSize === 1 ? "" : "s"}` : ""),
            uses && f.name
              ? h("td", {}, h("button", { class: "btn small", "data-testid": "field-find-uses", title: `Where ${t.name}.${f.name} is read and written, in every function's decompiled C`, onclick: () => uses(t.hash, t.name, field) }, "Uses"))
              : uses
                ? h("td", {})
                : null,
          ),
        );
      }
    } else if (t.detail.case === "enumeration") {
      rows.push(h("tr", { class: "dim" }, h("th", {}, "Name"), h("th", {}, "Value"), h("th", {}, "Hex")));
      for (const v of t.detail.value.values) rows.push(h("tr", { "data-testid": "type-field" }, h("td", { class: "mono" }, v.name), h("td", { class: "mono" }, String(v.value)), h("td", { class: "mono dim" }, v.value < 0n ? "" : `0x${v.value.toString(16)}`)));
    } else if (t.detail.case === "typedefType") {
      rows.push(h("tr", {}, h("td", { class: "dim" }, "Target"), h("td", { class: "mono k-ty" }, this.disp(t.detail.value.targetHash))));
    }
    const editable = this.canEdit() && !t.superseded && (t.kind === TypeKind.STRUCT || t.kind === TypeKind.UNION || t.kind === TypeKind.ENUM || t.kind === TypeKind.TYPEDEF);
    const why = this.canEdit() ? "" : "Editing types needs a daemon that parses C (api_minor 25, feature parse-c)";
    fill(
      this.detail,
      h(
        "div",
        { class: "types-title" },
        h("span", { class: "badge b-kind" }, KIND_LABEL[t.kind] ?? "type"),
        h("span", { class: "mono types-big", "data-testid": "type-title" }, t.name),
        h("span", { class: "dim" }, `${Number(t.size)} bytes${t.alignment ? ` · align ${t.alignment}` : ""}${t.detail.case === "composite" && t.detail.value.packed ? " · packed" : ""}`),
        t.superseded ? h("span", { class: "badge b-none" }, "superseded") : null,
        h("span", { class: "spacer" }),
        editable || why ? h("button", { class: "btn small", "data-testid": "type-edit", disabled: !editable, title: why || "Edit the fields", onclick: () => this.edit("fields") }, "Edit") : null,
        editable ? h("button", { class: "btn small", "data-testid": "type-edit-c", title: "Edit the C definition; saving parses it with the program's types in scope", onclick: () => this.edit("c") }, "Edit in C") : null,
        editable ? h("button", { class: "btn small", "data-testid": "type-duplicate", title: "A copy under another name", onclick: () => void this.duplicate() }, "Duplicate…") : null,
        editable ? h("button", { class: "btn small", "data-testid": "type-rename", title: "The definition under a new name; the old name's binding goes", onclick: () => void this.rename() }, "Rename…") : null,
        this.host.archives && !t.superseded ? h("button", { class: "btn small", "data-testid": "type-move", title: "File the type under another category (folder)", onclick: () => void this.moveShown() }, "Move to category…") : null,
        this.host.projectTypes && !t.superseded && t.name && !t.project && t.origin?.source.case === "asserted"
          ? h("button", { class: "btn small", "data-testid": "type-to-project", title: "Make it the project's: every program of the project sees it, and an edit reaches them all (one undo step)", onclick: () => void this.copyShown(CopyTypesMode.MOVE_TO_PROJECT) }, "Move to project")
          : null,
        this.host.projectTypes && !t.superseded && t.project
          ? h("button", { class: "btn small", "data-testid": "type-to-program", title: "Give this program its own copy: it then changes alone (one undo step)", onclick: () => void this.copyShown(CopyTypesMode.COPY_TO_PROGRAM) }, "Copy to program")
          : null,
        uses ? h("button", { class: "btn small", "data-testid": "type-find-uses", title: "Where this type and its fields are used, in every function's decompiled C", onclick: () => uses(t.hash, t.name) }, "Find uses") : null,
        h("button", { class: "btn small", title: "Retype the selected variable, parameter, global or function result to this type", "data-testid": "type-apply", onclick: () => void this.host.apply(t, false) }, "Apply"),
        h("button", { class: "btn small", title: "Retype the selection to a pointer to this type", "data-testid": "type-apply-ptr", onclick: () => void this.host.apply(t, true) }, "Apply as pointer"),
      ),
      h("div", { class: "dim types-origin" }, `${t.project ? "project · " : ""}${originText(t.origin)}${t.category ? ` · ${t.category}` : ""} · ${t.hash}`),
      h("table", { class: "types-table" }, ...rows),
      h("pre", { class: "types-c mono", "data-testid": "type-c", tabindex: "0", "aria-label": `C definition of ${t.name}` }, t.cDefinition),
      this.error ? h("div", { class: "error" }, this.error) : null,
    );
  }

  /** The editor's status line: what the daemon laid out. */
  private statusText(): string {
    const d = this.draft, l = this.layout;
    if (!d) return "";
    if (!/^[A-Za-z_]\w*$/.test(d.name)) return "Name the type to lay it out.";
    if (!l) return "Laying out…";
    if (d.kind === "typedef") return `Laid out by the daemon for ${l.profile}${l.identical ? " · no changes" : ""}`;
    if (d.kind === "enum") return `Laid out by the daemon for ${l.profile}: ${l.size} bytes${l.identical ? " · no changes" : ""}`;
    return `Laid out by the daemon for ${l.profile}: size 0x${l.size.toString(16)} (${l.size}), align ${l.align || "?"}${l.packed ? ", packed" : ""}${l.identical ? " · no changes" : ""}`;
  }

  private paintStatus() {
    const el = this.detail.querySelector<HTMLElement>("[data-testid=type-layout]");
    if (el) el.textContent = this.statusText();
  }

  private paintEditor(d: Draft) {
    // Repainting keeps the focused input (and its caret) focused.
    const focused = document.activeElement as HTMLInputElement | null;
    const fk = focused?.dataset?.fk;
    const sel = fk && "selectionStart" in focused! ? [focused!.selectionStart, focused!.selectionEnd] : null;
    const explicit = d.kind === "struct" && d.packing === "explicit";
    const num = (v: number, set: (n: number) => void, attrs: Record<string, string> = {}) => {
      const el = h("input", { class: "cell num mono", value: attrs.hex ? `0x${v.toString(16)}` : String(v), inputmode: "numeric", ...attrs });
      el.removeAttribute("hex");
      el.addEventListener("change", () => {
        const n = parseNum(el.value);
        if (n !== null && n >= 0) set(n);
        else this.paintDetail();
      });
      return el;
    };
    const text = (v: string, set: (s: string) => void, attrs: Record<string, string> = {}, commit?: () => void) => {
      const el = h("input", { class: "cell mono", value: v, spellcheck: "false", ...attrs });
      el.addEventListener("input", () => {
        set(el.value);
        this.dirty = true;
      });
      el.addEventListener("change", () => (commit ? commit() : this.changed(false)));
      el.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          if (commit) {
            el.blur();
            return;
          }
          void this.save();
        } else if (e.key === "Escape") this.cancel();
      });
      return el;
    };
    const body: (HTMLElement | null)[] = [];
    if (this.tab === "c") {
      body.push(this.cEditor());
    } else if (d.kind === "struct" || d.kind === "union") {
      body.push(this.layoutControls(d));
      const rows: HTMLElement[] = [h("tr", { class: "dim" }, h("th", { title: explicit ? "Byte offset, or byte:bit for a bitfield (decimal or 0x…)" : "Where the daemon put it (byte:bit for a bitfield)" }, explicit ? "Offset (byte:bit)" : "Offset"), h("th", {}, "Size"), h("th", {}, "Type"), h("th", {}, "Name"), h("th", { title: "Bitfield width in bits (0: not a bitfield)" }, "Width"), h("th", { title: "A flexible array member (type name[]), last in the struct" }, "[]"), h("th", {}))];
      const order = explicit ? byOffset(d.fields) : d.fields;
      let pos = 0;
      const last = order.at(-1);
      order.forEach((f) => {
        const i = d.fields.indexOf(f);
        if (explicit) {
          const at = f.offset * 8 + f.bitOffset;
          if (at >= pos + 8 || (at > pos && !f.bitSize)) rows.push(this.fillerRow(pos, at));
          pos = Math.max(pos, extent(f)?.end ?? at);
        }
        const offCell = explicit
          ? text(`0x${f.offset.toString(16)}${f.bitSize ? `:${f.bitOffset}` : ""}`, () => undefined, { "data-testid": "field-offset", "data-fk": `off${i}`, title: "Byte offset, or byte:bit for a bitfield", "aria-label": `Offset of field ${i + 1}` }, () => {
              const el = this.detail.querySelector<HTMLInputElement>(`[data-fk=off${i}]`);
              const p = parsePos(el?.value ?? "");
              if (!p) {
                this.error = `"${el?.value}" isn't an offset (0x10, 16, or byte:bit as 0x4:3)`;
                return this.paintDetail();
              }
              f.offset = p.byte;
              f.bitOffset = p.bit;
              this.error = "";
              this.changed();
            })
          : h("span", { class: "mono", "data-testid": "field-offset" }, `0x${f.offset.toString(16)}${f.bitSize ? `:${f.bitOffset}` : ""}`);
        const flex = h("input", { type: "checkbox", "data-testid": "field-flex", "aria-label": "Flexible array member", disabled: f !== last || !!f.bitSize || d.kind === "union" });
        flex.checked = f.flex;
        flex.addEventListener("change", () => {
          f.flex = flex.checked;
          this.changed();
        });
        rows.push(
          h(
            "tr",
            { "data-testid": "edit-field", class: f.problem ? "has-problem" : "" },
            h("td", {}, offCell),
            h("td", { class: "mono dim", "data-testid": "field-size" }, f.flex ? "0" : f.size < 0 ? "?" : String(f.size)),
            h("td", {}, text(f.type, (s) => (f.type = s), { "data-testid": "field-type", "data-fk": `type${i}`, placeholder: "int, char *, void (*)(int), or declarations", "aria-label": `Type of field ${i + 1}` }, () => void this.typeCommitted(i))),
            h("td", {}, text(f.name, (s) => (f.name = s), { "data-testid": "field-name", "data-fk": `name${i}`, placeholder: "name", "aria-label": `Name of field ${i + 1}` })),
            h("td", {}, num(f.bitSize, (n) => {
              f.bitSize = n;
              if (!n) f.bitOffset = 0;
              this.changed();
            }, { "data-testid": "field-bits", "data-fk": `bits${i}`, title: "Bitfield width (0: not a bitfield)", "aria-label": `Bitfield width of field ${i + 1}` })),
            h("td", {}, flex),
            h(
              "td",
              { class: "row-actions" },
              !explicit ? h("button", { class: "icon", title: "Insert a field above", "aria-label": "Insert a field above", onclick: () => { d.fields.splice(i, 0, newField(`field_${d.fields.length}`, "int", f.offset)); this.changed(); } }, "⤒") : null,
              !explicit ? h("button", { class: "icon", title: "Move up", "aria-label": "Move up", onclick: () => this.move(i, -1) }, "↑") : null,
              !explicit ? h("button", { class: "icon", title: "Move down", "aria-label": "Move down", onclick: () => this.move(i, 1) }, "↓") : null,
              h("button", { class: "icon", title: explicit ? "Delete the field (its bytes become undefined filler)" : "Delete the field", "aria-label": "Delete the field", "data-testid": "field-delete", onclick: () => this.deleteField(i) }, "✕"),
            ),
          ),
        );
        if (f.problem) rows.push(h("tr", { class: "field-problem" }, h("td", {}), h("td", { colspan: "6", class: "error", "data-testid": "field-problem" }, f.problem)));
      });
      if (explicit && d.size * 8 > pos) rows.push(this.fillerRow(pos, d.size * 8));
      body.push(h("table", { class: "types-table editing" }, ...rows));
      body.push(this.pasteBox(d));
    } else if (d.kind === "enum") {
      const size = h("select", { class: "filter select", "aria-label": "Enum size", "data-testid": "enum-size" }, h("option", { value: "0" }, "C's rules"), ...[1, 2, 4, 8].map((n) => h("option", { value: String(n) }, `${n} byte${n === 1 ? "" : "s"}`)));
      size.value = String(d.enumSize);
      size.addEventListener("change", () => {
        d.enumSize = Number(size.value);
        this.changed();
      });
      const signed = h("input", { type: "checkbox", "data-testid": "enum-signed", disabled: !d.enumSize });
      signed.checked = d.enumSigned;
      signed.addEventListener("change", () => {
        d.enumSigned = signed.checked;
        this.changed();
      });
      body.push(
        h(
          "div",
          { class: "types-actions" },
          h("label", { class: "dim small-label" }, "size", size),
          h("label", { class: "dim small-label" }, signed, "signed"),
          h("button", { class: "btn small", "data-testid": "enum-sort", title: "Order the values by value", onclick: () => this.sortValues() }, "Sort by value"),
        ),
      );
      const dupNames = new Set(d.values.map((v) => v.name).filter((n, i, a) => a.indexOf(n) !== i));
      const rows: HTMLElement[] = [h("tr", { class: "dim" }, h("th", {}, "Name"), h("th", { title: "A C constant expression (1 << 3, OTHER + 1); empty: the previous value + 1" }, "Value"), h("th", {}, "="), h("th", {}))];
      d.values.forEach((v, i) => {
        rows.push(
          h(
            "tr",
            { "data-testid": "edit-field", class: v.problem || dupNames.has(v.name) ? "has-problem" : "" },
            h("td", {}, text(v.name, (s) => (v.name = s), { "data-testid": "enum-name", "data-fk": `ename${i}`, "aria-label": `Name of value ${i + 1}` })),
            h("td", {}, text(v.value, (s) => (v.value = s), { "data-testid": "enum-value", "data-fk": `evalue${i}`, placeholder: "previous + 1", "aria-label": `Value ${i + 1}` })),
            h("td", { class: "mono dim", "data-testid": "enum-shown" }, v.shown === undefined ? "" : `${v.shown}${BigInt(v.shown) >= 0n ? ` (0x${BigInt(v.shown).toString(16)})` : ""}`),
            h(
              "td",
              { class: "row-actions" },
              h("button", { class: "icon", title: "Move up", "aria-label": "Move up", onclick: () => this.moveValue(i, -1) }, "↑"),
              h("button", { class: "icon", title: "Move down", "aria-label": "Move down", onclick: () => this.moveValue(i, 1) }, "↓"),
              h("button", { class: "icon", title: "Delete", "aria-label": "Delete the value", "data-testid": "enum-delete", onclick: () => { d.values.splice(i, 1); this.changed(); } }, "✕"),
            ),
          ),
        );
        const problem = v.problem ?? (dupNames.has(v.name) ? `${v.name} is named twice` : "");
        if (problem) rows.push(h("tr", { class: "field-problem" }, h("td", { colspan: "4", class: "error", "data-testid": "field-problem" }, problem)));
      });
      body.push(h("table", { class: "types-table editing" }, ...rows));
      body.push(this.pasteBox(d));
    } else {
      body.push(h("table", { class: "types-table editing" }, h("tr", {}, h("td", { class: "dim" }, "Target"), h("td", {}, text(d.target, (s) => (d.target = s), { "data-testid": "typedef-target", "data-fk": "target", placeholder: "unsigned int, struct x *, void (*)(int)", "aria-label": "Target type" })))));
    }
    const add = () => {
      if (d.kind === "enum") {
        d.values.push({ name: `VALUE_${d.values.length}`, value: "" });
        return this.changed();
      }
      if (explicit) {
        const end = d.fields.reduce((m, f) => Math.max(m, Math.ceil((extent(f)?.end ?? 0) / 8)), 0);
        return void this.insertAt(end, "int", `field_${d.fields.length}`);
      }
      d.fields.push(newField(`field_${d.fields.length}`, "int", 0));
      this.changed();
    };
    const name = text(d.name, (s) => (d.name = s), { "data-testid": "type-name", "data-fk": "tname", placeholder: "name", class: "cell mono types-big", "aria-label": "Type name" });
    const size = explicit ? num(d.size, (n) => this.resize(n), { "data-testid": "type-size", "data-fk": "tsize", title: "Size in bytes (grow adds filler at the end)", hex: "1", "aria-label": "Size in bytes" }) : null;
    const tabs = h(
      "div",
      { class: "types-tabs", role: "tablist" },
      h("button", { class: "btn seg" + (this.tab === "fields" ? " on" : ""), role: "tab", "aria-selected": String(this.tab === "fields"), "data-testid": "type-tab-fields", onclick: () => this.switchTab("fields") }, d.kind === "enum" ? "Values" : d.kind === "typedef" ? "Target" : "Fields"),
      h("button", { class: "btn seg" + (this.tab === "c" ? " on" : ""), role: "tab", "aria-selected": String(this.tab === "c"), "data-testid": "type-tab-c", onclick: () => this.switchTab("c") }, "C"),
    );
    const verb = this.renaming ? `Renaming ${d.fromName} · the old name's binding goes (uses by hash keep the old definition)` : d.from ? `Editing ${d.from.slice(0, 16)} · saved as a new version bound to the name (user provenance, undoable)` : "A new type (user provenance, undoable)";
    fill(
      this.detail,
      h(
        "div",
        { class: "types-title" },
        h("span", { class: "badge b-kind" }, d.kind),
        this.tab === "fields" ? name : h("span", { class: "mono types-big" }, d.name),
        size && this.tab === "fields" ? h("label", { class: "dim small-label" }, "size", size) : null,
        h("span", { class: "spacer" }),
        tabs,
      ),
      h("div", { class: "dim types-origin" }, verb),
      ...body,
      this.tab === "fields" ? h("div", { class: "dim small", "data-testid": "type-layout", "aria-live": "polite" }, this.statusText()) : null,
      h(
        "div",
        { class: "types-actions" },
        this.tab === "fields" && d.kind !== "typedef" ? h("button", { class: "btn small", "data-testid": "field-add", onclick: add }, d.kind === "enum" ? "+ value" : "+ field") : null,
        this.tab === "fields" && d.kind === "struct" ? h("button", { class: "btn small", "data-testid": "field-insert-at", title: "A field at a byte offset: in undefined filler it takes those bytes; over fields, they move up", onclick: () => void this.askInsert() }, "Insert at offset…") : null,
        h("span", { class: "spacer" }),
        h("button", { class: "btn small", "data-testid": "type-cancel", onclick: () => this.cancel() }, "Cancel"),
        h("button", { class: "btn small primary", "data-testid": "type-save", onclick: () => void this.save() }, this.busy ? "Saving…" : "Save"),
      ),
      this.error ? h("div", { class: "error", "data-testid": "type-error" }, this.error) : null,
      this.layout?.errors.length && this.tab === "fields" ? h("div", { class: "error", "data-testid": "type-layout-error" }, this.layout.errors.join(" · ")) : null,
    );
    if (fk) {
      const el = this.detail.querySelector<HTMLInputElement>(`[data-fk="${fk}"]`);
      if (el) {
        el.focus({ preventScroll: true });
        if (sel && el.setSelectionRange) {
          try {
            el.setSelectionRange(sel[0], sel[1]);
          } catch {
            /* not a text input */
          }
        }
      }
    }
  }

  /** Packing and alignment (structs and unions). */
  private layoutControls(d: Draft): HTMLElement {
    const pack = h(
      "select",
      { class: "filter select", "aria-label": "Packing", "data-testid": "type-packing", title: "Explicit: fields stay at their offsets (gaps are undefined filler). Natural: C's layout for the field order. Packed, pack(N): as the attribute and #pragma pack" },
      d.kind === "struct" ? h("option", { value: "explicit" }, "explicit offsets") : null,
      h("option", { value: "natural" }, "natural (C rules)"),
      h("option", { value: "packed" }, "__attribute__((packed))"),
      ...[1, 2, 4, 8, 16].map((n) => h("option", { value: String(n) }, `#pragma pack(${n})`)),
    );
    pack.value = String(d.packing);
    pack.addEventListener("change", () => {
      const v = pack.value;
      d.packing = v === "explicit" || v === "natural" || v === "packed" ? v : (Number(v) as Packing);
      this.changed();
    });
    const align = h("select", { class: "filter select", "aria-label": "Alignment", "data-testid": "type-align", title: "aligned(N): the type's alignment at least N" }, h("option", { value: "0" }, "natural"), ...[1, 2, 4, 8, 16, 32, 64].map((n) => h("option", { value: String(n) }, `aligned(${n})`)));
    align.value = String(d.align);
    align.addEventListener("change", () => {
      d.align = Number(align.value);
      this.changed();
    });
    return h("div", { class: "types-actions" }, h("label", { class: "dim small-label" }, "packing", pack), h("label", { class: "dim small-label" }, "alignment", align));
  }

  /** A row of undefined filler in an explicit layout, with a button to put a field there. */
  private fillerRow(fromBits: number, toBits: number): HTMLElement {
    const from = Math.ceil(fromBits / 8), to = Math.floor(toBits / 8);
    const n = Math.max(0, to - from);
    return h(
      "tr",
      { class: "filler", "data-testid": "filler" },
      h("td", { class: "mono dim" }, `0x${from.toString(16)}`),
      h("td", { class: "mono dim" }, String(n)),
      h("td", { class: "mono dim", colspan: "4" }, `undefined${n > 1 ? `[${n}]` : ""} (filler)`),
      h("td", { class: "row-actions" }, n ? h("button", { class: "icon", title: "A field here", "aria-label": "A field here", "data-testid": "filler-add", onclick: () => void this.insertAt(from, n >= 4 ? "undefined4" : "undefined1") }, "+") : null),
    );
  }

  private async askInsert() {
    const r = await askFields("Insert a field", [
      { name: "offset", label: "Offset", placeholder: "0x10", required: true },
      { name: "type", label: "Type", placeholder: "undefined4", value: "undefined4" },
      { name: "name", label: "Name", placeholder: "field_0x10" },
    ]);
    if (!r) return;
    const off = parseNum(r.offset ?? "");
    if (off === null || off < 0) return toast(`"${r.offset}" isn't an offset`, { kind: "error" });
    await this.insertAt(off, r.type || "undefined4", r.name ?? "");
  }

  private move(i: number, by: number) {
    const d = this.draft;
    if (!d || i + by < 0 || i + by >= d.fields.length) return;
    const [x] = d.fields.splice(i, 1);
    d.fields.splice(i + by, 0, x);
    this.changed();
  }

  private moveValue(i: number, by: number) {
    const d = this.draft;
    if (!d || i + by < 0 || i + by >= d.values.length) return;
    const [x] = d.values.splice(i, 1);
    d.values.splice(i + by, 0, x);
    this.changed();
  }

  /** Orders an enum's values by value, each given its value (so "previous + 1" stays right). */
  private sortValues() {
    const d = this.draft;
    if (!d) return;
    if (d.values.some((v) => v.shown === undefined)) return toast("The values aren't evaluated yet", { kind: "error" });
    for (const v of d.values) v.value = v.shown!;
    d.values.sort((a, b) => (BigInt(a.shown!) < BigInt(b.shown!) ? -1 : BigInt(a.shown!) > BigInt(b.shown!) ? 1 : 0));
    this.changed();
  }

  /** "Paste C": member declarations (or enumerators) the daemon turns into rows. */
  private pasteBox(d: Draft): HTMLElement {
    const area = h("textarea", { class: "cell mono types-paste", rows: 3, spellcheck: "false", placeholder: d.kind === "enum" ? "RED = 1, GREEN, BLUE = 1 << 4" : "int count;\nvoid (*callback)(void *ctx, int n);\nchar name[16];", "data-testid": "type-paste", "aria-label": "C to add" });
    const go = async () => {
      const text = area.value.trim();
      if (!text) return;
      if (d.kind === "enum") {
        const parsed = await parseText(this.host.rk, this.host.programId, `enum __rk_probe_paste { ${text.replace(/,?\s*$/, "")} };\n`, "paste.h");
        const e = parsed.named.find((n) => n.key === "enum __rk_probe_paste");
        const node = e ? parsed.nodes[e.index] : undefined;
        if (!node || parsed.errors) {
          this.error = `Paste: ${parsed.diagnostics.find((x) => x.severity === ParseCSeverity.ERROR)?.text ?? "not enumerators"}`;
          return this.paintDetail();
        }
        d.values.push(...node.enumerators.map((v) => ({ name: v.name, value: String(v.value) })));
      } else {
        const at = d.fields.length;
        if (!(await this.pasteFields(text, at, false))) {
          this.error ||= "Paste: no member declarations (int a; char *b;)";
          return this.paintDetail();
        }
      }
      area.value = "";
      this.changed();
    };
    return h(
      "details",
      { class: "types-paste-box", "data-testid": "type-paste-box" },
      h("summary", { class: "dim" }, "Paste C…"),
      area,
      h("div", { class: "types-actions" }, h("span", { class: "dim small" }, d.kind === "enum" ? "Enumerators, as C writes them" : "Member declarations, as C writes them: function pointers, arrays, bitfields"), h("span", { class: "spacer" }), h("button", { class: "btn small", "data-testid": "type-paste-add", onclick: () => void go() }, "Add")),
    );
  }

  /** The C tab: the definition as text, with the parser's diagnostics at their lines. */
  private cEditor(): HTMLElement {
    const area = h("textarea", { class: "types-ctext mono", spellcheck: "false", "data-testid": "type-ctext", "data-fk": "ctext", "aria-label": "C definition", rows: Math.min(30, Math.max(8, this.cText.split("\n").length + 1)) });
    area.value = this.cText;
    const byLine = new Map<number, LineNote[]>();
    for (const n of this.notes) byLine.set(n.line, [...(byLine.get(n.line) ?? []), n]);
    const gutter = h("div", { class: "types-gutter mono", "aria-hidden": "true" });
    const paintGutter = () => {
      const count = area.value.split("\n").length;
      gutter.replaceChildren(
        ...Array.from({ length: count }, (_, i) => {
          const ns = byLine.get(i + 1);
          return h("div", { class: ns ? (ns.some((n) => n.error) ? "g-error" : "g-warning") : "", title: ns?.map((n) => n.text).join("\n") ?? "" }, String(i + 1));
        }),
      );
      gutter.scrollTop = area.scrollTop;
    };
    area.addEventListener("input", () => {
      this.cText = area.value;
      paintGutter();
    });
    area.addEventListener("scroll", () => (gutter.scrollTop = area.scrollTop));
    area.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        void this.save();
      } else if (e.key === "Escape") this.cancel();
      else if (e.key === "Tab" && !e.shiftKey) {
        e.preventDefault();
        area.setRangeText("    ", area.selectionStart, area.selectionEnd, "end");
        this.cText = area.value;
      }
    });
    paintGutter();
    const goLine = (line: number) => {
      const lines = area.value.split("\n");
      const start = lines.slice(0, line - 1).reduce((n, l) => n + l.length + 1, 0);
      area.focus();
      area.setSelectionRange(start, start + (lines[line - 1]?.length ?? 0));
    };
    return h(
      "div",
      { class: "types-cedit" },
      h("div", { class: "types-cwrap" }, gutter, area),
      this.notes.length
        ? h(
            "div",
            { class: "types-notes", "data-testid": "type-notes" },
            ...this.notes.map((n) => h("div", { class: n.error ? "error c-note" : "c-note warning", "data-testid": "type-note", "data-line": n.line, onclick: () => goLine(n.line) }, `line ${n.line}: ${n.text}`)),
          )
        : h(
            "div",
            { class: "dim small" },
            "Saving parses this C for the program's target, with its named types in scope (Ctrl+Enter)",
            this.draft?.kind === "struct" && this.draft.packing === "explicit" && this.dirty ? "; C's layout rules place the fields (the explicit offsets' filler isn't C)." : ".",
          ),
    );
  }

  private onListKey(e: KeyboardEvent) {
    const r = this.rows[this.active];
    switch (e.key) {
      case "ArrowDown":
        this.active = Math.min(this.rows.length - 1, this.active + 1);
        break;
      case "ArrowUp":
        this.active = Math.max(0, this.active - 1);
        break;
      case "ArrowRight":
        if (e.target === this.filter) return;
        if (r?.node && !this.open.has(r.node.key)) this.toggle(r.node, true);
        else if (r?.node) this.active = Math.min(this.rows.length - 1, this.active + 1);
        break;
      case "ArrowLeft": {
        if (e.target === this.filter) return;
        if (r?.node && this.open.has(r.node.key)) this.toggle(r.node, false);
        else {
          // To the parent branch.
          const depth = r?.depth ?? 0;
          for (let i = this.active - 1; i >= 0; i--)
            if (this.rows[i].node && this.rows[i].depth < depth) {
              this.active = i;
              break;
            }
        }
        break;
      }
      case "Enter":
        if (this.active < 0) this.active = 0;
        this.activate(this.active);
        return e.preventDefault();
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
    this.scrollToRow(this.active);
    this.paintRows();
  }

  /** Opens the branch at `path` ("Program types/structs/A"), for tests. */
  async openPath(...labels: string[]) {
    let nodes = this.roots;
    for (const l of labels) {
      const n = nodes.find((x) => x.label === l || x.label.startsWith(l));
      if (!n) throw new Error(`no branch ${l} in ${nodes.map((x) => x.label).join(", ")}`);
      this.open.add(n.key);
      await this.expand(n);
      this.flatten();
      nodes = n.children ?? [];
    }
  }

  /** The header import dialog's state (tests). */
  importState() {
    return headerImportDialog()?.describe() ?? null;
  }

  /** The export archive dialog's state (tests). */
  exportState() {
    return exportArchiveDialog()?.describe() ?? null;
  }

  private foldersShown(): [string, string[]][] {
    const out: [string, string[]][] = [];
    const walk = (nodes: TNode[]) => {
      for (const n of nodes) {
        if (n.category !== undefined && this.open.has(n.key)) out.push([n.category || "/", n.types.map((t) => keyOfType(t))]);
        if (n.children) walk(n.children);
      }
    };
    walk(this.roots);
    return out;
  }

  /** State for tests. */
  describe() {
    return {
      count: this.total,
      names: this.types.map((t) => `${KIND_LABEL[t.kind] ?? "?"} ${t.name}${t.superseded ? " (superseded)" : ""}`),
      tree: this.tree,
      rows: this.rows.length,
      branches: this.rows.filter((r) => r.node).map((r) => `${"  ".repeat(r.depth)}${r.node!.label} ${r.node!.count ?? ""}${this.open.has(r.node!.key) ? " (open)" : ""}`),
      group: this.group,
      /** The type rows under each open folder ("/net": ["struct wire"]). */
      folders: Object.fromEntries(this.foldersShown()),
      shown: this.shown ? { name: this.shown.name, hash: this.shown.hash, c: this.shown.cDefinition, origin: originText(this.shown.origin), category: this.shown.category, project: this.shown.project } : null,
      /** The Archives section (feature project-types). */
      archives: this.archivesOpen ? this.archiveList.map((a) => ({ name: a.name, enabled: a.enabled, applies: a.applies, kind: a.kind, functions: a.functions })) : null,
      editing: this.draft !== null,
      error: this.error,
      tab: this.tab,
      draft: this.draft
        ? {
            name: this.draft.name,
            size: this.draft.size,
            packing: String(this.draft.packing),
            align: this.draft.align,
            fields: this.draft.fields.map((f) => ({ name: f.name, type: f.type, offset: f.offset, bit: f.bitOffset, bits: f.bitSize, size: f.size, flex: f.flex, problem: f.problem ?? "" })),
            values: this.draft.values.map((v) => ({ name: v.name, value: v.value, shown: v.shown ?? "", problem: v.problem ?? "" })),
          }
        : null,
      layout: this.layout ? { ok: this.layout.ok, size: this.layout.size, align: this.layout.align, packed: this.layout.packed, identical: this.layout.identical, errors: this.layout.errors, profile: this.layout.profile } : null,
      notes: this.notes.map((n) => `${n.line}: ${n.text}`),
    };
  }
}

