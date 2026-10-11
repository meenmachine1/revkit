// Ghidra's searches (api_minor 41, feature "search"; docs/ui.md "Search"):
// Search Memory (S, Ctrl+Shift+E), Search Program Text (Ctrl+F in the Ghidra keymap),
// Search for Scalars and the decompiled-code search. Each is a floating
// dialog that stays open while the listing moves: Next and Previous from
// the cursor (F3 and Shift+F3 repeat the last search after it closes), and
// Search All into the dockable results table (sortable, filterable,
// copyable as CSV, a listing selection from the results, cancellable while
// it streams). Everything is searched on the daemon.

import {
  Endianness,
  SearchEncoding,
  SearchFormat,
  TextField,
  splitMatch,
  type DecompiledMatch,
  type MemoryMatch,
  type Revkit,
  type ScalarMatch,
  type TextMatch,
  type TypeUse,
  FieldAccess,
  TypeUseKind,
} from "@revkit/api";
import { errText, fmtAddr } from "../data/format";
import { h, overlayRoot, prefs } from "./dom";
import { toast } from "./dialogs";
import { VirtualRows } from "./vlist";

/** "uses": Find Uses of a type or field (feature type-uses), into the same results table. */
export type SearchKind = "memory" | "text" | "scalars" | "decompiled" | "uses";

export interface SearchHost {
  rk: Revkit;
  programId: string;
  addrWidth: number;
  /** The cursor (the listing's selected address). */
  location: () => bigint | null;
  /** The listing's selection as address ranges (inclusive); empty: none. */
  selection: () => [bigint, bigint][];
  /** The function the cursor is in. */
  currentFunction: () => bigint | null;
  /** Goes to an address in the listing. */
  navigate: (addr: bigint) => Promise<void>;
  /** Shows the decompiler at a line of a function, the match marked. */
  openDecompiled: (entry: bigint, line: number, from: number, to: number, address: bigint | null) => Promise<void>;
  /** Makes the listing's selection these ranges. */
  select: (ranges: [bigint, bigint][]) => void;
  /** Marks these addresses in the listing's gutter (null: none). */
  markHits: (addrs: Set<bigint> | null) => void;
  /** Shows the results view. */
  showResults: () => void;
  /** Closes the results view (its tab goes until a search opens it again). */
  closeResults: () => void;
  /** Gives the keyboard back to the listing. */
  focusListing: () => void;
}

const KIND_TITLE: Record<SearchKind, string> = {
  memory: "Search Memory",
  text: "Search Program Text",
  scalars: "Search for Scalars",
  decompiled: "Search Decompiled Code",
  uses: "Find Uses",
};

const MAX_ALL = 100_000;

/** A field use's access (TypeUse.access), as the results table shows it. */
const ACCESS_TEXT: Record<number, string> = {
  [FieldAccess.READ]: "read",
  [FieldAccess.WRITE]: "write",
  [FieldAccess.READ_WRITE]: "read/write",
  [FieldAccess.ADDRESS]: "address of",
};

// --------------------------------------------------------------- values --

/** "123", "-0x10", "0xffffffffffffffff" as a 64-bit two's complement int64, or null. */
export function parseValue(text: string): bigint | null {
  const t = text.trim().replace(/_/g, "");
  if (!/^[-+]?(0x[0-9a-f]+|[0-9]+)$/i.test(t)) return null;
  const neg = t.startsWith("-");
  const body = t.replace(/^[-+]/, "");
  let v = BigInt(body);
  if (neg) v = -v;
  if (v < -(1n << 63n) || v >= 1n << 64n) return null;
  if (v >= 1n << 63n) v -= 1n << 64n; // an unsigned 64-bit pattern
  return v;
}

function csvCell(s: string): string {
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function bytesHex(b: Uint8Array, max = 24): string {
  const out: string[] = [];
  for (let i = 0; i < Math.min(b.length, max); i++) out.push(b[i].toString(16).padStart(2, "0"));
  return out.join(" ") + (b.length > max ? " …" : "");
}

// --------------------------------------------------------------- results --

interface Column {
  title: string;
  /** CSS grid track. */
  width: string;
  numeric?: boolean;
}

interface ResultRow {
  /** Where it goes in the listing (null: nowhere). */
  addr: bigint | null;
  /** The selection it makes: [addr, end]. */
  end: bigint | null;
  cells: string[];
  sort: (string | number | bigint)[];
  /** The matched part of a cell, as JS string offsets. */
  hl?: { col: number; start: number; len: number };
  open: () => void;
}

class ResultSet {
  rows: ResultRow[] = [];
  order: number[] = [];
  sortCol = -1;
  sortDesc = false;
  filter = "";
  selected = new Set<number>();
  /** The row the keyboard is on (an index into `order`). */
  cursor = -1;
  running = true;
  truncated = false;
  error = "";
  cancelled = false;
  done = 0;
  total = 0;
  unit = "";
  elapsedMs = 0;
  abort = new AbortController();
  /** Set while sorted or filtered: `order` is rebuilt when rows arrive. */
  dirty = true;

  constructor(
    readonly id: number,
    readonly kind: SearchKind,
    readonly title: string,
    readonly columns: Column[],
  ) {}

  rebuild() {
    const f = this.filter.trim().toLowerCase();
    let idx = this.rows.map((_, i) => i);
    if (f) idx = idx.filter((i) => this.rows[i].cells.some((c) => c.toLowerCase().includes(f)));
    if (this.sortCol >= 0) {
      const c = this.sortCol;
      const dir = this.sortDesc ? -1 : 1;
      idx.sort((a, b) => {
        const x = this.rows[a].sort[c], y = this.rows[b].sort[c];
        return (x < y ? -1 : x > y ? 1 : a - b) * dir;
      });
    }
    this.order = idx;
    this.dirty = false;
  }

  status(): string {
    const n = this.rows.length;
    const shown = this.order.length !== n ? `${this.order.length.toLocaleString()} of ` : "";
    const what = `${shown}${n.toLocaleString()} ${n === 1 ? "match" : "matches"}`;
    if (this.error) return `${what} · ${this.error}`;
    if (this.running) {
      const pct = this.total > 0 ? ` · ${Math.floor((100 * this.done) / this.total)}%` : "";
      return `${what} · searching${this.unit && this.total ? ` ${this.done.toLocaleString()} of ${this.total.toLocaleString()} ${this.unit}` : ""}${pct}…`;
    }
    const ms = this.elapsedMs;
    const time = this.running ? "" : ` in ${ms < 1 ? "under 1 ms" : ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`}`;
    return `${what}${this.truncated ? ` (stopped at the limit)` : ""}${this.cancelled ? " · cancelled" : ""}${time}`;
  }

  csv(): string {
    const lines = [this.columns.map((c) => csvCell(c.title)).join(",")];
    for (const i of this.order) lines.push(this.rows[i].cells.map(csvCell).join(","));
    return lines.join("\n") + "\n";
  }
}

const ROW_H = 22;

/** The dockable results table (view "search"): recent result sets, newest first. */
export class SearchResultsView {
  readonly el: HTMLElement;
  private sets: ResultSet[] = [];
  private current: ResultSet | null = null;
  private seq = 0;
  private picker: HTMLSelectElement;
  private statusEl: HTMLElement;
  private bar: HTMLProgressElement;
  private cancelBtn: HTMLButtonElement;
  private filterEl: HTMLInputElement;
  private headEl: HTMLElement;
  private listEl: HTMLElement;
  /** The controls that act on the shown result set (disabled without one). */
  private setTools: (HTMLButtonElement | HTMLInputElement)[] = [];
  private vrows: VirtualRows;
  private raf = 0;

  constructor(
    el: HTMLElement,
    private host: SearchHost,
  ) {
    this.el = el;
    this.picker = h("select", { class: "filter select sr-picker", "aria-label": "Result sets", "data-testid": "search-sets" });
    this.picker.addEventListener("change", () => this.show(this.sets.find((s) => String(s.id) === this.picker.value) ?? null));
    this.statusEl = h("span", { class: "dim sr-status", "data-testid": "search-status", role: "status", "aria-live": "polite" });
    this.bar = h("progress", { class: "sr-bar", max: "1", value: "0", "aria-label": "Search progress", hidden: true });
    this.cancelBtn = h("button", { class: "btn small", type: "button", "data-testid": "search-cancel", hidden: true, onclick: () => this.cancel() }, "Cancel");
    this.filterEl = h("input", { class: "filter", placeholder: "Filter the results", spellcheck: "false", "aria-label": "Filter results", "data-testid": "search-filter" });
    this.filterEl.addEventListener("input", () => {
      if (!this.current) return;
      this.current.filter = this.filterEl.value;
      this.current.dirty = true;
      this.current.cursor = -1;
      this.repaint();
    });
    this.filterEl.addEventListener("keydown", (e) => this.onKey(e));
    const copy = h("button", { class: "btn small", type: "button", "data-testid": "search-csv", title: "Copy the rows shown as CSV", onclick: () => void this.copyCsv() }, "Copy CSV");
    const sel = h("button", { class: "btn small", type: "button", "data-testid": "search-select", title: "Select the chosen rows' addresses in the listing (every row shown when none is chosen)", onclick: () => this.makeSelection() }, "Make selection");
    const close = h("button", { class: "btn small", type: "button", "data-testid": "search-close-set", title: "Close this result set (the view closes with the last one)", onclick: () => this.closeSet() }, "Close set");
    const closeView = h("button", { class: "icon", type: "button", "data-testid": "search-close-view", title: "Close the search results (Escape)", "aria-label": "Close the search results", onclick: () => this.host.closeResults() }, "×");
    this.setTools = [copy, sel, close, this.filterEl];
    this.headEl = h("div", { class: "sr-row sr-head dim", role: "row" });
    this.listEl = h("div", { class: "sr-list", tabindex: "0", role: "grid", "aria-label": "Search results", "data-testid": "search-results" });
    this.listEl.addEventListener("keydown", (e) => this.onKey(e));
    this.vrows = new VirtualRows(this.listEl, ROW_H, (i) => this.renderRow(i));
    el.append(
      h("div", { class: "panel-head view-head" }, h("span", { class: "panel-title" }, "Search results"), this.picker, h("span", { class: "spacer" }), this.cancelBtn, close, closeView),
      h("div", { class: "fn-filter sr-tools" }, this.filterEl, copy, sel),
      h("div", { class: "sr-progress" }, this.bar, this.statusEl),
      this.headEl,
      this.listEl,
    );
    this.paintEmpty();
  }

  /** A new result set, shown. */
  add(kind: SearchKind, title: string, columns: Column[]): ResultSet {
    const s = new ResultSet(++this.seq, kind, title, columns);
    this.sets.unshift(s);
    for (const old of this.sets.splice(10)) old.abort.abort();
    this.show(s);
    return s;
  }

  get shown(): ResultSet | null {
    return this.current;
  }

  private show(s: ResultSet | null) {
    this.current = s;
    this.picker.replaceChildren(...this.sets.map((x) => h("option", { value: String(x.id) }, `${x.title} (${x.rows.length.toLocaleString()})`)));
    if (s) this.picker.value = String(s.id);
    this.picker.disabled = this.sets.length < 2;
    this.picker.hidden = !this.sets.length;
    for (const t of this.setTools) t.disabled = !s;
    this.filterEl.value = s?.filter ?? "";
    if (!s) return this.paintEmpty();
    this.headEl.style.gridTemplateColumns = s.columns.map((c) => c.width).join(" ");
    this.headEl.replaceChildren(
      ...s.columns.map((c, i) => {
        const sorted = s.sortCol === i;
        const b = h(
          "button",
          { class: "sr-th" + (c.numeric ? " num" : ""), type: "button", role: "columnheader", "aria-sort": sorted ? (s.sortDesc ? "descending" : "ascending") : "none", "data-testid": `search-col-${i}`, title: `Sort by ${c.title.toLowerCase()}` },
          c.title,
          sorted ? (s.sortDesc ? " ▾" : " ▴") : "",
        );
        b.addEventListener("click", () => this.sortBy(i));
        return b;
      }),
    );
    this.listEl.scrollTop = 0;
    this.repaint();
    this.markHits();
  }

  private paintEmpty() {
    this.headEl.replaceChildren();
    this.picker.hidden = !this.sets.length;
    for (const t of this.setTools) t.disabled = true;
    this.statusEl.textContent = "No searches yet: Search → Memory, Program text, Scalars, Decompiled code (their keys are in the menu)";
    this.bar.hidden = true;
    this.cancelBtn.hidden = true;
    this.vrows.count = 0;
    this.host.markHits(null);
  }

  sortBy(col: number) {
    const s = this.current;
    if (!s) return;
    if (s.sortCol === col) s.sortDesc = !s.sortDesc;
    else (s.sortCol = col), (s.sortDesc = false);
    s.dirty = true;
    this.show(s);
  }

  /** Rows arrived or progress moved: repaint on the next frame. */
  changed(s: ResultSet) {
    s.dirty = true;
    if (s !== this.current || this.raf) return;
    this.raf = requestAnimationFrame(() => {
      this.raf = 0;
      this.repaint();
      this.picker.querySelector<HTMLOptionElement>(`option[value="${s.id}"]`)?.replaceChildren(`${s.title} (${s.rows.length.toLocaleString()})`);
    });
  }

  finished(s: ResultSet) {
    this.changed(s);
    if (s === this.current) this.markHits();
  }

  private repaint() {
    const s = this.current;
    if (!s) return;
    if (s.dirty) s.rebuild();
    this.statusEl.textContent = s.status();
    this.statusEl.classList.toggle("error", !!s.error);
    this.bar.hidden = !s.running;
    if (s.running) {
      if (s.total > 0) this.bar.value = s.done / s.total;
      else this.bar.removeAttribute("value");
    }
    this.cancelBtn.hidden = !s.running;
    this.vrows.count = s.order.length;
  }

  private renderRow(i: number): HTMLElement {
    const s = this.current!;
    const ri = s.order[i];
    const r = s.rows[ri];
    const el = h("div", {
      class: "sr-row" + (s.selected.has(ri) ? " selected" : "") + (i === s.cursor ? " active" : ""),
      role: "row",
      "aria-selected": s.selected.has(ri) ? "true" : "false",
      "data-i": String(i),
      "data-testid": "search-row",
    });
    el.style.gridTemplateColumns = s.columns.map((c) => c.width).join(" ");
    r.cells.forEach((text, c) => {
      const cell = h("span", { class: "sr-cell" + (s.columns[c].numeric ? " num" : ""), role: "gridcell", title: text });
      if (r.hl && r.hl.col === c) cell.append(text.slice(0, r.hl.start), h("mark", { class: "sr-hit" }, text.slice(r.hl.start, r.hl.start + r.hl.len)), text.slice(r.hl.start + r.hl.len));
      else cell.textContent = text;
      el.append(cell);
    });
    el.addEventListener("mousedown", (e) => {
      e.preventDefault();
      this.listEl.focus({ preventScroll: true });
      this.pick(i, e.shiftKey, e.ctrlKey || e.metaKey);
    });
    return el;
  }

  /** Clicked (or Enter): choose the row and go to it. */
  private pick(i: number, extend = false, toggle = false) {
    const s = this.current;
    if (!s || i < 0 || i >= s.order.length) return;
    const ri = s.order[i];
    if (toggle) {
      if (s.selected.has(ri)) s.selected.delete(ri);
      else s.selected.add(ri);
    } else if (extend && s.cursor >= 0) {
      const [a, b] = s.cursor < i ? [s.cursor, i] : [i, s.cursor];
      for (let k = a; k <= b; k++) s.selected.add(s.order[k]);
    } else {
      s.selected = new Set([ri]);
    }
    s.cursor = i;
    this.vrows.reveal(i);
    if (!toggle && !extend) s.rows[ri].open();
  }

  /** F3 / Shift+F3 on a result set: the next or previous row. */
  step(backward: boolean): boolean {
    const s = this.current;
    if (!s || !s.order.length) return false;
    if (s.dirty) s.rebuild();
    const i = s.cursor < 0 ? (backward ? s.order.length - 1 : 0) : s.cursor + (backward ? -1 : 1);
    if (i < 0 || i >= s.order.length) {
      toast(backward ? "No earlier result" : "No more results");
      return true;
    }
    this.pick(i);
    return true;
  }

  private onKey(e: KeyboardEvent) {
    // Escape in the table (or an empty filter) closes the view.
    if (e.key === "Escape" && (e.target !== this.filterEl || !this.filterEl.value)) {
      e.preventDefault();
      e.stopPropagation();
      return this.host.closeResults();
    }
    const s = this.current;
    if (!s) return;
    const page = Math.max(1, Math.floor(this.listEl.clientHeight / ROW_H));
    const move = (to: number) => {
      if (!s.order.length) return;
      const i = Math.max(0, Math.min(s.order.length - 1, to));
      if (e.shiftKey) this.pick(i, true);
      else {
        s.cursor = i;
        s.selected = new Set([s.order[i]]);
        this.vrows.reveal(i);
      }
    };
    switch (e.key) {
      case "ArrowDown":
        move(s.cursor + 1);
        break;
      case "ArrowUp":
        move(s.cursor - 1);
        break;
      case "PageDown":
        move(s.cursor + page);
        break;
      case "PageUp":
        move(s.cursor - page);
        break;
      case "Home":
        if (e.target === this.filterEl) return;
        move(0);
        break;
      case "End":
        if (e.target === this.filterEl) return;
        move(s.order.length - 1);
        break;
      case "Enter":
        this.pick(s.cursor < 0 ? 0 : s.cursor);
        break;
      case "a":
        if (!(e.ctrlKey || e.metaKey) || e.target === this.filterEl) return;
        s.selected = new Set(s.order);
        this.vrows.paint();
        break;
      case "c":
        if (!(e.ctrlKey || e.metaKey) || e.target === this.filterEl) return;
        void this.copyCsv();
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
  }

  csv(): string {
    const s = this.current;
    if (!s) return "";
    if (s.dirty) s.rebuild();
    return s.csv();
  }

  async copyCsv() {
    const text = this.csv();
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      toast(`Copied ${this.current!.order.length.toLocaleString()} rows as CSV`);
    } catch {
      toast("Can't reach the clipboard", { kind: "error" });
    }
  }

  /** The chosen rows' (or every shown row's) addresses as the listing's selection. */
  makeSelection(): [bigint, bigint][] {
    const s = this.current;
    if (!s) return [];
    if (s.dirty) s.rebuild();
    const pick = s.selected.size > 1 ? [...s.selected] : s.order;
    const ranges: [bigint, bigint][] = [];
    for (const i of pick) {
      const r = s.rows[i];
      if (r.addr !== null) ranges.push([r.addr, r.end ?? r.addr]);
    }
    ranges.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const merged: [bigint, bigint][] = [];
    for (const r of ranges) {
      const last = merged[merged.length - 1];
      if (last && r[0] <= last[1] + 1n) last[1] = r[1] > last[1] ? r[1] : last[1];
      else merged.push([r[0], r[1]]);
    }
    if (!merged.length) {
      toast("No addresses to select");
      return merged;
    }
    this.host.select(merged);
    toast(`Selected ${merged.length.toLocaleString()} ${merged.length === 1 ? "range" : "ranges"} in the listing`);
    return merged;
  }

  cancel() {
    this.current?.abort.abort();
  }

  closeSet() {
    const s = this.current;
    if (!s) return;
    s.abort.abort();
    this.sets = this.sets.filter((x) => x !== s);
    this.show(this.sets[0] ?? null);
    if (!this.sets.length) this.host.closeResults();
  }

  private markHits() {
    const s = this.current;
    if (!s || s.kind === "decompiled") return this.host.markHits(null);
    const set = new Set<bigint>();
    for (const r of s.rows) if (r.addr !== null) set.add(r.addr);
    this.host.markHits(set.size ? set : null);
  }

  focus() {
    this.listEl.focus({ preventScroll: true });
  }

  /** The shown rows' cells (tests). */
  visible(): string[][] {
    const s = this.current;
    if (!s) return [];
    if (s.dirty) s.rebuild();
    return s.order.slice(0, 500).map((i) => s.rows[i].cells);
  }
}

// --------------------------------------------------------------- dialogs --

interface MemoryState {
  query: string;
  format: SearchFormat;
  encoding: SearchEncoding;
  caseSensitive: boolean;
  escapes: boolean;
  size: number;
  unsigned: boolean;
  order: Endianness;
  where: "all" | "selection";
  insn: boolean;
  data: boolean;
  undef: boolean;
  exec: boolean;
  alignment: number;
  wrap: boolean;
  limit: number;
}

interface TextState {
  query: string;
  regex: boolean;
  caseSensitive: boolean;
  wholeWord: boolean;
  fields: TextField[];
  where: "all" | "selection";
  wrap: boolean;
  limit: number;
}

interface ScalarState {
  mode: "exact" | "range" | "any";
  value: string;
  min: string;
  max: string;
  insn: boolean;
  data: boolean;
  where: "all" | "selection";
  wrap: boolean;
  limit: number;
}

interface DecompState {
  query: string;
  regex: boolean;
  caseSensitive: boolean;
  wholeWord: boolean;
  where: "all" | "selection" | "function";
  limit: number;
}

const ALL_FIELDS = [TextField.FUNCTIONS, TextField.COMMENTS, TextField.LABELS, TextField.MNEMONICS, TextField.OPERANDS, TextField.DATA_MNEMONICS, TextField.DATA_VALUES];
const FIELD_NAMES: Record<number, string> = {
  [TextField.FUNCTIONS]: "Functions",
  [TextField.COMMENTS]: "Comments",
  [TextField.LABELS]: "Labels",
  [TextField.MNEMONICS]: "Mnemonics",
  [TextField.OPERANDS]: "Operands",
  [TextField.DATA_MNEMONICS]: "Data mnemonics",
  [TextField.DATA_VALUES]: "Data values",
};
const FORMATS: { f: SearchFormat; label: string; hint: string; placeholder: string }[] = [
  { f: SearchFormat.HEX, label: "Hex", hint: "Bytes in hex; ? or . is a wildcard nibble: 48 8b ?? e8, 4? 0f", placeholder: "48 8b ?? e8" },
  { f: SearchFormat.STRING, label: "String", hint: "Text in the encoding chosen; ASCII letters in either case unless case-sensitive", placeholder: "usage:" },
  { f: SearchFormat.DECIMAL, label: "Decimal", hint: "Integers (or 0x hex), separated by spaces, each the size chosen", placeholder: "1000000 -1" },
  { f: SearchFormat.FLOAT, label: "Float", hint: "Numbers as 4-byte IEEE floats", placeholder: "3.14159" },
  { f: SearchFormat.DOUBLE, label: "Double", hint: "Numbers as 8-byte IEEE doubles", placeholder: "0.5" },
  { f: SearchFormat.BINARY, label: "Binary", hint: "8 binary digits a byte; x, ? or . is a bit that may be either", placeholder: "10xx0101 11110000" },
  { f: SearchFormat.REGEX, label: "Regular expression", hint: "RE2 over bytes: \\x55\\x48\\x89\\xe5, PK\\x03\\x04, [\\x20-\\x7e]{8,}", placeholder: "\\x55\\x48\\x89\\xe5" },
];

function load<T>(key: string, fallback: T): T {
  try {
    return { ...fallback, ...(JSON.parse(prefs.get(key) ?? "{}") as Partial<T>) };
  } catch {
    return fallback;
  }
}

function checkbox(label: string, checked: boolean, testid: string, title?: string): [HTMLLabelElement, HTMLInputElement] {
  const box = h("input", { type: "checkbox", "data-testid": testid });
  box.checked = checked;
  return [h("label", { class: "sd-check", title }, box, label), box];
}

function select<T extends string | number>(label: string, options: { value: T; label: string }[], value: T, testid: string): [HTMLLabelElement, HTMLSelectElement] {
  const sel = h("select", { class: "filter select", "data-testid": testid, "aria-label": label }, ...options.map((o) => h("option", { value: String(o.value) }, o.label)));
  sel.value = String(value);
  return [h("label", { class: "sd-field" }, h("span", { class: "dim" }, label), sel), sel];
}

/** A floating dialog that leaves the listing usable (Ghidra's search dialogs aren't modal). */
class Floating {
  readonly el: HTMLElement;
  readonly body: HTMLElement;
  readonly status: HTMLElement;
  readonly buttons: HTMLElement;
  onKey: ((e: KeyboardEvent) => boolean) | null = null;
  /** Called each time it opens (to bring choices up to date with the listing). */
  onOpen: (() => void) | null = null;

  constructor(
    title: string,
    readonly testid: string,
    private onClose: () => void,
  ) {
    this.body = h("div", { class: "sd-body" });
    this.status = h("div", { class: "sd-status dim", role: "status", "aria-live": "polite", "data-testid": `${testid}-status` });
    this.buttons = h("div", { class: "sd-buttons" });
    const close = h("button", { class: "icon sd-x", type: "button", "aria-label": "Close", title: "Close (Esc)", onclick: () => this.close() }, "×");
    this.el = h(
      "div",
      { class: "modal search-dialog", role: "dialog", "aria-modal": "false", "aria-label": title, "data-testid": testid },
      h("div", { class: "modal-title sd-title" }, h("span", {}, title), close),
      this.body,
      this.buttons,
      this.status,
    );
    this.el.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        this.close();
        return;
      }
      if (this.onKey?.(e)) {
        e.preventDefault();
        e.stopPropagation();
        return;
      }
      // The app's single-letter keys belong to the listing, not here.
      if (!e.ctrlKey && !e.metaKey && !e.altKey && !/^F\d+$/.test(e.key)) e.stopPropagation();
    });
  }

  get isOpen(): boolean {
    return this.el.isConnected;
  }

  open() {
    if (!this.isOpen) overlayRoot().append(this.el);
    this.onOpen?.();
    const focus = () => {
      const first = this.el.querySelector<HTMLInputElement>("[data-focus]") ?? this.el.querySelector<HTMLInputElement>("input[type=text], input:not([type])");
      first?.focus();
      first?.select();
    };
    focus();
    // Opened from the palette or a menu, which give the focus back when they close.
    setTimeout(() => {
      if (this.isOpen && !this.el.contains(document.activeElement)) focus();
    }, 0);
  }

  close() {
    if (!this.isOpen) return;
    this.el.remove();
    this.onClose();
  }

  say(text: string, kind: "" | "error" | "ok" = "") {
    this.status.textContent = text;
    this.status.className = `sd-status ${kind === "error" ? "error" : kind === "ok" ? "ok" : "dim"}`;
  }
}

// ------------------------------------------------------------ controller --

/** The four searches, their dialogs and the last search for F3. */
export class Search {
  readonly results: SearchResultsView;
  private dialogs = new Map<SearchKind, { f: Floating; read: () => void }>();
  private memory = load<MemoryState>("rk.search.memory", {
    query: "", format: SearchFormat.HEX, encoding: SearchEncoding.ASCII, caseSensitive: false, escapes: false, size: 4, unsigned: false,
    order: Endianness.UNSPECIFIED, where: "all", insn: true, data: true, undef: true, exec: false, alignment: 1, wrap: true, limit: 10_000,
  });
  private text = load<TextState>("rk.search.text", { query: "", regex: false, caseSensitive: false, wholeWord: false, fields: ALL_FIELDS, where: "all", wrap: true, limit: 10_000 });
  private scalars = load<ScalarState>("rk.search.scalars", { mode: "exact", value: "", min: "", max: "", insn: true, data: true, where: "all", wrap: true, limit: 10_000 });
  private decomp = load<DecompState>("rk.search.decompiled", { query: "", regex: false, caseSensitive: false, wholeWord: false, where: "all", limit: 10_000 });
  /** The search F3 repeats. */
  last: SearchKind | null = null;
  /** Where the last Next/Previous found something, and where that left the cursor
   * (a match inside an instruction selects the instruction: the next search
   * goes on from the match, not the instruction's start). */
  private hit: { addr: bigint; at: bigint | null } | null = null;
  private busy = false;

  constructor(
    resultsEl: HTMLElement,
    private host: SearchHost,
  ) {
    this.results = new SearchResultsView(resultsEl, host);
  }

  open(kind: SearchKind) {
    let d = this.dialogs.get(kind);
    if (!d) {
      d = this.build(kind);
      this.dialogs.set(kind, d);
    }
    for (const [k, other] of this.dialogs) if (k !== kind) other.f.close();
    d.f.open();
  }

  isOpen(kind?: SearchKind): boolean {
    return [...this.dialogs.entries()].some(([k, d]) => d.f.isOpen && (kind === undefined || k === kind));
  }

  private save() {
    prefs.set("rk.search.memory", JSON.stringify(this.memory));
    prefs.set("rk.search.text", JSON.stringify(this.text));
    prefs.set("rk.search.scalars", JSON.stringify(this.scalars));
    prefs.set("rk.search.decompiled", JSON.stringify(this.decomp));
  }

  /** F3 / Shift+F3: the last search again from the cursor, or the next row of a decompiled search's results. */
  async repeat(backward: boolean) {
    const kind = this.last;
    if (kind === null) return this.open("memory");
    if (kind === "decompiled") {
      if (!this.results.step(backward)) toast("No decompiled-code results to step through");
      return;
    }
    await this.step(kind, backward);
  }

  private dialog(kind: SearchKind): Floating | null {
    const d = this.dialogs.get(kind);
    return d && d.f.isOpen ? d.f : null;
  }

  private say(kind: SearchKind, text: string, how: "" | "error" | "ok" = "") {
    const f = this.dialog(kind);
    if (f) f.say(text, how);
    else if (how === "error" || text.startsWith("Not found")) toast(text, how === "error" ? { kind: "error" } : undefined);
  }

  private scope(where: string): { ranges: { first: { offset: bigint }; last: { offset: bigint } }[] } | null {
    if (where !== "selection") return { ranges: [] };
    const sel = this.host.selection();
    if (!sel.length) return null;
    return { ranges: sel.map(([a, b]) => ({ first: { offset: a }, last: { offset: b } })) };
  }

  private memoryRequest(): Record<string, unknown> | string {
    const m = this.memory;
    if (!m.query.trim()) return "Type what to search for";
    const sc = this.scope(m.where);
    if (!sc) return "Select a range in the listing first (or search the entire program)";
    const all = m.insn && m.data && m.undef;
    if (!m.insn && !m.data && !m.undef) return "Choose at least one kind of code unit";
    return {
      programId: this.host.programId,
      format: m.format,
      query: m.query,
      encoding: m.encoding,
      caseSensitive: m.caseSensitive,
      escapeSequences: m.escapes,
      valueSize: m.size,
      unsignedValues: m.unsigned,
      byteOrder: m.order,
      scope: { ...sc, instructions: !all && m.insn, definedData: !all && m.data, undefined: !all && m.undef, executableOnly: m.exec },
      alignment: Math.max(1, m.alignment | 0),
    };
  }

  private textRequest(): Record<string, unknown> | string {
    const t = this.text;
    if (!t.query) return "Type what to search for";
    if (!t.fields.length) return "Choose at least one field";
    const sc = this.scope(t.where);
    if (!sc) return "Select a range in the listing first (or search the entire program)";
    return {
      programId: this.host.programId,
      query: t.query,
      regex: t.regex,
      caseSensitive: t.caseSensitive,
      wholeWord: t.wholeWord,
      fields: t.fields.length === ALL_FIELDS.length ? [] : t.fields,
      scope: sc,
    };
  }

  private scalarRequest(): Record<string, unknown> | string {
    const s = this.scalars;
    const req: Record<string, unknown> = { programId: this.host.programId };
    if (s.mode === "exact") {
      const v = parseValue(s.value);
      if (v === null) return "The value is a number: 4096, 0x1000 or -1";
      req.min = v;
      req.max = v;
    } else if (s.mode === "range") {
      const lo = s.min.trim() ? parseValue(s.min) : null, hi = s.max.trim() ? parseValue(s.max) : null;
      if ((s.min.trim() && lo === null) || (s.max.trim() && hi === null)) return "The range's ends are numbers: 0, 0xff, -128";
      if (lo !== null && hi !== null && lo > hi) return "The range's minimum is above its maximum";
      if (lo !== null) req.min = lo;
      if (hi !== null) req.max = hi;
    }
    if (!s.insn && !s.data) return "Choose instructions, data or both";
    const sc = this.scope(s.where);
    if (!sc) return "Select a range in the listing first (or search the entire program)";
    req.scope = { ...sc, instructions: s.insn && !s.data, definedData: s.data && !s.insn };
    return req;
  }

  private startFrom(): bigint | null {
    const loc = this.host.location();
    if (this.hit && loc !== null && loc === this.hit.at) return this.hit.addr;
    return loc;
  }

  /** Next or Previous from the cursor. */
  async step(kind: Exclude<SearchKind, "decompiled">, backward: boolean) {
    if (this.busy) return;
    const req = kind === "memory" ? this.memoryRequest() : kind === "text" ? this.textRequest() : this.scalarRequest();
    if (typeof req === "string") return this.say(kind, req, "error");
    this.last = kind;
    this.save();
    const from = this.startFrom();
    const wrap = kind === "memory" ? this.memory.wrap : kind === "text" ? this.text.wrap : this.scalars.wrap;
    const r = { ...req, maxResults: 1, start: { from: from === null ? undefined : { offset: from }, backward, wrap } } as never;
    this.busy = true;
    this.say(kind, backward ? "Searching backward…" : "Searching…");
    try {
      let found: { addr: bigint; wrapped: boolean; what: string } | null = null;
      let pattern = "";
      if (kind === "memory") {
        for await (const m of this.host.rk.queries.searchMemory(r)) {
          if (m.pattern) pattern = m.pattern;
          for (const x of m.matches) found ??= { addr: x.address!.offset, wrapped: x.wrapped, what: bytesHex(x.bytes) };
        }
      } else if (kind === "text") {
        for await (const m of this.host.rk.queries.searchText(r))
          for (const x of m.matches) found ??= { addr: x.address!.offset, wrapped: x.wrapped, what: `${FIELD_NAMES[x.field] ?? "text"}: ${x.text}` };
      } else {
        for await (const m of this.host.rk.queries.searchScalars(r))
          for (const x of m.matches) found ??= { addr: x.address!.offset, wrapped: x.wrapped, what: x.text };
      }
      const bytes = pattern ? ` (bytes ${pattern})` : "";
      if (!found) {
        this.say(kind, `Not found ${backward ? "before" : "after"} ${from === null ? "the start" : fmtAddr(from, this.host.addrWidth)}${bytes}`);
        return;
      }
      await this.host.navigate(found.addr);
      this.hit = { addr: found.addr, at: this.host.location() };
      this.say(kind, `${found.wrapped ? "Wrapped around: " : ""}found at ${fmtAddr(found.addr, this.host.addrWidth)} · ${found.what}${bytes}`, "ok");
    } catch (e) {
      this.say(kind, errText(e), "error");
    } finally {
      this.busy = false;
    }
  }

  /** Search All into the results table. */
  async all(kind: SearchKind) {
    const req = kind === "memory" ? this.memoryRequest() : kind === "text" ? this.textRequest() : kind === "scalars" ? this.scalarRequest() : this.decompRequest();
    if (typeof req === "string") return this.say(kind, req, "error");
    this.last = kind;
    this.save();
    const limit = Math.max(1, Math.min(MAX_ALL, (kind === "memory" ? this.memory.limit : kind === "text" ? this.text.limit : kind === "scalars" ? this.scalars.limit : this.decomp.limit) | 0));
    const w = this.host.addrWidth;
    const set = this.results.add(kind, this.describe(kind), COLUMNS[kind](w));
    this.host.showResults();
    this.dialog(kind)?.close();
    const r = { ...req, maxResults: limit } as never;
    const opts = { signal: set.abort.signal };
    const t0 = performance.now();
    try {
      if (kind === "memory") {
        set.unit = "bytes";
        for await (const m of this.host.rk.queries.searchMemory({ ...(r as object), details: true } as never, opts)) {
          for (const x of m.matches) set.rows.push(this.memoryRow(x));
          set.done = Number(m.bytesSearched);
          set.total = Number(m.bytesTotal);
          set.truncated = m.truncated;
          if (m.done) set.elapsedMs = m.elapsedMs;
          this.results.changed(set);
        }
      } else if (kind === "text") {
        set.unit = "code units";
        for await (const m of this.host.rk.queries.searchText(r, opts)) {
          for (const x of m.matches) set.rows.push(this.textRow(x));
          set.done = Number(m.rowsSearched);
          set.total = Number(m.rowsTotal);
          set.truncated = m.truncated;
          if (m.done) set.elapsedMs = m.elapsedMs;
          this.results.changed(set);
        }
      } else if (kind === "scalars") {
        set.unit = "code units";
        for await (const m of this.host.rk.queries.searchScalars(r, opts)) {
          for (const x of m.matches) set.rows.push(this.scalarRow(x));
          set.done = Number(m.rowsSearched);
          set.total = Number(m.rowsTotal);
          set.truncated = m.truncated;
          if (m.done) set.elapsedMs = m.elapsedMs;
          this.results.changed(set);
        }
      } else {
        set.unit = "functions";
        for await (const m of this.host.rk.queries.searchDecompiled(r, opts)) {
          for (const x of m.matches) set.rows.push(this.decompRow(x));
          set.done = m.functionsDone;
          set.total = m.functionsTotal;
          set.truncated = m.truncated;
          if (m.done) set.elapsedMs = m.elapsedMs;
          this.results.changed(set);
        }
      }
    } catch (e) {
      if (set.abort.signal.aborted) set.cancelled = true;
      else set.error = errText(e);
    }
    if (!set.elapsedMs) set.elapsedMs = performance.now() - t0;
    set.running = false;
    this.results.finished(set);
  }

  private decompRequest(): Record<string, unknown> | string {
    const d = this.decomp;
    if (!d.query) return "Type what to search for";
    const req: Record<string, unknown> = { programId: this.host.programId, query: d.query, regex: d.regex, caseSensitive: d.caseSensitive, wholeWord: d.wholeWord };
    if (d.where === "all") req.all = true;
    else if (d.where === "function") {
      const f = this.host.currentFunction();
      if (f === null) return "The cursor isn't in a function";
      req.functions = [{ offset: f }];
    } else {
      const sel = this.host.selection();
      if (!sel.length) return "Select a range in the listing first (or search every function)";
      req.ranges = sel.map(([a, b]) => ({ first: { offset: a }, last: { offset: b } }));
    }
    return req;
  }

  private describe(kind: SearchKind): string {
    switch (kind) {
      case "memory": {
        const f = FORMATS.find((x) => x.f === this.memory.format)?.label ?? "Hex";
        return `Memory: ${f.toLowerCase()} "${this.memory.query}"`;
      }
      case "text":
        return `Text: "${this.text.query}"${this.text.regex ? " (regex)" : ""}`;
      case "scalars":
        return `Scalars: ${this.scalars.mode === "exact" ? this.scalars.value : this.scalars.mode === "range" ? `${this.scalars.min || "…"} to ${this.scalars.max || "…"}` : "all"}`;
      case "decompiled":
        return `Decompiled: "${this.decomp.query}"${this.decomp.regex ? " (regex)" : ""}`;
      case "uses":
        return "Uses";
    }
  }

  // ----------------------------------------------------------- rows --

  private memoryRow(m: MemoryMatch): ResultRow {
    const a = m.address!.offset;
    const fn = m.functionName;
    return {
      addr: a,
      end: a + BigInt(Math.max(1, m.bytes.length)) - 1n,
      cells: [fmtAddr(a, this.host.addrWidth), m.label, bytesHex(m.bytes), m.preview, fn],
      sort: [a, m.label, bytesHex(m.bytes, 64), m.preview, fn],
      open: () => void this.host.navigate(a),
    };
  }

  private textRow(m: TextMatch): ResultRow {
    const a = m.address!.offset;
    const [before, hit] = splitMatch(m.text, m.matchStart, m.matchLength);
    const field = FIELD_NAMES[m.field] ?? "";
    return {
      addr: a,
      end: a,
      cells: [fmtAddr(a, this.host.addrWidth), field, m.text, m.label, m.functionName],
      sort: [a, field, m.text, m.label, m.functionName],
      hl: { col: 2, start: before.length, len: hit.length },
      open: () => void this.host.navigate(a),
    };
  }

  private scalarRow(m: ScalarMatch): ResultRow {
    const a = m.address!.offset;
    const hexv = `0x${m.unsignedValue.toString(16)}`;
    return {
      addr: a,
      end: a,
      cells: [fmtAddr(a, this.host.addrWidth), hexv, m.value.toString(), m.bits ? String(m.bits) : "", m.text, m.functionName],
      sort: [a, m.unsignedValue, m.value, m.bits, m.text, m.functionName],
      open: () => void this.host.navigate(a),
    };
  }

  /**
   * Find Uses of a struct or union, or one of its fields (feature
   * type-uses; Ghidra's Find Uses of): every function's decompiled C read on
   * the daemon (DecompileMany's cache and workers), streamed into the
   * results table with progress; Cancel stops it. `what` titles the set.
   */
  async findUses(typeHash: string, what: string, field?: { offset: bigint; name: string }) {
    const w = this.host.addrWidth;
    const set = this.results.add("uses", `Uses of ${what}`, COLUMNS.uses(w));
    set.unit = "functions";
    this.host.showResults();
    const t0 = performance.now();
    try {
      const req = {
        programId: this.host.programId,
        typeHash,
        all: true,
        maxResults: MAX_ALL,
        ...(field ? { fieldOffset: field.offset, fieldName: field.name } : {}),
      };
      for await (const m of this.host.rk.queries.findTypeUses(req, { signal: set.abort.signal })) {
        for (const x of m.uses) set.rows.push(this.useRow(x));
        set.done = m.functionsDone;
        set.total = m.functionsTotal;
        set.truncated = m.truncated;
        if (m.done) set.elapsedMs = m.elapsedMs;
        this.results.changed(set);
      }
    } catch (e) {
      if (set.abort.signal.aborted) set.cancelled = true;
      else set.error = errText(e);
    }
    if (!set.elapsedMs) set.elapsedMs = performance.now() - t0;
    set.running = false;
    this.results.finished(set);
  }

  private useRow(m: TypeUse): ResultRow {
    const entry = m.function!.offset;
    const at = m.address?.offset ?? null;
    const [before, hit] = splitMatch(m.text, m.matchStart, m.matchLength);
    const kind = m.kind === TypeUseKind.TYPE ? "type" : (ACCESS_TEXT[m.access] ?? "field");
    return {
      addr: at,
      end: at,
      cells: [m.functionName, String(m.line + 1), kind, m.text, at === null ? "" : fmtAddr(at, this.host.addrWidth)],
      sort: [m.functionName, m.line, kind, m.text, at ?? -1n],
      hl: { col: 3, start: before.length, len: hit.length },
      open: () => void this.host.openDecompiled(entry, m.line, before.length, before.length + hit.length, at),
    };
  }

  private decompRow(m: DecompiledMatch): ResultRow {
    const entry = m.function!.offset;
    const at = m.address?.offset ?? null;
    const [before, hit] = splitMatch(m.text, m.matchStart, m.matchLength);
    return {
      addr: at,
      end: at,
      cells: [m.functionName, String(m.line + 1), m.text, at === null ? "" : fmtAddr(at, this.host.addrWidth)],
      sort: [m.functionName, m.line, m.text, at ?? -1n],
      hl: { col: 2, start: before.length, len: hit.length },
      open: () => void this.host.openDecompiled(entry, m.line, before.length, before.length + hit.length, at),
    };
  }

  // -------------------------------------------------------- dialogs --

  private build(kind: SearchKind): { f: Floating; read: () => void } {
    const f = new Floating(KIND_TITLE[kind], `search-${kind}`, () => this.host.focusListing());
    const run = (what: "next" | "prev" | "all") => {
      read();
      if (what === "all" || kind === "decompiled") void this.all(kind);
      else void this.step(kind, what === "prev");
    };
    const btn = (label: string, keys: string, what: "next" | "prev" | "all", primary = false) =>
      h("button", { class: "btn" + (primary ? " primary" : ""), type: "button", "data-testid": `search-${what}`, title: `${label} (${keys})`, onclick: () => run(what) }, label, " ", h("kbd", {}, keys));
    let read: () => void;
    if (kind === "memory") read = this.memoryForm(f);
    else if (kind === "text") read = this.textForm(f);
    else if (kind === "scalars") read = this.scalarForm(f);
    else read = this.decompForm(f);
    if (kind === "decompiled") {
      f.buttons.append(btn("Search All", "Enter", "all", true));
      f.onKey = (e) => {
        if (e.key === "Enter" && !(e.target instanceof HTMLButtonElement)) {
          run("all");
          return true;
        }
        return false;
      };
    } else {
      f.buttons.append(btn("Previous", "Shift+Enter", "prev"), btn("Next", "Enter", "next", true), btn("Search All", "Ctrl+Enter", "all"));
      f.onKey = (e) => {
        if (e.key === "F3") {
          run(e.shiftKey ? "prev" : "next");
          return true;
        }
        if (e.key !== "Enter" || e.target instanceof HTMLButtonElement) return false;
        run(e.ctrlKey || e.metaKey ? "all" : e.shiftKey ? "prev" : "next");
        return true;
      };
    }
    // The selection and the cursor's function may have changed since it was built.
    f.onOpen = () => {
      const sel = this.host.selection().length > 0, fn = this.host.currentFunction() !== null;
      for (const r of f.el.querySelectorAll<HTMLInputElement>("input[data-needs]")) {
        const ok = r.dataset.needs === "selection" ? sel : fn;
        r.disabled = !ok;
        r.closest("label")?.setAttribute("title", ok ? "" : r.dataset.needs === "selection" ? "Select a range in the listing first" : "The cursor isn't in a function");
        if (!ok && r.checked) {
          r.checked = false;
          const all = f.el.querySelector<HTMLInputElement>(`input[type=radio][name="${r.name}"][value=all]`);
          if (all) {
            all.checked = true;
            all.dispatchEvent(new Event("change"));
          }
        }
      }
    };
    f.say(kind === "decompiled" ? "Decompiles each function (once: results are cached) and searches its C." : "Enter: next · Shift+Enter: previous · Ctrl+Enter: all · F3 repeats after closing");
    return { f, read };
  }

  private whereRow(where: string, testid: string, onChange: (w: "all" | "selection") => void): HTMLElement {
    const name = `${testid}-where`;
    const sel = this.host.selection().length > 0;
    const mk = (value: "all" | "selection", label: string) => {
      const r = h("input", { type: "radio", name, value, "data-testid": `${testid}-where-${value}`, "data-needs": value === "selection" ? "selection" : undefined });
      r.checked = where === value || (value === "all" && !sel && where === "selection");
      r.disabled = value === "selection" && !sel;
      r.addEventListener("change", () => r.checked && onChange(value));
      return h("label", { class: "sd-check", title: value === "selection" && !sel ? "Select a range in the listing first" : undefined }, r, label);
    };
    if (!sel && where === "selection") onChange("all");
    return h("div", { class: "sd-row" }, h("span", { class: "dim sd-label" }, "Where"), mk("all", "Entire program"), mk("selection", "Selection"));
  }

  private memoryForm(f: Floating): () => void {
    const m = this.memory;
    const query = h("input", { class: "ask-input", spellcheck: "false", autocomplete: "off", "aria-label": "Search for", "data-testid": "search-query" });
    query.value = m.query;
    const [fmtL, fmt] = select("Format", FORMATS.map((x) => ({ value: x.f, label: x.label })), m.format, "search-format");
    const hint = h("div", { class: "dim sd-hint" });
    const [encL, enc] = select("Encoding", [{ value: SearchEncoding.ASCII, label: "ASCII" }, { value: SearchEncoding.UTF8, label: "UTF-8" }, { value: SearchEncoding.UTF16, label: "UTF-16" }], m.encoding, "search-encoding");
    const [caseL, caseBox] = checkbox("Case sensitive", m.caseSensitive, "search-case");
    const [escL, escBox] = checkbox("Escape sequences", m.escapes, "search-escapes", "\\n \\t \\r \\0 \\\\ \\xHH \\uHHHH");
    const [sizeL, size] = select("Size", [1, 2, 4, 8].map((n) => ({ value: n, label: `${n} byte${n === 1 ? "" : "s"}` })), m.size, "search-size");
    const [unsL, uns] = checkbox("Unsigned", m.unsigned, "search-unsigned");
    const [ordL, ord] = select("Byte order", [{ value: Endianness.UNSPECIFIED, label: "The program's" }, { value: Endianness.LITTLE, label: "Little-endian" }, { value: Endianness.BIG, label: "Big-endian" }], m.order, "search-order");
    const opts = h("div", { class: "sd-row" });
    const [insnL, insn] = checkbox("Instructions", m.insn, "search-insn");
    const [dataL, data] = checkbox("Defined data", m.data, "search-data");
    const [undefL, undef] = checkbox("Undefined", m.undef, "search-undef");
    const [execL, exec] = checkbox("Executable blocks only", m.exec, "search-exec");
    const align = h("input", { class: "filter sd-num", type: "number", min: "1", value: String(m.alignment), "aria-label": "Alignment", "data-testid": "search-align" });
    const [wrapL, wrap] = checkbox("Wrap around", m.wrap, "search-wrap");
    const limit = h("input", { class: "filter sd-num", type: "number", min: "1", max: String(MAX_ALL), value: String(m.limit), "aria-label": "Search All limit", "data-testid": "search-limit" });
    const shape = () => {
      const fm = Number(fmt.value) as SearchFormat;
      const meta = FORMATS.find((x) => x.f === fm)!;
      hint.textContent = meta.hint;
      query.placeholder = meta.placeholder;
      const str = fm === SearchFormat.STRING, dec = fm === SearchFormat.DECIMAL;
      const ordered = dec || fm === SearchFormat.FLOAT || fm === SearchFormat.DOUBLE || (str && Number(enc.value) === SearchEncoding.UTF16);
      opts.replaceChildren(...[str && encL, str && caseL, str && escL, dec && sizeL, dec && unsL, ordered && ordL, fm === SearchFormat.REGEX && caseL].filter((x): x is HTMLLabelElement => !!x));
      opts.hidden = !opts.childElementCount;
    };
    fmt.addEventListener("change", shape);
    enc.addEventListener("change", shape);
    shape();
    let where = m.where;
    f.body.append(
      h("div", { class: "sd-row" }, query, fmtL),
      hint,
      opts,
      this.whereRow(where, "search-memory", (w) => (where = w)),
      h("div", { class: "sd-row" }, h("span", { class: "dim sd-label" }, "Code units"), insnL, dataL, undefL),
      h("div", { class: "sd-row" }, execL, h("label", { class: "sd-field" }, h("span", { class: "dim" }, "Alignment"), align), wrapL, h("label", { class: "sd-field" }, h("span", { class: "dim" }, "Limit"), limit)),
    );
    return () => {
      Object.assign(m, {
        query: query.value,
        format: Number(fmt.value),
        encoding: Number(enc.value),
        caseSensitive: caseBox.checked,
        escapes: escBox.checked,
        size: Number(size.value),
        unsigned: uns.checked,
        order: Number(ord.value),
        where,
        insn: insn.checked,
        data: data.checked,
        undef: undef.checked,
        exec: exec.checked,
        alignment: Math.max(1, Number(align.value) || 1),
        wrap: wrap.checked,
        limit: Math.max(1, Math.min(MAX_ALL, Number(limit.value) || 10_000)),
      });
    };
  }

  private textForm(f: Floating): () => void {
    const t = this.text;
    const query = h("input", { class: "ask-input", spellcheck: "false", autocomplete: "off", "aria-label": "Search for", "data-testid": "search-query", placeholder: "a name, a comment, MOV EAX, …" });
    query.value = t.query;
    const [reL, re] = checkbox("Regular expression", t.regex, "search-regex", "RE2 syntax");
    const [caseL, caseBox] = checkbox("Case sensitive", t.caseSensitive, "search-case");
    const [wordL, word] = checkbox("Whole word", t.wholeWord, "search-word");
    const boxes = ALL_FIELDS.map((fd) => checkbox(FIELD_NAMES[fd], t.fields.includes(fd), `search-field-${fd}`));
    const [wrapL, wrap] = checkbox("Wrap around", t.wrap, "search-wrap");
    const limit = h("input", { class: "filter sd-num", type: "number", min: "1", max: String(MAX_ALL), value: String(t.limit), "aria-label": "Search All limit", "data-testid": "search-limit" });
    let where = t.where;
    f.body.append(
      query,
      h("div", { class: "sd-row" }, reL, caseL, wordL),
      h("div", { class: "sd-row sd-fields" }, h("span", { class: "dim sd-label" }, "Fields"), ...boxes.map(([l]) => l)),
      this.whereRow(where, "search-text", (w) => (where = w)),
      h("div", { class: "sd-row" }, wrapL, h("label", { class: "sd-field" }, h("span", { class: "dim" }, "Limit"), limit)),
      h("div", { class: "dim sd-hint" }, "Matched against the listing as shown: names after renames, operands as the symbols they name, comments line by line."),
    );
    return () => {
      Object.assign(t, {
        query: query.value,
        regex: re.checked,
        caseSensitive: caseBox.checked,
        wholeWord: word.checked,
        fields: ALL_FIELDS.filter((_, i) => boxes[i][1].checked),
        where,
        wrap: wrap.checked,
        limit: Math.max(1, Math.min(MAX_ALL, Number(limit.value) || 10_000)),
      });
    };
  }

  private scalarForm(f: Floating): () => void {
    const s = this.scalars;
    const radio = (value: ScalarState["mode"], label: string) => {
      const r = h("input", { type: "radio", name: "search-scalar-mode", value, "data-testid": `search-mode-${value}` });
      r.checked = s.mode === value;
      return [h("label", { class: "sd-check" }, r, label), r] as const;
    };
    const [exactL, exact] = radio("exact", "Value");
    const [rangeL, range] = radio("range", "Range");
    const [anyL, any] = radio("any", "Every scalar");
    const value = h("input", { class: "ask-input sd-val", spellcheck: "false", autocomplete: "off", "aria-label": "Value", "data-testid": "search-value", placeholder: "4096, 0x1000, -1" });
    value.value = s.value;
    const min = h("input", { class: "filter sd-val", spellcheck: "false", "aria-label": "Minimum", "data-testid": "search-min", placeholder: "minimum" });
    min.value = s.min;
    const max = h("input", { class: "filter sd-val", spellcheck: "false", "aria-label": "Maximum", "data-testid": "search-max", placeholder: "maximum" });
    max.value = s.max;
    value.addEventListener("input", () => (exact.checked = true));
    for (const x of [min, max]) x.addEventListener("input", () => (range.checked = true));
    // The field of the mode chosen gets the focus when the dialog opens.
    const focusMode = () => {
      for (const x of [value, min]) x.removeAttribute("data-focus");
      if (range.checked) min.setAttribute("data-focus", "");
      else value.setAttribute("data-focus", "");
    };
    for (const r of [exact, range, any]) r.addEventListener("change", focusMode);
    focusMode();
    const [insnL, insn] = checkbox("Instructions", s.insn, "search-insn");
    const [dataL, data] = checkbox("Defined data", s.data, "search-data");
    const [wrapL, wrap] = checkbox("Wrap around", s.wrap, "search-wrap");
    const limit = h("input", { class: "filter sd-num", type: "number", min: "1", max: String(MAX_ALL), value: String(s.limit), "aria-label": "Search All limit", "data-testid": "search-limit" });
    let where = s.where;
    f.body.append(
      h("div", { class: "sd-row" }, exactL, value),
      h("div", { class: "sd-row" }, rangeL, min, h("span", { class: "dim" }, "to"), max),
      h("div", { class: "sd-row" }, anyL),
      h("div", { class: "sd-row" }, h("span", { class: "dim sd-label" }, "In"), insnL, dataL),
      this.whereRow(where, "search-scalars", (w) => (where = w)),
      h("div", { class: "sd-row" }, wrapL, h("label", { class: "sd-field" }, h("span", { class: "dim" }, "Limit"), limit)),
      h("div", { class: "dim sd-hint" }, "A scalar matches read as signed or as unsigned (an 8-bit 0xff is 255 and -1)."),
    );
    return () => {
      Object.assign(s, {
        mode: exact.checked ? "exact" : range.checked ? "range" : any.checked ? "any" : s.mode,
        value: value.value,
        min: min.value,
        max: max.value,
        insn: insn.checked,
        data: data.checked,
        where,
        wrap: wrap.checked,
        limit: Math.max(1, Math.min(MAX_ALL, Number(limit.value) || 10_000)),
      });
    };
  }

  private decompForm(f: Floating): () => void {
    const d = this.decomp;
    const query = h("input", { class: "ask-input", spellcheck: "false", autocomplete: "off", "aria-label": "Search for", "data-testid": "search-query", placeholder: "strcpy(, == 0x10, while (true)" });
    query.value = d.query;
    const [reL, re] = checkbox("Regular expression", d.regex, "search-regex", "RE2 syntax");
    const [caseL, caseBox] = checkbox("Case sensitive", d.caseSensitive, "search-case");
    const [wordL, word] = checkbox("Whole word", d.wholeWord, "search-word");
    const sel = this.host.selection().length > 0;
    const fn = this.host.currentFunction() !== null;
    let where = d.where === "selection" && !sel ? "all" : d.where === "function" && !fn ? "all" : d.where;
    const mk = (value: DecompState["where"], label: string, ok: boolean) => {
      const r = h("input", { type: "radio", name: "search-decomp-where", value, "data-testid": `search-decompiled-where-${value}`, "data-needs": value === "all" ? undefined : value });
      r.checked = where === value;
      r.disabled = !ok;
      r.addEventListener("change", () => r.checked && (where = value));
      return h("label", { class: "sd-check" }, r, label);
    };
    const limit = h("input", { class: "filter sd-num", type: "number", min: "1", max: String(MAX_ALL), value: String(d.limit), "aria-label": "Search All limit", "data-testid": "search-limit" });
    f.body.append(
      query,
      h("div", { class: "sd-row" }, reL, caseL, wordL),
      h("div", { class: "sd-row" }, h("span", { class: "dim sd-label" }, "Functions"), mk("all", "Every function", true), mk("selection", "In the selection", sel), mk("function", "This function", fn)),
      h("div", { class: "sd-row" }, h("label", { class: "sd-field" }, h("span", { class: "dim" }, "Limit"), limit)),
    );
    return () => {
      Object.assign(d, { query: query.value, regex: re.checked, caseSensitive: caseBox.checked, wholeWord: word.checked, where, limit: Math.max(1, Math.min(MAX_ALL, Number(limit.value) || 10_000)) });
    };
  }

  /** The current dialog and results (tests). */
  state() {
    const open = [...this.dialogs.entries()].find(([, d]) => d.f.isOpen);
    return {
      dialog: open ? open[0] : null,
      status: open ? open[1].f.status.textContent ?? "" : "",
      last: this.last,
      results: this.results.shown ? { title: this.results.shown.title, running: this.results.shown.running, count: this.results.shown.rows.length, truncated: this.results.shown.truncated, error: this.results.shown.error, cancelled: this.results.shown.cancelled } : null,
    };
  }
}

const COLUMNS: Record<SearchKind, (w: number) => Column[]> = {
  memory: (w) => [
    { title: "Address", width: `${Math.max(10, w + 2)}ch` },
    { title: "Label", width: "minmax(0, 1fr)" },
    { title: "Match", width: "minmax(0, 1fr)" },
    { title: "Code unit", width: "minmax(0, 1.4fr)" },
    { title: "Function", width: "minmax(0, 1fr)" },
  ],
  text: (w) => [
    { title: "Address", width: `${Math.max(10, w + 2)}ch` },
    { title: "Field", width: "12ch" },
    { title: "Text", width: "minmax(0, 2fr)" },
    { title: "Label", width: "minmax(0, 1fr)" },
    { title: "Function", width: "minmax(0, 1fr)" },
  ],
  scalars: (w) => [
    { title: "Address", width: `${Math.max(10, w + 2)}ch` },
    { title: "Value", width: "14ch", numeric: true },
    { title: "Decimal", width: "14ch", numeric: true },
    { title: "Bits", width: "5ch", numeric: true },
    { title: "Instruction / data", width: "minmax(0, 2fr)" },
    { title: "Function", width: "minmax(0, 1fr)" },
  ],
  uses: (w) => [
    { title: "Function", width: "minmax(0, 1fr)" },
    { title: "Line", width: "6ch", numeric: true },
    { title: "Use", width: "11ch" },
    { title: "Code", width: "minmax(0, 3fr)" },
    { title: "Address", width: `${Math.max(10, w + 2)}ch` },
  ],
  decompiled: (w) => [
    { title: "Function", width: "minmax(0, 1fr)" },
    { title: "Line", width: "6ch", numeric: true },
    { title: "Text", width: "minmax(0, 3fr)" },
    { title: "Address", width: `${Math.max(10, w + 2)}ch` },
  ],
};
