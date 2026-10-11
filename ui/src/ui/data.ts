// Defined data: strings by default (address, the string, references), or
// any category of the program's defined data (pointers, accessed
// undefinedN, globals with an asserted type). A virtualized table paged
// from ListData by position, pinned to one revision; the filter is the
// daemon's text_contains. Click (or Enter) goes to the item.

import { DataCategory, type DefinedData, type Revkit } from "@revkit/api";
import { errText, hex, originClass, fmtAddr } from "../data/format";
import { h } from "./dom";

const ROW_H = 22;
const PAGE = 200;

const CATEGORIES: { label: string; cats: DataCategory[] }[] = [
  { label: "Strings", cats: [DataCategory.STRING] },
  { label: "All defined data", cats: [] },
  { label: "Pointers", cats: [DataCategory.POINTER] },
  { label: "Typed globals", cats: [DataCategory.TYPED] },
  { label: "Accessed (undefinedN)", cats: [DataCategory.UNDEFINED] },
];

export class DataView {
  private pages = new Map<number, DefinedData[]>();
  private inFlight = new Set<number>();
  private total = 0;
  private revision = 0n;
  private seq = 0;
  private list: HTMLElement;
  private spacer: HTMLElement;
  private rowsEl: HTMLElement;
  readonly filter: HTMLInputElement;
  private kind: HTMLSelectElement;
  private count: HTMLElement;
  private active = -1;
  private timer = 0;
  private loaded = false;
  /** A load has returned (rows, none, or an error): what an empty list says. */
  private settled = false;
  onOpen: ((address: bigint) => void) | null = null;

  constructor(
    root: HTMLElement,
    private rk: Revkit,
    private programId: string,
    private addrWidth: number,
  ) {
    this.filter = h("input", { class: "filter", placeholder: "Filter by text, label or type", spellcheck: "false", "aria-label": "Filter data", "data-testid": "data-filter" });
    this.kind = h("select", { class: "filter select", "aria-label": "Data category", "data-testid": "data-kind" }, ...CATEGORIES.map((c, i) => h("option", { value: String(i) }, c.label)));
    this.count = h("span", { class: "dim count", "data-testid": "data-count" });
    this.spacer = h("div", {});
    this.rowsEl = h("div", { class: "data-rows" });
    this.list = h("div", { class: "data-list", tabindex: "0", role: "listbox", "aria-label": "Defined data" }, this.spacer, this.rowsEl);
    const head = h("div", { class: "data-row data-head dim" }, h("span", { class: "d-addr" }, "Address"), h("span", { class: "d-val" }, "Value"), h("span", { class: "d-type" }, "Type"), h("span", { class: "d-refs" }, "Refs"));
    root.append(
      h("div", { class: "panel-head view-head" }, h("span", { class: "panel-title" }, "Defined data"), this.count),
      h("div", { class: "fn-filter data-filters" }, this.kind, this.filter),
      head,
      this.list,
    );
    const reload = () => {
      clearTimeout(this.timer);
      this.timer = window.setTimeout(() => void this.load(), 120);
    };
    this.filter.addEventListener("input", reload);
    this.kind.addEventListener("change", () => void this.load());
    this.filter.addEventListener("keydown", (e) => this.onKey(e));
    this.list.addEventListener("keydown", (e) => this.onKey(e));
    this.list.addEventListener("scroll", () => this.paint());
    new ResizeObserver(() => this.paint()).observe(this.list);
    this.rowsEl.addEventListener("mousedown", (e) => {
      const el = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (!el) return;
      e.preventDefault();
      this.active = Number(el.dataset.i);
      this.paint();
      this.open();
    });
  }

  /** What is shown is out of date: load again when next shown. */
  markStale() {
    this.loaded = false;
  }

  /** Loads on first show; later shows keep what is there. */
  ensureLoaded() {
    if (!this.loaded) void this.load();
  }

  focusFilter() {
    this.filter.focus();
    this.filter.select();
  }

  /** Shows strings (or every category) and focuses the filter. */
  setCategory(i: number) {
    if (Number(this.kind.value) !== i) {
      this.kind.value = String(i);
      void this.load();
    }
  }

  /** Reloads the pages in view at head (an invalidation). */
  async load() {
    this.loaded = true;
    const seq = ++this.seq;
    this.pages.clear();
    this.inFlight.clear();
    try {
      const r = await this.fetch(0, 0n);
      if (seq !== this.seq) return;
      this.total = Number(r.page?.totalCount ?? 0n);
      this.revision = r.snapshot?.revision ?? 0n;
      this.pages.set(0, r.data);
      this.count.textContent = `${this.total.toLocaleString()} ${this.total === 1 ? "item" : "items"}`;
    } catch (e) {
      if (seq !== this.seq) return;
      this.total = 0;
      this.count.textContent = errText(e);
    }
    this.settled = true;
    this.spacer.style.height = `${this.total * ROW_H}px`;
    this.paint();
  }

  private fetch(page: number, revision: bigint) {
    const cats = CATEGORIES[Number(this.kind.value)]?.cats ?? [];
    return this.rk.queries.listData({ programId: this.programId, categories: cats, textContains: this.filter.value.trim(), offset: BigInt(page * PAGE), page: { pageSize: PAGE }, read: { revision } });
  }

  private ensure(page: number) {
    if (this.pages.has(page) || this.inFlight.has(page) || this.inFlight.size > 2) return;
    const seq = this.seq;
    this.inFlight.add(page);
    void this.fetch(page, this.revision)
      .then((r) => {
        if (seq !== this.seq) return;
        this.pages.set(page, r.data);
        this.paint();
      })
      .catch(() => {})
      .finally(() => this.inFlight.delete(page));
  }

  private item(i: number): DefinedData | undefined {
    return this.pages.get(Math.floor(i / PAGE))?.[i % PAGE];
  }

  private paint() {
    const top = this.list.scrollTop;
    const first = Math.max(0, Math.floor(top / ROW_H) - 4);
    const last = Math.min(this.total, Math.ceil((top + this.list.clientHeight) / ROW_H) + 4);
    const out: HTMLElement[] = [];
    for (let i = first; i < last; i++) {
      const d = this.item(i);
      if (!d) {
        this.ensure(Math.floor(i / PAGE));
        out.push(h("div", { class: "data-row loading", style: `top:${i * ROW_H}px`, role: "option", "aria-disabled": "true" }, h("span", { class: "dim" }, "…")));
        continue;
      }
      const addr = d.address?.offset ?? 0n;
      const value = d.category === DataCategory.STRING ? JSON.stringify(d.value) : d.value || d.label;
      out.push(
        h(
          "div",
          { class: "data-row" + (i === this.active ? " active" : ""), style: `top:${i * ROW_H}px`, "data-i": i, role: "option", title: `${d.label}\n${d.dataType} at ${fmtAddr(addr)} (${d.length} bytes)` },
          h("span", { class: "d-addr" }, fmtAddr(addr, this.addrWidth)),
          h("span", { class: `d-val o-${originClass(d.origin)}` }, value),
          h("span", { class: "d-type" }, d.dataType),
          h("span", { class: "d-refs" }, d.xrefToCount ? String(d.xrefToCount) : ""),
        ),
      );
    }
    // A listbox always holds an option: one that says why there are no rows.
    if (!this.total) out.push(h("div", { class: "notes-empty dim", role: "option", "aria-disabled": "true" }, !this.settled ? "Loading…" : this.filter.value.trim() ? "No defined data matches" : "Nothing in this category"));
    this.rowsEl.replaceChildren(...out);
  }

  private open() {
    const d = this.item(this.active);
    if (d?.address) this.onOpen?.(d.address.offset);
  }

  private onKey(e: KeyboardEvent) {
    const move = (to: number) => {
      this.active = Math.max(0, Math.min(this.total - 1, to));
      const y = this.active * ROW_H;
      if (y < this.list.scrollTop) this.list.scrollTop = y;
      else if (y + ROW_H > this.list.scrollTop + this.list.clientHeight) this.list.scrollTop = y + ROW_H - this.list.clientHeight;
      this.paint();
    };
    switch (e.key) {
      case "ArrowDown":
        move(this.active + 1);
        break;
      case "ArrowUp":
        move(this.active - 1);
        break;
      case "PageDown":
        move(this.active + Math.floor(this.list.clientHeight / ROW_H));
        break;
      case "PageUp":
        move(this.active - Math.floor(this.list.clientHeight / ROW_H));
        break;
      case "Enter":
        if (this.active < 0) move(0);
        this.open();
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
  }

  /** The rows in view (tests). */
  visible() {
    const out: { address: string; value: string; type: string; refs: number }[] = [];
    for (let i = 0; i < Math.min(this.total, 200); i++) {
      const d = this.item(i);
      if (d) out.push({ address: hex(d.address?.offset ?? 0n), value: d.value, type: d.dataType, refs: d.xrefToCount });
    }
    return out;
  }
}
