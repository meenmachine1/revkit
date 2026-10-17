// Relocations: the relocations the file carries (Ghidra's relocation
// table), by address, with the type's name, the symbol, the addend, where
// it points once applied and the bytes there; a text filter on the symbol
// and the type (the daemon's ListRelocations, feature "relocation-table").
// A virtualized table paged by position, pinned to one revision. Click (or
// Enter) goes to the relocation; Shift+Enter or a double-click goes to its
// target.

import { RelocationKind, type ProgramRelocation, type Revkit } from "@revkit/api";
import { errText, fmtAddr, hex } from "../data/format";
import { h } from "./dom";

const ROW_H = 22;
const PAGE = 200;

const KIND_TEXT: Record<number, string> = {
  [RelocationKind.RELATIVE]: "relative",
  [RelocationKind.IRELATIVE]: "irelative",
  [RelocationKind.JUMP_SLOT]: "jump slot",
  [RelocationKind.GLOB_DAT]: "GOT entry",
  [RelocationKind.ABSOLUTE]: "absolute",
  [RelocationKind.OTHER]: "",
};

export interface RelocationsHost {
  rk: Revkit;
  programId: string;
  addrWidth: number;
  navigate(address: bigint): void;
}

function bytesHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(" ");
}

function signedHex(v: bigint): string {
  return v < 0n ? `-0x${hex(-v)}` : `0x${hex(v)}`;
}

export class RelocationsView {
  private pages = new Map<number, ProgramRelocation[]>();
  private inFlight = new Set<number>();
  private tokens = new Map<number, string>();
  private total = 0;
  private revision = 0n;
  private seq = 0;
  private list: HTMLElement;
  private spacer: HTMLElement;
  private rowsEl: HTMLElement;
  readonly filter: HTMLInputElement;
  private count: HTMLElement;
  private active = -1;
  private timer = 0;
  private loaded = false;
  private settled = false;
  private format = "";

  constructor(
    root: HTMLElement,
    private host: RelocationsHost,
  ) {
    this.filter = h("input", { class: "filter", placeholder: "Filter by symbol or type", spellcheck: "false", "aria-label": "Filter relocations", "data-testid": "relocations-filter" });
    this.count = h("span", { class: "dim count", "data-testid": "relocations-count" });
    this.spacer = h("div", {});
    this.rowsEl = h("div", { class: "data-rows" });
    this.list = h("div", { class: "data-list", tabindex: "0", role: "listbox", "aria-label": "Relocations", "data-testid": "relocations-list" }, this.spacer, this.rowsEl);
    const head = h(
      "div",
      { class: "data-row data-head dim relocs-row" },
      h("span", { class: "d-addr" }, "Address"),
      h("span", { class: "r-type" }, "Type"),
      h("span", { class: "r-sym" }, "Symbol or target"),
      h("span", { class: "r-addend" }, "Addend"),
      h("span", { class: "r-bytes" }, "Bytes"),
    );
    root.append(h("div", { class: "panel-head view-head" }, h("span", { class: "panel-title" }, "Relocations"), this.count), h("div", { class: "fn-filter data-filters" }, this.filter), head, this.list);
    this.filter.addEventListener("input", () => {
      clearTimeout(this.timer);
      this.timer = window.setTimeout(() => void this.load(), 150);
    });
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
      // A double-click's second press goes to the target (the rows are
      // repainted under the pointer, so no dblclick event reaches a row).
      this.open(e.detail >= 2);
    });
  }

  markStale() {
    this.loaded = false;
  }

  ensureLoaded() {
    if (!this.loaded) void this.load();
  }

  focus() {
    this.filter.focus();
    this.filter.select();
  }

  async load() {
    this.loaded = true;
    const seq = ++this.seq;
    this.pages.clear();
    this.inFlight.clear();
    try {
      const r = await this.fetch(0, 0n);
      if (seq !== this.seq) return;
      this.total = Number(r.total);
      this.revision = r.snapshot?.revision ?? 0n;
      this.format = r.format;
      this.pages.set(0, r.relocations);
      this.tokens.clear();
      if (r.page?.nextPageToken) this.tokens.set(1, r.page.nextPageToken);
      this.count.textContent = `${this.total.toLocaleString()} ${this.total === 1 ? "relocation" : "relocations"}`;
    } catch (e) {
      if (seq !== this.seq) return;
      this.total = 0;
      this.count.textContent = errText(e);
    }
    this.settled = true;
    this.active = Math.min(this.active, this.total - 1);
    this.spacer.style.height = `${this.total * ROW_H}px`;
    this.paint();
  }

  private fetch(page: number, revision: bigint) {
    return this.host.rk.queries.listRelocations({
      programId: this.host.programId,
      textContains: this.filter.value.trim(),
      page: { pageSize: PAGE, pageToken: page === 0 ? "" : this.tokens.get(page) ?? "" },
      read: { revision },
    });
  }

  private ensure(page: number) {
    if (this.pages.has(page) || this.inFlight.has(page) || this.inFlight.size > 2) return;
    // Pages come in order: the token for page n comes with page n-1.
    if (page > 0 && !this.tokens.has(page)) {
      this.ensure(page - 1);
      return;
    }
    const seq = this.seq;
    this.inFlight.add(page);
    void this.fetch(page, this.revision)
      .then((r) => {
        if (seq !== this.seq) return;
        this.pages.set(page, r.relocations);
        if (r.page?.nextPageToken) this.tokens.set(page + 1, r.page.nextPageToken);
        this.paint();
      })
      .catch(() => {})
      .finally(() => this.inFlight.delete(page));
  }

  private item(i: number): ProgramRelocation | undefined {
    return this.pages.get(Math.floor(i / PAGE))?.[i % PAGE];
  }

  private paint() {
    const top = this.list.scrollTop;
    const first = Math.max(0, Math.floor(top / ROW_H) - 4);
    const last = Math.min(this.total, Math.ceil((top + this.list.clientHeight) / ROW_H) + 4);
    const out: HTMLElement[] = [];
    for (let i = first; i < last; i++) {
      const r = this.item(i);
      if (!r) {
        this.ensure(Math.floor(i / PAGE));
        out.push(h("div", { class: "data-row loading", style: `top:${i * ROW_H}px`, role: "option", "aria-disabled": "true" }, h("span", { class: "dim" }, "…")));
        continue;
      }
      const addr = r.address?.offset ?? 0n;
      const target = r.target ? (r.targetName || fmtAddr(r.target.offset, this.host.addrWidth)) : "";
      const sym = r.symbol || (target ? `→ ${target}` : "");
      const kind = KIND_TEXT[r.kind] ?? "";
      out.push(
        h(
          "div",
          {
            class: "data-row relocs-row" + (i === this.active ? " active" : ""),
            style: `top:${i * ROW_H}px`,
            "data-i": i,
            "data-testid": "relocation-row",
            "data-address": hex(addr),
            role: "option",
            "aria-selected": String(i === this.active),
            title: `${r.typeName}${kind ? ` (${kind})` : ""} at ${fmtAddr(addr)}${r.symbol ? `\nsymbol ${r.symbol}` : ""}${r.target ? `\npoints at ${fmtAddr(r.target.offset)}${r.targetName ? ` (${r.targetName})` : ""}` : ""}\n\nClick to go there${r.target ? "; double-click to go to its target" : ""}`,
          },
          h("span", { class: "d-addr" }, fmtAddr(addr, this.host.addrWidth)),
          h("span", { class: "r-type" }, r.typeName),
          h("span", { class: r.symbol ? "r-sym named" : "r-sym dim" }, sym),
          h("span", { class: "r-addend dim" }, r.addend !== 0n ? signedHex(r.addend) : ""),
          h("span", { class: "r-bytes dim" }, bytesHex(r.original)),
        ),
      );
    }
    if (!this.total)
      out.push(
        h(
          "div",
          { class: "notes-empty dim", role: "option", "aria-disabled": "true" },
          !this.settled ? "Loading…" : this.filter.value.trim() ? "No relocation matches" : this.format === "raw" ? "A raw image has no relocations" : "No relocations",
        ),
      );
    this.rowsEl.replaceChildren(...out);
  }

  private open(target: boolean) {
    const r = this.item(this.active);
    if (!r?.address) return;
    if (target && r.target) this.host.navigate(r.target.offset);
    else this.host.navigate(r.address.offset);
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
        this.open(e.shiftKey);
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
  }

  /** The rows loaded (tests). */
  visible() {
    const out: { address: string; type: string; symbol: string; target: string; targetName: string }[] = [];
    for (let i = 0; i < Math.min(this.total, 200); i++) {
      const r = this.item(i);
      if (r) out.push({ address: hex(r.address?.offset ?? 0n), type: r.typeName, symbol: r.symbol, target: r.target ? hex(r.target.offset) : "", targetName: r.targetName });
    }
    return out;
  }
}
