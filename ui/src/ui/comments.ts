// Comments: every comment of the program (Ghidra's comment window), by
// address, with its kind, the function it is in and who wrote it; a kind
// filter and a text filter (the daemon's ListComments, feature
// "comment-table"). A virtualized table paged by position, pinned to one
// revision. Click (or Enter) goes to the comment; Shift+Enter or a
// double-click edits it.

import { CommentKind, type ProgramComment, type Revkit } from "@revkit/api";
import { errText, fmtAddr, hex, originClass } from "../data/format";
import { h } from "./dom";

const ROW_H = 22;
const PAGE = 200;

const KINDS: { label: string; kinds: CommentKind[] }[] = [
  { label: "All comments", kinds: [] },
  { label: "End of line", kinds: [CommentKind.EOL] },
  { label: "Pre", kinds: [CommentKind.PRE] },
  { label: "Post", kinds: [CommentKind.POST] },
  { label: "Plate", kinds: [CommentKind.PLATE] },
  { label: "Repeatable", kinds: [CommentKind.REPEATABLE] },
  { label: "Decompiler", kinds: [CommentKind.DECOMPILER] },
];

const KIND_TEXT: Record<number, string> = {
  [CommentKind.EOL]: "EOL",
  [CommentKind.PRE]: "Pre",
  [CommentKind.POST]: "Post",
  [CommentKind.PLATE]: "Plate",
  [CommentKind.REPEATABLE]: "Repeatable",
  [CommentKind.DECOMPILER]: "Decompiler",
};

export interface CommentsHost {
  rk: Revkit;
  programId: string;
  addrWidth: number;
  navigate(address: bigint): void;
  /** Edits the comment of this kind at the address (the comment dialog). */
  edit(address: bigint, kind: CommentKind): void;
}

export class CommentsView {
  private pages = new Map<number, ProgramComment[]>();
  private inFlight = new Set<number>();
  private tokens = new Map<number, string>();
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
  private settled = false;

  constructor(
    root: HTMLElement,
    private host: CommentsHost,
  ) {
    this.filter = h("input", { class: "filter", placeholder: "Filter by text", spellcheck: "false", "aria-label": "Filter comments", "data-testid": "comments-filter" });
    this.kind = h("select", { class: "filter select", "aria-label": "Comment kind", "data-testid": "comments-kind" }, ...KINDS.map((k, i) => h("option", { value: String(i) }, k.label)));
    this.count = h("span", { class: "dim count", "data-testid": "comments-count" });
    this.spacer = h("div", {});
    this.rowsEl = h("div", { class: "data-rows" });
    this.list = h("div", { class: "data-list", tabindex: "0", role: "listbox", "aria-label": "Comments", "data-testid": "comments-list" }, this.spacer, this.rowsEl);
    const head = h(
      "div",
      { class: "data-row data-head dim comments-row" },
      h("span", { class: "d-addr" }, "Address"),
      h("span", { class: "c-kind" }, "Kind"),
      h("span", { class: "c-fn" }, "Function"),
      h("span", { class: "d-val" }, "Comment"),
    );
    root.append(h("div", { class: "panel-head view-head" }, h("span", { class: "panel-title" }, "Comments"), this.count), h("div", { class: "fn-filter data-filters" }, this.kind, this.filter), head, this.list);
    this.filter.addEventListener("input", () => {
      clearTimeout(this.timer);
      this.timer = window.setTimeout(() => void this.load(), 150);
    });
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
      // A double-click's second press edits (the rows are repainted under
      // the pointer, so no dblclick event reaches a row).
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
      this.pages.set(0, r.comments);
      this.tokens.clear();
      if (r.page?.nextPageToken) this.tokens.set(1, r.page.nextPageToken);
      this.count.textContent = `${this.total.toLocaleString()} ${this.total === 1 ? "comment" : "comments"}`;
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
    const kinds = KINDS[Number(this.kind.value)]?.kinds ?? [];
    // At the first page's revision; page n's token came with page n-1.
    return this.host.rk.queries.listComments({
      programId: this.host.programId,
      kinds,
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
        this.pages.set(page, r.comments);
        if (r.page?.nextPageToken) this.tokens.set(page + 1, r.page.nextPageToken);
        this.paint();
      })
      .catch(() => {})
      .finally(() => this.inFlight.delete(page));
  }

  private item(i: number): ProgramComment | undefined {
    return this.pages.get(Math.floor(i / PAGE))?.[i % PAGE];
  }

  private paint() {
    const top = this.list.scrollTop;
    const first = Math.max(0, Math.floor(top / ROW_H) - 4);
    const last = Math.min(this.total, Math.ceil((top + this.list.clientHeight) / ROW_H) + 4);
    const out: HTMLElement[] = [];
    for (let i = first; i < last; i++) {
      const c = this.item(i);
      if (!c) {
        this.ensure(Math.floor(i / PAGE));
        out.push(h("div", { class: "data-row loading", style: `top:${i * ROW_H}px`, role: "option", "aria-disabled": "true" }, h("span", { class: "dim" }, "…")));
        continue;
      }
      const addr = c.address?.offset ?? 0n;
      const fn = c.functionName ? `${c.functionName}${c.function && c.function.offset !== addr ? `+0x${hex(addr - c.function.offset)}` : ""}` : c.label;
      const text = c.text.replace(/\s+/g, " ");
      out.push(
        h(
          "div",
          {
            class: "data-row comments-row" + (i === this.active ? " active" : ""),
            style: `top:${i * ROW_H}px`,
            "data-i": i,
            "data-testid": "comment-row",
            "data-address": hex(addr),
            role: "option",
            "aria-selected": String(i === this.active),
            title: `${KIND_TEXT[c.kind] ?? "comment"} at ${fmtAddr(addr)}\n${c.text}\n\nClick to go there; double-click to edit`,
          },
          h("span", { class: "d-addr" }, fmtAddr(addr, this.host.addrWidth)),
          h("span", { class: "c-kind dim" }, KIND_TEXT[c.kind] ?? ""),
          h("span", { class: "c-fn" }, fn),
          h("span", { class: `d-val o-${originClass(c.origin)}` }, text),
        ),
      );
    }
    if (!this.total) out.push(h("div", { class: "notes-empty dim", role: "option", "aria-disabled": "true" }, !this.settled ? "Loading…" : this.filter.value.trim() ? "No comment matches" : "No comments"));
    this.rowsEl.replaceChildren(...out);
  }

  private open(edit: boolean) {
    const c = this.item(this.active);
    if (!c?.address) return;
    if (edit) this.host.edit(c.address.offset, c.kind);
    else this.host.navigate(c.address.offset);
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
    const out: { address: string; kind: string; fn: string; text: string }[] = [];
    for (let i = 0; i < Math.min(this.total, 200); i++) {
      const c = this.item(i);
      if (c) out.push({ address: hex(c.address?.offset ?? 0n), kind: KIND_TEXT[c.kind] ?? "", fn: c.functionName, text: c.text });
    }
    return out;
  }
}
