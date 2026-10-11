// Functions panel: a virtualized list paged from the daemon, so it stays
// fast with hundreds of thousands of functions. Pages of ListFunctions are
// fetched by position (offset, feature function-list-offset) as rows come
// into view, all pinned to one revision; the filter is the daemon's
// name_contains. A FUNCTION_LIST invalidation reloads the pages in view at
// the new head. The current function's position comes from a range query
// (how many functions start before it).
//
// With feature function-list-filters (api_minor 19) each row shows the
// signature (asserted, debug info's or parameter ID's), size and
// references; the column bar sorts by name, address, size or references
// (click again to reverse), and "Show" filters named, unnamed (FUN_),
// thunks and functions the decompiler fails on. Sort and filter are the
// daemon's, so they work at any size.

import { FunctionNameFilter, FunctionSort, FunctionThunkFilter, type Revkit, type Function as Fn } from "@revkit/api";
import { originClass, originText, fmtAddr } from "../data/format";
import { otherSpellings, showName, showNameIn } from "../data/names";
import { h, prefs } from "./dom";

type SortKey = "address" | "name" | "size" | "xrefs";
type Show = "all" | "named" | "unnamed" | "thunks" | "nothunks" | "failed";
const SORTS: { key: SortKey; label: string; sort: FunctionSort; extended: boolean }[] = [
  { key: "name", label: "Name", sort: FunctionSort.NAME, extended: false },
  { key: "address", label: "Address", sort: FunctionSort.ADDRESS, extended: false },
  { key: "size", label: "Size", sort: FunctionSort.SIZE, extended: true },
  { key: "xrefs", label: "Refs", sort: FunctionSort.XREFS, extended: true },
];
const SHOWS: { key: Show; label: string }[] = [
  { key: "all", label: "All functions" },
  { key: "named", label: "Named" },
  { key: "unnamed", label: "Unnamed (FUN_)" },
  { key: "thunks", label: "Thunks" },
  { key: "nothunks", label: "Without thunks" },
  { key: "failed", label: "Decompiler failed" },
];
/** Functions per page (?fnpage= overrides it, for tests). */
const PAGE = Number(new URLSearchParams(location.search).get("fnpage")) || 200;
/** Pages fetched at once; more wait for scrolling to settle. */
const MAX_IN_FLIGHT = 3;

interface Entry {
  entry: bigint;
  name: string;
  /** A demangled name's other spellings, for the tooltip (names.ts). */
  spellings: string;
  origin: string;
  size: number;
  proto: string;
  protoOrigin: string;
  protoFrom: string;
  xrefs: number;
  thunk: boolean;
  failed: boolean;
  /** Calls to it don't return (analysis's, or the user's word). */
  noReturn: boolean;
}

export class FunctionsPanel {
  private pages = new Map<number, Entry[]>();
  private inFlight = new Set<number>();
  private total = 0;
  /** Revision the pages are read at (0: not loaded). */
  private revision = 0n;
  /** A load has returned: what an empty list says. */
  private settled = false;
  private query = "";
  private list: HTMLElement;
  private spacer: HTMLElement;
  private rowsEl: HTMLElement;
  readonly filter: HTMLInputElement;
  private count: HTMLElement;
  private active = -1;
  /** Entry of the function containing the current selection. */
  private current: bigint | null = null;
  private loadSeq = 0;
  private filterTimer = 0;
  private revealSeq = 0;
  /** Names seen in any page, by entry (status bar, decompiler title). */
  private names = new Map<bigint, string>();
  onOpen: ((entry: bigint) => void) | null = null;
  /** An import thunk's "→ libc.so.6!strlen" was clicked (feature program-libraries). */
  onExternal: ((entry: bigint) => void) | null = null;
  /** Import thunks' targets, by entry ("libc.so.6!strlen"). */
  private externals = new Map<bigint, string>();
  /** Functions marked with Ctrl+click (at most two): what Compare takes. */
  private marked: { entry: bigint; name: string }[] = [];
  /** A row's context menu was asked for (right-click). */
  onContext: ((row: { entry: bigint; name: string; noReturn?: boolean }, marked: { entry: bigint; name: string }[], x: number, y: number) => void) | null = null;
  /** The list was (re)loaded. */
  onLoaded: (() => void) | null = null;
  /** Offsets work (feature function-list-offset); otherwise everything is loaded once. */
  private paged: boolean;
  /** Sorts beyond name and address, filters, and the columns (api_minor 19). */
  private extended: boolean;
  private sort: SortKey = "address";
  private desc = false;
  private show: Show = "all";
  private sortBar: HTMLElement;
  private showSel: HTMLSelectElement;
  /** Row height: two lines (name, then signature and figures) with the columns. */
  private rowH = 22;

  constructor(
    root: HTMLElement,
    private rk: Revkit,
    private programId: string,
    private addrWidth: number,
    features: Set<string>,
  ) {
    this.paged = features.has("function-list-offset");
    this.extended = features.has("function-list-filters");
    this.rowH = this.extended ? 36 : 22;
    const saved = (prefs.get("rk.fn.sort") ?? "").split(":");
    if (SORTS.some((x) => x.key === saved[0] && (this.extended || !x.extended))) this.sort = saved[0] as SortKey;
    this.desc = saved[1] === "desc";
    const savedShow = prefs.get("rk.fn.show") as Show | null;
    if (this.extended && savedShow && SHOWS.some((x) => x.key === savedShow)) this.show = savedShow;
    this.filter = h("input", { class: "filter", placeholder: "Filter functions", spellcheck: "false", "aria-label": "Filter functions", "data-testid": "fn-filter" });
    this.count = h("span", { class: "dim count", "data-testid": "fn-count" });
    this.spacer = h("div", { class: "fn-spacer" });
    this.rowsEl = h("div", { class: "fn-rows" });
    this.list = h("div", { class: "fn-list" + (this.extended ? " two-line" : ""), tabindex: "0", role: "listbox", "aria-label": "Functions" }, this.spacer, this.rowsEl);
    this.sortBar = h("div", { class: "fn-sort", role: "toolbar", "aria-label": "Sort functions by" });
    this.showSel = h(
      "select",
      { class: "ctl-select fn-show", "aria-label": "Show functions", "data-testid": "fn-show", hidden: !this.extended },
      ...SHOWS.map((x) => h("option", { value: x.key, selected: x.key === this.show }, x.label)),
    ) as HTMLSelectElement;
    this.showSel.addEventListener("change", () => {
      this.show = this.showSel.value as Show;
      prefs.set("rk.fn.show", this.show);
      void this.load(true);
    });
    this.paintSortBar();
    root.append(
      h("div", { class: "panel-head" }, h("span", { class: "panel-title" }, "Functions"), this.count),
      h("div", { class: "fn-filter" }, this.filter, this.showSel),
      this.sortBar,
      this.list,
    );
    this.filter.addEventListener("input", () => {
      clearTimeout(this.filterTimer);
      this.filterTimer = window.setTimeout(() => {
        this.filterTimer = 0;
        void this.load(true);
      }, 120);
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
      if (e.button !== 0) return this.paint();
      // An import thunk's "→ libc.so.6!strlen": the library program there.
      if ((e.target as HTMLElement).closest(".fn-ext")) {
        const it = this.at(this.active);
        if (it) this.onExternal?.(it.entry);
        return;
      }
      if (e.ctrlKey || e.metaKey) {
        const it = this.at(this.active);
        if (it) this.toggleMark(it.entry, it.name);
        return;
      }
      this.open();
    });
    this.rowsEl.addEventListener("contextmenu", (e) => {
      const el = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      const it = el ? this.at(Number(el.dataset.i)) : undefined;
      if (!it || !this.onContext) return;
      e.preventDefault();
      this.onContext({ entry: it.entry, name: it.name, noReturn: it.noReturn }, [...this.marked], e.clientX, e.clientY);
    });
    this.paint();
  }

  /** The column bar: one button per sort, the current one marked with its direction. */
  private paintSortBar() {
    this.sortBar.replaceChildren(
      ...SORTS.filter((x) => this.extended || !x.extended).map((x) => {
        const on = x.key === this.sort;
        return h(
          "button",
          {
            type: "button",
            class: "fn-sort-btn" + (on ? " on" : ""),
            "data-testid": `fn-sort-${x.key}`,
            "aria-pressed": String(on),
            title: on ? `Sorted by ${x.label.toLowerCase()} ${this.desc ? "descending" : "ascending"}; click to reverse` : `Sort by ${x.label.toLowerCase()}`,
            onclick: () => this.setSort(x.key),
          },
          x.label,
          on ? h("span", { class: "fn-sort-dir", "aria-hidden": "true" }, this.desc ? " ↓" : " ↑") : null,
        );
      }),
    );
  }

  /** Sorts by `key`; the current key again reverses it. Sizes and references start largest first. */
  setSort(key: SortKey, desc?: boolean) {
    if (desc !== undefined) this.desc = desc;
    else if (key === this.sort) this.desc = !this.desc;
    else this.desc = key === "size" || key === "xrefs";
    this.sort = key;
    prefs.set("rk.fn.sort", `${key}:${this.desc ? "desc" : "asc"}`);
    this.paintSortBar();
    void this.load(true);
  }

  /** The next sort: size, references, name, address (the palette). */
  cycleSort() {
    const order: SortKey[] = this.extended ? ["size", "xrefs", "name", "address"] : ["name", "address"];
    this.setSort(order[(order.indexOf(this.sort) + 1) % order.length]);
  }

  /** In address order with no filter but the name's: positions can be computed from a range count. */
  private get addressOrder() {
    return this.sort === "address" && !this.desc && this.show === "all";
  }

  /**
   * (Re)loads at head: the count and the pages in view. `reset` (a new
   * filter) goes back to the top; otherwise the scroll position stays.
   */
  async load(reset = false) {
    const seq = ++this.loadSeq;
    const query = this.filter.value.trim();
    const r = await this.fetch(0, query, 0n, this.paged ? PAGE : 5000);
    if (seq !== this.loadSeq) return;
    this.query = query;
    this.settled = true;
    this.revision = r.revision;
    this.total = r.total;
    this.pages.clear();
    this.inFlight.clear();
    if (this.paged) this.pages.set(0, r.entries);
    else {
      // An older daemon: page through everything once with tokens.
      const all = r.entries;
      let token = r.next;
      while (token) {
        const more = await this.rk.queries.listFunctions({ programId: this.programId, nameContains: query, page: { pageSize: 5000, pageToken: token }, ...this.request() });
        if (seq !== this.loadSeq) return;
        for (const f of more.functions) all.push(this.entry(f));
        token = more.page?.nextPageToken ?? "";
      }
      for (let i = 0; i * PAGE < all.length; i++) this.pages.set(i, all.slice(i * PAGE, (i + 1) * PAGE));
      this.total = all.length;
    }
    this.count.textContent = query || this.show !== "all" ? `${this.total.toLocaleString()} match${this.total === 1 ? "" : "es"}` : this.total.toLocaleString();
    this.list.dataset.total = String(this.total);
    if (reset) {
      this.active = this.total ? 0 : -1;
      this.list.scrollTop = 0;
    } else if (this.active >= this.total) this.active = this.total - 1;
    this.spacer.style.height = `${this.total * this.rowH}px`;
    this.paint();
    this.onLoaded?.();
    if (this.current !== null && !reset) void this.reveal(this.current);
  }

  /** The sort and filters as ListFunctions fields. */
  private request() {
    const sort = SORTS.find((x) => x.key === this.sort)!.sort;
    if (!this.extended) return { sort };
    return {
      sort,
      descending: this.desc,
      named: this.show === "named" ? FunctionNameFilter.NAMED : this.show === "unnamed" ? FunctionNameFilter.UNNAMED : FunctionNameFilter.UNSPECIFIED,
      thunks: this.show === "thunks" ? FunctionThunkFilter.ONLY : this.show === "nothunks" ? FunctionThunkFilter.EXCLUDE : FunctionThunkFilter.UNSPECIFIED,
      decompileFailed: this.show === "failed",
    };
  }

  private async fetch(offset: number, query: string, revision: bigint, pageSize = PAGE) {
    const r = await this.rk.queries.listFunctions({
      programId: this.programId,
      nameContains: query,
      offset: BigInt(offset),
      page: { pageSize },
      read: { revision },
      ...this.request(),
    });
    const entries = r.functions.map((f) => this.entry(f));
    const total = r.page && r.page.totalCount >= 0n ? Number(r.page.totalCount) : entries.length;
    return { entries, total, revision: r.snapshot?.revision ?? 0n, next: r.page?.nextPageToken ?? "" };
  }

  private entry(f: Fn): Entry {
    let size = Number(f.size);
    if (!size) for (const b of f.body) size += Number((b.last?.offset ?? 0n) - (b.first?.offset ?? 0n) + 1n);
    const e: Entry = {
      entry: f.entry?.offset ?? 0n,
      name: showName(f.name, f.demangled),
      spellings: otherSpellings(f.name, f.demangled),
      origin: originClass(f.nameOrigin),
      size,
      proto: showNameIn(f.prototype, f.name, f.demangled),
      protoOrigin: originClass(f.prototypeOrigin),
      protoFrom: f.prototype ? originText(f.prototypeOrigin) : "",
      xrefs: f.xrefCount || f.callerCount,
      thunk: f.thunk,
      noReturn: f.noReturn,
      failed: f.decompileFailed,
    };
    this.names.set(e.entry, e.name);
    if (this.names.size > 50000) this.names.delete(this.names.keys().next().value!);
    return e;
  }

  /** Functions in the pages loaded so far (not every function). */
  get functions(): readonly { entry: bigint; name: string }[] {
    return [...this.pages.values()].flat();
  }

  get totalCount() {
    return this.total;
  }

  /** The name, if a page that listed it was loaded. */
  nameAt(entry: bigint): string | undefined {
    return this.names.get(entry);
  }

  /** Forget cached names (an edit renamed something). */
  forgetNames() {
    this.names.clear();
  }

  private at(i: number): Entry | undefined {
    return this.pages.get(Math.floor(i / PAGE))?.[i % PAGE];
  }

  private want(first: number, last: number) {
    if (!this.paged || !this.revision) return;
    const seq = this.loadSeq;
    for (let p = Math.floor(first / PAGE); p <= Math.floor(last / PAGE); p++) {
      if (this.pages.has(p) || this.inFlight.has(p) || this.inFlight.size >= MAX_IN_FLIGHT) continue;
      this.inFlight.add(p);
      this.fetch(p * PAGE, this.query, this.revision).then(
        (r) => {
          if (seq !== this.loadSeq) return;
          this.inFlight.delete(p);
          this.pages.set(p, r.entries);
          // Keep a bounded window of pages.
          if (this.pages.size > 200) for (const k of [...this.pages.keys()]) if (Math.abs(k - p) > 50 && this.pages.delete(k) && this.pages.size <= 150) break;
          this.paint();
        },
        (e) => {
          this.inFlight.delete(p);
          if (seq !== this.loadSeq) return;
          // The pinned revision expired (many edits since): reload at head.
          if (String(e).includes("REVISION_EXPIRED")) void this.load();
        },
      );
    }
  }

  private paint() {
    const ROW_H = this.rowH;
    const top = this.list.scrollTop;
    const height = this.list.clientHeight || 600;
    const first = Math.max(0, Math.floor(top / ROW_H) - 4);
    const last = Math.min(this.total, Math.ceil((top + height) / ROW_H) + 4);
    this.want(first, Math.max(first, last - 1));
    const frag = document.createDocumentFragment();
    for (let i = first; i < last; i++) {
      const e = this.at(i);
      const cls = ["fn-row"];
      if (i === this.active) cls.push("active");
      if (!e) {
        frag.append(h("div", { class: cls.join(" ") + " loading", "data-i": i, style: `top:${i * ROW_H}px;height:${ROW_H}px`, role: "option", "aria-selected": String(i === this.active) }, h("span", { class: "fn-name dim" }, "…")));
        continue;
      }
      if (e.entry === this.current) cls.push("current");
      if (this.marked.some((m) => m.entry === e.entry)) cls.push("marked");
      if (e.thunk) cls.push("thunk");
      const title = [`${e.name} @ ${fmtAddr(e.entry)}`, e.spellings, e.proto ? `${e.proto}  (${e.protoFrom})` : "no signature yet", `${e.size.toLocaleString()} bytes · ${e.xrefs} reference${e.xrefs === 1 ? "" : "s"}`, e.thunk ? "thunk" : "", e.failed ? "the decompiler fails on it" : ""].filter(Boolean).join("\n");
      const ext = this.externals.get(e.entry);
      const badges = [e.failed ? h("span", { class: "fn-badge fail", title: "The decompiler fails on it" }, "⚠") : null, e.thunk ? h("span", { class: "fn-badge", title: "Thunk" }, "⇢") : null];
      if (!this.extended) {
        frag.append(
          h(
            "div",
            { class: cls.join(" "), "data-i": i, style: `top:${i * ROW_H}px`, title, role: "option", "aria-selected": String(i === this.active) },
            h("span", { class: `fn-name o-${e.origin}` }, e.name),
            h("span", { class: "fn-addr" }, fmtAddr(e.entry, this.addrWidth)),
          ),
        );
        continue;
      }
      const metric = (k: SortKey) => (k === this.sort ? " fn-sorted" : "");
      frag.append(
        h(
          "div",
          { class: cls.join(" ") + " two", "data-i": i, style: `top:${i * ROW_H}px;height:${ROW_H}px`, title, role: "option", "aria-selected": String(i === this.active) },
          h("div", { class: "fn-line" }, h("span", { class: `fn-name o-${e.origin}` }, e.name), ...badges, h("span", { class: "fn-addr" + metric("address") }, fmtAddr(e.entry, this.addrWidth))),
          h(
            "div",
            { class: "fn-line fn-sub" },
            ext
              ? h("span", { class: "fn-ext", "data-testid": "fn-ext", title: `Imported from ${ext}: click to open the library program there` }, `→ ${ext}`)
              : h("span", { class: `fn-sig o-${e.protoOrigin}`, "data-testid": "fn-sig" }, e.proto || "—"),
            h("span", { class: "fn-size" + metric("size") }, sizeText(e.size)),
            h("span", { class: "fn-refs" + metric("xrefs"), title: `${e.xrefs} references` }, `${e.xrefs}↙`),
          ),
        ),
      );
    }
    // A listbox always holds an option: one that says why there are no rows.
    if (!this.total) frag.append(h("div", { class: "notes-empty dim", role: "option", "aria-disabled": "true" }, !this.settled ? "Loading…" : this.query || this.show !== "all" ? "No functions match" : "No functions"));
    this.rowsEl.replaceChildren(frag);
  }

  private onKey(e: KeyboardEvent) {
    // Enter right after typing: filter first, then open the first match.
    if (e.key === "Enter" && (this.filterTimer || this.filter.value.trim() !== this.query)) {
      e.preventDefault();
      e.stopPropagation();
      clearTimeout(this.filterTimer);
      this.filterTimer = 0;
      void this.load(true).then(() => this.open());
      return;
    }
    const n = this.total;
    if (!n) return;
    const ROW_H = this.rowH;
    const page = Math.max(1, Math.floor(this.list.clientHeight / ROW_H) - 1);
    let handled = true;
    switch (e.key) {
      case "ArrowDown":
        this.active = Math.min(n - 1, this.active + 1);
        break;
      case "ArrowUp":
        this.active = Math.max(0, this.active - 1);
        break;
      case "PageDown":
        this.active = Math.min(n - 1, this.active + page);
        break;
      case "PageUp":
        this.active = Math.max(0, this.active - page);
        break;
      case "Enter":
        this.open();
        break;
      case "Escape":
        if (this.filter.value) {
          this.filter.value = "";
          void this.load(true);
        } else handled = false;
        break;
      default:
        handled = false;
    }
    if (!handled) return;
    e.preventDefault();
    e.stopPropagation();
    this.scrollTo(this.active);
    this.paint();
  }

  private scrollTo(i: number) {
    const ROW_H = this.rowH;
    const top = i * ROW_H;
    if (top < this.list.scrollTop) this.list.scrollTop = top;
    else if (top + ROW_H > this.list.scrollTop + this.list.clientHeight) this.list.scrollTop = top + ROW_H - this.list.clientHeight;
  }

  private open() {
    const e = this.at(this.active);
    if (e) this.onOpen?.(e.entry);
  }

  /** Marks or unmarks a function for Compare (Ctrl+click); a third mark drops the oldest. */
  toggleMark(entry: bigint, name: string) {
    const i = this.marked.findIndex((m) => m.entry === entry);
    if (i >= 0) this.marked.splice(i, 1);
    else {
      this.marked.push({ entry, name });
      if (this.marked.length > 2) this.marked.shift();
    }
    this.paint();
  }

  /** The marked functions, oldest first. */
  markedFunctions(): { entry: bigint; name: string }[] {
    return [...this.marked];
  }

  /** Import thunks' targets ("libc.so.6!strlen"), shown under their names. */
  setExternals(m: Map<bigint, string>) {
    this.externals = m;
    this.paint();
  }

  /** Marks the function containing the selection and scrolls it into view. */
  setCurrent(entry: bigint | null) {
    if (entry === this.current) return;
    this.current = entry;
    if (entry !== null) void this.reveal(entry);
    this.paint();
  }

  /**
   * Scrolls to `entry` unless the user is in the panel. Its position is
   * the number of matching functions that start before it (ListFunctions
   * over [0, entry - 1], one item, at the pages' revision).
   */
  private async reveal(entry: bigint) {
    if (document.activeElement === this.filter || this.list.contains(document.activeElement)) return;
    const seq = ++this.revealSeq;
    let i = -1;
    for (const [p, entries] of this.pages) {
      const k = entries.findIndex((e) => e.entry === entry);
      if (k >= 0) i = p * PAGE + k;
    }
    if (i < 0 && this.paged && this.revision && entry > 0n && this.addressOrder) {
      try {
        const r = await this.rk.queries.listFunctions({
          programId: this.programId,
          nameContains: this.query,
          range: { first: { offset: 0n }, last: { offset: entry - 1n } },
          page: { pageSize: 1 },
          read: { revision: this.revision },
        });
        if (seq !== this.revealSeq || this.current !== entry) return;
        i = Number(r.page?.totalCount ?? -1n);
        // Not a match of the filter: nothing to show.
        if (this.at(i) && this.at(i)!.entry !== entry) return;
      } catch {
        return;
      }
    }
    if (i < 0 || i >= this.total) return;
    this.active = i;
    const ROW_H = this.rowH;
    const top = i * ROW_H;
    if (top < this.list.scrollTop || top + ROW_H > this.list.scrollTop + this.list.clientHeight) this.list.scrollTop = top - this.list.clientHeight / 3;
    this.paint();
  }

  focusFilter() {
    this.filter.focus();
    this.filter.select();
  }
}

/** "64 B", "1.2 KB": a function's size, short. */
function sizeText(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1 << 20) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  return `${(n / (1 << 20)).toFixed(1)} MB`;
}
