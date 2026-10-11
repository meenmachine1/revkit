// The byte viewer (Ghidra's Bytes window; feature byte-viewer, api_minor 44):
// a dockable hex view of the program's memory with an ASCII column and,
// optionally, octal, binary, UTF-16 and integer columns; as many bytes a
// line as fit the pane (auto: 4, 8, 16 or 32, the default) or 8, 16 or 32,
// in groups of 1, 2, 4 or 8. Its cursor and selection follow the
// listing (and so the decompiler) and drive it back. Bytes are tinted by
// what the listing makes of them (code, data, undefined; uninitialized
// shows "??"), patched ones are marked, and with Edit on, typing hex or
// characters over them writes patches (PatchService.PatchBytes) that undo
// as one step per edit session. QueryService.GetByteView supplies bytes,
// kinds and the file's bytes where patched, for the lines in view.

import { ByteKind, type ByteRun, type Revkit } from "@revkit/api";
import { userProvenance } from "../api/client";
import type { Edits } from "../data/edits";
import { errText, fmtAddr, hex } from "../data/format";
import { toast } from "../ui/dialogs";
import { h, prefs } from "../ui/dom";
import { showMenuAt, type MenuItem } from "../ui/menu";
import "./bytes.css";

export interface ByteViewHost {
  rk: Revkit;
  programId: string;
  addrWidth: number;
  edits: Edits;
  bigEndian: boolean;
  /** The memory blocks, in address order (inclusive ranges). */
  blocks: { first: bigint; last: bigint; name: string; initialized: boolean }[];
  /** Whether PatchService is there (feature patch): Edit writes through it. */
  canPatch: boolean;
  /** The cursor moved here in the viewer: select its code unit in the listing. */
  select: (addr: bigint) => void;
  /** A range was selected in the viewer: select the listing rows over it. */
  selectRange: (lo: bigint, hi: bigint) => void;
  /** Waits until this tab has applied a revision. */
  settle: (rev: bigint) => Promise<void>;
}

export type Column = "hex" | "ascii" | "octal" | "binary" | "utf16" | "int";
const COLUMNS: { id: Column; label: string }[] = [
  { id: "hex", label: "Hex" },
  { id: "ascii", label: "ASCII" },
  { id: "octal", label: "Octal" },
  { id: "binary", label: "Binary" },
  { id: "utf16", label: "UTF-16" },
  { id: "int", label: "Integer (signed, by group)" },
];

/** A fetched stretch of memory: bytes, the kind of each, the runs, patches. */
interface Chunk {
  start: bigint;
  data: Uint8Array;
  kinds: Uint8Array;
  runs: ByteRun[];
  /** Original (file) byte by offset into `data`, where patched. */
  original: Map<number, number>;
}

const KIND_CLASS: Record<number, string> = {
  [ByteKind.CODE]: "k-code",
  [ByteKind.DATA]: "k-data",
  [ByteKind.UNDEFINED]: "k-undef",
  [ByteKind.EXTERNAL]: "k-ext",
  [ByteKind.UNINITIALIZED]: "k-uninit",
};
const KIND_NAME: Record<number, string> = {
  [ByteKind.CODE]: "code",
  [ByteKind.DATA]: "data",
  [ByteKind.UNDEFINED]: "undefined",
  [ByteKind.EXTERNAL]: "external",
  [ByteKind.UNINITIALIZED]: "uninitialized",
};

const LINE_H = 18;

export class ByteViewer {
  readonly el: HTMLElement;
  private body: HTMLElement;
  private head: HTMLElement;
  private status: HTMLElement;
  private editBtn: HTMLButtonElement;
  private followBox: HTMLInputElement;
  private bplSel: HTMLSelectElement;
  private groupSel: HTMLSelectElement;

  /** The cursor byte; null before anything is shown. */
  cursor: bigint | null = null;
  /** The selection's other end while the viewer selects (click, drag, Shift). */
  private anchor: bigint | null = null;
  /** The selection, inclusive (set by the viewer or by the listing). */
  selection: [bigint, bigint] | null = null;
  /** First line's address. */
  top = 0n;
  bpl = 16;
  /** Bytes per line chosen: "auto" (as many as fit, a power of two) or 8, 16, 32. */
  bplMode: "auto" | number = "auto";
  /** The group size chosen (the one in use is at most bpl). */
  private groupPref = 1;
  group = 1;
  private charW = 0;
  columns = new Set<Column>(["hex", "ascii"]);
  /** Edit is on: typing writes patches. */
  editing = false;
  /** Which column typing goes to. */
  editCol: "hex" | "ascii" = "hex";
  /** The low nibble is next (hex typing). */
  private nibble = 0;
  /** Follow the listing's cursor (off: the view stays where it is, pinned). */
  follow = true;

  private chunks: Chunk[] = [];
  private stale = true;
  private fetchSeq = 0;
  private loading: Promise<void> | null = null;
  /** Typed bytes not yet written, by address. */
  private pending = new Map<bigint, number>();
  private flushTimer = 0;
  private writing: Promise<void> = Promise.resolve();
  private session = "";
  private sessionBytes = new Set<bigint>();
  private dragging = false;
  private visible = false;
  /** A range this view selected and sent to the listing: kept when the listing's (whole code units) comes back over it. */
  private ownRange: [bigint, bigint] | null = null;

  constructor(private host: ByteViewHost) {
    const savedBpl = Number(prefs.get("rk.bv.bpl"));
    this.bplMode = [8, 16, 32].includes(savedBpl) ? savedBpl : "auto";
    this.bpl = this.bplMode === "auto" ? 16 : this.bplMode;
    this.groupPref = [1, 2, 4, 8].includes(Number(prefs.get("rk.bv.group"))) ? Number(prefs.get("rk.bv.group")) : 1;
    this.group = Math.min(this.groupPref, this.bpl);
    const saved = (prefs.get("rk.bv.cols") ?? "").split(",").filter((c) => COLUMNS.some((x) => x.id === c)) as Column[];
    if (saved.length) this.columns = new Set(saved);
    this.bplSel = h(
      "select",
      { class: "bv-select", "aria-label": "Bytes per line", "data-testid": "bv-bpl", title: "Bytes per line: auto fits the pane" },
      h("option", { value: "auto", selected: this.bplMode === "auto" }, "auto / line"),
      ...[8, 16, 32].map((n) => h("option", { value: n, selected: n === this.bplMode }, `${n} / line`)),
    );
    this.groupSel = h("select", { class: "bv-select", "aria-label": "Group size", "data-testid": "bv-group" }, ...[1, 2, 4, 8].map((n) => h("option", { value: n, selected: n === this.group }, `group ${n}`)));
    this.bplSel.onchange = () => this.setLayout(this.bplSel.value === "auto" ? "auto" : Number(this.bplSel.value), this.groupPref);
    this.groupSel.onchange = () => this.setLayout(this.bplMode, Number(this.groupSel.value));
    const colsBtn = h("button", { class: "btn bv-btn", type: "button", "aria-haspopup": "menu", "data-testid": "bv-columns", title: "Columns: hex, ASCII, octal, binary, UTF-16, integer" }, "Columns ▾");
    colsBtn.onclick = () => showMenuAt(colsBtn, this.columnItems(), "Columns");
    this.editBtn = h("button", { class: "btn bv-btn", type: "button", "aria-pressed": "false", "data-testid": "bv-edit", title: "Edit: type hex or characters over the bytes (patches; one undo step per edit session)" }, "Edit");
    this.editBtn.onclick = () => this.setEditing(!this.editing);
    this.followBox = h("input", { type: "checkbox", checked: true, "data-testid": "bv-follow" });
    this.followBox.onchange = () => {
      this.follow = this.followBox.checked;
    };
    this.status = h("span", { class: "bv-status dim", "data-testid": "bv-status", "aria-live": "polite" });
    this.head = h(
      "div",
      { class: "view-head bv-head" },
      h("span", { class: "panel-title" }, "Bytes"),
      this.bplSel,
      this.groupSel,
      colsBtn,
      this.editBtn,
      h("label", { class: "bv-follow", title: "Follow the listing's cursor (off: this view stays put, a snapshot)" }, this.followBox, " Follow"),
      this.status,
    );
    this.body = h("div", { class: "bv-body mono", tabindex: "0", role: "grid", "aria-label": "Bytes", "data-testid": "bv-body" });
    this.el = h("div", { class: "bv", "data-testid": "byte-viewer" }, this.head, this.body);
    this.body.addEventListener("wheel", (e) => this.onWheel(e), { passive: false });
    this.body.addEventListener("mousedown", (e) => this.onMouseDown(e));
    this.body.addEventListener("mousemove", (e) => this.onMouseMove(e));
    window.addEventListener("mouseup", () => this.onMouseUp());
    this.body.addEventListener("keydown", (e) => this.onKey(e));
    this.body.addEventListener("copy", (e) => this.onCopy(e));
    this.body.addEventListener("blur", () => this.flushSoon(0));
    new ResizeObserver(() => {
      if (this.visible) this.render();
    }).observe(this.body);
  }

  // ------------------------------------------------------------- layout --

  private get lines(): number {
    return Math.max(1, Math.floor((this.body.clientHeight || 400) / LINE_H));
  }

  private lineOf(a: bigint): bigint {
    return a - (a % BigInt(this.bpl));
  }

  /** The block holding `a`, or null. */
  private blockAt(a: bigint) {
    return this.host.blocks.find((b) => a >= b.first && a <= b.last) ?? null;
  }

  /** The line after `line`, skipping gaps between blocks; null at the end. */
  private nextLine(line: bigint): bigint | null {
    const n = line + BigInt(this.bpl);
    const end = n + BigInt(this.bpl) - 1n;
    if (this.host.blocks.some((b) => b.first <= end && b.last >= n)) return n;
    const next = this.host.blocks.find((b) => b.first >= n);
    return next ? this.lineOf(next.first) : null;
  }

  /** The line before `line`, skipping gaps; null at the start. */
  private prevLine(line: bigint): bigint | null {
    if (line === 0n) return null;
    const p = line - BigInt(this.bpl);
    if (this.host.blocks.some((b) => b.first <= line - 1n && b.last >= p)) return p;
    const prev = [...this.host.blocks].reverse().find((b) => b.last < line);
    return prev ? this.lineOf(prev.last) : null;
  }

  /** The lines in view, from `top`. */
  private viewLines(): bigint[] {
    const out: bigint[] = [];
    let l: bigint | null = this.top;
    for (let i = 0; i < this.lines && l !== null; i++) {
      out.push(l);
      l = this.nextLine(l);
    }
    return out;
  }

  setLayout(bpl: "auto" | number, group: number) {
    this.bplMode = bpl;
    this.groupPref = group;
    prefs.set("rk.bv.bpl", String(bpl));
    prefs.set("rk.bv.group", String(group));
    this.bplSel.value = String(bpl);
    this.groupSel.value = String(group);
    this.applyBpl(bpl === "auto" ? this.fittingBpl() : bpl);
    this.scrollToCursor();
    this.render();
  }

  /** Uses `n` bytes a line (and a group no larger), keeping the cursor's line. */
  private applyBpl(n: number) {
    this.bpl = n;
    this.group = Math.min(this.groupPref, n);
    this.top = this.lineOf(this.cursor ?? this.top);
    const auto = this.bplSel.querySelector<HTMLOptionElement>("option[value=auto]");
    if (auto) auto.textContent = this.bplMode === "auto" ? `auto (${n}) / line` : "auto / line";
  }

  /** How wide a line of `n` bytes is, in px, with the columns shown. */
  private lineWidth(n: number): number {
    if (!this.charW) {
      const probe = h("span", { class: "bv-col" }, "0".repeat(40));
      this.body.append(probe);
      this.charW = probe.getBoundingClientRect().width / 40 || 7.8;
      probe.remove();
    }
    const g = Math.min(this.groupPref, n);
    let chars = fmtAddr(0n, this.host.addrWidth).length;
    let cols = 1;
    const add = (c: number) => {
      chars += c;
      cols++;
    };
    if (this.columns.has("hex")) add(2 * n + n / g - 1);
    if (this.columns.has("octal")) add(4 * n - 1);
    if (this.columns.has("binary")) add(9 * n - 1);
    if (this.columns.has("int")) add((n / g) * ((g === 1 ? 4 : g === 2 ? 6 : g === 4 ? 11 : 20) + 1));
    if (this.columns.has("utf16")) add(n / 2);
    if (this.columns.has("ascii")) add(n);
    // The line's gaps (14 px) and the body's padding (8 px a side).
    return chars * this.charW + (cols - 1) * 14 + 16;
  }

  /** Auto: the most bytes a line (32, 16, 8, else 4) that fit the pane's width. */
  private fittingBpl(): number {
    const w = this.body.clientWidth;
    if (!w) return this.bpl;
    for (const n of [32, 16, 8]) if (this.lineWidth(n) <= w) return n;
    return 4;
  }

  setColumn(c: Column, on: boolean) {
    if (on) this.columns.add(c);
    else this.columns.delete(c);
    if (!this.columns.size) this.columns.add("hex");
    prefs.set("rk.bv.cols", [...this.columns].join(","));
    this.charW = 0;
    this.render();
  }

  private columnItems(): MenuItem[] {
    return COLUMNS.map((c) => ({
      label: c.label,
      checked: this.columns.has(c.id),
      testid: `bv-col-${c.id}`,
      run: () => this.setColumn(c.id, !this.columns.has(c.id)),
    }));
  }

  // -------------------------------------------------------------- data --

  /** The view became visible or the program changed: refetch what is shown. */
  invalidate() {
    this.stale = true;
    if (this.visible) void this.load();
  }

  setVisible(v: boolean) {
    this.visible = v;
    if (v) {
      if (this.cursor === null && this.host.blocks.length) this.moveTo(this.host.blocks[0].first, false);
      void this.load();
    }
  }

  /** The contiguous stretches of the lines in view (lines are contiguous but at gaps). */
  private segments(lines: bigint[]): [bigint, bigint][] {
    const out: [bigint, bigint][] = [];
    const n = BigInt(this.bpl);
    for (const l of lines) {
      const last = out.at(-1);
      if (last && last[1] === l) last[1] = l + n;
      else out.push([l, l + n]);
    }
    return out;
  }

  private covered(lines: bigint[]): boolean {
    return this.segments(lines).every(([a, b]) => this.chunks.some((c) => c.start <= a && c.start + BigInt(c.data.length) >= b));
  }

  /** Fetches the lines in view (and a screenful either side) unless held. */
  async load(): Promise<void> {
    const lines = this.viewLines();
    if (!this.stale && this.covered(lines)) return this.render();
    const seq = ++this.fetchSeq;
    const n = BigInt(this.bpl * this.lines);
    const segs = this.segments(lines).map(([a, b]) => [a > n ? a - n : 0n, b + n] as [bigint, bigint]);
    const run = (async () => {
      const chunks: Chunk[] = [];
      for (const [a, b] of segs) {
        for (let at = a; at < b; at += 65536n) {
          const len = Number(b - at < 65536n ? b - at : 65536n);
          const r = await this.host.rk.queries.getByteView({ programId: this.host.programId, address: { offset: at }, length: len });
          const data = r.data;
          const kinds = new Uint8Array(data.length);
          const start = r.address?.offset ?? at;
          for (const run of r.runs) {
            const s = run.start?.offset ?? 0n;
            const from = s < start ? 0 : Number(s - start);
            const to = Math.min(data.length, Number(s - start) + run.length);
            kinds.fill(run.kind, Math.max(0, from), Math.max(0, to));
          }
          const original = new Map<number, number>();
          for (const p of r.patched) {
            const off = Number((p.start?.offset ?? 0n) - start);
            p.original.forEach((v, i) => original.set(off + i, v));
          }
          chunks.push({ start, data, kinds, runs: r.runs, original });
        }
      }
      if (seq !== this.fetchSeq) return;
      this.chunks = chunks;
      this.stale = false;
      this.render();
    })();
    this.loading = run;
    try {
      await run;
    } catch (e) {
      if (seq === this.fetchSeq) this.status.textContent = errText(e);
    } finally {
      if (this.loading === run) this.loading = null;
    }
  }

  /** Settles once the lines in view are loaded (tests). */
  async ready(): Promise<void> {
    while (this.loading) await this.loading;
  }

  private byteAt(a: bigint): { v: number; kind: number; orig?: number } | null {
    for (const c of this.chunks) {
      if (a < c.start || a >= c.start + BigInt(c.data.length)) continue;
      const i = Number(a - c.start);
      return { v: c.data[i], kind: c.kinds[i], orig: c.original.get(i) };
    }
    return null;
  }

  /** The code unit (instruction, data item) or run holding `a`. */
  private runAt(a: bigint): ByteRun | null {
    for (const c of this.chunks)
      for (const r of c.runs) {
        const s = r.start?.offset ?? 0n;
        if (a >= s && a < s + BigInt(r.length)) return r;
      }
    return null;
  }

  // ----------------------------------------------------------- cursor --

  /** The listing (or the decompiler through it) moved to a code unit. */
  followListing(addr: bigint, length: number, range: [bigint, bigint] | null) {
    if (!this.follow) return;
    const inUnit = this.cursor !== null && this.cursor >= addr && this.cursor < addr + BigInt(Math.max(1, length));
    if (!inUnit) {
      this.cursor = addr;
      this.nibble = 0;
    }
    const own = this.ownRange;
    if (own && range && range[0] <= own[0] && range[1] >= own[1]) {
      this.selection = own;
    } else {
      this.ownRange = null;
      this.anchor = null;
      this.selection = range;
    }
    this.scrollToCursor();
    if (this.visible) void this.load();
  }

  private scrollToCursor() {
    if (this.cursor === null) return;
    const lines = this.viewLines();
    const line = this.lineOf(this.cursor);
    if (lines.length && line >= lines[0] && line <= lines[lines.length - 1]) return;
    // A third down the view, like the listing's jumps.
    let t = line;
    for (let i = 0; i < Math.floor(this.lines / 3); i++) t = this.prevLine(t) ?? t;
    this.top = t;
  }

  /** Moves the cursor (keys, clicks); `extend` grows the selection. */
  moveTo(a: bigint, notify = true, extend = false) {
    if (extend) {
      if (this.anchor === null) this.anchor = this.cursor ?? a;
    } else this.anchor = null;
    this.cursor = a;
    this.nibble = 0;
    if (this.anchor !== null && this.anchor !== a) this.selection = this.anchor < a ? [this.anchor, a] : [a, this.anchor];
    else if (!extend) this.selection = null;
    this.scrollToCursor();
    void this.load();
    this.ownRange = extend ? this.selection : null;
    if (!notify) return;
    if (this.selection && extend) this.host.selectRange(this.selection[0], this.selection[1]);
    else this.host.select(a);
  }

  private step(delta: number, extend: boolean) {
    if (this.cursor === null) return;
    let a = this.cursor + BigInt(delta);
    if (a < 0n) a = 0n;
    // Off the end of a block: into the next (or previous) one.
    if (!this.blockAt(a)) {
      const b = delta > 0 ? this.host.blocks.find((x) => x.first > this.cursor!) : [...this.host.blocks].reverse().find((x) => x.last < this.cursor!);
      if (!b) return;
      a = delta > 0 ? b.first : b.last;
    }
    this.moveTo(a, true, extend);
  }

  // ------------------------------------------------------------ input --

  private addrOf(e: MouseEvent): { a: bigint; col: string } | null {
    const el = (e.target as HTMLElement).closest<HTMLElement>("[data-a]");
    if (!el) return null;
    return { a: BigInt("0x" + el.dataset.a), col: el.dataset.col ?? "hex" };
  }

  private onMouseDown(e: MouseEvent) {
    const hit = this.addrOf(e);
    this.body.focus({ preventScroll: true });
    if (!hit || e.button !== 0) return;
    e.preventDefault();
    if (hit.col === "ascii" || hit.col === "hex") this.editCol = hit.col;
    this.moveTo(hit.a, true, e.shiftKey && this.cursor !== null);
    this.dragging = true;
  }

  private onMouseMove(e: MouseEvent) {
    if (!this.dragging || !(e.buttons & 1)) return;
    const hit = this.addrOf(e);
    if (!hit || hit.a === this.cursor) return;
    if (this.anchor === null) this.anchor = this.cursor;
    this.cursor = hit.a;
    this.selection = this.anchor! < hit.a ? [this.anchor!, hit.a] : [hit.a, this.anchor!];
    this.render();
  }

  private onMouseUp() {
    if (!this.dragging) return;
    this.dragging = false;
    if (this.selection && this.anchor !== null) {
      this.ownRange = this.selection;
      this.host.selectRange(this.selection[0], this.selection[1]);
    }
  }

  private onWheel(e: WheelEvent) {
    e.preventDefault();
    const n = Math.max(1, Math.round(Math.abs(e.deltaMode === 1 ? e.deltaY : e.deltaY / LINE_H)));
    for (let i = 0; i < n; i++) {
      const t = e.deltaY > 0 ? this.nextLine(this.top) : this.prevLine(this.top);
      if (t === null) break;
      this.top = t;
    }
    void this.load();
  }

  private onKey(e: KeyboardEvent) {
    const k = e.key;
    const page = this.bpl * (this.lines - 1);
    const nav: Record<string, () => void> = {
      ArrowLeft: () => this.step(-1, e.shiftKey),
      ArrowRight: () => this.step(1, e.shiftKey),
      ArrowUp: () => this.step(-this.bpl, e.shiftKey),
      ArrowDown: () => this.step(this.bpl, e.shiftKey),
      PageUp: () => this.step(-page, e.shiftKey),
      PageDown: () => this.step(page, e.shiftKey),
      Home: () => this.cursor !== null && this.moveTo(this.lineOf(this.cursor), true, e.shiftKey),
      End: () => this.cursor !== null && this.moveTo(this.lineOf(this.cursor) + BigInt(this.bpl - 1), true, e.shiftKey),
    };
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (nav[k]) {
      e.preventDefault();
      e.stopPropagation();
      nav[k]();
      return;
    }
    if (k === "Escape") {
      e.stopPropagation();
      this.selection = null;
      this.anchor = null;
      this.render();
      return;
    }
    if (!this.editing) return;
    if (k === "Tab") {
      e.preventDefault();
      e.stopPropagation();
      this.editCol = this.editCol === "hex" ? "ascii" : "hex";
      this.nibble = 0;
      this.render();
      return;
    }
    if (k === "Enter") {
      e.preventDefault();
      e.stopPropagation();
      this.flushSoon(0);
      return;
    }
    if (k === "Backspace") {
      e.preventDefault();
      e.stopPropagation();
      this.step(-1, false);
      return;
    }
    if (k.length !== 1) return;
    e.preventDefault();
    e.stopPropagation();
    this.type(k);
  }

  /** Typing over the byte at the cursor (Edit on). */
  type(k: string) {
    const a = this.cursor;
    if (a === null) return;
    const cur = this.byteAt(a);
    const block = this.blockAt(a);
    if (!cur || !block || !block.initialized || cur.kind === ByteKind.UNINITIALIZED) {
      toast("No bytes to edit here (uninitialized memory)", { kind: "error" });
      return;
    }
    let v = this.pending.get(a) ?? cur.v;
    if (this.editCol === "hex") {
      if (!/^[0-9a-f]$/i.test(k)) return;
      const d = parseInt(k, 16);
      v = this.nibble === 0 ? (d << 4) | (v & 0x0f) : (v & 0xf0) | d;
    } else {
      const c = k.charCodeAt(0);
      if (c > 0xff) {
        toast("Only Latin-1 characters fit a byte", { kind: "error" });
        return;
      }
      v = c;
    }
    this.pending.set(a, v);
    if (this.editCol === "hex" && this.nibble === 0) this.nibble = 1;
    else {
      this.nibble = 0;
      this.cursor = a + 1n;
      if (!this.blockAt(this.cursor)) this.cursor = a;
      this.scrollToCursor();
    }
    this.flushSoon();
    void this.load();
  }

  setEditing(on: boolean) {
    if (on && !this.host.canPatch) {
      toast("This daemon can't patch bytes (feature patch)", { kind: "error" });
      return;
    }
    if (!on) this.flushSoon(0);
    this.editing = on;
    if (on) {
      // A new edit session: its writes undo as one step.
      this.session = `bv-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
      this.sessionBytes.clear();
    }
    this.editBtn.setAttribute("aria-pressed", String(on));
    this.editBtn.classList.toggle("on", on);
    this.el.classList.toggle("editing", on);
    this.nibble = 0;
    this.render();
    if (on) this.body.focus({ preventScroll: true });
  }

  private flushSoon(ms = 250) {
    clearTimeout(this.flushTimer);
    if (!this.pending.size) return;
    this.flushTimer = window.setTimeout(() => void this.flush(), ms);
  }

  /** Writes the typed bytes: one PatchBytes per contiguous run, recorded in the session's undo step. */
  flush(): Promise<void> {
    clearTimeout(this.flushTimer);
    const todo = [...this.pending.entries()].sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
    if (!todo.length) return this.writing;
    const runs: { start: bigint; bytes: number[] }[] = [];
    for (const [a, v] of todo) {
      const last = runs.at(-1);
      if (last && last.start + BigInt(last.bytes.length) === a) last.bytes.push(v);
      else runs.push({ start: a, bytes: [v] });
    }
    const written = new Map(todo);
    this.writing = this.writing.then(async () => {
      let rev = 0n;
      try {
        if (!this.host.edits.sessionOnTop(this.session)) this.sessionBytes.clear();
        for (const r of runs) {
          const resp = await this.host.rk.patch.patchBytes({
            programId: this.host.programId,
            address: { offset: r.start },
            data: new Uint8Array(r.bytes),
            provenance: userProvenance("byte viewer"),
          });
          rev = resp.revision;
          for (let i = 0; i < r.bytes.length; i++) this.sessionBytes.add(r.start + BigInt(i));
          const first = [...this.sessionBytes].reduce((m, x) => (x < m ? x : m));
          const n = this.sessionBytes.size;
          this.host.edits.recordSession(this.session, `Edit ${n} byte${n === 1 ? "" : "s"} at 0x${hex(first)}`, resp.seqs);
        }
      } catch (e) {
        toast(`Edit bytes: ${errText(e)}`, { kind: "error" });
      }
      if (rev) await this.host.settle(rev);
      // Drop the bytes written (unless typed over again since).
      for (const [a, v] of written) if (this.pending.get(a) === v) this.pending.delete(a);
      this.stale = true;
      await this.load();
    });
    return this.writing;
  }

  /** The selected bytes (or the cursor's), as written: for Copy Special. */
  selectedRange(): [bigint, bigint] | null {
    if (this.selection) return this.selection;
    return this.cursor === null ? null : [this.cursor, this.cursor];
  }

  private onCopy(e: ClipboardEvent) {
    const r = this.selectedRange();
    if (!r || !e.clipboardData) return;
    const out: string[] = [];
    for (let a = r[0]; a <= r[1] && out.length < 65536; a++) {
      const b = this.byteAt(a);
      if (!b) break;
      out.push(b.v.toString(16).padStart(2, "0"));
    }
    e.clipboardData.setData("text/plain", out.join(" "));
    e.preventDefault();
  }

  // ----------------------------------------------------------- render --

  private int(bytes: number[]): string {
    const ordered = this.host.bigEndian ? bytes : [...bytes].reverse();
    let v = 0n;
    for (const b of ordered) v = (v << 8n) | BigInt(b);
    const bits = BigInt(8 * bytes.length);
    if (v >> (bits - 1n)) v -= 1n << bits;
    return v.toString();
  }

  render() {
    if (this.bplMode === "auto") {
      const n = this.fittingBpl();
      if (n !== this.bpl) this.applyBpl(n);
    }
    const lines = this.viewLines();
    const sel = this.selection;
    const unit = this.cursor !== null ? this.runAt(this.cursor) : null;
    const uStart = unit?.start?.offset ?? -1n;
    const uEnd = unit ? uStart + BigInt(unit.length) : -1n;
    const frag = document.createDocumentFragment();
    for (const line of lines) {
      const row = h("div", { class: "bv-line", role: "row", "data-line": hex(line) });
      row.append(h("span", { class: "bv-addr" }, fmtAddr(line, this.host.addrWidth)));
      const bytes: ({ a: bigint; v: number; kind: number; orig?: number; pending: boolean } | null)[] = [];
      for (let i = 0; i < this.bpl; i++) {
        const a = line + BigInt(i);
        const b = this.blockAt(a) ? this.byteAt(a) : null;
        const p = this.pending.get(a);
        bytes.push(b ? { a, v: p ?? b.v, kind: b.kind, orig: b.orig, pending: p !== undefined } : null);
      }
      const cell = (b: (typeof bytes)[number], text: string, col: string, extra = "") => {
        if (!b) return h("span", { class: `bv-b bv-none ${extra}` }, text.replace(/./g, " "));
        let cls = `bv-b ${KIND_CLASS[b.kind] ?? ""} ${extra}`;
        if (b.orig !== undefined) cls += " patched";
        if (b.pending) cls += " pending";
        if (sel && b.a >= sel[0] && b.a <= sel[1]) cls += " sel";
        if (b.a >= uStart && b.a < uEnd) cls += " unit";
        if (b.a === this.cursor) cls += this.editing && col === this.editCol ? " cur edit" : " cur";
        const title = `${fmtAddr(b.a)} · ${KIND_NAME[b.kind] ?? "?"}${b.orig !== undefined ? ` · patched (was ${b.orig.toString(16).padStart(2, "0")})` : ""}`;
        return h("span", { class: cls, "data-a": hex(b.a), "data-col": col, title }, text);
      };
      if (this.columns.has("hex")) {
        const area = h("span", { class: "bv-col bv-hex" });
        bytes.forEach((b, i) => {
          if (i && i % this.group === 0) area.append(" ");
          const t = b && b.kind !== ByteKind.UNINITIALIZED ? b.v.toString(16).padStart(2, "0") : b ? "??" : "  ";
          area.append(cell(b, t, "hex"));
        });
        row.append(area);
      }
      if (this.columns.has("octal")) {
        const area = h("span", { class: "bv-col bv-oct" });
        bytes.forEach((b, i) => {
          if (i) area.append(" ");
          area.append(cell(b, b && b.kind !== ByteKind.UNINITIALIZED ? b.v.toString(8).padStart(3, "0") : "???", "octal"));
        });
        row.append(area);
      }
      if (this.columns.has("binary")) {
        const area = h("span", { class: "bv-col bv-bin" });
        bytes.forEach((b, i) => {
          if (i) area.append(" ");
          area.append(cell(b, b && b.kind !== ByteKind.UNINITIALIZED ? b.v.toString(2).padStart(8, "0") : "????????", "binary"));
        });
        row.append(area);
      }
      if (this.columns.has("int")) {
        const area = h("span", { class: "bv-col bv-int" });
        const w = this.group === 1 ? 4 : this.group === 2 ? 6 : this.group === 4 ? 11 : 20;
        for (let i = 0; i < this.bpl; i += this.group) {
          const g = bytes.slice(i, i + this.group);
          const known = g.every((b) => b && b.kind !== ByteKind.UNINITIALIZED);
          const t = known ? this.int(g.map((b) => b!.v)) : g.some((b) => b) ? "?" : "";
          area.append(cell(g.find((b) => b) ?? null, t.padStart(w), "int"), " ");
        }
        row.append(area);
      }
      if (this.columns.has("ascii")) {
        const area = h("span", { class: "bv-col bv-ascii" });
        for (const b of bytes) area.append(cell(b, b && b.kind !== ByteKind.UNINITIALIZED && b.v >= 0x20 && b.v < 0x7f ? String.fromCharCode(b.v) : b ? "." : " ", "ascii"));
        row.append(area);
      }
      if (this.columns.has("utf16")) {
        const area = h("span", { class: "bv-col bv-utf16" });
        for (let i = 0; i + 1 < this.bpl; i += 2) {
          const [x, y] = [bytes[i], bytes[i + 1]];
          let t = " ";
          if (x && y && x.kind !== ByteKind.UNINITIALIZED) {
            const c = this.host.bigEndian ? (x.v << 8) | y.v : (y.v << 8) | x.v;
            t = c >= 0x20 && c !== 0x7f && !(c >= 0xd800 && c < 0xe000) ? String.fromCharCode(c) : ".";
          } else if (x) t = ".";
          area.append(cell(x, t, "utf16"));
        }
        row.append(area);
      }
      frag.append(row);
    }
    this.body.replaceChildren(frag);
    const c = this.cursor;
    const b = c !== null ? this.blockAt(c) : null;
    this.status.textContent =
      c === null
        ? ""
        : `${fmtAddr(c)}${b ? ` ${b.name}` : ""}${sel && sel[1] > sel[0] ? ` · ${(sel[1] - sel[0] + 1n).toLocaleString()} bytes selected` : ""}${this.editing ? ` · editing ${this.editCol === "hex" ? "hex" : "characters"} (Tab switches)` : ""}${this.pending.size ? ` · writing ${this.pending.size}` : ""}`;
  }

  focus() {
    this.body.focus({ preventScroll: true });
  }

  /** State for tests. */
  state() {
    return {
      cursor: this.cursor === null ? null : hex(this.cursor),
      selection: this.selection ? [hex(this.selection[0]), hex(this.selection[1])] : null,
      top: hex(this.top),
      bpl: this.bpl,
      bplMode: this.bplMode,
      group: this.group,
      columns: [...this.columns],
      editing: this.editing,
      editCol: this.editCol,
      pending: this.pending.size,
      lines: this.viewLines().map((l) => {
        const out = { address: hex(l), bytes: [] as string[], kinds: [] as string[], patched: [] as boolean[] };
        for (let i = 0; i < this.bpl; i++) {
          const a = l + BigInt(i);
          const b = this.blockAt(a) ? this.byteAt(a) : null;
          out.bytes.push(b ? b.v.toString(16).padStart(2, "0") : "");
          out.kinds.push(b ? (KIND_NAME[b.kind] ?? "") : "");
          out.patched.push(b?.orig !== undefined);
        }
        return out;
      }),
      // Each line's columns, as drawn.
      text: [...this.body.querySelectorAll(".bv-line")].map((l) => [...l.children].map((c) => c.textContent).join("  ")).join("\n"),
    };
  }
}
