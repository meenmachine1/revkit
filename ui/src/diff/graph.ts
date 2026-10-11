// Graph diff: both functions' control-flow graphs, coloured by what
// changed (docs/ui.md "Graph diff"). Blocks come from DiffDetail (each
// side's blocks, their successors and the one-to-one block map).
//
// Primary mode, side by side: one ELK layout of the union of both graphs
// (a matched pair of blocks is one node, sized to hold either side; a block
// only in A or only in B a node of its own), drawn twice: A's canvas shows
// the nodes and edges A has, B's those B has. Matched blocks are therefore
// at exactly the same place on both sides, and what one side lacks leaves
// a hole where the other has code; pan and zoom are shared. Unchanged
// blocks are neutral, modified ones amber, added green, removed red; edges
// both sides have are neutral, A's alone red, B's alone green.
//
// Merged mode: the same union as one graph, each node tagged A, B or A+B,
// a modified pair showing its lines interleaved (removed red, added
// green). Compact, but a node no longer reads as either program's code,
// which is why it isn't the default.
//
// Drawing is culled to the viewport, with a level of detail below about
// 6 px per line (a bar per instruction), as the function graph does: a
// 2,000-block function stays at frame rate.

import { DiffBlockStatus, DiffLineStatus, type DiffDetail, type DiffRow } from "@revkit/api";
import { errText, hex } from "../data/format";
import type { Theme } from "../listing/theme";
import { h } from "../ui/dom";
import { layout, type Placed } from "../graph/elk";
import { blockClass, type PairDetail } from "./detail";

const PAD = 6;
const LINE_H = 16;
const FONT_PX = 12;
const MIN_SCALE = 0.02;
const MAX_SCALE = 3;

type Status = "same" | "mod" | "add" | "del";
type LineKind = "eq" | "chg" | "ins" | "del" | "moved" | "head";

export const DIFF_COLORS: Record<Status, string> = { same: "#8b949e", mod: "#d29922", add: "#3fb950", del: "#f85149" };

interface GLine {
  text: string;
  kind: LineKind;
}

interface GNode {
  id: string;
  /** Block index on each side, or -1. */
  a: number;
  b: number;
  status: Status;
  linesA: GLine[];
  linesB: GLine[];
  merged: GLine[];
  /** Size for the side-by-side layout and for the merged one. */
  w: number;
  h: number;
  mw: number;
  mh: number;
  // Placed (current mode).
  x: number;
  y: number;
}

interface GEdge {
  from: number;
  to: number;
  inA: boolean;
  inB: boolean;
  pts: { x: number; y: number }[];
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
}

type Side = "a" | "b" | "m";

export class DiffGraphView {
  readonly el: HTMLElement;
  private canvases: Record<Side, HTMLCanvasElement>;
  private wraps: Record<Side, HTMLElement>;
  private msg: HTMLElement;
  private info: HTMLElement;
  private modeBtn: HTMLButtonElement;
  private pd: PairDetail | null = null;
  private nodes: GNode[] = [];
  private edges: GEdge[] = [];
  private byBlockA = new Map<number, number>();
  private byBlockB = new Map<number, number>();
  private placed: { split: Placed | null; merged: Placed | null } = { split: null, merged: null };
  private width = 0;
  private height = 0;
  merged = false;
  private seq = 0;
  private s = 1;
  private tx = 0;
  private ty = 0;
  private dpr = 1;
  private size: Record<Side, { w: number; h: number }> = { a: { w: 0, h: 0 }, b: { w: 0, h: 0 }, m: { w: 0, h: 0 } };
  private charW = 7.2;
  private selected = -1;
  /** Panned or zoomed by hand: resizing no longer refits. */
  private moved = false;
  private raf = 0;
  private drag: { x: number; y: number; tx: number; ty: number; moved: boolean } | null = null;
  layoutMs = 0;
  /** A block was clicked: its side and index on that side (and its partner's). */
  onSelectBlock: ((side: "a" | "b", block: number) => void) | null = null;
  onFrame: ((ms: number) => void) | null = null;

  constructor(
    private theme: Theme,
    private font: string,
    title = "Graph diff",
  ) {
    const mk = (side: Side) => {
      const c = h("canvas", { class: "graph-canvas", tabindex: "0", "aria-label": `Graph diff ${side.toUpperCase()}`, "data-testid": `diffgraph-canvas-${side}` });
      return c;
    };
    this.canvases = { a: mk("a"), b: mk("b"), m: mk("m") };
    this.wraps = {
      a: h("div", { class: "dg-pane" }, h("span", { class: "dg-label" }, "A"), this.canvases.a),
      b: h("div", { class: "dg-pane" }, h("span", { class: "dg-label" }, "B"), this.canvases.b),
      m: h("div", { class: "dg-pane", hidden: true }, h("span", { class: "dg-label" }, "A + B"), this.canvases.m),
    };
    this.msg = h("div", { class: "graph-msg dim" }, "Select a match to see both graphs.");
    this.info = h("span", { class: "dim graph-info", "data-testid": "diffgraph-info" });
    this.modeBtn = h("button", { class: "btn small", title: "Side by side, or one merged graph (m)", "data-testid": "diffgraph-mode", onclick: () => this.setMerged(!this.merged) }, "Merged");
    const btn = (label: string, t: string, run: () => void) => h("button", { class: "btn small", title: t, onclick: run }, label);
    const legend = h(
      "span",
      { class: "dg-legend dim" },
      ...(["same", "mod", "add", "del"] as Status[]).map((s) => h("span", { class: `dg-key dg-${s}` }, { same: "unchanged", mod: "modified", add: "added", del: "removed" }[s])),
    );
    this.el = h(
      "div",
      { class: "dg", "data-testid": "diffgraph" },
      h("div", { class: "dg-head" }, h("span", { class: "dg-title" }, title), legend, h("span", { class: "spacer" }), this.info, this.modeBtn, btn("Fit", "Fit both graphs (0)", () => this.fit()), btn("1:1", "Actual size (1)", () => this.zoomTo(1))),
      h("div", { class: "dg-panes" }, this.wraps.a, this.wraps.b, this.wraps.m, this.msg),
    );
    for (const side of ["a", "b", "m"] as Side[]) {
      new ResizeObserver(() => this.resize()).observe(this.canvases[side]);
      this.attach(side);
    }
  }

  setTheme(t: Theme) {
    this.theme = t;
    this.invalidate();
  }

  /** Shows a pair (null: nothing). Lays out once per pair and mode. */
  async set(pd: PairDetail | null, message = "") {
    const seq = ++this.seq;
    this.pd = pd;
    this.nodes = [];
    this.edges = [];
    this.selected = -1;
    this.moved = false;
    this.layoutMs = 0;
    this.placed = { split: null, merged: null };
    this.info.textContent = "";
    if (!pd) {
      this.message(message || "Select a match to see both graphs.");
      this.invalidate();
      return;
    }
    this.build(pd.detail);
    this.message(this.nodes.length > 300 ? `Laying out ${this.nodes.length.toLocaleString()} blocks…` : "");
    await this.relayout(seq);
    if (seq === this.seq) this.fit();
  }

  setMerged(on: boolean) {
    if (on === this.merged) return;
    this.merged = on;
    this.modeBtn.classList.toggle("on", on);
    this.wraps.a.hidden = on;
    this.wraps.b.hidden = on;
    this.wraps.m.hidden = !on;
    this.el.dataset.mode = on ? "merged" : "split";
    if (this.pd) void this.relayout(this.seq).then(() => this.fit());
  }

  private message(text: string) {
    this.msg.textContent = text;
    this.msg.hidden = !text;
  }

  // ------------------------------------------------------------ the model --

  private measure() {
    const ctx = this.canvases.a.getContext("2d")!;
    ctx.font = `${FONT_PX}px ${this.font}`;
    this.charW = ctx.measureText("0123456789").width / 10 || 7.2;
  }

  private build(d: DiffDetail) {
    this.measure();
    const kindOf = (r: DiffRow): LineKind =>
      r.moved ? "moved" : r.status === DiffLineStatus.CHANGED ? "chg" : r.status === DiffLineStatus.INSERTED ? "ins" : r.status === DiffLineStatus.DELETED ? "del" : "eq";
    const text = (r: DiffRow) => `${hex(r.address?.offset ?? 0n).replace(/^0+(?=.{6})/, "")}  ${r.text}`;
    const lines = (rows: DiffRow[], first: number, n: number) => rows.slice(first, first + n).map((r) => ({ text: text(r), kind: kindOf(r) }));
    const ofBlockA = new Map<number, number>(), ofBlockB = new Map<number, number>();
    d.blocksA.forEach((bl, x) => {
      for (let r = bl.firstRow; r < bl.firstRow + bl.rows; r++) ofBlockA.set(r, x);
    });
    d.blocksB.forEach((bl, y) => {
      for (let r = bl.firstRow; r < bl.firstRow + bl.rows; r++) ofBlockB.set(r, y);
    });
    const status = (s: DiffBlockStatus): Status => blockClass(s);
    // Merged mode's lines of each pair of blocks (by A's block), in one pass
    // over the aligned lines.
    const mutual = (x: number) => {
      const y = d.blocksA[x]?.partner ?? -1;
      return y >= 0 && d.blocksB[y]?.partner === x ? y : -1;
    };
    const mergedOf = new Map<number, GLine[]>();
    const push = (x: number, l: GLine) => {
      let v = mergedOf.get(x);
      if (!v) mergedOf.set(x, (v = []));
      v.push(l);
    };
    for (const l of d.lines) {
      const ba = l.a >= 0 ? ofBlockA.get(l.a) : undefined, bb = l.b >= 0 ? ofBlockB.get(l.b) : undefined;
      const pa = ba !== undefined && mutual(ba) >= 0 ? ba : undefined;
      const pb = bb !== undefined && d.blocksB[bb].partner >= 0 && mutual(d.blocksB[bb].partner) === bb ? d.blocksB[bb].partner : undefined;
      if (pa !== undefined && pa === pb && d.rowsA[l.a].status === DiffLineStatus.EQUAL && !d.rowsA[l.a].moved) {
        push(pa, { text: "  " + text(d.rowsA[l.a]), kind: "eq" });
        continue;
      }
      if (pa !== undefined) push(pa, { text: "\u2212 " + text(d.rowsA[l.a]), kind: d.rowsA[l.a].status === DiffLineStatus.CHANGED ? "chg" : kindOf(d.rowsA[l.a]) === "eq" ? "moved" : "del" });
      if (pb !== undefined) push(pb, { text: "+ " + text(d.rowsB[l.b]), kind: d.rowsB[l.b].status === DiffLineStatus.CHANGED ? "chg" : kindOf(d.rowsB[l.b]) === "eq" ? "moved" : "ins" });
    }
    const nodes: GNode[] = [];
    this.byBlockA.clear();
    this.byBlockB.clear();
    const add = (a: number, b: number) => {
      const bla = a >= 0 ? d.blocksA[a] : null, blb = b >= 0 ? d.blocksB[b] : null;
      const st: Status = bla && blb ? (status(bla.status) === "same" && status(blb.status) === "same" ? "same" : "mod") : bla ? status(bla.status) : status(blb!.status);
      const head = (s: string): GLine => ({ text: s, kind: "head" });
      const addrOf = (bl: { range?: { first?: { offset: bigint } } } | null) => (bl ? hex(bl.range?.first?.offset ?? 0n) : "");
      const linesA = bla ? [head(addrOf(bla)), ...lines(d.rowsA, bla.firstRow, bla.rows)] : [];
      const linesB = blb ? [head(addrOf(blb)), ...lines(d.rowsB, blb.firstRow, blb.rows)] : [];
      // Merged: interleaved along the aligned lines.
      const merged: GLine[] = [head(`${bla && blb ? "A+B" : bla ? "A" : "B"}  ${addrOf(bla)}${bla && blb && addrOf(bla) !== addrOf(blb) ? " / " + addrOf(blb) : addrOf(blb) && !bla ? addrOf(blb) : ""}`)];
      if (bla && blb) {
        merged.push(...(mergedOf.get(a) ?? []));
      } else merged.push(...(bla ? linesA : linesB).slice(1));
      const dims = (ls: GLine[]) => [Math.ceil(Math.max(14, ...ls.map((l) => l.text.length)) * this.charW + 2 * PAD), ls.length * LINE_H + 2 * PAD];
      const [wa, ha] = dims(linesA.length ? linesA : [head("")]);
      const [wb, hb] = dims(linesB.length ? linesB : [head("")]);
      const [mw, mh] = dims(merged);
      const i = nodes.length;
      nodes.push({ id: `n${i}`, a, b, status: st, linesA, linesB, merged, w: Math.max(wa, wb), h: Math.max(ha, hb), mw, mh, x: 0, y: 0 });
      if (a >= 0) this.byBlockA.set(a, i);
      if (b >= 0) this.byBlockB.set(b, i);
    };
    d.blocksA.forEach((bl, x) => {
      const y = bl.partner;
      add(x, y >= 0 && d.blocksB[y]?.partner === x ? y : -1);
    });
    d.blocksB.forEach((_, y) => {
      if (!this.byBlockB.has(y)) add(-1, y);
    });
    const edges = new Map<string, GEdge>();
    const edge = (from: number, to: number, side: "a" | "b") => {
      const k = `${from}-${to}`;
      let e = edges.get(k);
      if (!e) edges.set(k, (e = { from, to, inA: false, inB: false, pts: [], minX: 0, minY: 0, maxX: 0, maxY: 0 }));
      if (side === "a") e.inA = true;
      else e.inB = true;
    };
    d.blocksA.forEach((bl, x) => bl.successors.forEach((s) => edge(this.byBlockA.get(x)!, this.byBlockA.get(s)!, "a")));
    d.blocksB.forEach((bl, y) => bl.successors.forEach((s) => edge(this.byBlockB.get(y)!, this.byBlockB.get(s)!, "b")));
    this.nodes = nodes;
    this.edges = [...edges.values()].filter((e) => e.from !== undefined && e.to !== undefined);
    const n = { same: 0, mod: 0, add: 0, del: 0 };
    for (const x of nodes) n[x.status]++;
    this.info.textContent = `${n.same} unchanged · ${n.mod} modified · ${n.add} added · ${n.del} removed`;
  }

  private async relayout(seq: number) {
    const which = this.merged ? "merged" : "split";
    let placed = this.placed[which];
    if (!placed) {
      try {
        placed = await layout(
          this.nodes.map((n) => ({ id: n.id, width: this.merged ? n.mw : n.w, height: this.merged ? n.mh : n.h })),
          this.edges.map((e, i) => ({ id: `e${i}`, from: this.nodes[e.from].id, to: this.nodes[e.to].id })),
        );
      } catch (e) {
        if (seq === this.seq) this.message(`Layout failed: ${errText(e)}`);
        return;
      }
      if (seq !== this.seq) return;
      this.placed[which] = placed;
      this.layoutMs = placed.ms;
    }
    for (const n of this.nodes) {
      const p = placed.nodes.get(n.id)!;
      n.x = p.x;
      n.y = p.y;
    }
    this.edges.forEach((e, i) => {
      e.pts = placed!.edges.get(`e${i}`) ?? [];
      e.minX = Math.min(...e.pts.map((p) => p.x));
      e.maxX = Math.max(...e.pts.map((p) => p.x));
      e.minY = Math.min(...e.pts.map((p) => p.y));
      e.maxY = Math.max(...e.pts.map((p) => p.y));
    });
    this.width = placed.width;
    this.height = placed.height;
    this.message(this.nodes.length ? "" : "No instructions.");
    this.el.dataset.blocks = String(this.nodes.length);
    this.invalidate();
  }

  // ------------------------------------------------------------ selection --

  /** Highlights the node holding a block of one side (from the listing), and brings it into view. */
  selectBlock(side: "a" | "b", block: number, reveal = true) {
    const i = (side === "a" ? this.byBlockA : this.byBlockB).get(block);
    if (i === undefined) return;
    this.selected = i;
    if (reveal) this.reveal(i);
    this.invalidate();
  }

  /** The block of a row (from the listing's selection). */
  selectRow(side: "a" | "b", row: number) {
    const d = this.pd?.detail;
    if (!d) return;
    const r = (side === "a" ? d.rowsA : d.rowsB)[row];
    if (r) this.selectBlock(side, r.block);
  }

  private reveal(i: number) {
    const n = this.nodes[i];
    const { w, h: hh } = this.size[this.merged ? "m" : "a"];
    if (!w) return;
    const nw = this.merged ? n.mw : n.w;
    const sx = n.x * this.s + this.tx, sy = n.y * this.s + this.ty;
    if (sx >= 0 && sy >= 0 && sx + nw * this.s <= w && sy + 40 <= hh) return;
    if (this.s < 0.4) this.s = 0.8;
    this.tx = w / 2 - (n.x + nw / 2) * this.s;
    this.ty = hh / 3 - n.y * this.s;
  }

  fit() {
    const { w, h: hh } = this.size[this.merged ? "m" : "a"];
    if (!this.nodes.length || !w) return;
    this.s = Math.max(MIN_SCALE, Math.min(1.2, w / (this.width + 40), hh / (this.height + 40)));
    this.tx = (w - this.width * this.s) / 2;
    this.ty = Math.max(10, (hh - this.height * this.s) / 2);
    this.invalidate();
  }

  zoomTo(scale: number, cx?: number, cy?: number) {
    this.moved = true;
    const { w, h: hh } = this.size[this.merged ? "m" : "a"];
    cx ??= w / 2;
    cy ??= hh / 2;
    const s = Math.max(MIN_SCALE, Math.min(MAX_SCALE, scale));
    this.tx = cx - ((cx - this.tx) / this.s) * s;
    this.ty = cy - ((cy - this.ty) / this.s) * s;
    this.s = s;
    this.invalidate();
  }

  panBy(dx: number, dy: number) {
    this.moved = true;
    this.tx += dx;
    this.ty += dy;
    this.invalidate();
  }

  get scale() {
    return this.s;
  }

  /** The canvas a mode draws on (A's in side by side). */
  get canvas(): HTMLCanvasElement {
    return this.canvases[this.merged ? "m" : "a"];
  }

  // ---------------------------------------------------------------- input --

  private attach(side: Side) {
    const c = this.canvases[side];
    c.addEventListener(
      "wheel",
      (e) => {
        e.preventDefault();
        const r = c.getBoundingClientRect();
        if (e.ctrlKey || e.metaKey || !e.shiftKey) this.zoomTo(this.s * Math.exp(-e.deltaY * (e.deltaMode === 1 ? 0.05 : 0.0015)), e.clientX - r.left, e.clientY - r.top);
        else {
          this.moved = true;
          this.tx -= e.deltaX;
          this.ty -= e.deltaY;
          this.invalidate();
        }
      },
      { passive: false },
    );
    c.addEventListener("pointerdown", (e) => {
      c.focus({ preventScroll: true });
      if (e.button !== 0) return;
      c.setPointerCapture(e.pointerId);
      this.drag = { x: e.clientX, y: e.clientY, tx: this.tx, ty: this.ty, moved: false };
    });
    c.addEventListener("pointermove", (e) => {
      const d = this.drag;
      if (!d) return;
      if (Math.abs(e.clientX - d.x) + Math.abs(e.clientY - d.y) > 3) d.moved = true;
      if (d.moved) {
        this.moved = true;
        this.tx = d.tx + e.clientX - d.x;
        this.ty = d.ty + e.clientY - d.y;
        this.invalidate();
      }
    });
    c.addEventListener("pointerup", (e) => {
      const d = this.drag;
      this.drag = null;
      if (!d || d.moved) return;
      const i = this.hit(side, e);
      if (i < 0) return;
      this.selected = i;
      this.invalidate();
      const n = this.nodes[i];
      const s: "a" | "b" = side === "b" || (side === "m" && n.a < 0) ? "b" : n.a >= 0 ? "a" : "b";
      this.onSelectBlock?.(s, s === "a" ? n.a : n.b);
    });
    c.addEventListener("keydown", (e) => {
      const step = 60;
      const k = e.key;
      if (k === "0") this.fit();
      else if (k === "1") this.zoomTo(1);
      else if (k === "+" || k === "=") this.zoomTo(this.s * 1.25);
      else if (k === "-") this.zoomTo(this.s / 1.25);
      else if (k === "m") this.setMerged(!this.merged);
      else if (k === "ArrowLeft") this.tx += step;
      else if (k === "ArrowRight") this.tx -= step;
      else if (k === "ArrowUp") this.ty += step;
      else if (k === "ArrowDown") this.ty -= step;
      else return;
      e.preventDefault();
      e.stopPropagation();
      this.invalidate();
    });
  }

  private present(side: Side, n: GNode) {
    return side === "m" || (side === "a" ? n.a >= 0 : n.b >= 0);
  }

  private hit(side: Side, e: MouseEvent): number {
    const r = this.canvases[side].getBoundingClientRect();
    const wx = (e.clientX - r.left - this.tx) / this.s, wy = (e.clientY - r.top - this.ty) / this.s;
    for (let i = 0; i < this.nodes.length; i++) {
      const n = this.nodes[i];
      if (!this.present(side, n)) continue;
      const w = side === "m" ? n.mw : n.w, hh = side === "m" ? n.mh : n.h;
      if (wx >= n.x && wx <= n.x + w && wy >= n.y && wy <= n.y + hh) return i;
    }
    return -1;
  }

  /** Nodes as drawn (tests): which blocks, the status, the colour, where. */
  describe() {
    return {
      mode: this.merged ? "merged" : "split",
      selected: this.selected,
      nodes: this.nodes.map((n) => ({ a: n.a, b: n.b, status: n.status, color: DIFF_COLORS[n.status] })),
      edges: this.edges.map((e) => ({ from: e.from, to: e.to, inA: e.inA, inB: e.inB })),
      layoutMs: this.layoutMs,
    };
  }

  /** A node's centre on a side's canvas, in client coordinates (tests). */
  pointOf(i: number, side: Side): { x: number; y: number } | null {
    const n = this.nodes[i];
    if (!n || !this.present(side, n)) return null;
    const r = this.canvases[side].getBoundingClientRect();
    const w = side === "m" ? n.mw : n.w;
    return { x: r.left + (n.x + Math.min(w / 2, 40)) * this.s + this.tx, y: r.top + (n.y + PAD + LINE_H * 0.5) * this.s + this.ty };
  }

  // -------------------------------------------------------------- drawing --

  resize() {
    this.dpr = window.devicePixelRatio || 1;
    let changed = false;
    for (const side of ["a", "b", "m"] as Side[]) {
      const c = this.canvases[side];
      const r = c.getBoundingClientRect();
      if (!r.width || !r.height) continue;
      if (this.size[side].w !== r.width || this.size[side].h !== r.height) changed = true;
      this.size[side] = { w: r.width, h: r.height };
      const w = Math.round(r.width * this.dpr), hh = Math.round(r.height * this.dpr);
      if (c.width !== w || c.height !== hh) {
        c.width = w;
        c.height = hh;
      }
    }
    if (changed && !this.moved && this.nodes.length) this.fit();
    this.invalidate();
  }

  invalidate() {
    if (!this.raf) this.raf = requestAnimationFrame(() => {
      this.raf = 0;
      const t0 = performance.now();
      if (this.merged) this.draw("m");
      else {
        this.draw("a");
        this.draw("b");
      }
      this.onFrame?.(performance.now() - t0);
    });
  }

  private draw(side: Side) {
    const c = this.canvases[side];
    const { w: cw, h: ch } = this.size[side];
    if (!cw || c.offsetParent === null) return;
    const ctx = c.getContext("2d", { alpha: false })!;
    const th = this.theme;
    const { s, tx, ty } = this;
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    ctx.fillStyle = th.bg;
    ctx.fillRect(0, 0, cw, ch);
    if (!this.nodes.length) return;
    const x0 = -tx / s, y0 = -ty / s, x1 = (cw - tx) / s, y1 = (ch - ty) / s;
    ctx.setTransform(this.dpr * s, 0, 0, this.dpr * s, this.dpr * tx, this.dpr * ty);
    const merged = side === "m";
    // Edges, one path per colour.
    const arrow = Math.min(9, 7 / Math.max(s, 0.35));
    ctx.lineWidth = Math.max(1, 1.4 / s);
    for (const [color, pick] of [
      [th.arrow, (e: GEdge) => e.inA && e.inB],
      [DIFF_COLORS.del, (e: GEdge) => e.inA && !e.inB],
      [DIFF_COLORS.add, (e: GEdge) => e.inB && !e.inA],
    ] as const) {
      const mine = this.edges.filter((e) => pick(e) && (merged || (side === "a" ? e.inA : e.inB)) && e.pts.length >= 2 && !(e.maxX < x0 || e.minX > x1 || e.maxY < y0 || e.minY > y1));
      ctx.strokeStyle = color;
      ctx.fillStyle = color;
      ctx.beginPath();
      for (const e of mine) {
        ctx.moveTo(e.pts[0].x, e.pts[0].y);
        for (let i = 1; i < e.pts.length; i++) ctx.lineTo(e.pts[i].x, e.pts[i].y);
      }
      ctx.stroke();
      ctx.beginPath();
      for (const e of mine) {
        const p = e.pts[e.pts.length - 1], q = e.pts[e.pts.length - 2];
        const dx = p.x - q.x, dy = p.y - q.y, len = Math.hypot(dx, dy) || 1, ux = dx / len, uy = dy / len;
        ctx.moveTo(p.x, p.y);
        ctx.lineTo(p.x - ux * arrow - uy * arrow * 0.5, p.y - uy * arrow + ux * arrow * 0.5);
        ctx.lineTo(p.x - ux * arrow + uy * arrow * 0.5, p.y - uy * arrow - ux * arrow * 0.5);
        ctx.closePath();
      }
      ctx.fill();
    }
    // Nodes.
    const text = s * LINE_H >= 6;
    ctx.font = `${FONT_PX}px ${this.font}`;
    ctx.textBaseline = "middle";
    for (let i = 0; i < this.nodes.length; i++) {
      const n = this.nodes[i];
      if (!this.present(side, n)) continue;
      const w = merged ? n.mw : n.w, hh = merged ? n.mh : n.h;
      if (n.x + w < x0 || n.x > x1 || n.y + hh < y0 || n.y > y1) continue;
      const color = DIFF_COLORS[n.status];
      ctx.fillStyle = th.headerBg;
      ctx.fillRect(n.x, n.y, w, hh);
      if (n.status !== "same") {
        ctx.globalAlpha = 0.16;
        ctx.fillStyle = color;
        ctx.fillRect(n.x, n.y, w, hh);
        ctx.globalAlpha = 1;
      }
      // The header line: a solid band of the status colour.
      ctx.fillStyle = n.status === "same" ? th.entryRule : color;
      ctx.fillRect(n.x, n.y, w, PAD + LINE_H);
      ctx.lineWidth = Math.max(1, (i === this.selected ? 3 : 1.4) / s);
      ctx.strokeStyle = i === this.selected ? th.mnemonic : n.status === "same" ? th.entryRule : color;
      ctx.strokeRect(n.x, n.y, w, hh);
      const lines = merged ? n.merged : side === "a" ? n.linesA : n.linesB;
      if (!text) {
        ctx.globalAlpha = 0.5;
        for (let k = 1; k < lines.length; k++) {
          const l = lines[k];
          ctx.fillStyle = l.kind === "eq" ? th.punct : l.kind === "chg" ? DIFF_COLORS.mod : l.kind === "ins" ? DIFF_COLORS.add : l.kind === "del" ? DIFF_COLORS.del : th.punct;
          ctx.fillRect(n.x + PAD, n.y + PAD + k * LINE_H + 4, Math.min(w - 2 * PAD, l.text.length * this.charW), LINE_H - 8);
        }
        ctx.globalAlpha = 1;
        continue;
      }
      for (let k = 0; k < lines.length; k++) {
        const l = lines[k];
        const y = n.y + PAD + k * LINE_H;
        if (y + LINE_H < y0 || y > y1) continue;
        if (l.kind === "chg" || l.kind === "ins" || l.kind === "del") {
          ctx.globalAlpha = 0.28;
          ctx.fillStyle = l.kind === "chg" ? DIFF_COLORS.mod : l.kind === "ins" ? DIFF_COLORS.add : DIFF_COLORS.del;
          ctx.fillRect(n.x + 1, y, w - 2, LINE_H);
          ctx.globalAlpha = 1;
        }
        ctx.fillStyle = l.kind === "head" ? (n.status === "same" ? th.fg : th.bg) : l.kind === "eq" ? th.punct : th.fg;
        ctx.fillText(l.text, n.x + PAD, y + LINE_H / 2);
      }
    }
    ctx.setTransform(1, 0, 0, 1, 0, 0);
  }
}
