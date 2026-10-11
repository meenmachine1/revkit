// Control-flow graph of one function: its basic blocks with their
// instructions (GetFunctionGraph), laid out with ELK's layered algorithm,
// drawn on a canvas with pan and zoom. Edges are colored by kind
// (fallthrough, conditional taken / not taken, unconditional, switch).
//
// Drawing is culled to the viewport and switches level of detail with the
// zoom: below about 6 px per line, blocks are drawn as boxes with one bar
// per instruction instead of text, so a 2,000-block function stays at
// frame rate when it is zoomed out to fit.
//
// Selection is linked: clicking an instruction selects it in the listing
// (and so the decompiler); selecting elsewhere highlights the instruction
// here. Double-clicking a call follows it.
//
// Switch edges are labelled with their cases, from the decompiler's case
// labels (setDecompiled). A minimap (m) shows the whole function and the
// viewport; click or drag it to move there. Blocks collapse to their first
// instruction (c), and a block groups with the blocks it dominates, such as
// a loop or an if's arm, into one node (Shift+C, again to expand); the
// right-click menu has both. Analyzer plugins' facts are shown at the end
// of their instructions (setAnnotations).

import { CodeTokenKind, FlowEdgeKind, type DecompiledFunction, type GetFunctionGraphResponse, type Revkit } from "@revkit/api";
import { errText, hex, fmtAddr } from "../data/format";
import { toRow } from "../data/listingSource";
import { Flow, type ListingRow } from "../data/types";
import { C, palette, tokenColor } from "../listing/layout";
import type { Theme } from "../listing/theme";
import { h, prefs } from "../ui/dom";
import { showMenu, type MenuItem } from "../ui/menu";
import { layout, type Placed } from "./elk";

const PAD = 6;
const LINE_H = 16;
const FONT_PX = 12;
const MIN_SCALE = 0.02;
const MAX_SCALE = 3;

interface Run {
  col: number;
  text: string;
  color: C;
}

interface Line {
  runs: Run[];
  /** Instruction address (null for the block's label line). */
  address: bigint | null;
  row: ListingRow | null;
}

interface Block {
  index: number;
  x: number;
  y: number;
  w: number;
  h: number;
  start: bigint;
  lines: Line[];
  exit: boolean;
  entry: boolean;
  /** The server's blocks it shows (one, or a group's). */
  members: number[];
  group: boolean;
  collapsed: boolean;
}

interface Edge {
  from: number;
  to: number;
  kind: FlowEdgeKind;
  pts: { x: number; y: number }[];
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
  back: boolean;
  /** A switch edge's cases ("case 1, 4", "default"). */
  label: string;
}

/** A block as the daemon returned it. */
interface RawBlock {
  start: bigint;
  end: bigint;
  rows: ListingRow[];
  exit: boolean;
  entry: boolean;
}

interface RawEdge {
  from: number;
  to: number;
  kind: FlowEdgeKind;
}

const MINIMAP_W = 200;
const MINIMAP_H = 150;
/** Lines a collapsed block keeps (label, first instruction). */
const COLLAPSED_LINES = 1;

export interface GraphStats {
  blocks: number;
  edges: number;
  instructions: number;
  layoutMs: number;
  fetchMs: number;
}

export interface FrameSample {
  renderMs: number;
}

export class CfgView {
  readonly root: HTMLElement;
  readonly canvas: HTMLCanvasElement;
  private title: HTMLElement;
  private info: HTMLElement;
  private msg: HTMLElement;
  private ctx: CanvasRenderingContext2D;
  private pal: string[];
  private dpr = 1;
  private cssW = 0;
  private cssH = 0;
  private charW = 7.2;

  entry: bigint | null = null;
  /** The function whose blocks are shown (entry is the one asked for). */
  private shownEntry: bigint | null = null;
  private loadSeq = 0;
  private blocks: Block[] = [];
  private edges: Edge[] = [];
  private byAddr = new Map<bigint, { block: number; line: number }>();
  private structure = "";
  private placed: Placed | null = null;
  stats: GraphStats | null = null;
  /** The function as fetched, before collapsing and grouping. */
  private raw: { entry: bigint; blocks: RawBlock[]; edges: RawEdge[]; truncated: boolean; fetchMs: number } | null = null;
  /** Collapsed blocks and groups (by block start: they survive a refetch). */
  private collapsed = new Set<bigint>();
  private groups = new Map<bigint, Set<bigint>>();
  private buildSeq = 0;
  /** Case labels by the address of the code they select (setDecompiled). */
  private cases = new Map<bigint, string[]>();
  private casesFor: bigint | null = null;
  /** Plugin facts by instruction address (setAnnotations). */
  private notes: ReadonlyMap<bigint, string> = new Map();
  private minimap: HTMLCanvasElement;
  private mctx: CanvasRenderingContext2D;
  private mapBtn: HTMLButtonElement;
  showMinimap = prefs.get("rk.graph.minimap") !== "0";

  // world -> screen: screen = world * s + t
  private s = 1;
  private tx = 0;
  private ty = 0;
  private fitted = false;

  selected: bigint | null = null;
  /** The emulator's program counter: its line is marked. */
  pc: bigint | null = null;
  private hoverBlock = -1;
  sync: Set<bigint> | null = null;
  private rafId = 0;
  private drag: { x: number; y: number; tx: number; ty: number; moved: boolean } | null = null;
  /** Called with each frame's render time (the benchmark). */
  onFrame: ((s: FrameSample) => void) | null = null;
  onSelect: ((address: bigint) => void) | null = null;
  onFollow: ((address: bigint) => void) | null = null;
  onLoaded: (() => void) | null = null;

  constructor(
    root: HTMLElement,
    private rk: Revkit,
    private programId: string,
    private addrWidth: number,
    private theme: Theme,
    private font: string,
  ) {
    this.root = root;
    this.title = h("span", { class: "graph-title mono" });
    this.info = h("span", { class: "dim graph-info", "data-testid": "graph-info" });
    const btn = (label: string, title: string, run: () => void) => h("button", { class: "btn small", title, onclick: run }, label);
    this.canvas = h("canvas", { class: "graph-canvas", tabindex: "0", "aria-label": "Function graph", "data-testid": "graph-canvas" });
    this.msg = h("div", { class: "graph-msg dim" }, "Select a function to see its graph.");
    this.minimap = h("canvas", { class: "graph-minimap", width: MINIMAP_W, height: MINIMAP_H, "aria-label": "Minimap: click to move there", "data-testid": "graph-minimap", role: "img" });
    this.mapBtn = btn("Map", "Show or hide the minimap (m)", () => this.toggleMinimap()) as HTMLButtonElement;
    this.mapBtn.setAttribute("aria-pressed", String(this.showMinimap));
    this.mapBtn.dataset.testid = "graph-map";
    root.append(
      h(
        "div",
        { class: "panel-head view-head" },
        h("span", { class: "panel-title" }, "Graph"),
        this.title,
        h("span", { class: "spacer" }),
        this.info,
        btn("Expand all", "Expand collapsed blocks and groups (Shift+E)", () => this.expandAll()),
        this.mapBtn,
        btn("Fit", "Fit the whole function (0)", () => this.fit()),
        btn("1:1", "Actual size (1)", () => this.zoomTo(1)),
      ),
      h("div", { class: "graph-wrap" }, this.canvas, this.minimap, this.msg),
    );
    this.minimap.hidden = !this.showMinimap;
    this.mctx = this.minimap.getContext("2d")!;
    this.attachMinimap();
    this.ctx = this.canvas.getContext("2d", { alpha: false })!;
    this.pal = palette(theme);
    new ResizeObserver(() => this.resize()).observe(this.canvas);
    this.attach();
  }

  setTheme(t: Theme) {
    this.theme = t;
    this.pal = palette(t);
    this.invalidate();
  }

  get blockCount() {
    return this.blocks.length;
  }

  /** Shows the graph of the function at `entry` (reloads it with `force`). */
  async load(entry: bigint, force = false): Promise<void> {
    if (!force && entry === this.entry && this.blocks.length) return;
    const seq = ++this.loadSeq;
    const same = entry === this.entry;
    this.entry = entry;
    if (!same) {
      this.blocks = [];
      this.edges = [];
      this.byAddr.clear();
      this.structure = "";
      this.fitted = false;
      this.message("Loading the function's blocks…");
    }
    const t0 = performance.now();
    let r: GetFunctionGraphResponse;
    try {
      r = await this.rk.queries.getFunctionGraph({ programId: this.programId, function: { offset: entry }, omitBytes: true });
    } catch (e) {
      if (seq === this.loadSeq) this.message(`No graph: ${errText(e)}`);
      return;
    }
    if (seq !== this.loadSeq) return;
    const fetchMs = performance.now() - t0;
    const rev = r.snapshot?.revision ?? 0n;
    this.title.textContent = r.function?.name ?? fmtAddr(entry);
    this.title.title = `${r.function?.name ?? ""} at ${fmtAddr(entry)}`;
    if (!same) {
      this.collapsed.clear();
      this.groups.clear();
    }
    this.raw = {
      entry,
      blocks: r.blocks.map((b, i) => ({
        start: b.range?.first?.offset ?? 0n,
        end: b.range?.last?.offset ?? b.range?.first?.offset ?? 0n,
        rows: b.rows.map((x) => toRow(x, rev, this.addrWidth)),
        exit: b.exit,
        entry: i === r.entryBlock,
      })),
      edges: r.edges.map((e) => ({ from: e.fromBlock, to: e.toBlock, kind: e.kind })),
      truncated: r.truncated,
      fetchMs,
    };
    await this.rebuild();
  }

  /** Lays out what is shown: the fetched blocks with collapsing and grouping applied. */
  private async rebuild(folding = false) {
    const raw = this.raw;
    if (!raw) return;
    const seq = ++this.buildSeq;
    this.measure();
    // Which shown block each fetched block is in.
    const groupOf = new Map<bigint, bigint>();
    for (const [head, members] of this.groups) for (const m of members) groupOf.set(m, head);
    const owner: number[] = [];
    const blocks: Block[] = [];
    const nodeOf = new Map<bigint, number>();
    raw.blocks.forEach((rb, i) => {
      const head = groupOf.get(rb.start);
      if (head !== undefined && nodeOf.has(head)) {
        owner[i] = nodeOf.get(head)!;
        blocks[owner[i]].members.push(i);
        return;
      }
      const index = blocks.length;
      owner[i] = index;
      if (head !== undefined) nodeOf.set(head, index);
      blocks.push({ index, x: 0, y: 0, w: 0, h: 0, start: head ?? rb.start, lines: [], exit: false, entry: false, members: [i], group: head !== undefined, collapsed: false });
    });
    for (const b of blocks) {
      const members = b.members.map((i) => raw.blocks[i]);
      const head = members.find((m) => m.start === b.start) ?? members[0];
      b.exit = members.some((m) => m.exit);
      b.entry = members.some((m) => m.entry);
      const lines: Line[] = [];
      const total = members.reduce((k, m) => k + m.rows.length, 0);
      if (b.group) {
        const n = total;
        const last = members.reduce((m, x) => (x.end > m ? x.end : m), head.end);
        lines.push({ runs: [{ col: 0, text: `⊞ ${members.length} blocks · ${n} instructions · ${fmtAddr(head.start)}–${fmtAddr(last)}`, color: C.Header }], address: null, row: null });
      }
      const first = head.rows[0];
      if (first?.label) lines.push({ runs: [{ col: 0, text: first.label + ":", color: first.functionEntry ? C.Header : C.Label }], address: null, row: null });
      const keep = b.group ? 2 : this.collapsed.has(b.start) ? COLLAPSED_LINES : Infinity;
      b.collapsed = !b.group && this.collapsed.has(b.start);
      for (const row of head.rows.slice(0, keep)) lines.push({ runs: this.runs(row), address: row.address, row });
      const hidden = b.group ? total - Math.min(keep, head.rows.length) : head.rows.length - Math.min(keep, head.rows.length);
      if (hidden > 0) lines.push({ runs: [{ col: 0, text: `  ⋯ ${hidden} more instruction${hidden === 1 ? "" : "s"} (${b.group ? "Shift+C" : "c"} expands)`, color: C.Comment }], address: null, row: null });
      b.lines = lines;
      const cols = Math.max(12, ...lines.map((l) => l.runs.reduce((m, x) => Math.max(m, x.col + x.text.length), 0)));
      b.w = Math.ceil(cols * this.charW + 2 * PAD);
      b.h = lines.length * LINE_H + 2 * PAD;
    }
    // Edges between shown blocks; a group's inner edges disappear.
    const seen = new Map<string, { from: number; to: number; kind: FlowEdgeKind; labels: string[] }>();
    for (const e of raw.edges) {
      const from = owner[e.from], to = owner[e.to];
      if (from === to && e.from !== e.to) continue;
      const key = `${from}-${to}-${e.kind}`;
      let x = seen.get(key);
      if (!x) seen.set(key, (x = { from, to, kind: e.kind, labels: [] }));
      if (e.kind === FlowEdgeKind.SWITCH) x.labels.push(...this.casesIn(raw.blocks[e.to]));
    }
    const shown = [...seen.values()];
    const structure = blocks.map((b) => `${b.start}:${b.w}x${b.h}`).join(",") + "|" + shown.map((e) => `${e.from}-${e.to}-${e.kind}`).join(",");
    let placed = this.placed;
    let layoutMs = this.stats?.layoutMs ?? 0;
    if (structure !== this.structure || !placed) {
      if (blocks.length > 1) this.message(blocks.length > 300 ? `Laying out ${blocks.length.toLocaleString()} blocks…` : "");
      try {
        placed = await layout(
          blocks.map((b) => ({ id: `b${b.index}`, width: b.w, height: b.h })),
          shown.map((e, i) => ({ id: `e${i}`, from: `b${e.from}`, to: `b${e.to}` })),
        );
      } catch (e) {
        if (seq === this.buildSeq) this.message(`Layout failed: ${errText(e)}`);
        return;
      }
      if (seq !== this.buildSeq || raw !== this.raw) return;
      layoutMs = placed.ms;
    }
    for (const b of blocks) {
      const p = placed.nodes.get(`b${b.index}`)!;
      b.x = p.x;
      b.y = p.y;
    }
    const edges: Edge[] = shown.map((e, i) => {
      const pts = placed!.edges.get(`e${i}`) ?? [];
      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
      for (const p of pts) {
        minX = Math.min(minX, p.x);
        minY = Math.min(minY, p.y);
        maxX = Math.max(maxX, p.x);
        maxY = Math.max(maxY, p.y);
      }
      return { from: e.from, to: e.to, kind: e.kind, pts, minX, minY, maxX, maxY, back: blocks[e.to].start <= blocks[e.from].start, label: caseText(e.labels) };
    });
    this.blocks = blocks;
    this.edges = edges;
    this.placed = placed;
    this.structure = structure;
    this.shownEntry = raw.entry;
    this.byAddr.clear();
    for (const b of blocks) {
      b.lines.forEach((l, j) => l.address !== null && this.byAddr.set(l.address, { block: b.index, line: j }));
      // Hidden instructions select their block's first line.
      for (const i of b.members) for (const row of raw.blocks[i].rows) if (!this.byAddr.has(row.address)) this.byAddr.set(row.address, { block: b.index, line: 0 });
    }
    const n = raw.blocks.reduce((m, b) => m + b.rows.length, 0);
    this.stats = { blocks: raw.blocks.length, edges: raw.edges.length, instructions: n, layoutMs, fetchMs: raw.fetchMs };
    const folded = blocks.filter((b) => b.group || b.collapsed).length;
    this.info.textContent = `${raw.blocks.length.toLocaleString()} blocks · ${raw.edges.length.toLocaleString()} edges${folded ? ` · ${folded} folded` : ""}${raw.truncated ? " · truncated" : ""}`;
    this.info.title = `fetch ${raw.fetchMs.toFixed(0)} ms · layout ${layoutMs.toFixed(0)} ms`;
    this.message(blocks.length ? "" : "No instructions.");
    if (!this.fitted) {
      this.fitted = true;
      if (this.selected !== null && this.byAddr.has(this.selected)) this.reveal(this.selected, true);
      else this.showEntry();
    } else if (folding && this.selected !== null) this.reveal(this.selected, false);
    this.root.dataset.blocks = String(raw.blocks.length);
    this.root.dataset.shown = String(blocks.length);
    this.invalidate();
    this.onLoaded?.();
  }

  /** Drops the graph (the function is gone, or another program). */
  clear(text = "Select a function to see its graph.") {
    this.loadSeq++;
    this.buildSeq++;
    this.raw = null;
    this.entry = null;
    this.shownEntry = null;
    this.blocks = [];
    this.edges = [];
    this.byAddr.clear();
    this.structure = "";
    this.title.textContent = "";
    this.info.textContent = "";
    delete this.root.dataset.blocks;
    this.message(text);
    this.invalidate();
  }

  private message(text: string) {
    this.msg.textContent = text;
    this.msg.hidden = !text;
  }

  private runs(r: ListingRow): Run[] {
    const out: Run[] = [{ col: 0, text: r.addrText.replace(/^0+(?=.{6})/, ""), color: C.Addr }];
    const m = Math.max(8, out[0].text.length + 2);
    out.push({ col: m, text: r.mnemonic, color: r.isFlow ? C.FlowMnemonic : C.Mnemonic });
    const ops = m + Math.max(7, r.mnemonic.length + 1);
    let end = ops;
    for (const o of r.operands) {
      if (o.text) out.push({ col: ops + o.col, text: o.text, color: tokenColor(o.kind) });
      end = Math.max(end, ops + o.col + o.text.length);
    }
    if (r.comment) {
      out.push({ col: end + 2, text: r.comment.length > 48 ? r.comment.slice(0, 47) + "…" : r.comment, color: C.Comment });
      end += 2 + Math.min(48, r.comment.length);
    }
    const note = this.notes.get(r.address);
    if (note) out.push({ col: end + 2, text: note.length > 60 ? note.slice(0, 59) + "…" : note, color: C.AgentName });
    return out;
  }

  // ------------------------------------------------- labels, annotations --

  /**
   * The decompiled function, for the switch edges' case labels: Ghidra
   * prints each case label with the address of the code it selects.
   */
  setDecompiled(fn: DecompiledFunction | null) {
    const entry = fn?.entry?.offset ?? null;
    const cases = new Map<bigint, string[]>();
    if (fn) {
      for (const line of fn.lines) {
        const toks = line.tokens.filter((t) => t.kind !== CodeTokenKind.WHITESPACE && t.text.trim());
        toks.forEach((t, i) => {
          if (t.kind !== CodeTokenKind.CONSTANT || !t.address) return;
          const prev = toks[i - 1];
          const label = t.text === "default" ? "default" : prev?.kind === CodeTokenKind.KEYWORD && prev.text === "case" ? t.text : null;
          if (label === null) return;
          const a = t.address.offset;
          const list = cases.get(a) ?? [];
          if (!list.includes(label)) list.push(label);
          cases.set(a, list);
        });
      }
    }
    const key = (m: Map<bigint, string[]>) => [...m].map(([a, l]) => `${a}:${l.join(",")}`).join(";");
    if (entry === this.casesFor && key(cases) === key(this.cases)) return;
    this.cases = cases;
    this.casesFor = entry;
    if (this.raw && entry === this.raw.entry) void this.rebuild();
  }

  /** The cases that select code in a block (setDecompiled), in order. */
  private casesIn(b: RawBlock): string[] {
    if (this.casesFor !== this.raw?.entry) return [];
    const out: string[] = [];
    for (const [a, labels] of this.cases) if (a >= b.start && a <= b.end) out.push(...labels);
    return out;
  }

  /** Analyzer plugins' facts by instruction address, drawn after the instructions. */
  setAnnotations(notes: ReadonlyMap<bigint, string>) {
    const raw = this.raw;
    const changed = (m: ReadonlyMap<bigint, string>) => {
      if (!raw) return false;
      for (const b of raw.blocks) for (const r of b.rows) if (m.get(r.address) !== this.notes.get(r.address)) return true;
      return false;
    };
    const differs = changed(notes);
    this.notes = notes;
    if (differs) void this.rebuild();
  }

  /** Plugin facts shown on the graph's instructions (tests). */
  annotations(): { address: string; text: string }[] {
    const out: { address: string; text: string }[] = [];
    for (const b of this.blocks) for (const l of b.lines) if (l.address !== null && l.row && this.notes.has(l.address)) out.push({ address: hex(l.address), text: this.notes.get(l.address)! });
    return out;
  }

  // ------------------------------------------------- collapse and group --

  /** Collapses the block at `start` to its first instruction, or expands it. */
  toggleCollapse(start: bigint) {
    if (this.collapsed.has(start)) this.collapsed.delete(start);
    else this.collapsed.add(start);
    void this.rebuild(true);
  }

  /**
   * Groups the block at `start` with every block it dominates (reached
   * only through it: a loop, an if's arm, the rest of the function), or
   * ungroups the group it heads.
   */
  toggleGroup(start: bigint) {
    if (this.groups.delete(start)) return void this.rebuild(true);
    const raw = this.raw;
    if (!raw) return;
    const at = raw.blocks.findIndex((b) => b.start === start);
    if (at < 0) return;
    const dom = dominated(raw.blocks.length, raw.blocks.findIndex((b) => b.entry), raw.edges, at);
    if (dom.size < 2) return;
    const members = new Set([...dom].map((i) => raw.blocks[i].start));
    // Groups inside it fold into it.
    for (const [head, m] of [...this.groups]) if (members.has(head)) {
      for (const x of m) members.add(x);
      this.groups.delete(head);
    }
    this.groups.set(start, members);
    void this.rebuild(true);
  }

  /** The selected block: collapse or expand it (`c`), or group it (`Shift+C`). */
  foldSelected(group: boolean) {
    const b = this.selectedBlock();
    if (!b) return;
    if (b.group || group) this.toggleGroup(b.start);
    else this.toggleCollapse(b.start);
  }

  expandAll() {
    if (!this.collapsed.size && !this.groups.size) return;
    this.collapsed.clear();
    this.groups.clear();
    void this.rebuild(true);
  }

  /** Shown blocks (tests): their starts, folding and edge labels. */
  shown() {
    return {
      blocks: this.blocks.map((b) => ({
        start: hex(b.start),
        group: b.group,
        collapsed: b.collapsed,
        members: b.members.length,
        lines: b.lines.length,
        first: b.lines.find((l) => l.row)?.row?.mnemonic ?? "",
        last: [...b.lines].reverse().find((l) => l.row)?.row?.mnemonic ?? "",
      })),
      minimap: !this.minimap.hidden,
      view: { s: this.s, tx: this.tx, ty: this.ty },
      labels: this.edges.filter((e) => e.label).map((e) => ({ from: hex(this.blocks[e.from].start), to: hex(this.blocks[e.to].start), label: e.label })),
    };
  }

  /** The block menu: collapse, group, expand. */
  private blockMenu(b: Block, x: number, y: number) {
    const items: MenuItem[] = b.group
      ? [{ label: "Expand group", keys: "Shift+C", run: () => this.toggleGroup(b.start) }]
      : [
          { label: b.collapsed ? "Expand block" : "Collapse block", keys: "c", run: () => this.toggleCollapse(b.start) },
          { label: "Group with the blocks it dominates", keys: "Shift+C", disabled: b.entry && this.blocks.length < 2, run: () => this.toggleGroup(b.start) },
        ];
    items.push({ label: "Expand all", keys: "Shift+E", disabled: !this.collapsed.size && !this.groups.size, run: () => this.expandAll() });
    showMenu(items, x, y, `Block ${fmtAddr(b.start)}`);
  }

  /** The shown block holding the selection. */
  private selectedBlock(): Block | null {
    const at = this.selected !== null ? this.byAddr.get(this.selected) : undefined;
    return at ? this.blocks[at.block] : null;
  }

  // -------------------------------------------------------------- minimap --

  toggleMinimap() {
    this.showMinimap = !this.showMinimap;
    prefs.set("rk.graph.minimap", this.showMinimap ? "1" : "0");
    this.minimap.hidden = !this.showMinimap;
    this.mapBtn.setAttribute("aria-pressed", String(this.showMinimap));
    this.invalidate();
  }

  /** World <-> minimap: the whole graph fitted in the minimap. */
  private mapScale() {
    const p = this.placed;
    if (!p || !p.width || !p.height) return null;
    const k = Math.min((MINIMAP_W - 8) / p.width, (MINIMAP_H - 8) / p.height);
    return { k, ox: (MINIMAP_W - p.width * k) / 2, oy: (MINIMAP_H - p.height * k) / 2 };
  }

  private attachMinimap() {
    const m = this.minimap;
    const go = (e: PointerEvent) => {
      const ms = this.mapScale();
      if (!ms) return;
      const r = m.getBoundingClientRect();
      // The minimap may be drawn smaller than its canvas (a narrow view).
      const fx = MINIMAP_W / (r.width || MINIMAP_W), fy = MINIMAP_H / (r.height || MINIMAP_H);
      const wx = ((e.clientX - r.left) * fx - ms.ox) / ms.k, wy = ((e.clientY - r.top) * fy - ms.oy) / ms.k;
      this.tx = this.cssW / 2 - wx * this.s;
      this.ty = this.cssH / 2 - wy * this.s;
      this.invalidate();
    };
    m.addEventListener("pointerdown", (e) => {
      e.preventDefault();
      m.setPointerCapture(e.pointerId);
      go(e);
      const move = (x: PointerEvent) => go(x);
      const up = () => {
        m.removeEventListener("pointermove", move);
        m.removeEventListener("pointerup", up);
      };
      m.addEventListener("pointermove", move);
      m.addEventListener("pointerup", up);
    });
  }

  private renderMinimap() {
    // Not needed while the whole function is in view.
    const p = this.placed;
    const all = !!p && this.tx >= 0 && this.ty >= 0 && p.width * this.s + this.tx <= this.cssW && p.height * this.s + this.ty <= this.cssH;
    const show = this.showMinimap && this.blocks.length > 1 && !all;
    this.minimap.hidden = !show;
    if (!show) return;
    const ms = this.mapScale();
    if (!ms) return;
    const mdpr = window.devicePixelRatio || 1;
    if (this.minimap.width !== MINIMAP_W * mdpr) {
      this.minimap.width = MINIMAP_W * mdpr;
      this.minimap.height = MINIMAP_H * mdpr;
    }
    const c = this.mctx, th = this.theme;
    c.setTransform(mdpr, 0, 0, mdpr, 0, 0);
    c.fillStyle = th.headerBg;
    c.fillRect(0, 0, MINIMAP_W, MINIMAP_H);
    const sel = this.selected !== null ? this.byAddr.get(this.selected)?.block : undefined;
    c.fillStyle = th.punct;
    c.globalAlpha = 0.55;
    for (const b of this.blocks) if (b.index !== sel) c.fillRect(ms.ox + b.x * ms.k, ms.oy + b.y * ms.k, Math.max(1, b.w * ms.k), Math.max(1, b.h * ms.k));
    c.globalAlpha = 1;
    if (sel !== undefined) {
      const b = this.blocks[sel];
      c.fillStyle = th.mnemonic;
      c.fillRect(ms.ox + b.x * ms.k, ms.oy + b.y * ms.k, Math.max(2, b.w * ms.k), Math.max(2, b.h * ms.k));
    }
    // The viewport.
    const vx = (-this.tx / this.s) * ms.k + ms.ox, vy = (-this.ty / this.s) * ms.k + ms.oy;
    c.strokeStyle = th.arrowSel;
    c.lineWidth = 1.5;
    c.strokeRect(vx, vy, (this.cssW / this.s) * ms.k, (this.cssH / this.s) * ms.k);
  }

  // ------------------------------------------------------------ selection --

  /** Highlights the instruction at `address` (from the listing or the decompiler); scrolls to it unless it's in view. */
  select(address: bigint | null, reveal = true) {
    this.selected = address;
    if (address !== null && reveal && this.byAddr.has(address)) this.reveal(address, false);
    this.invalidate();
  }

  has(address: bigint) {
    return this.byAddr.has(address);
  }

  private reveal(address: bigint, center: boolean) {
    const at = this.byAddr.get(address);
    if (!at) return;
    const b = this.blocks[at.block];
    const y = b.y + PAD + at.line * LINE_H;
    const sx = b.x * this.s + this.tx, sy = y * this.s + this.ty;
    const visible = sx >= 0 && sx + Math.min(b.w * this.s, this.cssW) <= this.cssW && sy >= 0 && sy + LINE_H * this.s <= this.cssH;
    if (visible && !center) return;
    if (this.s < 0.5) this.s = 0.9;
    this.tx = this.cssW / 2 - (b.x + b.w / 2) * this.s;
    this.ty = this.cssH / 3 - y * this.s;
  }

  private showEntry() {
    const e = this.blocks.find((b) => b.entry) ?? this.blocks[0];
    if (!e) return;
    this.s = 0.9;
    this.tx = this.cssW / 2 - (e.x + e.w / 2) * this.s;
    this.ty = 20 - e.y * this.s;
  }

  fit() {
    if (!this.placed || !this.blocks.length) return;
    const w = this.placed.width + 40, hh = this.placed.height + 40;
    this.s = Math.max(MIN_SCALE, Math.min(1.2, this.cssW / w, this.cssH / hh));
    this.tx = (this.cssW - this.placed.width * this.s) / 2;
    this.ty = Math.max(10, (this.cssH - this.placed.height * this.s) / 2);
    this.invalidate();
  }

  zoomTo(scale: number, cx = this.cssW / 2, cy = this.cssH / 2) {
    const s = Math.max(MIN_SCALE, Math.min(MAX_SCALE, scale));
    // Keep the world point under (cx, cy) in place.
    this.tx = cx - ((cx - this.tx) / this.s) * s;
    this.ty = cy - ((cy - this.ty) / this.s) * s;
    this.s = s;
    this.invalidate();
  }

  panBy(dx: number, dy: number) {
    this.tx += dx;
    this.ty += dy;
    this.invalidate();
  }

  get scale() {
    return this.s;
  }

  // ---------------------------------------------------------------- input --

  private attach() {
    const c = this.canvas;
    c.addEventListener(
      "wheel",
      (e) => {
        e.preventDefault();
        const r = c.getBoundingClientRect();
        if (e.ctrlKey || e.metaKey || !e.shiftKey) {
          // Wheel zooms around the pointer (pinch is ctrl+wheel).
          const k = Math.exp(-e.deltaY * (e.deltaMode === 1 ? 0.05 : 0.0015));
          this.zoomTo(this.s * k, e.clientX - r.left, e.clientY - r.top);
        } else this.panBy(-e.deltaX, -e.deltaY);
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
      if (d) {
        if (Math.abs(e.clientX - d.x) + Math.abs(e.clientY - d.y) > 3) d.moved = true;
        if (d.moved) {
          this.tx = d.tx + e.clientX - d.x;
          this.ty = d.ty + e.clientY - d.y;
          this.invalidate();
        }
        return;
      }
      const hit = this.hit(e);
      const b = hit?.block ?? -1;
      c.style.cursor = hit?.line !== undefined && hit.line >= 0 ? "pointer" : "grab";
      if (b !== this.hoverBlock) {
        this.hoverBlock = b;
        this.invalidate();
      }
    });
    c.addEventListener("pointerup", (e) => {
      const d = this.drag;
      this.drag = null;
      if (!d || d.moved) return;
      const hit = this.hit(e);
      const line = hit ? this.blocks[hit.block].lines[hit.line] : undefined;
      if (line?.address != null) {
        this.selected = line.address;
        this.invalidate();
        this.onSelect?.(line.address);
      } else if (hit && hit.line >= 0 && line && (this.blocks[hit.block].group || this.blocks[hit.block].collapsed) && line.runs[0]?.text.trimStart().startsWith(this.blocks[hit.block].group && hit.line === 0 ? "⊞" : "⋯")) {
        // The group's header or the "more instructions" line expands it.
        const b = this.blocks[hit.block];
        if (b.group) this.toggleGroup(b.start);
        else this.toggleCollapse(b.start);
      }
    });
    c.addEventListener("dblclick", (e) => {
      const hit = this.hit(e);
      const line = hit ? this.blocks[hit.block].lines[hit.line] : undefined;
      const row = line?.row;
      if (!row) return;
      const target = row.flowTargets[0];
      if (target === undefined) return;
      if (row.flow === Flow.Call || row.flow === Flow.IndirectCall || !this.byAddr.has(target)) this.onFollow?.(target);
      else {
        this.selected = target;
        this.reveal(target, true);
        this.invalidate();
        this.onSelect?.(target);
      }
    });
    c.addEventListener("keydown", (e) => this.onKey(e));
    c.addEventListener("contextmenu", (e) => {
      const hit = this.hit(e);
      if (!hit) return;
      e.preventDefault();
      const line = this.blocks[hit.block].lines[hit.line];
      if (line?.address != null) {
        this.selected = line.address;
        this.invalidate();
        this.onSelect?.(line.address);
      }
      this.blockMenu(this.blocks[hit.block], e.clientX, e.clientY);
    });
  }

  private onKey(e: KeyboardEvent) {
    const step = 60;
    let handled = true;
    switch (e.key) {
      case "0":
        this.fit();
        break;
      case "1":
        this.zoomTo(1);
        break;
      case "+":
      case "=":
        this.zoomTo(this.s * 1.25);
        break;
      case "-":
        this.zoomTo(this.s / 1.25);
        break;
      case "ArrowLeft":
        this.panBy(step, 0);
        break;
      case "ArrowRight":
        this.panBy(-step, 0);
        break;
      case "ArrowUp":
        if (e.altKey) return;
        this.panBy(0, step);
        break;
      case "ArrowDown":
        this.panBy(0, -step);
        break;
      case "m":
        this.toggleMinimap();
        break;
      case "c":
      case "C":
        if (!this.selectedBlock()) return;
        this.foldSelected(e.shiftKey);
        break;
      case "E":
        this.expandAll();
        break;
      case "Enter": {
        const at = this.selected !== null ? this.byAddr.get(this.selected) : undefined;
        const row = at ? this.blocks[at.block].lines[at.line].row : null;
        if (row?.flowTargets[0] !== undefined) this.onFollow?.(row.flowTargets[0]);
        break;
      }
      default:
        handled = false;
    }
    if (handled) {
      e.preventDefault();
      e.stopPropagation();
    }
  }

  private hit(e: MouseEvent): { block: number; line: number } | null {
    const r = this.canvas.getBoundingClientRect();
    const wx = (e.clientX - r.left - this.tx) / this.s;
    const wy = (e.clientY - r.top - this.ty) / this.s;
    for (const b of this.blocks)
      if (wx >= b.x && wx <= b.x + b.w && wy >= b.y && wy <= b.y + b.h) {
        const line = Math.floor((wy - b.y - PAD) / LINE_H);
        return { block: b.index, line: line >= 0 && line < b.lines.length ? line : -1 };
      }
    return null;
  }

  /** Screen position of an instruction (tests). */
  pointOf(address: bigint): { x: number; y: number } | null {
    const at = this.byAddr.get(address);
    if (!at) return null;
    const b = this.blocks[at.block];
    const r = this.canvas.getBoundingClientRect();
    return { x: r.left + (b.x + PAD + 4 * this.charW) * this.s + this.tx, y: r.top + (b.y + PAD + (at.line + 0.5) * LINE_H) * this.s + this.ty };
  }

  /** Blocks and edges as loaded (tests). */
  describe() {
    return {
      entry: this.shownEntry === null ? null : hex(this.shownEntry),
      blocks: this.blocks.map((b) => ({ start: hex(b.start), lines: b.lines.length, exit: b.exit, entry: b.entry })),
      edges: this.edges.map((e) => ({ from: e.from, to: e.to, kind: e.kind })),
      selected: this.selected === null ? null : hex(this.selected),
      scale: this.s,
      stats: this.stats,
    };
  }

  // -------------------------------------------------------------- drawing --

  private measure() {
    this.ctx.font = `${FONT_PX}px ${this.font}`;
    this.charW = this.ctx.measureText("0123456789").width / 10;
  }

  resize() {
    const r = this.canvas.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return;
    const firstSize = this.cssW === 0;
    this.dpr = window.devicePixelRatio || 1;
    this.cssW = r.width;
    this.cssH = r.height;
    const w = Math.round(r.width * this.dpr), hh = Math.round(r.height * this.dpr);
    if (this.canvas.width !== w || this.canvas.height !== hh) {
      this.canvas.width = w;
      this.canvas.height = hh;
    }
    if (firstSize && this.blocks.length) this.showEntry();
    this.invalidate();
  }

  invalidate() {
    if (!this.rafId) this.rafId = requestAnimationFrame(() => this.render());
  }

  render() {
    this.rafId = 0;
    if (!this.cssW || this.canvas.offsetParent === null) return;
    const t0 = performance.now();
    const { ctx, s, tx, ty } = this;
    const th = this.theme;
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    ctx.fillStyle = th.bg;
    ctx.fillRect(0, 0, this.cssW, this.cssH);
    if (!this.blocks.length) return;
    // The viewport in world coordinates.
    const x0 = -tx / s, y0 = -ty / s, x1 = (this.cssW - tx) / s, y1 = (this.cssH - ty) / s;
    ctx.setTransform(this.dpr * s, 0, 0, this.dpr * s, this.dpr * tx, this.dpr * ty);

    // Edges, one path per color.
    const colors: Record<number, string> = {
      [FlowEdgeKind.FALL_THROUGH]: th.arrow,
      [FlowEdgeKind.UNCONDITIONAL]: th.mnemonic,
      [FlowEdgeKind.CONDITIONAL_TRUE]: "#3fb950",
      [FlowEdgeKind.CONDITIONAL_FALSE]: "#f85149",
      [FlowEdgeKind.SWITCH]: th.register,
    };
    ctx.lineWidth = Math.max(1, 1.4 / s);
    ctx.lineJoin = "round";
    const sel = this.selected !== null ? this.byAddr.get(this.selected)?.block : undefined;
    const arrow = Math.min(9, 7 / Math.max(s, 0.35));
    for (const kind of [FlowEdgeKind.FALL_THROUGH, FlowEdgeKind.UNCONDITIONAL, FlowEdgeKind.CONDITIONAL_TRUE, FlowEdgeKind.CONDITIONAL_FALSE, FlowEdgeKind.SWITCH]) {
      ctx.strokeStyle = colors[kind];
      ctx.fillStyle = colors[kind];
      ctx.beginPath();
      const heads: Edge[] = [];
      for (const e of this.edges) {
        if (e.kind !== kind || e.pts.length < 2) continue;
        if (e.maxX < x0 || e.minX > x1 || e.maxY < y0 || e.minY > y1) continue;
        ctx.moveTo(e.pts[0].x, e.pts[0].y);
        for (let i = 1; i < e.pts.length; i++) ctx.lineTo(e.pts[i].x, e.pts[i].y);
        heads.push(e);
      }
      ctx.stroke();
      ctx.beginPath();
      for (const e of heads) {
        const p = e.pts[e.pts.length - 1], q = e.pts[e.pts.length - 2];
        const dx = p.x - q.x, dy = p.y - q.y, len = Math.hypot(dx, dy) || 1;
        const ux = dx / len, uy = dy / len;
        ctx.moveTo(p.x, p.y);
        ctx.lineTo(p.x - ux * arrow - uy * arrow * 0.5, p.y - uy * arrow + ux * arrow * 0.5);
        ctx.lineTo(p.x - ux * arrow + uy * arrow * 0.5, p.y - uy * arrow - ux * arrow * 0.5);
        ctx.closePath();
      }
      ctx.fill();
    }
    // Edges of the selected block, on top and thicker.
    if (sel !== undefined) {
      ctx.lineWidth = Math.max(2, 2.6 / s);
      for (const e of this.edges) {
        if ((e.from !== sel && e.to !== sel) || e.pts.length < 2) continue;
        ctx.strokeStyle = colors[e.kind];
        ctx.beginPath();
        ctx.moveTo(e.pts[0].x, e.pts[0].y);
        for (let i = 1; i < e.pts.length; i++) ctx.lineTo(e.pts[i].x, e.pts[i].y);
        ctx.stroke();
      }
    }

    // Switch cases, at the end of their edges (readable sizes only).
    if (s * LINE_H >= 6) {
      ctx.font = `${FONT_PX - 1}px ${this.font}`;
      ctx.textBaseline = "bottom";
      for (const e of this.edges) {
        if (!e.label || e.pts.length < 2) continue;
        if (e.maxX < x0 || e.minX > x1 || e.maxY < y0 || e.minY > y1) continue;
        const p = e.pts[e.pts.length - 1];
        const w = ctx.measureText(e.label).width;
        const lx = p.x + 3, ly = p.y - arrow - 1;
        ctx.fillStyle = th.bg;
        ctx.globalAlpha = 0.85;
        ctx.fillRect(lx - 1, ly - LINE_H + 3, w + 2, LINE_H - 3);
        ctx.globalAlpha = 1;
        ctx.fillStyle = colors[FlowEdgeKind.SWITCH];
        ctx.fillText(e.label, lx, ly);
      }
    }

    // Blocks.
    const text = s * LINE_H >= 6;
    const visible: Block[] = [];
    for (const b of this.blocks) if (!(b.x + b.w < x0 || b.x > x1 || b.y + b.h < y0 || b.y > y1)) visible.push(b);
    ctx.fillStyle = th.headerBg;
    ctx.beginPath();
    for (const b of visible) ctx.rect(b.x, b.y, b.w, b.h);
    ctx.fill();
    ctx.lineWidth = Math.max(1, 1 / s);
    ctx.strokeStyle = th.entryRule;
    ctx.stroke();
    for (const b of visible) {
      if (b.lines.some((l) => l.row?.patched) && b.index !== sel) {
        // A block with patched instructions (PatchService).
        ctx.strokeStyle = th.patchMark;
        ctx.lineWidth = Math.max(1.5, 1.5 / s);
        ctx.strokeRect(b.x, b.y, b.w, b.h);
      }
      if (b.entry || b.exit || b.index === this.hoverBlock || b.index === sel) {
        ctx.strokeStyle = b.index === sel ? th.mnemonic : b.entry ? "#3fb950" : b.exit ? "#f85149" : th.arrow;
        ctx.lineWidth = Math.max(1.5, (b.index === sel ? 2.2 : 1.5) / s);
        ctx.strokeRect(b.x, b.y, b.w, b.h);
      }
    }
    if (!text) {
      // Far out: a bar per line.
      ctx.fillStyle = th.punct;
      ctx.globalAlpha = 0.45;
      ctx.beginPath();
      for (const b of visible)
        for (let i = 0; i < b.lines.length; i++) {
          const len = b.lines[i].runs.reduce((m, r) => Math.max(m, r.col + r.text.length), 0);
          ctx.rect(b.x + PAD, b.y + PAD + i * LINE_H + 4, Math.min(b.w - 2 * PAD, len * this.charW), LINE_H - 8);
        }
      ctx.fill();
      ctx.globalAlpha = 1;
    } else {
      ctx.font = `${FONT_PX}px ${this.font}`;
      ctx.textBaseline = "middle";
      for (const b of visible) {
        const ly0 = Math.max(0, Math.floor((y0 - b.y - PAD) / LINE_H));
        const ly1 = Math.min(b.lines.length, Math.ceil((y1 - b.y - PAD) / LINE_H));
        for (let i = ly0; i < ly1; i++) {
          const line = b.lines[i];
          const y = b.y + PAD + i * LINE_H;
          if (line.address !== null && (line.address === this.selected || this.sync?.has(line.address))) {
            ctx.fillStyle = line.address === this.selected ? th.selRow : th.syncRow;
            ctx.fillRect(b.x + 1, y, b.w - 2, LINE_H);
          }
          if (line.row?.patched) {
            ctx.fillStyle = th.patchedRow;
            ctx.fillRect(b.x + 1, y, b.w - 2, LINE_H);
            ctx.fillStyle = th.patchMark;
            ctx.fillRect(b.x + b.w - 4, y, 3, LINE_H);
          }
          if (line.address !== null && line.address === this.pc) {
            ctx.fillStyle = "rgba(63, 185, 80, 0.22)";
            ctx.fillRect(b.x + 1, y, b.w - 2, LINE_H);
            ctx.fillStyle = "#3fb950";
            ctx.fillRect(b.x + 1, y, 3, LINE_H);
          }
          for (const r of line.runs) {
            ctx.fillStyle = this.pal[r.color];
            ctx.fillText(r.text, b.x + PAD + r.col * this.charW, y + LINE_H / 2);
          }
        }
      }
    }
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    this.renderMinimap();
    this.onFrame?.({ renderMs: performance.now() - t0 });
  }
}

/** A switch edge's label: its cases, a few of them. */
function caseText(labels: string[]): string {
  if (!labels.length) return "";
  const def = labels.includes("default");
  const cases = labels.filter((l) => l !== "default");
  const shown = cases.slice(0, 4).join(", ") + (cases.length > 4 ? ` +${cases.length - 4}` : "");
  return [cases.length ? `case ${shown}` : "", def ? "default" : ""].filter(Boolean).join(" · ");
}

/**
 * The blocks `head` dominates (every path from the entry to them passes
 * through it), itself included: Cooper, Harvey and Kennedy's iterative
 * dominators over a reverse postorder. Unreachable blocks are left out.
 */
export function dominated(n: number, entry: number, edges: { from: number; to: number }[], head: number): Set<number> {
  const succ: number[][] = Array.from({ length: n }, () => []);
  const pred: number[][] = Array.from({ length: n }, () => []);
  for (const e of edges) {
    succ[e.from].push(e.to);
    pred[e.to].push(e.from);
  }
  const start = entry >= 0 ? entry : 0;
  const order: number[] = [];
  const seen = new Uint8Array(n);
  // Iterative DFS postorder.
  const stack: [number, number][] = [[start, 0]];
  seen[start] = 1;
  while (stack.length) {
    const top = stack[stack.length - 1];
    const [v, i] = top;
    if (i < succ[v].length) {
      top[1]++;
      const w = succ[v][i];
      if (!seen[w]) {
        seen[w] = 1;
        stack.push([w, 0]);
      }
    } else {
      order.push(v);
      stack.pop();
    }
  }
  const rpo = order.reverse();
  const num = new Int32Array(n).fill(-1);
  rpo.forEach((v, i) => (num[v] = i));
  const idom = new Int32Array(n).fill(-1);
  idom[start] = start;
  const intersect = (a: number, b: number) => {
    while (a !== b) {
      while (num[a] > num[b]) a = idom[a];
      while (num[b] > num[a]) b = idom[b];
    }
    return a;
  };
  for (let changed = true; changed; ) {
    changed = false;
    for (const v of rpo) {
      if (v === start) continue;
      let d = -1;
      for (const p of pred[v]) if (idom[p] >= 0) d = d < 0 ? p : intersect(p, d);
      if (d >= 0 && idom[v] !== d) {
        idom[v] = d;
        changed = true;
      }
    }
  }
  const out = new Set<number>();
  if (num[head] < 0) return out;
  for (const v of rpo) {
    for (let x = v; ; x = idom[x]) {
      if (x === head) {
        out.add(v);
        break;
      }
      if (x === start || idom[x] < 0) break;
    }
  }
  return out;
}

