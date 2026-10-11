// Canvas listing view: virtual scrolling over the whole program, custom
// scrollbar, wheel/trackpad/keyboard input, hover and selection highlighting.
//
// Scroll position is kept as a double in CSS pixels (millions of rows x 18 px
// is far beyond any browser's maximum element height, which is why there is
// no native scroll container here). Every frame derives the first visible
// row from it, asks the row cache for that range, and redraws the canvas.

import { Flow, RowKind, type ListingRow, type ListingSource } from "../data/types";
import type { RowCache } from "../data/rowCache";
import { layoutRow, palette, showsXrefs, type Columns, type HotSpan } from "./layout";
import type { Painter, PaintItem } from "./painters";
import type { Theme } from "./theme";

export interface FrameStats {
  /** JS time spent in render(), ms. */
  renderMs: number;
  visibleRows: number;
  /** Visible rows drawn as placeholders because data hadn't arrived. */
  blankRows: number;
  /** Rows whose text was rasterized this frame (painter cache misses). */
  rasterized: number;
  /** Drew an older, fully loaded position because the requested one wasn't loaded. */
  stale: boolean;
  /** How long ago the drawn position was requested (0 unless stale). */
  lagMs: number;
}

export interface ViewOptions {
  canvas: HTMLCanvasElement;
  cache: RowCache;
  source: ListingSource;
  painter: Painter;
  theme: Theme;
  columns: Columns;
  fontFamily?: string;
  fontSize?: number;
  rowHeight?: number;
}

export type Hit = HotSpan & { row: number; data: ListingRow };

/** Rows a single copy takes at most. */
const MAX_COPY_ROWS = 20000;
const SCROLLBAR_W = 12;
const THUMB_MIN = 28;
/** Flow arrow gutter, left of the text. */
/** Hits that select their row but highlight nothing else (markers, badges). */
const UNKEYED = new Set<string>(["xref", "comment", "disclosure", "mutability", "field", "pcode"]);

export const GUTTER = 44;
export const PAD_X = GUTTER + 10;
const LANE_W = 5;
const MAX_LANES = Math.floor((GUTTER - 10) / LANE_W);
/** Rows above and below the viewport searched for jumps into it. */
const ARROW_SCAN = 600;

/** A flow arrow in the gutter, in CSS px. */
export interface Arrow {
  /** Rows (absolute); a source or target out of view is clipped to the edge. */
  from: number;
  to: number;
  x: number;
  y0: number;
  y1: number;
  target: bigint;
  conditional: boolean;
  /** One end is out of view: clicking follows the jump. */
  offscreen: boolean;
}

const isJump = (r: ListingRow) =>
  r.kind === RowKind.Instruction && (r.flow === Flow.Branch || r.flow === Flow.CondBranch || r.flow === Flow.IndirectBranch) && r.flowTargets.length > 0;
const SMOOTH_TAU_MS = 60;

export class ListingView {
  readonly canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D;
  readonly cache: RowCache;
  private source: ListingSource;
  painter: Painter;
  private theme: Theme;
  private pal: string[];
  cols: Columns;

  private font: string;
  readonly rowH: number;
  private charW = 8;
  private baseline = 13;

  private dpr = 1;
  /** Render at this device pixel ratio instead of the window's (null = native). */
  dprOverride: number | null = null;
  private cssW = 0;
  private cssH = 0;

  /** Scroll offset in CSS px. */
  scrollY = 0;
  private targetY = 0;
  private lastDir = 0;

  hoverKey: string | null = null;
  selectedKey: string | null = null;
  selectedRow = -1;
  /** The other end of a multi-row selection (shift-click, drag,
   * shift-arrows); -1 when only the cursor row is selected. */
  anchorRow = -1;
  /** A left-button drag is extending the selection. */
  private selecting = false;
  /** Shown when copying rows that aren't loaded yet. */
  onNotice?: (text: string) => void;
  /** The token/label the selection was made on (rename and follow use it). */
  selectedHit: Hit | null = null;
  /** Instruction addresses the decompiler pane points at. */
  syncAddrs: Set<bigint> | null = null;
  /** Collaborators' cursors by address (a colored tag at the row's right). */
  cursors: Map<bigint, { name: string; color: string }[]> | null = null;
  /** Addresses with notes (a marker at the row's left edge). */
  noteAddrs: Set<bigint> | null = null;
  /** Search hits (a marker in the gutter), from the search results shown. */
  searchMarks: Set<bigint> | null = null;
  /** The decompiler's slice (feature decompile-slices): its instructions, tinted. */
  sliceMarks: Set<bigint> | null = null;
  /** A selection of several address ranges (inclusive, sorted, disjoint),
   * made from search results; the next click or key selection replaces it. */
  rangeSelection: [bigint, bigint][] | null = null;
  /** The emulator's program counter and breakpoints (gutter markers). */
  emuMarks: { pc: bigint | null; breakpoints: Set<bigint> } | null = null;
  /** A click in the gutter that isn't on a flow arrow (breakpoints). */
  onGutterClick: ((row: ListingRow) => void) | null = null;
  /** Right-click (or the context-menu key) on the rows: the app shows its actions there. */
  onContextMenu: ((clientX: number, clientY: number) => void) | null = null;
  private pointer: { x: number; y: number } | null = null;
  private hoverHit: Hit | null = null;

  private drag: { offsetY: number } | null = null;
  /** Last wheel input: hover badges stay quiet while content scrolls. */
  private lastWheel = 0;
  private rafId = 0;
  private lastFrameTs = 0;
  private jumpSeq = 0;

  /** Max time to keep showing the last loaded position instead of placeholders. */
  holdMs = 150;
  private recentWants: { y: number; at: number }[] = [];
  private prevWantFirst = -1;

  onFrame: ((s: FrameStats) => void) | null = null;
  /** The user moved the selection (click, keys). */
  onSelect: ((row: ListingRow, rowIndex: number) => void) | null = null;
  /** Follow a reference (double-click, Enter). */
  onFollow: ((target: bigint) => void) | null = null;
  /** Pointer over a hot span (or off one: null), for provenance badges. */
  onHover: ((hit: Hit | null, clientX: number, clientY: number) => void) | null = null;
  /** A data item's disclosure marker (+/−) was clicked: expand or collapse it. */
  onDisclosure: ((row: ListingRow) => void) | null = null;
  /** The xref marker was clicked. */
  onXrefs: ((row: ListingRow) => void) | null = null;
  /** The selection was moved back onto its code unit after a renumbering. */
  onReselect: (() => void) | null = null;
  /** A flow arrow was clicked: go to its target. */
  onArrow: ((target: bigint) => void) | null = null;
  /** Draw flow arrows in the gutter. */
  arrows = true;
  /** The arrows drawn in the last frame (hit testing, tests). */
  lastArrows: Arrow[] = [];
  onStatus: ((first: number, total: number) => void) | null = null;

  constructor(opts: ViewOptions) {
    this.canvas = opts.canvas;
    this.cache = opts.cache;
    this.source = opts.source;
    this.painter = opts.painter;
    this.theme = opts.theme;
    this.cols = opts.columns;
    this.pal = palette(opts.theme);
    this.rowH = opts.rowHeight ?? 18;
    this.font = `${opts.fontSize ?? 13}px ${opts.fontFamily ?? "monospace"}`;
    const ctx = this.canvas.getContext("2d", { alpha: false });
    if (!ctx) throw new Error("no 2d context");
    this.ctx = ctx;
    this.measureFont();
    this.attach();
    this.cache.onUpdate(() => this.invalidate());
    this.cache.onShift = (map, before) => this.shifted(map, before);
    this.resize();
  }

  /** Rows were renumbered: keep the same rows selected and on screen. */
  private shifted(map: (row: number) => number | null, before: (row: number) => ListingRow | undefined) {
    const near = (row: number) => {
      for (let r = row; r >= 0 && r > row - 4096; r--) {
        const m = map(r);
        if (m !== null) return m + (row - r);
      }
      return row;
    };
    if (this.anchorRow >= 0) this.anchorRow = map(this.anchorRow) ?? -1;
    if (this.selectedRow >= 0) {
      const m = map(this.selectedRow);
      const sel = before(this.selectedRow);
      if (m !== null) this.selectedRow = m;
      else {
        // The selected row was renumbered away: select its code unit again
        // once its new rows are known.
        this.selectedRow = near(this.selectedRow);
        if (sel && sel.kind !== RowKind.Header) {
          const keep = { key: this.selectedKey, hit: this.selectedHit };
          void this.goTo(sel.address, { notify: false }).then((row) => {
            if (row < 0) return;
            this.selectedKey = keep.key;
            this.selectedHit = keep.hit && { ...keep.hit, row, data: this.cache.get(row) ?? keep.hit.data };
            this.onReselect?.();
          });
        }
      }
    }
    const top = Math.floor(this.scrollY / this.rowH);
    const d = (near(top) - top) * this.rowH;
    this.scrollY += d;
    this.targetY += d;
    this.recentWants = [];
    this.clamp();
    this.invalidate();
  }

  // ------------------------------------------------------------- geometry --

  private measureFont() {
    this.ctx.font = this.font;
    const m = this.ctx.measureText("0123456789abcdef");
    this.charW = m.width / 16;
    const asc = m.fontBoundingBoxAscent ?? m.actualBoundingBoxAscent ?? 10;
    const desc = m.fontBoundingBoxDescent ?? m.actualBoundingBoxDescent ?? 3;
    this.baseline = Math.round((this.rowH - (asc + desc)) / 2 + asc);
  }

  setTheme(t: Theme) {
    this.theme = t;
    this.pal = palette(t);
    this.painter.reset();
    this.invalidate();
  }

  setPainter(p: Painter) {
    this.painter = p;
    this.invalidate();
  }

  setColumns(c: Columns) {
    this.cols = c;
    this.painter.reset();
    this.invalidate();
  }

  /** The ratio the canvas backing store is rendered at. */
  get renderDpr() {
    return this.dpr;
  }

  resize() {
    const dpr = this.dprOverride ?? (window.devicePixelRatio || 1);
    const rect = this.canvas.getBoundingClientRect();
    this.cssW = rect.width;
    this.cssH = rect.height;
    this.dpr = dpr;
    const w = Math.round(rect.width * dpr);
    const h = Math.round(rect.height * dpr);
    // Upscaling a reduced-resolution canvas: nearest-neighbour is the cheap
    // path in CPU compositors (and keeps glyph edges crisp, pixel-doubled).
    this.canvas.style.imageRendering = dpr < (window.devicePixelRatio || 1) ? "pixelated" : "";
    if (this.canvas.width !== w || this.canvas.height !== h) {
      this.canvas.width = w;
      this.canvas.height = h;
    }
    this.measureFont();
    this.painter.reset();
    this.clamp();
    this.invalidate();
  }

  get charWidth() {
    return this.charW;
  }

  get viewportRows() {
    return Math.max(1, Math.floor(this.cssH / this.rowH));
  }
  get rowCount() {
    return this.cache.rowCount;
  }
  private get maxScroll() {
    return Math.max(0, this.rowCount * this.rowH - this.cssH);
  }
  private clamp() {
    const m = this.maxScroll;
    this.scrollY = Math.min(Math.max(0, this.scrollY), m);
    this.targetY = Math.min(Math.max(0, this.targetY), m);
  }

  /** Top visible row (fractional rows allowed). */
  get topRow() {
    return this.scrollY / this.rowH;
  }

  // ------------------------------------------------------------ scrolling --

  /** Immediate scroll (trackpads, drags, programmatic). */
  scrollBy(dy: number) {
    this.scrollY += dy;
    this.targetY += dy;
    this.lastDir = Math.sign(dy);
    this.clamp();
    this.invalidate();
  }

  /** Animated scroll (mouse wheel notches, page keys). */
  scrollBySmooth(dy: number) {
    this.targetY += dy;
    this.lastDir = Math.sign(dy);
    this.clamp();
    this.invalidate();
  }

  scrollToRow(row: number, align: "top" | "center" | "third" = "top", smooth = false) {
    let y = row * this.rowH;
    if (align === "center") y -= (this.cssH - this.rowH) / 2;
    else if (align === "third") y -= this.cssH / 3;
    this.lastDir = Math.sign(y - this.scrollY);
    this.targetY = y;
    if (!smooth) this.scrollY = y;
    this.clamp();
    this.invalidate();
  }

  private rowVisible(row: number) {
    const top = row * this.rowH;
    return top >= this.targetY && top + this.rowH <= this.targetY + this.cssH;
  }

  private ensureRowVisible(row: number) {
    const top = row * this.rowH;
    if (top < this.targetY) this.scrollToRow(row, "top", true);
    else if (top + this.rowH > this.targetY + this.cssH) {
      this.targetY = top + this.rowH - this.cssH;
      this.clamp();
      this.invalidate();
    }
  }

  // ---------------------------------------------------------- navigation --

  /**
   * Shows an address: selects the row containing it and scrolls it into
   * view (a third down the viewport when it was off screen). Uses cached
   * rows when it can, else one address-window request. Resolves to the row
   * index, or -1 when a later call superseded this one.
   */
  async goTo(address: bigint, opts: { notify?: boolean; align?: "top" | "center" | "third" } = {}): Promise<number> {
    const seq = ++this.jumpSeq;
    let row = this.cache.findCached(address);
    if (row < 0) {
      const ps = this.cache.pageSize;
      const res = await this.source.rowsAround(address, ps, ps);
      if (seq !== this.jumpSeq) return -1;
      this.cache.insert(res.startRow, res.rows, res.revision, res.totalRows);
      row = res.anchorRow;
    }
    this.selectedRow = row;
    this.anchorRow = -1;
    const r = this.cache.get(row);
    this.selectedHit = null;
    this.selectedKey = null;
    if (!this.rowVisible(row)) this.scrollToRow(row, opts.align ?? "third");
    this.invalidate();
    if (r && opts.notify !== false) this.onSelect?.(r, row);
    return row;
  }

  /** The row of the code unit holding `address`, fetching around it if needed; -1 when superseded. */
  private async rowFor(address: bigint, seq: number): Promise<number> {
    let row = this.cache.findCached(address);
    if (row >= 0) return row;
    const ps = this.cache.pageSize;
    const res = await this.source.rowsAround(address, ps, ps);
    if (seq !== this.jumpSeq) return -1;
    this.cache.insert(res.startRow, res.rows, res.revision, res.totalRows);
    return res.anchorRow;
  }

  /**
   * Selects the rows over [lo, hi] (inclusive addresses; the byte viewer's
   * selection): the anchor on the code unit holding `lo`, the cursor on the
   * one holding `hi`, scrolled into view.
   */
  async selectAddressRange(lo: bigint, hi: bigint, notify = true): Promise<void> {
    const seq = ++this.jumpSeq;
    const a = await this.rowFor(lo, seq);
    if (a < 0) return;
    const b = await this.rowFor(hi, seq);
    if (b < 0 || seq !== this.jumpSeq) return;
    this.anchorRow = a === b ? -1 : a;
    this.selectedRow = b;
    this.selectedHit = null;
    this.selectedKey = null;
    if (!this.rowVisible(b)) this.scrollToRow(b, "third");
    this.invalidate();
    const r = this.cache.get(b);
    if (r && notify) this.onSelect?.(r, b);
  }

  selectedAddress(): bigint | null {
    if (this.selectedRow < 0) return null;
    return this.cache.get(this.selectedRow)?.address ?? null;
  }

  selectedRowData(): ListingRow | undefined {
    return this.selectedRow < 0 ? undefined : this.cache.get(this.selectedRow);
  }

  private select(row: number, hit: Hit | null = null) {
    this.selectedRow = row;
    this.anchorRow = -1;
    this.rangeSelection = null;
    this.selectedHit = hit;
    const r = this.cache.get(row);
    if (r) this.onSelect?.(r, row);
    this.invalidate();
  }

  /** Moves the cursor to `row`, keeping the anchor: the selection becomes
   * every row between them. */
  private extendTo(row: number, notify = true) {
    this.rangeSelection = null;
    if (this.anchorRow < 0) this.anchorRow = this.selectedRow >= 0 ? this.selectedRow : row;
    this.selectedRow = row;
    this.selectedHit = null;
    this.selectedKey = null;
    const r = this.cache.get(row);
    if (r && notify) this.onSelect?.(r, row);
    this.invalidate();
  }

  /** The selected rows, inclusive; [-1, -1] when nothing is selected. */
  selectionRange(): [number, number] {
    if (this.selectedRow < 0) return [-1, -1];
    const a = this.anchorRow >= 0 ? this.anchorRow : this.selectedRow;
    return [Math.min(a, this.selectedRow), Math.max(a, this.selectedRow)];
  }

  private inSelection(row: number): boolean {
    const [lo, hi] = this.selectionRange();
    if (row >= lo && row <= hi) return true;
    return this.rangeSelection !== null && this.inRanges(row);
  }

  /** Whether the row's bytes overlap the range selection. */
  private inRanges(rowIdx: number): boolean {
    const r = this.cache.get(rowIdx);
    const ranges = this.rangeSelection;
    if (!r || !ranges?.length) return false;
    const end = r.address + BigInt(Math.max(1, r.length)) - 1n;
    // The first range ending at or after the row's start.
    let lo = 0, hi = ranges.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (ranges[mid][1] < r.address) lo = mid + 1;
      else hi = mid;
    }
    return lo < ranges.length && ranges[lo][0] <= end;
  }

  /** One row as plain text, laid out in the same columns as on screen. */
  rowText(r: ListingRow): string {
    let out = "";
    for (const run of layoutRow(r, this.cols).runs) {
      if (out.length < run.col) out = out.padEnd(run.col);
      else if (out.length > run.col && !out.endsWith(" ")) out += " ";
      out += run.text;
    }
    return out.trimEnd();
  }

  /** Loads any selected rows the cache doesn't hold (up to MAX_COPY_ROWS),
   * so a copy right after a long shift-click has them. */
  private async loadSelection(): Promise<void> {
    const [lo, hi0] = this.selectionRange();
    if (lo < 0) return;
    const hi = Math.min(hi0, lo + MAX_COPY_ROWS - 1);
    const page = this.cache.pageSize;
    for (let r = lo; r <= hi; r++) {
      if (this.cache.get(r)) continue;
      const start = r - (r % page);
      const res = await this.source.rows(start, page);
      this.cache.insert(res.startRow, res.rows, res.revision, res.totalRows);
      r = start + page - 1;
    }
  }

  /** The selection as text, or null if some of its rows aren't loaded. */
  selectionText(): string | null {
    const [lo, hi0] = this.selectionRange();
    if (lo < 0) return null;
    const hi = Math.min(hi0, lo + MAX_COPY_ROWS - 1);
    const lines: string[] = [];
    for (let r = lo; r <= hi; r++) {
      const row = this.cache.get(r);
      if (!row) return null;
      lines.push(this.rowText(row));
    }
    return lines.join("\n") + "\n";
  }

  private onCopy(e: ClipboardEvent) {
    if (document.activeElement !== this.canvas || this.selectedRow < 0) return;
    const text = this.selectionText();
    if (text !== null && e.clipboardData) {
      e.clipboardData.setData("text/plain", text);
      e.preventDefault();
      return;
    }
    e.preventDefault();
    this.onNotice?.("Loading the selected rows… press Ctrl+C again in a moment.");
    void this.loadSelection().then(() => this.onNotice?.("Selected rows loaded: press Ctrl+C to copy."));
  }

  // --------------------------------------------------------------- input --

  private attach() {
    const c = this.canvas;
    c.addEventListener("wheel", (e) => this.onWheel(e), { passive: false });
    c.addEventListener("pointerdown", (e) => this.onPointerDown(e));
    // Right-click: select what is under the pointer (keeping a selection it
    // falls inside), then the app's actions, not the browser's menu for a
    // canvas ("Save image as…").
    c.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      const p = this.local(e as unknown as PointerEvent);
      if (p.x >= GUTTER) {
        const row = Math.floor((p.y + this.scrollY) / this.rowH);
        const anchor = this.anchorRow >= 0 ? this.anchorRow : this.selectedRow;
        const lo = Math.min(this.selectedRow, anchor);
        const hi = Math.max(this.selectedRow, anchor);
        if (row < this.rowCount && (row < lo || row > hi)) {
          const hit = this.hitTest(p.x, p.y);
          this.selectedKey = hit && !UNKEYED.has(hit.kind) ? hit.key : null;
          this.select(row, hit);
        } else if (row === this.selectedRow && lo === hi) {
          // On the selected row: what the menu acts on is under the pointer (an operand's Convert).
          const hit = this.hitTest(p.x, p.y);
          if (hit) {
            this.selectedHit = hit;
            this.selectedKey = !UNKEYED.has(hit.kind) ? hit.key : null;
            this.invalidate();
          }
        }
      }
      if (e.button === 2 || e.clientX !== 0 || e.clientY !== 0) this.onContextMenu?.(e.clientX, e.clientY);
      else {
        // The context-menu key: at the selected row.
        const r = this.canvas.getBoundingClientRect();
        this.onContextMenu?.(r.left + GUTTER + 24, r.top + Math.max(0, (this.selectedRow + 1) * this.rowH - this.scrollY));
      }
    });
    c.addEventListener("pointermove", (e) => this.onPointerMove(e));
    c.addEventListener("pointerup", (e) => this.onPointerUp(e));
    c.addEventListener("pointerleave", () => {
      this.pointer = null;
      this.setHover(null, 0, 0);
      if (this.hoverKey !== null) {
        this.hoverKey = null;
        this.invalidate();
      }
    });
    c.addEventListener("dblclick", (e) => this.onDblClick(e));
    c.addEventListener("keydown", (e) => this.onKey(e));
    // A focused canvas isn't editable, so the copy event goes to the document.
    document.addEventListener("copy", (e) => this.onCopy(e));
  }

  onWheel(e: WheelEvent) {
    e.preventDefault();
    this.lastWheel = performance.now();
    let dy = e.deltaY;
    if (e.deltaMode === 1) dy *= this.rowH;
    else if (e.deltaMode === 2) dy *= this.cssH;
    // Line/page deltas and large integral pixel steps come from wheel mice:
    // animate them. Small pixel deltas are trackpad (or momentum) events,
    // already smooth: apply directly so the content tracks the fingers.
    if (e.deltaMode !== 0 || (Math.abs(dy) >= 50 && Number.isInteger(dy))) this.scrollBySmooth(dy);
    else this.scrollBy(dy);
  }

  private local(e: MouseEvent) {
    const r = this.canvas.getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  }

  private thumbGeom() {
    const trackH = this.cssH;
    const total = this.rowCount * this.rowH;
    const h = total <= 0 ? trackH : Math.max(THUMB_MIN, (this.cssH / total) * trackH);
    const max = this.maxScroll;
    const y = max <= 0 ? 0 : (this.scrollY / max) * (trackH - h);
    return { y, h, trackH };
  }

  onPointerDown(e: PointerEvent) {
    const p = this.local(e);
    this.canvas.focus({ preventScroll: true });
    if (p.x >= this.cssW - SCROLLBAR_W) {
      const t = this.thumbGeom();
      if (p.y >= t.y && p.y <= t.y + t.h) {
        this.drag = { offsetY: p.y - t.y };
        try {
          this.canvas.setPointerCapture(e.pointerId);
        } catch {
          /* synthetic events have no active pointer */
        }
      } else {
        this.scrollBySmooth((p.y < t.y ? -1 : 1) * (this.cssH - this.rowH));
      }
      this.invalidate();
      return;
    }
    if (e.button !== 0) return;
    if (p.x < GUTTER) {
      const a = this.arrowAt(p.x, p.y);
      if (a) this.onArrow?.(a.target);
      else {
        const r = this.cache.get(Math.floor((p.y + this.scrollY) / this.rowH));
        if (r && r.kind === RowKind.Instruction) this.onGutterClick?.(r);
      }
      return;
    }
    const row = Math.floor((p.y + this.scrollY) / this.rowH);
    if (row >= this.rowCount) return;
    if (e.shiftKey && this.selectedRow >= 0) {
      this.extendTo(row);
      void this.loadSelection();
      return;
    }
    const hit = this.hitTest(p.x, p.y);
    this.selectedKey = hit && !UNKEYED.has(hit.kind) ? hit.key : null;
    this.select(row, hit);
    this.selecting = true;
    try {
      this.canvas.setPointerCapture(e.pointerId);
    } catch {
      /* synthetic events have no active pointer */
    }
    if (hit?.kind === "xref") this.onXrefs?.(hit.data);
    else if (hit?.kind === "disclosure") this.onDisclosure?.(hit.data);
  }

  onPointerMove(e: PointerEvent) {
    const p = this.local(e);
    if (this.drag) {
      const t = this.thumbGeom();
      const frac = Math.min(1, Math.max(0, (p.y - this.drag.offsetY) / Math.max(1, t.trackH - t.h)));
      const y = frac * this.maxScroll;
      this.lastDir = Math.sign(y - this.scrollY);
      this.scrollY = this.targetY = y;
      this.invalidate();
      return;
    }
    if (this.selecting && (e.buttons & 1)) {
      // Past the top or bottom edge: scroll a row and keep extending.
      if (p.y < 0) this.scrollBy(-this.rowH);
      else if (p.y > this.cssH) this.scrollBy(this.rowH);
      const y = Math.min(Math.max(p.y, 0), this.cssH - 1);
      const row = Math.min(this.rowCount - 1, Math.max(0, Math.floor((y + this.scrollY) / this.rowH)));
      if (row !== this.selectedRow) this.extendTo(row, false);
      return;
    }
    this.pointer = p;
    this.updateHover(e.clientX, e.clientY);
  }

  onPointerUp(e: PointerEvent) {
    if (this.selecting) {
      this.selecting = false;
      try {
        this.canvas.releasePointerCapture(e.pointerId);
      } catch {
        /* ignore */
      }
      if (this.anchorRow === this.selectedRow) this.anchorRow = -1;
      else {
        const r = this.cache.get(this.selectedRow);
        if (r) this.onSelect?.(r, this.selectedRow);
        void this.loadSelection();
      }
    }
    if (this.drag) {
      this.drag = null;
      try {
        this.canvas.releasePointerCapture(e.pointerId);
      } catch {
        /* ignore */
      }
      this.invalidate();
    }
  }

  private onDblClick(e: MouseEvent) {
    const p = this.local(e);
    const hit = this.hitTest(p.x, p.y);
    if (hit?.target !== undefined && hit.kind === "token") this.onFollow?.(hit.target);
  }

  private onKey(e: KeyboardEvent) {
    if (e.ctrlKey && !["Home", "End"].includes(e.key)) return;
    if (e.altKey || e.metaKey) return;
    const page = (this.viewportRows - 1) * this.rowH;
    switch (e.key) {
      case "PageDown":
        this.scrollBySmooth(page);
        if (this.selectedRow >= 0) this.moveCursor(Math.min(this.rowCount - 1, this.selectedRow + this.viewportRows - 1), e.shiftKey);
        break;
      case "PageUp":
        this.scrollBySmooth(-page);
        if (this.selectedRow >= 0) this.moveCursor(Math.max(0, this.selectedRow - this.viewportRows + 1), e.shiftKey);
        break;
      case "ArrowDown":
      case "j":
        this.moveCursor(Math.min(this.rowCount - 1, Math.max(0, this.selectedRow + 1)), e.shiftKey);
        this.ensureRowVisible(this.selectedRow);
        break;
      case "ArrowUp":
      case "k":
        this.moveCursor(Math.max(0, this.selectedRow - 1), e.shiftKey);
        this.ensureRowVisible(this.selectedRow);
        break;
      case "Home":
        if (!e.ctrlKey) return;
        this.scrollToRow(0, "top", false);
        this.select(0);
        break;
      case "End":
        if (!e.ctrlKey) return;
        this.scrollToRow(this.rowCount, "top", false);
        this.select(this.rowCount - 1);
        break;
      case "Escape":
        if (this.anchorRow < 0) return;
        this.anchorRow = -1;
        this.invalidate();
        break;
      case "Enter": {
        const t = this.followTarget();
        if (t !== undefined) this.onFollow?.(t);
        break;
      }
      default:
        return;
    }
    e.preventDefault();
    this.invalidate();
  }

  private moveCursor(row: number, extend: boolean) {
    if (extend) {
      this.extendTo(row);
      void this.loadSelection();
    } else this.select(row);
  }

  /** The reference Enter follows: the selected token's, else the row's first. */
  followTarget(): bigint | undefined {
    if (this.selectedHit?.kind === "token" && this.selectedHit.target !== undefined) return this.selectedHit.target;
    const r = this.cache.get(this.selectedRow);
    return r?.operands.find((o) => o.target !== undefined)?.target;
  }

  hitTest(x: number, y: number): Hit | null {
    const row = Math.floor((y + this.scrollY) / this.rowH);
    const r = this.cache.get(row);
    if (!r) return null;
    const col = (x - PAD_X) / this.charW;
    for (const h of layoutRow(r, this.cols).hot) {
      if (col >= h.col && col < h.col + h.len) return { ...h, row, data: r };
    }
    return null;
  }

  private setHover(hit: Hit | null, cx: number, cy: number) {
    if (hit && performance.now() - this.lastWheel < 400) hit = null;
    const same = hit && this.hoverHit && hit.row === this.hoverHit.row && hit.col === this.hoverHit.col;
    if (same || (!hit && !this.hoverHit)) return;
    this.hoverHit = hit;
    this.onHover?.(hit, cx, cy);
  }

  /** The arrow under a gutter point. */
  arrowAt(x: number, y: number): Arrow | null {
    let best: Arrow | null = null;
    let bestD = 4;
    for (const a of this.lastArrows) {
      const lo = Math.min(a.y0, a.y1) - 3;
      const hi = Math.max(a.y0, a.y1) + 3;
      if (y < lo || y > hi) continue;
      // The vertical run, or a horizontal end at a row in view.
      let d = Math.abs(x - a.x);
      if (x > a.x && (Math.abs(y - a.y0) < 4 || Math.abs(y - a.y1) < 4)) d = 0;
      if (d < bestD) {
        bestD = d;
        best = a;
      }
    }
    return best;
  }

  private updateHover(cx = -1, cy = -1) {
    const p = this.pointer;
    const hit = p && p.x < this.cssW - SCROLLBAR_W ? this.hitTest(p.x, p.y) : null;
    const key = hit && (hit.kind === "token" || hit.kind === "label" || hit.kind === "mnemonic") ? hit.key : null;
    if (key !== this.hoverKey) {
      this.hoverKey = key;
      this.invalidate();
    }
    if (cx >= 0) this.setHover(hit, cx, cy);
    const overArrow = p !== null && p.x < GUTTER && this.arrowAt(p.x, p.y) !== null;
    this.canvas.style.cursor = overArrow || (hit && ((hit.target !== undefined && hit.kind !== "type" && hit.kind !== "mutability" && hit.kind !== "field") || hit.kind === "xref")) ? "pointer" : "default";
  }

  // ------------------------------------------------------------ rendering --

  private loaded(y: number, n: number): boolean {
    const first = Math.floor(y / this.rowH);
    const end = Math.min(this.rowCount, first + n);
    for (let r = first; r < end; r++) if (!this.cache.get(r)) return false;
    return true;
  }

  invalidate() {
    if (!this.rafId) this.rafId = requestAnimationFrame((ts) => this.frame(ts));
  }

  private frame(ts: number) {
    this.rafId = 0;
    const dt = this.lastFrameTs ? Math.min(100, ts - this.lastFrameTs) : 16.7;
    this.lastFrameTs = ts;
    let animating = false;
    const diff = this.targetY - this.scrollY;
    if (Math.abs(diff) > 0.5) {
      this.scrollY += diff * (1 - Math.exp(-dt / SMOOTH_TAU_MS));
      animating = true;
    } else this.scrollY = this.targetY;
    // Rows move under a stationary pointer while scrolling.
    if (this.pointer && !this.drag) this.updateHover();
    this.render();
    if (animating) this.invalidate();
    else this.lastFrameTs = 0;
  }

  /** Collaborators' cursors: a bar and a name tag at the right of their code unit's row. */
  private drawCursors(first: number, n: number, yOff: number, listW: number) {
    const ctx = this.ctx;
    for (let i = 0; i < n; i++) {
      const r = this.cache.get(first + i);
      if (!r || r.kind === RowKind.Header) continue;
      const cs = this.cursors!.get(r.address);
      if (!cs) continue;
      const y = yOff + i * this.rowH;
      let x = listW - 6;
      ctx.font = `11px ${this.font.split("px ")[1] ?? "monospace"}`;
      for (const c of cs) {
        const w = ctx.measureText(c.name).width + 10;
        x -= w;
        ctx.fillStyle = c.color;
        ctx.globalAlpha = 0.85;
        ctx.fillRect(x, y + 2, w, this.rowH - 4);
        ctx.globalAlpha = 1;
        ctx.fillStyle = "#0d1117";
        ctx.fillText(c.name, x + 5, y + this.rowH - 5);
        x -= 4;
        ctx.fillStyle = c.color;
        ctx.fillRect(GUTTER, y, 2, this.rowH);
      }
    }
  }

  private jumpCache: { key: string; jumps: { from: number; to: number | undefined; target: bigint; conditional: boolean }[] } | null = null;

  /**
   * The jumps whose source is within ARROW_SCAN rows of [first, last], with
   * their target rows where those are cached. Recomputed only when the
   * cache changes or the view moves to another 64-row step, so a frame
   * just filters them.
   */
  private jumpsNear(first: number, last: number) {
    const step = 64;
    const lo = Math.max(0, Math.floor(first / step) * step - ARROW_SCAN);
    const hi = Math.min(this.rowCount - 1, Math.ceil((last + 1) / step) * step + ARROW_SCAN);
    const key = `${this.cache.version}:${lo}:${hi}`;
    if (this.jumpCache?.key === key) return this.jumpCache.jumps;
    const byAddr = new Map<bigint, number>();
    for (let i = lo; i <= hi; i++) {
      const r = this.cache.get(i);
      if (r && r.kind !== RowKind.Header && !byAddr.has(r.address)) byAddr.set(r.address, i);
    }
    const jumps: { from: number; to: number | undefined; target: bigint; conditional: boolean }[] = [];
    for (let i = lo; i <= hi; i++) {
      const r = this.cache.get(i);
      if (!r || !isJump(r)) continue;
      for (const t of r.flowTargets) jumps.push({ from: i, to: byAddr.get(t), target: t, conditional: r.flow === Flow.CondBranch });
    }
    this.jumpCache = { key, jumps };
    return jumps;
  }

  /**
   * Flow arrows for the jumps in view: both ends visible, or one end out of
   * view (clipped to the edge; a click follows it). Sources up to
   * ARROW_SCAN rows away that jump into view are found in the cache.
   * Lanes are assigned shortest first, nearest the text.
   */
  private drawArrows(first: number, n: number, yOff: number, H: number) {
    const ctx = this.ctx;
    const rowH = this.rowH;
    const last = Math.min(this.rowCount - 1, first + n - 1);
    const jumps = this.jumpsNear(first, last);
    let firstAddr: bigint | null = null;
    let lastAddr: bigint | null = null;
    for (let i = first; i <= last; i++) {
      const r = this.cache.get(i);
      if (!r || r.kind === RowKind.Header) continue;
      if (firstAddr === null) firstAddr = r.address;
      lastAddr = r.address;
    }
    if (firstAddr === null || lastAddr === null) {
      this.lastArrows = [];
      return;
    }
    const raw: { from: number; to: number; target: bigint; conditional: boolean }[] = [];
    const inView = (x: number) => x >= first && x <= last;
    for (const j of jumps) {
      const visible = inView(j.from);
      let to = j.to;
      if (to === undefined) {
        // Target outside the scanned rows: only a visible source shows it,
        // as a stub to the edge it lies beyond.
        if (!visible) continue;
        to = j.target < firstAddr ? first - 1 : j.target > lastAddr ? last + 1 : j.from;
        if (to === j.from) continue;
      }
      // Skip jumps that neither start, end nor pass through the view.
      if (!visible && !inView(to) && !(Math.min(j.from, to) < first && Math.max(j.from, to) > last)) continue;
      raw.push({ from: j.from, to, target: j.target, conditional: j.conditional });
    }
    raw.sort((a, b) => Math.abs(a.to - a.from) - Math.abs(b.to - b.from));
    const lanes: [number, number][][] = [];
    const arrows: Arrow[] = [];
    const yOf = (row: number) => Math.min(H + 2, Math.max(-2, yOff + (row - first) * rowH + rowH / 2));
    for (const a of raw) {
      const top = Math.min(a.from, a.to);
      const bot = Math.max(a.from, a.to);
      let lane = 0;
      for (; lane < MAX_LANES - 1; lane++) {
        const used = lanes[lane] ?? (lanes[lane] = []);
        if (!used.some(([u0, u1]) => top <= u1 + 1 && bot >= u0 - 1)) break;
      }
      (lanes[lane] ?? (lanes[lane] = [])).push([top, bot]);
      const offscreen = a.from < first || a.from > last || a.to < first || a.to > last;
      arrows.push({ from: a.from, to: a.to, x: GUTTER - 6 - lane * LANE_W, y0: yOf(a.from), y1: yOf(a.to), target: a.target, conditional: a.conditional, offscreen });
    }
    this.lastArrows = arrows;
    const sel = this.selectedRow;
    const theme = this.theme;
    ctx.lineWidth = 1;
    for (const a of arrows) {
      const hiLite = a.from === sel || a.to === sel;
      ctx.strokeStyle = hiLite ? theme.arrowSel : a.conditional ? theme.arrowCond : theme.arrow;
      ctx.fillStyle = ctx.strokeStyle;
      ctx.setLineDash(a.conditional ? [3, 2] : []);
      const x = Math.round(a.x) + 0.5;
      const fromIn = a.from >= first && a.from <= last;
      const toIn = a.to >= first && a.to <= last;
      ctx.beginPath();
      if (fromIn) {
        ctx.moveTo(GUTTER - 1, Math.round(a.y0) + 0.5);
        ctx.lineTo(x, Math.round(a.y0) + 0.5);
      } else ctx.moveTo(x, a.y0);
      ctx.lineTo(x, Math.round(a.y1) + 0.5);
      if (toIn) ctx.lineTo(GUTTER - 4, Math.round(a.y1) + 0.5);
      ctx.stroke();
      ctx.setLineDash([]);
      if (toIn) {
        // Arrowhead at the target row.
        const y = Math.round(a.y1) + 0.5;
        ctx.beginPath();
        ctx.moveTo(GUTTER - 1, y);
        ctx.lineTo(GUTTER - 5, y - 3);
        ctx.lineTo(GUTTER - 5, y + 3);
        ctx.fill();
      } else {
        // Out of view: a chevron at the edge it leaves through.
        const up = a.to < first;
        const y = up ? 4 : H - 4;
        ctx.beginPath();
        ctx.moveTo(x - 3, up ? y + 3 : y - 3);
        ctx.lineTo(x, y);
        ctx.lineTo(x + 3, up ? y + 3 : y - 3);
        ctx.stroke();
      }
    }
  }

  render() {
    const t0 = performance.now();
    const { ctx, dpr, rowH, theme, cols } = this;
    const W = this.cssW;
    const H = this.cssH;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.fillStyle = theme.bg;
    ctx.fillRect(0, 0, W, H);

    // Snap the scroll offset to device pixels so text lands on the pixel grid.
    const wantY = Math.round(this.scrollY * dpr) / dpr;
    const wantFirst = Math.floor(wantY / rowH);
    const nWant = Math.ceil(H / rowH) + 1;
    // Velocity in rows/frame, for one-frame-ahead prefetch on big jumps.
    const vel = this.prevWantFirst >= 0 ? wantFirst - this.prevWantFirst : 0;
    const predicted = Math.abs(vel) > nWant / 2 ? Math.max(0, wantFirst + vel) : undefined;
    this.cache.want(wantFirst, wantFirst + nWant - 1, this.lastDir, predicted);

    // Hold: if the requested position isn't loaded yet, draw the most recent
    // position requested within holdMs whose rows are all loaded, instead of
    // placeholders. Content then lags the scrollbar by about one fetch
    // latency; FrameStats.stale counts those frames.
    const now = performance.now();
    const recent = this.recentWants;
    recent.push({ y: wantY, at: now });
    while (recent.length && now - recent[0].at > this.holdMs) recent.shift();
    let sy = wantY;
    let lagMs = 0;
    if (!this.loaded(wantY, nWant)) {
      for (let i = recent.length - 2; i >= 0; i--) {
        if (this.loaded(recent[i].y, nWant)) {
          sy = recent[i].y;
          lagMs = now - recent[i].at;
          break;
        }
      }
    }
    this.prevWantFirst = wantFirst;
    const stale = sy !== wantY;
    const first = Math.floor(sy / rowH);
    const yOff = first * rowH - sy;
    const n = Math.ceil((H - yOff) / rowH);

    const items: PaintItem[] = [];
    let blank = 0;
    const listW = W - SCROLLBAR_W;
    const cw = this.charW;
    const sync = this.syncAddrs;
    for (let i = 0; i < n; i++) {
      const rowIdx = first + i;
      if (rowIdx >= this.rowCount) break;
      const y = yOff + i * rowH;
      const r = this.cache.get(rowIdx);
      if (!r) {
        // Not loaded yet: skeleton bars. Counted in FrameStats.blankRows.
        blank++;
        ctx.fillStyle = theme.placeholder;
        ctx.fillRect(PAD_X, y + 5, 8 * cw, rowH - 10);
        ctx.fillRect(PAD_X + cols.mnem * cw, y + 5, 22 * cw, rowH - 10);
        continue;
      }
      const header = r.kind === RowKind.Header;
      // A function's band: its header rows (with header rows), else its entry row.
      const band = r.functionEntry && (header || !cols.headerRows);
      if (this.inSelection(rowIdx)) {
        ctx.fillStyle = theme.selRow;
        ctx.fillRect(GUTTER, y, listW - GUTTER, rowH);
      } else if (sync && sync.has(r.address) && !header) {
        ctx.fillStyle = theme.syncRow;
        ctx.fillRect(GUTTER, y, listW - GUTTER, rowH);
      } else if (this.sliceMarks?.has(r.address) && !header) {
        ctx.fillStyle = theme.sliceRow;
        ctx.fillRect(GUTTER, y, listW - GUTTER, rowH);
      } else if (band) {
        ctx.fillStyle = theme.headerBg;
        ctx.fillRect(GUTTER, y, listW - GUTTER, rowH);
      } else if (header) {
        ctx.fillStyle = theme.headerRowBg;
        ctx.fillRect(GUTTER, y, listW - GUTTER, rowH);
      }
      if (band) {
        // A rule above the first line of the function.
        const prev = this.cache.get(rowIdx - 1);
        if (!prev || prev.address !== r.address || prev.kind !== RowKind.Header) {
          ctx.fillStyle = theme.entryRule;
          ctx.fillRect(GUTTER, y, listW - GUTTER, 1);
        }
      }
      if (this.hoverKey !== null || this.selectedKey !== null) {
        for (const h of layoutRow(r, cols).hot) {
          if (UNKEYED.has(h.kind)) continue;
          const sel = h.key === this.selectedKey;
          if (sel || h.key === this.hoverKey) {
            ctx.fillStyle = sel ? theme.selTok : theme.hoverTok;
            ctx.fillRect(PAD_X + h.col * cw - 1, y + 1, h.len * cw + 2, rowH - 2);
          }
        }
      }
      const emu = this.emuMarks;
      if (emu && r.kind === RowKind.Instruction) {
        if (emu.pc === r.address) {
          ctx.fillStyle = "rgba(63, 185, 80, 0.20)";
          ctx.fillRect(GUTTER, y, listW - GUTTER, rowH);
          ctx.fillStyle = "#3fb950";
          ctx.beginPath();
          ctx.moveTo(GUTTER - 13, y + 4);
          ctx.lineTo(GUTTER - 5, y + rowH / 2);
          ctx.lineTo(GUTTER - 13, y + rowH - 4);
          ctx.fill();
        }
        if (emu.breakpoints.has(r.address)) {
          ctx.fillStyle = "#f85149";
          ctx.beginPath();
          ctx.arc(7, y + rowH / 2, 4.5, 0, 2 * Math.PI);
          ctx.fill();
        }
      }
      if (r.patched && !header) {
        // Patched (PatchService): a tint, a mark in the gutter, and the
        // changed bytes in the bytes column.
        if (!this.inSelection(rowIdx)) {
          ctx.fillStyle = theme.patchedRow;
          ctx.fillRect(GUTTER, y, listW - GUTTER, rowH);
        }
        ctx.fillStyle = theme.patchMark;
        ctx.fillRect(GUTTER - 4, y + 2, 3, rowH - 4);
        if (cols.showBytes) {
          ctx.fillStyle = theme.patchedByte;
          for (const i of r.patchedBytes) ctx.fillRect(PAD_X + (cols.bytes + 3 * i) * cw - 1, y + 2, 2 * cw + 2, rowH - 4);
        }
      }
      if (this.noteAddrs?.has(r.address) && !header) {
        ctx.fillStyle = theme.note;
        ctx.fillRect(GUTTER + 2, y + 4, 3, rowH - 8);
      }
      if (this.sliceMarks?.has(r.address) && !header) {
        ctx.fillStyle = theme.sliceMark;
        ctx.fillRect(GUTTER - 4, y + 3, 3, rowH - 6);
      }
      if (this.searchMarks?.has(r.address) && !header) {
        ctx.fillStyle = theme.searchMark;
        ctx.fillRect(GUTTER - 9, y + 3, 4, rowH - 6);
      }
      if (showsXrefs(r, cols)) {
        // Xref marker: a small left-pointing triangle before the count.
        ctx.fillStyle = theme.xref;
        const mx = PAD_X + cols.xref * cw + 1;
        ctx.beginPath();
        ctx.moveTo(mx + 5, y + 5);
        ctx.lineTo(mx, y + rowH / 2);
        ctx.lineTo(mx + 5, y + rowH - 5);
        ctx.fill();
      }
      if (r.kind === RowKind.Instruction && r.isFlow) {
        ctx.fillStyle = theme.marker;
        const mx = PAD_X + (cols.mnem - 1.4) * cw;
        ctx.beginPath();
        ctx.moveTo(mx, y + 6);
        ctx.lineTo(mx + 5, y + rowH / 2);
        ctx.lineTo(mx, y + rowH - 6);
        ctx.fill();
      }
      items.push({ row: r, y });
    }

    if (this.arrows) this.drawArrows(first, n, yOff, H);
    else this.lastArrows = [];

    this.painter.paint(
      {
        ctx,
        dpr,
        font: this.font,
        x0: PAD_X,
        charW: cw,
        rowH,
        baseline: this.baseline,
        palette: this.pal,
        cols,
      },
      items,
    );

    if (cols.showBytes) {
      // Patched bytes: underlined under the text, which stays readable.
      ctx.fillStyle = theme.patchMark;
      for (const it of items)
        if (it.row.patched && it.row.kind !== RowKind.Header)
          for (const i of it.row.patchedBytes) ctx.fillRect(PAD_X + (cols.bytes + 3 * i) * cw, it.y + rowH - 3, 2 * cw, 2);
    }

    if (this.cursors?.size) this.drawCursors(first, n, yOff, listW);

    // Scrollbar.
    const t = this.thumbGeom();
    ctx.fillStyle = theme.track;
    ctx.fillRect(W - SCROLLBAR_W, 0, SCROLLBAR_W, H);
    ctx.fillStyle = this.drag ? theme.thumbActive : theme.thumb;
    ctx.fillRect(W - SCROLLBAR_W + 2, t.y, SCROLLBAR_W - 4, t.h);
    if (this.selectedRow >= 0 && this.rowCount > 0) {
      const my = (this.selectedRow / this.rowCount) * H;
      ctx.fillStyle = theme.selTok;
      ctx.fillRect(W - SCROLLBAR_W, my - 1, SCROLLBAR_W, 2);
    }

    const stats: FrameStats = {
      stale,
      lagMs,
      renderMs: performance.now() - t0,
      visibleRows: n,
      blankRows: blank,
      rasterized: this.painter.lastRasterized,
    };
    this.onFrame?.(stats);
    this.onStatus?.(first, this.rowCount);
  }
}
