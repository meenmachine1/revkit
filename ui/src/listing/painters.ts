// Text painting strategies for the listing. The view draws backgrounds,
// highlights, placeholders and the scrollbar itself; a painter only puts row
// text on screen. Selected with ?render=direct|rowcache|atlas.
//
// direct:   fillText for every run on every frame, batched by color so the
//           fill style changes ~13 times per frame instead of per run.
// rowcache: each row's text is rasterized once into a slot of a shared
//           backing canvas and blitted with drawImage on later frames; a
//           steady scroll only rasterizes the 1-2 rows entering the viewport.
// atlas:    static per-color glyph atlas, one drawImage per glyph.

import type { ListingRow } from "../data/types";
import { C, layoutRow, type Columns } from "./layout";

export interface PaintItem {
  row: ListingRow;
  /** Top of the row in CSS px, already snapped to device pixels. */
  y: number;
}

export interface PaintContext {
  ctx: CanvasRenderingContext2D;
  dpr: number;
  font: string;
  x0: number;
  charW: number;
  rowH: number;
  baseline: number;
  palette: string[];
  cols: Columns;
}

export interface Painter {
  readonly name: string;
  paint(pc: PaintContext, items: PaintItem[]): void;
  /** Font, DPR or theme changed: drop anything rasterized. */
  reset(): void;
  /** Rows rasterized during the last paint (cache misses). */
  lastRasterized: number;
}

export class DirectPainter implements Painter {
  readonly name = "direct";
  lastRasterized = 0;
  private bt: string[][] = [];
  private bx: number[][] = [];
  private by: number[][] = [];

  constructor() {
    for (let c = 0; c < C.Count; c++) {
      this.bt.push([]);
      this.bx.push([]);
      this.by.push([]);
    }
  }

  reset() {}

  paint(pc: PaintContext, items: PaintItem[]) {
    const { ctx, x0, charW, baseline, palette } = pc;
    const { bt, bx, by } = this;
    for (let c = 0; c < C.Count; c++) {
      bt[c].length = 0;
      bx[c].length = 0;
      by[c].length = 0;
    }
    for (const it of items) {
      const y = it.y + baseline;
      for (const r of layoutRow(it.row, pc.cols).runs) {
        bt[r.color].push(r.text);
        bx[r.color].push(x0 + r.col * charW);
        by[r.color].push(y);
      }
    }
    ctx.font = pc.font;
    for (let c = 0; c < C.Count; c++) {
      const t = bt[c];
      if (!t.length) continue;
      ctx.fillStyle = palette[c];
      const xs = bx[c];
      const ys = by[c];
      for (let i = 0; i < t.length; i++) ctx.fillText(t[i], xs[i], ys[i]);
    }
    this.lastRasterized = items.length;
  }
}

// One small canvas per row slot: drawing a canvas that was modified since it
// was last drawn snapshots (copies) the whole canvas in Chromium, so big
// shared sheets turn every new row into a multi-megabyte copy.
const SLOTS_PER_SHEET = 1;

interface Sheet {
  canvas: HTMLCanvasElement | OffscreenCanvas;
  ctx: CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D;
}

export class RowCachePainter implements Painter {
  readonly name = "rowcache";
  lastRasterized = 0;
  private sheets: Sheet[] = [];
  private slotOf = new Map<ListingRow, number>();
  private rowOf: (ListingRow | undefined)[] = [];
  private stamp: number[] = [];
  private frame = 0;
  private slotW = 0;
  private slotH = 0;
  private key = "";

  constructor(private slots = 192) {}

  reset() {
    this.sheets = [];
    this.slotOf.clear();
    this.rowOf = [];
    this.stamp = [];
    this.key = "";
  }

  private ensure(pc: PaintContext) {
    const key = `${pc.font}|${pc.dpr}|${pc.charW}|${pc.rowH}|${pc.palette.join()}|${pc.cols.version}`;
    if (key === this.key) return;
    this.reset();
    this.key = key;
    this.slotW = Math.ceil((pc.x0 + pc.cols.end * pc.charW) * pc.dpr);
    this.slotH = Math.round(pc.rowH * pc.dpr);
    const nSheets = Math.ceil(this.slots / SLOTS_PER_SHEET);
    for (let s = 0; s < nSheets; s++) {
      const w = this.slotW;
      const h = this.slotH * SLOTS_PER_SHEET;
      let canvas: HTMLCanvasElement | OffscreenCanvas;
      if (typeof OffscreenCanvas !== "undefined") canvas = new OffscreenCanvas(w, h);
      else {
        canvas = document.createElement("canvas");
        canvas.width = w;
        canvas.height = h;
      }
      const ctx = canvas.getContext("2d", { alpha: true }) as CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D;
      ctx.setTransform(pc.dpr, 0, 0, pc.dpr, 0, 0);
      ctx.font = pc.font;
      this.sheets.push({ canvas, ctx });
    }
    for (let i = 0; i < this.slots; i++) {
      this.rowOf.push(undefined);
      this.stamp.push(-1);
    }
  }

  private allocate(): number {
    let best = 0;
    let bestStamp = Infinity;
    for (let i = 0; i < this.slots; i++) {
      const s = this.stamp[i];
      if (s < bestStamp) {
        bestStamp = s;
        best = i;
        if (s < 0) break;
      }
    }
    const old = this.rowOf[best];
    if (old) this.slotOf.delete(old);
    return best;
  }

  private rasterize(pc: PaintContext, row: ListingRow, slot: number) {
    const sheet = this.sheets[Math.floor(slot / SLOTS_PER_SHEET)];
    const top = (slot % SLOTS_PER_SHEET) * pc.rowH;
    const ctx = sheet.ctx;
    ctx.clearRect(0, top, this.slotW / pc.dpr, pc.rowH);
    let last = -1;
    for (const r of layoutRow(row, pc.cols).runs) {
      if (r.color !== last) {
        ctx.fillStyle = pc.palette[r.color];
        last = r.color;
      }
      ctx.fillText(r.text, pc.x0 + r.col * pc.charW, top + pc.baseline);
    }
  }

  paint(pc: PaintContext, items: PaintItem[]) {
    this.ensure(pc);
    this.frame++;
    let misses = 0;
    const { ctx, dpr } = pc;
    ctx.save();
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    for (const it of items) {
      let slot = this.slotOf.get(it.row);
      if (slot === undefined) {
        slot = this.allocate();
        this.slotOf.set(it.row, slot);
        this.rowOf[slot] = it.row;
        this.rasterize(pc, it.row, slot);
        misses++;
      }
      this.stamp[slot] = this.frame;
      const sheet = this.sheets[Math.floor(slot / SLOTS_PER_SHEET)];
      const sy = (slot % SLOTS_PER_SHEET) * this.slotH;
      ctx.drawImage(sheet.canvas, 0, sy, this.slotW, this.slotH, 0, Math.round(it.y * dpr), this.slotW, this.slotH);
    }
    ctx.restore();
    this.lastRasterized = misses;
  }
}

// Printable ASCII plus the ellipsis used for truncated bytes.
const ATLAS_CHARS = Array.from({ length: 95 }, (_, i) => String.fromCharCode(32 + i)).join("") + "…";
const ATLAS_INDEX = new Map([...ATLAS_CHARS].map((c, i) => [c, i]));

/** Static glyph atlas: every (color, glyph) pre-rasterized once at device
 * resolution into one canvas that never changes afterwards, then one
 * drawImage per visible non-space glyph. Glyph x positions are rounded to
 * device pixels. Runs with characters outside the atlas fall back to
 * fillText. */
export class AtlasPainter implements Painter {
  readonly name = "atlas";
  lastRasterized = 0;
  private atlas: HTMLCanvasElement | null = null;
  private cellW = 0;
  private cellH = 0;
  private pad = 0;
  private key = "";

  reset() {
    this.atlas = null;
    this.key = "";
  }

  private ensure(pc: PaintContext) {
    const key = `${pc.font}|${pc.dpr}|${pc.charW}|${pc.rowH}|${pc.palette.join()}|${pc.cols.version}`;
    if (key === this.key && this.atlas) return;
    this.key = key;
    this.pad = Math.ceil(2 * pc.dpr);
    this.cellW = Math.ceil(pc.charW * pc.dpr) + 2 * this.pad;
    this.cellH = Math.round(pc.rowH * pc.dpr);
    const c = document.createElement("canvas");
    c.width = this.cellW * ATLAS_CHARS.length;
    c.height = this.cellH * C.Count;
    const ctx = c.getContext("2d")!;
    ctx.font = pc.font;
    ctx.setTransform(pc.dpr, 0, 0, pc.dpr, 0, 0);
    for (let col = 0; col < C.Count; col++) {
      ctx.fillStyle = pc.palette[col];
      for (let i = 0; i < ATLAS_CHARS.length; i++) {
        ctx.fillText(ATLAS_CHARS[i], (i * this.cellW + this.pad) / pc.dpr, col * pc.rowH + pc.baseline);
      }
    }
    this.atlas = c;
  }

  paint(pc: PaintContext, items: PaintItem[]) {
    this.ensure(pc);
    const atlas = this.atlas!;
    const { ctx, dpr, x0, charW, baseline } = pc;
    const { cellW, cellH, pad } = this;
    ctx.save();
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    const fallback: { text: string; x: number; y: number; color: C }[] = [];
    for (const it of items) {
      const dy = Math.round(it.y * dpr);
      for (const r of layoutRow(it.row, pc.cols).runs) {
        const sy = r.color * cellH;
        const t = r.text;
        for (let i = 0; i < t.length; i++) {
          const ch = t[i];
          if (ch === " ") continue;
          const gi = ATLAS_INDEX.get(ch);
          if (gi === undefined) {
            fallback.push({ text: t, x: x0 + r.col * charW, y: it.y + baseline, color: r.color });
            break;
          }
          const dx = Math.round((x0 + (r.col + i) * charW) * dpr) - pad;
          ctx.drawImage(atlas, gi * cellW, sy, cellW, cellH, dx, dy, cellW, cellH);
        }
      }
    }
    ctx.restore();
    if (fallback.length) {
      ctx.font = pc.font;
      for (const f of fallback) {
        ctx.fillStyle = pc.palette[f.color];
        ctx.fillText(f.text, f.x, f.y);
      }
    }
    this.lastRasterized = 0;
  }
}

export function makePainter(name: string | null): Painter {
  if (name === "rowcache") return new RowCachePainter();
  if (name === "atlas") return new AtlasPainter();
  return new DirectPainter();
}
