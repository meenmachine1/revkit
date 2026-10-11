// The overview bars beside the listing's scrollbar (Ghidra's OverviewPlugin;
// feature overview, api_minor 44): one coloured by what the program's bytes
// are (code, data, undefined, external, uninitialized), one by entropy per
// slice. Both run over every memory block in address order, each block in
// proportion to its size; a click (or a drag) goes to the address there,
// and a line marks the cursor. QueryService.GetOverview computes the
// slices on the daemon; they are refetched after an edit that changes the
// listing or the bytes, and when the bars change height.

import type { GetOverviewResponse, OverviewBucket, Revkit } from "@revkit/api";
import { ByteKind } from "@revkit/api";
import { errText, fmtAddr } from "../data/format";
import { h } from "../ui/dom";

export interface OverviewHost {
  rk: Revkit;
  programId: string;
  navigate: (addr: bigint) => void;
}

/** Colours by kind, per theme; entropy runs from cool (low) to hot (high). */
const KIND_COLORS = {
  dark: { [ByteKind.CODE]: "#4c8fd6", [ByteKind.DATA]: "#3fb950", [ByteKind.UNDEFINED]: "#3b414c", [ByteKind.EXTERNAL]: "#b58be6", [ByteKind.UNINITIALIZED]: "#22262e" } as Record<number, string>,
  light: { [ByteKind.CODE]: "#3b7fd0", [ByteKind.DATA]: "#2da44e", [ByteKind.UNDEFINED]: "#d0d7de", [ByteKind.EXTERNAL]: "#8250df", [ByteKind.UNINITIALIZED]: "#eef1f4" } as Record<number, string>,
};
const KIND_TEXT: Record<number, string> = {
  [ByteKind.CODE]: "code",
  [ByteKind.DATA]: "data",
  [ByteKind.UNDEFINED]: "undefined",
  [ByteKind.EXTERNAL]: "external",
  [ByteKind.UNINITIALIZED]: "uninitialized",
};

/** Entropy (0..8 bits per byte) as a colour: dark blue, through green and yellow, to red. */
export function entropyColor(e: number, dark: boolean): string {
  const t = Math.min(1, Math.max(0, e / 8));
  const stops = dark
    ? [
        [24, 30, 48],
        [40, 90, 160],
        [60, 170, 110],
        [230, 200, 60],
        [230, 70, 50],
      ]
    : [
        [232, 238, 248],
        [120, 170, 230],
        [90, 190, 120],
        [235, 190, 40],
        [215, 60, 40],
      ];
  const x = t * (stops.length - 1);
  const i = Math.min(stops.length - 2, Math.floor(x));
  const f = x - i;
  const c = stops[i].map((v, k) => Math.round(v + (stops[i + 1][k] - v) * f));
  return `rgb(${c[0]}, ${c[1]}, ${c[2]})`;
}

export class OverviewBars {
  readonly el: HTMLElement;
  private kindCanvas: HTMLCanvasElement;
  private entropyCanvas: HTMLCanvasElement;
  private buckets: OverviewBucket[] = [];
  /** Cumulative bytes before each bucket (bars are proportional to size). */
  private before: number[] = [];
  private total = 0;
  private cursor: bigint | null = null;
  private seq = 0;
  private reloadTimer = 0;
  private dragging = false;
  private loadedFor = 0;
  dark = true;
  /** Settles when the last load is done (tests). */
  loading: Promise<void> = Promise.resolve();

  constructor(private host: OverviewHost) {
    this.kindCanvas = h("canvas", { class: "ov-bar", "data-testid": "overview-kind", role: "img", "aria-label": "Overview: code, data, undefined, external" });
    this.entropyCanvas = h("canvas", { class: "ov-bar", "data-testid": "overview-entropy", role: "img", "aria-label": "Overview: entropy" });
    this.el = h("div", { class: "overview", "data-testid": "overview" }, this.kindCanvas, this.entropyCanvas);
    for (const c of [this.kindCanvas, this.entropyCanvas]) {
      c.addEventListener("mousedown", (e) => {
        if (e.button !== 0) return;
        e.preventDefault();
        this.dragging = true;
        this.go(e);
      });
      c.addEventListener("mousemove", (e) => {
        this.hover(c, e);
        if (this.dragging && e.buttons & 1) this.go(e);
      });
    }
    window.addEventListener("mouseup", () => (this.dragging = false));
    new ResizeObserver(() => {
      this.draw();
      // Taller bars want finer slices.
      if (Math.abs(this.el.clientHeight - this.loadedFor) > 64) this.reload(0);
    }).observe(this.el);
  }

  get shown(): boolean {
    return !this.el.hidden;
  }

  /** Refetches the slices (debounced: edits come in bursts). */
  reload(ms = 800) {
    clearTimeout(this.reloadTimer);
    if (!this.shown) return;
    this.reloadTimer = window.setTimeout(() => {
      this.loading = this.load();
    }, ms);
  }

  async load(): Promise<void> {
    const seq = ++this.seq;
    const height = this.el.clientHeight || 600;
    let r: GetOverviewResponse;
    try {
      r = await this.host.rk.queries.getOverview({ programId: this.host.programId, buckets: Math.min(4096, Math.max(64, Math.round(height * (window.devicePixelRatio || 1)))) });
    } catch (e) {
      this.el.title = `Overview: ${errText(e)}`;
      return;
    }
    if (seq !== this.seq) return;
    this.loadedFor = height;
    this.buckets = r.buckets;
    this.before = [];
    let sum = 0;
    for (const b of r.buckets) {
      this.before.push(sum);
      sum += Number(b.length);
    }
    this.total = sum;
    this.draw();
  }

  setCursor(a: bigint | null) {
    if (a === this.cursor) return;
    this.cursor = a;
    this.draw();
  }

  /** The bucket at a fraction of the bars' height, and the address there. */
  private at(frac: number): { b: OverviewBucket; addr: bigint } | null {
    if (!this.buckets.length || this.total <= 0) return null;
    const x = Math.min(this.total - 1, Math.max(0, frac * this.total));
    let lo = 0;
    let hi = this.buckets.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.before[mid] <= x) lo = mid;
      else hi = mid - 1;
    }
    const b = this.buckets[lo];
    const off = Math.min(Number(b.length) - 1, Math.floor(x - this.before[lo]));
    return { b, addr: (b.start?.offset ?? 0n) + BigInt(Math.max(0, off)) };
  }

  /** The fraction of the height an address sits at (null outside every bucket). */
  private fracOf(a: bigint): number | null {
    for (let i = 0; i < this.buckets.length; i++) {
      const b = this.buckets[i];
      const s = b.start?.offset ?? 0n;
      if (a >= s && a < s + b.length) return (this.before[i] + Number(a - s)) / this.total;
    }
    return null;
  }

  private go(e: MouseEvent) {
    const r = (e.target as HTMLElement).getBoundingClientRect();
    const hit = this.at((e.clientY - r.top) / r.height);
    if (hit) this.host.navigate(hit.addr);
  }

  private hover(c: HTMLCanvasElement, e: MouseEvent) {
    const r = c.getBoundingClientRect();
    const hit = this.at((e.clientY - r.top) / r.height);
    if (!hit) return;
    const b = hit.b;
    const n = Number(b.length) || 1;
    const parts = (
      [
        ["code", b.code],
        ["data", b.data],
        ["undefined", b.undefined],
        ["external", b.external],
        ["uninitialized", b.uninitialized],
      ] as [string, bigint][]
    )
      .filter(([, v]) => v > 0n)
      .map(([k, v]) => `${k} ${Math.round((100 * Number(v)) / n)}%`);
    c.title = `${fmtAddr(hit.addr)} ${b.block}\n${parts.join(", ")}\nentropy ${b.entropy.toFixed(2)} bits/byte\nClick to go there`;
  }

  draw() {
    const dpr = window.devicePixelRatio || 1;
    const colors = this.dark ? KIND_COLORS.dark : KIND_COLORS.light;
    for (const [c, entropy] of [
      [this.kindCanvas, false],
      [this.entropyCanvas, true],
    ] as const) {
      const w = Math.max(1, Math.round(c.clientWidth * dpr));
      const hgt = Math.max(1, Math.round(c.clientHeight * dpr));
      if (c.width !== w || c.height !== hgt) {
        c.width = w;
        c.height = hgt;
      }
      const ctx = c.getContext("2d");
      if (!ctx) continue;
      ctx.fillStyle = this.dark ? "#10141b" : "#ffffff";
      ctx.fillRect(0, 0, w, hgt);
      if (!this.total) continue;
      // Each device pixel row: the bucket there (several buckets on one row:
      // the one that covers most of it; code and externals win ties).
      for (let y = 0; y < hgt; y++) {
        const hit = this.at((y + 0.5) / hgt);
        if (!hit) continue;
        ctx.fillStyle = entropy ? (hit.b.kind === ByteKind.UNINITIALIZED ? colors[ByteKind.UNINITIALIZED] : entropyColor(hit.b.entropy, this.dark)) : (colors[hit.b.kind] ?? colors[ByteKind.UNDEFINED]);
        ctx.fillRect(0, y, w, 1);
      }
      // Block boundaries: a thin rule.
      ctx.fillStyle = this.dark ? "rgba(255,255,255,0.25)" : "rgba(0,0,0,0.25)";
      let prev = "";
      for (let i = 0; i < this.buckets.length; i++) {
        if (this.buckets[i].block !== prev && i > 0) ctx.fillRect(0, Math.round((this.before[i] / this.total) * hgt), w, Math.max(1, Math.round(dpr)));
        prev = this.buckets[i].block;
      }
      if (this.cursor !== null) {
        const f = this.fracOf(this.cursor);
        if (f !== null) {
          ctx.fillStyle = this.dark ? "#ffd54f" : "#9a6700";
          ctx.fillRect(0, Math.round(f * hgt) - Math.round(dpr), w, Math.max(2, Math.round(2 * dpr)));
        }
      }
    }
  }

  /** What the bars show (tests): the slices, and the y fraction of an address. */
  state() {
    return {
      buckets: this.buckets.map((b) => ({ start: (b.start?.offset ?? 0n).toString(16), length: Number(b.length), kind: KIND_TEXT[b.kind] ?? "", entropy: b.entropy, block: b.block })),
      total: this.total,
      cursorFrac: this.cursor === null ? null : this.fracOf(this.cursor),
    };
  }

  /** Where an address is drawn on the kind bar, in client coordinates (tests). */
  pointOf(a: bigint): { x: number; y: number } | null {
    const f = this.fracOf(a);
    if (f === null) return null;
    const r = this.kindCanvas.getBoundingClientRect();
    return { x: r.left + r.width / 2, y: r.top + f * r.height };
  }
}
