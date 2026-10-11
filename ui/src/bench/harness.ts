// In-page benchmark harness. Playwright calls window.__bench.run(...) and gets
// back a summary. Scenarios drive the real input handlers with synthetic
// wheel/pointer events (or the same goTo the go-to box uses), one step per
// animation frame, while FrameMeter records:
//
//   delta    requestAnimationFrame timestamp deltas (what the user sees)
//   render   JS time inside the listing's render() for that frame
//   cost     rAF start -> first task after the frame (main-thread frame cost
//            including style/layout/paint/canvas flush, as far as the engine
//            does that work on the main thread)
//   blank    visible rows drawn as placeholders (data not yet arrived)
//
// plus long tasks / long animation frames where the engine reports them.

import type { ListingView, FrameStats } from "../listing/view";
import type { RowCache } from "../data/rowCache";
import { SCENARIOS } from "./scenarios";

interface Frame {
  ts: number;
  delta: number;
  renderMs: number;
  costMs: number;
  blankRows: number;
  visibleRows: number;
  rasterized: number;
  rendered: boolean;
  stale: boolean;
  lagMs: number;
}

export interface Dist {
  n: number;
  mean: number;
  median: number;
  p95: number;
  p99: number;
  max: number;
}

export interface ScenarioResult {
  scenario: string;
  params: Record<string, unknown>;
  durationMs: number;
  frames: number;
  renderedFrames: number;
  nominalIntervalMs: number;
  delta: Dist;
  render: Dist;
  cost: Dist;
  droppedPct: number;
  blankFramePct: number;
  blankRowPct: number;
  /** Frames that showed an older loaded position (content lagging the scroll). */
  staleFramePct: number;
  /** Over stale frames: how far the drawn content lagged the scroll position. */
  staleLagMs: Dist;
  rasterizedPerFrame: number;
  longTasks: { supported: boolean; count: number; totalMs: number; maxMs: number };
  longAnimationFrames: { supported: boolean; count: number; maxMs: number; maxRenderMs: number };
  fetch: { requests: number; aborted: number; meanMs: number; maxMs: number; latency: Dist };
  jumps?: { count: number; latency: Dist };
}

export function dist(xs: number[]): Dist {
  if (!xs.length) return { n: 0, mean: 0, median: 0, p95: 0, p99: 0, max: 0 };
  const s = [...xs].sort((a, b) => a - b);
  const q = (p: number) => s[Math.min(s.length - 1, Math.max(0, Math.ceil(p * s.length) - 1))];
  const r = (x: number) => Math.round(x * 1000) / 1000;
  return {
    n: s.length,
    mean: r(s.reduce((a, b) => a + b, 0) / s.length),
    median: r(q(0.5)),
    p95: r(q(0.95)),
    p99: r(q(0.99)),
    max: r(s[s.length - 1]),
  };
}

const raf = () => new Promise<number>((r) => requestAnimationFrame(r));

class FrameMeter {
  frames: Frame[] = [];
  private running = false;
  private last = 0;
  private pending: FrameStats | null = null;
  private chan = new MessageChannel();
  private costStart = 0;
  private costFrame: Frame | null = null;
  step: ((ts: number, dt: number) => void) | null = null;
  private stepDt = 16.7;
  longTasks: number[] = [];
  loafs: { duration: number; render: number }[] = [];
  private observers: PerformanceObserver[] = [];

  constructor(private view: ListingView) {
    // Fires as the first task after the frame has been produced. Input for the
    // next frame is dispatched from here, i.e. between frames, the way real
    // input arrives (dispatching it inside a rAF callback would defer the
    // view's redraw by a frame and make it render only every other frame).
    this.chan.port1.onmessage = () => {
      const f = this.costFrame;
      if (f) f.costMs = performance.now() - this.costStart;
      this.costFrame = null;
      if (f) this.step?.(f.ts, this.stepDt);
    };
  }

  start() {
    this.frames = [];
    this.longTasks = [];
    this.loafs = [];
    this.running = true;
    this.last = 0;
    this.view.onFrame = (s) => (this.pending = s);
    const types = PerformanceObserver.supportedEntryTypes ?? [];
    if (types.includes("longtask")) {
      const o = new PerformanceObserver((l) => l.getEntries().forEach((e) => this.longTasks.push(e.duration)));
      o.observe({ type: "longtask" });
      this.observers.push(o);
    }
    if (types.includes("long-animation-frame")) {
      const o = new PerformanceObserver((l) =>
        l.getEntries().forEach((e) => {
          const x = e as PerformanceEntry & { renderStart: number; styleAndLayoutStart: number };
          this.loafs.push({ duration: e.duration, render: x.renderStart ? e.startTime + e.duration - x.renderStart : 0 });
        }),
      );
      o.observe({ type: "long-animation-frame" });
      this.observers.push(o);
    }
    const tick = (ts: number) => {
      if (!this.running) return;
      requestAnimationFrame(tick);
      // Attribute the previous frame's render stats, then open a new frame.
      const prev = this.frames[this.frames.length - 1];
      if (prev && this.pending) {
        prev.renderMs = this.pending.renderMs;
        prev.blankRows = this.pending.blankRows;
        prev.visibleRows = this.pending.visibleRows;
        prev.rasterized = this.pending.rasterized;
        prev.stale = this.pending.stale;
        prev.lagMs = this.pending.lagMs;
        prev.rendered = true;
      }
      this.pending = null;
      const delta = this.last ? ts - this.last : 0;
      const dt = this.last ? delta : 16.7;
      this.last = ts;
      const f: Frame = { ts, delta, renderMs: 0, costMs: 0, blankRows: 0, visibleRows: 0, rasterized: 0, rendered: false, stale: false, lagMs: 0 };
      this.frames.push(f);
      this.costStart = performance.now();
      this.costFrame = f;
      this.stepDt = dt;
      this.chan.port2.postMessage(0);
    };
    requestAnimationFrame(tick);
  }

  async stop() {
    this.step = null;
    await raf();
    await raf();
    this.running = false;
    for (const o of this.observers) o.disconnect();
    this.observers = [];
    this.view.onFrame = null;
    // Drop the first frame (no delta) and the trailing frame (no render stats yet).
    return this.frames.slice(1, -1);
  }
}

export interface BenchDeps {
  view: ListingView;
  cache: RowCache;
  /** Addresses random-jumps picks from (function entries). */
  targets: () => bigint[];
}

export class Bench {
  private meter: FrameMeter;
  nominalIntervalMs = 16.667;

  constructor(private d: BenchDeps) {
    this.meter = new FrameMeter(d.view);
  }

  private canvasPoint(fx: number, fy: number) {
    const r = this.d.view.canvas.getBoundingClientRect();
    return { clientX: r.left + fx, clientY: r.top + fy };
  }

  private wheel(dy: number) {
    const p = this.canvasPoint(400, 300);
    this.d.view.canvas.dispatchEvent(
      new WheelEvent("wheel", { deltaY: dy, deltaMode: 0, bubbles: true, cancelable: true, ...p }),
    );
  }

  private pointer(type: string, x: number, y: number) {
    const p = this.canvasPoint(x, y);
    this.d.view.canvas.dispatchEvent(
      new PointerEvent(type, { pointerId: 1, pointerType: "mouse", isPrimary: true, bubbles: true, buttons: type === "pointerup" ? 0 : 1, ...p }),
    );
  }

  /** What the page can tell about the engine it runs in. */
  env() {
    let webgl = "unavailable";
    try {
      const gl = document.createElement("canvas").getContext("webgl");
      if (gl) {
        const ext = gl.getExtension("WEBGL_debug_renderer_info");
        webgl = ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : String(gl.getParameter(gl.RENDERER));
      }
    } catch {
      /* ignore */
    }
    // Smallest observable performance.now() step.
    let res = Infinity;
    let last = performance.now();
    for (let i = 0; i < 200000 && res > 0.0005; i++) {
      const t = performance.now();
      if (t !== last) {
        res = Math.min(res, t - last);
        last = t;
      }
    }
    return {
      userAgent: navigator.userAgent,
      devicePixelRatio: window.devicePixelRatio,
      viewport: { width: innerWidth, height: innerHeight },
      hardwareConcurrency: navigator.hardwareConcurrency,
      crossOriginIsolated: self.crossOriginIsolated ?? false,
      timerResolutionMs: Math.round(res * 10000) / 10000,
      webglRenderer: webgl,
      painter: this.d.view.painter.name,
      holdMs: this.d.view.holdMs,
      offscreenCanvas: typeof OffscreenCanvas !== "undefined",
    };
  }

  /** Every scenario in SCENARIOS, in order. */
  async runAll(only?: string[]) {
    const env = this.env();
    const nominal = await this.calibrate();
    const results: (ScenarioResult & { id: string })[] = [];
    for (const s of SCENARIOS) {
      if (only && !only.includes(s.id)) continue;
      results.push({ id: s.id, ...(await this.run(s.scenario, s.params)) });
    }
    return { env, nominalIntervalMs: nominal, results };
  }

  /** Idle rAF cadence, used to count missed vsyncs. */
  async calibrate(ms = 1000): Promise<number> {
    const ts: number[] = [];
    const end = performance.now() + ms;
    while (performance.now() < end) ts.push(await raf());
    // Mean, not median: with a 1 ms timer (WebKitGTK over tauri://) the
    // median of 16/17 ms deltas reads 16 and hides 18 ms frames.
    this.nominalIntervalMs = (ts[ts.length - 1] - ts[0]) / (ts.length - 1);
    return this.nominalIntervalMs;
  }

  /** Default start: 30 % into the listing (row 2,000,000 on the spike's 11M rows). */
  get startRow() {
    return Math.floor(this.d.view.rowCount * 0.3);
  }

  /** Put the view in a known state: fixed row, all rows loaded, settled. */
  async reset(row = this.startRow) {
    const v = this.d.view;
    v.hoverKey = null;
    v.selectedKey = null;
    v.selectedRow = -1;
    v.syncAddrs = null;
    v.canvas.dispatchEvent(new PointerEvent("pointerleave"));
    v.scrollToRow(row, "top");
    await this.settle();
  }

  async settle(maxMs = 5000) {
    const end = performance.now() + maxMs;
    const v = this.d.view;
    while (performance.now() < end) {
      let blank = 0;
      const first = Math.floor(v.topRow);
      for (let i = 0; i <= v.viewportRows; i++) if (!this.d.cache.get(first + i)) blank++;
      v.invalidate();
      await raf();
      if (!blank && this.d.cache.pendingRequests === 0) break;
    }
    for (let i = 0; i < 10; i++) await raf();
  }

  async run(name: string, params: Record<string, number> = {}): Promise<ScenarioResult> {
    await this.reset(params.startRow ?? this.startRow);
    const c = this.d.cache;
    const s0 = { ...c.stats };
    c.stats.latencies = [];
    let jumpLat: number[] | undefined;
    const t0 = performance.now();
    this.meter.start();
    switch (name) {
      case "steady":
        await this.steady(params.speed ?? 2000, params.durationMs ?? 5000);
        break;
      case "fling":
        await this.fling(params.v0 ?? 25000, params.tauMs ?? 400, params.count ?? 4);
        break;
      case "scrollbar-drag":
        await this.drag(params.durationMs ?? 4000);
        break;
      case "random-jumps":
        jumpLat = await this.jumps(params.count ?? 24, params.intervalMs ?? 250);
        break;
      case "hover-scroll":
        await this.hoverScroll(params.speed ?? 1500, params.durationMs ?? 5000);
        break;
      case "fill-baseline":
        await this.fillBaseline(params.durationMs ?? 3000);
        break;
      default:
        throw new Error(`unknown scenario ${name}`);
    }
    const frames = await this.meter.stop();
    const durationMs = performance.now() - t0;
    const I = this.nominalIntervalMs > 10 ? this.nominalIntervalMs : 1000 / 60;
    let missed = 0;
    for (const f of frames) missed += Math.max(0, Math.round(f.delta / I) - 1);
    const span = frames.reduce((a, f) => a + f.delta, 0);
    const rendered = frames.filter((f) => f.rendered);
    const visible = rendered.reduce((a, f) => a + f.visibleRows, 0);
    const blankRows = rendered.reduce((a, f) => a + f.blankRows, 0);
    const lt = this.meter.longTasks;
    const types = PerformanceObserver.supportedEntryTypes ?? [];
    const dReq = c.stats.requests - s0.requests;
    return {
      scenario: name,
      params,
      durationMs: Math.round(durationMs),
      frames: frames.length,
      renderedFrames: rendered.length,
      nominalIntervalMs: Math.round(this.nominalIntervalMs * 1000) / 1000,
      delta: dist(frames.map((f) => f.delta)),
      render: dist(rendered.map((f) => f.renderMs)),
      cost: dist(frames.map((f) => f.costMs)),
      droppedPct: span ? Math.round((missed / (span / I)) * 10000) / 100 : 0,
      blankFramePct: rendered.length ? Math.round((rendered.filter((f) => f.blankRows > 0).length / rendered.length) * 10000) / 100 : 0,
      blankRowPct: visible ? Math.round((blankRows / visible) * 10000) / 100 : 0,
      staleFramePct: rendered.length ? Math.round((rendered.filter((f) => f.stale).length / rendered.length) * 10000) / 100 : 0,
      staleLagMs: dist(rendered.filter((f) => f.stale).map((f) => f.lagMs)),
      rasterizedPerFrame: rendered.length ? Math.round((rendered.reduce((a, f) => a + f.rasterized, 0) / rendered.length) * 10) / 10 : 0,
      longTasks: {
        supported: types.includes("longtask"),
        count: lt.length,
        totalMs: Math.round(lt.reduce((a, b) => a + b, 0)),
        maxMs: Math.round(Math.max(0, ...lt)),
      },
      longAnimationFrames: {
        supported: types.includes("long-animation-frame"),
        count: this.meter.loafs.length,
        maxMs: Math.round(Math.max(0, ...this.meter.loafs.map((l) => l.duration))),
        maxRenderMs: Math.round(Math.max(0, ...this.meter.loafs.map((l) => l.render))),
      },
      fetch: {
        requests: dReq,
        aborted: c.stats.aborted - s0.aborted,
        meanMs: dReq ? Math.round(((c.stats.fetchMsTotal - s0.fetchMsTotal) / dReq) * 100) / 100 : 0,
        maxMs: Math.round(c.stats.fetchMsMax),
        latency: dist(c.stats.latencies),
      },
      ...(jumpLat ? { jumps: { count: jumpLat.length, latency: dist(jumpLat) } } : {}),
    };
  }

  private untilDone(stepFn: (elapsed: number, dt: number) => boolean): Promise<void> {
    return new Promise((resolve) => {
      let start = -1;
      this.meter.step = (ts, dt) => {
        if (start < 0) start = ts;
        if (!stepFn(ts - start, dt)) {
          this.meter.step = null;
          resolve();
        }
      };
    });
  }

  private steady(speed: number, durationMs: number) {
    return this.untilDone((t, dt) => {
      this.wheel((speed * dt) / 1000);
      return t < durationMs;
    });
  }

  private async fling(v0: number, tauMs: number, count: number) {
    for (let i = 0; i < count; i++) {
      const dir = i % 4 === 3 ? -1 : 1;
      await this.untilDone((t, dt) => {
        const v = v0 * Math.exp(-t / tauMs);
        this.wheel((dir * v * dt) / 1000);
        return v > 30;
      });
    }
  }

  private async drag(durationMs: number) {
    const v = this.d.view;
    const r = v.canvas.getBoundingClientRect();
    const x = r.width - 6;
    // Thumb starts at the reset position; grab its middle.
    const total = v.rowCount * v.rowH;
    const thumbH = Math.max(28, (r.height / total) * r.height);
    const maxScroll = total - r.height;
    const thumbY = (v.scrollY / maxScroll) * (r.height - thumbH);
    const grabY = thumbY + thumbH / 2;
    this.pointer("pointerdown", x, grabY);
    // Down to the bottom, then all the way to the top: sweeps the whole range.
    const half = durationMs / 2;
    const top = thumbH / 2;
    const bottom = r.height - thumbH / 2;
    await this.untilDone((t) => {
      let y: number;
      if (t < half) y = grabY + (bottom - grabY) * (t / half);
      else y = bottom + (top - bottom) * Math.min(1, (t - half) / half);
      this.pointer("pointermove", x, y);
      return t < durationMs;
    });
    this.pointer("pointerup", x, top);
  }

  private async jumps(count: number, intervalMs: number): Promise<number[]> {
    const targets = this.d.targets();
    if (!targets.length) throw new Error("no jump targets (functions not loaded)");
    let rnd = 12345;
    const next = () => ((rnd = (Math.imul(rnd, 1103515245) + 12345) >>> 0) / 4294967296);
    const lat: number[] = [];
    const v = this.d.view;
    const cache = this.d.cache;
    for (let i = 0; i < count; i++) {
      const addr = targets[Math.floor(next() * targets.length)];
      const t0 = performance.now();
      await v.goTo(addr, { notify: false });
      // Latency until every visible row is drawn with real data.
      for (;;) {
        await raf();
        const first = Math.floor(v.topRow);
        let blank = 0;
        for (let k = 0; k < v.viewportRows; k++) if (first + k < v.rowCount && !cache.get(first + k)) blank++;
        if (!blank) break;
      }
      lat.push(performance.now() - t0);
      const rest = intervalMs - (performance.now() - t0);
      // Keep the view busy between jumps: a small scroll each frame.
      await this.untilDone((t, dt) => {
        this.wheel((300 * dt) / 1000);
        return t < rest;
      });
    }
    return lat;
  }

  /** Control: repaint the whole listing canvas with a flat color every frame
   * and draw nothing else. Measures the engine's per-frame floor for a
   * full-viewport canvas update at this size and DPR. */
  private fillBaseline(durationMs: number) {
    const c = this.d.view.canvas;
    const ctx = c.getContext("2d")!;
    let i = 0;
    return this.untilDone((t) => {
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.fillStyle = i++ % 2 ? "#16181d" : "#181a20";
      ctx.fillRect(0, 0, c.width, c.height);
      return t < durationMs;
    });
  }

  private hoverScroll(speed: number, durationMs: number) {
    const v = this.d.view;
    // Hover over the operand column; wiggle across a few tokens.
    const cw = v.charWidth;
    const baseX = 14 + (v.cols.ops + 2) * cw;
    return this.untilDone((t, dt) => {
      const x = baseX + Math.sin(t / 180) * 6 * cw;
      this.pointer("pointermove", x, 400 + Math.sin(t / 700) * 120);
      this.wheel((speed * dt) / 1000);
      return t < durationMs;
    });
  }
}
