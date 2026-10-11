// Rendering fallback for engines without GPU compositing.
//
// WebKitGTK (Tauri's engine on Linux) falls back to painting on the CPU
// without compositing when it has no usable GPU path (no DRI3, VMs, remote
// X, WEBKIT_DISABLE_COMPOSITING_MODE=1). There, a full-window canvas at
// device pixel ratio 2 costs ~17 ms per frame before anything is drawn
// (bench/RESULTS.md), so the listing runs at 50-54 fps instead of 60. The
// engine doesn't say which path it took, but it shows: time the idle frame
// cadence, then the real listing redraw, and when redraws at DPR > 1 miss
// vsync, render the canvas at DPR 1 (the browser upscales it) and say so in
// the status bar. Comparing against the idle cadence keeps a loaded machine
// (both slow) or a 120 Hz display (both fast) from deciding it.

const raf = () => new Promise<number>((r) => requestAnimationFrame(r));

/** Median rAF interval while `paint` runs every frame. */
export async function measureFrames(paint: () => void, frames = 36, warmup = 6, timeoutMs = 4000): Promise<number> {
  const deltas: number[] = [];
  const end = performance.now() + timeoutMs;
  let last = await raf();
  for (let i = 0; i < frames + warmup && performance.now() < end; i++) {
    paint();
    const ts = await raf();
    if (i >= warmup) deltas.push(ts - last);
    last = ts;
  }
  if (!deltas.length) return 0;
  deltas.sort((a, b) => a - b);
  return deltas[Math.floor(deltas.length / 2)];
}

/** Redraws faster than this never fall back (they hold 60 Hz). */
export const BUDGET_MS = 17;

/** Redraws at `workMs` per frame miss vsync when idle frames take `idleMs`. */
export function needsFallback(workMs: number, idleMs: number, dpr: number): boolean {
  // Medians: with a 1 ms timer (WebKitGTK over tauri://) idle reads 16 and
  // a frame that misses vsync about half the time reads 17.
  return dpr > 1 && workMs > BUDGET_MS - 0.5 && workMs >= idleMs + 0.75;
}

export type DprMode = "auto" | "native" | number;

export function dprMode(param: string | null): DprMode {
  if (param === "native") return "native";
  const n = Number(param);
  if (param && Number.isFinite(n) && n > 0) return n;
  return "auto";
}
