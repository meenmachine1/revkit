// Function-graph benchmark: a generated function of about 2,000 basic
// blocks (ifs, loops, switches; cc -O0), served by a real rk-daemon and
// shown in the UI's graph view. Measures the daemon's GetFunctionGraph,
// ELK's layout (in its worker), and frame times while the graph is panned
// and zoomed: fitted (every block on screen, drawn as boxes), at 1:1
// (text), and a zoom sweep between the two (both levels of detail).
//
//   npm run build
//   RK_DAEMON=../build/tools/rk-daemon/rk-daemon npx tsx bench/graph.ts [--engines chrome,chrome-uncapped] [--dpr 1,2] [--ifs 900] [--out bench/raw/graph.json]
//
// Frame time is the rAF interval while the view redraws every frame
// (capped engines land on vsync: 16.7 ms is "every frame"); render is the
// JS time in CfgView.render().

import { chromium, type Browser } from "playwright";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const ui = path.resolve(here, "..");
const root = path.resolve(ui, "..");
const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i].replace(/^--/, ""), process.argv[i + 1]);
const engines = (args.get("engines") ?? "chrome,chrome-uncapped").split(",");
const dprs = (args.get("dpr") ?? "1,2").split(",").map(Number);
const ifs = Number(args.get("ifs") ?? 900);
const out = args.get("out");

function program(n: number): string {
  const l = ["#include <stdio.h>", "__attribute__((noinline)) int big(int x, int *a) {", "  int r = 0;"];
  for (let k = 0; k < n; k++) {
    if (k % 10 === 9) l.push(`  for (int i${k} = 0; i${k} < (x & ${(k % 7) + 1}); i${k}++) r += a[i${k}] ^ ${k};`);
    else if (k % 25 === 24) l.push(`  switch ((x + r) & 7) { case 0: r += ${k}; break; case 1: r -= a[1]; break; case 2: r ^= ${k}; break; case 3: a[3] = r; break; case 5: r *= 3; break; default: r++; }`);
    else l.push(`  if (a[${k % 32}] > ${k}) { r += a[${(k * 7) % 32}]; a[${k % 32}] = r; }`);
  }
  l.push("  return r;", "}", 'int main(int argc, char **argv) { int a[32] = {0}; a[0] = argc; printf("%d\\n", big(argc, a)); return 0; }');
  return l.join("\n") + "\n";
}

const UNCAP = ["--disable-gpu-vsync", "--disable-frame-rate-limit"];
const tmp = mkdtempSync(path.join(tmpdir(), "rk-graph-"));
let daemon: ChildProcess | null = null;

async function start(exe: string): Promise<string> {
  const bin = process.env.RK_DAEMON ?? path.join(root, "build/tools/rk-daemon/rk-daemon");
  const web = process.env.RK_WEB_ROOT ?? path.join(ui, "dist");
  const ports = path.join(tmp, "ports.json");
  daemon = spawn(bin, ["--open", exe, "--grpc", "127.0.0.1:0", "--http", "127.0.0.1:0", "--web-root", web, "--port-file", ports, "--no-auth"], { stdio: ["ignore", "ignore", "inherit"] });
  for (let i = 0; i < 600; i++) {
    if (existsSync(ports)) {
      try {
        return `http://127.0.0.1:${JSON.parse(readFileSync(ports, "utf8")).http}`;
      } catch {
        /* partial */
      }
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("rk-daemon did not start");
}

const pct = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length ? s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))] : 0;
};

// Runs in the page: drives the graph for `frames` frames, one step per
// frame, and returns rAF intervals and render times.
const DRIVE = `async ({ mode, frames }) => {
  const g = window.__revkit.app.graph;
  const renders = [];
  g.onFrame = (s) => renders.push(s.renderMs);
  g.fit();
  const sFit = g.scale;
  if (mode !== "fit") g.zoomTo(1, g.canvas.clientWidth / 2, g.canvas.clientHeight / 3);
  await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  renders.length = 0;
  const times = [];
  let last = performance.now();
  for (let i = 0; i < frames; i++) {
    await new Promise((r) => requestAnimationFrame(r));
    const now = performance.now();
    times.push(now - last);
    last = now;
    if (mode === "fit") g.panBy(i % 40 < 20 ? 6 : -6, i % 60 < 30 ? 4 : -4);
    else if (mode === "pan") g.panBy(0, -14);
    else {
      // From fitted (boxes) to 1.2 (text) and back, through both levels of detail.
      const t = (1 - Math.cos((i / frames) * 2 * Math.PI)) / 2;
      g.zoomTo(Math.exp(Math.log(sFit) + (Math.log(1.2) - Math.log(sFit)) * t), g.canvas.clientWidth / 2, g.canvas.clientHeight / 2);
    }
  }
  g.onFrame = null;
  return { times: times.slice(2), renders: renders.slice(2) };
}`;

async function main() {
  const src = path.join(tmp, "big.c");
  const exe = path.join(tmp, "big");
  writeFileSync(src, program(ifs));
  execFileSync(process.env.CC ?? "cc", ["-O0", "-o", exe, src]);
  const base = await start(exe);
  const sym = await (await fetch(`${base}/revkit.v1.QueryService/ListSymbols`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ programId: "default/big", nameEquals: "big" }) })).json();
  const entry = BigInt(sym.symbols[0].address.offset);
  // The daemon alone: GetFunctionGraph, cold and warm.
  const rpcMs: number[] = [];
  let blocks = 0, edges = 0, insns = 0;
  for (let i = 0; i < 5; i++) {
    const t0 = performance.now();
    const r = await (await fetch(`${base}/revkit.v1.QueryService/GetFunctionGraph`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ programId: "default/big", function: { offset: String(entry) }, omitBytes: true }) })).json();
    rpcMs.push(performance.now() - t0);
    blocks = r.blocks.length;
    edges = r.edges.length;
    insns = r.blocks.reduce((m: number, b: { rows: unknown[] }) => m + b.rows.length, 0);
  }
  console.log(`function big: ${blocks} blocks, ${edges} edges, ${insns} instructions; GetFunctionGraph (JSON) cold ${rpcMs[0].toFixed(0)} ms, warm median ${pct(rpcMs.slice(1), 50).toFixed(0)} ms`);
  const results: unknown[] = [];
  for (const engine of engines)
    for (const dpr of dprs) {
      const browser: Browser = await chromium.launch({ executablePath: "/usr/bin/google-chrome", args: engine.endsWith("uncapped") ? UNCAP : [] });
      const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: dpr });
      const p = await ctx.newPage();
      await p.goto(`${base}/?program=default%2Fbig&dpr=native#${entry.toString(16)}`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 30000 });
      const t0 = Date.now();
      await p.evaluate("window.__revkit.app.showView('graph')");
      await p.waitForFunction(`(window.__revkit.app.graph.describe().blocks.length || 0) >= ${blocks}`, undefined, { timeout: 120000 });
      const shown = Date.now() - t0;
      const stats = (await p.evaluate("window.__revkit.app.graph.stats")) as { layoutMs: number; fetchMs: number };
      const row: Record<string, unknown> = { engine, dpr, blocks, edges, instructions: insns, fetchMs: Math.round(stats.fetchMs), layoutMs: Math.round(stats.layoutMs), shownMs: shown };
      for (const mode of ["fit", "pan", "zoom"]) {
        const r = (await p.evaluate(`(${DRIVE})({ mode: "${mode}", frames: 150 })`)) as { times: number[]; renders: number[] };
        row[mode] = { frameP50: +pct(r.times, 50).toFixed(1), frameP95: +pct(r.times, 95).toFixed(1), renderP50: +pct(r.renders, 50).toFixed(2), renderP95: +pct(r.renders, 95).toFixed(2), frames: r.times.length };
      }
      console.log(JSON.stringify(row));
      results.push(row);
      await browser.close();
    }
  if (out) {
    mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
    writeFileSync(out, JSON.stringify({ date: new Date().toISOString(), ifs, results }, null, 2));
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(() => {
    daemon?.kill("SIGTERM");
    rmSync(tmp, { recursive: true, force: true });
  });
