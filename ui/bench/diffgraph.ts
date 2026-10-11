// Graph diff benchmark: the generated 2,000-block function of bench/graph.ts
// in two versions (B changes every 50th if's constant, inserts a statement
// every 200 and drops one every 300), served by a real rk-daemon and shown
// in Compare's graph diff. Measures GetFunctionDiff with detail (the
// correlation, cold and memoized), ELK's layout of the union graph, and
// frame times while it is panned and zoomed, side by side and merged.
//
//   npm run build
//   RK_DAEMON=../build/tools/rk-daemon/rk-daemon npx tsx bench/diffgraph.ts [--engines chrome,chrome-uncapped] [--dpr 1] [--ifs 900]

import { chromium, type Browser } from "playwright";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const ui = path.resolve(here, "..");
const root = path.resolve(ui, "..");
const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i].replace(/^--/, ""), process.argv[i + 1]);
const engines = (args.get("engines") ?? "chrome,chrome-uncapped").split(",");
const dprs = (args.get("dpr") ?? "1").split(",").map(Number);
const ifs = Number(args.get("ifs") ?? 900);

function program(n: number, v2: boolean): string {
  const l = ["#include <stdio.h>", "__attribute__((noinline)) int big(int x, int *a) {", "  int r = 0;"];
  for (let k = 0; k < n; k++) {
    if (v2 && k % 300 === 150) continue;
    if (v2 && k % 200 === 100) l.push(`  r ^= a[${k % 32}] + ${k};`);
    const c = v2 && k % 50 === 7 ? k + 1 : k;
    if (k % 10 === 9) l.push(`  for (int i${k} = 0; i${k} < (x & ${(k % 7) + 1}); i${k}++) r += a[i${k}] ^ ${c};`);
    else if (k % 25 === 24) l.push(`  switch ((x + r) & 7) { case 0: r += ${c}; break; case 1: r -= a[1]; break; case 2: r ^= ${k}; break; case 3: a[3] = r; break; case 5: r *= 3; break; default: r++; }`);
    else l.push(`  if (a[${k % 32}] > ${c}) { r += a[${(k * 7) % 32}]; a[${k % 32}] = r; }`);
  }
  l.push("  return r;", "}", 'int main(int argc, char **argv) { int a[32] = {0}; a[0] = argc; printf("%d\\n", big(argc, a)); return 0; }');
  return l.join("\n") + "\n";
}

const UNCAP = ["--disable-gpu-vsync", "--disable-frame-rate-limit"];
const tmp = mkdtempSync(path.join(tmpdir(), "rk-diffgraph-"));
let daemon: ChildProcess | null = null;

async function start(exes: string[]): Promise<string> {
  const bin = process.env.RK_DAEMON ?? path.join(root, "build/tools/rk-daemon/rk-daemon");
  const web = process.env.RK_WEB_ROOT ?? path.join(ui, "dist");
  const ports = path.join(tmp, "ports.json");
  daemon = spawn(bin, [...exes.flatMap((e) => ["--open", e]), "--grpc", "127.0.0.1:0", "--http", "127.0.0.1:0", "--web-root", web, "--port-file", ports, "--no-auth"], { stdio: ["ignore", "ignore", "inherit"] });
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

async function rpc(base: string, method: string, body: unknown) {
  const r = await fetch(`${base}/revkit.v1.${method}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`${method}: ${r.status} ${await r.text()}`);
  return r.json();
}

const DRIVE = `async ({ mode, frames }) => {
  const g = window.__revkit.app.diff.graph;
  const renders = [];
  g.onFrame = (ms) => renders.push(ms);
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
      const t = (1 - Math.cos((i / frames) * 2 * Math.PI)) / 2;
      g.zoomTo(Math.exp(Math.log(sFit) + (Math.log(1.2) - Math.log(sFit)) * t), g.canvas.clientWidth / 2, g.canvas.clientHeight / 2);
    }
  }
  g.onFrame = null;
  return { times: times.slice(2), renders: renders.slice(2) };
}`;

async function main() {
  const exes: string[] = [];
  for (const v of [1, 2]) {
    const src = path.join(tmp, `big${v}.c`);
    const exe = path.join(tmp, `big${v}`);
    writeFileSync(src, program(ifs, v === 2));
    execFileSync(process.env.CC ?? "cc", ["-O0", "-o", exe, src]);
    exes.push(exe);
  }
  const base = await start(exes);
  const sym = async (prog: string) => BigInt((await rpc(base, "QueryService/ListSymbols", { programId: prog, nameEquals: "big" })).symbols[0].address.offset);
  const a = await sym("default/big1"), b = await sym("default/big2");
  const s = await rpc(base, "DiffService/CreateDiffSession", { projectId: "default", programA: "default/big1", programB: "default/big2", run: true });
  const sessionId = s.session.sessionId;
  for (let i = 0; i < 600; i++) {
    const st = await rpc(base, "DiffService/GetDiffStatus", { projectId: "default", sessionId });
    if (st.session.run?.state !== "DIFF_RUN_STATE_RUNNING") break;
    await new Promise((r) => setTimeout(r, 100));
  }
  const ms: number[] = [];
  let d: any = null;
  for (let i = 0; i < 4; i++) {
    const t0 = performance.now();
    d = (await rpc(base, "DiffService/GetFunctionDiff", { projectId: "default", sessionId, entryA: { offset: String(a) }, entryB: { offset: String(b) }, detail: true, omitBytes: true })).detail;
    ms.push(performance.now() - t0);
  }
  console.log(`big: ${d.blocksA.length} / ${d.blocksB.length} blocks, ${d.rowsA.length} / ${d.rowsB.length} instructions; ${d.summary.text}`);
  console.log(`GetFunctionDiff with detail (JSON): cold ${ms[0].toFixed(0)} ms (correlate ${(d.correlateMs ?? 0).toFixed?.(1)}), warm ${pct(ms.slice(1), 50).toFixed(0)} ms`);
  for (const engine of engines)
    for (const dpr of dprs) {
      const browser: Browser = await chromium.launch({ executablePath: "/usr/bin/google-chrome", args: engine.endsWith("uncapped") ? UNCAP : [] });
      const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: dpr });
      const p = await ctx.newPage();
      await p.goto(`${base}/?program=default%2Fbig2&dpr=native`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 30000 });
      await p.evaluate("window.__revkit.app.showView('diff')");
      await p.waitForFunction("window.__revkit.app.diff.session !== null", undefined, { timeout: 30000 });
      for (const merged of [false, true]) {
        await p.evaluate(`window.__revkit.app.diff.setLower("graph"); window.__revkit.app.diff.graph.setMerged(${merged})`);
        const t0 = Date.now();
        const open = await p.evaluate(`(async () => { const t0 = performance.now(); await window.__revkit.app.diff.openPair(${a}n, ${b}n); return performance.now() - t0; })()`);
        await p.waitForFunction(`window.__revkit.app.diff.graph.describe().nodes.length > 0 && window.__revkit.app.diff.graph.describe().layoutMs > 0`, undefined, { timeout: 120000 });
        const shown = Date.now() - t0;
        if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `diffgraph-${merged ? "merged" : "split"}.png`) });
        const desc = (await p.evaluate("window.__revkit.app.diff.graph.describe()")) as { nodes: unknown[]; layoutMs: number };
        const row: Record<string, unknown> = { engine, dpr, mode: merged ? "merged" : "side by side", nodes: desc.nodes.length, layoutMs: Math.round(desc.layoutMs), openMs: Math.round(open as number), shownMs: shown };
        for (const m of ["fit", "pan", "zoom"]) {
          const r = (await p.evaluate(`(${DRIVE})({ mode: "${m}", frames: 150 })`)) as { times: number[]; renders: number[] };
          row[m] = { frameP50: +pct(r.times, 50).toFixed(1), frameP95: +pct(r.times, 95).toFixed(1), renderP50: +pct(r.renders, 50).toFixed(2), renderP95: +pct(r.renders, 95).toFixed(2) };
        }
        console.log(JSON.stringify(row));
      }
      await browser.close();
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
