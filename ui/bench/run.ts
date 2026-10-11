// Playwright benchmark runner.
//
//   tsx bench/run.ts --engines chromium,webkit,firefox --dpr 1,2 \
//       --base http://127.0.0.1:50052 --out bench/raw/docker.json [--query render=rowcache]
//
// Expects rk-daemon serving a program and the built bundle at --base
// (npm run build; rk-daemon --no-auth --open <binary>). The page runs with
// dpr=native so the DPR fallback doesn't change what is measured (pass
// --query dpr=auto to measure with it). Engines:
//   chromium            Playwright's Chromium, new headless (full browser)
//   chromium-uncapped   same, with vsync and the frame-rate limit disabled, so
//                       rAF deltas measure real frame cost instead of 16.7 ms
//   chromium-shell      chromium-headless-shell (Playwright's default headless)
//   webkit              Playwright's WebKit (stand-in for WebKitGTK)
//   firefox             Playwright's Firefox
//   chrome              /usr/bin/google-chrome, headless
//   chrome-gpu          same, on the hardware GPU (--enable-gpu --ignore-gpu-blocklist)
//   chrome-uncapped     host Chrome, software, uncapped
//   chrome-gpu-uncapped host Chrome, GPU, uncapped

import { chromium, firefox, webkit, type Browser, type BrowserType } from "playwright";
import { mkdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { SCENARIOS } from "../src/bench/scenarios";

const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i].replace(/^--/, ""), process.argv[i + 1]);
const engines = (args.get("engines") ?? "chromium,webkit,firefox").split(",");
const dprs = (args.get("dpr") ?? "1,2").split(",").map(Number);
const base = args.get("base") ?? "http://127.0.0.1:50052";
const out = args.get("out") ?? "bench/raw/run.json";
const query = args.get("query") ?? "dpr=native";
const only = args.get("only")?.split(",");
const host = args.get("host") ?? os.hostname();

const UNCAP = ["--disable-gpu-vsync", "--disable-frame-rate-limit"];

interface EngineSpec {
  type: BrowserType;
  launch: Parameters<BrowserType["launch"]>[0];
  note: string;
}

function spec(name: string): EngineSpec {
  switch (name) {
    case "chromium":
      // channel "chromium" = full Chromium in new-headless mode (same
      // rendering pipeline as headed Chrome), not chromium-headless-shell.
      return { type: chromium, launch: { channel: "chromium" }, note: "Playwright Chromium (new headless)" };
    case "chromium-uncapped":
      return { type: chromium, launch: { channel: "chromium", args: UNCAP }, note: "Playwright Chromium (new headless), vsync/frame-rate limit off" };
    case "chromium-shell":
      return { type: chromium, launch: {}, note: "Playwright chromium-headless-shell" };
    case "webkit":
      return { type: webkit, launch: {}, note: "Playwright WebKit headless" };
    case "firefox":
      return { type: firefox, launch: {}, note: "Playwright Firefox headless" };
    case "chrome":
      return { type: chromium, launch: { executablePath: "/usr/bin/google-chrome" }, note: "host Google Chrome headless" };
    case "chrome-uncapped":
      return { type: chromium, launch: { executablePath: "/usr/bin/google-chrome", args: UNCAP }, note: "host Google Chrome headless, uncapped" };
    case "chrome-gpu":
      return {
        type: chromium,
        launch: {
          executablePath: "/usr/bin/google-chrome",
          args: ["--enable-gpu", "--ignore-gpu-blocklist"],
        },
        note: "host Google Chrome headless on the hardware GPU (--enable-gpu --ignore-gpu-blocklist)",
      };
    case "chrome-gpu-uncapped":
      return {
        type: chromium,
        launch: { executablePath: "/usr/bin/google-chrome", args: ["--enable-gpu", "--ignore-gpu-blocklist", ...UNCAP] },
        note: "host Google Chrome headless on the hardware GPU, uncapped",
      };
    default:
      throw new Error(`unknown engine ${name}`);
  }
}

async function gpuStatus(browser: Browser): Promise<string | undefined> {
  try {
    const p = await browser.newPage();
    await p.goto("chrome://gpu", { timeout: 10000 });
    await p.waitForTimeout(1500);
    // A string, not a function: tsx's keepNames helper (__name) doesn't exist in the page.
    const text: string = await p.evaluate(`(() => {
      const walk = (n) => {
        let s = "";
        if (n.nodeType === 3) s += n.textContent;
        if (n.shadowRoot) s += walk(n.shadowRoot);
        for (const c of n.childNodes) s += walk(c) + (c.nodeType === 1 ? "\\n" : "");
        return s;
      };
      return walk(document.body);
    })()`);
    await p.close();
    const lines = text
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && l !== "*");
    const a = lines.findIndex((l) => l === "Canvas:");
    const b = lines.findIndex((l) => l === "Video Decode:");
    if (a < 0) return undefined;
    const kv: string[] = [];
    for (let i = a; i < (b > a ? b : a + 20); i += 2) kv.push(`${lines[i]} ${lines[i + 1]}`);
    return kv.join("; ");
  } catch (e) {
    console.log("  chrome://gpu unavailable:", String(e).split("\n")[0]);
    return undefined;
  }
}

async function main() {
  const runs: unknown[] = [];
  for (const name of engines) {
    const s = spec(name);
    const browser = await s.type.launch(s.launch);
    const version = browser.version();
    const gpu = s.type === chromium ? await gpuStatus(browser) : undefined;
    console.log(`== ${name} ${version}`);
    for (const dpr of dprs) {
      const ctx = await browser.newContext({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: dpr });
      const page = await ctx.newPage();
      page.on("pageerror", (e) => console.log("  pageerror:", e.message));
      const url = `${base}/?theme=dark${query ? "&" + query : ""}`;
      await page.goto(url);
      await page.waitForSelector("body[data-ready='1']", { timeout: 30000 });
      // Let the random-jumps targets (sampled function entries) and first pages land.
      await page.waitForFunction("window.__revkit.app.jumpTargets.length > 0", undefined, { timeout: 30000 });
      const t0 = Date.now();
      const res = await page.evaluate((o) => (window as any).__bench.runAll(o), only);
      for (const r of res.results) {
        const f = (d: any) => `${d.median.toFixed(1)}/${d.p95.toFixed(1)}/${d.p99.toFixed(1)}`;
        console.log(
          `  dpr${dpr} ${r.id.padEnd(15)} delta ${f(r.delta)}  render ${f(r.render)}  cost ${f(r.cost)}  drop ${r.droppedPct}%  blank ${r.blankFramePct}%  stale ${r.staleFramePct}%`,
        );
      }
      runs.push({
        engine: name,
        note: s.note,
        version,
        gpuStatus: gpu ?? null,
        dpr,
        url,
        wallMs: Date.now() - t0,
        loadavg: os.loadavg().map((x) => Math.round(x * 10) / 10),
        ...res,
      });
      await ctx.close();
    }
    await browser.close();
  }
  const doc = {
    generatedAt: new Date().toISOString(),
    host,
    machine: {
      cpus: os.cpus().length,
      cpuModel: os.cpus()[0]?.model,
      memGB: Math.round(os.totalmem() / 2 ** 30),
      platform: `${os.type()} ${os.release()}`,
      inDocker: process.env.IN_DOCKER === "1",
    },
    query,
    scenarios: SCENARIOS,
    runs,
  };
  await mkdir(path.dirname(out), { recursive: true });
  await writeFile(out, JSON.stringify(doc, null, 2));
  console.log(`wrote ${out}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
