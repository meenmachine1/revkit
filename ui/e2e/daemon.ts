// End-to-end checks for the daemon status chip (docs/ui.md, "Daemon
// status"), against a daemon of the test's own on a fixed port in
// 53900-53999 (so a second one can take its place):
//
//   - connected: green, the daemon's version and the project; the popover
//     shows the server version, the API, the uptime and the address;
//   - disconnected: the daemon is killed (SIGKILL, by its PID); the chip
//     turns red, the listing keeps its rows, and the popover offers
//     Reconnect and the command that starts the daemon with the flags it
//     ran with (copied to the clipboard);
//   - restart (feature daemon-restart): Restart daemon… in the popover, a
//     confirmation that counts the other tab, the chip restarting, then
//     green and live again on the same daemon process and port, no reload;
//   - reconnect: a new daemon on the same port with the same flags, and
//     Reconnect turns the chip green and the stream live again.
//
// run.ts calls daemonChecks().

import type { Browser, Page } from "playwright";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import path from "node:path";

export interface DaemonContext {
  browser: Browser;
  /** rk-daemon, the web bundle and a program to open. */
  bin: string;
  web: string;
  exe: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
  /** Extra environment for the daemon (the test's own config directory). */
  env: Record<string, string>;
}

/** The first port in 53900-53999 nothing listens on. */
async function freePort(): Promise<number> {
  for (let p = 53900; p < 54000; p++) {
    const ok = await new Promise<boolean>((resolve) => {
      const s = createServer();
      s.once("error", () => resolve(false));
      s.listen(p, "127.0.0.1", () => s.close(() => resolve(true)));
    });
    if (ok) return p;
  }
  throw new Error("no free port in 53900-53999");
}

async function healthy(base: string, ms: number): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try {
      const r = await fetch(`${base}/healthz`);
      if (r.ok) return;
    } catch {
      /* not yet */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`no daemon at ${base}`);
}

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

async function exited(d: ChildProcess, ms = 15000): Promise<void> {
  if (d.exitCode !== null || d.signalCode !== null) return;
  await Promise.race([new Promise((r) => d.once("exit", r)), new Promise((r) => setTimeout(r, ms))]);
}

export async function daemonChecks(c: DaemonContext) {
  const { check, log } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  // In-process decompilation: killing the daemon leaves no worker behind.
  const args = ["--open", c.exe, "--http", `127.0.0.1:${port}`, "--no-grpc", "--web-root", c.web, "--no-auth", "--decompile-in-process", "--memo-budget", "256"];
  const start = async () => {
    const d = spawn(c.bin, args, { stdio: ["ignore", "ignore", "ignore"], env: { ...process.env, ...c.env } });
    await healthy(base, 60000);
    return d;
  };
  let d: ChildProcess | null = await start();
  let page!: Page;
  const chip = () => page.evaluate("[document.getElementById('st-daemon')?.dataset.state, document.getElementById('st-daemon')?.textContent]") as Promise<[string, string]>;
  const untilChip = async (state: string, ms = 20000) => {
    await page.waitForFunction((s) => document.getElementById("st-daemon")?.dataset.state === s, state, { timeout: ms });
  };
  const text = (id: string) => page.textContent(`[data-testid=${id}]`).then((t) => t ?? "");

  try {
    await check("daemon chip: connected, green, with the daemon's version and the project; the popover's details", async () => {
      const ctx = await c.browser.newContext({ viewport: { width: 1400, height: 860 } });
      await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: base });
      page = await ctx.newPage();
      page.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await page.goto(`${base}/?program=default%2Fprog&theme=dark`);
      await page.waitForSelector("body[data-ready='1']", { timeout: 30000 });
      await untilChip("connected");
      const [, label] = await chip();
      assert(/rk-daemon \S+/.test(label) && label.includes("default"), `chip: ${label}`);
      // Bottom left: the status bar's first item.
      const box = (await page.locator("#st-daemon").boundingBox())!;
      assert(box.x < 40 && box.y > 800, `chip at ${JSON.stringify(box)}`);
      const color = await page.evaluate("getComputedStyle(document.querySelector('#st-daemon i')).backgroundColor");
      assert(color === "rgb(63, 185, 80)", `dot colour ${color}`);
      await page.click("#st-daemon");
      await page.waitForSelector("[data-testid=daemon-popover]");
      assert((await text("daemon-version")).startsWith("rk-daemon"), `version: ${await text("daemon-version")}`);
      assert(/^v1\.\d+$/.test(await text("daemon-api")), `api: ${await text("daemon-api")}`);
      assert(/^\d+ (s|min)/.test(await text("daemon-uptime")), `uptime: ${await text("daemon-uptime")}`);
      assert((await text("daemon-address")) === base, `address: ${await text("daemon-address")}`);
      await page.keyboard.press("Escape");
      await page.waitForSelector("[data-testid=daemon-popover]", { state: "detached" });
    });

    await check("daemon chip: Restart daemon… in the browser: the confirmation counts the other tab; restarting…; the same daemon (PID, port) back, live, no reload", async () => {
      // Another tab on the program: the confirmation says it will be dropped.
      const other = await page.context().newPage();
      await other.goto(`${base}/?program=default%2Fprog&theme=dark`);
      await other.waitForSelector("body[data-ready='1']", { timeout: 30000 });
      await other.waitForFunction("document.body.dataset.live === 'live'", undefined, { timeout: 20000 });
      await page.waitForFunction("document.body.dataset.live === 'live'", undefined, { timeout: 20000 });
      const pid = d!.pid;
      // Every state the chip goes through, and a marker a reload would lose.
      await page.evaluate(() => {
        const w = window as unknown as { __states: string[]; __marker: number };
        w.__states = [];
        w.__marker = 1;
        new MutationObserver(() => w.__states.push(document.getElementById("st-daemon")?.dataset.state ?? "")).observe(document.getElementById("st-daemon")!, { attributes: true, attributeFilter: ["data-state"] });
      });
      const upBefore = await page.evaluate("window.__daemon.info.uptimeSeconds") as number;
      await page.click("#st-daemon");
      await page.waitForSelector("[data-testid=daemon-restart-browser]");
      await page.click("[data-testid=daemon-restart-browser]");
      await page.waitForSelector("[data-testid=restart-confirm]");
      const others = await text("restart-others");
      assert(/^1 other connection/.test(others), `others: ${others}`);
      await shot(page, "daemon-restart-confirm");
      await page.click("[data-testid=restart-confirm-ok]");
      await page.waitForFunction(() => (window as unknown as { __states: string[] }).__states.includes("restarting"), undefined, { timeout: 10000 });
      await untilChip("connected", 60000);
      const states = (await page.evaluate("window.__states")) as string[];
      assert(states.includes("restarting"), `states: ${states}`);
      assert((await page.evaluate("window.__marker")) === 1, "the page reloaded");
      await page.waitForFunction("document.body.dataset.live === 'live'", undefined, { timeout: 20000 });
      // The same process, on the same port, started again.
      assert(d!.exitCode === null && d!.pid === pid, `daemon process: exit ${d!.exitCode}`);
      const up = (await page.evaluate("window.__revkit.rk.meta.getServerInfo({}).then((r) => Number(r.uptimeSeconds))")) as number;
      assert(up < 30 && up <= upBefore + 30, `uptime ${upBefore} -> ${up}`);
      const n = (await page.evaluate("window.__revkit.rk.projects.listProjects({}).then((r) => r.projects.length)")) as number;
      assert(n >= 1, `projects: ${n}`);
      // The other tab is back too.
      await other.waitForFunction(() => document.getElementById("st-daemon")?.dataset.state === "connected", undefined, { timeout: 30000 });
      await other.waitForFunction("document.body.dataset.live === 'live'", undefined, { timeout: 30000 });
      await other.close();
    });

    await check("daemon chip: the daemon killed, red; the listing stays; Reconnect and the start command with its flags", async () => {
      const rowsBefore = ((await page.evaluate("window.__revkit.app.visibleRows()")) as unknown[]).length;
      d!.kill("SIGKILL");
      await exited(d!);
      d = null;
      await untilChip("disconnected");
      const [, label] = await chip();
      assert(label.includes("disconnected"), `chip: ${label}`);
      const color = await page.evaluate("getComputedStyle(document.querySelector('#st-daemon i')).backgroundColor");
      assert(color === "rgb(248, 81, 73)", `dot colour ${color}`);
      assert(await page.isVisible("[data-testid=daemon-action]"), "no Reconnect beside the chip");
      assert((await text("daemon-action")) === "Reconnect", `action: ${await text("daemon-action")}`);
      // What was loaded stays: the page is still there, with its rows.
      const rowsAfter = ((await page.evaluate("window.__revkit.app.visibleRows()")) as unknown[]).length;
      assert(rowsAfter > 0 && rowsAfter === rowsBefore, `rows ${rowsBefore} -> ${rowsAfter}`);
      assert((await page.getAttribute("body", "data-ready")) === "1", "the page was replaced");
      // A call now says why it fails.
      const err = (await page.evaluate("window.__revkit.rk.projects.listProjects({}).then(() => 'ok', (e) => e.message)")) as string;
      assert(err.includes("daemon is disconnected"), `error: ${err}`);
      await page.click("#st-daemon");
      await page.waitForSelector("[data-testid=daemon-start-cmd]");
      const cmd = await text("daemon-start-cmd");
      for (const a of args) assert(cmd.includes(a), `start command lacks ${a}: ${cmd}`);
      assert(cmd.startsWith(c.bin), `start command: ${cmd}`);
      await page.click("[data-testid=daemon-copy]");
      await page.waitForSelector("[data-testid=daemon-copy][data-copied]");
      const clip = (await page.evaluate("navigator.clipboard.readText()")) as string;
      assert(clip === cmd, `clipboard: ${clip}`);
      assert(await page.isVisible("[data-testid=daemon-reconnect]"), "no Reconnect in the popover");
    });

    await check("daemon chip: Reconnect once a daemon is back on the address; green and live again", async () => {
      // Reconnect while it is still down: stays red.
      await page.click("[data-testid=daemon-reconnect]");
      await untilChip("disconnected", 10000);
      d = await start();
      await page.click("[data-testid=daemon-reconnect]");
      await untilChip("connected", 10000);
      await page.waitForFunction("document.body.dataset.live === 'live'", undefined, { timeout: 20000 });
      // The new daemon's uptime: seconds.
      assert(/^\d+ s$/.test(await text("daemon-uptime")), `uptime: ${await text("daemon-uptime")}`);
      const [, label] = await chip();
      assert(label.includes("default"), `chip: ${label}`);
      assert(!(await page.isVisible("[data-testid=daemon-action]")), "Reconnect still beside the chip");
      // Calls work again.
      const n = (await page.evaluate("window.__revkit.rk.projects.listProjects({}).then((r) => r.projects.length)")) as number;
      assert(n >= 1, `projects: ${n}`);
      await page.context().close();
    });
  } finally {
    if (d && d.exitCode === null) {
      d.kill("SIGTERM");
      await exited(d);
    }
  }
}
