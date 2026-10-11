// End-to-end checks for the Python console and the script editor's
// completion (docs/ui.md, "Python console"; docs/scripting.md, "The
// console"): a statement and a block at the console bound to the program,
// current_function following the cursor, Tab completion from the live
// namespace and signature help, a console edit as one undo step with script
// provenance "console", the history on Up, Ctrl+C interrupting a statement,
// a viewer's console that reads but can't edit (an authenticated daemon
// with --scripts-host-role viewer), and the editor completing the script
// API with its signatures. run.ts calls consoleChecks().

import type { Browser, Page } from "playwright";
import { execFileSync } from "node:child_process";
import { chmodSync, writeFileSync } from "node:fs";
import path from "node:path";

interface Snap {
  address: string | null;
  decompName: string | null;
  decompText: string;
  live: string;
}

export interface ConsoleContext {
  base: string;
  tmp: string;
  browser: () => Browser;
  daemonBin: () => string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  open: (base: string) => Promise<Page>;
  palette: (p: Page, text: string) => Promise<void>;
  until: (p: Page, what: string, pred: (s: Snap) => boolean, ms?: number) => Promise<Snap>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
  timeScale: number;
  /** Another daemon on the e2e program with these flags instead of --no-auth; its base URL. */
  startDaemon: (extra: string[], portFile: string) => Promise<string>;
}

interface Last {
  input: string;
  status: string;
  more: boolean;
  stdout: string;
  stderr: string;
  seqs: string[];
  runId: string;
  error: string;
}

const last = (p: Page): Promise<Last | null> => p.evaluate("window.__revkit.app.console?.last ?? null") as Promise<Last | null>;
const count = (p: Page): Promise<number> => p.evaluate("window.__revkit.app.console?.statements ?? 0") as Promise<number>;

async function command(p: Page, query: string, title: string) {
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+Shift+P");
  await p.waitForSelector("[data-testid=palette-input]");
  await p.fill("[data-testid=palette-input]", `>${query}`);
  await p.waitForFunction((t) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").includes(t), title);
  await p.keyboard.press("Enter");
}

/** Opens the Python view and waits for the console's banner. */
async function openConsole(p: Page, ms: number) {
  await command(p, "Show Python", "Show Python");
  await p.waitForSelector("[data-testid=python-view]:not([hidden])");
  await p.waitForFunction(() => /Python \d/.test(document.querySelector("[data-testid=py-output]")?.textContent ?? ""), null, { timeout: ms });
}

/** Types `lines` at the console, Enter after each, and waits for the statement's end. */
async function stmt(p: Page, lines: string[], ms: number): Promise<Last> {
  const before = await count(p);
  await p.click("[data-testid=py-input]");
  for (const [i, line] of lines.entries()) {
    await p.keyboard.type(line);
    await p.keyboard.press("Enter");
    // An open block: the continuation prompt before the next line.
    if (i < lines.length - 1) await p.waitForFunction(() => document.querySelector("[data-testid=py-prompt]")?.textContent === "...", null, { timeout: ms });
  }
  await p.waitForFunction((n) => ((window as unknown as { __revkit: { app: { console: { statements: number } } } }).__revkit.app.console.statements ?? 0) > n, before, { timeout: ms }).catch(async (e) => {
    throw new Error(`${lines.join(" ⏎ ")}: ${e instanceof Error ? e.message : e}; output: ${(await p.textContent("[data-testid=py-output]"))?.slice(-600)}`);
  });
  return (await last(p))!;
}

/** waitForFunction with what the console and its tooltips show on failure. */
async function waitFor(p: Page, what: string, fn: () => boolean, _arg: null, ms: number) {
  await p.waitForFunction(fn, null, { timeout: ms }).catch(async (e) => {
    const state = await p.evaluate(() => ({
      input: document.querySelector("[data-testid=py-input]")?.textContent,
      prompt: document.querySelector("[data-testid=py-prompt]")?.textContent,
      tooltips: [...document.querySelectorAll(".cm-tooltip")].map((t) => t.textContent?.slice(0, 200)),
      output: document.querySelector("[data-testid=py-output]")?.textContent?.slice(-300),
    }));
    throw new Error(`${what}: ${e instanceof Error ? e.message.split("\n")[0] : e}; ${JSON.stringify(state)}`);
  });
}

export async function consoleChecks(c: ConsoleContext) {
  const { base, check, open, until, rpc, timeScale } = c;
  const assert: ConsoleContext["assert"] = c.assert;
  const ms = 30000 * timeScale;
  let a!: Page;

  await check("console: Window → Python opens a console on the program; a statement and a block; current_function follows the cursor", async () => {
    a = await open(base);
    await c.palette(a, "main");
    await until(a, "at main", (s) => s.decompName === "main" && s.live === "live");
    await openConsole(a, ms);
    let r = await stmt(a, ["x = 40 + 2"], ms);
    assert(r.status === "ok" && r.stdout === "", `x = 40 + 2: ${JSON.stringify(r)}`);
    r = await stmt(a, ["x"], ms);
    assert(r.stdout === "42\n", `x: ${JSON.stringify(r.stdout)}`);
    // A block: the continuation prompt, the indentation kept, an empty line ends it.
    r = await stmt(a, ["for i in range(2):", "print('i', i)", ""], ms);
    assert(r.status === "ok" && r.stdout === "i 0\ni 1\n", `the block: ${JSON.stringify(r)}`);
    const out = (await a.textContent("[data-testid=py-output]")) ?? "";
    assert(out.includes(">>> for i in range(2):\n...     print('i', i)"), `the echo: ${out.slice(-300)}`);
    r = await stmt(a, ["current_function.name"], ms);
    assert(r.stdout === "'main'\n", `current_function: ${r.stdout} ${r.stderr}`);
    await c.palette(a, "checksum");
    await until(a, "at checksum", (s) => s.decompName === "checksum");
    r = await stmt(a, ["current_function.name"], ms);
    assert(r.stdout === "'checksum'\n", `after moving: ${r.stdout} ${r.stderr}`);
  });

  await check("console: Tab completes from the live namespace; signature help on (; Up recalls the history", async () => {
    await stmt(a, ["console_answer = 7"], ms);
    await a.click("[data-testid=py-input]");
    await a.keyboard.type("console_ans");
    await a.keyboard.press("Tab");
    await waitFor(a, "the completion list", () => document.querySelector(".cm-tooltip-autocomplete li") !== null, null, ms);
    await a.keyboard.press("Enter");
    await waitFor(a, "the completion accepted", () => document.querySelector("[data-testid=py-input]")?.textContent === "console_answer", null, ms);
    await a.keyboard.press("Control+c"); // drops the input
    await waitFor(a, "the input dropped", () => document.querySelector("[data-testid=py-input]")?.textContent === "", null, ms);
    // A flat API function: its completion carries the signature.
    await a.keyboard.type("decompile_m");
    await a.keyboard.press("Tab");
    await waitFor(a, "decompile_many offered", () => [...document.querySelectorAll(".cm-tooltip-autocomplete li")].some((li) => li.textContent?.includes("decompile_many")), null, ms);
    await a.keyboard.press("Enter");
    await a.keyboard.type("(");
    await waitFor(a, "the signature", () => (document.querySelector("[data-testid=signature-help]")?.textContent ?? "").startsWith("decompile_many(funcs=None"), null, ms);
    await a.keyboard.press("Control+c");
    // Up: the last statement; Down: back to the (empty) draft.
    await a.keyboard.press("ArrowUp");
    await waitFor(a, "the history", () => document.querySelector("[data-testid=py-input]")?.textContent === "console_answer = 7", null, ms);
    await a.keyboard.press("ArrowDown");
    await waitFor(a, "the draft", () => document.querySelector("[data-testid=py-input]")?.textContent === "", null, ms);
  });

  await check("console: an edit is one revision with script provenance console, and one Ctrl+Z undoes it", async () => {
    await c.palette(a, "main");
    await until(a, "at main", (s) => s.decompName === "main");
    const r = await stmt(a, ["rename(current_function, 'console_named'); comment(current_address, 'from the console')"], ms);
    assert(r.status === "ok" && r.seqs.length === 2, `the edit: ${JSON.stringify(r)}`);
    await until(a, "renamed", (s) => s.decompName === "console_named", 15000);
    const la = await rpc<{ assertions?: { revision: string; provenance?: { kind?: string; id?: string; session?: string } }[] }>(base, "AssertionService/ListAssertions", {
      programId: "default/prog",
      filter: { provenance: { session: r.runId } },
    });
    const mine = (la.assertions ?? []).filter((x) => x.provenance?.id === "console");
    assert(mine.length === 2 && new Set(mine.map((x) => x.revision)).size === 1, `one revision: ${JSON.stringify(la.assertions)}`);
    assert(mine[0].provenance?.kind === "PROVENANCE_KIND_SCRIPT", `provenance ${JSON.stringify(mine[0].provenance)}`);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+z");
    await until(a, "undone", (s) => s.decompName === "main", 15000);
  });

  await check("console: Ctrl+C interrupts a running statement (KeyboardInterrupt), and the console carries on", async () => {
    const before = await count(a);
    await a.click("[data-testid=py-input]");
    await a.keyboard.type("while True: pass");
    await a.keyboard.press("Enter");
    await a.waitForFunction(() => document.querySelector("[data-testid=py-prompt]")?.textContent === "...");
    await a.keyboard.press("Enter");
    await a.waitForFunction(() => (window as unknown as { __revkit: { app: { console: { running: boolean } } } }).__revkit.app.console.running);
    await new Promise((r) => setTimeout(r, 500));
    const t0 = Date.now();
    await a.keyboard.press("Control+c");
    await a.waitForFunction((n) => (window as unknown as { __revkit: { app: { console: { statements: number } } } }).__revkit.app.console.statements > n, before, { timeout: ms });
    const r = (await last(a))!;
    assert(r.status === "interrupted" && r.stderr.includes("KeyboardInterrupt"), `interrupted: ${JSON.stringify(r)}`);
    c.log(`     (interrupted in ${Date.now() - t0} ms)`);
    const again = await stmt(a, ["console_answer * 6"], ms);
    assert(again.stdout === "42\n", `the namespace survives: ${again.stdout}`);
  });

  await check("scripts: the editor completes the script API and Ghidra's names, with signature help on (", async () => {
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+Shift+S");
    await a.waitForSelector("[data-testid=scripts-view]:not([hidden])");
    await a.click("[data-testid=scripts-new]");
    await a.waitForSelector("[data-testid=choose]");
    await a.keyboard.press("Enter"); // My scripts
    await a.waitForSelector("[data-testid=script-editor]");
    await a.click("[data-testid=script-editor-text]");
    await a.keyboard.press("Control+End");
    await a.keyboard.press("Enter");
    await a.keyboard.type("decompile_m");
    await a.waitForFunction(() => [...document.querySelectorAll(".script-editor .cm-tooltip-autocomplete li")].some((li) => li.textContent?.includes("decompile_many")), null, { timeout: ms });
    await a.keyboard.press("Enter");
    await a.keyboard.type("(");
    await a.waitForFunction(() => (document.querySelector(".script-editor [data-testid=signature-help]")?.textContent ?? "").startsWith("decompile_many(funcs=None, *, text=True"), null, { timeout: ms });
    await a.keyboard.press("Escape");
    // A member of current_program, and Ghidra's flat API.
    await a.keyboard.press("End");
    await a.keyboard.press("Enter");
    await a.keyboard.type("current_program.functi");
    await a.waitForFunction(() => [...document.querySelectorAll(".script-editor .cm-tooltip-autocomplete li")].some((li) => li.textContent?.startsWith("functions")), null, { timeout: ms });
    await a.keyboard.press("Escape");
    await a.keyboard.press("Enter");
    await a.keyboard.type("getFunctionA");
    await a.waitForFunction(() => [...document.querySelectorAll(".script-editor .cm-tooltip-autocomplete li")].some((li) => li.textContent?.includes("getFunctionAt")), null, { timeout: ms });
    await a.keyboard.press("Escape");
    await a.keyboard.press("Escape");
    await a.waitForSelector("[data-testid=choose]");
    await a.click("[data-testid=choose] .palette-item[data-value=discard]");
    await a.waitForSelector("[data-testid=script-editor]", { state: "detached" });
    await a.context().close();
  });

  await check("console: a viewer's console reads but can't edit (--scripts-host-role viewer, signed in)", async () => {
    const authFile = path.join(c.tmp, "auth-console.db");
    execFileSync(c.daemonBin(), ["user", "add", "victor", "--role", "viewer", "--password-stdin", "--auth-file", authFile], { input: "victor-password\n" });
    const secure = await c.startDaemon(["--auth-file", authFile, "--tls-self-signed", "--tls-dir", path.join(c.tmp, "tls-console"), "--scripts-host-role", "viewer"], "ports-console-auth.json");
    const ctx = await c.browser().newContext({ viewport: { width: 1500, height: 900 }, ignoreHTTPSErrors: true });
    const p = await ctx.newPage();
    await p.goto(`${secure}/?program=default%2Fprog&theme=dark`);
    await p.waitForSelector("body[data-ready='login']", { timeout: 20000 });
    await p.fill("[data-testid=login-user]", "victor");
    await p.fill("[data-testid=login-password]", "victor-password");
    await Promise.all([p.waitForEvent("load"), p.click("[data-testid=login-submit]")]);
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    await openConsole(p, ms);
    await p.waitForSelector("[data-testid=py-readonly]:not([hidden])");
    let r = await stmt(p, ["sum(1 for f in functions()) > 3"], ms);
    assert(r.stdout === "True\n", `reads: ${JSON.stringify(r)}`);
    r = await stmt(p, ["rename(function_at('main'), 'viewer_was_here')"], ms);
    assert(r.status === "error" && r.stderr.includes("read-only") && r.seqs.length === 0, `refused: ${JSON.stringify(r)}`);
    await ctx.close();
  });

  await check("console: an SDK older than the daemon says so, with Set up Python in the console and the Script Manager", async () => {
    // A Python whose revkit predates the daemon's script API (the daemon's probe exits 3).
    const stale = path.join(c.tmp, "stale-python");
    writeFileSync(stale, "#!/bin/sh\n[ \"$1\" = -c ] && exit 3\nexit 1\n");
    chmodSync(stale, 0o755);
    const old = await c.startDaemon(["--no-auth", "--script-python", stale], "ports-console-stale.json");
    const p = await c.open(old);
    await command(p, "Show Python", "Show Python");
    await p.waitForSelector("[data-testid=python-view]:not([hidden])");
    await p.waitForFunction((want) => (document.querySelector("[data-testid=py-output]")?.textContent ?? "").includes(want), `the revkit SDK in ${stale} is older than this daemon`, { timeout: ms });
    const out = (await p.textContent("[data-testid=py-output]")) ?? "";
    assert(out.includes("Set up Python (or run `rk-script setup`) to update it"), `console: ${out}`);
    assert(await p.isVisible("[data-testid=py-setup-python]"), "no Set up Python in the console");
    await command(p, "Show scripts", "Show scripts");
    await p.waitForSelector("[data-testid=scripts-setup-python]");
    await p.context().close();
  });
}
