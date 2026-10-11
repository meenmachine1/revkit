// End-to-end checks for scripts in the UI (docs/scripting.md, phase 2): a
// shipped starter run from the palette answers its ask_choice prompt in the
// standard chooser and shows progress; its edits are one revision with
// script provenance, seen live in a second page and undone in one Ctrl+Z;
// a per-user script needs the trust confirmation (source and hash) once,
// and Cancel ends it within two seconds; an @context function script runs
// from the listing's right-click menu on the function there; and a daemon
// with no Python sets one up from the Script Manager in one click. run.ts
// calls scriptsChecks() with a daemon whose $XDG_CONFIG_HOME is `configDir`.

import type { Page } from "playwright";
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

interface Snap {
  address: string | null;
  decompName: string | null;
  decompText: string;
  live: string;
}

export interface ScriptsContext {
  base: string;
  /** The daemon's $XDG_CONFIG_HOME (user scripts in revkit/scripts). */
  configDir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  /** A new page on the e2e program (default/prog), once ready. */
  open: (base: string) => Promise<Page>;
  /** Goes to a symbol or address through the palette. */
  palette: (p: Page, text: string) => Promise<void>;
  until: (p: Page, what: string, pred: (s: Snap) => boolean, ms?: number) => Promise<Snap>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
  timeScale: number;
  /** Another daemon on the e2e program with `env` added; its base URL. */
  startDaemon: (env: Record<string, string>, portFile: string) => Promise<string>;
}

// Stand-ins for python3 and the venv it makes (as in
// sdk/python/tests/test_script_service.py), so "Set up Python" runs its real
// steps with no network: "-m venv DIR" makes DIR/bin/python, which
// "installs" what pip is given and then imports revkit.script.worker.
const FAKE_PYTHON3 = `#!/bin/sh
PATH=/usr/bin:/bin
if [ "$1" = -m ] && [ "$2" = venv ]; then
  mkdir -p "$3/bin" && cp "$(dirname "$0")/venv-python" "$3/bin/python" && echo "made $3"
  exit 0
fi
exit 1
`;
const FAKE_VENV_PYTHON = `#!/bin/sh
PATH=/usr/bin:/bin
here=$(dirname "$0")
case "$1 $2" in
  "-m pip") echo "Successfully installed revkit"; touch "$here/../installed"; exit 0 ;;
esac
# The daemon's probe: a program that imports revkit.script.worker (and checks SCRIPT_API).
case "$1" in
  -c) case "$2" in *revkit.script.worker*) [ -f "$here/../installed" ]; exit $? ;; esac ;;
esac
exit 1
`;

interface Last {
  scriptId: string;
  runId: string;
  status: string;
  seqs: string[];
  output: string;
  error: string;
}

const SLOW = `# @category Tests
# @description Counts slowly until cancelled
import time

monitor.set_max(2000)
for i in range(2000):
    monitor.increment()
    print("tick", i)
    time.sleep(0.05)
`;

const last = (p: Page): Promise<Last | null> => p.evaluate("window.__revkit.app.scripts?.last ?? null") as Promise<Last | null>;

/** Runs a palette command whose title contains `title`. */
async function command(p: Page, query: string, title: string) {
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+Shift+P");
  await p.waitForSelector("[data-testid=palette-input]");
  await p.fill("[data-testid=palette-input]", `>${query}`);
  await p.waitForFunction((t) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").includes(t), title);
  await p.keyboard.press("Enter");
}

async function untilDone(p: Page, what: string, ms: number): Promise<Last> {
  await p.waitForSelector("[data-testid=script-output]:not([data-status=running])", { timeout: ms }).catch(async (e) => {
    const out = await p.textContent("[data-testid=script-output]").catch(() => "");
    throw new Error(`${what}: ${e instanceof Error ? e.message : e}; output: ${out?.slice(-800)}`);
  });
  return (await last(p))!;
}

export async function scriptsChecks(c: ScriptsContext) {
  const { base, check, open, until, rpc, timeScale } = c;
  const assert: ScriptsContext["assert"] = c.assert;
  // A per-user script, there before the pages list the scripts.
  const userDir = path.join(c.configDir, "revkit", "scripts");
  mkdirSync(userDir, { recursive: true });
  writeFileSync(path.join(userDir, "slow_count.py"), SLOW);

  let a!: Page;
  let b!: Page;

  await check("scripts: the Script Manager lists shipped and per-user scripts by category; Ctrl+Shift+S shows it", async () => {
    a = await open(base);
    b = await open(base);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+Shift+S");
    await a.waitForSelector("[data-testid=scripts-view]:not([hidden])");
    await a.waitForSelector("[data-testid=script-row][data-script-id='shipped/tag_functions_by_complexity.py']", { timeout: 10000 });
    await a.waitForSelector("[data-testid=script-row][data-script-id='user/slow_count.py']");
    const cats = await a.$$eval("[data-testid=scripts-category]", (els) => els.map((e) => (e as HTMLElement).dataset.category));
    assert(cats.includes("Analysis/Functions") && cats.includes("Tests"), `categories: ${cats.join(", ")}`);
    const banner = await a.$eval("[data-testid=scripts-banner]", (e) => ((e as HTMLElement).hidden ? "" : e.textContent));
    assert(!banner, `the daemon runs scripts here: ${banner}`);
    // Search narrows the tree.
    await a.fill("[data-testid=scripts-search]", "slow_count");
    await a.waitForFunction(() => document.querySelectorAll("[data-testid=script-row]").length === 1);
    await a.fill("[data-testid=scripts-search]", "");
  });

  await check("scripts: a starter from the palette with an ask_choice prompt and progress; one revision with script provenance, live in a second page, one undo step", async () => {
    await c.palette(b, "main");
    await until(b, "page B at main", (s) => s.decompName === "main" && s.live === "live");
    await command(a, "script tag_functions_by_complexity", "tag_functions_by_complexity");
    // The prompt, in the standard chooser, with the default marked.
    await a.waitForSelector("[data-testid=choose]");
    const title = await a.textContent("[data-testid=choose] .modal-title");
    assert(/complexity/i.test(title ?? ""), `the prompt's message: ${title}`);
    await a.click("[data-testid=choose] .palette-item[data-value=instructions]");
    const r = await untilDone(a, "the run", 60000 * timeScale);
    assert(r.status === "ok", `status ${r.status}: ${r.error}`);
    assert(r.seqs.length > 1, `edits: ${r.seqs.length}`);
    const max = await a.$eval("[data-testid=script-progress]", (e) => Number((e as HTMLElement).dataset.maximum ?? 0));
    assert(max > 0, "progress had a maximum");
    // One revision, script provenance, the run as its session.
    const la = await rpc<{ assertions?: { revision: string; provenance?: { kind?: string; id?: string; session?: string; onBehalfOf?: string } }[] }>(base, "AssertionService/ListAssertions", {
      programId: "default/prog",
      filter: { provenance: { session: r.runId } },
    });
    const as = la.assertions ?? [];
    assert(as.length === r.seqs.length, `assertions in the run's session: ${as.length} of ${r.seqs.length}`);
    assert(new Set(as.map((x) => x.revision)).size === 1, "one revision");
    const prov = as[0].provenance!;
    assert(prov.kind === "PROVENANCE_KIND_SCRIPT" && prov.id === "tag_functions_by_complexity", `provenance ${JSON.stringify(prov)}`);
    // The second page sees the plate comment live; one Ctrl+Z here takes the whole run back there.
    await until(b, "the comment in page B", (s) => s.decompText.includes("complexity:"), 15000);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+z");
    await until(b, "the run undone in page B", (s) => !s.decompText.includes("complexity:"), 15000);
    const still = await rpc<{ assertions?: unknown[] }>(base, "AssertionService/ListAssertions", { programId: "default/prog", filter: { provenance: { session: r.runId } } });
    assert((still.assertions ?? []).length === 0, `nothing of the run is active after one undo: ${(still.assertions ?? []).length}`);
  });

  await check("scripts: a per-user script asks for confirmation (source and hash) once; Cancel ends it within 2 s", async () => {
    await a.click("[data-testid=script-row][data-script-id='user/slow_count.py']");
    await a.click("[data-testid=script-run]");
    await a.waitForSelector("[data-testid=script-trust]");
    const src = await a.textContent("[data-testid=script-trust-source]");
    assert(src?.includes("Counts slowly until cancelled"), "the trust dialog shows the source");
    const sha = await a.textContent("[data-testid=script-trust-sha]");
    assert(/sha256 [0-9a-f]{64}/.test(sha ?? ""), `the full hash: ${sha}`);
    await a.click("[data-testid=script-trust-run]");
    await a.waitForFunction(() => (document.querySelector("[data-testid=script-console]")?.textContent ?? "").includes("tick 3"), null, { timeout: 30000 * timeScale });
    const t0 = Date.now();
    await a.click("[data-testid=script-cancel]");
    const r = await untilDone(a, "the cancel", 10000);
    const ms = Date.now() - t0;
    assert(r.status === "cancelled", `status ${r.status}: ${r.error}`);
    assert(ms <= 2500 * timeScale, `cancelled in ${ms} ms`);
    c.log(`     (cancelled in ${ms} ms)`);
    // Pinned: the second run starts without asking.
    await a.click("[data-testid=script-row][data-script-id='user/slow_count.py']");
    await a.click("[data-testid=script-run]");
    await a.waitForFunction(() => (document.querySelector("[data-testid=script-console]")?.textContent ?? "").includes("tick 1"), null, { timeout: 30000 * timeScale });
    assert((await a.$("[data-testid=script-trust]")) === null, "no confirmation the second time");
    await a.click("[data-testid=script-cancel]");
    await untilDone(a, "the second cancel", 10000);
  });

  await check("scripts: an @context function script from the listing's right-click menu acts on the function there; Revert this run; undo", async () => {
    await c.palette(a, "main");
    await until(a, "at main", (s) => s.decompName === "main");
    await a.locator("#listing-canvas").dispatchEvent("contextmenu", { button: 0, clientX: 0, clientY: 0 });
    // Only function scripts (and address ones) are offered; program-wide ones aren't.
    await a.locator("[data-testid=ctx-script-summarize_function]").waitFor({ timeout: 5000 });
    assert((await a.$("[data-testid=ctx-script-tag_functions_by_complexity]")) === null, "a program script isn't in the menu");
    await a.locator("[data-testid=ctx-script-summarize_function]").click();
    const r = await untilDone(a, "the summary", 30000 * timeScale);
    assert(r.status === "ok" && r.seqs.length >= 1, `status ${r.status}, ${r.seqs.length} edits: ${r.error}`);
    assert(r.output.includes("main"), `it printed main's summary: ${r.output}`);
    await until(a, "main's summary comment", (s) => s.decompText.includes("main:"), 15000);
    await until(b, "main's summary comment in page B", (s) => s.decompText.includes("main:"), 15000);
    // "Revert this run" (RevertByProvenance on its session), then Ctrl+Z
    // twice: the revert undone (back), then the run itself (gone).
    await a.click(`[data-testid=script-run-row][data-run-id='${r.runId}'] [data-testid=script-run-revert]`);
    await until(b, "the run reverted in page B", (s) => !s.decompText.includes("main:"), 15000);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+z");
    await until(b, "the revert undone in page B", (s) => s.decompText.includes("main:"), 15000);
    await a.keyboard.press("Control+z");
    await until(b, "the run undone in page B", (s) => !s.decompText.includes("main:"), 15000);
    await a.context().close();
    await b.context().close();
  });

  await check("scripts: a daemon with no Python: the Script Manager sets one up in one click (its steps in the output panel), then the banner goes", async () => {
    const dir = path.join(c.configDir, "..", "scripts-no-python");
    const bin = path.join(dir, "bin");
    mkdirSync(bin, { recursive: true });
    for (const [name, text] of [["python3", FAKE_PYTHON3], ["venv-python", FAKE_VENV_PYTHON]] as const) {
      writeFileSync(path.join(bin, name), text);
      chmodSync(path.join(bin, name), 0o755);
    }
    // Its PATH has only the stand-in python3, which imports nothing.
    const other = await c.startDaemon({ PATH: bin, XDG_DATA_HOME: path.join(dir, "data"), REVKIT_PYTHON: "" }, "ports-scripts-setup.json");
    const p = await open(other);
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+Shift+S");
    await p.waitForSelector("[data-testid=scripts-view]:not([hidden])");
    await p.waitForSelector("[data-testid=scripts-setup-python]", { timeout: 10000 });
    const banner = (await p.textContent("[data-testid=scripts-banner]")) ?? "";
    assert(/no Python/.test(banner), `the banner says why: ${banner}`);
    await p.click("[data-testid=scripts-setup-python]");
    await p.waitForFunction(() => (window as unknown as { __revkit: { app: { scripts?: { lastSetup: unknown } } } }).__revkit.app.scripts?.lastSetup, null, { timeout: 30000 * timeScale });
    const r = (await p.evaluate("window.__revkit.app.scripts.lastSetup")) as { ok: boolean; python: string; error: string; output: string };
    assert(r.ok, `set up: ${r.error}; output: ${r.output}`);
    assert(r.python.endsWith(path.join("data", "revkit", "pyenv", "bin", "python")), `scripts run with ${r.python}`);
    assert(r.output.includes("-m venv") && r.output.includes("Successfully installed revkit"), `the steps' output: ${r.output}`);
    const status = (await p.textContent("[data-testid=script-status]")) ?? "";
    assert(status.includes("scripts run with"), `the output panel's status: ${status}`);
    await p.waitForSelector("[data-testid=scripts-setup-python]", { state: "detached", timeout: 10000 });
    const after = await p.$eval("[data-testid=scripts-banner]", (e) => ((e as HTMLElement).hidden ? "" : e.textContent));
    assert(!after, `no banner once Python is there: ${after}`);
    await p.context().close();
  });
}
