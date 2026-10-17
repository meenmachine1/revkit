// End-to-end checks for separate debug files (feature "debug-files";
// docs/backend.md "External debug files"): a program built here with -g and
// a build ID, split with objcopy --only-keep-debug and stripped. The
// palette's "Load debug file…" refuses a file of no use, then loads the
// debug file by path: the decompiler names the function; Ctrl+Z takes it
// back. "Debug file directories and debuginfod…" saves a directory, with
// fetching left off. Skipped without objcopy.
// run.ts calls debugFileChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import path from "node:path";

export interface DebugFileContext {
  base: string;
  dir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  page: (query: string) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
}

const SOURCE = `
struct point { int x; int y; };
struct point grid[4] = {{1, 2}, {3, 4}, {5, 6}, {7, 8}};
__attribute__((noinline)) int sum_points(struct point *pts, int n) {
  int total_sum = 0;
  for (int i = 0; i < n; i++) total_sum += pts[i].x * pts[i].y;
  return total_sum;
}
int main(int argc, char **argv) { (void)argv; return sum_points(grid, argc & 3); }
`;

async function until<T>(p: Page, what: string, get: string, pred: (v: T) => boolean, ms = 15000): Promise<T> {
  const end = Date.now() + ms;
  let v = (await p.evaluate(get)) as T;
  while (!pred(v)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify(v).slice(0, 1500)}`);
    await p.waitForTimeout(50);
    v = (await p.evaluate(get)) as T;
  }
  return v;
}

function which(name: string): string | null {
  try {
    return execFileSync("sh", ["-c", `command -v ${name}`]).toString().trim() || null;
  } catch {
    return null;
  }
}

async function palette(p: Page, command: string) {
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+Shift+P");
  await p.waitForSelector("[data-testid=palette-input]");
  await p.fill("[data-testid=palette-input]", `>${command}`);
  await p.waitForFunction((c) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").startsWith(c), command, { timeout: 10000 });
  await p.keyboard.press("Enter");
  await p.waitForSelector("[data-testid=ask] .ask-input");
}

export async function debugFileChecks(c: DebugFileContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const cc = process.env.CC ?? "cc";
  if (!which("objcopy") || !which(cc)) {
    c.log("  (debug files: no objcopy or C compiler, skipped)");
    return;
  }
  const src = path.join(c.dir, "dbg.c");
  const full = path.join(c.dir, "dbg.full");
  const debug = path.join(c.dir, "dbg.debug");
  const stripped = path.join(c.dir, "dbg");
  writeFileSync(src, SOURCE);
  execFileSync(cc, ["-g", "-O0", "-fno-pie", "-no-pie", "-Wl,--build-id=sha1", "-o", full, src]);
  execFileSync("objcopy", ["--only-keep-debug", full, debug]);
  execFileSync("objcopy", ["--strip-all", full, stripped]);
  const imported = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", {
    projectId: "default", path: stripped, name: "dbg", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
  });
  const programId = imported.program.programId;
  const funcs = await rpc<{ functions?: { name: string; entry: { offset: string } }[] }>(base, "QueryService/ListFunctions", { programId });
  const user = (funcs.functions ?? []).filter((f) => f.name.startsWith("FUN_"));
  assert(user.length > 0, `the stripped program's functions: ${JSON.stringify(funcs.functions?.map((f) => f.name))}`);
  const p = await c.page(`program=${encodeURIComponent(programId)}&user=e2e&theme=dark`);
  const names = async () =>
    ((await rpc<{ functions?: { name: string }[] }>(base, "QueryService/ListFunctions", { programId })).functions ?? []).map((f) => f.name);

  await check("debug files: Load debug file… refuses a file of no use, loads the program's by path (the function is named); Ctrl+Z takes it back", async () => {
    const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", { client: "e2e" });
    assert(info.features?.includes("debug-files"), `features: ${JSON.stringify(info.features)}`);
    await palette(p, "Load debug file");
    // The stripped binary itself has no DWARF: refused, the dialog stays.
    await p.fill("[data-testid=ask] .ask-input", stripped);
    await p.keyboard.press("Enter");
    await p.waitForFunction(() => (document.querySelector("[data-testid=ask-error]")?.textContent ?? "").includes("debug_info"), undefined, { timeout: 15000 });
    await p.fill("[data-testid=ask] .ask-input", debug);
    await p.keyboard.press("Enter");
    await p.waitForSelector("[data-testid=ask]", { state: "detached", timeout: 30000 });
    const end = Date.now() + 15000;
    while (!(await names()).includes("sum_points")) {
      assert(Date.now() < end, `sum_points named: ${JSON.stringify(await names())}`);
      await p.waitForTimeout(100);
    }
    await until<{ undo: string }>(p, "the undo step", `({ undo: document.querySelector("#undo")?.getAttribute("title") ?? "" })`, (v) => v.undo.includes("Load debug file"));
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+z");
    const end2 = Date.now() + 15000;
    while ((await names()).includes("sum_points")) {
      assert(Date.now() < end2, "sum_points unnamed again");
      await p.waitForTimeout(100);
    }
  });

  await check("debug files: the settings dialog saves a directory and leaves fetching off", async () => {
    await palette(p, "Debug file directories and debuginfod");
    await p.fill("[data-testid=ask] .ask-input:not(.ask-extra)", c.dir);
    assert((await p.inputValue("[data-testid=ask] .ask-extra")) === "", "no servers listed by default");
    assert(!(await p.isChecked("[data-testid=ask-debuginfod]")), "fetching is off by default");
    await p.keyboard.press("Enter");
    await p.waitForFunction(() => !document.querySelector("[data-testid=ask]") || !!document.querySelector("[data-testid=ask-error]")?.textContent, undefined, { timeout: 10000 });
    const refused = await p.evaluate(() => document.querySelector("[data-testid=ask-error]")?.textContent ?? "");
    assert(!refused, `the settings were refused: ${refused}`);
    const end = Date.now() + 10000;
    for (;;) {
      const s = await rpc<{ settings?: { debugDirs?: string[]; debuginfod?: boolean } }>(base, "ProjectService/GetSymbolSettings", {});
      if (s.settings?.debugDirs?.includes(c.dir)) {
        assert(!s.settings.debuginfod, "debuginfod stays off");
        break;
      }
      if (Date.now() > end) {
        const toasts = await p.evaluate(() => [...document.querySelectorAll(".toast")].map((t) => t.textContent));
        assert(false, `the directory saved: ${JSON.stringify(s)}; toasts: ${JSON.stringify(toasts)}`);
      }
      await p.waitForTimeout(100);
    }
    await rpc(base, "ProjectService/SetSymbolSettings", { settings: {} });
  });
  await p.context().close();
}
