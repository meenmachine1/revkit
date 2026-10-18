// End-to-end checks for Trace value across calls (feature "value-trace";
// docs/ui.md "Tracing a value across calls"): a program built here with
// -g, combine(x, y) = pick(scale(x), y) called from main. Right-click x in
// combine's C, Trace value across calls ▸ Where it goes…: the dialog lists
// scale, pick and main (not other, scale's other caller), the calls
// crossed, the indirect call and main's missing callers; the start
// function's tokens are highlighted; a line opens its function. Skipped
// without a C compiler. run.ts calls traceChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import path from "node:path";

export interface TraceContext {
  base: string;
  dir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  page: (query: string) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
}

const SOURCE = `
#include <string.h>
__attribute__((noinline)) int scale(int v) { return v * 3 + 1; }
__attribute__((noinline)) int pick(int a, int b) { return a > b ? a : b; }
__attribute__((noinline)) int combine(int x, int y) { int s = scale(x); return pick(s, y); }
__attribute__((noinline)) int other(int q) { return scale(q + 5); }
int (*volatile hook)(int) = other;
int main(int argc, char **argv) {
  int r = combine(argc, (int)strlen(argv[0]));
  r += hook(r);
  return r + other(argc);
}
`;

type Snap = { decompName: string | null; slice: { label: string; tokens: string[] } | null };
const snap = (p: Page) => p.evaluate("window.__revkit.app.snapshot()") as Promise<Snap>;

async function until(p: Page, what: string, pred: (s: Snap) => boolean, ms = 20000) {
  const end = Date.now() + ms;
  let s = await snap(p);
  while (!pred(s)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify(s).slice(0, 600)}`);
    await p.waitForTimeout(50);
    s = await snap(p);
  }
  return s;
}

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

export async function traceChecks(c: TraceContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const cc = process.env.CC ?? "cc";
  const src = path.join(c.dir, "trace.c");
  const bin = path.join(c.dir, "traceprog");
  writeFileSync(src, SOURCE);
  try {
    execFileSync(cc, ["-O1", "-g", "-fno-inline", "-fno-optimize-sibling-calls", "-fno-pie", "-no-pie", "-o", bin, src], { stdio: "ignore" });
  } catch {
    c.log("  (trace: no C compiler, skipped)");
    return;
  }
  const imported = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", {
    projectId: "default", path: bin, name: "traceprog", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
  });
  const programId = imported.program.programId;
  const p = await c.page(`program=${encodeURIComponent(programId)}&user=e2e&theme=dark`);

  await check("trace: Trace value across calls from a parameter lists the callees and callers it reaches, what it couldn't follow, and opens a line's function", async () => {
    const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", { client: "e2e" });
    assert(info.features?.includes("value-trace"), `features: ${JSON.stringify(info.features)}`);
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+k");
    await p.fill("[data-testid=palette-input]", "combine");
    await p.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").includes("combine"));
    await p.keyboard.press("Enter");
    await until(p, "combine decompiled", (s) => s.decompName === "combine");
    // x in the body (the last parameter token named x: scale(x)).
    const tok = p.locator("#cm .cm-content span.k-pa", { hasText: /^x$/ }).last();
    await tok.waitFor();
    await tok.click();
    await tok.click({ button: "right" });
    await p.click("[data-testid=ctx-trace]");
    await p.click("[data-testid=submenu] [data-testid=ctx-trace-forward]");
    await p.waitForSelector("[data-testid=trace-function][data-name=main]", { timeout: 30000 });
    const names = await p.$$eval("[data-testid=trace-function]", (els) => els.map((e) => (e as HTMLElement).dataset.name));
    assert(names[0] === "combine" && names.includes("scale") && names.includes("pick") && !names.includes("other"), `functions: ${JSON.stringify(names)}`);
    const crossings = await p.$$eval("[data-testid=trace-crossing]", (els) => els.map((e) => e.textContent ?? ""));
    assert(crossings.some((t) => t.startsWith("combine → scale")), `crossings: ${JSON.stringify(crossings)}`);
    const unknowns = await p.$$eval("[data-testid=trace-unknown]", (els) => els.map((e) => (e as HTMLElement).dataset.kind));
    assert(unknowns.includes("indirect call") && unknowns.includes("no callers"), `unknowns: ${JSON.stringify(unknowns)}`);
    const s = await until(p, "the start's tokens highlighted", (x) => !!x.slice && x.slice.label.startsWith("Trace"));
    assert(s.slice!.tokens.includes("x"), `highlighted: ${JSON.stringify(s.slice)}`);
    await shot(p, "trace-forward");
    await p.click("[data-testid=trace-line][data-function=scale]");
    await p.waitForSelector("[data-testid=trace-dialog]", { state: "detached", timeout: 5000 });
    await until(p, "scale opened", (x) => x.decompName === "scale");
  });
  await p.context().close();
}
