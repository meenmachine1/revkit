// End-to-end checks for comparing any two functions (docs/ui.md "Compare
// two functions", docs/diff.md; feature "function-compare"): a program
// built with debug info (A) and its stripped copy (B), the same code at
// the same addresses. Compare with… from the function list's context menu
// opens both functions in the Compare view without a session; the C pane
// pairs their variables, a token's context menu applies A's parameter name
// to B (the toast's Undo takes it back) and "Apply all A → B" names B's
// function and the global it uses; the function list's marked pair compares two functions of one
// program; in a session's table, m matches a function by hand with another
// one, u unmatches it, and the toast's Undo brings the manual match back.
// Skipped without gcc. run.ts calls compareChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import path from "node:path";

export interface CompareContext {
  base: string;
  dir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  page: (query: string) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
}

const SRC = String.raw`
#include <stdio.h>
int total;
__attribute__((noinline)) int scale(int count, int factor) {
  int acc = 0;
  for (int k = 0; k < count; k++) acc += factor * k;
  total += acc;
  return acc;
}
__attribute__((noinline)) int offset(int base) { return base + 0x55; }
int main(int argc, char **argv) {
  printf("%d %d %s\n", scale(argc, 7), offset(argc), argv[0]);
  return total & 1;
}
`;

function which(name: string): string | null {
  try {
    return execFileSync("sh", ["-c", `command -v ${name}`]).toString().trim() || null;
  } catch {
    return null;
  }
}

async function until<T>(p: Page, what: string, get: string, pred: (v: T) => boolean, ms = 30000): Promise<T> {
  const end = Date.now() + ms;
  let v = (await p.evaluate(get)) as T;
  while (!pred(v)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify(v).slice(0, 1500)}`);
    await p.waitForTimeout(100);
    v = (await p.evaluate(get)) as T;
  }
  return v;
}

type Fn = { entry?: { offset?: string }; name: string };
type CDesc = { variables: { a: string | null; b: string | null; evidence: string }[]; lines: number; signatureA: string; signatureB: string };

export async function compareChecks(c: CompareContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const gcc = which("gcc");
  if (!gcc) {
    c.log("  (compare two functions: no gcc, skipped)");
    return;
  }
  const d = path.join(c.dir, "cmp");
  execFileSync("mkdir", ["-p", d]);
  writeFileSync(path.join(d, "p.c"), SRC);
  execFileSync(gcc, ["-O1", "-g", "-fno-inline", path.join(d, "p.c"), "-o", path.join(d, "dbg")]);
  execFileSync("strip", ["--strip-all", "-o", path.join(d, "stripped"), path.join(d, "dbg")]);
  const prov = { kind: "PROVENANCE_KIND_USER", id: "e2e" };
  const imp = async (file: string, name: string) =>
    (await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", { projectId: "default", path: path.join(d, file), name, provenance: prov })).program.programId;
  const a = await imp("dbg", "cmp-debug");
  const b = await imp("stripped", "cmp-stripped");
  const functions = async (program: string) => (await rpc<{ functions?: Fn[] }>(base, "QueryService/ListFunctions", { programId: program, page: { pageSize: 1000 } })).functions ?? [];
  const entryOf = async (program: string, name: string) => {
    const f = (await functions(program)).find((x) => x.name === name);
    assert(f?.entry?.offset, `${name} in ${program}`);
    return BigInt(f.entry.offset);
  };
  const nameAt = async (program: string, entry: bigint) => (await functions(program)).find((x) => BigInt(x.entry?.offset ?? -1) === entry)?.name ?? "";
  const scale = await entryOf(a, "scale");
  // strip moves no code: B's scale is at the same address, a default name.
  const scaleB = await nameAt(b, scale);
  assert(scaleB.startsWith("FUN_"), `B's scale is unnamed: ${scaleB}`);
  const p = await c.page(`program=${encodeURIComponent(a)}&user=e2e&theme=dark`);
  const desc = "window.__revkit.app.diff.cview.describe()";

  await check("compare two functions: Compare with… from the function list, aligned, no session", async () => {
    await p.locator(".fn-row .fn-name", { hasText: /^scale$/ }).first().click({ button: "right" });
    await p.click("[data-testid=fn-menu-compare]");
    await p.waitForSelector("[data-testid=compare-with]");
    await p.selectOption("[data-testid=pick-fn-program]", b);
    await p.fill("[data-testid=pick-fn-filter]", scaleB);
    await p.locator("[data-testid=pick-fn-item]", { hasText: scaleB }).first().waitFor();
    await p.keyboard.press("Enter");
    await p.waitForSelector("[data-testid=compare-with]", { state: "detached" });
    await p.waitForSelector("[data-testid=diff-adhoc]:not([hidden])");
    const head = (await p.textContent("[data-testid=diff-adhoc]")) ?? "";
    assert(head.includes("scale") && head.includes(scaleB), `head: ${head}`);
    // The same code: aligned, no difference.
    await p.waitForFunction(() => document.querySelector("[data-testid=diff-count]")?.textContent === "no differences", undefined, { timeout: 20000 });
    assert(await p.locator("[data-testid=diff-table]").isHidden(), "no match table for two functions");
  });

  await check("compare two functions: the C pane pairs variables; apply a name to B, undo, apply all", async () => {
    await p.click("[data-testid=diff-show-c]");
    const v = await until<CDesc>(p, "paired variables", desc, (x) => x.variables.some((y) => y.a === "count" && y.b !== null));
    const count = v.variables.find((y) => y.a === "count")!;
    assert(count.evidence === "parameter 1", `count pairs by position: ${JSON.stringify(count)}`);
    assert(/paired/.test((await p.textContent("[data-testid=diff-c-vars]")) ?? ""), "the head counts paired variables");
    // Right-click A's count: apply its name to B.
    await p.locator("[data-testid=diff-c-cell-a] [data-testid=diff-c-var]", { hasText: /^count$/ }).first().click({ button: "right" });
    if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, "compare-functions-menu.png") });
    await p.click("[data-testid=dc-apply-var-name]");
    await until<CDesc>(p, "B's count", desc, (x) => x.variables.some((y) => y.a === "count" && y.b === "count"));
    await p.locator("[data-testid=diff-c-cell-b] [data-testid=diff-c-var]", { hasText: /^count$/ }).first().waitFor();
    // One undo step: the toast's Undo (B isn't this tab's program).
    await p.locator(".toast", { hasText: "Apply 1 variable name" }).locator("button", { hasText: "Undo" }).click();
    await until<CDesc>(p, "B's name back", desc, (x) => x.variables.some((y) => y.a === "count" && y.b !== "count"));
    // Apply all A → B: the function's name, its signature, the named variables.
    await p.click("[data-testid=diff-c-apply-a]");
    // Every variable A's debug info named now has its name in B too.
    const made = /^(param_|local_|in_|unaff_|extraout_|[a-z]{1,5}Var\d|[a-z]{1,5}Stack)/;
    await until<CDesc>(p, "everything applied", desc, (x) => x.variables.filter((y) => y.a && y.b && !made.test(y.a)).every((y) => y.a === y.b) && x.variables.some((y) => y.b === "factor"));
    if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, "compare-functions-c.png") });
    const end = Date.now() + 10000;
    while ((await nameAt(b, scale)) !== "scale" && Date.now() < end) await p.waitForTimeout(100);
    assert((await nameAt(b, scale)) === "scale", "B's function named");
    // The global scale uses, by its aligned reference (api_minor 69): named in B too.
    const syms = await rpc<{ symbols?: { name: string }[] }>(base, "QueryService/ListSymbols", { programId: b, nameEquals: "total" });
    assert((syms.symbols ?? []).length === 1, `B's global named by Apply all: ${JSON.stringify(syms)}`);
    const blame = await rpc<{ candidates: { provenance: { kind: string }; portedFrom?: { programId: string } }[] }>(base, "AssertionService/Blame", { key: { programId: b, kind: "FACT_KIND_NAME", address: { offset: String(scale) } } });
    assert(blame.candidates[0].provenance.kind === "PROVENANCE_KIND_USER" && blame.candidates[0].portedFrom?.programId === a, `blame: ${JSON.stringify(blame.candidates[0])}`);
  });

  await check("compare two functions: two of one program, marked in the function list", async () => {
    await p.locator(".fn-row .fn-name", { hasText: /^scale$/ }).first().click({ modifiers: ["Control"] });
    await p.locator(".fn-row .fn-name", { hasText: /^offset$/ }).first().click({ modifiers: ["Control"] });
    assert((await p.locator(".fn-row.marked").count()) === 2, "two marked");
    await p.locator(".fn-row .fn-name", { hasText: /^offset$/ }).first().click({ button: "right" });
    await p.click("[data-testid=fn-menu-compare-marked]");
    await p.waitForFunction(() => /scale[\s\S]*offset/.test(document.querySelector("[data-testid=diff-adhoc]")?.textContent ?? ""));
    await p.waitForFunction(() => Number(document.querySelector("[data-testid=diff-count]")?.getAttribute("data-total") ?? 0) > 0, undefined, { timeout: 20000 });
  });

  await check("compare: manual matching in a session (m matches by hand, u unmatches, Undo)", async () => {
    const s = await rpc<{ session: { sessionId: string } }>(base, "DiffService/CreateDiffSession", { projectId: "default", programA: a, programB: b, run: true, provenance: prov });
    await p.evaluate(`window.__revkit.app.diff.openSession(${JSON.stringify(s.session.sessionId)})`);
    await p.waitForSelector("[data-testid=diff-adhoc]", { state: "hidden" });
    await p.waitForFunction(() => document.querySelector("[data-testid=diff-status]")?.getAttribute("data-state") === "done", undefined, { timeout: 30000 });
    await p.fill("[data-testid=diff-filter]", "scale");
    await p.waitForFunction(() => document.querySelectorAll("[data-testid=diff-row]").length === 1);
    const offsetB = await nameAt(b, await entryOf(a, "offset"));
    // m: match A's scale by hand with B's offset.
    await p.focus("[data-testid=diff-table]");
    await p.keyboard.press("m");
    await p.waitForSelector("[data-testid=match-with]");
    await p.fill("[data-testid=pick-fn-filter]", offsetB);
    await p.locator("[data-testid=pick-fn-item]", { hasText: offsetB }).first().waitFor();
    await p.keyboard.press("Enter");
    const rowB = () => p.textContent("[data-testid=diff-row] .d-name:nth-of-type(3)");
    const end = Date.now() + 10000;
    while (!((await rowB()) ?? "").includes(offsetB) && Date.now() < end) await p.waitForTimeout(100);
    assert(((await rowB()) ?? "").includes(offsetB), `matched by hand: ${await rowB()}`);
    assert((await p.textContent("[data-testid=diff-row-status]")) === "accepted", "accepted");
    if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, "compare-manual-match.png") });
    // u: unmatch; scale finds its own partner again.
    await p.focus("[data-testid=diff-table]");
    await p.keyboard.press("u");
    await p.waitForFunction(() => document.querySelector("[data-testid=diff-row-status]")?.textContent === "proposed");
    assert(((await rowB()) ?? "") === "scale", `its partner again: ${await rowB()}`);
    // The toast's Undo: the manual match is back (one step).
    await p.locator(".toast", { hasText: "Unmatch" }).locator("button", { hasText: "Undo" }).click();
    await p.waitForFunction(() => document.querySelector("[data-testid=diff-row-status]")?.textContent === "accepted", undefined, { timeout: 10000 });
    await p.context().close();
  });
}
