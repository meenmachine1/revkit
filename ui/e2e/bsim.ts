// End-to-end checks for BSim (docs/ui.md "BSim", features bsim and
// bsim-search): two builds of one program compiled here (-O1 with debug
// info, -O2), a database created at a temporary path with A ingested; on
// B's page, Find similar functions (the function list's menu) shows the
// BSim view with checksum's match in A first, a double click opens the two
// side by side in Compare; All functions lists the matched ones; the
// Overview counts. With feature bsim-apply, on a stripped build: Apply name
// on one hit (the toast's Undo takes it back), then each function's best
// (Ctrl+A) with Apply signature in one step. run.ts calls bsimChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const SRC = String.raw`
volatile int sink;
__attribute__((noinline)) unsigned checksum(const unsigned char *p, unsigned long n) {
  unsigned h = 2166136261u;
  for (unsigned long i = 0; i < n; ++i) h = (h ^ p[i]) * 16777619u;
  return h;
}
__attribute__((noinline)) int classify(int c) {
  switch (c) {
    case 0: return 10; case 1: return 22; case 2: return 37; case 3: return 41;
    case 4: return 58; case 5: return 63; case 6: return 79; default: return -1;
  }
}
int main(int argc, char **argv) {
  sink = (int)checksum((const unsigned char *)argv[0], 4) + classify(argc);
  return 0;
}
`;

export interface BsimContext {
  base: string;
  dir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
  page: (query: string) => Promise<Page>;
}

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

export async function bsimChecks(c: BsimContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", {});
  if (!info.features?.includes("bsim-search")) return c.log("  (bsim: no feature bsim-search, skipped)");
  const d = path.join(c.dir, "bsim");
  mkdirSync(d, { recursive: true });
  writeFileSync(path.join(d, "p.c"), SRC);
  try {
    execFileSync("cc", ["-O1", "-g", path.join(d, "p.c"), "-o", path.join(d, "bsim-O1")]);
    execFileSync("cc", ["-O2", path.join(d, "p.c"), "-o", path.join(d, "bsim-O2")]);
    execFileSync("cc", ["-O1", "-s", path.join(d, "p.c"), "-o", path.join(d, "bsim-O1s")]);
  } catch {
    return c.log("  (bsim: no C compiler, skipped)");
  }
  const imp = async (name: string) =>
    (await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", { projectId: "default", path: path.join(d, name), name, provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } })).program.programId;
  const a = await imp("bsim-O1");
  const b = await imp("bsim-O2");
  const db = path.join(d, "e2e.rkbsim");
  await rpc(base, "BSimService/CreateBSimDatabase", { projectId: "default", path: db, name: "e2e", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
  await rpc(base, "BSimService/IngestBSim", { projectId: "default", database: db, programIds: [a] });
  const p = await c.page(`program=${encodeURIComponent(b)}&user=e2e&theme=dark`);
  const view = () => p.evaluate("window.__revkit.app.bsim?.describe()") as Promise<{ status: string; mode: string; database: string; rows: { function: string; match?: string; executable?: string; similarity?: number; programId?: string; hits?: number }[] }>;
  const until = async <T>(what: string, get: () => Promise<T>, pred: (v: T) => boolean, ms = 30000) => {
    const end = Date.now() + ms;
    let v = await get();
    while (!pred(v)) {
      if (Date.now() > end) throw new Error(`timed out waiting for ${what}: ${JSON.stringify(v)}`);
      await p.waitForTimeout(150);
      v = await get();
    }
    return v;
  };

  await check("bsim: Find similar functions (the function list's menu) shows checksum's match in the database's other build first; a double click compares them side by side", async () => {
    await p.locator(".fn-row .fn-name", { hasText: /^checksum$/ }).first().click({ button: "right" });
    await p.click("[data-testid=fn-menu-bsim]");
    await p.waitForSelector("[data-testid=bsim-view]:not([hidden])");
    const v = await until("checksum's matches", view, (x) => x.rows.length > 0 && x.mode === "function");
    assert(v.database === db, `the database: ${v.database}`);
    assert(v.rows[0].function === "checksum" && v.rows[0].match === "checksum" && v.rows[0].executable === "bsim-O1", `first match: ${JSON.stringify(v.rows)}`);
    assert(v.rows[0].programId === a && (v.rows[0].similarity ?? 0) > 0.7, `in this project, similar: ${JSON.stringify(v.rows[0])}`);
    await shot(p, "bsim-function");
    await p.locator("[data-testid=bsim-row]").first().dblclick();
    await p.waitForSelector("[data-testid=diff-view]:not([hidden]), #diff:not([hidden])", { timeout: 15000 });
    const both = await until(
      "Compare with both functions",
      () => p.evaluate(() => document.querySelector("#diff")?.textContent ?? ""),
      (t) => t.includes("bsim-O1") && t.includes("bsim-O2"),
    );
    assert(both.includes("checksum"), "Compare names checksum");
    await shot(p, "bsim-compare");
  });

  await check("bsim: All functions lists the matched ones best first; the Overview counts each function's matches", async () => {
    await p.evaluate("window.__revkit.app.showView('bsim')");
    await p.fill("[data-testid=bsim-similarity]", "0.3");  // -O1 against -O2: classify's switch differs
    await p.click("[data-testid=bsim-search-all]");
    const all = await until("all functions", view, (x) => x.mode === "all" && x.rows.length > 0);
    const names = new Set(all.rows.filter((r) => r.match).map((r) => r.function));
    assert(names.has("checksum") && names.has("classify"), `matched functions: ${[...names].join(", ")}`);
    assert(all.rows.every((r) => r.executable !== "bsim-O2"), "the query's own file is left out");
    await p.click("[data-testid=bsim-overview]");
    const ov = await until("the overview", view, (x) => x.mode === "overview" && x.rows.length > 0);
    assert(ov.rows.every((r) => r.match === undefined && typeof r.hits === "number"), `counts only: ${JSON.stringify(ov.rows.slice(0, 3))}`);
    assert((ov.rows.find((r) => r.function === "checksum")?.hits ?? 0) >= 1, `checksum's count: ${JSON.stringify(ov.rows)}`);
    await shot(p, "bsim-overview");
  });
  await p.context().close();

  if (!info.features?.includes("bsim-apply")) return c.log("  (bsim: no feature bsim-apply, apply skipped)");
  const s = await imp("bsim-O1s");
  const q = await c.page(`program=${encodeURIComponent(s)}&user=e2e&theme=dark`);
  type Row = { function: string; address?: string; match?: string; applied?: string };
  const sview = () => q.evaluate("window.__revkit.app.bsim?.describe()") as Promise<{ mode: string; picked: number[]; rows: Row[] }>;
  const nameAt = async (addr: string) =>
    (await rpc<{ function: { name: string } }>(base, "QueryService/GetFunction", { programId: s, address: { offset: BigInt(addr).toString() } })).function.name;
  const wait = async <T>(what: string, get: () => Promise<T>, pred: (v: T) => boolean, ms = 30000) => {
    const end = Date.now() + ms;
    let v = await get();
    while (!pred(v)) {
      if (Date.now() > end) throw new Error(`timed out waiting for ${what}: ${JSON.stringify(v)}`);
      await q.waitForTimeout(150);
      v = await get();
    }
    return v;
  };

  await check("bsim: Apply name on a stripped build's hit renames the function; the toast's Undo takes it back; Ctrl+A and Apply signature apply each function's best in one step", async () => {
    await q.evaluate("window.__revkit.app.showView('bsim')");
    await q.fill("[data-testid=bsim-similarity]", "0.9");
    await q.click("[data-testid=bsim-search-all]");
    const all = await wait("all functions", sview, (x) => x.mode === "all" && x.rows.some((r) => r.match === "checksum"));
    const i = all.rows.findIndex((r) => r.match === "checksum");
    const addr = all.rows[i].address!;
    assert(all.rows[i].function.startsWith("FUN_"), `stripped: ${JSON.stringify(all.rows[i])}`);
    await q.locator("[data-testid=bsim-row]").nth(i).click();
    await q.click("[data-testid=bsim-apply-name]");
    const named = await wait("checksum applied", sview, (x) => x.rows[i]?.applied === "applied");
    assert(named.rows[i].function === "checksum", `the row's function renamed: ${JSON.stringify(named.rows[i])}`);
    assert((await nameAt(addr)) === "checksum", "the program's function is checksum");
    await shot(q, "bsim-applied");
    await q.locator("#toasts button", { hasText: "Undo" }).last().click();
    await wait("undone", () => nameAt(addr), (n) => n.startsWith("FUN_"));

    await q.locator("[data-testid=bsim-table]").focus();
    await q.keyboard.press("Control+a");
    const picked = await wait("each function's best", sview, (x) => x.picked.length >= 2);
    const names = picked.picked.map((k) => picked.rows[k].match);
    assert(names.includes("checksum") && names.includes("classify"), `picked: ${names.join(", ")}`);
    await q.click("[data-testid=bsim-apply-signature]");
    const done = await wait("applied", sview, (x) => x.picked.every((k) => !!x.rows[k].applied));
    for (const k of done.picked) {
      const r = done.rows[k];
      if (r.match !== "checksum" && r.match !== "classify") continue;
      assert(r.applied === "applied" && r.function === r.match, `renamed: ${JSON.stringify(r)}`);
      assert((await nameAt(r.address!)) === r.match, `${r.match} in the program`);
    }
    // Ctrl+Z on the tab undoes the whole apply.
    await q.evaluate("window.__revkit.app.redoOrUndo('undo')");
    await wait("undone", () => nameAt(addr), (n) => n.startsWith("FUN_"));
  });
  await q.context().close();
}
