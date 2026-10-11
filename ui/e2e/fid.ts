// End-to-end checks for Function ID (docs/fid.md, docs/ui.md "Function ID";
// feature "function-id"): a small static library built here into two
// programs; a database made from the one with symbols (CreateFidDatabase,
// attached to the project) names the library's functions in the other,
// stripped; the Function ID window lists them as applied, Reject takes a
// name off (the listing's function list shows FUN_ again) and Apply puts it
// back as the user's; the Databases dialog lists the project's database.
// Skipped without gcc.
// run.ts calls fidChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import path from "node:path";

export interface FidContext {
  base: string;
  dir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  page: (query: string) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
}

interface Shown {
  status: string;
  rows: { entry: string; now: string; name: string; status: string; score: number }[];
  selected: string;
  candidates: string[];
}

const LIB = `
#include <string.h>
struct acc { unsigned long sum, count, max; };
__attribute__((noinline)) void acc_add(struct acc *a, unsigned long v) { a->sum += v; a->count += 1; if (v > a->max) a->max = v; }
__attribute__((noinline)) unsigned long acc_mean(const struct acc *a) { return a->count ? a->sum / a->count : 0; }
__attribute__((noinline)) unsigned long checksum(const unsigned char *p, unsigned long n) {
  unsigned long h = 5381; for (unsigned long i = 0; i < n; i++) h = ((h << 5) + h) ^ p[i]; return h; }
__attribute__((noinline)) int rle_encode(const unsigned char *in, int n, unsigned char *out) {
  int o = 0; for (int i = 0; i < n;) { int j = i; while (j < n && in[j] == in[i] && j - i < 255) j++;
  out[o++] = (unsigned char)(j - i); out[o++] = in[i]; i = j; } return o; }
__attribute__((noinline)) unsigned long summarize(const unsigned char *p, int n, unsigned char *scratch) {
  struct acc a; memset(&a, 0, sizeof a); for (int i = 0; i < n; i++) acc_add(&a, p[i]);
  int r = rle_encode(p, n, scratch); return acc_mean(&a) * 31 + checksum(scratch, (unsigned long)r) + a.max; }
`;
const A = `#include <stdio.h>
unsigned long summarize(const unsigned char *p, int n, unsigned char *scratch);
unsigned long checksum(const unsigned char *p, unsigned long n);
int main(int argc, char **argv) { static unsigned char buf[4096];
  printf("%lu %lu\\n", summarize((const unsigned char *)argv[0], argc * 3, buf), checksum(buf, 16)); return 0; }
`;
const B = `#include <stdlib.h>
unsigned long summarize(const unsigned char *p, int n, unsigned char *scratch);
int rle_encode(const unsigned char *in, int n, unsigned char *out);
int main(int argc, char **argv) { unsigned char *s = malloc(8192); int n = rle_encode((const unsigned char *)argv[0], argc, s);
  return (int)(summarize(s, n, s + 4096) & 0x7f); }
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

export async function fidChecks(c: FidContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const gcc = which("gcc");
  if (!gcc) {
    c.log("  (Function ID: no gcc, skipped)");
    return;
  }
  const d = path.join(c.dir, "fid");
  execFileSync("mkdir", ["-p", d]);
  writeFileSync(path.join(d, "lib.c"), LIB);
  writeFileSync(path.join(d, "a.c"), A);
  writeFileSync(path.join(d, "b.c"), B);
  execFileSync(gcc, ["-O2", "-g", "-c", path.join(d, "lib.c"), "-o", path.join(d, "lib.o")]);
  execFileSync("ar", ["rcs", path.join(d, "libacc.a"), path.join(d, "lib.o")]);
  for (const n of ["a", "b"]) execFileSync(gcc, ["-O2", "-g", path.join(d, `${n}.c`), path.join(d, "libacc.a"), "-o", path.join(d, n)]);
  execFileSync("strip", ["--strip-all", "-o", path.join(d, "b-stripped"), path.join(d, "b")]);
  const prov = { kind: "PROVENANCE_KIND_USER", id: "e2e" };
  const imp = async (file: string, name: string) =>
    (await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", { projectId: "default", path: path.join(d, file), name, provenance: prov })).program.programId;
  const a = await imp("a", "fid-a");
  const b = await imp("b-stripped", "fid-b");
  const db = path.join(d, "acc.rkfid");
  const made = await rpc<{ functionsAdded: number }>(base, "AnalysisService/CreateFidDatabase", {
    projectId: "default", programIds: [a], path: db, family: "acc", version: "1", attach: "FID_SCOPE_PROJECT", provenance: prov,
  });
  assert(made.functionsAdded >= 5, `functions added: ${made.functionsAdded}`);
  await rpc(base, "AnalysisService/StartAnalysis", { programId: b, analyzers: ["function-id"], provenance: prov });
  for (let i = 0; i < 300; i++) {
    const s = await rpc<{ idle?: boolean }>(base, "AnalysisService/GetAnalysisStatus", { programId: b });
    if (s.idle) break;
    await new Promise((r) => setTimeout(r, 200));
  }
  const p = await c.page(`program=${encodeURIComponent(b)}&user=e2e&theme=dark`);
  const shown = "window.__revkit.app.fid.describe()";
  const functions = async () =>
    (await rpc<{ functions?: { entry?: { offset?: string }; name: string }[] }>(base, "QueryService/ListFunctions", { programId: b, page: { pageSize: 1000 } })).functions ?? [];

  await check("Function ID: the library's functions named, as a table with scores", async () => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+Shift+P");
    await p.waitForSelector("[data-testid=palette-input]");
    await p.fill("[data-testid=palette-input]", ">Show Function ID");
    await p.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").toLowerCase().startsWith("show function id"), undefined, { timeout: 10000 });
    await p.keyboard.press("Enter");
    const s = await until<Shown>(p, "the matches", shown, (v) => ["summarize", "rle_encode", "checksum"].every((n) => v.rows.some((r) => r.name === n && r.status === "applied")));
    assert(s.status.includes("named"), `status: ${s.status}`);
    const fns = await functions();
    assert(fns.some((f) => f.name === "summarize"), `the function list has summarize: ${fns.map((f) => f.name).join(", ")}`);
  });

  await check("Function ID: Reject takes the name off, Apply puts it back (the user's)", async () => {
    await p.click("[data-testid=fid-row][data-name=summarize]");
    await until<Shown>(p, "the selection", shown, (v) => v.selected !== "" && v.candidates.includes("summarize"));
    await p.click("[data-testid=fid-reject]");
    await until<Shown>(p, "rejected", shown, (v) => v.rows.some((r) => r.name === "summarize" && r.status === "rejected" && r.now.startsWith("FUN_")));
    assert(!(await functions()).some((f) => f.name === "summarize"), "summarize is gone from the function list");
    await p.click("[data-testid=fid-apply]");
    await until<Shown>(p, "accepted", shown, (v) => v.rows.some((r) => r.name === "summarize" && r.status === "accepted" && r.now === "summarize"));
  });

  await check("Function ID: the Databases dialog lists the project's database, attached", async () => {
    await p.click("[data-testid=fid-databases]");
    await p.waitForSelector(`[data-testid=fid-db][data-id="${db}"]`);
    const on = await p.$eval(`[data-testid=fid-db][data-id="${db}"] input`, (e) => (e as HTMLInputElement).checked);
    assert(on, "the project's database is attached");
    await p.click("[data-testid=fid-dbs-close]");
    assert(!(await p.$("[data-testid=fid-dbs]")), "the dialog closed");
  });
}
