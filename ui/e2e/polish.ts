// End-to-end checks for the daily-use polish (phase 7): program and project
// management, the function list's columns and filters, graph switch labels
// and the minimap, the types tree, plugin facts in the graph and the
// decompiler, virtualized tables, the file picker and accessibility.
// run.ts calls polishChecks() with its helpers; RK_SHOTS=<dir> also saves
// a screenshot per check there.

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import path from "node:path";
import { audit } from "./a11y";

export interface PolishContext {
  base: string;
  /** The test program and its symbols. */
  exe: string;
  sym: (name: string) => Promise<bigint>;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  open: (base: string, query?: string, hash?: string, dpr?: number) => Promise<Page>;
  palette: (p: Page, text: string) => Promise<void>;
  answer: (p: Page, text: string) => Promise<void>;
  until: <T>(p: Page, what: string, pred: (s: T) => boolean, ms?: number) => Promise<T>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
  /** A daemon whose decompiler crashes at `fault` ("segv@<hex>"). */
  crashingDaemon: (fault: string) => Promise<string>;
}

interface Snap {
  decompName: string | null;
  live: string;
  address: string | null;
}

const shotsDir = process.env.RK_SHOTS;

async function shot(p: Page, name: string) {
  if (!shotsDir) return;
  await p.screenshot({ path: path.join(shotsDir, `${name}.png`) });
}

async function command(p: Page, title: string) {
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+Shift+P");
  await p.waitForSelector("[data-testid=palette-input]");
  await p.fill("[data-testid=palette-input]", `>${title}`);
  await p.waitForFunction((t) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").toLowerCase().startsWith(t.toLowerCase()), title);
  await p.keyboard.press("Enter");
}

export async function polishChecks(c: PolishContext) {
  const { base, check, open, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const ready = (p: Page) => c.until<Snap>(p, "ready", (s) => s.decompName === "main" && s.live === "live");
  type Prog = { programId: string; name: string; deleted?: boolean };
  const programs = async (includeDeleted = false) =>
    (await rpc<{ programs?: Prog[] }>(base, "ProjectService/ListPrograms", { projectId: "default", includeDeleted })).programs ?? [];

  await check("programs: rename and delete from the open dialog's menu, restore from the trash, a new project", async () => {
    // A leftover program to clean up.
    await rpc(base, "ProjectService/ImportProgram", { projectId: "default", path: c.exe, name: "leftover", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
    const p = await open(base);
    await ready(p);
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+o");
    const row = p.locator("[data-testid=open-row]", { hasText: /^leftover/ });
    await row.waitFor();
    // Rename from the context menu.
    await row.click({ button: "right" });
    await p.waitForSelector("[data-testid=menu]");
    await shot(p, "01-open-menu");
    await p.click("[data-testid=menu-rename]");
    await c.answer(p, "scratch copy");
    await p.locator("[data-testid=open-row]", { hasText: /^scratch copy/ }).waitFor();
    const renamed = (await programs()).find((x) => x.name === "scratch copy");
    assert(renamed, `renamed: ${JSON.stringify(await programs())}`);
    // Delete with the keyboard: select it (Home, then the arrows), Delete, confirm.
    const rows = await p.locator("[data-testid=open-list] > .od-row").allTextContents();
    const at = rows.findIndex((t) => t.startsWith("scratch copy"));
    await p.focus("[data-testid=open-list]");
    await p.keyboard.press("Home");
    for (let i = 0; i < at; i++) await p.keyboard.press("ArrowDown");
    assert((await p.locator("[data-testid=open-row].active").textContent())?.startsWith("scratch copy"), "the arrows picked it");
    await p.keyboard.press("Delete");
    await p.waitForSelector("[data-testid=choose]");
    await shot(p, "02-delete-confirm");
    await p.keyboard.press("ArrowUp");
    await p.keyboard.press("Enter");
    await p.locator("[data-testid=open-row]", { hasText: /^scratch copy/ }).waitFor({ state: "detached" });
    assert(!(await programs()).some((x) => x.programId === renamed.programId), "hidden from ListPrograms");
    assert((await programs(true)).some((x) => x.programId === renamed.programId && x.deleted), "listed as deleted");
    // The trash (⋯ → Show deleted programs) restores it: a double click.
    await p.click("[data-testid=open-overflow]");
    await p.click("[data-testid=menu-show-deleted]");
    const gone = p.locator("[data-testid=open-row].deleted", { hasText: "scratch copy" });
    await gone.waitFor();
    await shot(p, "03-trash");
    await gone.click();
    assert((await p.textContent("[data-testid=open-go]"))?.includes("Restore"), "the footer's button restores a deleted program");
    await gone.dblclick();
    await p.locator("[data-testid=open-row]:not(.deleted)", { hasText: /^scratch copy/ }).waitFor();
    assert((await programs()).some((x) => x.programId === renamed.programId), "restored");
    // And deleted for good (the leftover is cleaned up), from the row's ⋯ button.
    const again = p.locator("[data-testid=open-row]:not(.deleted)", { hasText: /^scratch copy/ });
    await again.hover();
    await again.locator("[data-testid=open-row-menu]").click();
    await p.click("[data-testid=menu-delete]");
    await p.locator("[data-testid=choose] .palette-item").first().click();
    await p.locator("[data-testid=open-row]:not(.deleted)", { hasText: /^scratch copy/ }).waitFor({ state: "detached" });
    // A new project from the switcher, then back.
    await p.selectOption("[data-testid=open-project]", { label: "New project…" });
    await c.answer(p, "e2e-scratch");
    await p.waitForFunction(() => (document.querySelector("[data-testid=open-project]") as HTMLSelectElement).value === "e2e-scratch");
    await p.locator("[data-testid=open-list]", { hasText: "No programs yet" }).waitFor();
    await p.selectOption("[data-testid=open-project]", "default");
    await p.locator("[data-testid=open-row]", { hasText: /^prog/ }).first().waitFor();
    await p.context().close();
  });

  await check("programs: renaming the open program updates every tab's title", async () => {
    const a = await open(base);
    const b = await open(base);
    await ready(a);
    await ready(b);
    await command(a, "File: Rename this program");
    await c.answer(a, "prog renamed");
    await b.waitForFunction(() => document.getElementById("program")?.textContent === "prog renamed");
    await a.waitForFunction(() => document.title.startsWith("prog renamed"));
    // Undo from the API (an empty name restores the imported one).
    await rpc(base, "ProjectService/RenameProgram", { programId: "default/prog", name: "", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
    await b.waitForFunction(() => document.getElementById("program")?.textContent === "prog");
    await a.context().close();
    await b.context().close();
  });

  await check("functions: signatures, sorting by size and references, filters (thunks, decompiler failures)", async () => {
    type F = { name: string; size?: string; xrefCount?: number; thunk?: boolean; prototype?: string };
    const list = async (body: object) =>
      (await rpc<{ functions?: F[]; page?: { totalCount?: string } }>(base, "QueryService/ListFunctions", { programId: "default/prog", page: { pageSize: 1000 }, ...body }));
    const p = await open(base);
    await ready(p);
    // A user's prototype shows in the list, in the user's colour.
    const twice = await c.sym("twice");
    const r = await rpc<{ assertions: { seq: string }[] }>(base, "AssertionService/AppendAssertions", {
      programId: "default/prog",
      provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
      assertions: [{ body: { retype: { target: { address: { offset: String(twice) } }, type: { cDeclaration: "int twice(int x)" } } } }],
    });
    const sig = p.locator(".fn-row", { has: p.locator(".fn-name", { hasText: /^twice$/ }) }).locator("[data-testid=fn-sig].o-user");
    await sig.waitFor({ timeout: 10000 });
    c.assert((await sig.textContent())?.includes("int twice(int x)"), `signature: ${await sig.textContent()}`);
    await rpc(base, "AssertionService/RetractAssertions", { programId: "default/prog", seqs: [r.assertions[0].seq], provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
    // Sorted by size, largest first; again, smallest first.
    const bySize = (await list({ sort: "FUNCTION_SORT_SIZE", descending: true })).functions ?? [];
    await p.click("[data-testid=fn-sort-size]");
    await p.locator(".fn-row").first().locator(".fn-name", { hasText: new RegExp(`^${bySize[0].name}$`) }).waitFor({ timeout: 5000 });
    c.assert((await p.getAttribute("[data-testid=fn-sort-size]", "aria-pressed")) === "true", "size sort pressed");
    await shot(p, "10-functions-size");
    await p.click("[data-testid=fn-sort-size]");
    await p.locator(".fn-row").first().locator(".fn-name", { hasText: new RegExp(`^${bySize[bySize.length - 1].name}$`) }).waitFor({ timeout: 5000 });
    // References, most first.
    const byRefs = (await list({ sort: "FUNCTION_SORT_XREFS", descending: true })).functions ?? [];
    await p.click("[data-testid=fn-sort-xrefs]");
    await p.locator(".fn-row").first().locator(".fn-name", { hasText: new RegExp(`^${byRefs[0].name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`) }).waitFor({ timeout: 5000 });
    // Thunks only.
    const thunks = Number((await list({ thunks: "FUNCTION_THUNK_FILTER_ONLY" })).page?.totalCount ?? 0);
    c.assert(thunks > 0, "the program has thunks (PLT stubs)");
    await p.selectOption("[data-testid=fn-show]", "thunks");
    await p.locator("[data-testid=fn-count]", { hasText: `${thunks} match` }).waitFor({ timeout: 5000 });
    c.assert((await p.locator(".fn-row:not(.thunk):not(.loading)").count()) === 0, "only thunks listed");
    // Back to the default (remembered otherwise).
    await p.selectOption("[data-testid=fn-show]", "all");
    await p.click("[data-testid=fn-sort-address]");
    await p.context().close();

    // A function the decompiler crashes on is listed under "Decompiler failed".
    const crashing = await c.crashingDaemon(`segv@${twice.toString(16)}`);
    const q = await open(crashing, "", `#${twice.toString(16)}`);
    await q.waitForSelector("[data-testid=decomp-failure]:not([hidden])", { timeout: 20000 });
    await q.selectOption("[data-testid=fn-show]", "failed");
    await q.locator("[data-testid=fn-count]", { hasText: "1 match" }).waitFor({ timeout: 5000 });
    await q.locator(".fn-row .fn-name", { hasText: /^twice$/ }).waitFor();
    c.assert((await q.locator(".fn-row .fn-badge.fail").count()) === 1, "failure badge");
    await shot(q, "11-functions-failed");
    await q.selectOption("[data-testid=fn-show]", "all");
    await q.context().close();
  });

  // A program with a jump table, for the graph's switch labels.
  const SWITCHY = String.raw`
#include <stdio.h>
__attribute__((noinline)) void classify(int c) {
  switch (c) {
    case 0: puts("zero"); break;
    case 1: puts("one"); break;
    case 2: puts("two"); break;
    case 3: puts("three"); break;
    case 4: puts("four"); break;
    case 5: puts("five"); break;
    default: puts("many"); break;
  }
}
int main(int argc, char **argv) { (void)argv; classify(argc); return 0; }
`;
  type Shown = {
    blocks: { start: string; group: boolean; collapsed: boolean; members: number; lines: number; first: string; last: string }[];
    labels: { from: string; to: string; label: string }[];
    minimap: boolean;
    view: { s: number; tx: number; ty: number };
  };
  /** A page on another program of the daemon. */
  const openProgram = async (id: string, hash: string) => {
    const p = await open(base);
    await p.goto(`${base}/?program=${encodeURIComponent(id)}&user=e2e&theme=dark#${hash}`);
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    return p;
  };
  const shown = (p: Page) => p.evaluate("window.__revkit.app.graph.shown()") as Promise<Shown>;
  const untilShown = async (p: Page, what: string, pred: (s: Shown) => boolean, ms = 10000) => {
    const end = Date.now() + ms;
    let s = await shown(p);
    while (!pred(s)) {
      if (Date.now() > end) throw new Error(`timed out waiting for ${what}: ${JSON.stringify(s).slice(0, 600)}`);
      await p.waitForTimeout(50);
      s = await shown(p);
    }
    return s;
  };
  const dir = path.dirname(c.exe);
  const swExe = path.join(dir, "switchy");
  writeFileSync(swExe + ".c", SWITCHY);
  execFileSync(process.env.CC ?? "cc", ["-O1", "-g0", "-o", swExe, swExe + ".c"]);
  await rpc(base, "ProjectService/ImportProgram", { projectId: "default", path: swExe, name: "switchy", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
  const sw = await rpc<{ symbols: { address: { offset: string } }[] }>(base, "QueryService/ListSymbols", { programId: "default/switchy", nameEquals: "classify" });
  const classify = BigInt(sw.symbols[0].address.offset);

  await check("graph: switch edges labelled with their cases, the minimap, collapsing and grouping blocks", async () => {
    const p = await openProgram("default/switchy", classify.toString(16));
    await c.until<Snap>(p, "classify", (s) => s.decompName === "classify");
    await p.keyboard.press("Control+4");
    const s = await untilShown(p, "case labels", (x) => x.labels.length >= 6);
    for (const k of ["0", "1", "2", "3", "4", "5"]) assert(s.labels.some((l) => l.label === `case ${k}`), `case ${k}: ${JSON.stringify(s.labels)}`);
    await shot(p, "20-graph-switch");
    // Zoomed in, the minimap shows; a click on it moves the view.
    await p.focus("[data-testid=graph-canvas]");
    for (let i = 0; i < 4; i++) await p.keyboard.press("+");
    const before = await untilShown(p, "the minimap", (x) => x.minimap);
    const box = (await p.locator("[data-testid=graph-minimap]").boundingBox())!;
    await p.mouse.click(box.x + box.width - 6, box.y + box.height - 6);
    const after = await untilShown(p, "the view moved", (x) => x.view.tx !== before.view.tx || x.view.ty !== before.view.ty);
    assert(after.view.s === before.view.s, "the minimap pans, it doesn't zoom");
    await shot(p, "21-graph-minimap");
    // Collapse the entry block (c), and back.
    await p.focus("[data-testid=graph-canvas]");
    await p.keyboard.press("0");
    await p.evaluate(`window.__revkit.app.navigate(0x${classify.toString(16)}n)`);
    await p.focus("[data-testid=graph-canvas]");
    const blocks = before.blocks.length;
    await p.keyboard.press("c");
    await untilShown(p, "collapsed", (x) => x.blocks.some((b) => b.collapsed));
    await p.keyboard.press("c");
    await untilShown(p, "expanded", (x) => !x.blocks.some((b) => b.collapsed));
    // Group the dispatch block with the cases it dominates (Shift+C), then the menu's Expand group.
    const dispatch = s.labels[0].from;
    await p.evaluate(`window.__revkit.app.navigate(0x${dispatch}n)`);
    await p.focus("[data-testid=graph-canvas]");
    await p.keyboard.press("Shift+C");
    const grouped = await untilShown(p, "a group", (x) => x.blocks.some((b) => b.group));
    assert(grouped.blocks.length < blocks, `grouped: ${grouped.blocks.length} of ${blocks}`);
    await shot(p, "22-graph-grouped");
    await p.keyboard.press("Shift+E");
    await untilShown(p, "expanded again", (x) => x.blocks.length === blocks && !x.blocks.some((b) => b.group));
    await p.context().close();
  });

  await check("plugins: analyzer facts in the graph and the decompiler, not only the listing", async () => {
    const p = await openProgram("default/switchy", classify.toString(16));
    await c.until<Snap>(p, "classify", (s) => s.decompName === "classify");
    const analyzers = (await p.evaluate("window.__revkit.app.plugins.analyzers.length")) as number;
    if (!analyzers) {
      c.log("     (no analyzer plugins loaded: skipped)");
      await p.context().close();
      return;
    }
    await p.waitForFunction("window.__revkit.app.pane.shownNotes().some((t) => t.includes('string-refs') && t.includes('zero'))", undefined, { timeout: 10000 });
    await p.keyboard.press("Control+4");
    await p.waitForFunction("window.__revkit.app.graph.annotations().some((a) => a.text.includes('zero'))", undefined, { timeout: 10000 });
    await shot(p, "30-plugin-facts");
    await p.context().close();
  });

  await check("graph: delay slots (MIPS) stay in their branch's block", async () => {
    let mips = "";
    try {
      const src = path.join(dir, "mips.c");
      writeFileSync(src, "int g;\n__attribute__((noinline)) int h(int x) { return x ^ g; }\n__attribute__((noinline)) int f(const int *p, int n) { int s = 0; for (int i = 0; i < n; i++) s += h(p[i]); return s; }\nvoid __start(void) { g = f(&g, g); for (;;); }\n");
      execFileSync("clang", ["--target=mipsel-linux-gnu", "-O1", "-fno-pic", "-mno-abicalls", "-c", src, "-o", path.join(dir, "mips.o")], { stdio: "ignore" });
      execFileSync("ld.lld", ["-e", "__start", "-o", path.join(dir, "mips.elf"), path.join(dir, "mips.o")], { stdio: "ignore" });
      mips = path.join(dir, "mips.elf");
    } catch {
      c.log("     (no clang and ld.lld for MIPS: skipped)");
      return;
    }
    await rpc(base, "ProjectService/ImportProgram", { projectId: "default", path: mips, name: "mips", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
    const f = await rpc<{ symbols: { address: { offset: string } }[] }>(base, "QueryService/ListSymbols", { programId: "default/mips", nameEquals: "f" });
    const at = BigInt(f.symbols[0].address.offset).toString(16);
    const p = await openProgram("default/mips", at);
    await p.waitForFunction("window.__revkit.app.snapshot().decompName === 'f'", undefined, { timeout: 20000 });
    await p.keyboard.press("Control+4");
    const s = await untilShown(p, "f's graph", (x) => x.blocks.length >= 4);
    for (const b of s.blocks) assert(!b.first.startsWith("_"), `block ${b.start} starts with the delay slot ${b.first}`);
    assert(s.blocks.some((b) => b.last.startsWith("_")), `a block ends with its branch's delay slot: ${JSON.stringify(s.blocks)}`);
    await shot(p, "23-graph-mips");
    await p.context().close();
  });

  await check("types: a category tree by source and kind, letters for big kinds, loaded as opened, only rows in view drawn", async () => {
    type T = { tree: boolean; rows: number; branches: string[]; names: string[]; shown: { name: string } | null };
    const types = (p: Page) => p.evaluate("window.__revkit.app.types.describe()") as Promise<T>;
    const untilTypes = async (p: Page, what: string, pred: (t: T) => boolean) => {
      const end = Date.now() + 15000;
      let t = await types(p);
      while (!pred(t)) {
        if (Date.now() > end) throw new Error(`timed out waiting for ${what}: ${JSON.stringify({ ...t, names: t.names.slice(0, 20) })}`);
        await p.waitForTimeout(50);
        t = await types(p);
      }
      return t;
    };
    const p = await open(base);
    await ready(p);
    await p.keyboard.press("Control+7");
    await p.selectOption("[data-testid=types-source]", "0");
    let t = await untilTypes(p, "the tree's roots", (x) => x.tree && x.branches.some((b) => b.startsWith("Library archives")));
    // The library is closed until opened; its typedefs split by letter.
    assert(!t.branches.some((b) => b.startsWith("  typedefs") && b.includes("(open)") && t.branches.indexOf(b) > t.branches.findIndex((x) => x.startsWith("Library"))), "library closed");
    // Close the program's types (open by default), so the library's root is in view.
    await p.locator("[data-testid=types-branch]", { hasText: /^▾Program types/ }).click();
    const lib = p.locator("[data-testid=types-branch]", { hasText: "Library archives" });
    await lib.click();
    t = await untilTypes(p, "library kinds", (x) => x.branches.some((b) => /^ {2}typedefs \d+/.test(b) && x.branches.indexOf(b) > x.branches.findIndex((y) => y.startsWith("Library"))));
    // Keyboard: down to the library's structs, Right opens them, by letter.
    await p.locator("[data-testid=types-branch]", { hasText: /^▸structs/ }).last().click();
    t = await untilTypes(p, "letters", (x) => x.branches.some((b) => /^ {4}T \d+/.test(b)));
    // Scrolled into view (only the rows in view are in the DOM).
    const scrollTo = async (loc: ReturnType<Page["locator"]>) => {
      for (let i = 0; i < 200 && !(await loc.count()); i++) {
        await p.locator("[data-testid=types-list]").evaluate((el) => (el.scrollTop += 120));
        await p.waitForTimeout(20);
      }
    };
    const letterT = p.locator("[data-testid=types-branch]", { hasText: /^▸T\d/ });
    await scrollTo(letterT);
    await letterT.click();
    t = await untilTypes(p, "struct timespec under T", (x) => x.names.includes("struct timespec"));
    const drawn = await p.locator("[data-testid=types-list] .types-row").count();
    assert(drawn < t.rows || t.rows < 40, `virtualized: ${drawn} rows in the DOM of ${t.rows}`);
    const ts = p.locator("[data-testid=types-list] .types-row", { hasText: /^structtimespec\d/ });
    await scrollTo(ts);
    await ts.click();
    await untilTypes(p, "timespec shown", (x) => x.shown?.name === "timespec");
    await shot(p, "40-types-tree");
    // A search is flat again.
    await p.fill("[data-testid=types-filter]", "timespec");
    await untilTypes(p, "flat search", (x) => !x.tree && x.names.includes("struct timespec"));
    await p.context().close();
  });

  await check("large tables: 10,500 references and 12,000 notes, only the rows in view in the DOM", async () => {
    // 105 functions with 100 calls each to one sink.
    const fns = Array.from({ length: 105 }, (_, i) => `__attribute__((noinline)) void caller${i}(int x) {\n${"  sink(x);\n".repeat(100)}}`).join("\n");
    const src = `__attribute__((noinline)) void sink(int x) { __asm__ volatile("" :: "r"(x)); }\n${fns}\nint main(int argc, char **argv) { (void)argv; caller0(argc); return 0; }\n`;
    const bigExe = path.join(dir, "manyrefs");
    writeFileSync(bigExe + ".c", src);
    execFileSync(process.env.CC ?? "cc", ["-O1", "-g0", "-o", bigExe, bigExe + ".c"]);
    await rpc(base, "ProjectService/ImportProgram", { projectId: "default", path: bigExe, name: "manyrefs", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
    const sink = (await rpc<{ symbols: { address: { offset: string } }[] }>(base, "QueryService/ListSymbols", { programId: "default/manyrefs", nameEquals: "sink" })).symbols[0].address.offset;
    // 12,000 notes in one request.
    const notes = Array.from({ length: 12000 }, (_, i) => ({ body: { note: { address: { offset: sink }, tag: `n${String(i).padStart(5, "0")}`, text: `note ${i}` } } }));
    await rpc(base, "AssertionService/AppendAssertions", { programId: "default/manyrefs", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" }, assertions: notes });
    const p = await openProgram("default/manyrefs", BigInt(sink).toString(16));
    await p.waitForFunction("document.querySelector('[data-testid=notes-count]')?.textContent === '12000'", undefined, { timeout: 30000 });
    const noteRows = await p.locator("[data-testid=notes] .note-row").count();
    assert(noteRows > 0 && noteRows < 200, `${noteRows} note rows in the DOM`);
    await p.locator("[data-testid=notes]").evaluate((el) => (el.scrollTop = el.scrollHeight));
    await p.locator("[data-testid=notes] .note-row", { hasText: "note 11999" }).waitFor({ timeout: 5000 });
    // References: the dialog says 10,500 and draws a screenful.
    await p.focus("#listing-canvas");
    await p.keyboard.press("x");
    await p.locator("[data-testid=xrefs] .modal-title", { hasText: "(10,500)" }).waitFor({ timeout: 20000 });
    const refRows = await p.locator("[data-testid=xrefs] .palette-item").count();
    assert(refRows > 0 && refRows < 200, `${refRows} reference rows in the DOM`);
    await shot(p, "50-xrefs-10500");
    // End: the last reference (pages load as the list scrolls).
    await p.keyboard.press("End");
    await p.locator("[data-testid=xrefs] .palette-item.active .pi-detail", { hasText: "caller104" }).waitFor({ timeout: 20000 });
    await p.keyboard.press("Escape");
    await p.context().close();
  });

  await check("file chooser: made on demand and timed, the live stream paused while it is open, the diagnostics dialog", async () => {
    const p = await open(base);
    await ready(p);
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+o");
    await p.waitForSelector("[data-testid=open-dialog] [data-testid=open-row]");
    assert((await p.locator("input[type=file]").count()) === 0, "no file input waits in the page");
    await p.click("[data-testid=open-import-binary]");
    // Cancelled from the chooser (Playwright answers it): the stream pauses and comes back.
    const [chooser] = await Promise.all([p.waitForEvent("filechooser"), p.click("[data-testid=open-import]")]);
    assert(!chooser.isMultiple(), "one file");
    await p.waitForFunction("document.body.dataset.live === 'paused'", undefined, { timeout: 5000 });
    await chooser.setFiles([]);
    await p.waitForFunction("document.body.dataset.live === 'live'", undefined, { timeout: 10000 });
    assert((await p.locator("input[type=file]").count()) === 0, "the input is removed after the pick");
    // Escape: back to the programs from the import section, then closed.
    await p.keyboard.press("Escape");
    await p.waitForSelector("[data-testid=open-import-view][hidden]", { state: "attached" });
    await p.keyboard.press("Escape");
    await p.waitForSelector("[data-testid=open-dialog]", { state: "detached" });
    // The diagnostics dialog lists the pick.
    await command(p, "Diagnostics: time the system file chooser");
    await p.waitForSelector("[data-testid=picker-diagnostics]");
    const rows = await p.locator("[data-testid=picker-results] tr").count();
    assert(rows >= 2, `${rows} rows of timings`);
    await shot(p, "60-picker-diagnostics");
    await p.keyboard.press("Escape");
    await p.context().close();
  });

  await check("accessibility: names, roles and AA contrast in both themes, ten states (axe too when installed)", async () => {
    const problems: string[] = [];
    let withAxe = false;
    for (const theme of ["dark", "light"]) {
      const p = await open(base);
      await p.goto(`${base}/?program=default%2Fswitchy&user=e2e&theme=${theme}#${classify.toString(16)}`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      await c.until<Snap>(p, "classify", (s) => s.decompName === "classify");
      // Each state is audited once it has settled (its rows loaded), not after a pause.
      const settled = (what: string, expr: string) =>
        p.waitForFunction(expr, undefined, { timeout: 20000 }).catch(() => {
          throw new Error(`${theme}: timed out waiting for ${what}`);
        });
      await settled("the notes", "!document.querySelector('[data-testid=notes]')?.hasAttribute('aria-busy')");
      const run = async (state: string) => {
        const r = await audit(p);
        withAxe ||= r.axe;
        for (const i of r.issues) problems.push(`${theme}/${state}: ${i.rule} ${i.where} ${i.detail}`);
      };
      await run("main");
      await p.keyboard.press("Control+Shift+P");
      await p.waitForSelector("[data-testid=palette] .palette-item");
      await run("palette");
      await p.keyboard.press("Escape");
      await p.keyboard.press("Control+o");
      await p.waitForSelector("[data-testid=open-row]");
      await run("open dialog");
      await p.keyboard.press("Escape");
      await p.keyboard.press("Control+4");
      await untilShown(p, "graph", (x) => x.blocks.length > 1);
      await run("graph");
      await p.locator("[data-testid=graph-canvas]").click({ button: "right", position: { x: 300, y: 120 } });
      if (await p.locator("[data-testid=menu]").count()) await run("graph menu");
      await p.keyboard.press("Escape");
      await p.keyboard.press("Control+7");
      await p.waitForSelector("[data-testid=types-branch]");
      await run("types");
      // The type editor, laid out, and the header import with a parse.
      await p.selectOption("[data-testid=types-new]", "struct");
      await p.fill("[data-testid=type-name]", "a11y_s");
      await p.press("[data-testid=type-name]", "Tab");
      await settled("the editor's layout", "(document.querySelector('[data-testid=type-layout]')?.textContent ?? '').startsWith('Laid out by the daemon')");
      await run("type editor");
      await p.click("[data-testid=type-cancel]");
      await p.click("[data-testid=types-import]");
      await p.fill("[data-testid=hi-text]", "#define K 1\nstruct a11y_a { int x; };\nstruct a11y_b { nope_t y; };\n");
      await p.click("[data-testid=hi-parse]");
      await settled("the header's parse", "!!document.querySelector('[data-testid=hi-diag]')");
      await run("header import");
      await p.keyboard.press("Escape");
      // The view keys are not taken from a text field, and showing the types
      // (and then the data) leaves the focus in the view's filter.
      const leaveFilter = () => p.evaluate("document.activeElement?.blur()");
      await leaveFilter();
      await p.keyboard.press("Control+6");
      await settled("the data view", "!!document.querySelector('[data-testid=data-view] [data-testid=data-count]')?.textContent");
      await run("data");
      await leaveFilter();
      await p.keyboard.press("Control+5");
      await settled("the call tree", "(() => { const r = [...document.querySelectorAll('[data-testid=calls-tree] .calls-row .tw')]; return r.length > 0 && r.every((t) => t.textContent !== '…'); })()");
      await run("calls");
      if (theme === "dark") await shot(p, "70-a11y-dark");
      else await shot(p, "71-a11y-light");
      await p.context().close();
    }
    c.log(`     ${withAxe ? "built-in checks and axe-core" : "built-in checks (axe-core not installed; RK_AXE=<axe.min.js> adds it)"}: ${problems.length} problem${problems.length === 1 ? "" : "s"}`);
    assert(!problems.length, problems.slice(0, 25).join("\n"));
  });

  await check("keyboard: one tab stop per tab group, notes reachable, every key in the palette with its key", async () => {
    const p = await openProgram("default/switchy", classify.toString(16));
    await c.until<Snap>(p, "classify", (s) => s.decompName === "classify");
    await p.evaluate("document.activeElement?.blur()");
    const stops: string[] = [];
    for (let i = 0; i < 40; i++) {
      await p.keyboard.press("Tab");
      const at = (await p.evaluate("(() => { const a = document.activeElement; return a ? (a.dataset.testid || a.id || a.getAttribute('aria-label') || a.tagName) : '' })()")) as string;
      if (stops.includes(at)) break;
      stops.push(at);
    }
    const tabs = stops.filter((x) => x.startsWith("tab-"));
    assert(tabs.length === 2, `one stop per tab group: ${tabs.join(", ")}`);
    for (const want of ["search", "fn-filter", "fn-show", "notes", "listing-canvas", "Decompiled code"]) assert(stops.includes(want), `${want} is reachable by Tab: ${stops.join(" → ")}`);
    // Arrow keys move between tabs.
    await p.focus(`[data-testid=${tabs[0]}]`);
    await p.keyboard.press("ArrowRight");
    const next = (await p.evaluate("document.activeElement?.dataset.testid")) as string;
    assert(next !== tabs[0] && next.startsWith("tab-"), `ArrowRight moved to ${next}`);
    await p.keyboard.press("Control+2");
    // The palette lists the graph's keys, and running one works.
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+Shift+P");
    await p.fill("[data-testid=palette-input]", ">graph");
    const items = await p.locator(".palette-item").allTextContents();
    for (const k of ["fit the whole function0", "the minimapm", "collapse or expand the selected blockc", "dominatesShift+C", "expand all blocks and groupsShift+E"])
      assert(items.some((t) => t.includes(k)), `palette has "${k}": ${items.join(" | ")}`);
    await p.keyboard.press("Escape");
    const on = (await p.evaluate("window.__revkit.app.graph.showMinimap")) as boolean;
    await command(p, `Graph: ${on ? "hide" : "show"} the minimap`);
    await p.waitForFunction(`window.__revkit.app.graph.showMinimap === ${!on}`);
    assert((await p.evaluate("window.__revkit.app.dock.isVisible('graph')")) === true, "the command showed the graph");
    await command(p, `Graph: ${on ? "show" : "hide"} the minimap`);
    await p.waitForFunction(`window.__revkit.app.graph.showMinimap === ${on}`);
    await p.context().close();
  });
}
