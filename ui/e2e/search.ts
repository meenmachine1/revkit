// End-to-end checks for the searches (feature search; docs/ui.md "Search"):
// Search Memory from S (hex with wildcards, Next and Previous, F3 and
// Shift+F3 after closing; Ctrl+Shift+E; a string in any case and a decimal
// into the results table, sorted, filtered, copied as CSV, made a
// selection), Search Program Text from Ctrl+Shift+F (a rename counts; a
// click on a result jumps there), scalars from the palette, and decompiled
// code from the Search menu (progress, a click opens the decompiler at the
// line, F3 steps through the results, Cancel). run.ts calls searchChecks()
// with page A open on default/prog.

import type { Page } from "playwright";
import path from "node:path";

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

interface Snap {
  address: string | null;
  rowKind: number | null;
  func: string | null;
  decompName: string | null;
  views: string[];
  foundLine: number | null;
  rangeSelection: [string, string][];
  searchMarks: number;
  search: {
    dialog: string | null;
    status: string;
    last: string | null;
    results: { title: string; running: boolean; count: number; truncated: boolean; error: string; cancelled: boolean } | null;
  } | null;
}

export interface SearchContext {
  base: string;
  a: Page;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  sym: (name: string) => Promise<bigint>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  go: (p: Page, addr: bigint | string) => Promise<unknown>;
}

const hx = (a: bigint) => a.toString(16);
const snap = (p: Page): Promise<Snap> => p.evaluate("window.__revkit.app.snapshot()") as Promise<Snap>;
const rows = (p: Page): Promise<string[][]> => p.evaluate("window.__revkit.app.search.results.visible()") as Promise<string[][]>;

/** Runs a palette command by the start of its title. */
async function command(p: Page, title: string) {
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+Shift+P");
  await p.waitForSelector("[data-testid=palette-input]");
  await p.fill("[data-testid=palette-input]", ">" + title.toLowerCase());
  await p.waitForFunction((t) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").startsWith(t), title);
  await p.keyboard.press("Enter");
}

/** Waits until the keyboard is in a search dialog. */
async function inDialog(p: Page, kind: string) {
  await p.waitForFunction((k) => !!document.querySelector(`[data-testid=search-${k}]`)?.contains(document.activeElement), kind);
}

async function until(p: Page, what: string, pred: (s: Snap) => boolean, ms = 20000): Promise<Snap> {
  const end = Date.now() + ms;
  let s = await snap(p);
  while (!pred(s)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify({ address: s.address, search: s.search, views: s.views, foundLine: s.foundLine, decompName: s.decompName })}`);
    await p.waitForTimeout(50);
    s = await snap(p);
  }
  return s;
}

/** Waits for the shown result set to finish; its rows. */
async function results(p: Page, what: string, ms = 60000): Promise<string[][]> {
  await until(p, what, (s) => !!s.search?.results && !s.search.results.running, ms);
  const s = await snap(p);
  if (s.search?.results?.error) throw new Error(`${what}: ${s.search.results.error}`);
  return rows(p);
}

export async function searchChecks(c: SearchContext) {
  const { a, check } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const checksum = await c.sym("checksum");
  const twice = await c.sym("twice");
  const main = await c.sym("main");

  await check("search memory: S opens the dialog; hex with wildcards, Next, Previous, F3 and Shift+F3 after closing", async () => {
    await c.go(a, main);
    await a.focus("#listing-canvas");
    await a.keyboard.press("s");
    await a.waitForSelector("[data-testid=search-memory]");
    await a.selectOption("[data-testid=search-memory] [data-testid=search-format]", "1"); // hex
    // CALL rel32: e8 and four bytes of any value.
    await a.fill("[data-testid=search-memory] [data-testid=search-query]", "e8 ?? ?? ?? ??");
    await a.keyboard.press("Enter");
    let s = await until(a, "the first call after main", (s) => /found at/.test(s.search?.status ?? "") && s.address !== hx(main));
    const first = BigInt("0x" + s.address);
    assert(first > main, `next goes forward: ${s.address}`);
    await shot(a, "search-memory-dialog");
    await a.keyboard.press("Enter");
    s = await until(a, "the second call", (s) => s.address !== hx(first) && /found at/.test(s.search?.status ?? ""));
    const second = BigInt("0x" + s.address);
    assert(second > first, `the second call is after the first: ${hx(second)} ${hx(first)}`);
    await a.keyboard.press("Shift+Enter");
    await until(a, "back to the first call", (s) => s.address === hx(first));
    // Closed, F3 and Shift+F3 repeat it.
    await a.keyboard.press("Escape");
    await a.waitForSelector("[data-testid=search-memory]", { state: "detached" });
    await a.focus("#listing-canvas");
    await a.keyboard.press("F3");
    await until(a, "F3: the second call again", (s) => s.address === hx(second));
    await a.keyboard.press("Shift+F3");
    await until(a, "Shift+F3: the first", (s) => s.address === hx(first));
    // Ctrl+Shift+E opens it too, with what was typed.
    await a.keyboard.press("Control+Shift+E");
    await a.waitForSelector("[data-testid=search-memory]");
    assert((await a.inputValue("[data-testid=search-memory] [data-testid=search-query]")) === "e8 ?? ?? ?? ??", "the query is kept");
    await a.keyboard.press("Escape");
  });

  await check("search memory: a string in any case and a decimal into the results table; sort, filter, CSV, make selection", async () => {
    // From the toolbar's Search menu.
    await a.click("[data-testid=search-menu]");
    await a.click("[data-testid=menu-search-memory]");
    await a.waitForSelector("[data-testid=search-memory]");
    await a.selectOption("[data-testid=search-memory] [data-testid=search-format]", "2"); // string
    await a.fill("[data-testid=search-memory] [data-testid=search-query]", "%U %D");
    await a.uncheck("[data-testid=search-memory] [data-testid=search-case]");
    await a.focus("[data-testid=search-memory] [data-testid=search-query]");
    await a.keyboard.press("Control+Enter");
    let r = await results(a, "the format string");
    assert(r.length === 1, `one match for the format string: ${JSON.stringify(r)}`);
    assert(r[0][2] === "25 75 20 25 64", `the bytes as found: ${r[0][2]}`);
    let s = await snap(a);
    assert(s.views.includes("searchresults"), `the results are shown: ${s.views}`);
    assert(s.searchMarks === 1, "the hit is marked in the listing");
    // The FNV offset basis as a 4-byte decimal (the program's byte order).
    await a.keyboard.press("Control+Shift+E");
    await a.selectOption("[data-testid=search-memory] [data-testid=search-format]", "3"); // decimal
    await a.fill("[data-testid=search-memory] [data-testid=search-query]", "2166136261");
    await a.check("[data-testid=search-memory] [data-testid=search-unsigned]");
    await a.click("[data-testid=search-memory] [data-testid=search-all]");
    r = await results(a, "the FNV basis");
    assert(r.length >= 1 && r.every((x) => x[3].includes("0x811c9dc5") && x[4] === "checksum"), `the basis in checksum: ${JSON.stringify(r)}`);
    // Every call, then sorted, filtered, copied, selected.
    await a.keyboard.press("Control+Shift+E");
    await a.selectOption("[data-testid=search-memory] [data-testid=search-format]", "1");
    await a.fill("[data-testid=search-memory] [data-testid=search-query]", "e8 ?? ?? ?? ??");
    await a.uncheck("[data-testid=search-memory] [data-testid=search-data]");
    await a.uncheck("[data-testid=search-memory] [data-testid=search-undef]");
    await a.click("[data-testid=search-memory] [data-testid=search-all]");
    r = await results(a, "every call");
    assert(r.length >= 3, `calls: ${r.length}`);
    const addrs = r.map((x) => BigInt("0x" + x[0]));
    assert(addrs.every((x, i) => i === 0 || addrs[i - 1] < x), "in address order");
    assert(r.every((x) => x[3].startsWith("CALL")), `instructions only: ${JSON.stringify(r.map((x) => x[3]))}`);
    await a.click("[data-testid=search-col-0]");
    await a.click("[data-testid=search-col-0]");
    r = await rows(a);
    assert(BigInt("0x" + r[0][0]) === addrs[addrs.length - 1], "sorted by address, descending");
    await a.fill("[data-testid=search-filter]", "main");
    r = await rows(a);
    assert(r.length >= 2 && r.every((x) => x.join(" ").includes("main")), `filtered to main's calls: ${JSON.stringify(r)}`);
    const csv = (await a.evaluate("window.__revkit.app.search.results.csv()")) as string;
    const lines = csv.trim().split("\n");
    assert(lines[0] === "Address,Label,Match,Code unit,Function" && lines.length === r.length + 1, `CSV: ${csv}`);
    await a.click("[data-testid=search-csv]");
    await a.click("[data-testid=search-select]");
    s = await until(a, "a selection of the calls", (s) => s.rangeSelection.length === r.length);
    await shot(a, "search-results-memory");
    // A click on a row goes there (the selection made stays).
    await a.locator("[data-testid=search-row]").nth(1).click();
    await until(a, "the second row's call", (s) => s.address !== null && BigInt("0x" + s.address) === BigInt("0x" + r[1][0]));
    await a.fill("[data-testid=search-filter]", "");
    // Searching the selection made: only those calls.
    await a.keyboard.press("Control+Shift+E");
    await a.check("[data-testid=search-memory] [data-testid=search-memory-where-selection]");
    await a.click("[data-testid=search-memory] [data-testid=search-all]");
    const inSel = await results(a, "calls in the selection");
    assert(inSel.length === r.length && inSel.every((x) => x[4] === "main"), `the selection's calls: ${JSON.stringify(inSel)}`);
    await a.keyboard.press("Control+Shift+E");
    await a.check("[data-testid=search-memory] [data-testid=search-memory-where-all]");
    await a.check("[data-testid=search-memory] [data-testid=search-data]");
    await a.check("[data-testid=search-memory] [data-testid=search-undef]");
    await a.keyboard.press("Escape");
  });

  await check("search program text: Ctrl+F (Ghidra's); a rename counts; a click on a result jumps there", async () => {
    const renamed = "twice_found_by_search";
    const res = await c.rpc<{ assertions: { seq: string }[] }>(c.base, "AssertionService/AppendAssertions", {
      programId: "default/prog",
      provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
      assertions: [{ body: { rename: { target: { address: { offset: String(twice) } }, name: renamed } } }],
    });
    try {
      await c.go(a, main);
      await a.focus("#listing-canvas");
      await a.keyboard.press("Control+f");
      await a.waitForSelector("[data-testid=search-text]");
      await a.fill("[data-testid=search-text] [data-testid=search-query]", renamed);
      await a.keyboard.press("Enter");
      // Next from main: main's call of it (its operand) comes after main's entry.
      await until(a, "the call in main", (s) => s.func === hx(main) && /found at/.test(s.search?.status ?? ""));
      await a.keyboard.press("Control+Enter");
      const r = await results(a, "the renamed function");
      const fields = new Set(r.map((x) => x[1]));
      assert(fields.has("Labels") && fields.has("Functions") && fields.has("Operands"), `fields: ${JSON.stringify(r)}`);
      const call = r.find((x) => x[1] === "Operands")!;
      assert(call[2].includes(renamed), `the operand as shown: ${call[2]}`);
      const i = r.indexOf(call);
      await a.locator("[data-testid=search-row]").nth(i).click();
      await until(a, "the call", (s) => s.address !== null && BigInt("0x" + s.address) === BigInt("0x" + call[0]));
      // A regex over instructions.
      await a.keyboard.press("Control+f");
      await a.fill("[data-testid=search-text] [data-testid=search-query]", "^CALL\\s+(checksum|" + renamed + ")$");
      await a.check("[data-testid=search-text] [data-testid=search-regex]");
      await a.keyboard.press("Control+Enter");
      const calls = await results(a, "calls by regex");
      assert(calls.length >= 3 && calls.every((x) => /^CALL\s+/.test(x[2])), `calls: ${JSON.stringify(calls)}`);
      await a.keyboard.press("Control+f");
      await a.uncheck("[data-testid=search-text] [data-testid=search-regex]");
      await a.keyboard.press("Escape");
      await shot(a, "search-results-text");
    } finally {
      await c.rpc(c.base, "AssertionService/RetractAssertions", {
        programId: "default/prog",
        provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
        seqs: res.assertions.map((x) => x.seq),
      });
    }
  });

  await check("search scalars: from the palette, a value and a range; the table shows the instruction and function", async () => {
    await c.go(a, main);
    await command(a, "Search: scalars");
    await inDialog(a, "scalars");
    await a.fill("[data-testid=search-scalars] [data-testid=search-value]", "0x1000193");
    await a.keyboard.press("Control+Enter");
    let r = await results(a, "the FNV prime");
    assert(r.length >= 1 && r.every((x) => x[1] === "0x1000193" && x[2] === "16777619" && x[5] === "checksum" && x[4].includes("0x1000193")), `the prime: ${JSON.stringify(r)}`);
    await command(a, "Search: scalars");
    await inDialog(a, "scalars");
    await a.fill("[data-testid=search-scalars] [data-testid=search-min]", "0x811c9dc5");
    await a.fill("[data-testid=search-scalars] [data-testid=search-max]", "0x811c9dc5");
    await a.keyboard.press("Control+Enter");
    r = await results(a, "the FNV basis");
    assert(r.length >= 1 && r[0][5] === "checksum", `the basis: ${JSON.stringify(r)}`);
    // Next from the start of checksum finds it in the listing.
    await c.go(a, checksum);
    await command(a, "Search: scalars");
    await inDialog(a, "scalars");
    await a.keyboard.press("Enter");
    await until(a, "the basis's instruction", (s) => s.func === hx(checksum) && s.address !== hx(checksum) && /found at/.test(s.search?.status ?? ""));
    await a.keyboard.press("Escape");
  });

  await check("search decompiled code: from the Search menu over every function; a click opens the decompiler at the line; F3 steps; Cancel", async () => {
    await a.click("[data-testid=search-menu]");
    await a.click("[data-testid=menu-search-decompiled]");
    await a.waitForSelector("[data-testid=search-decompiled]");
    await a.fill("[data-testid=search-decompiled] [data-testid=search-query]", "checksum(");
    await a.check("[data-testid=search-decompiled] [data-testid=search-decompiled-where-all]");
    await a.keyboard.press("Enter");
    const r = await results(a, "calls of checksum in C", 120000);
    const fns = new Set(r.map((x) => x[0]));
    assert(fns.has("main") && fns.has("twice"), `functions: ${JSON.stringify(r)}`);
    const row = 0;
    await shot(a, "search-results-decompiled");
    await a.locator("[data-testid=search-row]").nth(row).click();
    let s = await until(a, `${r[row][0]} in the decompiler at the line`, (s) => s.decompName === r[row][0] && s.foundLine === Number(r[row][1]) - 1 && s.views.includes("decomp"));
    // F3 and Shift+F3: the next result and back.
    await a.focus("#listing-canvas");
    await a.keyboard.press("F3");
    s = await until(a, "F3: the next result", (s) => s.decompName === r[1][0] && s.foundLine === Number(r[1][1]) - 1);
    await a.keyboard.press("Shift+F3");
    s = await until(a, "Shift+F3: back", (s) => s.decompName === r[0][0] && s.foundLine === Number(r[0][1]) - 1);
    // Cancel at once: the set says so (or it had already finished).
    await a.click("[data-testid=search-menu]");
    await a.click("[data-testid=menu-search-decompiled]");
    await a.fill("[data-testid=search-decompiled] [data-testid=search-query]", "return");
    await a.keyboard.press("Enter");
    // Every function is decompiled by now, so it may already be done.
    await a.locator("[data-testid=search-cancel]").click({ timeout: 1000 }).catch(() => {});
    s = await until(a, "stopped", (s) => !!s.search?.results && !s.search.results.running);
    assert(!s.search!.results!.error, `no error: ${s.search!.results!.error}`);
    // Leave the views as the checks after these expect them.
    await a.evaluate("window.__revkit.app.showView('decomp')");
    await a.evaluate("window.__revkit.app.showView('listing')");
  });
}
