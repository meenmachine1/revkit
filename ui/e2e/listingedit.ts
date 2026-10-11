// End-to-end checks for editing what bytes are from the listing (feature
// listing-edit, docs/listing-edit.md; docs/ui.md "Listing edits"): Clear
// (c) over a function's rows takes it out of the functions list and leaves
// undefined bytes, Disassemble here (d) and the menu's "Disassemble and
// create function" bring it back; on printf's format string, b defines a
// byte and cycles it to a word, ' a char, [ an array that + expands and its marker
// collapses, i shows who defined it; " makes a string, the context menu's
// Data group marks it constant and its Recently used group redefines it;
// Shift+B still toggles the bytes column; Ctrl+Z undoes every step, and
// page B follows live. run.ts calls listingEditChecks() with pages A and B
// open on default/prog.

import type { Page } from "playwright";
import path from "node:path";

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

interface Row {
  row: number;
  address: string;
  kind: number;
  label: string;
  mnemonic: string;
  dataType: string;
  func: string | null;
  entry: boolean;
  operands: string;
  length: number;
  dataField: string;
  dataDepth: number;
  dataComponents: number;
  dataCollapsed: boolean;
  unit: string;
  mutability: number;
}

interface Snap {
  address: string | null;
  rowKind: number | null;
  selection: [number, number];
  functionCount: number;
}

export interface ListingEditContext {
  base: string;
  a: Page;
  b: Page;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  sym: (name: string) => Promise<bigint>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  /** Selects the code unit at an address (navigate), once it is selected. */
  go: (p: Page, addr: bigint | string) => Promise<unknown>;
  answer: (p: Page, text: string) => Promise<void>;
}

const KIND = { Instruction: 1, Data: 2, Undefined: 3, Header: 4 };
const CODE_UNIT = 11;
const MUTABILITY = 12;
const CONSTANT = 3;

const hx = (a: bigint) => a.toString(16);
const rows = (p: Page): Promise<Row[]> => p.evaluate("window.__revkit.app.visibleRows()") as Promise<Row[]>;
const snap = (p: Page): Promise<Snap> => p.evaluate("window.__revkit.app.snapshot()") as Promise<Snap>;

async function untilRows(p: Page, what: string, pred: (r: Row[]) => boolean, ms = 15000): Promise<Row[]> {
  const end = Date.now() + ms;
  let r = await rows(p);
  while (!pred(r)) {
    if (Date.now() > end)
      throw new Error(`timed out waiting for ${what}; rows: ${JSON.stringify(r.slice(0, 80).map((x) => [x.row, x.address, x.kind, x.length, x.mnemonic, x.dataType, x.dataField, x.unit, x.mutability, x.func, x.entry]))}`);
    await p.waitForTimeout(50);
    r = await rows(p);
  }
  return r;
}

async function until(p: Page, what: string, pred: (s: Snap) => boolean, ms = 15000): Promise<Snap> {
  const end = Date.now() + ms;
  let s = await snap(p);
  while (!pred(s)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify(s)}`);
    await p.waitForTimeout(50);
    s = await snap(p);
  }
  return s;
}

/** The code unit row starting at `addr` (not a header or a field row). */
const unitAt = (r: Row[], addr: string) => r.find((x) => x.address === addr && x.kind !== KIND.Header && !x.dataField);

/** The row containing `addr`. */
const containing = (r: Row[], addr: bigint) => r.find((x) => x.kind !== KIND.Header && BigInt("0x" + x.address) <= addr && addr < BigInt("0x" + x.address) + BigInt(Math.max(1, x.length)));

/** Scrolls the selected row to the top of the listing (all of a function in view). */
async function toTop(p: Page) {
  await p.evaluate(`window.__revkit.view.scrollToRow(window.__revkit.view.selectedRow, "top")`);
  await p.waitForTimeout(50);
}

async function key(p: Page, k: string) {
  await p.focus("#listing-canvas");
  await p.keyboard.press(k);
}

/** Ctrl+Z, then waits until the undo button names the step before. */
async function undo(p: Page) {
  const before = await p.getAttribute("#undo", "title");
  await key(p, "Control+z");
  await p.waitForFunction((t) => document.querySelector("#undo")?.getAttribute("title") !== t, before);
}

/** The listing's context menu at the selected row (the context-menu key). */
async function menu(p: Page) {
  await p.locator("#listing-canvas").dispatchEvent("contextmenu", { button: 0, clientX: 0, clientY: 0 });
  await p.locator("[data-testid=menu]").waitFor({ timeout: 5000 });
}

export async function listingEditChecks(c: ListingEditContext) {
  const { a, b, base, check, rpc, go } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  await check("listing edit: the daemon reports feature listing-edit", async () => {
    const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", { client: "e2e" });
    assert(info.features?.includes("listing-edit"), `features: ${JSON.stringify(info.features)}`);
  });
  const twice = await c.sym("twice");
  // Data needs bytes (the daemon refuses uninitialized memory, so not
  // .bss's counter): printf's format string in .rodata.
  const found = await rpc<{ data?: { address: { offset: string }; length: number; value: string }[] }>(base, "QueryService/ListData", { programId: "default/prog", textContains: "%u" });
  const fmt = found.data?.find((d) => d.value.startsWith("%u"));
  const fmtAt = fmt ? BigInt(fmt.address.offset) : 0n;

  await check("listing edit: c clears twice's rows (out of the functions list, undefined bytes), d and Disassemble and create function bring it back; Ctrl+Z", async () => {
    const fns0 = (await snap(a)).functionCount;
    await go(a, twice);
    await go(b, twice);
    await toTop(a);
    const r0 = await untilRows(a, "twice's instructions", (r) => r.filter((x) => x.func === hx(twice) && x.kind === KIND.Instruction).length >= 2);
    const mine = r0.filter((x) => x.func === hx(twice) && x.kind === KIND.Instruction);
    const first = mine[0], last = mine[mine.length - 1];
    assert(first.address === hx(twice) && first.entry, `twice starts its rows: ${JSON.stringify(first)}`);
    const end = BigInt("0x" + last.address) + BigInt(last.length);
    // Select the function's rows with the keyboard, then c.
    await a.focus("#listing-canvas");
    for (let i = first.row; i < last.row; i++) await a.keyboard.press("Shift+ArrowDown");
    const s = await snap(a);
    assert(s.selection[0] === first.row && s.selection[1] === last.row, `selected rows ${s.selection}, expected ${first.row}..${last.row}`);
    await key(a, "c");
    for (const p of [a, b]) await until(p, "twice gone from the functions", (s) => s.functionCount === fns0 - 1);
    await go(a, twice);
    await untilRows(a, "undefined bytes at twice", (r) => containing(r, twice)?.kind === KIND.Undefined && !r.some((x) => x.func === hx(twice)));
    await untilRows(b, "page B: undefined bytes at twice", (r) => containing(r, twice)?.kind === KIND.Undefined);
    const title = (await a.getAttribute("#undo", "title")) ?? "";
    assert(title.includes(`Clear ${end - twice} bytes at 0x${hx(twice)}`), `undo step: ${title}`);
    // d: code again at twice.
    await go(a, twice);
    await key(a, "d");
    await untilRows(a, "twice disassembled", (r) => unitAt(r, hx(twice))?.kind === KIND.Instruction && unitAt(r, hx(twice))!.unit === "user:e2e");
    assert(((await a.getAttribute("#undo", "title")) ?? "").includes(`Disassemble at 0x${hx(twice)}`), "the Disassemble undo step");
    await undo(a);
    await untilRows(a, "cleared again", (r) => containing(r, twice)?.kind === KIND.Undefined);
    // The menu: Disassemble and create function.
    await go(a, twice);
    await menu(a);
    await a.locator("[data-testid=ctx-le-disasm]").waitFor();
    await a.locator("[data-testid=ctx-le-clear]").waitFor();
    await a.locator("[data-testid=ctx-le-disasm-fn]").click();
    for (const p of [a, b]) await until(p, "twice back in the functions", (s) => s.functionCount === fns0);
    await untilRows(a, "twice's entry", (r) => !!unitAt(r, hx(twice))?.entry && unitAt(r, hx(twice))!.kind === KIND.Instruction);
    await undo(a);
    await until(a, "the function gone again", (s) => s.functionCount === fns0 - 1);
    await undo(a);
    for (const p of [a, b]) await until(p, "twice back after undoing the clear", (s) => s.functionCount === fns0);
    await go(a, twice);
    await toTop(a);
    await untilRows(a, "twice's instructions as before", (r) => !!unitAt(r, hx(twice))?.entry && !unitAt(r, hx(twice))!.unit && r.filter((x) => x.func === hx(twice) && x.kind === KIND.Instruction).length === mine.length);
  });

  await check("listing edit: on data, b defines a byte and cycles to a word, ' a char, [ an array expanded by + and collapsed by its marker, i names who; Shift+B toggles bytes; Ctrl+Z", async () => {
    assert(fmt, `printf's format string: ${JSON.stringify(found)}`);
    await go(a, fmtAt);
    await go(b, fmtAt);
    const g = hx(fmtAt);
    const at = (r: Row[]) => unitAt(r, g);
    await key(a, "b");
    for (const p of [a, b]) await untilRows(p, "a byte at the format string", (r) => at(r)?.kind === KIND.Data && at(r)!.length === 1 && at(r)!.unit === "user:e2e");
    await key(a, "b");
    await untilRows(a, "a word at the format string", (r) => at(r)?.kind === KIND.Data && at(r)!.length === 2);
    await key(a, "'");
    await untilRows(a, "a char at the format string", (r) => at(r)?.length === 1 && /char/.test(at(r)!.dataType));
    await key(a, "[");
    await c.answer(a, "byte[4]");
    await untilRows(a, "an array at the format string", (r) => at(r)?.length === 4 && at(r)!.dataComponents === 4 && at(r)!.dataCollapsed);
    await key(a, "+");
    const open = await untilRows(a, "its elements", (r) => r.filter((x) => x.dataField && x.dataDepth === 1 && BigInt("0x" + x.address) >= fmtAt && BigInt("0x" + x.address) < fmtAt + 4n).length === 4 && !at(r)!.dataCollapsed);
    assert(open.some((x) => x.dataField === "[3]"), `element [3]: ${JSON.stringify(open.filter((x) => x.dataField))}`);
    await untilRows(b, "page B: its elements", (r) => r.some((x) => x.dataField === "[3]"));
    await shot(a, "listing-edit-expanded");
    // Clicking the marker collapses it.
    const pt = (await a.evaluate(`window.__revkit.app.disclosurePoint(0x${g}n)`)) as { x: number; y: number } | null;
    assert(pt, "the item has a disclosure marker");
    await a.mouse.click(pt.x, pt.y);
    await untilRows(a, "collapsed by the marker", (r) => !!at(r)?.dataCollapsed && !r.some((x) => x.dataField && x.address === g));
    // i: who defined it.
    await go(a, fmtAt);
    await key(a, "i");
    const sec = a.locator(`[data-testid=provenance] [data-testid=prov-section][data-kind="${CODE_UNIT}"]`);
    await sec.waitFor({ timeout: 5000 });
    assert(((await sec.locator("[data-testid=prov-who]").textContent()) ?? "").includes("user:e2e"), "the listing edit is user:e2e's");
    await a.keyboard.press("Escape");
    // Shift+B: the bytes column (b defines data now).
    const hasBytes = () => a.evaluate(() => [...document.querySelectorAll("#colhdr span")].some((e) => e.textContent === "Bytes"));
    const shown = await hasBytes();
    await key(a, "Shift+B");
    await a.waitForFunction((was) => [...document.querySelectorAll("#colhdr span")].some((e) => e.textContent === "Bytes") !== was, shown);
    await key(a, "Shift+B");
    assert((await hasBytes()) === shown, "Shift+B toggles the bytes column back");
    for (let i = 0; i < 6; i++) await undo(a); // collapse, expand, array, char, word, byte
    for (const p of [a, b]) await untilRows(p, "the format string as before", (r) => !!at(r) && !at(r)!.unit);
  });

  await check("listing edit: \" makes a string; the context menu's Data group (constant) and Recently used group; i shows the mutability; Ctrl+Z", async () => {
    assert(fmt, `printf's format string: ${JSON.stringify(found)}`);
    const addr = fmtAt;
    const s = hx(addr);
    const at = (r: Row[]) => unitAt(r, s);
    await go(a, addr);
    await key(a, '"');
    for (const p of [a, b]) await untilRows(p, "a user string", (r) => at(r)?.kind === KIND.Data && at(r)!.unit === "user:e2e" && at(r)!.length > 2);
    // The menu: Data ▸ (types, strings, array, mutability) and Recently used ▸.
    await menu(a);
    await a.locator("[data-testid=ctx-data]").click();
    for (const id of ["le-cycle", "le-data-dword", "le-data-string16", "le-data-pascal", "le-data-pointer", "le-array", "le-type", "le-mut-volatile", "le-mut-default"])
      await a.locator(`[data-testid=submenu] [data-testid=ctx-${id}]`).waitFor({ timeout: 5000 });
    await shot(a, "listing-edit-menu");
    await a.locator("[data-testid=submenu] [data-testid=ctx-le-mut-const]").click();
    await untilRows(a, "constant", (r) => at(r)?.mutability === CONSTANT);
    await shot(a, "listing-edit-const");
    assert((await a.locator("[data-testid=menu], [data-testid=submenu]").count()) === 0, "the menu and its submenu closed");
    await key(a, "i");
    await a.locator(`[data-testid=provenance] [data-testid=prov-section][data-kind="${MUTABILITY}"]`).waitFor({ timeout: 5000 });
    await a.keyboard.press("Escape");
    await menu(a);
    await a.locator("[data-testid=ctx-data]").click();
    await a.locator("[data-testid=submenu] [data-testid=ctx-le-recent]").click();
    const recentMenu = a.locator("[data-testid=submenu]").nth(1);
    await recentMenu.waitFor();
    const recent = await recentMenu.locator(".menu-item").allTextContents();
    assert(recent.length >= 3 && recent.some((t) => t.startsWith("string")) && recent.some((t) => t.startsWith("byte[4]")), `recently used: ${JSON.stringify(recent)}`);
    await recentMenu.locator(".menu-item", { hasText: /^word/ }).click();
    await untilRows(a, "a word from the recent group", (r) => at(r)?.kind === KIND.Data && at(r)!.length === 2);
    for (let i = 0; i < 3; i++) await undo(a); // word, constant, string
    for (const p of [a, b]) await untilRows(p, "the string as analysis had it", (r) => !!at(r) && !at(r)!.unit && !at(r)!.mutability);
  });
}
