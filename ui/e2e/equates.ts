// End-to-end checks for equates and user references (features equates,
// user-references; docs/ui.md "Equates and references"), on grade() of the
// e2e program: `cmp edi, 0x41` ... `add eax, 0x41` and a computed call
// through `hook`. The listing's Convert submenu shows 0x41 as 'A' in the
// listing and the decompiler (page B follows), i names who; E on the
// decompiler's constant sets an enum member the dialog suggests, on every
// matching scalar in the function; the Equates window lists it with its
// uses (a click goes there), renames and removes it everywhere, and a name
// with another value is refused in the dialog; R adds a primary computed
// call to twice (the decompiler calls twice; the References window and
// xrefs say user:e2e), a second reference is made primary from the
// window, and an analysis reference is deleted from the References
// submenu; Ctrl+Z undoes every step. run.ts calls equateChecks() with
// pages A and B open on default/prog.

import type { Page } from "playwright";
import path from "node:path";

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

interface Row {
  row: number;
  address: string;
  kind: number;
  mnemonic: string;
  func: string | null;
  operands: string;
}

interface Snap {
  address: string | null;
  decompName: string | null;
  decompText: string;
  decompSelected: string | null;
}

export interface EquateContext {
  base: string;
  a: Page;
  b: Page;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  sym: (name: string) => Promise<bigint>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  go: (p: Page, addr: bigint | string) => Promise<unknown>;
  answer: (p: Page, text: string) => Promise<void>;
}

const INSTRUCTION = 1;
const EQUATE = 13;

const hx = (a: bigint) => a.toString(16);
const rows = (p: Page): Promise<Row[]> => p.evaluate("window.__revkit.app.visibleRows()") as Promise<Row[]>;
const snap = (p: Page): Promise<Snap> => p.evaluate("window.__revkit.app.snapshot()") as Promise<Snap>;

async function untilRows(p: Page, what: string, pred: (r: Row[]) => boolean, ms = 15000): Promise<Row[]> {
  const end = Date.now() + ms;
  let r = await rows(p);
  while (!pred(r)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; rows: ${JSON.stringify(r.slice(0, 60).map((x) => [x.address, x.kind, x.mnemonic, x.operands, x.func]))}`);
    await p.waitForTimeout(50);
    r = await rows(p);
  }
  return r;
}

async function until(p: Page, what: string, pred: (s: Snap) => boolean, ms = 15000): Promise<Snap> {
  const end = Date.now() + ms;
  let s = await snap(p);
  while (!pred(s)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify({ address: s.address, decompName: s.decompName, decompSelected: s.decompSelected, decompText: s.decompText.slice(0, 500) })}`);
    await p.waitForTimeout(50);
    s = await snap(p);
  }
  return s;
}

/** Waits for a condition on the page's DOM (a window's rows). */
async function untilDom(p: Page, what: string, fn: () => Promise<boolean>, ms = 15000) {
  const end = Date.now() + ms;
  while (!(await fn())) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await p.waitForTimeout(50);
  }
}

const unitAt = (r: Row[], addr: bigint) => r.find((x) => x.address === hx(addr) && x.kind === INSTRUCTION);

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

/** Runs a palette command by its title. */
async function command(p: Page, title: string) {
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+Shift+P");
  await p.waitForSelector("[data-testid=palette-input]");
  await p.fill("[data-testid=palette-input]", `>${title}`);
  await p.waitForFunction((t) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").startsWith(t), title);
  await p.keyboard.press("Enter");
}

/** Clicks (or right-clicks) an operand of the instruction at `addr` in the listing. */
async function clickOperand(p: Page, addr: bigint, text: string, button: "left" | "right" = "left") {
  const pt = (await p.evaluate(`window.__revkit.app.operandPoint(0x${hx(addr)}n, ${JSON.stringify(text)})`)) as { x: number; y: number } | null;
  if (!pt) throw new Error(`no operand ${text} at ${hx(addr)} on screen`);
  await p.mouse.click(pt.x, pt.y, { button });
}

export async function equateChecks(c: EquateContext) {
  const { a, b, base, check, rpc, go } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  await check("equates: the daemon reports features equates and user-references", async () => {
    const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", { client: "e2e" });
    assert(info.features?.includes("equates") && info.features.includes("user-references"), `features: ${JSON.stringify(info.features)}`);
  });

  const grade = await c.sym("grade");
  const twice = await c.sym("twice");
  const second = await c.sym("second");
  // grade's instructions: cmp edi, 0x41 · jz · ... · call rax · add eax, 0x41 · mov eax, 0x3.
  type ListingResp = { rows?: { address: { offset: string }; kind: string; tokens?: { kind: string; text: string }[] }[] };
  const listed = await rpc<ListingResp>(base, "QueryService/GetListing", { programId: "default/prog", addresses: { start: { offset: String(grade) }, maxRows: 24 } });
  const insns = (listed.rows ?? []).filter((r) => r.kind === "LISTING_ROW_KIND_INSTRUCTION").map((r) => ({ at: BigInt(r.address.offset), text: (r.tokens ?? []).map((t) => t.text).join("") }));
  const withA = insns.filter((i) => /,0x41$/.test(i.text));
  const cmpAt = withA[0]?.at ?? 0n;
  const addAt = withA[1]?.at ?? 0n;
  const callAt = insns.find((i) => /^CALL RAX/.test(i.text))?.at ?? 0n;
  const jzAt = insns.find((i) => /^JZ /.test(i.text))?.at ?? 0n;
  const threeAt = insns.find((i) => /^MOV EAX,0x3$/.test(i.text))?.at ?? 0n;
  const opAt = (r: Row[], addr: bigint) => unitAt(r, addr)?.operands ?? "";

  await check("equates: the listing's Convert submenu shows 0x41 as 'A' in the listing and the decompiler (page B too); i names who; Ctrl+Z", async () => {
    assert(cmpAt && addAt && callAt && jzAt && threeAt, `grade's instructions: ${JSON.stringify(insns.map((i) => [hx(i.at), i.text]))}`);
    await go(b, cmpAt);
    await go(a, cmpAt);
    await untilRows(a, "the cmp", (r) => opAt(r, cmpAt).endsWith(",0x41"));
    await clickOperand(a, cmpAt, "0x41", "right");
    await a.locator("[data-testid=menu]").waitFor({ timeout: 5000 });
    await a.locator("[data-testid=ctx-eq-set]").waitFor({ timeout: 5000 });
    await a.locator("[data-testid=ctx-convert]").click();
    for (const id of ["hex", "sdec", "udec", "oct", "bin", "char", "float", "default"]) await a.locator(`[data-testid=submenu] [data-testid=ctx-conv-${id}]`).waitFor({ timeout: 5000 });
    const label = (await a.locator("[data-testid=ctx-conv-char]").textContent()) ?? "";
    assert(label.includes("'A'"), `the Char item previews 'A': ${label}`);
    await shot(a, "equates-convert-menu");
    await a.locator("[data-testid=ctx-conv-char]").click();
    for (const p of [a, b]) await untilRows(p, "'A' in the listing", (r) => opAt(r, cmpAt).endsWith(",'A'"));
    assert(((await a.getAttribute("#undo", "title")) ?? "").includes(`Convert 0x41 to char at 0x${hx(cmpAt)}`), "the Convert undo step");
    for (const p of [a, b]) await until(p, "'A' in the decompiler", (s) => s.decompName === "grade" && /== L?'A'/.test(s.decompText));
    // i on the operand: the conversion and who made it.
    await clickOperand(a, cmpAt, "'A'");
    await key(a, "i");
    const sec = a.locator(`[data-testid=provenance] [data-testid=prov-section][data-kind="${EQUATE}"]`);
    await sec.waitFor({ timeout: 5000 });
    assert(((await sec.locator("[data-testid=prov-who]").textContent()) ?? "").includes("user:e2e"), "the conversion is user:e2e's");
    await a.keyboard.press("Escape");
    await undo(a);
    for (const p of [a, b]) await untilRows(p, "0x41 again", (r) => opAt(r, cmpAt).endsWith(",0x41"));
    await until(a, "0x41 in the decompiler", (s) => !/'A'/.test(s.decompText) && s.decompText.includes("== 0x41"));
  });

  // An enum with a member of 0x41 (as a header import would define it).
  const parsed = await rpc<{ nodes: unknown[] }>(base, "TypeService/ParseC", { programId: "default/prog", sources: [{ text: "enum grade_kind { GK_NONE = 0, GK_LETTER = 0x41, GK_THREE = 3 };", name: "grade.h" }] });
  const defined = await rpc<{ assertions: { seq: string }[] }>(base, "AssertionService/AppendAssertions", {
    programId: "default/prog",
    provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
    assertions: parsed.nodes.map((type) => ({ body: { defineType: { type } } })),
  });

  await check("equates: E on the decompiler's constant suggests the enum member; applied to the function, both views show it in both pages", async () => {
    await go(a, grade);
    await until(a, "grade decompiled", (s) => s.decompName === "grade" && s.decompText.includes("== 0x41"));
    const k = a.locator("#cm .cm-content span.k-co", { hasText: /^0x41$/ }).first();
    await k.click();
    await until(a, "the constant selected", (s) => s.decompSelected === "0x41");
    await a.keyboard.press("Shift+E");
    await a.locator("[data-testid=ask]").waitFor({ timeout: 5000 });
    const row = a.locator("[data-testid=ask-drop-row]", { hasText: "GK_LETTER" });
    await row.waitFor({ timeout: 5000 });
    assert(((await row.textContent()) ?? "").includes("grade_kind"), "the suggestion names its enum");
    await a.locator("[data-testid=ask-scope-function]").check();
    await shot(a, "equates-set-dialog");
    await row.dispatchEvent("mousedown");
    assert((await a.inputValue("[data-testid=ask] .ask-input")) === "GK_LETTER", "the suggestion fills the name");
    await a.focus("[data-testid=ask] .ask-input");
    await a.keyboard.press("Enter");
    await a.locator("[data-testid=ask]").waitFor({ state: "detached", timeout: 10000 });
    for (const p of [a, b]) {
      await go(p, cmpAt);
      await untilRows(p, "GK_LETTER on both operands", (r) => opAt(r, cmpAt).endsWith(",GK_LETTER") && opAt(r, addAt).endsWith(",GK_LETTER"));
      await until(p, "GK_LETTER in the decompiler", (s) => s.decompName === "grade" && (s.decompText.match(/GK_LETTER/g) ?? []).length === 2);
    }
    assert(((await a.getAttribute("#undo", "title")) ?? "").includes("Set equate GK_LETTER = 0x41"), "the Set equate undo step");
  });

  await check("equates: the Equates window lists GK_LETTER with 2 uses (a click goes there); rename and remove everywhere, live in page B; a name with another value is refused; Ctrl+Z", async () => {
    await command(a, "Show equates");
    await command(b, "Show equates");
    const eqRow = (p: Page, name: string) => p.locator(`[data-testid=equate-row][data-name="${name}"]`);
    for (const p of [a, b]) {
      await eqRow(p, "GK_LETTER").waitFor({ timeout: 10000 });
      assert((await eqRow(p, "GK_LETTER").locator("[data-testid=equate-count]").textContent()) === "2", "2 uses");
      assert((await eqRow(p, "GK_LETTER").locator("[data-testid=equate-value]").textContent()) === "0x41", "value 0x41");
    }
    await eqRow(a, "GK_LETTER").click();
    const uses = a.locator("[data-testid=equate-use]");
    await untilDom(a, "two uses", async () => (await uses.count()) === 2);
    await uses.nth(1).click();
    await until(a, "at the second use", (s) => s.address === hx(addAt));
    await shot(a, "equates-window");
    // Rename everywhere: one edit.
    await a.locator("[data-testid=equates-rename]").click();
    await c.answer(a, "LETTER_A");
    for (const p of [a, b]) {
      await eqRow(p, "LETTER_A").waitFor({ timeout: 10000 });
      assert((await eqRow(p, "GK_LETTER").count()) === 0, "GK_LETTER renamed");
      await untilRows(p, "LETTER_A on both operands", (r) => opAt(r, cmpAt).endsWith(",LETTER_A") && opAt(r, addAt).endsWith(",LETTER_A"));
    }
    assert(((await a.getAttribute("#undo", "title")) ?? "").includes("Rename equate GK_LETTER to LETTER_A (2 uses)"), "the rename undo step");
    // LETTER_A is 0x41: the daemon refuses it for 0x3, in the dialog.
    await go(a, threeAt);
    await key(a, "Shift+E");
    await a.locator("[data-testid=ask] .ask-input").waitFor({ timeout: 5000 });
    await a.fill("[data-testid=ask] .ask-input", "LETTER_A");
    await a.keyboard.press("Enter");
    await a.locator("[data-testid=ask-error]", { hasText: "already" }).waitFor({ timeout: 5000 });
    await a.keyboard.press("Escape");
    await a.keyboard.press("Escape");
    await a.locator("[data-testid=ask]").waitFor({ state: "detached", timeout: 5000 });
    // Remove everywhere.
    await eqRow(a, "LETTER_A").click();
    await a.locator("[data-testid=equates-remove]").click();
    for (const p of [a, b]) {
      await untilDom(p, "the window empty", async () => (await p.locator("[data-testid=equate-row]").count()) === 0);
      await go(p, cmpAt);
      await untilRows(p, "0x41 on both operands", (r) => opAt(r, cmpAt).endsWith(",0x41") && opAt(r, addAt).endsWith(",0x41"));
    }
    await undo(a); // remove
    await eqRow(a, "LETTER_A").waitFor({ timeout: 10000 });
    await undo(a); // rename
    await eqRow(b, "GK_LETTER").waitFor({ timeout: 10000 });
    await undo(a); // set
    for (const p of [a, b]) {
      await untilDom(p, "no equates", async () => (await p.locator("[data-testid=equate-row]").count()) === 0);
      await untilRows(p, "0x41 again", (r) => opAt(r, cmpAt).endsWith(",0x41") && opAt(r, addAt).endsWith(",0x41"));
    }
  });

  // The enum goes again (it was the test's, not an undo step).
  await rpc(base, "AssertionService/RetractAssertions", { programId: "default/prog", seqs: defined.assertions.map((x) => x.seq), provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });

  await check("references: R adds a primary computed call to twice (the decompiler calls it; the References window and xrefs say user:e2e); Set primary from the window; Delete an analysis reference from the menu; Ctrl+Z", async () => {
    const refRow = (p: Page, dir: "from" | "to", to: bigint) => p.locator(`[data-testid=refs-${dir}] [data-testid=ref-row][data-to="${hx(to)}"]`);
    await command(a, "Show references (from and to");
    await command(b, "Show references (from and to");
    for (const p of [a, b]) await go(p, callAt);
    await until(a, "grade's call", (s) => s.decompName === "grade" && s.decompText.includes("(*hook)"));
    await a.locator("[data-testid=refs-at]", { hasText: hx(callAt) }).waitFor({ timeout: 10000 });
    // R: to twice, a computed call, from operand 0, primary.
    await key(a, "Shift+R");
    await a.locator("[data-testid=ask] .ask-input").waitFor({ timeout: 5000 });
    await a.fill("[data-testid=ask] .ask-input", "twice");
    await a.selectOption("[data-testid=ask-type]", "computed-call");
    assert((await a.inputValue("[data-testid=ask-operand]")) === "0", "from the call's operand");
    await a.locator("[data-testid=ask-primary]").check();
    await shot(a, "references-add-dialog");
    await a.focus("[data-testid=ask] .ask-input");
    await a.keyboard.press("Enter");
    await a.locator("[data-testid=ask]").waitFor({ state: "detached", timeout: 10000 });
    for (const p of [a, b]) {
      const r = refRow(p, "from", twice);
      await r.waitFor({ timeout: 10000 });
      assert((await r.getAttribute("data-source")) === "user:e2e" && (await r.getAttribute("data-primary")) === "1", `user:e2e's primary: ${await r.getAttribute("data-source")} ${await r.getAttribute("data-primary")}`);
      await untilRows(p, "the call shows twice", (rs) => opAt(rs, callAt).includes("twice"));
      await until(p, "the decompiler calls twice", (s) => s.decompName === "grade" && /twice\(/.test(s.decompText));
    }
    await shot(a, "references-window");
    // x on twice: the reference, with who made it.
    await go(a, twice);
    await key(a, "x");
    await a.locator("[data-testid=xrefs] [data-testid=xref-source]", { hasText: "user:e2e" }).waitFor({ timeout: 10000 });
    await a.keyboard.press("Escape");
    // A second reference, not primary, from the menu; then Set primary from the window.
    await go(a, callAt);
    await a.locator("#listing-canvas").dispatchEvent("contextmenu", { button: 0, clientX: 0, clientY: 0 });
    await a.locator("[data-testid=ctx-refs]").click();
    await a.locator("[data-testid=submenu] [data-testid=ctx-ref-add]").click();
    await a.locator("[data-testid=ask] .ask-input").waitFor({ timeout: 5000 });
    await a.fill("[data-testid=ask] .ask-input", `0x${hx(second)}`);
    await a.selectOption("[data-testid=ask-type]", "computed-call");
    await a.focus("[data-testid=ask] .ask-input");
    await a.keyboard.press("Enter");
    await a.locator("[data-testid=ask]").waitFor({ state: "detached", timeout: 10000 });
    await refRow(a, "from", second).waitFor({ timeout: 10000 });
    assert((await refRow(a, "from", second).getAttribute("data-primary")) === "0", "the second reference isn't primary");
    await refRow(a, "from", second).locator("[data-testid=ref-primary]").click();
    for (const p of [a, b]) {
      await untilDom(p, "second primary, twice not", async () => (await refRow(p, "from", second).getAttribute("data-primary")) === "1" && (await refRow(p, "from", twice).getAttribute("data-primary")) === "0");
      await until(p, "the decompiler calls second", (s) => /second\(/.test(s.decompText) && !/twice\(/.test(s.decompText));
    }
    // Delete analysis's jump reference from the jz, from the References submenu.
    await go(a, jzAt);
    await go(b, jzAt);
    const jzTo = await untilDom(a, "the jz's analysis reference", async () => (await a.locator("[data-testid=refs-from] [data-testid=ref-row][data-source=analysis]").count()) === 1).then(() => a.locator("[data-testid=refs-from] [data-testid=ref-row]").first().getAttribute("data-to"));
    assert(jzTo, "the jump's target");
    await a.locator("#listing-canvas").dispatchEvent("contextmenu", { button: 0, clientX: 0, clientY: 0 });
    await a.locator("[data-testid=ctx-refs]").click();
    await a.locator("[data-testid=submenu] [data-testid=ctx-ref-delete]").click();
    await a.locator("[data-testid=choose] .palette-item", { hasText: jzTo }).first().click();
    for (const p of [a, b]) await untilDom(p, "the jump's reference gone", async () => (await p.locator("[data-testid=refs-from] [data-testid=ref-row]").count()) === 0);
    const left = await rpc<{ xrefs?: unknown[] }>(base, "QueryService/GetXrefs", { programId: "default/prog", address: { offset: String(jzAt) }, direction: "XREF_DIRECTION_FROM" });
    assert(!left.xrefs?.length, `xrefs from the jz: ${JSON.stringify(left.xrefs)}`);
    assert(((await a.getAttribute("#undo", "title")) ?? "").includes("Delete reference"), "the Delete undo step");
    for (let i = 0; i < 4; i++) await undo(a); // delete, set primary, the second, the first
    for (const p of [a, b]) await untilDom(p, "the jump's reference back", async () => (await p.locator("[data-testid=refs-from] [data-testid=ref-row][data-source=analysis]").count()) === 1);
    await go(a, callAt);
    await untilDom(a, "no references from the call", async () => (await a.locator("[data-testid=refs-from] [data-testid=ref-row]").count()) === 0);
    for (const p of [a, b]) await until(p, "the decompiler calls through hook again", (s) => s.decompText.includes("(*hook)"));
    for (const p of [a, b]) await command(p, "Show decompiler");
  });
}
