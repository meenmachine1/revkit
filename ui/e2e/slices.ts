// End-to-end checks for the decompiler's def-use and slice highlights
// (docs/ui.md, "Slices"; feature decompile-slices): a backward slice from a
// return value highlights the values it is computed from in the C and
// marks their instructions in the listing; next and previous walk the
// highlighted tokens; Escape clears both; def-use of a variable marks its
// definition and uses; a forward operator slice from a parameter marks the
// operations it flows through. run.ts calls sliceChecks() with a page
// factory.

import type { Page } from "playwright";
import path from "node:path";

export interface SliceContext {
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  assert: (cond: unknown, msg: string) => asserts cond;
  /** A page on default/prog at this viewport, ready (main decompiled). */
  page: (width: number, height: number) => Promise<Page>;
  log: (s: string) => void;
}

type Snap = {
  decompName: string | null;
  decompText: string;
  decompSelected: string | null;
  slice: { label: string; tokens: string[]; selected: string | null } | null;
  sliceMarks: string[];
};
const snap = (p: Page) => p.evaluate("window.__revkit.app.snapshot()") as Promise<Snap>;

async function until(p: Page, what: string, pred: (s: Snap) => boolean, ms = 15000) {
  const end = Date.now() + ms;
  let s = await snap(p);
  while (!pred(s)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify({ ...s, decompText: s.decompText.slice(0, 600) })}`);
    await p.waitForTimeout(50);
    s = await snap(p);
  }
  return s;
}

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

async function goTo(p: Page, name: string) {
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+k");
  await p.fill("[data-testid=palette-input]", name);
  await p.waitForFunction((n) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").includes(n), name);
  await p.keyboard.press("Enter");
  await until(p, `${name} decompiled`, (s) => s.decompName === name);
}

/** Right-clicks a token of the C and runs Highlight ▸ `item`. */
async function highlight(p: Page, text: string, cls: string, item: string) {
  const tok = p.locator(`#cm .cm-content span.${cls}`, { hasText: new RegExp(`^${text}$`) }).first();
  await tok.waitFor();
  await tok.click();
  await tok.click({ button: "right" });
  await p.click("[data-testid=ctx-highlight]");
  await p.click(`[data-testid=submenu] [data-testid=ctx-${item}]`);
}

export async function sliceChecks(c: SliceContext) {
  const { check } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const p = await c.page(1500, 900);

  await check("slices: a backward slice from a return value highlights its operands, here and in the listing; next/previous; Escape clears", async () => {
    await goTo(p, "second");
    const text = (await snap(p)).decompText;
    c.log(`     second: ${text.replace(/\s+/g, " ").slice(0, 160)}`);
    await highlight(p, "return", "k-kw", "slice-backward");
    const s = await until(p, "the backward slice", (x) => !!x.slice && x.slice.label.startsWith("Backward slice of return"));
    // second(int *p) { return p[1]; }: the parameter (the pointer) and the index.
    const ret = text.split("\n").find((l) => /\breturn\b/.test(l)) ?? "";
    c.log(`     backward slice of return: ${JSON.stringify(s.slice!.tokens)}`);
    // Only what the return statement reads: the pointer and the index.
    assert(s.slice!.tokens.length > 0 && s.slice!.tokens.every((t) => ret.includes(t)), `slice ${JSON.stringify(s.slice)} of ${ret}`);
    assert(s.slice!.tokens.includes("param_1"), `the parameter in ${JSON.stringify(s.slice!.tokens)}`);
    assert(s.sliceMarks.length > 0, "no instructions marked in the listing");
    const n = await p.locator("#cm .cm-slice").count();
    assert(n === s.slice!.tokens.length && n > 0, `${n} marked spans for ${s.slice!.tokens.length} tokens`);
    await shot(p, "slice-backward");
    // Next and previous (Ghidra's Ctrl+. and Ctrl+,) walk the highlighted tokens.
    await p.click("#cm .cm-content");
    await p.keyboard.press("Control+Period");
    const a = await until(p, "next", (x) => !!x.slice?.selected && x.slice.tokens.includes(x.slice.selected));
    await p.keyboard.press("Control+Period");
    await p.keyboard.press("Control+Comma");
    const b = await until(p, "previous", (x) => x.slice?.selected === a.slice!.selected);
    assert(b.slice!.selected === a.slice!.selected, "previous went back");
    // Escape clears the C's highlight and the listing's marks.
    await p.keyboard.press("Escape");
    await until(p, "cleared", (x) => x.slice === null && x.sliceMarks.length === 0);
  });

  await check("slices: def-use of a variable and a forward operator slice from a parameter", async () => {
    await goTo(p, "checksum");
    const text = (await snap(p)).decompText;
    c.log(`     checksum: ${text.replace(/\s+/g, " ").slice(0, 200)}`);
    // A local variable token in the body (the last one: not its declaration).
    const local = p.locator("#cm .cm-content span.k-lv").last();
    const name = ((await local.textContent()) ?? "").trim();
    assert(name, "a local variable token");
    await local.click();
    await local.click({ button: "right" });
    await p.click("[data-testid=ctx-highlight]");
    await p.click("[data-testid=submenu] [data-testid=ctx-slice-def-use]");
    const du = await until(p, "def-use", (x) => !!x.slice && x.slice.label.startsWith("Def-use of"));
    assert(du.slice!.tokens.length >= 1 && du.slice!.tokens.every((t) => t === name), `def-use of ${name}: ${JSON.stringify(du.slice!.tokens)}`);
    await p.keyboard.press("Escape");
    await until(p, "cleared", (x) => x.slice === null);
    // A parameter in the body (the last one: not the signature's).
    const param = p.locator("#cm .cm-content span.k-pa").last();
    await param.click();
    await param.click({ button: "right" });
    await p.click("[data-testid=ctx-highlight]");
    await p.click("[data-testid=submenu] [data-testid=ctx-slice-forward-ops]");
    const fo = await until(p, "forward operator slice", (x) => !!x.slice && x.slice.label.startsWith("Forward operator slice"));
    assert(fo.slice!.tokens.length > 0 && fo.sliceMarks.length > 0, `forward ops: ${JSON.stringify(fo.slice)} marks ${fo.sliceMarks.length}`);
    await shot(p, "slice-forward-ops");
    await p.keyboard.press("Escape");
    await p.context().close();
  });
}
