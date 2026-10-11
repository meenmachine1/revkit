// End-to-end checks for Find Uses of a type or field (feature type-uses)
// and call-site signature overrides (feature call-signature-override;
// docs/ui.md "Find uses" and "Signature overrides"): with second() taking a
// struct pair, Find uses of field from the decompiler's p->second fills the
// results table (second reads it; a click opens the decompiler there), Find
// uses of type from the type's name and from the Types window; on main's
// __printf_chk call, Override signature from the decompiler's context menu drops
// the call's second argument here and in page B, the listing marks the
// call, the hover card shows the override, Remove signature override puts
// it back, and Ctrl+Z steps back through both. run.ts calls callsiteChecks()
// with pages A and B open on default/prog.

import type { Page } from "playwright";
import path from "node:path";

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

interface Snap {
  address: string | null;
  decompName: string | null;
  decompText: string;
  foundLine: number | null;
  views: string[];
  search: { results: { title: string; running: boolean; count: number; error: string } | null } | null;
}

interface Row {
  address: string;
  kind: number;
  mnemonic: string;
  callSignature: string;
  text: string;
}

export interface CallsiteContext {
  base: string;
  a: Page;
  b: Page;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  sym: (name: string) => Promise<bigint>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  go: (p: Page, addr: bigint | string) => Promise<unknown>;
}

const CARD = "[data-testid=hover]";
const snap = (p: Page): Promise<Snap> => p.evaluate("window.__revkit.app.snapshot()") as Promise<Snap>;
const rows = (p: Page): Promise<Row[]> => p.evaluate("window.__revkit.app.visibleRows()") as Promise<Row[]>;
const results = (p: Page): Promise<string[][]> => p.evaluate("window.__revkit.app.search.results.visible()") as Promise<string[][]>;

async function until(p: Page, what: string, pred: (s: Snap) => boolean, ms = 30000): Promise<Snap> {
  const end = Date.now() + ms;
  let s = await snap(p);
  while (!pred(s)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify({ ...s, decompText: s.decompText.slice(0, 600) })}`);
    await p.waitForTimeout(50);
    s = await snap(p);
  }
  return s;
}

/** Runs `act` (which starts a Find Uses) and waits for the new result set
 * to finish: its rows. */
async function finished(p: Page, title: string, act: () => Promise<void>, ms = 120000): Promise<string[][]> {
  await p.evaluate("window.__e2eSet = window.__revkit.app.search.results.shown");
  await act();
  await p.waitForFunction(() => {
    const w = window as unknown as { __e2eSet: unknown; __revkit: { app: { search: { results: { shown: { running: boolean } | null } } } } };
    const s = w.__revkit.app.search.results.shown;
    return !!s && s !== w.__e2eSet && !s.running;
  }, undefined, { timeout: ms });
  const s = await snap(p);
  if (s.search?.results?.title !== title) throw new Error(`result set ${JSON.stringify(s.search?.results)}, expected ${title}`);
  if (s.search.results.error) throw new Error(`${title}: ${s.search.results.error}`);
  return results(p);
}

async function rightClick(p: Page, text: string, cls: string) {
  const tok = p.locator(`#cm .cm-content span.${cls}`, { hasText: new RegExp(`^${text}$`) }).first();
  await tok.waitFor();
  const box = (await tok.boundingBox())!;
  await p.mouse.click(box.x + box.width / 2, box.y + box.height / 2, { button: "right" });
  await p.locator("[data-testid=menu]").waitFor({ timeout: 5000 });
}

async function undo(p: Page) {
  const before = await p.getAttribute("#undo", "title");
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+z");
  await p.waitForFunction((t) => document.querySelector("#undo")?.getAttribute("title") !== t, before);
}

/** main's __printf_chk call as the decompiler prints it. */
function printfLine(text: string): string {
  return text.split("\n").find((l) => l.includes("printf_chk(")) ?? "";
}

export async function callsiteChecks(c: CallsiteContext) {
  const { a, b, base, check, rpc, go } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  await check("type-uses, call-signature-override: the daemon reports both features", async () => {
    const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", { client: "e2e" });
    assert(info.features?.includes("type-uses") && info.features?.includes("call-signature-override"), `features: ${JSON.stringify(info.features)}`);
  });
  const second = await c.sym("second");
  const main = await c.sym("main");

  await check("find uses: of a field from the decompiler (second reads p->second; a row opens it), of the type from its name and from the Types window", async () => {
    const parsed = await rpc<{ nodes: unknown[] }>(base, "TypeService/ParseC", { programId: "default/prog", sources: [{ text: "struct pair { int first; int second; };", name: "pair.h" }] });
    const append = (assertions: unknown[]) =>
      rpc<{ assertions: { seq: string }[] }>(base, "AssertionService/AppendAssertions", { programId: "default/prog", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" }, assertions });
    const made = (await append(parsed.nodes.map((type) => ({ body: { defineType: { type } } })))).assertions;
    made.push(...(await append([{ body: { retype: { target: { address: { offset: String(second) } }, type: { cDeclaration: "int second(struct pair *p)" } } } }])).assertions);
    try {
      await go(a, second);
      await until(a, "second reads p->second", (s) => s.decompName === "second" && /p->second/.test(s.decompText));
      // The field.
      await rightClick(a, "second", "k-fd");
      let r = await finished(a, "Uses of pair.second", () => a.locator("[data-testid=ctx-find-uses-field]").click());
      assert(r.length === 1 && r[0][0] === "second" && r[0][2] === "read" && r[0][3].includes("p->second"), `uses of pair.second: ${JSON.stringify(r)}`);
      await shot(a, "find-uses-field");
      await a.evaluate("window.__revkit.app.showView('listing')");
      await a.locator("[data-testid=search-row]").first().click();
      await until(a, "the use in the decompiler", (s) => s.decompName === "second" && s.foundLine === Number(r[0][1]) - 1 && s.views.includes("decomp"));
      // The type, from its name in the prototype: the declaration and the field.
      await rightClick(a, "pair", "k-ty");
      r = await finished(a, "Uses of pair", () => a.locator("[data-testid=ctx-find-uses-type]").click());
      const kinds = r.filter((x) => x[0] === "second").map((x) => x[2]).sort();
      assert(JSON.stringify(kinds) === JSON.stringify(["read", "type"]), `uses of pair: ${JSON.stringify(r)}`);
      // The Types window's Find uses (the type) and a field row's Uses.
      await a.evaluate("window.__revkit.app.showView('types')");
      await a.evaluate("window.__revkit.app.types.showNamed('pair')");
      r = await finished(a, "Uses of pair", () => a.locator("[data-testid=type-find-uses]").click());
      assert(r.some((x) => x[0] === "second" && x[2] === "type"), `types window: ${JSON.stringify(r)}`);
      await a.evaluate("window.__revkit.app.showView('types')");
      r = await finished(a, "Uses of pair.second", () => a.locator("[data-testid=field-find-uses]").nth(1).click());
      assert(r.length === 1 && r[0][2] === "read", `field row: ${JSON.stringify(r)}`);
    } finally {
      await rpc(base, "AssertionService/RetractAssertions", { programId: "default/prog", seqs: made.map((x) => x.seq), provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
      await a.evaluate("window.__revkit.app.showView('decomp')");
      await a.evaluate("window.__revkit.app.showView('listing')");
    }
  });

  await check("signature override: on main's __printf_chk from the decompiler, in both pages, marked in the listing and the hover card; Remove; Ctrl+Z", async () => {
    await go(a, main);
    await go(b, main);
    const before = await until(a, "main calls printf", (s) => s.decompName === "main" && /__printf_chk\(2,"%u %d\\n",\w+,\w+\);/.test(printfLine(s.decompText)));
    const was = printfLine(before.decompText).trim();
    await rightClick(a, "__printf_chk", "k-fn");
    assert((await a.locator("[data-testid=ctx-callsig-remove]").count()) === 0, "Remove offered with no override");
    await a.locator("[data-testid=ctx-callsig-override]").click();
    await a.waitForSelector("[data-testid=ask] .ask-input");
    const prefilled = await a.inputValue("[data-testid=ask] .ask-input");
    assert(prefilled.includes("printf_chk("), `prefilled with the callee's prototype: ${prefilled}`);
    await a.fill("[data-testid=ask] .ask-input", "int __printf_chk(int flag, char *fmt, unsigned int u)");
    await a.keyboard.press("Enter");
    await a.waitForSelector("[data-testid=ask]", { state: "detached" });
    const one = /__printf_chk\(2,"%u %d\\n",\w+\);/;
    for (const p of [a, b]) await until(p, "printf with one argument", (s) => s.decompName === "main" && one.test(printfLine(s.decompText)));
    await shot(a, "signature-override");
    // The listing marks the call.
    const marked = await (async () => {
      const end = Date.now() + 15000;
      for (;;) {
        const r = (await rows(a)).find((x) => x.callSignature.startsWith("int __printf_chk("));
        if (r) return r;
        if (Date.now() > end) throw new Error(`no call row with the override: ${JSON.stringify((await rows(a)).map((x) => [x.address, x.mnemonic, x.callSignature]))}`);
        await a.waitForTimeout(100);
      }
    })();
    assert(marked.text.includes("⤷ signature: int __printf_chk("), `row text: ${marked.text}`);
    // The hover card on the call's name.
    await a.locator("#cm .cm-content span.k-fn", { hasText: /^__printf_chk$/ }).first().hover();
    const card = (await a.locator(`${CARD} [data-testid=hc-callsig]`).textContent({ timeout: 5000 })) ?? "";
    assert(card.includes("int __printf_chk("), `card: ${card}`);
    await a.mouse.move(2, 2);
    // Edit is offered now, and Remove takes it away.
    await rightClick(a, "__printf_chk", "k-fn");
    await a.locator("[data-testid=ctx-callsig-edit]").waitFor();
    await a.locator("[data-testid=ctx-callsig-remove]").click();
    for (const p of [a, b]) await until(p, "printf as before", (s) => printfLine(s.decompText).trim() === was);
    // Ctrl+Z: the override again, then none.
    await undo(a);
    await until(a, "the override back", (s) => one.test(printfLine(s.decompText)));
    await undo(a);
    for (const p of [a, b]) await until(p, "printf as before", (s) => printfLine(s.decompText).trim() === was);
  });
}
