// End-to-end checks for hover cards (docs/ui.md "Hover cards", feature
// "hover"), on the e2e program: in the listing, main's call to checksum
// previews checksum's signature and first lines of C, and grade's 0x41
// shows as hex, decimal and 'A'; in the decompiler the same constant, a
// callee's name (with the provenance badge's section below), and a struct
// parameter's type, a field's struct (its member marked) and the type
// token show the struct's layout. The card never takes the focus, scrolls
// when long, and Escape closes it. run.ts calls hoverChecks() with page A
// open on default/prog.

import type { Page } from "playwright";
import path from "node:path";

export interface HoverContext {
  base: string;
  a: Page;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  sym: (name: string) => Promise<bigint>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  go: (p: Page, addr: bigint | string) => Promise<unknown>;
}

interface Snap {
  address: string | null;
  decompName: string | null;
  decompText: string;
}

const hx = (a: bigint) => a.toString(16);
const snap = (p: Page): Promise<Snap> => p.evaluate("window.__revkit.app.snapshot()") as Promise<Snap>;
const CARD = "[data-testid=hover]";

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

async function until(p: Page, what: string, pred: (s: Snap) => boolean, ms = 15000): Promise<Snap> {
  const end = Date.now() + ms;
  let s = await snap(p);
  while (!pred(s)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify({ address: s.address, decompName: s.decompName, decompText: s.decompText.slice(0, 400) })}`);
    await p.waitForTimeout(50);
    s = await snap(p);
  }
  return s;
}

/** Moves the pointer away and waits until no card is shown. */
async function away(p: Page) {
  await p.mouse.move(2, 2);
  await p.locator(CARD).waitFor({ state: "detached", timeout: 5000 });
}

/** Rests the pointer on an operand of the listing's code unit at `addr`
 * (again where it is drawn now, while a navigation's scroll settles); the
 * card's text. */
async function hoverOperand(p: Page, addr: bigint, text: string): Promise<string> {
  for (let attempt = 0; attempt < 8; attempt++) {
    const pt = (await p.evaluate(`window.__revkit.app.operandPoint(0x${hx(addr)}n, ${JSON.stringify(text)})`)) as { x: number; y: number } | null;
    if (pt) {
      await p.mouse.move(pt.x, pt.y + (attempt % 2));
      try {
        await p.locator(CARD).waitFor({ timeout: 1500 });
        return (await p.locator(CARD).textContent()) ?? "";
      } catch {
        // Moved under the pointer: find it again.
      }
    } else await p.waitForTimeout(200);
  }
  throw new Error(`no card for operand ${text} at ${hx(addr)}`);
}

export async function hoverChecks(c: HoverContext) {
  const { a, base, check, rpc, go } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const main = await c.sym("main");
  const grade = await c.sym("grade");
  const second = await c.sym("second");
  type ListingResp = { rows?: { address: { offset: string }; kind: string; tokens?: { text: string }[] }[] };
  const insns = async (at: bigint) =>
    ((await rpc<ListingResp>(base, "QueryService/GetListing", { programId: "default/prog", addresses: { start: { offset: String(at) }, maxRows: 40 } })).rows ?? [])
      .filter((r) => r.kind === "LISTING_ROW_KIND_INSTRUCTION")
      .map((r) => ({ at: BigInt(r.address.offset), text: (r.tokens ?? []).map((t) => t.text).join("") }));
  const callAt = (await insns(main)).find((i) => /^CALL checksum$/.test(i.text))?.at ?? 0n;
  const cmpAt = (await insns(grade)).find((i) => /,0x41$/.test(i.text))?.at ?? 0n;

  await check("hover: the daemon reports feature hover", async () => {
    const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", { client: "e2e" });
    assert(info.features?.includes("hover"), `features: ${JSON.stringify(info.features)}`);
    assert(callAt && cmpAt, `main calls checksum at ${hx(callAt)}; grade compares with 0x41 at ${hx(cmpAt)}`);
  });

  await check("hover: a call's target in the listing previews its signature and first lines of C; the focus stays; Escape closes it", async () => {
    await go(a, callAt);
    await a.focus("#listing-canvas");
    await hoverOperand(a, callAt, "checksum");
    const sig = (await a.locator(`${CARD} [data-testid=hc-signature]`).textContent({ timeout: 5000 })) ?? "";
    assert(sig.includes("checksum("), `signature: ${sig}`);
    const code = a.locator(`${CARD} [data-testid=hc-code]`);
    await code.waitFor({ timeout: 15000 });
    const text = (await code.textContent()) ?? "";
    assert(/checksum\(/.test(text.split("\n")[0]) && text.includes("{") && text.split("\n").length >= 4, `C preview: ${text}`);
    assert(await a.evaluate(() => document.activeElement?.id === "listing-canvas"), "the listing keeps the focus");
    // Scrollable when long: bounded height, overflow auto.
    const style = await a.locator(CARD).evaluate((el) => ({ overflow: getComputedStyle(el).overflowY, max: getComputedStyle(el).maxHeight }));
    assert(style.overflow === "auto" && style.max !== "none", `card style: ${JSON.stringify(style)}`);
    await shot(a, "hover-listing-call");
    await a.keyboard.press("Escape");
    await a.locator(CARD).waitFor({ state: "detached", timeout: 5000 });
    await a.mouse.move(2, 2);
  });

  await check("hover: a scalar in the listing shows hex, decimal and the character", async () => {
    await go(a, cmpAt);
    await hoverOperand(a, cmpAt, "0x41");
    const card = a.locator(CARD);
    assert((await card.locator("[data-testid=hc-hex]").textContent()) === "0x41", "hex");
    assert((await card.locator("[data-testid=hc-dec]").textContent()) === "65", "decimal");
    assert((await card.locator("[data-testid=hc-char]").textContent()) === "'A'", "char");
    await away(a);
  });

  await check("hover: the decompiler's constant, and a callee's name with who named it", async () => {
    await go(a, grade);
    await until(a, "grade decompiled", (s) => s.decompName === "grade" && s.decompText.includes("0x41"));
    await a.locator("#cm .cm-content span.k-co", { hasText: /^0x41$/ }).first().hover();
    await a.locator(`${CARD} [data-testid=hc-char]`).waitFor({ timeout: 5000 });
    assert((await a.locator(`${CARD} [data-testid=hc-dec]`).textContent()) === "65", "decimal");
    await away(a);
    await go(a, main);
    await until(a, "main decompiled", (s) => s.decompName === "main" && s.decompText.includes("checksum("));
    await a.locator("#cm .cm-content span.k-fn", { hasText: /^checksum$/ }).first().hover();
    const sig = (await a.locator(`${CARD} [data-testid=hc-signature]`).textContent({ timeout: 5000 })) ?? "";
    assert(sig.includes("checksum("), `signature: ${sig}`);
    await a.locator(`${CARD} [data-testid=hc-code]`).waitFor({ timeout: 15000 });
    // The provenance badge's section, in the card.
    await a.locator(`${CARD} [data-testid=provenance] [data-testid=prov-who]`).waitFor({ timeout: 5000 });
    await shot(a, "hover-decompiler-callee");
    await away(a);
  });

  await check("hover: a struct parameter, its type and a field show the struct's layout", async () => {
    const parsed = await rpc<{ nodes: unknown[] }>(base, "TypeService/ParseC", { programId: "default/prog", sources: [{ text: "struct pair { int first; int second; };", name: "pair.h" }] });
    const append = (assertions: unknown[]) =>
      rpc<{ assertions: { seq: string }[] }>(base, "AssertionService/AppendAssertions", {
        programId: "default/prog",
        provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
        assertions,
      });
    // The struct first: the prototype names it.
    const made = (await append(parsed.nodes.map((type) => ({ body: { defineType: { type } } })))).assertions;
    made.push(...(await append([{ body: { retype: { target: { address: { offset: String(second) } }, type: { cDeclaration: "int second(struct pair *p)" } } } }])).assertions);
    try {
      await go(a, second);
      await until(a, "second takes a pair", (s) => s.decompName === "second" && /pair \*p/.test(s.decompText) && /p->second/.test(s.decompText));
      const layout = async (what: string) => {
        const rows = a.locator(`${CARD} [data-testid=hc-layout] [data-testid=hc-field]`);
        await rows.first().waitFor({ timeout: 5000 }).catch(async (e) => {
          throw new Error(`${what}: no layout; the card: ${await a.locator(CARD).textContent().catch(() => "(none)")}; ${e}`);
        });
        const names = await rows.evaluateAll((els) => els.map((e) => e.getAttribute("data-name")));
        assert(JSON.stringify(names) === JSON.stringify(["first", "second"]), `${what}: fields ${JSON.stringify(names)}`);
      };
      // The parameter.
      await a.locator("#cm .cm-content span.k-pa", { hasText: /^p$/ }).first().hover();
      await layout("the parameter");
      await away(a);
      // The field: its member is marked.
      await a.locator("#cm .cm-content span.k-fd", { hasText: /^second$/ }).first().hover();
      await layout("the field");
      const marked = await a.locator(`${CARD} [data-testid=hc-field][data-mark]`).getAttribute("data-name");
      assert(marked === "second", `marked: ${marked}`);
      await shot(a, "hover-field");
      await away(a);
      // The type's name.
      await a.locator("#cm .cm-content span.k-ty", { hasText: /^pair$/ }).first().hover();
      await layout("the type");
      await away(a);
    } finally {
      await rpc(base, "AssertionService/RetractAssertions", { programId: "default/prog", seqs: made.map((x) => x.seq), provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
    }
  });
}
