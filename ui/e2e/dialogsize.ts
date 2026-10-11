// End-to-end checks for resizable dialogs (docs/ui.md, "Resizable
// dialogs"; src/ui/dialogsize.ts): the Open dialog (Ctrl+O, the dialog a
// fresh start shows) dragged by its corner grows, its program list taller
// with it; the size is kept after a reload; a double click on the grip
// gives the usual size back; another dialog (About) has the grips too.
// run.ts calls dialogSizeChecks() with a page factory.

import type { Page } from "playwright";
import path from "node:path";

export interface DialogSizeContext {
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  assert: (cond: unknown, msg: string) => asserts cond;
  /** A page on default/prog at this viewport, ready. */
  page: (width: number, height: number) => Promise<Page>;
}

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

type Sizes = { w: number; h: number; list: number; top: number; bottom: number };

async function sizes(p: Page): Promise<Sizes> {
  return p.evaluate(() => {
    const box = document.querySelector<HTMLElement>("[data-testid=open-dialog]")!.getBoundingClientRect();
    const list = document.querySelector<HTMLElement>("[data-testid=open-list]")!.getBoundingClientRect();
    return { w: Math.round(box.width), h: Math.round(box.height), list: Math.round(list.height), top: Math.round(box.top), bottom: Math.round(box.bottom) };
  });
}

async function openDialog(p: Page) {
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+o");
  await p.waitForSelector("[data-testid=open-dialog]");
  // The program list has loaded (not "Loading…").
  await p.waitForFunction(() => !(document.querySelector("[data-testid=open-list]")?.textContent ?? "").includes("Loading"));
  await p.waitForSelector("[data-testid=dialog-resize-se]");
}

async function closeDialog(p: Page) {
  await p.keyboard.press("Escape");
  await p.waitForSelector("[data-testid=open-dialog]", { state: "detached" });
}

export async function dialogSizeChecks(c: DialogSizeContext) {
  const { check } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const p = await c.page(1500, 900);
  let before!: Sizes;
  let after!: Sizes;

  await check("dialogs: drag the Open dialog's corner; it grows and its program list grows with it", async () => {
    await openDialog(p);
    before = await sizes(p);
    await shot(p, "dialog-open-before");
    // The grip is at the dialog's bottom-right corner (its ResizeObserver
    // moves it a frame after the program list fills the dialog).
    const atCorner = (b: { x: number; y: number; width: number; height: number }, s: Sizes) => Math.abs(b.x + b.width - (750 + s.w / 2)) < 20 && Math.abs(b.y + b.height - s.bottom) < 20;
    let g = (await p.locator("[data-testid=dialog-resize-se]").boundingBox())!;
    for (let end = Date.now() + 3000; !atCorner(g, before) && Date.now() < end; ) {
      await p.waitForTimeout(100);
      before = await sizes(p);
      g = (await p.locator("[data-testid=dialog-resize-se]").boundingBox())!;
    }
    assert(atCorner(g, before), `grip at ${JSON.stringify(g)}; dialog ${JSON.stringify(before)}`);
    const x = g.x + g.width / 2, y = g.y + g.height / 2;
    await p.mouse.move(x, y);
    await p.mouse.down();
    for (let i = 1; i <= 8; i++) await p.mouse.move(x + 10 * i, y + 10 * i);
    await p.mouse.up();
    after = await sizes(p);
    await shot(p, "dialog-open-resized");
    // Centered: 80 px to the right is 160 px wider; 80 px down, 80 px more list.
    assert(Math.abs(after.w - (before.w + 160)) <= 4, `width ${before.w} -> ${after.w}`);
    assert(Math.abs(after.list - (before.list + 80)) <= 4, `list ${before.list} -> ${after.list}`);
    assert(Math.abs(after.h - (before.h + 80)) <= 4 && after.top === before.top, `dialog ${JSON.stringify(before)} -> ${JSON.stringify(after)}`);
    // Not past the window.
    await p.mouse.move(x + 80, y + 80);
    await p.mouse.down();
    await p.mouse.move(x + 900, y + 900, { steps: 6 });
    await p.mouse.up();
    const big = await sizes(p);
    assert(big.w <= 1500 - 16 && big.bottom <= 900, `grown past the window: ${JSON.stringify(big)}`);
    // Back to the size above, for the reload.
    const g2 = (await p.locator("[data-testid=dialog-resize-se]").boundingBox())!;
    await p.mouse.move(g2.x + g2.width / 2, g2.y + g2.height / 2);
    await p.mouse.down();
    await p.mouse.move(g2.x + g2.width / 2 - (big.w - after.w) / 2, g2.y + g2.height / 2 - (big.list - after.list), { steps: 6 });
    await p.mouse.up();
    after = await sizes(p);
    await closeDialog(p);
  });

  await check("dialogs: the Open dialog's size is kept after a reload; a double click on the grip gives the usual size back", async () => {
    await p.reload();
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    await openDialog(p);
    const again = await sizes(p);
    assert(Math.abs(again.w - after.w) <= 2 && Math.abs(again.list - after.list) <= 2, `after a reload ${JSON.stringify(again)}, before ${JSON.stringify(after)}`);
    await p.dblclick("[data-testid=dialog-resize-se]");
    const reset = await sizes(p);
    assert(Math.abs(reset.w - before.w) <= 2 && Math.abs(reset.list - before.list) <= 2, `reset ${JSON.stringify(reset)}, usual ${JSON.stringify(before)}`);
    await closeDialog(p);
    await openDialog(p);
    const fresh = await sizes(p);
    assert(Math.abs(fresh.w - before.w) <= 2, `forgotten: ${JSON.stringify(fresh)}`);
    await closeDialog(p);
  });

  await check("dialogs: every modal gets the grips (About)", async () => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+Shift+P");
    await p.fill("[data-testid=palette-input]", ">About revkit");
    await p.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").startsWith("About revkit"));
    // The palette is a dialog too.
    assert(await p.isVisible("[data-testid=dialog-resize-se]"), "no grip on the palette");
    await p.keyboard.press("Enter");
    await p.waitForSelector("[data-testid=about]");
    await p.waitForFunction(() => document.querySelectorAll("[data-testid=dialog-resize-se]").length === 1);
    await p.keyboard.press("Escape");
    await p.waitForSelector("[data-testid=about]", { state: "detached" });
    await p.context().close();
  });
}
