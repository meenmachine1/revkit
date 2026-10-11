// End-to-end checks for the keymap presets (docs/ui.md, "Keymap presets";
// src/ui/keymap.ts): Ghidra's keys by default (L renames, Ctrl+L sets a
// type, Ctrl+Shift+F finds references), IDA Pro's from the palette (N
// renames and L doesn't, Tab switches the listing and the decompiler, Esc
// goes back, Y sets a type and Ctrl+L doesn't), the palette, the Search
// menu, the toolbar's tooltips and the cheat sheet showing the active keys,
// the choice kept after a reload, and Binary Ninja's from Preferences
// (Ctrl+[ goes back). run.ts calls keymapChecks() with a page factory.

import type { Page } from "playwright";
import path from "node:path";

export interface KeymapContext {
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  assert: (cond: unknown, msg: string) => asserts cond;
  /** A page on default/prog at this viewport, ready (main decompiled). */
  page: (width: number, height: number) => Promise<Page>;
}

type Snap = { keymap: string; active: string; back: number; address: string | null; decompName: string | null };
const snap = (p: Page) => p.evaluate("window.__revkit.app.snapshot()") as Promise<Snap>;

async function until(p: Page, what: string, pred: (s: Snap) => boolean, ms = 10000) {
  const end = Date.now() + ms;
  let s = await snap(p);
  while (!pred(s)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify(s)}`);
    await p.waitForTimeout(50);
    s = await snap(p);
  }
  return s;
}

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

async function command(p: Page, title: string) {
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+Shift+P");
  await p.waitForSelector("[data-testid=palette-input]");
  await p.fill("[data-testid=palette-input]", `>${title}`);
  await p.waitForFunction((t) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").toLowerCase().startsWith(t.toLowerCase()), title);
  await p.keyboard.press("Enter");
  await p.waitForSelector("[data-testid=palette]", { state: "detached" });
}

/** The palette's keys for a command. */
async function paletteKeys(p: Page, title: string): Promise<string> {
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+Shift+P");
  await p.fill("[data-testid=palette-input]", `>${title}`);
  await p.waitForFunction((t) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").startsWith(t), title);
  const keys = (await p.textContent(".palette-item.active kbd")) ?? "";
  await p.keyboard.press("Escape");
  await p.waitForSelector("[data-testid=palette]", { state: "detached" });
  return keys;
}

/** The dialog a key opened (its title), or null if none opened. */
async function dialogAfter(p: Page, key: string, ms = 2500): Promise<string | null> {
  await p.keyboard.press(key);
  try {
    await p.waitForSelector("[data-testid=ask], [data-testid=xrefs]", { timeout: ms });
  } catch {
    return null;
  }
  const title = (await p.textContent("[data-testid=ask] .modal-title, [data-testid=xrefs] .modal-title")) ?? "";
  await p.keyboard.press("Escape");
  await p.waitForSelector("[data-testid=ask], [data-testid=xrefs]", { state: "detached" });
  return title;
}

async function clickToken(p: Page, text: string, cls: string) {
  const loc = p.locator(`#cm .cm-content span.${cls}`, { hasText: new RegExp(`^${text}$`) }).first();
  await loc.waitFor();
  await loc.click();
}

export async function keymapChecks(c: KeymapContext) {
  const { check } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const p = await c.page(1500, 900);

  await check("keymap: Ghidra's by default; L renames and Ctrl+L sets a type (listing, decompiler); Ctrl+Shift+F finds references", async () => {
    assert((await snap(p)).keymap === "ghidra", "the default keymap");
    await p.focus("#listing-canvas");
    const l = await dialogAfter(p, "l");
    assert(l?.startsWith("Rename"), `L in the listing: ${l}`);
    // Tab is the browser's (focus) in Ghidra's keymap, not the decompiler.
    await clickToken(p, "checksum", "k-fn");
    await until(p, "the decompiler focused", (s) => s.active === "decomp");
    const ld = await dialogAfter(p, "l");
    assert(ld?.startsWith("Rename") && ld.includes("checksum"), `L in the decompiler: ${ld}`);
    const ty = await dialogAfter(p, "Control+l");
    assert(ty !== null && !ty.startsWith("Rename"), `Ctrl+L in the decompiler: ${ty}`);
    const refs = await dialogAfter(p, "Control+Shift+F");
    assert(refs?.startsWith("References to"), `Ctrl+Shift+F: ${refs}`);
    assert((await paletteKeys(p, "Rename (function")) === "L / N / F2", "the palette's rename keys");
    assert((await p.getAttribute("#back", "title")) === "Back (Alt+←)", `back tooltip: ${await p.getAttribute("#back", "title")}`);
  });

  await check("keymap: IDA Pro from the palette: N renames, L doesn't, Tab switches listing and decompiler, Esc goes back, Y types; keys shown; kept after a reload", async () => {
    await command(p, "Keymap: IDA Pro");
    await until(p, "the IDA keymap", (s) => s.keymap === "ida");
    await p.focus("#listing-canvas");
    assert((await dialogAfter(p, "l", 600)) === null, "L opened a dialog in IDA's keymap");
    const n = await dialogAfter(p, "n");
    assert(n?.startsWith("Rename"), `N in the listing: ${n}`);
    // Tab: the decompiler, and back to the listing.
    await p.focus("#listing-canvas");
    await p.keyboard.press("Tab");
    await until(p, "Tab to the decompiler", (s) => s.active === "decomp");
    await p.keyboard.press("Tab");
    await until(p, "Tab back to the listing", (s) => s.active === "listing");
    // Esc goes back (G is go to, as in every keymap).
    const before = await snap(p);
    await p.keyboard.press("g");
    await p.waitForSelector("[data-testid=palette-input]");
    await p.fill("[data-testid=palette-input]", "checksum");
    await p.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").includes("checksum"));
    await p.keyboard.press("Enter");
    const moved = await until(p, "at checksum", (s) => s.back > before.back && s.address !== before.address);
    await p.focus("#listing-canvas");
    await p.keyboard.press("Escape");
    // The first Escape may only drop a selection, as in IDA.
    try {
      await until(p, "Esc back", (s) => s.back < moved.back, 1500);
    } catch {
      await p.keyboard.press("Escape");
      await until(p, "Esc back", (s) => s.back < moved.back);
    }
    // The decompiler: Y sets a type, Ctrl+L is nothing here.
    await clickToken(p, "checksum", "k-fn");
    const y = await dialogAfter(p, "y");
    assert(y !== null && !y.startsWith("Rename"), `Y in the decompiler: ${y}`);
    assert((await dialogAfter(p, "Control+l", 600)) === null, "Ctrl+L opened a dialog in IDA's keymap");
    const n2 = await dialogAfter(p, "n");
    assert(n2?.startsWith("Rename") && n2.includes("checksum"), `N in the decompiler: ${n2}`);
    // The keys shown: the palette, the Search menu, the toolbar's tooltip.
    assert((await paletteKeys(p, "Rename (function")) === "N", "the palette's rename keys");
    assert((await paletteKeys(p, "Switch between the listing and the decompiler")) === "Tab", "the palette's Tab");
    assert((await p.getAttribute("#back", "title")) === "Back (Esc / Alt+←)", `back tooltip: ${await p.getAttribute("#back", "title")}`);
    const hints = (await p.textContent("[data-testid=key-hints]")) ?? "";
    assert(hints.startsWith("N rename · Y type") && hints.includes("C U D code/data") && hints.includes("Tab decompiler"), `status bar hints: ${hints}`);
    if (await p.isVisible("[data-testid=search-menu]")) {
      await p.click("[data-testid=search-menu]");
      await p.waitForSelector("[data-testid=menu-search-text]");
      const k = (await p.textContent("[data-testid=menu-search-text] kbd")) ?? "";
      assert(k === "Alt+T", `Search → Program text: ${k}`);
      await p.keyboard.press("Escape");
    }
    // The cheat sheet lists IDA's keys.
    await command(p, "Help: Keyboard shortcuts");
    await p.waitForSelector("[data-testid=shortcuts][data-preset=ida]");
    const rename = (await p.textContent("[data-testid=shortcut-row][data-action=rename]")) ?? "";
    const code = (await p.textContent("[data-testid=shortcut-row][data-action=le-disasm]")) ?? "";
    assert(rename.endsWith("N") && code.endsWith("C"), `cheat sheet: ${rename} | ${code}`);
    await shot(p, "keymap-cheatsheet-ida");
    await p.keyboard.press("Escape");
    await p.waitForSelector("[data-testid=shortcuts]", { state: "detached" });
    // Kept for this viewer.
    await p.reload();
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    await until(p, "IDA after a reload", (s) => s.keymap === "ida");
  });

  await check("keymap: Binary Ninja from File → Preferences; Ctrl+[ goes back; Ghidra's again", async () => {
    await p.click("[data-testid=file-menu]");
    await p.click("[data-testid=file-preferences]");
    await p.waitForSelector("[data-testid=preferences]");
    await shot(p, "keymap-preferences");
    await p.check("[data-testid=pref-keymap-binja]");
    await until(p, "the Binary Ninja keymap", (s) => s.keymap === "binja");
    await p.click("[data-testid=pref-close]");
    await p.waitForSelector("[data-testid=preferences]", { state: "detached" });
    const before = await snap(p);
    await p.keyboard.press("Control+k");
    await p.fill("[data-testid=palette-input]", "twice");
    await p.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").includes("twice"));
    await p.keyboard.press("Enter");
    const moved = await until(p, "at twice", (s) => s.back > before.back);
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+BracketLeft");
    await until(p, "Ctrl+[ back", (s) => s.back < moved.back);
    await command(p, "Keymap: Ghidra");
    await until(p, "Ghidra's again", (s) => s.keymap === "ghidra");
    await p.context().close();
  });
}
