// End-to-end checks for the UI polish pass (phase 9; docs/ui.md "Docked
// views", "Menus and dialogs"): menus whose items are all disabled still
// close with Escape; a palette command that opens a menu keeps the focus
// there; tabs that don't fit get the » menu and the active one scrolls into
// view; a long context menu stays inside a short window and scrolls; Tab
// stays inside a modal dialog; the palette lists each command once; the side
// leaves the listing room in a narrow window; the call graph's root follows
// a rename. run.ts calls uiPolishChecks() with a page factory.

import type { Page } from "playwright";
import path from "node:path";

export interface UiPolishContext {
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  assert: (cond: unknown, msg: string) => asserts cond;
  /** A page on default/prog at this viewport, ready. */
  page: (width: number, height: number) => Promise<Page>;
}

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

async function palette(p: Page, title: string) {
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+Shift+P");
  await p.waitForSelector("[data-testid=palette-input]");
  await p.fill("[data-testid=palette-input]", `>${title}`);
  await p.waitForFunction((t) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").toLowerCase().startsWith(t.toLowerCase()), title);
  await p.keyboard.press("Enter");
}

const focusIn = (p: Page, sel: string) => p.evaluate((s) => !!document.activeElement?.closest(s), sel);

export async function uiPolishChecks(c: UiPolishContext) {
  const { check } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const p = await c.page(1500, 900);

  await check("polish: the palette lists each command once, with descriptions apart and names capitalized", async () => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+Shift+P");
    await p.fill("[data-testid=palette-input]", ">");
    await p.waitForSelector(".palette-item");
    const items = await p.$$eval(".palette-item", (els) => els.map((e) => ({ label: e.querySelector(".pi-label")?.textContent ?? "", keys: e.querySelector("kbd")?.textContent ?? "" })));
    await p.keyboard.press("Escape");
    const labels = items.map((i) => i.label);
    const dup = labels.filter((l, i) => labels.indexOf(l) !== i);
    assert(!dup.length, `duplicate commands: ${dup.join(", ")}`);
    // One command per shortcut (the views' and the others').
    const byKeys = new Map<string, string[]>();
    for (const i of items) if (i.keys) byKeys.set(i.keys, [...(byKeys.get(i.keys) ?? []), i.label]);
    const shared = [...byKeys].filter(([k, l]) => l.length > 1 && !/\(in |Enter|^Ctrl\+L \/ Y$|^L \/ N \/ F2$|^Ctrl\+C$/.test(k));
    assert(!shared.length, `shortcuts on two commands: ${shared.map(([k, l]) => `${k}: ${l.join(" | ")}`).join("; ")}`);
    assert(!labels.some((l) => l.includes(" — ")), "a description in a command's title");
    assert(!labels.some((l) => /\bpython\b|function id\b/.test(l)), `lower-cased names: ${labels.filter((l) => /\bpython\b|function id\b/.test(l)).join(", ")}`);
  });

  await check("polish: the listing's right-click menu keeps the common actions on top and the rest in submenus, by keyboard too", async () => {
    await p.focus("#listing-canvas");
    // As the context-menu key or Shift+F10 sends it: at (0, 0), placed by the selected row.
    await p.locator("#listing-canvas").dispatchEvent("contextmenu", { button: 0, clientX: 0, clientY: 0 });
    await p.waitForSelector("[data-testid=menu]");
    const top = await p.$$eval("[data-testid=menu] > .menu-item", (els) => els.map((e) => e.getAttribute("data-testid") ?? ""));
    for (const id of ["ctx-follow", "ctx-xrefs", "ctx-goto", "ctx-rename", "ctx-retype", "ctx-comment", "ctx-comments", "ctx-function", "ctx-copy"])
      assert(top.includes(id), `${id} not at the top level: ${top.join(" ")}`);
    for (const id of ["ctx-fn-create", "ctx-comment-plate", "ctx-copy-special", "ctx-note"]) assert(!top.includes(id), `${id} at the top level`);
    assert(top.length <= 22, `${top.length} items at the top level: ${top.join(" ")}`);
    // Down to Comments, → opens it with the focus on its first item, ← back, Escape closes.
    for (let i = 0; i < 30; i++) {
      if ((await p.evaluate(() => document.activeElement?.getAttribute("data-testid"))) === "ctx-comments") break;
      await p.keyboard.press("ArrowDown");
    }
    await p.keyboard.press("ArrowRight");
    await p.waitForSelector("[data-testid=submenu]");
    assert((await p.evaluate(() => document.activeElement?.getAttribute("data-testid"))) === "ctx-comment-plate", "focus in the Comments submenu");
    await p.keyboard.press("ArrowDown");
    assert((await p.evaluate(() => document.activeElement?.getAttribute("data-testid"))) === "ctx-comment-pre", "down in the submenu");
    await p.keyboard.press("ArrowLeft");
    await p.waitForSelector("[data-testid=submenu]", { state: "detached" });
    assert((await p.evaluate(() => document.activeElement?.getAttribute("data-testid"))) === "ctx-comments", "back on Comments");
    await shot(p, "listing-context-menu");
    await p.keyboard.press("Escape");
    await p.waitForSelector("[data-testid=menu]", { state: "detached" });
  });

  await check("polish: a menu with every item disabled takes the focus, and Escape closes it", async () => {
    // A fresh page has only the current location in its history: its one item is disabled.
    await p.click("[data-testid=history]");
    await p.waitForSelector("[data-testid=menu]");
    assert(await focusIn(p, "[data-testid=menu]"), "the focus is in the menu");
    await p.keyboard.press("Escape");
    await p.waitForSelector("[data-testid=menu]", { state: "detached", timeout: 3000 });
    // From the palette, the menu keeps the focus (the palette doesn't take it back).
    await palette(p, "Navigation history");
    await p.waitForSelector("[data-testid=menu]");
    await p.waitForTimeout(100);
    assert(await focusIn(p, "[data-testid=menu]"), "the palette left the focus in the menu");
    await p.keyboard.press("Escape");
    await p.waitForSelector("[data-testid=menu]", { state: "detached", timeout: 3000 });
  });

  await check("polish: Tab and Shift+Tab stay inside a modal dialog", async () => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("n");
    await p.waitForSelector("[data-testid=ask] .ask-input");
    for (let i = 0; i < 6; i++) {
      await p.keyboard.press("Tab");
      await p.waitForTimeout(30);
      assert(await focusIn(p, "[data-testid=ask]"), `Tab ${i + 1} left the dialog`);
    }
    for (let i = 0; i < 6; i++) {
      await p.keyboard.press("Shift+Tab");
      await p.waitForTimeout(30);
      assert(await focusIn(p, "[data-testid=ask]"), `Shift+Tab ${i + 1} left the dialog`);
    }
    // A click on the page behind returns the focus to the dialog.
    await p.evaluate(() => (document.getElementById("search") as HTMLElement).focus());
    assert(await focusIn(p, "[data-testid=ask]"), "the focus went behind the dialog");
    await p.keyboard.press("Escape");
    await p.waitForSelector("[data-testid=ask]", { state: "detached" });
  });

  await check("polish: the call graph's root follows a rename (and its undo)", async () => {
    await p.evaluate(() => (window as unknown as { __revkit: { app: { showView: (v: string) => void } } }).__revkit.app.showView("calls"));
    const title = () => p.textContent("[data-testid=calls-view] .panel-head .graph-title");
    await p.waitForFunction(() => document.querySelector("[data-testid=calls-view] .graph-title")?.textContent === "main");
    await p.focus("#listing-canvas");
    await p.keyboard.press("n");
    await p.fill("[data-testid=ask] .ask-input", "main_polish");
    await p.keyboard.press("Enter");
    await p.waitForFunction(() => document.querySelector("[data-testid=calls-view] .graph-title")?.textContent === "main_polish", undefined, { timeout: 10000 }).catch(async () => {
      throw new Error(`calls title: ${await title()}`);
    });
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+z");
    await p.waitForFunction(() => document.querySelector("[data-testid=calls-view] .graph-title")?.textContent === "main", undefined, { timeout: 10000 });
    await p.evaluate(() => (window as unknown as { __revkit: { app: { showView: (v: string) => void } } }).__revkit.app.showView("decomp"));
  });

  await check("polish: a narrow window: the side leaves the listing room, tabs that don't fit get the » menu", async () => {
    const n = await c.page(1024, 600);
    const w = await n.evaluate(() => [document.getElementById("dock-main")!.getBoundingClientRect().width, document.getElementById("dock-side")!.getBoundingClientRect().width]);
    assert(w[0] >= 340, `the main area is ${w[0]} px wide (the side ${w[1]})`);
    // The narrow listing hides its bytes (the instructions show); the wide page keeps them.
    const bytes = (q: Page) => q.evaluate(() => (window as unknown as { __revkit: { app: { cols: { showBytes: boolean } } } }).__revkit.app.cols.showBytes);
    assert((await bytes(n)) === false && (await bytes(p)) === true, "the bytes column: hidden in the narrow listing only");
    await n.waitForSelector("[data-testid=dock-more-side]:not([hidden])");
    await n.click("[data-testid=dock-more-side]");
    await n.waitForSelector("[data-testid=menu]");
    const last = await n.$$eval("[data-testid=menu] .menu-item", (els) => els.at(-1)?.getAttribute("data-testid") ?? "");
    assert(last.startsWith("dock-more-"), `menu items: ${last}`);
    await n.click(`[data-testid=${last}]`);
    const id = last.slice("dock-more-".length);
    await n.waitForSelector(`[data-testid=tab-${id}].active`);
    // The active tab scrolled into the strip's view.
    const inView = await n.evaluate((v) => {
      const t = document.querySelector(`[data-testid=tab-${v}]`)!.getBoundingClientRect();
      const s = document.querySelector("#dock-side .dock-tabs")!.getBoundingClientRect();
      return t.left >= s.left - 1 && t.right <= s.right + 1;
    }, id);
    assert(inView, `tab ${id} is out of the strip's view`);
    await shot(n, "80-polish-narrow");
    // The listing's context menu: inside the window, scrolling when taller.
    await n.evaluate(() => (window as unknown as { __revkit: { app: { showView: (v: string) => void } } }).__revkit.app.showView("listing"));
    const box = (await n.locator("#listing-canvas").boundingBox())!;
    await n.mouse.click(box.x + box.width / 2, box.y + box.height - 20, { button: "right" });
    await n.waitForSelector("[data-testid=menu]");
    const m = await n.evaluate(() => {
      const el = document.querySelector<HTMLElement>("[data-testid=menu]")!;
      const r = el.getBoundingClientRect();
      return { top: r.top, bottom: r.bottom, h: innerHeight, scrolls: el.scrollHeight > el.clientHeight };
    });
    assert(m.top >= 0 && m.bottom <= m.h, `the menu spans ${m.top}-${m.bottom} in a ${m.h} px window`);
    assert(m.scrolls, "the long menu scrolls");
    await n.keyboard.press("Escape");
    await n.context().close();
  });

  await check("polish: an 820 px window keeps the program's name in the context row; the menus fold into ☰", async () => {
    const n = await c.page(820, 600);
    const t = await n.evaluate(() => {
      const b = document.getElementById("program")!;
      const app = document.getElementById("app")!;
      const bar = document.getElementById("toolbar")!;
      return { fits: b.scrollWidth <= b.clientWidth + 1, text: b.textContent, wide: app.scrollWidth <= innerWidth + 1, bar: bar.scrollWidth <= bar.clientWidth + 1 };
    });
    assert(t.fits && t.wide && t.bar, `toolbar: ${JSON.stringify(t)}`);
    assert(!(await n.isVisible("[data-testid=edit-menu]")) && (await n.isVisible("[data-testid=all-menu]")), "the menus behind one button");
    await n.click("[data-testid=all-menu]");
    await n.click("[data-testid=all-menu-nav]");
    await n.waitForSelector("[data-testid=menu-cmd-goto]");
    await n.keyboard.press("Escape");
    await n.keyboard.press("Escape");
    await shot(n, "82-polish-820");
    await n.context().close();
  });

  await check("polish: the menus (Edit, View, Navigate, Analyze) hold the palette's commands; the context row; Import binary… opens the import section", async () => {
    const q = await c.page(1440, 900);
    // The context row: the project, the program; the toolbar's command field.
    assert((await q.textContent("#project-name")) === "default", `project ${await q.textContent("#project-name")}`);
    assert((await q.textContent("#program")) === "prog", `program ${await q.textContent("#program")}`);
    assert(/Go to address, symbol, or command/.test((await q.textContent("#search")) ?? ""), "the command field");
    const items = async (menu: string) => {
      await q.click(`[data-testid=${menu}]`);
      await q.waitForSelector("[data-testid=menu]");
      const t = await q.$$eval("[data-testid=menu] .menu-item", (els) => els.map((e) => e.getAttribute("data-testid") ?? ""));
      await q.keyboard.press("Escape");
      return t;
    };
    const edit = await items("edit-menu");
    assert(["menu-cmd-undo", "menu-cmd-rename", "menu-cmd-retype", "menu-cmd-comment"].every((x) => edit.includes(x)), `Edit: ${edit}`);
    const view = await items("view-menu");
    assert(["menu-view-listing", "menu-view-decomp", "menu-view-graph", "menu-cmd-layout-reset", "menu-cmd-theme"].every((x) => view.includes(x)), `View: ${view}`);
    const nav = await items("nav-menu");
    assert(["menu-cmd-goto", "menu-cmd-back", "menu-cmd-forward", "menu-cmd-xrefs"].every((x) => nav.includes(x)), `Navigate: ${nav}`);
    const analyze = await items("analyze-menu");
    assert(["menu-cmd-auto-struct", "menu-cmd-compare"].every((x) => analyze.includes(x)), `Analyze: ${analyze}`);
    // View → Graph shows it; a menu command runs (Navigate → Go to opens the palette).
    await q.click("[data-testid=view-menu]");
    await q.click("[data-testid=menu-view-graph]");
    await q.waitForSelector("[data-testid=tab-graph].active");
    await q.click("[data-testid=view-menu]");
    await q.click("[data-testid=menu-view-listing]");
    await q.click("[data-testid=nav-menu]");
    await q.click("[data-testid=menu-cmd-goto]");
    await q.waitForSelector("[data-testid=palette-input]");
    await q.keyboard.press("Escape");
    await shot(q, "81-polish-chrome");
    // Import binary…: the Open dialog, in its import section; the project crumb: the project switcher.
    await q.click("[data-testid=import-binary]");
    await q.waitForSelector("[data-testid=open-import-view]:not([hidden])");
    assert(await q.isVisible("[data-testid=open-import]"), "Choose file… is there");
    await q.keyboard.press("Escape");
    await q.keyboard.press("Escape");
    await q.waitForSelector("[data-testid=open-dialog]", { state: "detached" });
    await q.click("[data-testid=project-crumb]");
    await q.waitForFunction(() => document.activeElement?.getAttribute("data-testid") === "open-project");
    await q.keyboard.press("Escape");
    await q.context().close();
  });

  await check("decompiler: drag selects two lines (highlighted) and Ctrl+C copies them; a click still selects a token and Ctrl+C copies it; Ctrl+A; Copy in the menu", async () => {
    const q = await c.page(1500, 900);
    await q.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    type Pane = { __revkit: { app: { pane: { copyText: () => string | null; selected: { tok: { text: string } } | null; text: string } } } };
    // Captures what the copy event puts on the clipboard.
    await q.evaluate(() => {
      (window as unknown as { __copied: string[] }).__copied = [];
      // Bubble phase, after the pane set the data (it is gone once the event ends).
      window.addEventListener("copy", (e) => (window as unknown as { __copied: string[] }).__copied.push((e as ClipboardEvent).clipboardData?.getData("text/plain") ?? ""));
    });
    const copied = () => q.evaluate(() => (window as unknown as { __copied: string[] }).__copied.at(-1) ?? null);
    const lines = q.locator("#cm .cm-line");
    await lines.nth(3).waitFor();
    const a = (await lines.nth(2).boundingBox())!, b = (await lines.nth(3).boundingBox())!;
    await q.mouse.move(a.x + 2, a.y + a.height / 2);
    await q.mouse.down();
    await q.mouse.move(b.x + 120, b.y + b.height / 2, { steps: 8 });
    await q.mouse.up();
    const want = ((await lines.nth(2).textContent()) ?? "").trim();
    const sel = await q.evaluate(() => (window as unknown as Pane).__revkit.app.pane.copyText());
    assert(sel !== null && sel.includes("\n") && sel.includes(want), `the selection spans two lines: ${JSON.stringify(sel)}`);
    assert((await q.locator("#cm .cm-selectionBackground").count()) > 0, "the selection is drawn");
    await q.keyboard.press("Control+c");
    await q.waitForTimeout(100);
    assert((await copied()) === sel, `Ctrl+C copied the selection: ${JSON.stringify(await copied())}`);
    // A plain click selects a token (no text selected) and Ctrl+C copies it.
    const tok = q.locator("#cm .cm-content span.k-fn").nth(1);
    const name = ((await tok.textContent()) ?? "").trim();
    await tok.click();
    await q.waitForFunction((n) => (window as unknown as Pane).__revkit.app.pane.selected?.tok.text === n, name);
    assert((await q.locator("#cm .cm-selectionBackground").count()) === 0, "the click left no text selection");
    await q.keyboard.press("Control+c");
    await q.waitForTimeout(100);
    assert((await copied()) === name, `Ctrl+C copied the token ${name}: ${await copied()}`);
    // Ctrl+A selects the whole function.
    await q.keyboard.press("Control+a");
    const all = await q.evaluate(() => [(window as unknown as Pane).__revkit.app.pane.copyText(), (window as unknown as Pane).__revkit.app.pane.text]);
    assert(all[0] === all[1] && (all[0] ?? "").length > 20, "Ctrl+A selected the function");
    // The context menu has Copy and Copy function; Copy function puts the C on the clipboard.
    await tok.click({ button: "right" });
    await q.waitForSelector("[data-testid=ctx-decomp-copy]");
    await q.click("[data-testid=ctx-decomp-copy-all]");
    await q.waitForFunction(async () => (await navigator.clipboard.readText()).length > 20);
    const clip = await q.evaluate(() => navigator.clipboard.readText());
    assert(clip === all[1], "Copy function copied the C");
    await q.context().close();
  });

  await check("polish: search results start closed; a search opens them; × closes them and they stay closed after a reload; Escape closes too", async () => {
    type W = { __revkit: { app: { dock: { isOpen: (v: string) => boolean } } } };
    const open = (q: Page) => q.evaluate(() => (window as unknown as W).__revkit.app.dock.isOpen("searchresults"));
    const q = await c.page(1500, 900);
    assert((await open(q)) === false && (await q.locator("[data-testid=tab-searchresults]").count()) === 0, "closed before any search");
    await q.focus("#listing-canvas");
    await q.keyboard.press("Control+f");
    await q.waitForSelector(".search-dialog input");
    await q.keyboard.type("main");
    await q.keyboard.press("Control+Enter");
    await q.waitForSelector("[data-testid=search-view]:not([hidden]) .sr-list .sr-row", { timeout: 15000 });
    await q.keyboard.press("Escape"); // the search dialog
    await q.click("[data-testid=tab-close-searchresults]");
    await q.waitForSelector("[data-testid=tab-searchresults]", { state: "detached" });
    await q.waitForSelector("[data-testid=tab-decomp].active"); // back to the tab shown before the search
    assert(await q.evaluate(() => (document.querySelector("[data-testid=search-view]") as HTMLElement).hidden), "the view is hidden");
    await q.reload();
    await q.waitForSelector("body[data-ready='1']");
    await q.waitForTimeout(300);
    assert((await open(q)) === false, "still closed after a reload");
    // The palette's command opens it again; Escape in the table closes it.
    await palette(q, "Show search results");
    await q.waitForSelector("[data-testid=tab-searchresults].active");
    await q.focus("[data-testid=search-results]");
    await q.keyboard.press("Escape");
    await q.waitForSelector("[data-testid=tab-searchresults]", { state: "detached" });
    await q.context().close();
  });

  await check("polish: clicking a tab half out of the strip scrolls it just into view (no jump)", async () => {
    const n = await c.page(1024, 600);
    const strip = n.locator("#dock-side .dock-tabs");
    await strip.evaluate((e) => (e.scrollLeft = 120));
    const tab = await n.evaluate(() => {
      const s = document.querySelector("#dock-side .dock-tabs")!.getBoundingClientRect();
      const t = [...document.querySelectorAll<HTMLElement>("#dock-side .dock-tab")].find((x) => { const r = x.getBoundingClientRect(); return r.left < s.right && r.right > s.right; });
      return t?.dataset.testid ?? "";
    });
    assert(tab, "a tab half out of the strip");
    const before = await strip.evaluate((e) => e.scrollLeft);
    const w = (await n.locator(`[data-testid=${tab}]`).boundingBox())!.width;
    await n.click(`[data-testid=${tab}]`, { position: { x: 4, y: 8 } });
    await n.waitForTimeout(100);
    const after = await strip.evaluate((e) => e.scrollLeft);
    assert(after > before && after - before <= w + 10, `the strip scrolled ${after - before} px for a ${w} px tab`);
    await n.context().close();
  });

  await p.context().close();
}
