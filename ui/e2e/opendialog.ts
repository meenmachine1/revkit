// End-to-end checks for the Open dialog's table (docs/ui.md, "Opening
// programs"; src/ui/open.ts): the search (by name, architecture, folder;
// a letter typed on the list goes there; Escape clears it), the sortable
// columns, the details of the program picked, the Open program button
// (disabled on a folder, enabled on a program), and opening with Enter, a
// double click and the button. run.ts calls openDialogChecks() with its
// helpers.

import type { Page } from "playwright";
import path from "node:path";

export interface OpenDialogContext {
  base: string;
  exe: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  open: (base: string, query?: string, hash?: string, dpr?: number) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
}

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

type Prog = { programId: string; name: string; sha256: string; languageId: string };

export async function openDialogChecks(c: OpenDialogContext) {
  const { base, check, open, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const prov = { kind: "PROVENANCE_KIND_USER", id: "e2e" };
  let second: Prog | undefined;
  let folderId = "";

  const openDialog = async (p: Page) => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+o");
    await p.locator("[data-testid=open-row]", { hasText: /^prog/ }).first().waitFor();
  };
  // The program rows' names, in order.
  const names = (p: Page) => p.locator("[data-testid=open-row] .open-name").allTextContents();
  const search = async (p: Page, text: string) => {
    await p.fill("[data-testid=open-search]", text);
    await p.waitForFunction((t) => (document.querySelector("[data-testid=open-search]") as HTMLInputElement).value === t, text);
  };
  const detail = (p: Page, key: string) => p.textContent(`[data-testid=open-detail-${key}]`);

  await check("open dialog: search by name, architecture and folder; sortable columns; the details; Enter opens the match", async () => {
    // A second program, in a folder.
    second = (await rpc<{ program: Prog }>(base, "ProjectService/ImportProgram", { projectId: "default", path: c.exe, name: "zz-second", provenance: prov })).program;
    folderId = (await rpc<{ folder: { folderId: string } }>(base, "ProjectService/CreateFolder", { projectId: "default", parentId: "", name: "e2e-sub", provenance: prov })).folder.folderId;
    await rpc(base, "ProjectService/MoveToFolder", { projectId: "default", folderId, programIds: [second.programId], provenance: prov });
    const p = await open(base);
    await openDialog(p);
    // The header's columns, the breadcrumb's count.
    const heads = await p.locator(".od-thead .od-th").allTextContents();
    assert(heads.map((t) => t.replace(/[▲▼]/g, "").trim()).join("|") === "Name|Architecture|Imported|Status", `columns ${heads}`);
    assert(/^\d+ programs?/.test((await p.textContent("[data-testid=open-count]")) ?? ""), "the program count");
    // A folder picked: no program to open.
    await p.locator("[data-testid=open-folder]", { hasText: "e2e-sub" }).click();
    assert(await p.isDisabled("[data-testid=open-go]"), "Open program is disabled on a folder");
    assert((await p.textContent("[data-testid=open-details]"))?.includes("/e2e-sub"), "the folder's details");
    assert((await p.locator("[data-testid=open-crumb]").allTextContents()).join("/") === "e2e-sub", "the breadcrumb shows the folder");
    // A program picked: its details, and the button.
    await p.locator("[data-testid=open-row]", { hasText: /^prog/ }).first().click();
    assert(await p.isEnabled("[data-testid=open-go]"), "Open program is enabled on a program");
    const prog = (await rpc<{ programs: Prog[] }>(base, "ProjectService/ListPrograms", { projectId: "default" })).programs.find((x) => x.name === "prog")!;
    assert((await detail(p, "format")) === "ELF", `format ${await detail(p, "format")}`);
    assert((await detail(p, "language")) === prog.languageId, `language ${await detail(p, "language")}`);
    assert((await p.textContent("[data-testid=open-copy-sha]"))?.trim() === prog.sha256.slice(0, 12), "the short fingerprint");
    assert((await p.getAttribute("[data-testid=open-copy-sha]", "title"))?.includes(prog.sha256), "the full SHA-256 in its title");
    assert(/gcc|default/.test((await detail(p, "compiler")) ?? ""), `compiler ${await detail(p, "compiler")}`);
    assert(/\d+(\.\d)? KB \([\d,]+ bytes\)/.test((await detail(p, "size")) ?? ""), `size ${await detail(p, "size")}`);
    const arch = (await p.locator("[data-testid=open-row]", { hasText: /^prog/ }).first().locator(".od-c-arch").textContent()) ?? "";
    assert(arch === "x86 · 64-bit · LE", `architecture as people read it: ${arch}`);
    await p.locator("[data-testid=open-row] .od-st-here", { hasText: "Open here" }).waitFor();
    await p.locator("[data-testid=open-row]", { hasText: /^zz-second/ }).locator(".od-st-ready, .od-st-busy").waitFor({ timeout: 20000 });
    await shot(p, "open-dialog-details");
    // Search by architecture: both, flat, the folder shown beside the name.
    await search(p, "x86 64");
    const both = await names(p);
    assert(both.includes("prog") && both.includes("zz-second"), `x86 matches ${both}`);
    assert((await p.textContent("[data-testid=open-row] .od-where")) === "/e2e-sub", "the folder beside a match");
    // Sort by name: descending, then ascending again.
    await p.click("[data-testid=open-sort-name]");
    const desc = await names(p);
    assert(desc.indexOf("zz-second") < desc.indexOf("prog"), `descending ${desc}`);
    assert((await p.getAttribute("[data-testid=open-sort-name]", "data-dir")) === "desc", "the header says so");
    await p.click("[data-testid=open-sort-name]");
    const asc = await names(p);
    assert(asc.indexOf("prog") < asc.indexOf("zz-second"), `ascending ${asc}`);
    // Sort by date: the newest first.
    await p.click("[data-testid=open-sort-date]");
    assert((await names(p))[0] === "zz-second", `newest first: ${await names(p)}`);
    await p.click("[data-testid=open-sort-name]");
    // Search by folder; no match; Escape clears it and leaves the dialog open.
    await search(p, "e2e-sub");
    assert((await names(p)).join() === "zz-second", `by folder: ${await names(p)}`);
    assert(/^1 of \d+ programs$/.test((await p.textContent("[data-testid=open-count]")) ?? ""), `count ${await p.textContent("[data-testid=open-count]")}`);
    await search(p, "no-such-program-here");
    await p.locator("[data-testid=open-list]", { hasText: "No programs match" }).waitFor();
    assert(await p.isDisabled("[data-testid=open-go]"), "nothing to open");
    await p.focus("[data-testid=open-search]");
    await p.keyboard.press("Escape");
    assert((await p.inputValue("[data-testid=open-search]")) === "", "Escape clears the search");
    assert(await p.isVisible("[data-testid=open-dialog]"), "and the dialog stays");
    // Type to filter: letters typed on the list go to the search; Enter opens the match.
    await p.focus("[data-testid=open-list]");
    await p.keyboard.type("zz-sec");
    assert((await p.inputValue("[data-testid=open-search]")) === "zz-sec", `typed into the search: ${await p.inputValue("[data-testid=open-search]")}`);
    assert((await names(p)).join() === "zz-second", `filtered ${await names(p)}`);
    await Promise.all([p.waitForEvent("load"), p.keyboard.press("Enter")]);
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    assert(new URL(p.url()).searchParams.get("program") === second.programId, `Enter opened ${p.url()}`);
    await p.context().close();
  });

  await check("open dialog: a click picks a program, a double click or Open program opens it", async () => {
    assert(second, "the program the check above imported");
    const p = await open(base);
    await openDialog(p);
    // In the folder (open: the tree remembers per project).
    const folder = p.locator("[data-testid=open-folder]", { hasText: "e2e-sub" });
    if ((await folder.getAttribute("aria-expanded")) === "false") await folder.locator(".od-caret").click();
    const row = p.locator("[data-testid=open-row]", { hasText: /^zz-second/ });
    await row.click();
    assert(await p.isVisible("[data-testid=open-dialog]"), "a click only picks it");
    assert((await row.getAttribute("aria-selected")) === "true", "picked");
    assert((await p.textContent("[data-testid=open-detail-location]"))?.endsWith("/ e2e-sub"), "the details say where it is");
    assert((await p.locator("[data-testid=open-crumb]").allTextContents()).join("/") === "e2e-sub", "the breadcrumb follows the pick");
    await Promise.all([p.waitForEvent("load"), row.dblclick()]);
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    assert(new URL(p.url()).searchParams.get("program") === second.programId, `the double click opened ${p.url()}`);
    // The footer's button, back to prog.
    await openDialog(p);
    await p.locator("[data-testid=open-row]", { hasText: /^prog/ }).first().click();
    await Promise.all([p.waitForEvent("load"), p.click("[data-testid=open-go]")]);
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    assert(new URL(p.url()).searchParams.get("program") === "default/prog", `Open program opened ${p.url()}`);
    await p.context().close();
    // Left as the checks after these expect: no second program, no folder.
    await rpc(base, "ProjectService/MoveToFolder", { projectId: "default", folderId: "", programIds: [second.programId], provenance: prov });
    await rpc(base, "ProjectService/DeleteProgram", { programId: second.programId, provenance: prov });
    await rpc(base, "ProjectService/DeleteFolder", { projectId: "default", folderId, provenance: prov });
  });
}
