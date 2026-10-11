// End-to-end checks for the project tree and project archives (api_minor
// 35, features "project-folders" and "project-archive"): a folder made in
// the Open dialog, a program dragged into it, the folder renamed, the tree
// after a reload; File → Export project… saving a .rkproj and File →
// Import project… bringing it into a new project, whose program opens.
// run.ts calls projectChecks() with its helpers.

import type { Page } from "playwright";
import { readFileSync } from "node:fs";
import path from "node:path";

export interface ProjectsContext {
  base: string;
  tmp: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  open: (base: string, query?: string, hash?: string, dpr?: number) => Promise<Page>;
  answer: (p: Page, text: string) => Promise<void>;
  until: <T>(p: Page, what: string, pred: (s: T) => boolean, ms?: number) => Promise<T>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
}

interface Snap {
  decompName: string | null;
  live: string;
}

type Prog = { programId: string; name: string; folderPath?: string };

export async function projectChecks(c: ProjectsContext) {
  const { base, check, open, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const ready = (p: Page) => c.until<Snap>(p, "ready", (s) => s.decompName === "main" && s.live === "live");
  const programs = async (projectId = "default") =>
    (await rpc<{ programs?: Prog[] }>(base, "ProjectService/ListPrograms", { projectId })).programs ?? [];
  const openDialog = async (p: Page) => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+o");
    await p.locator("[data-testid=open-root]").waitFor();
  };
  const archive = path.join(c.tmp, "default.rkproj");

  await check("project tree: a new folder, a program dragged into it, renamed with F2, the tree after a reload", async () => {
    const p = await open(base);
    await ready(p);
    await openDialog(p);
    // The root, then the program: no folders yet.
    await p.locator("[data-testid=open-root]").click();
    await p.click("[data-testid=open-new-folder]");
    await c.answer(p, "libs");
    const folder = p.locator("[data-testid=open-folder]", { hasText: "libs" });
    await folder.waitFor();
    // Drag the test program onto it.
    const prog = p.locator("[data-testid=open-row]", { hasText: /^prog/ }).first();
    await prog.dragTo(folder);
    await p.waitForFunction(() => {
      const row = [...document.querySelectorAll<HTMLElement>("[data-testid=open-row]")].find((r) => r.textContent?.startsWith("prog"));
      return row?.dataset.parent && row.getAttribute("aria-level") === "2";  // folder 1, in it 2
    });
    assert((await programs()).find((x) => x.name === "prog")?.folderPath === "/libs", `moved: ${JSON.stringify(await programs())}`);
    // Rename the folder from the keyboard: pick it, F2.
    await folder.click();  // a click picks it
    await p.keyboard.press("F2");
    await c.answer(p, "third-party");
    await p.locator("[data-testid=open-folder]", { hasText: "third-party" }).waitFor();
    assert((await programs()).find((x) => x.name === "prog")?.folderPath === "/third-party", "renamed");
    // After a reload: the same tree (expanded with →).
    await p.reload();
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    await ready(p);
    await openDialog(p);
    const renamed = p.locator("[data-testid=open-folder]", { hasText: "third-party" });
    await renamed.waitFor();
    if ((await renamed.getAttribute("aria-expanded")) === "false") {
      await renamed.dblclick();
    }
    await p.waitForFunction(() =>
      [...document.querySelectorAll<HTMLElement>("[data-testid=open-row]")].some((r) => r.textContent?.startsWith("prog") && r.getAttribute("aria-level") === "2"));
    assert((await p.getAttribute("[data-testid=open-list]", "role")) === "tree", "a tree");
    await p.context().close();
  });

  await check("project archive: File → Export project saves a .rkproj, Import project brings it into a new project", async () => {
    const p = await open(base);
    await ready(p);
    // Export: the whole project.
    await p.click("[data-testid=file-menu]");
    await p.click("[data-testid=file-export-project]");
    await p.locator("[data-testid=export-project-dialog]").waitFor();
    await p.check("[data-testid=export-scope-project]");
    const [download] = await Promise.all([p.waitForEvent("download"), p.click("[data-testid=export-go]")]);
    assert(download.suggestedFilename() === "default.rkproj", `file name ${download.suggestedFilename()}`);
    await download.saveAs(archive);
    const bytes = readFileSync(archive);
    assert(bytes.length > 1000 && bytes[0] === 0x1f && bytes[1] === 0x8b, `a gzip file, ${bytes.length} bytes`);
    // Import it into a new project.
    await p.click("[data-testid=file-menu]");
    const [chooser] = await Promise.all([p.waitForEvent("filechooser"), p.click("[data-testid=file-import-project]")]);
    await chooser.setFiles(archive);
    const dialog = p.locator("[data-testid=import-project-dialog]");
    await dialog.locator("[data-testid=import-program]", { hasText: "prog" }).first().waitFor();
    assert((await dialog.locator("[data-testid=import-binary]").first().textContent()) === "in the archive", "binaries in the archive");
    await p.fill("[data-testid=import-name]", "e2e-imported");
    await Promise.all([p.waitForEvent("load"), p.click("[data-testid=import-go]")]);
    await p.waitForSelector("body[data-ready='1']", { timeout: 30000 });
    assert(new URL(p.url()).searchParams.get("program")?.startsWith("e2e-imported/"), `opened ${p.url()}`);
    await c.until<Snap & { functionCount: number }>(p, "the imported program", (s) => s.live === "live" && s.functionCount > 0);
    const copy = await programs("e2e-imported");
    assert(copy.some((x) => x.name === "prog" && x.folderPath === "/third-party"), `imported: ${JSON.stringify(copy)}`);
    await p.context().close();
    // Back to the root, so the checks after these find prog where they did.
    const id = (await programs()).find((x) => x.name === "prog")?.programId;
    await rpc(base, "ProjectService/MoveToFolder", { projectId: "default", folderId: "", programIds: [id], provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
  });
}
