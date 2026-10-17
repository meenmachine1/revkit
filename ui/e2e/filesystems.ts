// End-to-end checks for the file system browser (api_minor 48, feature
// "filesystems"; docs/filesystems.md): File → Open file system… from the
// daemon host, a gzip and a tar opened in place inside a zip, Info with the
// container path, a program imported and opened; then "Open as file
// system" in the Open dialog for an uploaded zip, and Import programs
// below… with its preview, cap and import (and the libraries they need,
// looked for in the zip). run.ts calls fileSystemChecks()
// with its helpers.

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import path from "node:path";

export interface FileSystemContext {
  base: string;
  exe: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  open: (base: string, query?: string, hash?: string, dpr?: number) => Promise<Page>;
  until: <T>(p: Page, what: string, pred: (s: T) => boolean, ms?: number) => Promise<T>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
}

interface Snap {
  decompName: string | null;
  live: string;
  functionCount: number;
}

type Prog = { programId: string; name: string; containerPath?: string };

// fw.zip beside the test program (the daemon's --browse-root): bin/prog (the
// test program), etc/motd, and pkg/data.tar.gz holding usr/bin/tool.
const MAKE = String.raw`
import io, sys, tarfile, zipfile
exe = open(sys.argv[1], 'rb').read()
tgz = io.BytesIO()
with tarfile.open(fileobj=tgz, mode='w:gz') as t:
    i = tarfile.TarInfo('usr/bin/tool'); i.size = len(exe); i.mode = 0o755; t.addfile(i, io.BytesIO(exe))
    r = tarfile.TarInfo('usr/share/readme'); r.size = 5; t.addfile(r, io.BytesIO(b'hello'))
with zipfile.ZipFile(sys.argv[2], 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('bin/prog', exe)
    z.writestr('etc/motd', 'welcome\n')
    z.writestr('pkg/data.tar.gz', tgz.getvalue())
`;

export async function fileSystemChecks(c: FileSystemContext) {
  const { base, check, open, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const zip = path.join(path.dirname(c.exe), "fw.zip");
  execFileSync(process.env.REVKIT_PYTHON || "python3", ["-I", "-c", MAKE, c.exe, zip]);
  const ready = (p: Page) => c.until<Snap>(p, "ready", (s) => s.decompName === "main" && s.live === "live");
  const programs = async () => (await rpc<{ programs?: Prog[] }>(base, "ProjectService/ListPrograms", { projectId: "default" })).programs ?? [];
  const row = (p: Page, name: string) => p.locator(`[data-testid=fs-row][data-name="${name}"]`).first();
  const at = (p: Page, path: string) => p.locator(`[data-testid=fs-row][data-path="${path}"]`);
  const expand = async (p: Page, path: string) => {
    await at(p, path).click();
    await p.keyboard.press("ArrowRight");
  };

  await check("file system browser: File → Open file system… from the daemon host; a gzip and a tar opened in place; Info; import a program and open it", async () => {
    const p = await open(base);
    await ready(p);
    await p.click("[data-testid=file-menu]");
    await p.click("[data-testid=file-open-filesystem]");
    await p.locator("[data-testid=choose] .palette-item", { hasText: "daemon host" }).click();
    await p.locator(`[data-testid=host-entry][data-path="${zip}"]`).click();
    const browser = p.locator("[data-testid=fs-browser]");
    await browser.waitFor();
    assert((await p.textContent("[data-testid=fs-desc]"))?.includes("zip archive"), "a zip");
    await row(p, "pkg").waitFor();
    assert((await p.locator("[data-testid=fs-row][aria-level='1']").count()) === 3, "bin, etc, pkg");
    await expand(p, "/pkg");
    await row(p, "data.tar.gz").waitFor();
    assert((await row(p, "data.tar.gz").textContent())?.includes("gzip"), "the gzip recognised by its magic");
    // Open as file system from the menu: the gzip's member, then the tar inside it.
    await row(p, "data.tar.gz").click({ button: "right" });
    await p.click("[data-testid=fs-menu-open]");
    await row(p, "data.tar").waitFor();
    const tar = "/pkg/data.tar.gz!/data.tar";
    await expand(p, tar);
    await at(p, `${tar}!/usr`).waitFor();
    await expand(p, `${tar}!/usr`);
    await at(p, `${tar}!/usr/bin`).waitFor();
    await expand(p, `${tar}!/usr/bin`);
    const tool = at(p, `${tar}!/usr/bin/tool`);
    await tool.waitFor();
    await p.waitForFunction(() => document.querySelector<HTMLElement>('[data-testid=fs-row][data-name="tool"]')?.dataset.kind === "elf");
    assert((await tool.getAttribute("aria-level")) === "6", `nested 6 deep in the tree: ${await tool.getAttribute("aria-level")}`);
    // Info: the container path.
    await tool.click({ button: "right" });
    await p.click("[data-testid=fs-menu-info]");
    await p.locator("[data-testid=fs-info-sha256]").waitFor();
    assert((await p.textContent("[data-testid=fs-info-path]")) === "zip://fw.zip!/pkg/data.tar.gz!/data.tar!/usr/bin/tool", "the container path");
    await p.click("[data-testid=fs-info-close]");
    // Import it and open it from the toast.
    await tool.click({ button: "right" });
    await p.click("[data-testid=fs-menu-import]");
    await p.waitForFunction(() => /Imported 1 program/.test(document.querySelector("[data-testid=fs-status]")?.textContent ?? ""), null, { timeout: 60000 });
    const imported = (await programs()).find((x) => x.containerPath === "zip://fw.zip!/pkg/data.tar.gz!/data.tar!/usr/bin/tool");
    assert(imported, `recorded its container path: ${JSON.stringify(await programs())}`);
    await Promise.all([p.waitForEvent("load"), p.locator(".toast button", { hasText: "Open tool" }).click()]);
    await p.waitForSelector("body[data-ready='1']", { timeout: 30000 });
    assert(new URL(p.url()).searchParams.get("program") === imported.programId, `opened ${p.url()}`);
    await c.until<Snap>(p, "the imported program", (s) => s.live === "live" && s.functionCount > 0);
    await p.context().close();
  });

  await check("file system browser: Open as file system in the Open dialog; Import programs below… previews, caps and imports", async () => {
    const p = await open(base);
    await ready(p);
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+o");
    await p.click("[data-testid=open-import-binary]");
    const [chooser] = await Promise.all([p.waitForEvent("filechooser"), p.click("[data-testid=open-import]")]);
    await chooser.setFiles(zip);
    await p.locator("[data-testid=open-as-filesystem]").waitFor();
    await p.click("[data-testid=open-as-filesystem]");
    await p.locator("[data-testid=fs-browser]").waitFor();
    await row(p, "bin").waitFor();
    await p.click("[data-testid=fs-batch]");
    const dialog = p.locator("[data-testid=fs-batch-dialog]");
    await dialog.waitFor();
    const imports = dialog.locator("[data-testid=fs-batch-item][data-action=import]");
    await p.waitForFunction(() => document.querySelectorAll("[data-testid=fs-batch-item][data-action=import]").length === 2);
    assert((await dialog.locator("[data-testid=fs-batch-item][data-action=skipped]").count()) >= 2, "motd and the readme left out");
    // A cap of one: one to import, the other over the cap.
    await p.fill("[data-testid=fs-batch-cap]", "1");
    await p.dispatchEvent("[data-testid=fs-batch-cap]", "change");
    await p.waitForFunction(() => document.querySelectorAll("[data-testid=fs-batch-item][data-action=import]").length === 1);
    assert((await p.textContent("[data-testid=fs-batch-status]"))?.includes("capped"), "capped");
    await p.fill("[data-testid=fs-batch-cap]", "100");
    await p.dispatchEvent("[data-testid=fs-batch-cap]", "change");
    await p.waitForFunction(() => document.querySelectorAll("[data-testid=fs-batch-item][data-action=import]").length === 2);
    assert((await imports.count()) === 2, "both programs");
    const before = (await programs()).length;
    // Their libraries from the zip (feature library-roots): libc isn't in it.
    await p.check("[data-testid=fs-batch-libraries]");
    await p.click("[data-testid=fs-batch-go]");
    await p.waitForFunction(() => /Imported 2 programs/.test(document.querySelector("[data-testid=fs-status]")?.textContent ?? ""), null, { timeout: 120000 });
    const said = (await p.textContent("[data-testid=fs-status]")) ?? "";
    assert(said.includes("not in the file system: libc.so.6"), `the libraries looked for in the zip: ${said}`);
    const after = await programs();
    assert(after.length === before + 2, `two more programs: ${after.length} after ${before}`);
    assert(after.some((x) => x.containerPath === "zip://fw.zip!/bin/prog"), `bin/prog's container path: ${JSON.stringify(after)}`);
    await p.context().close();
  });
}
