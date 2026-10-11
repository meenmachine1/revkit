// End-to-end checks for the Memory Map view (docs/memory-map.md): a raw ARM
// firmware (hand-assembled, as src/backend/tests/memory_map_test.cc) whose
// code reads RAM, a constant in another file and calls a bootloader in a
// third. Through the view: the image's block, Ctrl+Shift+M, adding RAM (the
// decompiler's read becomes DAT_20000000), an overlap refused in the form
// (it stays open), a bootloader's bytes chosen on the daemon's host (its
// function appears), a block made volatile, a removal undone with Ctrl+Z,
// a second page following live, and Set image base moving the program (with a
// rename) and Ctrl+Z moving it back. run.ts calls memoryChecks().

import type { Page } from "playwright";
import { writeFileSync } from "node:fs";
import path from "node:path";

export interface MemoryContext {
  base: string;
  /** A directory under the daemon's --browse-root. */
  browseDir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  /** A new page at `${base}/?<query>`, once the app is ready. */
  page: (query: string) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
}

function words(...ws: number[]): Buffer {
  const b = Buffer.alloc(ws.length * 4);
  ws.forEach((w, i) => b.writeUInt32LE(w >>> 0, 4 * i));
  return b;
}

const FIRMWARE = Buffer.concat([
  words(0xea000006, ...Array(7).fill(0xeafffffe)),
  words(0xe52de004, 0xeb000005, 0xeb000008, 0xeb03fff3, 0xe49df004, 0, 0, 0),
  words(0xe59f0004, 0xe5900000, 0xe12fff1e, 0x20000000),
  words(0xe59f0004, 0xe5900000, 0xe12fff1e, 0x00080000),
  Buffer.alloc(0x100 - 0x60),
]);
const BOOT = words(0xe3a00007, 0xe12fff1e); // mov r0, #7; bx lr

type Row = { name: string; start: string; perms: string; initialized: boolean; volatile: boolean; source: string; file: string; regionId: string; by: string; rejected: string };
const rows = (p: Page): Promise<Row[]> => p.evaluate("window.__revkit.app.memmap.rows()") as Promise<Row[]>;

async function untilRows(p: Page, what: string, pred: (r: Row[]) => boolean, ms = 15000): Promise<Row[]> {
  const end = Date.now() + ms;
  let r = await rows(p);
  while (!pred(r)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; rows: ${JSON.stringify(r)}`);
    await p.waitForTimeout(50);
    r = await rows(p);
  }
  return r;
}

let programId = "";

async function decompiled(p: Page, base: string, rpc: MemoryContext["rpc"], at: number): Promise<string> {
  void p;
  const r = await rpc<{ function?: { text?: string } }>(base, "QueryService/Decompile", { programId, function: { offset: String(at) }, options: { includeText: true } });
  return r.function?.text ?? "";
}

async function fill(p: Page, testid: string, value: string) {
  await p.fill(`[data-testid=region-form] [data-testid=${testid}]`, value);
}

export async function memoryChecks(c: MemoryContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  writeFileSync(path.join(c.browseDir, "boot.bin"), BOOT);
  // Its own name: the run imports other firmware too (its id says which).
  const imported = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", {
    projectId: "default", name: "memmap-fw.bin", content: FIRMWARE.toString("base64"),
    options: { format: "raw", languageId: "ARM:LE:32:v4t", rawPermissions: "r-x" },
  });
  programId = imported.program.programId;
  const q = encodeURIComponent(programId);
  let a!: Page;
  let b!: Page;

  await check("memory map: the image's block, from the palette's key (Ctrl+Shift+M)", async () => {
    a = await c.page(`program=${q}&user=e2e&theme=dark#40`);
    b = await c.page(`program=${q}&user=e2e&theme=light#40`);
    await a.keyboard.press("Control+Shift+M");
    await a.waitForSelector("#memory:not([hidden]) [data-testid=mem-row]");
    const r = await untilRows(a, "the image block", (r) => r.length === 1);
    assert(r[0].name === "ram" && r[0].start === "0" && r[0].perms === "r-x" && r[0].source === "image" && r[0].by === "loader", `block: ${JSON.stringify(r[0])}`);
    assert((await a.getAttribute("[data-testid=mem-add]", "disabled")) === null, "Add region is enabled (feature memory-map)");
  });

  await check("memory map: add RAM; read_ram's load becomes DAT_20000000; the second page follows", async () => {
    assert(!(await decompiled(a, base, rpc, 0x40)).includes("DAT_20000000"), "no DAT_ before");
    await a.click("[data-testid=mem-add]");
    await a.waitForSelector("[data-testid=region-form]");
    await a.selectOption("[data-testid=rf-kind]", "ram");
    await fill(a, "rf-name", "sram");
    await fill(a, "rf-start", "20000000");
    await fill(a, "rf-size", "1000");
    await a.click("[data-testid=rf-submit]");
    await a.waitForSelector("[data-testid=region-form]", { state: "detached" });
    const r = await untilRows(a, "sram", (r) => r.some((x) => x.name === "sram"));
    const sram = r.find((x) => x.name === "sram")!;
    assert(sram.regionId && !sram.initialized && sram.perms === "rw-" && sram.by === "user:e2e", `sram: ${JSON.stringify(sram)}`);
    assert((await decompiled(a, base, rpc, 0x40)).includes("DAT_20000000"), "the decompiler sees the RAM");
    await b.keyboard.press("Control+Shift+M");
    await untilRows(b, "sram in page B", (r) => r.some((x) => x.name === "sram"));
  });

  await check("memory map: an overlapping region is refused in the form, which stays open", async () => {
    await a.click("[data-testid=mem-add]");
    await fill(a, "rf-name", "low");
    await fill(a, "rf-start", "80");
    await fill(a, "rf-size", "100");
    await a.click("[data-testid=rf-submit]");
    await a.waitForFunction(() => /overlaps block ram \[0x0, 0xff\]/.test(document.querySelector("[data-testid=rf-error]")?.textContent ?? ""));
    if (process.env.RK_SHOTS) await a.screenshot({ path: path.join(process.env.RK_SHOTS, "memory-map-form.png") });
    await a.click("[data-testid=rf-cancel]");
    await a.waitForSelector("[data-testid=region-form]", { state: "detached" });
  });

  await check("memory map: a bootloader's bytes from the daemon's host; its function appears", async () => {
    await a.click("[data-testid=mem-add]");
    await a.selectOption("[data-testid=rf-kind]", "file");
    await a.click("[data-testid=rf-host]");
    await a.waitForSelector("[data-testid=host-browser]");
    await a.locator("[data-testid=host-entry]", { hasText: /^boot\.bin/ }).click();
    await a.waitForSelector("[data-testid=host-browser]", { state: "detached" });
    assert((await a.textContent("[data-testid=rf-file]"))?.includes("boot.bin"), "the file is chosen");
    await fill(a, "rf-start", "100000");
    await a.uncheck("[data-testid=rf-write]");
    await a.check("[data-testid=rf-exec]");
    await a.click("[data-testid=rf-submit]");
    await a.waitForSelector("[data-testid=region-form]", { state: "detached" });
    const r = await untilRows(a, "boot", (r) => r.some((x) => x.name === "boot"));
    const boot = r.find((x) => x.name === "boot")!;
    assert(boot.source === "file" && boot.file === "boot.bin" && boot.perms === "r-x", `boot: ${JSON.stringify(boot)}`);
    assert((await decompiled(a, base, rpc, 0x100000)).includes("return 7;"), "the bootloader decompiles");
  });

  await check("memory map: edit a region (volatile), revert an image block's edit", async () => {
    await a.locator("[data-testid=mem-row][data-name=sram] [data-testid=mem-edit]").click();
    await a.waitForSelector("[data-testid=region-form]");
    await a.check("[data-testid=rf-volatile]");
    await a.click("[data-testid=rf-submit]");
    await untilRows(a, "sram volatile", (r) => r.some((x) => x.name === "sram" && x.volatile));
    await a.locator("[data-testid=mem-row][data-name=ram] [data-testid=mem-edit]").click();
    assert(await a.isDisabled("[data-testid=region-form] [data-testid=rf-start]"), "an image block's start is fixed");
    await fill(a, "rf-name", "flash");
    await a.click("[data-testid=rf-submit]");
    await untilRows(a, "flash", (r) => r.some((x) => x.name === "flash"));
    await a.locator("[data-testid=mem-row][data-name=flash] [data-testid=mem-revert]").click();
    await untilRows(a, "ram again", (r) => r.some((x) => x.name === "ram"));
  });

  await check("memory map: remove a region, Ctrl+Z brings it back here and in page B", async () => {
    await a.locator("[data-testid=mem-row][data-name=boot] [data-testid=mem-remove]").click();
    await untilRows(a, "boot removed", (r) => !r.some((x) => x.name === "boot"));
    await untilRows(b, "boot removed in page B", (r) => !r.some((x) => x.name === "boot"));
    await a.focus("[data-testid=mem-table]");
    await a.keyboard.press("Control+z");
    await untilRows(a, "boot back", (r) => r.some((x) => x.name === "boot"));
    await untilRows(b, "boot back in page B", (r) => r.some((x) => x.name === "boot"));
    if (process.env.RK_SHOTS) await a.screenshot({ path: path.join(process.env.RK_SHOTS, "memory-map.png") });
  });

  await check("memory map: Set image base moves the program with its work; Ctrl+Z moves it back (feature rebase)", async () => {
    type Sym = { symbols?: { name: string; address: { offset: string } }[] };
    const at = async (name: string) =>
      BigInt((await rpc<Sym>(base, "QueryService/ListSymbols", { programId, nameEquals: name })).symbols?.[0]?.address.offset ?? "-1");
    await rpc(base, "AssertionService/AppendAssertions", {
      programId, provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
      assertions: [{ body: { rename: { target: { address: { offset: "64" } }, name: "read_ram" } } }],
    });
    assert((await at("read_ram")) === 0x40n, "renamed at 0x40");
    await a.click("[data-testid=mem-rebase]");
    await a.waitForSelector("[data-testid=ask] .ask-input");
    assert((await a.inputValue("[data-testid=ask] .ask-input")) === "0", "the dialog shows the current base");
    await a.fill("[data-testid=ask] .ask-input", "8000");
    await a.keyboard.press("Enter");
    await a.waitForSelector("[data-testid=ask]", { state: "detached" });
    await untilRows(a, "the program at 0x8000", (r) =>
      r.some((x) => x.name === "ram" && x.start === "8000") && r.some((x) => x.name === "sram" && x.start === "20008000") &&
      r.some((x) => x.name === "boot" && x.start === "108000"));
    await untilRows(b, "page B follows", (r) => r.some((x) => x.name === "ram" && x.start === "8000"));
    assert((await at("read_ram")) === 0x8040n, "the rename moved with the code");
    const summary = await rpc<{ summary: { imageBase: { offset?: string }; importImageBase: { offset?: string } } }>(
      base, "ProjectService/GetProgramSummary", { programId });
    assert(summary.summary.imageBase.offset === "32768" && (summary.summary.importImageBase.offset ?? "0") === "0", JSON.stringify(summary));
    await a.focus("[data-testid=mem-table]");
    await a.keyboard.press("Control+z");
    await untilRows(a, "back at 0", (r) => r.some((x) => x.name === "ram" && x.start === "0"));
    await untilRows(b, "page B back at 0", (r) => r.some((x) => x.name === "ram" && x.start === "0"));
    assert((await at("read_ram")) === 0x40n, "the rename moved back");
    await a.context().close();
    await b.context().close();
  });
}
