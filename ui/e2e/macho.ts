// End-to-end checks for Mach-O (docs/macho.md, feature "macho"):
// tests/data/macho's fixtures built with clang and ld64.lld. A universal
// file imports its arm64 slice; the Open dialog's details say which slice
// it is, and Import x86_64 brings in the other one from the stored file.
// Skipped without clang, ld64.lld or the llvm tools. run.ts calls
// machoChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export interface MachoContext {
  base: string;
  dir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  page: (query: string) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
}

function which(...names: string[]): string | null {
  for (const name of names) {
    try {
      const p = execFileSync("sh", ["-c", `command -v ${name}`]).toString().trim();
      if (p) return p;
    } catch {
      /* the next */
    }
  }
  return null;
}

export async function machoChecks(c: MachoContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const tools = [which("clang"), which("ld64.lld", "ld64.lld-18"), which("llvm-lipo", "llvm-lipo-18"), which("llvm-nm", "llvm-nm-18"),
    which("llvm-objdump", "llvm-objdump-18")];
  if (tools.some((t) => !t)) {
    c.log("  (Mach-O: no clang, ld64.lld or llvm tools, skipped)");
    return;
  }
  const fixture = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../tests/data/macho");
  const out = path.join(c.dir, "macho");
  fs.mkdirSync(out, { recursive: true });
  execFileSync("sh", [path.join(fixture, "build.sh"), ...(tools as string[]), out]);
  const prov = { kind: "PROVENANCE_KIND_USER", id: "e2e" };
  const imported = await rpc<{ program: { programId: string; machoSlice: string; machoSlices: string[] } }>(base, "ProjectService/ImportProgram", {
    projectId: "default", path: path.join(out, "hello-fat"), name: "hello-fat", provenance: prov,
  });
  assert(imported.program.machoSlice === "arm64", `default slice: ${JSON.stringify(imported.program)}`);
  const p = await c.page(`program=${encodeURIComponent(imported.program.programId)}&user=e2e&theme=dark`);

  await check("Mach-O: a universal file's slice in the Open dialog; Import x86_64 brings in the other slice", async () => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+o");
    await p.locator("[data-testid=open-row]", { hasText: /^hello-fat/ }).first().click();
    await p.waitForSelector("[data-testid=open-detail-slice]");
    const slice = await p.textContent("[data-testid=open-detail-slice]");
    assert(slice?.includes("arm64 (of x86_64, arm64)"), `slice detail: ${slice}`);
    assert((await p.textContent("[data-testid=open-detail-format]"))?.includes("Mach-O"), "format: Mach-O");
    await p.click("[data-testid=open-import-slice-x86_64]");
    const row = p.locator("[data-testid=open-row]", { hasText: "hello-fat-x86_64" }).first();
    await row.waitFor({ timeout: 60000 });
    await row.click();
    await p.waitForFunction(() => (document.querySelector("[data-testid=open-detail-language]")?.textContent ?? "").includes("x86:LE:64"), undefined, { timeout: 15000 });
    const other = await p.textContent("[data-testid=open-detail-slice]");
    assert(other?.includes("x86_64 (of x86_64, arm64)"), `x86_64 slice detail: ${other}`);
  });
  await p.context().close();
}
