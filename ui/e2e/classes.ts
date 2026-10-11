// End-to-end checks for the class hierarchy (docs/pe.md, feature
// "msvc-rtti"): tests/data/msvc/classes.cc built for x86_64-pc-windows-msvc
// with clang in cl mode and lld-link, stripped. The Class hierarchy view
// lists the RTTI classes as a tree, shows a class's bases, derived classes
// and vftables, and a virtual function goes to its address, where the
// decompiler shows `this` typed; Load PDB applies the PDB and undoes.
// Skipped without clang or lld-link.
// run.ts calls classesChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

export interface ClassesContext {
  base: string;
  dir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  page: (query: string) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
}

interface Shown {
  rows: { name: string; depth: number }[];
  selected: string;
  bases: string[];
  derived: string[];
  vftables: { name: string; functions: string[] }[];
}

async function until<T>(p: Page, what: string, get: string, pred: (v: T) => boolean, ms = 15000): Promise<T> {
  const end = Date.now() + ms;
  let v = (await p.evaluate(get)) as T;
  while (!pred(v)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify(v).slice(0, 1500)}`);
    await p.waitForTimeout(50);
    v = (await p.evaluate(get)) as T;
  }
  return v;
}

function which(name: string): string | null {
  try {
    return execFileSync("sh", ["-c", `command -v ${name}`]).toString().trim() || null;
  } catch {
    return null;
  }
}

export async function classesChecks(c: ClassesContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const clang = which("clang");
  const lld = which("lld-link") ?? which("lld-link-18");
  if (!clang || !lld) {
    c.log("  (class hierarchy: no clang or lld-link, skipped)");
    return;
  }
  const fixture = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../tests/data/msvc");
  execFileSync("sh", [path.join(fixture, "build.sh"), clang, lld, c.dir, "x86_64"]);
  const exe = path.join(c.dir, "classes-x86_64-stripped.exe");
  const imported = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", {
    projectId: "default", path: exe, name: "classes", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
  });
  const programId = imported.program.programId;
  const p = await c.page(`program=${encodeURIComponent(programId)}&user=e2e&theme=dark`);
  const shown = "window.__revkit.app.classes.describe()";

  await check("class hierarchy: the RTTI classes as a tree, a class's bases, derived classes and vftables", async () => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+Shift+P");
    await p.waitForSelector("[data-testid=palette-input]");
    await p.fill("[data-testid=palette-input]", ">Show class hierarchy");
    await p.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").toLowerCase().startsWith("show class hierarchy"), undefined, { timeout: 10000 });
    await p.keyboard.press("Enter");
    const s = await until<Shown>(p, "the classes", shown, (v) => v.rows.some((r) => r.name === "geo::Square"));
    // Square under Rect (which shows under each of its bases).
    const sq = s.rows.find((r) => r.name === "geo::Square")!;
    const rect = s.rows.find((r) => r.name === "geo::Rect")!;
    assert(sq.depth === rect.depth + 1, `tree: ${JSON.stringify(s.rows)}`);
    await p.click(`#classes [data-cls="geo::Square"]`);
    const d = await until<Shown>(p, "Square's details", shown, (v) => v.selected === "geo::Square" && v.vftables.length === 2);
    assert(JSON.stringify(d.bases) === JSON.stringify(["geo::Rect", "geo::Shape", "geo::Named"]), `bases: ${JSON.stringify(d.bases)}`);
    assert(d.vftables[0].name === "geo::Square::vftable" && d.vftables[0].functions[1] === "geo::Square::vfunc1", `vftables: ${JSON.stringify(d.vftables)}`);
    // A base's link selects it; its derived classes list Square.
    await p.click(`#classes .classes-detail [data-goto-cls="geo::Rect"]`);
    await until<Shown>(p, "Rect selected", shown, (v) => v.selected === "geo::Rect" && v.derived.includes("geo::Square"));
    // A virtual function goes to its address; the decompiler types `this`.
    await p.click(`#classes .classes-detail .class-fn >> nth=1 >> [data-addr]`);
    await until<{ decompText: string }>(p, "Rect::vfunc1 decompiled", "window.__revkit.app.snapshot()", (v) => v.decompText.includes("geo::Rect::vfunc1(Rect *this"), 30000);
    // The filter.
    await p.fill("[data-testid=classes-filter]", "box");
    await until<Shown>(p, "the filter", shown, (v) => v.rows.length === 1 && v.rows[0].name === "geo::Box<int>");
  });
  await check("Load PDB: another build's PDB, forced, names the functions; Ctrl+Z takes it back", async () => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+Shift+P");
    await p.waitForSelector("[data-testid=palette-input]");
    await p.fill("[data-testid=palette-input]", ">Load PDB");
    await p.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").startsWith("Load PDB"), undefined, { timeout: 10000 });
    await p.keyboard.press("Enter");
    await p.waitForSelector("[data-testid=ask] .ask-input");
    await p.fill("[data-testid=ask] .ask-input", path.join(c.dir, "classes-x86_64.pdb"));
    // The stripped build has no CodeView record: refused without force.
    await p.keyboard.press("Enter");
    await p.waitForFunction(() => (document.querySelector("[data-testid=ask-error]")?.textContent ?? "").includes("force"), undefined, { timeout: 15000 });
    await p.check("[data-testid=ask-force]");
    await p.focus("[data-testid=ask] .ask-input");
    await p.keyboard.press("Enter");
    await p.waitForSelector("[data-testid=ask]", { state: "detached", timeout: 30000 });
    await until<{ decompText: string }>(p, "the PDB's name", "window.__revkit.app.snapshot()", (v) => v.decompText.includes("geo::Rect::area"), 30000);
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+z");
    await until<{ decompText: string }>(p, "the analysis's name again", "window.__revkit.app.snapshot()", (v) => v.decompText.includes("geo::Rect::vfunc1"), 30000);
  });
  await p.context().close();
}
