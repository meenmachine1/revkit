// End-to-end checks for project-wide types and the Archives section
// (docs/types.md#project-types, feature "project-types"): two programs
// built with the same struct; "Move to project" in the Types window makes
// the first program's the project's, an edit at project scope reaches the
// second program's types, "Copy to program" gives the first its own copy
// again, and the Archives section switches Ghidra's archive off and on.
// run.ts calls projectTypesChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import path from "node:path";

export interface ProjectTypesContext {
  base: string;
  dir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  page: (query: string) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
}

interface Shown {
  shown: { name: string; hash: string; project?: boolean } | null;
  archives: { name: string; enabled: boolean; applies: boolean; kind: number; functions: number }[] | null;
}

async function until(p: Page, what: string, pred: (v: Shown) => boolean, ms = 15000): Promise<Shown> {
  const end = Date.now() + ms;
  let v = (await p.evaluate("window.__revkit.app.types.describe()")) as Shown;
  while (!pred(v)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify(v).slice(0, 1500)}`);
    await p.waitForTimeout(50);
    v = (await p.evaluate("window.__revkit.app.types.describe()")) as Shown;
  }
  return v;
}

const SOURCES = {
  pt_first: "struct point { int x; int y; };\nstruct point origin = {1, 2};\n__attribute__((noinline)) int gety(struct point *p) { return p->y; }\nint main(void) { return gety(&origin); }\n",
  pt_second: "struct point { int x; int y; };\nstruct point corner = {3, 4};\n__attribute__((noinline)) int sumxy(struct point *p) { return p->x + p->y * 3; }\nint main(void) { return sumxy(&corner); }\n",
};

export async function projectTypesChecks(c: ProjectTypesContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const cc = process.env.CC ?? "cc";
  const ids: string[] = [];
  for (const [name, src] of Object.entries(SOURCES)) {
    const file = path.join(c.dir, `${name}.c`), exe = path.join(c.dir, name);
    writeFileSync(file, src);
    execFileSync(cc, ["-g", "-O1", "-fno-inline", "-o", exe, file]);
    const r = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", {
      projectId: "default", path: exe, name, provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
    });
    ids.push(r.program.programId);
  }
  const [first, second] = ids;
  const p = await c.page(`program=${encodeURIComponent(first)}&user=e2e&theme=dark`);
  const point = async (program: string, source = "") => {
    const r = await rpc<{ types?: { name: string; hash: string; bound?: boolean; project?: boolean }[] }>(base, "QueryService/FindTypes",
      { programId: program, nameContains: "point", ...(source ? { sources: [source] } : {}) });
    return (r.types ?? []).filter((t) => t.name === "point");
  };

  await check("project types: Move to project in the Types window; an edit at project scope reaches the other program; Copy to program", async () => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+7");
    await p.evaluate("window.__revkit.app.types.showNamed('point')");
    await until(p, "struct point shown", (v) => v.shown?.name === "point");
    await p.click("[data-testid=type-to-project]");
    await until(p, "the project's struct point", (v) => v.shown?.name === "point" && v.shown.project === true);
    const inProject = await point(first, "TYPE_SOURCE_PROJECT");
    assert(inProject.length === 1, `the project's: ${JSON.stringify(inProject)}`);

    // An edit at project scope: struct point with renamed fields, bound to its name for every program.
    const old = (await rpc<{ types: { composite?: { fields: { typeHash: string }[] } }[] }>(base, "QueryService/GetTypes", { programId: first, hashes: [inProject[0].hash] })).types[0];
    const intHash = old.composite!.fields[0].typeHash;
    const edit = await rpc<{ snapshot: { revision: string }; assertions: { key: { sub: string; project?: boolean } }[] }>(base, "AssertionService/AppendAssertions", {
      programId: first, projectScope: true, provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
      assertions: [
        { body: { defineType: { type: { kind: "TYPE_KIND_STRUCT", name: "point", size: "8", fields: [
          { name: "px", offset: "0", type: { hash: intHash } }, { name: "py", offset: "4", type: { hash: intHash } }] } } } },
        { body: { bindTypeName: { type: { assertionIndex: 0 } } } },
      ],
    });
    const edited = edit.assertions[0].key.sub;
    assert(edit.assertions[0].key.project === true, `a project key: ${JSON.stringify(edit.assertions[0].key)}`);
    const inSecond = await point(second);
    assert(inSecond.some((t) => t.hash === edited && t.bound), `the second program's struct point is the edited one: ${JSON.stringify(inSecond)}`);
    // The page sees the edit (its revision), then shows the edited definition.
    const rev = Number(edit.snapshot.revision);
    await p.waitForFunction((r) => Number(document.body.dataset.revision) >= r, rev, { timeout: 15000 });

    // Copy to program: the first program's own copy, no longer the project's.
    await p.evaluate("window.__revkit.app.types.showNamed('point')");
    await until(p, "the edited project struct point shown", (v) => v.shown?.hash === edited && v.shown.project === true);
    try {
      await p.waitForSelector("[data-testid=type-to-program]", { timeout: 10000 });
    } catch {
      const state = await p.evaluate("JSON.stringify(window.__revkit.app.types.describe().shown)");
      const detail = await p.evaluate(`document.querySelector("[data-testid=types-detail]")?.textContent?.slice(0, 600)`);
      throw new Error(`no Copy to program: ${state} ${detail}`);
    }
    await p.click("[data-testid=type-to-program]");
    await until(p, "the program's copy", (v) => v.shown?.name === "point" && !v.shown.project);
  });

  await check("archives: the Archives section lists the project's type archives and switches Ghidra's off and on", async () => {
    await p.click("[data-testid=types-archives-toggle]");
    let s = await until(p, "the archives listed", (v) => (v.archives ?? []).some((a) => a.name === "ghidra"));
    const libc = s.archives!.find((a) => a.name === "libc-lp64");
    if (libc) assert(libc.enabled && libc.applies && libc.functions > 1000, `libc-lp64: ${JSON.stringify(libc)}`);
    await p.click("[data-testid=archive-enabled-ghidra]");
    s = await until(p, "ghidra off", (v) => (v.archives ?? []).some((a) => a.name === "ghidra" && !a.enabled));
    const listed = await rpc<{ archives: { name: string; enabled?: boolean }[] }>(base, "TypeService/ListTypeArchives", { programId: second });
    assert(listed.archives.some((a) => a.name === "ghidra" && !a.enabled), `off for every program: ${JSON.stringify(listed.archives.map((a) => [a.name, a.enabled]))}`);
    await p.click("[data-testid=archive-enabled-ghidra]");
    await until(p, "ghidra on", (v) => (v.archives ?? []).some((a) => a.name === "ghidra" && a.enabled));
  });
}
