// End-to-end checks for the Nintendo DS support (feature "nds"; docs/ui.md
// "Nintendo DS"): the synthetic ds-decomp project (tests/data/nds/
// make_fixture.py, built here with clang and ld.lld) imported through File
// → Import ds-decomp project… and the host browser; the overlay's listing
// names main's functions and a click opens main there; the decompiler's
// Copy as decomp scratch; File → Export ds-decomp symbols… shows a rename as
// a diff and writes it; File → Apply decomp knowledge base… on game 3 (a
// rebuild, as dsd init leaves it) lists the matches by kind, shows a near match and applies the names.
// Skipped without clang, ld.lld or python3. run.ts
// calls ndsChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";

export interface NdsContext {
  base: string;
  dir: string;
  root: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  page: (query: string) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
}

type Snap = { decompName: string | null };
const snap = (p: Page) => p.evaluate("window.__revkit.app.snapshot()") as Promise<Snap>;

async function until(p: Page, what: string, pred: (s: Snap) => boolean, ms = 20000) {
  const end = Date.now() + ms;
  let s = await snap(p);
  while (!pred(s)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify(s).slice(0, 600)}`);
    await p.waitForTimeout(50);
    s = await snap(p);
  }
  return s;
}

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

export async function ndsChecks(c: NdsContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const out = path.join(c.dir, "nds");
  try {
    execFileSync("python3", ["-I", path.join(c.root, "tests/data/nds/make_fixture.py"), "--clang", "clang", "--lld", "ld.lld", "--out", out], { stdio: "ignore" });
  } catch {
    c.log("  (nds: no clang, ld.lld or python3, skipped)");
    return;
  }
  const config = path.join(out, "dsd/config/arm9/config.yaml");
  // The checks before these import programs of their own: open the default
  // one by name (with more than one and no program=, the page asks which and
  // never becomes ready; ui_e2e part B3 failed so).
  const p = await c.page("program=default%2Fprog&user=e2e&theme=dark");

  await check("nds: File → Import ds-decomp project… makes the module programs; the overlay decompiles with main's names and prototypes", async () => {
    const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", { client: "e2e" });
    assert(info.features?.includes("nds"), `features: ${JSON.stringify(info.features)}`);
    await p.click("[data-testid=file-menu]");
    await p.click("[data-testid=file-import-dsd]");
    // The host browser: down the folders to the config, by each entry's path.
    await p.waitForSelector("[data-testid=host-browser]");
    for (let i = 0; i < 20; i++) {
      await p.waitForSelector("[data-testid=host-entry]");
      const paths = await p.$$eval("[data-testid=host-entry]", (els) => els.map((e) => (e as HTMLElement).dataset.path ?? ""));
      const next = paths.find((x) => x === config) ?? paths.find((x) => config.startsWith(x.endsWith("/") ? x : x + "/"));
      assert(next, `no way to ${config} from ${JSON.stringify(paths)}`);
      await p.click(`[data-testid=host-entry][data-path="${next}"]`);
      if (next === config) break;
      await p.waitForFunction((prev) => !document.querySelector(`[data-testid=host-entry][data-path="${prev}"]`), next);
    }
    await p.waitForSelector("[data-testid=nds-import-summary]", { timeout: 60000 });
    const summary = (await p.textContent("[data-testid=nds-import-summary]")) ?? "";
    assert(summary.startsWith("6 modules imported"), `summary: ${summary}`);
    await shot(p, "nds-import");
    await p.click("[data-testid=nds-open-ov000]");
    await p.waitForURL(/program=/, { timeout: 20000 });
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    // GameOverScene::Update calls SceneBase::Update in main.
    const expect = JSON.parse(readFileSync(path.join(out, "expect.json"), "utf8"));
    const upd = expect.modules.ov000.symbols.find((s: { name: string }) => s.name === "_ZN13GameOverScene6UpdateEv").addr as number;
    const u = new URL(p.url());
    u.hash = "#" + upd.toString(16);
    await p.goto(u.toString());
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    await until(p, "GameOverScene::Update decompiled", (s) => s.decompName === "GameOverScene::Update");
    const text = (await p.textContent("#cm .cm-content")) ?? "";
    assert(text.includes("SceneBase::Update((SceneBase *)this)"), `decompiled: ${text.slice(0, 400)}`);
    await shot(p, "nds-overlay");
  });

  await check("nds: Copy as decomp scratch puts the PROBE line, the declarations and the C on the clipboard", async () => {
    await p.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    const tok = p.locator("#cm .cm-content span.k-fn").first();
    await tok.waitFor();
    await tok.click({ button: "right" });
    await p.click("[data-testid=ctx-decomp-scratch]");
    await p.waitForFunction(() => document.getElementById("toasts")?.textContent?.includes("as a decomp scratch"), undefined, { timeout: 30000 });
    const clip = (await p.evaluate("navigator.clipboard.readText()")) as string;
    assert(clip.startsWith("// PROBE: _ZN13GameOverScene6UpdateEv ov000 0x"), `clipboard: ${clip.slice(0, 200)}`);
    assert(clip.includes("/* Callees */") && clip.includes("SceneBase::Update(SceneBase *this);"), `clipboard: ${clip.slice(0, 1200)}`);
  });

  await check("nds: File → Export ds-decomp symbols… shows a rename in main as a diff and writes symbols.txt", async () => {
    const programs = await rpc<{ programs: { programId: string; name: string }[] }>(base, "ProjectService/ListPrograms", { projectId: "default" });
    const main = programs.programs.find((x) => x.name === "main");
    assert(main, `programs: ${JSON.stringify(programs.programs.map((x) => x.name))}`);
    const clamp = expect_addr(out, "main", String(JSON.parse(readFileSync(path.join(out, "expect.json"), "utf8")).placeholder));
    await rpc(base, "AssertionService/AppendAssertions", {
      programId: main.programId, provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
      assertions: [{ body: { rename: { target: { address: { offset: String(clamp) } }, name: "Clamp" } } }],
    });
    await p.click("[data-testid=file-menu]");
    await p.click("[data-testid=file-export-dsd]");
    await p.waitForSelector("[data-testid=nds-export-diff]", { timeout: 30000 });
    const diff = (await p.textContent("[data-testid=nds-export-diff]")) ?? "";
    assert(diff.includes("+Clamp kind:function(arm,"), `diff: ${diff.slice(0, 800)}`);
    await shot(p, "nds-export");
    await p.click("[data-testid=nds-export-write]");
    await p.waitForFunction(() => document.querySelector("[data-testid=nds-export-summary]")?.textContent?.includes("1 file written"), undefined, { timeout: 20000 });
    const written = readFileSync(path.join(out, "dsd/config/arm9/symbols.txt"), "utf8");
    assert(written.includes("Clamp kind:function(arm,"), "symbols.txt not written");
  });

  await check("nds: File → Apply decomp knowledge base… lists game 3's matches by kind, shows a near match's diff and applies the names", async () => {
    // The finished game (the dsd project imported above) into a KB, game 3 imported beside it.
    const kb = path.join(out, "kb");
    const programs = await rpc<{ programs: { programId: string; name: string }[] }>(base, "ProjectService/ListPrograms", { projectId: "default" });
    const modules = programs.programs.filter((x) => ["main", "itcm", "dtcm", "ov000", "ov001"].includes(x.name)).map((x) => x.programId);
    assert(modules.length === 5, `programs: ${JSON.stringify(programs.programs.map((x) => x.name))}`);
    const built = await rpc<{ functions?: number }>(base, "ProjectService/BuildDecompKb", { projectId: "default", kbPath: kb, programIds: modules, game: "game1", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
    assert((built.functions ?? 0) >= 15, `built: ${JSON.stringify(built)}`);
    const g3 = await rpc<{ modules: { module: string; program?: { programId: string } }[] }>(base, "ProjectService/ImportDsdProject", { projectId: "default", configPath: path.join(out, "game3/config/arm9/config.yaml"), folderName: "game3", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
    const main3 = g3.modules.find((m) => m.module === "main")?.program?.programId;
    assert(main3, `game 3: ${JSON.stringify(g3).slice(0, 400)}`);
    const q = await c.page(`program=${encodeURIComponent(main3)}&user=e2e&theme=dark`);
    await q.click("[data-testid=file-menu]");
    await q.click("[data-testid=file-apply-decomp-kb]");
    await q.waitForSelector("[data-testid=host-browser]");
    for (let i = 0; i < 20; i++) {
      // The path shows once the folder's listing has loaded (or an error does).
      await q.waitForFunction(() => {
        const list = document.querySelector("[data-testid=host-list]")?.textContent ?? "";
        const path = document.querySelector("[data-testid=host-browser] .browse-path")?.textContent?.trim();
        return (!!path && !list.startsWith("Loading")) || list.startsWith("Can't browse");
      });
      const here = ((await q.textContent("[data-testid=host-browser] .browse-path")) ?? "").trim();
      if (here === kb) break;
      const paths = await q.$$eval("[data-testid=host-entry]", (els) => els.map((e) => (e as HTMLElement).dataset.path ?? ""));
      const next = paths.find((x) => x === kb) ?? paths.find((x) => kb.startsWith(x.endsWith("/") ? x : x + "/"));
      const listed = ((await q.textContent("[data-testid=host-list]")) ?? "").slice(0, 300);
      assert(next, `no way to ${kb} from ${here}: ${JSON.stringify(paths)} (${listed})`);
      await q.click(`[data-testid=host-entry][data-path="${next}"]`);
      await q.waitForFunction((want) => document.querySelector("[data-testid=host-browser] .browse-path")?.textContent?.trim() === want, next);
    }
    await q.click("[data-testid=host-use-folder]");
    await q.waitForSelector("[data-testid=kb-summary]", { timeout: 120000 });
    const summary = (await q.textContent("[data-testid=kb-summary]")) ?? "";
    assert(/[1-9]\d* exact/.test(summary), `summary: ${summary}`);
    await q.waitForSelector("[data-testid=kb-group-exact]");
    await q.waitForSelector("[data-testid=kb-group-near] [data-testid=kb-match-near]", { timeout: 10000 });
    await q.click("[data-testid=kb-group-near] [data-testid=kb-match-near]");
    const detail = (await q.textContent("[data-testid=kb-detail]")) ?? "";
    assert(detail.includes("similarity") && detail.includes("Instructions, the KB function's"), `detail: ${detail.slice(0, 600)}`);
    await shot(q, "nds-decomp-kb");
    await q.click("[data-testid=kb-apply]");
    await q.waitForFunction(() => document.getElementById("toasts")?.textContent?.includes("from the knowledge base"), undefined, { timeout: 60000 });
    const fns = await rpc<{ functions: { name: string }[] }>(base, "QueryService/ListFunctions", { programId: main3 });
    assert(fns.functions.some((f) => f.name === "SceneBase::Update"), `functions: ${JSON.stringify(fns.functions.map((f) => f.name))}`);
    await q.context().close();
  });
  await p.context().close();
}

function expect_addr(out: string, module: string, name: string): number {
  const e = JSON.parse(readFileSync(path.join(out, "expect.json"), "utf8"));
  const s = e.modules[module].symbols.find((x: { name: string }) => x.name === name);
  if (!s) throw new Error(`no ${name} in ${module}`);
  return s.addr as number;
}
