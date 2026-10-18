// End-to-end checks for structures from pointer use and from a listing
// selection (feature auto-struct; docs/types.md "Structures from pointer
// use", docs/ui.md "Auto create structure"): right-click second()'s
// parameter in the decompiler, Auto create structure previews field_0x4
// (p[1]), Apply types the parameter `struct astruct *` here and in page B
// (the body reads param_1->field_0x4),
// Auto fill in structure then has nothing to add, and Ctrl+Z undoes it; in
// the listing, Create structure from selection on printf's format string
// previews a char array field, Apply defines the struct there, Ctrl+Z
// gives the string back. Rename on a keyword says there is nothing to
// rename (never the function). run.ts calls autoStructChecks() with pages A and B
// open on default/prog.

import type { Page } from "playwright";
import path from "node:path";

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

interface Snap {
  address: string | null;
  decompName: string | null;
  decompText: string;
}

interface Row {
  address: string;
  kind: number;
  dataType: string;
  dataField: string;
}

export interface AutoStructContext {
  base: string;
  a: Page;
  b: Page;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  sym: (name: string) => Promise<bigint>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  go: (p: Page, addr: bigint | string) => Promise<unknown>;
}

const KIND = { Data: 2, Header: 4 };
const hx = (a: bigint) => a.toString(16);
const snap = (p: Page): Promise<Snap> => p.evaluate("window.__revkit.app.snapshot()") as Promise<Snap>;
const rows = (p: Page): Promise<Row[]> => p.evaluate("window.__revkit.app.visibleRows()") as Promise<Row[]>;

async function until(p: Page, what: string, pred: (s: Snap) => boolean, ms = 15000): Promise<Snap> {
  const end = Date.now() + ms;
  let s = await snap(p);
  while (!pred(s)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify({ ...s, decompText: s.decompText.slice(0, 500) })}`);
    await p.waitForTimeout(50);
    s = await snap(p);
  }
  return s;
}

async function untilRows(p: Page, what: string, pred: (r: Row[]) => boolean, ms = 15000): Promise<Row[]> {
  const end = Date.now() + ms;
  let r = await rows(p);
  while (!pred(r)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; rows: ${JSON.stringify(r.slice(0, 30).map((x) => [x.address, x.kind, x.dataType, x.dataField]))}`);
    await p.waitForTimeout(50);
    r = await rows(p);
  }
  return r;
}

/** Ctrl+Z, then waits until the undo button names the step before. */
async function undo(p: Page) {
  const before = await p.getAttribute("#undo", "title");
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+z");
  await p.waitForFunction((t) => document.querySelector("#undo")?.getAttribute("title") !== t, before);
}

/** Right-clicks a decompiler token (by coordinates: tokens have hover tooltips). */
async function rightClick(p: Page, text: string, cls: string) {
  const tok = p.locator(`#cm .cm-content span.${cls}`, { hasText: new RegExp(`^${text}$`) }).first();
  await tok.waitFor();
  const box = (await tok.boundingBox())!;
  await p.mouse.click(box.x + box.width / 2, box.y + box.height / 2, { button: "right" });
  await p.locator("[data-testid=menu]").waitFor({ timeout: 5000 });
}

async function answer(p: Page, text: string) {
  await p.waitForSelector("[data-testid=ask] .ask-input");
  await p.fill("[data-testid=ask] .ask-input", text);
  await p.keyboard.press("Enter");
  await p.waitForSelector("[data-testid=ask]", { state: "detached" });
}

interface FieldRow {
  name: string;
  offset: number;
  type: string;
}

/** A named struct's fields as the daemon has it now (FindTypes, then GetTypes). */
async function structFields(c: AutoStructContext, name: string): Promise<FieldRow[]> {
  type Def = { hash: string; name: string; display: string; superseded?: boolean; composite?: { fields: { name: string; offset?: string; typeHash: string }[] } };
  const found = await c.rpc<{ types?: Def[] }>(c.base, "QueryService/FindTypes", { programId: "default/prog", nameContains: name });
  const t = found.types?.find((x) => x.name === name && !x.superseded);
  if (!t) return [];
  const got = await c.rpc<{ types?: Def[] }>(c.base, "QueryService/GetTypes", { programId: "default/prog", hashes: [t.hash], includeDependencies: true });
  const def = got.types?.find((x) => x.hash === t.hash);
  return (def?.composite?.fields ?? []).map((f) => ({ name: f.name, offset: Number(f.offset ?? 0), type: got.types?.find((x) => x.hash === f.typeHash)?.display ?? "" }));
}

async function untilFields(c: AutoStructContext, name: string, what: string, pred: (f: FieldRow[]) => boolean, ms = 15000): Promise<FieldRow[]> {
  const end = Date.now() + ms;
  let f = await structFields(c, name);
  while (!pred(f)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; ${name}: ${JSON.stringify(f)}`);
    await new Promise((r) => setTimeout(r, 100));
    f = await structFields(c, name);
  }
  return f;
}

export async function autoStructChecks(c: AutoStructContext) {
  const { a, b, base, check, rpc, go } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  await check("auto-struct: the daemon reports feature auto-struct", async () => {
    const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", { client: "e2e" });
    assert(info.features?.includes("auto-struct"), `features: ${JSON.stringify(info.features)}`);
  });
  const second = await c.sym("second");

  await check("auto-struct: right-click a parameter, Auto create structure previews field_0x4, Apply types it here and in page B, Auto fill in has nothing to add, Rename Field and Retype Field on field_0x4; Ctrl+Z", async () => {
    await go(a, second);
    await go(b, second);
    const before = await until(a, "second decompiled", (s) => s.decompName === "second" && /\bparam_1\b/.test(s.decompText));
    assert(!before.decompText.includes("astruct"), "astruct before");
    await rightClick(a, "param_1", "k-pa");
    await a.locator("[data-testid=ctx-auto-fill]").waitFor();  // both actions on a variable
    await a.locator("[data-testid=ctx-auto-struct]").click();
    await a.locator("[data-testid=auto-struct]").waitFor();
    await a.waitForFunction(() => (document.querySelector("[data-testid=as-summary]")?.textContent ?? "") !== "Composing…" || !!document.querySelector("[data-testid=as-error]")?.textContent);
    const dialog = (await a.locator("[data-testid=auto-struct]").textContent()) ?? "";
    const names = await a.$$eval("[data-testid=as-field-name]", (els) => els.map((e) => (e as HTMLInputElement).value).join(" "));
    assert(dialog.includes("field_0x4") || names.includes("field_0x4"), `the preview: ${dialog} ${names}`);
    assert((await a.inputValue("[data-testid=as-name]")) === "astruct", "default name");
    await shot(a, "auto-struct-preview");
    const row = (await a.locator("[data-testid=as-field][data-offset='0x4']").textContent()) ?? "";
    // Names are cells (feature auto-struct-edit) or text.
    const rowName = (await a.locator("[data-testid=as-field-name][data-offset='0x4']").count()) ? await a.inputValue("[data-testid=as-field-name][data-offset='0x4']") : row;
    assert(rowName.includes("field_0x4") && row.includes("new"), `field row: ${row} ${rowName}`);
    // The call depth re-composes the preview.
    await a.selectOption("[data-testid=as-depth]", "0");
    await a.locator("[data-testid=as-field][data-offset='0x4']").waitFor();
    await a.waitForFunction(() => !(document.querySelector("[data-testid=as-apply]") as HTMLButtonElement).disabled);
    await a.click("[data-testid=as-apply]");
    await a.locator("[data-testid=auto-struct]").waitFor({ state: "detached" });
    await until(a, "param_1 is a struct astruct *", (s) => /astruct \*\s*param_1/.test(s.decompText));
    // The type is committed, not only printed: the body reads the field.
    await until(a, "the body reads param_1->field_0x4", (s) => s.decompText.includes("param_1->field_0x4"));
    await until(b, "page B: param_1 is a struct astruct *", (s) => s.decompName === "second" && /astruct \*\s*param_1/.test(s.decompText));

    // Fill in: the struct it now points to already has the field.
    await rightClick(a, "param_1", "k-pa");
    await a.locator("[data-testid=ctx-auto-fill]").click();
    await a.locator("[data-testid=auto-struct]").waitFor();
    await a.waitForFunction(() => (document.querySelector("[data-testid=as-summary]")?.textContent ?? "").includes("nothing would change"));
    const kept = (await a.locator("[data-testid=as-field][data-offset='0x4']").textContent()) ?? "";
    assert(kept.includes("kept"), `kept field: ${kept}`);
    assert(await a.locator("[data-testid=as-apply]").isDisabled(), "Apply enabled with nothing to change");
    await a.keyboard.press("Escape");
    await a.locator("[data-testid=auto-struct]").waitFor({ state: "detached" });

    // Rename Field and Retype Field (feature field-tokens) on the body's
    // param_1->field_0x4: the struct's next version, in both pages.
    await rightClick(a, "field_0x4", "k-fd");
    await a.locator("[data-testid=ctx-retype-field]").waitFor();
    assert((await a.locator("[data-testid=ctx-rename]").count()) === 0, "plain Rename (the function's) offered on a field");
    await a.locator("[data-testid=ctx-rename-field]").click();
    await answer(a, "second_int");
    await until(a, "param_1->second_int", (s) => s.decompText.includes("param_1->second_int"));
    await until(b, "page B: param_1->second_int", (s) => s.decompText.includes("param_1->second_int"));
    let fields = await structFields(c, "astruct");
    assert(fields.some((f) => f.name === "second_int" && f.offset === 4), `astruct after Rename Field: ${JSON.stringify(fields)}`);
    assert((await snap(a)).decompName === "second", "the function was renamed");
    // Retype Field from the keyboard (y) on the selected field.
    await a.locator("#cm .cm-content span.k-fd", { hasText: /^second_int$/ }).first().click();
    await a.keyboard.press("y");
    await answer(a, "unsigned int");
    fields = await untilFields(c, "astruct", "second_int is unsigned", (fs) => fs.some((f) => f.name === "second_int" && /^(uint|unsigned int)$/.test(f.type)));
    await shot(a, "retype-field");
    await undo(a);
    await untilFields(c, "astruct", "second_int is int again", (fs) => fs.some((f) => f.name === "second_int" && f.type === "int"));
    await undo(a);
    await until(a, "param_1->field_0x4 back", (s) => s.decompText.includes("param_1->field_0x4"));
    await until(b, "page B: param_1->field_0x4 back", (s) => s.decompText.includes("param_1->field_0x4"));

    await undo(a);
    await until(a, "param_1's type back", (s) => !s.decompText.includes("astruct") && /\bparam_1\b/.test(s.decompText));
    await until(b, "page B: param_1's type back", (s) => !s.decompText.includes("astruct"));
  });

  await check("rename: a token that names nothing says so and leaves the function alone; no token is the function", async () => {
    await go(a, second);
    await until(a, "second decompiled", (s) => s.decompName === "second" && s.decompText.includes("return"));
    await rightClick(a, "return", "k-kw");
    await a.locator("[data-testid=ctx-rename]").click();
    await a.locator(".toast", { hasText: "Nothing to rename here" }).first().waitFor({ timeout: 5000 });
    assert((await a.locator("[data-testid=ask]").count()) === 0, "a rename dialog opened on a keyword");
    // A constant, from the keyboard.
    const k = a.locator("#cm .cm-content span.k-co").first();
    if (await k.count()) {
      await k.click();
      await a.keyboard.press("n");
      await a.waitForTimeout(200);
      assert((await a.locator("[data-testid=ask]").count()) === 0, "a rename dialog opened on a constant");
    }
    // The signature line's type still means the function, as the listing's signature row does.
    const ty = a.locator("#cm .cm-line").first().locator("span.k-ty").first();
    await ty.click();
    await a.keyboard.press("n");
    await a.waitForSelector("[data-testid=ask]");
    const title = (await a.locator("[data-testid=ask]").getAttribute("aria-label")) ?? "";
    assert(title.startsWith("Rename function second"), `signature line: ${title}`);
    await a.keyboard.press("Escape");
    await a.waitForSelector("[data-testid=ask]", { state: "detached" });
    assert((await snap(a)).decompName === "second", "the function was renamed");
  });

  await check("auto-struct: Create structure from selection on printf's format string, in both pages; Ctrl+Z", async () => {
    const found = await rpc<{ data?: { address: { offset: string }; value: string }[] }>(base, "QueryService/ListData", { programId: "default/prog", textContains: "%u" });
    const fmt = found.data?.find((d) => d.value.startsWith("%u"));
    assert(fmt, "printf's format string");
    const at = hx(BigInt(fmt.address.offset));
    await go(a, at);
    await go(b, at);
    const r0 = await untilRows(a, "the string's row", (r) => r.some((x) => x.address === at && x.kind === KIND.Data));
    const was = r0.find((x) => x.address === at && x.kind === KIND.Data)!.dataType;
    await a.locator("#listing-canvas").dispatchEvent("contextmenu", { button: 0, clientX: 0, clientY: 0 });
    await a.locator("[data-testid=ctx-data]").click();
    await a.locator("[data-testid=submenu] [data-testid=ctx-struct-from-selection]").click();
    await a.locator("[data-testid=auto-struct]").waitFor();
    await a.locator("[data-testid=as-field][data-offset='0x0']").waitFor({ timeout: 15000 });
    await shot(a, "struct-from-selection-preview");
    const fieldRow = a.locator("[data-testid=as-field][data-offset='0x0']");
    const field = ((await fieldRow.textContent()) ?? "") + ((await fieldRow.locator("[data-testid=as-field-type]").count()) ? await fieldRow.locator("[data-testid=as-field-type]").inputValue() : "");
    assert(/char ?\[\d+\]/.test(field) && field.includes("data"), `field row: ${field}`);
    await a.fill("[data-testid=as-name]", "fmt_t");
    await a.waitForFunction(() => {
      const apply = document.querySelector("[data-testid=as-apply]") as HTMLButtonElement;
      return !apply.disabled && (document.querySelector("[data-testid=as-summary]")?.textContent ?? "").startsWith("struct fmt_t");
    });
    await a.click("[data-testid=as-apply]");
    await a.locator("[data-testid=auto-struct]").waitFor({ state: "detached" });
    for (const p of [a, b]) await untilRows(p, "struct fmt_t at the string", (r) => r.some((x) => x.address === at && x.kind === KIND.Data && !x.dataField && x.dataType === "struct fmt_t"));
    await undo(a);
    for (const p of [a, b]) await untilRows(p, "the string back", (r) => r.some((x) => x.address === at && x.kind === KIND.Data && !x.dataField && x.dataType === was));
  });
}

// --- Editing the preview and chained structures (feature auto-struct-edit) ---

const CHAIN_SRC = String.raw`
struct inner { long id; int count; short tag; };
struct outer { long a; struct inner *in; int flags; };
__attribute__((noinline)) void touch(struct outer *o) { o->flags = 1; o->in->count += 2; o->in->tag = 3; }
__attribute__((noinline)) long sum2(struct outer *o) { return o->flags + o->a; }
int main(int argc, char **argv) {
  (void)argv;
  static struct inner i;
  static struct outer o;
  o.in = &i;
  touch(&o);
  return i.count + argc + (int)sum2(&o);
}
`;

export interface AutoStructEditContext {
  base: string;
  dir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
  page: (query: string) => Promise<Page>;
}

/**
 * On touch(struct outer *) compiled without debug info: Auto create
 * structure on param_1, a field renamed (Enter commits the cell, not Apply)
 * and retyped in the dialog, a type that runs into the next field refused
 * inline, Ctrl+Enter applies; the decompiler reads param_1->flags. Then a
 * chain: Auto create structure on the field token param_1->field_0x8, an
 * inner field renamed in the dialog, Apply: param_1->field_0x8->count; one
 * Ctrl+Z each.
 */
export async function autoStructEditChecks(c: AutoStructEditContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const { execFileSync } = await import("node:child_process");
  const { writeFileSync, mkdirSync } = await import("node:fs");
  const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", {});
  if (!info.features?.includes("auto-struct-edit")) return c.log("  (auto-struct-edit: not in this daemon, skipped)");
  let gcc = "";
  try {
    gcc = execFileSync("sh", ["-c", "command -v gcc"]).toString().trim();
  } catch {
    /* none */
  }
  if (!gcc) return c.log("  (auto-struct-edit: no gcc, skipped)");
  const d = path.join(c.dir, "chain");
  mkdirSync(d, { recursive: true });
  writeFileSync(path.join(d, "chain.c"), CHAIN_SRC);
  execFileSync(gcc, ["-O1", "-fno-inline", "-fno-pie", "-no-pie", path.join(d, "chain.c"), "-o", path.join(d, "chain")]);
  const imp = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", { projectId: "default", path: path.join(d, "chain"), name: "chain", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
  const prog = imp.program.programId;
  // Background analysis first: inference types touch's and sum2's parameter
  // with a structure of its own (astruct_<n>, category /inferred), and the
  // checks start from the decompilation it settles on.
  for (let i = 0; i < 600; i++) {
    const s = await rpc<{ idle?: boolean }>(base, "AnalysisService/GetAnalysisStatus", { programId: prog });
    if (s.idle) break;
    await new Promise((r) => setTimeout(r, 200));
  }
  type Fn = { entry?: { offset?: string }; name: string };
  const fns = (await rpc<{ functions?: Fn[] }>(base, "QueryService/ListFunctions", { programId: prog, page: { pageSize: 1000 } })).functions ?? [];
  const touch = fns.find((f) => f.name === "touch");
  assert(touch?.entry?.offset, "touch in the chain program");
  const p = await c.page(`program=${encodeURIComponent(prog)}&user=e2e&theme=dark#${BigInt(touch.entry.offset).toString(16)}`);
  const decomp = () => p.evaluate("window.__revkit.app.snapshot().decompText") as Promise<string>;
  const untilText = async (what: string, pred: (t: string) => boolean, ms = 20000) => {
    const end = Date.now() + ms;
    let t = await decomp();
    while (!pred(t)) {
      if (Date.now() > end) throw new Error(`timed out waiting for ${what}: ${t.slice(0, 600)}`);
      await p.waitForTimeout(100);
      t = await decomp();
    }
    return t;
  };
  const ready = async () => {
    await p.locator("[data-testid=auto-struct]").waitFor();
    await p.waitForFunction(() => (document.querySelector("[data-testid=as-summary]")?.textContent ?? "") !== "Composing…" || !!document.querySelector("[data-testid=as-error]")?.textContent, undefined, { timeout: 20000 });
  };
  const cellAt = (kind: "type" | "name", off: string) => p.locator(`[data-testid=as-field-${kind}][data-offset='${off}']`);
  const settled = () => p.waitForFunction(() => !document.querySelector("[data-testid=auto-struct]")?.classList.contains("busy"), undefined, { timeout: 15000 });
  const undo = async () => {
    const before = await p.getAttribute("#undo", "title");
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+z");
    await p.waitForFunction((t) => document.querySelector("#undo")?.getAttribute("title") !== t, before);
  };

  let inferred = "";  // inference's structure touch's param_1 pointed to
  await check("auto-struct edit: rename and retype fields in the preview (Enter commits a cell), a type into the next field is refused inline, Ctrl+Enter applies; the decompiler reads them", async () => {
    // param_1 is inference's structure (param_1->field_0x8->field_0xc), or
    // without inference a char * (param_1 + 8): Auto create structure makes a
    // new one either way.
    const was = await untilText("touch decompiled", (t) => /\btouch\(/.test(t) && (t.includes("param_1 + 8") || /param_1->field_0x8\b/.test(t)));
    inferred = /\b(astruct_\d+) \*\s*param_1\b/.exec(was)?.[1] ?? "";
    await rightClick(p, "param_1", "k-pa");
    await p.locator("[data-testid=ctx-auto-struct]").click();
    await ready();
    await p.selectOption("[data-testid=as-depth]", "0");
    await settled();
    await cellAt("name", "0x10").waitFor();
    // A type that runs into the next field: refused at its row, Apply off.
    await cellAt("type", "0x8").fill("char[12]");
    await cellAt("type", "0x8").press("Enter");
    await p.locator("[data-testid=as-field-error][data-offset='0x8']").waitFor({ timeout: 10000 });
    const msg = (await p.textContent("[data-testid=as-field-error][data-offset='0x8']")) ?? "";
    assert(/runs into/.test(msg), `the inline error: ${msg}`);
    assert(await p.locator("[data-testid=as-apply]").isDisabled(), "Apply with an edit that doesn't fit");
    assert((await p.locator("[data-testid=auto-struct]").count()) === 1, "Enter in a cell applied");
    await cellAt("type", "0x8").fill("undefined8");
    await cellAt("type", "0x8").press("Enter");
    await p.locator("[data-testid=as-field-error]").waitFor({ state: "detached", timeout: 10000 });
    // The int store at 0x10 reads as four bytes when the parameter was
    // inferred char * (no inference): remove 0x11..0x13 (×), if there; then
    // rename 0x10 to flags and retype it
    // unsigned int; the edits survive a name change.
    for (const off of ["0x11", "0x12", "0x13"]) {
      const remove = p.locator(`[data-testid=as-field][data-offset='${off}'] [data-testid=as-field-remove]`);
      if (!(await remove.count())) continue;
      await remove.click();
      await p.locator(`[data-testid=as-removed][data-offset='${off}']`).waitFor({ timeout: 10000 });
    }
    await cellAt("name", "0x10").fill("flags");
    await cellAt("name", "0x10").press("Enter");
    await cellAt("type", "0x10").fill("unsigned int");
    await cellAt("type", "0x10").press("Tab");
    await p.fill("[data-testid=as-name]", "outer_e2e");
    await settled();
    await p.waitForFunction(() => (document.querySelector("[data-testid=as-summary]")?.textContent ?? "").startsWith("struct outer_e2e"));
    assert((await cellAt("name", "0x10").inputValue()) === "flags", "the rename survived the struct's name change");
    await shot(p, "auto-struct-edit");
    await p.waitForFunction(() => !(document.querySelector("[data-testid=as-apply]") as HTMLButtonElement).disabled);
    await p.focus("[data-testid=as-name]");
    await p.keyboard.press("Control+Enter");
    await p.locator("[data-testid=auto-struct]").waitFor({ state: "detached" });
    await untilText("param_1->flags", (t) => /param_1->flags\b/.test(t) && /outer_e2e \*\s*param_1/.test(t));
  });

  await check("auto-struct chain: Auto create structure on the field token param_1->field_0x8, an inner field renamed in the preview, Apply: param_1->field_0x8->count; Ctrl+Z each", async () => {
    await rightClick(p, "field_0x8", "k-fd");
    await p.locator("[data-testid=ctx-auto-struct]").click();
    await ready();
    const title = (await p.locator("[data-testid=auto-struct] .modal-title").textContent()) ?? "";
    assert(title.includes("param_1->field_0x8"), `the chained title: ${title}`);
    await p.selectOption("[data-testid=as-depth]", "0");
    await settled();
    await cellAt("name", "0x8").waitFor({ timeout: 15000 });
    const summary = (await p.textContent("[data-testid=as-summary]")) ?? "";
    assert(summary.includes("struct outer_e2e's field will point to it"), `summary: ${summary}`);
    await cellAt("name", "0x8").fill("count");
    await cellAt("name", "0x8").press("Enter");
    await p.fill("[data-testid=as-name]", "inner_e2e");
    await settled();
    assert((await cellAt("name", "0x8").inputValue()) === "count", `the inner field's name: ${await cellAt("name", "0x8").inputValue()}`);
    await p.waitForFunction(() => !(document.querySelector("[data-testid=as-apply]") as HTMLButtonElement).disabled);
    await shot(p, "auto-struct-chain");
    await p.click("[data-testid=as-apply]");
    await p.locator("[data-testid=auto-struct]").waitFor({ state: "detached" });
    await untilText("param_1->field_0x8->count", (t) => /param_1->field_0x8->count\b/.test(t));
    // One undo takes the chain back (the inner struct and the outer's next version).
    await undo();
    await untilText("the chain undone", (t) => !/->count\b/.test(t) && /param_1->flags\b/.test(t));
    await undo();
    // Back to the parameter's type before: inference's structure, if it had one.
    await untilText("the outer struct undone", (t) => !t.includes("outer_e2e") && (!inferred || new RegExp(`\\b${inferred} \\*\\s*param_1\\b`).test(t)));
  });
  await check("auto-struct edit: retype a parameter of a function nothing gave a prototype: the return value's code stays (the return isn't locked to void)", async () => {
    const sum2 = fns.find((f) => f.name === "sum2");
    assert(sum2?.entry?.offset, "sum2 in the chain program");
    await p.evaluate((a) => (window as unknown as { __revkit: { app: { navigate: (x: bigint) => Promise<void> } } }).__revkit.app.navigate(BigInt(a)), sum2.entry.offset);
    // Inference may give sum2 a prototype, its return included; that the
    // return stays the decompiler's when nothing gave one is
    // AutoStructTest.ATypedParameterLeavesTheReturnToTheDecompiler too.
    await untilText("sum2 decompiled", (t) => /\bsum2\(/.test(t) && t.includes(" + "));
    await p.locator("#cm .cm-content span.k-pa", { hasText: /^param_1$/ }).first().click();
    await p.keyboard.press("y");
    await p.waitForSelector("[data-testid=ask] .ask-input");
    await p.fill("[data-testid=ask] .ask-input", "void *");
    await p.keyboard.press("Enter");
    await p.waitForSelector("[data-testid=ask]", { state: "detached" });
    const t = await untilText("param_1 typed", (x) => /void \*\s*param_1/.test(x));
    assert(t.includes(" + ") && !/\bvoid sum2\(/.test(t) && !t.includes("return;"), `the sum is kept: ${t}`);
    await undo();
    await untilText("the type undone", (x) => !/void \*\s*param_1/.test(x));
  });
  await p.context().close();
}
