// End-to-end checks for Edit Function (docs/ui.md "Edit function", feature
// calling-conventions): on a 32-bit Windows program compiled here (clang
// and lld; skipped without them), the dialog opens from the decompiler's
// function name with F, lists x86win.cspec's models with __stdcall the
// default; __fastcall chosen in the dropdown shows in the C signature,
// a parameter renamed and moved follows in the C, the C edited fills the
// fields, a bad type is an error under the signature, and Apply shows
// __fastcall in the decompiler's signature; Ctrl+Z takes it back. Set no
// return on mix ends start's C at the call; the dialog's No return box
// unchecked gives it back (feature no-return). run.ts
// calls editFunctionChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const SRC = String.raw`
__attribute__((noinline)) int __stdcall mix(int a, int b, int c) { return a * 3 + b * 5 - c; }
volatile int sink;
int start(int n) {
  sink = mix(n, n + 1, 9);
  return sink;
}
`;

export interface EditFunctionContext {
  base: string;
  dir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
  page: (query: string) => Promise<Page>;
}

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

function which(name: string): string {
  try {
    return execFileSync("sh", ["-c", `command -v ${name}`]).toString().trim();
  } catch {
    return "";
  }
}

export async function editFunctionChecks(c: EditFunctionContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", {});
  if (!info.features?.includes("calling-conventions")) return c.log("  (edit function: no feature calling-conventions, skipped)");
  const clang = which("clang"), lld = which("ld.lld");
  if (!clang || !lld) return c.log("  (edit function: no clang or ld.lld, skipped)");
  const d = path.join(c.dir, "editfn");
  mkdirSync(d, { recursive: true });
  writeFileSync(path.join(d, "conv.c"), SRC);
  try {
    execFileSync(clang, ["--target=i686-w64-mingw32", "-O1", "-ffreestanding", "-nostdlib", "-fuse-ld=lld", "-Wl,-e,_start", path.join(d, "conv.c"), "-o", path.join(d, "conv.exe")]);
  } catch {
    return c.log("  (edit function: clang can't build an i386 PE, skipped)");
  }
  const imp = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", { projectId: "default", path: path.join(d, "conv.exe"), name: "conv.exe", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
  const prog = imp.program.programId;
  type Fn = { entry?: { offset?: string }; name: string };
  const fns = (await rpc<{ functions?: Fn[] }>(base, "QueryService/ListFunctions", { programId: prog, page: { pageSize: 100 } })).functions ?? [];
  // No symbols: mix comes first in .text, then start (the entry).
  const entries = fns.map((f) => BigInt(f.entry?.offset ?? 0)).sort((a, b) => (a < b ? -1 : 1));
  assert(entries.length >= 2, `functions: ${JSON.stringify(fns)}`);
  const mix = entries[0];
  const mixName = fns.find((f) => BigInt(f.entry?.offset ?? 0) === mix)!.name;
  const p = await c.page(`program=${encodeURIComponent(prog)}&user=e2e&theme=dark#${mix.toString(16)}`);
  // The decompiled C's signature: its first line that isn't a comment.
  const sig = () =>
    p.evaluate("window.__revkit.app.snapshot().decompText").then((t) => (String(t).split("\n").find((l) => l.trim() && !l.trim().startsWith("/*") && !l.trim().startsWith("*")) ?? "").trim());
  const untilSig = async (what: string, pred: (s: string) => boolean, ms = 20000) => {
    const end = Date.now() + ms;
    let s = await sig();
    while (!pred(s)) {
      if (Date.now() > end) throw new Error(`timed out waiting for ${what}: ${s}`);
      await p.waitForTimeout(100);
      s = await sig();
    }
    return s;
  };
  const sigBox = "[data-testid=ef-signature]";
  const settled = () => p.waitForFunction(() => !(document.querySelector("[data-testid=ef-apply]") as HTMLButtonElement).disabled || !!document.querySelector("[data-testid=ef-error]")?.textContent, undefined, { timeout: 15000 });

  await check("edit function: F on the function's name opens it; x86win's conventions with __stdcall the default; __fastcall from the dropdown shows in the C; Apply: the decompiler's signature says __fastcall; Ctrl+Z", async () => {
    await untilSig("mix decompiled", (s) => s.includes(mixName));
    await p.locator("#cm .cm-content span.k-fn", { hasText: new RegExp(`^${mixName}$`) }).first().click();
    await p.keyboard.press("f");
    await p.waitForSelector("[data-testid=edit-function]");
    const options = await p.$$eval("[data-testid=ef-convention] option", (els) => els.map((e) => [(e as HTMLOptionElement).value, e.textContent ?? ""]));
    assert(options.some(([, t]) => /^default \(__stdcall\)/.test(t)), `the default: ${JSON.stringify(options)}`);
    assert(options.some(([v]) => v === "__fastcall") && options.some(([v]) => v === "__cdecl") && options.some(([v]) => v === "unknown"), `models: ${JSON.stringify(options)}`);
    await settled();
    assert((await p.locator("[data-testid=ef-param]").count()) === 3, "three parameters");
    await p.selectOption("[data-testid=ef-convention]", "__fastcall");
    let c1 = await p.inputValue(sigBox);
    assert(c1.includes("__fastcall") && c1.includes(`${mixName}(`), `the C: ${c1}`);
    // A parameter renamed, then moved down: the C follows.
    await p.locator("[data-testid=ef-param-name]").first().fill("first");
    await p.locator("[data-testid=ef-param-down]").first().click();
    c1 = await p.inputValue(sigBox);
    assert(/\(\s*\w[^,]*,\s*[^,]*\bfirst\s*,/.test(c1), `first moved to second place: ${c1}`);
    await p.locator("[data-testid=ef-param-up]").nth(1).click();
    // The C edited fills the fields: a bad type is the daemon's error under it.
    await p.fill(sigBox, `int __fastcall ${mixName}(nope_t a, int b, int c)`);
    await p.locator("[data-testid=ef-error]", { hasText: /\S/ }).waitFor({ timeout: 10000 });
    assert(await p.locator("[data-testid=ef-apply]").isDisabled(), "Apply with an error");
    await p.fill(sigBox, `int __fastcall ${mixName}(int a, int b, int c)`);
    await p.waitForFunction(() => !(document.querySelector("[data-testid=ef-apply]") as HTMLButtonElement).disabled, undefined, { timeout: 10000 });
    assert((await p.inputValue("[data-testid=ef-convention]")) === "__fastcall", "the dropdown follows the C");
    assert((await p.locator("[data-testid=ef-param-name]").first().inputValue()) === "a", "the fields follow the C");
    await shot(p, "edit-function");
    await p.click("[data-testid=ef-apply]");
    await p.waitForSelector("[data-testid=edit-function]", { state: "detached" });
    await untilSig("__fastcall in the signature", (s) => s.includes("__fastcall"));
    const before = await p.getAttribute("#undo", "title");
    assert((before ?? "").includes("Edit function"), `one undo step: ${before}`);
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+z");
    await untilSig("the convention undone", (s) => !s.includes("__fastcall"));
  });

  await check("edit function: from the palette and the function list's menu; renaming in the dialog renames the function in the same step", async () => {
    await p.locator(".fn-row .fn-name", { hasText: new RegExp(`^${mixName}$`) }).first().click({ button: "right" });
    await p.click("[data-testid=fn-menu-edit]");
    await p.waitForSelector("[data-testid=edit-function]");
    await settled();
    await p.fill("[data-testid=ef-name]", "mix_e2e");
    assert((await p.inputValue(sigBox)).includes("mix_e2e("), "the name in the C");
    await p.waitForFunction(() => !(document.querySelector("[data-testid=ef-apply]") as HTMLButtonElement).disabled, undefined, { timeout: 10000 });
    await p.keyboard.press("Control+Enter");
    await p.waitForSelector("[data-testid=edit-function]", { state: "detached" });
    await untilSig("renamed", (s) => s.includes("mix_e2e("));
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+z");
    await untilSig("the rename undone", (s) => s.includes(`${mixName}(`));
  });
  await check("edit function: no return: Set no return on mix (the function list's menu) ends start at the call; the dialog's No return box unchecked gives the return back; Ctrl+Z each", async () => {
    if (!info.features?.includes("no-return")) return c.log("  (no feature no-return, skipped)");
    const start = entries.find((e) => e !== mix)!;
    const startName = fns.find((f) => BigInt(f.entry?.offset ?? 0) === start)!.name;
    const text = () => p.evaluate("window.__revkit.app.snapshot().decompText").then(String);
    const untilText = async (what: string, pred: (t: string) => boolean, ms = 20000) => {
      const end = Date.now() + ms;
      let t = await text();
      while (!pred(t)) {
        if (Date.now() > end) throw new Error(`timed out waiting for ${what}: ${t}`);
        await p.waitForTimeout(100);
        t = await text();
      }
      return t;
    };
    await p.evaluate((h) => (location.hash = h), start.toString(16));
    await untilSig("start decompiled", (s) => s.includes(`${startName}(`));
    // The decompiler's warning at a call that doesn't return ("Subroutine does not return").
    const ends = (t: string) => /does not return/.test(t);
    await untilText("start goes on after mix", (t) => !ends(t) && t.includes(`${mixName}(`));
    await p.locator(".fn-row .fn-name", { hasText: new RegExp(`^${mixName}$`) }).first().click({ button: "right" });
    await p.click("[data-testid=fn-menu-no-return-set]");
    await untilText("start ends at the call to mix", (t) => ends(t) && t.includes(`${mixName}(`));
    // The dialog shows it; unchecked and applied, start returns again.
    // The function list's row learns it with its next page (the new revision's).
    for (let end = Date.now() + 10000; ; ) {
      await p.locator(".fn-row .fn-name", { hasText: new RegExp(`^${mixName}$`) }).first().click({ button: "right" });
      if ((await p.locator("[data-testid=fn-menu-no-return-clear]").count()) === 1) break;
      assert(Date.now() < end, "the menu offers Clear no return");
      await p.keyboard.press("Escape");
      await p.waitForTimeout(200);
    }
    await p.click("[data-testid=fn-menu-edit]");
    await p.waitForSelector("[data-testid=edit-function]");
    await settled();
    assert(await p.isChecked("[data-testid=ef-no-return]"), "No return is checked");
    await p.uncheck("[data-testid=ef-no-return]");
    await p.waitForFunction(() => !(document.querySelector("[data-testid=ef-apply]") as HTMLButtonElement).disabled, undefined, { timeout: 10000 });
    await shot(p, "edit-function-no-return");
    await p.click("[data-testid=ef-apply]");
    await p.waitForSelector("[data-testid=edit-function]", { state: "detached" });
    await untilText("start goes on again", (t) => !ends(t));
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+z");
    await untilText("the clear undone", (t) => ends(t));
    await p.keyboard.press("Control+z");
    await untilText("the set undone", (t) => !ends(t));
  });
  await p.context().close();
}
