// End-to-end checks for register values over ranges (docs/ui.md "Register
// values", feature register-values): on a MIPS program built with small
// data here (clang and lld; skipped without them), the loader's _gp names
// bump's globals in the C; the Register values view lists gp, set by
// analysis; Set register value… from the listing's Function menu, with
// "No value" checked, over the function takes the names away (unaff_gp)
// and the view shows the user's range; Ctrl+Z gives them back; a value
// set from the dialog over the function brings them back too, and the
// view's Delete clears it. run.ts calls regValuesChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const SRC = String.raw`
int counter;
int limit = 7;
__attribute__((noinline)) int bump(int x) { counter += x; return counter < limit; }
void __start(void) { for (;;) if (!bump(3)) limit = 0; }
`;

export interface RegValuesContext {
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

type Row = { register: string; first: string; last: string; value: string; by: string };

export async function regValuesChecks(c: RegValuesContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", {});
  if (!info.features?.includes("register-values")) return c.log("  (register values: no feature register-values, skipped)");
  const clang = which("clang"), lld = which("ld.lld");
  if (!clang || !lld) return c.log("  (register values: no clang or ld.lld, skipped)");
  const d = path.join(c.dir, "regvalues");
  mkdirSync(d, { recursive: true });
  writeFileSync(path.join(d, "g.c"), SRC);
  try {
    execFileSync(clang, ["--target=mipsel-linux-gnu", "-O1", "-fno-pic", "-mno-abicalls", "-G", "8", "-c", path.join(d, "g.c"), "-o", path.join(d, "g.o")], { stdio: "ignore" });
    execFileSync(lld, ["-e", "__start", "-o", path.join(d, "gp.elf"), path.join(d, "g.o")], { stdio: "ignore" });
  } catch {
    return c.log("  (register values: clang can't build a MIPS program, skipped)");
  }
  const imp = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", { projectId: "default", path: path.join(d, "gp.elf"), name: "gp.elf", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
  const prog = imp.program.programId;
  const syms = await rpc<{ symbols?: { address: { offset: string } }[] }>(base, "QueryService/ListSymbols", { programId: prog, nameEquals: "bump" });
  const bump = BigInt(syms.symbols?.[0]?.address.offset ?? 0);
  assert(bump !== 0n, "bump's symbol");
  const p = await c.page(`program=${encodeURIComponent(prog)}&user=e2e&theme=dark#${bump.toString(16)}`);
  const text = () => p.evaluate("window.__revkit.app.snapshot().decompText").then(String);
  const until = async <T>(what: string, get: () => Promise<T>, pred: (v: T) => boolean, ms = 20000) => {
    const end = Date.now() + ms;
    let v = await get();
    while (!pred(v)) {
      if (Date.now() > end) throw new Error(`timed out waiting for ${what}: ${JSON.stringify(v)}`);
      await p.waitForTimeout(100);
      v = await get();
    }
    return v;
  };
  const rows = () => p.evaluate("window.__revkit.app.snapshot().regvalues").then((r) => (r ?? []) as Row[]);
  const named = (t: string) => t.includes("counter") && t.includes("limit") && !t.includes("unaff_gp");

  await check("register values: the loader's gp names bump's globals; the Register values view lists gp (analysis); Set register value… with No value over the function (the listing's Function menu) gives unaff_gp; Ctrl+Z; a value set from the view brings the names back and Delete clears it", async () => {
    await until("bump's C names counter and limit", text, named);
    await p.evaluate("window.__revkit.app.showView('regvalues')");
    const r0 = await until("the view lists gp", rows, (r) => r.some((x) => x.register === "gp" && x.by.startsWith("analysis")));
    const gp = r0.find((x) => x.register === "gp")!.value;
    await shot(p, "regvalues-view");

    // The listing's right-click menu ▸ Function ▸ Clear register value… over bump.
    await p.evaluate("window.__revkit.app.showView('listing')");
    await p.focus("#listing-canvas");
    await p.locator("#listing-canvas").dispatchEvent("contextmenu", { button: 0, clientX: 0, clientY: 0 });
    await p.waitForSelector("[data-testid=menu]");
    await p.hover("[data-testid=ctx-function]");
    await p.waitForSelector("[data-testid=submenu] [data-testid=ctx-regval-clear]");
    await p.click("[data-testid=ctx-regval-clear]");
    await p.waitForSelector("[data-testid=regvalue-dialog]");
    assert(await p.isChecked("[data-testid=regvalue-clear]"), "No value is checked");
    await p.fill("[data-testid=regvalue-register]", "gp");
    await shot(p, "regvalues-dialog");
    await p.keyboard.press("Enter");
    await p.waitForSelector("[data-testid=regvalue-dialog]", { state: "detached" });
    await until("unaff_gp in bump", text, (t) => t.includes("unaff_gp"));
    await p.evaluate("window.__revkit.app.showView('regvalues')");
    await until("the view: no gp over bump", rows, (r) => !r.some((x) => x.register === "gp" && BigInt("0x" + x.first) <= bump && BigInt("0x" + x.last) >= bump));
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+z");
    await until("the names back", text, named);

    // From the view: Set… with gp's value over bump (the dialog's range).
    await p.evaluate("window.__revkit.app.showView('regvalues')");
    await p.click("[data-testid=regvalues-add]");
    await p.waitForSelector("[data-testid=regvalue-dialog]");
    await p.fill("[data-testid=regvalue-register]", "gp");
    await p.fill("[data-testid=regvalue-value]", "0x" + gp);
    await p.fill("[data-testid=regvalue-first]", bump.toString(16));
    await p.fill("[data-testid=regvalue-last]", (bump + 3n).toString(16));
    await p.keyboard.press("Enter");
    await p.waitForSelector("[data-testid=regvalue-dialog]", { state: "detached" });
    const r1 = await until("e2e's range in the view", rows, (r) => r.some((x) => x.register === "gp" && x.first === bump.toString(16) && x.by.includes("e2e")));
    assert(r1.find((x) => x.first === bump.toString(16))!.value === gp, `the value: ${JSON.stringify(r1)}`);
    await until("the names still", text, named);
    // Delete on that row: no value there (another undo step).
    const i = r1.findIndex((x) => x.first === bump.toString(16) && x.by.includes("e2e"));
    await p.locator("[data-testid=regvalue-row]").nth(i).click();
    await p.evaluate("window.__revkit.app.showView('regvalues')");
    await p.focus("[data-testid=regvalues-list]");
    await p.keyboard.press("Delete");
    await until("cleared from the view", rows, (r) => !r.some((x) => x.register === "gp" && x.first === bump.toString(16)));
    await p.evaluate("window.__revkit.app.showView('listing')");
    await until("unaff_gp again", text, (t) => t.includes("unaff_gp"));
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+z");
    await p.keyboard.press("Control+z");
    await until("as analysis has it", text, named);
  });
  await p.context().close();
}
