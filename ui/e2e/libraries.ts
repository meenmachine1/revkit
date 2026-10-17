// End-to-end checks for shared libraries (api_minor 70, feature
// "program-libraries"; docs/ui.md "Libraries"): a program built here against
// a tiny shared library (both without libc, so nothing of the host's is
// imported), imported from the Open dialog with "Also import the libraries
// it needs"; the import thunk's "→ libmylib.so!lib_add" in the functions
// list; Analyze → Libraries…; the Open dialog's details; and the thunk's
// target opening the library program at the function, whose References list
// prog2's call (references back from a library); under gdbserver, a stop in
// the library opening its tab, which follows the pc. run.ts calls
// librariesChecks() with its helpers.

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

export interface LibrariesContext {
  base: string;
  tmp: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  open: (base: string, query?: string, hash?: string, dpr?: number) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  until: <T>(p: Page, what: string, pred: (s: T) => boolean, ms?: number) => Promise<T>;
}

type Dbg = { active: boolean; busy: boolean; stop: string | null; target: string | null; running: boolean };
type FollowSnap = { address: string | null; following: string | null; pcMark: string | null; emu: Dbg | null };
const hx = (n: bigint) => n.toString(16);

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

const LIB = `__attribute__((noinline)) int lib_add(int a, int b) { return a + b + 1000; }
int lib_twice(int a) { return lib_add(a, a); }
`;
// No libc: _start calls the library and exits by a system call (x86-64).
const PROG = `int lib_add(int a, int b);
int lib_twice(int a);
void _start(void) {
  int r = lib_add(1, 2) + lib_twice(3);
  __asm__ volatile("mov $60, %%eax\\n\\tsyscall" : : "D"(r) : "rax");
  for (;;) {}
}
`;

type Prog = { programId: string; name: string; deleted?: boolean };

export async function librariesChecks(c: LibrariesContext) {
  const { base, check, open, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const programs = async () => (await rpc<{ programs?: Prog[] }>(base, "ProjectService/ListPrograms", { projectId: "default" })).programs ?? [];

  await check("libraries: imported with the program, the thunk's library function, Analyze → Libraries…, opened at the function", async () => {
    if (process.arch !== "x64") return;
    const dir = path.join(c.tmp, "libs");
    mkdirSync(dir, { recursive: true });
    writeFileSync(path.join(dir, "mylib.c"), LIB);
    writeFileSync(path.join(dir, "prog2.c"), PROG);
    const cc = process.env.CC ?? "cc";
    execFileSync(cc, ["-O1", "-shared", "-fPIC", "-nostdlib", "-Wl,-soname,libmylib.so", "-o", path.join(dir, "libmylib.so"), path.join(dir, "mylib.c")]);
    execFileSync(cc, ["-O1", "-nostdlib", "-o", path.join(dir, "prog2"), path.join(dir, "prog2.c"), `-L${dir}`, "-lmylib", `-Wl,-rpath,${dir}`]);

    // Import it from the Open dialog, with its libraries.
    const p = await open(base);
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+o");
    await p.click("[data-testid=open-import-binary]");
    await p.check("[data-testid=open-import-libraries]");
    await p.fill("[data-testid=open-path]", path.join(dir, "prog2"));
    await shot(p, "libraries-import");
    await Promise.all([p.waitForURL(/program=default%2Fprog2|program=default\/prog2/, { timeout: 60000 }), p.press("[data-testid=open-path]", "Enter")]);
    await p.waitForSelector("body[data-ready='1']", { timeout: 30000 });
    const names = (await programs()).map((x) => x.name);
    assert(names.includes("prog2") && names.includes("libmylib.so"), `imported: ${names}`);

    // The import thunk says where it goes.
    const ext = p.locator("[data-testid=fn-ext]", { hasText: "libmylib.so!lib_add" });
    await ext.waitFor({ timeout: 20000 });

    // References to the thunk say where it goes.
    await p.locator(".fn-row .fn-name", { hasText: /^lib_add$/ }).click();
    await p.waitForFunction(() => /^lib_add/.test(document.getElementById("st-fn")?.textContent ?? ""), null, { timeout: 10000 });
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+Shift+F");
    await p.locator("[data-testid=xrefs-external]", { hasText: "libmylib.so!lib_add" }).waitFor();
    await p.keyboard.press("Escape");

    // Analyze → Libraries…: libmylib.so by name, and its imports.
    await p.click("[data-testid=analyze-menu]");
    await p.click("[data-testid=menu-cmd-libraries]");
    const dialog = p.locator("[data-testid=libs-dialog]");
    await dialog.waitFor();
    const row = dialog.locator("[data-testid=libs-row][data-name='libmylib.so']");
    await row.waitFor();
    assert((await row.getAttribute("data-resolution")) === "by name", `resolution ${await row.getAttribute("data-resolution")}`);
    assert(/2 imports/.test((await row.textContent()) ?? ""), `imports counted: ${await row.textContent()}`);
    await dialog.locator("[data-testid=libs-imports-box] summary").click();
    await dialog.locator("[data-testid=libs-import][data-name=lib_twice]", { hasText: "libmylib.so!lib_twice" }).waitFor();
    await shot(p, "libraries-dialog");
    await p.keyboard.press("Escape");

    // The Open dialog's details list its libraries.
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+o");
    await p.fill("[data-testid=open-search]", "prog2");
    await p.locator("[data-testid=open-row]", { hasText: /^prog2/ }).click();
    await p.locator("[data-testid=open-detail-libraries]", { hasText: "libmylib.so" }).waitFor();
    await p.keyboard.press("Escape");
    await p.waitForSelector("[data-testid=open-dialog]", { state: "detached" });

    // The thunk's target: the library program, at lib_add.
    await Promise.all([p.waitForURL(/program=default%2Flibmylib\.so|program=default\/libmylib\.so/, { timeout: 30000 }), ext.click()]);
    await p.waitForSelector("body[data-ready='1']", { timeout: 30000 });
    await p.waitForFunction(() => /^lib_add/.test(document.getElementById("st-fn")?.textContent ?? ""), null, { timeout: 20000 });
    await shot(p, "libraries-opened");
    // References back from the library (feature library-importers): prog2's call of lib_add, opened there.
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+Shift+F");
    const back = p.locator("[data-testid=xrefs-importer]", { hasText: "prog2!_start" });
    await back.waitFor({ timeout: 20000 });
    await shot(p, "libraries-importers");
    await Promise.all([p.waitForURL(/program=default%2Fprog2|program=default\/prog2/, { timeout: 30000 }), back.click()]);
    await p.waitForSelector("body[data-ready='1']", { timeout: 30000 });
    await p.waitForFunction(() => /^_start/.test(document.getElementById("st-fn")?.textContent ?? ""), null, { timeout: 20000 });

    // The debugger, under gdbserver: stopped in the library, "Open libmylib.so at lib_add"
    // opens a tab that follows the pc while it is in the library.
    let gdbserver = true;
    try {
      execFileSync("sh", ["-c", "command -v gdbserver"], { stdio: "ignore" });
    } catch {
      gdbserver = false;
    }
    if (gdbserver) {
      const prog = (await programs()).find((x) => x.name === "prog2")!;
      const lib = (await programs()).find((x) => x.name === "libmylib.so")!;
      const fns = async (id: string) =>
        Object.fromEntries(((await rpc<{ functions?: { name: string; entry?: { offset: string } }[] }>(base, "QueryService/ListFunctions", { programId: id, page: { pageSize: 500 } })).functions ?? []).map((f) => [f.name, BigInt(f.entry?.offset ?? "0")]));
      const progFns = await fns(prog.programId);
      const libFns = await fns(lib.programId);
      const dbg = (what: string, pred: (e: Dbg) => boolean, page = p) => c.until<FollowSnap>(page, what, (s) => !!s.emu && !s.emu.busy && pred(s.emu), 30000);
      await p.focus("#listing-canvas");
      await p.keyboard.press("Control+8");
      await p.waitForSelector("[data-testid=dbg-target]");
      await p.selectOption("[data-testid=dbg-target]", "launch");
      await p.click("[data-testid=dbg-start]");
      await dbg("launched", (e) => e.active && e.target === "gdb-remote");
      const session = (await p.evaluate("window.__revkit.app.emu.session.sessionId")) as string;
      const breakAt = (offset: bigint, program = false) =>
        rpc(base, "DebugService/SetDebugBreakpoints", { sessionId: session, add: [{ address: { offset: offset.toString(), program } }] });
      // To _start (the libraries are loaded by then), then into the library.
      await breakAt(progFns["_start"], true);
      await p.focus("#listing-canvas");
      await p.keyboard.press("F9");
      await dbg("at _start", (e) => e.stop === "breakpoint");
      const mods = await rpc<{ modules?: { name: string; librarySlide?: string }[] }>(base, "DebugService/ListDebugModules", { sessionId: session });
      const mod = (mods.modules ?? []).find((m) => m.name === "libmylib.so");
      assert(mod, `libmylib.so mapped: ${JSON.stringify(mods)}`);
      const slide = BigInt(mod.librarySlide ?? "0");
      await breakAt(libFns["lib_add"] + slide);
      await breakAt(libFns["lib_twice"] + slide);
      await p.keyboard.press("F9");
      const link = p.locator("[data-testid=dbg-library-link]", { hasText: "Open libmylib.so at lib_add" });
      await link.waitFor({ timeout: 30000 });
      const [tab] = await Promise.all([p.context().waitForEvent("page"), link.click()]);
      await tab.waitForSelector("body[data-ready='1']", { timeout: 30000 });
      // It follows the session, and marks the pc at lib_add (asked for when it opened).
      await c.until<FollowSnap>(tab, "the library tab at the pc", (s) => s.following === session && s.pcMark === hx(libFns["lib_add"]) && s.address === hx(libFns["lib_add"]), 20000);
      // The next stop, lib_twice: the tab goes there.
      await p.focus("#listing-canvas");
      await p.keyboard.press("F9");
      await c.until<FollowSnap>(tab, "the library tab following to lib_twice", (s) => s.pcMark === hx(libFns["lib_twice"]) && s.address === hx(libFns["lib_twice"]), 30000);
      await shot(tab, "libraries-follow");
      // The session closed: the mark goes.
      await rpc(base, "DebugService/CloseDebugSession", { sessionId: session });
      await p.evaluate("window.__revkit.app.emu.close()");
      await c.until<FollowSnap>(tab, "the mark gone", (s) => s.pcMark === null, 20000);
    }
    await p.context().close();

    // Left as the other checks expect: neither program listed.
    for (const x of await programs())
      if (x.name === "prog2" || x.name === "libmylib.so")
        await rpc(base, "ProjectService/DeleteProgram", { programId: x.programId, provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
  });
}
