// End-to-end checks for crash dumps (api_minor 102, feature "crash-dumps";
// docs/crash-dumps.md, docs/ui.md "Crash dumps"): a core of
// tests/data/crash/crash.c crashing in libcrash.so (the kernel's, or gcore's
// when core_pattern pipes cores to a helper), the program and its library
// imported; the Debugger view's Crash dump… from the daemon host: the crash
// box (reason, where, the faulting instruction), the stack through the
// library to main, the threads, and Continue disabled. run.ts calls
// crashChecks() with its helpers.

import type { Page } from "playwright";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";

export interface CrashContext {
  base: string;
  exe: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  open: (base: string, query?: string, hash?: string, dpr?: number) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
}

/** The core and whether the kernel wrote it (else gcore, at the program's SIGSTOP). */
async function makeCore(dir: string): Promise<{ core: string; kernel: boolean } | null> {
  const pattern = readFileSync("/proc/sys/kernel/core_pattern", "utf8").trim();
  if (pattern && !pattern.startsWith("|")) {
    try {
      execFileSync("sh", ["-c", "ulimit -c unlimited; exec ./crash"], { cwd: dir, stdio: "ignore" });
    } catch {
      /* it crashes */
    }
    const core = readdirSync(dir).find((n) => n.startsWith("core"));
    if (core) return { core: path.join(dir, core), kernel: true };
  }
  const child = spawn("./crash", ["stop"], { cwd: dir, stdio: "ignore" });
  for (let i = 0; i < 500; i++) {
    const stat = existsSync(`/proc/${child.pid}/stat`) ? readFileSync(`/proc/${child.pid}/stat`, "utf8") : "";
    if (stat.split(")")[1]?.trim().startsWith("T")) break;
    await new Promise((r) => setTimeout(r, 10));
  }
  try {
    execFileSync("gcore", ["-o", path.join(dir, "gcore"), String(child.pid)], { stdio: "ignore" });
  } catch {
    child.kill("SIGKILL");
    return null;
  }
  child.kill("SIGKILL");
  return { core: path.join(dir, `gcore.${child.pid}`), kernel: false };
}

export async function crashChecks(c: CrashContext) {
  const { base, check, open, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const dir = path.join(path.dirname(c.exe), "crashdemo");
  mkdirSync(dir, { recursive: true });
  const data = path.resolve(import.meta.dirname, "../../tests/data/crash");
  execFileSync("cc", ["-O1", "-g", "-shared", "-fPIC", "-o", path.join(dir, "libcrash.so"), path.join(data, "libcrash.c")]);
  execFileSync("cc", ["-O1", "-g", "-o", path.join(dir, "crash"), path.join(data, "crash.c"), `-L${dir}`, "-lcrash", "-Wl,-rpath,$ORIGIN", "-pthread"]);
  const made = await makeCore(dir);

  await check("crash dumps: a core opened from the daemon host over its program: the reason, the faulting instruction, the stack through the library, read-only", async () => {
    assert(made, "a core");
    const imported = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", {
      projectId: "default", path: path.join(dir, "crash"), options: { importLibraries: true, analyze: true },
      provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
    });
    const id = imported.program.programId;
    const p = await open(base);
    await p.goto(`${base}/?program=${encodeURIComponent(id)}&user=e2e&theme=dark`);
    await p.waitForSelector("body[data-ready='1']", { timeout: 30000 });
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+8");
    await p.waitForSelector("[data-testid=dbg-target]");
    await p.selectOption("[data-testid=dbg-target]", "crash");
    await p.click("[data-testid=dbg-start]");
    await p.locator("[data-testid=choose] .palette-item", { hasText: "daemon host" }).click();
    await p.locator(`[data-testid=host-entry][data-path="${dir}"]`).click();
    await p.locator(`[data-testid=host-entry][data-path="${made.core}"]`).click();
    const reason = p.locator("[data-testid=dbg-crash-reason]");
    await Promise.race([reason.waitFor({ timeout: 30000 }), p.locator(".toast.error").first().waitFor({ timeout: 30000 })]);
    if (await p.locator(".toast.error").count()) throw new Error(`the dump didn't open: ${await p.locator(".toast.error").first().textContent()}`);
    if (made.kernel) {
      assert((await reason.textContent()) === "SIGSEGV (SEGV_MAPERR) at 0x0", `the reason: ${await reason.textContent()}`);
      assert((await p.textContent("[data-testid=dbg-crash-where]"))?.includes("lib_store"), "where: lib_store");
      assert((await p.textContent("[data-testid=dbg-crash-insn]"))?.startsWith("MOV dword ptr [RDI]"), "the faulting store");
      const stack = p.locator("[data-testid=dbg-stack]");
      await stack.locator("text=main").first().waitFor({ timeout: 20000 });
      const text = (await stack.textContent()) ?? "";
      assert(text.includes("lib_compute") && text.includes("run_crash"), `the stack: ${text}`);
    }
    assert(await p.locator("[data-testid=emu-run]").isDisabled(), "Continue is disabled for a dump");
    await p.close();
  });
}
