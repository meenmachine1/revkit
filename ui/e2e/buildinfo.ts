// End-to-end checks for build info (feature "build-info"; docs/build-info.md,
// docs/ui.md "Build info"): a Go program built here (a dependency replaced by
// a local directory, so no network). The palette's "Build info" shows the Go
// version, the build settings and the dependency, the filter narrows the
// table, and the Open dialog's details say "Built with". Skipped without Go
// ($RK_GO, go on PATH, ~/.local/go/bin/go or /usr/local/go/bin/go).
// run.ts calls buildInfoChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

export interface BuildInfoContext {
  base: string;
  dir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  page: (query: string) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
}

function findGo(): string | null {
  const candidates = [process.env.RK_GO, path.join(homedir(), ".local/go/bin/go"), "/usr/local/go/bin/go"];
  try {
    candidates.splice(1, 0, execFileSync("sh", ["-c", "command -v go"]).toString().trim());
  } catch {
    /* not on PATH */
  }
  return candidates.find((c) => !!c && existsSync(c)) ?? null;
}

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

async function palette(p: Page, command: string) {
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+Shift+P");
  await p.waitForSelector("[data-testid=palette-input]");
  await p.fill("[data-testid=palette-input]", `>${command}`);
  try {
    await p.waitForFunction((c) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").startsWith(c), command, { timeout: 10000 });
  } catch (e) {
    const items = await p.$$eval(".palette-item .pi-label", (els) => els.slice(0, 8).map((x) => x.textContent));
    throw new Error(`the palette's "${command}": ${JSON.stringify(items)}: ${e}`);
  }
  await p.keyboard.press("Enter");
}

export async function buildInfoChecks(c: BuildInfoContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const go = findGo();
  if (!go) {
    c.log("  (build info: no Go toolchain, skipped)");
    return;
  }
  const src = path.join(c.dir, "gomod");
  mkdirSync(path.join(src, "dep"), { recursive: true });
  writeFileSync(path.join(src, "go.mod"), "module example.com/hello\n\ngo 1.21\n\nrequire example.com/dep v0.1.0\n\nreplace example.com/dep => ./dep\n");
  writeFileSync(path.join(src, "dep/go.mod"), "module example.com/dep\n\ngo 1.21\n");
  writeFileSync(path.join(src, "dep/dep.go"), 'package dep\n\nfunc Greeting() string { return "hi" }\n');
  writeFileSync(path.join(src, "main.go"), 'package main\n\nimport (\n\t"fmt"\n\n\t"example.com/dep"\n)\n\nfunc main() { fmt.Println(dep.Greeting()) }\n');
  const bin = path.join(c.dir, "gohello");
  execFileSync(go, ["build", "-ldflags=-s -w", "-o", bin, "."], {
    cwd: src,
    env: { ...process.env, GOTOOLCHAIN: "local", GOPROXY: "off", GOFLAGS: "-p=2", CGO_ENABLED: "0", GOWORK: "off" },
    stdio: "ignore",
  });
  const imported = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", {
    projectId: "default", path: bin, name: "gohello", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
  });
  const programId = imported.program.programId;
  const p = await c.page(`program=${encodeURIComponent(programId)}&user=e2e&theme=dark`);

  await check("build info: the palette's Build info shows the Go version, the settings and the replaced dependency; the filter narrows it", async () => {
    const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", { client: "e2e" });
    assert(info.features?.includes("build-info"), `features: ${JSON.stringify(info.features)}`);
    await palette(p, "Build info");
    await p.waitForSelector("[data-testid=bi-go-version]", { timeout: 15000 });
    const version = await p.textContent("[data-testid=bi-go-version]");
    assert(version?.startsWith("go1."), `the Go version: ${version}`);
    assert((await p.textContent("[data-testid=bi-go-main]"))?.startsWith("example.com/hello"), "the main module");
    // The function table that named the stripped binary's functions (docs/go.md).
    const table = await p.textContent("[data-testid=bi-go-pclntab]");
    assert(/^\d+ functions, \d+ files · pclntab 1\.20 layout at 0x[0-9a-f]+ \(section\)$/.test(table ?? ""), `the function table: ${table}`);
    const deps = await p.$$eval("[data-testid=bi-go-dep]", (rows) => rows.map((r) => r.textContent ?? ""));
    assert(deps.length === 1 && deps[0].includes("example.com/dep") && deps[0].includes("./dep"), `the dependency: ${JSON.stringify(deps)}`);
    const settings = await p.textContent("[data-testid=bi-go-settings]");
    assert(settings?.includes("-ldflags") && settings.includes("CGO_ENABLED"), `the settings: ${settings}`);
    await p.fill("[data-testid=bi-filter]", "no-such-module");
    const shown = await p.$$eval("[data-testid=bi-go-dep]", (rows) => rows.filter((r) => !(r as HTMLElement).hidden).length);
    assert(shown === 0, `filtered out: ${shown}`);
    await p.fill("[data-testid=bi-filter]", "EXAMPLE.COM/DEP");
    const back = await p.$$eval("[data-testid=bi-go-dep]", (rows) => rows.filter((r) => !(r as HTMLElement).hidden).length);
    assert(back === 1, `filtered in (any case): ${back}`);
    await p.fill("[data-testid=bi-filter]", "");
    await shot(p, "build-info-go");
    await p.keyboard.press("Escape");
    await p.waitForSelector("[data-testid=bi-dialog]", { state: "detached", timeout: 5000 });
  });

  await check("build info: the Open dialog's details say what built the program, and its button opens the dialog", async () => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+o");
    await p.waitForSelector("[data-testid=open-row]");
    await p.click(`[data-testid=open-row][data-id="${programId}"]`);
    await p.waitForSelector("[data-testid=open-detail-build]", { timeout: 15000 });
    const line = await p.textContent("[data-testid=open-detail-build]");
    assert(line?.includes("Go go1.") && line.includes("1 module"), `the details line: ${line}`);
    await shot(p, "build-info-open-details");
    await p.click("[data-testid=open-build-info]");
    await p.waitForSelector("[data-testid=bi-go-version]", { timeout: 15000 });
    await p.click("[data-testid=bi-close]");
  });
  await p.context().close();
}
