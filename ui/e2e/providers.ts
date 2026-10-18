// End-to-end checks for the external decompilers (feature
// "external-decompilers"; docs/providers.md, docs/ui.md "External
// decompilers"): a .NET class library built here (dotnet) and imported as a
// program shows ILSpy's C# in the decompiler pane, highlighted, with the bar
// switching to Ghidra's C and back; a jar built here (javac) inside a zip on
// the daemon host opens in the file system browser, whose "Decompile with
// …" shows the output's files and their Java. Each part is skipped when
// its toolchain or the decompiler isn't installed. run.ts calls
// providerChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

export interface ProviderContext {
  base: string;
  /** The daemon's --browse-root. */
  dir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  page: (query: string) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
}

interface Providers {
  providers?: { name: string; available?: boolean; reason?: string }[];
}

function has(cmd: string): boolean {
  try {
    execFileSync("sh", ["-c", `command -v ${cmd}`], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

/** The colour of the first highlighted token with this text in the code view. */
async function tokenColor(p: Page, scope: string, text: string): Promise<{ token: string; line: string } | null> {
  return p.evaluate(
    ([scope, text]) => {
      for (const line of document.querySelectorAll<HTMLElement>(`${scope} .cm-line`)) {
        for (const span of line.querySelectorAll<HTMLElement>("span"))
          if (span.textContent === text) return { token: getComputedStyle(span).color, line: getComputedStyle(line).color };
      }
      return null;
    },
    [scope, text] as const,
  );
}

export async function providerChecks(c: ProviderContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", { client: "e2e" });
  if (!info.features?.includes("external-decompilers")) {
    c.log("  (external decompilers: not served, skipped)");
    return;
  }
  const list = await rpc<Providers>(base, "ProviderService/ListProviders", {});
  const available = (n: string) => !!list.providers?.find((p) => p.name === n)?.available;

  if (!has("dotnet") || !available("ilspy")) {
    c.log("  (external decompilers: no .NET SDK or ilspycmd, the decompiler pane's part skipped)");
  } else {
    const src = path.join(c.dir, "dotnet-tiny");
    const env = { ...process.env, DOTNET_CLI_TELEMETRY_OPTOUT: "1", DOTNET_NOLOGO: "1" };
    execFileSync("dotnet", ["new", "classlib", "-n", "Tiny", "-o", src, "--force"], { env, stdio: "ignore" });
    writeFileSync(
      path.join(src, "Class1.cs"),
      'namespace Tiny;\npublic class Calc {\n  public static int Add(int a, int b) { int c = a + b; if (c > 10) c -= 3; return c * 2; }\n  public static string Hello(string n) => "hi " + n.Length;\n}\n',
    );
    execFileSync("dotnet", ["build", "-c", "Release", "-o", path.join(src, "out")], { cwd: src, env, stdio: "ignore" });
    const imported = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", {
      projectId: "default", path: path.join(src, "out", "Tiny.dll"), name: "Tiny.dll", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
    });
    const programId = imported.program.programId;
    const p = await c.page(`program=${encodeURIComponent(programId)}&user=e2e&theme=dark`);

    await check("external decompilers: a .NET assembly shows ILSpy's C# in the decompiler pane, highlighted; the bar switches to Ghidra's C and back", async () => {
      await p.waitForSelector("[data-testid=ext-bar]", { timeout: 20000 });
      assert((await p.textContent("[data-testid=ext-kind]")) === ".NET assembly", `the kind: ${await p.textContent("[data-testid=ext-kind]")}`);
      await p.waitForFunction(() => (document.querySelector("[data-testid=ext-pane] .cm-content")?.textContent ?? "").includes("public static int Add(int a, int b)"), null, { timeout: 60000 });
      const code = (await p.textContent("[data-testid=ext-pane] .cm-content")) ?? "";
      assert(code.includes('return "hi " + n.Length;'), `ILSpy's C#: ${code.slice(0, 400)}`);
      assert((await p.getAttribute("[data-testid=ext-pane] [data-testid=ext-code]", "data-language")) === "csharp", "shown as C#");
      const status = (await p.textContent("[data-testid=ext-pane] [data-testid=ext-status]")) ?? "";
      assert(/ILSpy 11|ILSpy \d/.test(status), `the status names ILSpy: ${status}`);
      // Highlighted: a keyword's colour isn't the text's.
      const kw = await tokenColor(p, "[data-testid=ext-pane]", "public");
      assert(kw && kw.token !== kw.line, `"public" highlighted: ${JSON.stringify(kw)}`);
      assert(await p.isHidden("#cm"), "Ghidra's C hidden");
      await shot(p, "external-ilspy-pane");
      // Ghidra's C, then back (from the cache: no second run).
      await p.selectOption("[data-testid=ext-mode]", "native");
      assert(await p.isVisible("#cm"), "Ghidra's C shown");
      assert(await p.isHidden("[data-testid=ext-pane]"), "the C# hidden");
      await p.selectOption("[data-testid=ext-mode]", "external");
      assert(await p.isVisible("[data-testid=ext-pane]"), "the C# shown again");
      // Run again: the status says it ran (not "cached").
      await p.click("[data-testid=ext-pane] [data-testid=ext-rerun]");
      await p.waitForFunction(() => /\d+(\.\d)? s$/.test(document.querySelector("[data-testid=ext-pane] [data-testid=ext-status]")?.textContent ?? ""), null, { timeout: 60000 });
      // The output's other files: the project file is XML.
      const files = await p.$$eval("[data-testid=ext-file] option", (os) => os.map((o) => (o as HTMLOptionElement).value));
      const csproj = files.find((f) => f.endsWith(".csproj"));
      assert(csproj, `the files: ${JSON.stringify(files)}`);
      await p.selectOption("[data-testid=ext-file]", csproj);
      await p.waitForFunction(() => (document.querySelector("[data-testid=ext-pane] .cm-content")?.textContent ?? "").includes("<Project"), null, { timeout: 20000 });
      assert((await p.getAttribute("[data-testid=ext-pane] [data-testid=ext-code]", "data-language")) === "xml", "the project shown as XML");
    });
    await p.context().close();
  }

  const java = ["vineflower", "cfr", "jadx"].find(available);
  if (!has("javac") || !has("jar") || !java) {
    c.log("  (external decompilers: no JDK or JVM decompiler, the file system browser's part skipped)");
    return;
  }
  const jdir = path.join(c.dir, "java-tiny");
  mkdirSync(path.join(jdir, "src", "tiny"), { recursive: true });
  writeFileSync(path.join(jdir, "src", "tiny", "Tiny.java"), "package tiny;\npublic class Tiny {\n  public static int add(int a, int b) { int c = a + b; if (c > 10) c -= 3; return c * 2; }\n}\n");
  execFileSync("javac", ["--release", "8", "-nowarn", "-d", path.join(jdir, "classes"), path.join(jdir, "src", "tiny", "Tiny.java")], { stdio: "ignore" });
  execFileSync("jar", ["cf", path.join(jdir, "tiny.jar"), "tiny/Tiny.class"], { cwd: path.join(jdir, "classes") });
  const zip = path.join(c.dir, "app-bundle.zip");
  execFileSync(process.env.REVKIT_PYTHON || "python3", [
    "-I", "-c", "import sys, zipfile\nwith zipfile.ZipFile(sys.argv[2], 'w') as z: z.write(sys.argv[1], 'lib/tiny.jar'); z.writestr('readme.txt', 'hi')",
    path.join(jdir, "tiny.jar"), zip,
  ]);

  await check("external decompilers: the file system browser's Decompile with … on a jar inside a zip shows its files and their Java", async () => {
    const p = await c.page("program=default%2Fprog&user=e2e&theme=dark");
    await p.click("[data-testid=file-menu]");
    await p.click("[data-testid=file-open-filesystem]");
    await p.locator("[data-testid=choose] .palette-item", { hasText: "daemon host" }).click();
    await p.locator(`[data-testid=host-entry][data-path="${zip}"]`).click();
    await p.locator("[data-testid=fs-browser]").waitFor();
    const lib = p.locator('[data-testid=fs-row][data-path="/lib"]');
    await lib.waitFor();
    await lib.click();
    await p.keyboard.press("ArrowRight");
    const jar = p.locator('[data-testid=fs-row][data-path="/lib/tiny.jar"]');
    await jar.waitFor();
    await jar.click({ button: "right" });
    const item = p.locator(`[data-testid=fs-menu-decompile-${java}]`);
    await item.waitFor({ timeout: 15000 });
    // The other JVM decompilers are offered too (disabled when not installed).
    assert((await p.locator("[data-testid^=fs-menu-decompile-]").count()) === 3, "Vineflower, CFR and jadx offered");
    await item.click();
    await p.locator("[data-testid=ext-dialog]").waitFor();
    await p.waitForFunction(() => (document.querySelector("[data-testid=ext-dialog] .cm-content")?.textContent ?? "").includes("add(int"), null, { timeout: 60000 });
    const files = await p.$$eval("[data-testid=ext-f]", (rows) => rows.map((r) => (r as HTMLElement).dataset.path ?? ""));
    assert(files.some((f) => f.endsWith("Tiny.java")), `the output's files: ${JSON.stringify(files)}`);
    assert((await p.getAttribute("[data-testid=ext-dialog] [data-testid=ext-code]", "data-language")) === "java", "shown as Java");
    const kw = await tokenColor(p, "[data-testid=ext-dialog]", "public");
    assert(kw && kw.token !== kw.line, `"public" highlighted: ${JSON.stringify(kw)}`);
    // The filter narrows the files.
    await p.fill("[data-testid=ext-filter]", "no-such-file");
    const shown = await p.$$eval("[data-testid=ext-f]", (rows) => rows.filter((r) => !(r as HTMLElement).hidden).length);
    assert(shown === 0, `filtered out: ${shown}`);
    await p.fill("[data-testid=ext-filter]", "");
    await shot(p, "external-jar-dialog");
    // A file that isn't bytecode offers none.
    await p.keyboard.press("Escape");
    await p.locator("[data-testid=ext-dialog]").waitFor({ state: "detached" });
    const readme = p.locator('[data-testid=fs-row][data-path="/readme.txt"]');
    await readme.click({ button: "right" });
    await p.locator("[data-testid=fs-menu-info]").waitFor();
    assert((await p.locator("[data-testid^=fs-menu-decompile-]").count()) === 0, "nothing offered for a text file");
    await p.keyboard.press("Escape");
    await p.context().close();
  });
}
