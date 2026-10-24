// End-to-end checks for Apple applications (api_minor 100, feature
// "apple-bundles"; docs/apple-apps.md): tests/data/apple's fixtures built
// with clang and ld64.lld (skipped without them). The .ipa opened as a file
// system from the Open dialog; the bundle badge; Apple bundle… with what
// Info.plist says, the main executable's signature (marked not verified),
// the nested bundles and the provisioning profile; Import main executable
// bringing its framework; Property list… on Info.plist; and the imported
// program's Signed line and Signature… in the Open dialog. run.ts calls
// appleChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export interface AppleContext {
  base: string;
  dir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  page: (query: string) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
}

function which(...names: string[]): string | null {
  for (const name of names) {
    try {
      const p = execFileSync("sh", ["-c", `command -v ${name}`]).toString().trim();
      if (p) return p;
    } catch {
      /* the next */
    }
  }
  return null;
}

type Prog = { programId: string; name: string; containerPath?: string };

export async function appleChecks(c: AppleContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const tools = [which("clang"), which("ld64.lld", "ld64.lld-18")];
  if (tools.some((t) => !t)) {
    c.log("  (Apple bundles: no clang or ld64.lld, skipped)");
    return;
  }
  const fixture = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../tests/data/apple");
  const out = path.join(c.dir, "apple");
  fs.mkdirSync(out, { recursive: true });
  execFileSync("sh", [path.join(fixture, "build.sh"), ...(tools as string[]), out]);
  const ipa = path.join(out, "Demo.ipa");
  const programs = async () => (await rpc<{ programs?: Prog[] }>(base, "ProjectService/ListPrograms", { projectId: "default" })).programs ?? [];
  // A page on a program of its own (the macOS build; its framework isn't imported).
  const host = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", {
    projectId: "default", path: path.join(out, "bin", "MacDemo"), name: "MacDemo", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
  });
  const p = await c.page(`program=${encodeURIComponent(host.program.programId)}&user=e2e&theme=dark`);
  const row = (name: string) => p.locator(`[data-testid=fs-row][data-name="${name}"]`).first();
  const at = (path: string) => p.locator(`[data-testid=fs-row][data-path="${path}"]`);
  const expand = async (path: string) => {
    await at(path).click();
    await p.keyboard.press("ArrowRight");
  };

  await check("apple bundles: an .ipa's app badge, Apple bundle… (Info.plist, signature not verified, nested bundles, profile), Import main executable with its framework", async () => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+o");
    await p.click("[data-testid=open-import-binary]");
    const [chooser] = await Promise.all([p.waitForEvent("filechooser"), p.click("[data-testid=open-import]")]);
    await chooser.setFiles(ipa);
    await p.locator("[data-testid=open-as-filesystem]").waitFor();
    await p.click("[data-testid=open-as-filesystem]");
    await p.locator("[data-testid=fs-browser]").waitFor();
    await row("Payload").waitFor();
    await expand("/Payload");
    await row("Demo.app").waitFor();
    assert((await row("Demo.app").locator("[data-testid=fs-bundle-kind]").textContent()) === "app", "the app's badge");
    await row("Demo.app").click({ button: "right" });
    await p.click("[data-testid=fs-menu-bundle]");
    const dialog = p.locator("[data-testid=ap-bundle-dialog]");
    await dialog.locator("[data-testid=ap-bundle-id]").waitFor();
    assert((await dialog.locator("[data-testid=ap-bundle-id]").textContent()) === "com.example.demo", "the identifier");
    assert((await dialog.locator("[data-testid=ap-bundle-schemes]").textContent()) === "demo, demo-auth", "URL schemes");
    const sig = (await dialog.locator("[data-testid=ap-bundle-signature]").textContent()) ?? "";
    assert(sig.includes("team ABCDE12345") && sig.includes("hardened runtime"), `the signature line: ${sig}`);
    assert((await dialog.locator("[data-testid=ap-not-verified]").textContent())?.includes("not verified"), "says it isn't verified");
    assert((await dialog.locator("[data-testid=ap-sig-requirement]").textContent())?.includes("anchor apple generic"), "the requirement");
    await dialog.locator("[data-testid=ap-entitlements] [data-key=get-task-allow]").waitFor();
    assert((await dialog.locator("[data-testid=ap-nested-row]").count()) === 2, "a framework and an extension");
    assert((await dialog.locator("[data-testid=ap-profile-kind]").textContent()) === "development", "the profile's kind");
    assert((await dialog.locator("[data-testid=ap-usage]").textContent())?.includes("Scan codes with the camera."), "usage descriptions");
    // A nested bundle opens in place.
    await dialog.locator("[data-testid=ap-nested-row]", { hasText: "Share.appex" }).click();
    await p.waitForFunction(() => document.querySelector("[data-testid=ap-bundle-id]")?.textContent === "com.example.demo.share");
    await dialog.locator("[data-testid=ap-close]").click();
    // Import main executable: Demo, and Greeter.framework found by @rpath.
    await row("Demo.app").click({ button: "right" });
    await p.click("[data-testid=fs-menu-bundle]");
    await p.locator("[data-testid=ap-bundle-id]").waitFor();
    await p.click("[data-testid=ap-import-main]");
    await p.waitForFunction(() => /Imported 1 program and 1 library they need \(Greeter\)/.test(document.querySelector("[data-testid=fs-status]")?.textContent ?? ""), null, { timeout: 120000 });
    const names = (await programs()).map((x) => x.name);
    assert(names.includes("Demo") && names.includes("Greeter"), `imported: ${names}`);
    // UI actions (api_minor 101): traced to the imported Demo's methods; one opens the program there.
    await row("Demo.app").click({ button: "right" });
    await p.click("[data-testid=fs-menu-bundle]");
    const tap = p.locator('[data-testid=ap-ui-action][data-selector="buttonTapped:"]');
    await tap.waitFor({ timeout: 30000 });
    assert((await tap.getAttribute("data-resolution")) === "resolved", `buttonTapped: ${await tap.getAttribute("data-resolution")}`);
    assert((await tap.textContent())?.includes("touchUpInside"), "its event");
    assert((await tap.textContent())?.includes("File's Owner (ViewController)"), `its target: ${await tap.textContent()}`);
    assert((await p.textContent("[data-testid=ap-ui-title]"))?.includes("resolved in Demo"), "resolved in Demo");
    assert((await p.locator('[data-testid=ap-ui-action][data-selector="copyAll:"]').getAttribute("data-resolution")) === "resolved-by-selector", "copyAll: by selector");
    const demo = (await programs()).find((x) => x.name === "Demo")!;
    await Promise.all([p.waitForEvent("load"), tap.locator("[data-testid=ap-ui-method]").click()]);
    await p.waitForSelector("body[data-ready='1']", { timeout: 30000 });
    const url = new URL(p.url());
    assert(url.searchParams.get("program") === demo.programId && url.hash.length > 1, `opened ${p.url()}`);
  });

  await check("apple bundles: Property list… on Info.plist; the program's Signed line and Signature… in the Open dialog", async () => {
    // (The page is on Demo now; open the .ipa again.)
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+o");
    await p.click("[data-testid=open-import-binary]");
    const [chooser] = await Promise.all([p.waitForEvent("filechooser"), p.click("[data-testid=open-import]")]);
    await chooser.setFiles(ipa);
    await p.locator("[data-testid=open-as-filesystem]").waitFor();
    await p.click("[data-testid=open-as-filesystem]");
    await row("Payload").waitFor();
    await expand("/Payload");
    await row("Demo.app").waitFor();
    await expand("/Payload/Demo.app");
    await row("Info.plist").waitFor();
    await row("Info.plist").click({ button: "right" });
    await p.click("[data-testid=fs-menu-plist]");
    await p.locator("[data-testid=ap-plist-format]").waitFor();
    assert((await p.textContent("[data-testid=ap-plist-format]"))?.startsWith("Binary property list"), "binary");
    await p.locator("[data-testid=ap-plist-dialog] [data-key=CFBundleIdentifier]").waitFor();
    await p.locator("[data-testid=ap-plist-dialog] [data-testid=ap-close]").click();
    await p.click("[data-testid=fs-close]");
    // The Open dialog: the imported Demo's signature (the visible dialog: the one the .ipa came
    // through may still be open beneath).
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+o");
    await p.locator("[data-testid=open-row]:visible", { hasText: /^Demo/ }).first().click();
    const signed = p.locator("[data-testid=open-detail-signature]:visible");
    await p.waitForFunction(() => [...document.querySelectorAll("[data-testid=open-detail-signature]")].some((x) => (x.textContent ?? "").includes("com.example.demo")), null, { timeout: 30000 })
      .catch(async (e) => {
        const shown = await p.evaluate(() => [...document.querySelectorAll("[data-testid^=open-detail]")].map((x) => `${x.getAttribute("data-testid")}=${x.textContent}`).join(" | "));
        throw new Error(`${e}; the details: ${shown}`);
      });
    await signed.last().locator("[data-testid=open-signature]").click();
    await p.locator("[data-testid=ap-sig-team]").waitFor();
    assert((await p.textContent("[data-testid=ap-sig-team]")) === "ABCDE12345", "the team");
    assert((await p.textContent("[data-testid=ap-sig-flags]"))?.includes("runtime"), "hardened runtime");
  });
  await p.context().close();
}
