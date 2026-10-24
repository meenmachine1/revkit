// End-to-end checks for Android packages (api_minor 98, feature "android";
// docs/android.md, docs/ui.md "Android packages"): an APK written by
// tests/data/android/make_apk.py (with JNI and Flutter libraries compiled
// for the host) opened from the daemon host in the file system browser, its
// Android… dialog: the manifest's fields and components, the XML with
// references resolved, the French strings, the native libraries and
// methods, Flutter's snapshot hash; then a JNI library imported with the
// library it needs. run.ts calls androidChecks() with its helpers.

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import path from "node:path";

export interface AndroidContext {
  base: string;
  exe: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  open: (base: string, query?: string, hash?: string, dpr?: number) => Promise<Page>;
  until: <T>(p: Page, what: string, pred: (s: T) => boolean, ms?: number) => Promise<T>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
}

interface Snap {
  decompName: string | null;
  live: string;
}

type Prog = { programId: string; name: string; containerPath?: string };

export async function androidChecks(c: AndroidContext) {
  const { base, check, open, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const apk = path.join(path.dirname(c.exe), "droid.apk");
  const gen = path.resolve(import.meta.dirname, "../../tests/data/android/make_apk.py");
  execFileSync(process.env.REVKIT_PYTHON || "python3", ["-I", gen, apk, "--cc", "cc:x86_64", "--flutter"]);
  const ready = (p: Page) => c.until<Snap>(p, "ready", (s) => s.decompName === "main" && s.live === "live");
  const programs = async () => (await rpc<{ programs?: Prog[] }>(base, "ProjectService/ListPrograms", { projectId: "default" })).programs ?? [];
  const text = async (p: Page, sel: string) => (await p.locator(sel).first().textContent()) ?? "";

  await check("android: an APK's manifest, XML, strings, native libraries and methods, Flutter hash; a JNI library imported with its neighbour", async () => {
    const p = await open(base);
    await ready(p);
    await p.click("[data-testid=file-menu]");
    await p.click("[data-testid=file-open-filesystem]");
    await p.locator("[data-testid=choose] .palette-item", { hasText: "daemon host" }).click();
    await p.locator(`[data-testid=host-entry][data-path="${apk}"]`).click();
    await p.locator("[data-testid=fs-browser]").waitFor();
    const btn = p.locator("[data-testid=fs-android]");
    await btn.waitFor({ state: "visible" });
    await btn.click();
    const dlg = p.locator("[data-testid=and-dialog]");
    await dlg.waitFor();
    await p.locator("[data-testid=and-package]").waitFor();
    assert((await text(p, "[data-testid=and-package]")) === "com.example.droid", "the package");
    assert((await text(p, "[data-testid=and-version]")).includes("1.2.3 (code 7)"), "the version");
    assert((await text(p, "[data-testid=and-sdk]")).startsWith("min 24 · target 34"), `the SDK: ${await text(p, "[data-testid=and-sdk]")}`);
    assert((await text(p, "[data-testid=and-debuggable]")) === "true", "debuggable");
    assert((await p.locator("[data-testid=and-debuggable] .and-risk").count()) === 1, "debuggable is marked");
    assert((await text(p, "[data-testid=and-cleartext]")) === "true", "cleartext through @bool/cleartext");
    const deep = p.locator('[data-testid=and-component][data-name="com.example.droid.DeepLinkActivity"]');
    assert((await deep.textContent())?.includes("yes (implied)"), "an exported flag implied by an intent filter");
    assert((await deep.textContent())?.includes("https://example.com/open"), "its filter's data");
    // The network security config, decoded.
    await p.click("[data-testid=and-nsc-show]");
    await p.locator("[data-testid=and-xml-file]", { hasText: "domain-config" }).waitFor();
    await p.keyboard.press("Escape");
    // XML, resolved.
    await p.click("[data-testid=and-tab-xml]");
    await p.locator("[data-testid=and-manifest-xml]", { hasText: 'android:label="@string/app_name"' }).waitFor();
    await p.click("[data-testid=and-resolve]");
    await p.locator("[data-testid=and-manifest-xml]", { hasText: 'android:label="Droid Test"' }).waitFor();
    // Resources: the French strings.
    await p.click("[data-testid=and-tab-resources]");
    await p.locator('[data-testid=and-resource][data-name="@string/app_name"]').waitFor();
    await p.locator("[data-testid=and-res-config] option[value=fr]").waitFor({ state: "attached" });
    await p.selectOption("[data-testid=and-res-config]", "fr");
    await p.locator("[data-testid=and-resource]", { hasText: "Bonjour, le monde !" }).waitFor();
    assert((await p.locator("[data-testid=and-resource]").count()) === 2, "two French strings");
    await p.fill("[data-testid=and-res-filter]", "bonjour");
    await p.locator("[data-testid=and-res-count]", { hasText: "1 entry" }).waitFor();
    // Native libraries and methods.
    await p.click("[data-testid=and-tab-native]");
    const lib = p.locator('[data-testid=and-lib][data-name="libnative.so"]');
    await lib.waitFor();
    assert((await lib.textContent())?.includes("5 Java_ · JNI_OnLoad"), `libnative's JNI: ${await lib.textContent()}`);
    assert((await p.locator('[data-testid=and-lib][data-name="libapp.so"]').textContent())?.includes("Flutter app"), "libapp is Flutter's");
    const methods = p.locator("[data-testid=and-method]");
    assert((await methods.count()) === 6, "six native methods");
    assert((await methods.filter({ hasText: "registered()V" }).textContent())?.includes("registered at run time"), "one bound at run time");
    assert((await methods.filter({ hasText: "add(JJ)J" }).textContent())?.includes("lib/x86_64/libnative.so"), "an overload by its long name");
    // Flutter.
    await p.click("[data-testid=and-tab-flutter]");
    assert((await text(p, "[data-testid=and-flutter-hash]")) === "90b56a561f70cd55e972cb49b79b3d8b", "the snapshot hash");
    assert((await text(p, "[data-testid=and-flutter-build-x86_64]")).length === 40, "the engine's build id");
    // Import libnative.so: libhelper.so comes with it, linked.
    await p.click("[data-testid=and-tab-native]");
    await lib.locator("[data-testid=and-lib-import]").click();
    await p.locator("[data-testid=fs-status]", { hasText: "libhelper.so" }).waitFor({ timeout: 60000 });
    const progs = await programs();
    const native = progs.find((x) => x.name === "libnative.so");
    assert(native && native.containerPath === "zip://droid.apk!/lib/x86_64/libnative.so", `libnative imported: ${JSON.stringify(progs.map((x) => x.name))}`);
    assert(progs.some((x) => x.name === "libhelper.so"), "libhelper.so imported with it");
    const libs = await rpc<{ libraries?: { name: string; programId?: string }[] }>(base, "ProjectService/ListProgramLibraries", { programId: native.programId });
    assert(libs.libraries?.some((l) => l.name === "libhelper.so" && l.programId), "libhelper.so linked");
    await p.click("[data-testid=and-close]");
    await p.close();
  });
}
