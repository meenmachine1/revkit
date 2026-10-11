// Change language… (api_minor 73, feature "set-language"; docs/ui.md
// "Changing the language"): the dialog compares the processor's variants on
// the program's code, marks the current language and auto-detection's pick,
// and keeps Switch off while the current language is chosen; Escape closes
// it; while a switch runs, the import's progress bar follows it (the call
// held back and refused here). Switching itself is covered by the backend's tests
// (RawRebaseTest.TheLanguageChangesInPlaceAndBack), so the shared test
// program stays in its language for the checks after this one.
// run.ts calls languageChecks().

import type { Page } from "playwright";

export interface LanguageContext {
  base: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  open: (base: string, query?: string, hash?: string, dpr?: number) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
}

export async function languageChecks(c: LanguageContext) {
  const { base, check, open, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", {});
  if (!(info.features ?? []).includes("set-language")) return;

  await check("change language: the variants compared on the code, the current one marked, Switch off for it", async () => {
    const p = await open(base);
    await p.click("#analyzemenu");
    await p.click("[data-testid=menu] .menu-item:has-text('Change language')");
    await p.waitForSelector("[data-testid=lang-dialog]");
    await p.waitForSelector("[data-testid=lang-row]", { timeout: 60000 });
    const rows = await p.locator("[data-testid=lang-row]").count();
    assert(rows >= 1, `variant rows: ${rows}`);
    assert((await p.locator("[data-testid=lang-now]").count()) >= 1, "the current language is marked");
    assert(/bytes of code in \d+ samples/.test((await p.textContent("[data-testid=lang-meta]")) ?? ""), "what was swept");
    assert(await p.isDisabled("[data-testid=lang-apply]"), "Switch is off while the current language is chosen");
    await p.keyboard.press("Escape");
    await p.waitForSelector("[data-testid=lang-dialog]", { state: "detached" });
    await p.context().close();
  });

  await check("change language: Switch shows the import's progress bar while the program is analyzed again; a refusal gives the dialog back", async () => {
    const p = await open(base);
    // Held back, then refused here: the shared program keeps its language.
    await p.route("**/revkit.v1.ProjectService/SetProgramLanguage", async (route) => {
      await new Promise((r) => setTimeout(r, 1500));
      await route.fulfill({ status: 400, contentType: "application/json", body: JSON.stringify({ code: "failed_precondition", message: "held back by the test" }) });
    });
    await p.click("#analyzemenu");
    await p.click("[data-testid=menu] .menu-item:has-text('Change language')");
    await p.waitForSelector("[data-testid=lang-row]", { timeout: 60000 });
    const current = await p.inputValue("[data-testid=lang-other]");
    const another = (await p.$$eval("[data-testid=lang-other] option", (os) => os.map((o) => (o as HTMLOptionElement).value))).find((v) => v !== current);
    assert(another, "another language of the processor to pick");
    await p.selectOption("[data-testid=lang-other]", another);
    await p.click("[data-testid=lang-apply]");
    const bar = "[data-testid=lang-dialog] [data-testid=import-progress]";
    await p.waitForSelector(`${bar}:not([hidden])`);
    assert((await p.getAttribute(`${bar} [data-testid=import-bar]`, "aria-label")) === "Language switch progress", "the bar is the switch's");
    assert(/^Switching to /.test((await p.textContent(`${bar} [data-testid=import-progress-text]`)) ?? ""), "what it is doing");
    assert(await p.isDisabled("[data-testid=lang-apply]"), "Switch is off while it runs");
    await p.waitForSelector(bar, { state: "hidden", timeout: 10000 });
    assert(!(await p.isDisabled("[data-testid=lang-apply]")), "Switch is back after the refusal");
    await p.keyboard.press("Escape");
    await p.context().close();
  });

  await check("change language: refused for a language that lays memory out differently, allowed back to the imported one", async () => {
    let refused = "";
    try {
      await rpc(base, "ProjectService/SetProgramLanguage", { programId: "default/prog", languageId: "avr8:LE:16:default", validateOnly: true, provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
    } catch (e) {
      refused = String(e);
    }
    assert(/lays memory out differently/.test(refused), `refused: ${refused}`);
    const ok = await rpc<{ languageId?: string; assertion?: unknown }>(base, "ProjectService/SetProgramLanguage", { programId: "default/prog", languageId: "", validateOnly: true });
    assert(!ok.assertion, "validate_only asserts nothing");
  });
}
