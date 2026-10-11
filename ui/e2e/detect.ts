// End-to-end checks for raw layout detection in the Open dialog (feature
// "raw-detect", api_minor 23; src/ui/rawdetect.ts): a file that isn't ELF
// or PE gets its raw import options suggested, each with a confidence chip
// and its evidence, alternatives from a menu, the user's own values kept,
// and nothing imported until the user chooses Import as raw; a refusal with
// its reason and nothing filled in; a typed language as a hint; skipping
// detection; and the dialog's accessibility with suggestions shown. Also
// the picked file shown throughout, the one Import as raw button (no raw
// checkbox), the regions' High confidence only / Select all / Select none,
// and regions that overlap the image marked and never sent.
// run.ts calls detectChecks() with its helpers. The firmware is generated
// here (src/analysis/tests/fixtures/armfw scaled up), the noise is random.

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import path from "node:path";
import { audit } from "./a11y";

export interface DetectContext {
  base: string;
  /** The test program (an ELF). */
  exe: string;
  root: string;
  tmp: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  open: (base: string, query?: string, hash?: string, dpr?: number) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  log: (s: string) => void;
}

const shotsDir = process.env.RK_SHOTS;

export async function detectChecks(c: DetectContext) {
  const { base, check, open, rpc, log } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", {});
  if (!(info.features ?? []).includes("raw-detect")) {
    log("  (raw detection checks skipped: the daemon predates raw-detect)");
    return;
  }
  // ARMv4T firmware with 300 generated functions (34 KB, about a second
  // to detect; minutes under a sanitizer on a busy machine), and 64 KB of
  // random bytes.
  const fw = path.join(c.tmp, "armfw-detect");
  try {
    execFileSync("sh", [path.join(c.root, "src/analysis/tests/fixtures/armfw/build.sh"), "clang", "ld.lld", "llvm-objcopy", fw, "-O2", "300"], { stdio: "ignore" });
  } catch {
    log("  (raw detection checks skipped: need clang, ld.lld, llvm-objcopy and python3)");
    return;
  }
  const image = path.join(fw, "fw.bin");
  const noise = path.join(c.tmp, "noise.bin");
  writeFileSync(noise, randomBytes(64 << 10));

  type Prog = { programId: string; name: string; languageId: string };
  const programs = async () => (await rpc<{ programs?: Prog[] }>(base, "ProjectService/ListPrograms", { projectId: "default" })).programs ?? [];
  const dialog = async (p: Page) => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+o");
    await p.waitForSelector("[data-testid=open-dialog]");
    // The import section: Choose file…, the daemon host, a path, raw.
    await p.click("[data-testid=open-import-binary]");
    await p.waitForSelector("[data-testid=open-import-view]:not([hidden])");
  };
  const detectState = (p: Page) => p.getAttribute("[data-testid=raw-options]", "data-detect");
  const untilDetect = async (p: Page, state: string, ms = 300000) => {
    try {
      await p.waitForFunction((s) => document.querySelector("[data-testid=raw-options]")?.getAttribute("data-detect") === s, state, { timeout: ms });
    } catch {
      const now = await p.evaluate(() => [
        document.querySelector("[data-testid=raw-options]")?.getAttribute("data-detect") ?? "(none)",
        document.querySelector(".open-status")?.textContent ?? "",
        document.querySelector("[data-testid=import-progress-text]")?.textContent ?? "",
      ]);
      throw new Error(`timed out waiting for detection "${state}": it is "${now[0]}"; status "${now[1]}"; bar "${now[2]}"`);
    }
  };
  const field = (p: Page, key: string) =>
    p.evaluate((k) => {
      const el = document.querySelector(`[data-testid=raw-field-${k}]`) as HTMLElement | null;
      const input = el?.querySelector("input, textarea") as HTMLInputElement | null;
      return {
        value: input?.value ?? "",
        state: el?.dataset.state ?? "",
        chips: [...(el?.querySelectorAll("[data-testid=raw-chip]") ?? [])].map((x) => `${x.textContent}/${(x as HTMLElement).dataset.level}`),
        why: [...(el?.querySelectorAll("[data-testid=raw-why] li") ?? [])].map((x) => x.textContent ?? ""),
      };
    }, key);
  const menuItems = (p: Page) => p.locator("[data-testid=menu] .menu-item").allTextContents();
  // The picked file as the dialog shows it.
  const pickedFile = (p: Page) =>
    p.evaluate(() => {
      const el = document.querySelector("[data-testid=open-picked]") as HTMLElement | null;
      const [name, where, size] = ["name", "where", "size"].map((k) => el?.querySelector(`[data-testid=open-picked-${k}]`)?.textContent ?? "");
      return { shown: !!el && !el.hidden && el.getBoundingClientRect().height > 0, name, where, size };
    });
  const status = async (p: Page) => (await p.textContent(".open-status")) ?? "";

  await check("raw detection: a file that isn't ELF or PE gets raw options suggested, with confidence and evidence; the user confirms", async () => {
    const beforeIds = new Set((await programs()).map((x) => x.programId));
    const before = beforeIds.size;
    const p = await open(base);
    // Every state the bar shows during the detection.
    type Shown = { state: string; phase: string; text: string; now: string | null; label: string };
    const shown: Shown[] = [];
    await p.exposeFunction("__detectProgress", (s: Shown) => void shown.push(s));
    await p.evaluate(() => {
      const send = (window as unknown as { __detectProgress: (s: unknown) => void }).__detectProgress;
      let last = "";
      new MutationObserver(() => {
        const el = document.querySelector("[data-testid=import-progress]") as HTMLElement | null;
        if (!el || el.hidden) return;
        const bar = el.querySelector("[role=progressbar]");
        const s = {
          state: el.dataset.state ?? "",
          phase: el.dataset.phase ?? "",
          text: el.querySelector("[data-testid=import-progress-text]")?.textContent ?? "",
          now: bar?.getAttribute("aria-valuenow") ?? null,
          label: bar?.getAttribute("aria-label") ?? "",
        };
        const key = JSON.stringify(s);
        if (key !== last) send(s);
        last = key;
      }).observe(document.body, { subtree: true, childList: true, attributes: true, characterData: true });
    });
    await dialog(p);
    await p.fill("[data-testid=open-path]", image);
    await p.press("[data-testid=open-path]", "Enter");
    // The file is named from the moment it is picked.
    const atPick = await pickedFile(p);
    assert(atPick.shown && atPick.name === "fw.bin" && atPick.where === image, `the picked file is shown: ${JSON.stringify(atPick)}`);
    // The ELF/PE import fails, detection starts on its own.
    await untilDetect(p, "running", 30000);
    assert(await p.isVisible("[data-testid=raw-detect-skip]"), "Skip detection is offered while it runs");
    const during = await pickedFile(p);
    assert(during.shown && during.name === "fw.bin", `the file is named during detection: ${JSON.stringify(during)}`);
    assert(/fw\.bin/.test(await status(p)), `the detection status names the file: ${await status(p)}`);
    await untilDetect(p, "suggested");
    const after = await pickedFile(p);
    assert(after.shown && after.name === "fw.bin" && after.where === image && /KB/.test(after.size), `the file, where it is and its size after the suggestions: ${JSON.stringify(after)}`);
    if (shotsDir) await p.locator("[data-testid=open-dialog]").screenshot({ path: path.join(shotsDir, "raw-detect.png") }).catch(() => {});
    log(`     ${shown.length} states: ${shown.map((s) => `${s.now ?? "…"}% ${s.text}`).join(" | ").slice(0, 300)}`);
    assert(shown.some((s) => s.label === "Detection progress" && /languages/.test(s.text)), `the bar said what detection was doing: ${JSON.stringify(shown)}`);
    const fractions = shown.filter((s) => s.now !== null).map((s) => Number(s.now));
    assert(fractions.every((v, i) => i === 0 || v >= fractions[i - 1]), `the bar never goes back: ${fractions.join(" ")}`);
    assert(shown[shown.length - 1]?.state === "done", `the bar ends done: ${JSON.stringify(shown[shown.length - 1])}`);
    assert(!(await p.isVisible("[data-testid=raw-detect-skip]")), "Skip detection goes once it ends");

    // The language field: ARM, little-endian, with its chips and evidence.
    const lang = await field(p, "language");
    assert(/^ARM:LE:32:/.test(lang.value), `language suggested: ${JSON.stringify(lang)}`);
    assert(lang.state === "suggested", `language state ${lang.state}`);
    assert(lang.chips.some((x) => /^processor (high|medium|low)\//.test(x)) && lang.chips.some((x) => /^variant /.test(x)), `chips: ${lang.chips}`);
    assert(lang.why.some((w) => /instructions decode/.test(w)), `why: ${lang.why}`);
    // The evidence is behind an expander, closed until asked.
    const why = p.locator("[data-testid=raw-field-language] [data-testid=raw-why]");
    assert(!(await why.evaluate((d) => (d as HTMLDetailsElement).open)), "the evidence starts folded");
    await why.locator("summary").click();
    assert(await why.locator("li").first().isVisible(), "the evidence unfolds");
    const baseField = await field(p, "base");
    assert(baseField.chips.length > 0, `the load address says how sure it is: ${JSON.stringify(baseField)}`);
    assert(/Suggested from fw\.bin's bytes/.test((await p.textContent("[data-testid=raw-detected]")) ?? ""), "a summary of what was detected, naming the file");
    assert(/fw\.bin/.test(await status(p)), `the status names the file: ${await status(p)}`);
    assert(await p.isVisible("[data-testid=raw-segments]"), "the file's map");
    // Nothing imported yet.
    assert((await programs()).length === before, "detection imports nothing");

    // Regions: a row each, with its own chip and evidence; ticked rows are
    // the lines in the regions box, and a row's edits go there.
    const rows = p.locator("[data-testid=raw-region-row]");
    let region = "";
    if (await rows.count()) {
      const row = rows.first();
      const spec = await row.locator("[data-testid=raw-region-spec]").inputValue();
      const lines = async () => (await p.inputValue("[data-testid=raw-regions]")).split("\n").map((l) => l.trim()).filter(Boolean);
      assert((await row.locator("[data-testid=raw-chip]").count()) === 1, "a confidence chip per region");
      assert(/^(RAM|MMIO|memory) (high|medium|low)$/.test((await row.locator("[data-testid=raw-chip]").textContent()) ?? ""), "the chip names the kind and confidence");
      assert((await row.locator("[data-testid=raw-why] li").count()) > 0, "evidence per region");
      const ticked = await row.locator("[data-testid=raw-region-include]").isChecked();
      assert(ticked === (await lines()).includes(spec), `ticked ${ticked}: ${spec} in ${await lines()}`);
      if (!ticked) await row.locator("[data-testid=raw-region-include]").check();
      assert((await lines()).includes(spec), "ticked: in the box");
      await row.locator("[data-testid=raw-region-include]").uncheck();
      assert(!(await lines()).includes(spec), "unticked: out of the box");
      // Renamed while unticked, then ticked: the box has the edited line.
      region = spec.replace(/^[^:]+/, "detected");
      await row.locator("[data-testid=raw-region-spec]").fill(region);
      await row.locator("[data-testid=raw-region-include]").check();
      assert((await lines()).includes(region) && !(await lines()).includes(spec), `the edited region in the box: ${await lines()}`);

      // High confidence only, Select all, Select none: the rows and the box agree.
      const state = () =>
        p.$$eval("[data-testid=raw-region-row]", (rs) =>
          rs.map((r) => ({ level: (r as HTMLElement).dataset.level, ticked: (r.querySelector("[data-testid=raw-region-include]") as HTMLInputElement).checked, spec: (r.querySelector("[data-testid=raw-region-spec]") as HTMLInputElement).value })));
      const agree = async (what: string, want: (r: { level?: string }) => boolean) => {
        const rs = await state();
        const box = await lines();
        assert(rs.every((r) => r.ticked === want(r)), `${what}: ${JSON.stringify(rs)}`);
        assert(rs.every((r) => box.includes(r.spec) === r.ticked), `${what}: the box follows the rows: ${box} vs ${JSON.stringify(rs)}`);
      };
      await p.click("[data-testid=raw-regions-all]");
      await agree("Select all", () => true);
      await p.click("[data-testid=raw-regions-none]");
      await agree("Select none", () => false);
      await p.click("[data-testid=raw-regions-high]");
      await agree("High confidence only", (r) => r.level === "high");
      // From the keyboard: Enter on a focused tool presses it (not the program list's Enter).
      await p.focus("[data-testid=raw-regions-all]");
      await p.keyboard.press("Enter");
      await agree("Select all (keyboard)", () => true);
      await p.focus("[data-testid=raw-regions-none]");
      await p.keyboard.press(" ");
      await agree("Select none (keyboard)", () => false);
      assert(/0 of \d+ ticked/.test((await p.textContent("[data-testid=raw-region-count]")) ?? ""), "the count follows");
      // Only the renamed region, for the import below.
      await row.locator("[data-testid=raw-region-include]").check();

      // A ticked region over the image: an error on its row, the import not
      // sent, and Clip leaves what lies outside.
      const baseHex = (await p.inputValue("[data-testid=raw-base]")).trim() || "0";
      const over = `detected:${baseHex.replace(/^0x/i, "")}:100000:rw-`;
      await row.locator("[data-testid=raw-region-spec]").fill(over);
      const err = row.locator("[data-testid=raw-region-error]");
      assert(await err.isVisible(), "the overlap is marked on its row");
      const errText = (await err.locator("[data-testid=raw-region-error-text]").textContent()) ?? "";
      assert(/^overlaps the image \(0x[0-9a-f]+–0x[0-9a-f]+\)$/.test(errText), `the error names the image's range: ${errText}`);
      assert((await row.locator("[data-testid=raw-region-spec]").getAttribute("aria-invalid")) === "true", "the region's field is marked invalid");
      const progs = (await programs()).length;
      await p.click("[data-testid=raw-import]");
      await p.waitForFunction(() => /not imported/.test(document.querySelector(".open-status")?.textContent ?? ""), null, { timeout: 30000 });
      assert(/fw\.bin not imported: a region overlaps/.test(await status(p)), `the status says why: ${await status(p)}`);
      await p.waitForTimeout(500);
      assert((await programs()).length === progs, "an overlapping region is never sent");
      assert(await p.evaluate(() => document.activeElement?.getAttribute("data-testid") === "raw-region-clip"), "focus goes to the fix");
      if (shotsDir) await p.locator("[data-testid=open-dialog]").screenshot({ path: path.join(shotsDir, "raw-region-overlap.png") }).catch(() => {});
      await row.locator("[data-testid=raw-region-clip]").click();
      const clipped = await row.locator("[data-testid=raw-region-spec]").inputValue();
      const imageEnd = BigInt(errText.match(/–(0x[0-9a-f]+)/)![1]) + 1n;
      assert(clipped.startsWith(`detected:${imageEnd.toString(16)}:`), `clipped to after the image (${imageEnd.toString(16)}): ${clipped}`);
      assert(!(await err.isVisible()) && (await lines()).includes(clipped), `clipped and still ticked: ${await lines()}`);
      // Untick, the other fix.
      await row.locator("[data-testid=raw-region-spec]").fill(over);
      await row.locator("[data-testid=raw-region-untick]").click();
      assert(!(await row.locator("[data-testid=raw-region-include]").isChecked()) && !(await err.isVisible()), "unticked, the error goes");
      await row.locator("[data-testid=raw-region-spec]").fill(region);
      await row.locator("[data-testid=raw-region-include]").check();
    } else {
      log("     (no regions detected in this image; region rows not checked)");
    }
    // A line typed in the box over the image: listed under the regions, with Remove.
    {
      const baseHex = (await p.inputValue("[data-testid=raw-base]")).trim() || "0";
      const box = await p.inputValue("[data-testid=raw-regions]");
      await p.fill("[data-testid=raw-regions]", `${box}\ntyped:${baseHex.replace(/^0x/i, "")}:4`.trim());
      const problem = p.locator("[data-testid=raw-region-problem]");
      assert((await problem.count()) === 1 && /overlaps the image \(0x/.test((await problem.textContent()) ?? ""), `a typed overlap is listed: ${await problem.allTextContents()}`);
      await problem.locator("[data-testid=raw-region-remove]").click();
      assert((await problem.count()) === 0 && !(await p.inputValue("[data-testid=raw-regions]")).includes("typed:"), "Remove takes it out of the box");
    }

    // Alternatives: the languages the same evidence fits, and the other suggestions.
    await p.click("[data-testid=raw-field-language] [data-testid=raw-alternatives]");
    await p.waitForSelector("[data-testid=menu]");
    const items = await menuItems(p);
    assert(items.some((t) => /^ARM:LE:32:\S+ · same evidence/.test(t)), `tie group in the menu: ${items}`);
    const others = await p.locator("[data-testid=raw-alt-suggestion]").count();
    assert(others >= 1, `other suggestions in the menu: ${items}`);
    // The user's own load address stays through choosing another suggestion.
    await p.keyboard.press("Escape");
    await p.fill("[data-testid=raw-base]", "0");
    assert((await field(p, "base")).state === "edited", "a typed load address is the user's");
    await p.click("[data-testid=raw-field-language] [data-testid=raw-alternatives]");
    await p.locator("[data-testid=raw-alt-suggestion]").first().click();
    const other = await field(p, "language");
    assert(!/^ARM:LE:32:/.test(other.value) || other.value !== lang.value, `another suggestion chosen: ${other.value}`);
    assert((await p.inputValue("[data-testid=raw-base]")) === "0", "the user's load address stayed");
    // Back to the first suggestion, then a language of its tie group.
    await p.click("[data-testid=raw-field-language] [data-testid=raw-alternatives]");
    await p.locator("[data-testid=raw-alt-suggestion]", { hasText: `${lang.value} ·` }).first().click();
    assert((await p.inputValue("[data-testid=raw-language]")) === lang.value, "the first suggestion again");
    await p.click("[data-testid=raw-field-language] [data-testid=raw-alternatives]");
    // ARMv7 when the group has it (ARMv4 and v5 without Thumb don't load yet:
    // docs/autodetect.md, Risks).
    const v7 = p.locator("[data-testid=raw-alt-tie]", { hasText: "ARM:LE:32:v7 ·" });
    const tie = (await v7.count()) ? v7.first() : p.locator("[data-testid=raw-alt-tie]").first();
    const tied = ((await tie.textContent()) ?? "").split(" ·")[0];
    await tie.click();
    assert((await p.inputValue("[data-testid=raw-language]")) === tied, `a tie group member chosen: ${tied}`);
    // A language typed over the suggestion is the user's, with the suggestion offered back.
    await p.fill("[data-testid=raw-language]", tied === "ARM:LE:32:v5t" ? "ARM:LE:32:v6" : "ARM:LE:32:v5t");
    const typed = await field(p, "language");
    assert(typed.state === "edited" && typed.chips.some((x) => x.startsWith("edited")), `typed language: ${JSON.stringify(typed)}`);
    await p.click("[data-testid=raw-field-language] [data-testid=raw-use]");
    assert((await p.inputValue("[data-testid=raw-language]")) === tied, "Use puts the suggestion back");
    assert((await programs()).length === before, "still nothing imported");

    // The user confirms: the import uses what the fields say.
    await p.click("[data-testid=raw-import]");
    await p.waitForURL(/program=default%2Ffw\.bin/, { timeout: 300000 }).catch(async (e) => {
      throw new Error(`${e}; status: ${await p.textContent(".open-status").catch(() => "")}`);
    });
    await p.waitForSelector("body[data-ready='1']", { timeout: 300000 });
    const imported = (await programs()).find((x) => !beforeIds.has(x.programId));
    assert(imported && imported.languageId.startsWith(tied), `imported as ${tied}: ${JSON.stringify(imported)}`);
    if (region) {
      const sum = await rpc<{ summary?: { memory?: { name: string }[] } }>(base, "ProjectService/GetProgramSummary", { programId: imported.programId });
      const names = (sum.summary?.memory ?? []).map((m) => m.name);
      assert(names.includes("detected"), `the region imported: ${names}`);
    }
    await p.context().close();
  });

  await check("raw detection: random bytes are refused with the reason, the guesses shown and nothing filled in", async () => {
    const before = (await programs()).length;
    const p = await open(base);
    await dialog(p);
    // One way to import as raw: no checkbox, and the raw options' own
    // button, shown with them.
    assert((await p.locator("[data-testid=raw-on]").count()) === 0, "no raw checkbox");
    assert((await p.locator("[data-testid=raw-import]").count()) === 1, "one Import as raw button");
    assert(!(await p.isVisible("[data-testid=raw-import]")), "Import as raw hides with the raw options closed");
    assert(!(await pickedFile(p)).shown, "no file shown before one is picked");
    await p.click("[data-testid=raw-options] summary");
    assert(await p.isVisible("[data-testid=raw-import]"), "Import as raw shows with the raw options open");
    await p.click("[data-testid=raw-options] summary");
    assert(!(await p.isVisible("[data-testid=raw-import]")), "and hides again when they close");
    await p.fill("[data-testid=open-path]", noise);
    await p.press("[data-testid=open-path]", "Enter");
    await untilDetect(p, "refused");
    assert(await p.isVisible("[data-testid=raw-import]"), "a file that isn't ELF or PE opens the raw options with Import as raw");
    const noisePick = await pickedFile(p);
    assert(noisePick.shown && noisePick.name === "noise.bin" && noisePick.where === noise && /64\.0 KB/.test(noisePick.size), `the refused file is shown: ${JSON.stringify(noisePick)}`);
    const refusal = p.locator("[data-testid=raw-refusal]");
    assert((await refusal.getAttribute("data-reason")) === "high-entropy", `reason ${await refusal.getAttribute("data-reason")}`);
    const text = (await refusal.textContent()) ?? "";
    assert(/compressed or encrypted/.test(text) && /noise\.bin/.test(text), `the reason in words, naming the file: ${text}`);
    for (const k of ["language", "base", "offset", "regions"]) {
      const f = await field(p, k);
      assert(f.value === "" && f.state === "none", `${k} not filled in: ${JSON.stringify(f)}`);
    }
    assert(/not detected/i.test((await p.textContent(".open-status")) ?? ""), "the status says so");
    if (shotsDir) await p.locator("[data-testid=open-dialog]").screenshot({ path: path.join(shotsDir, "raw-detect-refused.png") }).catch(() => {});
    // A refusal with guesses (armfw as it is, 1 KB: too little to be sure
    // of) shows them; one is applied only when the user picks it.
    const small = path.join(c.tmp, "armfw-small");
    execFileSync("sh", [path.join(c.root, "src/analysis/tests/fixtures/armfw/build.sh"), "clang", "ld.lld", "llvm-objcopy", small], { stdio: "ignore" });
    await p.fill("[data-testid=open-path]", path.join(small, "fw.bin"));
    await p.press("[data-testid=open-path]", "Enter");
    // Another pick replaces the file shown.
    const smallPick = await pickedFile(p);
    assert(smallPick.name === "fw.bin" && smallPick.where === path.join(small, "fw.bin"), `the new pick replaces the old: ${JSON.stringify(smallPick)}`);
    await p.waitForFunction(() => ["refused", "suggested"].includes(document.querySelector("[data-testid=raw-options]")?.getAttribute("data-detect") ?? ""), null, { timeout: 300000 });
    const guesses = await p.locator("[data-testid=raw-guess]").count();
    if ((await detectState(p)) === "refused" && guesses) {
      assert((await p.inputValue("[data-testid=raw-language]")) === "", "no guess applied by itself");
      const first = ((await p.locator("[data-testid=raw-guess-use]").first().textContent()) ?? "").replace(/^Use /, "");
      await p.locator("[data-testid=raw-guess-use]").first().click();
      assert((await p.inputValue("[data-testid=raw-language]")) === first, `the guess used: ${first}`);
    } else {
      log(`     (armfw's 1 KB image: ${await detectState(p)} with ${guesses} guesses; the guesses aren't checked)`);
    }
    // Back to the noise: nothing filled again.
    await p.fill("[data-testid=open-path]", noise);
    await p.press("[data-testid=open-path]", "Enter");
    await untilDetect(p, "refused");
    assert((await p.inputValue("[data-testid=raw-language]")) === "", "a new file forgets the last one's guess");
    // Import as raw with no language asks for one; it doesn't detect again or import.
    await p.click("[data-testid=raw-import]");
    assert(/needs a language/.test((await p.textContent(".open-status")) ?? ""), `status: ${await p.textContent(".open-status")}`);
    assert((await programs()).length === before, "nothing imported");
    await p.context().close();
    // An ELF picked after a refusal is imported as one: detection ticked
    // raw, not the user.
    const q = await open(base);
    await dialog(q);
    await q.fill("[data-testid=open-path]", noise);
    await q.press("[data-testid=open-path]", "Enter");
    await untilDetect(q, "refused");
    await q.fill("[data-testid=open-path]", c.exe);
    await q.press("[data-testid=open-path]", "Enter");
    await q.waitForURL((u) => /program=default%2Fprog-\d/.test(u.search), { timeout: 300000 });
    const after = await programs();
    assert(after.length === before + 1 && after.filter((x) => x.languageId.startsWith("x86:LE:64")).length >= 2, `the ELF imported as ELF: ${JSON.stringify(after)}`);
    await q.context().close();
  });

  await check("raw detection: a typed language narrows the search and is kept; skipping detection", async () => {
    const p = await open(base);
    await dialog(p);
    await p.fill("[data-testid=open-path]", image);
    await p.click("[data-testid=raw-options] summary");
    await p.fill("[data-testid=raw-language]", "ARM:LE:32:v7");
    await p.click("[data-testid=raw-detect]");
    await untilDetect(p, "suggested");
    const lang = await field(p, "language");
    assert(lang.value === "ARM:LE:32:v7" && lang.state === "suggested", `the typed language is the suggestion's: ${JSON.stringify(lang)}`);
    assert(lang.why.some((w) => /language you chose/.test(w)), `pinned: ${lang.why}`);
    // Skipping: the fields stay as the user left them, nothing more is suggested.
    await p.fill("[data-testid=raw-language]", "");
    // Clearing a field (Delete) edits it; it doesn't ask to delete the program.
    assert(!(await p.isVisible("[data-testid=choose]")), "keys in a raw field are the field's");
    await p.click("[data-testid=raw-detect]");
    await p.click("[data-testid=raw-detect-skip]", { timeout: 5000 });
    const state = await detectState(p);
    assert(state === "skipped", `detection skipped: ${state}`);
    assert(await p.isHidden("[data-testid=import-progress]"), "the bar goes");
    assert(/skipped/i.test((await p.textContent(".open-status")) ?? ""), "the status says so");
    await p.waitForTimeout(2500);
    assert((await detectState(p)) === "skipped" && (await p.inputValue("[data-testid=raw-language]")) === "", "a skipped detection fills in nothing later");
    // Import as raw on another file with no language detects first instead of importing.
    const before = (await programs()).length;
    await p.fill("[data-testid=open-path]", noise);
    await p.click("[data-testid=raw-import]");
    await untilDetect(p, "refused");
    assert((await programs()).length === before, "Import as raw without a language imports nothing");
    await p.context().close();
  });

  await check("raw detection: the dialog with suggestions has names, roles and AA contrast in both themes", async () => {
    // One detection, audited in both themes (the dialog is styled by
    // data-theme; the canvases behind it don't matter to its contrast).
    const problems: string[] = [];
    const p = await open(base);
    const both = async (state: string) => {
      for (const theme of ["dark", "light"]) {
        await p.evaluate((t) => (document.documentElement.dataset.theme = t), theme);
        for (const i of (await audit(p)).issues) problems.push(`${theme}/${state}: ${i.rule} ${i.where} ${i.detail}`);
      }
    };
    await dialog(p);
    await p.fill("[data-testid=open-path]", image);
    await p.press("[data-testid=open-path]", "Enter");
    await untilDetect(p, "suggested");
    await p.locator("[data-testid=raw-field-language] [data-testid=raw-why] summary").click();
    await both("suggested");
    // With a region over the image marked.
    const box = await p.inputValue("[data-testid=raw-regions]");
    const at = ((await p.inputValue("[data-testid=raw-base]")).trim() || "0").replace(/^0x/i, "");
    await p.fill("[data-testid=raw-regions]", `${box}\nover:${at}:100000`.trim());
    await p.waitForSelector("[data-testid=raw-region-problem]");
    await both("overlap");
    await p.fill("[data-testid=open-path]", noise);
    await p.press("[data-testid=open-path]", "Enter");
    await untilDetect(p, "refused");
    await both("refused");
    await p.context().close();
    assert(!problems.length, problems.slice(0, 25).join("\n"));
  });
}
