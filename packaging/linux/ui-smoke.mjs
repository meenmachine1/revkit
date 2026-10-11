// Opens the web UI that a packaged rk-daemon serves, in headless Chrome, and
// checks what a new user sees first: the program opens, the decompiler shows
// a function, and the About box reports the daemon's and the UI's versions.
// Run by packaging/linux/smoke.sh:
//
//   node packaging/linux/ui-smoke.mjs <http base URL> <program id> <function> [<version>]
//
// Needs ui/node_modules (playwright) and a Chrome: RK_BROWSER (default
// /usr/bin/google-chrome), or "chromium" for Playwright's own.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const ui = path.resolve(here, "../../ui");
const { chromium } = await import(pathToFileURL(path.join(ui, "node_modules/playwright/index.mjs")).href);

const [base, program, fn, version] = process.argv.slice(2);
if (!base || !program || !fn) {
  console.error("usage: ui-smoke.mjs <base URL> <program id> <function> [<version>]");
  process.exit(2);
}
const browserPath = process.env.RK_BROWSER ?? "/usr/bin/google-chrome";
const browser = await chromium.launch(browserPath === "chromium" ? {} : { executablePath: browserPath });
let ok = false;
try {
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(`${base}/?program=${encodeURIComponent(program)}&theme=dark`);
  await page.waitForSelector("body[data-ready='1']", { timeout: 30000 });

  // Go to the function from the palette, as a user would.
  await page.focus("#listing-canvas");
  await page.keyboard.press("Control+k");
  await page.fill("[data-testid=palette-input]", fn);
  await page.waitForFunction((t) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").includes(t), fn);
  await page.keyboard.press("Enter");
  await page.waitForFunction((t) => (document.querySelector("#cm .cm-content")?.textContent ?? "").includes(t), fn, { timeout: 30000 });
  const c = (await page.locator("#cm .cm-content").textContent()) ?? "";
  console.log(`ui-smoke: decompiler shows ${fn} (${c.length} characters of C)`);

  // About revkit, from the palette.
  await page.keyboard.press("Control+k");
  await page.fill("[data-testid=palette-input]", ">about");
  await page.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").includes("About"));
  await page.keyboard.press("Enter");
  const server = (await page.locator("[data-testid=about-server]").textContent({ timeout: 10000 })) ?? "";
  const uiVersion = (await page.locator("[data-testid=about-ui]").textContent()) ?? "";
  console.log(`ui-smoke: About: daemon "${server}", UI "${uiVersion}"`);
  if (version && (!server.includes(version) || !uiVersion.startsWith(version)))
    throw new Error(`About box doesn't report version ${version}`);
  if (errors.length) throw new Error(`page errors: ${errors.join("; ")}`);
  ok = true;
} catch (e) {
  console.error(`ui-smoke: FAILED: ${e instanceof Error ? e.message : e}`);
} finally {
  await browser.close();
}
process.exit(ok ? 0 : 1);
