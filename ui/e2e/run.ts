// End-to-end test of the UI against a real rk-daemon (image backend),
// serving a C program compiled here and the built bundle (ui/dist).
//
//   npm run build && npm run e2e
//
// Environment:
//   RK_DAEMON   rk-daemon binary (default ../build/tools/rk-daemon/rk-daemon)
//   RK_WEB_ROOT the built bundle to serve (default ui/dist)
//   CC          C compiler (default cc)
//   RK_BROWSER  chrome (default: /usr/bin/google-chrome), chromium
//               (Playwright's), or a path to a Chromium-family binary
//   RK_HEADED=1 show the browser
//
// Flows: open, navigate (palette by symbol and address, back/forward,
// xrefs), decompile and listing <-> C sync, rename (function, local),
// comment, the provenance badge, live updates in a second page, undo via
// Ctrl+Z and via the badge, header rows (signature, label, plate and
// pre-comment lines, renumbered live), flow arrows and following one out
// of view, compare (version tracking: a new version, the match table,
// accept/reject by key, apply names, blame, undo), retype (prototype, parameter, global; the daemon's error;
// definitions before the declaration), types (header import: pasted and from the daemon host, preview
// buckets, a diagnostic's line, policies, prototypes retyping by name, one revision, undo; Edit in C with
// an error at its line; the editor's insert at an offset, delete leaving filler, grow and shrink,
// bitfields at byte:bit, packing and alignment, flexible arrays, function pointers and pasted
// declarations, duplicate and rename, enum values),
// function bounds (create, remove), flow overrides, notes, listing edits
// (Clear, Disassemble here, the Data menu: e2e/listingedit.ts), structures from pointer use and from a
// selection (e2e/autostruct.ts), equates and user references (e2e/equates.ts), the byte
// viewer, next/previous by kind, Go To expressions, history, the overview bars, Copy Special and
// the optional listing fields (e2e/byteview.ts), the paged
// functions panel, the emulator (emulate from here, step, a breakpoint
// from the gutter, changed registers), the debugger on the program launched
// under gdbserver (a breakpoint, a step, threads, modules, scrubbing the
// timeline back and forth), the DPR 1 rendering fallback, a
// function the decompiler crashes on (banner, instructions, Retry, Export
// repro), and authentication (a daemon with accounts over TLS: the login
// page, the HttpOnly cookie, an edit stamped user:alice, emulating, a
// reload, logging out, and signing in from another origin with a bearer
// token as the Tauri shell does), and raw layout detection in the Open
// dialog (e2e/detect.ts), and scripts (e2e/scripts.ts), demangled names (e2e/demangle.ts), the class hierarchy (e2e/classes.ts), Function ID (e2e/fid.ts), and the daemon status chip
// (e2e/daemon.ts: connected, a killed daemon, Reconnect), the searches (e2e/search.ts), the polish pass's menus, focus and narrow windows (e2e/uipolish.ts), the keymap presets (e2e/keymap.ts), resizable dialogs (e2e/dialogsize.ts), the Open dialog's table (e2e/opendialog.ts) and shared libraries (e2e/libraries.ts). Every edit is checked in a second page and
// undone.

import { chromium, type Browser, type Download, type Page } from "playwright";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { memoryChecks } from "./memory";
import { polishChecks } from "./polish";
import { detectChecks } from "./detect";
import { listingEditChecks } from "./listingedit";
import { autoStructChecks, autoStructEditChecks } from "./autostruct";
import { equateChecks } from "./equates";
import { consoleChecks } from "./console";
import { scriptsChecks } from "./scripts";
import { projectChecks } from "./projects";
import { fileSystemChecks } from "./filesystems";
import { daemonChecks } from "./daemon";
import { byteViewChecks } from "./byteview";
import { searchChecks } from "./search";
import { demangleChecks } from "./demangle";
import { hoverChecks } from "./hover";
import { classesChecks } from "./classes";
import { debugFileChecks } from "./debugfiles";
import { projectTypesChecks } from "./projecttypes";
import { fidChecks } from "./fid";
import { callsiteChecks } from "./callsite";
import { compareChecks } from "./compare";
import { uiPolishChecks } from "./uipolish";
import { editFunctionChecks } from "./editfunction";
import { regValuesChecks } from "./regvalues";
import { bsimChecks } from "./bsim";
import { keymapChecks } from "./keymap";
import { dialogSizeChecks } from "./dialogsize";
import { openDialogChecks } from "./opendialog";
import { librariesChecks } from "./libraries";
import { languageChecks } from "./language";
import { sliceChecks } from "./slices";

const here = path.dirname(fileURLToPath(import.meta.url));
const ui = path.resolve(here, "..");
const root = path.resolve(ui, "..");
// How much longer than usual the slowest steps may take (CTest sets 3 for
// sanitizer builds, as it triples the test's own timeout there).
const timeScale = Number(process.env.RK_E2E_TIME_SCALE ?? "1") || 1;

const PROGRAM = String.raw`
#include <stdio.h>
#include <string.h>
int counter;
int (*volatile hook)(int);
__attribute__((noinline)) int grade(int c) {
  if (c == 0x41) return 3;
  return hook ? hook(c) + 0x41 : 0;
}
__attribute__((noinline)) unsigned checksum(const unsigned char *p, int n) {
  unsigned h = 0x811c9dc5;
  for (int i = 0; i < n; i++) h = (h ^ p[i]) * 0x1000193;
  counter++;
  return h;
}
__attribute__((noinline)) int twice(int x) { return checksum((const unsigned char *)&x, 4) * 2; }
__attribute__((noinline)) int second(int *p) { return p[1]; }
int main(int argc, char **argv) {
  unsigned r = checksum((const unsigned char *)argv[0], (int)strlen(argv[0]));
  printf("%u %d\n", r, twice(argc));
  return (int)r + second(&argc);
}
`;

// ------------------------------------------------------------------ setup --

let daemon: ChildProcess | null = null;
let others: ChildProcess[] = [];
let browser: Browser | null = null;
const tmp = mkdtempSync(path.join(tmpdir(), "rk-e2e-"));
let failures = 0;
let step = "";

function log(s: string) {
  process.stdout.write(s + "\n");
}

/**
 * With RK_E2E_ONLY, whether a module (e2e/<file>) has a check it matches:
 * a module none of whose checks are wanted is skipped entirely, its setup
 * too (programs compiled and imported, pages opened), so a run of part of
 * the checks stays small (systemd-run -p MemoryMax=6G).
 */
function wants(file: string): boolean {
  const only = process.env.RK_E2E_ONLY;
  if (!only) return true;
  const re = new RegExp(only);
  const src = readFileSync(path.join(here, file), "utf8");
  return [...src.matchAll(/check\(\s*[`"]([^`"]+)[`"]/g)].some((m) => re.test(m[1]));
}

// Daemons a check starts for itself (startDaemon inside it): stopped when it
// ends, so the run never holds one per check that needed its own (several
// hundred MB each, under a capped scope).
let checkDaemons: ChildProcess[] | null = null;

async function check(name: string, fn: () => Promise<void>) {
  // RK_E2E_ONLY=<regex>: only the checks it matches (by hand, while working on one).
  if (process.env.RK_E2E_ONLY && !new RegExp(process.env.RK_E2E_ONLY).test(name)) return;
  step = name;
  const t0 = Date.now();
  checkDaemons = [];
  try {
    await fn();
    log(`ok   ${name} (${Date.now() - t0} ms)`);
  } catch (e) {
    failures++;
    log(`FAIL ${name}: ${e instanceof Error ? (process.env.RK_E2E_STACK ? e.stack : e.message) : e}`);
    throw e;
  } finally {
    const mine = checkDaemons;
    checkDaemons = null;
    for (const d of mine) {
      if (d.exitCode !== null || d.signalCode !== null) continue;
      const gone = new Promise((r) => d.once("exit", r));
      d.kill("SIGTERM");
      await Promise.race([gone, new Promise((r) => setTimeout(r, 10000))]);
    }
  }
}

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}

// `extra` replaces --no-auth (the authenticated flows pass --auth-file and TLS flags).
function daemonBin(): string {
  return process.env.RK_DAEMON ?? path.join(root, "build/tools/rk-daemon/rk-daemon");
}

async function startDaemon(exe: string, env: Record<string, string> = {}, portFile = "ports.json", extra: string[] = []): Promise<string> {
  const bin = process.env.RK_DAEMON ?? path.join(root, "build/tools/rk-daemon/rk-daemon");
  assert(existsSync(bin), `rk-daemon not found at ${bin} (set RK_DAEMON)`);
  const web = process.env.RK_WEB_ROOT ?? path.join(ui, "dist");
  assert(existsSync(path.join(web, "index.html")), `${web}/index.html is missing: run npm run build first`);
  const ports = path.join(tmp, portFile);
  if (daemon) others.push(daemon);
  const plugins = process.env.RK_PLUGIN_DIR ?? path.resolve(path.dirname(bin), "../../plugins");
  const pluginArgs = existsSync(path.join(plugins, "rename-regex.wasm")) ? ["--plugin-dir", plugins] : [];
  // A small memo budget: the test's programs are tiny, and the run's daemons
  // fit a capped scope (systemd-run -p MemoryMax=6G).
  daemon = spawn(bin, ["--open", exe, "--grpc", "127.0.0.1:0", "--http", "127.0.0.1:0", "--web-root", web, "--port-file", ports, "--memo-budget", "384",
                       "--browse-root", path.dirname(exe), "--debug-live", ...pluginArgs, ...(extra.length ? extra : ["--no-auth"])], {
    stdio: ["ignore", "inherit", "inherit"],
    // Per-user scripts and trust pins under the test's own config directory, never ~/.config.
    env: { ...process.env, XDG_CONFIG_HOME: path.join(tmp, "xdg-config"), ...env },
  });
  if (checkDaemons) checkDaemons.push(daemon);
  // Up to a minute: sanitizer builds start slowly on a loaded machine.
  for (let i = 0; i < 600; i++) {
    if (existsSync(ports)) {
      try {
        const p = JSON.parse(readFileSync(ports, "utf8"));
        if (p.http) return `${p.tls ? "https" : "http"}://127.0.0.1:${p.http}`;
      } catch {
        /* partially written */
      }
    }
    if (daemon.exitCode !== null) throw new Error(`rk-daemon exited with ${daemon.exitCode}`);
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("rk-daemon did not start");
}

async function launch(): Promise<Browser> {
  const which = process.env.RK_BROWSER ?? "chrome";
  const headless = !process.env.RK_HEADED;
  if (which === "chromium") return chromium.launch({ headless });
  const exe = which === "chrome" ? "/usr/bin/google-chrome" : which;
  return chromium.launch({ headless, executablePath: exe });
}

// The daemon's API, for facts the test checks the UI against.
async function rpc<T>(base: string, method: string, body: unknown): Promise<T> {
  const r = await fetch(`${base}/revkit.v1.${method}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json();
  if (!r.ok) throw new Error(`${method}: ${JSON.stringify(j)}`);
  return j as T;
}

// ---------------------------------------------------------------- helpers --

interface Snap {
  address: string | null;
  label: string | null;
  comment: string | null;
  rowKind: number | null;
  selectedRow: number;
  selection: [number, number];
  totalRows: number;
  headerRows: boolean;
  functionCount: number;
  notes: { address: string; tag: string; text: string; who: string }[];
  decompSig: string;
  collaborators: { name: string; address: string | null; view: string }[];
  func: string | null;
  decompName: string | null;
  decompText: string;
  decompSelected: string | null;
  live: string;
  revision: string;
  renderDpr: number;
  back: number;
  forward: number;
  views: string[];
}

const snap = (p: Page): Promise<Snap> => p.evaluate("window.__revkit.app.snapshot()") as Promise<Snap>;

interface VisRow {
  row: number;
  address: string;
  kind: number;
  header: { kind: number; text: string } | null;
  label: string;
  mnemonic: string;
  comment: string;
  dataType: string;
  flow: number;
  flowOverride: number;
  /** The fallthrough override's address (hex), "none", or null without one. */
  fallthrough: string | null;
  targets: string[];
  func: string | null;
  entry: boolean;
  annot: string;
  operands: string;
  bytes: string;
  patched: boolean;
}
const ROW = { Instruction: 1, Data: 2, Header: 4 };
const HDR = { Plate: 1, Signature: 2, Label: 3, Pre: 4 };
const visible = (p: Page): Promise<VisRow[]> => p.evaluate("window.__revkit.app.visibleRows()") as Promise<VisRow[]>;

/** Waits until the visible rows satisfy `pred`. */
async function untilRows(p: Page, what: string, pred: (rows: VisRow[]) => boolean, ms = 10000): Promise<VisRow[]> {
  const end = Date.now() + ms;
  let rows = await visible(p);
  while (!pred(rows)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; rows: ${JSON.stringify(rows.slice(0, 40).map((r) => [r.row, r.address, r.kind, r.header?.text ?? r.mnemonic, r.label, r.dataType, r.flowOverride]))}`);
    await p.waitForTimeout(50);
    rows = await visible(p);
  }
  return rows;
}

/** The header rows above the code unit at `addr`, in order (texts). */
function headersAt(rows: VisRow[], addr: string): { kind: number; text: string }[] {
  return rows.filter((r) => r.kind === ROW.Header && r.address === addr).map((r) => r.header!);
}

async function until(p: Page, what: string, pred: (s: Snap) => boolean, ms = 10000): Promise<Snap> {
  const end = Date.now() + ms;
  let s = await snap(p);
  while (!pred(s)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify({ ...s, decompText: s.decompText.slice(0, 400) })}`);
    await p.waitForTimeout(50);
    s = await snap(p);
  }
  return s;
}

async function open(base: string, query = "", hash = "", dpr = 1): Promise<Page> {
  const ctx = await browser!.newContext({ viewport: { width: 1500, height: 900 }, deviceScaleFactor: dpr });
  const p = await ctx.newPage();
  p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
  p.on("console", (m) => {
    if (m.type() === "error") log(`  [console] ${m.text()}`);
  });
  await p.goto(`${base}/?program=default%2Fprog&user=e2e&theme=dark${query}${hash}`);
  await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
  return p;
}

async function palette(p: Page, text: string) {
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+k");
  await p.waitForSelector("[data-testid=palette-input]");
  await p.fill("[data-testid=palette-input]", text);
  // Results arrive asynchronously (symbol search).
  await p.waitForFunction((t) => {
    const first = document.querySelector(".palette-item.active .pi-label");
    return !!first && (first.textContent ?? "").includes(t);
  }, text.replace(/^0x/, ""));
  await p.keyboard.press("Enter");
}

async function answer(p: Page, text: string) {
  await p.waitForSelector("[data-testid=ask] .ask-input");
  await p.fill("[data-testid=ask] .ask-input", text);
  await p.keyboard.press("Enter");
  await p.waitForSelector("[data-testid=ask]", { state: "detached" });
}

async function clickToken(p: Page, text: string, cls: string, nth = 0) {
  const loc = p.locator(`#cm .cm-content span.${cls}`, { hasText: new RegExp(`^${text}$`) }).nth(nth);
  await loc.waitFor();
  await loc.click();
}

/** Emulates from the selection, steps once and closes the session: the
 * emulator panel works for a signed-in page (cookie or bearer token). */
async function emulateOneStep(p: Page, at: string) {
  type Emu = { active: boolean; busy: boolean; pc: string | null; stop: string | null; steps: string };
  const emuOf = (s: Snap) => (s as unknown as { emu: Emu | null }).emu;
  const untilEmu = (what: string, pred: (e: Emu) => boolean) => until(p, what, (s) => !!emuOf(s) && !emuOf(s)!.busy && pred(emuOf(s)!), 15000);
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+Shift+P");
  await p.waitForSelector("[data-testid=palette-input]");
  await p.fill("[data-testid=palette-input]", ">emulate from here");
  await p.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "") === "Emulate from here");
  await p.keyboard.press("Enter");
  await untilEmu("a session", (e) => e.active && e.pc === at);
  await p.focus("#listing-canvas");
  await p.keyboard.press("F7");
  await untilEmu("one step", (e) => e.steps === "1" && e.pc !== at);
  await p.click("[data-testid=emu-close]");
  await untilEmu("closed", (e) => !e.active);
}

// ------------------------------------------------------------------- test --

async function main() {
  const cc = process.env.CC ?? "cc";
  const src = path.join(tmp, "prog.c");
  const exe = path.join(tmp, "prog");
  writeFileSync(src, PROGRAM);
  execFileSync(cc, ["-O1", "-g0", "-fno-inline", "-o", exe, src]);
  const base = await startDaemon(exe);
  log(`daemon ${base}, program ${exe}`);
  browser = await launch();
  log(`browser ${browser.version()}`);

  const sym = async (name: string) => {
    const r = await rpc<{ symbols?: { address: { offset: string } }[] }>(base, "QueryService/ListSymbols", { programId: "default/prog", nameEquals: name });
    assert(r.symbols?.length === 1, `symbol ${name} not found`);
    return BigInt(r.symbols[0].address.offset);
  };
  const checksum = await sym("checksum");
  const twice = await sym("twice");
  const main = await sym("main");
  const hx = (a: bigint) => a.toString(16);

  let a!: Page;
  let b!: Page;

  await check("open: the program opens at main, decompiled, subscription live", async () => {
    a = await open(base);
    const s = await until(a, "main decompiled", (s) => s.decompName === "main" && s.live === "live");
    assert(s.address === hx(main), `opened at ${s.address}, expected main ${hx(main)}`);
    assert(s.decompText.includes("checksum("), "main's C calls checksum");
    assert((await a.locator(".fn-row .fn-name", { hasText: /^twice$/ }).count()) === 1, "functions panel lists twice");
  });

  await check("second page opens on main", async () => {
    b = await open(base, "", `#${hx(main)}`);
    await until(b, "main in page B", (s) => s.decompName === "main" && s.live === "live");
  });

  await check("navigate: palette by symbol, by address, back and forward", async () => {
    await palette(a, "checksum");
    let s = await until(a, "checksum", (s) => s.decompName === "checksum");
    assert(s.address === hx(checksum), `at ${s.address}`);
    await palette(a, "0x" + hx(twice));
    s = await until(a, "twice", (s) => s.decompName === "twice" && s.address === hx(twice));
    assert(s.back === 2, `back history ${s.back}`);
    await a.keyboard.press("Alt+ArrowLeft");
    await until(a, "back to checksum", (s) => s.address === hx(checksum) && s.decompName === "checksum");
    await a.keyboard.press("Alt+ArrowLeft");
    await until(a, "back to main", (s) => s.address === hx(main));
    await a.keyboard.press("Alt+ArrowRight");
    s = await until(a, "forward to checksum", (s) => s.address === hx(checksum));
    assert(s.forward === 1, `forward history ${s.forward}`);
  });

  await check("functions panel: filter and open", async () => {
    await a.fill("[data-testid=fn-filter]", "twi");
    await a.keyboard.press("Enter");
    await until(a, "twice via panel", (s) => s.address === hx(twice) && s.decompName === "twice");
    await a.fill("[data-testid=fn-filter]", "");
  });

  await check("xrefs: references to checksum, and following one", async () => {
    await palette(a, "checksum");
    await until(a, "checksum", (s) => s.address === hx(checksum));
    await a.focus("#listing-canvas");
    await a.keyboard.press("x");
    await a.waitForSelector("[data-testid=xrefs] .palette-item");
    const n = await a.locator("[data-testid=xrefs] .palette-item").count();
    assert(n >= 2, `expected >= 2 references to checksum, got ${n}`);
    const callers = await a.locator("[data-testid=xrefs] .pi-detail").allTextContents();
    assert(callers.includes("main") && callers.includes("twice"), `callers: ${callers}`);
    await a.keyboard.press("Enter");
    const s = await until(a, "a caller", (s) => s.func === hx(main) || s.func === hx(twice));
    assert(s.address !== s.func, "landed on the call site, not the entry");
  });

  await check("decompiler <-> listing sync", async () => {
    await palette(a, "main");
    await until(a, "main", (s) => s.decompName === "main");
    await clickToken(a, "checksum", "k-fn");
    const s = await until(a, "listing at the call", (s) => s.address !== hx(main) && s.func === hx(main));
    // The listing row the click selected holds the call instruction whose
    // operand names checksum.
    const ops = (await a.evaluate("window.__revkit.view.selectedRowData().operands.map(o => o.text).join('')")) as string;
    assert(ops.includes("checksum"), `selected ${s.address}: ${ops}`);
    // Arrow keys walk the tokens and keep the listing in sync.
    await a.keyboard.press("ArrowRight");
    await until(a, "next token", (x) => x.decompSelected !== "checksum" && x.decompSelected !== null);
    await a.keyboard.press("ArrowLeft");
    await until(a, "back on checksum", (x) => x.decompSelected === "checksum" && x.address === s.address);
    // Double-click follows into the callee.
    await a.locator("#cm .cm-content span.k-fn", { hasText: /^checksum$/ }).first().dblclick();
    await until(a, "followed into checksum", (s) => s.decompName === "checksum" && s.address === hx(checksum));
  });

  await check("rename a function: both views here, and the second page", async () => {
    await palette(a, "checksum");
    await until(a, "checksum", (s) => s.address === hx(checksum) && s.label === "checksum");
    await a.focus("#listing-canvas");
    await a.keyboard.press("n");
    await answer(a, "fnv1a_hash");
    await until(a, "renamed here", (s) => s.decompName === "fnv1a_hash" && s.label === "fnv1a_hash");
    await a.locator(".fn-row .fn-name", { hasText: /^fnv1a_hash$/ }).waitFor({ timeout: 5000 });
    // Page B shows main, whose call site prints the callee's name.
    await until(b, "page B's decompiled main calls fnv1a_hash", (s) => s.decompText.includes("fnv1a_hash(") && !s.decompText.includes("checksum("));
    await b.locator(".fn-row .fn-name", { hasText: /^fnv1a_hash$/ }).waitFor({ timeout: 5000 });
    await b.waitForSelector(".toast.remote");
  });

  await check("right-click: the app's actions in the listing and the decompiler, not the browser's", async () => {
    // The listing is a canvas: without a handler, the browser offers "Save image as…".
    await palette(a, "fnv1a_hash");
    await until(a, "at fnv1a_hash", (s) => s.label === "fnv1a_hash");
    const blocked = await a.evaluate(() => {
      const c = document.querySelector("#listing-canvas")!;
      const e = new MouseEvent("contextmenu", { bubbles: true, cancelable: true, button: 2, clientX: 40, clientY: 40 });
      return !c.dispatchEvent(e);
    });
    if (!blocked) throw new Error("the listing's right-click reached the browser's own menu");
    await a.keyboard.press("Escape");
    // The context-menu key (an event at 0,0): the menu opens at the selected
    // row, which stays selected.
    await a.locator("#listing-canvas").dispatchEvent("contextmenu", { button: 0, clientX: 0, clientY: 0 });
    await a.locator("[data-testid=ctx-rename]").waitFor({ timeout: 5000 });
    await a.locator("[data-testid=ctx-xrefs]").waitFor({ timeout: 5000 });
    await a.keyboard.press("Escape");
    await a.locator("[data-testid=menu]").waitFor({ state: "detached", timeout: 5000 });
    // The decompiler: right-click a name selects it, and Rename acts on it.
    await until(a, "decompiled again after the listing's selection", (s) => s.decompName !== "" && s.decompText.includes("fnv1a_hash"));
    // By coordinates: the name has a provenance tooltip on hover, and a
    // locator click's stability wait keeps re-hovering it.
    const name = a.locator("#cm .cm-content span.k-fn", { hasText: /^fnv1a_hash$/ }).first();
    await name.waitFor();
    const box = (await name.boundingBox())!;
    await a.mouse.click(box.x + box.width / 2, box.y + box.height / 2, { button: "right" });
    await a.locator("[data-testid=ctx-rename]").click();
    await answer(a, "fnv1a_hash_ctx");
    await until(a, "renamed from the decompiler's menu", (s) => s.decompName === "fnv1a_hash_ctx");
    await a.keyboard.press("Control+z");
    await until(a, "undone", (s) => s.decompName === "fnv1a_hash");
  });

  await check("set type: the chooser's dropdown suggests types as you type", async () => {
    await palette(a, "fnv1a_hash");
    await until(a, "at fnv1a_hash", (s) => s.label === "fnv1a_hash");
    await clickToken(a, "param_1", "k-pa");
    await a.keyboard.press("y");
    const field = a.locator("[data-testid=ask] .ask-input");
    await field.waitFor();
    await field.fill("uint8");
    const rows = a.locator("[data-testid=ask-drop-row]");
    await rows.first().waitFor({ timeout: 5000 });
    const first = await rows.first().innerText();
    if (!first.startsWith("uint8_t")) throw new Error(`first suggestion for uint8 was ${first}`);
    // A pointer kept around the name: "uint8 *" takes "uint8_t *".
    await field.fill("const uint8 *");
    await rows.first().waitFor({ timeout: 5000 });
    await a.keyboard.press("ArrowDown");
    await a.keyboard.press("Tab");
    const v = await field.inputValue();
    if (v !== "const uint8_t *") throw new Error(`taken: ${v}`);
    await a.keyboard.press("Enter");
    await until(a, "retyped", (s) => s.decompText.includes("uint8_t *param_1") || s.decompText.includes("uint8_t *"));
    await a.keyboard.press("Control+z");
  });

  await check("provenance badge names the user", async () => {
    await a.focus("#listing-canvas");
    await a.keyboard.press("i");
    const who = await a.locator("[data-testid=provenance] [data-testid=prov-who]").textContent({ timeout: 5000 });
    assert(who === "user:e2e", `badge says ${who}`);
    await a.keyboard.press("Escape");
    // Hovering the name in the decompiler shows it too.
    await a.locator("#cm .cm-content span.k-fn", { hasText: /^fnv1a_hash$/ }).first().hover();
    await a.waitForSelector("[data-testid=provenance] [data-testid=prov-who]:text('user:e2e')", { timeout: 5000 });
    await a.mouse.move(5, 5);
  });

  await check("rename a local variable in the decompiler", async () => {
    const before = (await snap(a)).decompText;
    const m = before.match(/\b(param_1)\b/);
    assert(m, "checksum has param_1");
    await clickToken(a, "param_1", "k-pa");
    await a.keyboard.press("n");
    await answer(a, "buf");
    await until(a, "param renamed", (s) => /\bbuf\b/.test(s.decompText) && !/\bparam_1\b/.test(s.decompText));
    await b.evaluate(`window.__revkit.app.navigate(0x${hx(checksum)}n)`);
    await until(b, "page B sees the parameter name", (s) => s.decompName === "fnv1a_hash" && /\bbuf\b/.test(s.decompText));
  });

  await check("comment from the decompiler: C, and a pre-comment line above the instruction", async () => {
    await clickToken(a, "counter", "k-gv");
    const s0 = await snap(a);
    const at = s0.address!;
    await a.keyboard.press(";");
    await answer(a, "decomp note");
    await until(a, "comment in C", (s) => s.decompText.includes("decomp note"));
    await untilRows(a, "pre-comment line", (rows) => headersAt(rows, at).some((h) => h.kind === HDR.Pre && h.text === "decomp note"));
    // The new line renumbered the rows; the instruction stays selected.
    const s = await until(a, "still on the instruction", (s) => s.address === at && s.rowKind === ROW.Instruction);
    assert(s.totalRows === s0.totalRows + 1, `rows ${s0.totalRows} -> ${s.totalRows}`);
  });

  await check("comment from the listing shows in page B's listing", async () => {
    await a.focus("#listing-canvas");
    // Down to the next instruction (past any label or comment lines).
    let s0 = await snap(a);
    const from = s0.address;
    for (let i = 0; i < 6 && (s0.address === from || s0.rowKind !== ROW.Instruction); i++) {
      await a.keyboard.press("ArrowDown");
      s0 = await until(a, "moved", (s) => s.selectedRow !== s0.selectedRow);
    }
    assert(s0.rowKind === ROW.Instruction && s0.address !== from, `on the next instruction: ${JSON.stringify(s0.address)}`);
    await a.keyboard.press(";");
    await answer(a, "hash state");
    await until(a, "comment here", (s) => (s.comment ?? "").includes("hash state"));
    await b.evaluate(`window.__revkit.app.navigate(0x${s0.address}n)`);
    await until(b, "comment in page B", (s) => s.address === s0.address && (s.comment ?? "").includes("hash state"));
  });

  await check("comment table: both comments listed; a filter; a click goes there", async () => {
    type Row = { address: string; kind: string; fn: string; text: string };
    const rowsOf = (s: Snap) => (s as unknown as { comments: Row[] | null }).comments ?? [];
    await a.evaluate("window.__revkit.app.showView('comments')");
    let s = await until(a, "both comments listed", (s) => rowsOf(s).some((r) => r.text === "hash state") && rowsOf(s).some((r) => r.text === "decomp note"));
    const hash = rowsOf(s).find((r) => r.text === "hash state")!;
    assert(hash.kind === "EOL" && hash.fn !== "", `the EOL comment: ${JSON.stringify(hash)}`);
    assert(rowsOf(s).find((r) => r.text === "decomp note")!.kind === "Pre", "the decompiler's is a pre-comment");
    await a.fill("[data-testid=comments-filter]", "hash");
    s = await until(a, "filtered", (s) => rowsOf(s).length === 1);
    await a.locator("[data-testid=comment-row]").first().click();
    await until(a, "the listing at the comment", (s) => s.address === hash.address);
    // A double-click opens the comment dialog with the comment in it.
    await a.locator("[data-testid=comment-row]").first().dblclick();
    await a.waitForSelector("[data-testid=ask] .ask-input");
    const value = await a.inputValue("[data-testid=ask] .ask-input");
    assert(value === "hash state", `the dialog's text: ${JSON.stringify(value)}`);
    await a.keyboard.press("Escape");
    await a.waitForSelector("[data-testid=ask]", { state: "detached" });
    await a.fill("[data-testid=comments-filter]", "");
    // The view shares the side dock with the decompiler, which the next checks use.
    await a.evaluate("window.__revkit.app.showView('decomp')");
    await a.evaluate("window.__revkit.app.showView('listing')");
  });

  await check("relocations: the PLT slots by type, a filter, a click goes there, a double-click to a pointer's target", async () => {
    type Row = { address: string; type: string; symbol: string; target: string; targetName: string };
    const rowsOf = (s: Snap) => (s as unknown as { relocations: Row[] | null }).relocations ?? [];
    await a.evaluate("window.__revkit.app.showView('relocations')");
    let s = await until(a, "relocations listed", (s) => rowsOf(s).some((r) => r.type === "R_X86_64_JUMP_SLOT" && r.symbol === "strlen"));
    const relative = rowsOf(s).find((r) => r.type === "R_X86_64_RELATIVE" && r.target !== "");
    assert(relative !== undefined, `a RELATIVE relocation with a target: ${JSON.stringify(rowsOf(s).slice(0, 5))}`);
    await a.fill("[data-testid=relocations-filter]", "strlen");
    s = await until(a, "filtered", (s) => rowsOf(s).length === 1);
    const slot = rowsOf(s)[0];
    await a.locator("[data-testid=relocation-row]").first().click();
    await until(a, "the listing at the slot", (s) => s.address === slot.address);
    await a.fill("[data-testid=relocations-filter]", "RELATIVE");
    await until(a, "the RELATIVE ones", (s) => rowsOf(s).length > 0 && rowsOf(s).every((r) => r.type === "R_X86_64_RELATIVE"));
    const row = a.locator(`[data-testid=relocation-row][data-address="${relative!.address}"]`);
    if ((await row.count()) > 0) {
      await row.dblclick();
      await until(a, "the listing at the target", (s) => s.address === relative!.target);
    }
    await a.fill("[data-testid=relocations-filter]", "");
    await a.evaluate("window.__revkit.app.showView('decomp')");
    await a.evaluate("window.__revkit.app.showView('listing')");
  });

  await check("export c: every function with a header, then the one at the cursor alone", async () => {
    type X = { which: string; status: string; sourceName: string; source: string; headerName: string; header: string; functions: number };
    const xc = (s: Snap) => (s as unknown as { exportC: X | null }).exportC;
    await palette(a, "checksum");
    await until(a, "at checksum", (s) => s.label === "checksum");
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+Shift+P");
    await a.waitForSelector("[data-testid=palette-input]");
    await a.fill("[data-testid=palette-input]", ">File: Export C/C++");
    await a.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").startsWith("File: Export C/C++"));
    await a.keyboard.press("Enter");
    await a.waitForSelector("[data-testid=export-c]");
    await a.click("[data-testid=xc-export]");
    let s = await until(a, "exported", (s) => (xc(s)?.functions ?? 0) > 0, 60000);
    let x = xc(s)!;
    assert(x.sourceName === "prog.c" && x.headerName === "prog.h", `the files: ${x.sourceName} ${x.headerName}`);
    assert(x.source.includes("/* checksum @ 0x") && x.source.includes("/* main @ 0x") && x.source.includes('#include "prog.h"'), "both functions in the .c");
    assert(x.header.includes("checksum(") && x.header.includes("typedef unsigned int uint;"), "the prototypes and built-in types in the .h");
    assert(/prog\.c and prog\.h: \d+ functions/.test(x.status), `the status: ${x.status}`);
    await a.selectOption("[data-testid=xc-which]", "current");
    await a.uncheck("[data-testid=xc-header]");
    await a.click("[data-testid=xc-export]");
    s = await until(a, "one function", (s) => xc(s)?.functions === 1 && xc(s)?.headerName === "");
    x = xc(s)!;
    assert(x.source.includes("/* checksum @ 0x") && !x.source.includes("/* main @ 0x"), "only checksum");
    await a.click("[data-testid=xc-close]");
    await a.waitForSelector("[data-testid=export-c]", { state: "detached" });
  });

  await check("symbol tree: the folders, Functions expanded and filtered, a click goes there, an import under its library", async () => {
    type Row = { path: string; more: boolean; name: string; kind: number; address: string; children: number };
    const rowsOf = (s: Snap) => (s as unknown as { symtree: Row[] | null }).symtree ?? [];
    const row = (path: string) => a.locator(`[data-testid=symtree-row][data-path="${path}"]`);
    await a.evaluate("window.__revkit.app.showView('symtree')");
    let s = await until(a, "the folders", (s) => rowsOf(s).map((r) => r.name).join(",") === "Imports,Exports,Functions,Labels,Classes,Namespaces");
    assert(rowsOf(s).find((r) => r.name === "Functions")!.children >= 3, "Functions counts the functions");
    await row("Functions").click();
    s = await until(a, "the functions", (s) => rowsOf(s).some((r) => r.path === "Functions/checksum"));
    const checksum = rowsOf(s).find((r) => r.path === "Functions/checksum")!;
    await row("Functions/checksum").click();
    await until(a, "the listing at checksum", (s) => s.address === checksum.address);
    await a.fill("[data-testid=symtree-filter]", "twice");
    await until(a, "filtered", (s) => {
      const fns = rowsOf(s).filter((r) => r.path.startsWith("Functions/"));
      return fns.length === 1 && fns[0].name === "twice";
    });
    await a.fill("[data-testid=symtree-filter]", "");
    await until(a, "unfiltered", (s) => rowsOf(s).some((r) => r.path === "Functions/checksum"));
    await row("Imports").click();
    await until(a, "a library", (s) => rowsOf(s).some((r) => r.path === "Imports/<EXTERNAL>"));
    await row("Imports/<EXTERNAL>").click();
    await until(a, "strlen imported", (s) => rowsOf(s).some((r) => r.path === "Imports/<EXTERNAL>/strlen" && r.address !== ""));
    await a.evaluate("window.__revkit.app.showView('decomp')");
    await a.evaluate("window.__revkit.app.showView('listing')");
  });

  await check("clear flow: twice's flow cleared from the palette in one step, Ctrl+Z brings it back", async () => {
    await palette(a, "twice");
    let s = await until(a, "at twice", (s) => s.label === "twice" && s.rowKind === 1);
    const at = s.address;
    const before = s.functionCount;
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+Shift+P");
    await a.waitForSelector("[data-testid=palette-input]");
    await a.fill("[data-testid=palette-input]", ">Clear flow and repair");
    await a.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").startsWith("Clear flow and repair"));
    await a.keyboard.press("Enter");
    s = await until(a, "twice gone", (s) => s.functionCount === before - 1);
    await until(b, "page B sees it", (s) => s.functionCount === before - 1);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+z");
    s = await until(a, "twice back", (s) => s.functionCount === before);
    assert(s.address === at, `still at twice: ${s.address}`);
  });

  await check("undo (Ctrl+Z) retracts, in reverse order, everywhere", async () => {
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+z");
    await until(a, "comment gone", (s) => !(s.comment ?? "").includes("hash state"));
    await until(b, "comment gone in page B", (s) => !(s.comment ?? "").includes("hash state"));
    await a.keyboard.press("Control+z");
    await until(a, "decompiler comment gone", (s) => !s.decompText.includes("decomp note"));
    await a.keyboard.press("Control+z");
    await until(a, "param name back", (s) => /\bparam_1\b/.test(s.decompText));
    await a.keyboard.press("Control+z");
    await until(a, "function name back", (s) => s.decompName === "checksum");
    await b.evaluate(`window.__revkit.app.navigate(0x${hx(main)}n)`);
    await until(b, "page B's main calls checksum again", (s) => s.decompName === "main" && s.decompText.includes("checksum(") && !s.decompText.includes("fnv1a_hash"));
    // Redo reinstates the function name (retracting the retraction).
    await a.keyboard.press("Control+Shift+z");
    await until(b, "redo reaches page B", (s) => s.decompText.includes("fnv1a_hash("));
  });

  await check("undo from the provenance badge", async () => {
    await a.locator(".fn-row .fn-name", { hasText: /^fnv1a_hash$/ }).waitFor({ timeout: 10000 });
    await palette(a, "fnv1a_hash");
    await until(a, "at fnv1a_hash", (s) => s.label === "fnv1a_hash");
    await a.focus("#listing-canvas");
    await a.keyboard.press("i");
    await a.click("[data-testid=prov-undo]");
    await until(a, "badge undo", (s) => s.label === "checksum" && s.decompName === "checksum");
    await until(b, "badge undo in page B", (s) => s.decompText.includes("checksum(") && !s.decompText.includes("fnv1a_hash"));
    const hist = await rpc<{ entries: { op: string }[] }>(base, "AssertionService/GetHistory", { key: { programId: "default/prog", kind: "FACT_KIND_NAME", address: { offset: String(checksum) } } });
    assert(hist.entries.some((e) => e.op === "ASSERTION_OP_RETRACT"), "the undo is a retraction in the log");
  });

  // ------------------------------------------------------------ v1.1 --

  const rowsTotal = async () => {
    const r = await rpc<{ totalRows: string }>(base, "QueryService/GetListing", { programId: "default/prog", headerRows: true, rows: { firstRow: "0", rowCount: 1 } });
    return Number(r.totalRows);
  };
  const go = async (p: Page, addr: bigint | string) => {
    const a = typeof addr === "string" ? addr : hx(addr);
    await p.evaluate(`window.__revkit.app.navigate(0x${a}n)`);
    return until(p, `at ${a}`, (s) => s.address === a && s.rowKind !== null && s.rowKind !== ROW.Header);
  };
  const undoIn = async (p: Page) => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+z");
  };

  await check("header rows: plate, signature and label lines above the entry, as the daemon numbers them", async () => {
    let s = await go(a, checksum);
    const rows = await untilRows(a, "checksum's header", (rows) => headersAt(rows, hx(checksum)).length >= 2);
    const hs = headersAt(rows, hx(checksum));
    assert(hs[0].kind === HDR.Signature && hs[0].text === "undefined checksum()", `signature: ${JSON.stringify(hs)}`);
    assert(hs[1].kind === HDR.Label && hs[1].text === "checksum", `label: ${JSON.stringify(hs)}`);
    const unit = rows.find((r) => r.address === hx(checksum) && r.kind === ROW.Instruction)!;
    assert(unit.row === rows.find((r) => r.header?.kind === HDR.Label && r.address === hx(checksum))!.row + 1, "the label is right above the instruction");
    assert(s.selectedRow === unit.row, `selected row ${s.selectedRow}, entry at ${unit.row}`);
    assert(s.totalRows === (await rowsTotal()), `total ${s.totalRows} vs daemon ${await rowsTotal()}`);
    // A plate comment from the listing: lines of their own, live in page B.
    await go(b, checksum);
    await a.focus("#listing-canvas");
    await a.evaluate("void window.__revkit.app.comment('plate')");
    await answer(a, "FNV-1a hash");
    await untilRows(a, "plate line", (rows) => headersAt(rows, hx(checksum))[0]?.kind === HDR.Plate);
    await untilRows(b, "plate line in page B", (rows) => headersAt(rows, hx(checksum))[0]?.text === "FNV-1a hash");
    s = await until(b, "page B renumbered, still on checksum", (s) => s.address === hx(checksum) && s.rowKind === ROW.Instruction);
    assert(s.totalRows === (await rowsTotal()), `page B total ${s.totalRows}`);
    await undoIn(a);
    await untilRows(b, "plate gone in page B", (rows) => headersAt(rows, hx(checksum))[0]?.kind === HDR.Signature);
  });

  await check("a name on an unlabelled instruction adds a label line in both pages; undo removes it", async () => {
    const rows = await untilRows(a, "checksum rows", (rows) => rows.some((r) => r.address === hx(checksum) && r.kind === ROW.Instruction));
    const entryIdx = rows.findIndex((r) => r.address === hx(checksum) && r.kind === ROW.Instruction);
    const next = rows.slice(entryIdx + 1).find((r) => r.kind === ROW.Instruction && !r.label)!;
    assert(next, "an unlabelled instruction after the entry");
    const before = (await snap(a)).totalRows;
    await go(a, next.address);
    await go(b, next.address);
    await a.focus("#listing-canvas");
    await a.keyboard.press("n");
    await answer(a, "after_entry");
    await untilRows(a, "label line", (rows) => headersAt(rows, next.address).some((h) => h.kind === HDR.Label && h.text === "after_entry"));
    await untilRows(b, "label line in page B", (rows) => headersAt(rows, next.address).some((h) => h.text === "after_entry"));
    for (const p of [a, b]) await until(p, "one more row, same instruction", (s) => s.totalRows === before + 1 && s.address === next.address && s.rowKind === ROW.Instruction);
    await undoIn(a);
    await untilRows(b, "label line gone in page B", (rows) => headersAt(rows, next.address).length === 0);
    for (const p of [a, b]) await until(p, "rows back", (s) => s.totalRows === before);
  });

  await check("flow arrows: the loop's jumps in view, and following one out of view", async () => {
    await go(a, checksum);
    const rows = await untilRows(a, "a jump in checksum", (rows) => rows.some((r) => r.func === hx(checksum) && r.targets.length > 0 && (r.flow === 2 || r.flow === 3)));
    const jumps = rows.filter((r) => r.func === hx(checksum) && r.targets.length > 0 && (r.flow === 2 || r.flow === 3));
    await a.waitForFunction("window.__revkit.app.arrows().length > 0");
    let arrows = (await a.evaluate("window.__revkit.app.arrows()")) as { from: number; to: number; target: string; offscreen: boolean; x: number; y: number }[];
    for (const j of jumps) assert(arrows.some((x) => x.from === j.row && j.targets.includes(x.target)), `an arrow from row ${j.row} (${j.mnemonic}) to ${j.targets}: ${JSON.stringify(arrows)}`);
    // The backward jump with its source at the top of the view: its target
    // is above it, drawn to the edge; clicking the arrow goes there.
    const back = jumps.find((j) => BigInt("0x" + j.targets[0]) < BigInt("0x" + j.address)) ?? jumps[0];
    await a.evaluate(`window.__revkit.view.scrollToRow(${back.row}, "top")`);
    await a.waitForFunction(`window.__revkit.app.arrows().some(x => x.from === ${back.row} && x.offscreen)`);
    arrows = (await a.evaluate("window.__revkit.app.arrows()")) as typeof arrows;
    const stub = arrows.find((x) => x.from === back.row && x.offscreen)!;
    const box = (await a.locator("#listing-canvas").boundingBox())!;
    await a.mouse.click(stub.x, box.y + 6);
    await until(a, "followed the jump", (s) => s.address === back.targets[0]);
  });

  await check("retype a prototype: the daemon's error, then C and the signature line here and in page B; undo", async () => {
    await go(a, checksum);
    await go(b, checksum);
    await until(a, "checksum decompiled", (s) => s.decompName === "checksum");
    await a.locator("#cm .cm-content span.k-fn", { hasText: /^checksum$/ }).first().click();
    await a.keyboard.press("y");
    await a.waitForSelector("[data-testid=ask] .ask-input");
    await a.fill("[data-testid=ask] .ask-input", "");
    await a.keyboard.press("Enter");
    await a.waitForFunction(() => !!document.querySelector("[data-testid=ask-error]")?.textContent, undefined, { timeout: 5000 });
    const err = await a.locator("[data-testid=ask-error]").textContent();
    assert(err && /empty/i.test(err), `the daemon's validation error: ${err}`);
    const proto = "unsigned int checksum(const unsigned char *data, int len)";
    await a.fill("[data-testid=ask] .ask-input", proto);
    await a.keyboard.press("Enter");
    await a.waitForSelector("[data-testid=ask]", { state: "detached" });
    await until(a, "decompiler signature", (s) => s.decompSig === proto);
    for (const p of [a, b]) await untilRows(p, "signature line", (rows) => headersAt(rows, hx(checksum)).some((h) => h.kind === HDR.Signature && h.text === proto));
    // Its provenance.
    await a.focus("#listing-canvas");
    const sigRow = (await visible(a)).find((r) => r.address === hx(checksum) && r.header?.kind === HDR.Signature)!;
    await a.evaluate(`(() => { const v = window.__revkit.view; v.selectedRow = ${sigRow.row}; v.selectedHit = null; v.invalidate(); })()`);
    await a.keyboard.press("i");
    const who = await a.locator("[data-testid=provenance] [data-testid=prov-who]").textContent({ timeout: 5000 });
    assert(who === "user:e2e", `prototype badge: ${who}`);
    await a.keyboard.press("Escape");
    await undoIn(a);
    for (const p of [a, b]) await untilRows(p, "signature back", (rows) => headersAt(rows, hx(checksum)).some((h) => h.text === "undefined checksum()"));
    await until(a, "decompiler signature cleared", (s) => s.decompSig === "");
  });

  await check("retype a parameter: its declaration in C, here and in page B; undo", async () => {
    await go(a, checksum);
    await until(a, "checksum decompiled", (s) => s.decompName === "checksum" && /\bparam_2\b/.test(s.decompText));
    await clickToken(a, "param_2", "k-pa");
    await a.keyboard.press("y");
    await answer(a, "long");
    await until(a, "long param_2", (s) => /\blong param_2\b/.test(s.decompText));
    await until(b, "page B: long param_2", (s) => s.decompName === "checksum" && /\blong param_2\b/.test(s.decompText));
    await undoIn(a);
    await until(b, "page B: param_2's type back", (s) => !/\blong param_2\b/.test(s.decompText) && /\bparam_2\b/.test(s.decompText));
  });

  await check("retype a global: its row in both pages; undo", async () => {
    const counter = await sym("counter");
    await go(a, counter);
    await go(b, counter);
    // Data analysis may already type the global (sized by how code accesses
    // it); undo must bring back exactly that.
    const before = (await untilRows(b, "the global's row", (rows) => rows.some((r) => r.address === hx(counter) && r.kind !== ROW.Header)))
      .find((r) => r.address === hx(counter) && r.kind !== ROW.Header)!.dataType;
    assert(before !== "unsigned int", `already unsigned int`);
    await a.focus("#listing-canvas");
    await a.keyboard.press("y");
    await answer(a, "unsigned int");
    for (const p of [a, b]) await untilRows(p, "the global's type", (rows) => rows.some((r) => r.address === hx(counter) && r.kind !== ROW.Header && r.dataType === "unsigned int"));
    await undoIn(a);
    await untilRows(b, "type restored in page B", (rows) => rows.some((r) => r.address === hx(counter) && r.kind !== ROW.Header && r.dataType === before));
  });

  await check("function bounds: create a function inside main and remove twice, in both pages; undo", async () => {
    const fns0 = (await snap(a)).functionCount;
    // An instruction in main after a call (not an entry, no label).
    await go(a, main);
    const rows = await untilRows(a, "main's rows", (rows) => rows.filter((r) => r.func === hx(main) && r.kind === ROW.Instruction).length > 4);
    const inside = rows.filter((r) => r.func === hx(main) && r.kind === ROW.Instruction && !r.entry && !r.label).slice(-2)[0];
    await go(a, inside.address);
    await go(b, inside.address);
    await a.focus("#listing-canvas");
    await a.keyboard.press("f");
    for (const p of [a, b]) {
      await until(p, "one more function", (s) => s.functionCount === fns0 + 1);
      await untilRows(p, "its signature line", (rows) => headersAt(rows, inside.address).some((h) => h.kind === HDR.Signature));
    }
    await until(a, "the new function decompiles", (s) => s.func === inside.address && s.decompName === `FUN_${inside.address.padStart(8, "0")}`);
    await undoIn(a);
    for (const p of [a, b]) await until(p, "function gone", (s) => s.functionCount === fns0);
    await untilRows(b, "signature gone in page B", (rows) => !headersAt(rows, inside.address).some((h) => h.kind === HDR.Signature));
    // Remove twice (Shift+F asks first).
    await go(a, twice);
    await go(b, twice);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Shift+F");
    await a.waitForSelector("[data-testid=choose] .palette-item");
    await a.keyboard.press("Enter");
    for (const p of [a, b]) {
      await until(p, "one function fewer", (s) => s.functionCount === fns0 - 1);
      await untilRows(p, "no signature at twice", (rows) => !headersAt(rows, hx(twice)).some((h) => h.kind === HDR.Signature));
    }
    await undoIn(a);
    for (const p of [a, b]) await until(p, "twice back", (s) => s.functionCount === fns0);
    await untilRows(b, "twice's signature back in page B", (rows) => headersAt(rows, hx(twice)).some((h) => h.kind === HDR.Signature));
  });

  await check("flow override on main's call: the row in both pages; undo", async () => {
    await go(a, main);
    const rows = await untilRows(a, "main's call", (rows) => rows.some((r) => r.func === hx(main) && r.flow === 4 && r.targets.includes(hx(checksum))));
    const call = rows.find((r) => r.func === hx(main) && r.flow === 4 && r.targets.includes(hx(checksum)))!;
    await go(a, call.address);
    await go(b, call.address);
    await a.focus("#listing-canvas");
    await a.keyboard.press("o");
    await a.waitForSelector("[data-testid=choose] .palette-item");
    await a.locator("[data-testid=choose] .palette-item", { hasText: "Call + return" }).click();
    for (const p of [a, b]) await untilRows(p, "the override", (rows) => rows.some((r) => r.address === call.address && r.kind === ROW.Instruction && r.flowOverride === 4));
    const hist = await rpc<{ entries: { provenance: { id: string } }[] }>(base, "AssertionService/GetHistory", { key: { programId: "default/prog", kind: "FACT_KIND_FLOW_OVERRIDE", address: { offset: String(BigInt("0x" + call.address)) } } });
    assert(hist.entries.some((e) => e.provenance.id === "e2e"), "a user:e2e assertion");
    await undoIn(a);
    for (const p of [a, b]) await untilRows(p, "override gone", (rows) => rows.some((r) => r.address === call.address && r.kind === ROW.Instruction && r.flowOverride === 0));
  });

  await check("notes: added here, listed live in page B; undo", async () => {
    await go(a, checksum);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Shift+N");
    await a.waitForSelector("[data-testid=ask] .ask-extra");
    await a.fill("[data-testid=ask] .ask-extra", "todo");
    await a.fill("[data-testid=ask] textarea.ask-input", "check the length");
    await a.keyboard.press("Enter");
    for (const p of [a, b]) {
      await until(p, "the note", (s) => s.notes.some((n) => n.address === hx(checksum) && n.tag === "todo" && n.text === "check the length" && n.who === "user:e2e"));
      await p.locator("[data-testid=notes] .note-row", { hasText: "check the length" }).waitFor({ timeout: 5000 });
    }
    // Clicking it in page B goes there.
    await go(b, main);
    await b.locator("[data-testid=notes] .note-row", { hasText: "check the length" }).click();
    await until(b, "at the note", (s) => s.address === hx(checksum));
    await undoIn(a);
    for (const p of [a, b]) await until(p, "note gone", (s) => !s.notes.length);
  });

  // Clear, Disassemble here and the Data menu from the listing (e2e/listingedit.ts).
  if (wants("listingedit.ts")) await listingEditChecks({ base, a, b, check, sym, rpc, assert, go, answer });

  // Auto create / fill in structure and Create structure from selection (e2e/autostruct.ts).
  if (wants("autostruct.ts")) await autoStructChecks({ base, a, b, check, sym, rpc, assert, go });

  // The searches (e2e/search.ts): memory, program text, scalars, decompiled code, the results table.
  if (wants("search.ts")) await searchChecks({ base, a, check, sym, rpc, assert, go });
  // Equates (Convert, Set Equate, the Equates window) and user references (e2e/equates.ts).
  if (wants("equates.ts")) await equateChecks({ base, a, b, check, sym, rpc, assert, go, answer });

  // Hover cards (e2e/hover.ts): previews in the listing and the decompiler.
  if (wants("hover.ts")) await hoverChecks({ base, a, check, sym, rpc, assert, go });
  // Find uses of a type or field, and call-site signature overrides (e2e/callsite.ts).
  if (wants("callsite.ts")) await callsiteChecks({ base, a, b, check, sym, rpc, assert, go });
  // The byte viewer, next/previous, Go To expressions, history, the overview
  // bars, Copy Special and the optional fields (e2e/byteview.ts).
  if (wants("byteview.ts")) await byteViewChecks({ base, check, sym, rpc, assert, open, log });

  await check("presence: each page shows where the other one is", async () => {
    await go(b, twice);
    await until(a, "page B's cursor in page A", (s) => s.collaborators.some((c) => c.address === hx(twice)));
    await a.locator("[data-testid=collab]", { hasText: "1 other here" }).waitFor({ timeout: 5000 });
    await go(a, main);
    await until(b, "page A's cursor in page B", (s) => s.collaborators.some((c) => c.address === hx(main)));
  });

  await check("functions panel pages from the daemon (4 per page) and finds the current function", async () => {
    const all = await rpc<{ page: { totalCount: string }; functions: { name: string; entry: { offset: string } }[] }>(base, "QueryService/ListFunctions", { programId: "default/prog", page: { pageSize: 1000 } });
    const total = Number(all.page.totalCount);
    const c = await open(base, "&fnpage=4", `#${hx(main)}`);
    await until(c, "loaded", (s) => s.functionCount === total && s.decompName === "main");
    assert((await c.locator("[data-testid=fn-count]").textContent()) === total.toLocaleString(), "count");
    // The last function's row appears once its page loads.
    await c.locator(".fn-list").evaluate((el) => (el.scrollTop = el.scrollHeight));
    const last = all.functions[all.functions.length - 1];
    await c.locator(".fn-row .fn-name", { hasText: new RegExp(`^${last.name}$`) }).waitFor({ timeout: 5000 });
    // The current function is marked after going to it (its position from a range query).
    await c.evaluate(`window.__revkit.app.navigate(0x${hx(main)}n)`);
    await c.locator(".fn-row.current .fn-name", { hasText: /^main$/ }).waitFor({ timeout: 5000 });
    // Filtering is the daemon's.
    await c.fill("[data-testid=fn-filter]", "check");
    await c.locator("[data-testid=fn-count]", { hasText: "1 match" }).waitFor({ timeout: 5000 });
    await c.context().close();
  });

  await check("open: import a binary by upload and open it", async () => {
    const c = await open(base);
    await until(c, "ready", (s) => s.decompName === "main");
    await c.focus("#listing-canvas");
    await c.keyboard.press("Control+o");
    await c.waitForSelector("[data-testid=open-dialog] .open-row");
    const listed = await c.locator("[data-testid=open-dialog] .open-row .open-name").allTextContents();
    assert(listed.includes("prog"), `programs listed: ${listed}`);
    // Import binary… opens the import section; the file input is made when
    // Choose file… is pressed (src/ui/filepick.ts).
    await c.click("[data-testid=open-import-binary]");
    const [chooser] = await Promise.all([c.waitForEvent("filechooser"), c.click("[data-testid=open-import]")]);
    await chooser.setFiles(exe);
    await c.waitForURL(/program=default%2Fprog-2|program=default\/prog-2/, { timeout: 15000 });
    await c.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    const s = await until(c, "uploaded program open", (s) => s.decompName === "main");
    assert(s.label === "main", `label ${s.label}`);
    assert((await c.title()).startsWith("prog"), `title ${await c.title()}`);
    await c.context().close();
  });

  await check("open: browse the daemon host and import by path", async () => {
    const c = await open(base);
    await until(c, "ready", (s) => s.decompName === "main");
    await c.focus("#listing-canvas");
    await c.keyboard.press("Control+o");
    await c.waitForSelector("[data-testid=open-dialog] .open-row");
    await c.click("[data-testid=open-import-binary]");
    await c.click("[data-testid=open-browse]");
    const entry = c.locator("[data-testid=browse-entry]", { hasText: path.basename(exe) }).first();
    await entry.waitFor({ timeout: 5000 });
    await entry.click();
    await c.waitForURL(/program=default%2Fprog-3|program=default\/prog-3/, { timeout: 15000 });
    await c.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    const s = await until(c, "browsed program open", (s) => s.decompName === "main");
    assert(s.label === "main", `label ${s.label}`);
    await c.context().close();
  });

  await check("open: raw import suggests every language the daemon has", async () => {
    const c = await open(base);
    await until(c, "ready", (s) => s.decompName === "main");
    await c.focus("#listing-canvas");
    await c.keyboard.press("Control+o");
    await c.waitForSelector("[data-testid=open-dialog] .open-row");
    await c.click("[data-testid=open-import-binary]");
    await c.click("[data-testid=raw-options] summary");
    const options = c.locator("#raw-languages option");
    await c.waitForFunction(() => document.querySelectorAll("#raw-languages option").length > 100, null, { timeout: 10000 });
    assert((await options.count()) > 100, `${await options.count()} languages`);
    await c.fill("[data-testid=raw-language]", "68000:BE:32:default");
    const info = (await c.textContent("[data-testid=raw-language-info]")) ?? "";
    assert(/compilers: default/.test(info) && !/No language/.test(info), `language info: ${info}`);
    await c.fill("[data-testid=raw-language]", "NOPE:LE:32:x");
    assert(/No language/.test((await c.textContent("[data-testid=raw-language-info]")) ?? ""), "unknown language is called out");
    await c.context().close();
  });

  // The Open dialog's table (e2e/opendialog.ts): search, sort, details, the Open button, Enter and double click.
  if (wants("opendialog.ts")) await openDialogChecks({ base, exe, check, open, rpc, assert });

  // Shared libraries (e2e/libraries.ts): imported with a program, an import's library function, the Libraries dialog.
  if (wants("libraries.ts")) await librariesChecks({
    base, tmp, check, open, rpc, assert,
    until: (p, what, pred, ms) => until(p, what, pred as unknown as (s: Snap) => boolean, ms) as never,
  });

  // Change language (e2e/language.ts): the variant comparison, and the refusals.
  if (wants("language.ts")) await languageChecks({ base, check, open, rpc, assert });

  await check("listing: select several rows (drag, shift-click, shift-arrows) and copy them", async () => {
    const c = await open(base);
    await until(c, "ready", (s) => s.decompName === "main");
    const canvas = c.locator("#listing-canvas");
    const box = (await canvas.boundingBox())!;
    const rowH = (await c.evaluate("window.__revkit.app.view.rowH")) as number;
    const x = box.x + box.width / 2;
    const yOf = (i: number) => box.y + rowH * i + rowH / 2;
    // Drag from the 3rd visible row to the 7th.
    await c.mouse.move(x, yOf(2));
    await c.mouse.down();
    await c.mouse.move(x, yOf(4), { steps: 3 });
    await c.mouse.move(x, yOf(6), { steps: 3 });
    await c.mouse.up();
    let s = await snap(c);
    assert(s.selection[1] - s.selection[0] === 4, `drag selected ${s.selection}`);
    const first = s.selection[0];
    // Shift-click extends to the 10th row; shift+down extends one more.
    await c.keyboard.down("Shift");
    await c.mouse.click(x, yOf(9));
    await c.keyboard.up("Shift");
    await c.keyboard.press("Shift+ArrowDown");
    s = await snap(c);
    assert(s.selection[0] === first && s.selection[1] - first === 8, `extended to ${s.selection}`);
    // Ctrl+C copies one line per selected row, as shown.
    await c.evaluate(`document.addEventListener("copy", (e) => { window.__copied = e.clipboardData.getData("text/plain"); })`);
    await c.keyboard.press("Control+c");
    const copied = (await c.evaluate("window.__copied")) as string;
    const lines = copied.trimEnd().split("\n");
    assert(lines.length === 9, `copied ${lines.length} lines: ${copied.slice(0, 200)}`);
    assert(lines.some((l) => /\b[0-9a-f]{6,}\b/.test(l)), `no address in copied text: ${copied.slice(0, 200)}`);
    // Escape collapses to the cursor row.
    await c.keyboard.press("Escape");
    s = await snap(c);
    assert(s.selection[0] === s.selection[1], `after Escape ${s.selection}`);
    await c.context().close();
  });

  await check("emulator: emulate from here, step, a breakpoint from the gutter, changed registers", async () => {
    const c = await open(base, "", `#${hx(twice)}`);
    await until(c, "twice", (s) => s.address === hx(twice) && s.decompName !== null);
    type Emu = { active: boolean; busy: boolean; pc: string | null; stop: string | null; breakpoints: string[]; changed: string[]; steps: string };
    const emuOf = (s: Snap) => (s as unknown as { emu: Emu | null }).emu;
    const untilEmu = (what: string, pred: (e: Emu) => boolean, ms = 15000) => until(c, what, (s) => !!emuOf(s) && !emuOf(s)!.busy && pred(emuOf(s)!), ms);
    // "Emulate from here" from the command palette.
    await c.focus("#listing-canvas");
    await c.keyboard.press("Control+Shift+P");
    await c.waitForSelector("[data-testid=palette-input]");
    await c.fill("[data-testid=palette-input]", ">emulate from here");
    await c.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "") === "Emulate from here");
    await c.keyboard.press("Enter");
    await c.waitForSelector("[data-testid=emulator]:not([hidden])");
    let e = emuOf(await untilEmu("a session at twice", (e) => e.active && e.pc === hx(twice)))!;
    assert(e.stop === "ready", `stop ${e.stop}`);
    assert((await c.locator("#emu .emu-reg").count()) >= 16, "registers shown");
    // One step (F7): the listing follows the pc, the changed registers are marked.
    await c.focus("#listing-canvas");
    await c.keyboard.press("F7");
    e = emuOf(await untilEmu("one step", (e) => e.steps === "1"))!;
    assert(e.pc !== hx(twice) && e.changed.includes("RIP") && !e.changed.includes("R15"), `after a step: ${JSON.stringify(e)}`);
    await until(c, "listing at the pc", (s) => s.address === e.pc);
    // A breakpoint from the gutter on twice's call, then continue (F9) to it.
    const rows = await visible(c);
    const call = rows.find((r) => r.func === hx(twice) && r.kind === ROW.Instruction && r.mnemonic.startsWith("CALL"));
    assert(call, `no call in twice: ${JSON.stringify(rows.map((r) => [r.address, r.mnemonic]))}`);
    const pt = (await c.evaluate(`(() => { const v = window.__revkit.view; const b = v.canvas.getBoundingClientRect(); return { x: b.left + 7, y: b.top + ${call.row} * v.rowH - v.scrollY + v.rowH / 2 }; })()`)) as { x: number; y: number };
    await c.mouse.click(pt.x, pt.y);
    await untilEmu("breakpoint set", (e) => e.breakpoints.includes(call.address));
    await c.keyboard.press("F9");
    e = emuOf(await untilEmu("at the breakpoint", (e) => e.stop === "breakpoint" && e.pc === call.address))!;
    // The decompiler (the emulator shares its tab group) marks the C the call is in.
    await c.keyboard.press("Control+3");
    await c.waitForFunction(() => [...document.querySelectorAll("#cm .cm-pc-line")].some((l) => (l.textContent ?? "").includes("(")), undefined, { timeout: 10000 });
    // Over the call (F8): checksum ran, its result is in RAX.
    await c.keyboard.press("F8");
    e = emuOf(await untilEmu("over the call", (e) => e.stop === "stepped" && e.pc !== call.address))!;
    assert(e.changed.includes("RAX"), `after the call: ${JSON.stringify(e)}`);
    // To the end: twice returns to the session's return trap.
    await c.keyboard.press("F9");
    await untilEmu("returned", (e) => e.stop === "returned");
    await c.keyboard.press("Control+8");  // the emulator's tab again
    const status = (await c.textContent("[data-testid=emu-status]")) ?? "";
    assert(status.includes("returned") && status.includes("value"), `status: ${status}`);
    await c.click("[data-testid=emu-close]");
    await c.waitForSelector("[data-testid=emu-empty]", { state: "visible" });
    await untilEmu("closed", (e) => !e.active && e.pc === null);
    await c.context().close();
  });

  await check("debugger: launch under gdbserver, break, step, scrub the timeline", async () => {
    let gdbserver = true;
    try {
      execFileSync("sh", ["-c", "command -v gdbserver"], { stdio: "ignore" });
    } catch {
      gdbserver = false;
    }
    if (!gdbserver) {
      log("  (skipped: gdbserver is not installed)");
      return;
    }
    const c = await open(base, "", `#${hx(twice)}`);
    await until(c, "twice", (s) => s.address === hx(twice) && s.decompName !== null);
    type Dbg = {
      active: boolean; busy: boolean; pc: string | null; stop: string | null; breakpoints: string[]; changed: string[]; steps: string;
      target: string | null; running: boolean; snapshot: string | null; first: string; last: string; historical: boolean;
      threads: number; modules: string[]; slide: string; mapped: boolean;
      frames: { function: string; how: string; address: string | null }[]; frame: number;
      watches: { expr: string; text: string; error: string; changed: boolean }[];
      disasm: { address: string; program: string | null; text: string; pc: boolean; symbol: string }[];
      bps: { id: number; address: string | null; condition: string; ignore: number; disabled: boolean; hits: string; error: string; inserted: boolean }[];
    };
    const dbgOf = (s: Snap) => (s as unknown as { emu: Dbg | null }).emu;
    const untilDbg = (what: string, pred: (e: Dbg) => boolean, ms = 20000) =>
      until(c, what, (s) => !!dbgOf(s) && !dbgOf(s)!.busy && pred(dbgOf(s)!), ms);
    await c.keyboard.press("Control+8");
    await c.waitForSelector("[data-testid=dbg-target]");
    await c.click("[data-testid=dbg-clear-bps]");
    await untilDbg("no breakpoints", (e) => e.breakpoints.length === 0);
    // A breakpoint on twice's first instruction, from the gutter.
    await c.keyboard.press("Control+2");
    const rows = await visible(c);
    const entry = rows.find((r) => r.address === hx(twice) && r.kind === ROW.Instruction);
    assert(entry, "twice's first instruction is visible");
    const pt = (await c.evaluate(`(() => { const v = window.__revkit.view; const b = v.canvas.getBoundingClientRect(); return { x: b.left + 7, y: b.top + ${entry.row} * v.rowH - v.scrollY + v.rowH / 2 }; })()`)) as { x: number; y: number };
    await c.mouse.click(pt.x, pt.y);
    await untilDbg("breakpoint at twice", (e) => e.breakpoints.includes(hx(twice)));
    // A conditional breakpoint (feature debugger-conditions) on checksum,
    // from the palette: main's call (its length isn't 4) is passed over, so
    // the run below stops at twice first; twice's own call (4 bytes) would stop.
    const checksumAt = await sym("checksum");
    await palette(c, "checksum");
    await until(c, "listing at checksum", (s) => s.address === hx(checksumAt));
    await c.keyboard.press("Control+Shift+P");
    await c.waitForSelector("[data-testid=palette-input]");
    await c.fill("[data-testid=palette-input]", ">breakpoint condition");
    await c.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").startsWith("Debugger: breakpoint condition"));
    await c.keyboard.press("Enter");
    await c.waitForSelector("[data-testid=ask-fields] [data-field=condition]");
    await c.fill("[data-testid=ask-fields] [data-field=condition]", "(int)$RSI == 4");
    await c.press("[data-testid=ask-fields] [data-field=condition]", "Enter");
    await untilDbg("a conditional breakpoint", (e) => e.breakpoints.includes(hx(checksumAt)));
    await c.keyboard.press("Control+8");
    await c.locator("#emu [data-testid=dbg-bp]", { hasText: "if (int)$RSI == 4" }).waitFor({ state: "attached", timeout: 5000 });
    // Launch locally: the program under gdbserver, stopped before it runs; a PIE, so it slid.
    await c.keyboard.press("Control+8");
    await c.selectOption("[data-testid=dbg-target]", "launch");
    await c.click("[data-testid=dbg-start]");
    let e = dbgOf(await untilDbg("launched", (e) => e.active && e.target === "gdb-remote"))!;
    assert(e.mapped && e.slide !== "0", `mapping: ${JSON.stringify(e)}`);
    // Continue (F9) to the breakpoint: the pc mark is at twice's static address.
    await c.focus("#listing-canvas");
    await c.keyboard.press("F9");
    e = dbgOf(await untilDbg("at twice", (e) => e.stop === "breakpoint" && e.pc === hx(twice)))!;
    await until(c, "listing at twice", (s) => s.address === hx(twice));
    const atBreak = e.last;
    assert(e.threads === 1, `threads ${e.threads}`);
    const cbp = e.bps.find((b) => b.address === hx(checksumAt));
    assert(cbp && cbp.condition === "(int)$RSI == 4" && cbp.hits === "1" && cbp.inserted, `checksum's breakpoint passed over once: ${JSON.stringify(e.bps)}`);
    await c.keyboard.press("Control+8");
    assert((await c.locator("#emu [data-testid=dbg-bp]", { hasText: "if (int)$RSI == 4" }).locator("[data-testid=dbg-bp-hits]").textContent()) === "1 hit", "the table counts the hit");
    // The call stack: twice, then its caller in the program; clicking the
    // caller's frame shows it in the listing and its registers.
    e = dbgOf(await untilDbg("a call stack", (e) => e.frames.length >= 2))!;
    assert(e.frames[0].function === "twice" && e.frames[0].address === hx(twice), `frames ${JSON.stringify(e.frames)}`);
    const caller = e.frames[1];
    assert(caller.address !== null && caller.function !== "" && caller.how !== "stack scan", `caller ${JSON.stringify(caller)}`);
    await c.keyboard.press("Control+8");
    await c.click("#emu [data-testid=dbg-frame][data-frame='1']");
    await untilDbg("frame 1 chosen", (e) => e.frame === 1);
    await until(c, "listing at the caller", (s) => s.address === caller.address);
    assert(await c.locator("#emu .emu-regs.frame").count() === 1, "the frame's registers shown");
    // Runtime disassembly (feature debugger-disassembly): a frame outside
    // the program (the C library's call of main) shows its instructions in
    // the Disassembly box; an expression shows the pc's, marked.
    const outside = e.frames.findIndex((f) => f.address === null);
    if (outside > 0) {
      await c.click(`#emu [data-testid=dbg-frame][data-frame='${outside}']`);
      e = dbgOf(await untilDbg("a library's instructions", (e) => e.disasm.length > 0 && e.disasm[0].program === null))!;
      assert(e.disasm.every((i) => i.text.length > 0), `disassembly ${JSON.stringify(e.disasm.slice(0, 3))}`);
    }
    await c.fill("[data-testid=dbg-disasm-input]", "$RIP");
    await c.press("[data-testid=dbg-disasm-input]", "Enter");
    e = dbgOf(await untilDbg("the pc's instructions", (e) => e.disasm.length > 0 && e.disasm[0].pc))!;
    assert(e.disasm[0].program === hx(twice) && e.disasm[0].symbol === "twice", `at the pc: ${JSON.stringify(e.disasm[0])}`);
    await c.focus("#listing-canvas");
    await c.click("#emu [data-testid=dbg-frame][data-frame='0']");
    await untilDbg("frame 0 again", (e) => e.frame === 0);
    // Copy runtime memory into the program (feature debugger-copy): the
    // stack's region as a new block, from the listing's Debugger menu; one
    // undo takes it out again.
    type MapResp = { blocks?: { name: string; range: { first: { offset: string } } }[] };
    const blocks = async () => ((await rpc<MapResp>(base, "QueryService/GetMemoryMap", { programId: "default/prog" })).blocks ?? []).map((b) => b.name);
    const before = await blocks();
    await c.keyboard.press("Control+2");
    await c.locator("#listing-canvas").click({ button: "right", position: { x: 200, y: 40 } });
    await c.click("[data-testid=ctx-debugger]");
    await c.click("[data-testid=submenu] [data-testid=ctx-dbg-copy]");
    await c.waitForSelector("[data-testid=ask-fields] [data-field=address]");
    await c.fill("[data-testid=ask-fields] [data-field=address]", "$RSP");
    await c.fill("[data-testid=ask-fields] [data-field=name]", "e2e_stack");
    await c.press("[data-testid=ask-fields] [data-field=address]", "Enter");
    await c.locator("[data-testid=choose] .palette-item", { hasText: "A new memory block" }).click();
    const t0 = Date.now();
    while (!(await blocks()).includes("e2e_stack")) {
      assert(Date.now() - t0 < 15000, `no block e2e_stack: ${JSON.stringify(await blocks())}`);
      await c.waitForTimeout(100);
    }
    await c.focus("#listing-canvas");
    await c.keyboard.press("Control+z");
    while ((await blocks()).includes("e2e_stack")) {
      assert(Date.now() - t0 < 30000, "the copy was not undone");
      await c.waitForTimeout(100);
    }
    assert(JSON.stringify(await blocks()) === JSON.stringify(before), `blocks after the undo: ${JSON.stringify(await blocks())}`);
    // Back to twice (the right-click moved the listing): frame 0 of the Stack.
    await c.keyboard.press("Control+8");
    await c.click("#emu [data-testid=dbg-frame][data-frame='0']");
    await until(c, "listing back at twice", (s) => s.address === hx(twice));
    // Emulate from here (feature debugger-emulate-from): an emulator on the
    // process's state; a step there; closing it comes back to the process, unchanged.
    await c.keyboard.press("Control+8");
    await c.click("[data-testid=dbg-emulate-here]");
    let fork = dbgOf(await untilDbg("an emulator from the process", (e) => e.target === "emulator" && (e as unknown as { parent: string | null }).parent === "gdb-remote"))!;
    assert(fork.pc === hx(twice), `the emulator at twice: ${fork.pc}`);
    await c.focus("#listing-canvas");
    await c.keyboard.press("F7");
    fork = dbgOf(await untilDbg("a step in the emulator", (e) => e.target === "emulator" && e.pc !== hx(twice)))!;
    await c.keyboard.press("Control+8");
    await c.click("[data-testid=emu-close]");
    fork = dbgOf(await untilDbg("back to the process", (e) => e.target === "gdb-remote"))!;
    assert(fork.pc === hx(twice) && fork.stop === "breakpoint", `the process as it was: ${JSON.stringify({ pc: fork.pc, stop: fork.stop })}`);
    // Value hovers (feature debugger-values): in the decompiler, twice's
    // parameter is argc (1); in the listing, a memory operand's register and
    // what the operand addresses, with the registers at the stop.
    await c.keyboard.press("Control+3");
    await until(c, "twice decompiled", (s) => s.decompName === "twice");
    const card = "[data-testid=hover]";
    await c.locator("#cm .cm-content span.k-pa").first().hover();
    await c.locator(`${card} [data-testid=hc-value]`).waitFor({ timeout: 10000 });
    const pv = (await c.locator(`${card} [data-testid=hc-value]`).textContent()) ?? "";
    assert(pv === "1", `parameter value ${pv}; card ${await c.locator(card).textContent()}`);
    await c.mouse.move(2, 2);
    await c.locator(card).waitFor({ state: "detached", timeout: 5000 });
    type LRows = { rows?: { address: { offset: string }; kind: string; tokens?: { text: string }[] }[] };
    const lrows = ((await rpc<LRows>(base, "QueryService/GetListing", { programId: "default/prog", addresses: { start: { offset: String(twice) }, maxRows: 12 } })).rows ?? []).filter(
      (r) => r.kind === "LISTING_ROW_KIND_INSTRUCTION",
    );
    const memRow = lrows.find((r) => (r.tokens ?? []).map((t) => t.text).join("").includes("[RSP"));
    assert(memRow, `an instruction of twice addresses the stack: ${JSON.stringify(lrows.map((r) => (r.tokens ?? []).map((t) => t.text).join("")))}`);
    const memAt = BigInt(memRow.address.offset);
    await c.keyboard.press("Control+2");
    let values: string[] = [];
    for (let attempt = 0; attempt < 8 && values.length < 2; attempt++) {
      const pt = (await c.evaluate(`window.__revkit.app.operandPoint(0x${hx(memAt)}n, "RSP")`)) as { x: number; y: number } | null;
      if (!pt) {
        await c.waitForTimeout(200);
        continue;
      }
      await c.mouse.move(pt.x, pt.y + (attempt % 2));
      try {
        await c.locator(`${card} [data-testid=hc-value]`).nth(1).waitFor({ timeout: 3000 });
        values = await c.locator(`${card} [data-testid=hc-value]`).allTextContents();
      } catch {
        /* moved: again */
      }
    }
    assert(values.length === 2 && /^0x[0-9a-f]+$/.test(values[0]), `register and operand values: ${JSON.stringify(values)}`);
    await c.mouse.move(2, 2);
    // Watches (feature debugger-watches): typed in, and the decompiler
    // parameter's from its right-click menu (evaluated in twice's frame).
    await c.keyboard.press("Control+8");
    for (const w of ["$RIP", "$RDI"]) {
      await c.fill("[data-testid=dbg-watch-input]", w);
      await c.press("[data-testid=dbg-watch-input]", "Enter");
    }
    await c.focus("#listing-canvas");  // out of the watch field, which keeps its keys
    await c.keyboard.press("Control+3");
    const ptok = c.locator("#cm .cm-content span.k-pa").first();
    const pname = ((await ptok.textContent()) ?? "").trim();
    await ptok.click();
    await ptok.click({ button: "right" });
    await c.click("[data-testid=ctx-dbg-watch]");
    await c.waitForSelector("[data-testid=ask] .ask-input");
    assert((await c.inputValue("[data-testid=ask] .ask-input")) === pname, "the prompt offers the variable");
    await c.keyboard.press("Enter");
    e = dbgOf(await untilDbg("three watches", (e) => e.watches.length === 3 && e.watches.every((w) => !!w.text || !!w.error)))!;
    assert(e.watches[1].text === "0x1" && e.watches[2].expr === pname && e.watches[2].text === "1", `watches ${JSON.stringify(e.watches)}`);
    // One step (F7): RIP changed.
    await c.keyboard.press("F7");
    e = dbgOf(await untilDbg("a step", (e) => e.stop === "stepped" && e.pc !== hx(twice)))!;
    assert(e.changed.includes("RIP"), `changed: ${e.changed}`);
    // The watches against the stop before: RIP moved, RDI did not.
    e = dbgOf(await untilDbg("watches after the step", (e) => e.watches.length === 3 && e.watches[0].changed))!;
    assert(!e.watches[1].changed, `watches ${JSON.stringify(e.watches)}`);
    await c.keyboard.press("Control+8");
    assert((await c.locator("#emu [data-testid=dbg-watch][data-changed]").count()) === 1, "one watch marked changed");
    // Removed again (watches are kept per program in this browser).
    for (let i = 0; i < 3; i++) await c.locator("#emu [data-testid=dbg-watch-remove]").first().click();
    await untilDbg("no watches", (e) => e.watches.length === 0);
    const stepped = e.pc;
    // Modules: the program among them.
    await c.keyboard.press("Control+8");
    await c.click("#emu [data-testid=dbg-modules-box] summary");
    await untilDbg("modules", (e) => e.modules.includes("prog"));
    // Scrub back to the breakpoint: registers and the pc mark as they were.
    await c.$eval("[data-testid=dbg-scrub]", (el, v) => {
      (el as HTMLInputElement).value = v;
      el.dispatchEvent(new Event("input"));
    }, atBreak);
    e = dbgOf(await untilDbg("back at the breakpoint", (e) => e.historical && e.pc === hx(twice)))!;
    assert(e.snapshot === atBreak, `snapshot ${e.snapshot}`);
    assert((await c.locator("#emu .emu-reg").count()) >= 16, "registers shown at the snapshot");
    await until(c, "listing back at twice", (s) => s.address === hx(twice));
    // And forward to now.
    await c.click("[data-testid=dbg-live]");
    await untilDbg("now again", (e) => !e.historical && e.pc === stepped);
    // To the end.
    await c.click("[data-testid=dbg-clear-bps]");
    await c.focus("#listing-canvas");
    await c.keyboard.press("F9");
    await untilDbg("exited", (e) => e.stop === "exited");
    await c.keyboard.press("Control+8");
    const out = (await c.textContent("pre[data-testid=emu-out]")) ?? "";
    assert(/^-?\d+ -?\d+$/m.test(out), `output: ${out}`);
    await c.click("[data-testid=emu-close]");
    await untilDbg("closed", (e) => !e.active);
    await c.context().close();
  });

  await check("debugger: the emulator steps back, and resumes from a past snapshot", async () => {
    const c = await open(base, "", `#${hx(twice)}`);
    await until(c, "twice", (s) => s.address === hx(twice) && s.decompName !== null);
    type Dbg = { active: boolean; busy: boolean; pc: string | null; stop: string | null; target: string | null; first: string; last: string; historical: boolean; snapshot: string | null; rewindable: boolean };
    const dbgOf = (s: Snap) => (s as unknown as { emu: Dbg | null }).emu;
    const untilDbg = (what: string, pred: (e: Dbg) => boolean, ms = 20000) =>
      until(c, what, (s) => !!dbgOf(s) && !dbgOf(s)!.busy && pred(dbgOf(s)!), ms);
    // Emulate from twice's entry; three steps.
    await c.focus("#listing-canvas");
    await c.keyboard.press("Control+Shift+P");
    await c.waitForSelector("[data-testid=palette-input]");
    await c.fill("[data-testid=palette-input]", ">emulate from here");
    await c.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "") === "Emulate from here");
    await c.keyboard.press("Enter");
    let e = dbgOf(await untilDbg("an emulator session", (e) => e.active && e.target === "emulator" && e.pc === hx(twice)))!;
    assert(e.rewindable, "the emulator can go back");
    const pcs: string[] = [e.pc!];
    for (let i = 0; i < 3; i++) {
      await c.focus("#listing-canvas");
      await c.keyboard.press("F7");
      e = dbgOf(await untilDbg(`step ${i + 1}`, (e) => e.last === String(i + 1)))!;
      pcs.push(e.pc!);
    }
    // Back (Shift+F7, then the button): the pc as it was.
    await c.focus("#listing-canvas");
    await c.keyboard.press("Shift+F7");
    e = dbgOf(await untilDbg("one back", (e) => e.last === "2"))!;
    assert(e.pc === pcs[2] && !e.historical, `after one back: ${JSON.stringify(e)}`);
    await c.keyboard.press("Control+8");
    await c.click("[data-testid=dbg-back]");
    e = dbgOf(await untilDbg("two back", (e) => e.last === "1"))!;
    assert(e.pc === pcs[1], `after two back: ${e.pc} (want ${pcs[1]})`);
    // Scrub to the start; Resume from here, keeping the later snapshot as a trace.
    await c.$eval("[data-testid=dbg-scrub]", (el) => {
      (el as HTMLInputElement).value = "0";
      el.dispatchEvent(new Event("input"));
    });
    await untilDbg("at snapshot 0", (e) => e.historical && e.snapshot === "0");
    await c.click("[data-testid=dbg-resume-here]");
    await c.locator("[data-testid=choose] .palette-item", { hasText: "Keep them as a trace" }).click();
    e = dbgOf(await untilDbg("resumed from 0", (e) => !e.historical && e.last === "0"))!;
    assert(e.pc === pcs[0], `back at the start: ${e.pc}`);
    await c.focus("#listing-canvas");
    await c.keyboard.press("F7");
    e = dbgOf(await untilDbg("on again", (e) => e.last === "1"))!;
    assert(e.pc === pcs[1], `the same first step: ${e.pc}`);
    const traces = await rpc<{ traces?: { name: string }[] }>(base, "DebugService/ListDebugTraces", { programId: "default/prog" });
    assert((traces.traces ?? []).some((t) => t.name.startsWith("branch-0-")), `the branch saved: ${JSON.stringify(traces)}`);
    await c.click("[data-testid=emu-close]");
    await untilDbg("closed", (e) => !e.active);
    await c.context().close();
  });

  await check("debugger: firmware on a machine, the timer's interrupts on the timeline", async () => {
    // The timer fixture (src/emu/tests/fixtures/fwemu/arm_timer.c): raw ARMv4T on
    // the versatilepb machine, saved with the program.
    const fix = path.join(root, "src/emu/tests/fixtures/fwemu");
    const out = path.join(tmp, "fwemu");
    try {
      execFileSync("sh", [path.join(fix, "build.sh"), "clang", "ld.lld", "llvm-objcopy", out], { stdio: "ignore" });
    } catch {
      log("  (skipped: needs clang, ld.lld and llvm-objcopy)");
      return;
    }
    await rpc(base, "ProjectService/ImportProgram", {
      projectId: "default", path: path.join(out, "arm_timer.bin"), name: "arm_timer", options: { format: "raw", languageId: "ARM:LE:32:v4t" },
    });
    await rpc(base, "EmulatorService/SaveMachine", { programId: "default/arm_timer", name: "versatilepb", machine: readFileSync(path.join(fix, "versatilepb.json"), "utf8") });
    const ctx = await browser!.newContext({ viewport: { width: 1500, height: 900 } });
    const c = await ctx.newPage();
    c.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
    await c.goto(`${base}/?program=default%2Farm_timer&user=e2e&theme=dark`);
    await c.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    type Dbg = { active: boolean; busy: boolean; pc: string | null; stop: string | null; machine: string | null; events: string[]; eventSnapshots: string[]; historical: boolean; snapshot: string | null };
    const dbgOf = (s: Snap) => (s as unknown as { emu: Dbg | null }).emu;
    const untilDbg = (what: string, pred: (e: Dbg) => boolean, ms = 30000) => until(c, what, (s) => !!dbgOf(s) && !dbgOf(s)!.busy && pred(dbgOf(s)!), ms);
    await c.keyboard.press("Control+8");
    await c.waitForSelector("[data-testid=dbg-target]");
    // Emulator (machine…): the saved machine is offered.
    await c.selectOption("[data-testid=dbg-target]", "machine");
    await c.waitForFunction(() => [...document.querySelectorAll("[data-testid=dbg-machine] option")].some((o) => (o as HTMLOptionElement).value === "versatilepb"));
    await c.selectOption("[data-testid=dbg-machine]", "versatilepb");
    await c.click("[data-testid=dbg-start]");
    await untilDbg("a session on the machine", (e) => e.active && e.machine === "arm");
    // Run (F9) to the end: ten timer IRQs and two FIQs on the timeline.
    await c.focus("#listing-canvas");
    await c.keyboard.press("F9");
    let e = dbgOf(await untilDbg("exited with the interrupts on the timeline", (e) => e.stop === "exited" && e.events.length > 0))!;
    const irqs = e.events.filter((k) => k === "irq").length;
    const fiqs = e.events.filter((k) => k === "fiq").length;
    assert(irqs === 10 && fiqs === 2, `events: ${e.events.join(" ")}`);
    await c.keyboard.press("Control+8");
    assert((await c.locator("#emu .dbg-event[data-kind=irq]").count()) === 10, "ten IRQ marks under the scrubber");
    // IRQs, FIQs and the program's SWIs (its waits and its exit).
    const counted = /(\d+) exceptions/.exec((await c.textContent("[data-testid=dbg-events-label]")) ?? "");
    assert(counted && Number(counted[1]) >= 12, `the count of exceptions: ${counted?.[0]}`);
    const outText = (await c.textContent("pre[data-testid=emu-out]")) ?? "";
    assert(outText.includes("ticks 10 fiq 2 r8 kept"), `output: ${outText}`);
    // A mark goes to its snapshot: the IRQ vector.
    const first = e.eventSnapshots[e.events.indexOf("irq")];
    await c.locator("#emu .dbg-event[data-kind=irq]").first().click();
    e = dbgOf(await untilDbg("at the first IRQ: the vector", (e) => e.historical && e.snapshot === first && e.pc === "18"))!;
    assert(/irq/.test((await c.textContent("[data-testid=dbg-scrub-label]")) ?? ""), "the snapshot is labelled with its event");
    // A starter machine, derived in one click.
    await c.click("[data-testid=dbg-derive]");
    await c.waitForFunction(() => ((document.querySelector("[data-testid=dbg-machine-json]") as HTMLTextAreaElement | null)?.value ?? "").includes("starter"), null, { timeout: 60000 });
    await c.click("[data-testid=emu-close]");
    await untilDbg("closed", (e) => !e.active);
    await ctx.close();
  });

  await check("open dialog: an import's progress bar, phase by phase, to the end", async () => {
    const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", {});
    if (!(info.features ?? []).includes("import-progress")) {
      log("  (skipped: the daemon predates import-progress)");
      return;
    }
    // Firmware that takes a while: armfw scaled up with 8000 generated
    // functions (0.9 MB; discovery searches it as it would a real image).
    const fix = path.join(root, "src/analysis/tests/fixtures/armfw");
    const out = path.join(tmp, "armfw-bulk");
    try {
      execFileSync("sh", [path.join(fix, "build.sh"), "clang", "ld.lld", "llvm-objcopy", out, "-O2", "8000"], { stdio: "ignore" });
    } catch {
      log("  (skipped: needs clang, ld.lld, llvm-objcopy and python3)");
      return;
    }
    // Every state the bar shows, recorded in the page as it changes (the
    // page navigates away once the program opens).
    type Shown = { state: string; phase: string; text: string; now: string | null; live: string };
    const shown: Shown[] = [];
    const p = await open(base);
    await p.exposeFunction("__importProgress", (s: Shown) => void shown.push(s));
    await p.evaluate(() => {
      const send = (window as unknown as { __importProgress: (s: unknown) => void }).__importProgress;
      let last = "";
      new MutationObserver(() => {
        const el = document.querySelector("[data-testid=import-progress]") as HTMLElement | null;
        if (!el || el.hidden) return;
        const s = {
          state: el.dataset.state ?? "",
          phase: el.dataset.phase ?? "",
          text: el.querySelector("[data-testid=import-progress-text]")?.textContent ?? "",
          now: el.querySelector("[role=progressbar]")?.getAttribute("aria-valuenow") ?? null,
          live: el.querySelector("[aria-live]")?.textContent ?? "",
        };
        const key = JSON.stringify(s);
        if (key !== last) send(s);
        last = key;
      }).observe(document.body, { subtree: true, childList: true, attributes: true, characterData: true });
    });
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+o");
    await p.waitForSelector("[data-testid=open-dialog]");
    await p.click("[data-testid=open-import-binary]");
    await p.fill("[data-testid=open-path]", path.join(out, "fw.bin"));
    await p.click("[data-testid=raw-options] summary");
    await p.fill("[data-testid=raw-language]", "ARM:LE:32:v4t");
    await p.click("[data-testid=raw-import]");
    await p.waitForSelector("[data-testid=import-progress]:not([hidden])");
    // Mid-import: a fraction and a line saying what it's doing.
    await p.waitForFunction(() => {
      const el = document.querySelector("[data-testid=import-progress]") as HTMLElement | null;
      return !!el && el.dataset.state === "running" && el.querySelector("[role=progressbar]")?.hasAttribute("aria-valuenow");
    }, null, { timeout: 120000 * timeScale });
    if (process.env.RK_SHOTS) await p.locator("[data-testid=open-dialog]").screenshot({ path: path.join(process.env.RK_SHOTS, "import-progress.png") }).catch(() => {});
    // It completes, and the program opens. Under ASan (a Debug build) the
    // import alone takes about three minutes on a quiet machine and four on
    // a busy one, master and this tree alike, so it gets ten.
    await p.waitForURL(/program=default%2Ffw\.bin/, { timeout: 600000 });
    await p.waitForSelector("body[data-ready='1']", { timeout: 60000 });
    await p.context().close();
    log(`  ${shown.length} states: ${shown.map((s) => `${s.now ?? "…"}% ${s.text}`).join(" | ").slice(0, 400)}`);
    const running = shown.filter((s) => s.state === "running" && s.now !== null);
    assert(running.some((s) => /function/i.test(s.text) && /\d/.test(s.text)), `a phase text with functions found: ${JSON.stringify(shown)}`);
    assert(shown.some((s) => s.live !== ""), "the live region announced the phase");
    const fractions = shown.filter((s) => s.now !== null).map((s) => Number(s.now));
    assert(fractions.every((v, i) => i === 0 || v >= fractions[i - 1]), `the bar never goes back: ${fractions.join(" ")}`);
    const last = shown[shown.length - 1];
    assert(last?.state === "done" && last.now === "100", `completed: ${JSON.stringify(last)}`);
    assert(/Imported fw\.bin/.test(last.text), `the last line: ${last.text}`);
  });

  // Raw layout detection in the Open dialog (e2e/detect.ts).
  if (wants("detect.ts")) await detectChecks({ base, exe, root, tmp, check, open, rpc, assert, log });

  // ---------------------------------------------------------- phase 5 --

  interface GraphState {
    entry: string | null;
    blocks: { start: string; lines: number; exit: boolean; entry: boolean }[];
    edges: { from: number; to: number; kind: number }[];
    selected: string | null;
    stats: { blocks: number; layoutMs: number } | null;
  }
  const graphOf = (p: Page) => p.evaluate("window.__revkit.app.graph.describe()") as Promise<GraphState>;
  async function untilGraph(p: Page, what: string, pred: (g: GraphState) => boolean, ms = 10000) {
    const end = Date.now() + ms;
    let g = await graphOf(p);
    while (!pred(g)) {
      if (Date.now() > end) throw new Error(`timed out waiting for ${what}; graph: ${JSON.stringify({ ...g, blocks: g.blocks.length, edges: g.edges.length })}`);
      await p.waitForTimeout(50);
      g = await graphOf(p);
    }
    return g;
  }
  const EDGE = { FallThrough: 1, True: 2, False: 3, Jump: 4, Switch: 5 };

  await check("graph: checksum's blocks and typed edges, selection linked with the listing and C, a call followed", async () => {
    await go(a, checksum);
    await a.focus("#listing-canvas");
    await a.keyboard.press(" ");
    await a.waitForSelector("[data-testid=graph-canvas]", { state: "visible" });
    const g = await untilGraph(a, "checksum's graph", (g) => g.entry === hx(checksum) && g.blocks.length >= 3);
    assert(g.blocks.find((b) => b.entry)?.start === hx(checksum), `entry block: ${JSON.stringify(g.blocks)}`);
    assert(g.blocks.some((b) => b.exit), "an exit block");
    const kinds = new Set(g.edges.map((e) => e.kind));
    assert(kinds.has(EDGE.True) && kinds.has(EDGE.False), `edge kinds ${[...kinds]}`);
    assert(g.edges.some((e) => e.kind === EDGE.True && e.to <= e.from), "the loop's back edge");
    assert((await snap(a)).views.includes("graph") && !(await snap(a)).views.includes("listing"), "Space shows the graph in the listing's place");
    // Graph -> listing and C: click an instruction of the last block.
    const last = g.blocks[g.blocks.length - 1];
    const pt = (await a.evaluate(`window.__revkit.app.graph.pointOf(0x${last.start}n)`)) as { x: number; y: number };
    await a.mouse.click(pt.x, pt.y);
    await until(a, "listing at the clicked instruction", (s) => s.address === last.start && s.decompName === "checksum");
    // Listing -> graph: another instruction is highlighted there.
    await a.evaluate(`window.__revkit.app.navigate(0x${g.blocks[1].start}n)`);
    await untilGraph(a, "graph follows the selection", (x) => x.selected === g.blocks[1].start);
    // Double-click a call in main's graph: into the callee.
    await a.evaluate(`window.__revkit.app.navigate(0x${hx(main)}n)`);
    await untilGraph(a, "main's graph", (x) => x.entry === hx(main));
    const rows = await rpc<{ blocks: { rows: { address: { offset: string }; flow: string; flowTargets?: { offset: string }[] }[] }[] }>(base, "QueryService/GetFunctionGraph", { programId: "default/prog", function: { offset: String(main) }, omitBytes: true });
    const call = rows.blocks.flatMap((b) => b.rows).find((r) => r.flow === "FLOW_KIND_CALL" && r.flowTargets?.some((t) => BigInt(t.offset) === twice))!;
    assert(call, "main calls twice");
    const cp = (await a.evaluate(`window.__revkit.app.graph.pointOf(${call.address.offset}n)`)) as { x: number; y: number } | null;
    assert(cp, "the call is in main's graph");
    await a.mouse.dblclick(cp.x, cp.y);
    await until(a, "followed into twice", (s) => s.decompName === "twice" && s.address === hx(twice));
    await untilGraph(a, "twice's graph", (x) => x.entry === hx(twice));
    await a.focus("[data-testid=graph-canvas]");
    await a.keyboard.press(" ");
    await until(a, "the listing again", (s) => s.views.includes("listing"));
  });

  await check("call graph: callers and callees of the current function, expandable", async () => {
    await go(a, main);
    await a.keyboard.press("Control+5");
    type CallRow = { name: string; entry: string; dir: string; depth: number; open: boolean; loading: boolean; leaf: boolean };
    const tree = () => a.evaluate("window.__revkit.app.calls.describe()") as Promise<CallRow[]>;
    const untilTree = async (what: string, pred: (t: CallRow[]) => boolean) => {
      const end = Date.now() + 10000;
      let t = await tree();
      while (!pred(t)) {
        if (Date.now() > end) throw new Error(`timed out waiting for ${what}: ${JSON.stringify(t)}`);
        await a.waitForTimeout(50);
        t = await tree();
      }
      return t;
    };
    let t = await untilTree("main's callees", (t) => t.some((r) => r.dir === "callees" && r.depth === 1 && r.name === "twice") && !t.some((r) => r.loading));
    assert(t.some((r) => r.dir === "callees" && r.depth === 1 && r.name === "checksum"), `callees: ${JSON.stringify(t)}`);
    await a.evaluate("window.__revkit.app.calls.expandNamed('callees', 'twice')");
    t = await untilTree("twice expanded", (t) => t.some((r) => r.dir === "callees" && r.depth === 2 && r.name === "checksum"));
    // Callers of checksum: main and twice.
    await go(a, checksum);
    t = await untilTree("checksum's callers", (t) => t.filter((r) => r.dir === "callers" && r.depth === 1).length >= 2 && !t.some((r) => r.loading));
    const callers = t.filter((r) => r.dir === "callers" && r.depth === 1).map((r) => r.name);
    assert(callers.includes("main") && callers.includes("twice"), `callers ${callers}`);
    // Clicking one goes there.
    await a.locator("[data-testid=calls-tree] .calls-row[data-dir=callers][data-depth='1']", { hasText: "twice" }).click();
    await until(a, "at twice", (s) => s.address === hx(twice));
    await a.keyboard.press("Control+3");
  });

  await check("strings window: the program's strings with references; clicking one goes there", async () => {
    await a.keyboard.press("Control+6");
    await a.waitForSelector("[data-testid=data-view] .data-row[data-i]");
    const items = (await a.evaluate("window.__revkit.app.data.visible()")) as { address: string; value: string; refs: number }[];
    const fmt = items.find((d) => d.value === "%u %d\n");
    assert(fmt && fmt.refs >= 1, `strings: ${JSON.stringify(items.slice(0, 20))}`);
    await a.fill("[data-testid=data-filter]", "%u");
    await a.locator("[data-testid=data-count]", { hasText: /^1 item$/ }).waitFor({ timeout: 5000 });
    await a.locator("[data-testid=data-view] .data-row[data-i]").first().click();
    await until(a, "the listing at the string", (s) => s.address === fmt.address && s.rowKind === ROW.Data);
    await a.fill("[data-testid=data-filter]", "");
    await a.keyboard.press("Control+3");
  });

  await check("types: a new struct, used in a prototype, edited (C follows in both pages), undone", async () => {
    const second = await sym("second");
    const typesOf = (p: Page) => p.evaluate("window.__revkit.app.types.describe()") as Promise<{ names: string[]; shown: { name: string; c: string; origin: string } | null; editing: boolean; error: string }>;
    const untilTypes = async (p: Page, what: string, pred: (t: Awaited<ReturnType<typeof typesOf>>) => boolean) => {
      const end = Date.now() + 10000;
      let t = await typesOf(p);
      while (!pred(t)) {
        if (Date.now() > end) throw new Error(`timed out waiting for ${what}: ${JSON.stringify(t)}`);
        await p.waitForTimeout(50);
        t = await typesOf(p);
      }
      return t;
    };
    for (const p of [a, b]) {
      await p.focus("#listing-canvas");
      await p.keyboard.press("Control+7");
    }
    // A new struct: two ints, a and b.
    await a.selectOption("[data-testid=types-new]", "struct");
    await a.fill("[data-testid=type-name]", "pair");
    await a.fill("tr:nth-child(2) [data-testid=field-name]", "a");
    await a.click("[data-testid=field-add]");
    await a.locator("[data-testid=edit-field]").nth(1).waitFor();
    await a.fill("tr:nth-child(3) [data-testid=field-name]", "b");
    await a.click("[data-testid=type-save]");
    let t = await untilTypes(a, "pair saved", (t) => !t.editing && t.shown?.name === "pair");
    assert(t.shown!.c.includes("int b; /* 0x4 */"), `definition: ${t.shown!.c}`);
    await untilTypes(b, "pair in page B", (t) => t.names.includes("struct pair"));
    // Used in second's prototype (by hash, so the decompiler gets it).
    await go(a, second);
    await go(b, second);
    await a.focus("#listing-canvas");
    await a.keyboard.press("y");
    await answer(a, "int second(struct pair *p)");
    for (const p of [a, b]) await until(p, "p->b in C", (s) => s.decompName === "second" && /\bp->b\b/.test(s.decompText));
    // Edit: b becomes count; every use follows, in both pages.
    await a.evaluate("window.__revkit.app.types.showNamed('pair')");
    await untilTypes(a, "pair shown", (t) => t.shown?.name === "pair");
    await a.click("[data-testid=type-edit]");
    await a.fill("tr:nth-child(3) [data-testid=field-name]", "count");
    await a.click("[data-testid=type-save]");
    t = await untilTypes(a, "pair edited", (t) => !t.editing && (t.shown?.c ?? "").includes("count"));
    for (const p of [a, b]) await until(p, "p->count in C", (s) => /\bp->count\b/.test(s.decompText));
    await b.evaluate("window.__revkit.app.types.showNamed('pair')");
    await untilTypes(b, "the edit in page B's types", (t) => (t.shown?.c ?? "").includes("int count;"));
    const hist = await rpc<{ entries: { provenance: { kind: string; id: string } }[] }>(base, "AssertionService/GetHistory", { key: { programId: "default/prog", kind: "FACT_KIND_TYPE_DEF", sub: "name:struct pair" } });
    assert(hist.entries.length === 2 && hist.entries.every((e) => e.provenance.kind === "PROVENANCE_KIND_USER" && e.provenance.id === "e2e"), `bindings: ${JSON.stringify(hist.entries)}`);
    // Undo the edit: b again, everywhere.
    await undoIn(a);
    for (const p of [a, b]) await until(p, "p->b again", (s) => /\bp->b\b/.test(s.decompText));
    await untilTypes(b, "page B's types back to b", (t) => (t.shown?.c ?? "").includes("int b;"));
    // Undo the prototype and the struct.
    await undoIn(a);
    await until(b, "prototype gone", (s) => !s.decompText.includes("pair"));
    await undoIn(a);
    await untilTypes(b, "pair gone in page B", (t) => !t.names.includes("struct pair"));
    // The library archive's types (revkit's libc-lp64 for this x86-64 ELF
    // since library-types; Ghidra's generic_clib_64 before).
    await a.selectOption("[data-testid=types-source]", "2");
    await a.fill("[data-testid=types-filter]", "timespec");
    await a.evaluate("window.__revkit.app.types.showNamed('timespec')");
    t = await untilTypes(a, "a library struct", (t) => t.shown?.name === "timespec");
    assert(/^derived · library:(libc-lp64|generic_clib_64)$/.test(t.shown!.origin) && t.shown!.c.includes("tv_sec"), `library type: ${JSON.stringify(t.shown)}`);
    await a.selectOption("[data-testid=types-source]", "1");
    await a.fill("[data-testid=types-filter]", "");
    for (const p of [a, b]) await p.keyboard.press("Control+3");
  });

  // ---- Types: header import, Edit in C, the editor's operations (docs/ui.md, "Types") ----

  interface FieldState { name: string; type: string; offset: number; bit: number; bits: number; size: number; flex: boolean; problem: string }
  interface TypesState {
    names: string[];
    shown: { name: string; hash: string; c: string; origin: string } | null;
    editing: boolean;
    error: string;
    tab: string;
    draft: { name: string; size: number; packing: string; align: number; fields: FieldState[]; values: { name: string; value: string; shown: string; problem: string }[] } | null;
    layout: { ok: boolean; size: number; align: number; packed: boolean; identical: boolean; errors: string[]; profile: string } | null;
    notes: string[];
    group: string;
    folders: Record<string, string[]>;
  }
  interface ImportState { parsed: boolean; profile: string; buckets: { new: string[]; replaces: string[]; identical: string[] }; policies: Record<string, string>; prototypes: string[]; diagnostics: string[]; status: string; archive: { verified: number; types: number; mismatches: string[]; headerChanged: boolean; origin: string } | null; importable: boolean }
  const typesState = (p: Page) => p.evaluate("window.__revkit.app.types.describe()") as Promise<TypesState>;
  const untilT = async (p: Page, what: string, pred: (t: TypesState) => boolean, ms = 10000 * timeScale) => {
    const end = Date.now() + ms;
    let t = await typesState(p);
    while (!pred(t)) {
      if (Date.now() > end) throw new Error(`timed out waiting for ${what}: ${JSON.stringify(t)}`);
      await p.waitForTimeout(50);
      t = await typesState(p);
    }
    return t;
  };
  const importState = (p: Page) => p.evaluate("window.__revkit.app.types.importState()") as Promise<ImportState | null>;
  const untilImport = async (p: Page, what: string, pred: (s: ImportState) => boolean) => {
    const end = Date.now() + 10000 * timeScale;
    let s = await importState(p);
    while (!s || !pred(s)) {
      if (Date.now() > end) throw new Error(`timed out waiting for ${what}: ${JSON.stringify(s)}`);
      await p.waitForTimeout(50);
      s = await importState(p);
    }
    return s;
  };
  /** The types view's list unfiltered (the tree), so `names` lists every program type. */
  const allTypes = (p: Page) => p.evaluate("window.__revkit.app.types.showNamed('')");
  const showType = async (p: Page, name: string) => {
    await p.evaluate(`window.__revkit.app.types.showNamed(${JSON.stringify(name)})`);
    return untilT(p, `${name} shown`, (t) => t.shown?.name === name);
  };
  const history = (sub: string) => rpc<{ entries?: { revision: string; op: string; provenance: { kind: string; id: string; version?: string; session?: string } }[] }>(base, "AssertionService/GetHistory", { key: { programId: "default/prog", kind: "FACT_KIND_TYPE_DEF", sub } });
  const typeByName = async (name: string, kind = "TYPE_KIND_STRUCT") => {
    const r = await rpc<{ types?: { hash: string; name: string; superseded?: boolean }[] }>(base, "QueryService/FindTypes", { programId: "default/prog", nameContains: name, kinds: [kind] });
    const t = r.types?.find((x) => x.name === name && !x.superseded);
    assert(t, `no ${kind} ${name}`);
    const g = await rpc<{ types: { composite?: { fields: { name: string; offset?: string; bitOffset?: number; bitSize?: number }[]; packed?: boolean }; size?: string; alignment?: number; cDefinition: string }[] }>(base, "QueryService/GetTypes", { programId: "default/prog", hashes: [t.hash] });
    return g.types[0];
  };
  /** A struct made in the editor, field by field (its type, then its name). */
  const newStruct = async (p: Page, name: string, fields: [string, string][]) => {
    await p.selectOption("[data-testid=types-new]", "struct");
    await p.fill("[data-testid=type-name]", name);
    for (const [i, [type, fname]] of fields.entries()) {
      if (i > 0) {
        await p.click("[data-testid=field-add]");
        await untilT(p, `field ${i}`, (t) => (t.draft?.fields.length ?? 0) > i);
      }
      const row = p.locator("[data-testid=edit-field]").nth(i);
      await row.locator("[data-testid=field-type]").fill(type);
      await row.locator("[data-testid=field-type]").press("Tab");
      await untilT(p, `field ${i}'s type`, (t) => t.draft?.fields[i]?.type === type || (t.draft?.fields.length ?? 0) > fields.length);
      await p.locator("[data-testid=edit-field]").nth(i).locator("[data-testid=field-name]").fill(fname);
      await p.locator("[data-testid=edit-field]").nth(i).locator("[data-testid=field-name]").press("Tab");
    }
  };
  const save = async (p: Page, what: string, pred: (t: TypesState) => boolean) => {
    await p.click("[data-testid=type-save]");
    return untilT(p, what, (t) => !t.editing && pred(t));
  };
  const typesView = async () => {
    for (const p of [a, b]) {
      await p.focus("#listing-canvas");
      await p.keyboard.press("Control+7");
      await allTypes(p);
    }
  };
  const listingView = async () => {
    for (const p of [a, b]) {
      await allTypes(p);
      await p.focus("#listing-canvas");
      await p.keyboard.press("Control+3");
    }
  };

  await check("types: import a header (uploaded, then pasted): new, replaces (both definitions), identical, a diagnostic's line, policies, prototypes retyping by name; one revision in both pages; undo", async () => {
    await typesView();
    // A first import, uploaded: two structs, one to stay as it is and one to replace.
    const first = path.join(tmp, "first.h");
    writeFileSync(first, "struct keep { int x; };\nstruct duo { int a; int b; };\n");
    await a.click("[data-testid=types-import]");
    const [chooser] = await Promise.all([a.waitForEvent("filechooser"), a.click("[data-testid=hi-upload]")]);
    await chooser.setFiles(first);
    await a.waitForFunction(() => (document.querySelector("[data-testid=hi-text]") as HTMLTextAreaElement | null)?.value.includes("struct duo"), undefined, { timeout: 5000 });
    assert((await a.inputValue("[data-testid=hi-name]")) === "first.h", "the uploaded file's name");
    await a.click("[data-testid=hi-parse]");
    let st = await untilImport(a, "the first parse", (s) => s.parsed);
    assert(JSON.stringify(st.buckets.new.sort()) === JSON.stringify(["struct duo", "struct keep"]) && !st.buckets.replaces.length, `first buckets: ${JSON.stringify(st)}`);
    await a.click("[data-testid=hi-import]");
    await a.waitForSelector("[data-testid=header-import]", { state: "detached" });
    await untilT(b, "the first import in page B", (t) => t.names.includes("struct duo") && t.names.includes("struct keep"));
    // The second: an identical type, a replacing one, new ones, a broken one, constants and a prototype.
    const header = [
      "#define FLAG_A 1",
      "#define FLAG_B (FLAG_A << 3)",
      "struct keep { int x; };",
      "struct duo { int a; long b; };",
      "struct fresh { char *s; void (*cb)(int); };",
      "struct broken { mystery_t m; };",
      "int twice(int value);",
    ].join("\n") + "\n";
    await a.click("[data-testid=types-import]");
    await a.fill("[data-testid=hi-text]", header);
    await a.fill("[data-testid=hi-name]", "demo.h");
    await a.check("[data-testid=hi-retype]");
    await a.click("[data-testid=hi-parse]");
    st = await untilImport(a, "the parse", (s) => s.parsed);
    assert(st.profile === "x86_64-linux-gnu", `profile ${st.profile}`);
    for (const k of ["struct fresh", "struct broken", "enum demo_h_constants"]) assert(st.buckets.new.includes(k), `new: ${JSON.stringify(st.buckets)}`);
    assert(JSON.stringify(st.buckets.replaces) === '["struct duo"]' && JSON.stringify(st.buckets.identical) === '["struct keep"]', `buckets: ${JSON.stringify(st.buckets)}`);
    assert(st.policies["struct keep"] === "skip" && st.policies["struct duo"] === "import", `policies: ${JSON.stringify(st.policies)}`);
    assert(JSON.stringify(st.prototypes) === '["twice"]', `prototypes naming functions: ${st.prototypes}`);
    assert(st.diagnostics.some((d) => d.startsWith("6:") && d.includes("mystery_t")), `diagnostics: ${st.diagnostics}`);
    // A diagnostic shows its line.
    await a.locator("[data-testid=hi-diag]", { hasText: "mystery_t" }).first().click();
    const line = await a.locator("[data-testid=hi-line]").textContent();
    assert(line?.includes("    6  struct broken { mystery_t m; };"), `the diagnostic's line: ${line}`);
    // Both definitions of the replaced type, side by side.
    await a.locator("[data-testid=hi-item][data-key='struct duo']").click();
    await a.waitForFunction(() => (document.querySelector("[data-testid=hi-old-c]")?.textContent ?? "").includes("int b;"), undefined, { timeout: 5000 });
    const mine = await a.locator("[data-testid=hi-new-c]").textContent();
    assert(mine?.includes("long b;"), `the header's pair: ${mine}`);
    // Policies: skip the broken one, rename the fresh one.
    await a.locator("[data-testid=hi-item][data-key='struct broken'] [data-testid=hi-policy]").selectOption("skip");
    await a.locator("[data-testid=hi-item][data-key='struct fresh'] [data-testid=hi-policy]").selectOption("rename");
    await a.fill("[data-testid=hi-item][data-key='struct fresh'] [data-testid=hi-rename]", "fresh2");
    st = (await importState(a))!;
    assert(st.policies["struct broken"] === "skip" && st.policies["struct fresh"] === "rename:fresh2", `policies: ${JSON.stringify(st.policies)}`);
    const before = Number(await b.evaluate("document.body.dataset.revision"));
    await a.click("[data-testid=hi-import]");
    await a.waitForSelector("[data-testid=header-import]", { state: "detached" });
    // Page B: the renamed struct, the constants' enum, duo replaced, broken skipped; twice retyped.
    await untilT(b, "the import in page B", (t) => t.names.includes("struct fresh2") && t.names.includes("enum demo_h_constants") && !t.names.includes("struct broken") && !t.names.includes("struct fresh"));
    await showType(b, "duo");
    await untilT(b, "duo replaced in page B", (t) => (t.shown?.c ?? "").includes("long b;"));
    await go(b, twice);
    await until(b, "twice retyped in page B", (s) => s.decompName === "twice" && /\bint twice\(int value\)/.test(s.decompText));
    // One revision, import:header with the file as its version.
    const fresh = (await history("name:struct fresh2")).entries ?? [];
    const duo = (await history("name:struct duo")).entries ?? [];
    assert(fresh.length === 1 && fresh[0].provenance.kind === "PROVENANCE_KIND_IMPORT" && fresh[0].provenance.id === "header" && fresh[0].provenance.version === "demo.h", `fresh2's binding: ${JSON.stringify(fresh)}`);
    assert(duo.length === 2 && duo[1].revision === fresh[0].revision && Number(fresh[0].revision) === before + 1, `one revision: ${JSON.stringify({ duo, fresh, before })}`);
    // Undo: one step, everywhere.
    await undoIn(a);
    await allTypes(b);
    await untilT(b, "the import undone in page B", (t) => !t.names.includes("struct fresh2") && !t.names.includes("enum demo_h_constants") && t.names.includes("struct duo"));
    await showType(b, "duo");
    await untilT(b, "duo as before in page B", (t) => (t.shown?.c ?? "").includes("int b;"));
    await until(b, "twice as before in page B", (s) => s.decompName === "twice" && !/\bvalue\b/.test(s.decompText));
    await undoIn(a);
    await allTypes(b);
    await untilT(b, "the first import undone in page B", (t) => !t.names.includes("struct duo") && !t.names.includes("struct keep"));
  });

  await check("types: import a header from the daemon host (browsed), with an include folder (browsed); undo", async () => {
    const dir = path.dirname(exe);
    mkdirSync(path.join(dir, "inc"), { recursive: true });
    writeFileSync(path.join(dir, "inc", "sub.h"), "struct sub { int v; };\n");
    writeFileSync(path.join(dir, "hosted.h"), '#include "sub.h"\nstruct hosted { struct sub s; short t; };\n');
    await a.click("[data-testid=types-import]");
    await a.click("[data-testid=hi-browse]");
    const entry = a.locator("[data-testid=host-entry]", { hasText: /^hosted\.h/ });
    await entry.waitFor({ timeout: 5000 });
    await entry.click();
    await a.waitForSelector("[data-testid=host-browser]", { state: "detached" });
    assert((await a.inputValue("[data-testid=hi-path]")).endsWith("/hosted.h"), "the picked path");
    await a.click("[data-testid=hi-add-include]");
    await a.locator("[data-testid=host-entry]", { hasText: /^inc\// }).click();
    await a.waitForFunction(() => (document.querySelector("[data-testid=host-browser] .browse-path")?.textContent ?? "").endsWith("/inc"), undefined, { timeout: 5000 });
    await a.click("[data-testid=host-use-folder]");
    assert((await a.inputValue("[data-testid=hi-includes]")).endsWith("/inc"), "the include folder");
    await a.click("[data-testid=hi-parse]");
    const st = await untilImport(a, "the host header parsed", (s) => s.parsed);
    assert(st.buckets.new.includes("struct hosted") && st.buckets.new.includes("struct sub") && !st.diagnostics.length, `host header: ${JSON.stringify(st)}`);
    await a.click("[data-testid=hi-import]");
    await a.waitForSelector("[data-testid=header-import]", { state: "detached" });
    await untilT(b, "the host header's types in page B", (t) => t.names.includes("struct hosted") && t.names.includes("struct sub"));
    const h = (await history("name:struct hosted")).entries ?? [];
    assert(h[0]?.provenance.version === "hosted.h", `version: ${JSON.stringify(h)}`);
    await undoIn(a);
    await untilT(b, "undone in page B", (t) => !t.names.includes("struct hosted"));
  });

  await check("types: a type archive imported (both files uploaded, checked against the sidecar's hashes, one undo step) and exported (both files downloaded, byte for byte the debug build's); folders: move to category, drag onto a folder, search across folders; undo", async () => {
    await typesView();
    const program = await rpc<{ types?: unknown[] }>(base, "QueryService/FindTypes", { programId: "default/prog", sources: ["TYPE_SOURCE_PROGRAM"] });
    const clean = !(program.types ?? []).length;
    // A debug build's types to carry: its own program, exported by the daemon.
    const cc = process.env.CC ?? "cc";
    const src = path.join(tmp, "wire.c"), dbg = path.join(tmp, "wire-debug");
    writeFileSync(src, [
      "#include <stdint.h>",
      "struct __attribute__((packed)) wire { uint8_t tag; uint32_t len; uint16_t crc; };",
      "struct flags { unsigned a : 1, b : 3; int c : 5; };",
      "typedef struct node { struct node *next; struct wire w; struct flags f; } node_t;",
      "__attribute__((noinline)) int walk(node_t *n) { int s = 0; for (; n; n = n->next) s += n->w.len + n->f.c; return s; }",
      "int main(void) { node_t n = {0}; return walk(&n); }",
    ].join("\n") + "\n");
    execFileSync(cc, ["-g", "-O1", "-o", dbg, src]);
    const dbgId = (await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", { projectId: "default", path: dbg, name: "wire-debug" })).program.programId;
    const made = await rpc<{ header: string; sidecar: string; headerName: string; sidecarName: string }>(base, "TypeService/ExportTypeArchive", { programId: dbgId, scope: "TYPE_ARCHIVE_SCOPE_ALL" });
    assert(made.headerName === "wire-debug.h" && made.header.includes("#pragma pack(push, 1)\nstruct wire {"), `the archive: ${made.header.slice(0, 400)}`);
    const hFile = path.join(tmp, made.headerName), jFile = path.join(tmp, made.sidecarName);
    writeFileSync(hFile, made.header);
    writeFileSync(jFile, made.sidecar);

    // Import archive…: both files at once, parsed for the sidecar's data model, every hash checked.
    await a.click("[data-testid=types-import-archive]");
    await a.locator("[data-testid=header-import][data-mode=archive]").waitFor();
    const [chooser] = await Promise.all([a.waitForEvent("filechooser"), a.click("[data-testid=hi-upload-archive]")]);
    await chooser.setFiles([hFile, jFile]);
    await a.waitForFunction(() => (document.querySelector("[data-testid=hi-sidecar]") as HTMLTextAreaElement | null)?.value.includes("revkit-type-archive"), undefined, { timeout: 5000 });
    assert((await a.inputValue("[data-testid=hi-name]")) === "wire-debug.h", "the header's name");
    await a.click("[data-testid=hi-parse]");
    let st = await untilImport(a, "the archive parsed", (x) => x.parsed);
    assert(st.archive && st.archive.types >= 4 && st.archive.verified === st.archive.types && !st.archive.headerChanged && st.archive.origin === "wire-debug", `the check: ${JSON.stringify(st)}`);
    assert(st.buckets.new.includes("struct wire") && st.buckets.new.includes("typedef node_t") && st.importable, `buckets: ${JSON.stringify(st.buckets)}`);
    const before = Number(await b.evaluate("document.body.dataset.revision"));
    await a.click("[data-testid=hi-import]");
    for (let i = 0; i < 300 && (await a.$("[data-testid=header-import]")); i++) {
      const x = await importState(a);
      assert(!x?.status.startsWith("Import failed"), `the import: ${x?.status}`);
      await a.waitForTimeout(50);
    }
    assert(!(await a.$("[data-testid=header-import]")), `the import dialog closed: ${JSON.stringify(await importState(a))}`);
    // Page B: the types, under the archive's categories (the debug info's: the source file).
    let t = await untilT(b, "the archive's types in page B's folders", (x) => (x.folders["/wire.c"] ?? []).includes("struct wire") && (x.folders["/wire.c"] ?? []).includes("struct flags"));
    assert(t.group === "folders", `the tree by folder: ${t.group}`);
    const bound = (await history("name:struct wire")).entries ?? [];
    assert(bound.length === 1 && bound[0].provenance.kind === "PROVENANCE_KIND_IMPORT" && bound[0].provenance.id === "archive" && bound[0].provenance.version === "wire-debug" && Number(bound[0].revision) === before + 1, `one revision, import:archive: ${JSON.stringify(bound)}`);

    // Export archive…: both files downloaded; the program's types are the archive's, so the same bytes.
    const downloads: Download[] = [];
    a.on("download", (d) => downloads.push(d));
    await a.click("[data-testid=types-export-archive]");
    await a.locator("[data-testid=export-archive]").waitFor();
    await a.selectOption("[data-testid=ta-scope]", "all");
    await a.click("[data-testid=ta-export]");
    for (let i = 0; i < 200 && downloads.length < 2; i++) await a.waitForTimeout(50);
    assert(downloads.length === 2, `two downloads: ${downloads.map((d) => d.suggestedFilename())}`);
    const got = new Map<string, string>();
    for (const d of downloads) got.set(d.suggestedFilename(), readFileSync((await d.path())!, "utf8"));
    const want = clean ? made : await rpc<{ header: string; sidecar: string; headerName: string; sidecarName: string }>(base, "TypeService/ExportTypeArchive", { programId: "default/prog", scope: "TYPE_ARCHIVE_SCOPE_ALL" });
    assert(got.get(want.headerName) === want.header && got.get(want.sidecarName) === want.sidecar, `the downloads: ${[...got.keys()]} (the program had ${clean ? "no" : "other"} types)`);
    await a.click("[data-testid=ta-close]");
    await a.waitForSelector("[data-testid=export-archive]", { state: "detached" });

    // Move to category…: wire to /net (a new folder), in both pages.
    await showType(a, "wire");
    await allTypes(a);
    await a.click("[data-testid=type-move]");
    await answer(a, "/net");
    await untilT(b, "/net in page B", (x) => (x.folders["/net"] ?? []).includes("struct wire") && !(x.folders["/wire.c"] ?? []).includes("struct wire"));
    // Dragged onto the folder: flags too.
    await untilT(a, "/net in page A", (x) => (x.folders["/net"] ?? []).includes("struct wire"));
    // By the mouse, in steps (HTML5 drag and drop starts after a move), with
    // both rows in view (the other folders closed).
    for (const f of ["/stdint-uintn.h", "/types.h"]) {
      const row = a.locator(`[data-testid=types-branch][data-category='${f}'][aria-expanded=true]`);
      if (await row.count()) await row.click();
    }
    await untilT(a, "the other folders closed", (x) => !x.folders["/types.h"] && !x.folders["/stdint-uintn.h"]);
    await a.locator("[data-type-key='struct flags']").evaluate((el) => el.scrollIntoView({ block: "nearest" }));
    await a.waitForTimeout(200);
    const from = (await a.locator("[data-type-key='struct flags']").boundingBox())!;
    const onto = (await a.locator("[data-testid=types-branch][data-category='/net']").boundingBox())!;
    const at = await a.evaluate(([x1, y1, x2, y2]) => [document.elementFromPoint(x1, y1), document.elementFromPoint(x2, y2)].map((e) => e?.closest("[data-type-key], [data-category]")?.getAttribute("data-type-key") ?? e?.closest("[data-category]")?.getAttribute("data-category") ?? ""), [from.x + 20, from.y + from.height / 2, onto.x + 20, onto.y + onto.height / 2]);
    assert(at[0] === "struct flags" && at[1] === "/net", `both rows in view: ${JSON.stringify(at)}`);
    await a.mouse.move(from.x + 20, from.y + from.height / 2);
    await a.mouse.down();
    await a.mouse.move(from.x + 30, from.y + from.height / 2 + 3, { steps: 3 });
    await a.mouse.move(onto.x + 20, onto.y + onto.height / 2, { steps: 5 });
    await a.mouse.up();

    t = await untilT(b, "flags dragged into /net", (x) => (x.folders["/net"] ?? []).includes("struct flags"));
    // A search lists every folder's matches.
    await a.fill("[data-testid=types-filter]", "n");
    t = await untilT(a, "a search across folders", (x) => x.names.includes("struct wire") && x.names.includes("typedef node_t"));
    await a.fill("[data-testid=types-filter]", "");
    // Undo the drag, the move, the import: one step each.
    await undoIn(a);
    await untilT(b, "flags back", (x) => (x.folders["/wire.c"] ?? []).includes("struct flags"));
    await undoIn(a);
    await untilT(b, "wire back", (x) => (x.folders["/wire.c"] ?? []).includes("struct wire") && !x.folders["/net"]);
    await undoIn(a);
    await allTypes(b);
    await untilT(b, "the import undone in page B", (x) => !x.names.includes("struct wire") && !x.names.includes("typedef node_t"));
  });

  await check("types: Edit in C: a parse error shown at its line, then saved (both pages); undo", async () => {
    await newStruct(a, "point", [["int", "x"], ["int", "y"]]);
    await save(a, "point created", (t) => t.shown?.name === "point");
    await a.click("[data-testid=type-edit-c]");
    await untilT(a, "the C tab", (t) => t.editing && t.tab === "c");
    const text = await a.inputValue("[data-testid=type-ctext]");
    assert(text.startsWith("struct point {") && text.includes("int y;"), `the C to edit: ${text}`);
    await a.fill("[data-testid=type-ctext]", "struct point {\n    int x;\n    int y;\n    mystery_t z;\n};\n");
    await a.click("[data-testid=type-save]");
    let t = await untilT(a, "the error at line 4", (t) => t.notes.some((n) => n.startsWith("4:")));
    assert(t.editing && /line 4/.test(t.error), `still editing, the error named: ${JSON.stringify(t)}`);
    assert((await a.locator(".types-gutter .g-error").textContent()) === "4", "the gutter marks line 4");
    await a.fill("[data-testid=type-ctext]", "struct point {\n    int x;\n    int y;\n    long z;\n};\n");
    await save(a, "saved from C", (t) => (t.shown?.c ?? "").includes("long z;"));
    await showType(b, "point");
    await untilT(b, "the C edit in page B", (t) => (t.shown?.c ?? "").includes("long z;"));
    await undoIn(a);
    await untilT(b, "page B's point back", (t) => !(t.shown?.c ?? "").includes("long z;") && (t.shown?.c ?? "").includes("int y;"));
  });

  await check("types editor: insert at an offset into undefined filler, delete leaving filler, grow, a refused shrink, shrink (explicit offsets); undo", async () => {
    await showType(a, "point");
    await a.click("[data-testid=type-edit]");
    await untilT(a, "point's draft laid out", (t) => t.draft?.packing === "explicit" && !!t.layout?.ok && t.layout.identical);
    // At 0x10: past the end, so 0x8..0x10 is filler and the struct grows to 0x14.
    await a.click("[data-testid=field-insert-at]");
    await a.fill("[data-testid=ask-fields] [data-field=offset]", "0x10");
    await a.fill("[data-testid=ask-fields] [data-field=type]", "int");
    await a.fill("[data-testid=ask-fields] [data-field=name]", "w");
    await a.keyboard.press("Enter");
    await untilT(a, "w at 0x10", (t) => !!t.draft?.fields.some((f) => f.name === "w" && f.offset === 0x10 && f.size === 4) && t.draft.size === 0x14 && !!t.layout?.ok && !t.layout.identical);
    assert((await a.locator("[data-testid=filler]").count()) === 1, "one filler row (0x8..0x10)");
    await save(a, "w saved", (t) => (t.shown?.c ?? "").includes("int w; /* 0x10 */"));
    await showType(b, "point");
    await untilT(b, "w in page B", (t) => (t.shown?.c ?? "").includes("int w; /* 0x10 */"));
    // Delete y: x and w stay where they are.
    await a.click("[data-testid=type-edit]");
    await untilT(a, "draft", (t) => !!t.layout?.ok);
    await a.locator("[data-testid=edit-field]").nth(1).locator("[data-testid=field-delete]").click();
    await untilT(a, "y deleted", (t) => t.draft?.fields.length === 2 && !!t.layout?.ok && t.layout.size === 0x14);
    assert((await a.locator("[data-testid=filler]").count()) === 1, "one filler row (0x4..0x10)");
    await save(a, "y gone", (t) => !(t.shown?.c ?? "").includes("int y;") && (t.shown?.c ?? "").includes("int w; /* 0x10 */"));
    // Grow to 0x20; a shrink that would cut w off is refused; 0x18 is fine.
    await a.click("[data-testid=type-edit]");
    await untilT(a, "draft", (t) => !!t.layout?.ok);
    await a.fill("[data-testid=type-size]", "0x20");
    await a.press("[data-testid=type-size]", "Tab");
    await untilT(a, "grown", (t) => t.draft?.size === 0x20 && t.layout?.size === 0x20);
    await a.fill("[data-testid=type-size]", "0x10");
    await a.press("[data-testid=type-size]", "Tab");
    await untilT(a, "the shrink refused", (t) => t.error.includes("0x14") && t.draft?.size === 0x20);
    await a.fill("[data-testid=type-size]", "0x18");
    await a.press("[data-testid=type-size]", "Tab");
    await untilT(a, "shrunk", (t) => t.layout?.size === 0x18);
    await save(a, "0x18 saved", (t) => (t.shown?.c ?? "").includes("size 0x18"));
    await untilT(b, "0x18 in page B", (t) => (t.shown?.c ?? "").includes("size 0x18"));
    for (let i = 0; i < 3; i++) await undoIn(a);
    await untilT(b, "page B's point back", (t) => (t.shown?.c ?? "").includes("int y;") && !(t.shown?.c ?? "").includes("int w;"));
  });

  await check("types editor: bitfields at byte:bit with a width; undo", async () => {
    await newStruct(a, "flags", [["unsigned int", "lo"], ["unsigned int", "hi"]]);
    for (const [i, w] of [[0, "3"], [1, "2"]] as const) {
      await a.locator("[data-testid=edit-field]").nth(i).locator("[data-testid=field-bits]").fill(w);
      await a.locator("[data-testid=edit-field]").nth(i).locator("[data-testid=field-bits]").press("Tab");
    }
    // Natural: hi right after lo.
    await untilT(a, "hi at 0:3", (t) => t.draft?.fields[1]?.bits === 2 && t.draft.fields[1].bit === 3 && !!t.layout?.ok && t.layout.size === 4);
    // Explicit: hi at byte 0, bit 6.
    await a.selectOption("[data-testid=type-packing]", "explicit");
    await untilT(a, "explicit", (t) => t.draft?.packing === "explicit" && !!t.layout?.ok);
    await a.locator("[data-testid=edit-field]").nth(1).locator("[data-testid=field-offset]").fill("0:6");
    await a.locator("[data-testid=edit-field]").nth(1).locator("[data-testid=field-offset]").press("Tab");
    await untilT(a, "hi at 0:6", (t) => t.draft?.fields[1]?.bit === 6 && !!t.layout?.ok && !t.draft.fields[1].problem);
    await save(a, "flags saved", (t) => t.shown?.name === "flags");
    const f = await typeByName("flags");
    const hi = f.composite!.fields.find((x) => x.name === "hi")!;
    assert(hi.bitOffset === 6 && hi.bitSize === 2 && Number(f.size) === 4, `flags: ${JSON.stringify(f)}`);
    await allTypes(b);
    await untilT(b, "flags in page B", (t) => t.names.includes("struct flags"));
    await undoIn(a);
    await untilT(b, "flags gone in page B", (t) => !t.names.includes("struct flags"));
  });

  await check("types editor: packing and alignment, laid out by the daemon; undo", async () => {
    await newStruct(a, "pk", [["char", "c"], ["int", "i"]]);
    await untilT(a, "natural: 8 bytes", (t) => !!t.layout?.ok && t.layout.size === 8 && t.draft?.fields[1].offset === 4);
    await a.selectOption("[data-testid=type-packing]", "packed");
    await untilT(a, "packed: 5 bytes", (t) => t.layout?.size === 5 && t.layout.packed && t.draft?.fields[1].offset === 1);
    await a.selectOption("[data-testid=type-packing]", "2");
    await untilT(a, "pack(2): 6 bytes", (t) => t.layout?.size === 6 && t.draft?.fields[1].offset === 2);
    await a.selectOption("[data-testid=type-packing]", "natural");
    await a.selectOption("[data-testid=type-align]", "16");
    await untilT(a, "aligned(16): 16 bytes", (t) => t.layout?.size === 16 && t.layout.align === 16);
    await save(a, "pk saved", (t) => (t.shown?.c ?? "").includes("aligned(16)") && (t.shown?.c ?? "").includes("size 0x10"));
    await allTypes(b);
    await untilT(b, "pk in page B", (t) => t.names.includes("struct pk"));
    await undoIn(a);
    await untilT(b, "pk gone in page B", (t) => !t.names.includes("struct pk"));
  });

  await check("types editor: a flexible array member; undo", async () => {
    await newStruct(a, "msg", [["int", "len"], ["char", "data"]]);
    await a.locator("[data-testid=edit-field]").nth(1).locator("[data-testid=field-flex]").check();
    await untilT(a, "data[]", (t) => !!t.draft?.fields[1].flex && !!t.layout?.ok && t.layout.size === 4);
    await save(a, "msg saved", (t) => /char data\[0?\];/.test(t.shown?.c ?? ""));
    await showType(b, "msg");
    await untilT(b, "msg in page B", (t) => /char data\[0?\];/.test(t.shown?.c ?? ""));
    await undoIn(a);
    await allTypes(b);
    await untilT(b, "msg gone in page B", (t) => !t.names.includes("struct msg"));
  });

  await check("types editor: function-pointer fields, typed and pasted as declarations; undo", async () => {
    await newStruct(a, "ops", [["void (*)(int)", "cb"]]);
    // A declaration where a type goes becomes the field (its name too).
    await a.click("[data-testid=field-add]");
    await untilT(a, "a second field", (t) => t.draft?.fields.length === 2);
    await a.locator("[data-testid=edit-field]").nth(1).locator("[data-testid=field-type]").fill("int (*open)(const char *path, int flags)");
    await a.locator("[data-testid=edit-field]").nth(1).locator("[data-testid=field-type]").press("Tab");
    await untilT(a, "open as a field", (t) => t.draft?.fields[1]?.name === "open" && !!t.layout?.ok && t.layout.size === 16);
    // The paste box: member declarations become fields.
    await a.click("[data-testid=type-paste-box] summary");
    await a.fill("[data-testid=type-paste]", "char name[16];\nunsigned short port;");
    await a.click("[data-testid=type-paste-add]");
    await untilT(a, "pasted fields", (t) => JSON.stringify(t.draft?.fields.map((f) => f.name)) === '["cb","open","name","port"]' && !!t.layout?.ok && t.layout.size === 40);
    await save(a, "ops saved", (t) => (t.shown?.c ?? "").includes("void (*cb)(int);") && (t.shown?.c ?? "").includes("(*open)(") && (t.shown?.c ?? "").includes("char name[16];"));
    await showType(b, "ops");
    await untilT(b, "ops in page B", (t) => (t.shown?.c ?? "").includes("void (*cb)(int);"));
    await undoIn(a);
    await allTypes(b);
    await untilT(b, "ops gone in page B", (t) => !t.names.includes("struct ops"));
  });

  await check("types: duplicate and rename (the old name's binding retracted); undo", async () => {
    await showType(a, "point");
    await a.click("[data-testid=type-duplicate]");
    await answer(a, "point_copy");
    await untilT(a, "the copy shown", (t) => t.shown?.name === "point_copy" && !t.editing);
    await allTypes(b);
    await untilT(b, "the copy in page B", (t) => t.names.includes("struct point_copy"));
    await a.click("[data-testid=type-rename]");
    await answer(a, "point2");
    await untilT(a, "renamed", (t) => t.shown?.name === "point2" && !t.editing);
    const old = (await history("name:struct point_copy")).entries ?? [];
    assert(old.some((e) => e.op === "ASSERTION_OP_RETRACT"), `point_copy's binding retracted: ${JSON.stringify(old)}`);
    await allTypes(b);
    await untilT(b, "point2 in page B", (t) => t.names.includes("struct point2"));
    // Undo the rename (one step): point2 goes, point_copy's binding is back.
    await undoIn(a);
    await untilT(b, "point2 gone in page B", (t) => !t.names.includes("struct point2"));
    const back = await rpc<{ candidates?: { status: string; op: string }[] }>(base, "AssertionService/Blame", { key: { programId: "default/prog", kind: "FACT_KIND_TYPE_DEF", sub: "name:struct point_copy" } });
    assert(back.candidates?.some((c) => c.status === "ASSERTION_STATUS_EFFECTIVE"), `point_copy bound again: ${JSON.stringify(back)}`);
    await undoIn(a);
    await untilT(b, "the copy gone in page B", (t) => !t.names.includes("struct point_copy"));
  });

  await check("types editor: an enum's values as C expressions, its size, sorted; undo", async () => {
    await a.selectOption("[data-testid=types-new]", "enum");
    await a.fill("[data-testid=type-name]", "color");
    const val = async (i: number, name: string, value: string) => {
      if (i > 0) {
        await a.click("[data-testid=field-add]");
        await untilT(a, `value ${i}`, (t) => (t.draft?.values.length ?? 0) > i);
      }
      const row = a.locator("[data-testid=edit-field]").nth(i);
      await row.locator("[data-testid=enum-name]").fill(name);
      await row.locator("[data-testid=enum-name]").press("Tab");
      await a.locator("[data-testid=edit-field]").nth(i).locator("[data-testid=enum-value]").fill(value);
      await a.locator("[data-testid=edit-field]").nth(i).locator("[data-testid=enum-value]").press("Tab");
    };
    await val(0, "RED", "");
    await val(1, "GREEN", "RED + 2");
    await val(2, "BLUE", "1 << 4");
    await val(3, "ALPHA", "1");
    await a.selectOption("[data-testid=enum-size]", "1");
    await untilT(a, "values from the daemon", (t) => JSON.stringify(t.draft?.values.map((v) => v.shown)) === '["0","2","16","1"]' && t.layout?.size === 1);
    await a.click("[data-testid=enum-sort]");
    await untilT(a, "sorted", (t) => JSON.stringify(t.draft?.values.map((v) => v.name)) === '["RED","ALPHA","GREEN","BLUE"]' && !!t.layout?.ok);
    await save(a, "color saved", (t) => (t.shown?.c ?? "").includes("GREEN = 2") && (t.shown?.c ?? "").includes("size 1"));
    await allTypes(b);
    await untilT(b, "color in page B", (t) => t.names.includes("enum color"));
    await undoIn(a);
    await untilT(b, "color gone in page B", (t) => !t.names.includes("enum color"));
  });

  await check("retype with definitions first (struct ctr { int n; }; struct ctr): defined and applied in one step, both pages; undo", async () => {
    await listingView();
    const counter = await sym("counter");
    await go(a, counter);
    await go(b, counter);
    await a.focus("#listing-canvas");
    await a.keyboard.press("y");
    await answer(a, "struct ctr { int n; }; struct ctr");
    for (const p of [a, b]) await untilRows(p, "the global typed struct ctr", (rows) => rows.some((r) => r.address === hx(counter) && r.kind !== ROW.Header && /ctr/.test(r.dataType)));
    const bind = (await history("name:struct ctr")).entries ?? [];
    assert(bind.length === 1 && bind[0].provenance.kind === "PROVENANCE_KIND_USER", `ctr bound by the retype: ${JSON.stringify(bind)}`);
    await undoIn(a);
    await untilRows(b, "the global's type back", (rows) => rows.some((r) => r.address === hx(counter) && r.kind !== ROW.Header && !/ctr/.test(r.dataType)));
    const after = await rpc<{ candidates?: { status: string }[] }>(base, "AssertionService/Blame", { key: { programId: "default/prog", kind: "FACT_KIND_TYPE_DEF", sub: "name:struct ctr" } });
    assert(!after.candidates?.some((c) => c.status === "ASSERTION_STATUS_EFFECTIVE"), `ctr unbound: ${JSON.stringify(after)}`);
    // Clean up point (made for Edit in C).
    await typesView();
    await showType(a, "point");
    await undoIn(a);
    await untilT(b, "point gone", (t) => !t.names.includes("struct point"));
    await listingView();
  });

  await check("plugins: analyzer facts on listing rows, a command from the palette (its edits shown, undone)", async () => {
    const info = await rpc<{ features: string[] }>(base, "MetaService/GetServerInfo", {});
    if (!info.features.includes("plugins")) {
      log("     (no example plugins: rk-daemon has no --plugin-dir; skipped)");
      return;
    }
    // string-refs comments the instruction in main that loads the format string.
    await go(a, main);
    const rows = await untilRows(a, "a string-refs annotation", (rows) => rows.some((r) => r.annot.includes("string-refs") && r.annot.includes("%u %d")));
    const annotated = rows.find((r) => r.annot.includes("string-refs"))!;
    assert(annotated.func === hx(main), "in main");
    // Hovering it shows the plugin's provenance.
    const pt = (await a.evaluate(`window.__revkit.app.annotationPoint(0x${annotated.address}n)`)) as { x: number; y: number } | null;
    assert(pt, "the annotation is drawn");
    await a.mouse.move(pt.x, pt.y);
    await a.waitForSelector("[data-testid=provenance] [data-testid=prov-who]:text('plugin:string-refs@1.0.0')", { timeout: 5000 });
    await a.mouse.move(5, 5);
    // rename-regex from the palette.
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+Shift+P");
    await a.fill("[data-testid=palette-input]", ">rename-regex");
    await a.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").includes("rename-regex"));
    await a.keyboard.press("Enter");
    await a.waitForSelector("[data-testid=ask-fields]");
    await a.fill("[data-testid=ask-fields] [data-field=pattern]", "^twice$");
    await a.fill("[data-testid=ask-fields] [data-field=replace]", "doubled");
    await a.keyboard.press("Enter");
    for (const p of [a, b]) await p.locator(".fn-row .fn-name", { hasText: /^doubled$/ }).waitFor({ timeout: 10000 });
    const hist = await rpc<{ entries: { provenance: { kind: string; id: string } }[] }>(base, "AssertionService/GetHistory", { key: { programId: "default/prog", kind: "FACT_KIND_NAME", address: { offset: String(twice) } } });
    assert(hist.entries.some((e) => e.provenance.kind === "PROVENANCE_KIND_PLUGIN" && e.provenance.id === "rename-regex"), `history: ${JSON.stringify(hist.entries)}`);
    // Its edits, listed; and undone with Ctrl+Z.
    await a.evaluate("void window.__revkit.app.showPluginEdits()");
    await a.locator("[data-testid=choose] .palette-item", { hasText: "doubled" }).waitFor();
    await a.keyboard.press("Escape");
    await undoIn(a);
    for (const p of [a, b]) await p.locator(".fn-row .fn-name", { hasText: /^twice$/ }).waitFor({ timeout: 10000 });
  });

  await check("layout: a view moved to the other side, remembered after a reload", async () => {
    const c = await open(base);
    await until(c, "ready", (s) => s.decompName === "main");
    await c.focus("#listing-canvas");
    await c.keyboard.press("Control+Shift+P");
    await c.fill("[data-testid=palette-input]", ">move graph");
    await c.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").includes("Move graph"));
    await c.keyboard.press("Enter");
    await c.locator("#dock-side [data-testid=tab-graph]").waitFor();
    await c.reload();
    await c.waitForSelector("body[data-ready='1']");
    await c.locator("#dock-side [data-testid=tab-graph]").waitFor();
    // The listing and the graph side by side; the graph follows the listing.
    await until(c, "both visible", (s) => s.views.includes("graph") && s.views.includes("listing"));
    await untilGraph(c, "main's graph at the side", (g) => g.entry === hx(main));
    await c.evaluate("window.__revkit.app.dock.reset({ listing: 'main', graph: 'main', decomp: 'side', calls: 'side', strings: 'side', types: 'side' })");
    await c.context().close();
  });

  await check("compare: a new version against this one, the match table, accept and reject by key, apply names, blame, undo", async () => {
    // Version 2: a function inserted first (everything moves), second() changed; stripped.
    const cc = process.env.CC ?? "cc";
    const src2 = path.join(tmp, "prog2.c");
    const exe2 = path.join(tmp, "prog2");
    writeFileSync(src2, PROGRAM.replace("int counter;", "int counter;\n__attribute__((noinline)) int fresh(int x) { return x - 7; }").replace("return p[1];", "return p[1] + p[0];"));
    execFileSync(cc, ["-O1", "-g0", "-fno-inline", "-o", exe2 + ".full", src2]);
    execFileSync("strip", ["-o", exe2, exe2 + ".full"]);
    const imported = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", { projectId: "default", path: exe2, name: "prog2" });
    const b2 = imported.program.programId;
    const fns = async () => (await rpc<{ functions: { name: string; entry: { offset: string } }[] }>(base, "QueryService/ListFunctions", { programId: b2, page: { pageSize: 500 } })).functions;
    const before = await fns();
    assert(!before.some((f) => f.name === "checksum"), "prog2 is stripped");

    const c = await browser!.newContext({ viewport: { width: 1500, height: 900 } });
    const p = await c.newPage();
    p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
    p.on("console", (m) => {
      if (m.type() === "error") log(`  [console] ${m.text()}`);
    });
    await p.goto(`${base}/?program=${encodeURIComponent(b2)}&user=e2e&theme=dark`);
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    // Tools → Compare from the palette.
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+Shift+P");
    await p.fill("[data-testid=palette-input]", ">compare programs");
    await p.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").includes("Compare programs"));
    await p.keyboard.press("Enter");
    await p.waitForSelector("[data-testid=compare-dialog]");
    assert((await p.inputValue("[data-testid=compare-b]")) === b2, "B defaults to this program");
    await p.selectOption("[data-testid=compare-a]", "default/prog");
    await p.click("[data-testid=compare-go]");
    await p.waitForSelector("[data-testid=compare-dialog]", { state: "detached" });
    // The run's progress, then the table.
    await p.waitForFunction(() => document.querySelector("[data-testid=diff-status]")?.getAttribute("data-state") === "done", undefined, { timeout: 30000 }).catch(async (e) => {
      throw new Error(`${e}; status: ${await p.textContent("[data-testid=diff-status]")} / ${await p.getAttribute("[data-testid=diff-status]", "data-state")}; rows ${await p.locator("[data-testid=diff-row]").count()}`);
    });
    await p.waitForFunction(() => document.querySelectorAll("[data-testid=diff-row]").length >= 3);
    const status = (await p.textContent("[data-testid=diff-status]")) ?? "";
    assert(/matched/.test(status), `status: ${status}`);
    const names = await p.$$eval("[data-testid=diff-row] .d-name:first-child", (els) => els.map((e) => e.textContent));
    assert(names.includes("checksum") && names.includes("main") && names.includes("second"), `rows: ${names}`);
    // Sort by confidence, then filter to one function.
    await p.click("[data-testid=diff-head] .d-conf");
    await p.fill("[data-testid=diff-filter]", "checksum");
    const onlyRow = (name: string) =>
      p.waitForFunction((n) => {
        const rows = document.querySelectorAll("[data-testid=diff-row]");
        return rows.length === 1 && rows[0].querySelector(".d-name")?.textContent === n;
      }, name);
    await onlyRow("checksum");
    // Both listings of the selected match, aligned: checksum only moved, so no difference.
    await p.waitForFunction(() => document.querySelectorAll("[data-testid=diff-lines] [data-testid=diff-cell-a]").length > 2 &&
      document.querySelectorAll("[data-testid=diff-lines] [data-testid=diff-cell-b]").length > 2);
    await p.waitForFunction(() => document.querySelector("[data-testid=diff-count]")?.textContent === "no differences");
    // a accepts the selected match.
    await p.focus("[data-testid=diff-table]");
    await p.keyboard.press("a");
    await p.waitForFunction(() => document.querySelector("[data-testid=diff-row-status]")?.textContent === "accepted");
    // r rejects one: it leaves the table.
    await p.fill("[data-testid=diff-filter]", "twice");
    await onlyRow("twice");
    await p.focus("[data-testid=diff-table]");
    const rejectedB = await p.textContent("[data-testid=diff-row] .d-addr:nth-of-type(4)");
    await p.keyboard.press("r");
    // The pair is never proposed again (twice may find another partner).
    await p.waitForFunction((b) => ![...document.querySelectorAll("[data-testid=diff-row] .d-addr:nth-of-type(4)")].some((e) => e.textContent === b), rejectedB);
    await p.fill("[data-testid=diff-filter]", "");
    // Apply markup: the preview, then one revision.
    await p.click("[data-testid=diff-apply]");
    await p.waitForSelector("[data-testid=apply-dialog]");
    await p.waitForFunction(() => /Would port [1-9]\d* names/.test(document.querySelector("[data-testid=apply-preview]")?.textContent ?? ""));
    await p.click("[data-testid=apply-go]");
    await p.waitForSelector("[data-testid=apply-dialog]", { state: "detached" });
    const end = Date.now() + 10000;
    let after = await fns();
    while (!after.some((f) => f.name === "checksum") && Date.now() < end) {
      await p.waitForTimeout(100);
      after = await fns();
    }
    const ck = after.find((f) => f.name === "checksum");
    assert(ck, `names ported: ${after.map((f) => f.name)}`);
    assert(!after.some((f) => f.name === "twice" && (BigInt(f.entry.offset).toString(16).padStart(8, "0") === rejectedB || BigInt(f.entry.offset).toString(16) === rejectedB)), "a rejected pair ports nothing");
    await p.waitForFunction(() => [...document.querySelectorAll("[data-testid=diff-row-status]")].some((e) => e.textContent === "applied"));
    // The ported name's provenance: migration:diff, from prog.
    const blame = await rpc<{ candidates: { provenance: { kind: string; id: string }; portedFrom?: { programId: string } }[] }>(base, "AssertionService/Blame", { key: { programId: b2, kind: "FACT_KIND_NAME", address: { offset: ck.entry.offset } } });
    assert(blame.candidates[0].provenance.id === "diff" && blame.candidates[0].portedFrom?.programId === "default/prog", `blame: ${JSON.stringify(blame.candidates[0])}`);
    await p.evaluate(`window.__revkit.app.navigate(${ck.entry.offset}n)`);
    await until(p, "checksum in prog2", (s) => s.decompName === "checksum");
    // Hovering the ported name in the decompiler: migration:diff, from prog.
    await p.locator("#cm .cm-content span.k-fn", { hasText: /^checksum$/ }).first().hover();
    await p.waitForSelector("[data-testid=provenance] [data-testid=prov-ported]", { timeout: 5000 });
    assert(((await p.textContent("[data-testid=prov-ported]")) ?? "").includes("default/prog"), "ported from prog");
    await p.mouse.move(5, 5);
    // Ctrl+Z undoes the whole apply run.
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+z");
    const end2 = Date.now() + 10000;
    after = await fns();
    while (after.some((f) => f.name === "checksum") && Date.now() < end2) {
      await p.waitForTimeout(100);
      after = await fns();
    }
    assert(!after.some((f) => f.name === "checksum"), "undo removed the ported names");
    await c.close();
  });

  await check("compare inside a pair: an in-place patch of the ARM firmware, aligned and highlighted, next/previous difference, graph diff colours, C", async () => {
    const armfw = path.join(root, "src/analysis/tests/fixtures/armfw");
    const fw = path.join(tmp, "armfw");
    try {
      execFileSync("sh", [path.join(armfw, "build.sh"), "clang", "ld.lld", "llvm-objcopy", fw], { stdio: "ignore" });
    } catch {
      log("  (skipped: no clang, ld.lld and llvm-objcopy for armv4t)");
      return;
    }
    // h2 (sink = 12; return v - 7): sub r0, r0, #7 becomes a BL to new code written over
    // data (zeros at the end of both images); dispatch: two cases' immediates change.
    const nm = execFileSync("llvm-nm", [path.join(fw, "fw.elf")], { encoding: "utf8" });
    const sym = (name: string) => parseInt(nm.split("\n").find((l) => new RegExp(` [Tt] ${name}$`).test(l))!.split(" ")[0], 16);
    const h2 = sym("h2"), dispatch = sym("dispatch");
    const orig = readFileSync(path.join(fw, "fw.bin"));
    const a = Buffer.alloc(Math.ceil(orig.length / 16) * 16 + 64);
    orig.copy(a);
    const b = Buffer.from(a);
    const find = (from: number, word: number) => {
      for (let at = from; at < from + 0x100; at += 4) if (a.readUInt32LE(at) === word) return at;
      throw new Error(`no ${word.toString(16)} after ${from.toString(16)}`);
    };
    const sub = find(h2, 0xe2400007), add5 = find(dispatch, 0xe2800005), eor9 = find(dispatch, 0xe2200009);
    const fresh = b.length - 32;
    b.writeUInt32LE(0xe2800009, fresh); // add r0, r0, #9
    b.writeUInt32LE(0xe12fff1e, fresh + 4); // bx lr
    b.writeUInt32LE((0xeb000000 | (((fresh - (sub + 8)) >> 2) & 0xffffff)) >>> 0, sub);
    b.writeUInt32LE(0xe2800006, add5);
    b.writeUInt32LE(0xe220000a, eor9);
    writeFileSync(path.join(tmp, "fw-a.bin"), a);
    writeFileSync(path.join(tmp, "fw-b.bin"), b);
    const raw = { format: "raw", languageId: "ARM:LE:32:v4t", hasEntryPoint: true, entryPoint: "0" };
    const pa = (await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", { projectId: "default", path: path.join(tmp, "fw-a.bin"), name: "fw-a", options: raw })).program.programId;
    const pb = (await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", { projectId: "default", path: path.join(tmp, "fw-b.bin"), name: "fw-b", options: raw })).program.programId;
    await rpc(base, "DiffService/CreateDiffSession", { projectId: "default", programA: pa, programB: pb, run: true, name: "fw-a -> fw-b" });

    const c = await browser!.newContext({ viewport: { width: 1500, height: 950 } });
    const p = await c.newPage();
    p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
    await p.goto(`${base}/?program=${encodeURIComponent(pb)}&user=e2e&theme=dark`);
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+9");
    await p.waitForFunction(() => document.querySelector("[data-testid=diff-status]")?.getAttribute("data-state") === "done", undefined, { timeout: 30000 });
    // Only the modified pairs, h2 and dispatch, each with what changed.
    await p.selectOption("[data-testid=diff-change]", String(2));
    await p.waitForFunction(() => document.querySelectorAll("[data-testid=diff-row]").length === 2);
    await p.waitForFunction(() => [...document.querySelectorAll("[data-testid=diff-row-summary]")].every((e) => e.textContent), undefined, { timeout: 10000 }).catch(async (e) => {
      throw new Error(`${e}; summaries: ${await p.$$eval("[data-testid=diff-row-summary]", (els) => els.map((x) => x.textContent))}`);
    });
    const sums = await p.$$eval("[data-testid=diff-row-summary]", (els) => els.map((x) => x.textContent ?? ""));
    assert(/^1 instruction changed: sub r0,r0,#0x7 → bl FUN_[0-9a-f]+ \(new\)$/.test(sums[0]), `h2: ${sums[0]}`);
    assert(sums[1] === "2 instructions changed: add r0,r0,#0x5 → add r0,r0,#0x6; eor r0,r0,#0x9 → eor r0,r0,#0xa", `dispatch: ${sums[1]}`);
    const hx = (n: number) => n.toString(16);
    type Shown = { differing: { a: string; b: string }[]; current: number };
    const differing = async () => ((await p.evaluate("window.__revkit.app.diff.listing.describe()")) as Shown).differing.map((x) => `${x.a}:${x.b}`).join(",");
    // h2 (selected first): one changed line, sub on A, the BL on B labelled new.
    await p.waitForFunction(() => document.querySelector("[data-testid=diff-count]")?.getAttribute("data-total") === "1");
    assert((await differing()) === `${hx(sub)}:${hx(sub)}`, `h2 differs at ${await differing()}`);
    const changed = p.locator("[data-testid=diff-line][data-status=chg]");
    assert((await changed.count()) === 1, `changed lines: ${await changed.count()}`);
    assert(/sub/.test((await changed.locator("[data-testid=diff-cell-a]").textContent()) ?? ""), "A: sub");
    assert(/bl/.test((await changed.locator("[data-testid=diff-cell-b]").textContent()) ?? ""), "B: bl");
    assert((await changed.locator("[data-testid=diff-new]").count()) === 1, "the call into new code is labelled new");
    if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, "compare-h2.png") });
    // dispatch: two differences, exactly the two changed immediates, amber, tokens emphasised.
    await p.locator("[data-testid=diff-row]").nth(1).click();
    await p.waitForFunction(() => document.querySelector("[data-testid=diff-count]")?.getAttribute("data-total") === "2");
    assert((await differing()) === `${hx(add5)}:${hx(add5)},${hx(eor9)}:${hx(eor9)}`, `dispatch differs at ${await differing()}`);
    assert((await changed.count()) === 2 || (await p.locator("[data-testid=diff-line][data-status=chg]").count()) >= 1, "changed lines");
    assert((await p.locator("[data-testid=diff-line][data-status=ins], [data-testid=diff-line][data-status=del]").count()) === 0, "nothing inserted or deleted");
    const first = p.locator("[data-testid=diff-line][data-status=chg]").first();
    assert((await first.locator(".t-diff").count()) === 2, "the changed immediate is emphasised on both sides");
    const bg = await first.locator("[data-testid=diff-cell-b]").evaluate((el) => getComputedStyle(el).backgroundColor);
    assert(/rgba\(210, 153, 34/.test(bg), `changed rows are amber: ${bg}`);
    const eq = await p.locator("[data-testid=diff-line][data-status=eq] [data-testid=diff-cell-a]").first().evaluate((el) => getComputedStyle(el).opacity);
    assert(Number(eq) < 1, `equal rows are dimmed: ${eq}`);
    // Next and previous difference (n / p, the arrows), wrapping around.
    const cur = () => p.getAttribute("[data-testid=diff-count]", "data-current");
    assert((await cur()) === "0", `opens at the first difference: ${await cur()}`);
    await p.focus("[data-testid=diff-lines]");
    await p.keyboard.press("n");
    await p.waitForFunction(() => document.querySelector("[data-testid=diff-count]")?.getAttribute("data-current") === "1");
    assert(/^2\/2 differences/.test((await p.textContent("[data-testid=diff-count]")) ?? ""), `count: ${await p.textContent("[data-testid=diff-count]")}`);
    await p.keyboard.press("n");
    await p.waitForFunction(() => document.querySelector("[data-testid=diff-count]")?.getAttribute("data-current") === "0");
    await p.keyboard.press("p");
    await p.waitForFunction(() => document.querySelector("[data-testid=diff-count]")?.getAttribute("data-current") === "1");
    await p.click("[data-testid=diff-prev]");
    await p.waitForFunction(() => document.querySelector("[data-testid=diff-count]")?.getAttribute("data-current") === "0");
    if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, "compare-listing.png") });
    // The graph diff: the patched block amber on both sides, the others neutral, at the same place.
    await p.click("[data-testid=diff-show-graph]");
    await p.waitForFunction(() => (window as any).__revkit.app.diff.graph.describe().nodes.length > 0);
    await p.waitForTimeout(300);
    type GraphDesc = { nodes: { a: number; b: number; status: string; color: string }[]; mode: string };
    const g = await p.evaluate("window.__revkit.app.diff.graph.describe()") as GraphDesc;
    const mod = g.nodes.findIndex((n) => n.status === "mod");
    assert(mod >= 0 && g.nodes.filter((n) => n.status === "mod").length === 2 && g.nodes.every((n) => n.status === "mod" || n.status === "same") && g.nodes.every((n) => n.a >= 0 && n.b >= 0), `graph: ${JSON.stringify(g.nodes)}`);
    assert(g.nodes[mod].color === "#d29922", "modified blocks are amber");
    const pixel = async (side: "a" | "b", node: number) => {
      const pt = await p.evaluate(`window.__revkit.app.diff.graph.pointOf(${node}, "${side}")`) as { x: number; y: number };
      const shot = await p.screenshot({ clip: { x: Math.round(pt.x), y: Math.round(pt.y), width: 1, height: 1 } });
      const png = await p.evaluate(async (b64) => {
        const img = new Image();
        img.src = `data:image/png;base64,${b64}`;
        await img.decode();
        const cv = document.createElement("canvas");
        cv.width = cv.height = 1;
        const x = cv.getContext("2d")!;
        x.drawImage(img, 0, 0);
        return [...x.getImageData(0, 0, 1, 1).data];
      }, shot.toString("base64"));
      return { pt, rgb: png.slice(0, 3) };
    };
    const pa1 = await pixel("a", mod), pb1 = await pixel("b", mod);
    for (const x of [pa1, pb1]) assert(x.rgb[0] > 150 && x.rgb[1] > 100 && x.rgb[2] < 90, `the modified block's header is amber: ${JSON.stringify(x)}`);
    const left = (side: string) => p.$eval(`[data-testid=diffgraph-canvas-${side}]`, (el) => el.getBoundingClientRect().left);
    const [la, lb] = [await left("a"), await left("b")];
    assert(Math.abs(pa1.pt.y - pb1.pt.y) < 1 && Math.abs(pa1.pt.x - la - (pb1.pt.x - lb)) < 1, `the pair is at the same place on both sides: ${JSON.stringify([pa1.pt, pb1.pt, la, lb])}`);
    const same = g.nodes.findIndex((n) => n.status === "same");
    if (same >= 0) {
      const ps = await pixel("b", same);
      assert(!(ps.rgb[0] > 150 && ps.rgb[1] > 100 && ps.rgb[2] < 90), `unchanged blocks are neutral: ${JSON.stringify(ps)}`);
    }
    // Clicking the block on A selects its partner and scrolls the listing to it.
    await p.mouse.click(pa1.pt.x, pa1.pt.y);
    await p.waitForFunction(() => (window as any).__revkit.app.diff.graph.describe().selected >= 0);
    if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, "compare-graph.png") });
    await p.click("[data-testid=diffgraph-mode]");
    await p.waitForFunction(() => (window as any).__revkit.app.diff.graph.describe().mode === "merged");
    await p.waitForTimeout(300);
    if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, "compare-graph-merged.png") });
    await p.click("[data-testid=diffgraph-mode]");
    // Decompiled C: both sides, the lines printed from the patched instructions highlighted.
    await p.click("[data-testid=diff-show-c]");
    await p.waitForFunction(() => document.querySelectorAll("[data-testid=diff-c-line]").length > 2, undefined, { timeout: 30000 });
    assert((await p.locator(".dc-cell[data-status=chg], .dc-cell[data-status=ins], .dc-cell[data-status=del]").count()) >= 1, "a changed C line");
    if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, "compare-c.png") });
    // The dockable Graph diff follows the pair.
    await p.click("[data-testid=diff-show-listing]");
    await p.keyboard.press("Control+Shift+9");
    await p.waitForFunction(() => Number(document.querySelector("#diffgraph [data-testid=diffgraph]")?.getAttribute("data-blocks") ?? 0) > 0);
    if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, "compare-dock.png") });
    await c.close();
  });

  // Daily-use polish (e2e/polish.ts): programs, functions, graph, types, tables, accessibility.
  if (wants("polish.ts")) await polishChecks({
    base, exe, sym, check, open, palette, answer, rpc, assert, log,
    until: (p, what, pred, ms) => until(p, what, pred as unknown as (s: Snap) => boolean, ms) as never,
    crashingDaemon: (fault) => startDaemon(exe, { REVKIT_DECOMPD_FAULT: fault }, "ports-polish-crash.json"),
  });

  // The project tree and archives (e2e/projects.ts): folders, drag and drop, File → Export / Import project.
  if (wants("projects.ts")) await projectChecks({
    base, tmp, check, open, answer, rpc, assert,
    until: (p, what, pred, ms) => until(p, what, pred as unknown as (s: Snap) => boolean, ms) as never,
  });

  // The file system browser (e2e/filesystems.ts): nested containers, Info, import, batch import.
  if (wants("filesystems.ts")) await fileSystemChecks({
    base, exe, check, open, rpc, assert,
    until: (p, what, pred, ms) => until(p, what, pred as unknown as (s: Snap) => boolean, ms) as never,
  });

  // Scripts (e2e/scripts.ts): the Script Manager, a starter from the palette with a prompt and
  // progress, one undo step in two pages, trust and Cancel, the right-click entry.
  if (wants("scripts.ts")) await scriptsChecks({
    base, configDir: path.join(tmp, "xdg-config"), check, open: (b) => open(b), palette, rpc, assert, log, timeScale,
    until: (p, what, pred, ms) => until(p, what, pred as unknown as (s: Snap) => boolean, ms) as never,
    startDaemon: (env, portFile) => startDaemon(exe, env, portFile),
  });

  // The Python console and the editor's completion (e2e/console.ts): statements and blocks, the
  // cursor followed, completion and signature help, a console edit undone, Ctrl+C, a viewer's console.
  if (wants("console.ts")) await consoleChecks({
    base, tmp, check, open: (b) => open(b), palette, rpc, assert, log, timeScale,
    browser: () => browser!,
    daemonBin,
    until: (p, what, pred, ms) => until(p, what, pred as unknown as (s: Snap) => boolean, ms) as never,
    startDaemon: (extra, portFile) => startDaemon(exe, {}, portFile, extra),
  });

  await check("patching: an immediate and a call assembled in the listing, the Patches view, revert, export with a sum in the name, compare with the original", async () => {
    const waitFn = async (p: Page, ...args: Parameters<Page["waitForFunction"]>) => {
      try {
        await p.waitForFunction(...args);
      } catch (e) {
        await p.screenshot({ path: path.join(tmp, "..", "rk-e2e-patch-fail.png") });
        throw new Error(`waiting for ${String(args[0]).slice(0, 160)}: ${e instanceof Error ? e.message : e}`);
      }
    };
    // The immediate: checksum's FNV offset basis, one more.
    await palette(a, "checksum");
    await until(a, "checksum", (s) => s.decompName === "checksum");
    let rows = await untilRows(a, "the FNV basis", (rows) => rows.some((r) => r.operands.includes("0x811c9dc5")));
    const basis = rows.find((r) => r.operands.includes("0x811c9dc5"))!;
    await palette(a, "0x" + basis.address);
    await until(a, "on the basis", (s) => s.address === basis.address);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+Shift+G");
    await a.waitForSelector("[data-testid=patch-editor]");
    const shown = await a.inputValue("[data-testid=patch-input]");
    assert(shown.toLowerCase().includes("0x811c9dc5"), `the editor starts from the listing's text: ${shown}`);
    await a.fill("[data-testid=patch-input]", shown.replace(/0x811c9dc5/i, "0x811c9dc6"));
    await waitFn(a, () => (document.querySelector("[data-testid=patch-list] .pe-item.active .pe-label")?.textContent ?? "").includes("811c9dc6"));
    await a.keyboard.press("Enter");
    await a.waitForSelector("[data-testid=patch-editor]", { state: "detached" });
    rows = await untilRows(a, "the patched immediate", (rows) => rows.some((r) => r.address === basis.address && r.patched && r.operands.includes("0x811c9dc6")), 30000);
    await until(a, "C with the new basis", (s) => /0x811c9dc6|2166136262|-0x7ee3623a/i.test(s.decompText), 30000);
    // Ctrl+Z undoes a patch like any edit; Ctrl+Shift+Z brings it back.
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+z");
    await untilRows(a, "the immediate unpatched", (rows) => rows.some((r) => r.address === basis.address && !r.patched && r.operands.includes("0x811c9dc5")), 30000);
    await a.keyboard.press("Control+Shift+z");
    await untilRows(a, "the immediate patched again", (rows) => rows.some((r) => r.address === basis.address && r.patched), 30000);

    // A call assembled by name: main's call of checksum calls twice instead.
    await palette(a, "main");
    await until(a, "main", (s) => s.decompName === "main");
    const mainCall = (r: VisRow) => r.func === hx(main) && r.mnemonic === "CALL" && r.operands === "checksum";
    rows = await untilRows(a, "main's call of checksum", (rows) => rows.some(mainCall));
    const call = rows.find(mainCall)!;
    await palette(a, "0x" + call.address);
    await until(a, "on the call", (s) => s.address === call.address);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+Shift+G");
    await a.waitForSelector("[data-testid=patch-editor]");
    await a.fill("[data-testid=patch-input]", "CALL twic");
    await a.waitForSelector("[data-testid=patch-editor][data-error='1']");
    await a.fill("[data-testid=patch-input]", "CALL twice");
    await waitFn(a, () => (document.querySelector("[data-testid=patch-list] .pe-item.active .pe-detail")?.textContent ?? "").startsWith("e8 "));
    await a.keyboard.press("Enter");
    await untilRows(a, "the call patched", (rows) => rows.some((r) => r.address === call.address && r.patched && r.operands === "twice"), 30000);
    await until(a, "main's C calls twice first", (s) => s.decompName === "main" && !s.decompText.includes("checksum("), 30000);
    // Page B sees it too.
    await palette(b, "0x" + call.address);
    await untilRows(b, "the call patched in page B", (rows) => rows.some((r) => r.address === call.address && r.patched), 30000);

    // The Patches view: both, then the call reverted from it.
    await a.evaluate("window.__revkit.app.showView('patches')");
    await waitFn(a, () => document.querySelectorAll("[data-testid=patch-row]").length === 2);
    await a.click(`[data-testid=patch-row][data-address='${call.address}'] [data-testid=patch-revert]`);
    await waitFn(a, () => document.querySelectorAll("[data-testid=patch-row]").length === 1, null, { timeout: 30000 });
    await untilRows(a, "the call as it was", (rows) => rows.some((r) => r.address === call.address && !r.patched && r.operands === "checksum"), 30000);

    // Export: the whole file, its 32-bit sum in the name, verified by the daemon.
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+Shift+P");
    await a.fill("[data-testid=palette-input]", ">Export the patched");
    await waitFn(a, () => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").includes("Export the patched"));
    await a.keyboard.press("Enter");
    await a.waitForSelector("[data-testid=export-dialog]");
    await a.selectOption("[data-testid=export-alg]", { label: "sum32" });
    await a.click("[data-testid=export-add]");
    await a.fill("[data-testid=export-template]", "{NAME}_{SUM:08X}.bin");
    const [dl] = await Promise.all([a.waitForEvent("download"), a.click("[data-testid=export-run]")]);
    await a.waitForSelector("[data-testid=export-verify].ex-ok");
    const name = dl.suggestedFilename();
    const m = /^prog_([0-9A-F]{8})\.bin$/.exec(name);
    assert(m, `exported as ${name}`);
    const out = path.join(tmp, name);
    await dl.saveAs(out);
    const got = readFileSync(out);
    const orig = readFileSync(exe);
    assert(got.length === orig.length, `${got.length} bytes exported, the file has ${orig.length}`);
    let sum = 0;
    for (const x of got) sum = (sum + x) >>> 0;
    assert(sum === parseInt(m[1], 16), `the name's sum ${m[1]}, the bytes' ${sum.toString(16)}`);
    const diffs: number[] = [];
    for (let i = 0; i < got.length; i++) if (got[i] !== orig[i]) diffs.push(i);
    assert(diffs.length === 1 && orig[diffs[0]] === 0xc5 && got[diffs[0]] === 0xc6, `changed bytes ${JSON.stringify(diffs.map((i) => [i, orig[i], got[i]]))}`);
    await a.keyboard.press("Escape");
    await a.waitForSelector("[data-testid=export-dialog]", { state: "detached" });

    // Compare with original: the file as imported against the patched program.
    await a.click("[data-testid=patches-compare]");
    await waitFn(a, () => {
      const s = document.querySelector<HTMLSelectElement>("[data-testid=diff-session]");
      return !!s && (s.selectedOptions[0]?.textContent ?? "").includes("original vs patched");
    }, null, { timeout: 60000 });
    await a.evaluate("window.__revkit.app.showView('listing')");
  });

  // The memory map after import (e2e/memory.ts): a raw firmware gains RAM and another file's bytes.
  if (wants("memory.ts")) await memoryChecks({
    base, browseDir: tmp, check, rpc, assert,
    page: async (query) => {
      const ctx = await browser!.newContext({ viewport: { width: 1500, height: 900 } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?${query}`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      return p;
    },
  });

  // Demangled names (e2e/demangle.ts): a stripped C++ library's names in every view, either spelling.
  if (wants("demangle.ts")) await demangleChecks({
    base, dir: tmp, check, rpc, assert,
    page: async (query) => {
      const ctx = await browser!.newContext({ viewport: { width: 1500, height: 900 } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?${query}`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      return p;
    },
  });

  // The class hierarchy (e2e/classes.ts): MSVC RTTI classes, a tree, details, navigation.
  if (wants("classes.ts")) await classesChecks({
    base, dir: tmp, check, rpc, assert, log,
    page: async (query) => {
      const ctx = await browser!.newContext({ viewport: { width: 1500, height: 900 } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?${query}`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      return p;
    },
  });

  // Separate debug files (e2e/debugfiles.ts): Load debug file… and its settings.
  if (wants("debugfiles.ts")) await debugFileChecks({
    base, dir: tmp, check, rpc, assert, log,
    page: async (query) => {
      const ctx = await browser!.newContext({ viewport: { width: 1500, height: 900 } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?${query}`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      return p;
    },
  });

  // Project-wide types and the Archives section (e2e/projecttypes.ts).
  if (wants("projecttypes.ts")) await projectTypesChecks({
    base, dir: tmp, check, rpc, assert, log,
    page: async (query) => {
      const ctx = await browser!.newContext({ viewport: { width: 1500, height: 900 } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?${query}`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      return p;
    },
  });

  // Function ID (e2e/fid.ts): a database from one program names a library's functions in another.
  if (wants("fid.ts")) await fidChecks({
    base, dir: tmp, check, rpc, assert, log,
    page: async (query) => {
      const ctx = await browser!.newContext({ viewport: { width: 1500, height: 900 } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?${query}`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      return p;
    },
  });

  // Comparing any two functions (e2e/compare.ts): Compare with…, token-level apply, manual matching.
  if (wants("compare.ts")) await compareChecks({
    base, dir: tmp, check, rpc, assert, log,
    page: async (query) => {
      const ctx = await browser!.newContext({ viewport: { width: 1500, height: 900 } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?${query}`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      return p;
    },
  });

  // Editing the auto-struct preview and chained structures (e2e/autostruct.ts).
  if (wants("autostruct.ts")) await autoStructEditChecks({
    base, dir: tmp, check, rpc, assert, log,
    page: async (query) => {
      const ctx = await browser!.newContext({ viewport: { width: 1500, height: 900 } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?${query}`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      return p;
    },
  });

  // Edit Function and the calling conventions (e2e/editfunction.ts).
  if (wants("editfunction.ts")) await editFunctionChecks({
    base, dir: tmp, check, rpc, assert, log,
    page: async (query) => {
      const ctx = await browser!.newContext({ viewport: { width: 1500, height: 900 } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?${query}`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      return p;
    },
  });

  // Register values over ranges (e2e/regvalues.ts).
  if (wants("regvalues.ts")) await regValuesChecks({
    base, dir: tmp, check, rpc, assert, log,
    page: async (query) => {
      const ctx = await browser!.newContext({ viewport: { width: 1500, height: 900 } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?${query}`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      return p;
    },
  });

  // BSim databases (e2e/bsim.ts).
  if (wants("bsim.ts")) await bsimChecks({
    base, dir: tmp, check, rpc, assert, log,
    page: async (query) => {
      const ctx = await browser!.newContext({ viewport: { width: 1500, height: 900 } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?${query}`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      return p;
    },
  });

  // The UI polish pass (e2e/uipolish.ts): menus, focus, the palette, narrow windows.
  if (wants("uipolish.ts")) await uiPolishChecks({
    check, assert,
    page: async (width, height) => {
      const ctx = await browser!.newContext({ viewport: { width, height } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?program=default%2Fprog&user=e2e&theme=dark`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      await p.waitForFunction("window.__revkit.app.snapshot().decompName === 'main'", undefined, { timeout: 20000 });
      return p;
    },
  });

  // The keymap presets (e2e/keymap.ts): Ghidra, IDA Pro, Binary Ninja.
  await keymapChecks({
    check, assert,
    page: async (width, height) => {
      const ctx = await browser!.newContext({ viewport: { width, height } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?program=default%2Fprog&user=e2e&theme=dark`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      await p.waitForFunction("window.__revkit.app.snapshot().decompName === 'main'", undefined, { timeout: 20000 });
      return p;
    },
  });

  // Decompiler slices and def-use (e2e/slices.ts).
  await sliceChecks({
    check, assert, log,
    page: async (width, height) => {
      const ctx = await browser!.newContext({ viewport: { width, height } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?program=default%2Fprog&user=e2e&theme=dark`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      await p.waitForFunction("window.__revkit.app.snapshot().decompName === 'main'", undefined, { timeout: 20000 });
      return p;
    },
  });

  // Resizable dialogs (e2e/dialogsize.ts): the Open dialog grows, its size kept.
  await dialogSizeChecks({
    check, assert,
    page: async (width, height) => {
      const ctx = await browser!.newContext({ viewport: { width, height } });
      const p = await ctx.newPage();
      p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
      await p.goto(`${base}/?program=default%2Fprog&user=e2e&theme=dark`);
      await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
      return p;
    },
  });

  // The daemon status chip (e2e/daemon.ts): connected, a killed daemon, Reconnect.
  if (wants("daemon.ts")) await daemonChecks({
    browser: browser!, bin: daemonBin(), web: process.env.RK_WEB_ROOT ?? path.join(ui, "dist"), exe, check, assert, log,
    env: { XDG_CONFIG_HOME: path.join(tmp, "xdg-config") },
  });

  await check("rendering fallback: DPR 1 with a status indicator", async () => {
    const c = await open(base, "&dpr=1", "", 2);
    await c.waitForSelector("#st-render:not([hidden])");
    const r = (await c.evaluate(`(() => { const cv = document.getElementById("listing-canvas"); return [cv.width, Math.round(cv.getBoundingClientRect().width), window.devicePixelRatio, document.getElementById("st-render").textContent]; })()`)) as [number, number, number, string];
    assert(r[2] === 2 && r[0] === r[1], `canvas ${r[0]} px for ${r[1]} css px at DPR ${r[2]}`);
    assert(r[3].includes("DPR 1"), `indicator: ${r[3]}`);
    // Without the override, a fast engine keeps the native ratio.
    const d = await open(base, "", "", 2);
    await d.waitForFunction("document.body.dataset.probeMs !== undefined", undefined, { timeout: 10000 });
    const native = (await d.evaluate("[document.getElementById('listing-canvas').width, Math.round(document.getElementById('listing-canvas').getBoundingClientRect().width), document.body.dataset.probeMs, document.body.dataset.renderDpr ?? '2']")) as [number, number, string, string];
    log(`     probe at DPR 2: ${native[2]} ms/frame, canvas at DPR ${native[3]}`);
    // Whatever the probe decided on this machine, the canvas and the status agree.
    assert(native[0] === Number(native[3]) * native[1], `auto mode: ${native}`);
  });

  await check("decompiler failure: a crash shows the instructions, a banner, Retry and Export repro", async () => {
    // A daemon whose decompiler workers crash on twice (test fault injection).
    const crashing = await startDaemon(exe, { REVKIT_DECOMPD_FAULT: `segv@${hx(twice)}` }, "ports-crash.json");
    const p = await open(crashing, "", `#${hx(twice)}`);
    await p.waitForSelector("[data-testid=decomp-failure]:not([hidden])", { timeout: 20000 });
    const banner = (await p.textContent("#decomp-failure-text")) ?? "";
    assert(banner.includes("crashed") && banner.includes("SIGSEGV"), `banner: ${banner}`);
    // The banner first, then the instructions from the listing.
    await p.waitForFunction(`document.querySelector("#cm .cm-content").innerText.includes("instructions")`, undefined, { timeout: 20000 });
    const text = (await p.evaluate(`document.querySelector("#cm .cm-content").innerText`)) as string;
    assert(text.includes("instructions") && text.includes(hx(twice)), `pane: ${text.slice(0, 200)}`);
    assert((await p.textContent("#decomp-retry")) === "Retry", "a crash is retried as is");
    const [download] = await Promise.all([p.waitForEvent("download"), p.click("#decomp-repro")]);
    const bundle = readFileSync((await download.path())!);
    assert(bundle.subarray(0, 8).toString() === "RKBUNDLE", `downloaded ${bundle.length} bytes`);
    await p.click("#decomp-retry");
    await p.waitForSelector("[data-testid=decomp-failure]:not([hidden])", { timeout: 20000 });
    // The daemon is fine: another function decompiles, and the banner goes.
    await palette(p, "checksum");
    await until(p, "checksum after the crash", (s) => s.decompName === "checksum" && s.decompText.includes("return"));
    assert(await p.locator("[data-testid=decomp-failure]").isHidden(), "banner hidden for a decompiled function");
    await p.context().close();
  });

  await check("address spaces: an AVR firmware shows code:/mem: addresses in words, Go To and the space switch", async () => {
    // reset: jmp 0x100; at 0x100: ldi r30,0xa0; ldi r31,0; icall; rjmp . ; at 0x140:
    // lds r24,0x100; inc r24; sts 0x100,r24; ret
    const words: number[] = [0x940c, 0x0080];
    while (words.length < 0x80) words.push(0x9518);
    words.push(0xeae0, 0xe0f0, 0x9509, 0xcfff);
    while (words.length < 0xa0) words.push(0);
    words.push(0x9180, 0x0100, 0x9583, 0x9380, 0x0100, 0x9508);
    const fw = path.join(tmp, "avr.bin");
    const bytes = Buffer.alloc(words.length * 2);
    words.forEach((w, i) => bytes.writeUInt16LE(w, 2 * i));
    writeFileSync(fw, bytes);
    const imported = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", {
      projectId: "default", path: fw, name: "avr",
      options: { format: "raw", languageId: "avr8:LE:16:default", compilerSpecId: "gcc", analyze: true },
    });
    const id = imported.program.programId;
    const fns = (await rpc<{ functions: { name: string; entry: { offset: string } }[] }>(base, "QueryService/ListFunctions", { programId: id, page: { pageSize: 100 } })).functions;
    assert(fns.some((f) => f.name === "FUN_code_00a0" && BigInt(f.entry.offset) === 0x140n), `functions: ${fns.map((f) => f.name)}`);
    const c = await browser!.newContext({ viewport: { width: 1500, height: 900 } });
    const p = await c.newPage();
    p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
    await p.goto(`${base}/?program=${encodeURIComponent(id)}&user=e2e&theme=dark#code:00a0`);
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    await p.waitForFunction(() => (document.querySelector("#st-loc")?.textContent ?? "").startsWith("code:00a0"));
    assert(/2-byte words/.test((await p.getAttribute("#st-loc", "title")) ?? ""), "the word unit is noted");
    // The space switch lists code and mem; Go To takes mem:0x100.
    const spaces = await p.$$eval("#st-space option", (os) => os.map((o) => (o as HTMLOptionElement).value));
    assert(spaces.includes("code") && spaces.includes("mem"), `spaces: ${spaces}`);
    await palette(p, "mem:0100");
    await p.waitForFunction(() => (document.querySelector("#st-loc")?.textContent ?? "").startsWith("mem:0100"));
    await p.selectOption("#st-space", "code");
    await p.waitForFunction(() => (document.querySelector("#st-loc")?.textContent ?? "").startsWith("code:"));
    await c.close();
  });

  await check("auth: login page, sign in over TLS, edit as user:alice, reload keeps the session, log out", async () => {
    // A daemon with accounts and a self-signed certificate (docs/security.md).
    const authFile = path.join(tmp, "auth.db");
    execFileSync(daemonBin(), ["user", "add", "alice", "--role", "editor", "--password-stdin", "--auth-file", authFile], { input: "alice-password\n" });
    // It also lets the plain daemon's page (another origin, like the Tauri shell) call it.
    const secure = await startDaemon(exe, {}, "ports-auth.json", ["--auth-file", authFile, "--tls-self-signed", "--tls-dir", path.join(tmp, "tls"), "--allow-origin", base]);
    assert(secure.startsWith("https://"), `served at ${secure}`);
    const ctx = await browser!.newContext({ viewport: { width: 1500, height: 900 }, ignoreHTTPSErrors: true });
    const p = await ctx.newPage();
    p.on("pageerror", (e) => log(`  [pageerror] ${e.message}`));
    await p.goto(`${secure}/?program=default%2Fprog&theme=dark#${hx(twice)}`);
    await p.waitForSelector("body[data-ready='login']", { timeout: 20000 });
    assert(await p.locator("[data-testid=login]").isVisible(), "the login page");

    await p.fill("[data-testid=login-user]", "alice");
    await p.fill("[data-testid=login-password]", "not her password");
    await p.click("[data-testid=login-submit]");
    await p.waitForFunction(() => (document.querySelector("[data-testid=login-error]")?.textContent ?? "").includes("Wrong"));

    await p.fill("[data-testid=login-password]", "alice-password");
    await Promise.all([p.waitForEvent("load"), p.click("[data-testid=login-submit]")]);
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    assert((await p.textContent("#user")) === "user:alice", `toolbar: ${await p.textContent("#user")}`);
    assert(await p.locator("[data-testid=logout]").isVisible(), "a Log out button");
    // The session cookie: HttpOnly, Secure, SameSite=Strict, out of the page's reach.
    const cookie = (await ctx.cookies()).find((c) => c.name === "__Host-rk_session");
    assert(cookie && cookie.httpOnly && cookie.secure && cookie.sameSite === "Strict", `cookie: ${JSON.stringify(cookie)}`);
    assert(!((await p.evaluate("document.cookie")) as string).includes("rk_session"), "page scripts can't read the session");

    // Edit: the daemon records the signed-in account.
    await until(p, "twice", (s) => s.decompName === "twice" && s.live === "live");
    await p.focus("#listing-canvas");
    await p.keyboard.press("n");
    await answer(p, "twice_signed_in");
    await until(p, "renamed", (s) => s.decompName === "twice_signed_in");
    await p.focus("#listing-canvas");
    await p.keyboard.press("i");
    const who = await p.locator("[data-testid=provenance] [data-testid=prov-who]").textContent({ timeout: 5000 });
    assert(who === "user:alice", `badge says ${who}`);
    await p.keyboard.press("Escape");
    // Emulation is alice's too (sessions belong to who made them).
    await emulateOneStep(p, hx(twice));

    // A second tab of the same browser sees alice's cursor, named by the daemon.
    const q = await ctx.newPage();
    await q.goto(`${secure}/?program=default%2Fprog&theme=dark&user=someone-else#${hx(main)}`);
    await q.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    await until(q, "alice's cursor", (s) => s.collaborators.some((c) => c.name === "alice"), 15000);

    // A reload keeps the session.
    await p.reload();
    await p.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    await until(p, "still renamed", (s) => s.decompName === "twice_signed_in");
    assert((await p.textContent("#user")) === "user:alice", "still alice after a reload");

    // Log out: the login page again, the cookie gone, the session ended.
    await Promise.all([p.waitForEvent("load"), p.click("[data-testid=logout]")]);
    await p.waitForSelector("body[data-ready='login']", { timeout: 20000 });
    assert(!(await ctx.cookies()).some((c) => c.name === "__Host-rk_session"), "the cookie is cleared");
    const status = (await p.evaluate(async () => {
      const r = await fetch("/revkit.v1.QueryService/ListFunctions", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"programId":"default/prog"}' });
      return r.status;
    })) as number;
    assert(status === 401, `after logout the API answers ${status}`);

    // Another origin (the Tauri shell's case): no cookie can follow, so the
    // page signs in for a bearer token, which survives a reload.
    const x = await ctx.newPage();
    await x.goto(`${base}/?api=${encodeURIComponent(secure)}&program=default%2Fprog&theme=dark#${hx(main)}`);
    await x.waitForSelector("body[data-ready='login']", { timeout: 20000 });
    await x.fill("[data-testid=login-user]", "alice");
    await x.fill("[data-testid=login-password]", "alice-password");
    await Promise.all([x.waitForEvent("load"), x.click("[data-testid=login-submit]")]);
    await x.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    assert((await x.textContent("#user")) === "user:alice", "signed in across origins");
    await until(x, "main via the other origin", (s) => s.decompName === "main" && s.live === "live");
    await emulateOneStep(x, hx(main));
    await x.reload();
    await x.waitForSelector("body[data-ready='1']", { timeout: 20000 });
    await Promise.all([x.waitForEvent("load"), x.click("[data-testid=logout]")]);
    await x.waitForSelector("body[data-ready='login']", { timeout: 20000 });
    await ctx.close();
  });
}

async function cleanup() {
  await browser?.close().catch(() => {});
  for (const d of others) if (d.exitCode === null) d.kill("SIGTERM");
  if (daemon && daemon.exitCode === null) {
    daemon.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 300));
  }
  rmSync(tmp, { recursive: true, force: true });
}

main()
  .then(async () => {
    await cleanup();
    log(failures ? `${failures} failed` : "all e2e checks passed");
    process.exit(failures ? 1 : 0);
  })
  .catch(async (e) => {
    if (!failures) log(`FAIL ${step}: ${e instanceof Error ? e.stack : e}`);
    await cleanup();
    process.exit(1);
  });
