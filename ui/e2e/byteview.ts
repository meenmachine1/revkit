// End-to-end checks for the byte viewer, navigation, the overview bars,
// Copy Special and the optional listing fields (features byte-viewer,
// overview, find-next; docs/ui.md "Byte viewer, navigation and the
// overview"), on the e2e program, in two pages of their own:
//
// - the Bytes view follows the listing's cursor (bytes as ReadMemory reads
//   them, code tinted), changes bytes per line, group size and columns,
//   moves the listing from a click and a Shift+click, and shows the
//   listing's selection;
// - Edit: hex and characters typed over printf's format string write
//   patches (page B's listing shows them), and Ctrl+Z undoes the session
//   in one step;
// - next/previous function, instruction, label, different byte and note by
//   Ctrl+Alt keys and the palette, against FindNext and ListFunctions;
// - Go To expressions (sym+off, arithmetic, file offsets), wildcards and an
//   error; the history dropdown;
// - the overview bars: slices, the cursor's mark, a click that goes there,
//   hiding them;
// - Copy Special from the listing and the byte viewer in every format;
// - the Fields menu: file offset, function offset, p-code, XREF lists.
//
// run.ts calls byteViewChecks().

import type { Page } from "playwright";
import path from "node:path";

export interface ByteViewContext {
  base: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  sym: (name: string) => Promise<bigint>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
  open: (base: string, query?: string, hash?: string) => Promise<Page>;
  log: (s: string) => void;
}

interface Snap {
  address: string | null;
  rowKind: number | null;
  selection: [number, number];
  back: number;
  forward: number;
  views: string[];
}
interface BvLine {
  address: string;
  bytes: string[];
  kinds: string[];
  patched: boolean[];
}
interface BvState {
  cursor: string | null;
  selection: [string, string] | null;
  bpl: number;
  bplMode: "auto" | number;
  group: number;
  columns: string[];
  editing: boolean;
  pending: number;
  lines: BvLine[];
  text: string;
}
interface Row {
  row: number;
  address: string;
  kind: number;
  header: { kind: number; text: string } | null;
  length: number;
  patched: boolean;
  text: string;
  xrefCount: number;
}
interface Overview {
  buckets: { start: string; length: number; kind: string; entropy: number; block: string }[];
  total: number;
  cursorFrac: number | null;
  hidden: boolean;
}

const PROGRAM = "default/prog";
const INSTRUCTION = 1;
const HEADER = 4;
const LABEL = 3;
const hx = (a: bigint) => a.toString(16);
const snap = (p: Page) => p.evaluate("window.__revkit.app.snapshot()") as Promise<Snap>;
const bv = (p: Page) => p.evaluate("window.__revkit.app.byteState()") as Promise<BvState | null>;
const rows = (p: Page) => p.evaluate("window.__revkit.app.visibleRows()") as Promise<Row[]>;
const ov = (p: Page) => p.evaluate("window.__revkit.app.overviewState()") as Promise<Overview | null>;

async function poll<T>(what: string, get: () => Promise<T>, pred: (v: T) => boolean, ms = 15000): Promise<T> {
  const end = Date.now() + ms;
  let v = await get();
  while (!pred(v)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; last: ${JSON.stringify(v)?.slice(0, 1500)}`);
    await new Promise((r) => setTimeout(r, 50));
    v = await get();
  }
  return v;
}

/** `n` bytes from `a` as the viewer shows them (hex), across lines; "" for any not in view. */
function viewed(st: BvState, a: bigint, n: number): string[] {
  const out: string[] = [];
  for (let i = 0n; i < BigInt(n); i++) {
    const x = a + i;
    const line = st.lines.find((l) => BigInt("0x" + l.address) <= x && x < BigInt("0x" + l.address) + BigInt(l.bytes.length));
    out.push(line ? line.bytes[Number(x - BigInt("0x" + line.address))] : "");
  }
  return out;
}
function kindAt(st: BvState, a: bigint): string {
  const line = st.lines.find((l) => BigInt("0x" + l.address) <= a && a < BigInt("0x" + l.address) + BigInt(l.bytes.length));
  return line ? line.kinds[Number(a - BigInt("0x" + line.address))] : "";
}
function patchedAt(st: BvState, a: bigint): boolean {
  const line = st.lines.find((l) => BigInt("0x" + l.address) <= a && a < BigInt("0x" + l.address) + BigInt(l.bytes.length));
  return !!line && line.patched[Number(a - BigInt("0x" + line.address))];
}

async function shot(p: Page, name: string) {
  if (process.env.RK_SHOTS) await p.screenshot({ path: path.join(process.env.RK_SHOTS, `${name}.png`) });
}

export async function byteViewChecks(c: ByteViewContext) {
  const { base, check, sym, rpc } = c;
  const assert: ByteViewContext["assert"] = c.assert;
  const info = await rpc<{ features?: string[] }>(base, "MetaService/GetServerInfo", {});
  const features = new Set(info.features ?? []);
  if (!features.has("byte-viewer") || !features.has("find-next") || !features.has("overview")) {
    c.log("  (skipped the byte viewer checks: the daemon predates byte-viewer, find-next, overview)");
    return;
  }
  const main = await sym("main");
  const checksum = await sym("checksum");
  const twice = await sym("twice");
  const grade = await sym("grade");
  const mem = async (a: bigint, n: number) => {
    const r = await rpc<{ data?: string }>(base, "QueryService/ReadMemory", { programId: PROGRAM, address: { offset: String(a) }, length: n });
    return [...Buffer.from(r.data ?? "", "base64")].map((x) => x.toString(16).padStart(2, "0"));
  };
  /** The code unit holding `a` (address and length), from the daemon. */
  const unit = async (a: bigint) => {
    const r = await rpc<{ rows: { address: { offset: string }; length: number }[] }>(base, "QueryService/GetListing", { programId: PROGRAM, addresses: { start: { offset: String(a) }, maxRows: 1 } });
    return { address: BigInt(r.rows[0].address.offset), length: r.rows[0].length };
  };
  const findNext = async (from: bigint, kind: string, backward = false) => {
    const r = await rpc<{ found?: boolean; address?: { offset: string } }>(base, "QueryService/FindNext", { programId: PROGRAM, from: { offset: String(from) }, kind, backward });
    return r.found ? BigInt(r.address!.offset) : null;
  };
  const go = async (p: Page, a: bigint) => {
    await p.evaluate(`window.__revkit.app.navigate(0x${hx(a)}n)`);
    const u = await unit(a);
    return poll(`at ${hx(a)}`, () => snap(p), (s) => s.address === hx(u.address) && s.rowKind !== null && s.rowKind !== HEADER);
  };
  const atUnit = async (p: Page, a: bigint, what: string) => {
    const u = await unit(a);
    return poll(what, () => snap(p), (s) => s.address === hx(u.address));
  };
  const command = async (p: Page, title: string) => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+Shift+P");
    await p.waitForSelector("[data-testid=palette-input]");
    await p.fill("[data-testid=palette-input]", `>${title}`);
    await p.waitForFunction((t) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").startsWith(t), title);
    await p.keyboard.press("Enter");
  };
  /** Types into Go To and waits for the first result to start with `first`. */
  const goTo = async (p: Page, text: string, first: string, enter = true) => {
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+k");
    await p.waitForSelector("[data-testid=palette-input]");
    await p.fill("[data-testid=palette-input]", text);
    await p.waitForFunction((t) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").startsWith(t), first);
    const label = (await p.locator(".palette-item.active .pi-label").textContent()) ?? "";
    if (enter) await p.keyboard.press("Enter");
    else await p.keyboard.press("Escape");
    return label;
  };

  let a!: Page;
  let b!: Page;

  await check("byte viewer: follows the listing's cursor, bytes as the daemon reads them, code tinted", async () => {
    a = await c.open(base, "", `#${hx(checksum)}`);
    b = await c.open(base, "", `#${hx(checksum)}`);
    for (const p of [a, b]) await poll("checksum", () => snap(p), (s) => s.address === hx(checksum));
    await a.context().grantPermissions(["clipboard-read", "clipboard-write"], { origin: base });
    await command(a, "Show bytes");
    await poll("the Bytes view shown", () => snap(a), (s) => s.views.includes("bytes"));
    let st = await poll("bytes at checksum", () => bv(a), (s) => !!s && s.cursor === hx(checksum) && viewed(s, checksum, 16).every((x) => x));
    const want = await mem(checksum, 16);
    assert(viewed(st!, checksum, 16).join(" ") === want.join(" "), `bytes ${viewed(st!, checksum, 16).join(" ")} vs ${want.join(" ")}`);
    assert(kindAt(st!, checksum) === "code", `kind at checksum: ${kindAt(st!, checksum)}`);
    assert(st!.columns.includes("hex") && st!.columns.includes("ascii"), `columns ${st!.columns}`);
    // The listing moves: the viewer follows.
    await go(a, twice);
    st = await poll("bytes at twice", () => bv(a), (s) => !!s && s.cursor === hx(twice) && viewed(s, twice, 4).every((x) => x));
    await shot(a, "byte-viewer");
  });

  await check("byte viewer: auto bytes per line (the default) fits the side panel, no sideways scrolling; wider fits more", async () => {
    const fits = () => a.evaluate(() => { const b = document.querySelector<HTMLElement>("[data-testid=bv-body]")!; return [b.scrollWidth, b.clientWidth]; }) as Promise<[number, number]>;
    let st = await poll("auto", () => bv(a), (s) => !!s && s.bplMode === "auto" && s.lines.length > 2);
    let [sw, cw] = await fits();
    assert(sw <= cw + 1, `scrolls sideways at ${st!.bpl} a line: ${sw} > ${cw}`);
    assert(BigInt("0x" + st!.lines[1].address) - BigInt("0x" + st!.lines[0].address) === BigInt(st!.bpl), "line step");
    const narrow = st!.bpl;
    // A wider side: more a line, still fitting.
    await a.evaluate(() => { const side = document.getElementById("dock-side")!; side.style.width = "900px"; side.style.flexBasis = "900px"; });
    st = await poll("more a line", () => bv(a), (s) => !!s && s.bpl > narrow);
    [sw, cw] = await fits();
    assert(sw <= cw + 1, `scrolls sideways at ${st!.bpl} a line: ${sw} > ${cw}`);
    await a.evaluate(() => { const side = document.getElementById("dock-side")!; side.style.width = ""; side.style.flexBasis = ""; });
    await poll("back", () => bv(a), (s) => !!s && s.bpl === narrow);
    // The option says what auto chose.
    const label = (await a.textContent("[data-testid=bv-bpl] option[value=auto]")) ?? "";
    assert(label === `auto (${narrow}) / line`, `auto option: ${label}`);
  });

  await check("byte viewer: bytes per line, group size and the octal, binary, UTF-16 and integer columns", async () => {
    await a.selectOption("[data-testid=bv-bpl]", "8");
    await a.selectOption("[data-testid=bv-group]", "4");
    let st = await poll("8 a line in groups of 4", () => bv(a), (s) => !!s && s.bpl === 8 && s.group === 4 && s.lines.length > 2);
    assert(BigInt("0x" + st!.lines[1].address) - BigInt("0x" + st!.lines[0].address) === 8n, `line step ${st!.lines[0].address} ${st!.lines[1].address}`);
    const line = st!.lines.find((l) => l.bytes.every((x) => x))!;
    assert(st!.text.includes(`${line.bytes.slice(0, 4).join("")} ${line.bytes.slice(4, 8).join("")}`), `grouped hex in ${st!.text.slice(0, 300)}`);
    for (const col of ["octal", "binary", "utf16", "int"]) {
      await a.click("[data-testid=bv-columns]");
      await a.click(`[data-testid=bv-col-${col}]`);
    }
    st = await poll("every column", () => bv(a), (s) => !!s && s.columns.length === 6);
    const first = parseInt(line.bytes[0], 16);
    const lineText = st!.text.split("\n").find((t) => t.includes(line.bytes.slice(0, 4).join("")))!;
    assert(lineText.includes(first.toString(8).padStart(3, "0")) && lineText.includes(first.toString(2).padStart(8, "0")), `octal and binary of ${first} in ${lineText}`);
    // The integer column: the first group, little-endian, signed.
    const v = BigInt.asIntN(32, BigInt("0x" + line.bytes.slice(0, 4).reverse().join("")));
    assert(lineText.includes(String(v)), `int32 ${v} in ${lineText}`);
    for (const col of ["octal", "binary", "utf16", "int"]) {
      await a.click("[data-testid=bv-columns]");
      await a.click(`[data-testid=bv-col-${col}]`);
    }
    await a.selectOption("[data-testid=bv-bpl]", "16");
    await a.selectOption("[data-testid=bv-group]", "1");
    await poll("back to 16 bytes, hex and ASCII", () => bv(a), (s) => !!s && s.bpl === 16 && s.group === 1 && s.columns.length === 2);
    await a.selectOption("[data-testid=bv-bpl]", "auto");
    await poll("auto again", () => bv(a), (s) => !!s && s.bplMode === "auto");
  });

  await check("byte viewer: a click selects the code unit in the listing; Shift+click a range; the listing's selection shows here", async () => {
    await go(a, twice);
    await poll("twice in view", () => bv(a), (s) => !!s && viewed(s, twice, 12).every((x) => x));
    const u2 = await unit(twice + 2n);
    await a.click(`[data-testid=bv-body] [data-a="${hx(twice + 2n)}"][data-col=hex]`);
    await poll("the listing on the unit holding twice+2", () => snap(a), (s) => s.address === hx(u2.address));
    let st = await bv(a);
    assert(st!.cursor === hx(twice + 2n), `viewer cursor ${st!.cursor}`);
    await a.click(`[data-testid=bv-body] [data-a="${hx(twice + 9n)}"][data-col=hex]`, { modifiers: ["Shift"] });
    const s = await poll("rows selected over twice+2..twice+9", () => snap(a), (x) => x.selection[1] > x.selection[0]);
    const u9 = await unit(twice + 9n);
    assert(s.address === hx(u9.address), `cursor row at ${s.address}, want ${hx(u9.address)}`);
    st = await bv(a);
    assert(st!.selection?.[0] === hx(twice + 2n) && st!.selection?.[1] === hx(twice + 9n), `viewer selection ${JSON.stringify(st!.selection)}`);
    // The listing's selection (Shift+↓ twice from checksum) shows in the viewer.
    await go(a, checksum);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Shift+ArrowDown");
    await a.keyboard.press("Shift+ArrowDown");
    const r = await rows(a);
    const sel = await snap(a);
    const last = r.find((x) => x.row === sel.selection[1])!;
    const hi = BigInt("0x" + last.address) + BigInt(Math.max(1, last.length)) - 1n;
    await poll("the listing's selection in the viewer", () => bv(a), (x) => !!x && x.selection?.[0] === hx(checksum) && x.selection?.[1] === hx(hi));
  });

  let fmt = 0n;
  await check("byte viewer: Edit types hex and characters over bytes as patches (page B follows); Ctrl+Z undoes the session in one step", async () => {
    const found = await rpc<{ addresses?: { offset: string }[] }>(base, "QueryService/FindBytes", { programId: PROGRAM, pattern: Buffer.from("%u %d").toString("base64") });
    assert(found.addresses?.length === 1, `printf's format: ${JSON.stringify(found)}`);
    fmt = BigInt(found.addresses[0].offset);
    const before = await mem(fmt, 4);
    await go(a, fmt);
    await poll("the format string in view", () => bv(a), (s) => !!s && viewed(s, fmt, 4).every((x) => x));
    await a.click(`[data-testid=bv-body] [data-a="${hx(fmt)}"][data-col=hex]`);
    await a.click("[data-testid=bv-edit]");
    await poll("editing", () => bv(a), (s) => !!s && s.editing);
    await a.keyboard.type("41");
    await a.keyboard.press("Tab");
    await a.keyboard.type("BC");
    let st = await poll("three bytes written", () => bv(a), (s) => !!s && s.pending === 0 && viewed(s, fmt, 3).join("") === "414243" && patchedAt(s, fmt) && patchedAt(s, fmt + 2n));
    assert(!patchedAt(st!, fmt + 3n), "the fourth byte is as it was");
    assert((await mem(fmt, 3)).join("") === "414243", "the daemon has the patched bytes");
    // Page B: the listing's rows there are patched.
    await go(b, fmt);
    await poll("page B's row patched", () => rows(b), (r) => r.some((x) => x.patched && BigInt("0x" + x.address) <= fmt && fmt < BigInt("0x" + x.address) + BigInt(Math.max(1, x.length))));
    await a.click("[data-testid=bv-edit]");
    await poll("editing off", () => bv(a), (s) => !!s && !s.editing);
    const title = (await a.getAttribute("#undo", "title")) ?? "";
    assert(title.startsWith("Undo Edit 3 bytes at 0x" + hx(fmt)), `undo step: ${title}`);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+z");
    await poll("undone in one step", () => mem(fmt, 4), (m) => m.join("") === before.join(""));
    st = await poll("the viewer unpatched", () => bv(a), (s) => !!s && viewed(s, fmt, 4).join("") === before.join("") && !patchedAt(s, fmt));
    await poll("page B unpatched", () => rows(b), (r) => !r.some((x) => x.patched));
  });

  await check("navigation: next and previous function, instruction, label, different byte and note (Ctrl+Alt keys, palette)", async () => {
    const fns = await rpc<{ functions: { entry: { offset: string } }[] }>(base, "QueryService/ListFunctions", { programId: PROGRAM, page: { pageSize: 1000 } });
    const entries = fns.functions.map((f) => BigInt(f.entry.offset)).sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
    const next = entries.find((e) => e > checksum)!;
    await go(a, checksum);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+Alt+f");
    await atUnit(a, next, "the next function");
    await a.keyboard.press("Control+Alt+Shift+f");
    await atUnit(a, checksum, "the previous function");
    // Ctrl+Alt+↓ repeats the kind used last.
    await a.keyboard.press("Control+Alt+ArrowDown");
    await atUnit(a, next, "the next function again (Ctrl+Alt+↓)");
    // The next instruction run: past the bytes that aren't code.
    await go(a, main);
    const insn = (await findNext(main, "NAVIGATION_KIND_INSTRUCTION"))!;
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+Alt+i");
    await atUnit(a, insn, "the next instruction run");
    const back = (await findNext(insn, "NAVIGATION_KIND_INSTRUCTION", true))!;
    await a.keyboard.press("Control+Alt+Shift+i");
    await atUnit(a, back, "the previous instruction run");
    // The palette's entries.
    await go(a, checksum);
    const label = (await findNext(checksum, "NAVIGATION_KIND_LABEL"))!;
    await command(a, "Go to next label");
    await atUnit(a, label, "the next label");
    await go(a, fmt);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+Alt+v");
    await poll("the next different byte", () => bv(a), (s) => !!s && s.cursor !== null);
    const diff = (await findNext(fmt, "NAVIGATION_KIND_DIFFERENT_BYTE"))!;
    assert(diff === fmt + 1n, `'%' then 'u': ${hx(diff)}`);
    await atUnit(a, diff, "at the next different byte");
    // Notes (Ghidra's bookmarks): one at twice, found from grade.
    const appended = await rpc<{ assertions: { seq: string }[] }>(base, "AssertionService/AppendAssertions", {
      programId: PROGRAM,
      provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
      assertions: [{ body: { note: { address: { offset: String(twice) }, tag: "todo", text: "byte viewer e2e" } } }],
    });
    await go(a, grade);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Control+Alt+b");
    await atUnit(a, twice, "the next note");
    await rpc(base, "AssertionService/RetractAssertions", { programId: PROGRAM, seqs: appended.assertions.map((x) => x.seq), provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" } });
  });

  await check("go to: expressions (sym+off, arithmetic, file offsets), wildcards and an error", async () => {
    await go(a, main);
    await goTo(a, "checksum+0x4", "Go to");
    await atUnit(a, checksum + 4n, "checksum+0x4");
    await goTo(a, `0x${hx(main)} + 4*3`, "Go to");
    await atUnit(a, main + 12n, "main + 4*3");
    await goTo(a, "(twice - 2) + 2", "Go to");
    await atUnit(a, twice, "(twice - 2) + 2");
    const map = await rpc<{ blocks: { name: string; range: { first: { offset: string } }; hasFileOffset?: boolean; fileOffset?: string }[] }>(base, "QueryService/GetMemoryMap", { programId: PROGRAM });
    const text = map.blocks.find((x) => x.name === ".text" && x.hasFileOffset)!;
    const fo = BigInt(text.fileOffset ?? "0") + (main - BigInt(text.range.first.offset));
    await goTo(a, `file:0x${hx(fo)}`, "Go to");
    await atUnit(a, main, "file offset of main");
    const label = await goTo(a, "chec*", "checksum");
    assert(label === "checksum", `wildcard: ${label}`);
    await atUnit(a, checksum, "chec*");
    const err = await goTo(a, "nosuch+1", 'no symbol "nosuch"', false);
    assert(err.startsWith('no symbol "nosuch"'), `error: ${err}`);
  });

  await check("navigation: the history dropdown lists where you went and goes back there", async () => {
    await go(a, grade);
    await go(a, twice);
    await go(a, main);
    let s = await snap(a);
    const depth = s.back;
    assert(depth >= 3, `history depth ${depth}`);
    await a.click("[data-testid=history]");
    await a.waitForSelector(`[data-testid=history-${depth - 2}]`);
    const items = await a.locator("[role=menu] [data-testid^=history-]").count();
    assert(items === depth + 1 + s.forward, `items ${items}, back ${depth}, forward ${s.forward}`);
    await a.click(`[data-testid=history-${depth - 2}]`);
    s = await atUnit(a, grade, "back two places, from the dropdown");
    assert(s.back === depth - 2 && s.forward === 2, `back ${s.back} forward ${s.forward}`);
    await a.keyboard.press("Alt+ArrowRight");
    await atUnit(a, twice, "forward again");
  });

  await check("overview: code and entropy bars beside the scrollbar, the cursor marked, a click goes there; hidden from Fields", async () => {
    let o = await poll("the overview's slices", () => ov(a), (x) => !!x && x.buckets.length > 8 && !x.hidden);
    assert(o!.buckets.some((x) => x.block === ".text" && x.kind === "code"), "code in .text");
    assert(o!.buckets.some((x) => x.entropy > 0), "some entropy");
    await go(a, main);
    o = await poll("the cursor marked", () => ov(a), (x) => !!x && x.cursorFrac !== null);
    const pt = (await a.evaluate(`window.__revkit.app.overview.pointOf(0x${hx(checksum)}n)`)) as { x: number; y: number };
    await a.mouse.click(pt.x, pt.y);
    const s = await poll("moved by the overview", () => snap(a), (x) => x.address !== hx(main));
    const at = BigInt("0x" + s.address);
    const slice = o!.buckets.find((x) => BigInt("0x" + x.start) <= checksum && checksum < BigInt("0x" + x.start) + BigInt(x.length))!;
    const spread = BigInt(Math.ceil(o!.total / Math.max(1, (await a.locator("[data-testid=overview-kind]").boundingBox())!.height))) + BigInt(slice.length) + 32n;
    assert(at + spread >= checksum && at <= checksum + spread, `clicked near checksum ${hx(checksum)}, went to ${hx(at)} (±${spread})`);
    await shot(a, "overview");
    await a.click("[data-testid=fields-menu]");
    await a.click("[data-testid=field-overview]");
    await poll("hidden", () => ov(a), (x) => !!x && x.hidden);
    await a.click("[data-testid=fields-menu]");
    await a.click("[data-testid=field-overview]");
    await poll("shown again", () => ov(a), (x) => !!x && !x.hidden && x.buckets.length > 0);
  });

  await check("copy special: the listing's selection as hex, C, Python, Base64, addresses and text; the byte viewer's as hex", async () => {
    await go(a, checksum);
    await a.focus("#listing-canvas");
    await a.keyboard.press("Shift+ArrowDown");
    const s = await snap(a);
    const r = await rows(a);
    const sel = r.filter((x) => x.row >= s.selection[0] && x.row <= s.selection[1] && x.kind !== HEADER);
    const lo = BigInt("0x" + sel[0].address);
    const hi = BigInt("0x" + sel[sel.length - 1].address) + BigInt(sel[sel.length - 1].length);
    const bytes = await mem(lo, Number(hi - lo));
    await command(a, "Copy special");
    await a.waitForSelector("[data-testid=choose] .palette-item");
    await a.locator("[data-testid=choose] .palette-item", { hasText: "Hex string" }).click();
    let copy = await poll("hex copied", () => a.evaluate("window.__revkit.app.lastCopy") as Promise<{ format: string; text: string } | null>, (x) => x?.format === "hex");
    assert(copy!.text === bytes.join(""), `hex ${copy!.text} vs ${bytes.join("")}`);
    const clip = (await a.evaluate("navigator.clipboard.readText()")) as string;
    assert(clip === copy!.text, `clipboard ${clip}`);
    const fmtCopy = async (f: string) => {
      await a.evaluate(`window.__revkit.app.copySpecial(${JSON.stringify(f)})`);
      return (await poll(`${f} copied`, () => a.evaluate("window.__revkit.app.lastCopy") as Promise<{ format: string; text: string } | null>, (x) => x?.format === f))!.text;
    };
    // Each format, from the same selection (the listing has the focus).
    await a.focus("#listing-canvas");
    const cArr = await fmtCopy("c");
    assert(cArr.startsWith(`unsigned char data_${hx(lo)}[${bytes.length}] = {`) && cArr.includes(`0x${bytes[0]}, 0x${bytes[1]}`), `C: ${cArr}`);
    const py = await fmtCopy("python");
    assert(py === `b"${bytes.map((x) => `\\x${x}`).join("")}"`, `Python: ${py}`);
    const b64 = await fmtCopy("base64");
    assert(b64 === Buffer.from(bytes.join(""), "hex").toString("base64"), `Base64: ${b64}`);
    const addrs = await fmtCopy("addresses");
    assert(addrs === sel.map((x) => x.address).join("\n") + "\n", `addresses: ${addrs}`);
    const listing = await fmtCopy("listing");
    assert(listing.split("\n").length === s.selection[1] - s.selection[0] + 2 && listing.includes(sel[0].address), `listing text: ${listing}`);
    // From the byte viewer: its own selection.
    await poll("twice's bytes in view", async () => {
      await go(a, twice);
      return bv(a);
    }, (x) => !!x && viewed(x, twice, 6).every((y) => y));
    await a.click(`[data-testid=bv-body] [data-a="${hx(twice + 1n)}"][data-col=hex]`);
    await a.click(`[data-testid=bv-body] [data-a="${hx(twice + 4n)}"][data-col=hex]`, { modifiers: ["Shift"] });
    await poll("the viewer's selection", () => bv(a), (x) => !!x && x.selection?.[0] === hx(twice + 1n) && x.selection?.[1] === hx(twice + 4n));
    await a.focus("[data-testid=bv-body]");
    const spaced = await fmtCopy("hex-spaced");
    assert(spaced === (await mem(twice + 1n, 4)).join(" "), `viewer hex: ${spaced}`);
  });

  await check("fields: file offset, function offset, p-code and XREF lists from the Fields menu", async () => {
    await go(a, checksum);
    const map = await rpc<{ blocks: { name: string; range: { first: { offset: string } }; hasFileOffset?: boolean; fileOffset?: string }[] }>(base, "QueryService/GetMemoryMap", { programId: PROGRAM });
    const text = map.blocks.find((x) => x.name === ".text" && x.hasFileOffset)!;
    const fo = (BigInt(text.fileOffset ?? "0") + (checksum - BigInt(text.range.first.offset))).toString(16).padStart(8, "0");
    for (const f of ["fileOffset", "fnOffset", "pcode", "xrefList"]) {
      await a.click("[data-testid=fields-menu]");
      await a.click(`[data-testid=field-${f}]`);
    }
    const r = await poll(
      "every field drawn",
      async () => (await rows(a)).filter((x) => x.address === hx(checksum) || x.text.includes("checksum+0x")).map((x) => ({ ...x, operands: undefined, bytes: undefined })) as Row[],
      (rs) => {
        const entry = rs.find((x) => x.address === hx(checksum) && x.kind === INSTRUCTION);
        const later = rs.find((x) => x.kind === INSTRUCTION && BigInt("0x" + x.address) > checksum && x.text.includes("⟨"));
        const label = rs.find((x) => x.address === hx(checksum) && x.kind === HEADER && x.header?.kind === LABEL);
        return !!entry && entry.text.includes(fo) && !!later && !!label && /XREF\[2\]:\s+[0-9a-f]+\s*\(c\),\s+[0-9a-f]+\s*\(c\)/.test(label.text);
      },
    );
    const later = r.find((x) => x.kind === INSTRUCTION && x.text.includes("⟨"))!;
    assert(later.text.includes(`checksum+0x${(BigInt("0x" + later.address) - checksum).toString(16)}`), `function offset: ${later.text}`);
    assert(/⟨ .*(= [A-Z_0-9]+ |STORE|BRANCH|CALL|RETURN).* ⟩/.test(later.text), `p-code: ${later.text}`);
    const hdr = (await a.locator("#colhdr").textContent()) ?? "";
    assert(hdr.includes("File off") && hdr.includes("Function offset"), `column header: ${hdr}`);
    await shot(a, "listing-fields");
    for (const f of ["fileOffset", "fnOffset", "pcode", "xrefList"]) {
      await a.click("[data-testid=fields-menu]");
      await a.click(`[data-testid=field-${f}]`);
    }
    await poll("fields off", () => rows(a), (rs) => !rs.some((x) => x.text.includes("⟨") || x.text.includes("XREF[")));
    await a.context().close();
    await b.context().close();
  });
}
