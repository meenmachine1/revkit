// End-to-end checks for demangled names (docs/demangle.md, feature
// "demangle"): a stripped C++ library whose exports keep their mangled
// names. The function list, the listing's header rows, the decompiler and
// the palette's symbol search show the demangled names; a search by the
// mangled name finds them; the "Names:" commands show the mangled names
// (and the full signatures) everywhere and back. run.ts calls
// demangleChecks().

import type { Page } from "playwright";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import path from "node:path";

export interface DemangleContext {
  base: string;
  /** A directory under the daemon's --browse-root. */
  dir: string;
  check: (name: string, fn: () => Promise<void>) => Promise<void>;
  /** A new page at `${base}/?<query>`, once the app is ready. */
  page: (query: string) => Promise<Page>;
  rpc: <T>(base: string, method: string, body: unknown) => Promise<T>;
  assert: (cond: unknown, msg: string) => asserts cond;
}

const LIBRARY = String.raw`
namespace geo {
class Shape {
 public:
  explicit Shape(int id);
  virtual ~Shape();
  virtual double area() const;
  void scale(double factor);
  double grow(double factor);
  int id_;
  double size_;
};
Shape::Shape(int id) : id_(id), size_(1) {}
Shape::~Shape() {}
double Shape::area() const { return size_ * size_; }
__attribute__((noinline)) void Shape::scale(double factor) { size_ *= factor; }
double Shape::grow(double factor) {
  scale(factor);
  return area();
}
}  // namespace geo
`;

interface Snap {
  address: string | null;
  decompName: string | null;
  decompText: string;
  live: string;
}
type VisRow = { address: string; kind: number; header: { kind: number; text: string } | null; label: string; operands: string };
const HDR = { Signature: 2, Label: 3 };

async function until<T>(p: Page, what: string, get: string, pred: (v: T) => boolean, ms = 15000): Promise<T> {
  const end = Date.now() + ms;
  let v = (await p.evaluate(get)) as T;
  while (!pred(v)) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; state: ${JSON.stringify(v).slice(0, 1500)}`);
    await p.waitForTimeout(50);
    v = (await p.evaluate(get)) as T;
  }
  return v;
}

async function command(p: Page, title: string) {
  await p.focus("#listing-canvas");
  await p.keyboard.press("Control+Shift+P");
  await p.waitForSelector("[data-testid=palette-input]");
  await p.fill("[data-testid=palette-input]", `>${title}`);
  try {
    await p.waitForFunction((t) => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").toLowerCase().startsWith(t.toLowerCase()), title, { timeout: 10000 });
  } catch (e) {
    const items = await p.evaluate(() => [...document.querySelectorAll(".palette-item")].map((x) => x.textContent));
    throw new Error(`no command "${title}": ${JSON.stringify(items)}`);
  }
  await p.keyboard.press("Enter");
}

export async function demangleChecks(c: DemangleContext) {
  const { base, check, rpc } = c;
  const assert: (cond: unknown, msg: string) => asserts cond = c.assert;
  const src = path.join(c.dir, "libgeo.cc");
  const lib = path.join(c.dir, "libgeo.so");
  writeFileSync(src, LIBRARY);
  execFileSync(process.env.CC ?? "cc", ["-x", "c++", "-O1", "-fPIC", "-shared", "-fno-exceptions", "-fno-rtti", "-s", "-o", lib, src]);
  const imported = await rpc<{ program: { programId: string } }>(base, "ProjectService/ImportProgram", {
    projectId: "default", path: lib, name: "libgeo", provenance: { kind: "PROVENANCE_KIND_USER", id: "e2e" },
  });
  const programId = imported.program.programId;
  type Fn = { entry: { offset: string }; name: string; thunk?: boolean; demangled?: { mangled: string; full: string } };
  const fns = (await rpc<{ functions?: Fn[] }>(base, "QueryService/ListFunctions", { programId, page: { pageSize: 500 } })).functions ?? [];
  const scale = fns.find((f) => f.name === "geo::Shape::scale" && !f.thunk);
  assert(scale, `geo::Shape::scale not listed: ${JSON.stringify(fns.map((f) => f.name))}`);
  assert(scale.demangled?.mangled === "_ZN3geo5Shape5scaleEd", `its mangled name: ${JSON.stringify(scale.demangled)}`);
  const at = BigInt(scale.entry.offset).toString(16);
  const p = await c.page(`program=${encodeURIComponent(programId)}&user=e2e&theme=dark&headers=1`);
  const snap = "window.__revkit.app.snapshot()";
  const rows = "window.__revkit.app.visibleRows()";

  await check("demangled names: the function list, the palette by either spelling, header rows and the decompiler", async () => {
    // The function list names it demangled.
    await p.waitForFunction(() => [...document.querySelectorAll("#fnpanel .fn-name")].some((e) => e.textContent === "geo::Shape::scale"), undefined, { timeout: 15000 });
    // The palette finds it by its mangled name, says why, and goes there.
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+k");
    await p.waitForSelector("[data-testid=palette-input]");
    await p.fill("[data-testid=palette-input]", "_ZN3geo5Shape5scale");
    await p.waitForFunction(() => {
      const first = document.querySelector(".palette-item.active");
      return !!first && (first.querySelector(".pi-label")?.textContent ?? "") === "geo::Shape::scale" &&
        (first.textContent ?? "").includes("mangled _ZN3geo5Shape5scaleEd");
    }, undefined, { timeout: 15000 });
    await p.keyboard.press("Enter");
    // (The function or its PLT stub: both are named after it.)
    await until<Snap>(p, "the decompiled function", snap, (s) => s.decompName === "geo::Shape::scale" && s.decompText.includes("geo::Shape::scale(Shape *this,double param_2)"));
    // The function itself, by address.
    await p.focus("#listing-canvas");
    await p.keyboard.press("Control+k");
    await p.waitForSelector("[data-testid=palette-input]");
    await p.fill("[data-testid=palette-input]", "0x" + at);
    await p.waitForFunction(() => (document.querySelector(".palette-item.active .pi-label")?.textContent ?? "").startsWith("Go to"));
    await p.keyboard.press("Enter");
    await until<Snap>(p, "the function", snap, (s) => s.address === at && s.decompText.includes("geo::Shape::scale(Shape *this,double param_2)"));
    // Header rows: the demangled prototype and the label.
    const r = await until<VisRow[]>(p, "header rows", rows, (rs) => rs.some((x) => x.address === at && x.header?.kind === HDR.Label));
    const sig = r.find((x) => x.address === at && x.header?.kind === HDR.Signature)?.header?.text ?? "";
    assert(sig === "undefined geo::Shape::scale(geo::Shape *this, double param_2)", `signature: ${sig}`);
    // A caller names it as the decompiler qualifies it.
    const grow = fns.find((f) => f.name === "geo::Shape::grow" && !f.thunk)!;
    const g = await rpc<{ function?: { text?: string } }>(base, "QueryService/Decompile", { programId, function: { offset: grow.entry.offset }, options: { includeText: true } });
    assert((g.function?.text ?? "").includes("scale("), `grow: ${g.function?.text}`);
  });

  await check("demangled names: Names: show mangled, then full signatures, then back, in every view", async () => {
    await command(p, "Names: mangled (as the file spells them)");
    await until<Snap>(p, "mangled in the decompiler", snap, (s) => s.decompText.includes("_ZN3geo5Shape5scaleEd(Shape *this"));
    await until<VisRow[]>(p, "mangled in the listing", rows, (rs) =>
      rs.some((x) => x.address === at && x.header?.kind === HDR.Label && x.header.text === "_ZN3geo5Shape5scaleEd") &&
      rs.some((x) => x.address === at && x.header?.kind === HDR.Signature && x.header.text.includes(" _ZN3geo5Shape5scaleEd(")));
    await p.waitForFunction(() => [...document.querySelectorAll("#fnpanel .fn-name")].some((e) => e.textContent === "_ZN3geo5Shape5scaleEd"), undefined, { timeout: 15000 });
    await command(p, "Names: demangled, full signatures");
    await until<Snap>(p, "full signatures in the decompiler", snap, (s) => s.decompText.includes("geo::Shape::scale(double)(Shape *this"));
    await command(p, "Names: demangled, short");
    await until<Snap>(p, "short names again", snap, (s) => s.decompText.includes("geo::Shape::scale(Shape *this,double param_2)"));
    await until<VisRow[]>(p, "short names in the listing", rows, (rs) => rs.some((x) => x.address === at && x.header?.kind === HDR.Label && x.header.text === "geo::Shape::scale"));
    // The setting persists (per browser).
    const kept = await p.evaluate("localStorage.getItem('rk.names')");
    assert(kept === "short", `rk.names = ${kept}`);
  });
  await p.context().close();
}
