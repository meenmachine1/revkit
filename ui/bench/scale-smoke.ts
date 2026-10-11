// Large-binary smoke check: the API calls the functions panel and the
// header-rows listing make, timed, then the UI itself (load, panel scrolled
// to the middle and the end, filter) in host Chrome.
//
//   rk-daemon --no-auth --open /usr/lib/x86_64-linux-gnu/libLLVM.so.20.1   # serving ui/dist
//   npx tsx bench/scale-smoke.ts http://127.0.0.1:50052 default/libLLVM.so.20.1
//
// It renames one unlabelled instruction and retracts the rename.
import { chromium } from "playwright";
const [base, program] = process.argv.slice(2);
if (!base || !program) throw new Error("usage: scale-smoke.ts <daemon url> <program id>");
const rpc = async (m: string, body: unknown) => {
  const t0 = performance.now();
  const r = await fetch(`${base}/revkit.v1.${m}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json();
  if (!r.ok) throw new Error(`${m}: ${JSON.stringify(j)}`);
  return { j, ms: performance.now() - t0 };
};
const med = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const first = await rpc("QueryService/ListFunctions", { programId: program, page: { pageSize: 200 } });
const total = Number(first.j.page.totalCount);
console.log(`functions: ${total}; first page ${first.ms.toFixed(1)} ms`);
const offs: number[] = [];
for (let k = 0; k < 10; k++) offs.push((await rpc("QueryService/ListFunctions", { programId: program, offset: String(Math.floor((total * k) / 10)), page: { pageSize: 200 } })).ms);
console.log(`page of 200 by offset: median ${med(offs).toFixed(1)} ms, max ${Math.max(...offs).toFixed(1)} ms`);
const mid = first.j.functions.length ? (await rpc("QueryService/ListFunctions", { programId: program, offset: String(Math.floor(total / 2)), page: { pageSize: 1 } })).j.functions[0] : null;
const pos = await rpc("QueryService/ListFunctions", { programId: program, range: { first: { offset: "0" }, last: { offset: String(BigInt(mid.entry.offset) - 1n) } }, page: { pageSize: 1 } });
console.log(`position of the middle function (range count): ${pos.j.page.totalCount} in ${pos.ms.toFixed(1)} ms`);
const filt: number[] = [];
for (const q of ["parse", "x86", "zz_no_such"]) {
  const r = await rpc("QueryService/ListFunctions", { programId: program, nameContains: q, page: { pageSize: 200 } });
  filt.push(r.ms);
  console.log(`filter "${q}": ${r.j.page.totalCount} matches in ${r.ms.toFixed(1)} ms`);
}
const plain = await rpc("QueryService/GetListing", { programId: program, rows: { firstRow: "0", rowCount: 1 } });
const h1 = await rpc("QueryService/GetListing", { programId: program, headerRows: true, rows: { firstRow: "0", rowCount: 1 } });
const h2 = await rpc("QueryService/GetListing", { programId: program, headerRows: true, rows: { firstRow: String(Math.floor(Number(h1.j.totalRows) / 2)), rowCount: 256 } });
console.log(`listing rows: ${plain.j.totalRows} plain, ${h1.j.totalRows} with header rows; first header-rows call (computes listing.headers) ${h1.ms.toFixed(0)} ms, then 256 rows mid-program ${h2.ms.toFixed(1)} ms`);
// A rename on an unlabelled instruction: commit + header windows.
const row = h2.j.rows.find((r: { kind: string; labels?: unknown[] }) => r.kind === "LISTING_ROW_KIND_INSTRUCTION" && !r.labels?.length);
const ren = await rpc("AssertionService/AppendAssertions", { programId: program, provenance: { kind: "PROVENANCE_KIND_USER", id: "smoke" }, assertions: [{ body: { rename: { target: { address: row.address }, name: "smoke_label" } } }] });
const after = await rpc("QueryService/GetListing", { programId: program, headerRows: true, rows: { firstRow: "0", rowCount: 1 } });
console.log(`rename commit (with header windows) ${ren.ms.toFixed(1)} ms; header rows ${h1.j.totalRows} -> ${after.j.totalRows}; next listing read ${after.ms.toFixed(1)} ms`);
await rpc("AssertionService/RetractAssertions", { programId: program, seqs: [ren.j.assertions[0].seq], provenance: { kind: "PROVENANCE_KIND_USER", id: "smoke" } });

const b = await chromium.launch({ executablePath: "/usr/bin/google-chrome" });
const p = await (await b.newContext({ viewport: { width: 1500, height: 900 } })).newPage();
const t0 = performance.now();
await p.goto(`${base}/?program=${encodeURIComponent(program)}&user=smoke`);
await p.waitForSelector("body[data-ready='1']", { timeout: 120000 });
await p.waitForFunction(`document.querySelector(".fn-list")?.dataset.total === "${total}"`, undefined, { timeout: 60000 });
console.log(`UI: ready with ${total} functions listed in ${(performance.now() - t0).toFixed(0)} ms`);
for (const frac of [0.5, 0.999]) {
  const t1 = performance.now();
  await p.locator(".fn-list").evaluate((el, f) => (el.scrollTop = (el.scrollHeight - el.clientHeight) * f), frac);
  await p.waitForFunction(() => document.querySelectorAll(".fn-row.loading").length === 0 && document.querySelectorAll(".fn-row").length > 0, undefined, { timeout: 30000 });
  console.log(`UI: functions panel scrolled to ${frac * 100}%, rows loaded in ${(performance.now() - t1).toFixed(0)} ms`);
}
const t2 = performance.now();
await p.fill("[data-testid=fn-filter]", "parse");
await p.waitForFunction(() => /match/.test(document.querySelector("[data-testid=fn-count]")?.textContent ?? ""), undefined, { timeout: 30000 });
console.log(`UI: filter "parse" -> ${await p.locator("[data-testid=fn-count]").textContent()} in ${(performance.now() - t2).toFixed(0)} ms`);
if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT });
await b.close();
