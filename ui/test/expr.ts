// Unit tests for the Go To expression evaluator (src/data/expr.ts), without
// a daemon or a browser: CTest runs them as ui_expr.
//
//   node_modules/.bin/tsx test/expr.ts

import assert from "node:assert/strict";
import { ExprError, evaluateText, globLiteral, globToRegExp, isExpression, isGlob, parseExpr } from "../src/data/expr";

const symbols: Record<string, bigint> = {
  main: 0x401136n,
  checksum: 0x401040n,
  "ns::f": 0x402000n,
  add: 0x403000n,
  _start: 0x401000n,
};
const resolver = {
  symbol: async (n: string) => symbols[n] ?? null,
  // .text is file offset 0x1000.. at 0x401000.
  fileOffset: (o: bigint) => (o >= 0x1000n && o < 0x2000n ? 0x401000n + (o - 0x1000n) : null),
  isSpace: (n: string) => n === "mem" || n === "code",
  spaceAddress: (n: string, o: bigint) => (n === "mem" ? 0x10000n + o : n === "code" ? o * 2n : null),
};
const ev = (t: string) => evaluateText(t, resolver);

let n = 0;
async function test(name: string, fn: () => Promise<void> | void) {
  try {
    await fn();
    n++;
  } catch (e) {
    console.error(`FAIL ${name}`);
    throw e;
  }
}

async function rejects(text: string, re: RegExp) {
  await assert.rejects(ev(text), (e: unknown) => e instanceof ExprError && re.test(e.message), text);
}

await test("numbers are hex, with or without 0x, and an h suffix", async () => {
  assert.equal(await ev("401000"), 0x401000n);
  assert.equal(await ev("0x401000"), 0x401000n);
  assert.equal(await ev("401000h"), 0x401000n);
  assert.equal(await ev("10"), 0x10n);
});

await test("arithmetic: precedence, parentheses, unary minus", async () => {
  assert.equal(await ev("0x1000 + 4*3"), 0x100cn);
  assert.equal(await ev("(0x1000 + 4) * 3"), 0x300cn);
  assert.equal(await ev("0x1000 - 0x10 / 2"), 0xff8n);
  assert.equal(await ev("-1"), (1n << 64n) - 1n);
  assert.equal(await ev("0x10 - -0x10"), 0x20n);
  assert.equal(await ev("  0x1000+4 "), 0x1004n);
});

await test("symbols and offsets", async () => {
  assert.equal(await ev("main"), 0x401136n);
  assert.equal(await ev("main+0x10"), 0x401146n);
  assert.equal(await ev("main + 10"), 0x401146n);
  assert.equal(await ev("checksum - 8"), 0x401038n);
  assert.equal(await ev("ns::f+1"), 0x402001n);
  assert.equal(await ev("_start+main-main"), 0x401000n);
});

await test("a hex-letters name is the symbol when there is one, else a number", async () => {
  assert.equal(await ev("add+1"), 0x403001n);
  assert.equal(await ev("face"), 0xfacen);
});

await test("file offsets and address spaces", async () => {
  assert.equal(await ev("file:0x1200"), 0x401200n);
  assert.equal(await ev("file:1000 + 4"), 0x401004n);
  assert.equal(await ev("file:(0x1000+0x10)"), 0x401010n);
  assert.equal(await ev("mem:0x100"), 0x10100n);
  assert.equal(await ev("code:3a"), 0x74n);
  await rejects("file:0x10", /isn't loaded/);
  await rejects("bogus:0x10", /no address space/);
});

await test("errors say what and where", async () => {
  await rejects("nosuch+1", /no symbol "nosuch"/);
  await rejects("1 / 0", /division by zero/);
  await rejects("(1 + 2", /expected "\)"/);
  await rejects("1 +", /expected a number or a name/);
  await rejects("1 2", /unexpected "2"/);
  await rejects("1 % 2", /unexpected "%"/);
  assert.throws(() => parseExpr("main + #"), (e: unknown) => e instanceof ExprError && e.at === 7);
});

await test("what counts as an expression", () => {
  for (const t of ["main+0x10", "0x1000 + 4*3", "file:0x200", "(main)", "a-b"]) assert.ok(isExpression(t), t);
  for (const t of ["main", "401000", "FUN_*", "", "-"]) assert.ok(!isExpression(t), t);
});

await test("wildcards", () => {
  for (const t of ["FUN_*", "str?cpy", "*alloc*", "ns::*"]) assert.ok(isGlob(t), t);
  for (const t of ["4*3", "0x10*0x8", "main + 1", "main", "a * b"]) assert.ok(!isGlob(t), t);
  const re = globToRegExp("FUN_00*");
  assert.ok(re.test("FUN_00401000") && !re.test("xFUN_00401000") && !re.test("FUN_10"));
  assert.ok(globToRegExp("str?cpy").test("strncpy") && !globToRegExp("str?cpy").test("strcpy"));
  assert.ok(globToRegExp("a.b*").test("a.bc") && !globToRegExp("a.b*").test("axbc"));
  assert.equal(globLiteral("*alloc*"), "alloc");
  assert.equal(globLiteral("FUN_*"), "FUN_");
  assert.equal(globLiteral("st?ing_lit*"), "ing_lit");
});

console.log(`ok   ${n} expression tests`);
