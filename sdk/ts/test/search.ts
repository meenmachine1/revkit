// The searches through the TypeScript client (api_minor 41, feature
// "search"; docs/api.md "Search"): over Connect as a browser speaks it,
// against `rk-daemon --backend image` with a hand-assembled ARM image,
// memory (hex, a decimal, a string, next and previous), program text (a
// rename counts), scalars and decompiled C, with progress and cancel.
//
//   RK_DAEMON=../../build/tools/rk-daemon/rk-daemon npx tsx test/search.ts
import { createConnectTransport } from "@connectrpc/connect-node";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import assert from "node:assert/strict";

import {
  createRevkit, SEARCH_FEATURE, SearchFormat, searchDecompiled, searchMemory, searchScalars, searchText, splitMatch,
  TextField,
} from "../src/index";

const bin = process.env.RK_DAEMON ?? path.resolve(import.meta.dirname, "../../../build/tools/rk-daemon/rk-daemon");
const dir = mkdtempSync(path.join(tmpdir(), "rk-ts-search-"));

function words(...ws: number[]): Uint8Array {
  const out = new Uint8Array(ws.length * 4);
  const view = new DataView(out.buffer);
  ws.forEach((w, i) => view.setUint32(4 * i, w >>> 0, true));
  return out;
}

// 0x00 b main; 0x20 main: push {lr}; bl 0x40; bl 0x50; pop {pc}; 0x40, 0x50:
// mov r0, #7 / #9; bx lr; 0x60 a constant; 0x64 "Hello".
const image = new Uint8Array(0x80);
image.set(words(0xea000006), 0);
image.set(words(0xe52de004, 0xeb000005, 0xeb000008, 0xe49df004), 0x20);
image.set(words(0xe3a00007, 0xe12fff1e), 0x40);
image.set(words(0xe3a00009, 0xe12fff1e), 0x50);
image.set(words(0xdeadbeef), 0x60);
image.set(new TextEncoder().encode("Hello"), 0x64);

async function main() {
  const ports = path.join(dir, "ports.json");
  const daemon = spawn(bin, ["--backend", "image", "--no-auth", "--grpc", "127.0.0.1:0", "--http", "127.0.0.1:0", "--port-file", ports],
    { stdio: ["ignore", "ignore", "inherit"] });
  try {
    for (let i = 0; i < 600 && !existsSync(ports); i++) await new Promise((r) => setTimeout(r, 50));
    const { http } = JSON.parse(readFileSync(ports, "utf8"));
    const rk = createRevkit(createConnectTransport({ baseUrl: `http://127.0.0.1:${http}`, httpVersion: "1.1" }));
    const info = await rk.meta.getServerInfo({});
    assert.ok(info.apiMinor >= 41 && info.features.includes(SEARCH_FEATURE));
    const imported = await rk.projects.importProgram({
      projectId: "default", name: "fw.bin", source: { case: "content", value: image },
      options: { format: "raw", languageId: "ARM:LE:32:v4t", rawPermissions: "r-x" },
    });
    const programId = imported.program!.programId;

    // Memory: hex with a nibble wildcard, the same as a decimal, a string in any case.
    let progressed = 0;
    const hex = await searchMemory(rk, { programId, query: "ef be a? de", details: true }, { onProgress: () => progressed++ });
    assert.deepEqual(hex.matches.map((m) => m.address!.offset), [0x60n]);
    assert.ok(progressed >= 1 && hex.last!.done && hex.last!.pattern === "ef be a? de");
    const dec = await searchMemory(rk, { programId, format: SearchFormat.DECIMAL, query: "0xdeadbeef", unsignedValues: true });
    assert.deepEqual(dec.matches.map((m) => m.address!.offset), [0x60n]);
    const str = await searchMemory(rk, { programId, format: SearchFormat.STRING, query: "HELLO" });
    assert.deepEqual(str.matches.map((m) => m.address!.offset), [0x64n]);
    // Next and previous from 0x40: the two "bx lr".
    const next = await searchMemory(rk, { programId, query: "1e ff 2f e1", start: { from: { offset: 0x44n } }, maxResults: 1 });
    assert.deepEqual(next.matches.map((m) => m.address!.offset), [0x54n]);
    const prev = await searchMemory(rk, { programId, query: "1e ff 2f e1", start: { from: { offset: 0x54n }, backward: true }, maxResults: 1 });
    assert.deepEqual(prev.matches.map((m) => m.address!.offset), [0x44n]);

    // Program text, then a rename that it follows.
    const calls = await searchText(rk, { programId, query: "bl ", fields: [TextField.MNEMONICS, TextField.OPERANDS] });
    assert.equal(calls.matches.length, 2);
    await rk.assertions.appendAssertions({
      programId,
      provenance: { kind: 1, id: "ts" },
      assertions: [{ body: { kind: { case: "rename", value: { target: { kind: { case: "address", value: { offset: 0x40n } } }, name: "seven" } } } }],
    });
    const renamed = await searchText(rk, { programId, query: "seven", caseSensitive: true });
    const fields = new Set(renamed.matches.map((m) => m.field));
    assert.ok(fields.has(TextField.LABELS) && fields.has(TextField.OPERANDS), JSON.stringify([...fields]));
    const op = renamed.matches.find((m) => m.field === TextField.OPERANDS)!;
    assert.equal(splitMatch(op.text, op.matchStart, op.matchLength)[1], "seven");

    // Scalars: #7 and #9.
    const scal = await searchScalars(rk, { programId, min: 7n, max: 9n });
    assert.deepEqual(scal.matches.map((m) => [m.address!.offset, m.value]), [[0x40n, 7n], [0x50n, 9n]]);

    // Decompiled C: every function, with progress; cancelled at once.
    let done = 0;
    const c = await searchDecompiled(rk, { programId, query: "return 9;", all: true }, { onProgress: (m) => (done = m.functionsDone) });
    assert.equal(c.matches.length, 1);
    assert.equal(c.matches[0].function!.offset, 0x50n);
    assert.ok(done >= 3);
    const stop = new AbortController();
    stop.abort();
    await assert.rejects(searchDecompiled(rk, { programId, query: "return", all: true }, { signal: stop.signal }));
    console.log("ts search: ok");
  } finally {
    daemon.kill("SIGTERM");
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
