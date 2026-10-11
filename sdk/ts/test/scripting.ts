// Batch reads and script provenance through the TypeScript client
// (api_minor 29, features "script-batch" and "script-provenance";
// docs/scripting.md): over Connect as a browser speaks it, against
// `rk-daemon --backend image` with a hand-assembled ARM image, DecompileMany
// and ListInstructions stream, FindBytes finds a masked pattern, and an edit
// with script provenance keeps whom it was made for.
//
//   RK_DAEMON=../../build/tools/rk-daemon/rk-daemon npx tsx test/scripting.ts
import { createConnectTransport } from "@connectrpc/connect-node";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import assert from "node:assert/strict";

import {
  bytePattern, createRevkit, decompileMany, findBytes, listInstructions, ProvenanceKind, SCRIPT_BATCH_FEATURE,
  SCRIPT_PROVENANCE_FEATURE,
} from "../src/index";

const bin = process.env.RK_DAEMON ?? path.resolve(import.meta.dirname, "../../../build/tools/rk-daemon/rk-daemon");
const dir = mkdtempSync(path.join(tmpdir(), "rk-ts-scripting-"));

function words(...ws: number[]): Uint8Array {
  const out = new Uint8Array(ws.length * 4);
  const view = new DataView(out.buffer);
  ws.forEach((w, i) => view.setUint32(4 * i, w >>> 0, true));
  return out;
}

// 0x00 b main; 0x20 main: push {lr}; bl 0x40; bl 0x50; pop {pc}; 0x40, 0x50: mov r0, #n; bx lr; 0x60 a constant.
const image = new Uint8Array(0x80);
image.set(words(0xea000006), 0);
image.set(words(0xe52de004, 0xeb000005, 0xeb000008, 0xe49df004), 0x20);
image.set(words(0xe3a00007, 0xe12fff1e), 0x40);
image.set(words(0xe3a00009, 0xe12fff1e), 0x50);
image.set(words(0xdeadbeef), 0x60);

async function main() {
  const ports = path.join(dir, "ports.json");
  const daemon = spawn(bin, ["--backend", "image", "--no-auth", "--grpc", "127.0.0.1:0", "--http", "127.0.0.1:0", "--port-file", ports],
    { stdio: ["ignore", "ignore", "inherit"] });
  try {
    for (let i = 0; i < 600 && !existsSync(ports); i++) await new Promise((r) => setTimeout(r, 50));
    const { http } = JSON.parse(readFileSync(ports, "utf8"));
    const rk = createRevkit(createConnectTransport({ baseUrl: `http://127.0.0.1:${http}`, httpVersion: "1.1" }));
    const info = await rk.meta.getServerInfo({});
    assert.ok(info.apiMinor >= 29 && info.features.includes(SCRIPT_BATCH_FEATURE) && info.features.includes(SCRIPT_PROVENANCE_FEATURE));

    const imported = await rk.projects.importProgram({
      projectId: "default", name: "fw.bin", source: { case: "content", value: image },
      options: { format: "raw", languageId: "ARM:LE:32:v4t", rawPermissions: "r-x" },
    });
    const programId = imported.program!.programId;
    const fns = (await rk.queries.listFunctions({ programId })).functions;
    assert.ok(fns.length >= 3, `functions: ${fns.map((f) => f.name)}`);

    // DecompileMany: every function once, at one revision.
    const seen = new Map<bigint, string>();
    let revision = -1n;
    for await (const r of decompileMany(rk, programId, { includeText: true })) {
      assert.equal(r.error, "");
      assert.equal(r.total, fns.length);
      if (revision < 0n) revision = r.snapshot!.revision;
      assert.equal(r.snapshot!.revision, revision);
      seen.set(r.entry!.offset, r.function!.text);
    }
    assert.equal(seen.size, fns.length);
    assert.match(seen.get(0x40n) ?? "", /return 7;/);
    const named: number[] = [];
    for await (const r of decompileMany(rk, programId, { functions: [0x50n, 0x3n] })) named.push(r.index);
    assert.deepEqual(named.sort(), [0, 1]);

    // FindBytes with a nibble wildcard, and the pattern parser.
    assert.deepEqual(bytePattern("de ad"), { pattern: new Uint8Array([0xde, 0xad]), mask: new Uint8Array() });
    assert.deepEqual(bytePattern("e?").mask, new Uint8Array([0xf0]));
    const hits = await findBytes(rk, programId, "ef be a? de");
    assert.deepEqual(hits.addresses, [0x60n]);

    // ListInstructions: main's body with p-code.
    const insns = [];
    for await (const i of listInstructions(rk, programId, { function: 0x20n })) insns.push(i);
    assert.equal(insns.length, 4);
    assert.ok(insns[1].mnemonic.toLowerCase().startsWith("bl") && insns[1].pcode.length > 0);

    // An edit with script provenance, and the filter on whom it was for.
    await rk.assertions.appendAssertions({
      programId,
      provenance: { kind: ProvenanceKind.SCRIPT, id: "ts-script", version: "0123456789ab", session: "run-1", onBehalfOf: "user:ts" },
      assertions: [{ body: { kind: { case: "rename", value: { target: { kind: { case: "address", value: { offset: 0x40n } } }, name: "seven" } } } }],
    });
    const mine = await rk.assertions.listAssertions({ programId, filter: { provenance: { onBehalfOf: "user:ts" } } });
    assert.equal(mine.assertions.length, 1);
    assert.equal(mine.assertions[0].provenance?.kind, ProvenanceKind.SCRIPT);
    assert.equal(mine.assertions[0].provenance?.onBehalfOf, "user:ts");
    const none = await rk.assertions.listAssertions({ programId, filter: { provenance: { onBehalfOf: "user:else" } } });
    assert.equal(none.assertions.length, 0);
    console.log("ts scripting: ok");
  } finally {
    daemon.kill("SIGTERM");
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
