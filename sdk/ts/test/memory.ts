// The memory map after import (api_minor 24, feature "memory-map";
// docs/memory-map.md) through the TypeScript client: starts
// `rk-daemon --backend image` with accounts, imports a hand-assembled ARM
// firmware (as src/backend/tests/memory_map_test.cc), and as an editor adds
// RAM (a reference appears), changes and removes regions and undoes; reading
// another file from the daemon's host is an admin's, as importing is.
//
//   RK_DAEMON=../../build/tools/rk-daemon/rk-daemon npx tsx test/memory.ts
import { ConnectError, Code } from "@connectrpc/connect";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import assert from "node:assert/strict";

import { createRevkit, HOVER_FEATURE, MemoryBlockSourceKind, XrefDirection, preview, scalarText } from "../src/index";
import { nodeTransport } from "../node/index";

const bin = process.env.RK_DAEMON ?? path.resolve(import.meta.dirname, "../../../build/tools/rk-daemon/rk-daemon");
const dir = mkdtempSync(path.join(tmpdir(), "rk-ts-memory-"));
const auth = ["--auth-file", path.join(dir, "auth.db")];

function words(...ws: number[]): Uint8Array {
  const out = new Uint8Array(ws.length * 4);
  const view = new DataView(out.buffer);
  ws.forEach((w, i) => view.setUint32(4 * i, w >>> 0, true));
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(0x100);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

// 0x00 b main; 0x20 main calls read_ram (0x40), read_const (0x50) and 0x100000.
const firmware = concat(
  words(0xea000006, ...Array(7).fill(0xeafffffe)),
  words(0xe52de004, 0xeb000005, 0xeb000008, 0xeb03fff3, 0xe49df004, 0, 0, 0),
  words(0xe59f0004, 0xe5900000, 0xe12fff1e, 0x20000000),
  words(0xe59f0004, 0xe5900000, 0xe12fff1e, 0x00080000),
);
const boot = words(0xe3a00007, 0xe12fff1e); // mov r0, #7; bx lr

async function main() {
  const editor = execFileSync(bin, ["token", "create", "--name", "ts-editor", "--role", "editor", ...auth], { encoding: "utf8" }).trim();
  const admin = execFileSync(bin, ["token", "create", "--name", "ts-admin", "--role", "admin", ...auth], { encoding: "utf8" }).trim();
  const ports = path.join(dir, "ports.json");
  const daemon = spawn(bin, ["--backend", "image", "--grpc", "127.0.0.1:0", "--http", "127.0.0.1:0", "--port-file", ports, ...auth],
    { stdio: ["ignore", "ignore", "inherit"] });
  try {
    for (let i = 0; i < 600 && !existsSync(ports); i++) await new Promise((r) => setTimeout(r, 50));
    const { http } = JSON.parse(readFileSync(ports, "utf8"));
    const baseUrl = `http://127.0.0.1:${http}`;
    const ed = createRevkit(await nodeTransport({ baseUrl, token: editor }));
    const ad = createRevkit(await nodeTransport({ baseUrl, token: admin }));

    const info = await ed.meta.getServerInfo({});
    assert.ok(info.features.includes("memory-map") && info.apiMinor >= 24, "the daemon has feature memory-map");

    const imported = await ad.projects.importProgram({
      projectId: "default", name: "fw.bin", source: { case: "content", value: firmware },
      options: { format: "raw", languageId: "ARM:LE:32:v4t", rawPermissions: "r-x" },
    });
    const programId = imported.program!.programId;
    const xrefs = async () =>
      (await ed.queries.getXrefs({ programId, location: { case: "address", value: { offset: 0x20000000n } }, direction: XrefDirection.TO })).xrefs;
    assert.equal((await xrefs()).length, 0);

    // An editor adds RAM: read_ram's pointer becomes a reference.
    const ram = await ed.projects.addMemoryRegion({
      programId, provenance: { reason: "RAM" },
      region: { name: "sram", start: 0x20000000n, size: 0x1000n, read: true, write: true },
    });
    assert.ok(ram.regionId && ram.assertion?.seq);
    assert.equal(ram.assertion?.provenance?.id, "ts-editor");
    assert.equal(ram.block?.source?.kind, MemoryBlockSourceKind.NONE);
    assert.ok((await xrefs()).length > 0, "a reference into the new RAM");

    // Overlaps are refused with the block named.
    await assert.rejects(ed.projects.addMemoryRegion({ programId, region: { name: "x", start: 0x80n, size: 0x10n, read: true } }),
      (e: unknown) => e instanceof ConnectError && e.code === Code.InvalidArgument && /overlaps block ram/.test(e.rawMessage));

    // Another file's bytes: from the host only as admin; uploaded, as an editor.
    const file = path.join(dir, "boot.bin");
    writeFileSync(file, boot);
    await assert.rejects(ed.projects.addMemoryRegion({ programId, region: { name: "boot", start: 0x100000n, read: true, execute: true },
      bytes: { case: "path", value: file } }), (e: unknown) => e instanceof ConnectError && e.code === Code.PermissionDenied);
    const code = await ad.projects.addMemoryRegion({ programId, region: { name: "boot", start: 0x100000n, read: true, execute: true },
      bytes: { case: "path", value: file } });
    assert.equal(code.block?.source?.file, "boot.bin");
    const fns = await ed.queries.listFunctions({ programId });
    assert.ok(fns.functions.some((f) => f.entry?.offset === 0x100000n), "the call reaches the bootloader");
    const up = await ed.projects.addMemoryRegion({ programId, region: { name: "consts", start: 0x80000n, read: true },
      bytes: { case: "content", value: words(0x12345678) }, fileName: "consts.bin" });
    assert.equal(up.block?.range?.last?.offset, 0x80003n);

    // Change, remove, undo.
    const vol = await ed.projects.updateMemoryRegion({ programId, regionId: ram.regionId,
      region: { name: "sram", start: 0x20000000n, size: 0x1000n, read: true, write: true, isVolatile: true } });
    assert.ok(vol.block?.isVolatile);
    const removed = await ed.projects.removeMemoryRegion({ programId, regionId: code.regionId });
    let map = await ed.queries.getMemoryMap({ programId });
    assert.deepEqual(map.blocks.map((b) => b.name), ["ram", "consts", "sram"]);
    await ed.assertions.retractAssertions({ programId, seqs: [removed.assertion!.seq] });
    map = await ed.queries.getMemoryMap({ programId });
    assert.deepEqual(map.blocks.map((b) => b.name), ["ram", "consts", "boot", "sram"]);
    console.log(`memory map: ${map.blocks.map((b) => `${b.name}@0x${b.range!.first!.offset.toString(16)}`).join(", ")}`);

    // Rebase (api_minor 42, feature "rebase"): the whole program moves, the
    // user's regions with it, as one edit; undoing it moves it back.
    if (info.features.includes("rebase")) {
      const rebased = await ed.projects.setImageBase({ programId, imageBase: 0x8000n, provenance: { reason: "the flash is at 0x8000" } });
      assert.equal(rebased.previousImageBase, 0n);
      assert.ok(rebased.assertion?.seq);
      const summary = (await ed.projects.getProgramSummary({ programId })).summary!;
      assert.equal(summary.imageBase?.offset, 0x8000n);
      assert.equal(summary.importImageBase?.offset, 0n);
      map = await ed.queries.getMemoryMap({ programId });
      assert.deepEqual(map.blocks.map((b) => `${b.name}@0x${b.range!.first!.offset.toString(16)}`),
        ["ram@0x8000", "consts@0x88000", "boot@0x108000", "sram@0x20008000"]);
      await ed.assertions.retractAssertions({ programId, seqs: [rebased.assertion!.seq] });
      map = await ed.queries.getMemoryMap({ programId });
      assert.equal(map.blocks[0].range?.first?.offset, 0n);
    }

    // Previews (feature "hover"; docs/ui.md "Hover cards"): what a hover
    // card shows, for any client.
    assert.deepEqual(scalarText(0x41n, 32), { hex: "0x41", unsigned: "65", signed: "65", chars: "'A'" });
    assert.deepEqual(scalarText(-1n, 8), { hex: "0xff", unsigned: "255", signed: "-1", chars: null });
    assert.equal(scalarText(0x454c46n).chars, "'ELF'");
    if (info.features.includes(HOVER_FEATURE)) {
      const fn = await preview(ed, programId, 0x40n);
      assert.equal(fn.kind, "function");
      assert.ok(fn.kind === "function" && fn.signature.includes("(") && fn.lines[0].includes("(") && fn.lines.includes("{"), fn.lines.join("\n"));
      const data = await preview(ed, programId, 0x4cn);
      assert.equal(data.kind, "data");
      assert.ok(data.lines.length > 0 && data.lines[0].startsWith("4c"), data.lines.join("\n"));
    }
  } finally {
    daemon.kill("SIGTERM");
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
