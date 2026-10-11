// Editing what bytes are, from the listing (api_minor 30, feature
// "listing-edit"; docs/listing-edit.md) through the TypeScript client:
// against `rk-daemon --backend image` with a hand-assembled ARM image, the
// src/listing.ts builders define a string and an array (the listing shows
// them), clear a function and disassemble it back, disassemble Thumb code,
// and mark a constant volatile (the decompiler stops folding it); each undone
// by retracting what it appended.
//
//   RK_DAEMON=../../build/tools/rk-daemon/rk-daemon npx tsx test/listing_edit.ts
import { createConnectTransport } from "@connectrpc/connect-node";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import assert from "node:assert/strict";

import {
  ProvenanceKind,
  clearCode, createRevkit, defineData, disassemble, FactKind, LISTING_EDIT_FEATURE, listingEdit, listingEditOf,
  ListingRowKind, Mutability, setMutability, type AppendAssertionsResponse, type AssertionBody, type ListingRow,
} from "../src/index";

const bin = process.env.RK_DAEMON ?? path.resolve(import.meta.dirname, "../../../build/tools/rk-daemon/rk-daemon");
const dir = mkdtempSync(path.join(tmpdir(), "rk-ts-listing-edit-"));

function words(...ws: number[]): Uint8Array {
  const out = new Uint8Array(ws.length * 4);
  const view = new DataView(out.buffer);
  ws.forEach((w, i) => view.setUint32(4 * i, w >>> 0, true));
  return out;
}

// 0x00 b main (the other vectors b .); 0x20 main: push {lr}; bl read_g; bl helper; pop {pc};
// 0x40 read_g: ldr r0, =0x80; ldr r0, [r0]; bx lr; 0x50 helper: mov r0, #9; bx lr;
// 0x60 Thumb, called by nothing: movs r0, #5; bx lr; 0x80 a word; 0x84 "hello"; 0x90 four words.
const image = new Uint8Array(0x100);
image.set(words(0xea000006, ...Array(7).fill(0xeafffffe)), 0);
image.set(words(0xe52de004, 0xeb000005, 0xeb000008, 0xe49df004), 0x20);
image.set(words(0xe59f0004, 0xe5900000, 0xe12fff1e, 0x80), 0x40);
image.set(words(0xe3a00009, 0xe12fff1e), 0x50);
image.set(words(0x47702005), 0x60);
image.set(words(0x12345678), 0x80);
image.set(new TextEncoder().encode("hello\0"), 0x84);
image.set(words(1, 2, 3, 4), 0x90);

async function main() {
  // The builders check their arguments without a daemon.
  assert.throws(() => defineData(0x10, {}), /give a type/);
  assert.throws(() => defineData(0x10, { type: "char", layout: "fixed" }), /layout is for strings/);
  assert.throws(() => setMutability(0x10, 4, "readonly" as "constant"), /mutability is one of/);
  assert.throws(() => clearCode(0x10, 0), /at least 1/);
  const str = defineData(0x10, { string: "utf16" });
  assert.ok(str.kind.case === "listingEdit" && str.kind.value.kind.case === "data");
  assert.equal(str.kind.value.kind.value.type, undefined);
  assert.equal(listingEdit.defineData, defineData);

  const ports = path.join(dir, "ports.json");
  const daemon = spawn(bin, ["--backend", "image", "--no-auth", "--grpc", "127.0.0.1:0", "--http", "127.0.0.1:0", "--port-file", ports],
    { stdio: ["ignore", "ignore", "inherit"] });
  try {
    for (let i = 0; i < 600 && !existsSync(ports); i++) await new Promise((r) => setTimeout(r, 50));
    const { http } = JSON.parse(readFileSync(ports, "utf8"));
    const rk = createRevkit(createConnectTransport({ baseUrl: `http://127.0.0.1:${http}`, httpVersion: "1.1" }));
    const info = await rk.meta.getServerInfo({});
    assert.ok(info.apiMinor >= 30 && info.features.includes(LISTING_EDIT_FEATURE), "the daemon has feature listing-edit");

    const imported = await rk.projects.importProgram({
      projectId: "default", name: "fw.bin", source: { case: "content", value: image },
      options: { format: "raw", languageId: "ARM:LE:32:v4t", rawPermissions: "r-x" },
    });
    const programId = imported.program!.programId;
    const edit = (body: AssertionBody) =>
      rk.assertions.appendAssertions({ programId, assertions: [{ body }], provenance: { kind: ProvenanceKind.USER, id: "ts-editor", reason: "ts listing edit" } });
    const undo = (r: AppendAssertionsResponse) => rk.assertions.retractAssertions({ programId, seqs: r.assertions.map((a) => a.seq), provenance: { kind: ProvenanceKind.USER, id: "ts-editor" } });
    const row = async (offset: bigint): Promise<ListingRow> => {
      const rows = (await rk.queries.getListing({ programId, window: { case: "addresses", value: { start: { offset }, maxRows: 10 } } }))
        .rows.filter((r) => r.kind !== ListingRowKind.HEADER);
      return rows.find((r) => r.address?.offset === offset && !r.dataField) ?? rows[0];
    };
    const entries = async () => new Set((await rk.queries.listFunctions({ programId })).functions.map((f) => f.entry!.offset));
    const decompiled = async (offset: bigint) =>
      (await rk.queries.decompile({ programId, function: { offset }, options: { includeText: true } })).function?.text ?? "";

    // Define data: a string and an array, shown in the listing.
    const s = await edit(defineData(0x84, { string: "utf8" }));
    const sd = listingEditOf(s)!;
    assert.equal(sd.key?.kind, FactKind.CODE_UNIT);
    assert.equal(sd.key?.sub, "data");
    assert.ok(sd.body?.kind.case === "listingEdit" && sd.body.kind.value.kind.case === "data");
    assert.equal(sd.body.kind.value.kind.value.size, 6n);
    let r = await row(0x84n);
    assert.equal(r.kind, ListingRowKind.DATA);
    assert.equal(r.length, 6);
    assert.equal(r.dataType, "char[6]");
    assert.ok(r.unitOrigin?.source.case === "asserted");

    const arr = await edit(defineData(0x90, { type: "uint32_t", count: 4 }));
    r = await row(0x90n);
    assert.equal(r.kind, ListingRowKind.DATA);
    assert.equal(r.length, 16);
    assert.equal(r.dataType, "uint32_t[4]");
    assert.ok(r.dataCollapsed && r.dataComponents === 4);
    const dw = await edit(defineData(0x90, "dword"));
    assert.equal((await row(0x90n)).length, 4);
    await undo(dw);
    assert.equal((await row(0x90n)).length, 16);
    await undo(arr);
    await undo(s);
    assert.notEqual((await row(0x84n)).unitOrigin?.source.case, "asserted");

    // Clear a function: gone, though main calls it; disassemble it back as a function.
    assert.ok((await entries()).has(0x50n), "helper is a function");
    const cleared = await edit(clearCode(0x50, 8));
    assert.equal(listingEditOf(cleared)?.key?.sub, "clear:8");
    assert.ok(!(await entries()).has(0x50n), "nothing starts in cleared bytes");
    assert.equal((await row(0x50n)).kind, ListingRowKind.UNDEFINED);
    const back = await edit(disassemble(0x50, { function: true }));
    assert.ok((await entries()).has(0x50n), "Disassemble here with function brings it back");
    assert.equal((await row(0x50n)).kind, ListingRowKind.INSTRUCTION);
    await undo(back);
    await undo(cleared);
    assert.ok((await entries()).has(0x50n));

    // Thumb code nothing calls: two-byte instructions once disassembled as Thumb.
    const thumb = await edit(disassemble(0x60, { isa: "thumb", function: true }));
    r = await row(0x60n);
    assert.equal(r.kind, ListingRowKind.INSTRUCTION);
    assert.equal(r.length, 2);
    await undo(thumb);

    // Read-only memory folds; volatile stops it; undo folds again.
    assert.match(await decompiled(0x40n), /0x12345678/);
    const vol = await edit(setMutability(0x80, 4, "volatile"));
    assert.equal(listingEditOf(vol)?.key?.kind, FactKind.MUTABILITY);
    assert.equal((await row(0x80n)).mutability, Mutability.VOLATILE);
    assert.doesNotMatch(await decompiled(0x40n), /0x12345678/);
    await undo(vol);
    assert.match(await decompiled(0x40n), /0x12345678/);
    console.log("listing edits: string, array, clear, disassemble (ARM and Thumb), volatile: ok");
  } finally {
    daemon.kill("SIGTERM");
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
