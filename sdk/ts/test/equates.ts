// Equates and user references (api_minor 39, features "equates" and
// "user-references"; docs/api.md "Equates and user references") through
// the TypeScript client: against `rk-daemon --backend image` with a
// hand-assembled ARM image, the src/equates.ts builders convert a constant to
// a character (the listing and the decompiler show 'A'), name the 7s of a
// function (applyTo), fold the Equates table from ListAssertions, rename and
// remove an equate everywhere, add a data reference and delete an analysis
// call reference; each undone by retracting what it appended.
//
//   RK_DAEMON=../../build/tools/rk-daemon/rk-daemon npx tsx test/equates.ts
import { createConnectTransport } from "@connectrpc/connect-node";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import assert from "node:assert/strict";

import {
  AssertionOp, AssertionStatus, EQUATES_FEATURE, EquateScope, FactKind, ListingRowKind,
  ProvenanceKind, ReferenceType, ScalarFormat, USER_REFERENCES_FEATURE, XrefDirection, addReference, clearDisplay,
  convert, createRevkit, enumMember, equates, foldEquates, listEquates, operandDisplay, references,
  removeEquateBodies, removeReference, renameEquateBodies, scalarValue, setEquate, type AppendAssertionsResponse,
  type Assertion, type AssertionBody, type ListingRow,
} from "../src/index";

const bin = process.env.RK_DAEMON ?? path.resolve(import.meta.dirname, "../../../build/tools/rk-daemon/rk-daemon");
const dir = mkdtempSync(path.join(tmpdir(), "rk-ts-equates-"));

function words(...ws: number[]): Uint8Array {
  const out = new Uint8Array(ws.length * 4);
  const view = new DataView(out.buffer);
  ws.forEach((w, i) => view.setUint32(4 * i, w >>> 0, true));
  return out;
}

// 0x00 b main (the other vectors b .); 0x20 main: push {lr}; bl read_g; bl letter; bl sevens; pop {pc};
// 0x40 read_g: ldr r0, =0x80; ldr r0, [r0]; bx lr; 0x50 letter: mov r0, #0x41; bx lr;
// 0x60 sevens: and r0, r0, #7; add r0, r0, #7; bx lr; 0x80 a word; 0x84 "hello".
const image = new Uint8Array(0x100);
image.set(words(0xea000006, ...Array(7).fill(0xeafffffe)), 0);
image.set(words(0xe52de004, 0xeb000005, 0xeb000008, 0xeb00000b, 0xe49df004), 0x20);
image.set(words(0xe59f0004, 0xe5900000, 0xe12fff1e, 0x80), 0x40);
image.set(words(0xe3a00041, 0xe12fff1e), 0x50);
image.set(words(0xe2000007, 0xe2800007, 0xe12fff1e), 0x60);
image.set(words(0x12345678), 0x80);
image.set(new TextEncoder().encode("hello\0"), 0x84);

async function main() {
  // The builders check their arguments without a daemon.
  assert.throws(() => operandDisplay(0x10, 1, { format: "hex", equate: "ONE" }), /give one of/);
  assert.throws(() => operandDisplay(0x10, 1, { member: "RED" }), /needs enumTypeHash and member/);
  assert.throws(() => convert(0x10, 1, "roman" as "hex"), /format is one of/);
  assert.throws(() => addReference(0x10, 0x20, "pointer" as "data"), /type is one of/);
  assert.equal(scalarValue(-16), 0xfffffffffffffff0n);
  assert.equal(scalarValue("A"), 0x41n);
  const chr = convert(0x10, "A", "char", { applyTo: "function" });
  assert.ok(chr.kind.case === "operandDisplay" && chr.kind.value.display.case === "format");
  assert.equal(chr.kind.value.display.value, ScalarFormat.CHAR);
  assert.equal(chr.kind.value.applyTo, EquateScope.FUNCTION);
  assert.equal(chr.kind.value.operandIndex, undefined);
  const member = enumMember(0x10, 10, "abc", "NCOLORS", { operand: 1 });
  assert.ok(member.kind.case === "operandDisplay" && member.kind.value.display.case === "equate");
  assert.equal(member.kind.value.display.value.enumTypeHash, "abc");
  assert.equal(member.kind.value.operandIndex, 1);
  const cleared = clearDisplay(0x10, 7);
  assert.ok(cleared.kind.case === "operandDisplay" && cleared.kind.value.display.case === undefined);
  const call = addReference(0x10, 0x20, "computed_call", { primary: true });
  assert.ok(call.kind.case === "reference" && call.kind.value.type === ReferenceType.COMPUTED_CALL && call.kind.value.primary);
  const gone = removeReference(0x10, 0x20, 0);
  assert.ok(gone.kind.case === "reference" && gone.kind.value.remove && gone.kind.value.operandIndex === 0);
  assert.equal(equates.setEquate, setEquate);
  assert.equal(references.remove, removeReference);
  // The fold keeps effective equates only.
  const fake = (seq: bigint, status: AssertionStatus, body: AssertionBody) =>
    ({ seq, status, op: AssertionOp.ASSERT, body }) as unknown as Assertion;
  const folded = foldEquates([
    fake(5n, AssertionStatus.EFFECTIVE, setEquate(0x20, 7, "SEVEN", { operand: 1 })),
    fake(6n, AssertionStatus.SHADOWED, setEquate(0x30, 7, "SEVEN", { operand: 0 })),
    fake(7n, AssertionStatus.EFFECTIVE, convert(0x40, 7, "char")),
    fake(8n, AssertionStatus.EFFECTIVE, setEquate(0x10, 7, "SEVEN", { constantHash: 0xabcn })),
  ]);
  assert.deepEqual([...folded.keys()], ["SEVEN"]);
  assert.deepEqual(folded.get("SEVEN")!.references.map((r) => r.seq), [8n, 5n]);
  assert.equal(folded.get("SEVEN")!.references[0].constantHash, 0xabcn);
  // Two enums' members of one name (the server allows it) are two rows.
  const red = (at: number, value: number, hash: string) => {
    const b = enumMember(at, value, hash, "RED", { operand: 0 });
    if (b.kind.case === "operandDisplay" && b.kind.value.display.case === "equate") b.kind.value.display.value.name = "RED";
    return b;
  };
  const reds = foldEquates([fake(9n, AssertionStatus.EFFECTIVE, red(0x40, 0, "aaaa1111bbbb2222")),
                            fake(10n, AssertionStatus.EFFECTIVE, red(0x50, 5, "cccc3333dddd4444"))]);
  assert.deepEqual([...reds.keys()], ["RED#aaaa1111bbbb", "RED#cccc3333dddd"]);
  assert.equal(reds.get("RED#cccc3333dddd")!.name, "RED");

  const ports = path.join(dir, "ports.json");
  const daemon = spawn(bin, ["--backend", "image", "--no-auth", "--grpc", "127.0.0.1:0", "--http", "127.0.0.1:0", "--port-file", ports],
    { stdio: ["ignore", "ignore", "inherit"] });
  try {
    for (let i = 0; i < 600 && !existsSync(ports); i++) await new Promise((r) => setTimeout(r, 50));
    const { http } = JSON.parse(readFileSync(ports, "utf8"));
    const rk = createRevkit(createConnectTransport({ baseUrl: `http://127.0.0.1:${http}`, httpVersion: "1.1" }));
    const info = await rk.meta.getServerInfo({});
    assert.ok(info.apiMinor >= 39 && info.features.includes(EQUATES_FEATURE) && info.features.includes(USER_REFERENCES_FEATURE),
      "the daemon has features equates and user-references");

    const imported = await rk.projects.importProgram({
      projectId: "default", name: "fw.bin", source: { case: "content", value: image },
      options: { format: "raw", languageId: "ARM:LE:32:v4t", rawPermissions: "r-x" },
    });
    const programId = imported.program!.programId;
    const provenance = { kind: ProvenanceKind.USER, id: "ts-editor", reason: "ts equates" };
    const edit = (...bodies: AssertionBody[]) =>
      rk.assertions.appendAssertions({ programId, assertions: bodies.map((body) => ({ body })), provenance });
    const undo = (r: AppendAssertionsResponse) => rk.assertions.retractAssertions({ programId, seqs: r.assertions.map((a) => a.seq), provenance });
    const row = async (offset: bigint): Promise<ListingRow> =>
      (await rk.queries.getListing({ programId, window: { case: "addresses", value: { start: { offset }, maxRows: 4 } } }))
        .rows.find((r) => r.kind === ListingRowKind.INSTRUCTION && r.address?.offset === offset)!;
    // The text of the operand holding the scalar `value` (by its value, which a display keeps).
    const shown = async (offset: bigint, value: bigint) => {
      const t = (await row(offset)).tokens.find((t) => t.value === value && t.operandIndex !== undefined);
      assert.ok(t, `no scalar ${value} at ${offset}`);
      return { text: t.text, origin: t.displayOrigin };
    };
    const decompiled = async (offset: bigint) =>
      (await rk.queries.decompile({ programId, function: { offset }, options: { includeText: true } })).function?.text ?? "";
    const xrefsTo = async (offset: bigint) =>
      (await rk.queries.getXrefs({ programId, location: { case: "address", value: { offset } }, direction: XrefDirection.TO })).xrefs;

    // Convert to char: 'A' in the listing and the decompiler; undo.
    assert.match((await shown(0x50n, 0x41n)).text, /0x41/);
    const c = await edit(convert(0x50, 0x41, "char"));
    assert.equal(c.assertions[0].key?.kind, FactKind.EQUATE);
    assert.match(c.assertions[0].key?.sub ?? "", /^\d+:41$/);
    let s = await shown(0x50n, 0x41n);
    assert.match(s.text, /'A'/);
    assert.ok(s.origin?.source.case === "asserted" && s.origin.source.value.seq === c.assertions[0].seq);
    assert.match(await decompiled(0x50n), /'A'/);
    await undo(c);
    s = await shown(0x50n, 0x41n);
    assert.match(s.text, /0x41/);
    assert.equal(s.origin, undefined);

    // Every 7 of the function named at once; the table folded; rename and remove everywhere.
    const named = await edit(setEquate(0x60, 7, "SEVEN", { applyTo: "function" }));
    assert.equal(named.assertions.length, 2);
    assert.match((await shown(0x64n, 7n)).text, /SEVEN/);
    let table = await listEquates(rk, programId);
    assert.deepEqual([...table.keys()], ["SEVEN"]);
    assert.equal(table.get("SEVEN")!.value, 7n);
    assert.deepEqual(table.get("SEVEN")!.references.map((r) => r.address), [0x60n, 0x64n]);
    const renamed = await edit(...renameEquateBodies(table, "SEVEN", "WEEK"));
    assert.equal(new Set(renamed.assertions.map((a) => a.revision)).size, 1, "one revision");
    assert.match((await shown(0x60n, 7n)).text, /WEEK/);
    assert.match((await shown(0x64n, 7n)).text, /WEEK/);
    assert.match(await decompiled(0x60n), /WEEK/);
    assert.deepEqual([...(await listEquates(rk, programId)).keys()], ["WEEK"]);
    await undo(renamed);
    table = await listEquates(rk, programId);
    const removed = await edit(...removeEquateBodies(table, "SEVEN"));
    assert.equal((await listEquates(rk, programId)).size, 0);
    assert.match((await shown(0x60n, 7n)).text, /0x7|7/);
    assert.doesNotMatch((await shown(0x60n, 7n)).text, /SEVEN/);
    await undo(removed);
    assert.match((await shown(0x64n, 7n)).text, /SEVEN/);
    await undo(named);
    assert.equal((await listEquates(rk, programId)).size, 0);
    assert.throws(() => renameEquateBodies(table, "NO_SUCH", "X"), /no equate/);

    // A data reference the user adds: listed with its assertion as origin.
    const ref = await edit(addReference(0x50, 0x84, "data"));
    assert.equal(ref.assertions[0].key?.kind, FactKind.REFERENCE);
    assert.equal(ref.assertions[0].key?.sub, "i:84");
    const x = (await xrefsTo(0x84n)).find((x) => x.fromAddress?.offset === 0x50n);
    assert.ok(x?.origin?.source.case === "asserted" && x.origin.source.value.seq === ref.assertions[0].seq);
    await undo(ref);
    assert.ok(!(await xrefsTo(0x84n)).some((x) => x.fromAddress?.offset === 0x50n));

    // main's call of letter deleted from xrefs (the function stays), then back.
    assert.ok((await xrefsTo(0x50n)).some((x) => x.fromAddress?.offset === 0x28n));
    const cut = await edit(removeReference(0x28, 0x50));
    assert.ok(!(await xrefsTo(0x50n)).some((x) => x.fromAddress?.offset === 0x28n));
    const fns = new Set((await rk.queries.listFunctions({ programId })).functions.map((f) => f.entry!.offset));
    assert.ok(fns.has(0x50n), "discovery keeps what it found");
    await undo(cut);
    assert.ok((await xrefsTo(0x50n)).some((x) => x.fromAddress?.offset === 0x28n));
    console.log("equates and references: convert, equate applied to a function, table, rename, remove, user and deleted references: ok");
  } finally {
    daemon.kill("SIGTERM");
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
