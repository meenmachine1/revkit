// autoStructureBodies and the request builders (src/structures.ts), without a daemon.
import assert from "node:assert/strict";
import { create } from "@bufbuild/protobuf";

import { AutoStructureMode, AutoStructureResponseSchema, TypeKind, autoStructureBodies, autoStructureRequest, structureFromRangeRequest } from "../src/index";

const made = create(AutoStructureResponseSchema, {
  name: "astruct",
  namedKey: "struct astruct",
  nodes: [
    { kind: TypeKind.STRUCT, name: "astruct", size: 16n, fields: [{ name: "field_0x0", type: { kind: { case: "hash", value: "aa" } }, offset: 0n }] },
    { kind: TypeKind.POINTER, target: { kind: { case: "assertionIndex", value: 0 } } },
  ],
  structIndex: 0,
  pointerIndex: 1,
  structHash: "s1",
  pointerHash: "p1",
});

const onVariable = autoStructureBodies(made, { function: 0x401000n, storageKey: "param:0" });
assert.deepEqual(onVariable.map((b) => b.kind.case), ["defineType", "defineType", "bindTypeName", "retype"]);
const bind = onVariable[2].kind.case === "bindTypeName" ? onVariable[2].kind.value.type : undefined;
assert.deepEqual(bind?.kind, { case: "assertionIndex", value: 0 });
const retype = onVariable[3].kind.case === "retype" ? onVariable[3].kind.value : undefined;
assert.equal(retype?.target?.kind.case, "local");
assert.deepEqual(retype?.type?.kind, { case: "typeHash", value: "p1" });

const atRange = autoStructureBodies(made, { at: 0x404000 });
const data = atRange[3].kind.case === "listingEdit" ? atRange[3].kind.value : undefined;
assert.equal(data?.address?.offset, 0x404000n);
assert.deepEqual(data?.kind.case === "data" ? data.kind.value.type?.kind : undefined, { case: "typeHash", value: "s1" });

// An anonymous structure (filled in) is not bound.
assert.equal(autoStructureBodies(create(AutoStructureResponseSchema, { ...made, namedKey: "" }), { at: 1 }).length, 3);
assert.throws(() => autoStructureBodies(create(AutoStructureResponseSchema, { unchanged: true, notes: ["no accesses through p"] }), { at: 1 }), /no accesses/);

const req = autoStructureRequest("default/p", 0x401000, "param:0", { fill: true, callDepth: 2 });
assert.equal(req.mode, AutoStructureMode.FILL);
assert.equal(req.callDepth, 2);
assert.equal(req.source.case, "variable");
assert.equal(autoStructureRequest("p", 1, "param:1").callDepth, undefined);
const range = structureFromRangeRequest("p", 0x10, 0x1f, "hdr");
assert.equal(range.source.case === "range" ? range.source.value.last?.offset : 0n, 0x1fn);
console.log("structures: ok");
