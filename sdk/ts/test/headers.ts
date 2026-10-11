// headerImportBodies: chooses names, keeps only the nodes they need and
// renumbers the references (no daemon needed).
import assert from "node:assert/strict";
import { create } from "@bufbuild/protobuf";
import { TypeNodeSchema } from "../src/index";

import { headerImportBodies, headerImportPlan, parsedStatus, ParseCResponseSchema, TypeKind, typeByHash } from "../src/index";

const idx = (value: number) => ({ kind: { case: "assertionIndex" as const, value } });
const parsed = create(ParseCResponseSchema, {
  nodes: [
    { kind: TypeKind.INT, size: 4n },                                      // 0 int
    { kind: TypeKind.STRUCT, name: "a", size: 4n, fields: [{ name: "x", type: idx(0) }] },  // 1 struct a
    { kind: TypeKind.STRUCT, name: "b", size: 8n, fields: [{ name: "p", type: idx(3) }] },  // 2 struct b
    { kind: TypeKind.POINTER, size: 8n, target: idx(2) },                  // 3 struct b *
    { kind: TypeKind.TYPEDEF, name: "b_t", target: { kind: { case: "hash", value: "ff" } } },  // 4
  ],
  named: [
    { key: "struct a", index: 1, hash: "a1", existingHash: "" },
    { key: "struct b", index: 2, hash: "b1", existingHash: "b0" },
    { key: "typedef b_t", index: 4, hash: "t1", existingHash: "t1" },
  ],
  prototypes: [{ name: "use_b", index: 5, hash: "f1" }],
});
parsed.nodes.push(create(TypeNodeSchema, { kind: TypeKind.FUNCTION, target: idx(3) }));  // 5 struct b *use_b(void)

assert.deepEqual(parsed.named.map(parsedStatus), ["new", "replaces", "identical"]);
const all = headerImportBodies(parsed);
assert.deepEqual(all.map((b) => b.kind.case), ["defineType", "defineType", "defineType", "defineType", "bindTypeName", "bindTypeName"]);
const onlyB = headerImportBodies(parsed, { keys: ["struct b"] });
assert.equal(onlyB.length, 3);  // struct b, its pointer, the binding
const b = onlyB[0].kind.case === "defineType" ? onlyB[0].kind.value.type! : undefined;
assert.equal(b?.name, "b");
assert.deepEqual(b?.fields[0].type?.kind, { case: "assertionIndex", value: 1 });
const bind = onlyB[2].kind.case === "bindTypeName" ? onlyB[2].kind.value.type : undefined;
assert.deepEqual(bind?.kind, { case: "assertionIndex", value: 0 });
assert.throws(() => headerImportBodies(parsed, { keys: ["struct nope"] }), /not in the parse/);
assert.equal(headerImportBodies(parsed, { keys: ["typedef b_t"] }).length, 0);
assert.equal(headerImportBodies(parsed, { keys: ["typedef b_t"], includeIdentical: true }).length, 2);
// A rename: the node takes the new name; identical names renamed import too.
const renamed = headerImportBodies(parsed, { keys: ["typedef b_t"], rename: { "typedef b_t": "b2_t" } });
assert.equal(renamed.length, 2);
assert.equal(renamed[0].kind.case === "defineType" ? renamed[0].kind.value.type?.name : "", "b2_t");
// Prototypes' function types come along (to retype functions to), with where they went.
const plan = headerImportPlan(parsed, { keys: ["struct a"], prototypes: ["use_b"] });
assert.equal(plan.bodies.filter((b) => b.kind.case === "defineType").length, 5);  // int, struct a, struct b, struct b *, the function
assert.equal(plan.index.get(5), 4);
assert.throws(() => headerImportPlan(parsed, { prototypes: ["nope"] }), /no prototype nope/);
// Unbound roots: their nodes, no binding.
const roots = headerImportPlan(parsed, { keys: [], roots: [3] });
assert.deepEqual(roots.bodies.map((b) => b.kind.case), ["defineType", "defineType"]);  // struct b and its pointer
assert.equal(typeByHash("ab12"), "__revkit_type_ab12");
// The parse itself is left as it was.
assert.deepEqual(parsed.nodes[2].fields[0].type?.kind, { case: "assertionIndex", value: 3 });
console.log("headerImportBodies: selection, renumbering, renames and prototypes");
