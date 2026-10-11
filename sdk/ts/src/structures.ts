// Structures from pointer use and from data (TypeService.AutoStructure,
// api_minor 32, feature "auto-struct"; docs/types.md): the response is a
// preview, and autoStructureBodies() makes what applies it, for one
// AppendAssertions (one revision, one undo): the response's nodes as
// define_type bodies, a bind_type_name of the structure's name, then a
// retype of the variable to a pointer to it, or a data definition of it at
// the range's start.
//
//   const made = await rk.types.autoStructure({ programId, source: { case: "variable", value: { function: { offset: fn }, storageKey: "param:0" } } });
//   await rk.assertions.appendAssertions({ programId, provenance, assertions: autoStructureBodies(made, { function: fn, storageKey: "param:0" }).map((body) => ({ body })) });
import { create } from "@bufbuild/protobuf";

import { AssertionBodySchema, type AssertionBody } from "./gen/revkit/v1/assertion_pb";
import { AutoStructureMode, AutoStructureRequestSchema, type AutoStructureRequest, type AutoStructureResponse } from "./gen/revkit/v1/types_pb";

export const AUTO_STRUCT_FEATURE = "auto-struct";
/** Field edits in the preview and field targets (api_minor 56). */
export const AUTO_STRUCT_EDIT_FEATURE = "auto-struct-edit";

type Big = bigint | number;
const big = (v: Big): bigint => (typeof v === "bigint" ? v : BigInt(v));

/** What a structure is applied to: a variable (retyped to a pointer to it),
 * an address (the structure defined there as data), or a field (a
 * field-target response: the outer structure's next version, bound to its
 * name, points to it). */
export type StructureTarget = { function: Big; storageKey: string } | { at: Big } | { field: true };

export interface AutoStructureOptions {
  /** Auto Fill in Structure: add fields to the structure the variable points to. */
  fill?: boolean;
  /** Calls deep to follow the pointer (default 1). */
  callDepth?: number;
  /** The structure's name (default "astruct", or the first free "astruct_N"). */
  name?: string;
}

/** An AutoStructure request for a variable (the preview of Auto Create or Auto Fill in Structure). */
export function autoStructureRequest(programId: string, fn: Big, storageKey: string, o: AutoStructureOptions = {}): AutoStructureRequest {
  return create(AutoStructureRequestSchema, {
    programId,
    source: { case: "variable", value: { function: { offset: big(fn) }, storageKey } },
    mode: o.fill ? AutoStructureMode.FILL : AutoStructureMode.CREATE,
    callDepth: o.callDepth,
    name: o.name ?? "",
  });
}

/** An AutoStructure request for a struct's field as a pointer (chained structures, api_minor 56,
 * feature "auto-struct-edit"): `base` is the pointer it is read through ("param:0", "param:0->0x20"). */
export function fieldStructureRequest(programId: string, fn: Big, structHash: string, offset: Big, base = "", o: AutoStructureOptions = {}): AutoStructureRequest {
  return create(AutoStructureRequestSchema, {
    programId,
    source: { case: "field", value: { function: { offset: big(fn) }, structHash, offset: big(offset), baseStorageKey: base } },
    mode: o.fill ? AutoStructureMode.FILL : AutoStructureMode.CREATE,
    callDepth: o.callDepth,
    name: o.name ?? "",
  });
}

/** An AutoStructure request for the data defined in [first, last] (Create Structure from a selection). */
export function structureFromRangeRequest(programId: string, first: Big, last: Big, name = ""): AutoStructureRequest {
  return create(AutoStructureRequestSchema, {
    programId,
    source: { case: "range", value: { first: { offset: big(first) }, last: { offset: big(last) } } },
    mode: AutoStructureMode.CREATE,
    name,
  });
}

/** The bodies that apply a structure, in one request. */
export function autoStructureBodies(made: AutoStructureResponse, target: StructureTarget): AssertionBody[] {
  if (made.nodes.length === 0) throw new Error(`nothing to apply: ${made.notes.join("; ") || "the structure would not change"}`);
  const bodies: AssertionBody[] = made.nodes.map((type) => create(AssertionBodySchema, { kind: { case: "defineType", value: { type } } }));
  if (made.namedKey)
    bodies.push(create(AssertionBodySchema, { kind: { case: "bindTypeName", value: { type: { kind: { case: "assertionIndex", value: made.structIndex } } } } }));
  // A field target (api_minor 56): the outer structure's next version takes its name.
  if (made.outerIndex !== undefined)
    bodies.push(create(AssertionBodySchema, { kind: { case: "bindTypeName", value: { type: { kind: { case: "assertionIndex", value: made.outerIndex } } } } }));
  if ("field" in target) {
    if (made.outerIndex === undefined) throw new Error("not a field target's structure");
  } else if ("at" in target) {
    bodies.push(create(AssertionBodySchema, {
      kind: {
        case: "listingEdit",
        value: { address: { offset: big(target.at) }, kind: { case: "data", value: { type: { kind: { case: "typeHash", value: made.structHash } } } } },
      },
    }));
  } else {
    bodies.push(create(AssertionBodySchema, {
      kind: {
        case: "retype",
        value: {
          target: { kind: { case: "local", value: { function: { offset: big(target.function) }, storageKey: target.storageKey } } },
          type: { kind: { case: "typeHash", value: made.pointerHash } },
        },
      },
    }));
  }
  return bodies;
}
