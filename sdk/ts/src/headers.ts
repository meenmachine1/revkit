// Parsing C and importing a header (TypeService.ParseC, api_minor 25,
// feature "parse-c"; docs/cparse.md). ParseC asserts nothing; importHeader
// defines what it returned and binds the names in one AppendAssertions,
// with import:header provenance and a session of its own, so the import is
// one revision and one undo (RevertByProvenance on that session).
import { clone, create, type MessageInitShape } from "@bufbuild/protobuf";

import {
  AppendAssertionsRequestSchema,
  AssertionBodySchema,
  type AppendAssertionsResponse,
  type AssertionBody,
} from "./gen/revkit/v1/assertion_pb";
import { ProvenanceKind } from "./gen/revkit/v1/common_pb";
import {
  TypeNodeSchema,
  type ParseCRequestSchema,
  type ParseCResponse,
  type TypeNode,
  type TypeNodeRef,
} from "./gen/revkit/v1/types_pb";
import type { Revkit } from "./index";

/** ParseC for a program: its target, its types in scope. */
export function parseC(rk: Revkit, request: MessageInitShape<typeof ParseCRequestSchema>): Promise<ParseCResponse> {
  return rk.types.parseC(request);
}

/** Where a parsed name stands against the program's own definition. */
export function parsedStatus(n: { hash: string; existingHash: string }): "new" | "replaces" | "identical" {
  if (!n.existingHash) return "new";
  return n.existingHash === n.hash ? "identical" : "replaces";
}

export interface HeaderImportOptions {
  /** Names to import ("struct cJSON"); default every non-system name that is
   * new to the program or replaces its definition. */
  keys?: string[];
  /** Also bind names whose definition is already the program's. */
  includeIdentical?: boolean;
  /** Imports a name under another one ({"struct pair": "pair2"}): its
   * definition is renamed (so it, and every type reaching it, hashes anew). */
  rename?: Record<string, string>;
  /** Also define these prototypes' function types (by name), to retype
   * functions to; headerImportPlan says where each one is. */
  prototypes?: string[];
  /** Also define these nodes (indices into ParseCResponse.nodes), unbound. */
  roots?: number[];
  /** Also bind names whose definition is only the library archive's (the
   * program has none of its own), so the program gets its own; what a
   * type archive's import does. */
  includeLibrary?: boolean;
  /** File the types under ParseCNamedType.category (api_minor 35): the
   * chosen ones ("chosen", the default: a header's types under its name),
   * every parsed name whose category differs ("all": a type archive's
   * categories), or none. */
  categories?: "chosen" | "all" | "none";
}

export interface HeaderImportPlan {
  bodies: AssertionBody[];
  /** ParseC's node index -> the index of its defineType in `bodies`. */
  index: Map<number, number>;
}

function refs(node: TypeNode): TypeNodeRef[] {
  const out: TypeNodeRef[] = [];
  if (node.target) out.push(node.target);
  for (const f of node.fields) if (f.type) out.push(f.type);
  for (const p of node.params) if (p.type) out.push(p.type);
  return out;
}

/** The assertions that import a ParseC result: a defineType for every type
 * the chosen names need (references renumbered), then a bindTypeName for
 * each chosen name. */
export function headerImportBodies(parsed: ParseCResponse, options: HeaderImportOptions = {}): AssertionBody[] {
  return headerImportPlan(parsed, options).bodies;
}

/** headerImportBodies, with where each ParseC node went. */
export function headerImportPlan(parsed: ParseCResponse, options: HeaderImportOptions = {}): HeaderImportPlan {
  let chosen = parsed.named;
  if (options.keys) {
    const want = new Set(options.keys);
    const unknown = [...want].filter((k) => !parsed.named.some((n) => n.key === k));
    if (unknown.length) throw new Error(`not in the parse: ${unknown.join(", ")}`);
    chosen = chosen.filter((n) => want.has(n.key));
  } else {
    chosen = chosen.filter((n) => !n.system);
  }
  const rename = options.rename ?? {};
  if (!options.includeIdentical)
    chosen = chosen.filter((n) => n.existingHash !== n.hash || rename[n.key] || (options.includeLibrary && n.existingLibrary));
  const protos = (options.prototypes ?? []).map((name) => {
    const p = parsed.prototypes.find((x) => x.name === name);
    if (!p) throw new Error(`no prototype ${name} in the parse`);
    return p;
  });
  const need = new Set<number>();
  const stack = [...chosen.map((n) => n.index), ...protos.map((p) => p.index), ...(options.roots ?? [])];
  while (stack.length) {
    const i = stack.pop()!;
    if (need.has(i)) continue;
    need.add(i);
    for (const r of refs(parsed.nodes[i])) if (r.kind.case === "assertionIndex") stack.push(r.kind.value);
  }
  const order = [...need].sort((a, b) => a - b);
  const renumber = new Map(order.map((old, i) => [old, i]));
  const bodies: AssertionBody[] = [];
  const renamed = new Map<number, string>();
  for (const n of parsed.named) if (rename[n.key] && need.has(n.index)) renamed.set(n.index, rename[n.key]);
  for (const old of order) {
    // A copy: the parse stays as it was (create() would hand back the same message).
    const node = clone(TypeNodeSchema, parsed.nodes[old]);
    for (const r of refs(node)) if (r.kind.case === "assertionIndex") r.kind.value = renumber.get(r.kind.value)!;
    if (renamed.has(old)) node.name = renamed.get(old)!;
    bodies.push(create(AssertionBodySchema, { kind: { case: "defineType", value: { type: node } } }));
  }
  for (const n of chosen)
    bodies.push(create(AssertionBodySchema, {
      kind: { case: "bindTypeName", value: { type: { kind: { case: "assertionIndex", value: renumber.get(n.index)! } } } },
    }));
  const filing = options.categories ?? "chosen";
  if (filing !== "none") {
    const named = filing === "all" ? parsed.named : chosen;
    for (const n of named) {
      if (!n.category) continue;
      const key = rename[n.key] ? `${n.key.slice(0, n.key.indexOf(" "))} ${rename[n.key]}` : n.key;
      if (key === n.key && n.category === n.existingCategory) continue;
      bodies.push(create(AssertionBodySchema, { kind: { case: "typeCategory", value: { namedKey: key, path: n.category } } }));
    }
  }
  return { bodies, index: renumber };
}

/** A type the program has, by hash, where C wants a type name (ParseC
 * reads "__revkit_type_<hash>" as that very type). */
export function typeByHash(hash: string): string {
  return `__revkit_type_${hash}`;
}

export interface ImportHeaderOptions extends HeaderImportOptions {
  /** The header's name: the provenance's version. */
  file?: string;
  /** Default: a fresh "import-..." session, so this import alone can be undone. */
  session?: string;
  reason?: string;
  /** Default import:header (an admin's against a daemon with accounts);
   * give {} to have the daemon stamp the caller. */
  provenance?: { kind?: ProvenanceKind; id?: string };
}

/** Imports a ParseC result into a program: one AppendAssertions, one
 * revision, one undo. */
export async function importHeader(rk: Revkit, programId: string, parsed: ParseCResponse,
                                   options: ImportHeaderOptions = {}): Promise<AppendAssertionsResponse> {
  const assertions = headerImportBodies(parsed, options).map((body) => ({ body }));
  if (!assertions.length) throw new Error("nothing to import: every chosen type is already the program's");
  const session = options.session ?? `import-${Math.random().toString(16).slice(2, 14)}`;
  const who = options.provenance ?? { kind: ProvenanceKind.IMPORT, id: "header" };
  return rk.assertions.appendAssertions(create(AppendAssertionsRequestSchema, {
    programId,
    assertions,
    provenance: { ...who, version: options.file ?? "", session, reason: options.reason ?? "" },
  }));
}
