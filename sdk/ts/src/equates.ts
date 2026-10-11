// Equates and user references (api_minor 39, features "equates" and
// "user-references"; docs/api.md "Equates and user references").
//
// How a scalar operand shows (Ghidra's Convert and Set Equate) is an
// OperandDisplay assertion (AssertionBody.operandDisplay); a reference the
// user adds or deletes is a UserReference (AssertionBody.reference). Each
// builder makes an AppendAssertions body; undo is RetractAssertions on every
// seq the append returned (with applyTo, one assertion per operand).
//
//   await rk.assertions.appendAssertions({ programId, assertions: [{ body: convert(0x401129n, 0x41n, "char") }] });
//
// There is no equates RPC: listEquates folds ListAssertions (kind EQUATE)
// into Ghidra's Equates table, and renameEquateBodies / removeEquateBodies
// restate every reference of one equate (one append, one undo step).
import { create } from "@bufbuild/protobuf";

import {
  AssertionBodySchema,
  AssertionOp,
  AssertionStatus,
  EquateScope,
  ReferenceType,
  ScalarFormat,
  type Assertion,
  type AssertionBody,
} from "./gen/revkit/v1/assertion_pb";
import { FactKind } from "./gen/revkit/v1/common_pb";
import type { Revkit } from "./index";

export const EQUATES_FEATURE = "equates";
export const USER_REFERENCES_FEATURE = "user-references";

type Big = bigint | number;
const big = (v: Big): bigint => (typeof v === "bigint" ? v : BigInt(v));
const U64 = (1n << 64n) - 1n;

function pick<T>(table: Record<string, T>, value: string | T, what: string): T {
  if (typeof value !== "string") return value;
  const key = value.trim().toLowerCase().replace(/[- ]/g, "_");
  if (!(key in table)) throw new Error(`${what} is one of ${Object.keys(table).join(", ")}, not "${value}"`);
  return table[key];
}

/** A scalar as its 64-bit pattern: -16n is 0xfffffffffffffff0n (the server
 * matches it against a narrower operand by sign extension); a one-character
 * string is its code ("A" is 0x41n). */
export function scalarValue(value: Big | string): bigint {
  const v = typeof value === "string" ? (value.length === 1 ? BigInt(value.codePointAt(0)!) : BigInt(value)) : big(value);
  if (v < -(1n << 63n) || v > U64) throw new Error(`a scalar is at most 64 bits, not ${value}`);
  return v & U64;
}

export type FormatName = "default" | "hex" | "signed" | "unsigned" | "octal" | "binary" | "char" | "float";
const FORMATS: Record<string, ScalarFormat> = {
  default: ScalarFormat.UNSPECIFIED, hex: ScalarFormat.HEX, signed: ScalarFormat.SIGNED_DECIMAL,
  decimal: ScalarFormat.SIGNED_DECIMAL, unsigned: ScalarFormat.UNSIGNED_DECIMAL, octal: ScalarFormat.OCTAL,
  binary: ScalarFormat.BINARY, char: ScalarFormat.CHAR, float: ScalarFormat.FLOAT,
};
const SCOPES: Record<string, EquateScope> = {
  operand: EquateScope.UNSPECIFIED, function: EquateScope.FUNCTION, program: EquateScope.PROGRAM,
};
export type ReferenceTypeName = "data" | "read" | "write" | "call" | "jump" | "computed_call" | "computed_jump";
const REFERENCE_TYPES: Record<string, ReferenceType> = {
  data: ReferenceType.DATA, read: ReferenceType.DATA_READ, data_read: ReferenceType.DATA_READ,
  write: ReferenceType.DATA_WRITE, data_write: ReferenceType.DATA_WRITE, call: ReferenceType.CALL,
  jump: ReferenceType.JUMP, computed_call: ReferenceType.COMPUTED_CALL, computed_jump: ReferenceType.COMPUTED_JUMP,
};

export interface OperandDisplayOptions {
  /** The operand's index; default: the operand holding the value. */
  operand?: number;
  /** Ghidra's Convert: "hex", "signed", "unsigned", "octal", "binary",
   * "char", "float" ("default": as the disassembler prints it). */
  format?: FormatName | ScalarFormat;
  /** Set Equate: a name. */
  equate?: string;
  /** An enum member: the enum's type hash and the member's name. */
  enumTypeHash?: string;
  member?: string;
  /** A decompiler constant no operand holds: CodeToken.constantHash. */
  constantHash?: Big;
  /** Also every other operand holding the value in the function or program. */
  applyTo?: "operand" | "function" | "program" | EquateScope;
}

/** How the scalar `value` at the instruction `address` shows. With no
 * format, equate or member it clears the display. */
export function operandDisplay(address: Big, value: Big | string, o: OperandDisplayOptions = {}): AssertionBody {
  const kinds = [o.format !== undefined, !!o.equate, !!(o.enumTypeHash || o.member)].filter(Boolean).length;
  if (kinds > 1) throw new Error("operandDisplay: give one of format, equate, or enumTypeHash and member");
  if (!!o.enumTypeHash !== !!o.member) throw new Error("operandDisplay: an enum member needs enumTypeHash and member");
  const display = o.equate ? { case: "equate" as const, value: { name: o.equate } }
    : o.enumTypeHash ? { case: "equate" as const, value: { enumTypeHash: o.enumTypeHash, member: o.member } }
    : o.format !== undefined ? { case: "format" as const, value: pick(FORMATS, o.format, "format") }
    : { case: undefined };
  return create(AssertionBodySchema, {
    kind: {
      case: "operandDisplay",
      value: {
        address: { offset: big(address) },
        operandIndex: o.operand !== undefined && o.operand >= 0 ? o.operand : undefined,
        value: scalarValue(value),
        display,
        constantHash: big(o.constantHash ?? 0n) & U64,
        applyTo: o.applyTo === undefined ? EquateScope.UNSPECIFIED : pick(SCOPES, o.applyTo, "applyTo"),
      },
    },
  });
}

type Where = Pick<OperandDisplayOptions, "operand" | "constantHash" | "applyTo">;

/** Convert: the scalar shows in `format`. */
export function convert(address: Big, value: Big | string, format: FormatName | ScalarFormat, o: Where = {}): AssertionBody {
  return operandDisplay(address, value, { ...o, format });
}

/** Set Equate: the scalar shows as `name` (one name has one value program-wide). */
export function setEquate(address: Big, value: Big | string, name: string, o: Where = {}): AssertionBody {
  return operandDisplay(address, value, { ...o, equate: name });
}

/** The scalar shows as an enum's member (the enum by type hash). */
export function enumMember(address: Big, value: Big | string, enumTypeHash: string, member: string, o: Where = {}): AssertionBody {
  return operandDisplay(address, value, { ...o, enumTypeHash, member });
}

/** The scalar shows as the disassembler prints it again. */
export function clearDisplay(address: Big, value: Big | string, o: Pick<Where, "operand" | "constantHash"> = {}): AssertionBody {
  return operandDisplay(address, value, o);
}

export interface ReferenceOptions {
  /** The operand's index; default (or -1): the instruction as a whole. */
  operand?: number;
  /** The operand shows the target's symbol; a primary computed call makes
   * the decompiler call the target. */
  primary?: boolean;
}

/** References > Add: a reference from the instruction at `from` to `to`. */
export function addReference(from: Big, to: Big, type: ReferenceTypeName | ReferenceType, o: ReferenceOptions = {}): AssertionBody {
  return create(AssertionBodySchema, {
    kind: {
      case: "reference",
      value: {
        from: { offset: big(from) },
        to: { offset: big(to) },
        operandIndex: o.operand !== undefined && o.operand >= 0 ? o.operand : undefined,
        type: pick(REFERENCE_TYPES, type, "type"),
        primary: o.primary ?? false,
      },
    },
  });
}

/** Deletes the user's reference at this key (operand, or the instruction)
 * and every reference analysis made from `from` to `to`. */
export function removeReference(from: Big, to: Big, operand?: number): AssertionBody {
  return create(AssertionBodySchema, {
    kind: {
      case: "reference",
      value: {
        from: { offset: big(from) },
        to: { offset: big(to) },
        operandIndex: operand !== undefined && operand >= 0 ? operand : undefined,
        remove: true,
      },
    },
  });
}

/** The builders together: equates.convert(...), equates.setEquate(...), ... */
export const equates = { operandDisplay, convert, setEquate, enumMember, clearDisplay };
/** references.add(...), references.remove(...). */
export const references = { add: addReference, remove: removeReference };

export interface EquateReference {
  address: bigint;
  /** Undefined for a decompiler constant keyed by its hash. */
  operandIndex?: number;
  /** The scalar's 64-bit pattern at this operand. */
  value: bigint;
  /** The assertion that names it. */
  seq: bigint;
  constantHash: bigint;
}

/** One row of the Equates table. */
export interface Equate {
  name: string;
  value: bigint;
  /** An enum member's name: the enum's hash and the member. */
  enumTypeHash: string;
  member: string;
  references: EquateReference[];
}

/** The Equates table from assertions (ListAssertions, kind EQUATE): each
 * effective display that is an equate, by name, references in address
 * order. An enum's member may share its name with another enum's (the server
 * keeps one value per name otherwise): such a member is keyed
 * "NAME#<enum hash prefix>" (its `name` stays NAME). */
export function foldEquates(assertions: Iterable<Assertion>): Map<string, Equate> {
  const groups = new Map<string, Equate>();  // name, enum hash, value
  for (const a of assertions) {
    if (a.status !== AssertionStatus.EFFECTIVE || a.op !== AssertionOp.ASSERT) continue;
    if (a.body?.kind.case !== "operandDisplay") continue;
    const d = a.body.kind.value;
    if (d.display.case !== "equate") continue;
    const name = d.display.value.name || d.display.value.member;
    if (!name) continue;
    const enumTypeHash = d.display.value.enumTypeHash;
    const ident = JSON.stringify([name, enumTypeHash, enumTypeHash ? d.value.toString(16) : ""]);
    let e = groups.get(ident);
    if (!e) {
      e = { name, value: d.value, enumTypeHash, member: d.display.value.member, references: [] };
      groups.set(ident, e);
    }
    e.references.push({ address: d.address?.offset ?? 0n, operandIndex: d.operandIndex, value: d.value, seq: a.seq,
                        constantHash: d.constantHash });
  }
  const shared = new Map<string, number>();
  for (const e of groups.values()) shared.set(e.name, (shared.get(e.name) ?? 0) + 1);
  const out = new Map<string, Equate>();
  for (const e of groups.values()) {
    e.references.sort((x, y) => (x.address !== y.address ? (x.address < y.address ? -1 : 1)
      : (x.operandIndex ?? -1) - (y.operandIndex ?? -1)));
    let key = shared.get(e.name) === 1 || !e.enumTypeHash ? e.name : `${e.name}#${e.enumTypeHash.slice(0, 12)}`;
    if (out.has(key)) key = `${key}:${e.value.toString(16)}`;
    out.set(key, e);
  }
  return new Map([...out.entries()].sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)));
}

/** The program's Equates table (ListAssertions with kind EQUATE, every page). */
export async function listEquates(rk: Revkit, programId: string): Promise<Map<string, Equate>> {
  const all: Assertion[] = [];
  let pageToken = "";
  do {
    const r = await rk.assertions.listAssertions({ programId, filter: { kinds: [FactKind.EQUATE] }, page: { pageToken } });
    all.push(...r.assertions);
    pageToken = r.page?.nextPageToken ?? "";
  } while (pageToken);
  return foldEquates(all);
}

function restate(r: EquateReference, o: OperandDisplayOptions): AssertionBody {
  return operandDisplay(r.address, r.value, {
    ...o, operand: r.operandIndex, constantHash: r.operandIndex === undefined ? r.constantHash : 0n,
  });
}

function equateNamed(table: Map<string, Equate>, name: string): Equate {
  const e = table.get(name);
  if (!e) throw new Error(`no equate "${name}"`);
  return e;
}

/** Rename everywhere: `old` becomes `name` at every reference (one append). */
export function renameEquateBodies(table: Map<string, Equate>, old: string, name: string): AssertionBody[] {
  if (!name || /\s/.test(name)) throw new Error(`an equate name is not empty and has no whitespace: "${name}"`);
  return equateNamed(table, old).references.map((r) => restate(r, { equate: name }));
}

/** Remove everywhere: every reference shows the disassembler's text again. */
export function removeEquateBodies(table: Map<string, Equate>, name: string): AssertionBody[] {
  return equateNamed(table, name).references.map((r) => restate(r, {}));
}
