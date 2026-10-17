// Editing what bytes are, from the listing (api_minor 30, feature
// "listing-edit"; docs/listing-edit.md): Clear, Disassemble here and Define
// data (AssertionBody.listingEdit), and constant or volatile ranges
// (AssertionBody.mutability). Each builder makes an AppendAssertions body;
// undo is RetractAssertions on every seq the append returned (a defineData
// whose type the server parsed also returns that type's TYPE_DEF
// assertions).
//
//   await rk.assertions.appendAssertions({ programId, assertions: [{ body: defineData(0x4010n, "uint32_t") }] });
import { create } from "@bufbuild/protobuf";

import {
  AssertionBodySchema,
  DataEndian,
  DataFormat,
  DataPadding,
  DataSignedness,
  InstructionSet,
  Mutability,
  StringEncoding,
  StringLayout,
  StringTermination,
  PointerKind,
  type AppendAssertionsResponse,
  type Assertion,
  type AssertionBody,
} from "./gen/revkit/v1/assertion_pb";

export const LISTING_EDIT_FEATURE = "listing-edit";

type Big = bigint | number;
const big = (v: Big): bigint => (typeof v === "bigint" ? v : BigInt(v));

function pick<T>(table: Record<string, T>, value: string | T, what: string): T {
  if (typeof value !== "string") return value;
  const key = value.trim().toLowerCase().replace(/-/g, "");
  if (!(key in table)) throw new Error(`${what} is one of ${Object.keys(table).join(", ")}, not "${value}"`);
  return table[key];
}

const INSTRUCTION_SETS: Record<string, InstructionSet> = { arm: InstructionSet.ARM, thumb: InstructionSet.THUMB };
const ENCODINGS: Record<string, StringEncoding> = {
  utf8: StringEncoding.UTF8, utf16: StringEncoding.UTF16, utf32: StringEncoding.UTF32,
};
const LAYOUTS: Record<string, StringLayout> = {
  terminated: StringLayout.TERMINATED, fixed: StringLayout.FIXED, pascal: StringLayout.PASCAL, pascal16: StringLayout.PASCAL16,
};
const MUTABILITIES: Record<string, Mutability> = {
  default: Mutability.DEFAULT, normal: Mutability.NORMAL, constant: Mutability.CONSTANT, volatile: Mutability.VOLATILE,
};

/** Clear (Ghidra's C): bytes [address, address + length) back to undefined. */
export function clearCode(address: Big, length: Big = 1n): AssertionBody {
  if (big(length) < 1n) throw new Error("clearCode: length must be at least 1");
  return create(AssertionBodySchema, {
    kind: { case: "listingEdit", value: { address: { offset: big(address) }, kind: { case: "clear", value: { length: big(length) } } } },
  });
}

export interface DisassembleOptions {
  /** "arm" or "thumb" where the language has both; default as the context says. */
  isa?: "arm" | "thumb" | InstructionSet;
  /** Also a function starting here. */
  function?: boolean;
}

/** Disassemble here (Ghidra's D): code starts at the address. */
export function disassemble(address: Big, o: DisassembleOptions = {}): AssertionBody {
  const instructionSet = o.isa === undefined ? InstructionSet.UNSPECIFIED : pick(INSTRUCTION_SETS, o.isa, "isa");
  return create(AssertionBodySchema, {
    kind: {
      case: "listingEdit",
      value: { address: { offset: big(address) }, kind: { case: "disassemble", value: { instructionSet, function: o.function ?? false } } },
    },
  });
}

export interface DefineDataOptions {
  /** C ("uint32_t", "struct hdr", "char *") or a Ghidra builtin ("byte",
   * "word", "dword", "qword", "float", "double", "pointer", ...). */
  type?: string;
  /** An existing type by hash, instead of `type`. */
  typeHash?: string;
  /** An array of this many; for a "fixed" string, its characters. */
  count?: Big;
  /** A string of these characters (then the type is ignored). */
  string?: "utf8" | "utf16" | "utf32" | StringEncoding;
  /** How the string's length is known; default "terminated". */
  layout?: "terminated" | "fixed" | "pascal" | "pascal16" | StringLayout;
  /** One row, or a row per field or element (default: arrays collapsed, structs expanded). */
  collapsed?: boolean;
}

/** Define data: a typed item, an array of them, or a string, at the address.
 * `defineData(a, "dword")` is `defineData(a, { type: "dword" })`. */
export function defineData(address: Big, o: DefineDataOptions | string): AssertionBody {
  const d: DefineDataOptions = typeof o === "string" ? { type: o } : o;
  if (d.layout !== undefined && d.string === undefined) throw new Error("defineData: a layout is for strings (give string)");
  if (d.string === undefined && !d.type && !d.typeHash) throw new Error("defineData: give a type, typeHash or string");
  const type = d.string !== undefined && !d.type && !d.typeHash ? undefined
    : { kind: d.typeHash ? { case: "typeHash" as const, value: d.typeHash } : { case: "cDeclaration" as const, value: d.type ?? "" } };
  return create(AssertionBodySchema, {
    kind: {
      case: "listingEdit",
      value: {
        address: { offset: big(address) },
        kind: {
          case: "data",
          value: {
            type,
            count: big(d.count ?? 0n),
            string: d.string === undefined ? StringEncoding.UNSPECIFIED : pick(ENCODINGS, d.string, "string"),
            layout: d.string === undefined ? StringLayout.UNSPECIFIED : pick(LAYOUTS, d.layout ?? "terminated", "layout"),
            collapsed: d.collapsed,
          },
        },
      },
    },
  });
}

/** [address, address + length) is "constant" (reads fold), "volatile" (never
 * folded), "normal" (writable) or "default" (as the memory map says). */
export function setMutability(address: Big, length: Big,
                              mutability: "default" | "normal" | "constant" | "volatile" | Mutability): AssertionBody {
  if (big(length) < 1n) throw new Error("setMutability: length must be at least 1");
  return create(AssertionBodySchema, {
    kind: {
      case: "mutability",
      value: { address: { offset: big(address) }, length: big(length), mutability: pick(MUTABILITIES, mutability, "mutability") },
    },
  });
}

export const DATA_SETTINGS_FEATURE = "data-settings";

const FORMATS: Record<string, DataFormat> = {
  hex: DataFormat.HEX, decimal: DataFormat.DECIMAL, octal: DataFormat.OCTAL, binary: DataFormat.BINARY, char: DataFormat.CHAR,
};
const ENDIANS: Record<string, DataEndian> = { little: DataEndian.LITTLE, big: DataEndian.BIG };
const PADDINGS: Record<string, DataPadding> = { padded: DataPadding.PADDED, unpadded: DataPadding.UNPADDED };
const TERMINATIONS: Record<string, StringTermination> = { nul: StringTermination.NUL, all: StringTermination.ALL };
const POINTERS: Record<string, PointerKind> = {
  absolute: PointerKind.ABSOLUTE, imagebase: PointerKind.IMAGE_BASE_OFFSET, relative: PointerKind.RELATIVE,
};

/** Data settings (api_minor 84, feature "data-settings"); unset leaves a
 * setting to the type's default. */
export interface DataSettingsOptions {
  format?: "hex" | "decimal" | "octal" | "binary" | "char" | DataFormat;
  signed?: boolean;
  endian?: "little" | "big" | DataEndian;
  padding?: "padded" | "unpadded" | DataPadding;
  /** "US-ASCII", "ISO-8859-1", "windows-1252", "UTF-8", "UTF-16", "UTF-16LE", "UTF-16BE", "UTF-32", "UTF-32LE", "UTF-32BE". */
  charset?: string;
  termination?: "nul" | "all" | StringTermination;
  /** What a pointer's stored value is: the address, an image-base offset, or relative to the pointer. */
  pointer?: "absolute" | "image-base" | "relative" | PointerKind;
  /** Pointers: the stored value's bits that hold it, then a left shift (negative: right). */
  mask?: Big;
  shift?: number;
}

/** How a data item displays (Ghidra's Data Settings): the item at `address`
 * (`field`: a struct field's row, "hdr.magic"), or `{ typeName }` for that
 * type's default settings. No settings removes them. */
export function setDataSettings(target: Big | { address: Big; field?: string } | { typeName: string },
                                o: DataSettingsOptions = {}): AssertionBody {
  const settings = {
    format: o.format === undefined ? DataFormat.UNSPECIFIED : pick(FORMATS, o.format, "format"),
    signedness: o.signed === undefined ? DataSignedness.UNSPECIFIED : o.signed ? DataSignedness.SIGNED : DataSignedness.UNSIGNED,
    endian: o.endian === undefined ? DataEndian.UNSPECIFIED : pick(ENDIANS, o.endian, "endian"),
    padding: o.padding === undefined ? DataPadding.UNSPECIFIED : pick(PADDINGS, o.padding, "padding"),
    charset: o.charset ?? "",
    termination: o.termination === undefined ? StringTermination.UNSPECIFIED : pick(TERMINATIONS, o.termination, "termination"),
    pointerKind: o.pointer === undefined ? PointerKind.UNSPECIFIED : pick(POINTERS, o.pointer, "pointer"),
    pointerMask: o.mask === undefined ? undefined : big(o.mask),
    pointerShift: o.shift,
  };
  const value =
    typeof target === "object" && "typeName" in target
      ? { typeName: target.typeName, settings }
      : typeof target === "object"
        ? { address: { offset: big(target.address) }, field: target.field ?? "", settings }
        : { address: { offset: big(target) }, settings };
  return create(AssertionBodySchema, { kind: { case: "dataSettings", value } });
}

/** The builders together: listingEdit.defineData(...), ... */
export const listingEdit = { clearCode, disassemble, defineData, setMutability, setDataSettings };

/** The edit itself in an AppendAssertions response (without the TYPE_DEF
 * assertions of a type the server parsed for defineData). */
export function listingEditOf(resp: AppendAssertionsResponse): Assertion | undefined {
  return resp.assertions.find((a) => a.body?.kind.case === "listingEdit" || a.body?.kind.case === "mutability");
}
