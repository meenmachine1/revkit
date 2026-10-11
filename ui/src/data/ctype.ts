// C type spellings ("unsigned int", "struct point *", "char[16]",
// "const uint8_t *") turned into DefineType nodes, for retyping to a named
// type by hash against a daemon without the C parser (api_minor < 25):
// with feature parse-c the daemon parses every declaration (TypeService.
// ParseC, and Retype's c_declaration) and lays every type out, and the type
// editor goes through it (data/cgen.ts). Only spellings: a base type (C's
// arithmetic types, <stdint.h> names, undefinedN, or a named type the
// program has), then const, pointers and array bounds. No layout: sizes are
// the spelling's own, alignment isn't guessed at.

import { create } from "@bufbuild/protobuf";
import { FloatKind, IntegerRank, TypeKind, TypeNodeParamSchema, TypeNodeRefSchema, TypeNodeSchema, type TypeDefinition, type TypeNode, type TypeNodeRef } from "@revkit/api";

export interface SpellContext {
  /** Bytes in a pointer (the program's). */
  pointerSize: number;
  /** Plain char is signed (x86) or not (ARM, RISC-V). */
  charSigned: boolean;
  /** A named type of the program: "struct foo", "foo" (any kind), "enum e". */
  named: (kind: "struct" | "union" | "enum" | "" , name: string) => Promise<TypeDefinition | null>;
}

export interface Spelled {
  /** Nodes to define first, in order (refer to each other by `base + index`). */
  nodes: TypeNode[];
  /** The spelled type: a hash, or an index into `nodes`. */
  ref: { hash: string } | { index: number };
  size: number;
  /** It names a struct, union, enum or typedef of the program. */
  usesNamed: boolean;
}

type Base = { node: TypeNode; size: number } | { def: TypeDefinition };

const INT = (size: number, signed: boolean, rank: IntegerRank): Base => ({ node: create(TypeNodeSchema, { kind: signed ? TypeKind.INT : TypeKind.UINT, size: BigInt(size), rank }), size });

function builtin(words: string[], ctx: SpellContext): Base | null {
  const w = words.join(" ");
  const unsigned = words.includes("unsigned");
  const signed = words.includes("signed");
  const rest = words.filter((x) => x !== "unsigned" && x !== "signed").join(" ");
  const ptr = ctx.pointerSize;
  switch (w) {
    case "void":
      return { node: create(TypeNodeSchema, { kind: TypeKind.VOID }), size: 0 };
    case "bool":
    case "_Bool":
      return { node: create(TypeNodeSchema, { kind: TypeKind.BOOL, size: 1n }), size: 1 };
    case "char":
      return { node: create(TypeNodeSchema, { kind: TypeKind.CHAR, size: 1n, isSigned: ctx.charSigned }), size: 1 };
    case "float":
      return { node: create(TypeNodeSchema, { kind: TypeKind.FLOAT, size: 4n, floatKind: FloatKind.FLOAT }), size: 4 };
    case "double":
      return { node: create(TypeNodeSchema, { kind: TypeKind.FLOAT, size: 8n, floatKind: FloatKind.DOUBLE }), size: 8 };
    case "long double":
      return { node: create(TypeNodeSchema, { kind: TypeKind.FLOAT, size: 16n, floatKind: FloatKind.LONG_DOUBLE }), size: 16 };
    // Ghidra's names, as the decompiler prints them.
    case "uchar":
      return INT(1, false, IntegerRank.CHAR);
    case "schar":
    case "sbyte":
      return INT(1, true, IntegerRank.CHAR);
    case "ushort":
      return INT(2, false, IntegerRank.SHORT);
    case "uint":
      return INT(4, false, IntegerRank.INT);
    case "ulong":
      return INT(ptr === 8 ? 8 : 4, false, IntegerRank.LONG);
    case "longlong":
      return INT(8, true, IntegerRank.LONG_LONG);
    case "ulonglong":
      return INT(8, false, IntegerRank.LONG_LONG);
    case "sword":
      return INT(2, true, IntegerRank.SHORT);
    case "sdword":
      return INT(4, true, IntegerRank.INT);
    case "sqword":
      return INT(8, true, ptr === 8 ? IntegerRank.LONG : IntegerRank.LONG_LONG);
    case "longdouble":
      return { node: create(TypeNodeSchema, { kind: TypeKind.FLOAT, size: 16n, floatKind: FloatKind.LONG_DOUBLE }), size: 16 };
    case "code":
      return { node: create(TypeNodeSchema, { kind: TypeKind.UNDEFINED, size: 1n }), size: 1 };
    case "int8_t":
      return INT(1, true, IntegerRank.CHAR);
    case "uint8_t":
    case "byte":
      return INT(1, false, IntegerRank.CHAR);
    case "int16_t":
      return INT(2, true, IntegerRank.SHORT);
    case "uint16_t":
    case "word":
      return INT(2, false, IntegerRank.SHORT);
    case "int32_t":
      return INT(4, true, IntegerRank.INT);
    case "uint32_t":
    case "dword":
      return INT(4, false, IntegerRank.INT);
    case "int64_t":
      return INT(8, true, ptr === 8 ? IntegerRank.LONG : IntegerRank.LONG_LONG);
    case "uint64_t":
    case "qword":
      return INT(8, false, ptr === 8 ? IntegerRank.LONG : IntegerRank.LONG_LONG);
    case "size_t":
    case "uintptr_t":
      return INT(ptr, false, ptr === 8 ? IntegerRank.LONG : IntegerRank.INT);
    case "ssize_t":
    case "intptr_t":
    case "ptrdiff_t":
      return INT(ptr, true, ptr === 8 ? IntegerRank.LONG : IntegerRank.INT);
  }
  const m = /^undefined(\d*)$/.exec(w);
  if (m) {
    const n = Number(m[1] || 1);
    return { node: create(TypeNodeSchema, { kind: TypeKind.UNDEFINED, size: BigInt(n) }), size: n };
  }
  if (!(unsigned || signed) && rest !== "short" && rest !== "int" && rest !== "long" && rest !== "long long" && rest !== "short int" && rest !== "long int" && rest !== "long long int") return null;
  const s = !unsigned;
  switch (rest) {
    case "char":
      return INT(1, s, IntegerRank.CHAR);
    case "short":
    case "short int":
      return INT(2, s, IntegerRank.SHORT);
    case "":
    case "int":
      return INT(4, s, IntegerRank.INT);
    case "long":
    case "long int":
      return INT(ptr === 8 ? 8 : 4, s, IntegerRank.LONG);
    case "long long":
    case "long long int":
      return INT(8, s, IntegerRank.LONG_LONG);
  }
  return null;
}

/** Parses a spelling; throws an Error saying what is wrong. */
export async function spell(text: string, ctx: SpellContext): Promise<Spelled> {
  const src = text.trim();
  const m = /^((?:\s*(?:const|volatile)\s+)*)([A-Za-z_][\w:]*(?:\s+[A-Za-z_][\w:]*)*)((?:\s*(?:\*|const|volatile))*)((?:\s*\[\s*\d*\s*\])*)\s*$/.exec(src);
  if (!m) throw new Error(`"${src}" isn't a type spelling (a base type, then *, const or [n])`);
  const words = m[2].split(/\s+/).filter((x) => x !== "const" && x !== "volatile");
  let base: Base | null = builtin(words, ctx);
  let usesNamed = false;
  if (!base) {
    let kind: "struct" | "union" | "enum" | "" = "";
    let name = words.join(" ");
    if (words.length === 2 && (words[0] === "struct" || words[0] === "union" || words[0] === "enum" || words[0] === "class")) {
      kind = words[0] === "class" ? "struct" : words[0];
      name = words[1];
    } else if (words.length !== 1) throw new Error(`Unknown type "${words.join(" ")}"`);
    const def = await ctx.named(kind, name);
    if (!def) throw new Error(`No type named "${words.join(" ")}" in this program`);
    base = { def };
    usesNamed = true;
  }
  const nodes: TypeNode[] = [];
  let ref: Spelled["ref"];
  let size: number;
  if ("def" in base) {
    ref = { hash: base.def.hash };
    size = Number(base.def.size);
  } else {
    nodes.push(base.node);
    ref = { index: 0 };
    size = base.size;
  }
  const toRef = (r: Spelled["ref"]): TypeNodeRef => refTo(r);
  const qualify = (constQ: boolean, volQ: boolean) => {
    if (!constQ && !volQ) return;
    nodes.push(create(TypeNodeSchema, { kind: TypeKind.QUALIFIED, target: toRef(ref), qualifiers: { isConst: constQ, isVolatile: volQ } }));
    ref = { index: nodes.length - 1 };
  };
  qualify(/\bconst\b/.test(m[1]) || m[2].split(/\s+/).includes("const"), /\bvolatile\b/.test(m[1]));
  for (const tok of m[3].match(/\*|const|volatile/g) ?? []) {
    if (tok === "*") {
      nodes.push(create(TypeNodeSchema, { kind: TypeKind.POINTER, size: BigInt(ctx.pointerSize), target: toRef(ref) }));
      ref = { index: nodes.length - 1 };
      size = ctx.pointerSize;
    } else qualify(tok === "const", tok === "volatile");
  }
  // int x[2][3]: an array of 2 arrays of 3; built innermost first.
  const dims = [...m[4].matchAll(/\[\s*(\d*)\s*\]/g)].map((d) => Number(d[1] || 0)).reverse();
  for (const n of dims) {
    nodes.push(create(TypeNodeSchema, { kind: TypeKind.ARRAY, target: toRef(ref), count: BigInt(n) }));
    ref = { index: nodes.length - 1 };
    size *= n;
  }
  return { nodes, ref, size, usesNamed };
}

/** A TypeNodeRef to a hash or to the define_type at an assertion index. */
export function refTo(r: { hash: string } | { index: number }): TypeNodeRef {
  return create(TypeNodeRefSchema, "hash" in r ? { kind: { case: "hash", value: r.hash } } : { kind: { case: "assertionIndex", value: r.index } });
}

/** Rebases a spelling's node references by `offset` (its nodes start at that assertion index). */
export function rebase(nodes: TypeNode[], ref: Spelled["ref"], offset: number): { nodes: TypeNode[]; ref: TypeNodeRef } {
  const fix = (r: TypeNodeRef | undefined) => {
    if (r?.kind.case === "assertionIndex") r.kind.value += offset;
  };
  for (const n of nodes) {
    fix(n.target);
    for (const f of n.fields) fix(f.type);
    for (const p of n.params) fix(p.type);
  }
  return { nodes, ref: "hash" in ref ? refTo(ref) : refTo({ index: ref.index + offset }) };
}

export interface SpelledPrototype {
  nodes: TypeNode[];
  /** The function type: an index into `nodes`. */
  index: number;
  usesNamed: boolean;
}

/**
 * A prototype ("unsigned int f(struct pair *p, int n)") as a FUNCTION
 * node: the return and each parameter a spelling, optionally named;
 * "(void)", "()" and a trailing "..." as C has them. Throws when it isn't one.
 */
export async function spellPrototype(text: string, ctx: SpellContext): Promise<SpelledPrototype> {
  const m = /^(.*?)\b([A-Za-z_]\w*)\s*\(\s*(.*?)\s*\)\s*;?\s*$/.exec(text.trim());
  if (!m) throw new Error("not a prototype");
  const nodes: TypeNode[] = [];
  let usesNamed = false;
  const add = (s: Spelled): TypeNodeRef => {
    const rb = rebase(s.nodes, s.ref, nodes.length);
    nodes.push(...rb.nodes);
    usesNamed ||= s.usesNamed;
    return rb.ref;
  };
  const retText = m[1].replace(/\b__\w+\b/g, "").trim();
  if (!retText) throw new Error("no return type");
  const ret = add(await spell(retText, ctx));
  const fn = create(TypeNodeSchema, { kind: TypeKind.FUNCTION, target: ret });
  const params = m[3] === "" || m[3] === "void" ? [] : m[3].split(",").map((p) => p.trim());
  for (const [i, p] of params.entries()) {
    if (p === "...") {
      if (i !== params.length - 1) throw new Error("... must come last");
      fn.varargs = true;
      continue;
    }
    // "struct pair *p": the last word is a name when what precedes spells a type.
    const named = /^(.*?[\s*])([A-Za-z_]\w*)$/.exec(p);
    let spelled: Spelled | null = null;
    let name = "";
    if (named) {
      try {
        spelled = await spell(named[1], ctx);
        name = named[2];
      } catch {
        spelled = null;
      }
    }
    spelled ??= await spell(p, ctx);
    fn.params.push(create(TypeNodeParamSchema, { name, type: add(spelled) }));
  }
  nodes.push(fn);
  return { nodes, index: nodes.length - 1, usesNamed };
}
