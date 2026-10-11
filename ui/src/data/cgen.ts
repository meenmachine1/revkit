// The type editor's drafts as C, laid out by the daemon (TypeService.ParseC,
// feature "parse-c"): the editor never computes an offset, a size or an
// alignment itself. A draft becomes one C definition (fields it didn't
// change written by hash, `__revkit_type_<hash>`, so they keep their exact
// types; edited ones as typed, through __typeof__), plus a probe struct per
// field that measures its type's size and alignment. ParseC lays it out
// with the program's data model and returns DefineType-ready nodes; saving
// defines them and binds the name (one revision, one undo).
//
// Layouts:
//   natural   C's rules for the field order (the target's alignment,
//             bitfield model and padding), with #pragma pack(N),
//             __attribute__((packed)) and aligned(N) as chosen
//   explicit  fields at the offsets given (Ghidra's unpacked editing): the
//             gaps are undefined filler, written as unnamed bitfields in a
//             packed struct; the daemon still decides `packed` (the rule the
//             debug-info importers share) and checks each field lands where
//             it was put
//
// docs/ui.md ("Types") and docs/cparse.md ("In the UI").

import { headerImportPlan, typeByHash, type ParseCResponse, type Revkit, type TypeNode, ParseCSeverity, TypeKind, type AssertionBody } from "@revkit/api";

export type DraftKind = "struct" | "union" | "enum" | "typedef";

/** Struct packing: explicit offsets, C's natural layout, packed, or #pragma pack(N). */
export type Packing = "explicit" | "natural" | "packed" | 1 | 2 | 4 | 8 | 16;

export interface FieldDraft {
  name: string;
  /** The field's type as C spells it (for a flexible array, its element). */
  type: string;
  /** The exact type `type` spelled when loaded (kept while the text is unchanged). */
  hash: string;
  shown: string;
  offset: number;
  /** Bitfields: the first bit within the byte at `offset`, and the width (0: not a bitfield). */
  bitOffset: number;
  bitSize: number;
  /** A flexible array member (`type name[]`), last in a struct. */
  flex: boolean;
  /** The type's size and alignment, from the daemon (-1: not measured yet). */
  size: number;
  align: number;
  /** What the daemon said about this field (an error at its line). */
  problem?: string;
}

export interface EnumValueDraft {
  name: string;
  /** A C constant expression; empty: the previous value + 1. */
  value: string;
  /** Its value, from the daemon. */
  shown?: string;
  problem?: string;
}

export interface Draft {
  kind: DraftKind;
  name: string;
  /** Explicit layouts: the size (natural ones: the daemon's). */
  size: number;
  packing: Packing;
  /** Explicit alignment (aligned(N)); 0: the type's natural alignment. */
  align: number;
  fields: FieldDraft[];
  values: EnumValueDraft[];
  /** Enum size in bytes (0: C's rules) and signedness. */
  enumSize: number;
  enumSigned: boolean;
  target: string;
  targetHash: string;
  targetShown: string;
  /** The definition being edited (empty for a new type), and its name. */
  from: string;
  fromName: string;
}

/** A diagnostic on a line of the generated C, attributed. */
export interface LineNote {
  line: number;
  text: string;
  error: boolean;
}

export interface Layout {
  parsed: ParseCResponse;
  /** "struct pair", the key ParseC names the draft's type by. */
  key: string;
  /** The laid-out type (null when it didn't parse). */
  node: TypeNode | null;
  hash: string;
  /** The program's definition of the name already is this one. */
  identical: boolean;
  size: number;
  /** The type's alignment (structs and unions). */
  align: number;
  packed: boolean;
  /** Errors that belong to no field. */
  errors: string[];
  ok: boolean;
  profile: string;
  text: string;
}

const PROBE = "__rk_probe_";
const KW: Record<DraftKind, string> = { struct: "struct", union: "union", enum: "enum", typedef: "" };

/** The key ParseC and FindTypes name a draft's type by ("struct pair", "typedef pair_t"). */
export function keyOf(kind: DraftKind, name: string): string {
  return `${kind === "typedef" ? "typedef" : KW[kind]} ${name}`;
}

/**
 * Where a name goes in a C type spelling: `int` -> `int x`, `char[16]` ->
 * `char x[16]`, `void (*)(int)` -> `void (*x)(int)`. For readable C only
 * (the "C" tab of a draft); layouts go through __typeof__.
 */
export function declare(type: string, name: string): string {
  const t = type.trim();
  // The innermost pointer declarator of a function or array pointer: "(*)".
  const m = /\((?:\s*[*&^]|\s*const\b|\s*volatile\b|\s*restrict\b|\s*__\w+\b)+\s*\)/.exec(t);
  if (m) {
    const close = m.index + m[0].length - 1;
    return `${t.slice(0, close).trimEnd()}${name}${t.slice(close)}`;
  }
  const b = t.indexOf("[");
  if (b > 0) return `${t.slice(0, b).trimEnd()} ${name}${t.slice(b)}`;
  return /[*&]$/.test(t) ? `${t}${name}` : `${t} ${name}`;
}

/** The draft's name in place of the definition's old one, for self-references ("struct node *next"). */
function retarget(d: Draft, text: string): string {
  if (!d.fromName || d.fromName === d.name || d.kind === "typedef" || d.kind === "enum") return text;
  return text.replace(new RegExp(`\\b${KW[d.kind]}\\s+${d.fromName}\\b`, "g"), `${KW[d.kind]} ${d.name}`);
}

/** Does the spelling name the type being edited (a self-reference that must follow the edit)? */
function selfRef(d: Draft, text: string): boolean {
  if (d.kind !== "struct" && d.kind !== "union") return false;
  const names = [d.name, d.fromName].filter(Boolean);
  return names.some((n) => new RegExp(`\\b${KW[d.kind]}\\s+${n}\\b`).test(text));
}

/** A field's (or target's) type for the parser: by hash when unchanged, else as typed. */
function typeExpr(d: Draft, type: string, hash: string, shown: string): string {
  if (hash && type.trim() === shown.trim() && !selfRef(d, shown)) return typeByHash(hash);
  return `__typeof__(${retarget(d, type.trim())})`;
}

function fieldDecl(d: Draft, f: FieldDraft): string {
  const t = typeExpr(d, f.type, f.hash, f.shown);
  const anonymous = !f.name && t.startsWith("__revkit_type_");
  const name = anonymous ? "" : ` ${f.name || "field"}`;
  return `${t}${name}${f.flex ? "[]" : ""}${f.bitSize ? ` : ${f.bitSize}` : ""};`;
}

/** Unnamed bitfields skipping `bits` (compilers record none; a packed struct takes them bit for bit). */
function gap(bits: number, unit = "unsigned char"): string {
  const out: string[] = [];
  let n = bits;
  while (n >= 8) {
    out.push(`${unit} : 8;`);
    n -= 8;
  }
  if (n) out.push(`${unit} : ${n};`);
  return out.join(" ");
}

/** The fields in offset order (explicit layouts keep them so). */
export function byOffset(fields: FieldDraft[]): FieldDraft[] {
  return [...fields].sort((a, b) => a.offset - b.offset || a.bitOffset - b.bitOffset);
}

/** The bytes a field covers in an explicit layout (null: not measured). */
export function extent(f: FieldDraft): { start: number; end: number } | null {
  const start = f.offset * 8 + f.bitOffset;
  if (f.bitSize) return { start, end: start + f.bitSize };
  if (f.flex) return { start, end: start };
  if (f.size < 0) return null;
  return { start, end: start + f.size * 8 };
}

interface Generated {
  text: string;
  /** Line (1-based) -> what it declares. */
  lines: Map<number, { field?: number; value?: number; probe?: number; main?: boolean }>;
  /** Problems found before parsing (explicit overlaps). */
  problems: Map<number, string>;
  errors: string[];
}

/** The draft as C for ParseC: the definition, then a probe per field. */
export function generate(d: Draft, probesOnly = false): Generated {
  const out: string[] = [];
  const lines: Generated["lines"] = new Map();
  const problems = new Map<number, string>();
  const errors: string[] = [];
  const push = (s: string, what?: { field?: number; value?: number; probe?: number; main?: boolean }) => {
    out.push(s);
    if (what) lines.set(out.length, what);
  };
  const name = d.name;
  if (!probesOnly) {
    if (d.kind === "struct" || d.kind === "union") {
      const explicit = d.kind === "struct" && d.packing === "explicit";
      const attrs: string[] = [];
      if (explicit || d.packing === "packed") attrs.push("packed");
      if (d.align) attrs.push(`aligned(${d.align})`);
      if (typeof d.packing === "number") push(`#pragma pack(push, ${d.packing})`);
      push(`${KW[d.kind]} ${name} {`, { main: true });
      if (explicit) {
        let pos = 0;
        for (const f of byOffset(d.fields)) {
          const i = d.fields.indexOf(f);
          const at = f.offset * 8 + f.bitOffset;
          if (at < pos) {
            problems.set(i, `overlaps the field before it (it ends at 0x${Math.floor(pos / 8).toString(16)}${pos % 8 ? `:${pos % 8}` : ""})`);
            continue;
          }
          if (at > pos) push(gap(at - pos));
          push(fieldDecl(d, f), { field: i });
          const e = extent(f);
          if (!e) {
            errors.push(`the size of ${f.name || "a field"} isn't known yet`);
            pos = at;
          } else pos = e.end;
        }
        const end = d.size * 8;
        if (end > pos) push(gap(end - pos));
        else if (end < pos && d.fields.length) errors.push(`the fields end at 0x${Math.ceil(pos / 8).toString(16)}, past the size 0x${d.size.toString(16)}`);
      } else {
        d.fields.forEach((f, i) => push(fieldDecl(d, f), { field: i }));
      }
      push(`}${attrs.length ? ` __attribute__((${attrs.join(", ")}))` : ""};`, { main: true });
      if (typeof d.packing === "number") push("#pragma pack(pop)");
    } else if (d.kind === "enum") {
      const under = d.enumSize ? `${d.enumSigned ? "" : "u"}int${d.enumSize * 8}_t` : "";
      if (under) push("#include <stdint.h>");
      push(`enum ${name}${under ? ` : ${under}` : ""} {`, { main: true });
      d.values.forEach((v, i) => push(`${v.name || `VALUE_${i}`}${v.value.trim() ? ` = ${v.value.trim()}` : ""},`, { value: i }));
      push("};", { main: true });
    } else {
      push(`typedef ${typeExpr(d, d.target, d.targetHash, d.targetShown)} ${name};`, { main: true });
    }
  }
  // Probes: each field's type measured where C puts it after a char.
  if (d.kind === "struct" || d.kind === "union")
    d.fields.forEach((f, i) => {
      if (f.type.trim()) push(`struct ${PROBE}${i} { char c; ${typeExpr(d, f.type, f.hash, f.shown)} x; };`, { probe: i });
    });
  if (!probesOnly && (d.kind === "struct" || d.kind === "union")) push(`struct ${PROBE}self { char c; ${KW[d.kind]} ${name} x; };`);
  return { text: out.join("\n") + "\n", lines, problems, errors };
}

/** The draft as readable C (the editor's "C" tab), from its fields as typed. */
export function readable(d: Draft): string {
  if (d.kind === "enum") {
    const under = d.enumSize ? `${d.enumSigned ? "" : "u"}int${d.enumSize * 8}_t` : "";
    const head = `${under ? "#include <stdint.h>\n" : ""}enum ${d.name}${under ? ` : ${under}` : ""} {\n`;
    return head + d.values.map((v, i) => `    ${v.name || `VALUE_${i}`}${v.value.trim() ? ` = ${v.value.trim()}` : ""}`).join(",\n") + "\n};\n";
  }
  if (d.kind === "typedef") return `typedef ${declare(d.target, d.name)};\n`;
  const fields = d.kind === "struct" && d.packing === "explicit" ? byOffset(d.fields) : d.fields;
  const attrs: string[] = [];
  if (d.packing === "packed") attrs.push("packed");
  if (d.align) attrs.push(`aligned(${d.align})`);
  const body = fields.map((f) => `    ${declare(f.type, f.name)}${f.flex ? "[]" : ""}${f.bitSize ? ` : ${f.bitSize}` : ""};`).join("\n");
  const def = `${KW[d.kind]} ${d.name} {\n${body}\n}${attrs.length ? ` __attribute__((${attrs.join(", ")}))` : ""};\n`;
  return typeof d.packing === "number" ? `#pragma pack(push, ${d.packing})\n${def}#pragma pack(pop)\n` : def;
}

function sevError(s: ParseCSeverity) {
  return s === ParseCSeverity.ERROR;
}

/** ParseC of some C for the program (pasted text: viewer is enough). */
export function parseText(rk: Revkit, programId: string, text: string, name = "edit.h", options: { prototypes?: boolean; definesAsEnum?: boolean } = {}): Promise<ParseCResponse> {
  return rk.types.parseC({ programId, sources: [{ kind: { case: "text", value: text }, name }], options: { prototypes: !!options.prototypes, definesAsEnum: !!options.definesAsEnum } });
}

/** Measures the fields whose size isn't known (explicit layouts need it to place the gaps). */
export async function measure(rk: Revkit, programId: string, d: Draft): Promise<void> {
  if (!d.fields.some((f) => f.size < 0 && f.type.trim())) return;
  const g = generate(d, true);
  const parsed = await parseText(rk, programId, g.text);
  applyProbes(d, parsed);
}

function applyProbes(d: Draft, parsed: ParseCResponse) {
  for (const n of parsed.named) {
    if (!n.key.startsWith(`struct ${PROBE}`)) continue;
    const id = n.key.slice(`struct ${PROBE}`.length);
    const node = parsed.nodes[n.index];
    if (id === "self" || !node || node.fields.length < 2) continue;
    const f = d.fields[Number(id)];
    if (!f) continue;
    f.align = Number(node.fields[1].offset);
    f.size = Number(node.size) - f.align;
  }
}

/**
 * Lays a draft out on the daemon: offsets (natural layouts), sizes,
 * alignment, the C diagnostics at each field's line, and whether it is
 * already the program's definition.
 */
export async function layout(rk: Revkit, programId: string, d: Draft): Promise<Layout> {
  if (d.kind === "struct" && d.packing === "explicit") await measure(rk, programId, d);
  const g = generate(d);
  const parsed = await parseText(rk, programId, g.text);
  const key = keyOf(d.kind, d.name);
  for (const f of d.fields) f.problem = undefined;
  for (const v of d.values) v.problem = undefined;
  for (const [i, p] of g.problems) d.fields[i].problem = p;
  const errors = [...g.errors];
  for (const diag of parsed.diagnostics) {
    if (!sevError(diag.severity) && diag.severity !== ParseCSeverity.WARNING) continue;
    const what = g.lines.get(diag.line);
    const text = diag.text;
    if (what?.field !== undefined) {
      if (sevError(diag.severity)) d.fields[what.field].problem ??= text;
    } else if (what?.probe !== undefined) {
      if (sevError(diag.severity)) d.fields[what.probe].problem ??= text;
    } else if (what?.value !== undefined) {
      if (sevError(diag.severity)) d.values[what.value].problem ??= text;
    } else if (sevError(diag.severity)) errors.push(diag.line ? `line ${diag.line}: ${text}` : text);
  }
  applyProbes(d, parsed);
  const named = parsed.named.find((n) => n.key === key);
  const node = named ? parsed.nodes[named.index] ?? null : null;
  const self = parsed.named.find((n) => n.key === `struct ${PROBE}self`);
  const selfNode = self ? parsed.nodes[self.index] : undefined;
  const out: Layout = {
    parsed,
    key,
    node,
    hash: named?.hash ?? "",
    identical: !!named && named.existingHash === named.hash,
    size: Number(node?.size ?? 0n),
    align: selfNode && selfNode.fields.length > 1 ? Number(selfNode.fields[1].offset) : 0,
    packed: !!node?.packed,
    errors,
    ok: false,
    profile: parsed.profile,
    text: g.text,
  };
  if (node && (d.kind === "struct" || d.kind === "union")) {
    // The fields as laid out, in the draft's order (unnamed bitfields, the gaps, aren't fields).
    const order = d.kind === "struct" && d.packing === "explicit" ? byOffset(d.fields).filter((f) => !g.problems.has(d.fields.indexOf(f))) : d.fields;
    if (node.fields.length === order.length) {
      order.forEach((f, i) => {
        const nf = node.fields[i];
        const off = Number(nf.offset), bit = nf.bitOffset;
        if (d.kind === "struct" && d.packing === "explicit") {
          if (off !== f.offset || bit !== f.bitOffset) f.problem ??= `the target's layout rules put it at 0x${off.toString(16)}${nf.bitSize ? `:${bit}` : ""}`;
        } else {
          f.offset = off;
          f.bitOffset = bit;
        }
      });
    } else if (!errors.length && !d.fields.some((f) => f.problem)) errors.push(`the C declares ${node.fields.length} fields, the editor has ${order.length}`);
    if (!(d.kind === "struct" && d.packing === "explicit")) d.size = out.size;
    else {
      // The probe saw the packed struct the C writes; the daemon then
      // decided whether it is packed (the debug-info importers' rule).
      out.align = d.align || (out.packed ? 1 : d.fields.reduce((m, f) => Math.max(m, f.align), 1));
    }
  }
  if (node && d.kind === "enum") {
    node.enumerators.forEach((e, i) => {
      if (d.values[i]) d.values[i].shown = String(e.value);
    });
    d.size = out.size;
  }
  out.ok = !!node && !errors.length && !d.fields.some((f) => f.problem) && !d.values.some((v) => v.problem) && parsed.errors === 0;
  if (!node && !errors.length) errors.push(`no ${key} in the C`);
  return out;
}

/** The assertions that save a laid-out draft: its nodes, then the binding of its name. */
export function saveBodies(l: Layout): AssertionBody[] {
  return headerImportPlan(l.parsed, { keys: [l.key], includeIdentical: true }).bodies;
}

/** Member declarations ("int a; void (*cb)(int);") as fields, by the daemon; null when they aren't. */
export async function parseMembers(rk: Revkit, programId: string, text: string, union = false): Promise<{ fields: FieldDraft[]; errors: string[] } | null> {
  const body = text.trim().replace(/;?\s*$/, ";");
  const parsed = await parseText(rk, programId, `${union ? "union" : "struct"} ${PROBE}paste {\n${body}\n};\n`, "paste.h");
  const errors = parsed.diagnostics.filter((x) => sevError(x.severity)).map((x) => `line ${Math.max(1, x.line - 1)}: ${x.text}`);
  const named = parsed.named.find((n) => n.key === `${union ? "union" : "struct"} ${PROBE}paste`);
  const node = named ? parsed.nodes[named.index] : undefined;
  if (!node || !node.fields.length) return errors.length ? { fields: [], errors } : null;
  const fields: FieldDraft[] = node.fields.map((nf) => {
    const ref = nf.type?.kind;
    const display = ref?.case === "assertionIndex" ? parsed.displays[ref.value] ?? "" : "";
    let type = display;
    let hash = ref?.case === "hash" ? ref.value : "";
    let flex = false;
    const tn = ref?.case === "assertionIndex" ? parsed.nodes[ref.value] : undefined;
    if (tn && tn.kind === TypeKind.ARRAY && tn.count === 0n && tn.target) {
      flex = true;
      const t = tn.target.kind;
      type = t.case === "assertionIndex" ? parsed.displays[t.value] ?? "" : "";
      hash = t.case === "hash" ? t.value : "";
    }
    return { name: nf.name, type, hash, shown: type, offset: Number(nf.offset), bitOffset: nf.bitOffset, bitSize: nf.bitSize, flex, size: -1, align: -1 };
  });
  return { fields, errors };
}
