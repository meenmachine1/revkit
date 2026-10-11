// Optional listing fields (Ghidra's field formatter, a few of its fields),
// toggled from the listing's Fields menu: the file offset of each code unit,
// its function offset (`main+0x1c`), the instruction's p-code (on its own
// line, after the operands: listing rows are one line each in the daemon's
// numbering) and, on label rows, the first few references to the label
// with their kinds (`XREF[3]: 401020(c), 401088(j)`). The values that need
// the daemon (p-code, references, function names) are fetched for the rows
// in view by the app and kept here, by address; layoutRow() reads them.

export interface FieldFlags {
  fileOffset: boolean;
  fnOffset: boolean;
  pcode: boolean;
  xrefList: boolean;
}

export const NO_FIELDS: FieldFlags = { fileOffset: false, fnOffset: false, pcode: false, xrefList: false };

export const FIELD_MENU: { id: keyof FieldFlags; label: string }[] = [
  { id: "fileOffset", label: "File offset" },
  { id: "fnOffset", label: "Function offset" },
  { id: "pcode", label: "P-code" },
  { id: "xrefList", label: "References on labels (XREF list)" },
];

/** Where the values come from (set by the app). */
interface Sources {
  /** A code address's offset in the imported file, or null. */
  fileOffset: (a: bigint) => bigint | null;
  /** A function's name by its entry (undefined: not known yet; asked for). */
  fnName: (entry: bigint) => string | undefined;
}

let sources: Sources = { fileOffset: () => null, fnName: () => undefined };
/** P-code text by instruction address; references to an address. */
const pcode = new Map<bigint, string>();
export interface XrefBrief {
  count: number;
  from: { address: bigint; kind: string }[];
}
const xrefs = new Map<bigint, XrefBrief>();
let version = 0;

export function setFieldSources(s: Sources) {
  sources = s;
  version++;
}

/** Bumped whenever a field value arrives or is dropped: rows are laid out again. */
export function fieldsVersion(): number {
  return version;
}

export function bumpFields() {
  version++;
}

export function fileOffsetText(a: bigint, width: number): string {
  const o = sources.fileOffset(a);
  return o === null ? "" : o.toString(16).padStart(width, "0");
}

export function fnOffsetText(func: bigint | null, a: bigint): string {
  if (func === null) return "";
  const name = sources.fnName(func);
  if (name === undefined) return "";
  return a === func ? name : `${name}+0x${(a - func).toString(16)}`;
}

export function pcodeAt(a: bigint): string | undefined {
  return pcode.get(a);
}
export function hasPcode(a: bigint): boolean {
  return pcode.has(a);
}
export function setPcode(entries: Iterable<[bigint, string]>) {
  for (const [a, t] of entries) pcode.set(a, t);
  version++;
}

export function xrefsAt(a: bigint): XrefBrief | undefined {
  return xrefs.get(a);
}
export function setXrefs(a: bigint, x: XrefBrief) {
  xrefs.set(a, x);
  version++;
}

/** Forgets fetched values (an edit changed the listing or the references). */
export function dropFieldValues(which: { pcode?: boolean; xrefs?: boolean }) {
  if (which.pcode && pcode.size) pcode.clear();
  if (which.xrefs && xrefs.size) xrefs.clear();
  version++;
}

/** XrefKind (revkit.v1) as Ghidra's one-letter reference type. */
export const XREF_LETTER: Record<number, string> = { 1: "c", 2: "j", 3: "j", 4: "c", 5: "j", 6: "r", 7: "w", 8: "*", 9: "t" };

/** A varnode as p-code shows it: a register by name, a constant, a memory or unique location. */
export function varnodeText(v: { space: string; offset: bigint; size: number; registerName: string } | undefined): string {
  if (!v) return "";
  if (v.registerName) return v.registerName;
  switch (v.space) {
    case "const":
      return `0x${v.offset.toString(16)}`;
    case "unique":
      return `$U${v.offset.toString(16)}:${v.size}`;
    case "register":
      return `reg[0x${v.offset.toString(16)}]:${v.size}`;
    default:
      return `[${v.space}:0x${v.offset.toString(16)}]:${v.size}`;
  }
}

/** One instruction's p-code, ops separated by " ; ". */
export function pcodeText(ops: { mnemonic: string; output?: Parameters<typeof varnodeText>[0]; inputs: Parameters<typeof varnodeText>[0][] }[]): string {
  return ops.map((o) => `${o.output ? `${varnodeText(o.output)} = ` : ""}${o.mnemonic} ${o.inputs.map(varnodeText).join(", ")}`.trim()).join(" ; ");
}
