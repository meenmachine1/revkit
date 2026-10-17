// Column layout and per-row text runs. Runs are computed once per row object
// (when it is first drawn) and cached on the row, so a frame only iterates
// precomputed (color, column, text) triples.
//
// One listing row is one line. With header rows (the daemon's
// listing-header-rows numbering), plate comments, function signatures,
// labels and pre-comments are rows of their own above the code unit, as in
// Ghidra; without them (older daemons, ?headers=0), labels sit in a column
// of the row they name and function entries get a header band.

import { HeaderKind, RowKind, TokenKind, type ListingRow } from "../data/types";
import { NO_FIELDS, fieldsVersion, fileOffsetText, fnOffsetText, pcodeAt, xrefsAt, type FieldFlags } from "./fields";
import { fmtAddr } from "../data/format";
import type { Theme } from "./theme";

export const enum C {
  Addr,
  Bytes,
  Mnemonic,
  FlowMnemonic,
  Register,
  Immediate,
  Address,
  Symbol,
  Punct,
  Comment,
  Xref,
  Header,
  Label,
  UserName,
  AgentName,
  Type,
  Override,
  /** Optional fields: file and function offsets, p-code. */
  Field,
  Count,
}

export function palette(t: Theme): string[] {
  const p: string[] = [];
  p[C.Addr] = t.addr;
  p[C.Bytes] = t.bytes;
  p[C.Mnemonic] = t.mnemonic;
  p[C.FlowMnemonic] = t.flowMnemonic;
  p[C.Register] = t.register;
  p[C.Immediate] = t.immediate;
  p[C.Address] = t.address;
  p[C.Symbol] = t.symbol;
  p[C.Punct] = t.punct;
  p[C.Comment] = t.comment;
  p[C.Xref] = t.xref;
  p[C.Header] = t.header;
  p[C.Label] = t.label;
  p[C.UserName] = t.userName;
  p[C.AgentName] = t.agentName;
  p[C.Type] = t.type;
  p[C.Override] = t.override;
  p[C.Field] = t.bytes;
  return p;
}

/** Column starts, in characters. */
export interface Columns {
  addr: number;
  /** Optional fields (the Fields menu): where the file and function offsets go. */
  fileOff: number;
  fnOff: number;
  fields: FieldFlags;
  bytes: number;
  xref: number;
  label: number;
  labelWidth: number;
  mnem: number;
  ops: number;
  comment: number;
  end: number;
  showBytes: boolean;
  /** Labels, signatures and plate/pre-comments are rows of their own. */
  headerRows: boolean;
  /** Bumped whenever columns change, to drop cached layouts. */
  version: number;
}

let version = 0;

/** Characters of the function offset field ("checksum+0x1c"). */
export const FN_OFF_WIDTH = 22;

export function makeColumns(addrWidth: number, showBytes: boolean, headerRows = false, fields: FieldFlags = NO_FIELDS): Columns {
  const addr = 0;
  let next = addr + addrWidth + 2;
  const fileOff = next;
  if (fields.fileOffset) next += 10;
  const fnOff = next;
  if (fields.fnOffset) next += FN_OFF_WIDTH + 2;
  const bytes = next;
  const xref = showBytes ? bytes + 16 : bytes;
  const label = xref + 5;
  // Header rows carry the labels: no label column, instructions indent.
  const labelWidth = headerRows ? 0 : 22;
  const mnem = headerRows ? label + 4 : label + labelWidth + 1;
  const ops = mnem + 8;
  const comment = ops + 30;
  return { addr, fileOff, fnOff, fields: { ...fields }, bytes, xref, label, labelWidth, mnem, ops, comment, end: comment + 60, showBytes, headerRows, version: ++version };
}

export interface Run {
  color: C;
  col: number;
  text: string;
}

/** What a hit on a row means. */
export type HotKind = "token" | "label" | "xref" | "comment" | "mnemonic" | "signature" | "type" | "override" | "fallthrough" | "callsig" | "plugin" | "disclosure" | "mutability" | "field" | "pcode" | "regvalue";

/** FlowOverrideKind names, as shown on a row. */
export const OVERRIDE_TEXT: Record<number, string> = { 1: "none", 2: "branch", 3: "call", 4: "call-return", 5: "return" };

/** revkit.v1 Mutability names, as a row's badge (DEFAULT shows none). */
export const MUTABILITY_TEXT: Record<number, string> = { 2: "writable", 3: "const", 4: "volatile" };

/** The disclosure marker of a data item with fields or elements: before its type. */
export const DISCLOSURE = { collapsed: "+", expanded: "−" };

/** A field row's name: the last step of its path ("hdr.magic" → "magic"). */
export function fieldName(path: string): string {
  const dot = path.lastIndexOf(".");
  return dot >= 0 ? path.slice(dot + 1) : path;
}

/** A hoverable span on a row: highlight key plus character extent. */
export interface HotSpan {
  kind: HotKind;
  key: string;
  col: number;
  len: number;
  target?: bigint;
  /** For a "token": its index in the row's operands. */
  op?: number;
}

interface RowLayout {
  runs: Run[];
  hot: HotSpan[];
}

let layouts = new WeakMap<ListingRow, RowLayout>();
let layoutVersion = -1;
let layoutFields = -1;

/** Plugin annotations by address (analyzer plugins' facts), drawn after a row's comments. */
let annotations: ReadonlyMap<bigint, string> = new Map();
let annotationVersion = 0;
let layoutAnnotations = 0;

/** Replaces the annotations (rows are laid out again as they are drawn). */
export function setAnnotations(m: ReadonlyMap<bigint, string>) {
  annotations = m;
  annotationVersion++;
}

export function annotationAt(a: bigint): string | undefined {
  return annotations.get(a);
}

export function tokenColor(k: TokenKind): C {
  switch (k) {
    case TokenKind.Register:
      return C.Register;
    case TokenKind.Immediate:
    case TokenKind.Value:
      return C.Immediate;
    case TokenKind.Address:
      return C.Address;
    case TokenKind.Symbol:
      return C.Symbol;
    case TokenKind.Type:
      return C.Mnemonic;
    default:
      return C.Punct;
  }
}

function fit(s: string, w: number): string {
  return s.length <= w ? s : s.slice(0, Math.max(1, w - 1)) + "…";
}

function originColor(o: ListingRow["labelOrigin"], fallback: C): C {
  const src = o?.source;
  if (src?.case === "asserted") {
    const k = src.value.provenance?.kind;
    if (k === 1) return C.UserName; // ProvenanceKind.USER
    if (k === 3 || k === 6 || k === 7) return C.AgentName; // ProvenanceKind.AGENT, PLUGIN, SCRIPT
  }
  return fallback;
}

export function labelColor(r: ListingRow): C {
  return originColor(r.labelOrigin, r.functionEntry ? C.Header : C.Label);
}

/** The code unit row shows an xref count only when no label row above does. */
export function showsXrefs(r: ListingRow, cols: Columns): boolean {
  return r.xrefCount > 0 && (r.kind === RowKind.Header ? r.header?.kind === HeaderKind.Label : !(cols.headerRows && r.label));
}

function headerLayout(r: ListingRow, cols: Columns, runs: Run[], hot: HotSpan[]) {
  const h = r.header!;
  switch (h.kind) {
    case HeaderKind.Plate:
    case HeaderKind.Pre: {
      const text = h.kind === HeaderKind.Plate ? `/* ${h.text} */` : `// ${h.text}`;
      runs.push({ color: C.Comment, col: cols.label, text });
      hot.push({ kind: "comment", key: h.kind === HeaderKind.Plate ? "\0plate" : "\0pre", col: cols.label, len: text.length });
      break;
    }
    case HeaderKind.Signature:
      runs.push({ color: originColor(h.origin, C.Header), col: cols.label, text: h.text });
      hot.push({ kind: "signature", key: "\0sig", col: cols.label, len: h.text.length, target: r.address });
      break;
    case HeaderKind.Label: {
      const text = r.label + ":";
      runs.push({ color: labelColor(r), col: cols.label, text });
      hot.push({ kind: "label", key: r.label, col: cols.label, len: text.length - 1, target: r.address });
      if (cols.fields.xrefList && r.xrefCount > 0) xrefListRuns(r, cols.label + text.length + 2, runs, hot);
      break;
    }
  }
}

/** The XREF field after a label: how many references, and the first few with their kinds. */
function xrefListRuns(r: ListingRow, col: number, runs: Run[], hot: HotSpan[]) {
  const x = xrefsAt(r.address);
  const head = `XREF[${r.xrefCount}]: `;
  runs.push({ color: C.Xref, col, text: head });
  hot.push({ kind: "xref", key: "\0xref", col, len: head.length - 2 });
  col += head.length;
  if (!x) return;
  x.from.forEach((f, i) => {
    const t = f.address.toString(16);
    runs.push({ color: C.Address, col, text: t });
    hot.push({ kind: "token", key: t, col, len: t.length, target: f.address });
    col += t.length;
    const tail = `(${f.kind})${i + 1 < x.from.length ? ", " : ""}`;
    runs.push({ color: C.Punct, col, text: tail });
    col += tail.length;
  });
  if (x.count > x.from.length) runs.push({ color: C.Punct, col, text: ", …" });
}

export function layoutRow(r: ListingRow, cols: Columns): RowLayout {
  if (layoutVersion !== cols.version || layoutAnnotations !== annotationVersion || layoutFields !== fieldsVersion()) {
    layouts = new WeakMap();
    layoutVersion = cols.version;
    layoutAnnotations = annotationVersion;
    layoutFields = fieldsVersion();
  }
  let l = layouts.get(r);
  if (l) return l;
  const runs: Run[] = [];
  const hot: HotSpan[] = [];
  if (r.kind !== RowKind.Header) {
    runs.push({ color: C.Addr, col: cols.addr, text: r.addrText });
    if (cols.fields.fileOffset) {
      const t = fileOffsetText(r.address, 8);
      if (t) runs.push({ color: C.Field, col: cols.fileOff, text: t });
    }
    if (cols.fields.fnOffset) {
      const t = fnOffsetText(r.func, r.address);
      if (t) runs.push({ color: C.Field, col: cols.fnOff, text: fit(t, FN_OFF_WIDTH) });
    }
    if (cols.showBytes) runs.push({ color: C.Bytes, col: cols.bytes, text: r.bytesText });
  }
  if (showsXrefs(r, cols)) {
    const t = r.xrefCount > 999 ? "999+" : String(r.xrefCount);
    runs.push({ color: C.Xref, col: cols.xref + 1, text: t });
    hot.push({ kind: "xref", key: "\0xref", col: cols.xref, len: t.length + 1 });
  }
  if (r.kind === RowKind.Header) {
    if (r.header) headerLayout(r, cols, runs, hot);
    l = { runs, hot };
    layouts.set(r, l);
    return l;
  }
  if (r.label && cols.labelWidth > 0) {
    // Room for a data item's disclosure marker before the type column.
    const marker = r.kind === RowKind.Data && r.dataComponents > 0 && !r.dataField ? 2 : 0;
    const text = fit(r.label + (r.functionEntry ? "" : ":"), cols.labelWidth - marker);
    runs.push({ color: labelColor(r), col: cols.label, text });
    hot.push({ kind: "label", key: r.label, col: cols.label, len: text.length, target: r.address });
  }
  if (r.kind === RowKind.Data) {
    dataLayout(r, cols, runs, hot);
    l = { runs, hot };
    layouts.set(r, l);
    return l;
  }
  if (r.dataType && r.kind !== RowKind.Instruction) {
    // A global's asserted type stands in for "undefined[n]".
    runs.push({ color: C.Type, col: cols.mnem, text: r.dataType });
    hot.push({ kind: "type", key: "\0type", col: cols.mnem, len: r.dataType.length, target: r.address });
    l = { runs, hot };
    commentRuns(r, cols, Math.max(cols.ops, cols.mnem + r.dataType.length + 1), runs, hot);
    layouts.set(r, l);
    return l;
  }
  const mnemColor = r.kind === RowKind.Undefined ? C.Bytes : r.isFlow ? C.FlowMnemonic : C.Mnemonic;
  runs.push({ color: mnemColor, col: cols.mnem, text: r.mnemonic });
  if (r.kind === RowKind.Instruction) hot.push({ kind: "mnemonic", key: r.mnemonic, col: cols.mnem, len: r.mnemonic.length });
  // Long mnemonics push the operands right instead of overlapping them.
  const ops = Math.max(cols.ops, cols.mnem + r.mnemonic.length + 1);
  for (const [i, o] of r.operands.entries()) {
    runs.push({ color: tokenColor(o.kind), col: ops + o.col, text: o.text });
    if (o.kind !== TokenKind.Punct && o.text.trim()) hot.push({ kind: "token", key: o.text, col: ops + o.col, len: o.text.length, target: o.target, op: i });
  }
  let end = ops;
  for (const o of r.operands) end = Math.max(end, ops + o.col + o.text.length);
  if (cols.fields.pcode && r.kind === RowKind.Instruction) {
    const p = pcodeAt(r.address);
    if (p) {
      const text = `⟨ ${p} ⟩`;
      const col = Math.max(cols.comment, end + 2);
      runs.push({ color: C.Field, col, text });
      hot.push({ kind: "pcode", key: "\0pcode", col, len: text.length, target: r.address });
      end = col + text.length;
    }
  }
  commentRuns(r, cols, end, runs, hot);
  l = { runs, hot };
  layouts.set(r, l);
  return l;
}

/**
 * A data row: its type and value, as Ghidra shows data. A data item with
 * fields or elements has a disclosure marker (+ collapsed, − expanded)
 * before its type; its field and element rows (shown when it is expanded)
 * are indented by depth and lead with the field's name.
 */
function dataLayout(r: ListingRow, cols: Columns, runs: Run[], hot: HotSpan[]) {
  const indent = 2 * r.dataDepth;
  let col = cols.mnem + indent;
  if (r.dataComponents > 0 && !r.dataField) {
    const text = r.dataCollapsed ? DISCLOSURE.collapsed : DISCLOSURE.expanded;
    runs.push({ color: C.Punct, col: cols.mnem - 2, text });
    hot.push({ kind: "disclosure", key: "\0disclosure", col: cols.mnem - 2, len: 1, target: r.address });
  }
  if (r.dataField) {
    const name = fieldName(r.dataField);
    runs.push({ color: C.Label, col, text: name });
    hot.push({ kind: "field", key: "\0field", col, len: name.length, target: r.dataParent ?? r.address });
    col += Math.max(10, name.length + 1);
  }
  // A global's asserted type (a retype) stands in for the data's own.
  const type = r.dataType || r.mnemonic || "data";
  runs.push({ color: C.Type, col, text: type });
  hot.push({ kind: "type", key: "\0type", col, len: type.length, target: r.address });
  const ops = Math.max(cols.ops + indent, col + type.length + 1);
  let end = ops;
  for (const o of r.operands) {
    runs.push({ color: tokenColor(o.kind), col: ops + o.col, text: o.text });
    if ((o.kind === TokenKind.Address || o.kind === TokenKind.Symbol) && o.text.trim()) hot.push({ kind: "token", key: o.text, col: ops + o.col, len: o.text.length, target: o.target });
    end = Math.max(end, ops + o.col + o.text.length);
  }
  commentRuns(r, cols, end, runs, hot);
}

/** The mutability badge, the flow override marker and the comments, after column `end`. */
function commentRuns(r: ListingRow, cols: Columns, end: number, runs: Run[], hot: HotSpan[]) {
  let col = Math.max(cols.comment, end + 2);
  const m = MUTABILITY_TEXT[r.mutability];
  if (m) {
    const text = `[${m}]`;
    runs.push({ color: C.Override, col, text });
    hot.push({ kind: "mutability", key: "\0mutability", col, len: text.length, target: r.address });
    col += text.length + 2;
  }
  if (r.flowOverride) {
    const text = `⤷ flow: ${OVERRIDE_TEXT[r.flowOverride] ?? r.flowOverride}`;
    runs.push({ color: C.Override, col, text });
    hot.push({ kind: "override", key: "\0override", col, len: text.length, target: r.address });
    col += text.length + 2;
  }
  if (r.fallthroughOverride) {
    // The user's fallthrough (feature fallthrough-override); a click follows it.
    const text = r.fallthrough !== null ? `⤷ fallthrough: ${fmtAddr(r.fallthrough)}` : "⤷ no fallthrough";
    runs.push({ color: C.Override, col, text });
    hot.push({ kind: "fallthrough", key: "\0fallthrough", col, len: text.length, target: r.fallthrough ?? r.address });
    col += text.length + 2;
  }
  if (r.callSignature) {
    // A call's signature override (feature call-signature-override).
    const text = `⤷ signature: ${r.callSignature}`;
    runs.push({ color: C.Override, col, text });
    hot.push({ kind: "callsig", key: "\0callsig", col, len: text.length, target: r.address });
    col += text.length + 2;
  }
  // Register values from here (feature register-values): Ghidra's "assume gp = 0x...".
  for (const v of r.registerValues ?? []) {
    const text = `assume ${v.register} = 0x${v.value.toString(16)}`;
    runs.push({ color: C.Override, col, text });
    hot.push({ kind: "regvalue", key: "\0regvalue:" + v.register, col, len: text.length, target: r.address });
    col += text.length + 2;
  }
  if (r.comment) {
    runs.push({ color: C.Comment, col, text: r.comment });
    hot.push({ kind: "comment", key: "\0comment", col, len: r.comment.length });
    col += r.comment.length + 2;
  }
  const note = annotations.get(r.address);
  if (note) {
    runs.push({ color: C.AgentName, col, text: note });
    hot.push({ kind: "plugin", key: "\0plugin", col, len: note.length, target: r.address });
  }
}
