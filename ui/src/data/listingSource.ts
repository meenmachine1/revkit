// ListingSource over revkit.v1 QueryService.GetListing: row windows for
// scrolling, address windows (with rows_before context) for jumps.

import { CommentKind, ListingHeaderKind, ListingRowKind, ListingTokenKind, type ListingRow as PbRow, type Revkit } from "@revkit/api";
import { showName, showNameIn } from "./names";
import { fmtAddr } from "./format";
import { RowKind, type HeaderKind, TokenKind, type ListingRow, type ListingSource, type OperandToken, type RowsAroundResult, type RowsResult } from "./types";

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
export const MAX_BYTES_SHOWN = 5;

// Branches, calls and returns across x86, ARM/AArch64, RISC-V, MIPS and
// PowerPC, for the flow color. Cosmetic only.
const FLOW =
  /^(j[a-z]*|call|callq|ret[a-z]*|iret[a-z]*|loop[a-z]*|syscall|hlt|ud2|b|bl|blr|br|bx|blx|braa|blraa|retaa|cbn?z|tbn?z|jalr?|jr|beqz?|bnez?|bltu?|bgeu?|bgtz?|blez|bltz|bgez|c\.(j|jr|jal|jalr|beqz|bnez)|bc|bcl|bclr|bctr|bctrl|blr|bdnz|tail|mret|eret)(\.[a-z]+)?$|^b(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al|hs|lo)(\.[a-z]+)?$/i;

function tokenKind(k: ListingTokenKind): TokenKind {
  switch (k) {
    case ListingTokenKind.REGISTER:
      return TokenKind.Register;
    case ListingTokenKind.SCALAR:
      return TokenKind.Immediate;
    case ListingTokenKind.ADDRESS:
      return TokenKind.Address;
    case ListingTokenKind.SYMBOL:
      return TokenKind.Symbol;
    case ListingTokenKind.TYPE:
      return TokenKind.Type;
    case ListingTokenKind.DATA_VALUE:
      return TokenKind.Value;
    default:
      return TokenKind.Punct;
  }
}

const COMMENT_SUB: Record<number, string> = {
  [CommentKind.EOL]: "eol",
  [CommentKind.PRE]: "pre",
  [CommentKind.POST]: "post",
  [CommentKind.PLATE]: "plate",
  [CommentKind.REPEATABLE]: "repeatable",
  [CommentKind.DECOMPILER]: "decompiler",
};

function commentText(kind: CommentKind, text: string): string {
  const t = text.replace(/\s*\n\s*/g, " ⏎ ");
  switch (kind) {
    case CommentKind.EOL:
    case CommentKind.REPEATABLE:
      return "; " + t;
    case CommentKind.DECOMPILER:
      return "// " + t;
    default:
      return "/* " + t + " */";
  }
}

/** Comment kinds that header rows show on lines of their own. */
const HEADER_COMMENTS = new Set<number>([CommentKind.PLATE, CommentKind.PRE]);

/** A header line's text with its name spelled as the setting says (names.ts). */
function headerText(r: PbRow): string {
  const h = r.header!;
  if (!h.demangled) return h.text;
  if (h.kind === ListingHeaderKind.LABEL) return showName(h.text, h.demangled);
  if (h.kind === ListingHeaderKind.SIGNATURE) return showNameInSignature(h.text, h.demangled);
  return h.text;
}

/** A signature's name (the text before its last top-level "(") as the setting spells it. */
function showNameInSignature(text: string, d: NonNullable<PbRow["header"]>["demangled"]): string {
  let depth = 0;
  for (let i = text.length - 1; i >= 0; i--) {
    const c = text[i];
    if (c === ")") depth++;
    else if (c === "(" && --depth === 0) {
      const head = text.slice(0, i);
      // The name: from after the return type's last space or '*'.
      const start = Math.max(head.lastIndexOf(" "), head.lastIndexOf("*")) + 1;
      return showNameIn(text, head.slice(start), d);
    }
  }
  return text;
}

export function toRow(r: PbRow, revision: bigint, addrWidth: number, headerRows = false): ListingRow {
  const bytes = r.bytes;
  let bytesText = "";
  const shown = Math.min(bytes.length, MAX_BYTES_SHOWN);
  for (let i = 0; i < shown; i++) bytesText += (i ? " " : "") + HEX[bytes[i]];
  if (bytes.length > MAX_BYTES_SHOWN) bytesText += "…";
  else if (!bytes.length && r.length) bytesText = "??";
  // Patched bytes (PatchService): which shown ones differ from the file's.
  const orig = r.originalBytes;
  const patchedBytes: number[] = [];
  let originalBytesText = "";
  if (r.patched && orig.length) {
    for (let i = 0; i < Math.min(shown, orig.length); i++) if (orig[i] !== bytes[i]) patchedBytes.push(i);
    for (let i = 0; i < Math.min(orig.length, MAX_BYTES_SHOWN); i++) originalBytesText += (i ? " " : "") + HEX[orig[i]];
  }

  // Prefix and mnemonic go in the mnemonic column; everything after the
  // first whitespace following them is the operand field.
  let mnemonic = "";
  const operands: OperandToken[] = [];
  const toks = r.tokens;
  const isMnem = (k: ListingTokenKind) => k === ListingTokenKind.MNEMONIC || k === ListingTokenKind.PREFIX;
  let i = 0;
  while (i < toks.length) {
    const t = toks[i];
    if (isMnem(t.kind)) mnemonic += (mnemonic ? " " : "") + t.text;
    else if (!(t.kind === ListingTokenKind.WHITESPACE && i + 1 < toks.length && isMnem(toks[i + 1].kind))) break;
    i++;
  }
  // Data and undefined rows lead with their type ("undefined[16]", "dword").
  if (!mnemonic && i < toks.length && toks[i].kind === ListingTokenKind.TYPE) mnemonic = toks[i++].text;
  if (i < toks.length && toks[i].kind === ListingTokenKind.WHITESPACE) i++;
  let col = 0;
  for (; i < toks.length; i++) {
    const t = toks[i];
    const text = t.kind === ListingTokenKind.SYMBOL ? showName(t.text, t.demangled) : t.text;
    const o: OperandToken = { text, kind: tokenKind(t.kind), col };
    if ((t.kind === ListingTokenKind.ADDRESS || t.kind === ListingTokenKind.SYMBOL) && t.target) o.target = t.target.offset;
    if (t.operandIndex !== undefined) o.operandIndex = t.operandIndex;
    if (t.value !== undefined) o.value = t.value;
    if (t.scalarBits !== undefined) o.bits = t.scalarBits;
    if (t.displayOrigin) o.displayOrigin = t.displayOrigin;
    if (t.referenceOrigin) o.referenceOrigin = t.referenceOrigin;
    operands.push(o);
    col += text.length;
  }
  if (!toks.length) {
    if (r.kind === ListingRowKind.UNDEFINED) mnemonic = "??";
    else if (r.kind === ListingRowKind.DATA) mnemonic = r.dataType || "data";
  }

  const label = r.labels.find((l) => l.primary) ?? r.labels[0];
  const eol = r.comments.find((c) => c.kind === CommentKind.EOL);
  const onRow = headerRows ? r.comments.filter((c) => !HEADER_COMMENTS.has(c.kind)) : r.comments;
  const comment = onRow.map((c) => commentText(c.kind, c.text)).join("  ");
  const comments: Record<string, string> = {};
  for (const c of r.comments) comments[COMMENT_SUB[c.kind] ?? "eol"] = c.text;
  const kind =
    r.kind === ListingRowKind.DATA
      ? RowKind.Data
      : r.kind === ListingRowKind.UNDEFINED
        ? RowKind.Undefined
        : r.kind === ListingRowKind.HEADER
          ? RowKind.Header
          : RowKind.Instruction;
  const address = r.address?.offset ?? 0n;
  return {
    row: Number(r.row),
    kind,
    address,
    addrText: fmtAddr(address, addrWidth),
    bytesText,
    length: r.length,
    mnemonic,
    operands,
    label: label ? showName(label.name, label.demangled) : "",
    labelDemangled: label?.demangled,
    labelOrigin: label?.origin,
    functionEntry: r.functionEntry,
    func: r.function ? r.function.offset : null,
    comment,
    eol: eol?.text ?? "",
    commentSub: onRow.length ? COMMENT_SUB[onRow[0].kind] ?? "eol" : "",
    commentOrigin: (eol ?? onRow[0])?.origin,
    comments,
    xrefCount: r.xrefToCount,
    // The daemon's flow when it sends one (listing-flow), else the mnemonic.
    isFlow: kind === RowKind.Instruction && (r.flow ? r.flow !== 1 /* FALL_THROUGH */ : FLOW.test(mnemonic.split(" ").pop() ?? "")),
    flow: r.flow,
    flowTargets: r.flowTargets.map((a) => a.offset),
    flowOverride: r.flowOverride,
    flowOverrideOrigin: r.flowOverrideOrigin,
    callSignature: r.callSignature,
    callSignatureOrigin: r.callSignatureOrigin,
    dataType: r.dataType,
    dataTypeHash: r.dataTypeHash || undefined,
    header: r.header && kind === RowKind.Header ? { kind: r.header.kind as number as HeaderKind, text: headerText(r), line: r.header.line, origin: r.header.origin } : undefined,
    block: r.block,
    revision,
    patched: r.patched,
    patchedBytes,
    originalBytesText,
    dataField: r.dataField,
    dataParent: r.dataParent ? r.dataParent.offset : null,
    dataDepth: r.dataDepth,
    dataComponents: r.dataComponents,
    dataCollapsed: r.dataCollapsed,
    unitOrigin: r.unitOrigin,
    mutability: r.mutability,
    mutabilityOrigin: r.mutabilityOrigin,
  };
}

export class DaemonListing implements ListingSource {
  constructor(
    private rk: Revkit,
    private programId: string,
    /** Hex digits to pad addresses to. */
    public addrWidth = 8,
    /** Number rows as displayed, with header rows (feature listing-header-rows). */
    public headerRows = false,
  ) {}

  async rows(startRow: number, count: number, signal?: AbortSignal): Promise<RowsResult> {
    const r = await this.rk.queries.getListing(
      { programId: this.programId, headerRows: this.headerRows, window: { case: "rows", value: { firstRow: BigInt(startRow), rowCount: count } } },
      { signal },
    );
    const rev = r.snapshot?.revision ?? 0n;
    return {
      startRow: Number(r.firstRow),
      rows: r.rows.map((x) => toRow(x, rev, this.addrWidth, this.headerRows)),
      totalRows: Number(r.totalRows),
      revision: rev,
    };
  }

  async rowsAround(address: bigint, before: number, after: number, signal?: AbortSignal): Promise<RowsAroundResult> {
    const r = await this.rk.queries.getListing(
      {
        programId: this.programId,
        headerRows: this.headerRows,
        window: { case: "addresses", value: { start: { offset: address }, maxRows: before + after, rowsBefore: before } },
      },
      { signal },
    );
    const rev = r.snapshot?.revision ?? 0n;
    const rows = r.rows.map((x) => toRow(x, rev, this.addrWidth, this.headerRows));
    // Rows are in address order: the anchor is the code unit containing the
    // address (not its header rows), else the first one after it (an
    // address in a gap).
    const unit = (x: ListingRow) => x.kind !== RowKind.Header;
    let anchor = rows.findIndex((x) => unit(x) && address >= x.address && address < x.address + BigInt(Math.max(1, x.length)));
    if (anchor < 0) anchor = rows.findIndex((x) => unit(x) && x.address > address);
    if (anchor < 0) anchor = Math.max(0, rows.length - 1);
    return { startRow: Number(r.firstRow), rows, totalRows: Number(r.totalRows), revision: rev, anchorRow: Number(r.firstRow) + anchor };
  }
}
