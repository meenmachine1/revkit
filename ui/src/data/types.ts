// Transport-neutral listing model. The canvas view and the row cache see
// these, never protobuf messages; src/data/listingSource.ts maps
// revkit.v1 GetListing rows into them.

import type { DataSettings, DemangledName, FactOrigin } from "@revkit/api";

/** Header rows (plate comment lines, signatures, labels, pre-comments) are
 * display lines above a code unit, numbered by the daemon. */
export const RowKind = { Instruction: 1, Data: 2, Undefined: 3, Header: 4 } as const;
export type RowKind = (typeof RowKind)[keyof typeof RowKind];

export const HeaderKind = { Plate: 1, Signature: 2, Label: 3, Pre: 4 } as const;
export type HeaderKind = (typeof HeaderKind)[keyof typeof HeaderKind];

/** Flow of an instruction (revkit.v1 FlowKind values). */
export const Flow = { FallThrough: 1, Branch: 2, CondBranch: 3, Call: 4, Return: 5, IndirectBranch: 6, IndirectCall: 7, Terminator: 8 } as const;

/** Operand token kinds, as drawn. */
export const TokenKind = { Punct: 1, Register: 2, Immediate: 3, Address: 4, Symbol: 5, Type: 6, Value: 7 } as const;
export type TokenKind = (typeof TokenKind)[keyof typeof TokenKind];

export interface OperandToken {
  text: string;
  kind: TokenKind;
  /** Character column inside the operand field. */
  col: number;
  /** Navigation target for Address and Symbol tokens. */
  target?: bigint;
  /** The operand the token belongs to (unset: the mnemonic, separators). */
  operandIndex?: number;
  /** A scalar's value (ListingToken.value, signed) and width in bits. */
  value?: bigint;
  bits?: number;
  /** The operand shows as an assertion says (an equate or a conversion:
   * feature equates), or as a primary user reference's target (feature
   * user-references). */
  displayOrigin?: FactOrigin;
  referenceOrigin?: FactOrigin;
}

export interface RowHeader {
  kind: HeaderKind;
  text: string;
  /** Line index within a multi-line comment. */
  line: number;
  origin?: FactOrigin;
}

/** One listing line, already formatted for drawing. */
export interface ListingRow {
  /** Absolute row number at `revision`. */
  row: number;
  kind: RowKind;
  address: bigint;
  addrText: string;
  bytesText: string;
  /** Length in bytes (0 for header rows). */
  length: number;
  mnemonic: string;
  operands: OperandToken[];
  /** Primary label at the address (the function name on an entry row). */
  label: string;
  labelOrigin?: FactOrigin;
  /** The label's other spellings, when it is a demangled name (names.ts). */
  labelDemangled?: DemangledName;
  functionEntry: boolean;
  /** Entry of the containing function, if any. */
  func: bigint | null;
  /** The comments shown on the row, formatted for one line (with header
   * rows, plate and pre-comments have rows of their own instead). */
  comment: string;
  /** The end-of-line comment's raw text (what the comment editor edits). */
  eol: string;
  /** FactKey.sub of the first comment shown ("eol", "post", ...), for blame. */
  commentSub: string;
  commentOrigin?: FactOrigin;
  /** Raw comment texts by FactKey.sub. */
  comments: Record<string, string>;
  xrefCount: number;
  isFlow: boolean;
  /** Instructions: revkit.v1 FlowKind after any override (0 = unknown). */
  flow: number;
  /** Static branch, call and jump-table targets. */
  flowTargets: bigint[];
  /** Effective flow override (revkit.v1 FlowOverrideKind, 0 = none). */
  flowOverride: number;
  flowOverrideOrigin?: FactOrigin;
  /** The user's fallthrough override (feature fallthrough-override; Ghidra's
   * Set Fallthrough): set, with `fallthrough` where control goes on after
   * the instruction (null: it doesn't fall through). */
  fallthroughOverride: boolean;
  fallthrough: bigint | null;
  fallthroughOrigin?: FactOrigin;
  /** A call's signature override as C (feature call-signature-override; "" if none) and who set it. */
  callSignature: string;
  callSignatureOrigin?: FactOrigin;
  /** Register values from here (feature register-values; Ghidra's "assume gp = 0x..."):
   * where a range starts and at a function's entry. */
  registerValues: { register: string; value: bigint; analysis: boolean; origin?: FactOrigin }[];
  /** A global's asserted type (or a data row's type). */
  dataType: string;
  /** Its definition's hash (GetTypes), for the hover card's layout. */
  dataTypeHash?: string;
  header?: RowHeader;
  block: string;
  revision: bigint;
  /** Some byte is patched (PatchService): which of the shown bytes, and the
   * file's bytes. */
  patched: boolean;
  patchedBytes: number[];
  originalBytesText: string;
  /** Listing edits (feature listing-edit, docs/listing-edit.md). A field or
   * element row of an expanded data item: its path from the item ("magic",
   * "hdr.len", "[3]"), the item's address and how deep it is (1 for the
   * item's own fields); "" / null / 0 on other rows. */
  dataField: string;
  dataParent: bigint | null;
  dataDepth: number;
  /** On a data item's own row: its field or element rows when expanded (0:
   * nothing to expand), and whether it is collapsed. */
  dataComponents: number;
  dataCollapsed: boolean;
  /** The Clear, Disassemble here or Define data that says what the row's
   * first byte is; unset when analysis decided. */
  unitOrigin?: FactOrigin;
  /** revkit.v1 Mutability over the row's first byte (0: no edit), and who set it. */
  mutability: number;
  mutabilityOrigin?: FactOrigin;
  /** Data settings (feature data-settings): the row's own (its item's; a
   * struct field's own) and who set them, the type its defaults are kept
   * by, and that type's defaults. The operands already show them. */
  dataSettings?: DataSettings;
  dataSettingsOrigin?: FactOrigin;
  dataSettingsType?: string;
  dataTypeSettings?: DataSettings;
}

export interface RowsResult {
  startRow: number;
  rows: ListingRow[];
  totalRows: number;
  revision: bigint;
}

export interface RowsAroundResult extends RowsResult {
  /** Row containing the address (or the next row when it is in a gap). */
  anchorRow: number;
}

export interface ListingSource {
  rows(startRow: number, count: number, signal?: AbortSignal): Promise<RowsResult>;
  rowsAround(address: bigint, before: number, after: number, signal?: AbortSignal): Promise<RowsAroundResult>;
}

/** A renumbered stretch of rows, as InvalidatedQuery reports it: the rows
 * [prevFirst, prevFirst + prevCount) at the previous revision are
 * [first, first + count) now; rows after it move by count - prevCount. */
export interface RowShift {
  prevFirst: number;
  prevCount: number;
  first: number;
  count: number;
}

export const isCodeUnit = (r: ListingRow) => r.kind !== RowKind.Header;
