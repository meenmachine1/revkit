// Editing what bytes are, from the listing (feature listing-edit,
// docs/listing-edit.md): Ghidra's Clear Code Bytes (c), Disassemble (d),
// the Data menu (b cycles byte/word/dword/qword, ' char, " string, [ array,
// t any type, p pointer) and constant/volatile ranges. Every action is one
// AppendAssertions call, so one undo step with a label, blame and live
// updates like any other edit; nothing changes here until the
// subscription's event refetches the rows.

import { clone } from "@bufbuild/protobuf";
import { AssertionOp, AssertionStatus, DefineDataSchema, FactKind, InstructionSet, Mutability, StringEncoding, StringLayout, type DefineData, type Revkit } from "@revkit/api";
import { userProvenance } from "../api/client";
import { Edits, type DataSpec, type EditResult } from "../data/edits";
import { errText, fmtAddr, hex, spaceOf } from "../data/format";
import type { RowCache } from "../data/rowCache";
import { RowKind, type ListingRow } from "../data/types";
import type { ListingView } from "../listing/view";
import { ask, choose, toast, type Suggestion } from "./dialogs";
import { prefs } from "./dom";

export interface ListingEditHost {
  rk: Revkit;
  programId: string;
  edits: Edits;
  view: ListingView;
  cache: RowCache;
  /** The program's pointer size in bytes. */
  pointerSize: number;
  /** The language has ARM and Thumb (ARM, not Cortex-M): offer both. */
  armThumb: boolean;
  /** Resolves once this tab has the revision (its views refreshed). */
  settle: (revision: bigint) => Promise<void>;
  undo: () => void;
  /** The type chooser's dropdown (Set type's). */
  typeSuggestions: (text: string) => Promise<Suggestion[]>;
}

/** A data definition offered by name: the builtin's spelling and its size. */
export interface DataKind {
  id: string;
  /** What menus and undo labels say ("dword", "UTF-16 string"). */
  label: string;
  spec: DataSpec;
  /** Bytes per item (0: as the bytes say, a terminated string). */
  size: (ptr: number) => number;
  keys?: string;
}

const str = (string: StringEncoding, layout: StringLayout): DataSpec => ({ string, layout });

/** The Data menu, in order (Ghidra's names: the daemon reads them as types). */
export const DATA_KINDS: DataKind[] = [
  { id: "byte", label: "byte", spec: { decl: "byte" }, size: () => 1, keys: "b" },
  { id: "word", label: "word", spec: { decl: "word" }, size: () => 2 },
  { id: "dword", label: "dword", spec: { decl: "dword" }, size: () => 4 },
  { id: "qword", label: "qword", spec: { decl: "qword" }, size: () => 8 },
  { id: "char", label: "char", spec: { decl: "char" }, size: () => 1, keys: "'" },
  { id: "string", label: "string", spec: str(StringEncoding.UTF8, StringLayout.TERMINATED), size: () => 0, keys: '"' },
  { id: "string16", label: "UTF-16 string", spec: str(StringEncoding.UTF16, StringLayout.TERMINATED), size: () => 0 },
  { id: "pascal", label: "Pascal string", spec: str(StringEncoding.UTF8, StringLayout.PASCAL), size: () => 0 },
  { id: "float", label: "float", spec: { decl: "float" }, size: () => 4 },
  { id: "double", label: "double", spec: { decl: "double" }, size: () => 8 },
  { id: "pointer", label: "pointer", spec: { decl: "pointer" }, size: (p) => p, keys: "p" },
];

/** Ghidra's Cycle (b): byte → word → dword → qword → byte. */
const CYCLE = ["byte", "word", "dword", "qword"];
/** Type names a data row may show for each step of the cycle. */
const CYCLE_NAMES: string[][] = [
  ["byte", "uint8_t", "unsigned char", "uchar", "sbyte", "int8_t"],
  ["word", "uint16_t", "unsigned short", "ushort", "sword", "int16_t"],
  ["dword", "uint32_t", "unsigned int", "uint", "sdword", "int32_t"],
  ["qword", "uint64_t", "unsigned long long", "ulonglong", "sqword", "int64_t"],
];

export const MUTABILITY_CHOICES: { id: string; label: string; m: Mutability; verb: string }[] = [
  { id: "const", label: "Constant (never written)", m: Mutability.CONSTANT, verb: "constant" },
  { id: "volatile", label: "Volatile (memory-mapped I/O)", m: Mutability.VOLATILE, verb: "volatile" },
  { id: "normal", label: "Writable (normal)", m: Mutability.NORMAL, verb: "writable" },
  { id: "default", label: "Mutability as the memory map says", m: Mutability.DEFAULT, verb: "back to the memory map's" },
];

/** A data definition used recently (the menu's "Recently used"). */
export interface RecentData {
  label: string;
  spec: DataSpec;
}

const RECENT_KEY = "rk.recentData";
const RECENT_MAX = 5;

const at = (a: bigint) => (spaceOf(a) ? fmtAddr(a) : `0x${hex(a)}`);
const plural = (n: bigint | number, what: string) => `${n} ${what}${n === 1n || n === 1 ? "" : "s"}`;

/** "dword[4]" → dword and 4; "dword" → dword and 0. */
export function splitCount(text: string): { decl: string; count: number } {
  const m = /^(.*?)\s*\[\s*(0x[0-9a-f]+|\d+)\s*\]\s*$/i.exec(text.trim());
  if (!m || !m[1]) return { decl: text.trim(), count: 0 };
  return { decl: m[1].trim(), count: Number(m[2]) };
}

export class ListingEditor {
  constructor(private host: ListingEditHost) {}

  // ------------------------------------------------------------ targets --

  /** Where an edit starts: the code unit at the cursor, or at the start of
   * a selection of several rows (a header row's unit), with its row index. */
  target(): { row: ListingRow; index: number } | null {
    const v = this.host.view;
    const [lo, hi] = v.selectionRange();
    const i = lo >= 0 && lo !== hi ? lo : v.selectedRow;
    const r = i < 0 ? undefined : this.host.cache.get(i);
    if (!r) return null;
    if (r.kind !== RowKind.Header) return { row: r, index: i };
    for (let j = i + 1; j < i + 64; j++) {
      const u = this.host.cache.get(j);
      if (!u) break;
      if (u.kind !== RowKind.Header) return u.address === r.address ? { row: u, index: j } : null;
    }
    return null;
  }

  /** The selected bytes: from the first selected row's address to the end
   * of the last code unit (the cursor's unit when one row is selected). */
  range(): { start: bigint; length: bigint; rows: number } | null {
    const [lo, hi] = this.host.view.selectionRange();
    if (lo < 0) return null;
    if (lo === hi) {
      const t = this.target(); // the cursor's unit
      return t ? { start: t.row.address, length: BigInt(Math.max(1, t.row.length)), rows: 1 } : null;
    }
    let start: bigint | null = null;
    let end: bigint | null = null;
    let rows = 0;
    for (let i = lo; i <= hi; i++) {
      const r = this.host.cache.get(i);
      if (!r) return null; // not loaded (a long shift-click): the caller says so
      if (start === null || r.address < start) start = r.address;
      if (r.kind === RowKind.Header) continue;
      rows++;
      const e = r.address + BigInt(Math.max(1, r.length));
      if (end === null || e > end) end = e;
    }
    if (start === null) return null;
    if (end === null) {
      const t = this.target();
      end = t ? t.row.address + BigInt(Math.max(1, t.row.length)) : start + 1n;
    }
    return { start, length: end - start, rows: Math.max(1, rows) };
  }

  /** The data item a field or element row belongs to (or the row itself). */
  item(t: { row: ListingRow; index: number }): ListingRow {
    const r = t.row;
    if (!r.dataField || r.dataParent === null) return r;
    for (let j = t.index - 1; j >= Math.max(0, t.index - 4096); j--) {
      const u = this.host.cache.get(j);
      if (!u) break;
      if (u.address === r.dataParent && !u.dataField && u.kind === RowKind.Data) return u;
    }
    return r;
  }

  // ------------------------------------------------------------ actions --

  private async run(label: string, bodies: Parameters<Edits["bodies"]>[1], done: string, failed: string): Promise<EditResult | null> {
    try {
      const r = await this.host.edits.bodies(label, bodies);
      toast(done, { action: { label: "Undo", run: () => this.host.undo() } });
      await this.host.settle(r.revision);
      return r;
    } catch (e) {
      toast(`${failed}: ${errText(e)}`, { kind: "error" });
      return null;
    }
  }

  /** c: the selection's bytes (or the code unit at the cursor; a field's
   * whole item) become undefined. */
  async clear() {
    let r = this.range();
    if (!r) return toast("Select the rows to clear (or wait for them to load)", { kind: "error" });
    const t = this.target();
    if (r.rows === 1 && t?.row.dataField) {
      const it = this.item(t);
      if (it !== t.row) r = { start: it.address, length: BigInt(Math.max(1, it.length)), rows: 1 };
    }
    const label = `Clear ${plural(r.length, "byte")} at ${at(r.start)}`;
    await this.run(label, [Edits.clearBody(r.start, r.length)], `Cleared ${plural(r.length, "byte")} at ${at(r.start)}`, "Clear failed");
  }

  /** d: code starts at the cursor (in ARM or Thumb, as asked), and a function with `fn`. */
  async disassemble(isa: InstructionSet = InstructionSet.UNSPECIFIED, fn = false) {
    const t = this.target();
    if (!t) return toast("Select where the code starts", { kind: "error" });
    const a = t.row.address;
    const how = isa === InstructionSet.ARM ? " as ARM" : isa === InstructionSet.THUMB ? " as Thumb" : "";
    const label = `Disassemble${how}${fn ? " and create function" : ""} at ${at(a)}`;
    await this.run(label, [Edits.disassembleBody(a, isa, fn)], `${label.replace(/^Disassemble/, "Disassembled")}`, "Disassemble failed");
  }

  /** Defines `spec` at the cursor. A selection longer than one item first
   * asks whether to fill it (an array, or a fixed-length string). */
  async define(spec: DataSpec, what: string, size = 0): Promise<boolean> {
    const t = this.target();
    if (!t) {
      toast("Select where the data starts", { kind: "error" });
      return false;
    }
    if (t.row.dataField) {
      const it = this.item(t);
      toast(`${at(t.row.address)} is ${t.row.dataField} of ${it.dataType || "the item"} at ${at(t.row.dataParent ?? it.address)}: clear the item (c) first, or change its type in the Types view`, { kind: "error" });
      return false;
    }
    const sel = this.range();
    let s = { ...spec };
    let name = what;
    if (sel && sel.rows > 1 && sel.start === t.row.address && !s.count) {
      if (s.string !== undefined && s.string !== StringEncoding.UNSPECIFIED) {
        const unit = s.string === StringEncoding.UTF16 ? 2n : s.string === StringEncoding.UTF32 ? 4n : 1n;
        const n = Number(sel.length / unit);
        if (n > 1) {
          const pick = await choose(`Define ${what} at ${at(t.row.address)}`, [
            { label: `${n} characters (fills the selection)`, detail: `fixed length, ${plural(sel.length, "byte")}`, value: n },
            { label: "Up to its terminator", detail: "as the bytes say", value: 0 },
          ]);
          if (pick === null) return false;
          if (pick) {
            s = { ...s, layout: StringLayout.FIXED, count: pick };
            name = `${what} (${n} characters)`;
          }
        }
      } else if (size > 0 && sel.length > BigInt(size)) {
        const n = Number(sel.length / BigInt(size));
        if (n > 1) {
          const pick = await choose(`Define ${what} at ${at(t.row.address)}`, [
            { label: `${what}[${n}]`, detail: `an array filling the selection (${plural(BigInt(n * size), "byte")})`, value: n },
            { label: `One ${what}`, detail: plural(size, "byte"), value: 0 },
          ]);
          if (pick === null) return false;
          if (pick) {
            s = { ...s, count: pick };
            name = `${what}[${n}]`;
          }
        }
      }
    }
    const a = t.row.address;
    const r = await this.run(`Define ${name} at ${at(a)}`, [Edits.defineDataBody(a, s)], `${name} at ${at(a)}`, "Define data failed");
    if (!r) return false;
    this.remember({ label: name.replace(/ \(\d+ characters\)$/, ""), spec: s });
    return true;
  }

  /** A named kind from the Data menu. */
  defineKind(id: string) {
    const k = DATA_KINDS.find((x) => x.id === id);
    if (k) return this.define(k.spec, k.label, k.size(this.host.pointerSize));
  }

  /** b: the item at the cursor as the next of byte, word, dword, qword. */
  async cycle() {
    const t = this.target();
    if (!t) return toast("Select where the data starts", { kind: "error" });
    const r = t.row;
    let step = 0;
    if (r.kind === RowKind.Data && !r.dataField && !r.dataComponents) {
      const name = r.dataType.trim();
      const i = CYCLE_NAMES.findIndex((names, k) => names.includes(name) && r.length === 1 << k);
      if (i >= 0) step = (i + 1) % CYCLE.length;
    }
    const k = DATA_KINDS.find((x) => x.id === CYCLE[step])!;
    // The cycle redefines the one item at the cursor (no array offer).
    if (r.dataField) return this.define(k.spec, k.label);
    const a = r.address;
    const res = await this.run(`Define ${k.label} at ${at(a)}`, [Edits.defineDataBody(a, k.spec)], `${k.label} at ${at(a)}`, "Define data failed");
    if (res) this.remember({ label: k.label, spec: k.spec });
  }

  /** [: an array; the dialog holds element[count], the count filling the
   * selection (or the row: an undefined run) by default. */
  async array() {
    const t = this.target();
    if (!t) return toast("Select where the array starts", { kind: "error" });
    if (t.row.dataField) return this.define({}, "array");
    const r = t.row;
    const typed = r.kind === RowKind.Data && !!r.unitOrigin && !r.dataComponents && r.length > 0;
    const elem = typed ? r.dataType : "byte";
    const elemSize = typed ? r.length : 1;
    const sel = this.range();
    const bytes = sel && sel.rows > 1 ? Number(sel.length) : Math.max(1, r.length);
    const fill = Math.max(1, Math.floor(bytes / elemSize));
    const text = await ask({
      title: `Define an array at ${at(r.address)}`,
      value: `${elem}[${fill}]`,
      placeholder: "dword[16]",
      suggest: (v) => this.host.typeSuggestions(v),
      hint: `The element type and the count: type[count] (${fill} fills the ${sel && sel.rows > 1 ? "selection" : "row"}) · Enter to define · Esc to cancel`,
      validate: (v) => (splitCount(v).count > 0 ? null : "Give the count: type[count]"),
      check: (v) => {
        const s = splitCount(v);
        return this.host.edits.check(Edits.defineDataBody(r.address, { decl: s.decl, count: s.count }));
      },
    });
    if (text === null) return;
    const s = splitCount(text);
    await this.defineSpec({ decl: s.decl, count: s.count }, `${s.decl}[${s.count}]`);
  }

  /** t: any type, with the type chooser (Set type's); type[n] is an array. */
  async chooseType() {
    const t = this.target();
    if (!t) return toast("Select where the data starts", { kind: "error" });
    if (t.row.dataField) return this.define({}, "data");
    const r = t.row;
    const text = await ask({
      title: `Define data at ${at(r.address)}`,
      value: r.kind === RowKind.Data && r.unitOrigin ? r.dataType : "",
      placeholder: "dword, uint32_t, struct hdr, char[16]",
      suggest: (v) => this.host.typeSuggestions(v),
      hint: "A type: matching types drop down (↑↓, Tab or Enter takes one) · byte word dword qword char float double pointer, any C type, type[n] for an array · Enter to define · Esc to cancel",
      check: (v) => {
        const s = splitCount(v);
        return this.host.edits.check(Edits.defineDataBody(r.address, { decl: s.decl, count: s.count }));
      },
    });
    if (text === null || !text.trim()) return;
    const s = splitCount(text);
    if (s.count) return this.defineSpec({ decl: s.decl, count: s.count }, `${s.decl}[${s.count}]`);
    await this.define({ decl: s.decl }, s.decl, await this.sizeOf({ decl: s.decl }, r.address));
  }

  /** Defines exactly `spec` (no selection offer), remembering it. */
  async defineSpec(spec: DataSpec, label: string) {
    const t = this.target();
    if (!t) return toast("Select where the data starts", { kind: "error" });
    const a = t.row.address;
    const r = await this.run(`Define ${label} at ${at(a)}`, [Edits.defineDataBody(a, spec)], `${label} at ${at(a)}`, "Define data failed");
    if (r) this.remember({ label, spec });
  }

  /** The size the daemon gives a definition (validate_only), or 0. */
  private async sizeOf(spec: DataSpec, address: bigint): Promise<number> {
    try {
      const r = await this.host.rk.assertions.appendAssertions({
        programId: this.host.programId,
        provenance: userProvenance(),
        assertions: [{ body: Edits.defineDataBody(address, spec) }],
        validateOnly: true,
      });
      const b = r.assertions[0]?.body?.kind;
      if (b?.case === "listingEdit" && b.value.kind.case === "data") return Number(b.value.kind.value.size / BigInt(Math.max(1, Number(b.value.kind.value.count) || 1)));
    } catch {
      /* the define itself reports it */
    }
    return 0;
  }

  /** Constant, volatile, writable or default over the selection (or the cursor's unit). */
  async mutability(m: Mutability) {
    const r = this.range();
    if (!r) return toast("Select the rows to mark (or wait for them to load)", { kind: "error" });
    const c = MUTABILITY_CHOICES.find((x) => x.m === m)!;
    const label = m === Mutability.DEFAULT ? `Mutability of ${plural(r.length, "byte")} at ${at(r.start)} back to default` : `Mark ${plural(r.length, "byte")} at ${at(r.start)} ${c.verb}`;
    await this.run(label, [Edits.mutabilityBody(r.start, r.length, m)], label, "Mutability failed");
  }

  /** The item a row shows when it can expand: itself, or a field's item. */
  expandable(): ListingRow | null {
    const t = this.target();
    if (!t) return null;
    const it = this.item(t);
    return it.dataComponents > 0 && !it.dataField ? it : null;
  }

  /**
   * Expands or collapses a data item (`expand` undefined: toggles): the
   * same definition asserted again with `collapsed` flipped, so it is an
   * undo step and every client follows.
   */
  async toggle(row?: ListingRow, expand?: boolean) {
    const it = row ?? this.expandable();
    if (!it || it.dataComponents <= 0) return toast("Nothing to expand here: only data items with fields or elements expand");
    const want = expand ?? it.dataCollapsed;
    if (want === !it.dataCollapsed) return;
    let d: DefineData | null = null;
    try {
      const b = await this.host.rk.assertions.blame({ key: { programId: this.host.programId, kind: FactKind.CODE_UNIT, address: { offset: it.address }, sub: "data" } });
      const w = b.candidates.find((c) => c.status === AssertionStatus.EFFECTIVE && c.op === AssertionOp.ASSERT) ?? b.candidates[0];
      const k = w?.body?.kind;
      if (k?.case === "listingEdit" && k.value.kind.case === "data") d = k.value.kind.value;
    } catch (e) {
      return toast(`Can't read the definition at ${at(it.address)}: ${errText(e)}`, { kind: "error" });
    }
    if (!d) return toast(`No data definition at ${at(it.address)} to ${want ? "expand" : "collapse"}`, { kind: "error" });
    const next = clone(DefineDataSchema, d);
    next.collapsed = !want;
    const label = `${want ? "Expand" : "Collapse"} ${it.dataType || "data"} at ${at(it.address)}`;
    await this.run(label, [Edits.defineDataBody(it.address, next)], label.replace(/^Expand/, "Expanded").replace(/^Collapse/, "Collapsed"), want ? "Expand failed" : "Collapse failed");
  }

  // ------------------------------------------------------- recently used --

  /** The data definitions used last, newest first (per browser). */
  recent(): RecentData[] {
    try {
      const v = JSON.parse(prefs.get(RECENT_KEY) ?? "[]") as RecentData[];
      return Array.isArray(v) ? v.filter((x) => x && typeof x.label === "string" && x.spec && typeof x.spec === "object").slice(0, RECENT_MAX) : [];
    } catch {
      return [];
    }
  }

  private remember(d: RecentData) {
    const list = [d, ...this.recent().filter((x) => x.label !== d.label)].slice(0, RECENT_MAX);
    prefs.set(RECENT_KEY, JSON.stringify(list));
  }

  /** Defines a recently used definition at the cursor (as it was: one item, or the array). */
  defineRecent(d: RecentData) {
    const k = DATA_KINDS.find((x) => x.label === d.label);
    if (k) return this.define(k.spec, k.label, k.size(this.host.pointerSize));
    return this.defineSpec(d.spec, d.label);
  }
}
