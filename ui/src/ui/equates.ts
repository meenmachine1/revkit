// Equates and scalar display (feature equates; docs/ui.md "Equates and
// references"): Ghidra's Convert menu (hex, signed and unsigned decimal,
// octal, binary, char, float), Set Equate (E: a name or an enum member
// whose value matches, on this operand or every matching scalar in the
// function or program) and Remove Equate, on a listing operand or a
// decompiler constant; and the Equates window, folded from the EQUATE
// assertions (no dedicated RPC): each equate's value and uses, renamed or
// removed everywhere as one edit. Every action is one AppendAssertions
// call, so one undo step; nothing changes on screen until the
// subscription's event refetches the rows and the C.

import { AssertionOp, AssertionStatus, EquateScope, FactKind, ScalarFormat, TypeSource, type Revkit, type RevisionEvent, type TypeDefinition } from "@revkit/api";
import { Edits, type ScalarDisplay, type ScalarRef } from "../data/edits";
import { errText, fmtAddr, hex } from "../data/format";
import { ask, askMore, toast, type ControlValues, type Suggestion } from "./dialogs";
import { h } from "./dom";

export interface EquateHost {
  rk: Revkit;
  programId: string;
  edits: Edits;
  addrWidth: number;
  /** Resolves once this tab has the revision (its views refreshed). */
  settle: (revision: bigint) => Promise<void>;
  undo: () => void;
  navigate: (address: bigint) => void;
}

/** A scalar to convert or name: where it is, as shown, and its width. */
export interface ScalarTarget extends ScalarRef {
  /** Bits of the scalar (ListingToken.scalar_bits, a constant's varnode size); 0: unknown. */
  bits: number;
  /** How it shows now. */
  text: string;
  /** It shows as an assertion says (an equate or a conversion). */
  displayed: boolean;
  where: "listing" | "decomp";
}

/** The Convert menu, in Ghidra's order. */
export const FORMATS: { id: string; label: string; format: ScalarFormat }[] = [
  { id: "hex", label: "Hex", format: ScalarFormat.HEX },
  { id: "sdec", label: "Signed decimal", format: ScalarFormat.SIGNED_DECIMAL },
  { id: "udec", label: "Unsigned decimal", format: ScalarFormat.UNSIGNED_DECIMAL },
  { id: "oct", label: "Octal", format: ScalarFormat.OCTAL },
  { id: "bin", label: "Binary", format: ScalarFormat.BINARY },
  { id: "char", label: "Char", format: ScalarFormat.CHAR },
  { id: "float", label: "Float", format: ScalarFormat.FLOAT },
];

const CHAR_ESC: Record<number, string> = { 0: "\\0", 7: "\\a", 8: "\\b", 9: "\\t", 10: "\\n", 11: "\\v", 12: "\\f", 13: "\\r", 39: "\\'", 92: "\\\\" };

/** How `value` (a 64-bit pattern, `bits` wide) shows in `format`, as the
 * daemon prints it (the Convert menu's preview); "" when it can't. */
export function formatScalar(value: bigint, bits: number, format: ScalarFormat): string {
  const w = bits > 0 && bits <= 64 ? bits : 64;
  const u = BigInt.asUintN(w, value);
  switch (format) {
    case ScalarFormat.HEX:
      return `0x${u.toString(16)}`;
    case ScalarFormat.SIGNED_DECIMAL:
      return BigInt.asIntN(w, value).toString();
    case ScalarFormat.UNSIGNED_DECIMAL:
      return u.toString();
    case ScalarFormat.OCTAL:
      return `${u.toString(8)}o`;
    case ScalarFormat.BINARY:
      return `${u.toString(2)}b`;
    case ScalarFormat.CHAR: {
      const bytes: number[] = [];
      for (let x = u; x > 0n; x >>= 8n) bytes.unshift(Number(x & 0xffn));
      if (!bytes.length) bytes.push(0);
      return `'${bytes.map((b) => CHAR_ESC[b] ?? (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2, "0")}`)).join("")}'`;
    }
    case ScalarFormat.FLOAT: {
      if (w !== 32 && w !== 64) return "";
      const dv = new DataView(new ArrayBuffer(8));
      if (w === 32) {
        dv.setUint32(0, Number(u));
        return String(dv.getFloat32(0));
      }
      dv.setBigUint64(0, u);
      return String(dv.getFloat64(0));
    }
  }
  return "";
}

/** Float applies to 32- and 64-bit scalars only (the daemon refuses others);
 * a width that isn't known is offered and left to the daemon. */
export const floatable = (t: ScalarTarget) => t.bits === 0 || t.bits === 32 || t.bits === 64;

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const valueText = (t: ScalarTarget) => formatScalar(t.value, t.bits, ScalarFormat.HEX);
const where = (a: bigint) => `0x${hex(a)}`;

// ---------------------------------------------------------------- equates --

/** One use of an equate: the operand (or decompiler constant) and its assertion. */
export interface EquateUse extends ScalarRef {
  seq: bigint;
}

/** An equate, folded from its EQUATE assertions. */
export interface Equate {
  /** The row's key: the name, or for an enum member NAME#<enum hash prefix>
   * (two enums' members of one name are two equates). */
  key: string;
  name: string;
  value: bigint;
  /** An enum member's equate: the enum (by hash) and the member. */
  enumTypeHash: string;
  member: string;
  uses: EquateUse[];
}

/** Every equate the program has: the effective EQUATE assertions whose
 * display is a name, by name and enum (ListAssertions; there is no equates RPC). */
export async function loadEquates(rk: Revkit, programId: string): Promise<Equate[]> {
  const byName = new Map<string, Equate>();
  let token = "";
  for (let page = 0; page < 200; page++) {
    const r = await rk.assertions.listAssertions({ programId, filter: { kinds: [FactKind.EQUATE] }, page: { pageSize: 1000, pageToken: token } });
    for (const a of r.assertions) {
      if (a.status !== AssertionStatus.EFFECTIVE || a.op !== AssertionOp.ASSERT) continue;
      const b = a.body?.kind;
      if (b?.case !== "operandDisplay" || b.value.display.case !== "equate" || !b.value.display.value.name) continue;
      const d = b.value;
      const e = d.display.value as { name: string; enumTypeHash: string; member: string };
      const key = e.enumTypeHash ? `${e.name}#${e.enumTypeHash.slice(0, 8)}` : e.name;
      let q = byName.get(key);
      if (!q) byName.set(key, (q = { key, name: e.name, value: d.value, enumTypeHash: e.enumTypeHash, member: e.member, uses: [] }));
      q.uses.push({ address: d.address?.offset ?? a.key?.address?.offset ?? 0n, operandIndex: d.operandIndex, value: d.value, constantHash: d.constantHash || undefined, seq: a.seq });
    }
    token = r.page?.nextPageToken ?? "";
    if (!token) break;
  }
  const out = [...byName.values()];
  for (const q of out) q.uses.sort((x, y) => (x.address < y.address ? -1 : x.address > y.address ? 1 : (x.operandIndex ?? -1) - (y.operandIndex ?? -1)));
  return out.sort((x, y) => x.name.localeCompare(y.name) || x.key.localeCompare(y.key));
}

/** An enum member Set Equate offers: its name, the enum and where the enum is from. */
interface MemberSuggestion {
  member: string;
  enumName: string;
  enumHash: string;
  program: boolean;
}

/** Enums with a member of `value` (FindTypes enum_value): the program's
 * first, then the libraries'. */
async function enumMembers(rk: Revkit, programId: string, value: bigint, bits: number): Promise<MemberSuggestion[]> {
  const w = bits > 0 && bits <= 64 ? bits : 64;
  const signed = BigInt.asIntN(w, value);
  const unsigned = BigInt.asUintN(w, value);
  const out: MemberSuggestion[] = [];
  const seen = new Set<string>();
  const add = (types: TypeDefinition[], program: boolean) => {
    for (const t of types) {
      if (seen.has(t.hash)) continue;
      seen.add(t.hash);
      const tw = Number(t.size) > 0 && Number(t.size) <= 8 ? Number(t.size) * 8 : 64;
      for (const v of t.detail.case === "enumeration" ? t.detail.value.values : [])
        if (BigInt.asUintN(tw, v.value) === BigInt.asUintN(tw, unsigned)) out.push({ member: v.name, enumName: t.name || t.display, enumHash: t.hash, program });
    }
  };
  for (const program of [true, false]) {
    try {
      const r = await rk.queries.findTypes({ programId, enumValue: signed, sources: program ? [TypeSource.PROGRAM] : [], page: { pageSize: 50 } });
      add(r.types, program);
    } catch {
      /* no suggestions from this source */
    }
  }
  return out;
}

export class EquateEditor {
  constructor(private host: EquateHost) {}

  private async run(label: string, bodies: Parameters<Edits["bodies"]>[1], done: (n: number) => string, failed: string): Promise<boolean> {
    try {
      const r = await this.host.edits.bodies(label, bodies);
      toast(done(r.seqs.length), { action: { label: "Undo", run: () => this.host.undo() } });
      await this.host.settle(r.revision);
      return true;
    } catch (e) {
      toast(`${failed}: ${errText(e)}`, { kind: "error" });
      return false;
    }
  }

  /** Convert: the scalar shows in `format` (null: as the disassembler prints it). */
  async convert(t: ScalarTarget, format: ScalarFormat | null) {
    const f = FORMATS.find((x) => x.format === format);
    const label = f ? `Convert ${t.text} to ${f.label.toLowerCase()} at ${where(t.address)}` : `Default display of ${t.text} at ${where(t.address)}`;
    const display: ScalarDisplay = format === null ? null : { format };
    await this.run(label, [Edits.operandDisplayBody(t, display)], () => label.replace(/^Convert/, "Converted"), "Convert failed");
  }

  /** Remove Equate (and any conversion): the scalar as the disassembler prints it. */
  async remove(t: ScalarTarget) {
    const label = `Remove equate ${t.text} at ${where(t.address)}`;
    await this.run(label, [Edits.operandDisplayBody(t, null)], () => `Removed ${t.text} at ${where(t.address)}`, "Remove equate failed");
  }

  /**
   * Set Equate (Ghidra's SetEquateDialog): a name, with the enum members
   * and the equates that have the scalar's value dropping down under the
   * field, and where it applies (this operand, every matching scalar in
   * the function, or in the program). The daemon's refusal (a name that
   * has another value) shows in the dialog, which stays open.
   */
  async setEquate(t: ScalarTarget) {
    const vtext = valueText(t);
    const members = enumMembers(this.host.rk, this.host.programId, t.value, t.bits);
    const equates = loadEquates(this.host.rk, this.host.programId).catch(() => [] as Equate[]);
    /** What a name means: an enum member's equate, or a plain one. */
    const resolve = async (name: string): Promise<ScalarDisplay> => {
      const m = (await members).find((x) => x.member === name);
      return m ? { equate: { name, enumTypeHash: m.enumHash, member: m.member } } : { equate: { name } };
    };
    const scope = (v: string | boolean | undefined) => (v === "function" ? EquateScope.FUNCTION : v === "program" ? EquateScope.PROGRAM : EquateScope.UNSPECIFIED);
    const suggest = async (text: string): Promise<Suggestion[]> => {
      const q = text.trim().toLowerCase();
      const out: Suggestion[] = [];
      for (const e of await equates)
        if (BigInt.asUintN(64, e.value) === BigInt.asUintN(64, t.value) && (!q || e.name.toLowerCase().includes(q)))
          out.push({ label: e.name, detail: `equate · ${e.uses.length} use${e.uses.length === 1 ? "" : "s"}`, insert: e.name });
      for (const m of await members)
        if ((!q || m.member.toLowerCase().includes(q)) && !out.some((o) => o.label === m.member))
          out.push({ label: m.member, detail: `enum ${m.enumName}${m.program ? "" : " · library"}`, insert: m.member });
      return out.slice(0, 40);
    };
    const res = await askEquate({
      title: `Set equate for ${vtext} at ${where(t.address)}${t.where === "decomp" ? " (decompiler constant)" : ""}`,
      value: t.displayed && IDENT.test(t.text) ? t.text : "",
      suggest,
      check: async (v, c) => {
        const name = v.trim();
        if (!IDENT.test(name)) return "A name: letters, digits and _ (not starting with a digit)";
        return this.host.edits.check(Edits.operandDisplayBody(t, await resolve(name), scope(c.scope)));
      },
    });
    if (!res) return;
    const name = res.value.trim();
    const display = await resolve(name);
    const applyTo = scope(res.controls.scope);
    const wide = applyTo === EquateScope.FUNCTION ? " in the function" : applyTo === EquateScope.PROGRAM ? " in the program" : "";
    const label = `Set equate ${name} = ${vtext} at ${where(t.address)}${wide}`;
    await this.run(label, [Edits.operandDisplayBody(t, display, applyTo)], (n) => `${name} = ${vtext}${n > 1 ? ` on ${n} operands` : ` at ${where(t.address)}`}`, "Set equate failed");
  }
}

function askEquate(o: { title: string; value: string; suggest: (v: string) => Promise<Suggestion[]>; check: (v: string, c: ControlValues) => Promise<string | null> }) {
  return askMore({
      title: o.title,
      value: o.value,
      placeholder: "a name, or an enum member (they drop down)",
      suggest: o.suggest,
      check: o.check,
      controls: [
        {
          kind: "radio",
          name: "scope",
          label: "Apply to",
          value: "operand",
          choices: [
            { label: "this operand", value: "operand" },
            { label: "matching scalars in the function", value: "function" },
            { label: "in the program", value: "program" },
          ],
        },
      ],
      hint: "Equates and enum members with this value drop down (↑↓, Tab or Enter takes one) · Enter to set · Esc to cancel",
  });
}

// ---------------------------------------------------------- the window --

/** The Equates window: name, value and uses; a selected equate's uses go
 * there on a click; rename and remove act on every use as one edit. */
export class EquatesView {
  private table: HTMLElement;
  private uses: HTMLElement;
  private status: HTMLElement;
  private renameBtn: HTMLButtonElement;
  private removeBtn: HTMLButtonElement;
  private stale = true;
  private loading = 0;
  equates: Equate[] = [];
  selected: string | null = null;

  constructor(
    readonly el: HTMLElement,
    private host: EquateHost,
  ) {
    this.status = h("span", { class: "dim", "data-testid": "equates-status" });
    this.table = h("div", { class: "eq-table", role: "listbox", "aria-label": "Equates", tabindex: "0", "data-testid": "equates-table" }, h("div", { class: "pp-empty dim", role: "option", "aria-disabled": "true" }, "Loading…"));
    this.uses = h("div", { class: "eq-uses", "data-testid": "equate-uses" });
    this.renameBtn = h("button", { class: "btn small", "data-testid": "equates-rename", text: "Rename…", disabled: true, title: "Rename the selected equate everywhere (one undo step)", onclick: () => void this.rename() });
    this.removeBtn = h("button", { class: "btn small", "data-testid": "equates-remove", text: "Remove", disabled: true, title: "Remove the selected equate everywhere (one undo step)", onclick: () => void this.remove() });
    el.replaceChildren(
      h(
        "div",
        { class: "panel-head pp-head" },
        h("span", { class: "panel-title" }, "Equates"),
        this.status,
        h("span", { class: "grow" }),
        this.renameBtn,
        this.removeBtn,
      ),
      h("div", { class: "eq-cols dim" }, h("span", {}, "Name"), h("span", {}, "Value"), h("span", {}, "Uses")),
      this.table,
      this.uses,
    );
    this.table.addEventListener("keydown", (e) => {
      const i = this.equates.findIndex((q) => q.key === this.selected);
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        const n = this.equates[Math.max(0, Math.min(this.equates.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
        if (n) this.select(n.key);
      } else if (e.key === "Enter") {
        const q = this.current();
        if (q?.uses[0]) this.host.navigate(q.uses[0].address);
      } else if (e.key === "F2") void this.rename();
      else if (e.key === "Delete") void this.remove();
      else return;
      e.preventDefault();
    });
  }

  focus() {
    this.table.focus({ preventScroll: true });
  }

  ensureLoaded() {
    if (this.stale) void this.load();
  }

  markStale() {
    this.stale = true;
  }

  /** Reloads when an event touched an equate (or marks stale when hidden). */
  onRevision(ev: RevisionEvent, visible: boolean) {
    if (!ev.changedKeys.some((k) => k.programId === this.host.programId && k.kind === FactKind.EQUATE)) return;
    if (visible) void this.load();
    else this.stale = true;
  }

  async load() {
    this.stale = false;
    const n = ++this.loading;
    try {
      const all = await loadEquates(this.host.rk, this.host.programId);
      if (n !== this.loading) return;
      this.equates = all;
      this.status.textContent = `${all.length} equate${all.length === 1 ? "" : "s"}`;
      if (this.selected !== null && !all.some((q) => q.key === this.selected)) this.selected = null;
      this.paint();
    } catch (e) {
      this.status.textContent = errText(e);
    }
  }

  private current(): Equate | undefined {
    return this.equates.find((q) => q.key === this.selected);
  }

  select(key: string) {
    this.selected = key;
    this.paint();
  }

  private paint() {
    this.renameBtn.disabled = this.removeBtn.disabled = !this.current();
    if (!this.equates.length) {
      this.table.replaceChildren(h("div", { class: "pp-empty dim", role: "option", "aria-disabled": "true" }, "No equates. Set one on a scalar with E (listing or decompiler), or right-click → Set equate…"));
      this.uses.replaceChildren();
      return;
    }
    this.table.replaceChildren(
      ...this.equates.map((q) =>
        h(
          "div",
          {
            class: "eq-row" + (q.key === this.selected ? " active" : ""),
            role: "option",
            "aria-selected": String(q.key === this.selected),
            "data-testid": "equate-row",
            "data-name": q.name,
            "data-key": q.key,
            onclick: () => this.select(q.key),
            ondblclick: () => q.uses[0] && this.host.navigate(q.uses[0].address),
          },
          h("span", { class: "mono eq-name", title: q.enumTypeHash ? `enum member ${q.member} (enum ${q.enumTypeHash.slice(0, 8)})` : q.name }, q.name),
          h("span", { class: "mono", "data-testid": "equate-value" }, `0x${hex(BigInt.asUintN(64, q.value))}`),
          h("span", { class: "mono", "data-testid": "equate-count" }, String(q.uses.length)),
        ),
      ),
    );
    const q = this.current();
    if (!q) {
      this.uses.replaceChildren(h("div", { class: "dim eq-hint" }, "Select an equate to see its uses."));
      return;
    }
    this.uses.replaceChildren(
      h("div", { class: "dim eq-hint" }, `${q.name}: ${q.uses.length} use${q.uses.length === 1 ? "" : "s"}${q.member ? ` (enum member ${q.member})` : ""}`),
      ...q.uses.map((u) =>
        h(
          "a",
          { class: "eq-use mono link", href: "#", "data-testid": "equate-use", "data-address": hex(u.address), onclick: (e: Event) => (e.preventDefault(), this.host.navigate(u.address)) },
          fmtAddr(u.address, this.host.addrWidth),
          h("span", { class: "dim" }, u.operandIndex !== undefined ? ` operand ${u.operandIndex}` : " decompiler constant"),
        ),
      ),
    );
  }

  /** Renames the selected equate on every use: one edit. */
  async rename() {
    const q = this.current();
    if (!q) return toast("Select an equate first");
    const name = await ask({
      title: `Rename equate ${q.name} (${q.uses.length} use${q.uses.length === 1 ? "" : "s"})`,
      value: q.name,
      validate: (v) => (IDENT.test(v.trim()) ? null : "A name: letters, digits and _ (not starting with a digit)"),
      check: (v) => this.host.edits.check(Edits.operandDisplayBody(q.uses[0], { equate: { name: v.trim() } })),
    });
    if (name === null || name.trim() === q.name) return;
    const to = name.trim();
    const label = `Rename equate ${q.name} to ${to} (${q.uses.length} use${q.uses.length === 1 ? "" : "s"})`;
    try {
      const r = await this.host.edits.bodies(label, q.uses.map((u) => Edits.operandDisplayBody(u, { equate: { name: to } })));
      this.selected = to; // a renamed equate is a plain name
      toast(`Renamed ${q.name} to ${to}`, { action: { label: "Undo", run: () => this.host.undo() } });
      await this.host.settle(r.revision);
    } catch (e) {
      toast(`Rename failed: ${errText(e)}`, { kind: "error" });
    }
  }

  /** Removes the selected equate from every use: one edit. */
  async remove() {
    const q = this.current();
    if (!q) return toast("Select an equate first");
    const label = `Remove equate ${q.name} (${q.uses.length} use${q.uses.length === 1 ? "" : "s"})`;
    try {
      const r = await this.host.edits.bodies(label, q.uses.map((u) => Edits.operandDisplayBody(u, null)));
      toast(`Removed ${q.name}`, { action: { label: "Undo", run: () => this.host.undo() } });
      await this.host.settle(r.revision);
    } catch (e) {
      toast(`Remove failed: ${errText(e)}`, { kind: "error" });
    }
  }
}
