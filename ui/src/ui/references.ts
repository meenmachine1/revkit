// User references (feature user-references; docs/ui.md "Equates and
// references"): Ghidra's References menu (Add reference from here, Delete,
// Set primary) and the References window for the code unit at the cursor:
// what it refers to and what refers to it, with each reference's type,
// operand, whether it is primary and who made it (the user, by their
// assertion, or analysis). Every action is one AppendAssertions call
// (a UserReference body), so one undo step; the window and the listing
// follow from the subscription's events.

import { FactKind, QueryKind, ReferenceType, XrefDirection, XrefKind, type Revkit, type RevisionEvent, type Xref } from "@revkit/api";
import { Edits, type ReferenceSpec } from "../data/edits";
import { errText, fmtAddr, hex, originClass, originText } from "../data/format";
import { askMore, choose, toast, type Suggestion } from "./dialogs";
import { h } from "./dom";

export interface ReferenceHost {
  rk: Revkit;
  programId: string;
  edits: Edits;
  addrWidth: number;
  settle: (revision: bigint) => Promise<void>;
  undo: () => void;
  navigate: (address: bigint) => void;
  /** An address or a symbol's name, as the palette reads it; null when neither. */
  resolve: (text: string) => Promise<bigint | null>;
}

/** The types Add offers, as Ghidra's RefType names them. */
export const REFERENCE_TYPES: { type: ReferenceType; id: string; label: string }[] = [
  { type: ReferenceType.DATA, id: "data", label: "Data (address taken)" },
  { type: ReferenceType.DATA_READ, id: "read", label: "Read" },
  { type: ReferenceType.DATA_WRITE, id: "write", label: "Write" },
  { type: ReferenceType.CALL, id: "call", label: "Call" },
  { type: ReferenceType.JUMP, id: "jump", label: "Jump" },
  { type: ReferenceType.COMPUTED_CALL, id: "computed-call", label: "Computed call" },
  { type: ReferenceType.COMPUTED_JUMP, id: "computed-jump", label: "Computed jump" },
];

/** An xref's kind as the type of a user reference at its key. */
export function referenceTypeOf(k: XrefKind): ReferenceType {
  switch (k) {
    case XrefKind.DATA_READ:
      return ReferenceType.DATA_READ;
    case XrefKind.DATA_WRITE:
      return ReferenceType.DATA_WRITE;
    case XrefKind.CALL:
      return ReferenceType.CALL;
    case XrefKind.JUMP:
    case XrefKind.CONDITIONAL_JUMP:
      return ReferenceType.JUMP;
    case XrefKind.INDIRECT_CALL:
      return ReferenceType.COMPUTED_CALL;
    case XrefKind.INDIRECT_JUMP:
      return ReferenceType.COMPUTED_JUMP;
    default:
      return ReferenceType.DATA;
  }
}

const KIND_TEXT: Record<number, string> = {
  [XrefKind.CALL]: "call",
  [XrefKind.JUMP]: "jump",
  [XrefKind.CONDITIONAL_JUMP]: "cjump",
  [XrefKind.INDIRECT_CALL]: "computed call",
  [XrefKind.INDIRECT_JUMP]: "computed jump",
  [XrefKind.DATA_READ]: "read",
  [XrefKind.DATA_WRITE]: "write",
  [XrefKind.DATA_POINTER]: "data",
  [XrefKind.THUNK]: "thunk",
  [XrefKind.FALLTHROUGH]: "fallthrough",
};

export const xrefKindText = (k: XrefKind) => KIND_TEXT[k] ?? "ref";

/** Who made a reference: the user's assertion ("user:alice"), or "analysis". */
export const xrefSource = (x: Xref) => (x.origin?.source.case === "asserted" ? originText(x.origin) : "analysis");

const at = (a: bigint) => `0x${hex(a)}`;

/** The key of the user reference an xref is (or would be). */
const specOf = (x: Xref): ReferenceSpec => ({ from: x.fromAddress?.offset ?? 0n, operandIndex: x.operandIndex, to: x.toAddress?.offset ?? 0n, type: referenceTypeOf(x.kind) });

const describe = (x: Xref) => `${at(x.fromAddress?.offset ?? 0n)} → ${x.toName || at(x.toAddress?.offset ?? 0n)} (${xrefKindText(x.kind)}${x.operandIndex !== undefined ? `, operand ${x.operandIndex}` : ""})`;

export class ReferenceEditor {
  constructor(private host: ReferenceHost) {}

  private async run(label: string, spec: ReferenceSpec, done: string, failed: string) {
    try {
      const r = await this.host.edits.bodies(label, [Edits.referenceBody(spec)]);
      toast(done, { action: { label: "Undo", run: () => this.host.undo() } });
      await this.host.settle(r.revision);
    } catch (e) {
      toast(`${failed}: ${errText(e)}`, { kind: "error" });
    }
  }

  /** The references from an instruction (GetXrefs FROM). */
  async from(address: bigint): Promise<Xref[]> {
    const r = await this.host.rk.queries.getXrefs({ programId: this.host.programId, location: { case: "address", value: { offset: address } }, direction: XrefDirection.FROM, page: { pageSize: 500 } });
    return r.xrefs;
  }

  /**
   * Add reference from here (Ghidra's References > Add): to an address or
   * a symbol, of a type, from the operand at the cursor or the instruction
   * as a whole, primary or not. The daemon's refusal shows in the dialog.
   */
  async add(from: bigint, operand: number | undefined, operands: { index: number; text: string }[]) {
    const ops = [...operands];
    if (operand !== undefined && !ops.some((o) => o.index === operand)) ops.push({ index: operand, text: "" });
    const spec = async (to: string, c: Record<string, string | boolean>): Promise<ReferenceSpec | string> => {
      const t = await this.host.resolve(to.trim());
      if (t === null) return `No address or symbol ${to.trim() || "given"}`;
      const type = REFERENCE_TYPES.find((x) => x.id === c.type)?.type ?? ReferenceType.DATA;
      return { from, operandIndex: c.operand === "insn" ? undefined : Number(c.operand), to: t, type, primary: c.primary === true };
    };
    const res = await askMore({
      title: `Add reference from ${at(from)}`,
      placeholder: "to: an address (0x401000) or a symbol",
      suggest: (v) => this.symbols(v),
      controls: [
        { kind: "select", name: "type", label: "Type", value: "data", choices: REFERENCE_TYPES.map((x) => ({ label: x.label, value: x.id })) },
        {
          kind: "select",
          name: "operand",
          label: "From",
          value: operand !== undefined ? String(operand) : "insn",
          choices: [...ops.map((o) => ({ label: `operand ${o.index}${o.text ? `: ${o.text}` : ""}`, value: String(o.index) })), { label: "the instruction (no operand)", value: "insn" }],
        },
        { kind: "check", name: "primary", label: "Primary (the operand shows the target's name; a computed call calls it)", value: false },
      ],
      check: async (v, c) => {
        const s = await spec(v, c);
        return typeof s === "string" ? s : this.host.edits.check(Edits.referenceBody(s));
      },
      hint: "Symbols drop down as you type · Enter to add · Esc to cancel",
    });
    if (!res) return;
    const s = await spec(res.value, res.controls);
    if (typeof s === "string") return toast(s, { kind: "error" });
    const what = REFERENCE_TYPES.find((x) => x.type === s.type)?.label.toLowerCase() ?? "reference";
    const label = `Add ${what} reference ${at(from)} → ${res.value.trim()}`;
    await this.run(label, s, `Added a reference from ${at(from)} to ${res.value.trim()}`, "Add reference failed");
  }

  /** Deletes a reference: the user's at its key and analysis's from → to. */
  async remove(x: Xref) {
    const label = `Delete reference ${describe(x)}`;
    await this.run(label, { ...specOf(x), remove: true }, `Deleted the reference ${describe(x)}`, "Delete reference failed");
  }

  /**
   * Makes a reference its operand's primary one (asserting it as the
   * user's), and the operand's other primary user references not primary,
   * as Ghidra keeps one primary reference per operand: one edit.
   */
  async setPrimary(x: Xref) {
    const label = `Set primary reference ${describe(x)}`;
    const bodies = [Edits.referenceBody({ ...specOf(x), primary: true })];
    try {
      for (const o of await this.from(x.fromAddress?.offset ?? 0n))
        if (o.primary && o.operandIndex === x.operandIndex && o.origin?.source.case === "asserted" && o.toAddress?.offset !== x.toAddress?.offset) bodies.push(Edits.referenceBody({ ...specOf(o), primary: false }));
    } catch {
      /* the new primary alone */
    }
    try {
      const r = await this.host.edits.bodies(label, bodies);
      toast(`Primary: ${describe(x)}`, { action: { label: "Undo", run: () => this.host.undo() } });
      await this.host.settle(r.revision);
    } catch (e) {
      toast(`Set primary failed: ${errText(e)}`, { kind: "error" });
    }
  }

  /** Picks one of the references from `address`, then acts on it. */
  async pick(address: bigint, verb: "delete" | "primary") {
    let xs: Xref[];
    try {
      xs = await this.from(address);
    } catch (e) {
      return toast(errText(e), { kind: "error" });
    }
    if (verb === "primary") xs = xs.filter((x) => !x.primary);
    if (!xs.length) return toast(verb === "delete" ? `No references from ${at(address)}` : `No reference from ${at(address)} to make primary`);
    const x = await choose(
      verb === "delete" ? `Delete a reference from ${at(address)}` : `Set the primary reference from ${at(address)}`,
      xs.map((x) => ({ label: `→ ${x.toName || at(x.toAddress?.offset ?? 0n)}`, detail: `${xrefKindText(x.kind)}${x.operandIndex !== undefined ? ` · operand ${x.operandIndex}` : ""}${x.primary ? " · primary" : ""} · ${xrefSource(x)}`, value: x })),
    );
    if (!x) return;
    return verb === "delete" ? this.remove(x) : this.setPrimary(x);
  }

  private async symbols(text: string): Promise<Suggestion[]> {
    const q = text.trim();
    if (q.length < 2 || /^(0x)?[0-9a-f]+$/i.test(q)) return [];
    try {
      const r = await this.host.rk.queries.listSymbols({ programId: this.host.programId, nameContains: q, page: { pageSize: 12 } });
      return r.symbols.map((s) => ({ label: s.name, detail: fmtAddr(s.address?.offset ?? 0n, this.host.addrWidth), insert: s.name }));
    } catch {
      return [];
    }
  }
}

// ---------------------------------------------------------- the window --

/** The References window: the code unit at the cursor's references from
 * and to it, with Delete and Set primary, navigable by a click. */
export class ReferencesView {
  private body: HTMLElement;
  private title: HTMLElement;
  private stale = true;
  private loading = 0;
  address: bigint | null = null;
  fromRefs: Xref[] = [];
  toRefs: Xref[] = [];

  constructor(
    readonly el: HTMLElement,
    private host: ReferenceHost,
    private editor: ReferenceEditor,
    /** The cursor's operand, for Add (undefined: the instruction). */
    private operand: () => { operand: number | undefined; operands: { index: number; text: string }[] },
  ) {
    this.title = h("span", { class: "dim", "data-testid": "refs-at" });
    this.body = h("div", { class: "rw-body", "data-testid": "refs-body" });
    el.replaceChildren(
      h(
        "div",
        { class: "panel-head pp-head" },
        h("span", { class: "panel-title" }, "References"),
        this.title,
        h("span", { class: "grow" }),
        h("button", {
          class: "btn small",
          "data-testid": "refs-add",
          text: "Add…",
          title: "Add a reference from this instruction (R)",
          onclick: () => {
            if (this.address === null) return;
            const o = this.operand();
            void this.editor.add(this.address, o.operand, o.operands);
          },
        }),
      ),
      this.body,
    );
  }

  /** The cursor moved: show its code unit's references (when shown). */
  follow(address: bigint | null, visible: boolean) {
    if (address === this.address && !this.stale) return;
    this.address = address;
    if (visible) void this.load();
    else this.stale = true;
  }

  ensureLoaded() {
    if (this.stale) void this.load();
  }

  markStale() {
    this.stale = true;
  }

  /** References changed (an xrefs invalidation, a REFERENCE assertion): reload. */
  onRevision(ev: RevisionEvent, visible: boolean) {
    const hit =
      ev.invalidated.some((q) => q.programId === this.host.programId && (q.kind === QueryKind.XREFS || q.kind === QueryKind.LISTING)) ||
      ev.changedKeys.some((k) => k.programId === this.host.programId && k.kind === FactKind.REFERENCE);
    if (!hit) return;
    if (visible) void this.load();
    else this.stale = true;
  }

  async load() {
    this.stale = false;
    const a = this.address;
    const n = ++this.loading;
    if (a === null) {
      this.title.textContent = "";
      this.body.replaceChildren(h("div", { class: "pp-empty dim" }, "Select a code unit in the listing."));
      return;
    }
    try {
      const r = await this.host.rk.queries.getXrefs({ programId: this.host.programId, location: { case: "address", value: { offset: a } }, direction: XrefDirection.BOTH, page: { pageSize: 1000 } });
      if (n !== this.loading) return;
      this.fromRefs = r.xrefs.filter((x) => x.direction === XrefDirection.FROM);
      this.toRefs = r.xrefs.filter((x) => x.direction !== XrefDirection.FROM);
      this.title.textContent = `at ${fmtAddr(a, this.host.addrWidth)}`;
      this.paint();
    } catch (e) {
      if (n === this.loading) this.title.textContent = errText(e);
    }
  }

  private paint() {
    const section = (title: string, dir: "from" | "to", xs: Xref[]) =>
      h(
        "div",
        { class: "rw-section", "data-testid": `refs-${dir}` },
        h("div", { class: "rw-title dim" }, `${title} (${xs.length})`),
        ...(xs.length ? xs.map((x) => this.row(x, dir)) : [h("div", { class: "dim rw-none" }, "none")]),
      );
    this.body.replaceChildren(section("From here", "from", this.fromRefs), section("To here", "to", this.toRefs));
  }

  private row(x: Xref, dir: "from" | "to") {
    const other = dir === "from" ? (x.toAddress?.offset ?? 0n) : (x.fromAddress?.offset ?? 0n);
    const name = dir === "from" ? x.toName : x.fromFunctionName;
    const src = xrefSource(x);
    return h(
      "div",
      {
        class: "rw-row",
        "data-testid": "ref-row",
        "data-to": hex(x.toAddress?.offset ?? 0n),
        "data-from": hex(x.fromAddress?.offset ?? 0n),
        "data-kind": xrefKindText(x.kind),
        "data-source": src,
        "data-primary": x.primary ? "1" : "0",
      },
      h(
        "div",
        { class: "rw-main" },
        h("a", { class: "mono link", href: "#", title: `Go to ${at(other)}`, onclick: (e: Event) => (e.preventDefault(), this.host.navigate(other)) }, fmtAddr(other, this.host.addrWidth)),
        h("span", { class: "rw-name mono" }, name || ""),
        h("span", { class: "rw-primary", title: x.primary ? "the operand's primary reference" : "" }, x.primary ? "★ primary" : ""),
      ),
      h(
        "div",
        { class: "rw-sub" },
        h("span", { class: "badge b-xref" }, xrefKindText(x.kind)),
        h("span", { class: "dim" }, x.operandIndex !== undefined ? `operand ${x.operandIndex}` : "instruction"),
        h("span", { class: `badge b-${originClass(x.origin)}`, "data-testid": "ref-source" }, src),
        h("span", { class: "grow" }),
        x.primary ? null : h("button", { class: "btn small", "data-testid": "ref-primary", text: "Set primary", title: "Make this the operand's primary reference", onclick: () => void this.editor.setPrimary(x) }),
        h("button", { class: "btn small", "data-testid": "ref-delete", text: "Delete", title: "Delete this reference", onclick: () => void this.editor.remove(x) }),
      ),
    );
  }
}
