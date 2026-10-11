// Provenance badge: hover a name or comment (or press i) to see who or what
// set it, from Blame. An asserted value can be undone from here, which
// appends a retraction. Hovering shows it in a hover card, after the
// previews of what is under the pointer (hover.ts).

import { AssertionOp, AssertionStatus, FactKind, InstructionSet, Mutability, ReferenceType, ScalarFormat, StringEncoding, StringLayout, type Assertion, type BlameResponse, type OperandDisplay, type Revkit, type UserReference } from "@revkit/api";
import { ago, errText, originClass, originText, provBadge } from "../data/format";
import { h, placeNear } from "./dom";
import type { HoverPreviews, Preview } from "./hover";

/** How long the pointer rests on something before its hover card shows. */
export const HOVER_DELAY_MS = 450;

/** What a hover card shows (hover.ts): previews, then who set the fact. */
export interface HoverSubject {
  /** Identity: the card stays while the pointer moves within one thing. */
  key: string;
  title?: string;
  previews: Preview[];
  fact: FactRef | null;
}

export interface FactRef {
  kind: FactKind;
  address: bigint;
  sub?: string;
  /** What the user sees ("main", "local bVar1", "comment"). */
  label: string;
  /** Derived facts with no key to blame (analyzer plugins'): shown as they are. */
  derived?: { rule: string; text: string }[];
  /** The winning assertion, when `sub` isn't known (a Clear's or a
   * mutability edit's key holds its length): its key is looked up. */
  seq?: bigint;
}

const MUTABILITY_NAME: Record<number, string> = {
  [Mutability.DEFAULT]: "default",
  [Mutability.NORMAL]: "writable",
  [Mutability.CONSTANT]: "constant",
  [Mutability.VOLATILE]: "volatile",
};

/** A listing edit, in words ("clear 12 bytes", "define dword[4]", "disassemble (Thumb)"). */
export function listingEditText(b: Assertion["body"]): string {
  const k = b?.kind;
  if (k?.case === "mutability") return `${MUTABILITY_NAME[k.value.mutability] ?? "mutability"} (${k.value.length} bytes)`;
  if (k?.case === "operandDisplay") return operandDisplayText(k.value);
  if (k?.case === "reference") return referenceText(k.value);
  if (k?.case !== "listingEdit") return "";
  const e = k.value.kind;
  switch (e.case) {
    case "clear":
      return `clear ${e.value.length} bytes`;
    case "disassemble": {
      const isa = e.value.instructionSet === InstructionSet.ARM ? " (ARM)" : e.value.instructionSet === InstructionSet.THUMB ? " (Thumb)" : "";
      return `disassemble${isa}${e.value.function ? " + function" : ""}`;
    }
    case "data": {
      const d = e.value;
      if (d.string !== StringEncoding.UNSPECIFIED) {
        const enc = d.string === StringEncoding.UTF16 ? "UTF-16 " : d.string === StringEncoding.UTF32 ? "UTF-32 " : "";
        const lay = d.layout === StringLayout.PASCAL ? "Pascal " : d.layout === StringLayout.PASCAL16 ? "Pascal16 " : d.layout === StringLayout.FIXED ? `${d.count}-char ` : "";
        return `define ${lay}${enc}string`;
      }
      const t = d.typeName || (d.type?.kind.case === "cDeclaration" ? d.type.kind.value : "data");
      return `define ${t}${d.count ? `[${d.count}]` : ""}${d.collapsed === undefined ? "" : d.collapsed ? " (collapsed)" : " (expanded)"}`;
    }
  }
  return "listing edit";
}

const FORMAT_NAME: Record<number, string> = {
  [ScalarFormat.HEX]: "hex",
  [ScalarFormat.SIGNED_DECIMAL]: "signed decimal",
  [ScalarFormat.UNSIGNED_DECIMAL]: "unsigned decimal",
  [ScalarFormat.OCTAL]: "octal",
  [ScalarFormat.BINARY]: "binary",
  [ScalarFormat.CHAR]: "char",
  [ScalarFormat.FLOAT]: "float",
};

/** An equate or a conversion, in words ("equate GK_LETTER = 0x41 at operand 1", "0x41 as char"). */
function operandDisplayText(d: OperandDisplay): string {
  const v = `0x${d.value.toString(16)}`;
  const op = d.operandIndex !== undefined ? ` (operand ${d.operandIndex})` : d.constantHash ? " (decompiler constant)" : "";
  if (d.display.case === "equate") return `equate ${d.display.value.name}${d.display.value.member && d.display.value.member !== d.display.value.name ? ` (${d.display.value.member})` : ""} = ${v}${op}`;
  if (d.display.case === "format" && d.display.value !== ScalarFormat.UNSPECIFIED) return `${v} as ${FORMAT_NAME[d.display.value] ?? "a format"}${op}`;
  return `${v} as disassembled${op}`;
}

const REF_TYPE_NAME: Record<number, string> = {
  [ReferenceType.DATA]: "data",
  [ReferenceType.DATA_READ]: "read",
  [ReferenceType.DATA_WRITE]: "write",
  [ReferenceType.CALL]: "call",
  [ReferenceType.JUMP]: "jump",
  [ReferenceType.COMPUTED_CALL]: "computed call",
  [ReferenceType.COMPUTED_JUMP]: "computed jump",
};

/** A user reference, in words ("call reference → 0x401000 (operand 0, primary)", "deleted reference → 0x401000"). */
function referenceText(r: UserReference): string {
  const to = `0x${(r.to?.offset ?? 0n).toString(16)}`;
  const op = r.operandIndex !== undefined ? `operand ${r.operandIndex}` : "instruction";
  if (r.remove) return `deleted reference → ${to} (${op})`;
  return `${REF_TYPE_NAME[r.type] ?? ""} reference → ${to} (${op}${r.primary ? ", primary" : ""})`.trimStart();
}

const STATUS: Record<number, string> = {
  [AssertionStatus.EFFECTIVE]: "effective",
  [AssertionStatus.SHADOWED]: "shadowed",
  [AssertionStatus.RETRACTED]: "retracted",
  [AssertionStatus.DEPENDENCY_DEAD]: "dead",
};

function valueOf(a: Assertion): string {
  const b = a.body?.kind;
  if (!b) return "";
  switch (b.case) {
    case "rename":
      return b.value.name || "(default)";
    case "comment":
      return b.value.text || "(deleted)";
    case "retype":
      return b.value.type?.kind.case === "cDeclaration" ? b.value.type.kind.value : `type ${b.value.type?.kind.value ?? ""}`;
    case "functionBounds":
      return b.value.remove ? "(no function)" : "function";
    case "flowOverride":
      return ["", "none", "branch", "call", "call-return", "return"][b.value.kind] ?? "override";
    case "note":
      return `${b.value.tag}: ${b.value.text || "(cleared)"}`;
    case "callSignature":
      return b.value.signature?.kind.case === "cDeclaration" ? b.value.signature.kind.value : b.value.signature ? `type ${b.value.signature.kind.value ?? ""}` : "(removed)";
    case "listingEdit":
    case "mutability":
    case "operandDisplay":
    case "reference":
      return listingEditText(a.body);
    default:
      return b.case ?? "";
  }
}

const UNDO_WHAT: Partial<Record<FactKind, string>> = {
  [FactKind.NAME]: "name",
  [FactKind.COMMENT]: "comment",
  [FactKind.TYPE]: "type",
  [FactKind.FLOW_OVERRIDE]: "flow override",
  [FactKind.FUNCTION_BOUNDS]: "function",
  [FactKind.NOTE]: "note",
  [FactKind.CODE_UNIT]: "listing edit",
  [FactKind.MUTABILITY]: "mutability",
  [FactKind.EQUATE]: "equate",
  [FactKind.REFERENCE]: "reference",
};

function when(a: Assertion): string {
  const t = a.time;
  return t ? ago(Number(t.seconds) * 1000) : `rev ${a.revision}`;
}

export class ProvenancePopover {
  private el: HTMLElement | null = null;
  private showTimer = 0;
  private hideTimer = 0;
  private seq = 0;
  private over = false;
  /** The fact currently shown (or scheduled). */
  private current: string | null = null;
  onUndo: ((seq: bigint, label: string) => Promise<void>) | null = null;
  /** Fills the hover cards' previews (hover.ts); none: provenance only. */
  previews: HoverPreviews | null = null;

  constructor(
    private rk: Revkit,
    private programId: string,
  ) {}

  private key(f: FactRef) {
    return `${f.kind}|${f.address}|${f.sub ?? ""}`;
  }

  /** Pointer entered something with a hover card (hover.ts): show it after
   * a short delay. */
  hover(s: HoverSubject | null, x: number, y: number) {
    clearTimeout(this.showTimer);
    if (!s || (!s.fact && !s.previews.length)) {
      this.scheduleHide();
      return;
    }
    // Something else to show: a hide scheduled when the pointer left the
    // last thing mustn't take the new card away (or stop it showing).
    clearTimeout(this.hideTimer);
    if (s.key === this.current && this.el) return;
    this.current = s.key;
    this.showTimer = window.setTimeout(() => this.showCard(s, x, y + 18), HOVER_DELAY_MS);
  }

  /**
   * The hover card: the previews (each filled in as its read returns), then
   * who set the fact (the badge's sections). It never takes the focus; it
   * scrolls when long; Escape or leaving it closes it.
   */
  private showCard(s: HoverSubject, x: number, y: number) {
    clearTimeout(this.hideTimer);
    const seq = ++this.seq;
    this.current = s.key;
    const prov = s.fact ? h("div", { class: "hc-prov", "data-testid": "provenance" }, h("span", { class: "dim" }, "…")) : null;
    let el: HTMLElement | null = null;
    const alive = () => this.el !== null && this.el === el && seq === this.seq;
    const fit = () => {
      if (!alive() || !el) return;
      const r = el.getBoundingClientRect();
      if (r.bottom > innerHeight - 4 || r.right > innerWidth - 4) placeNear(el, x, y);
    };
    const previews = this.previews ? s.previews.map((p) => this.previews!.render(p, fit, alive)) : [];
    el = h(
      "div",
      { class: "popover prov hover-card", role: "tooltip", "data-testid": "hover", "data-key": s.key },
      ...(s.title ? [h("div", { class: "hc-head mono", "data-testid": "hc-head" }, s.title)] : []),
      ...previews,
      ...(prov ? [prov] : []),
    );
    this.mount(el, x, y);
    if (prov && s.fact)
      void this.provenance(s.fact, []).then((parts) => {
        if (!alive()) return;
        prov.replaceChildren(...parts);
        fit();
      });
  }

  private scheduleHide() {
    clearTimeout(this.hideTimer);
    this.hideTimer = window.setTimeout(() => {
      if (!this.over) this.hide();
    }, 250);
  }

  hide() {
    clearTimeout(this.showTimer);
    this.el?.remove();
    this.el = null;
    this.current = null;
    this.over = false;
  }

  get isOpen() {
    return this.el !== null;
  }

  /** Shows `f`, and below it the other facts about the same row (`more`:
   * the listing edit that says what it is, its mutability). */
  async show(f: FactRef, x: number, y: number, more: FactRef[] = []) {
    // A hide scheduled before (a menu opening) must not take this one away.
    clearTimeout(this.hideTimer);
    const seq = ++this.seq;
    this.current = this.key(f);
    const parts = await this.provenance(f, more);
    if (seq !== this.seq) return;
    this.mount(h("div", { class: "popover prov", role: "tooltip", "data-testid": "provenance" }, ...parts), x, y);
  }

  /** The badge's sections: who set `f` (and `more`), its value and history. */
  private async provenance(f: FactRef, more: FactRef[]): Promise<HTMLElement[]> {
    if (f.derived) return this.derivedParts(f);
    const all = await Promise.all(
      [f, ...more].map(async (ref) => {
        try {
          const k = await this.resolve(ref);
          const r = await this.rk.assertions.blame({ key: { programId: this.programId, kind: k.kind, address: { offset: k.address }, sub: k.sub ?? "" } });
          return { f: k, r, error: null };
        } catch (e) {
          return { f: ref, r: null, error: errText(e) };
        }
      }),
    );
    return all.map(({ f, r, error }, i) =>
      h(
        "div",
        { class: "prov-section" + (i ? " prov-more" : ""), "data-testid": "prov-section", "data-kind": String(f.kind) },
        h("div", { class: "prov-title dim" }, f.label),
        ...this.section(f, r, error),
      ),
    );
  }

  /** The key of a fact known by its winning assertion (FactRef.seq). */
  private async resolve(f: FactRef): Promise<FactRef> {
    if (f.sub !== undefined || f.seq === undefined) return f;
    let token = "";
    for (let page = 0; page < 20; page++) {
      const r = await this.rk.assertions.listAssertions({
        programId: this.programId,
        filter: { kinds: [f.kind], range: { first: { offset: 0n }, last: { offset: f.address } } },
        page: { pageSize: 1000, pageToken: token },
      });
      const a = r.assertions.find((x) => x.seq === f.seq);
      if (a?.key) return { ...f, address: a.key.address?.offset ?? f.address, sub: a.key.sub };
      token = r.page?.nextPageToken ?? "";
      if (!token) break;
    }
    throw new Error(`assertion ${f.seq} not found`);
  }

  private derivedParts(f: FactRef): HTMLElement[] {
    return [
      h("div", { class: "prov-title dim" }, f.label),
      ...(f.derived ?? []).map((d) =>
        h("div", { class: "prov-head" }, h("span", { class: "badge b-agent", "data-testid": "prov-who" }, d.rule), h("span", { class: "prov-value mono" }, d.text)),
      ),
      h("div", { class: "prov-meta dim" }, "derived by an analyzer plugin: recomputed when what it read changes, never asserted"),
    ];
  }

  /** Shows `el` at (x, y), replacing what was shown; the pointer over it keeps it. */
  private mount(el: HTMLElement, x: number, y: number) {
    this.el?.remove();
    this.over = false;
    el.addEventListener("mouseenter", () => {
      this.over = true;
      clearTimeout(this.hideTimer);
    });
    el.addEventListener("mouseleave", () => {
      this.over = false;
      this.scheduleHide();
    });
    document.body.append(el);
    placeNear(el, x, y);
    this.el = el;
  }

  /** One fact's part of the popover: who, the value, history, undo. */
  private section(f: FactRef, r: BlameResponse | null, error: string | null): HTMLElement[] {
    const body: HTMLElement[] = [];
    if (error || !r) body.push(h("div", { class: "error" }, error ?? "unavailable"));
    else {
      const o = r.origin;
      const cls = originClass(o);
      const winner = r.candidates.find((c) => c.status === AssertionStatus.EFFECTIVE && c.op === AssertionOp.ASSERT);
      body.push(
        h(
          "div",
          { class: "prov-head" },
          h("span", { class: `badge b-${cls}`, "data-testid": "prov-who" }, cls === "derived" ? "derived" : cls === "none" ? "none" : originText(o)),
          h("span", { class: "prov-value mono" }, r.valueText || (winner ? valueOf(winner) : "") || "(no value)"),
        ),
      );
      const meta: string[] = [];
      if (o?.source.case === "derived") meta.push(`rule ${o.source.value.rule}`, `confidence ${o.source.value.confidence.toFixed(2)}`);
      if (winner) {
        meta.push(when(winner));
        if (winner.provenance?.tool) meta.push(`via ${winner.provenance.tool}`);
      }
      if (meta.length) body.push(h("div", { class: "prov-meta dim" }, meta.join(" · ")));
      if (winner?.provenance?.reason) body.push(h("div", { class: "prov-reason" }, `“${winner.provenance.reason}”`));
      const ported = winner?.portedFrom;
      if (ported?.programId)
        body.push(
          h(
            "div",
            { class: "prov-ported dim", "data-testid": "prov-ported" },
            `ported from ${ported.programId} @ ${(ported.address?.offset ?? 0n).toString(16)} · comparison ${ported.sessionId} · run ${ported.runId}`,
          ),
        );
      const others = r.candidates.filter((c) => c !== winner);
      if (others.length) {
        body.push(
          h(
            "div",
            { class: "prov-hist" },
            ...others.slice(0, 6).map((c) =>
              h("div", { class: "prov-cand" }, h("span", { class: "st" }, STATUS[c.status] ?? "?"), h("span", { class: "mono" }, valueOf(c)), h("span", { class: "dim" }, `${provBadge(c.provenance)} · ${when(c)}`)),
            ),
          ),
        );
      }
      if (winner && this.onUndo) {
        const undo = this.onUndo;
        body.push(
          h(
            "div",
            { class: "prov-actions" },
            h("button", {
              class: "btn",
              "data-testid": "prov-undo",
              text: `Undo ${UNDO_WHAT[f.kind] ?? "edit"} (retract)`,
              onclick: async () => {
                this.hide();
                await undo(winner.seq, f.label);
              },
            }),
          ),
        );
      }
    }
    return body;
  }
}
