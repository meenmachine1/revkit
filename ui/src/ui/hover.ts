// Hover cards (docs/ui.md, "Hover cards"): what is under the pointer in the
// listing or the decompiler, previewed after a short delay: a reference's
// target (a function's signature and first lines of C, sdk/ts preview.ts,
// or the listing rows there), a variable's or a type's definition (a struct's layout), a
// scalar in hex, decimal and as characters with the symbol at that address,
// and a function's signature. The provenance badge's sections follow
// (provenance.ts). Only existing read calls: GetFunction, Decompile,
// GetListing, GetTypes, ListSymbols, GetMemoryMap.

import { TypeKind, previewLines, scalarText, type EvaluateDebugResponse, type Revkit, type TypeDefinition } from "@revkit/api";
import { errText, hex } from "../data/format";
import { showName, showNameIn } from "../data/names";
import type { ListingRow } from "../data/types";
import { h } from "./dom";

export type Preview =
  /** A reference's target or a name's address. `signatureOnly`: a function's
   * signature without its C (the function shown already, a label). */
  | { kind: "target"; address: bigint; signatureOnly?: boolean }
  /** A type by hash (empty: by the name in `declared`, the C spelling a
   * variable's TypeRef has when the decompiler sends no hash); `field`: the
   * member at that offset is marked; `declared`: how the variable or data
   * item spells it. */
  | { kind: "type"; hash: string; field?: bigint; declared?: string; label?: string }
  /** A scalar: `value` as the operand or the constant holds it. */
  | { kind: "scalar"; value: bigint; bits: number }
  /** A call's signature override (feature call-signature-override): the prototype as C. */
  | { kind: "callsig"; text: string }
  /** A value in the debug session (feature debugger-values): a register,
   * an operand's memory, a decompiler variable through its storage. */
  | { kind: "value"; item: ValueItem; label: string; frame?: number };

/** What EvaluateDebug evaluates (DebugEvalItem's oneof, as a request takes it). */
export type ValueItem =
  | { case: "expression"; value: string }
  | { case: "operand"; value: { address: { offset: bigint }; operand: number } }
  | {
      case: "variable";
      value: {
        function: { offset: bigint };
        storage: { space: string; offset: bigint; size: number; registerName: string }[];
        type?: { hash: string; display: string };
        name: string;
        address?: { offset: bigint };
      };
    };

export interface HoverHost {
  rk: Revkit;
  programId: string;
  /** Listing rows from the code unit containing `address` on. */
  rowsAround(address: bigint, rows: number): Promise<ListingRow[]>;
  /** A listing row as the listing shows it, as text. */
  rowText(r: ListingRow): string;
  /** Evaluates in the debug session at the stop or snapshot shown (null: no stopped session). */
  debugValue?(item: ValueItem, frame?: number): Promise<EvaluateDebugResponse | null>;
}

/** Listing rows a data preview shows. */
export const PREVIEW_ROWS = 8;

function section(testid: string, title: string): { el: HTMLElement; body: HTMLElement; title: HTMLElement } {
  const t = h("div", { class: "prov-title dim" }, title);
  const body = h("div", { class: "hc-body" }, h("span", { class: "dim" }, "…"));
  const el = h("div", { class: "hc-section", "data-testid": testid }, t, body);
  return { el, body, title: t };
}

function code(lines: string[], testid = "hc-code"): HTMLElement {
  return h("pre", { class: "hc-code mono", "data-testid": testid }, lines.join("\n"));
}

/** Fills previews: each section shows at once and fills in when its read returns. */
export class HoverPreviews {
  constructor(private host: HoverHost) {}

  /** The section for `p`; `filled` runs after its content arrives. */
  render(p: Preview, filled: () => void, alive: () => boolean): HTMLElement {
    if (p.kind === "callsig") {
      // Known already: no read.
      const s = section("hc-callsig", "signature override (this call)");
      s.body.replaceChildren(code([p.text], "hc-callsig-code"));
      queueMicrotask(() => alive() && filled());
      return s.el;
    }
    const s =
      p.kind === "target"
        ? section("hc-target", `${hex(p.address)}`)
        : p.kind === "type"
          ? section("hc-type", p.label ?? "type")
          : p.kind === "value"
            ? section("hc-value-section", p.label)
            : section("hc-scalar", "scalar");
    const run = p.kind === "target" ? this.target(p, s) : p.kind === "type" ? this.type(p, s) : p.kind === "value" ? this.value(p, s) : this.scalar(p, s);
    void run
      .catch((e) => {
        s.body.replaceChildren(h("div", { class: "error" }, errText(e)));
      })
      .finally(() => {
        if (alive()) filled();
      });
    return s.el;
  }

  private async target(p: Extract<Preview, { kind: "target" }>, s: ReturnType<typeof section>) {
    const { rk, programId } = this.host;
    let fn;
    try {
      fn = (await rk.queries.getFunction({ programId, address: { offset: p.address } })).function;
    } catch {
      fn = undefined;
    }
    if (fn) {
      s.title.textContent = `function at ${hex(p.address)}`;
      const sig = h("div", { class: "hc-sig mono", "data-testid": "hc-signature" }, showNameIn(fn.prototype || fn.name, fn.name, fn.demangled));
      s.body.replaceChildren(sig);
      if (p.signatureOnly) return;
      const more = h("div", { class: "dim" }, "decompiling…");
      s.body.append(more);
      try {
        const r = await rk.queries.decompile({ programId, function: { offset: p.address }, options: { timeoutMs: 5000 } });
        if (r.function && !r.failure) {
          const lines = previewLines(r.function);
          // No prototype recorded: the decompiler's signature line.
          if (!fn.prototype && lines.length > 1) sig.textContent = lines[0];
          more.replaceWith(code(lines));
          return;
        }
      } catch {
        // The listing's rows instead.
      }
      const rows = await this.host.rowsAround(p.address, PREVIEW_ROWS);
      more.replaceWith(code(rows.map((r) => this.host.rowText(r)), "hc-rows"));
      return;
    }
    const rows = await this.host.rowsAround(p.address, PREVIEW_ROWS);
    const label = rows.find((r) => r.label && r.address === p.address)?.label;
    s.title.textContent = label ? `${label} at ${hex(p.address)}` : `at ${hex(p.address)}`;
    s.body.replaceChildren(rows.length ? code(rows.map((r) => this.host.rowText(r)), "hc-rows") : h("div", { class: "dim" }, "nothing at this address"));
  }

  private async type(p: Extract<Preview, { kind: "type" }>, s: ReturnType<typeof section>) {
    const { rk, programId } = this.host;
    const hash = p.hash || (await this.named(p.declared ?? ""));
    if (!hash) {
      s.body.replaceChildren(h("div", { class: "hc-sig mono", "data-testid": "hc-declared" }, p.declared ?? "unknown type"));
      return;
    }
    const r = await rk.queries.getTypes({ programId, hashes: [hash], includeDependencies: true });
    const byHash = new Map(r.types.map((t) => [t.hash, t]));
    const top = byHash.get(hash);
    if (!top) {
      s.body.replaceChildren(h("div", { class: "dim" }, p.declared ?? "unknown type"));
      return;
    }
    // Through pointers, arrays, typedefs and qualifiers to what has a layout.
    let t: TypeDefinition | undefined = top;
    for (let i = 0; t && i < 8; i++) {
      if (t.kind === TypeKind.STRUCT || t.kind === TypeKind.UNION || t.kind === TypeKind.ENUM) break;
      const d: TypeDefinition["detail"] = t.detail;
      const next: string =
        d.case === "pointer" ? d.value.targetHash : d.case === "array" ? d.value.elementHash : d.case === "typedefType" ? d.value.targetHash : d.case === "qualified" ? d.value.targetHash : "";
      t = next ? byHash.get(next) : undefined;
    }
    const parts: HTMLElement[] = [];
    const declared = p.declared ?? top.display;
    parts.push(h("div", { class: "hc-sig mono", "data-testid": "hc-declared" }, `${declared}${top.size ? `  (${top.size} bytes)` : ""}`));
    if (t && (t.kind === TypeKind.STRUCT || t.kind === TypeKind.UNION)) parts.push(this.layout(t, byHash, t === top ? p.field : undefined));
    else if (t && t.kind === TypeKind.ENUM) parts.push(this.enumeration(t));
    else if (top.cDefinition && top.cDefinition !== top.display) parts.push(code(top.cDefinition.split("\n")));
    s.body.replaceChildren(...parts);
  }

  /** The program's named type a C spelling names ("struct pair *p",
   * "const pair *" → pair), or "" (a builtin, or no such type). */
  private async named(declared: string): Promise<string> {
    const name = declared
      .replace(/\b(const|volatile|restrict|struct|union|enum|class)\b/g, " ")
      .replace(/\[[^\]]*\]/g, " ")
      .split("*")[0]
      .trim()
      .split(/\s+/)[0];
    if (!name || !/^[A-Za-z_][\w:<>,]*$/.test(name)) return "";
    const r = await this.host.rk.queries.findTypes({ programId: this.host.programId, nameContains: name, page: { pageSize: 50 } });
    const exact = r.types.filter((t) => t.name === name && !t.superseded);
    return (exact.find((t) => t.bound) ?? exact.find((t) => t.complete) ?? exact[0])?.hash ?? "";
  }

  /** A struct's or union's members: offset, type, name (and size). */
  private layout(t: TypeDefinition, byHash: Map<string, TypeDefinition>, field?: bigint): HTMLElement {
    const word = t.kind === TypeKind.UNION ? "union" : t.isClass ? "class" : "struct";
    const fields = t.detail.case === "composite" ? t.detail.value.fields : [];
    const rows = fields.map((f) => {
      const ft = byHash.get(f.typeHash);
      const bits = f.bitSize ? `:${f.bitSize}` : "";
      const mark = field !== undefined && f.offset === field;
      return h(
        "tr",
        { class: mark ? "hc-mark" : "", "data-testid": "hc-field", "data-name": f.name, ...(mark ? { "data-mark": "" } : {}) },
        h("td", { class: "dim" }, `+0x${f.offset.toString(16)}`),
        h("td", {}, ft?.display ?? "?"),
        h("td", {}, f.name + bits),
        h("td", { class: "dim" }, ft?.size ? String(ft.size) : ""),
      );
    });
    return h(
      "div",
      { class: "hc-layout" },
      h("div", { class: "mono" }, `${word} ${t.name || "(anonymous)"} {  // ${t.size} bytes${t.complete ? "" : ", not defined"}`),
      h("table", { class: "hc-fields mono", "data-testid": "hc-layout" }, ...rows),
      h("div", { class: "mono" }, "}"),
    );
  }

  private enumeration(t: TypeDefinition): HTMLElement {
    const values = t.detail.case === "enumeration" ? t.detail.value.values : [];
    return h(
      "table",
      { class: "hc-fields mono", "data-testid": "hc-layout" },
      h("tr", {}, h("td", { colspan: "2" }, `enum ${t.name} {`)),
      ...values.slice(0, 200).map((v) => h("tr", { "data-testid": "hc-field", "data-name": v.name }, h("td", {}, `  ${v.name}`), h("td", { class: "dim" }, `= ${v.value}`))),
      h("tr", {}, h("td", { colspan: "2" }, "}")),
    );
  }

  /** A value in the debug session: typed, with where it is and a struct's fields. */
  private async value(p: Extract<Preview, { kind: "value" }>, s: ReturnType<typeof section>) {
    const r = this.host.debugValue ? await this.host.debugValue(p.item, p.frame) : null;
    const v = r?.values[0];
    if (!r || !v) {
      s.body.replaceChildren(h("div", { class: "dim" }, "no stopped debug session"));
      return;
    }
    s.title.textContent = `${p.label} · frame #${r.frame}${r.function ? ` ${r.function}` : ""}${r.snapshot ? ` · snapshot ${r.snapshot}` : ""}`;
    const row = (k: string, val: string, testid: string) => h("tr", {}, h("td", { class: "dim" }, k), h("td", { class: "mono", "data-testid": testid }, val));
    if (v.error) {
      s.body.replaceChildren(h("div", { class: "dim", "data-testid": "hc-value-error" }, v.error));
      return;
    }
    const table = h("table", { class: "hc-fields" }, row("value", v.text, "hc-value"));
    if (v.type) table.append(row("type", v.type, "hc-value-type"));
    if (v.hex && v.hex !== v.text) table.append(row("hex", v.hex, "hc-value-hex"));
    const where = v.location || v.registerName || (v.address !== undefined ? hex(v.address) : "");
    if (where) table.append(row("at", where, "hc-value-at"));
    for (const c of v.children.slice(0, 12)) table.append(row(`  ${c.name}`, c.text, "hc-value-child"));
    if (v.children.length > 12) table.append(row("", `… ${v.children.length - 12} more`, "hc-value-more"));
    s.body.replaceChildren(table);
  }

  private async scalar(p: Extract<Preview, { kind: "scalar" }>, s: ReturnType<typeof section>) {
    const t = scalarText(p.value, p.bits);
    const row = (k: string, v: string, testid: string) => h("tr", {}, h("td", { class: "dim" }, k), h("td", { class: "mono", "data-testid": testid }, v));
    const table = h(
      "table",
      { class: "hc-fields" },
      row("hex", t.hex, "hc-hex"),
      row("decimal", t.unsigned === t.signed ? t.unsigned : `${t.unsigned} (signed ${t.signed})`, "hc-dec"),
      ...(t.chars ? [row("char", t.chars, "hc-char")] : []),
    );
    s.title.textContent = `scalar, ${p.bits || 64} bits`;
    s.body.replaceChildren(table);
    // What is at that address, if it is one.
    const { rk, programId } = this.host;
    const u = BigInt(t.unsigned);
    const [syms, map] = await Promise.all([
      rk.queries.listSymbols({ programId, range: { first: { offset: u }, last: { offset: u } }, page: { pageSize: 4 } }).catch(() => null),
      rk.queries.getMemoryMap({ programId }).catch(() => null),
    ]);
    const sym = syms?.symbols.find((x) => x.address?.offset === u);
    const block = map?.blocks.find((b) => b.range?.first && b.range.last && u >= b.range.first.offset && u <= b.range.last.offset);
    if (sym) table.append(row("symbol", showName(sym.name, sym.demangled), "hc-symbol"));
    if (block) table.append(row("address", `in ${block.name}`, "hc-block"));
  }
}
