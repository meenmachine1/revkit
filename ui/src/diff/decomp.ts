// Both functions decompiled, side by side (docs/ui.md "Compare"). A line
// is highlighted when one of its tokens was printed from an instruction
// that changed (amber), was deleted (red, A) or inserted (green, B): the
// decompiler's tokens carry their instruction's address, and the
// instruction map says what happened to it. Lines align by LCS over their
// text (variables and default names like FUN_00401000 abstracted, since a
// rename or moved code changes them), unaligned ones get a gap on the
// other side.
//
// Token-level apply (feature function-compare): the daemon pairs the two
// functions' variables (CompareFunctions with markup), so a variable's
// name or type, the function's name or signature, or a comment can be
// carried to the other side from a token's context menu (right-click),
// one undo step each; "Apply all" carries everything someone set on one
// side to what the other side lacks (PortFunctionMarkup).

import {
  CodeTokenKind,
  FunctionMarkupKind,
  type CompareMarkup,
  type CompareVariable,
  type CompareVariablePair,
  type DecompiledFunction,
  type PortFunctionMarkupResponse,
  type Revkit,
} from "@revkit/api";
import { userProvenance } from "../api/client";
import { errText } from "../data/format";
import { toast } from "../ui/dialogs";
import { h } from "../ui/dom";
import { showMenu, type MenuItem } from "../ui/menu";
import { DiffLineStatus, type PairDetail } from "./detail";

interface CToken {
  text: string;
  kind: CodeTokenKind;
  /** A variable's storage key (its identity for porting). */
  varKey?: string;
  address?: bigint;
  target?: bigint;
}

interface CLine {
  text: string;
  key: string;
  tokens: CToken[];
  addresses: bigint[];
  status: "eq" | "chg" | "ins" | "del";
}

const KIND_CLASS: Partial<Record<CodeTokenKind, string>> = {
  [CodeTokenKind.KEYWORD]: "k-kw",
  [CodeTokenKind.TYPE]: "k-ty",
  [CodeTokenKind.FUNCTION_NAME]: "k-fn",
  [CodeTokenKind.CONSTANT]: "k-co",
  [CodeTokenKind.STRING]: "k-st",
  [CodeTokenKind.COMMENT]: "k-cm",
  [CodeTokenKind.GLOBAL_VARIABLE]: "k-gv",
};

export interface DiffCHost {
  rk: Revkit;
  projectId: string;
  /** The daemon pairs variables and ports markup (feature function-compare). */
  port: boolean;
  /** Markup was ported: what undoes it (retracting `seqs` on `toProgram`). */
  onPorted?: (r: { toProgram: string; seqs: bigint[]; label: string; revision: bigint }) => void;
}

/** What was ported, in words: "1 name, 2 variable names". */
export function portedText(r: PortFunctionMarkupResponse): string {
  const parts: [number, string][] = [
    [r.names, "name"],
    [r.signatures, "signature"],
    [r.variableNames, "variable name"],
    [r.variableTypes, "variable type"],
    [r.comments, "comment"],
    [r.globals, "global's name or type"],
    [r.callees, "callee's name or signature"],
  ];
  return parts.filter(([n]) => n > 0).map(([n, w]) => `${n} ${w}${n === 1 ? "" : "s"}`).join(", ");
}

type PortItem = { kind: FunctionMarkupKind; variable?: string; address?: { offset: bigint } };

const cache = new Map<string, DecompiledFunction>();

export class DiffCView {
  readonly el: HTMLElement;
  private body: HTMLElement;
  private head: HTMLElement;
  private pd: PairDetail | null = null;
  private seq = 0;
  private lines: [CLine[], CLine[]] = [[], []];
  private fns: [DecompiledFunction | undefined, DecompiledFunction | undefined] = [undefined, undefined];
  private rows: HTMLElement[] = [];
  private markup: CompareMarkup | null = null;
  /** Variable pairs by each side's storage key. */
  private vars: [Map<string, CompareVariablePair>, Map<string, CompareVariablePair>] = [new Map(), new Map()];
  onSelect: ((side: "a" | "b", address: bigint) => void) | null = null;

  constructor(private host: DiffCHost) {
    this.head = h("div", { class: "dc-head dim", "data-testid": "diff-c-head" });
    this.body = h("div", { class: "dc-body", "data-testid": "diff-c" });
    this.el = h("div", { class: "dc" }, this.head, this.body);
    this.body.addEventListener("mousedown", (e) => {
      if (e.button !== 0) return;
      const cell = (e.target as HTMLElement).closest<HTMLElement>("[data-side][data-i]");
      if (!cell) return;
      const side = cell.dataset.side as "a" | "b";
      const l = this.lines[side === "a" ? 0 : 1][Number(cell.dataset.i)];
      if (l?.addresses.length) this.onSelect?.(side, l.addresses.reduce((m, x) => (x < m ? x : m)));
    });
    this.body.addEventListener("contextmenu", (e) => {
      const cell = (e.target as HTMLElement).closest<HTMLElement>("[data-side][data-i]");
      if (!cell || !this.pd || !this.host.port) return;
      e.preventDefault();
      const side = cell.dataset.side as "a" | "b";
      const tok = (e.target as HTMLElement).closest<HTMLElement>("[data-k]");
      showMenu(this.menu(side, Number(cell.dataset.i), tok ? Number(tok.dataset.k) : -1), e.clientX, e.clientY, "Apply to the other side");
    });
  }

  async set(pd: PairDetail | null, message = "", force = false) {
    const seq = ++this.seq;
    if (pd === this.pd && this.rows.length && !force) return;
    this.pd = pd;
    this.rows = [];
    this.markup = null;
    this.vars = [new Map(), new Map()];
    this.head.replaceChildren();
    if (!pd || pd.pair.a < 0n || pd.pair.b < 0n) {
      this.body.replaceChildren(h("div", { class: "dim diff-empty" }, message || (pd ? "Only one side: nothing to compare." : "Select a match to see both functions decompiled.")));
      return;
    }
    this.body.replaceChildren(h("div", { class: "dim diff-empty" }, "Decompiling both functions…"));
    let fa: DecompiledFunction | undefined, fb: DecompiledFunction | undefined;
    let markup: CompareMarkup | null = null;
    try {
      const m = this.host.port
        ? this.host.rk.diff
            .compareFunctions({
              projectId: this.host.projectId,
              sessionId: pd.pair.sessionId,
              programA: pd.pair.sessionId ? "" : pd.pair.programA,
              programB: pd.pair.sessionId ? "" : pd.pair.programB,
              entryA: { offset: pd.pair.a },
              entryB: { offset: pd.pair.b },
              markup: true,
              omitBytes: true,
            })
            .then((r) => r.markup ?? null)
            .catch(() => null)
        : Promise.resolve(null);
      [fa, fb, markup] = await Promise.all([this.decompile(pd.pair.programA, pd.pair.a), this.decompile(pd.pair.programB, pd.pair.b), m]);
    } catch (e) {
      if (seq === this.seq) this.body.replaceChildren(h("div", { class: "error diff-empty" }, errText(e)));
      return;
    }
    if (seq !== this.seq) return;
    this.markup = markup;
    for (const p of markup?.variables ?? []) {
      if (p.a) this.vars[0].set(p.a.storageKey, p);
      if (p.b) this.vars[1].set(p.b.storageKey, p);
    }
    const d = pd.detail;
    const status = (rows: typeof d.rowsA) => {
      const m = new Map<bigint, DiffLineStatus>();
      for (const r of rows) if (r.address) m.set(r.address.offset, r.status);
      return m;
    };
    this.fns = [fa, fb];
    this.lines = [lines(fa, status(d.rowsA)), lines(fb, status(d.rowsB))];
    this.paint();
  }

  private async decompile(programId: string, entry: bigint): Promise<DecompiledFunction | undefined> {
    const k = `${programId}|${entry}`;
    const hit = cache.get(k);
    if (hit) return hit;
    const r = await this.host.rk.queries.decompile({ programId, function: { offset: entry } });
    if (r.function) {
      cache.set(k, r.function);
      if (cache.size > 32) cache.delete(cache.keys().next().value!);
    }
    return r.function;
  }

  private paint() {
    const [la, lb] = this.lines;
    const pairs = align(la, lb);
    const out: HTMLElement[] = [];
    let changed = 0;
    for (const [x, y] of pairs) {
      const a = x >= 0 ? la[x] : null, b = y >= 0 ? lb[y] : null;
      if ((a && a.status !== "eq") || (b && b.status !== "eq")) changed++;
      out.push(h("div", { class: "dc-line", "data-testid": "diff-c-line" }, this.cell("a", x, a), this.cell("b", y, b)));
    }
    this.rows = out;
    const m = this.markup;
    const paired = m ? m.variables.filter((v) => v.a && v.b).length : 0;
    const differ = m ? m.variables.filter((v) => v.a && v.b && v.a.name !== v.b.name).length : 0;
    const apply = (from: "a" | "b", label: string, title: string) =>
      h("button", { class: "btn small", title, "data-testid": `diff-c-apply-${from}`, onclick: () => void this.port(from, [], false) }, label);
    const parts: HTMLElement[] = [
      h("span", { "data-testid": "diff-c-summary" }, `${changed} line${changed === 1 ? "" : "s"} touched by changed instructions`),
      m
        ? h(
            "span",
            { "data-testid": "diff-c-vars", title: "Variables pair by parameter position and by the instructions and C lines that print them. Right-click a token to apply it to the other side." },
            ` · ${paired} variable${paired === 1 ? "" : "s"} paired, ${differ} named differently`,
          )
        : h("span", {}),
      h("span", { class: "spacer" }),
    ];
    if (this.host.port)
      parts.push(
        apply("a", "Apply all A → B", "Carry A's name, signature, named variables, comments, and the names and types of the globals and callees it uses to what B lacks (one undo step)"),
        apply("b", "Apply all B → A", "Carry B's name, signature, named variables, comments, and the names and types of the globals and callees it uses to what A lacks (one undo step)"),
      );
    this.head.replaceChildren(...parts);
    this.body.replaceChildren(...out);
  }

  private cell(side: "a" | "b", i: number, l: CLine | null): HTMLElement {
    if (!l) return h("span", { class: "dc-cell gap" });
    const vars = this.vars[side === "a" ? 0 : 1];
    return h(
      "span",
      { class: `dc-cell k-${l.status}`, "data-side": side, "data-i": i, "data-status": l.status, "data-testid": `diff-c-cell-${side}` },
      ...l.tokens.map((t, k) => {
        let cls = KIND_CLASS[t.kind] ?? "";
        let title: string | undefined;
        if (t.varKey) {
          const p = vars.get(t.varKey);
          const other = p ? (side === "a" ? p.b : p.a) : undefined;
          if (other && other.name !== t.text) {
            cls += " dc-port";
            title = `${t.text} ↔ ${other.name} (${p!.evidence}); right-click to apply`;
          } else if (other) title = `the same on both sides (${p!.evidence})`;
        }
        return h("span", { class: cls, "data-k": k, "data-testid": t.varKey ? "diff-c-var" : undefined, "data-var": t.varKey, title }, t.text);
      }),
    );
  }

  /** The context menu of a token: what of it can go to the other side. */
  private menu(side: "a" | "b", i: number, k: number): MenuItem[] {
    const l = this.lines[side === "a" ? 0 : 1][i];
    const t = l?.tokens[k];
    const other = side === "a" ? "B" : "A";
    const items: MenuItem[] = [];
    const f = this.fns[side === "a" ? 0 : 1];
    const entry = side === "a" ? this.pd!.pair.a : this.pd!.pair.b;
    if (t?.varKey) {
      const p = this.vars[side === "a" ? 0 : 1].get(t.varKey);
      const mine: CompareVariable | undefined = p ? (side === "a" ? p.a : p.b) : undefined;
      const theirs: CompareVariable | undefined = p ? (side === "a" ? p.b : p.a) : undefined;
      if (mine && theirs) {
        items.push({
          label: `Apply name “${mine.name}” to ${other} (now ${theirs.name})`,
          disabled: mine.name === theirs.name,
          testid: "dc-apply-var-name",
          run: () => this.port(side, [{ kind: FunctionMarkupKind.VARIABLE_NAME, variable: t.varKey! }], true),
        });
        items.push({
          label: `Apply type “${mine.type}” to ${other} (now ${theirs.type})`,
          disabled: mine.type === theirs.type,
          testid: "dc-apply-var-type",
          run: () => this.port(side, [{ kind: FunctionMarkupKind.VARIABLE_TYPE, variable: t.varKey! }], true),
        });
      } else {
        items.push({ label: `No variable of ${other} corresponds to ${t.text}`, disabled: true, testid: "dc-apply-none" });
      }
    } else if (t && t.kind === CodeTokenKind.FUNCTION_NAME && (t.target === entry || (f !== undefined && t.text === f.name))) {
      items.push({ label: `Apply name “${t.text}” to ${other}`, testid: "dc-apply-name", run: () => this.port(side, [{ kind: FunctionMarkupKind.NAME }], true) });
      items.push({ label: `Apply signature to ${other}`, testid: "dc-apply-signature", run: () => this.port(side, [{ kind: FunctionMarkupKind.SIGNATURE }], true) });
    } else if (t && t.kind === CodeTokenKind.FUNCTION_NAME && t.target !== undefined && t.target !== entry) {
      // A callee: its name and signature, to its partner (paired by the aligned call).
      const at = { offset: t.target };
      items.push({ label: `Apply callee name “${t.text}” to ${other}`, testid: "dc-apply-callee-name", run: () => this.port(side, [{ kind: FunctionMarkupKind.CALLEE_NAME, address: at }], true) });
      items.push({ label: `Apply ${t.text}'s signature to ${other}'s callee`, testid: "dc-apply-callee-signature", run: () => this.port(side, [{ kind: FunctionMarkupKind.CALLEE_SIGNATURE, address: at }], true) });
    } else if (t && t.kind === CodeTokenKind.GLOBAL_VARIABLE && t.target !== undefined) {
      // A global: its name and type, to its partner (paired by the aligned reference).
      const at = { offset: t.target };
      items.push({ label: `Apply global name “${t.text}” to ${other}`, testid: "dc-apply-global-name", run: () => this.port(side, [{ kind: FunctionMarkupKind.GLOBAL_NAME, address: at }], true) });
      items.push({ label: `Apply ${t.text}'s type to ${other}'s global`, testid: "dc-apply-global-type", run: () => this.port(side, [{ kind: FunctionMarkupKind.GLOBAL_TYPE, address: at }], true) });
    } else if (t && t.kind === CodeTokenKind.COMMENT) {
      const at = t.address ?? l.addresses[0];
      if (at !== undefined)
        items.push({ label: `Apply this comment to ${other}`, testid: "dc-apply-comment", run: () => this.port(side, [{ kind: FunctionMarkupKind.COMMENT, address: { offset: at } }], true) });
    }
    if (l?.addresses.length && t?.kind !== CodeTokenKind.COMMENT)
      items.push({
        label: `Apply this line's comments to ${other}`,
        testid: "dc-apply-line-comments",
        run: () => this.port(side, l.addresses.map((a) => ({ kind: FunctionMarkupKind.COMMENT, address: { offset: a } })), true),
      });
    items.push({ label: `Apply all to ${other} (only what ${other} lacks)`, separator: items.length > 0, testid: "dc-apply-all", run: () => this.port(side, [], false) });
    items.push({ label: `Apply all to ${other}, replacing ${other}'s`, testid: "dc-apply-all-replace", run: () => this.port(side, [], true) });
    return items;
  }

  /** Ports from one side to the other (PortFunctionMarkup), then shows both again. */
  async port(from: "a" | "b", items: PortItem[], overwrite: boolean) {
    const pd = this.pd;
    if (!pd) return;
    const p = pd.pair;
    const [fromProgram, fromEntry, toProgram, toEntry] = from === "a" ? [p.programA, p.a, p.programB, p.b] : [p.programB, p.b, p.programA, p.a];
    try {
      const r = await this.host.rk.diff.portFunctionMarkup({
        projectId: this.host.projectId,
        fromProgram,
        fromEntry: { offset: fromEntry },
        toProgram,
        toEntry: { offset: toEntry },
        items: items.map((i) => ({ kind: i.kind, variable: i.variable ?? "", address: i.address, commentKind: "" })),
        overwrite,
        sessionId: p.sessionId,
        provenance: userProvenance("applied in Compare"),
      });
      if (!r.seqs.length) {
        toast(r.warnings[0] ?? (r.skipped ? `Nothing applied: ${r.skipped} left alone (the other side has its own)` : "Nothing to apply: both sides agree"), { kind: r.warnings.length ? "error" : "info" });
        return;
      }
      this.host.onPorted?.({ toProgram, seqs: r.seqs, label: `Apply ${portedText(r)} from ${from === "a" ? "A" : "B"}`, revision: r.snapshot?.revision ?? 0n });
      cache.delete(`${toProgram}|${toEntry}`);
      if (this.pd === pd) await this.set(pd, "", true);
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  /** Forgets decompilations (an edit: of one program, or all). */
  static forget(programId?: string) {
    if (!programId) return cache.clear();
    for (const k of [...cache.keys()]) if (k.startsWith(`${programId}|`)) cache.delete(k);
  }

  /** Shows the same pair again (after an edit to either side). */
  async refresh() {
    if (this.pd) await this.set(this.pd, "", true);
  }

  /** Highlights the lines printed from an instruction and scrolls to the first. */
  selectAddress(side: "a" | "b", address: bigint) {
    if (!this.rows.length) return;
    for (const el of this.body.querySelectorAll(".dc-cell.sel")) el.classList.remove("sel");
    const ls = this.lines[side === "a" ? 0 : 1];
    let first: HTMLElement | null = null;
    for (const el of this.body.querySelectorAll<HTMLElement>(`.dc-cell[data-side="${side}"][data-i]`)) {
      const l = ls[Number(el.dataset.i)];
      if (l?.addresses.includes(address)) {
        el.classList.add("sel");
        first ??= el;
      }
    }
    first?.scrollIntoView({ block: "center" });
  }

  /** What the pane shows (tests): the paired variables and the signatures. */
  describe() {
    return {
      variables: (this.markup?.variables ?? []).map((v) => ({ a: v.a?.name ?? null, b: v.b?.name ?? null, aKey: v.a?.storageKey ?? null, bKey: v.b?.storageKey ?? null, evidence: v.evidence })),
      lines: this.rows.length,
      signatureA: this.markup?.signatureA ?? "",
      signatureB: this.markup?.signatureB ?? "",
    };
  }
}

type Token = DecompiledFunction["lines"][number]["tokens"][number];

function variableToken(t: Token, f: DecompiledFunction): boolean {
  if (t.variableIndex === undefined || t.variableIndex >= f.variables.length) return false;
  if (t.kind !== CodeTokenKind.LOCAL_VARIABLE && t.kind !== CodeTokenKind.PARAMETER) return false;
  return !!f.variables[t.variableIndex].storageKey;
}

function lines(f: DecompiledFunction | undefined, status: Map<bigint, DiffLineStatus>): CLine[] {
  if (!f) return [];
  return f.lines.map((l) => {
    const addresses: bigint[] = [];
    let st: CLine["status"] = "eq";
    for (const t of l.tokens) {
      const a = t.address?.offset;
      if (a === undefined) continue;
      if (!addresses.includes(a)) addresses.push(a);
      const s = status.get(a);
      if (s === DiffLineStatus.DELETED) st = "del";
      else if (s === DiffLineStatus.INSERTED) st = "ins";
      else if (s === DiffLineStatus.CHANGED && st === "eq") st = "chg";
    }
    const text = "  ".repeat(l.indent) + l.tokens.map((t) => t.text).join("");
    // Variables and default names abstracted: a renamed variable or moved code reads the same.
    const key = l.tokens
      .map((t) => (variableToken(t, f) ? "\u0001" : t.text))
      .join("")
      .trim()
      .replace(/\b(FUN|LAB|DAT|PTR|s|u|thunk_FUN)_[0-9a-f]{4,16}\b/g, "$1_*");
    const tokens: CToken[] = [{ text: "  ".repeat(l.indent), kind: CodeTokenKind.UNSPECIFIED }];
    for (const t of l.tokens)
      tokens.push({ text: t.text, kind: t.kind, varKey: variableToken(t, f) ? f.variables[t.variableIndex!].storageKey : undefined, address: t.address?.offset, target: t.target?.offset });
    return { text, key, tokens, addresses, status: st };
  });
}

/** Line pairs by LCS over the abstracted text (-1: a gap). */
function align(a: CLine[], b: CLine[]): [number, number][] {
  const n = a.length, m = b.length;
  const out: [number, number][] = [];
  if (n * m > 4_000_000) {
    for (let i = 0; i < Math.max(n, m); i++) out.push([i < n ? i : -1, i < m ? i : -1]);
    return out;
  }
  const t = new Uint32Array((n + 1) * (m + 1));
  for (let x = n - 1; x >= 0; x--)
    for (let y = m - 1; y >= 0; y--)
      t[x * (m + 1) + y] = a[x].key === b[y].key ? t[(x + 1) * (m + 1) + y + 1] + 1 : Math.max(t[(x + 1) * (m + 1) + y], t[x * (m + 1) + y + 1]);
  let x = 0, y = 0;
  while (x < n || y < m) {
    if (x < n && y < m && a[x].key === b[y].key) out.push([x++, y++]);
    else if (y >= m || (x < n && t[(x + 1) * (m + 1) + y] >= t[x * (m + 1) + y + 1])) {
      // A replaced line: pair it with B's next unmatched line when both differ.
      if (y < m && x < n && t[(x + 1) * (m + 1) + y + 1] === t[x * (m + 1) + y] && a[x].key !== b[y].key) out.push([x++, y++]);
      else out.push([x++, -1]);
    } else out.push([-1, y++]);
  }
  return out;
}
