// Both functions' listings aligned line by line (DiffDetail.lines):
// corresponding instructions on the same line, a gap where one side has
// nothing. Changed instructions are amber with the differing tokens
// emphasised, inserted ones green (B), deleted ones red (A), moved ones
// marked; equal lines are dimmed. One scroll container for both sides, so
// they always scroll together; virtualized, so a 20,000-line function
// scrolls as smoothly as a short one. n / p (or the arrows in the header)
// go to the next and previous difference.

import { DiffLineStatus, type DiffDetail, type DiffRow } from "@revkit/api";
import { hex } from "../data/format";
import { h } from "../ui/dom";
import { lineDiffers, tokenDiff, type PairDetail } from "./detail";

const LINE_H = 18;
const OVERSCAN = 30;

const TOKEN_CLASS: Record<number, string> = { 1: "t-mn", 2: "t-reg", 3: "t-num", 4: "t-addr", 5: "t-sym", 8: "t-mn" };

export interface AlignedSelection {
  side: "a" | "b";
  row: number;
  address: bigint;
}

export class AlignedListing {
  readonly el: HTMLElement;
  private body: HTMLElement;
  private spacer: HTMLElement;
  private win: HTMLElement;
  private pd: PairDetail | null = null;
  private hunk = -1;
  private selected: { side: "a" | "b"; row: number } | null = null;
  private raf = 0;
  private rendered = "";
  /** The difference count and position changed. */
  onHunk: ((current: number, total: number) => void) | null = null;
  /** A row was clicked. */
  onSelect: ((s: AlignedSelection) => void) | null = null;

  constructor(private addrWidth: number) {
    this.spacer = h("div", { class: "dl-spacer" });
    this.win = h("div", { class: "dl-window" });
    this.body = h("div", { class: "dl-body", tabindex: "0", "data-testid": "diff-lines" }, this.spacer, this.win);
    this.el = h("div", { class: "dl" }, this.body);
    this.body.addEventListener("scroll", () => this.schedule());
    new ResizeObserver(() => this.schedule()).observe(this.body);
    this.body.addEventListener("mousedown", (e) => {
      const cell = (e.target as HTMLElement).closest<HTMLElement>("[data-side][data-row]");
      if (!cell || !this.pd) return;
      const side = cell.dataset.side as "a" | "b";
      const row = Number(cell.dataset.row);
      this.select(side, row);
      const r = (side === "a" ? this.pd.detail.rowsA : this.pd.detail.rowsB)[row];
      this.onSelect?.({ side, row, address: r.address?.offset ?? 0n });
    });
  }

  get detail(): DiffDetail | null {
    return this.pd?.detail ?? null;
  }

  set(pd: PairDetail | null, message = "") {
    this.pd = pd;
    this.hunk = -1;
    this.selected = null;
    this.rendered = "";
    if (!pd) {
      this.spacer.style.height = "0px";
      this.win.replaceChildren(h("div", { class: "dim diff-empty" }, message || "Select a match to see both functions."));
      this.onHunk?.(-1, 0);
      return;
    }
    this.spacer.style.height = `${pd.detail.lines.length * LINE_H}px`;
    this.body.scrollTop = 0;
    this.onHunk?.(-1, pd.detail.hunks.length);
    // Open at the first difference.
    if (pd.detail.hunks.length) this.go(1);
    else this.render();
  }

  get hunks(): number {
    return this.pd?.detail.hunks.length ?? 0;
  }

  get currentHunk(): number {
    return this.hunk;
  }

  /** Next (+1) or previous (-1) difference, wrapping around. */
  go(dir: 1 | -1) {
    const d = this.pd?.detail;
    if (!d || !d.hunks.length) return;
    const n = d.hunks.length;
    this.hunk = this.hunk < 0 ? (dir > 0 ? 0 : n - 1) : (this.hunk + dir + n) % n;
    this.scrollToLine(d.hunks[this.hunk], true);
    this.onHunk?.(this.hunk, n);
  }

  focus() {
    this.body.focus({ preventScroll: true });
  }

  /** Brings a line into view (centred with `center`, else only if hidden). */
  scrollToLine(line: number, center = false) {
    const top = line * LINE_H;
    const hgt = this.body.clientHeight || 300;
    if (center || top < this.body.scrollTop || top + LINE_H > this.body.scrollTop + hgt)
      this.body.scrollTop = Math.max(0, top - Math.floor(hgt / 3));
    this.render();
  }

  /** Selects a row of one side (and so its line) and scrolls to it. */
  select(side: "a" | "b", row: number, scroll = false) {
    this.selected = { side, row };
    const d = this.pd?.detail;
    if (d && scroll) {
      const line = d.lines.findIndex((l) => (side === "a" ? l.a : l.b) === row);
      if (line >= 0) this.scrollToLine(line, true);
    }
    // The difference containing the selection becomes current.
    if (d) {
      const line = d.lines.findIndex((l) => (side === "a" ? l.a : l.b) === row);
      let k = -1;
      for (let i = 0; i < d.hunks.length && d.hunks[i] <= line; i++) k = i;
      if (k >= 0 && line >= 0 && lineDiffers(d, line)) {
        this.hunk = k;
        this.onHunk?.(k, d.hunks.length);
      }
    }
    this.rendered = "";
    this.render();
  }

  private schedule() {
    if (!this.raf) this.raf = requestAnimationFrame(() => {
      this.raf = 0;
      this.render();
    });
  }

  private render() {
    const d = this.pd?.detail;
    if (!d) return;
    const first = Math.max(0, Math.floor(this.body.scrollTop / LINE_H) - OVERSCAN);
    const last = Math.min(d.lines.length, Math.ceil((this.body.scrollTop + (this.body.clientHeight || 600)) / LINE_H) + OVERSCAN);
    const k = `${first}:${last}:${this.hunk}:${this.selected?.side}${this.selected?.row}`;
    if (k === this.rendered) return;
    this.rendered = k;
    const current = new Set<number>();
    if (this.hunk >= 0) for (let i = d.hunks[this.hunk]; i < d.lines.length && lineDiffers(d, i); i++) current.add(i);
    const out: HTMLElement[] = [];
    for (let i = first; i < last; i++) out.push(this.line(d, i, current.has(i)));
    this.win.style.transform = `translateY(${first * LINE_H}px)`;
    this.win.replaceChildren(...out);
  }

  private line(d: DiffDetail, i: number, current: boolean): HTMLElement {
    const l = d.lines[i];
    const ra = l.a >= 0 ? d.rowsA[l.a] : null;
    const rb = l.b >= 0 ? d.rowsB[l.b] : null;
    let emA = new Set<number>(), emB = new Set<number>();
    if (ra && rb && ra.status === DiffLineStatus.CHANGED) [emA, emB] = tokenDiff(ra.tokens, rb.tokens);
    const status = (ra ?? rb)!.status;
    const moved = (ra ?? rb)!.moved;
    const kind = moved ? "moved" : status === DiffLineStatus.EQUAL ? "eq" : status === DiffLineStatus.CHANGED ? "chg" : status === DiffLineStatus.INSERTED ? "ins" : status === DiffLineStatus.DELETED ? "del" : "eq";
    const mark = kind === "chg" ? "~" : kind === "ins" ? "+" : kind === "del" ? "−" : kind === "moved" ? "⇅" : "";
    return h(
      "div",
      { class: `dl-line k-${kind}${current ? " current" : ""}`, "data-testid": "diff-line", "data-line": i, "data-status": kind },
      this.cell(d, "a", l.a, ra, emA, false),
      h("span", { class: "dl-mark", title: kind === "moved" ? "moved: matched out of order" : "" }, mark),
      this.cell(d, "b", l.b, rb, emB, rb !== null && this.pd!.newCalls.has(l.b)),
    );
  }

  private cell(d: DiffDetail, side: "a" | "b", index: number, r: DiffRow | null, em: Set<number>, fresh: boolean): HTMLElement {
    if (!r) return h("span", { class: "dl-cell gap" });
    const rows = side === "a" ? d.rowsA : d.rowsB;
    const blockStart = index > 0 && rows[index - 1].block !== r.block;
    const sel = this.selected?.side === side && this.selected.row === index;
    const toks = r.tokens.length
      ? r.tokens.map((t, k) => h("span", { class: (TOKEN_CLASS[t.kind] ?? "") + (em.has(k) ? " t-diff" : "") }, t.text))
      : [h("span", {}, r.text)];
    return h(
      "span",
      {
        class: `dl-cell${blockStart ? " block-start" : ""}${sel ? " sel" : ""}`,
        "data-side": side,
        "data-row": index,
        "data-testid": `diff-cell-${side}`,
        title: r.label ? `${r.label}: ${r.text}` : r.text,
      },
      h("span", { class: "dl-addr" }, hex(r.address?.offset ?? 0n, this.addrWidth)),
      h("span", { class: "dl-text" }, ...toks, fresh ? h("span", { class: "badge-new", "data-testid": "diff-new", title: "calls a function only in B (new code)" }, "new") : null),
      r.comment ? h("span", { class: "dl-cmt" }, r.comment) : null,
    );
  }

  /** Lines as shown (tests): status and both texts. */
  describe() {
    const d = this.pd?.detail;
    if (!d) return null;
    return {
      lines: d.lines.length,
      hunks: d.hunks.length,
      current: this.hunk,
      differing: d.lines.map((_, i) => i).filter((i) => lineDiffers(d, i)).map((i) => {
        const l = d.lines[i];
        return { line: i, a: l.a >= 0 ? hex(d.rowsA[l.a].address?.offset ?? 0n) : null, b: l.b >= 0 ? hex(d.rowsB[l.b].address?.offset ?? 0n) : null };
      }),
      summary: d.summary?.text ?? "",
    };
  }
}
