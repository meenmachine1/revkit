// Decompiler pane: the daemon's token stream for one function in a
// read-only CodeMirror view. Every token keeps its CodeToken, so
//
//   listing -> C:  highlightAddress(addr) marks the tokens printed from the
//                  instruction at addr (CodeToken.address);
//   C -> listing:  clicking a token reports its address (or its line's), and
//                  double-clicking a function or global name follows it;
//   edits:         the selected token says what a rename targets: a
//                  function/global (CodeToken.target), a local
//                  (variables[variable_index].storage_key) or a struct
//                  field (CodeToken.parent_type_hash and field_offset).

import { EditorSelection, EditorState, StateEffect, StateField, RangeSetBuilder, type Range } from "@codemirror/state";
import { Decoration, EditorView, ViewPlugin, WidgetType, drawSelection, type DecorationSet, type ViewUpdate } from "@codemirror/view";
import { CodeTokenKind, type CodeToken, type DecompiledFunction, type Variable } from "@revkit/api";
import { originClass } from "../data/format";
import { showName } from "../data/names";

export interface TokSpan {
  from: number;
  to: number;
  tok: CodeToken;
  line: number;
}

const KIND_CLASS: Record<number, string> = {
  [CodeTokenKind.KEYWORD]: "k-kw",
  [CodeTokenKind.TYPE]: "k-ty",
  [CodeTokenKind.FUNCTION_NAME]: "k-fn",
  [CodeTokenKind.LOCAL_VARIABLE]: "k-lv",
  [CodeTokenKind.PARAMETER]: "k-pa",
  [CodeTokenKind.GLOBAL_VARIABLE]: "k-gv",
  [CodeTokenKind.CONSTANT]: "k-co",
  [CodeTokenKind.STRING]: "k-st",
  [CodeTokenKind.OPERATOR]: "k-op",
  [CodeTokenKind.PUNCTUATION]: "k-pu",
  [CodeTokenKind.COMMENT]: "k-cm",
  [CodeTokenKind.LABEL]: "k-lb",
  [CodeTokenKind.FIELD]: "k-fd",
  [CodeTokenKind.ERROR]: "k-er",
};

const IDENT = new Set<number>([
  CodeTokenKind.FUNCTION_NAME,
  CodeTokenKind.LOCAL_VARIABLE,
  CodeTokenKind.PARAMETER,
  CodeTokenKind.GLOBAL_VARIABLE,
  CodeTokenKind.FIELD,
  CodeTokenKind.LABEL,
]);

const setMarks = StateEffect.define<Range<Decoration>[]>();
const marksField = StateField.define<DecorationSet>({
  create: () => Decoration.none,
  update(deco, tr) {
    deco = deco.map(tr.changes);
    for (const e of tr.effects) if (e.is(setMarks)) deco = Decoration.set(e.value, true);
    return deco;
  },
  provide: (f) => EditorView.decorations.from(f),
});
// Analyzer plugins' facts, at the end of the first line printed from their
// address (setAnnotations).
const setNotes = StateEffect.define<Range<Decoration>[]>();
const notesField = StateField.define<DecorationSet>({
  create: () => Decoration.none,
  update(deco, tr) {
    deco = deco.map(tr.changes);
    for (const e of tr.effects) if (e.is(setNotes)) deco = Decoration.set(e.value, true);
    return deco;
  },
  provide: (f) => EditorView.decorations.from(f),
});
class NoteWidget extends WidgetType {
  constructor(readonly text: string) {
    super();
  }
  eq(o: NoteWidget) {
    return o.text === this.text;
  }
  toDOM() {
    const el = document.createElement("span");
    el.className = "cm-plugin-note";
    el.textContent = this.text;
    el.title = this.text;
    return el;
  }
}
const syncMark = Decoration.mark({ class: "cm-sync" });
const syncLine = Decoration.line({ class: "cm-sync-line" });
const pcLine = Decoration.line({ class: "cm-pc-line" });
// A search match (the decompiled-code search's results): its line and text.
const findLine = Decoration.line({ class: "cm-find-line" });
const findMark = Decoration.mark({ class: "cm-find" });
const selMark = Decoration.mark({ class: "cm-tok-sel" });
const curMark = Decoration.mark({ class: "cm-tok-cur" });
const sliceMark = Decoration.mark({ class: "cm-slice" });
const kindMarks = new Map<string, Decoration>();
function kindMark(cls: string) {
  let d = kindMarks.get(cls);
  if (!d) kindMarks.set(cls, (d = Decoration.mark({ class: cls })));
  return d;
}

export class DecompilerPane {
  readonly view: EditorView;
  fn: DecompiledFunction | null = null;
  spans: TokSpan[] = [];
  private lineAddr: (bigint | null)[] = [];
  /** The clicked token (rename/comment/xrefs act on it). */
  selected: TokSpan | null = null;
  private syncAddr: bigint | null = null;
  /** The emulator's program counter: its lines are marked. */
  private pcAddr: bigint | null = null;
  private hovered: TokSpan | null = null;
  /** A search match shown (revealLine): line, and offsets after its indent. */
  private find: { line: number; from: number; to: number } | null = null;
  /** A def-use or slice highlight (feature decompile-slices): its tokens, in
   * reading order, and what it is ("Backward slice of uVar1"). */
  slice: { spans: TokSpan[]; label: string } | null = null;
  /** The slice went (Escape, a new function, a refresh): the app clears the listing's marks. */
  onSliceCleared: (() => void) | null = null;

  /** C -> listing: a token or line was clicked. */
  onSelectAddress: ((address: bigint) => void) | null = null;
  /** Double-click on a function or global name. */
  onFollow: ((target: bigint) => void) | null = null;
  onHover: ((span: TokSpan | null, clientX: number, clientY: number) => void) | null = null;
  /** Right-click (or the context-menu key) in the code: the app shows its actions there. */
  onContextMenu: ((clientX: number, clientY: number) => void) | null = null;

  constructor(parent: HTMLElement) {
    const pane = this;
    const kindPlugin = ViewPlugin.fromClass(
      class {
        decorations: DecorationSet;
        constructor(v: EditorView) {
          this.decorations = pane.kindDecorations(v);
        }
        update(u: ViewUpdate) {
          if (u.docChanged || u.viewportChanged) this.decorations = pane.kindDecorations(u.view);
        }
      },
      { decorations: (p) => p.decorations },
    );
    this.view = new EditorView({
      parent,
      state: EditorState.create({
        doc: "",
        extensions: [
          EditorState.readOnly.of(true),
          EditorView.editable.of(false),
          EditorView.contentAttributes.of({ tabindex: "0", "aria-label": "Decompiled code" }),
          // Text selection (drag, Shift+click, double and triple click) drawn
          // in both themes; the code stays read-only.
          drawSelection(),
          kindPlugin,
          marksField,
          notesField,
          EditorView.domEventHandlers({
            keydown: (e) => this.onKey(e),
            mousedown: (e, view) => {
              if (e.button !== 0) return false;
              const pos = view.posAtCoords({ x: e.clientX, y: e.clientY });
              if (pos === null) return false;
              // A double click on a function or global name follows it;
              // anything else is CodeMirror's: a drag, Shift+click, a
              // double or triple click select text.
              if (e.detail === 2 && !e.shiftKey && this.followAt(pos)) return true;
              this.press = e.detail === 1 && !e.shiftKey ? { x: e.clientX, y: e.clientY, pos } : null;
              return false;
            },
            mouseup: (e, view) => {
              // A click without a drag selects the token under it.
              const p = this.press;
              this.press = null;
              if (!p || e.button !== 0 || Math.abs(e.clientX - p.x) > 3 || Math.abs(e.clientY - p.y) > 3) return false;
              const pos = view.posAtCoords({ x: e.clientX, y: e.clientY }) ?? p.pos;
              this.clickAt(pos, false);
              view.contentDOM.focus({ preventScroll: true });
              return false;
            },
            copy: (e) => {
              const text = this.copyText();
              if (text === null || !e.clipboardData) return false;
              e.clipboardData.setData("text/plain", text);
              e.preventDefault();
              return true;
            },
            contextmenu: (e, view) => {
              // Select the token under the pointer, then the app's actions
              // instead of the browser's menu.
              e.preventDefault();
              const pos = e.clientX || e.clientY ? view.posAtCoords({ x: e.clientX, y: e.clientY }) : null;
              // Inside a text selection, the selection stays (Copy acts on it).
              const sel = view.state.selection.main;
              if (pos !== null && !(sel.from < sel.to && pos >= sel.from && pos <= sel.to)) this.clickAt(pos, false);
              let x = e.clientX, y = e.clientY;
              if (!x && !y) {
                const c = view.coordsAtPos(view.state.selection.main.head);
                if (c) (x = c.left), (y = c.bottom);
              }
              this.onContextMenu?.(x, y);
              return true;
            },
            mousemove: (e, view) => {
              const pos = view.posAtCoords({ x: e.clientX, y: e.clientY }, false);
              const s = pos === null ? null : this.spanAt(pos, true);
              const named = s && this.hoverable(s) ? s : null;
              if (named !== this.hovered) {
                this.hovered = named;
                this.onHover?.(named, e.clientX, e.clientY);
              }
              return false;
            },
            mouseleave: (e) => {
              if (this.hovered) {
                this.hovered = null;
                this.onHover?.(null, e.clientX, e.clientY);
              }
              return false;
            },
          }),
        ],
      }),
    });
  }

  private kindDecorations(v: EditorView): DecorationSet {
    const b = new RangeSetBuilder<Decoration>();
    const vars = this.fn?.variables ?? [];
    for (const { from, to } of v.visibleRanges) {
      let i = this.firstSpanAt(from);
      for (; i < this.spans.length && this.spans[i].from < to; i++) {
        const s = this.spans[i];
        let cls = KIND_CLASS[s.tok.kind];
        if (!cls) continue;
        if (s.tok.variableIndex !== undefined) {
          const oc = originClass(vars[s.tok.variableIndex]?.nameOrigin);
          if (oc === "user" || oc === "agent") cls += " n-" + oc;
        }
        b.add(s.from, s.to, kindMark(cls));
      }
    }
    return b.finish();
  }

  private firstSpanAt(pos: number): number {
    let lo = 0;
    let hi = this.spans.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.spans[mid].to <= pos) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  /** The token covering pos (or ending at it, for clicks just after one). */
  spanAt(pos: number, strict = false): TokSpan | null {
    const i = this.firstSpanAt(pos);
    const s = this.spans[i];
    if (s && s.from <= pos && pos < s.to) return s;
    if (!strict) {
      const p = this.spans[i - 1];
      if (p && p.to === pos) return p;
    }
    return null;
  }

  /** Tokens a rename or provenance badge applies to. */
  nameable(s: TokSpan): boolean {
    const k = s.tok.kind;
    if (k === CodeTokenKind.FUNCTION_NAME || k === CodeTokenKind.GLOBAL_VARIABLE) return !!s.tok.target || s.tok.variableIndex !== undefined;
    if (k === CodeTokenKind.LOCAL_VARIABLE || k === CodeTokenKind.PARAMETER) return s.tok.variableIndex !== undefined;
    return false;
  }

  /** Tokens with a hover card (ui/hover.ts): names, types, fields, constants. */
  hoverable(s: TokSpan): boolean {
    const k = s.tok.kind;
    if (this.nameable(s)) return true;
    if (k === CodeTokenKind.TYPE) return true;
    if (k === CodeTokenKind.FIELD) return !!s.tok.parentTypeHash;
    if (k === CodeTokenKind.CONSTANT) return s.tok.value !== undefined;
    return false;
  }

  /**
   * A FIELD token's struct (or union) by hash, the field's offset in it and
   * its name (feature field-tokens): what Rename Field and Retype Field
   * edit. The hash is empty when the daemon couldn't name the struct.
   */
  field(s: TokSpan | null): { hash: string; offset: bigint; name: string } | undefined {
    if (!s || s.tok.kind !== CodeTokenKind.FIELD || s.tok.fieldOffset === undefined) return undefined;
    return { hash: s.tok.parentTypeHash, offset: s.tok.fieldOffset, name: s.tok.text };
  }

  variable(s: TokSpan | null): Variable | undefined {
    if (!s || s.tok.variableIndex === undefined) return undefined;
    return this.fn?.variables[s.tok.variableIndex];
  }

  /** Address a click on this token points the listing at. */
  addressOf(s: TokSpan): bigint | null {
    return s.tok.address?.offset ?? this.lineAddr[s.line] ?? null;
  }

  /** Where a plain left click went down (a token is selected on mouseup without a drag). */
  private press: { x: number; y: number; pos: number } | null = null;

  /** A double click on a function or global name: follow it (true when it did). */
  private followAt(pos: number): boolean {
    const s = this.spanAt(pos);
    if (!s?.tok.target || (s.tok.kind !== CodeTokenKind.FUNCTION_NAME && s.tok.kind !== CodeTokenKind.GLOBAL_VARIABLE)) return false;
    this.onFollow?.(s.tok.target.offset);
    return true;
  }

  /** The selected text, or the selected token's when nothing is selected (null: neither). */
  copyText(): string | null {
    const sel = this.view.state.selection.main;
    if (sel.from < sel.to) return this.view.state.sliceDoc(sel.from, sel.to);
    return this.selected ? this.view.state.sliceDoc(this.selected.from, this.selected.to) : null;
  }

  /** The whole function's C. */
  get text(): string {
    return this.fn ? this.view.state.doc.toString() : "";
  }

  /** Is text selected (not only a token)? */
  get hasTextSelection(): boolean {
    const sel = this.view.state.selection.main;
    return sel.from < sel.to;
  }

  /** Selects the text from `from` to `to` (tests, Select all). */
  selectText(from: number, to: number) {
    this.view.dispatch({ selection: EditorSelection.single(from, to) });
  }

  private clickAt(pos: number, double: boolean) {
    const s = this.spanAt(pos);
    if (double && this.followAt(pos)) return;
    this.selected = s;
    const line = this.view.state.doc.lineAt(pos).number - 1;
    const addr = s ? this.addressOf(s) : (this.lineAddr[line] ?? null);
    if (addr !== null) this.syncAddr = addr;
    this.paintMarks();
    if (addr !== null) this.onSelectAddress?.(addr);
  }

  /** Arrow keys walk the identifiers and constants, like clicking them. */
  private onKey(e: KeyboardEvent): boolean {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "a") {
      e.preventDefault();
      this.selectText(0, this.view.state.doc.length);
      return true;
    }
    if (e.ctrlKey || e.metaKey || e.altKey) return false;
    // Escape drops a text selection first, then a slice highlight.
    if (e.key === "Escape" && this.hasTextSelection) {
      e.preventDefault();
      this.selectText(this.view.state.selection.main.head, this.view.state.selection.main.head);
      return true;
    }
    if (e.key === "Escape" && this.slice) {
      e.preventDefault();
      this.clearSlice();
      return true;
    }
    const stops = this.spans.filter((s) => IDENT.has(s.tok.kind) || s.tok.kind === CodeTokenKind.CONSTANT || s.tok.kind === CodeTokenKind.STRING);
    if (!stops.length) return false;
    const cur = this.selected ? stops.findIndex((s) => s.from === this.selected!.from) : -1;
    let next: TokSpan | undefined;
    switch (e.key) {
      case "ArrowRight":
        next = stops[cur < 0 ? 0 : Math.min(stops.length - 1, cur + 1)];
        break;
      case "ArrowLeft":
        next = stops[cur < 0 ? 0 : Math.max(0, cur - 1)];
        break;
      case "ArrowDown":
      case "ArrowUp": {
        const doc = this.view.state.doc;
        const line = cur < 0 ? -1 : stops[cur].line;
        const col = cur < 0 ? 0 : stops[cur].from - doc.line(line + 1).from;
        const dir = e.key === "ArrowDown" ? 1 : -1;
        // Nearest stop by column on the next line (in that direction) that has one.
        for (let l = line + dir; l >= 0 && l < doc.lines; l += dir) {
          const onLine = stops.filter((s) => s.line === l);
          if (!onLine.length) continue;
          const base = doc.line(l + 1).from;
          next = onLine.reduce((a, b) => (Math.abs(b.from - base - col) < Math.abs(a.from - base - col) ? b : a));
          break;
        }
        if (!next && cur < 0) next = stops[0];
        break;
      }
      default:
        return false;
    }
    e.preventDefault();
    if (!next || next === this.selected) return true;
    this.selected = next;
    const addr = this.addressOf(next);
    if (addr !== null) this.syncAddr = addr;
    this.paintMarks();
    this.view.dispatch({ effects: EditorView.scrollIntoView(next.from, { y: "nearest", yMargin: 40 }) });
    if (addr !== null) this.onSelectAddress?.(addr);
    return true;
  }

  /** Shows a message instead of code (no function, loading errors). */
  showMessage(text: string) {
    this.clearSlice();
    this.fn = null;
    this.spans = [];
    this.lineAddr = [];
    this.selected = null;
    this.view.dispatch({
      changes: { from: 0, to: this.view.state.doc.length, insert: text },
      effects: [setMarks.of([])],
    });
  }

  /**
   * Shows a decompiled function. When it is the same function as before
   * (a refresh after an edit), the scroll position and the selected token
   * are kept.
   */
  setFunction(fn: DecompiledFunction) {
    const same = this.fn?.entry?.offset === fn.entry?.offset;
    // Token positions mean nothing in another decompilation.
    this.clearSlice();
    if (!same) this.find = null;
    const scroller = this.view.scrollDOM;
    const top = scroller.scrollTop;
    const prevSel = this.selected;
    this.fn = fn;
    const spans: TokSpan[] = [];
    const lineAddr: (bigint | null)[] = [];
    const parts: string[] = [];
    let pos = 0;
    fn.lines.forEach((l, li) => {
      const indent = "  ".repeat(l.indent);
      let text = indent;
      pos += indent.length;
      for (const t of l.tokens) {
        // A demangled name as the names setting spells it (names.ts).
        const shown = t.demangled && (t.kind === CodeTokenKind.FUNCTION_NAME || t.kind === CodeTokenKind.GLOBAL_VARIABLE) ? showName(t.text, t.demangled) : t.text;
        if (shown.length && t.kind !== CodeTokenKind.WHITESPACE) spans.push({ from: pos, to: pos + shown.length, tok: t, line: li });
        text += shown;
        pos += shown.length;
      }
      lineAddr.push(l.address ? l.address.offset : null);
      parts.push(text);
      pos += 1; // newline
    });
    this.spans = spans;
    this.lineAddr = lineAddr;
    this.selected = null;
    if (same && prevSel) {
      // Same function re-decompiled (an edit): reselect the same token.
      const p = prevSel.tok;
      this.selected =
        spans.find((s) => s.line === prevSel.line && s.tok.kind === p.kind && s.tok.variableIndex === p.variableIndex && s.tok.target?.offset === p.target?.offset && s.tok.fieldOffset === p.fieldOffset) ?? null;
    }
    this.view.dispatch({
      changes: { from: 0, to: this.view.state.doc.length, insert: parts.join("\n") },
      effects: [setMarks.of([])],
    });
    if (same) scroller.scrollTop = top;
    else this.view.dispatch({ effects: EditorView.scrollIntoView(0) });
    this.paintMarks(!same);
    this.paintNotes();
  }

  /** Draws the function again (the names setting changed). */
  rerender() {
    if (this.fn) this.setFunction(this.fn);
  }

  private notes: ReadonlyMap<bigint, string> = new Map();

  /** Analyzer plugins' facts by address: shown after the first C line printed from each. */
  setAnnotations(notes: ReadonlyMap<bigint, string>) {
    this.notes = notes;
    this.paintNotes();
  }

  private paintNotes() {
    const doc = this.view.state.doc;
    const byLine = new Map<number, string[]>();
    // The first line printed from each address; a fact on an instruction no
    // token came from (the LEA loading a call's argument) goes with the
    // nearest instruction after it that has one (the call), a few bytes on.
    const lineOf = new Map<bigint, number>();
    if (this.fn) for (const s of this.spans) if (s.tok.address && !lineOf.has(s.tok.address.offset)) lineOf.set(s.tok.address.offset, s.line);
    const addrs = [...lineOf.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    for (const [a, note] of this.notes) {
      let line = lineOf.get(a);
      if (line === undefined) {
        const next = addrs.find((x) => x > a);
        if (next !== undefined && next - a <= 32n) line = lineOf.get(next);
      }
      if (line === undefined) continue;
      const list = byLine.get(line) ?? [];
      list.push(note);
      byLine.set(line, list);
    }
    const ranges: Range<Decoration>[] = [];
    for (const [line, texts] of [...byLine].sort((a, b) => a[0] - b[0]))
      if (line < doc.lines) ranges.push(Decoration.widget({ widget: new NoteWidget(texts.join("  ")), side: 1 }).range(doc.line(line + 1).to));
    this.view.dispatch({ effects: setNotes.of(ranges) });
  }

  /** Plugin notes shown (tests). */
  shownNotes(): string[] {
    return [...this.view.dom.querySelectorAll(".cm-plugin-note")].map((e) => e.textContent ?? "");
  }

  /** Listing selection moved: mark the tokens printed from `address`. */
  highlightAddress(address: bigint | null) {
    this.syncAddr = address;
    this.paintMarks(true);
  }

  /** The emulator stopped at `address` (null: none): mark its lines. */
  setPc(address: bigint | null) {
    if (address === this.pcAddr) return;
    this.pcAddr = address;
    this.paintMarks(false);
  }

  private sameIdentity(a: CodeToken, b: CodeToken): boolean {
    if (a.variableIndex !== undefined || b.variableIndex !== undefined) return a.variableIndex === b.variableIndex;
    if (a.target || b.target) return !!a.target && !!b.target && a.target.offset === b.target.offset;
    return a.text === b.text;
  }

  private paintMarks(scroll = false) {
    const ranges: Range<Decoration>[] = [];
    const doc = this.view.state.doc;
    let first = -1;
    if (this.syncAddr !== null) {
      const lines = new Set<number>();
      for (const s of this.spans) {
        if (s.tok.address?.offset === this.syncAddr) {
          ranges.push(syncMark.range(s.from, s.to));
          lines.add(s.line);
          if (first < 0) first = s.from;
        }
      }
      this.lineAddr.forEach((a, i) => {
        if (a === this.syncAddr) lines.add(i);
      });
      for (const l of lines) if (l < doc.lines) ranges.push(syncLine.range(doc.line(l + 1).from));
    }
    if (this.pcAddr !== null) {
      const pcLines = new Set<number>();
      for (const s of this.spans) if (s.tok.address?.offset === this.pcAddr) pcLines.add(s.line);
      this.lineAddr.forEach((a, i) => {
        if (a === this.pcAddr) pcLines.add(i);
      });
      for (const l of pcLines) if (l < doc.lines) ranges.push(pcLine.range(doc.line(l + 1).from));
    }
    const f = this.find;
    let findAt = -1;
    if (f && this.fn && f.line < doc.lines) {
      const l = doc.line(f.line + 1);
      const indent = 2 * (this.fn.lines[f.line]?.indent ?? 0);
      const a = Math.min(l.to, l.from + indent + f.from), b = Math.min(l.to, l.from + indent + f.to);
      ranges.push(findLine.range(l.from));
      if (b > a) ranges.push(findMark.range(a, b));
      findAt = a;
    }
    if (this.slice) for (const s of this.slice.spans) ranges.push(sliceMark.range(s.from, s.to));
    const sel = this.selected;
    if (sel) ranges.push(curMark.range(sel.from, sel.to));
    if (sel && IDENT.has(sel.tok.kind)) {
      for (const s of this.spans) if (IDENT.has(s.tok.kind) && this.sameIdentity(s.tok, sel.tok)) ranges.push(selMark.range(s.from, s.to));
    }
    ranges.sort((a, b) => a.from - b.from || a.value.startSide - b.value.startSide);
    const effects: StateEffect<unknown>[] = [setMarks.of(ranges)];
    if (scroll && findAt >= 0) effects.push(EditorView.scrollIntoView(findAt, { y: "center" }));
    else if (scroll && first >= 0) effects.push(EditorView.scrollIntoView(first, { y: "nearest", yMargin: 40 }));
    this.view.dispatch({ effects });
  }

  /** Marks a search match on a line (offsets into the line's text after
   * its indent, as DecompiledMatch gives them) and scrolls to it. */
  revealLine(line: number, from: number, to: number) {
    if (!this.fn || line < 0 || line >= this.fn.lines.length) return;
    this.find = { line, from, to };
    this.paintMarks(true);
  }

  // ------------------------------------------------------------- slices --

  /** A token's position in the function (SliceDecompiled's TokenPosition). */
  tokenPosition(s: TokSpan): { line: number; token: number } | null {
    const toks = this.fn?.lines[s.line]?.tokens;
    const i = toks ? toks.indexOf(s.tok) : -1;
    return i < 0 ? null : { line: s.line, token: i };
  }

  /** Highlights a slice's tokens (positions in this function) and keeps them for next/previous. */
  setSlice(positions: { line: number; token: number }[], label: string) {
    const want = new Set<CodeToken>();
    for (const p of positions) {
      const t = this.fn?.lines[p.line]?.tokens[p.token];
      if (t) want.add(t);
    }
    this.slice = { spans: this.spans.filter((s) => want.has(s.tok)), label };
    this.paintMarks(false);
  }

  /** Drops the slice highlight (Escape); `notify` tells the app. */
  clearSlice(notify = true) {
    if (!this.slice) return;
    this.slice = null;
    if (this.fn) this.paintMarks(false);
    if (notify) this.onSliceCleared?.();
  }

  /** Moves the cursor to the slice's next (1) or previous (-1) token, wrapping. */
  sliceStep(dir: 1 | -1): TokSpan | null {
    const list = this.slice?.spans ?? [];
    if (!list.length) return null;
    const at = this.selected?.from ?? (dir > 0 ? -1 : Infinity);
    const next = dir > 0 ? (list.find((s) => s.from > at) ?? list[0]) : ([...list].reverse().find((s) => s.from < at) ?? list[list.length - 1]);
    this.selected = next;
    const addr = this.addressOf(next);
    if (addr !== null) this.syncAddr = addr;
    this.paintMarks(false);
    this.view.dispatch({ effects: EditorView.scrollIntoView(next.from, { y: "nearest", yMargin: 40 }) });
    if (addr !== null) this.onSelectAddress?.(addr);
    return next;
  }

  /** The line a search match is shown on (tests). */
  get foundLine(): number | null {
    return this.find?.line ?? null;
  }

  /** Instruction addresses of the selected token's line (for the listing). */
  lineAddresses(s: TokSpan | null): Set<bigint> {
    const out = new Set<bigint>();
    if (!s) return out;
    for (const t of this.spans) if (t.line === s.line && t.tok.address) out.add(t.tok.address.offset);
    return out;
  }

  focus() {
    this.view.contentDOM.focus({ preventScroll: true });
  }

  get hasFocus() {
    return this.view.dom.contains(document.activeElement);
  }
}
