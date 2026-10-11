// Completion and signature help for Python in CodeMirror (docs/ui.md,
// "Scripts"): the script editor completes from the static index of the
// script API (script-api.json, generated from the SDK's docstrings by
// sdk/python/generate.sh), the console from its live namespace on the daemon
// (CompleteConsole). Both show a function's signature while its arguments
// are typed, from `(` to its `)`, with the current argument in bold.

import { autocompletion, type Completion, type CompletionContext, type CompletionResult, type CompletionSource } from "@codemirror/autocomplete";
import { StateEffect, StateField, type EditorState, type Extension } from "@codemirror/state";
import { EditorView, ViewPlugin, showTooltip, type Tooltip, type ViewUpdate } from "@codemirror/view";

export interface ApiEntry {
  name: string;
  /** function, class, instance, property, keyword, module. */
  kind: string;
  signature: string;
  doc: string;
  /** "revkit" or "ghidra" (the compat names). */
  group: string;
  /** For a global: the `members` key of what it is. */
  type?: string;
}

export interface ApiIndex {
  format: string;
  globals: ApiEntry[];
  members: Record<string, ApiEntry[]>;
}

let index: Promise<ApiIndex> | null = null;

/** The script API's index (loaded once, on first use). */
export function apiIndex(): Promise<ApiIndex> {
  index ??= import("./script-api.json").then((m) => (m.default ?? m) as unknown as ApiIndex);
  return index;
}

const KEYWORDS =
  "False None True and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield".split(
    " ",
  );
const BUILTINS =
  "abs all any bin bool bytes callable chr dict dir divmod enumerate filter float format frozenset getattr hasattr hash hex id int isinstance issubclass iter len list map max min next object oct open ord pow print range repr reversed round set setattr sorted str sum super tuple type vars zip".split(
    " ",
  );

/** CodeMirror's completion type for an entry's kind (its icon). */
function cmType(kind: string): string {
  switch (kind) {
    case "function":
      return "function";
    case "class":
      return "class";
    case "module":
      return "namespace";
    case "keyword":
      return "keyword";
    case "property":
      return "property";
    case "param":
      return "variable";
    default:
      return "variable";
  }
}

function option(e: { name: string; kind: string; signature: string; doc: string }, boost = 0): Completion {
  return {
    label: e.name,
    type: cmType(e.kind),
    detail: e.signature ? e.signature.slice(e.name.length) : undefined,
    info: e.doc || undefined,
    boost,
  };
}

/** Whether a script looks like a Ghidra one (its names then come first). */
function ghidraish(text: string): boolean {
  return /\bcurrentProgram\b|^\s*(from|import)\s+ghidra\b|@runtime\s+(Jython|PyGhidra)/m.test(text);
}

/** The dotted name being typed before `pos` ("current_program.fu"). */
function wordBefore(state: EditorState, pos: number): { from: number; text: string } | null {
  const line = state.doc.lineAt(pos);
  const before = line.text.slice(0, pos - line.from);
  const m = /[A-Za-z_][\w.]*$|$/.exec(before);
  const text = m ? m[0] : "";
  // Inside a string or a comment: nothing to complete.
  const head = before.slice(0, before.length - text.length);
  if (/#/.test(head.replace(/(["'])(?:\\.|(?!\1).)*\1/g, ""))) return null;
  if ((head.match(/["']/g)?.length ?? 0) % 2 === 1) return null;
  return { from: pos - text.length, text };
}

/** Completion from the static index: globals, and `.` members of the
 * globals whose type it knows (current_program., monitor., client.,
 * currentProgram., ...). */
export function staticCompletions(): CompletionSource {
  return async (ctx: CompletionContext): Promise<CompletionResult | null> => {
    const w = wordBefore(ctx.state, ctx.pos);
    if (!w || (!w.text && !ctx.explicit)) return null;
    const api = await apiIndex();
    const ghidraFirst = ghidraish(ctx.state.doc.toString());
    const boost = (e: ApiEntry) => ((e.group === "ghidra") === ghidraFirst ? 2 : 0);
    const dot = w.text.lastIndexOf(".");
    if (dot >= 0) {
      const head = w.text.slice(0, dot);
      const g = api.globals.find((e) => e.name === head);
      const members = g?.type ? api.members[g.type] : undefined;
      if (!members) return null;
      return { from: w.from + dot + 1, options: members.map((e) => option(e)), validFor: /^\w*$/ };
    }
    const options: Completion[] = api.globals.map((e) => option(e, boost(e)));
    for (const k of KEYWORDS) options.push({ label: k, type: "keyword", boost: -1 });
    for (const b of BUILTINS) options.push({ label: b, type: "function", boost: -1 });
    return { from: w.from, options, validFor: /^\w*$/ };
  };
}

/** The signature of a dotted name from the static index. */
export async function staticSignature(callee: string): Promise<{ signature: string; doc: string } | null> {
  const api = await apiIndex();
  const dot = callee.lastIndexOf(".");
  if (dot < 0) {
    const e = api.globals.find((x) => x.name === callee && x.signature);
    return e ? { signature: e.signature, doc: e.doc } : null;
  }
  const g = api.globals.find((x) => x.name === callee.slice(0, dot));
  const e = g?.type ? api.members[g.type]?.find((x) => x.name === callee.slice(dot + 1) && x.signature) : undefined;
  return e ? { signature: e.signature, doc: e.doc } : null;
}

/** Completion from a live namespace (the console's CompleteConsole). */
export function liveCompletions(
  complete: (text: string) => Promise<{ completions: { text: string; kind: string; signature: string; doc: string }[]; prefixLength: number } | null>,
): CompletionSource {
  return async (ctx: CompletionContext): Promise<CompletionResult | null> => {
    const w = wordBefore(ctx.state, ctx.pos);
    if (!w || (!w.text && !ctx.explicit)) return null;
    const r = await complete(ctx.state.sliceDoc(0, ctx.pos));
    if (!r || ctx.aborted || !r.completions.length) return null;
    return {
      from: ctx.pos - r.prefixLength,
      options: r.completions.map((c) => option({ name: c.text, kind: c.kind, signature: c.signature, doc: c.doc })),
      validFor: /^\w*$/,
    };
  };
}

// ------------------------------------------------------- signature help --

interface Sig {
  /** Where the call's `(` is. */
  open: number;
  signature: string;
  doc: string;
  /** Which argument the cursor is in (0-based). */
  arg: number;
}

const setSig = StateEffect.define<Sig | null>();

/** The innermost open call before `pos` in the same statement: its `(`,
 * the dotted callee, and which argument the cursor is in. */
export function openCall(text: string, pos: number): { open: number; callee: string; arg: number } | null {
  let depth = 0;
  let arg = 0;
  let quote = "";
  // Scan back at most 4000 characters.
  for (let i = pos - 1; i >= Math.max(0, pos - 4000); i--) {
    const c = text[i];
    if (quote) {
      if (c === quote && text[i - 1] !== "\\") quote = "";
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === ")" || c === "]" || c === "}") depth++;
    else if (c === "[" || c === "{") {
      if (depth === 0) return null;
      depth--;
    } else if (c === "(") {
      if (depth === 0) {
        const m = /([A-Za-z_][\w.]*)\s*$/.exec(text.slice(Math.max(0, i - 200), i));
        if (!m) return null;
        if (/^(if|elif|while|for|return|and|or|not|in|is|with|assert|yield|lambda|await|except)$/.test(m[1])) return null;
        return { open: i, callee: m[1], arg };
      }
      depth--;
    } else if (c === "," && depth === 0) arg++;
    else if (c === "\n" && depth === 0 && i < pos - 1 && !/[\\,(\[{]\s*$/.test(text.slice(Math.max(0, i - 80), i))) {
      // A new line outside brackets ends the statement.
      return null;
    }
  }
  return null;
}

/** The signature with the `arg`th parameter in bold. */
function renderSig(s: Sig): HTMLElement {
  const box = document.createElement("div");
  box.className = "cm-sig";
  box.dataset.testid = "signature-help";
  const sigEl = document.createElement("div");
  sigEl.className = "cm-sig-text";
  const open = s.signature.indexOf("(");
  const close = s.signature.lastIndexOf(")");
  if (open < 0 || close < open) {
    sigEl.textContent = s.signature;
  } else {
    const params: string[] = [];
    let depth = 0;
    let cur = "";
    for (const c of s.signature.slice(open + 1, close)) {
      if (c === "(" || c === "[" || c === "{") depth++;
      if (c === ")" || c === "]" || c === "}") depth--;
      if (c === "," && depth === 0) {
        params.push(cur.trim());
        cur = "";
      } else cur += c;
    }
    if (cur.trim()) params.push(cur.trim());
    // A bare "*" separator isn't an argument.
    let k = -1;
    sigEl.append(s.signature.slice(0, open + 1));
    params.forEach((p, i) => {
      if (i) sigEl.append(", ");
      if (p !== "*") k++;
      if (p !== "*" && k === s.arg) {
        const b = document.createElement("b");
        b.textContent = p;
        sigEl.append(b);
      } else sigEl.append(p);
    });
    sigEl.append(s.signature.slice(close));
  }
  box.append(sigEl);
  if (s.doc) {
    const d = document.createElement("div");
    d.className = "cm-sig-doc";
    d.textContent = s.doc;
    box.append(d);
  }
  return box;
}

const sigField = StateField.define<Sig | null>({
  create: () => null,
  update(v, tr) {
    for (const e of tr.effects) if (e.is(setSig)) return e.value;
    if (v && tr.docChanged) return { ...v, open: tr.changes.mapPos(v.open) };
    return v;
  },
  provide: (f) =>
    showTooltip.compute([f], (state): Tooltip | null => {
      const s = state.field(f);
      if (!s) return null;
      return { pos: s.open, above: true, strictSide: false, arrow: false, create: () => ({ dom: renderSig(s) }) };
    }),
});

/** Signature help: `resolve` gives a dotted callee's signature (or null). */
export function signatureHelp(resolve: (callee: string) => Promise<{ signature: string; doc: string } | null>): Extension {
  const plugin = ViewPlugin.fromClass(
    class {
      seq = 0;
      constructor(readonly view: EditorView) {}
      update(u: ViewUpdate) {
        if (!u.docChanged && !u.selectionSet) return;
        const state = u.state;
        const pos = state.selection.main.head;
        const call = openCall(state.doc.toString(), pos);
        const cur = state.field(sigField);
        if (!call) {
          if (cur) queueMicrotask(() => this.view.dispatch({ effects: setSig.of(null) }));
          return;
        }
        if (cur && cur.open === call.open) {
          if (cur.arg !== call.arg) queueMicrotask(() => this.view.dispatch({ effects: setSig.of({ ...cur, arg: call.arg }) }));
          return;
        }
        const seq = ++this.seq;
        void resolve(call.callee).then((r) => {
          if (seq !== this.seq) return;
          this.view.dispatch({ effects: setSig.of(r ? { open: call.open, signature: r.signature, doc: r.doc, arg: call.arg } : null) });
        });
      }
    },
  );
  const clear = (view: EditorView) => {
    if (view.state.field(sigField, false)) view.dispatch({ effects: setSig.of(null) });
  };
  return [sigField, plugin, EditorView.domEventHandlers({ blur: (_e, view) => void setTimeout(() => !view.hasFocus && view.dom.isConnected && clear(view), 150) })];
}

/** Closes the signature tooltip (Escape). */
export function closeSignature(view: EditorView): boolean {
  if (!view.state.field(sigField, false)) return false;
  view.dispatch({ effects: setSig.of(null) });
  return true;
}

/** The script editor's completion: the static index, with signature help. */
export function editorAssist(): Extension {
  return [autocompletion({ override: [staticCompletions()], activateOnTyping: true, maxRenderedOptions: 80, interactionDelay: 0 }), signatureHelp(staticSignature)];
}
