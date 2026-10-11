// Edit Function (docs/ui.md "Edit function"), as Ghidra's dialog: the C
// signature on top, kept in step with the fields below it both ways (the
// function's name, its return type, the calling convention from the
// compiler spec's models, the parameters with add, remove and move, and
// varargs). Apply sets the prototype (and renames the function when its
// name changed) in one request, one undo step. The daemon checks the C as
// it is typed; its errors show under the signature.
//
// No Return is the user's word on whether it returns (feature no-return;
// SetNoReturn in the same request). Inline is not offered (revkit has no
// inline fact); parameter storage is not shown: the daemon doesn't report
// it before the decompiler assigns it.

import type { CallingConvention } from "@revkit/api";
import { h, overlayRoot } from "./dom";
import type { Suggestion } from "./dialogs";

export interface FunctionDraft {
  name: string;
  ret: string;
  /** The model's name, or "" for none (the spec's default). */
  convention: string;
  params: { name: string; type: string }[];
  varargs: boolean;
  /** Calls to it end their caller's flow (feature no-return); undefined: not offered. */
  noReturn?: boolean;
}

export interface EditFunctionOptions {
  title: string;
  initial: FunctionDraft;
  conventions: CallingConvention[];
  /** The spec's default model ("__stdcall"). */
  defaultName: string;
  /** The daemon's check of a C prototype: its error, or null. */
  check: (c: string) => Promise<string | null>;
  /** Applies (one undo step): an error to show, or null when done. */
  apply: (draft: FunctionDraft, c: string) => Promise<string | null>;
  suggest?: (text: string) => Promise<Suggestion[]>;
}

/** No convention keyword: the compiler spec's default, as Ghidra's "unknown" and "default" both decompile. */
const NONE = "";
const C_NAME = /^[A-Za-z_]\w*$/;
let lists = 0;

/** A declarator: "char *" + "s" is "char *s"; "int" + "n" is "int n". */
function declare(type: string, name: string): string {
  const t = type.trim();
  if (!name) return t;
  // A function pointer or an array keeps its name inside: int (*cb)(int), char buf[8].
  if (/\(\s*\*\s*\)/.test(t)) return t.replace(/\(\s*\*\s*\)/, `(*${name})`);
  const arr = /^(.*?)(\[[^\]]*\])+$/.exec(t);
  if (arr) return `${arr[1].trim()} ${name}${t.slice(arr[1].length)}`;
  return t.endsWith("*") ? `${t}${name}` : `${t} ${name}`;
}

/** The draft as C, the convention by its C spelling. */
export function draftToC(d: FunctionDraft, conventions: CallingConvention[]): string {
  const spell = conventions.find((c) => c.name === d.convention)?.cSpelling ?? "";
  const params = d.params.map((p) => declare(p.type || "int", p.name));
  if (d.varargs) params.push("...");
  // No return type: Ghidra's DEFAULT ("undefined"), which leaves the return
  // to the decompiler (unlocked); "void" says it returns nothing.
  const ret = d.ret.trim() || "undefined";
  return `${ret}${ret.endsWith("*") ? "" : " "}${spell ? `${spell} ` : ""}${d.name}(${params.length ? params.join(", ") : "void"})`;
}

/** Splits at top-level commas (not inside parentheses or brackets). */
function splitTop(s: string): string[] {
  const out: string[] = [];
  let depth = 0, from = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "(" || c === "[") depth++;
    else if (c === ")" || c === "]") depth--;
    else if (c === "," && depth === 0) {
      out.push(s.slice(from, i));
      from = i + 1;
    }
  }
  out.push(s.slice(from));
  return out.map((x) => x.trim()).filter((x) => x !== "");
}

/** One parameter's C as a name and a type ("char *s" -> s, char *; "int (*cb)(int)" -> cb, int (*)(int)). */
function splitParam(p: string): { name: string; type: string } {
  const fp = /^(.*\(\s*\*\s*)([A-Za-z_]\w*)(\s*\).*)$/.exec(p);
  if (fp) return { name: fp[2], type: `${fp[1]}${fp[3]}`.replace(/\(\s*\*\s*\)/, "(*)") };
  const arr = /^(.*?)([A-Za-z_]\w*)\s*((\[[^\]]*\])+)$/.exec(p);
  if (arr && /\S/.test(arr[1])) return { name: arr[2], type: `${arr[1].trim()}${arr[3]}` };
  const m = /^(.*?[\s*])([A-Za-z_]\w*)$/.exec(p);
  // A lone type ("int", "unsigned long", "struct x *") keeps no name.
  if (m && !/^(int|char|short|long|signed|unsigned|float|double|void|const|volatile)$/.test(m[2]) && /[A-Za-z_]/.test(m[1]))
    return { name: m[2], type: m[1].trim() };
  return { name: "", type: p };
}

/** C back to a draft (the common forms; the daemon has the last word on what it means). Null: unreadable. */
export function cToDraft(c: string, conventions: CallingConvention[]): FunctionDraft | null {
  const src = c.trim().replace(/;\s*$/, "");
  const open = src.indexOf("(");
  if (open < 0 || !src.endsWith(")")) return null;
  // The parameter list: the parentheses that close at the end.
  let depth = 0, start = -1;
  for (let i = src.length - 1; i >= 0; i--) {
    if (src[i] === ")") depth++;
    else if (src[i] === "(" && --depth === 0) {
      start = i;
      break;
    }
  }
  if (start < 0) return null;
  const head = src.slice(0, start).trim();
  const inner = src.slice(start + 1, -1);
  const nm = /([A-Za-z_]\w*)$/.exec(head);
  if (!nm) return null;
  let rest = head.slice(0, nm.index).trim();
  let convention = NONE;
  for (const cv of conventions) {
    if (!cv.cSpelling) continue;
    const at = rest.indexOf(cv.cSpelling);
    if (at >= 0) {
      convention = cv.name;
      rest = (rest.slice(0, at) + rest.slice(at + cv.cSpelling.length)).replace(/\s+/g, " ").trim();
      break;
    }
  }
  const parts = splitTop(inner);
  const varargs = parts.at(-1) === "...";
  if (varargs) parts.pop();
  const params = parts.length === 1 && parts[0] === "void" ? [] : parts.map(splitParam);
  return { name: nm[1], ret: rest === "undefined" ? "" : rest || "void", convention, params, varargs };
}

/** Opens the dialog; resolves when it closes (true: applied). */
export function editFunction(o: EditFunctionOptions): Promise<boolean> {
  return new Promise((resolve) => {
    const restore = document.activeElement as HTMLElement | null;
    let draft: FunctionDraft = structuredClone(o.initial);
    const listId = `ef-types-${++lists}`;
    const typeList = h("datalist", { id: listId });
    const sig = h("textarea", { class: "ask-input ef-sig mono", rows: 2, spellcheck: "false", "aria-label": "Signature (C)", "data-testid": "ef-signature" }) as HTMLTextAreaElement;
    const sigError = h("div", { class: "ask-error", role: "alert", "data-testid": "ef-error" });
    const name = h("input", { class: "filter ef-name", spellcheck: "false", autocomplete: "off", "aria-label": "Function name", "data-testid": "ef-name" }) as HTMLInputElement;
    const ret = h("input", {
      class: "filter ef-ret",
      spellcheck: "false",
      autocomplete: "off",
      placeholder: "undefined (the decompiler's)",
      title: "undefined, or empty: the decompiler decides the return (unlocked), as Ghidra's undefined return; void: it returns nothing",
      "aria-label": "Return type",
      "data-testid": "ef-return",
      list: o.suggest ? listId : undefined,
    }) as HTMLInputElement;
    const conv = h(
      "select",
      { class: "filter select ef-conv", "aria-label": "Calling convention", "data-testid": "ef-convention", title: "The compiler spec's prototype models: where the parameters and the return value go, and who cleans the stack" },
      h("option", { value: NONE }, `default${o.defaultName ? ` (${o.defaultName})` : ""}`),
      h("option", { value: "unknown", title: "Not specified: decompiled with the default" }, "unknown"),
      ...o.conventions.map((c) =>
        h(
          "option",
          { value: c.name, disabled: !c.cSpelling, title: c.cSpelling ? `${c.name}${c.isDefault ? " (the spec's default)" : ""}` : `${c.name}: revkit's C parser has no spelling for this model yet` },
          `${c.name}${c.isDefault ? " (default)" : ""}${c.cSpelling ? "" : " (no C spelling)"}`,
        ),
      ),
    ) as HTMLSelectElement;
    const varargs = h("input", { type: "checkbox", "data-testid": "ef-varargs" }) as HTMLInputElement;
    const noReturn = h("input", { type: "checkbox", "data-testid": "ef-no-return" }) as HTMLInputElement;
    const rows = h("tbody", {});
    const addBtn = h("button", { class: "btn small", type: "button", "data-testid": "ef-add", onclick: () => addParam() }, "+ Parameter");
    const apply = h("button", { class: "btn primary", type: "button", "data-testid": "ef-apply" }, "Apply");
    const cancel = h("button", { class: "btn", type: "button", "data-testid": "ef-cancel", onclick: () => done(false) }, "Cancel");
    const box = h(
      "div",
      { class: "modal edit-function", role: "dialog", "aria-modal": "true", "aria-label": o.title, "data-testid": "edit-function" },
      h("div", { class: "modal-title" }, o.title),
      h("label", { class: "ef-label dim" }, "Signature", sig),
      sigError,
      h(
        "div",
        { class: "ef-grid" },
        h("label", { class: "ef-label dim" }, "Name", name),
        h("label", { class: "ef-label dim" }, "Return type", ret),
        h("label", { class: "ef-label dim" }, "Calling convention", conv),
      ),
      h(
        "div",
        { class: "ef-scroll" },
        h("table", { class: "ef-params", "data-testid": "ef-params" }, h("thead", {}, h("tr", {}, h("th", {}, "#"), h("th", {}, "Type"), h("th", {}, "Name"), h("th", {}, ""))), rows),
        typeList,
      ),
      h(
        "div",
        { class: "ef-row" },
        addBtn,
        h("label", { class: "ask-check dim small" }, varargs, "Varargs (…)"),
        draft.noReturn !== undefined ? h("label", { class: "ask-check dim small", title: "Calls to it end their caller's flow there (Ghidra's No Return)" }, noReturn, "No return") : null,
        h("span", { class: "spacer" }),
        cancel,
        apply,
      ),
      h("div", { class: "modal-hint" }, "Edit the signature or the fields: each follows the other · Ctrl+Enter applies (one undo step) · Esc cancels"),
    );
    const backdrop = h("div", { class: "backdrop" }, box);

    // --- fields <-> draft <-> signature ---
    let explicitUnknown = false;
    const paintFields = () => {
      name.value = draft.name;
      ret.value = draft.ret;
      conv.value = draft.convention || (explicitUnknown ? "unknown" : NONE);
      varargs.checked = draft.varargs;
      noReturn.checked = !!draft.noReturn;
      rows.replaceChildren(
        ...draft.params.map((p, i) => {
          const type = h("input", { class: "as-cell mono", spellcheck: "false", autocomplete: "off", "aria-label": `Type of parameter ${i + 1}`, "data-testid": "ef-param-type", list: o.suggest ? listId : undefined }) as HTMLInputElement;
          const pname = h("input", { class: "as-cell mono", spellcheck: "false", autocomplete: "off", "aria-label": `Name of parameter ${i + 1}`, "data-testid": "ef-param-name" }) as HTMLInputElement;
          type.value = p.type;
          pname.value = p.name;
          type.addEventListener("input", () => {
            p.type = type.value;
            void fillTypes(type.value);
            fromFields();
          });
          pname.addEventListener("input", () => {
            p.name = pname.value;
            fromFields();
          });
          const act = (label: string, title: string, testid: string, run: () => void, disabled = false) =>
            h("button", { class: "icon", type: "button", title, "aria-label": `${title} (parameter ${i + 1})`, "data-testid": testid, disabled, onclick: () => { run(); paintFields(); fromFields(); } }, label);
          return h(
            "tr",
            { "data-testid": "ef-param" },
            h("td", { class: "mono dim" }, String(i + 1)),
            h("td", {}, type),
            h("td", {}, pname),
            h(
              "td",
              { class: "row-actions" },
              act("↑", "Move up", "ef-param-up", () => draft.params.splice(i - 1, 0, ...draft.params.splice(i, 1)), i === 0),
              act("↓", "Move down", "ef-param-down", () => draft.params.splice(i + 1, 0, ...draft.params.splice(i, 1)), i === draft.params.length - 1),
              act("×", "Remove", "ef-param-remove", () => draft.params.splice(i, 1)),
            ),
          );
        }),
      );
    };
    const fromFields = () => {
      draft.name = name.value.trim();
      draft.ret = ret.value.trim();
      explicitUnknown = conv.value === "unknown";
      draft.convention = conv.value === "unknown" ? NONE : conv.value;
      draft.varargs = varargs.checked;
      if (draft.noReturn !== undefined) draft.noReturn = noReturn.checked;
      sig.value = draftToC(draft, o.conventions);
      schedule();
    };
    const fromSignature = () => {
      const d = cToDraft(sig.value, o.conventions);
      if (!d) {
        sigError.textContent = "Not a prototype (int name(char *s, int n))";
        apply.disabled = true;
        return;
      }
      draft = { ...d, noReturn: draft.noReturn };
      paintFields();
      schedule();
    };
    const addParam = () => {
      draft.params.push({ type: "int", name: `param_${draft.params.length + 1}` });
      paintFields();
      fromFields();
      rows.querySelectorAll<HTMLInputElement>("[data-testid=ef-param-type]")[draft.params.length - 1]?.focus();
    };
    let typeSeq = 0;
    const fillTypes = async (text: string) => {
      if (!o.suggest) return;
      const n = ++typeSeq;
      const list = await o.suggest(text).catch(() => [] as Suggestion[]);
      if (n === typeSeq) typeList.replaceChildren(...list.slice(0, 40).map((s) => h("option", { value: s.insert }, s.detail ? `${s.label} · ${s.detail}` : s.label)));
    };

    // --- the daemon's check, debounced ---
    let timer: ReturnType<typeof setTimeout> | undefined;
    let checked = 0;
    const schedule = () => {
      clearTimeout(timer);
      apply.disabled = true;
      timer = setTimeout(() => void runCheck(), 250);
    };
    const runCheck = async (): Promise<boolean> => {
      timer = undefined;
      const n = ++checked;
      const local = !C_NAME.test(draft.name) ? `${draft.name || "(empty)"} is not a C name` : null;
      const err = local ?? (await o.check(sig.value).catch((e) => String(e)));
      if (n !== checked) return false;
      sigError.textContent = err ?? "";
      sig.classList.toggle("problem", !!err);
      apply.disabled = !!err;
      return !err;
    };
    const take = async () => {
      clearTimeout(timer);
      if (!(await runCheck())) return;
      apply.disabled = true;
      box.classList.add("busy");
      const err = await o.apply(draft, sig.value.trim());
      box.classList.remove("busy");
      if (err) {
        sigError.textContent = err;
        apply.disabled = false;
        return;
      }
      done(true);
    };
    apply.addEventListener("click", () => void take());
    for (const el of [name, ret]) el.addEventListener("input", fromFields);
    ret.addEventListener("input", () => void fillTypes(ret.value));
    conv.addEventListener("change", fromFields);
    varargs.addEventListener("change", fromFields);
    noReturn.addEventListener("change", fromFields);
    sig.addEventListener("input", fromSignature);

    const done = (v: boolean) => {
      clearTimeout(timer);
      backdrop.remove();
      restore?.focus({ preventScroll: true });
      resolve(v);
    };
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") done(false);
      else if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        void take();
      } else if (e.key === "Enter" && e.target === sig) e.preventDefault();
    });
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done(false);
    });
    overlayRoot().append(backdrop);
    paintFields();
    sig.value = draftToC(draft, o.conventions);
    void runCheck();
    name.focus();
    name.select();
  });
}
