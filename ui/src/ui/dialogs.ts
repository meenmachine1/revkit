// Modal text input (rename, comment) and toasts.

import { h, overlayRoot } from "./dom";

export interface AskOptions {
  title: string;
  value?: string;
  placeholder?: string;
  hint?: string;
  /** Multi-line (comments). Enter saves, Shift+Enter is a newline. */
  multiline?: boolean;
  validate?: (v: string) => string | null;
  /** Asked after `validate` passes (the daemon's validate_only): an error
   * keeps the dialog open and shows it. `controls` are the controls' values. */
  check?: (v: string, controls: ControlValues, extra: string) => Promise<string | null>;
  /** Choices under the field (Set Equate's "Apply to", a reference's type,
   * operand and primary): radio groups, drop-downs and check boxes. Enter
   * on any of them saves, as on the field. */
  controls?: Control[];
  /** A second field (a note's tag). */
  extra?: { label: string; value: string; placeholder?: string };
  /** Single-line only: suggestions for what is typed, shown in a dropdown
   *  under the field (a type chooser). ↑↓ move, Tab or Enter on a highlighted
   *  suggestion takes it into the field (Enter on the field as typed saves). */
  suggest?: (v: string) => Promise<Suggestion[]>;
  /** A button beside the field (e.g. "Browse types…"); closes the dialog. */
  browse?: { label: string; run: () => void };
}

export interface Suggestion {
  /** What the row shows (a type's name). */
  label: string;
  /** Dimmed, on the right (its kind, size, where it comes from). */
  detail?: string;
  /** The field's new text when it is taken. */
  insert: string;
}

export type Control =
  | { kind: "radio" | "select"; name: string; label: string; choices: { label: string; value: string }[]; value: string }
  | { kind: "check"; name: string; label: string; value: boolean };

export type ControlValues = Record<string, string | boolean>;

export interface AskResult {
  value: string;
  extra: string;
  controls: ControlValues;
}

/** The elements of `controls` (ask's) and a reader of their values. */
function controlElements(controls: Control[]): { els: HTMLElement[]; inputs: HTMLElement[]; values: () => ControlValues } {
  const els: HTMLElement[] = [];
  const inputs: HTMLElement[] = [];
  const read: (() => [string, string | boolean])[] = [];
  for (const c of controls) {
    const tid = `ask-${c.name}`;
    if (c.kind === "check") {
      const box = h("input", { type: "checkbox", "data-testid": tid }) as HTMLInputElement;
      box.checked = c.value;
      inputs.push(box);
      els.push(h("label", { class: "ask-control ask-check" }, box, h("span", {}, c.label)));
      read.push(() => [c.name, box.checked]);
    } else if (c.kind === "select") {
      const sel = h("select", { class: "ask-select", "data-testid": tid, "aria-label": c.label }, ...c.choices.map((x) => h("option", { value: x.value }, x.label))) as HTMLSelectElement;
      sel.value = c.value;
      inputs.push(sel);
      els.push(h("label", { class: "ask-control" }, h("span", { class: "ask-field-name dim" }, c.label), sel));
      read.push(() => [c.name, sel.value]);
    } else {
      const group = `ask-${c.name}-${Math.random().toString(36).slice(2)}`;
      const radios = c.choices.map((x) => {
        const r = h("input", { type: "radio", name: group, value: x.value, "data-testid": `${tid}-${x.value}` }) as HTMLInputElement;
        r.checked = x.value === c.value;
        inputs.push(r);
        return h("label", { class: "ask-radio" }, r, h("span", {}, x.label));
      });
      els.push(h("fieldset", { class: "ask-control ask-radios", "data-testid": tid }, h("legend", { class: "dim" }, c.label), ...radios));
      read.push(() => [c.name, (radios.map((l) => l.querySelector("input")!).find((r) => r.checked)?.value ?? c.value)]);
    }
  }
  return { els, inputs, values: () => Object.fromEntries(read.map((f) => f())) };
}

let open: HTMLElement | null = null;

/** Resolves to the entered text, or null when cancelled. */
export async function ask(o: AskOptions): Promise<string | null> {
  return (await askMore(o))?.value ?? null;
}

/** Like ask(), with the second field's value. */
export function askMore(o: AskOptions): Promise<AskResult | null> {
  open?.remove();
  return new Promise((resolve) => {
    const restore = document.activeElement as HTMLElement | null;
    const input = o.multiline
      ? h("textarea", { class: "ask-input", rows: 3, placeholder: o.placeholder ?? "", spellcheck: "false", "aria-label": o.title })
      : h("input", { class: "ask-input", placeholder: o.placeholder ?? "", spellcheck: "false", autocomplete: "off", "aria-label": o.title });
    input.value = o.value ?? "";
    const extra = o.extra ? h("input", { class: "ask-input ask-extra", placeholder: o.extra.placeholder ?? "", spellcheck: "false", autocomplete: "off", "aria-label": o.extra.label }) : null;
    if (extra) extra.value = o.extra!.value;
    const err = h("div", { class: "ask-error", "data-testid": "ask-error" });
    const ctl = controlElements(o.controls ?? []);
    // The dropdown of suggestions (a type chooser), under the field.
    const drop = o.suggest && !o.multiline ? h("div", { class: "ask-drop", role: "listbox", "data-testid": "ask-drop", hidden: true }) : null;
    let shown: Suggestion[] = [];
    let active = -1;
    let asked = 0;
    const paint = () => {
      if (!drop) return;
      drop.hidden = shown.length === 0;
      drop.replaceChildren(
        ...shown.map((sg, i) => {
          const row = h(
            "div",
            { class: "ask-drop-row" + (i === active ? " active" : ""), role: "option", "aria-selected": String(i === active), "data-testid": "ask-drop-row" },
            h("span", { class: "ask-drop-label" }, sg.label),
            sg.detail ? h("span", { class: "ask-drop-detail dim" }, sg.detail) : null,
          );
          row.addEventListener("mousedown", (e) => {
            e.preventDefault();
            take(i);
          });
          return row;
        }),
      );
      drop.querySelector(".active")?.scrollIntoView({ block: "nearest" });
    };
    const refresh = async () => {
      if (!drop || !o.suggest) return;
      const n = ++asked;
      const got = await o.suggest(input.value).catch(() => [] as Suggestion[]);
      if (n !== asked) return;  // typed on since
      shown = got;
      active = -1;
      paint();
    };
    const take = (i: number) => {
      const sg = shown[i];
      if (!sg) return;
      input.value = sg.insert;
      shown = [];
      active = -1;
      paint();
      input.focus();
      err.textContent = "";
    };
    let timer: ReturnType<typeof setTimeout> | undefined;
    if (drop) {
      input.addEventListener("input", () => {
        // What was suggested for the old text no longer applies.
        shown = [];
        active = -1;
        asked++;
        paint();
        clearTimeout(timer);
        timer = setTimeout(() => void refresh(), 90);
      });
      input.addEventListener("focus", () => void refresh());
    }
    const browseBtn = o.browse
      ? h("button", { class: "btn ask-browse", type: "button", "data-testid": "ask-browse", onclick: () => { done(null); o.browse!.run(); } }, o.browse.label)
      : null;
    const box = h(
      "div",
      { class: "modal ask", role: "dialog", "aria-modal": "true", "aria-label": o.title, "data-testid": "ask" },
      h("div", { class: "modal-title" }, o.title),
      extra ? h("label", { class: "ask-label dim" }, o.extra!.label, extra) : null,
      browseBtn ? h("div", { class: "ask-row" }, input, browseBtn) : input,
      drop,
      ...ctl.els,
      err,
      h("div", { class: "modal-hint" }, o.hint ?? (o.multiline ? "Enter to save · Shift+Enter for a new line · Esc to cancel" : "Enter to save · Esc to cancel")),
    );
    const backdrop = h("div", { class: "backdrop" }, box);
    const done = (v: string | null) => {
      backdrop.remove();
      if (open === backdrop) open = null;
      restore?.focus({ preventScroll: true });
      resolve(v === null ? null : { value: v, extra: extra?.value ?? "", controls: ctl.values() });
    };
    let checking = false;
    const onKey = async (e: Event) => {
      const ke = e as KeyboardEvent;
      ke.stopPropagation();
      if (drop && shown.length && ke.target === input) {
        if (ke.key === "ArrowDown" || ke.key === "ArrowUp") {
          ke.preventDefault();
          active = ke.key === "ArrowDown" ? (active + 1) % shown.length : (active - 1 + shown.length) % shown.length;
          paint();
          return;
        }
        if ((ke.key === "Tab" || ke.key === "Enter") && active >= 0) {
          ke.preventDefault();
          take(active);
          return;
        }
        if (ke.key === "Escape") {
          // First Escape closes the dropdown, the next the dialog.
          ke.preventDefault();
          shown = [];
          active = -1;
          paint();
          return;
        }
      }
      if (ke.key === "Escape") done(null);
      else if (ke.key === "Enter" && !(o.multiline && ke.shiftKey && ke.target === input)) {
        ke.preventDefault();
        if (checking) return;
        const v = input.value;
        let problem = o.validate?.(v) ?? null;
        if (!problem && o.check) {
          checking = true;
          box.classList.add("busy");
          problem = await o.check(v, ctl.values(), extra?.value ?? "");
          checking = false;
          box.classList.remove("busy");
        }
        if (problem) {
          err.textContent = problem;
          box.dataset.error = "1";
        } else done(v);
      }
    };
    input.addEventListener("keydown", onKey);
    extra?.addEventListener("keydown", onKey);
    for (const c of ctl.inputs) c.addEventListener("keydown", onKey);
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done(null);
    });
    overlayRoot().append(backdrop);
    open = backdrop;
    input.focus();
    input.select();
  });
}

export interface Choice<T> {
  label: string;
  detail?: string;
  value: T;
  current?: boolean;
}

/** A list to pick one item from (↑↓ Enter, or a click). Null when cancelled. */
export function choose<T>(title: string, choices: Choice<T>[], hint = "↑↓ select · Enter choose · Esc cancel"): Promise<T | null> {
  open?.remove();
  return new Promise((resolve) => {
    const restore = document.activeElement as HTMLElement | null;
    let active = Math.max(0, choices.findIndex((c) => c.current));
    const list = h("div", { class: "palette-list", role: "listbox", "aria-label": title, tabindex: "-1" });
    const box = h("div", { class: "modal palette", role: "dialog", "aria-modal": "true", tabindex: "-1", "aria-label": title, "data-testid": "choose" }, h("div", { class: "modal-title" }, title), list, h("div", { class: "modal-hint" }, hint));
    const backdrop = h("div", { class: "backdrop top" }, box);
    const done = (v: T | null) => {
      backdrop.remove();
      if (open === backdrop) open = null;
      restore?.focus({ preventScroll: true });
      resolve(v);
    };
    const paint = () =>
      list.replaceChildren(
        ...choices.map((c, i) =>
          h(
            "div",
            { class: "palette-item" + (i === active ? " active" : ""), "data-i": i, role: "option", "data-value": String(c.value) },
            h("span", { class: "pi-label" }, c.label + (c.current ? "  (current)" : "")),
            c.detail ? h("span", { class: "pi-detail dim" }, c.detail) : null,
          ),
        ),
      );
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") done(null);
      else if (e.key === "ArrowDown") active = Math.min(choices.length - 1, active + 1);
      else if (e.key === "ArrowUp") active = Math.max(0, active - 1);
      else if (e.key === "Enter") return done(choices[active]?.value ?? null);
      else return;
      e.preventDefault();
      paint();
    });
    list.addEventListener("mousedown", (e) => {
      const el = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (!el) return;
      e.preventDefault();
      done(choices[Number(el.dataset.i)]?.value ?? null);
    });
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done(null);
    });
    paint();
    overlayRoot().append(backdrop);
    open = backdrop;
    box.focus();
  });
}

export interface ToastAction {
  label: string;
  run: () => void;
}

export function toast(text: string, opts: { kind?: "info" | "error" | "remote"; action?: ToastAction; ms?: number } = {}) {
  let host = document.getElementById("toasts");
  if (!host) {
    host = h("div", { id: "toasts", "aria-live": "polite" });
    document.body.append(host);
  }
  const el = h("div", { class: `toast ${opts.kind ?? "info"}` }, h("span", {}, text));
  if (opts.action) {
    const a = opts.action;
    el.append(
      h("button", {
        class: "link",
        onclick: () => {
          a.run();
          el.remove();
        },
        text: a.label,
      }),
    );
  }
  host.append(el);
  setTimeout(() => el.classList.add("out"), (opts.ms ?? 4000) - 300);
  setTimeout(() => el.remove(), opts.ms ?? 4000);
  while (host.children.length > 4) host.firstElementChild?.remove();
}

export interface FieldSpec {
  name: string;
  label: string;
  placeholder?: string;
  required?: boolean;
  value?: string;
}

/** A form of text fields (a plugin command's arguments). Null when cancelled. */
export function askFields(title: string, fields: FieldSpec[], hint = "Enter to run · Esc to cancel"): Promise<Record<string, string> | null> {
  open?.remove();
  return new Promise((resolve) => {
    const restore = document.activeElement as HTMLElement | null;
    const inputs = fields.map((f) => {
      const el = h("input", { class: "ask-input", placeholder: f.placeholder ?? "", spellcheck: "false", autocomplete: "off", "aria-label": f.label, "data-field": f.name });
      el.value = f.value ?? "";
      return el;
    });
    const err = h("div", { class: "ask-error", "data-testid": "ask-error" });
    const box = h(
      "div",
      { class: "modal ask", role: "dialog", tabindex: "-1", "aria-label": title, "data-testid": "ask-fields" },
      h("div", { class: "modal-title" }, title),
      ...fields.map((f, i) => h("label", { class: "ask-label dim" }, h("span", { class: "ask-field-name" }, f.label + (f.required ? " *" : "")), inputs[i])),
      err,
      h("div", { class: "modal-hint" }, hint),
    );
    const backdrop = h("div", { class: "backdrop" }, box);
    const done = (v: Record<string, string> | null) => {
      backdrop.remove();
      if (open === backdrop) open = null;
      restore?.focus({ preventScroll: true });
      resolve(v);
    };
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") done(null);
      else if (e.key === "Enter") {
        e.preventDefault();
        const missing = fields.find((f, i) => f.required && !inputs[i].value.trim());
        if (missing) {
          err.textContent = `${missing.label} is required`;
          return;
        }
        const out: Record<string, string> = {};
        fields.forEach((f, i) => {
          if (inputs[i].value !== "") out[f.name] = inputs[i].value;
        });
        done(out);
      }
    });
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done(null);
    });
    overlayRoot().append(backdrop);
    open = backdrop;
    inputs[0]?.focus();
    if (!inputs.length) box.focus();
  });
}
