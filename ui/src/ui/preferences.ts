// Preferences (File → Preferences…, the palette's "Preferences…") and the
// keyboard cheat sheet ("Help: Keyboard shortcuts"): docs/ui.md, "Keymap
// presets". Per viewer, in localStorage (the keymap: rk.keymap).

import { h, overlayRoot } from "./dom";
import { chordLabel, type Keymap, PRESETS, type PresetId } from "./keymap";

/** A modal of the usual shape: Escape or a click outside closes it. */
function modal(box: HTMLElement): () => void {
  const restore = document.activeElement as HTMLElement | null;
  const backdrop = h("div", { class: "backdrop top" }, box);
  const close = () => {
    backdrop.remove();
    restore?.focus({ preventScroll: true });
  };
  box.addEventListener("keydown", (e) => {
    e.stopPropagation();
    if (e.key === "Escape") close();
  });
  backdrop.addEventListener("mousedown", (e) => {
    if (e.target === backdrop) close();
  });
  overlayRoot().append(backdrop);
  return close;
}

export interface PreferencesHost {
  keymap: Keymap;
  /** Opens the cheat sheet (after the dialog closes). */
  showShortcuts: () => void;
}

export function showPreferences(host: PreferencesHost) {
  const km = host.keymap;
  const radios = PRESETS.map((p) => {
    const input = h("input", { type: "radio", name: "rk-keymap", value: p.id, "data-testid": `pref-keymap-${p.id}` });
    input.checked = p.id === km.preset;
    input.addEventListener("change", () => {
      if (input.checked) km.set(p.id as PresetId);
    });
    return h("label", { class: "pref-choice" }, input, ` ${p.name}`, p.id === "ghidra" ? h("span", { class: "dim" }, " (default)") : null);
  });
  const sheet = h("button", { class: "btn", type: "button", "data-testid": "pref-shortcuts" }, "Show keyboard shortcuts…");
  const done = h("button", { class: "btn primary", type: "button", "data-testid": "pref-close" }, "Close");
  const box = h(
    "div",
    { class: "modal preferences", role: "dialog", "aria-modal": "true", tabindex: "-1", "aria-label": "Preferences", "data-testid": "preferences" },
    h("div", { class: "modal-title" }, "Preferences"),
    h(
      "fieldset",
      { class: "pref-group" },
      h("legend", {}, "Keymap"),
      h("div", { class: "pref-choices", role: "radiogroup", "aria-label": "Keymap" }, ...radios),
      h(
        "div",
        { class: "modal-hint" },
        "The keys of the tool you know: rename, set type, comments, cross references, go to, the listing's code and data keys, back and forward, the decompiler, search. Menus and the palette show the chosen keys. Kept in this browser.",
      ),
    ),
    h("div", { class: "pref-actions" }, sheet, h("span", { class: "spacer" }), done),
  );
  const close = modal(box);
  sheet.onclick = () => {
    close();
    host.showShortcuts();
  };
  done.onclick = close;
  (radios.find((r) => r.querySelector("input")!.checked)?.querySelector("input") ?? box).focus();
}

/** The active preset's bindings, grouped, with a filter. */
export function showShortcuts(km: Keymap, titles: Map<string, string>) {
  const rows = km
    .bindings()
    .filter(([id]) => titles.has(id))
    .map(([id, keys]) => ({ id, title: titles.get(id)!, keys: keys.map(chordLabel) }));
  rows.sort((a, b) => a.title.localeCompare(b.title));
  const filter = h("input", { class: "ask-input", placeholder: "Filter (an action or a key)", "aria-label": "Filter shortcuts", spellcheck: "false", "data-testid": "shortcuts-filter" });
  const body = h("tbody", {});
  const table = h("table", { class: "shortcuts-table" }, h("thead", {}, h("tr", {}, h("th", {}, "Action"), h("th", {}, "Keys"))), body);
  const fill = () => {
    const q = filter.value.trim().toLowerCase();
    body.replaceChildren(
      ...rows
        .filter((r) => !q || r.title.toLowerCase().includes(q) || r.keys.some((k) => k.toLowerCase() === q || k.toLowerCase().includes(q)))
        .map((r) => h("tr", { "data-action": r.id, "data-testid": "shortcut-row" }, h("td", {}, r.title), h("td", { class: "mono" }, ...r.keys.flatMap((k, i) => [i ? " " : "", h("kbd", {}, k)])))),
    );
  };
  filter.addEventListener("input", fill);
  fill();
  const box = h(
    "div",
    { class: "modal shortcuts", role: "dialog", "aria-modal": "true", tabindex: "-1", "aria-label": "Keyboard shortcuts", "data-testid": "shortcuts", "data-preset": km.preset },
    h("div", { class: "modal-title" }, `Keyboard shortcuts: ${km.name}`),
    filter,
    h("div", { class: "shortcuts-scroll" }, table),
    h("div", { class: "modal-hint" }, "Ctrl+K / G go to, Ctrl+Shift+P or F1 every command. Change the keymap in File → Preferences… · Esc closes"),
  );
  modal(box);
  filter.focus();
}
