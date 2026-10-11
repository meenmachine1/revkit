// Diagnostics: time the system file chooser (docs/known-issues.md, "Opening
// a file to import is slow"). Each button asks for a file one way
// (filepick.ts) and the table shows how long the chooser took to appear and
// to close, with the tab's streams running or paused, so the person on the
// affected machine can tell which way is slow and copy the numbers.

import { fsaAvailable, pickFile, pickerLog, type PickerMode } from "./filepick";
import { h, overlayRoot, prefs } from "./dom";
import { toast } from "./dialogs";

export function showPickerDiagnostics(pauseStreams?: () => () => void) {
  const restore = document.activeElement as HTMLElement | null;
  const table = h("table", { class: "types-table pick-table", "data-testid": "picker-results" });
  const pause = h("input", { type: "checkbox", "data-testid": "picker-pause" }) as HTMLInputElement;
  pause.disabled = !pauseStreams;
  const paint = () => {
    const ms = (v: number | null) => (v === null ? "—" : v < 1000 ? `${v.toFixed(0)} ms` : `${(v / 1000).toFixed(1)} s`);
    table.replaceChildren(
      h("tr", {}, ...["When", "Way", "Streams", "Shown after", "Closed after", "Picked"].map((t) => h("th", {}, t))),
      ...pickerLog().map((t) =>
        h(
          "tr",
          { class: t.shownMs !== null && t.shownMs > 2000 ? "slow" : "" },
          h("td", { class: "dim" }, new Date(t.at).toLocaleTimeString()),
          h("td", {}, t.mode),
          h("td", {}, t.paused ? "paused" : "running"),
          h("td", { class: "mono" }, ms(t.shownMs)),
          h("td", { class: "mono" }, ms(t.closedMs)),
          h("td", {}, t.error ? `error: ${t.error}` : t.picked ? "yes" : "cancelled"),
        ),
      ),
    );
  };
  const run = async (mode: PickerMode) => {
    await pickFile({ mode, pause: pause.checked ? pauseStreams : undefined });
    paint();
  };
  const fsa = fsaAvailable();
  const remembered = prefs.get("rk.picker") ?? "auto";
  const useSel = h(
    "select",
    { class: "ctl-select", "aria-label": "Way Import file uses", "data-testid": "picker-use" },
    ...(["auto", "input", "accept", "fsa"] as const).map((m) => h("option", { value: m, selected: m === remembered, disabled: m === "fsa" && !fsa }, m)),
  ) as HTMLSelectElement;
  useSel.addEventListener("change", () => {
    prefs.set("rk.picker", useSel.value);
    toast(`Import file… now uses ${useSel.value}`);
  });
  const copy = async () => {
    const text = [
      `revkit file chooser timings · ${navigator.userAgent} · ${location.protocol}//${location.host} · secure context: ${window.isSecureContext}`,
      ...pickerLog().map((t) => `${t.at} ${t.mode} streams=${t.paused ? "paused" : "running"} shown=${t.shownMs === null ? "?" : Math.round(t.shownMs)}ms closed=${Math.round(t.closedMs)}ms picked=${t.picked}${t.error ? " error=" + t.error : ""}`),
    ].join("\n");
    try {
      await navigator.clipboard.writeText(text);
      toast("Copied the timings");
    } catch {
      toast("Can't reach the clipboard here; the timings are in the console too", { kind: "error" });
      console.info(text);
    }
  };
  const btn = (label: string, mode: PickerMode, title: string, disabled = false) =>
    h("button", { class: "btn", type: "button", title, disabled, "data-testid": `picker-${mode}`, onclick: () => void run(mode) }, label);
  const box = h(
    "div",
    { class: "modal pick-diag", role: "dialog", "aria-modal": "true", "aria-label": "Time the system file chooser", tabindex: "-1", "data-testid": "picker-diagnostics" },
    h("div", { class: "modal-title" }, "Time the system file chooser"),
    h(
      "p",
      { class: "dim pick-intro" },
      "Each button opens the chooser one way; pick a file or cancel. \"Shown after\" is when the browser window lost focus to it. ",
      fsa ? "" : "The File System Access picker needs a secure context (HTTPS or localhost); this page isn't one.",
    ),
    h(
      "div",
      { class: "pick-buttons" },
      btn("Plain <input>", "input", "A file input made on the click, no accept filter"),
      btn("<input> with a filter", "accept", "The same, with binary extensions and MIME types as its accept filter"),
      btn("File System Access", "fsa", "showOpenFilePicker (secure contexts only)", !fsa),
      h("label", { class: "dim" }, pause, " pause the live stream while it is open"),
    ),
    table,
    h(
      "div",
      { class: "pick-buttons" },
      h("label", { class: "dim" }, "Import file… uses ", useSel),
      h("span", { class: "spacer" }),
      h("button", { class: "btn", type: "button", onclick: () => void copy(), "data-testid": "picker-copy" }, "Copy timings"),
      h("button", { class: "btn", type: "button", onclick: () => close() }, "Close"),
    ),
  );
  const backdrop = h("div", { class: "backdrop" }, box);
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
  paint();
  overlayRoot().append(backdrop);
  box.focus();
}
