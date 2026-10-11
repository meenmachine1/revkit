// The Open dialog's import progress (feature "import-progress", api_minor
// 22): a bar at the dialog's bottom right with a line saying what the
// daemon is doing ("Finding functions: 3,120 found", "Reading DWARF debug
// info", "Saving to the project"). ImportProgram is one blocking call, so
// while it runs the dialog polls GetImportProgress with the import_id it
// sent, about every 250 ms, one request at a time. The bar eases between
// polls (a CSS transition), and is indeterminate until the daemon has a
// fraction (before the import has started, or while a file uploads).
// Raw layout detection (rawdetect.ts) shows its progress on the same bar.

import { Code, ConnectError } from "@connectrpc/connect";
import { ImportPhase, type GetImportProgressResponse, type Revkit } from "@revkit/api";
import { h } from "./dom";

export const IMPORT_PROGRESS_FEATURE = "import-progress";
const POLL_MS = 250;

/** A random import_id: 96 bits, hex. */
export function newImportId(): string {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

const PHASE_NAMES: Record<number, string> = {
  [ImportPhase.READING]: "Reading the file",
  [ImportPhase.LOADING]: "Loading",
  [ImportPhase.DEBUG_INFO]: "Reading debug info",
  [ImportPhase.FUNCTIONS]: "Finding functions",
  [ImportPhase.DATA]: "Data analysis",
  [ImportPhase.PROTOTYPES]: "Inferring prototypes",
  [ImportPhase.SAVING]: "Saving to the project",
  [ImportPhase.DONE]: "Done",
};

/** One poll as the bar shows it (an import's, or a raw detection's: rawdetect.ts). */
export interface ProgressShown {
  text: string;
  /** 0..1; negative while unknown. */
  fraction: number;
  /** The phase's enum name, for data-phase. */
  phase: string;
  /** Said by the live region when the phase changes. */
  announce: string;
  done: boolean;
  error: boolean;
}

/** The bar and its line of text; `el` goes in the dialog's footer. */
export class ImportProgressView {
  readonly el: HTMLElement;
  private text: HTMLElement;
  private pct: HTMLElement;
  private bar: HTMLElement;
  private fill: HTMLElement;
  /** Announces phase changes only (the line itself changes several times a second). */
  private live: HTMLElement;
  private phase = "";

  constructor() {
    this.text = h("span", { class: "import-progress-text", "data-testid": "import-progress-text" });
    this.pct = h("span", { class: "import-progress-pct", "aria-hidden": "true" });
    this.fill = h("div", { class: "import-bar-fill" });
    this.bar = h(
      "div",
      { class: "import-bar", role: "progressbar", "aria-label": "Import progress", "aria-valuemin": "0", "aria-valuemax": "100", "data-testid": "import-bar" },
      this.fill,
    );
    this.live = h("span", { class: "sr-only", "aria-live": "polite", "data-testid": "import-progress-live" });
    this.el = h(
      "div",
      { class: "import-progress", hidden: true, "data-testid": "import-progress" },
      h("div", { class: "import-progress-head" }, this.text, this.pct),
      this.bar,
      this.live,
    );
  }

  /** Shows the bar, indeterminate, with `text`. */
  start(text: string, label = "Import progress") {
    this.phase = "";
    this.bar.setAttribute("aria-label", label);
    this.el.hidden = false;
    this.el.dataset.state = "running";
    this.setFraction(-1);
    this.text.textContent = text;
    this.text.title = text;
    this.live.textContent = text;
  }

  update(p: GetImportProgressResponse) {
    const text = p.message || PHASE_NAMES[p.phase] || "Importing…";
    this.show({ text, fraction: p.progress, phase: ImportPhase[p.phase] ?? String(p.phase), announce: PHASE_NAMES[p.phase] ?? text, done: p.done, error: !!p.error });
  }

  show(p: ProgressShown) {
    this.text.textContent = p.text;
    this.text.title = p.text;
    this.el.dataset.phase = p.phase;
    if (p.phase !== this.phase) {
      this.phase = p.phase;
      this.live.textContent = p.announce;
    }
    this.setFraction(p.done && !p.error ? 1 : p.fraction);
    this.bar.setAttribute("aria-valuetext", p.fraction >= 0 ? `${Math.round(p.fraction * 100)}%: ${p.text}` : p.text);
    if (p.done) this.el.dataset.state = p.error ? "error" : "done";
  }

  /** The import answered: full, with `text`. */
  finish(text: string) {
    this.el.dataset.state = "done";
    this.el.dataset.phase = "DONE";
    this.setFraction(1);
    this.text.textContent = text;
    this.text.title = text;
    this.live.textContent = text;
  }

  hide() {
    this.el.hidden = true;
    delete this.el.dataset.state;
  }

  private setFraction(f: number) {
    const known = f >= 0;
    this.bar.classList.toggle("indeterminate", !known);
    if (known) {
      const v = Math.max(0, Math.min(1, f));
      if (this.bar.dataset.known !== "1") {
        // From indeterminate (or the start): jump there, then ease from it.
        this.fill.style.transition = "none";
        this.fill.style.transform = `scaleX(${v})`;
        void this.fill.offsetWidth;
        this.fill.style.transition = "";
      }
      this.bar.dataset.known = "1";
      this.fill.style.transform = `scaleX(${v})`;
      this.bar.setAttribute("aria-valuenow", String(Math.round(v * 100)));
      this.pct.textContent = `${Math.floor(v * 100)}%`;
    } else {
      delete this.bar.dataset.known;
      this.fill.style.transform = "";
      this.bar.removeAttribute("aria-valuenow");
      this.pct.textContent = "";
    }
  }
}

/** Polls GetImportProgress into `view` until the returned stop is called. */
export function followImport(rk: Revkit, projectId: string, importId: string, view: ImportProgressView): () => void {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const tick = async () => {
    timer = undefined;
    if (stopped) return;
    try {
      const p = await rk.projects.getImportProgress({ projectId, importId });
      if (stopped) return;
      view.update(p);
      if (p.done) return;
    } catch (e) {
      // Not started yet (the request is still uploading): ask again. A
      // daemon that can't answer at all: stop, the bar stays indeterminate.
      if (e instanceof ConnectError && (e.code === Code.Unimplemented || e.code === Code.PermissionDenied)) return;
    }
    if (!stopped) timer = setTimeout(() => void tick(), POLL_MS);
  };
  timer = setTimeout(() => void tick(), 50);
  return () => {
    stopped = true;
    if (timer !== undefined) clearTimeout(timer);
  };
}
