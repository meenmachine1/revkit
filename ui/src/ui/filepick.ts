// Picking a local file to import, and timing the system file chooser.
//
// On one Ubuntu machine Chrome takes seconds to show its file chooser for
// this UI (docs/known-issues.md). What the page controls is how it asks:
//
//   input   a file <input> made when the button is pressed (none sits in
//           the page), no accept filter: the plainest request
//   accept  the same with an accept filter (binary extensions and MIME
//           types), so the chooser's filter list is built
//   fsa     the File System Access picker (showOpenFilePicker), only in
//           secure contexts (HTTPS, localhost), with its own start folder
//
// "auto" is input (fsa is offered to compare: it shows the same native
// dialog, with a start folder remembered per site). ?picker=<mode> (or the
// diagnostics dialog) forces one. The tab's long-lived streams (the
// subscription) can be paused while the chooser is open, to test whether
// they hold it up. Every pick records how long the chooser took to appear
// (the window's blur) and to close, kept for the diagnostics dialog.

import { prefs } from "./dom";

export type PickerMode = "auto" | "input" | "accept" | "fsa";

export interface PickTiming {
  mode: Exclude<PickerMode, "auto">;
  /** From the click to the window losing focus to the chooser (null: never seen). */
  shownMs: number | null;
  /** From the click to the chooser closing. */
  closedMs: number;
  picked: boolean;
  /** The live streams were paused while it was open. */
  paused: boolean;
  at: string;
  error?: string;
}

const LOG = "rk.picker.log";
export const BINARY_ACCEPT =
  ".exe,.dll,.sys,.so,.elf,.bin,.o,.ko,.axf,.out,.hex,.img,.fw,.efi,application/octet-stream,application/x-executable,application/x-sharedlib,application/x-elf,application/x-msdownload";

/** Whether the File System Access picker exists here (secure contexts). */
export function fsaAvailable(): boolean {
  return window.isSecureContext && "showOpenFilePicker" in window;
}

/** The mode for this page: ?picker=, else the remembered one, else auto. */
export function pickerMode(): PickerMode {
  const m = new URLSearchParams(location.search).get("picker") ?? prefs.get("rk.picker") ?? "auto";
  return (["auto", "input", "accept", "fsa"] as const).includes(m as PickerMode) ? (m as PickerMode) : "auto";
}

export function pickerLog(): PickTiming[] {
  try {
    return JSON.parse(prefs.get(LOG) ?? "[]") as PickTiming[];
  } catch {
    return [];
  }
}

function record(t: PickTiming) {
  const log = [t, ...pickerLog()].slice(0, 20);
  prefs.set(LOG, JSON.stringify(log));
  console.info(`revkit: file chooser (${t.mode}${t.paused ? ", streams paused" : ""}) shown after ${t.shownMs === null ? "?" : t.shownMs.toFixed(0) + " ms"}, closed after ${t.closedMs.toFixed(0)} ms`);
}

/** A file <input> made for this one pick and removed after it. */
function viaInput(accept: string): Promise<File | null> {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    if (accept) input.accept = accept;
    input.style.display = "none";
    input.dataset.testid = "open-file";
    let done = false;
    const finish = (f: File | null) => {
      if (done) return;
      done = true;
      input.remove();
      resolve(f);
    };
    input.addEventListener("change", () => finish(input.files?.[0] ?? null));
    // Chrome 113+, Safari 16.4+, Firefox 91+: the chooser was dismissed.
    input.addEventListener("cancel", () => finish(null));
    document.body.append(input);
    input.click();
  });
}

async function viaFsa(): Promise<File | null> {
  const pick = (window as unknown as { showOpenFilePicker: (o: object) => Promise<{ getFile(): Promise<File> }[]> }).showOpenFilePicker;
  try {
    const [handle] = await pick({ id: "revkit-import", multiple: false, excludeAcceptAllOption: false });
    return handle ? await handle.getFile() : null;
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") return null;
    throw e;
  }
}

export interface PickOptions {
  mode?: PickerMode;
  /** Pauses the tab's streams; returns the function that resumes them. */
  pause?: () => () => void;
}

/** Asks for one local file with the system chooser, timing it. */
export async function pickFile(o: PickOptions = {}): Promise<{ file: File | null; timing: PickTiming }> {
  const want = o.mode ?? pickerMode();
  const mode: PickTiming["mode"] = want === "auto" || (want === "fsa" && !fsaAvailable()) ? "input" : want;
  const resume = o.pause?.();
  const t0 = performance.now();
  let shownMs: number | null = null;
  const onBlur = () => {
    if (shownMs === null) shownMs = performance.now() - t0;
  };
  window.addEventListener("blur", onBlur);
  let file: File | null = null;
  let error: string | undefined;
  try {
    file = mode === "fsa" ? await viaFsa() : await viaInput(mode === "accept" ? BINARY_ACCEPT : "");
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  } finally {
    window.removeEventListener("blur", onBlur);
    resume?.();
  }
  const timing: PickTiming = { mode, shownMs, closedMs: performance.now() - t0, picked: !!file, paused: !!resume, at: new Date().toISOString(), ...(error ? { error } : {}) };
  record(timing);
  return { file, timing };
}

/** Asks for several local files (a type archive's header and sidecar) with
 * a file <input>; empty when the chooser is dismissed. */
export function pickFiles(accept = ""): Promise<File[]> {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.multiple = true;
    if (accept) input.accept = accept;
    input.style.display = "none";
    input.dataset.testid = "open-files";
    let done = false;
    const finish = (f: File[]) => {
      if (done) return;
      done = true;
      input.remove();
      resolve(f);
    };
    input.addEventListener("change", () => finish([...(input.files ?? [])]));
    input.addEventListener("cancel", () => finish([]));
    document.body.append(input);
    input.click();
  });
}
