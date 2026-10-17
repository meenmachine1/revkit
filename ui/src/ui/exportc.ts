// Export C/C++…: Ghidra's C/C++ exporter (feature "export-c";
// QueryService.ExportC). The function at the cursor or every function,
// decompiled into one .c in address order and, when asked, a .h of the
// program's types and the functions' prototypes that the .c includes; a
// progress bar while they decompile, then both files downloaded.
// docs/ui.md ("Export C").

import type { Revkit } from "@revkit/api";
import { errText, fmtAddr } from "../data/format";
import { h, overlayRoot } from "./dom";
import { download } from "./typearchive";

export interface ExportCHost {
  rk: Revkit;
  programId: string;
  /** The function at the cursor (entry and name), if any. */
  current?: { entry: bigint; name: string };
}

let current: ExportCDialog | null = null;

export function openExportC(host: ExportCHost): ExportCDialog {
  current?.close();
  current = new ExportCDialog(host);
  return current;
}

/** The dialog open now (tests). */
export function exportCDialog(): ExportCDialog | null {
  return current;
}

type Which = "current" | "all";

export class ExportCDialog {
  private backdrop: HTMLElement;
  private which: HTMLSelectElement;
  private header: HTMLInputElement;
  private name: HTMLInputElement;
  private status: HTMLElement;
  private bar: HTMLProgressElement;
  private exportBtn: HTMLButtonElement;
  private abort: AbortController | null = null;
  private restore: HTMLElement | null;
  private last: { sourceName: string; source: string; headerName: string; header: string; functions: number; failed: number } | null = null;

  constructor(private host: ExportCHost) {
    this.restore = document.activeElement as HTMLElement | null;
    this.which = h(
      "select",
      { class: "filter select", "aria-label": "Which functions", "data-testid": "xc-which" },
      host.current ? h("option", { value: "current" }, `${host.current.name} (the function at the cursor)`) : null,
      h("option", { value: "all" }, "Every function"),
    );
    this.which.value = "all";
    this.header = h("input", { type: "checkbox", checked: true, "aria-label": "With a header", "data-testid": "xc-header" });
    this.name = h("input", { class: "filter mono", spellcheck: "false", placeholder: "default: the program's name", "aria-label": "File name", "data-testid": "xc-name" });
    this.status = h("div", { class: "dim hi-status", "data-testid": "xc-status", "aria-live": "polite" });
    this.bar = h("progress", { class: "xc-progress", max: "1", value: "0", hidden: true, "aria-label": "Decompiled" }) as HTMLProgressElement;
    this.exportBtn = h("button", { class: "btn small primary", "data-testid": "xc-export", onclick: () => void this.export() }, "Export and download");
    const box = h(
      "div",
      { class: "modal header-import type-archive", role: "dialog", "aria-modal": "true", "aria-label": "Export C", "data-testid": "export-c" },
      h("div", { class: "modal-title" }, "Export C/C++"),
      h(
        "div",
        { class: "hi-source" },
        h("div", { class: "dim" }, "The decompiled C of the functions in one .c file, in address order. The header (.h) has the program's types, Ghidra's built-in type names and each function's prototype; the .c includes it."),
        h("div", { class: "hi-row" }, h("label", { class: "dim small-label hi-grow" }, "functions", this.which)),
        h("div", { class: "hi-row" }, h("label", { class: "dim small-label" }, this.header, " with a header of the types and prototypes")),
        h("div", { class: "hi-row" }, h("label", { class: "dim small-label hi-grow" }, "name", this.name)),
      ),
      this.bar,
      this.status,
      h("div", { class: "types-actions" }, h("span", { class: "spacer" }), h("button", { class: "btn small", "data-testid": "xc-close", onclick: () => this.close() }, "Close"), this.exportBtn),
    );
    this.backdrop = h("div", { class: "backdrop top" }, box);
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") this.close();
      if (e.key === "Enter" && (e.target as HTMLElement).tagName !== "SELECT") void this.export();
    });
    this.backdrop.addEventListener("mousedown", (e) => {
      if (e.target === this.backdrop) this.close();
    });
    overlayRoot().append(this.backdrop);
    this.which.focus();
  }

  close() {
    this.abort?.abort();
    this.backdrop.remove();
    if (current === this) current = null;
    this.restore?.focus({ preventScroll: true });
  }

  /** Sets the choices (tests), as picking them would. */
  fill(o: { which?: Which; header?: boolean; name?: string }) {
    if (o.which !== undefined) this.which.value = o.which;
    if (o.header !== undefined) this.header.checked = o.header;
    if (o.name !== undefined) this.name.value = o.name;
  }

  async export(): Promise<void> {
    if (this.abort) return;
    const abort = (this.abort = new AbortController());
    this.exportBtn.disabled = true;
    this.bar.hidden = false;
    this.bar.value = 0;
    this.status.textContent = "Decompiling…";
    const one = this.which.value === "current" && this.host.current;
    let sourceName = "";
    let headerName = "";
    let header = "";
    const parts: string[] = [];
    try {
      for await (const m of this.host.rk.queries.exportC(
        {
          programId: this.host.programId,
          all: !one,
          functions: one ? [{ offset: this.host.current!.entry }] : [],
          header: this.header.checked,
          name: this.name.value.trim(),
        },
        { signal: abort.signal },
      )) {
        if (m.sourceName) sourceName = m.sourceName;
        if (m.headerName) {
          headerName = m.headerName;
          header = m.header;
        }
        if (m.sourcePart) parts.push(m.sourcePart);
        if (m.total && !m.finished && !m.sourcePart) {
          this.bar.max = m.total;
          this.bar.value = m.done;
          this.status.textContent = `Decompiling… ${m.done.toLocaleString()} of ${m.total.toLocaleString()} functions`;
        }
        if (m.finished) {
          const source = parts.join("");
          this.last = { sourceName, source, headerName, header, functions: m.functions, failed: m.failed.length };
          download(sourceName, source, "text/x-c");
          if (headerName) download(headerName, header, "text/x-c");
          const failed = m.failed.length
            ? ` · ${m.failed.length} the decompiler failed on (${m.failed.slice(0, 3).map((a) => fmtAddr(a.offset)).join(", ")}${m.failed.length > 3 ? ", …" : ""}; a comment in the file says why)`
            : "";
          this.status.textContent = `${sourceName}${headerName ? ` and ${headerName}` : ""}: ${m.functions.toLocaleString()} function${m.functions === 1 ? "" : "s"}${failed}`;
        }
      }
    } catch (e) {
      if (!abort.signal.aborted) this.status.textContent = `Can't export: ${errText(e)}`;
    } finally {
      this.abort = null;
      this.exportBtn.disabled = false;
      this.bar.hidden = true;
    }
  }

  /** State for tests. */
  describe() {
    return {
      which: this.which.value,
      status: this.status.textContent ?? "",
      sourceName: this.last?.sourceName ?? "",
      source: this.last?.source ?? "",
      headerName: this.last?.headerName ?? "",
      header: this.last?.header ?? "",
      functions: this.last?.functions ?? 0,
    };
  }
}
