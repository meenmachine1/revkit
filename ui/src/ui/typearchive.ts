// Export archive…: a set of the program's types as a type archive (feature
// "type-archive"; TypeService.ExportTypeArchive): the shown type, a folder,
// the types made in revkit, or all of them, each with what it references,
// as a self-contained C header and a JSON sidecar of content hashes,
// categories, provenance and the data model, both downloaded. Import
// archive… (headerimport.ts) brings them into a program. docs/ui.md
// ("Types"), docs/types.md ("Type archives").

import { TypeArchiveScope, type ExportTypeArchiveResponse, type Revkit } from "@revkit/api";
import { errText } from "../data/format";
import { h, overlayRoot } from "./dom";

export interface ExportHost {
  rk: Revkit;
  programId: string;
  /** The type shown in the types view ("struct cJSON"), if any. */
  shownKey?: string;
  /** The folder picked in the tree ("/net"), if any. */
  folder?: string;
}

/** Saves text as a file the browser downloads. */
export function download(name: string, text: string, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h("a", { href: url, download: name, style: "display:none" });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

let current: ExportArchiveDialog | null = null;

export function openExportArchive(host: ExportHost): ExportArchiveDialog {
  current?.close();
  current = new ExportArchiveDialog(host);
  return current;
}

/** The dialog open now (tests). */
export function exportArchiveDialog(): ExportArchiveDialog | null {
  return current;
}

type Scope = "shown" | "folder" | "user" | "all";

export class ExportArchiveDialog {
  private backdrop: HTMLElement;
  private scope: HTMLSelectElement;
  private folder: HTMLInputElement;
  private name: HTMLInputElement;
  private status: HTMLElement;
  private notes: HTMLElement;
  private exportBtn: HTMLButtonElement;
  private busy = false;
  private last: ExportTypeArchiveResponse | null = null;
  private restore: HTMLElement | null;

  constructor(private host: ExportHost) {
    this.restore = document.activeElement as HTMLElement | null;
    this.scope = h(
      "select",
      { class: "filter select", "aria-label": "Which types", "data-testid": "ta-scope" },
      host.shownKey ? h("option", { value: "shown" }, `${host.shownKey} (and what it references)`) : null,
      h("option", { value: "folder" }, "A folder (and its subfolders)"),
      h("option", { value: "user" }, "Types made, edited or imported in revkit"),
      h("option", { value: "all" }, "All the program's types (debug info's too)"),
    );
    this.scope.value = host.shownKey ? "shown" : host.folder ? "folder" : "user";
    this.folder = h("input", { class: "filter mono", spellcheck: "false", value: host.folder ?? "/", "aria-label": "Folder", "data-testid": "ta-folder", placeholder: "/net/http" });
    this.name = h("input", { class: "filter mono", spellcheck: "false", placeholder: "default: the program it came from", "aria-label": "Archive name", "data-testid": "ta-name" });
    this.status = h("div", { class: "dim hi-status", "data-testid": "ta-status", "aria-live": "polite" });
    this.notes = h("div", { class: "hi-diags", "data-testid": "ta-notes", role: "list", "aria-label": "Notes" });
    this.exportBtn = h("button", { class: "btn small primary", "data-testid": "ta-export", onclick: () => void this.export() }, "Export and download");
    const folderRow = h("div", { class: "hi-row" }, h("label", { class: "dim small-label hi-grow" }, "folder", this.folder));
    const sync = () => (folderRow.hidden = this.scope.value !== "folder");
    this.scope.addEventListener("change", sync);
    sync();
    const box = h(
      "div",
      { class: "modal header-import type-archive", role: "dialog", "aria-modal": "true", "aria-label": "Export a type archive", "data-testid": "export-archive" },
      h("div", { class: "modal-title" }, "Export a type archive"),
      h(
        "div",
        { class: "hi-source" },
        h("div", { class: "dim" }, "A C header (definitions with #pragma pack and a _Static_assert of each size, for the program's data model) and a JSON sidecar of content hashes, categories and the data model. Import archive… brings them into another program; Ghidra's C parser reads the header too."),
        h("div", { class: "hi-row" }, h("label", { class: "dim small-label hi-grow" }, "types", this.scope)),
        folderRow,
        h("div", { class: "hi-row" }, h("label", { class: "dim small-label hi-grow" }, "name", this.name)),
      ),
      this.status,
      this.notes,
      h("div", { class: "types-actions" }, h("span", { class: "spacer" }), h("button", { class: "btn small", "data-testid": "ta-close", onclick: () => this.close() }, "Close"), this.exportBtn),
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
    this.scope.focus();
  }

  close() {
    this.backdrop.remove();
    if (current === this) current = null;
    this.restore?.focus({ preventScroll: true });
  }

  /** Sets the choices (tests), as picking them would. */
  fill(o: { scope?: Scope; folder?: string; name?: string }) {
    if (o.scope !== undefined) this.scope.value = o.scope;
    if (o.folder !== undefined) this.folder.value = o.folder;
    if (o.name !== undefined) this.name.value = o.name;
    this.scope.dispatchEvent(new Event("change"));
  }

  async export(): Promise<void> {
    if (this.busy) return;
    this.busy = true;
    this.exportBtn.disabled = true;
    this.status.textContent = "Exporting…";
    const scope = this.scope.value as Scope;
    try {
      const r = await this.host.rk.types.exportTypeArchive({
        programId: this.host.programId,
        scope: scope === "shown" ? TypeArchiveScope.SELECTED : scope === "folder" ? TypeArchiveScope.CATEGORY : scope === "user" ? TypeArchiveScope.USER : TypeArchiveScope.ALL,
        keys: scope === "shown" && this.host.shownKey ? [this.host.shownKey] : [],
        category: scope === "folder" ? this.folder.value.trim() || "/" : "",
        name: this.name.value.trim(),
      });
      this.last = r;
      download(r.headerName, r.header, "text/x-c");
      download(r.sidecarName, r.sidecar, "application/json");
      const n = r.archive?.types.length ?? 0;
      this.status.textContent = `${r.headerName} and ${r.sidecarName}: ${n} type${n === 1 ? "" : "s"} for ${r.archive?.dataModel?.profile ?? "the program's target"}` +
        (r.mismatches ? ` · ${r.mismatches} the header can't reproduce (below)` : " · every type reproduces");
      this.notes.replaceChildren(...r.notes.map((t) => h("div", { class: "hi-diag sev-warning", role: "listitem" }, t)));
    } catch (e) {
      this.status.textContent = `Can't export: ${errText(e)}`;
    } finally {
      this.busy = false;
      this.exportBtn.disabled = false;
    }
  }

  /** State for tests. */
  describe() {
    return {
      scope: this.scope.value,
      status: this.status.textContent ?? "",
      headerName: this.last?.headerName ?? "",
      header: this.last?.header ?? "",
      sidecar: this.last?.sidecar ?? "",
      types: this.last?.archive?.types.map((t) => t.key) ?? [],
      notes: this.last?.notes ?? [],
    };
  }
}
