// Nintendo DS games (api_minor 103, feature "nds"; docs/nds.md and docs/ui.md
// "Nintendo DS"): File → Import ds-decomp project… and Import DS ROM… (a
// file on the daemon's host, ProjectService.ImportDsdProject /
// ImportNdsRom), the result as a table of modules with Open; File → Export
// ds-decomp symbols… (ExportDsdSymbols): each module's symbols.txt diff,
// Copy patch, and Write files (each backed up first); and the
// decompiler's Copy as decomp scratch (QueryService.ExportDecompScratch).

import type { ExportDsdSymbolsResponse, NdsModuleImport, Revkit } from "@revkit/api";
import { userProvenance } from "../api/client";
import { errText } from "../data/format";
import { toast } from "./dialogs";
import { h, overlayRoot } from "./dom";
import { chooseHostFile } from "./hostfiles";

export const NDS_FEATURE = "nds";

const hex = (v: bigint) => "0x" + v.toString(16).padStart(8, "0");

interface Modal {
  box: HTMLElement;
  body: HTMLElement;
  close: () => void;
}

function modal(title: string, testid: string, hint: string, actions: HTMLElement[] = []): Modal {
  const restore = document.activeElement as HTMLElement | null;
  const body = h("div", { class: "bi-body", "data-testid": `${testid}-body` }, h("div", { class: "dim" }, "Working…"));
  const close = () => {
    backdrop.remove();
    restore?.focus({ preventScroll: true });
  };
  const box = h(
    "div",
    { class: "modal bi nds", role: "dialog", tabindex: "-1", "aria-label": title, "data-testid": testid },
    h("div", { class: "libs-head" }, h("div", { class: "modal-title" }, title), h("span", { class: "spacer" }), ...actions, h("button", { class: "btn", type: "button", "data-testid": `${testid}-close`, onclick: () => close(), text: "Close" })),
    body,
    h("div", { class: "modal-hint" }, hint),
  );
  const backdrop = h("div", { class: "backdrop" }, box);
  box.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      close();
    }
  });
  backdrop.addEventListener("mousedown", (e) => {
    if (e.target === backdrop) close();
  });
  overlayRoot().append(backdrop);
  box.focus();
  return { box, body, close };
}

function moduleTable(mods: NdsModuleImport[], open: (programId: string) => void): HTMLElement {
  const head = ["Module", "Address", "Functions", "Links", ""];
  const rows = mods.map((m) => {
    const id = m.program?.programId ?? "";
    const note = m.error ? `failed: ${m.error}` : [m.compressed ? "decompressed" : "", m.thumbFunctions ? `${m.thumbFunctions} Thumb` : "", ...m.warnings.slice(0, 2)].filter(Boolean).join(" · ");
    return h(
      "div",
      { class: "bi-row nds-row", role: "row", "data-testid": `nds-module-${m.module}` },
      h("span", { class: "mono", role: "cell", title: `${m.kind} · ${m.languageId}` }, m.module),
      h("span", { class: "mono", role: "cell" }, `${hex(m.address)} (${m.size} bytes)`),
      h("span", { role: "cell", title: note }, m.error ? "—" : `${m.functions} (${m.symbols} symbols)${note ? " · " + note : ""}`),
      h("span", { class: "mono", role: "cell" }, m.links.join(", ") || "—"),
      h("span", { role: "cell" }, id ? h("button", { class: "btn small", type: "button", "data-testid": `nds-open-${m.module}`, onclick: () => open(id), text: "Open" }) : ""),
    );
  });
  return h("div", { class: "bi-table", role: "table", "data-testid": "nds-modules" }, h("div", { class: "bi-row nds-row bi-th", role: "row" }, ...head.map((c) => h("span", { role: "columnheader" }, c))), ...rows);
}

export interface NdsImportOptions {
  rk: Revkit;
  projectId: string;
  folderId?: string;
  onOpenProgram: (programId: string) => void;
  /** Called after an import, to refresh the program list. */
  onImported?: () => void;
}

/** File → Import ds-decomp project…: a dsd config.yaml on the daemon's host. */
export async function importDsdProjectDialog(o: NdsImportOptions) {
  const file = await chooseHostFile(o.rk, "The ds-decomp project's config.yaml (config/<version>/arm9/config.yaml)");
  if (!file) return;
  await runImport(o, `Importing ${file.path}`, () =>
    o.rk.projects.importDsdProject({ projectId: o.projectId, configPath: file.path, folderId: o.folderId ?? "", provenance: userProvenance("Import ds-decomp project") }),
  );
}

/** File → Import DS ROM…: a .nds file on the daemon's host. */
export async function importNdsRomDialog(o: NdsImportOptions) {
  const file = await chooseHostFile(o.rk, "A Nintendo DS ROM image (.nds)");
  if (!file) return;
  await runImport(o, `Importing ${file.name}`, () =>
    o.rk.projects.importNdsRom({ projectId: o.projectId, source: { case: "path", value: file.path }, folderId: o.folderId ?? "", provenance: userProvenance("Import DS ROM") }),
  );
}

async function runImport(o: NdsImportOptions, title: string, call: () => Promise<{ folder?: { path: string }; modules: NdsModuleImport[]; warnings: string[]; imported: number; failed: number }>) {
  const m = modal(title, "nds-import", "One program per module, in the game's folder; overlays are linked to main and the autoloads · Esc closes");
  try {
    const r = await call();
    o.onImported?.();
    m.body.replaceChildren(
      h("div", { "data-testid": "nds-import-summary" }, `${r.imported} module${r.imported === 1 ? "" : "s"} imported into ${r.folder?.path ?? "/"}${r.failed ? `, ${r.failed} failed` : ""}`),
      moduleTable(r.modules, (id) => {
        m.close();
        o.onOpenProgram(id);
      }),
      ...(r.warnings.length ? [h("details", { class: "bi-details" }, h("summary", {}, `${r.warnings.length} warning${r.warnings.length === 1 ? "" : "s"}`), h("pre", { class: "mono nds-pre" }, r.warnings.join("\n")))] : []),
    );
  } catch (e) {
    m.body.replaceChildren(h("div", { class: "error", "data-testid": "nds-import-error" }, errText(e)));
  }
}

export interface NdsExportOptions {
  rk: Revkit;
  projectId: string;
  /** The modules of one game (its folder); empty: every dsd module of the project. */
  folderId?: string;
  programIds?: string[];
}

/** File → Export ds-decomp symbols…: the symbols.txt changes, then optionally written. */
export async function exportDsdSymbolsDialog(o: NdsExportOptions) {
  const write = h("button", { class: "btn small primary", type: "button", disabled: true, "data-testid": "nds-export-write", text: "Write files" }) as HTMLButtonElement;
  const copy = h("button", { class: "btn small", type: "button", disabled: true, "data-testid": "nds-export-copy", text: "Copy patch" }) as HTMLButtonElement;
  const m = modal("Export ds-decomp symbols", "nds-export", "Renames in place, new named functions and data added, in dsd's syntax; a demangled name keeps its mangled spelling · Write backs each file up first · Esc closes", [copy, write]);
  const req = { projectId: o.projectId, folderId: o.folderId ?? "", programIds: o.programIds ?? [], provenance: userProvenance("Export ds-decomp symbols") };
  const render = (r: ExportDsdSymbolsResponse, written: boolean) => {
    const rows = r.modules.map((x) =>
      h(
        "div",
        { class: "bi-row nds-xrow", role: "row", "data-testid": `nds-export-${x.module}` },
        h("span", { class: "mono", role: "cell", title: x.path }, x.module),
        h("span", { role: "cell" }, `${x.renamed} renamed · ${x.added} added${x.skipped ? ` · ${x.skipped} skipped` : ""}`),
        h("span", { class: "mono", role: "cell", title: x.backupPath }, x.written ? `written (backup ${x.backupPath.slice(x.backupPath.lastIndexOf("/") + 1)})` : x.diff ? "changed" : "unchanged"),
      ),
    );
    const skipped = r.modules.flatMap((x) => x.changes.filter((c) => c.kind === "skipped").map((c) => `${x.module} ${hex(c.address?.offset ?? 0n)} ${c.newName}: ${c.reason}`));
    m.body.replaceChildren(
      h("div", { "data-testid": "nds-export-summary" }, `${r.renamed} renamed, ${r.added} added${r.skipped ? `, ${r.skipped} skipped` : ""}${written ? `; ${r.written} file${r.written === 1 ? "" : "s"} written` : ""}`),
      h("div", { class: "bi-table", role: "table" }, ...rows),
      ...(skipped.length ? [h("details", { class: "bi-details" }, h("summary", {}, `${skipped.length} name${skipped.length === 1 ? "" : "s"} dsd can't take`), h("pre", { class: "mono nds-pre" }, skipped.join("\n")))] : []),
      h("pre", { class: "mono nds-pre nds-diff", "data-testid": "nds-export-diff" }, r.patch || "No changes."),
    );
    copy.disabled = !r.patch;
    write.disabled = written || !r.patch;
    copy.onclick = () => void navigator.clipboard?.writeText(r.patch).then(() => toast("Copied the patch"), (e) => toast(errText(e), { kind: "error" }));
  };
  try {
    render(await o.rk.projects.exportDsdSymbols(req), false);
  } catch (e) {
    m.body.replaceChildren(h("div", { class: "error", "data-testid": "nds-export-error" }, errText(e)));
    return;
  }
  write.onclick = async () => {
    write.disabled = true;
    try {
      const r = await o.rk.projects.exportDsdSymbols({ ...req, write: true });
      render(r, true);
      toast(`Wrote ${r.written} symbols.txt file${r.written === 1 ? "" : "s"} (backed up first)`);
    } catch (e) {
      toast(errText(e), { kind: "error" });
      write.disabled = false;
    }
  };
}

/** The decompiler's Copy as decomp scratch: the function's scratch text on the clipboard. */
export async function copyDecompScratch(rk: Revkit, programId: string, entry: bigint, copy: (text: string, done: string) => void) {
  try {
    const r = await rk.queries.exportDecompScratch({ programId, function: { offset: entry } });
    const extra = r.notes.length ? ` (${r.notes.length} note${r.notes.length === 1 ? "" : "s"})` : "";
    copy(r.text, `Copied ${r.functionName} as a decomp scratch: ${r.types} types, ${r.callees} callees, ${r.globals} globals${extra}`);
  } catch (e) {
    toast(errText(e), { kind: "error" });
  }
}
