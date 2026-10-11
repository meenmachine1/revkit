// Project archives (feature "project-archive", api_minor 37): File → Export
// project… and Import project….
//
// Export: the whole project, the programs picked in the project window, or
// a folder, as one .rkproj file (the programs' bytes, every edit with its
// history and provenance, the folders); "Annotations only" leaves the
// programs' files out. The archive streams from the daemon and is saved
// as a download (the desktop app asks where, with its native dialog).
//
// Import: a .rkproj is uploaded in pieces (UploadChunk), inspected (its
// programs, their folders, and whether each binary is in it or was found),
// and imported into a new project or into the current one, under the
// folder picked in the project window. For an annotations-only archive the
// user adds the missing binaries (matched by SHA-256) or skips them.

import {
  ARCHIVE_EXTENSION, PROJECT_ARCHIVE_FEATURE, exportProject, sha256Hex, uploadFile,
  type ImportProjectArchiveResponse, type ImportedArchiveProgram, type Revkit,
} from "@revkit/api";
import { userProvenance } from "../api/client";
import { errText } from "../data/format";
import { toast } from "./dialogs";
import { h, overlayRoot } from "./dom";
import { pickFile } from "./filepick";

export { PROJECT_ARCHIVE_FEATURE };

/** Saves bytes as a download (the desktop app's shell asks where). */
export function downloadBytes(data: Uint8Array, name: string) {
  const url = URL.createObjectURL(new Blob([new Uint8Array(data)], { type: "application/octet-stream" }));
  const a = h("a", { href: url, download: name, "data-testid": "archive-download" });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1 << 20) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1 << 30) return `${(n / (1 << 20)).toFixed(1)} MB`;
  return `${(n / (1 << 30)).toFixed(1)} GB`;
}

/** A modal with a title, a body and buttons; Escape or the backdrop closes it. */
function modal(title: string, testid: string, onClose: () => void) {
  const restore = document.activeElement as HTMLElement | null;
  const body = h("div", { class: "archive-body" });
  const buttons = h("div", { class: "archive-buttons" });
  const box = h("div", { class: "modal archive", role: "dialog", "aria-modal": "true", "aria-label": title, tabindex: "-1", "data-testid": testid },
    h("div", { class: "modal-title" }, title), body, buttons);
  const backdrop = h("div", { class: "backdrop top" }, box);
  const close = () => {
    backdrop.remove();
    restore?.focus({ preventScroll: true });
    onClose();
  };
  box.addEventListener("keydown", (e) => {
    e.stopPropagation();
    if (e.key === "Escape") close();
  });
  backdrop.addEventListener("mousedown", (e) => {
    if (e.target === backdrop) close();
  });
  overlayRoot().append(backdrop);
  box.focus();
  return { box, body, buttons, close };
}

export interface ExportScope {
  projectId: string;
  /** Shown in the dialog. */
  projectName?: string;
  /** Programs picked in the project window. */
  programs?: { programId: string; name: string }[];
  /** A folder picked in the project window. */
  folder?: { folderId: string; path: string };
}

/** File → Export project…: what to export, full or annotations only; saves the archive. */
export function exportProjectDialog(rk: Revkit, scope: ExportScope): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false;
    const m = modal("Export project", "export-project-dialog", () => resolve(done));
    const choices: { value: string; label: string }[] = [{ value: "project", label: `The whole project ${scope.projectName ?? scope.projectId}` }];
    if (scope.folder && scope.folder.folderId)
      choices.push({ value: "folder", label: `The folder ${scope.folder.path} and everything in it` });
    if (scope.programs?.length)
      choices.push({ value: "programs", label: scope.programs.length === 1 ? `The program ${scope.programs[0].name}` : `${scope.programs.length} programs` });
    let what = choices.length > 1 ? choices[choices.length - 1].value : "project";
    const radios = choices.map((c) => {
      const input = h("input", { type: "radio", name: "export-scope", value: c.value, "data-testid": `export-scope-${c.value}` }) as HTMLInputElement;
      input.checked = c.value === what;
      input.addEventListener("change", () => (what = c.value));
      return h("label", { class: "archive-line" }, input, h("span", {}, c.label));
    });
    const annotations = h("input", { type: "checkbox", "data-testid": "export-annotations" }) as HTMLInputElement;
    const status = h("div", { class: "archive-status dim", "aria-live": "polite", "data-testid": "export-status" });
    m.body.append(
      h("div", { class: "archive-section dim" }, "What to export"),
      ...radios,
      h("label", { class: "archive-line" }, annotations,
        h("span", {}, "Annotations only", h("span", { class: "dim" }, " — leave the programs' files out; on import each is found by its SHA-256"))),
      h("div", { class: "dim archive-note" }, "The archive holds every edit with its history and provenance, the folders and the types. Derived results (functions, listings, decompilations) are computed again on import."),
      status,
    );
    const ctl = new AbortController();
    const go = h("button", { class: "btn primary", "data-testid": "export-go", text: "Export…" }) as HTMLButtonElement;
    const cancel = h("button", { class: "btn", text: "Cancel", onclick: () => { ctl.abort(); m.close(); } });
    go.addEventListener("click", async () => {
      go.disabled = true;
      status.textContent = "Exporting…";
      status.className = "archive-status dim";
      try {
        const r = await exportProject(rk, {
          projectId: scope.projectId,
          programIds: what === "programs" ? scope.programs!.map((p) => p.programId) : [],
          folderIds: what === "folder" ? [scope.folder!.folderId] : [],
          annotationsOnly: annotations.checked,
        }, { signal: ctl.signal, onBytes: (n) => (status.textContent = `Exporting… ${bytes(n)}`) });
        downloadBytes(r.data, r.fileName);
        done = true;
        const n = r.manifest?.programs.length ?? 0;
        toast(`Exported ${n} program${n === 1 ? "" : "s"} to ${r.fileName} (${bytes(r.data.length)})`);
        m.close();
      } catch (e) {
        go.disabled = false;
        status.textContent = `Export failed: ${errText(e)}`;
        status.className = "archive-status error";
      }
    });
    m.buttons.append(cancel, go);
    go.focus();
  });
}

export interface ImportTarget {
  /** The project the window shows: the archive may go into it. */
  projectId?: string;
  /** The folder picked there (where the archive's tree goes in projectId). */
  folder?: { folderId: string; path: string };
  pauseStreams?: () => () => void;
  /** Called with the project imported into and its first program. */
  onImported?: (projectId: string, programId: string | undefined) => void;
}

function sourceText(p: ImportedArchiveProgram): string {
  const s = p.binarySource;
  if (s === "archive") return "in the archive";
  if (s.startsWith("project:")) return `found in this project (${s.slice(8)})`;
  if (s.startsWith("search:")) return `found at ${s.slice(7)}`;
  if (s === "upload") return "added";
  if (s.startsWith("path:")) return `at ${s.slice(5)}`;
  return "missing";
}

/** File → Import project…: pick a .rkproj, see what is in it, add missing binaries, import. */
export async function importProjectDialog(rk: Revkit, target: ImportTarget): Promise<void> {
  const { file } = await pickFile({ pause: target.pauseStreams });
  if (!file) return;
  let closed = false;
  const m = modal(`Import project from ${file.name}`, "import-project-dialog", () => {
    closed = true;
    ctl.abort();
  });
  const ctl = new AbortController();
  const status = h("div", { class: "archive-status dim", "aria-live": "polite", "data-testid": "import-status" }, `Uploading ${file.name} (${bytes(file.size)})…`);
  const list = h("div", { class: "archive-programs", role: "list", "aria-label": "Programs in the archive", "data-testid": "import-programs" });
  const summary = h("div", { class: "archive-summary" });
  m.body.append(summary, list, status);
  let uploadId = "";
  const binaries: { uploadId: string; name: string; sha: string }[] = [];
  let inspected: ImportProjectArchiveResponse | undefined;
  try {
    uploadId = await uploadFile(rk, file, {
      fileName: file.name, signal: ctl.signal,
      onProgress: (s, t) => (status.textContent = `Uploading ${file.name}: ${bytes(s)} of ${bytes(t)}`),
    });
  } catch (e) {
    if (!closed) {
      status.textContent = `Upload failed: ${errText(e)}`;
      status.className = "archive-status error";
      m.buttons.append(h("button", { class: "btn", text: "Close", onclick: () => m.close() }));
    }
    return;
  }
  const request = (inspectOnly: boolean, into: string, name: string, skip: boolean) =>
    rk.projects.importProjectArchive({
      archive: { source: { case: "uploadId", value: uploadId } },
      projectId: into,
      newProjectName: into ? "" : name,
      folderId: into && target.folder ? target.folder.folderId : "",
      binaries: binaries.map((b) => ({ source: { case: "uploadId" as const, value: b.uploadId } })),
      skipMissing: skip,
      inspectOnly,
      provenance: userProvenance(`import project archive ${file.name}`),
    }, { signal: ctl.signal });

  // Destination: a new project (named), or the one the window shows.
  const newRadio = h("input", { type: "radio", name: "import-into", "data-testid": "import-new" }) as HTMLInputElement;
  const hereRadio = h("input", { type: "radio", name: "import-into", "data-testid": "import-here" }) as HTMLInputElement;
  newRadio.checked = true;
  const nameInput = h("input", { class: "ask-input", spellcheck: "false", "aria-label": "New project's name", "data-testid": "import-name" }) as HTMLInputElement;
  const skip = h("input", { type: "checkbox", "data-testid": "import-skip" }) as HTMLInputElement;
  const addBtn = h("button", { class: "btn", "data-testid": "import-add-binary", text: "Add binary…" }) as HTMLButtonElement;
  const go = h("button", { class: "btn primary", "data-testid": "import-go", text: "Import" }) as HTMLButtonElement;
  const missing = () => inspected?.programs.filter((p) => !p.binarySource) ?? [];

  const paint = () => {
    const r = inspected!;
    const man = r.manifest;
    summary.replaceChildren(
      h("div", {}, `${man?.programs.length ?? 0} program${man?.programs.length === 1 ? "" : "s"} from project `, h("b", {}, man?.projectName ?? "?"),
        man?.annotationsOnly ? h("span", { class: "dim" }, " · annotations only: the programs' files are found by SHA-256") : null),
      h("div", { class: "dim" }, `${man?.createdBy ?? ""}${man?.folders.length ? ` · ${man.folders.length} folder${man.folders.length === 1 ? "" : "s"}` : ""}`),
    );
    list.replaceChildren(
      ...r.programs.map((p, i) =>
        h("div", { class: "archive-program" + (p.binarySource ? "" : " missing"), role: "listitem", "data-testid": "import-program" },
          h("span", { class: "open-name" }, p.name),
          h("span", { class: "dim" }, man?.programs[i]?.folder ?? "/"),
          h("span", { class: p.binarySource ? "dim" : "error", "data-testid": "import-binary" }, sourceText(p)),
          h("span", { class: "dim mono" }, p.sha256.slice(0, 12)))),
    );
    const n = missing().length;
    addBtn.hidden = n === 0;
    skip.parentElement!.hidden = n === 0;
    status.className = "archive-status " + (n && !skip.checked ? "hint" : "dim");
    status.textContent = n
      ? `${n} binar${n === 1 ? "y is" : "ies are"} missing: add ${n === 1 ? "it" : "them"} (matched by SHA-256), or skip ${n === 1 ? "that program" : "those programs"}.`
      : "Ready to import.";
    go.disabled = n > 0 && !skip.checked;
  };

  status.textContent = "Reading the archive…";
  try {
    inspected = await request(true, "", "", false);
  } catch (e) {
    if (closed) return;
    status.textContent = `Can't import ${file.name}: ${errText(e)}`;
    status.className = "archive-status error";
    m.buttons.append(h("button", { class: "btn", text: "Close", onclick: () => m.close() }));
    return;
  }
  if (closed) return;
  nameInput.value = inspected.manifest?.projectName || file.name.replace(/\.rkproj$/i, "");
  const here = target.projectId
    ? `This project (${target.projectId})${target.folder?.folderId ? `, in ${target.folder.path}` : ""}`
    : "";
  m.body.insertBefore(
    h("div", { class: "archive-dest" },
      h("div", { class: "archive-section dim" }, "Import into"),
      h("label", { class: "archive-line" }, newRadio, h("span", {}, "A new project named "), nameInput),
      here ? h("label", { class: "archive-line" }, hereRadio, h("span", {}, here, h("span", { class: "dim" }, " — as new programs; a name already there gets a suffix"))) : null,
      h("label", { class: "archive-line", hidden: true }, skip, h("span", {}, "Skip the programs whose binary is missing"))),
    status,
  );
  nameInput.addEventListener("input", () => (newRadio.checked = true));
  nameInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") go.click();
  });
  skip.addEventListener("change", paint);
  paint();

  addBtn.addEventListener("click", async () => {
    const { file: bin } = await pickFile({ pause: target.pauseStreams });
    if (!bin || closed) return;
    const sha = await sha256Hex(bin);
    if (!missing().some((p) => p.sha256 === sha)) {
      status.textContent = `${bin.name} is not one of the missing binaries (SHA-256 ${sha.slice(0, 12)}…).`;
      status.className = "archive-status error";
      return;
    }
    try {
      status.textContent = `Uploading ${bin.name}…`;
      const id = await uploadFile(rk, bin, { fileName: bin.name, signal: ctl.signal });
      binaries.push({ uploadId: id, name: bin.name, sha });
      inspected = await request(true, "", "", false);
      paint();
    } catch (e) {
      status.textContent = `Can't add ${bin.name}: ${errText(e)}`;
      status.className = "archive-status error";
    }
  });
  go.addEventListener("click", async () => {
    const into = hereRadio.checked && target.projectId ? target.projectId : "";
    if (!into && !nameInput.value.trim()) {
      status.textContent = "Name the new project.";
      status.className = "archive-status error";
      return nameInput.focus();
    }
    go.disabled = true;
    addBtn.disabled = true;
    status.className = "archive-status dim";
    status.textContent = "Importing: loading and analysing the programs…";
    try {
      const r = await request(false, into, nameInput.value.trim(), skip.checked);
      const pid = r.project?.projectId ?? into;
      const first = r.programs.find((p) => p.program?.programId)?.program?.programId;
      const n = r.programs.filter((p) => p.program?.programId).length;
      for (const w of r.warnings) toast(w, { ms: 8000 });
      toast(`Imported ${n} program${n === 1 ? "" : "s"} into ${r.project?.name ?? pid}`);
      m.close();
      target.onImported?.(pid, first);
    } catch (e) {
      go.disabled = false;
      addBtn.disabled = false;
      status.textContent = `Import failed: ${errText(e)}`;
      status.className = "archive-status error";
    }
  });
  m.buttons.append(addBtn, h("button", { class: "btn", text: "Cancel", onclick: () => m.close() }), go);
  go.focus();
}

export { ARCHIVE_EXTENSION };
