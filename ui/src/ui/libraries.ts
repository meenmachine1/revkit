// Libraries (api_minor 70, feature "program-libraries"; docs/ui.md
// "Libraries"): a program's shared libraries (ListProgramLibraries), each
// with the project program it resolves to or "not in project", and Open,
// Link… and Unlink; then its imports, each with the library function it
// goes to (a click opens that program there). Not-in-project libraries offer
// Import… (the Open dialog's import section, "Also import libraries").

import { LibraryResolution, type ListProgramLibrariesResponse, type ProgramLibrary, type ResolvedImport, type Revkit } from "@revkit/api";
import { userProvenance } from "../api/client";
import { errText } from "../data/format";
import { choose, toast } from "./dialogs";
import { h, overlayRoot } from "./dom";

export const LIBRARIES_FEATURE = "program-libraries";

export interface LibrariesOptions {
  programId: string;
  programName: string;
  /** Opens a program (at an address in it). */
  openProgram: (programId: string, address?: bigint) => void;
  /** The Open dialog in its import section, for a library not in the project. */
  importLibraries?: () => void;
}

/** "libc.so.6!strlen" for a resolved import, "libc.so.6" (or "") otherwise. */
export function importTarget(i: ResolvedImport): string {
  return i.resolved ? `${i.library}!${i.functionName}` : i.library;
}

/** Thunk entries -> their resolved imports (for the functions list and Go to library function). */
export async function importMap(rk: Revkit, programId: string): Promise<Map<bigint, ResolvedImport>> {
  const r = await rk.projects.listProgramLibraries({ programId, includeImports: true });
  const out = new Map<bigint, ResolvedImport>();
  for (const i of r.imports) if (i.thunk) out.set(i.thunk.offset, i);
  return out;
}

const RESOLUTION: Record<number, string> = {
  [LibraryResolution.LINKED]: "linked",
  [LibraryResolution.NAME]: "by name",
  [LibraryResolution.SONAME]: "by soname",
  [LibraryResolution.NONE]: "not in project",
};

/** One line per library, for a details panel: "libc.so.6 → libc.so.6 · libm.so.6 (not in project)". */
export function librariesSummary(r: ListProgramLibrariesResponse): string {
  const own = r.libraries.filter((l) => l.depth === 0);
  if (!own.length) return "none";
  return own.map((l) => (l.programId ? l.name : `${l.name} (not in project)`)).join(" · ");
}

export function showLibrariesDialog(rk: Revkit, o: LibrariesOptions) {
  const restore = document.activeElement as HTMLElement | null;
  const libsEl = h("div", { class: "libs-list", role: "table", "aria-label": "Libraries", "data-testid": "libs-list" }, h("div", { class: "dim" }, "Loading…"));
  const importsEl = h("div", { class: "libs-imports", role: "table", "aria-label": "Imports", "data-testid": "libs-imports" });
  const importsHead = h("summary", {}, "Imports");
  const importsBox = h("details", { class: "libs-imports-box", "data-testid": "libs-imports-box" }, importsHead, importsEl) as HTMLDetailsElement;
  const status = h("div", { class: "libs-status dim", "aria-live": "polite" });
  const close = () => {
    backdrop.remove();
    restore?.focus({ preventScroll: true });
  };
  const box = h(
    "div",
    { class: "modal libs", role: "dialog", tabindex: "-1", "aria-label": `Libraries of ${o.programName}`, "data-testid": "libs-dialog" },
    h("div", { class: "libs-head" }, h("div", { class: "modal-title" }, `Libraries of ${o.programName}`), h("span", { class: "spacer" }), h("button", { class: "btn", type: "button", "data-testid": "libs-close", onclick: close, text: "Close" })),
    h("div", { class: "libs-meta dim", "data-testid": "libs-meta" }),
    libsEl,
    importsBox,
    status,
    h("div", { class: "modal-hint" }, "Open goes to the library program · Link… says which program a library is · Esc closes"),
  );
  const meta = box.querySelector<HTMLElement>(".libs-meta")!;
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

  const link = async (l: ProgramLibrary) => {
    let programs;
    try {
      programs = (await rk.projects.listPrograms({ projectId: o.programId.split("/")[0] })).programs;
    } catch (e) {
      return toast(errText(e), { kind: "error" });
    }
    const target = await choose<string>(
      `Which program is ${l.name}?`,
      [
        { label: "Find it by name (no link)", detail: "a program named so, or whose soname it is", value: "", current: !l.programId || l.resolution !== LibraryResolution.LINKED },
        ...programs
          .filter((p) => p.programId !== o.programId)
          .map((p) => ({ label: p.name, detail: `${p.languageId}${p.folderPath && p.folderPath !== "/" ? ` · ${p.folderPath}` : ""}`, value: p.programId, current: p.programId === l.programId && l.resolution === LibraryResolution.LINKED })),
      ],
      "↑↓ select · Enter link · Esc cancel",
    );
    if (target === null) return;
    try {
      const r = await rk.projects.linkProgramLibrary({ programId: o.programId, library: l.name, targetProgramId: target, provenance: userProvenance(`link ${l.name}`) });
      toast(target ? `${l.name} is ${r.library?.programName ?? target}` : `${l.name}: found by name again`);
      await load();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  };
  const row = (l: ProgramLibrary) => {
    const resolved = !!l.programId;
    const name = h("span", { class: "libs-name mono", title: l.depth ? `needed by ${l.neededBy}` : "" }, l.depth ? `${"  ".repeat(l.depth)}↳ ${l.name}` : l.name);
    const chip = h("span", { class: `libs-chip ${resolved ? "ok" : "none"}`, "data-testid": "libs-resolution" }, RESOLUTION[l.resolution] ?? "?");
    const target = resolved
      ? h("button", { class: "link libs-target", type: "button", title: `Open ${l.programId}`, "data-testid": "libs-open", onclick: () => o.openProgram(l.programId) }, l.programName || l.programId)
      : h("span", { class: "dim" }, "—");
    const count = h("span", { class: "dim libs-count" }, resolved ? `${l.importsResolved} import${l.importsResolved === 1 ? "" : "s"}` : "");
    const actions = h(
      "span",
      { class: "libs-actions" },
      h("button", { class: "btn small", type: "button", "data-testid": "libs-link", title: `Say which project program ${l.name} is`, onclick: () => void link(l), text: "Link…" }),
      !resolved && o.importLibraries ? h("button", { class: "btn small", type: "button", "data-testid": "libs-import", title: "Import it (the Open dialog's import section, with Also import libraries)", onclick: () => { close(); o.importLibraries!(); }, text: "Import…" }) : null,
    );
    return h("div", { class: "libs-row", role: "row", "data-testid": "libs-row", "data-name": l.name, "data-resolution": RESOLUTION[l.resolution] ?? "" }, name, chip, target, count, actions);
  };
  const importRow = (i: ResolvedImport) =>
    h(
      "div",
      { class: "libs-import" + (i.resolved ? " resolved" : ""), role: "row", "data-testid": "libs-import", "data-name": i.name },
      h("span", { class: "mono" }, i.name),
      h("span", { class: "dim" }, "→"),
      i.resolved
        ? h("button", { class: "link mono", type: "button", title: `Open ${i.programId} at ${i.functionName}`, onclick: () => o.openProgram(i.programId, i.address?.offset) }, importTarget(i))
        : h("span", { class: "dim" }, i.library ? `${i.library} (not in project)` : "not resolved"),
    );
  const load = async () => {
    try {
      const r = await rk.projects.listProgramLibraries({ programId: o.programId, includeImports: true });
      meta.textContent = [r.soname ? `soname ${r.soname}` : "", r.buildId ? `build ID ${r.buildId}` : ""].filter(Boolean).join(" · ");
      meta.hidden = !meta.textContent;
      libsEl.replaceChildren(...(r.libraries.length ? r.libraries.map(row) : [h("div", { class: "dim" }, "It needs no shared libraries.")]));
      const resolved = r.imports.filter((i) => i.resolved).length;
      importsHead.textContent = `Imports (${r.imports.length}, ${resolved} resolved)`;
      importsEl.replaceChildren(...r.imports.map(importRow));
      status.textContent = "";
    } catch (e) {
      status.textContent = errText(e);
    }
  };
  overlayRoot().append(backdrop);
  box.focus();
  void load();
}
