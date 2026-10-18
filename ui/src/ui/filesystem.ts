// The file system browser (feature "filesystems", api_minor 48;
// docs/filesystems.md), as Ghidra's File System Browser: File → Open file
// system… (or "Open as file system" in the Open dialog) opens an archive,
// a compressed file, a file system image or a firmware package; containers
// inside it open in place, to any depth.
//
// The tree's columns: name, size, type, permissions and what each file is
// (ELF/PE with its processor, a nested container's format, text, data).
// Right-click (or the context-menu key, Shift+F10): Import, Import programs
// below… (batch, with a preview and a cap), Open as file system, Decompile
// with jadx… (bytecode: the external decompilers that take it; external.ts),
// Extract to the daemon's host… (admin, under --browse-root), Info…
// (hashes, magic, container path), Copy container path. Several rows:
// Ctrl/Shift-click or Space.

import {
  FILESYSTEMS_FEATURE, FileSystemEntryKind, displayPath, isBrowsable, isProgram, openFileSystem, parentPath,
  type FileSystemEntry, type FileSystemSession, type FileSystemSource, type ImportFromFileSystemResponse,
  type ProjectFolder, type Revkit,
} from "@revkit/api";
import { userProvenance } from "../api/client";
import { errText } from "../data/format";
import { choose, toast } from "./dialogs";
import { h, overlayRoot } from "./dom";
import { pickFile } from "./filepick";
import { browseHost } from "./hostfiles";
import { EXTERNAL_FEATURE, applicable, providersFor, showExternalDialog } from "./external";
import { showMenu, showMenuAt, type MenuItem } from "./menu";

export { FILESYSTEMS_FEATURE };

export interface FileSystemBrowserOptions {
  rk: Revkit;
  /** The project imports go into (and a program source is in). */
  projectId: string;
  features: Set<string>;
  /** The program this tab shows: "The current program's file" as a source. */
  currentProgram?: { programId: string; name: string };
  pauseStreams?: () => () => void;
  /** Opens an imported program (the page navigates). */
  onOpenProgram: (programId: string) => void;
}

function bytes(n: bigint | number): string {
  const v = Number(n);
  if (v < 1024) return `${v} B`;
  if (v < 1 << 20) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1 << 30) return `${(v / (1 << 20)).toFixed(1)} MB`;
  return `${(v / (1 << 30)).toFixed(1)} GB`;
}

function kindName(e: FileSystemEntry): string {
  switch (e.kind) {
    case FileSystemEntryKind.DIRECTORY: return "dir";
    case FileSystemEntryKind.SYMLINK: return "link";
    case FileSystemEntryKind.HARDLINK: return "hard link";
    case FileSystemEntryKind.CHAR_DEVICE: return "char dev";
    case FileSystemEntryKind.BLOCK_DEVICE: return "block dev";
    case FileSystemEntryKind.FIFO: return "fifo";
    case FileSystemEntryKind.SOCKET: return "socket";
    case FileSystemEntryKind.FILE: return "file";
    default: return "other";
  }
}

/** File → Open file system…: where from, then the browser. */
export async function openFileSystemDialog(o: FileSystemBrowserOptions): Promise<void> {
  type From = "local" | "host" | "program";
  const choices: { label: string; detail?: string; value: From }[] = [
    { label: "A file on this computer…", detail: "sent to the daemon", value: "local" },
  ];
  if (o.features.has("host-files")) choices.push({ label: "A file or folder on the daemon host…", detail: "--browse-root", value: "host" });
  if (o.currentProgram) choices.push({ label: `This program's file (${o.currentProgram.name})`, detail: "a raw image holding a file system", value: "program" });
  const from = choices.length === 1 ? "local" : await choose<From>("Open file system", choices);
  if (!from) return;
  let source: FileSystemSource;
  if (from === "local") {
    const { file } = await pickFile({ pause: o.pauseStreams });
    if (!file) return;
    source = { file, name: file.name };
  } else if (from === "host") {
    const path = await browseHost(o.rk, { title: "Open file system: a container on the daemon host", remember: "rk.fs.lastDir" });
    if (!path) return;
    source = { hostPath: path };
  } else {
    source = { programId: o.currentProgram!.programId };
  }
  await openAndShow(o, source);
}

/** Opens `source` and shows the browser; a toast says why when it can't. */
export async function openAndShow(o: FileSystemBrowserOptions, source: FileSystemSource): Promise<FileSystemSession | null> {
  try {
    const fs = await openFileSystem(o.rk, o.projectId, source);
    showFileSystemBrowser(o, fs);
    return fs;
  } catch (e) {
    toast(`Can't open it as a file system: ${errText(e)}`, { kind: "error", ms: 8000 });
    return null;
  }
}

interface Node {
  entry: FileSystemEntry;
  depth: number;
  expanded: boolean;
  children?: Node[];
  more?: number;
  loading?: boolean;
  error?: string;
  /** A container file's format, once opened: the layer under it. */
  layer?: string;
}

/** The browser over an open session; closing it closes the session. */
export function showFileSystemBrowser(o: FileSystemBrowserOptions, fs: FileSystemSession) {
  const restore = document.activeElement as HTMLElement | null;
  const rk = o.rk;
  let roots: Node[] = [];
  let rows: Node[] = [];
  let active = 0;
  const selected = new Set<string>();
  let anchor = -1;

  const status = h("div", { class: "fs-status", "aria-live": "polite", "data-testid": "fs-status" });
  const say = (text: string, kind: "" | "error" | "hint" = "") => {
    status.textContent = text;
    status.className = "fs-status" + (kind ? " " + kind : "");
  };
  const where = h("div", { class: "fs-where dim mono", "data-testid": "fs-where" });
  const list = h("div", { class: "fs-tree", role: "tree", "aria-multiselectable": "true", "aria-label": `Files in ${fs.name}`, tabindex: "0", "data-testid": "fs-tree" });
  const head = h(
    "div",
    { class: "fs-row fs-head", "aria-hidden": "true" },
    h("span", {}, "Name"), h("span", { class: "fs-size" }, "Size"), h("span", {}, "Type"), h("span", {}, "Permissions"), h("span", {}, "What it is"),
  );
  const btn = (label: string, testid: string, run: () => void, title = "") => h("button", { class: "btn small", "data-testid": testid, title, onclick: run, text: label });
  const box = h(
    "div",
    { class: "modal fs-browser", role: "dialog", "aria-modal": "true", tabindex: "-1", "aria-label": `File system: ${fs.name}`, "data-testid": "fs-browser" },
    h(
      "div",
      { class: "fs-top" },
      h("div", { class: "modal-title" }, `File system: ${fs.name}`),
      h("span", { class: "dim fs-desc", "data-testid": "fs-desc" }, fs.root?.description ?? ""),
      h("span", { class: "spacer" }),
      btn("Import…", "fs-import", () => void importSelection(), "Import the selected files as programs"),
      btn("Import programs below…", "fs-batch", () => void batchImport(), "Every program below the selected folders (or everywhere), with a preview"),
      btn("Extract…", "fs-extract", () => void extract(), "Write the selected files to a folder on the daemon host (admin)"),
      btn("Info", "fs-info", () => void info(), "Hashes, first bytes and the container path"),
      btn("Close", "fs-close", () => close()),
    ),
    fs.root?.warnings.length ? h("div", { class: "fs-warn" }, fs.root.warnings.join(" · ")) : null,
    head,
    list,
    where,
    status,
  );
  const backdrop = h("div", { class: "backdrop top" }, box);
  const close = () => {
    backdrop.remove();
    void fs.close();
    restore?.focus({ preventScroll: true });
  };

  const load = async (path: string, depth: number): Promise<{ nodes: Node[]; more: number; layer?: string }> => {
    const r = await fs.list(path, { detect: true, limit: 2000 });
    const nodes = r.entries.map((entry) => ({ entry, depth, expanded: false }));
    return { nodes, more: Math.max(0, r.total - r.entries.length), layer: r.layer?.format };
  };

  const flatten = () => {
    rows = [];
    const walk = (ns: Node[]) => {
      for (const n of ns) {
        rows.push(n);
        if (n.expanded && n.children) walk(n.children);
      }
    };
    walk(roots);
    active = Math.min(active, Math.max(0, rows.length - 1));
  };

  const typeText = (n: Node) => {
    const e = n.entry;
    if (e.containerFormat) return `${kindName(e)} · ${e.containerFormat}`;
    return kindName(e);
  };

  const render = () => {
    flatten();
    list.replaceChildren(
      ...rows.flatMap((n, i) => {
        const e = n.entry;
        const browsable = isBrowsable(e);
        const caret = browsable ? (n.loading ? "…" : n.expanded ? "▾" : "▸") : "";
        const what = [e.detected, e.processor && !e.detected.includes(e.processor) ? e.processor : "", e.languageId ? `loads as ${e.languageId}` : ""].filter(Boolean).join(" · ");
        const row = h(
          "div",
          {
            class: "fs-row" + (i === active ? " active" : "") + (selected.has(e.path) ? " selected" : "") + (e.unreadable ? " unreadable" : "") + (isProgram(e) ? " program" : ""),
            role: "treeitem",
            "aria-level": String(n.depth + 1),
            "aria-selected": String(selected.has(e.path)),
            ...(browsable ? { "aria-expanded": String(n.expanded) } : {}),
            "data-i": String(i),
            "data-path": e.path,
            "data-name": e.name,
            "data-kind": e.detectedKind,
            "data-testid": "fs-row",
            title: [displayPath(e.path), e.linkTarget ? `→ ${e.linkTarget}` : "", e.note].filter(Boolean).join("\n"),
          },
          h(
            "span",
            { class: "fs-name", style: `padding-left:${n.depth * 16}px` },
            h("span", { class: "fs-caret" }, caret),
            h("span", { class: "fs-label" }, e.name + (e.kind === FileSystemEntryKind.DIRECTORY ? "/" : "")),
            e.linkTarget ? h("span", { class: "dim" }, ` → ${e.linkTarget}`) : null,
            e.renamed ? h("span", { class: "badge fs-renamed", title: e.note }, "renamed") : null,
          ),
          h("span", { class: "fs-size dim" }, e.kind === FileSystemEntryKind.DIRECTORY ? `${e.childCount}` : e.sizeUnknown ? "?" : bytes(e.size)),
          h("span", { class: "dim" }, typeText(n)),
          h("span", { class: "mono dim" }, e.permissions),
          h(
            "span",
            { class: "fs-what" + (e.unreadable ? " error" : "") },
            e.unreadable ? e.note : what || (e.detectedKind ? "" : "…"),
            // What a script or bytecode decompiler would take it as (api_minor 95): "pyc:3.12", "lua:5.4", "js-source".
            e.contentKind && !e.unreadable
              ? h("span", { class: "badge mono fs-content-kind", "data-testid": "fs-content-kind", title: "Content kind: what a script or bytecode decompiler takes this file as" }, e.contentKind)
              : null,
          ),
        );
        const out: HTMLElement[] = [row];
        if (n.expanded && n.error) out.push(h("div", { class: "fs-row fs-note error", style: `padding-left:${(n.depth + 1) * 16 + 14}px` }, n.error));
        if (n.expanded && n.more) out.push(h("div", { class: "fs-row fs-note dim", style: `padding-left:${(n.depth + 1) * 16 + 14}px` }, `${n.more} more not shown`));
        return out;
      }),
    );
    const cur = rows[active];
    where.textContent = cur ? displayPath(cur.entry.path) : "";
    list.querySelector<HTMLElement>(".fs-row.active")?.scrollIntoView({ block: "nearest" });
  };

  const expand = async (n: Node, open = true) => {
    if (!isBrowsable(n.entry)) return;
    if (!open) {
      n.expanded = false;
      render();
      return;
    }
    n.expanded = true;
    if (!n.children) {
      n.loading = true;
      render();
      try {
        const r = await load(n.entry.path, n.depth + 1);
        n.children = r.nodes;
        n.more = r.more;
        n.layer = r.layer;
        n.error = undefined;
        if (n.entry.containerFormat) say(`Opened ${n.entry.name} as ${r.layer ?? n.entry.containerFormat}.`);
      } catch (e) {
        n.children = [];
        n.error = errText(e);
      } finally {
        n.loading = false;
      }
    }
    render();
  };

  const targets = (): Node[] => {
    const picked = rows.filter((n) => selected.has(n.entry.path));
    return picked.length ? picked : rows[active] ? [rows[active]] : [];
  };

  const select = (i: number, how: "only" | "toggle" | "range") => {
    const n = rows[i];
    if (!n) return;
    if (how === "only") {
      selected.clear();
      selected.add(n.entry.path);
      anchor = i;
    } else if (how === "toggle") {
      if (selected.has(n.entry.path)) selected.delete(n.entry.path);
      else selected.add(n.entry.path);
      anchor = i;
    } else {
      const from = anchor < 0 ? i : anchor;
      selected.clear();
      for (let k = Math.min(from, i); k <= Math.max(from, i); k++) if (rows[k]) selected.add(rows[k].entry.path);
    }
    active = i;
    render();
  };

  // --- actions ---

  const opened = (r: ImportFromFileSystemResponse) => {
    const done = r.items.filter((i) => i.action === "imported" && !i.libraryOf);
    const libs = r.items.filter((i) => i.action === "imported" && i.libraryOf);
    const first = done[0]?.program;
    const failed = r.items.filter((i) => i.action === "failed");
    // The libraries brought with them from this file system (api_minor 79).
    const missing = r.librariesNotFound ?? [];
    const text = `Imported ${done.length} program${done.length === 1 ? "" : "s"}` +
      (libs.length ? ` and ${libs.length} librar${libs.length === 1 ? "y" : "ies"} they need (${libs.map((i) => i.program?.name).join(", ")})` : "") +
      (missing.length ? `; not in the file system: ${missing.map((m) => m.name).join(", ")}` : "") +
      (r.skipped ? `, ${r.skipped} skipped` : "") + (failed.length ? `, ${failed.length} failed (${failed[0].reason})` : "") + (r.capped ? " (capped)" : "");
    say(text, failed.length && !done.length ? "error" : "");
    if (first) toast(text, { action: { label: `Open ${first.name}`, run: () => { close(); o.onOpenProgram(first.programId); } }, ms: 10000 });
    else if (failed.length) toast(text, { kind: "error", ms: 8000 });
  };

  const importSelection = async () => {
    const files = targets().filter((n) => !isBrowsable(n.entry) || n.entry.kind !== FileSystemEntryKind.DIRECTORY);
    if (!files.length) {
      say("Pick files to import (folders: Import programs below…).", "hint");
      return;
    }
    say(`Importing ${files.length === 1 ? files[0].entry.name : `${files.length} files`}…`);
    try {
      const r = await fs.import(files.map((n) => n.entry.path), { programsOnly: false, provenance: userProvenance("import from " + fs.name), options: { analyze: true } });
      opened(r);
    } catch (e) {
      say(`Import failed: ${errText(e)}`, "error");
    }
  };

  const batchImport = async () => {
    // The folders and containers picked, else everything.
    const picked = rows.filter((n) => selected.has(n.entry.path) && isBrowsable(n.entry));
    const paths = picked.length ? picked.map((n) => n.entry.path) : ["/"];
    await showBatchImport(o, fs, paths, (r) => opened(r));
  };

  const extract = async () => {
    const t = targets();
    if (!t.length) return;
    if (!o.features.has("host-files")) {
      say("Extracting writes under the daemon's --browse-root, and it has none.", "error");
      return;
    }
    const dir = await browseHost(rk, { title: `Extract ${t.length === 1 ? t[0].entry.name : `${t.length} items`} into a folder on the daemon host`, folders: true, remember: "rk.fs.extractDir" });
    if (!dir) return;
    say("Extracting…");
    try {
      const r = await fs.extract(t.map((n) => n.entry.path), dir);
      say(`Extracted ${r.files} file${r.files === 1 ? "" : "s"} (${bytes(r.bytes)}) into ${dir}` + (r.skipped.length ? `; ${r.skipped.length} skipped (${r.skipped[0]})` : ""));
    } catch (e) {
      say(`Extract failed: ${errText(e)}`, "error");
    }
  };

  const info = async () => {
    const n = rows[active];
    if (!n) return;
    await showInfo(fs, n.entry);
  };

  const menu = async (x?: number, y?: number) => {
    const t = targets();
    if (!t.length) return;
    const one = t.length === 1 ? t[0] : null;
    const e = one?.entry;
    const files = t.filter((n) => n.entry.kind !== FileSystemEntryKind.DIRECTORY);
    const items: MenuItem[] = [
      { label: files.length > 1 ? `Import ${files.length} files` : "Import", testid: "fs-menu-import", disabled: !files.length, run: () => void importSelection() },
      { label: "Import programs below…", testid: "fs-menu-batch", disabled: !t.some((n) => isBrowsable(n.entry)), run: () => void batchImport() },
    ];
    if (e?.containerFormat) items.push({ label: `Open as file system (${e.containerFormat})`, testid: "fs-menu-open", run: () => void expand(one!, true) });
    // Bytecode: the external decompilers that take it (a jar, an APK, a .pyc, ...).
    if (e && e.kind === FileSystemEntryKind.FILE && o.features.has(EXTERNAL_FEATURE)) {
      const list = await providersFor(rk, { sessionId: fs.id, path: e.path }).catch(() => null);
      if (list?.inputKind?.kind)
        for (const p of applicable(list))
          items.push({
            label: `Decompile with ${p.title}…`,
            testid: `fs-menu-decompile-${p.name}`,
            disabled: !p.available,
            title: p.available ? `${list.inputKind.description} → ${p.title} ${p.version} (in the daemon's sandbox)` : p.reason,
            run: () => showExternalDialog(rk, { sessionId: fs.id, path: e.path }, list, p.name, `${p.title}: ${e.name}`),
          });
    }
    items.push(
      { label: "Extract to daemon host…", testid: "fs-menu-extract", separator: true, disabled: !o.features.has("host-files"), run: () => void extract() },
      { label: "Info…", testid: "fs-menu-info", disabled: !one, run: () => void info() },
      { label: "Copy container path", testid: "fs-menu-copy", disabled: !one, run: () => void copyPath(one!.entry) },
    );
    if (x !== undefined && y !== undefined) showMenu(items, x, y, "File system");
    else showMenuAt(list.querySelector<HTMLElement>(".fs-row.active") ?? list, items, "File system");
  };

  const copyPath = async (e: FileSystemEntry) => {
    try {
      const r = await fs.info(e.path);
      await navigator.clipboard?.writeText(r.containerPath);
      say(`Copied ${r.containerPath}`);
    } catch (err) {
      say(errText(err), "error");
    }
  };

  // --- events ---

  list.addEventListener("mousedown", (ev) => {
    const el = (ev.target as HTMLElement).closest<HTMLElement>("[data-i]");
    if (!el) return;
    const i = Number(el.dataset.i);
    if (ev.button === 2) {
      if (!selected.has(rows[i]?.entry.path ?? "")) select(i, "only");
      return;
    }
    const onCaret = (ev.target as HTMLElement).classList.contains("fs-caret");
    if (onCaret) {
      const n = rows[i];
      void expand(n, !n.expanded);
      return;
    }
    select(i, ev.shiftKey ? "range" : ev.ctrlKey || ev.metaKey ? "toggle" : "only");
  });
  list.addEventListener("dblclick", (ev) => {
    const el = (ev.target as HTMLElement).closest<HTMLElement>("[data-i]");
    if (!el) return;
    const n = rows[Number(el.dataset.i)];
    if (n && isBrowsable(n.entry)) void expand(n, !n.expanded);
    else if (n) void info();
  });
  list.addEventListener("contextmenu", (ev) => {
    ev.preventDefault();
    void menu(ev.clientX, ev.clientY);
  });
  box.addEventListener("keydown", (ev) => {
    if ((ev.target as HTMLElement).tagName === "INPUT") return;
    ev.stopPropagation();
    const n = rows[active];
    if (ev.key === "Escape") return close();
    if (ev.key === "ArrowDown") select(Math.min(rows.length - 1, active + 1), ev.shiftKey ? "range" : "only");
    else if (ev.key === "ArrowUp") select(Math.max(0, active - 1), ev.shiftKey ? "range" : "only");
    else if (ev.key === "ArrowRight" && n) void expand(n, true);
    else if (ev.key === "ArrowLeft" && n) {
      if (n.expanded) void expand(n, false);
      else {
        const up = parentPath(n.entry.path);
        const i = rows.findIndex((r) => r.entry.path === up || r.entry.path === up.replace(/!$/, ""));
        if (i >= 0) select(i, "only");
      }
    } else if (ev.key === " " && n) select(active, "toggle");
    else if (ev.key === "Enter" && n) {
      if (isBrowsable(n.entry)) void expand(n, !n.expanded);
      else void info();
    } else if (ev.key === "ContextMenu" || (ev.key === "F10" && ev.shiftKey)) void menu();
    else return;
    ev.preventDefault();
  });
  backdrop.addEventListener("mousedown", (ev) => {
    if (ev.target === backdrop) close();
  });

  overlayRoot().append(backdrop);
  list.focus();
  say("Loading…");
  void (async () => {
    try {
      const r = await load("/", 0);
      roots = r.nodes;
      render();
      say(`${fs.root?.description ?? ""}${r.more ? ` (${r.more} more not shown)` : ""}`);
      active = 0;
      render();
    } catch (e) {
      say(errText(e), "error");
    }
  })();
}

/** Info…: the entry, what it is, its first bytes, hashes and container path. */
async function showInfo(fs: FileSystemSession, e: FileSystemEntry) {
  const body = h("div", { class: "fs-info-body", "data-testid": "fs-info" }, h("div", { class: "dim" }, "Reading…"));
  const restore = document.activeElement as HTMLElement | null;
  const box = h("div", { class: "modal archive", role: "dialog", "aria-modal": "true", tabindex: "-1", "aria-label": `Info: ${e.name}` },
    h("div", { class: "modal-title" }, `Info: ${e.name}`), body,
    h("div", { class: "archive-buttons" }, h("button", { class: "btn", "data-testid": "fs-info-close", onclick: () => done(), text: "Close" })));
  const backdrop = h("div", { class: "backdrop top" }, box);
  const done = () => {
    backdrop.remove();
    restore?.focus({ preventScroll: true });
  };
  box.addEventListener("keydown", (ev) => {
    ev.stopPropagation();
    if (ev.key === "Escape") done();
  });
  backdrop.addEventListener("mousedown", (ev) => {
    if (ev.target === backdrop) done();
  });
  overlayRoot().append(backdrop);
  box.focus();
  try {
    const small = e.kind === FileSystemEntryKind.FILE && !e.sizeUnknown && e.size <= 256n << 20n;
    const r = await fs.info(e.path, small);
    const x = r.entry ?? e;
    const hex = [...r.magic.slice(0, 32)].map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const text = [...r.magic.slice(0, 32)].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    const line = (k: string, v: string, testid?: string) => (v ? h("div", { class: "fs-info-line" }, h("span", { class: "dim" }, k), h("span", { class: "mono", ...(testid ? { "data-testid": testid } : {}) }, v)) : null);
    body.replaceChildren(
      ...[
        line("Container path", r.containerPath, "fs-info-path"),
        line("What it is", [x.detected, x.processor].filter(Boolean).join(" · "), "fs-info-detected"),
        line("Size", x.sizeUnknown ? "unknown until read" : `${x.size.toLocaleString("en-US")} bytes`),
        line("Stored", x.storedSize ? `${x.storedSize.toLocaleString("en-US")} bytes` : ""),
        line("Permissions", x.permissions),
        line("Owner", x.hasOwner ? `${x.uid}:${x.gid}` : ""),
        line("Modified", x.modified ? new Date(Number(x.modified.seconds) * 1000).toISOString().replace("T", " ").slice(0, 19) : ""),
        line("Link", x.linkTarget ? `${x.linkTarget}${x.linkPath ? ` (${displayPath(x.linkPath)})` : " (not in the container)"}` : ""),
        line("Loads as", x.languageId ? `${x.languageId}${x.hasLoadAddress ? ` at 0x${x.loadAddress.toString(16)}` : ""}` : ""),
        line("Note", x.note),
        line("Holds", r.container ? `${r.container.description}` : ""),
        line("SHA-256", r.sha256, "fs-info-sha256"),
        line("SHA-1", r.sha1),
        line("MD5", r.md5),
        line("First bytes", hex ? `${hex}\n${text}` : ""),
        small || x.kind !== FileSystemEntryKind.FILE ? null : h("button", {
          class: "btn small", text: "Compute hashes", onclick: async () => {
            try {
              const full = await fs.info(e.path, true);
              body.append(...[line("SHA-256", full.sha256, "fs-info-sha256"), line("SHA-1", full.sha1), line("MD5", full.md5)].filter((v): v is HTMLDivElement => !!v));
            } catch (err) {
              body.append(h("div", { class: "error" }, errText(err)));
            }
          },
        }),
      ].filter((v): v is HTMLDivElement | HTMLButtonElement => !!v),
    );
  } catch (err) {
    body.replaceChildren(h("div", { class: "error" }, errText(err)));
  }
}

/** Import programs below…: options, a preview of what would be imported, and the import. */
async function showBatchImport(o: FileSystemBrowserOptions, fs: FileSystemSession, paths: string[], done: (r: ImportFromFileSystemResponse) => void) {
  const rk = o.rk;
  const restore = document.activeElement as HTMLElement | null;
  const check = (label: string, testid: string, on: boolean, title = "") => {
    const input = h("input", { type: "checkbox", "data-testid": testid, ...(on ? { checked: true } : {}) }) as HTMLInputElement;
    return { input, el: h("label", { class: "archive-line", title }, input, label) };
  };
  const recursive = check("Subfolders too", "fs-batch-recursive", true);
  const descend = check("Look inside archives and images found", "fs-batch-descend", true);
  const detectRaw = check("Try raw detection on other data (slow: seconds per file)", "fs-batch-detect-raw", false);
  const keepFolders = check("Recreate the folders in the project", "fs-batch-keep-folders", false);
  const analyze = check("Analyze after import", "fs-batch-analyze", true);
  // Feature library-roots (api_minor 79): the libraries they need, found in this file system.
  const libraries = o.features.has("library-roots")
    ? check("Also import the libraries they need, from this file system", "fs-batch-libraries", false,
      "The shared libraries the programs need (ELF DT_NEEDED, PE import DLLs) that the project lacks: beside each program, on its runpath, in /etc/ld.so.conf's directories and /lib and /usr/lib of the container it is in; two levels deep")
    : null;
  const cap = h("input", { class: "ask-input", type: "number", min: "1", max: "1000", value: "100", "data-testid": "fs-batch-cap", "aria-label": "At most this many programs" }) as HTMLInputElement;
  const folderSel = h("select", { class: "ctl-select", "data-testid": "fs-batch-folder", "aria-label": "Into folder" }, h("option", { value: "" }, "/")) as HTMLSelectElement;
  const preview = h("div", { class: "archive-programs fs-preview", "data-testid": "fs-batch-preview" });
  const statusEl = h("div", { class: "archive-status", "aria-live": "polite", "data-testid": "fs-batch-status" });
  const go = h("button", { class: "btn primary", "data-testid": "fs-batch-go", disabled: true, text: "Import" }) as HTMLButtonElement;
  const box = h(
    "div",
    { class: "modal archive fs-batch", role: "dialog", "aria-modal": "true", tabindex: "-1", "aria-label": "Import programs", "data-testid": "fs-batch-dialog" },
    h("div", { class: "modal-title" }, `Import programs from ${paths.length === 1 ? displayPath(paths[0]) : `${paths.length} folders`}`),
    h("div", { class: "archive-note dim" }, "Programs only: ELF, PE, and raw images whose header names their processor."),
    recursive.el, descend.el, detectRaw.el, keepFolders.el, analyze.el, ...(libraries ? [libraries.el] : []),
    h("label", { class: "archive-line" }, "At most", cap, "programs, into folder", folderSel),
    h("div", { class: "archive-section dim" }, "Preview"),
    preview,
    statusEl,
    h("div", { class: "archive-buttons" }, h("button", { class: "btn", "data-testid": "fs-batch-cancel", onclick: () => finish(), text: "Cancel" }), go),
  );
  const backdrop = h("div", { class: "backdrop top" }, box);
  const finish = () => {
    backdrop.remove();
    restore?.focus({ preventScroll: true });
  };
  box.addEventListener("keydown", (ev) => {
    ev.stopPropagation();
    if (ev.key === "Escape") finish();
  });
  overlayRoot().append(backdrop);
  box.focus();
  try {
    const listed = await rk.projects.listPrograms({ projectId: fs.projectId });
    for (const f of [...listed.folders].sort((a: ProjectFolder, b: ProjectFolder) => a.path.localeCompare(b.path)))
      folderSel.append(h("option", { value: f.folderId }, f.path));
  } catch {
    /* folders unknown: the root */
  }
  const request = (previewOnly: boolean) => ({
    recursive: recursive.input.checked, descend: descend.input.checked, detectRaw: detectRaw.input.checked,
    keepFolders: keepFolders.input.checked, programsOnly: true, preview: previewOnly,
    maxPrograms: Math.max(1, Math.min(1000, Number(cap.value) || 100)), folderId: folderSel.value,
    options: { analyze: analyze.input.checked, importLibraries: !!libraries?.input.checked }, provenance: userProvenance(`batch import from ${fs.name}`),
  });
  let generation = 0;
  const refresh = async () => {
    const mine = ++generation;
    go.disabled = true;
    statusEl.textContent = "Looking…";
    statusEl.className = "archive-status";
    try {
      const r = await fs.import(paths, request(true));
      if (mine !== generation) return;
      const take = r.items.filter((i) => i.action === "import");
      preview.replaceChildren(
        ...r.items.slice(0, 500).map((i) =>
          h("div", { class: "archive-program" + (i.action === "import" ? "" : " dim"), "data-testid": "fs-batch-item", "data-action": i.action, title: i.reason },
            h("span", { class: "mono" }, displayPath(i.path)), h("span", {}, i.detected), h("span", {}, i.action === "import" ? "import" : i.reason)),
        ),
      );
      statusEl.textContent = `${take.length} program${take.length === 1 ? "" : "s"} to import, ${r.items.length - take.length} other file${r.items.length - take.length === 1 ? "" : "s"} left out` + (r.capped ? " (capped)" : "");
      go.textContent = `Import ${take.length} program${take.length === 1 ? "" : "s"}`;
      go.disabled = !take.length;
    } catch (e) {
      if (mine !== generation) return;
      statusEl.textContent = errText(e);
      statusEl.className = "archive-status error";
    }
  };
  for (const c of [recursive, descend, detectRaw, keepFolders]) c.input.addEventListener("change", () => void refresh());
  cap.addEventListener("change", () => void refresh());
  go.addEventListener("click", async () => {
    go.disabled = true;
    statusEl.textContent = "Importing… (each program is loaded and analyzed in turn)";
    try {
      const r = await fs.import(paths, request(false));
      finish();
      done(r);
    } catch (e) {
      statusEl.textContent = `Import failed: ${errText(e)}`;
      statusEl.className = "archive-status error";
      go.disabled = false;
    }
  });
  await refresh();
}
