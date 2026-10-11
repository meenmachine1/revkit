// A browser of the daemon host's files (ProjectService.ListHostFiles; the
// daemon needs --browse-root), as a dialog over the one that asked: picks
// a file, or with `folders` a folder. The open dialog has its own copy
// inline; this one serves the header import (a header, include folders).

import type { Revkit } from "@revkit/api";
import { errText } from "../data/format";
import { h, overlayRoot, prefs } from "./dom";

export interface BrowseOptions {
  title: string;
  /** Pick a folder ("Use this folder") instead of a file. */
  folders?: boolean;
  /** Where to start (default: the last folder this kind of pick used). */
  start?: string;
  /** Remembers the last folder under this key. */
  remember?: string;
}

/** Resolves to the chosen path on the daemon's host, or null. */
export function browseHost(rk: Revkit, o: BrowseOptions): Promise<string | null> {
  return new Promise((resolve) => {
    const key = o.remember ?? "rk.hostfiles.lastDir";
    const restore = document.activeElement as HTMLElement | null;
    const list = h("div", { class: "palette-list host-list", role: "listbox", "aria-label": o.title, tabindex: "0", "data-testid": "host-list" });
    const crumb = h("div", { class: "browse-path dim mono" });
    let current = "";
    let rows: HTMLElement[] = [];
    let active = 0;
    const useDir = o.folders ? h("button", { class: "btn small primary", "data-testid": "host-use-folder", onclick: () => done(current) }, "Use this folder") : null;
    const box = h(
      "div",
      { class: "modal palette host-browser", role: "dialog", "aria-modal": "true", tabindex: "-1", "aria-label": o.title, "data-testid": "host-browser" },
      h("div", { class: "modal-title" }, o.title),
      crumb,
      list,
      h("div", { class: "types-actions" }, h("span", { class: "modal-hint" }, o.folders ? "Enter opens a folder · Esc cancels" : "Enter opens a folder or picks a file · Esc cancels"), h("span", { class: "spacer" }), useDir),
    );
    const backdrop = h("div", { class: "backdrop top" }, box);
    const done = (v: string | null) => {
      backdrop.remove();
      restore?.focus({ preventScroll: true });
      resolve(v);
    };
    const paint = () => rows.forEach((r, i) => r.classList.toggle("active", i === active));
    const go = async (dir: string) => {
      list.replaceChildren(h("div", { class: "dim" }, "Loading…"));
      let r;
      try {
        r = await rk.projects.listHostFiles({ path: dir });
      } catch (e) {
        if (dir) return go("");
        list.replaceChildren(h("div", { class: "error" }, `Can't browse the daemon host: ${errText(e)}`));
        return;
      }
      current = r.path;
      prefs.set(key, r.path);
      crumb.textContent = r.path;
      rows = [];
      const pick = (path: string, directory: boolean) => (directory ? void go(path) : o.folders ? undefined : done(path));
      if (r.parent) rows.push(h("div", { class: "palette-item browse-row dir", role: "option", onclick: () => void go(r.parent) }, h("span", { class: "pi-label" }, "../")));
      for (const e of r.entries) {
        if (o.folders && !e.directory) continue;
        rows.push(
          h(
            "div",
            { class: "palette-item browse-row" + (e.directory ? " dir" : ""), role: "option", title: e.path, "data-testid": "host-entry", "data-path": e.path, onclick: () => pick(e.path, e.directory) },
            h("span", { class: "pi-label" }, e.directory ? `${e.name}/` : e.name),
            h("span", { class: "pi-detail dim" }, e.directory ? "folder" : `${Number(e.size).toLocaleString()} bytes`),
          ),
        );
      }
      active = 0;
      list.replaceChildren(...(rows.length ? rows : [h("div", { class: "dim" }, "Empty folder.")]));
      if (r.truncated) list.append(h("div", { class: "dim" }, "More entries than can be listed."));
      paint();
    };
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") done(null);
      else if (e.key === "ArrowDown") active = Math.min(rows.length - 1, active + 1);
      else if (e.key === "ArrowUp") active = Math.max(0, active - 1);
      else if (e.key === "Enter") return rows[active]?.click();
      else return;
      e.preventDefault();
      paint();
      rows[active]?.scrollIntoView({ block: "nearest" });
    });
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done(null);
    });
    overlayRoot().append(backdrop);
    box.focus();
    void go(o.start ?? prefs.get(key) ?? "");
  });
}

/** A file chosen on the daemon's host (the memory map's bytes from a file). */
export interface HostFile {
  path: string;
  name: string;
}

export function formatSize(n: bigint): string {
  const v = Number(n);
  if (v < 1024) return `${v} B`;
  if (v < 1 << 20) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1 << 30) return `${(v / (1 << 20)).toFixed(1)} MB`;
  return `${(v / (1 << 30)).toFixed(1)} GB`;
}

/** A file on the daemon's host, or null when cancelled. */
export async function chooseHostFile(rk: Revkit, title = "Choose a file on the daemon's host"): Promise<HostFile | null> {
  const path = await browseHost(rk, { title, remember: "rk.memory.lastDir" });
  return path ? { path, name: path.slice(path.lastIndexOf("/") + 1) } : null;
}
