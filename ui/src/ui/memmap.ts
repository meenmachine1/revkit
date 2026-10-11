// The Memory Map view (Ghidra's Window → Memory Map; docs/memory-map.md):
// every block of the program — the image's own and the regions added since
// import — with its range, size, permissions, whether it is initialized or
// volatile, where its bytes come from and who added or edited it; and,
// with the daemon's feature memory-map, adding a region (RAM, zero-filled,
// memory-mapped I/O, or bytes from another file, uploaded or from the
// daemon's host), changing or removing one, and editing an image block's
// name, permissions and volatile flag. Every change is an assertion: Ctrl+Z
// undoes it (the tab's undo stack), and every tab and client follows it.
//
// Keys in the table: ↑↓ select, Enter go to the block's start, e or F2
// edit, Delete remove (or revert an image block's edits), a add.

import { MemoryBlockSourceKind, type MemoryBlock, type Revkit } from "@revkit/api";
import { userProvenance } from "../api/client";
import { errText, hex, originClass, provText } from "../data/format";
import { ask, toast } from "./dialogs";
import { h } from "./dom";
import { chooseHostFile, formatSize } from "./hostfiles";
import { pickFile } from "./filepick";
import { kindOf, regionForm, type RegionDraft } from "./regionform";

export interface MemoryMapOptions {
  rk: Revkit;
  programId: string;
  addrWidth: number;
  /** Edits allowed (feature memory-map). */
  editable: boolean;
  /** The daemon lists its host's files (feature host-files). */
  hostFiles: boolean;
  /** Goes to an address in the listing. */
  navigate: (address: bigint) => void;
  /** Records an edit on the tab's undo stack. */
  recordUndo: (label: string, seqs: bigint[]) => void;
  /** Undoes the tab's last edit (the toast's Undo). */
  undo: () => void;
  /** Waits until this tab has seen a revision (so the views follow). */
  settle: (revision: bigint) => Promise<void>;
  /** Pauses the live streams while the system file chooser is open. */
  pause?: () => () => void;
  /** The daemon can move the program to another image base (feature rebase). */
  rebase?: boolean;
  /** After a rebase: the views follow the program from `from` to `to`. */
  rebased?: (from: bigint, to: bigint) => void;
}

const SOURCE: Record<number, string> = {
  [MemoryBlockSourceKind.IMAGE]: "image",
  [MemoryBlockSourceKind.FILE]: "file",
  [MemoryBlockSourceKind.ZERO]: "zero",
  [MemoryBlockSourceKind.NONE]: "none",
};

function perms(b: MemoryBlock): string {
  return (b.read ? "r" : "-") + (b.write ? "w" : "-") + (b.execute ? "x" : "-");
}

function size(b: MemoryBlock): bigint {
  return (b.range?.last?.offset ?? 0n) - (b.range?.first?.offset ?? 0n) + 1n;
}

export function sourceText(b: MemoryBlock): string {
  const s = b.source;
  if (!s || s.kind === MemoryBlockSourceKind.UNSPECIFIED) return b.hasFileOffset ? `image @${b.fileOffset.toString(16)}` : b.initialized ? "image" : "none";
  switch (s.kind) {
    case MemoryBlockSourceKind.IMAGE:
      return `image @${s.fileOffset.toString(16)}`;
    case MemoryBlockSourceKind.FILE:
      return `${s.file} @${s.fileOffset.toString(16)}${s.missing ? " (bytes on their way)" : ""}`;
    case MemoryBlockSourceKind.ZERO:
      return "zero-filled";
    default:
      return "none";
  }
}

export class MemoryMapView {
  private blocks: MemoryBlock[] = [];
  private rejected: MemoryBlock[] = [];
  private active = -1;
  private loaded = false;
  private seq = 0;
  private body: HTMLElement;
  private count: HTMLElement;
  private table: HTMLElement;
  private addBtn: HTMLButtonElement;
  private baseBtn: HTMLButtonElement;

  constructor(
    root: HTMLElement,
    private o: MemoryMapOptions,
  ) {
    this.count = h("span", { class: "dim count", "data-testid": "mem-count" });
    this.addBtn = h("button", {
      class: "btn small",
      type: "button",
      "data-testid": "mem-add",
      title: o.editable ? "Add RAM, memory-mapped I/O or another file's bytes (a)" : "This daemon can't edit the memory map",
      disabled: !o.editable,
      text: "Add region…",
    }) as HTMLButtonElement;
    this.addBtn.addEventListener("click", () => void this.add());
    this.baseBtn = h("button", {
      class: "btn small",
      type: "button",
      "data-testid": "mem-rebase",
      title: o.rebase
        ? "Move the whole program to another image base, with everything recorded about it (a raw image whose base was guessed wrong)"
        : "This daemon can't move a program (feature rebase)",
      disabled: !o.rebase,
      hidden: !o.rebase,
      text: "Set image base…",
    }) as HTMLButtonElement;
    this.baseBtn.addEventListener("click", () => void this.setImageBase());
    this.body = h("tbody", {});
    this.table = h(
      "table",
      { class: "mem-table", tabindex: "0", "aria-label": "Memory blocks", "data-testid": "mem-table" },
      h(
        "thead",
        {},
        h(
          "tr",
          {},
          ...["Name", "Start", "End", "Size", "Perms", "Init", "Volatile", "Source", "By", ""].map((t) => h("th", { scope: "col" }, t)),
        ),
      ),
      this.body,
    );
    root.append(
      h("div", { class: "panel-head view-head" }, h("span", { class: "panel-title" }, "Memory map"), this.count, h("span", { class: "spacer" }), this.baseBtn, this.addBtn),
      h("div", { class: "mem-scroll" }, this.table),
    );
    this.table.addEventListener("keydown", (e) => this.onKey(e));
    this.body.addEventListener("click", (e) => {
      const tr = (e.target as HTMLElement).closest<HTMLElement>("tr[data-i]");
      if (!tr || (e.target as HTMLElement).closest("button")) return;
      this.active = Number(tr.dataset.i);
      this.paint();
      this.go();
    });
  }

  /** The rows (tests): name, start, end, perms, flags, source, region id, origin. */
  rows() {
    return [...this.blocks, ...this.rejected].map((b) => ({
      name: b.name,
      start: hex(b.range?.first?.offset ?? 0n),
      end: hex(b.range?.last?.offset ?? 0n),
      perms: perms(b),
      initialized: b.initialized,
      volatile: b.isVolatile,
      source: SOURCE[b.source?.kind ?? 0] ?? "image",
      file: b.source?.file ?? "",
      regionId: b.regionId,
      edited: b.edited,
      rejected: b.rejected,
      by: originClass(b.origin) === "derived" ? "loader" : provText(b.origin?.source.case === "asserted" ? b.origin.source.value.provenance : undefined),
    }));
  }

  markStale() {
    this.loaded = false;
  }

  ensureLoaded() {
    if (!this.loaded) void this.load();
  }

  focus() {
    this.table.focus();
  }

  async load() {
    this.loaded = true;
    const mine = ++this.seq;
    try {
      const r = await this.o.rk.queries.getMemoryMap({ programId: this.o.programId });
      if (mine !== this.seq) return;
      this.blocks = r.blocks;
      this.rejected = r.rejected;
      const added = r.blocks.filter((b) => b.regionId).length;
      this.count.textContent = `${r.blocks.length} ${r.blocks.length === 1 ? "block" : "blocks"}${added ? `, ${added} added` : ""}${r.rejected.length ? `, ${r.rejected.length} not mapped` : ""}`;
    } catch (e) {
      if (mine !== this.seq) return;
      this.blocks = [];
      this.rejected = [];
      this.count.textContent = errText(e);
    }
    this.active = Math.min(this.active, this.blocks.length + this.rejected.length - 1);
    this.paint();
  }

  private all(): MemoryBlock[] {
    return [...this.blocks, ...this.rejected];
  }

  private paint() {
    const w = this.o.addrWidth;
    const rows = this.all().map((b, i) => {
      const user = !!b.regionId;
      const oc = originClass(b.origin);
      const by = oc === "derived" ? "loader" : provText(b.origin?.source.case === "asserted" ? b.origin.source.value.provenance : undefined);
      const actions: HTMLElement[] = [];
      if (this.o.editable) {
        actions.push(h("button", { class: "icon mem-act", type: "button", title: user ? "Edit the region (e)" : "Edit the block's name, permissions, volatile flag (e)", "aria-label": `Edit ${b.name}`, "data-testid": "mem-edit", onclick: () => void this.edit(b) }, "✎"));
        if (user) actions.push(h("button", { class: "icon mem-act", type: "button", title: "Remove the region (Delete)", "aria-label": `Remove ${b.name}`, "data-testid": "mem-remove", onclick: () => void this.remove(b) }, "✕"));
        else if (b.edited) actions.push(h("button", { class: "icon mem-act", type: "button", title: "Revert the edits to this block (Delete)", "aria-label": `Revert the edits to ${b.name}`, "data-testid": "mem-revert", onclick: () => void this.remove(b) }, "↺"));
      }
      const first = b.range?.first?.offset ?? 0n;
      return h(
        "tr",
        {
          class: "mem-row" + (i === this.active ? " active" : "") + (b.rejected ? " rejected" : "") + (user ? " user" : ""),
          "data-i": i,
          "data-testid": "mem-row",
          "data-name": b.name,
          "aria-selected": i === this.active ? "true" : "false",
          title: b.rejected ? `Not mapped: ${b.rejected}` : `${b.name}: ${sourceText(b)}${b.edited ? " (edited)" : ""}`,
        },
        h("td", { class: "mem-name" }, b.name, b.edited ? h("span", { class: "badge mem-badge", title: "edited" }, "edited") : null, b.rejected ? h("span", { class: "badge mem-badge error" }, "not mapped") : null),
        h("td", { class: "mono" }, hex(first, w)),
        h("td", { class: "mono" }, hex(b.range?.last?.offset ?? 0n, w)),
        h("td", { class: "mono", title: `${size(b)} bytes` }, formatSize(size(b))),
        h("td", { class: "mono" }, perms(b)),
        h("td", {}, b.initialized ? "yes" : "no"),
        h("td", {}, b.isVolatile ? "yes" : ""),
        h("td", { class: "mem-src", title: b.rejected || sourceText(b) }, b.rejected ? h("span", { class: "error" }, b.rejected) : sourceText(b)),
        h("td", { class: `o-${oc}` }, by),
        h("td", { class: "mem-acts" }, ...actions),
      );
    });
    if (!rows.length) rows.push(h("tr", {}, h("td", { class: "dim", colspan: 10 }, this.loaded ? "No memory" : "Loading…")));
    this.body.replaceChildren(...rows);
  }

  private go() {
    const b = this.all()[this.active];
    if (b && !b.rejected && b.range?.first) this.o.navigate(b.range.first.offset);
  }

  private onKey(e: KeyboardEvent) {
    const n = this.all().length;
    const move = (to: number) => {
      this.active = Math.max(0, Math.min(n - 1, to));
      this.paint();
      this.body.querySelector<HTMLElement>("tr.active")?.scrollIntoView({ block: "nearest" });
    };
    const b = this.all()[this.active];
    switch (e.key) {
      case "ArrowDown":
        move(this.active + 1);
        break;
      case "ArrowUp":
        move(this.active - 1);
        break;
      case "Home":
        move(0);
        break;
      case "End":
        move(n - 1);
        break;
      case "Enter":
        if (this.active < 0) move(0);
        this.go();
        break;
      case "e":
      case "F2":
        if (b && this.o.editable) void this.edit(b);
        break;
      case "Delete":
        if (b && this.o.editable && (b.regionId || b.edited)) void this.remove(b);
        break;
      case "a":
      case "Insert":
        if (this.o.editable) void this.add();
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
  }

  /** After an edit: on the undo stack, a toast, then the views follow. */
  private async committed(label: string, seq: bigint | undefined, revision: bigint | undefined) {
    if (seq) this.o.recordUndo(label, [seq]);
    toast(label, { action: { label: "Undo", run: () => this.o.undo() } });
    if (revision) await this.o.settle(revision);
    await this.load();
  }

  private uploader() {
    return async () => (await pickFile({ pause: this.o.pause })).file;
  }

  /** Opens the form to add a region; `kind` preselects one. */
  async add(kind?: RegionDraft["kind"]) {
    if (!this.o.editable) return;
    await regionForm({
      title: "Add a memory region",
      action: "Add",
      initial: kind ? { kind } : undefined,
      browseHost: this.o.hostFiles ? () => chooseHostFile(this.o.rk) : undefined,
      pickUpload: this.uploader(),
      submit: async (d) => {
        try {
          const r = await this.o.rk.projects.addMemoryRegion({
            programId: this.o.programId,
            provenance: userProvenance(),
            region: { name: d.name, start: d.start, size: d.size, read: d.read, write: d.write, execute: d.execute, initialized: d.initialized, isVolatile: d.isVolatile },
            bytes: d.kind === "file" && d.file ? (d.file.source === "upload" ? { case: "content", value: d.file.bytes } : { case: "path", value: d.file.path }) : { case: undefined },
            fileName: d.kind === "file" && d.file ? d.file.name : "",
            fileOffset: d.kind === "file" ? d.fileOffset : 0n,
            length: d.kind === "file" ? d.length : 0n,
          });
          void this.committed(`Added ${d.name} at ${hex(d.start)}`, r.assertion?.seq, r.snapshot?.revision);
          return null;
        } catch (e) {
          return errText(e);
        }
      },
    });
  }

  async edit(b: MemoryBlock) {
    if (!this.o.editable) return;
    const user = !!b.regionId;
    const file = b.source?.kind === MemoryBlockSourceKind.FILE;
    await regionForm({
      title: user ? `Change region ${b.name}` : `Change block ${b.name}`,
      action: "Save",
      mode: user ? "edit" : "image",
      initial: {
        kind: kindOf({ initialized: b.initialized, isVolatile: b.isVolatile, file }),
        name: b.name,
        start: b.range?.first?.offset ?? 0n,
        size: size(b),
        read: b.read,
        write: b.write,
        execute: b.execute,
        isVolatile: b.isVolatile,
        initialized: b.initialized,
        file: file ? { source: "host", name: b.source!.file, path: b.source!.file } : undefined,
      },
      submit: async (d) => {
        try {
          const r = await this.o.rk.projects.updateMemoryRegion({
            programId: this.o.programId,
            provenance: userProvenance(),
            regionId: user ? b.regionId : "",
            blockStart: user ? undefined : { offset: b.range?.first?.offset ?? 0n },
            region: { name: d.name, start: d.start, size: d.size, read: d.read, write: d.write, execute: d.execute, initialized: d.initialized, isVolatile: d.isVolatile },
          });
          void this.committed(`Changed ${d.name}`, r.assertion?.seq, r.snapshot?.revision);
          return null;
        } catch (e) {
          return errText(e);
        }
      },
    });
  }

  /**
   * Set image base… (docs/memory-map.md, "Rebase"): the whole program moves
   * by the difference, its blocks, functions, symbols and every fact
   * recorded about it, as one edit (Ctrl+Z moves it back).
   */
  async setImageBase() {
    if (!this.o.rebase) return;
    let summary;
    try {
      summary = (await this.o.rk.projects.getProgramSummary({ programId: this.o.programId })).summary;
    } catch (e) {
      toast(errText(e), { kind: "error" });
      return;
    }
    const now = summary?.imageBase?.offset ?? 0n;
    const imported = summary?.importImageBase?.offset ?? now;
    const parse = (v: string): bigint | null => {
      const t = v.trim().toLowerCase().replace(/^0x/, "").replace(/h$/, "");
      return /^[0-9a-f]{1,16}$/.test(t) ? BigInt("0x" + t) : null;
    };
    const v = await ask({
      title: "Set image base",
      value: hex(now),
      placeholder: "0x08000000",
      hint:
        `The whole program moves to the new base: its blocks, functions, symbols and everything recorded about it (names, comments, types, listing edits, patches, notes, memory regions). ` +
        `Now at ${hex(now)}` + (imported !== now ? `, imported at ${hex(imported)}` : "") + ".",
      validate: (s) => (parse(s) === null ? "A hexadecimal address" : null),
      check: async (s) => {
        try {
          await this.o.rk.projects.setImageBase({ programId: this.o.programId, imageBase: parse(s)!, validateOnly: true, provenance: userProvenance() });
          return null;
        } catch (e) {
          return errText(e);
        }
      },
    });
    if (v === null) return;
    const to = parse(v)!;
    if (to === now) return;
    try {
      const r = await this.o.rk.projects.setImageBase({ programId: this.o.programId, imageBase: to, provenance: userProvenance() });
      this.o.rebased?.(now, to);
      await this.committed(`Image base ${hex(now)} → ${hex(to)}`, r.assertion?.seq, r.snapshot?.revision);
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  async remove(b: MemoryBlock) {
    if (!this.o.editable) return;
    try {
      const r = await this.o.rk.projects.removeMemoryRegion({
        programId: this.o.programId,
        provenance: userProvenance(),
        regionId: b.regionId,
        blockStart: b.regionId ? undefined : { offset: b.range?.first?.offset ?? 0n },
      });
      await this.committed(b.regionId ? `Removed ${b.name}` : `Reverted the edits to ${b.name}`, r.assertion?.seq, r.snapshot?.revision);
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }
}
