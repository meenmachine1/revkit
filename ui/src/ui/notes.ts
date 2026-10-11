// Notes panel: the program's effective NOTE assertions (free-form
// annotations with a tag, for people and agents; not shown inline in code),
// from ListAssertions. Reloaded when a revision changes a NOTE key, so a
// note added in another tab or by an agent shows up live. Clicking a note
// goes to its address; the listing marks addresses that have notes.

import { AssertionOp, AssertionStatus, FactKind, ProvenanceKind, type Revkit } from "@revkit/api";
import { errText, provBadge, fmtAddr } from "../data/format";
import { h } from "./dom";
import { VirtualRows } from "./vlist";

export interface NoteView {
  seq: bigint;
  address: bigint;
  tag: string;
  text: string;
  who: string;
  origin: string;
}

export class NotesPanel {
  notes: NoteView[] = [];
  /** Addresses with at least one note (the listing's marker). */
  addresses = new Set<bigint>();
  private list: HTMLElement;
  private vrows: VirtualRows;
  private count: HTMLElement;
  private seq = 0;
  onOpen: ((n: NoteView) => void) | null = null;
  /** The keymap's keys for "Add or edit note…", for the empty list's hint. */
  private addKeys = "Shift+N";
  onChange: (() => void) | null = null;

  constructor(
    root: HTMLElement,
    private rk: Revkit,
    private programId: string,
    private addrWidth: number,
  ) {
    this.count = h("span", { class: "dim count", "data-testid": "notes-count" });
    this.list = h("div", { class: "notes-list", role: "listbox", "aria-label": "Notes", tabindex: "0", "data-testid": "notes" });
    root.append(h("div", { class: "panel-head" }, h("span", { class: "panel-title" }, "Notes"), this.count), this.list);
    // Agents can leave thousands of notes: only the rows in view are drawn.
    this.vrows = new VirtualRows(this.list, 22, (i) => this.row(i));
    // Until the first load returns the list holds one row saying so: a
    // listbox with no option in it is announced as an empty widget.
    this.list.setAttribute("aria-busy", "true");
    this.vrows.count = 1;
    // The keyboard: arrows choose, Enter goes there.
    this.list.addEventListener("keydown", (e) => {
      const n = this.notes.length;
      if (!n) return;
      if (e.key === "ArrowDown") this.active = Math.min(n - 1, this.active + 1);
      else if (e.key === "ArrowUp") this.active = Math.max(0, this.active - 1);
      else if (e.key === "Home") this.active = 0;
      else if (e.key === "End") this.active = n - 1;
      else if (e.key === "Enter" && this.notes[this.active]) this.onOpen?.(this.notes[this.active]);
      else return;
      e.preventDefault();
      e.stopPropagation();
      this.vrows.reveal(this.active);
    });
    this.list.addEventListener("mousedown", (e) => {
      const el = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (!el) return;
      e.preventDefault();
      const n = this.notes[Number(el.dataset.i)];
      if (n) this.onOpen?.(n);
    });
  }

  async load() {
    const seq = ++this.seq;
    const out: NoteView[] = [];
    let token = "";
    let revision = 0n;
    try {
      do {
        const r = await this.rk.assertions.listAssertions({
          programId: this.programId,
          filter: { kinds: [FactKind.NOTE] },
          page: { pageSize: 1000, pageToken: token },
          read: { revision },
        });
        if (seq !== this.seq) return;
        revision = r.snapshot?.revision ?? 0n;
        for (const a of r.assertions) {
          const b = a.body?.kind;
          if (a.op !== AssertionOp.ASSERT || a.status !== AssertionStatus.EFFECTIVE || b?.case !== "note" || !b.value.text) continue;
          out.push({
            seq: a.seq,
            address: b.value.address?.offset ?? 0n,
            tag: b.value.tag,
            text: b.value.text,
            who: provBadge(a.provenance),
            origin:
              a.provenance?.kind === ProvenanceKind.USER
                ? "user"
                : a.provenance?.kind === ProvenanceKind.AGENT || a.provenance?.kind === ProvenanceKind.PLUGIN || a.provenance?.kind === ProvenanceKind.SCRIPT
                  ? "agent"
                  : "import",
          });
        }
        token = r.page?.nextPageToken ?? "";
      } while (token);
    } catch (e) {
      if (seq !== this.seq) return;
      this.error = errText(e);
      this.settled();
      this.vrows.count = 1;
      return;
    }
    this.error = "";
    this.settled();
    out.sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : a.tag.localeCompare(b.tag)));
    this.notes = out;
    this.addresses = new Set(out.map((n) => n.address));
    this.paint();
    this.onChange?.();
  }

  at(address: bigint): NoteView[] {
    return this.notes.filter((n) => n.address === address);
  }

  private error = "";
  private active = 0;
  /** The first load has returned (with notes, none, or an error). */
  private loaded = false;

  private settled() {
    this.loaded = true;
    this.list.removeAttribute("aria-busy");
  }

  private paint() {
    this.count.textContent = this.notes.length ? String(this.notes.length) : "";
    this.vrows.count = Math.max(1, this.notes.length);
  }

  setAddKeys(keys: string) {
    this.addKeys = keys;
    this.vrows.paint();
  }

  private row(i: number): HTMLElement {
    if (!this.loaded) return h("div", { class: "notes-empty dim", role: "option", "aria-disabled": "true" }, "Loading…");
    if (this.error) return h("div", { class: "notes-empty error", role: "option", "aria-disabled": "true" }, this.error);
    const n = this.notes[i];
    if (!n) return h("div", { class: "notes-empty dim", role: "option", "aria-disabled": "true" }, this.addKeys ? `No notes. ${this.addKeys} adds one at the selection.` : "No notes. Add one at the selection from the palette (Add or edit note…).");
    return h(
      "div",
      { class: "note-row" + (i === this.active ? " active" : ""), "data-i": i, role: "option", "aria-selected": String(i === this.active), title: `${n.who} · ${n.text}` },
      h("span", { class: "note-addr mono" }, fmtAddr(n.address, this.addrWidth)),
      h("span", { class: `badge b-${n.origin}` }, n.tag || "note"),
      h("span", { class: "note-text" }, n.text),
    );
  }
}
