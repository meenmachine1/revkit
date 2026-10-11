// Command palette. Ctrl+K (or g) goes to an address or symbol; a leading
// ">" (Ctrl+Shift+P, F1) lists commands with their shortcuts.

import { h, overlayRoot } from "./dom";

export interface Command {
  id: string;
  title: string;
  /** A description after the title (dimmed; the filter matches it too). */
  detail?: string;
  /** Shortcut, for display. */
  keys?: string;
  enabled?: () => boolean;
  run: () => void | Promise<void>;
}

export interface Item {
  label: string;
  detail?: string;
  badge?: string;
  keys?: string;
  /** A command (">"): its label is set in the UI font, not as a symbol. */
  command?: boolean;
  run: () => void | Promise<void>;
}

/** Supplies items for a query (not starting with ">"). */
export type Provider = (query: string, signal: AbortSignal) => Promise<Item[]> | Item[];

export class Palette {
  private backdrop: HTMLElement | null = null;
  private input!: HTMLInputElement;
  private list!: HTMLElement;
  private items: Item[] = [];
  private active = 0;
  private seq = 0;
  private abort: AbortController | null = null;
  private restore: HTMLElement | null = null;

  constructor(
    private commands: () => Command[],
    private provider: Provider,
  ) {}

  get isOpen() {
    return this.backdrop !== null;
  }

  open(initial = "") {
    if (this.backdrop) {
      this.input.value = initial;
      this.refresh();
      this.input.focus();
      return;
    }
    this.restore = document.activeElement as HTMLElement | null;
    this.input = h("input", {
      class: "palette-input",
      placeholder: "Go to address or symbol · > for commands",
      spellcheck: "false",
      autocomplete: "off",
      "aria-label": "Command palette",
      role: "combobox",
      "aria-expanded": "true",
      "aria-controls": "palette-results",
      "aria-autocomplete": "list",
      "data-testid": "palette-input",
    });
    this.list = h("div", { class: "palette-list", id: "palette-results", role: "listbox", "aria-label": "Results", tabindex: "-1" });
    const box = h("div", { class: "modal palette", role: "dialog", "aria-modal": "true", "aria-label": "Command palette", "data-testid": "palette" }, this.input, this.list);
    this.backdrop = h("div", { class: "backdrop top" }, box);
    this.backdrop.addEventListener("mousedown", (e) => {
      if (e.target === this.backdrop) this.close();
    });
    this.input.addEventListener("input", () => this.refresh());
    this.input.addEventListener("keydown", (e) => this.onKey(e));
    this.list.addEventListener("mousedown", (e) => {
      const el = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (!el) return;
      e.preventDefault();
      this.active = Number(el.dataset.i);
      this.accept();
    });
    overlayRoot().append(this.backdrop);
    this.input.value = initial;
    this.input.focus();
    this.refresh();
  }

  close(restoreFocus = true) {
    this.abort?.abort();
    this.backdrop?.remove();
    this.backdrop = null;
    if (restoreFocus) this.restore?.focus({ preventScroll: true });
  }

  private onKey(e: KeyboardEvent) {
    e.stopPropagation();
    const n = this.items.length;
    switch (e.key) {
      case "Escape":
        this.close();
        break;
      case "ArrowDown":
        if (n) this.active = (this.active + 1) % n;
        this.paint();
        break;
      case "ArrowUp":
        if (n) this.active = (this.active - 1 + n) % n;
        this.paint();
        break;
      case "Enter":
        this.accept();
        break;
      default:
        return;
    }
    e.preventDefault();
  }

  private accept() {
    const it = this.items[this.active];
    if (!it) return;
    this.close(false);
    // Commands that open a dialog, a menu or a popover take the focus; others
    // return it to the view (closing the palette left it on the page).
    const lost = () => {
      const a = document.activeElement;
      return !a || a === document.body || !a.isConnected;
    };
    void Promise.resolve(it.run()).finally(() => {
      if (lost() && !document.querySelector(".backdrop, .search-dialog")) this.restore?.focus({ preventScroll: true });
    });
  }

  private async refresh() {
    const seq = ++this.seq;
    const q = this.input.value;
    this.abort?.abort();
    this.abort = new AbortController();
    let items: Item[];
    if (q.startsWith(">")) {
      const words = q.slice(1).trim().toLowerCase().split(/\s+/).filter(Boolean);
      items = this.commands()
        .filter((c) => c.enabled?.() ?? true)
        .filter((c) => {
          const t = c.title.toLowerCase();
          const d = c.detail?.toLowerCase() ?? "";
          return words.every((w) => t.includes(w) || d.includes(w));
        })
        // Title matches first, then those only the description matches.
        .sort((a, b) => Number(!words.every((w) => a.title.toLowerCase().includes(w))) - Number(!words.every((w) => b.title.toLowerCase().includes(w))))
        .map((c) => ({ label: c.title, detail: c.detail, keys: c.keys, run: c.run, command: true }));
    } else {
      try {
        items = await this.provider(q.trim(), this.abort.signal);
      } catch (e) {
        if (this.abort.signal.aborted) return;
        items = [{ label: "Search failed", detail: String(e), run: () => {} }];
      }
    }
    if (seq !== this.seq || !this.backdrop) return;
    this.items = items;
    this.active = 0;
    this.paint();
  }

  private paint() {
    const frag = document.createDocumentFragment();
    if (!this.items.length) frag.append(h("div", { class: "palette-empty dim", role: "option", "aria-disabled": "true" }, this.input.value ? "No matches" : "Type an address, a symbol, or > for commands"));
    this.items.forEach((it, i) => {
      frag.append(
        h(
          "div",
          { class: "palette-item" + (it.command ? " cmd" : "") + (i === this.active ? " active" : ""), "data-i": i, role: "option", id: `palette-item-${i}`, "aria-selected": String(i === this.active) },
          it.badge ? h("span", { class: `badge b-${it.badge}` }, it.badge) : null,
          h("span", { class: "pi-label" }, it.label),
          it.detail ? h("span", { class: "pi-detail dim" }, it.detail) : null,
          it.keys ? h("kbd", {}, it.keys) : null,
        ),
      );
    });
    this.list.replaceChildren(frag);
    this.list.querySelector(".active")?.scrollIntoView({ block: "nearest" });
    if (this.items.length) this.input.setAttribute("aria-activedescendant", `palette-item-${this.active}`);
    else this.input.removeAttribute("aria-activedescendant");
  }
}
