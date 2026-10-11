// Views in two tab groups, the main area and the side, like an IDE's
// editor and side panel: listing, graph, data and types in the main area,
// decompiler and calls at the side by default. A tab can be dragged to the
// other group (or moved from the palette); which views sit where, the active
// tab of each group and the side's width are remembered (localStorage).

import { h, prefs } from "./dom";
import { showMenuAt } from "./menu";

export type GroupName = "main" | "side";

export interface ViewSpec {
  id: string;
  title: string;
  /** Shortcut, shown in the tab's tooltip. */
  keys?: string;
  el: HTMLElement;
  /** The view became visible (its tab was chosen, or it moved). */
  onShow?: () => void;
  /**
   * A view that comes and goes (the search results): its tab has a close
   * button (× on the tab, middle-click, Delete on the focused tab), it starts
   * closed, stays closed across reloads, and show() opens it again.
   */
  closable?: boolean;
}

interface Saved {
  main: string[];
  side: string[];
  active: Partial<Record<GroupName, string>>;
  /** Closed closable views and the group each was in. */
  closed?: Record<string, GroupName>;
}

const KEY = "rk.layout";

class Group {
  readonly tabs: HTMLElement;
  readonly body: HTMLElement;
  /** Lists every view of the group when the tabs don't fit. */
  readonly more: HTMLButtonElement;
  views: string[] = [];
  active = "";
  /** The tab active before the current one (a closed view gives it back). */
  prev = "";
  constructor(
    readonly name: GroupName,
    readonly root: HTMLElement,
  ) {
    this.tabs = root.querySelector<HTMLElement>(".dock-tabs")!;
    this.body = root.querySelector<HTMLElement>(".dock-body")!;
    // The tab strip scrolls; the bar keeps the overflow button beside it.
    const bar = h("div", { class: "dock-bar" });
    this.tabs.replaceWith(bar);
    this.more = h("button", { class: "dock-more", type: "button", hidden: true, title: "All views in this group", "aria-label": `All ${name} views`, "aria-haspopup": "menu", "data-testid": `dock-more-${name}` }, "»");
    bar.append(this.tabs, this.more);
  }
}

export class Dock {
  private groups: Record<GroupName, Group>;
  private specs = new Map<string, ViewSpec>();
  /** Closed views (closable ones) and the group each reopens in. */
  private closed = new Map<string, GroupName>();
  /** Fired after any change of which views are visible. */
  onChange: (() => void) | null = null;

  constructor(main: HTMLElement, side: HTMLElement, private sideSplitter: HTMLElement | null) {
    this.groups = { main: new Group("main", main), side: new Group("side", side) };
    for (const g of Object.values(this.groups)) {
      g.tabs.addEventListener("dragover", (e) => {
        if (!e.dataTransfer?.types.includes("text/x-rk-view")) return;
        e.preventDefault();
        g.tabs.classList.add("drop");
      });
      g.tabs.addEventListener("dragleave", () => g.tabs.classList.remove("drop"));
      g.tabs.addEventListener("drop", (e) => {
        g.tabs.classList.remove("drop");
        const id = e.dataTransfer?.getData("text/x-rk-view");
        if (id) this.move(id, g.name);
      });
      // A mouse wheel scrolls the tab strip sideways.
      g.tabs.addEventListener("wheel", (e) => {
        if (e.deltaY === 0 || g.tabs.scrollWidth <= g.tabs.clientWidth) return;
        e.preventDefault();
        g.tabs.scrollLeft += e.deltaY;
      }, { passive: false });
      g.more.addEventListener("click", () =>
        showMenuAt(g.more, g.views.map((id) => {
          const v = this.specs.get(id)!;
          return { label: v.title, checked: id === g.active, keys: v.keys || undefined, testid: `dock-more-${id}`, run: () => this.show(id) };
        }), `${g.name === "main" ? "Main" : "Side"} views`),
      );
      new ResizeObserver(() => this.fitTabs(g)).observe(g.tabs);
    }
  }

  /** Shows the overflow button when the tabs don't fit, and keeps the active tab in view. */
  private fitTabs(g: Group) {
    g.more.hidden = g.tabs.scrollWidth <= g.tabs.clientWidth + 1;
    const tab = g.tabs.querySelector<HTMLElement>(".dock-tab.active");
    if (!tab) return;
    // Just enough to bring it into view (no jump when it is already there).
    const t = tab.getBoundingClientRect(), s = g.tabs.getBoundingClientRect();
    if (t.left < s.left) g.tabs.scrollLeft -= s.left - t.left + 8;
    else if (t.right > s.left + g.tabs.clientWidth) g.tabs.scrollLeft += t.right - (s.left + g.tabs.clientWidth) + 8;
  }

  /** The views' shortcuts changed (the keymap preset): the tabs' tooltips follow. */
  setKeys(keys: (id: string) => string | undefined) {
    for (const v of this.specs.values()) v.keys = keys(v.id);
    this.render();
  }

  /** Registers the views; `defaults` places those the saved layout doesn't know. */
  setup(views: ViewSpec[], defaults: Record<string, GroupName>) {
    for (const v of views) this.specs.set(v.id, v);
    let saved: Saved | null = null;
    try {
      saved = JSON.parse(prefs.get(KEY) ?? "null");
    } catch {
      saved = null;
    }
    const placed = new Set<string>();
    // Closable views start closed, and stay closed when they were.
    for (const v of views) {
      if (!v.closable) continue;
      const open = saved?.main?.includes(v.id) || saved?.side?.includes(v.id);
      if (!open || saved?.closed?.[v.id]) {
        this.closed.set(v.id, saved?.closed?.[v.id] ?? defaults[v.id] ?? "main");
        v.el.hidden = true;
        placed.add(v.id);
      }
    }
    for (const name of ["main", "side"] as GroupName[])
      for (const id of saved?.[name] ?? [])
        if (this.specs.has(id) && !placed.has(id)) {
          this.groups[name].views.push(id);
          placed.add(id);
        }
    for (const v of views)
      if (!placed.has(v.id)) this.groups[defaults[v.id] ?? "main"].views.push(v.id);
    // The listing always has a home.
    for (const name of ["main", "side"] as GroupName[]) {
      const g = this.groups[name];
      const want = saved?.active?.[name];
      g.active = want && g.views.includes(want) ? want : (g.views[0] ?? "");
    }
    this.render();
  }

  /** Every view set up, in tab order (main, then side, then closed ones), and whether its tab is the shown one. */
  viewList(): { id: string; title: string; visible: boolean }[] {
    const seen = new Set<string>();
    const out: { id: string; title: string; visible: boolean }[] = [];
    for (const g of Object.values(this.groups))
      for (const id of g.views) {
        seen.add(id);
        out.push({ id, title: this.specs.get(id)!.title, visible: g.active === id });
      }
    for (const [id, v] of this.specs) if (!seen.has(id)) out.push({ id, title: v.title, visible: false });
    return out;
  }

  groupOf(id: string): GroupName | null {
    for (const g of Object.values(this.groups)) if (g.views.includes(id)) return g.name;
    return null;
  }

  isVisible(id: string): boolean {
    const g = this.groupOf(id);
    return g !== null && this.groups[g].active === id;
  }

  isOpen(id: string): boolean {
    return this.groupOf(id) !== null;
  }

  /** Shows a view (its group's active tab), opening it again when it was closed. */
  show(id: string) {
    const back = this.closed.get(id);
    if (back) {
      this.closed.delete(id);
      const g = this.groups[back];
      g.views.push(id);
      g.prev = g.active;
      g.active = id;
      this.render();
      this.specs.get(id)?.onShow?.();
      return;
    }
    const g = this.groupOf(id);
    if (!g || this.groups[g].active === id) return;
    this.groups[g].prev = this.groups[g].active;
    this.groups[g].active = id;
    this.render();
    this.specs.get(id)?.onShow?.();
  }

  /** Moves a view to the other group (or the named one) and shows it. */
  move(id: string, to?: GroupName) {
    if (this.closed.has(id)) {
      if (to) this.closed.set(id, to);
      return this.show(id);
    }
    const from = this.groupOf(id);
    if (!from) return;
    const target = to ?? (from === "main" ? "side" : "main");
    if (target === from) return this.show(id);
    const src = this.groups[from];
    src.views = src.views.filter((v) => v !== id);
    if (src.active === id) src.active = src.views[0] ?? "";
    this.groups[target].views.push(id);
    this.groups[target].active = id;
    this.render();
    this.specs.get(id)?.onShow?.();
    if (src.active) this.specs.get(src.active)?.onShow?.();
  }

  /**
   * Closes a closable view: its tab goes, the group shows the tab beside it,
   * and the element is hidden until show() opens it again.
   */
  close(id: string) {
    const spec = this.specs.get(id);
    const from = this.groupOf(id);
    if (!spec?.closable || !from) return;
    const g = this.groups[from];
    const i = g.views.indexOf(id);
    g.views.splice(i, 1);
    this.closed.set(id, from);
    spec.el.hidden = true;
    const wasActive = g.active === id;
    if (wasActive) g.active = g.views.includes(g.prev) ? g.prev : (g.views[Math.min(i, g.views.length - 1)] ?? "");
    this.render();
    if (wasActive && g.active) this.specs.get(g.active)?.onShow?.();
  }

  /** Back to the default placement (closable views closed). */
  reset(defaults: Record<string, GroupName>) {
    for (const g of Object.values(this.groups)) {
      g.views = [];
      g.active = "";
    }
    this.closed.clear();
    for (const [id, spec] of this.specs) {
      if (spec.closable) {
        this.closed.set(id, defaults[id] ?? "main");
        spec.el.hidden = true;
      } else this.groups[defaults[id] ?? "main"].views.push(id);
    }
    for (const g of Object.values(this.groups)) g.active = g.views[0] ?? "";
    this.render();
    for (const g of Object.values(this.groups)) if (g.active) this.specs.get(g.active)?.onShow?.();
  }

  private save() {
    const s: Saved = { main: this.groups.main.views, side: this.groups.side.views, active: { main: this.groups.main.active, side: this.groups.side.active }, closed: Object.fromEntries(this.closed) };
    prefs.set(KEY, JSON.stringify(s));
  }

  private render() {
    for (const g of Object.values(this.groups)) {
      for (const id of g.views) {
        const el = this.specs.get(id)!.el;
        if (el.parentElement !== g.body) g.body.append(el);
        el.hidden = id !== g.active;
      }
      g.tabs.replaceChildren(
        ...g.views.map((id) => {
          const v = this.specs.get(id)!;
          const tab = h(
            "button",
            {
              class: "dock-tab" + (id === g.active ? " active" : ""),
              role: "tab",
              draggable: "true",
              "aria-selected": id === g.active ? "true" : "false",
              // Roving tab stop (ARIA tabs): Tab reaches the active tab, arrows the others.
              tabindex: id === g.active ? "0" : "-1",
              "aria-controls": v.el.id || undefined,
              title: `${v.title}${v.keys ? ` (${v.keys})` : ""} · drag to the other side to move${v.closable ? " · × or Delete closes" : ""}`,
              "data-testid": `tab-${id}`,
            },
            v.title,
            v.closable ? h("span", { class: "dock-tab-x", "aria-hidden": "true", "data-testid": `tab-close-${id}` }, "×") : null,
          );
          tab.addEventListener("click", (e) => ((e.target as HTMLElement).classList.contains("dock-tab-x") ? this.close(id) : this.show(id)));
          if (v.closable) {
            tab.addEventListener("auxclick", (e) => {
              if (e.button === 1) this.close(id);
            });
            tab.addEventListener("keydown", (e) => {
              if (e.key !== "Delete") return;
              e.preventDefault();
              e.stopPropagation();
              this.close(id);
              g.tabs.querySelector<HTMLElement>(".dock-tab.active")?.focus();
            });
          }
          tab.addEventListener("keydown", (e) => {
            const i = g.views.indexOf(id);
            const to = e.key === "ArrowRight" ? g.views[(i + 1) % g.views.length] : e.key === "ArrowLeft" ? g.views[(i - 1 + g.views.length) % g.views.length] : e.key === "Home" ? g.views[0] : e.key === "End" ? g.views[g.views.length - 1] : null;
            if (!to) return;
            e.preventDefault();
            e.stopPropagation();
            this.show(to);
            g.tabs.querySelector<HTMLElement>(`[data-testid=tab-${to}]`)?.focus();
          });
          tab.addEventListener("dragstart", (e) => {
            e.dataTransfer?.setData("text/x-rk-view", id);
            if (e.dataTransfer) e.dataTransfer.effectAllowed = "move";
          });
          return tab;
        }),
      );
      g.root.hidden = g.views.length === 0;
      this.fitTabs(g);
    }
    if (this.sideSplitter) this.sideSplitter.hidden = this.groups.side.views.length === 0;
    this.save();
    this.onChange?.();
  }
}
