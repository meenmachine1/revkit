// A small context menu (right-click, the context-menu key, Shift+F10, or a
// row's "⋯" button): arrow keys move, Enter or a click runs, Escape closes
// and returns the focus where it was. An item may open a submenu (→, Enter,
// a click or hovering it; ← or Escape goes back), so long groups stay one
// line.

import { h, overlayRoot, placeNear } from "./dom";

export interface MenuItem {
  label: string;
  /** Shortcut shown on the right. */
  keys?: string;
  danger?: boolean;
  /** A toggle: a check mark when true (menus with toggles keep a column for it). */
  checked?: boolean;
  disabled?: boolean;
  /** A tooltip (the full title when the label is short). */
  title?: string;
  /** data-testid (default: from the label). */
  testid?: string;
  /** A rule above this item (starts a group). */
  separator?: boolean;
  /** Opens these items beside this one instead of running. */
  submenu?: MenuItem[];
  run?: () => void | Promise<void>;
}

/** The open menu and its open submenus, outermost first. */
let levels: HTMLElement[] = [];
let teardown: (() => void) | null = null;

export function closeMenu() {
  for (const l of levels) l.remove();
  levels = [];
  teardown?.();
  teardown = null;
}

/** Opens a menu at (x, y) in client coordinates. */
export function showMenu(items: MenuItem[], x: number, y: number, label = "Actions") {
  closeMenu();
  const restore = document.activeElement as HTMLElement | null;
  const done = (restoreFocus: boolean) => {
    closeMenu();
    if (restoreFocus) restore?.focus({ preventScroll: true });
  };
  const outside = (e: MouseEvent) => {
    if (!levels.some((l) => l.contains(e.target as Node))) done(false);
  };
  document.addEventListener("mousedown", outside, true);
  teardown = () => document.removeEventListener("mousedown", outside, true);

  /** Closes the submenus deeper than `depth` (0: the root menu stays). */
  const closeFrom = (depth: number) => {
    for (const l of levels.splice(depth + 1)) l.remove();
    levels[depth]?.querySelectorAll("[aria-expanded=true]").forEach((b) => b.setAttribute("aria-expanded", "false"));
  };

  const build = (list: MenuItem[], depth: number, ariaLabel: string): HTMLElement => {
    let hoverTimer = 0;
    const checks = list.some((it) => it.checked !== undefined);
    const buttons = list.map((it) =>
      h(
        "button",
        {
          class: "menu-item" + (it.danger ? " danger" : "") + (it.separator ? " sep" : "") + (it.submenu ? " has-sub" : ""),
          role: it.checked !== undefined ? "menuitemcheckbox" : "menuitem",
          "aria-checked": it.checked !== undefined ? String(it.checked) : undefined,
          type: "button",
          disabled: it.disabled || (it.submenu !== undefined && it.submenu.length === 0),
          tabindex: "-1",
          title: it.title,
          "aria-haspopup": it.submenu ? "menu" : undefined,
          "aria-expanded": it.submenu ? "false" : undefined,
          "data-testid": it.testid ?? `menu-${it.label.replace(/[^a-z]+/gi, "-").replace(/-$/, "").toLowerCase()}`,
        },
        checks ? h("span", { class: "menu-check", "aria-hidden": "true" }, it.checked ? "✓" : "") : null,
        h("span", { class: "menu-label" }, it.label),
        it.keys ? h("kbd", {}, it.keys) : null,
        it.submenu ? h("span", { class: "menu-arrow", "aria-hidden": "true" }, "▸") : null,
      ),
    );
    // tabindex: a menu whose items are all disabled still takes the focus, so Escape closes it.
    const menu = h("div", { class: "menu" + (depth ? " submenu" : ""), role: "menu", tabindex: "-1", "aria-label": ariaLabel, "data-testid": depth ? "submenu" : "menu" }, ...buttons);
    const enabled = () => buttons.filter((b) => !b.disabled);
    const openSub = (i: number, focus: boolean) => {
      const it = list[i];
      if (!it.submenu?.length || !levels.includes(menu)) return;
      if (buttons[i].getAttribute("aria-expanded") === "true" && levels[depth + 1]) {
        if (focus) levels[depth + 1].querySelector<HTMLButtonElement>(".menu-item:not(:disabled)")?.focus();
        return;
      }
      closeFrom(depth);
      const sub = build(it.submenu, depth + 1, it.label);
      overlayRoot().append(sub);
      levels.push(sub);
      placeBeside(sub, buttons[i]);
      buttons[i].setAttribute("aria-expanded", "true");
      if (focus) (sub.querySelector<HTMLButtonElement>(".menu-item:not(:disabled)") ?? sub).focus();
    };
    buttons.forEach((b, i) => {
      b.addEventListener("click", () => {
        const it = list[i];
        if (it.submenu) return openSub(i, true);
        done(true);
        void it.run?.();
      });
      b.addEventListener("mouseenter", () => {
        clearTimeout(hoverTimer);
        if (b.disabled) return;
        b.focus({ preventScroll: true });
        hoverTimer = window.setTimeout(() => {
          if (!levels.includes(menu)) return; // closed meanwhile
          if (list[i].submenu) openSub(i, false);
          else closeFrom(depth);
        }, 120);
      });
    });
    menu.addEventListener("keydown", (e) => {
      e.stopPropagation();
      const all = enabled();
      if (!all.length && e.key !== "Escape" && e.key !== "Tab" && e.key !== "ArrowLeft") return;
      const at = all.indexOf(document.activeElement as HTMLButtonElement);
      const cur = at >= 0 ? buttons.indexOf(all[at]) : -1;
      if (e.key === "Escape" || (e.key === "ArrowLeft" && depth > 0)) {
        if (depth === 0) done(true);
        else {
          const opener = levels[depth - 1]?.querySelector<HTMLButtonElement>("[aria-expanded=true]");
          closeFrom(depth - 1);
          opener?.focus();
        }
      } else if (e.key === "Tab") done(true);
      else if (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Home" || e.key === "End") {
        // Moving within this menu closes a submenu another item opened.
        closeFrom(depth);
        const n = all.length;
        all[e.key === "ArrowDown" ? (at + 1) % n : e.key === "ArrowUp" ? (at - 1 + n) % n : e.key === "Home" ? 0 : n - 1]?.focus();
      }
      else if (e.key === "ArrowRight" && cur >= 0 && list[cur].submenu) openSub(cur, true);
      else if (e.key === "Enter" || e.key === " ") (document.activeElement as HTMLButtonElement | null)?.click();
      else return;
      e.preventDefault();
    });
    return menu;
  };

  const root = build(items, 0, label);
  overlayRoot().append(root);
  levels = [root];
  placeNear(root, x, y);
  (root.querySelector<HTMLButtonElement>(".menu-item:not(:disabled)") ?? root).focus();
}

/** A submenu to the right of its item (to the left when there is no room). */
function placeBeside(el: HTMLElement, item: HTMLElement) {
  el.style.left = "0px";
  el.style.top = "0px";
  const r = item.getBoundingClientRect();
  const m = el.getBoundingClientRect();
  const left = r.right + m.width + 8 <= innerWidth ? r.right - 2 : Math.max(8, r.left - m.width + 2);
  const top = Math.max(8, Math.min(r.top - 4, innerHeight - m.height - 8));
  el.style.left = `${left}px`;
  el.style.top = `${top}px`;
}

/** Opens a menu below an element (keyboard: Shift+F10, the menu key, a "⋯" button). */
export function showMenuAt(el: HTMLElement, items: MenuItem[], label?: string) {
  const r = el.getBoundingClientRect();
  showMenu(items, r.left + Math.min(24, r.width / 2), r.bottom + 2, label);
}

export function menuOpen(): boolean {
  return levels.length > 0;
}
