// Tiny DOM helpers: the UI is plain TypeScript, no framework.

type Attrs = Record<string, string | number | boolean | ((e: Event) => void) | undefined | null>;
type Child = Node | string | null | undefined | false;

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: (Child | Child[])[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v as EventListener);
    else if (k === "class") el.className = String(v);
    else if (k === "text") el.textContent = String(v);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, String(v));
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) el.append(c);
  return el;
}

export function $(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id} missing`);
  return el;
}

/** Is the keyboard focus in a text field (where letters are input, not commands)? */
export function typing(): boolean {
  const a = document.activeElement as HTMLElement | null;
  if (!a) return false;
  return a.tagName === "INPUT" || a.tagName === "TEXTAREA" || a.isContentEditable;
}

export function overlayRoot(): HTMLElement {
  return $("overlays");
}

/** Positions a floating element near a point, inside the viewport. */
export function placeNear(el: HTMLElement, x: number, y: number) {
  el.style.left = "0px";
  el.style.top = "0px";
  const r = el.getBoundingClientRect();
  const left = Math.min(Math.max(8, x), innerWidth - r.width - 8);
  const top = y + r.height + 8 > innerHeight ? Math.max(8, y - r.height - 24) : y;
  el.style.left = `${left}px`;
  el.style.top = `${top}px`;
}

/** localStorage that never throws (private windows, blocked storage). */
export const prefs = {
  get(key: string): string | null {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  },
  set(key: string, value: string) {
    try {
      localStorage.setItem(key, value);
    } catch {
      /* the preference lasts for this page only */
    }
  },
};
