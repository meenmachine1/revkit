// Resizable modal dialogs (docs/ui.md, "Resizable dialogs"), for every
// dialog at once: a modal is a .modal inside a .backdrop in #overlays, and
// this watches #overlays for them instead of each dialog adding its own.
//
// Each dialog gets a grip at its bottom-right corner and draggable right,
// left and bottom edges. Width is the dialog's own (it stays centered, so
// an edge moves twice as far as the box grows on one side); height goes to
// the part of the dialog that scrolls (its list, table, tree or log: the
// element marked data-grow, else the largest scrolling element), so the
// list grows and the buttons stay below it. Bounded: at least 280 px wide
// and 60 px of list, at most the window. The size is kept per dialog
// (its data-testid, else its aria-label) for this viewer in localStorage
// (rk.dialog:<name>); a double click on the grip forgets it.

import { h, prefs } from "./dom";

const MIN_W = 280;
const MIN_LIST_H = 60;
const MARGIN = 8;

interface Saved {
  w?: number;
  /** The grown element's height (or the dialog's, when nothing in it scrolls). */
  h?: number;
}

function keyOf(box: HTMLElement): string | null {
  const id = box.dataset.testid || box.getAttribute("aria-label") || [...box.classList].find((c) => c !== "modal");
  return id ? `rk.dialog:${id}` : null;
}

function load(key: string): Saved | null {
  try {
    const s = JSON.parse(prefs.get(key) ?? "null") as Saved | null;
    return s && typeof s === "object" ? s : null;
  } catch {
    return null;
  }
}

/** What grows when the dialog gets taller: its scrolling list, table or log. */
function growTarget(box: HTMLElement): HTMLElement | null {
  const marked = box.querySelector<HTMLElement>("[data-grow]");
  if (marked) return marked;
  let best: HTMLElement | null = null;
  let bestScore = -1;
  for (const el of box.querySelectorAll<HTMLElement>("*")) {
    if (el.closest(".rk-resize")) continue;
    const cs = getComputedStyle(el);
    const scrolls = cs.overflowY === "auto" || cs.overflowY === "scroll" || el.tagName === "TEXTAREA";
    if (!scrolls || cs.display === "none" || el.closest("[hidden]")) continue;
    // A list's own scroller beats a wrapper; the bigger one wins among equals.
    const score = el.scrollHeight * Math.max(1, el.clientWidth) + (/(list|table|tree|rows|scroll|log|body|results)/i.test(el.className) ? 1e9 : 0);
    if (score > bestScore) {
      best = el;
      bestScore = score;
    }
  }
  return best;
}

/** The dialog's tallest allowed height, in px (its CSS max-height, or the window's). */
function maxBoxHeight(box: HTMLElement): number {
  const m = parseFloat(getComputedStyle(box).maxHeight);
  return Number.isFinite(m) && m > 0 ? m : innerHeight - 2 * MARGIN;
}

class Sizer {
  private grips: HTMLElement[] = [];
  private ro: ResizeObserver;
  private key: string;

  constructor(
    private box: HTMLElement,
    private backdrop: HTMLElement,
    key: string,
  ) {
    this.key = key;
    box.dataset.resizable = "1";
    const grip = (edge: "e" | "w" | "s" | "se", title?: string) => {
      const el = h("div", { class: `rk-resize rk-resize-${edge}`, "aria-hidden": "true", "data-testid": `dialog-resize-${edge}`, title });
      el.addEventListener("pointerdown", (e) => this.drag(e, edge));
      return el;
    };
    this.grips = [grip("e"), grip("w"), grip("s"), grip("se", "Drag to resize · double-click for the usual size")];
    this.grips[3].addEventListener("dblclick", () => this.reset());
    backdrop.append(...this.grips);
    this.restore();
    this.ro = new ResizeObserver(() => this.place());
    this.ro.observe(box);
    addEventListener("resize", this.onWindow);
    this.place();
  }

  private onWindow = () => {
    if (!this.box.isConnected) return this.dispose();
    this.clampToWindow();
    this.place();
  };

  dispose() {
    this.ro.disconnect();
    removeEventListener("resize", this.onWindow);
  }

  /** The grips follow the dialog (they sit in the backdrop, outside its scrolling). */
  private place() {
    if (!this.box.isConnected) return this.dispose();
    const r = this.box.getBoundingClientRect();
    const b = this.backdrop.getBoundingClientRect();
    const x = r.left - b.left, y = r.top - b.top;
    const set = (el: HTMLElement, left: number, top: number, w: number, hgt: number) => Object.assign(el.style, { left: `${left}px`, top: `${top}px`, width: `${w}px`, height: `${hgt}px` });
    const [e, w, s, se] = this.grips;
    set(e, x + r.width - 4, y + 8, 8, Math.max(0, r.height - 20));
    set(w, x - 4, y + 8, 8, Math.max(0, r.height - 20));
    set(s, x + 8, y + r.height - 4, Math.max(0, r.width - 20), 8);
    set(se, x + r.width - 14, y + r.height - 14, 16, 16);
  }

  private apply(s: Saved, t: HTMLElement | null = growTarget(this.box)) {
    const box = this.box;
    if (s.w !== undefined) {
      box.style.width = `${Math.round(s.w)}px`;
      box.style.maxWidth = `calc(100vw - ${2 * MARGIN}px)`;
    }
    if (s.h !== undefined) {
      if (t) {
        t.style.height = `${Math.round(s.h)}px`;
        t.style.maxHeight = "none";
        t.style.flex = "0 0 auto";
      } else {
        box.style.height = `${Math.round(s.h)}px`;
      }
    }
    box.classList.add("rk-sized");
  }

  private restore() {
    const s = load(this.key);
    if (!s) return;
    this.apply(s);
    this.clampToWindow();
  }

  /** A size kept from a larger window still fits this one. */
  private clampToWindow() {
    const box = this.box;
    if (!box.classList.contains("rk-sized")) return;
    const maxW = innerWidth - 2 * MARGIN;
    if (box.offsetWidth > maxW) box.style.width = `${maxW}px`;
    const t = growTarget(box);
    const over = box.scrollHeight - maxBoxHeight(box);
    if (t && t.style.height && over > 0) t.style.height = `${Math.max(MIN_LIST_H, t.offsetHeight - over)}px`;
  }

  private reset() {
    const box = this.box;
    box.style.width = box.style.maxWidth = box.style.height = "";
    const t = growTarget(box);
    if (t) t.style.height = t.style.maxHeight = t.style.flex = "";
    box.classList.remove("rk-sized");
    try {
      localStorage.removeItem(this.key);
    } catch {
      /* nothing kept */
    }
  }

  private drag(e: PointerEvent, edge: "e" | "w" | "s" | "se") {
    if (e.button !== 0) return;
    e.preventDefault();
    e.stopPropagation();
    const box = this.box;
    const grip = e.currentTarget as HTMLElement;
    grip.setPointerCapture(e.pointerId);
    const t = growTarget(box);
    const w0 = box.offsetWidth;
    const th0 = t ? t.offsetHeight : box.offsetHeight;
    const bh0 = box.offsetHeight;
    const x0 = e.clientX, y0 = e.clientY;
    const maxW = innerWidth - 2 * MARGIN;
    const maxH = t ? th0 + (maxBoxHeight(box) - bh0) : maxBoxHeight(box);
    const minH = t ? MIN_LIST_H : Math.min(bh0, 120);
    const saved: Saved = load(this.key) ?? {};
    document.body.classList.add("rk-resizing");
    const move = (ev: PointerEvent) => {
      const dx = ev.clientX - x0, dy = ev.clientY - y0;
      const s: Saved = {};
      // Centered: the edge under the pointer moves dx when the box grows 2·dx.
      if (edge === "e" || edge === "se") s.w = Math.min(maxW, Math.max(Math.min(MIN_W, w0), w0 + 2 * dx));
      if (edge === "w") s.w = Math.min(maxW, Math.max(Math.min(MIN_W, w0), w0 - 2 * dx));
      if (edge === "s" || edge === "se") s.h = Math.min(Math.max(maxH, th0), Math.max(minH, th0 + dy));
      this.apply(s, t);
      if (s.w !== undefined) saved.w = s.w;
      if (s.h !== undefined) saved.h = s.h;
    };
    const up = () => {
      grip.removeEventListener("pointermove", move);
      grip.removeEventListener("pointerup", up);
      grip.removeEventListener("pointercancel", up);
      document.body.classList.remove("rk-resizing");
      prefs.set(this.key, JSON.stringify(saved));
    };
    grip.addEventListener("pointermove", move);
    grip.addEventListener("pointerup", up);
    grip.addEventListener("pointercancel", up);
  }
}

function upgrade(backdrop: HTMLElement) {
  if (backdrop.classList.contains("login-backdrop")) return; // the sign-in page, not a dialog
  const box = backdrop.querySelector<HTMLElement>(":scope > .modal");
  if (!box || box.dataset.resizable || box.dataset.resizable === "0") return;
  const key = keyOf(box);
  if (key) new Sizer(box, backdrop, key);
}

/** Watches for modal dialogs and makes each resizable (main.ts, once). */
export function installDialogResize() {
  const root = document.getElementById("overlays");
  const watch = (el: HTMLElement) =>
    new MutationObserver((records) => {
      for (const r of records)
        for (const n of r.addedNodes) if (n instanceof HTMLElement && n.classList.contains("backdrop")) upgrade(n);
    }).observe(el, { childList: true });
  if (root) watch(root);
  watch(document.body);
}
