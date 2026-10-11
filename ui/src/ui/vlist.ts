// A virtualized list: only the rows in view (and a few around them) are in
// the DOM, absolutely placed over a spacer as tall as every row, so a list
// of 100,000 references or notes scrolls as fast as one of ten. The
// scroller is any element with overflow-y: auto; rows have a fixed height.

import { h } from "./dom";

export class VirtualRows {
  private spacer: HTMLElement;
  private rows: HTMLElement;
  private n = 0;
  private raf = 0;
  /** The range of rows last drawn ([first, last)). */
  drawn: [number, number] = [0, 0];

  constructor(
    readonly scroller: HTMLElement,
    readonly rowH: number,
    private render: (i: number) => HTMLElement,
    /** Called with the rows about to be drawn (to fetch what they need). */
    private want?: (first: number, last: number) => void,
  ) {
    this.spacer = h("div", { class: "vl-spacer", "aria-hidden": "true" });
    this.rows = h("div", { class: "vl-rows" });
    this.scroller.classList.add("vl");
    this.scroller.replaceChildren(this.spacer, this.rows);
    this.scroller.addEventListener("scroll", () => this.schedule());
    new ResizeObserver(() => this.schedule()).observe(this.scroller);
  }

  get count() {
    return this.n;
  }

  set count(n: number) {
    this.n = n;
    this.spacer.style.height = `${n * this.rowH}px`;
    this.paint();
  }

  private schedule() {
    if (!this.raf) this.raf = requestAnimationFrame(() => this.paint());
  }

  /** Draws the rows in view now. */
  paint() {
    cancelAnimationFrame(this.raf);
    this.raf = 0;
    if (!this.scroller.isConnected) return;
    const top = this.scroller.scrollTop;
    const height = this.scroller.clientHeight || 600;
    const first = Math.max(0, Math.floor(top / this.rowH) - 6);
    const last = Math.min(this.n, Math.ceil((top + height) / this.rowH) + 6);
    this.want?.(first, last);
    const frag = document.createDocumentFragment();
    for (let i = first; i < last; i++) {
      const el = this.render(i);
      el.style.position = "absolute";
      el.style.left = "0";
      el.style.right = "0";
      el.style.top = `${i * this.rowH}px`;
      el.style.height = `${this.rowH}px`;
      el.style.boxSizing = "border-box";
      frag.append(el);
    }
    this.rows.replaceChildren(frag);
    this.drawn = [first, last];
  }

  /** Scrolls the least needed to show row i. */
  reveal(i: number) {
    const y = i * this.rowH;
    if (y < this.scroller.scrollTop) this.scroller.scrollTop = y;
    else if (y + this.rowH > this.scroller.scrollTop + this.scroller.clientHeight) this.scroller.scrollTop = y + this.rowH - this.scroller.clientHeight;
    this.paint();
  }

  /** Rows in the DOM now (tests). */
  get rendered() {
    return this.rows.childElementCount;
  }
}
