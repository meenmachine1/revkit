// Class hierarchy (feature msvc-rtti; docs/pe.md): the C++ classes MSVC
// run-time type information names, from GetClassHierarchy. A filtered list
// of classes, as a tree of derived classes under their bases (a class with
// several bases shows under each); the selected class's bases, derived
// classes, vftables and their functions below it. A function, a vftable
// or a type descriptor goes to its address; the class struct opens in the
// Types view.

import type { GetClassHierarchyResponse, Revkit, RttiClass } from "@revkit/api";
import { errText, fmtAddr, hex } from "../data/format";
import { h } from "./dom";

export interface ClassesHost {
  rk: Revkit;
  programId: string;
  addrWidth: number;
  navigate: (address: bigint) => void;
  /** Shows a named type in the Types view ("struct geo::Rect"). */
  showType: (name: string) => void;
}

interface Row {
  cls: RttiClass;
  depth: number;
}

export class ClassesView {
  readonly filter: HTMLInputElement;
  private list: HTMLElement;
  private detail: HTMLElement;
  private count: HTMLElement;
  private classes: RttiClass[] = [];
  private rows: Row[] = [];
  private selected = "";
  private loaded = false;
  private seq = 0;
  private timer = 0;

  constructor(
    root: HTMLElement,
    private host: ClassesHost,
  ) {
    this.filter = h("input", { class: "filter", placeholder: "Filter classes", spellcheck: "false", "aria-label": "Filter classes", "data-testid": "classes-filter" });
    this.count = h("span", { class: "dim count", "data-testid": "classes-count" });
    this.list = h("div", { class: "classes-list", role: "tree", tabindex: "0", "aria-label": "Classes", "data-testid": "classes-list" });
    this.detail = h("div", { class: "classes-detail", "data-testid": "classes-detail" });
    root.append(h("div", { class: "panel-head view-head" }, h("span", { class: "panel-title" }, "Class hierarchy"), this.count), h("div", { class: "fn-filter" }, this.filter), this.list, this.detail);
    this.filter.addEventListener("input", () => {
      clearTimeout(this.timer);
      this.timer = window.setTimeout(() => this.paint(), 80);
    });
    this.list.addEventListener("click", (e) => {
      const el = (e.target as HTMLElement).closest<HTMLElement>("[data-cls]");
      if (el) this.select(el.dataset.cls!);
    });
    this.list.addEventListener("keydown", (e) => this.onKey(e));
    this.detail.addEventListener("click", (e) => {
      const t = e.target as HTMLElement;
      const a = t.closest<HTMLElement>("[data-addr]");
      if (a) return this.host.navigate(BigInt(a.dataset.addr!));
      const c = t.closest<HTMLElement>("[data-goto-cls]");
      if (c) return this.select(c.dataset.gotoCls!);
      const ty = t.closest<HTMLElement>("[data-type]");
      if (ty) this.host.showType(ty.dataset.type!);
    });
  }

  markStale() {
    this.loaded = false;
  }

  ensureLoaded() {
    if (!this.loaded) void this.load();
  }

  focus() {
    this.filter.focus();
  }

  async load() {
    this.loaded = true;
    const seq = ++this.seq;
    let r: GetClassHierarchyResponse;
    try {
      r = await this.host.rk.queries.getClassHierarchy({ programId: this.host.programId });
    } catch (e) {
      if (seq !== this.seq) return;
      this.count.textContent = errText(e);
      return;
    }
    if (seq !== this.seq) return;
    this.classes = r.classes;
    this.count.textContent = `${r.classes.length.toLocaleString()} ${r.classes.length === 1 ? "class" : "classes"}`;
    this.paint();
  }

  /** Selects a class by name (tests, and a base's link). */
  select(name: string) {
    this.selected = name;
    if (!this.rows.some((r) => r.cls.name === name) && this.filter.value) {
      this.filter.value = "";
      this.paint();
    } else {
      this.paintList();
    }
    this.paintDetail();
    this.list.querySelector<HTMLElement>(".active")?.scrollIntoView({ block: "nearest" });
  }

  /** What is shown (tests). */
  describe() {
    const c = this.classes.find((x) => x.name === this.selected);
    return {
      rows: this.rows.map((r) => ({ name: r.cls.name, depth: r.depth })),
      selected: this.selected,
      bases: c?.bases.map((b) => b.name) ?? [],
      derived: c ? [...c.derived] : [],
      vftables: c?.vftables.map((t) => ({ name: t.name, functions: t.functions.map((f) => f.name) })) ?? [],
    };
  }

  private paint() {
    const needle = this.filter.value.trim().toLowerCase();
    const byName = new Map(this.classes.map((c) => [c.name, c]));
    this.rows = [];
    if (needle) {
      for (const c of this.classes) if (c.name.toLowerCase().includes(needle)) this.rows.push({ cls: c, depth: 0 });
    } else {
      // Roots: classes without a known direct base; derived ones under each base.
      const walk = (c: RttiClass, depth: number, seen: Set<string>) => {
        this.rows.push({ cls: c, depth });
        if (seen.has(c.name) || depth > 32) return;
        seen.add(c.name);
        for (const d of c.derived) {
          const k = byName.get(d);
          if (k) walk(k, depth + 1, seen);
        }
        seen.delete(c.name);
      };
      for (const c of this.classes) if (!c.bases.some((b) => b.direct && byName.has(b.name))) walk(c, 0, new Set());
    }
    if (!this.selected && this.rows.length) this.selected = this.rows[0].cls.name;
    this.paintList();
    this.paintDetail();
  }

  private paintList() {
    if (!this.rows.length) {
      this.list.replaceChildren(h("div", { class: "notes-empty dim", role: "treeitem", "aria-disabled": "true" }, this.loaded ? (this.filter.value ? "No class matches" : "No MSVC RTTI in this program") : "Loading…"));
      return;
    }
    this.list.replaceChildren(
      ...this.rows.map((r) =>
        h(
          "div",
          { class: "class-row" + (r.cls.name === this.selected ? " active" : ""), role: "treeitem", "data-cls": r.cls.name, style: `padding-left:${8 + r.depth * 14}px`, title: r.cls.mangled },
          h("span", { class: "class-kind dim" }, r.cls.isStruct ? "struct" : "class"),
          " ",
          r.cls.name,
          r.cls.vftables.length ? h("span", { class: "dim" }, `  ${r.cls.vftables.reduce((n, t) => n + t.functions.length, 0)} virtual`) : "",
        ),
      ),
    );
  }

  private paintDetail() {
    const c = this.classes.find((x) => x.name === this.selected);
    if (!c) {
      this.detail.replaceChildren();
      return;
    }
    const w = this.host.addrWidth;
    const addr = (a: bigint | undefined, text?: string) => h("a", { class: "mono link", "data-addr": String(a ?? 0n), href: "#" }, text ?? fmtAddr(a ?? 0n, w));
    const section = (title: string, ...items: (HTMLElement | string)[]) => h("div", { class: "class-section" }, h("div", { class: "class-section-title dim" }, title), ...items);
    const parts: HTMLElement[] = [
      h(
        "div",
        { class: "class-title" },
        h("b", {}, c.name),
        " ",
        c.typeHash ? h("a", { class: "link", href: "#", "data-type": c.typeName, title: "Open the struct `this` points to" }, c.typeName) : h("span", { class: "dim" }, c.typeName),
      ),
      h("div", { class: "dim" }, "Type descriptor ", addr(c.typeDescriptor?.offset), c.hierarchy ? h("span", {}, " · hierarchy ", addr(c.hierarchy.offset)) : ""),
    ];
    if (c.bases.length)
      parts.push(
        section(
          "Bases",
          ...c.bases.map((b) =>
            h(
              "div",
              { class: "class-base", style: `padding-left:${(b.depth - 1) * 14}px` },
              h("a", { class: "link", href: "#", "data-goto-cls": b.name }, b.name),
              h("span", { class: "dim" }, `  ${b.isVirtual ? "virtual" : `at +0x${b.offset.toString(16)}`}${b.direct ? "" : " (indirect)"}`),
            ),
          ),
        ),
      );
    if (c.derived.length) parts.push(section("Derived", ...c.derived.map((d) => h("div", {}, h("a", { class: "link", href: "#", "data-goto-cls": d }, d)))));
    for (const t of c.vftables)
      parts.push(
        section(
          `${t.name || "vftable"}${t.subobject ? ` (the ${t.subobject} subobject at +0x${t.offset.toString(16)})` : ""}`,
          h("div", { class: "dim" }, addr(t.address?.offset)),
          ...t.functions.map((f) => h("div", { class: "class-fn" }, h("span", { class: "dim mono" }, `[${f.slot}] `), addr(f.entry?.offset, f.name || hex(f.entry?.offset ?? 0n)))),
        ),
      );
    this.detail.replaceChildren(...parts);
  }

  private onKey(e: KeyboardEvent) {
    const i = this.rows.findIndex((r) => r.cls.name === this.selected);
    if (e.key === "ArrowDown" && i + 1 < this.rows.length) this.select(this.rows[i + 1].cls.name);
    else if (e.key === "ArrowUp" && i > 0) this.select(this.rows[i - 1].cls.name);
    else return;
    e.preventDefault();
  }
}
