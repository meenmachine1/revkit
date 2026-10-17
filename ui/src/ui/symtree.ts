// Symbol tree: Ghidra's symbol tree (feature "symbol-tree";
// QueryService.ListSymbolTree). The folders Imports (by library), Exports,
// Functions, Labels, Classes and Namespaces, each expanded one level at a
// time from the daemon and paged (500 at a time, "more…" for the rest). A
// filter narrows every expanded level by name. Click or Enter on a symbol
// goes there; Right and Left (or a click on the twisty) expand and
// collapse. docs/ui.md ("Symbol tree").

import { SymbolTreeNodeKind, type Revkit, type SymbolTreeNode } from "@revkit/api";
import { errText, fmtAddr } from "../data/format";
import { h } from "./dom";

const PAGE = 500;

export interface SymbolTreeHost {
  rk: Revkit;
  programId: string;
  addrWidth: number;
  navigate(address: bigint): void;
}

interface TreeNode {
  path: string[];
  data: SymbolTreeNode | null; // null: the root
  expanded: boolean;
  children: TreeNode[] | null;
  total: number;
  token: string;
  loading: boolean;
  error: string;
}

/** A visible row: a node, or the "more…" row of one. */
type Row = { node: TreeNode; depth: number; more?: boolean };

const ICON: Record<number, string> = {
  [SymbolTreeNodeKind.FOLDER]: "▤",
  [SymbolTreeNodeKind.LIBRARY]: "L",
  [SymbolTreeNodeKind.NAMESPACE]: "N",
  [SymbolTreeNodeKind.CLASS]: "C",
  [SymbolTreeNodeKind.FUNCTION]: "F",
  [SymbolTreeNodeKind.LABEL]: "L",
  [SymbolTreeNodeKind.IMPORT]: "I",
  [SymbolTreeNodeKind.EXPORT]: "E",
};

function isContainer(n: SymbolTreeNode): boolean {
  return n.kind === SymbolTreeNodeKind.FOLDER || n.kind === SymbolTreeNodeKind.LIBRARY || n.kind === SymbolTreeNodeKind.NAMESPACE || n.kind === SymbolTreeNodeKind.CLASS;
}

export class SymbolTreeView {
  readonly filter: HTMLInputElement;
  private list: HTMLElement;
  private count: HTMLElement;
  private root: TreeNode = { path: [], data: null, expanded: true, children: null, total: 0, token: "", loading: false, error: "" };
  private rows: Row[] = [];
  private active = 0;
  private loaded = false;
  private timer = 0;
  private gen = 0;

  constructor(
    el: HTMLElement,
    private host: SymbolTreeHost,
  ) {
    this.filter = h("input", { class: "filter", placeholder: "Filter by name", spellcheck: "false", "aria-label": "Filter symbols", "data-testid": "symtree-filter" });
    this.count = h("span", { class: "dim count", "data-testid": "symtree-count" });
    this.list = h("div", { class: "symtree-list", role: "tree", tabindex: "0", "aria-label": "Symbol tree", "data-testid": "symtree-list" });
    el.append(h("div", { class: "panel-head view-head" }, h("span", { class: "panel-title" }, "Symbol tree"), this.count), h("div", { class: "fn-filter" }, this.filter), this.list);
    this.filter.addEventListener("input", () => {
      clearTimeout(this.timer);
      this.timer = window.setTimeout(() => void this.refilter(), 200);
    });
    this.filter.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        this.list.focus();
      }
    });
    this.list.addEventListener("keydown", (e) => this.onKey(e));
    this.list.addEventListener("mousedown", (e) => {
      const el = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (!el) return;
      e.preventDefault();
      this.list.focus();
      this.active = Number(el.dataset.i);
      const row = this.rows[this.active];
      if (!row) return;
      if (row.more) return void this.loadMore(row.node);
      if ((e.target as HTMLElement).closest(".sy-twisty") || (row.node.data && isContainer(row.node.data))) void this.toggle(row.node);
      else this.open(row.node);
      this.paint();
    });
  }

  markStale() {
    this.loaded = false;
  }

  ensureLoaded() {
    if (!this.loaded) void this.load();
  }

  focus() {
    this.list.focus();
  }

  /** Reloads the root and every expanded node (an edit or a filter). */
  async load() {
    this.loaded = true;
    const gen = ++this.gen;
    const expanded = new Set<string>();
    const walk = (n: TreeNode) => {
      if (n.expanded && n.data) expanded.add(n.path.join("\u0000"));
      n.children?.forEach(walk);
    };
    walk(this.root);
    await this.fetchChildren(this.root, gen);
    // Expand again what was expanded, level by level.
    const again = async (n: TreeNode) => {
      for (const c of n.children ?? []) {
        if (gen !== this.gen) return;
        if (expanded.has(c.path.join("\u0000"))) {
          c.expanded = true;
          await this.fetchChildren(c, gen);
          await again(c);
        }
      }
    };
    await again(this.root);
    if (gen === this.gen) this.paint();
  }

  private async refilter() {
    await this.load();
  }

  private async fetchChildren(n: TreeNode, gen: number, more = false) {
    n.loading = true;
    if (!more) this.paint();
    try {
      const r = await this.host.rk.queries.listSymbolTree({
        programId: this.host.programId,
        path: n.path,
        nameContains: n.path.length ? this.filter.value.trim() : "",
        page: { pageSize: PAGE, pageToken: more ? n.token : "" },
      });
      if (gen !== this.gen) return;
      const kids = r.nodes.map(
        (d): TreeNode => ({
          path: [...n.path, d.kind === SymbolTreeNodeKind.CLASS && n.path[0] === "Classes" && n.path.length === 1 ? d.fullName : d.name],
          data: d,
          expanded: false,
          children: null,
          total: 0,
          token: "",
          loading: false,
          error: "",
        }),
      );
      n.children = more ? [...(n.children ?? []), ...kids] : kids;
      n.total = Number(r.total);
      n.token = r.page?.nextPageToken ?? "";
      n.error = "";
      if (n === this.root) this.count.textContent = this.filter.value.trim() ? "filtered" : "";
    } catch (e) {
      if (gen !== this.gen) return;
      n.error = errText(e);
    } finally {
      n.loading = false;
    }
    this.paint();
  }

  private async loadMore(n: TreeNode) {
    if (n.loading || !n.token) return;
    await this.fetchChildren(n, this.gen, true);
  }

  private async toggle(n: TreeNode) {
    if (!n.data || !isContainer(n.data)) return;
    n.expanded = !n.expanded;
    if (n.expanded && !n.children) await this.fetchChildren(n, this.gen);
    this.paint();
  }

  private open(n: TreeNode) {
    const a = n.data?.address;
    if (a) this.host.navigate(a.offset);
  }

  private flatten() {
    this.rows = [];
    const walk = (n: TreeNode, depth: number) => {
      for (const c of n.children ?? []) {
        this.rows.push({ node: c, depth });
        if (c.expanded) {
          walk(c, depth + 1);
          if (c.token) this.rows.push({ node: c, depth: depth + 1, more: true });
        }
      }
    };
    walk(this.root, 0);
    this.active = Math.max(0, Math.min(this.active, this.rows.length - 1));
  }

  private paint() {
    this.flatten();
    const out: HTMLElement[] = this.rows.map((r, i) => {
      const cls = "sy-row" + (i === this.active ? " active" : "");
      if (r.more) {
        const left = r.node.total - (r.node.children?.length ?? 0);
        return h("div", { class: cls + " sy-more dim", "data-i": i, role: "treeitem", style: `padding-left:${8 + r.depth * 14}px`, "data-testid": "symtree-more" }, r.node.loading ? "Loading…" : `more… (${left.toLocaleString()} left)`);
      }
      const d = r.node.data!;
      const container = isContainer(d);
      const twisty = container ? (r.node.expanded ? "▾" : "▸") : "";
      const count = container ? (r.node.expanded && r.node.children ? r.node.total : Number(d.children)) : -1;
      return h(
        "div",
        {
          class: cls,
          "data-i": i,
          role: "treeitem",
          "aria-expanded": container ? String(r.node.expanded) : undefined,
          "aria-level": String(r.depth + 1),
          "data-testid": "symtree-row",
          "data-path": r.node.path.join("/"),
          style: `padding-left:${8 + r.depth * 14}px`,
          title: d.fullName && d.fullName !== d.name ? d.fullName : d.address ? `${d.name} at ${fmtAddr(d.address.offset)}` : d.name,
        },
        h("span", { class: "sy-twisty dim" }, twisty),
        h("span", { class: `sy-icon sy-k${d.kind}` }, ICON[d.kind] ?? ""),
        h("span", { class: "sy-name" }, d.name),
        count >= 0 ? h("span", { class: "dim sy-count" }, ` ${count.toLocaleString()}`) : "",
        d.address ? h("span", { class: "dim sy-addr" }, fmtAddr(d.address.offset, this.host.addrWidth)) : "",
        r.node.loading ? h("span", { class: "dim" }, " …") : r.node.error ? h("span", { class: "sy-error" }, ` ${r.node.error}`) : "",
      );
    });
    if (!out.length) out.push(h("div", { class: "notes-empty dim", role: "treeitem", "aria-disabled": "true" }, this.root.error || (this.loaded ? "No symbols" : "Loading…")));
    this.list.replaceChildren(...out);
    this.list.querySelector(".sy-row.active")?.scrollIntoView({ block: "nearest" });
  }

  private onKey(e: KeyboardEvent) {
    const row = this.rows[this.active];
    switch (e.key) {
      case "ArrowDown":
        this.active = Math.min(this.rows.length - 1, this.active + 1);
        break;
      case "ArrowUp":
        this.active = Math.max(0, this.active - 1);
        break;
      case "ArrowRight":
        if (row && !row.more && row.node.data && isContainer(row.node.data) && !row.node.expanded) void this.toggle(row.node);
        break;
      case "ArrowLeft":
        if (row && !row.more && row.node.expanded) void this.toggle(row.node);
        else if (row) {
          // To the parent.
          const parent = row.node.path.slice(0, -1).join("\u0000");
          const at = this.rows.findIndex((r) => !r.more && r.node.path.join("\u0000") === parent);
          if (at >= 0) this.active = at;
        }
        break;
      case "Enter":
        if (!row) return;
        if (row.more) void this.loadMore(row.node);
        else if (row.node.data && isContainer(row.node.data)) void this.toggle(row.node);
        else this.open(row.node);
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
    this.paint();
  }

  /** Expands the node at this path, its parents first (tests, and Show in symbol tree). */
  async expand(path: string[]) {
    let n = this.root;
    if (!n.children) await this.fetchChildren(n, this.gen);
    for (const name of path) {
      const c = n.children?.find((k) => k.path[k.path.length - 1] === name);
      if (!c) return false;
      if (!c.expanded) {
        c.expanded = true;
        if (!c.children) await this.fetchChildren(c, this.gen);
      }
      n = c;
    }
    this.paint();
    return true;
  }

  /** The visible rows (tests). */
  visible() {
    return this.rows.map((r) => (r.more ? { path: r.node.path.join("/"), more: true, name: "", kind: 0, address: "", children: 0 } : { path: r.node.path.join("/"), more: false, name: r.node.data!.name, kind: r.node.data!.kind, address: r.node.data!.address ? r.node.data!.address.offset.toString(16) : "", children: Number(r.node.data!.children) }));
  }
}
