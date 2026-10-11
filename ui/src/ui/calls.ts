// Call graph of the current function: what it calls and what calls it, as
// two trees expandable level by level, from the daemon's references
// (GetXrefs: CALL references into a function's entry, and out of its
// body). A function already on the path is marked as recursion and not
// expanded again. Click goes to the function (or the call site with Alt);
// Enter on a row makes it the root.

import { XrefDirection, XrefKind, type AddressRange, type Revkit } from "@revkit/api";
import { errText, hex, fmtAddr } from "../data/format";
import { h } from "./dom";
import { VirtualRows } from "./vlist";

interface Node {
  entry: bigint;
  name: string;
  /** Where the call is (the call site in the caller). */
  site: bigint | null;
  depth: number;
  dir: "callees" | "callers";
  open: boolean;
  loading: boolean;
  children: Node[] | null;
  path: Set<bigint>;
  /** Already on the path from the root: not expanded again. */
  rec?: boolean;
  error?: string;
}

const CALL_KINDS = [XrefKind.CALL, XrefKind.INDIRECT_CALL, XrefKind.THUNK];

export class CallsView {
  private root: Node | null = null;
  private rootCallers: Node | null = null;
  private body: HTMLElement;
  private vrows: VirtualRows;
  private title: HTMLElement;
  private rows: Node[] = [];
  private active = 0;
  private seq = 0;
  /** Children by (direction, entry), until the next invalidation. */
  private cache = new Map<string, Promise<Node[]>>();
  current: bigint | null = null;
  onOpen: ((address: bigint) => void) | null = null;

  constructor(
    root: HTMLElement,
    private rk: Revkit,
    private programId: string,
    private addrWidth: number,
  ) {
    this.title = h("span", { class: "mono graph-title" });
    this.body = h("div", { class: "calls-list", tabindex: "0", role: "tree", "aria-label": "Call graph", "data-testid": "calls-tree" });
    root.append(h("div", { class: "panel-head view-head" }, h("span", { class: "panel-title" }, "Calls"), this.title), this.body);
    // Only the rows in view are drawn: a hot function can have thousands of callers.
    this.vrows = new VirtualRows(this.body, 22, (i) => this.row(i));
    this.body.addEventListener("keydown", (e) => this.onKey(e));
    this.body.addEventListener("mousedown", (e) => {
      const el = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (!el) return;
      e.preventDefault();
      this.body.focus({ preventScroll: true });
      this.active = Number(el.dataset.i);
      const n = this.rows[this.active];
      if ((e.target as HTMLElement).classList.contains("tw")) void this.toggle(n);
      else this.go(n, e.altKey);
      this.paint();
    });
    this.body.addEventListener("dblclick", (e) => {
      const el = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (el && !(e.target as HTMLElement).classList.contains("tw")) void this.setRoot(this.rows[Number(el.dataset.i)].entry, this.rows[Number(el.dataset.i)].name);
    });
    this.paint();
  }

  /** Shows the call graph of the function at `entry` (no-op when it already does). */
  async setRoot(entry: bigint, name: string, force = false) {
    if (!force && this.current === entry && this.root) return;
    this.current = entry;
    const seq = ++this.seq;
    this.title.textContent = name;
    const mk = (dir: Node["dir"]): Node => ({ entry, name, site: null, depth: 0, dir, open: true, loading: true, children: null, path: new Set([entry]) });
    this.root = mk("callees");
    this.rootCallers = mk("callers");
    this.active = 0;
    this.paint();
    await Promise.all([this.expand(this.root), this.expand(this.rootCallers)]);
    if (seq === this.seq) this.paint();
  }

  /** Something changed (names, functions, references): load again, keeping what was open. */
  async refresh() {
    this.cache.clear();
    if (this.current === null || !this.root || !this.rootCallers) return;
    const open = new Set<string>();
    const walk = (n: Node, key: string) => {
      if (n.open) open.add(key);
      for (const c of n.children ?? []) walk(c, `${key}/${c.entry}`);
    };
    walk(this.root, "d");
    walk(this.rootCallers, "u");
    const seq = ++this.seq;
    const reopen = async (n: Node, key: string) => {
      await this.expand(n);
      for (const c of n.children ?? []) if (open.has(`${key}/${c.entry}`)) await reopen(c, `${key}/${c.entry}`);
    };
    const r = { ...this.root, children: null, open: true }, u = { ...this.rootCallers, children: null, open: true };
    // The root's own name may be what changed (a rename).
    const name = this.rk.queries.getFunction({ programId: this.programId, address: { offset: this.current } }).then((f) => f.function?.name || null, () => null);
    await Promise.all([reopen(r, "d"), reopen(u, "u")]);
    const named = await name;
    if (seq !== this.seq) return;
    if (named) {
      r.name = u.name = named;
      this.title.textContent = named;
    }
    this.root = r;
    this.rootCallers = u;
    this.paint();
  }

  clear() {
    this.current = null;
    this.root = this.rootCallers = null;
    this.title.textContent = "";
    this.paint();
  }

  focus() {
    this.body.focus({ preventScroll: true });
  }

  private async children(n: Node): Promise<Node[]> {
    const key = `${n.dir}:${n.entry}`;
    let p = this.cache.get(key);
    if (!p) {
      p = n.dir === "callers" ? this.callers(n.entry) : this.callees(n.entry);
      this.cache.set(key, p);
      p.catch(() => this.cache.delete(key));
    }
    const kids = await p;
    return kids.map((k) => ({ ...k, depth: n.depth + 1, dir: n.dir, path: new Set([...n.path, k.entry]), rec: n.path.has(k.entry) }));
  }

  /** Every page of a reference query, at one revision. */
  private async allXrefs(req: { programId: string; location: { case: "address"; value: { offset: bigint } } | { case: "range"; value: AddressRange }; direction: XrefDirection; kinds: XrefKind[] }) {
    const out = [];
    let token = "";
    let revision = 0n;
    do {
      const r = await this.rk.queries.getXrefs({ ...req, page: { pageSize: 5000, pageToken: token }, read: { revision } });
      out.push(...r.xrefs);
      revision = r.snapshot?.revision ?? revision;
      token = r.page?.nextPageToken ?? "";
    } while (token && out.length < 500_000);
    return out;
  }

  private async callers(entry: bigint): Promise<Node[]> {
    const xrefs = await this.allXrefs({ programId: this.programId, location: { case: "address", value: { offset: entry } }, direction: XrefDirection.TO, kinds: CALL_KINDS });
    const seen = new Map<bigint, Node>();
    for (const x of xrefs) {
      const f = x.fromFunction?.offset;
      if (f === undefined || seen.has(f)) continue;
      seen.set(f, this.node(f, x.fromFunctionName || `FUN_${hex(f, 8)}`, x.fromAddress?.offset ?? null));
    }
    return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  private async callees(entry: bigint): Promise<Node[]> {
    const f = await this.rk.queries.getFunction({ programId: this.programId, address: { offset: entry } });
    const body = f.function?.body ?? [];
    const seen = new Map<bigint, Node>();
    for (const range of body) {
      if (!range.first || !range.last) continue;
      const xrefs = await this.allXrefs({ programId: this.programId, location: { case: "range", value: range }, direction: XrefDirection.FROM, kinds: CALL_KINDS });
      for (const x of xrefs) {
        const to = x.toAddress?.offset;
        if (to === undefined || seen.has(to)) continue;
        seen.set(to, this.node(to, x.toName || fmtAddr(to, this.addrWidth), x.fromAddress?.offset ?? null));
      }
    }
    return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  private node(entry: bigint, name: string, site: bigint | null): Node {
    return { entry, name, site, depth: 0, dir: "callees", open: false, loading: false, children: null, path: new Set() };
  }

  private async expand(n: Node) {
    n.open = true;
    if (n.children) return;
    n.loading = true;
    try {
      n.children = await this.children(n);
    } catch (e) {
      n.children = [];
      n.error = errText(e);
    }
    n.loading = false;
  }

  private async toggle(n: Node | undefined) {
    if (!n || this.recursive(n)) return;
    if (n.open) {
      n.open = false;
      this.paint();
      return;
    }
    n.open = true;
    this.paint();
    await this.expand(n);
    this.paint();
  }

  private recursive(n: Node) {
    return n.rec === true;
  }

  private go(n: Node | undefined, site: boolean) {
    if (!n) return;
    if (site && n.site !== null) this.onOpen?.(n.site);
    else this.onOpen?.(n.entry);
  }

  private flatten(): Node[] {
    const out: Node[] = [];
    const walk = (n: Node) => {
      out.push(n);
      if (n.open && !this.recursive(n)) for (const c of n.children ?? []) walk(c);
    };
    if (this.root) walk(this.root);
    if (this.rootCallers) walk(this.rootCallers);
    return out;
  }

  private paint() {
    this.rows = this.flatten();
    this.active = Math.max(0, Math.min(this.active, this.rows.length - 1));
    this.vrows.count = Math.max(1, this.rows.length);
    this.vrows.reveal(this.active);
  }

  private row(i: number): HTMLElement {
    if (!this.rows.length) return h("div", { class: "notes-empty dim", role: "treeitem", "aria-disabled": "true" }, "Select a function to see what it calls and what calls it.");
    const n = this.rows[i];
    const rec = this.recursive(n);
    const leaf = n.children !== null && n.children.length === 0;
    const tw = n.loading ? "…" : rec || leaf ? "·" : n.open ? "▾" : "▸";
    const label =
      n.depth === 0
        ? h("span", { class: "calls-root" }, n.dir === "callees" ? `Calls from ${n.name}` : `Called by (callers of ${n.name})`)
        : h("span", { class: "fn-name" }, n.name);
    return h(
      "div",
      {
        class: "calls-row" + (i === this.active ? " active" : "") + (n.depth === 0 ? " root" : ""),
        style: `padding-left:${8 + n.depth * 16}px`,
        "data-i": i,
        "data-dir": n.dir,
        "data-depth": n.depth,
        role: "treeitem",
        "aria-level": n.depth + 1,
        "aria-selected": String(i === this.active),
        "aria-expanded": n.open ? "true" : "false",
        title: n.depth === 0 ? "" : `${n.name} at ${fmtAddr(n.entry)}${n.site !== null ? `\ncall site ${fmtAddr(n.site)} (Alt+click)` : ""}${rec ? "\nrecursive" : ""}\nDouble-click: make it the root`,
      },
      h("span", { class: "tw" }, tw),
      label,
      n.depth > 0 ? h("span", { class: "fn-addr" }, fmtAddr(n.entry, this.addrWidth)) : null,
      rec ? h("span", { class: "badge b-fn" }, "recursion") : null,
      n.error ? h("span", { class: "error" }, n.error) : null,
      n.depth === 0 && leaf ? h("span", { class: "dim" }, n.dir === "callees" ? " (no calls)" : " (no callers)") : null,
    );
  }

  private onKey(e: KeyboardEvent) {
    const n = this.rows[this.active];
    switch (e.key) {
      case "ArrowDown":
        this.active = Math.min(this.rows.length - 1, this.active + 1);
        break;
      case "ArrowUp":
        this.active = Math.max(0, this.active - 1);
        break;
      case "ArrowRight":
        if (n && !n.open) void this.toggle(n);
        break;
      case "ArrowLeft":
        if (n?.open && n.depth > 0) void this.toggle(n);
        break;
      case "Enter":
        if (n && n.depth > 0) {
          if (e.shiftKey) void this.setRoot(n.entry, n.name);
          else this.go(n, e.altKey);
        }
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
    this.paint();
  }

  /** The tree as shown (tests). */
  describe() {
    return this.flatten().map((n) => ({ name: n.name, entry: hex(n.entry), dir: n.dir, depth: n.depth, open: n.open, loading: n.loading, leaf: n.children !== null && n.children.length === 0 }));
  }

  /** Expands the row for `name` under `dir` (tests). */
  async expandNamed(dir: Node["dir"], name: string) {
    const n = this.flatten().find((x) => x.dir === dir && x.name === name && x.depth > 0);
    if (n && !n.open) await this.toggle(n);
  }
}
