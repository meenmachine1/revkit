// Plugins in the UI: what analyzer plugins derive (GetPluginFacts) as
// annotations on the listing rows in view, refetched when the daemon says
// what they read changed (QUERY_KIND_PLUGIN_FACTS); and command plugins
// (ListPlugins) as palette commands run with RunCommand, whose edits come
// back as assertions this tab can undo.

import { PluginFactKind, PluginKind, type Plugin, type PluginFact, type Revkit } from "@revkit/api";

export function factText(f: PluginFact): string {
  const rule = f.origin?.source.case === "derived" ? f.origin.source.value.rule.replace(/^plugin:/, "") : "plugin";
  const name = rule.replace(/@.*$/, "");
  switch (f.kind) {
    case PluginFactKind.LABEL:
      return `⚙ ${name}: label ${f.text}`;
    case PluginFactKind.COMMENT:
      return `⚙ ${name}: ${f.text}`;
    case PluginFactKind.DATA_TYPE:
      return `⚙ ${name}: type ${f.text}`;
    case PluginFactKind.NOTE:
      return `⚙ ${name}: ${f.sub ? f.sub + ": " : ""}${f.text}`;
    default:
      return `⚙ ${name}: ${f.text}`;
  }
}

export class PluginFacts {
  /** Annotation text by address, for the rows last asked about. */
  readonly byAddress = new Map<bigint, string>();
  readonly facts: PluginFact[] = [];
  private key = "";
  private seq = 0;
  private timer = 0;
  private stale = true;
  analyzers: Plugin[] = [];
  commands: Plugin[] = [];
  /** The annotations changed. */
  onChange: (() => void) | null = null;
  errors: string[] = [];

  constructor(
    private rk: Revkit,
    private programId: string,
  ) {}

  async loadPlugins() {
    try {
      const r = await this.rk.plugins.listPlugins({});
      this.analyzers = r.plugins.filter((p) => p.loaded && p.kind === PluginKind.ANALYZER);
      this.commands = r.plugins.filter((p) => p.loaded && p.kind === PluginKind.COMMAND);
    } catch {
      this.analyzers = [];
      this.commands = [];
    }
  }

  /** What analyzer plugins read changed: fetch the window again. */
  invalidate() {
    this.stale = true;
    this.key = "";
  }

  /** The rows in view span [first, last] (from the containing function's entry): fetch their facts, debounced. */
  want(first: bigint, last: bigint) {
    if (!this.analyzers.length) return;
    const key = `${first}:${last}`;
    if (key === this.key && !this.stale) return;
    clearTimeout(this.timer);
    this.timer = window.setTimeout(() => void this.fetch(first, last, key), 120);
  }

  private async fetch(first: bigint, last: bigint, key: string) {
    const seq = ++this.seq;
    this.key = key;
    this.stale = false;
    try {
      const r = await this.rk.plugins.getPluginFacts({ programId: this.programId, range: { first: { offset: first }, last: { offset: last } } });
      if (seq !== this.seq) return;
      this.byAddress.clear();
      this.facts.length = 0;
      for (const f of r.facts) {
        const a = f.address?.offset;
        if (a === undefined) continue;
        this.facts.push(f);
        const t = factText(f);
        const prev = this.byAddress.get(a);
        this.byAddress.set(a, prev ? `${prev}  ${t}` : t);
      }
      this.errors = r.errors.map((e) => `${e.plugin}: ${e.failure} ${e.message}`);
      this.onChange?.();
    } catch {
      if (seq === this.seq) this.key = "";
    }
  }
}
