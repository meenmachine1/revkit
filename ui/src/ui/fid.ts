// Function ID (feature function-id; docs/fid.md, docs/ui.md "Function ID"):
// the last run's matches as a table (entry, the name now, the name Function
// ID proposes, score, status, library), the selected match's candidates
// with their scores below; Run runs it again (the analyzer function-id),
// Apply names the function as the selected candidate (an edit of yours,
// one undo step), Reject retracts Function ID's name and keeps later runs
// off it; Databases… lists the databases (Ghidra's builtin ones, yours, the
// project's) to attach and detach.

import { FidMatchStatus, FidScope, type FidDatabase, type FidMatch, type Revkit } from "@revkit/api";
import { userProvenance } from "../api/client";
import { errText, fmtAddr, hex } from "../data/format";
import { ask, toast } from "./dialogs";
import { h } from "./dom";

export interface FidHost {
  rk: Revkit;
  programId: string;
  projectId: string;
  addrWidth: number;
  navigate: (address: bigint) => void;
  /** Resolves once this tab has the revision (its views refreshed). */
  settle: (revision: bigint) => Promise<void>;
  undo: () => void;
}

const STATUS: Record<number, string> = {
  [FidMatchStatus.APPLIED]: "applied",
  [FidMatchStatus.KEPT]: "kept",
  [FidMatchStatus.UNAPPLIED]: "not applied",
  [FidMatchStatus.REJECTED]: "rejected",
  [FidMatchStatus.ACCEPTED]: "accepted",
};
const STATUS_TITLE: Record<number, string> = {
  [FidMatchStatus.APPLIED]: "Function ID named it (an analysis name: anything else wins over it)",
  [FidMatchStatus.KEPT]: "A name from symbols, debug info, a user or an agent stays",
  [FidMatchStatus.UNAPPLIED]: "Names that differ, scoring under 30: Function ID names nothing",
  [FidMatchStatus.REJECTED]: "Rejected: Function ID leaves it alone",
  [FidMatchStatus.ACCEPTED]: "Named as one of the candidates",
};
const SCOPE: Record<number, string> = { [FidScope.BUILTIN]: "Ghidra", [FidScope.USER]: "yours", [FidScope.PROJECT]: "project" };

export class FidView {
  readonly filter: HTMLInputElement;
  private table: HTMLElement;
  private detail: HTMLElement;
  private applyBtn: HTMLButtonElement;
  private rejectBtn: HTMLButtonElement;
  private status: HTMLElement;
  private matches: FidMatch[] = [];
  private selected: bigint | null = null;
  private stale = true;
  private loading = 0;
  private running = false;
  private timer = 0;

  constructor(
    root: HTMLElement,
    private host: FidHost,
  ) {
    this.status = h("span", { class: "dim count", "data-testid": "fid-status" });
    this.filter = h("input", { class: "filter", placeholder: "Filter by name or library", spellcheck: "false", "aria-label": "Filter matches", "data-testid": "fid-filter" });
    this.table = h("div", { class: "fid-table", role: "listbox", tabindex: "0", "aria-label": "Function ID matches", "data-testid": "fid-table" }, h("div", { class: "pp-empty dim", role: "option", "aria-disabled": "true" }, "Loading…"));
    this.detail = h("div", { class: "fid-detail", "data-testid": "fid-detail" });
    this.applyBtn = h("button", { class: "btn small", "data-testid": "fid-apply", text: "Apply", disabled: true, title: "Name the function as the selected match (Enter)", onclick: () => void this.apply() });
    this.rejectBtn = h("button", { class: "btn small", "data-testid": "fid-reject", text: "Reject", disabled: true, title: "Take Function ID's name off and keep it off (Delete)", onclick: () => void this.reject() });
    root.replaceChildren(
      h(
        "div",
        { class: "panel-head view-head" },
        h("span", { class: "panel-title" }, "Function ID"),
        this.status,
        h("span", { class: "grow" }),
        h("button", { class: "btn small", "data-testid": "fid-run", text: "Run", title: "Run Function ID on this program again", onclick: () => void this.run() }),
        this.applyBtn,
        this.rejectBtn,
        h("button", { class: "btn small", "data-testid": "fid-databases", text: "Databases…", title: "The databases Function ID matches against", onclick: () => void this.databases() }),
      ),
      h("div", { class: "fn-filter" }, this.filter),
      h("div", { class: "fid-cols dim" }, h("span", {}, "Address"), h("span", {}, "Now"), h("span", {}, "Function ID"), h("span", {}, "Score"), h("span", {}, "Status"), h("span", {}, "Library")),
      this.table,
      this.detail,
    );
    this.filter.addEventListener("input", () => {
      clearTimeout(this.timer);
      this.timer = window.setTimeout(() => this.paint(), 80);
    });
    this.table.addEventListener("click", (e) => {
      const row = (e.target as HTMLElement).closest<HTMLElement>("[data-entry]");
      if (row) this.select(BigInt(row.dataset.entry!));
    });
    this.table.addEventListener("dblclick", (e) => {
      const row = (e.target as HTMLElement).closest<HTMLElement>("[data-entry]");
      if (row) this.host.navigate(BigInt(row.dataset.entry!));
    });
    this.table.addEventListener("keydown", (e) => this.onKey(e));
    this.detail.addEventListener("click", (e) => {
      const c = (e.target as HTMLElement).closest<HTMLElement>("[data-candidate]");
      if (c) void this.apply(c.dataset.candidate!);
    });
  }

  focus() {
    this.table.focus({ preventScroll: true });
  }

  /** What the view shows (the e2e checks read it). */
  describe() {
    return {
      status: this.status.textContent ?? "",
      rows: this.shown().map((m) => ({ entry: `0x${hex(m.entry)}`, now: m.currentName, name: m.name, status: STATUS[m.status] ?? "", score: m.score })),
      selected: this.selected === null ? "" : `0x${hex(this.selected)}`,
      candidates: this.current()?.candidates.map((c) => c.name) ?? [],
    };
  }

  markStale() {
    this.stale = true;
  }

  ensureLoaded() {
    if (this.stale) void this.load();
  }

  async load() {
    this.stale = false;
    const n = ++this.loading;
    try {
      const r = await this.host.rk.analysis.listFidMatches({ programId: this.host.programId });
      if (n !== this.loading) return;
      this.matches = r.matches;
      const applied = r.matches.filter((m) => m.status === FidMatchStatus.APPLIED || m.status === FidMatchStatus.ACCEPTED).length;
      this.status.textContent =
        r.revision === 0n
          ? this.running
            ? "running…"
            : "not run yet"
          : `${r.matches.length} match${r.matches.length === 1 ? "" : "es"} of ${r.functionsHashed} functions, ${applied} named · ${r.databases.length} database${r.databases.length === 1 ? "" : "s"}`;
      if (this.selected !== null && !r.matches.some((m) => m.entry === this.selected)) this.selected = null;
      this.paint();
    } catch (e) {
      this.status.textContent = errText(e);
    }
  }

  private shown(): FidMatch[] {
    const f = this.filter.value.trim().toLowerCase();
    if (!f) return this.matches;
    return this.matches.filter((m) => m.name.toLowerCase().includes(f) || m.currentName.toLowerCase().includes(f) || m.libraries.some((l) => l.toLowerCase().includes(f)) || m.candidates.some((c) => c.name.toLowerCase().includes(f)));
  }

  private current(): FidMatch | undefined {
    return this.matches.find((m) => m.entry === this.selected);
  }

  select(entry: bigint) {
    this.selected = entry;
    this.paint();
  }

  private onKey(e: KeyboardEvent) {
    const rows = this.shown();
    const i = rows.findIndex((m) => m.entry === this.selected);
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      const n = rows[Math.max(0, Math.min(rows.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
      if (n) this.select(n.entry);
    } else if (e.key === "Enter") void this.apply();
    else if (e.key === "Delete") void this.reject();
    else if (e.key === "g" && this.selected !== null) this.host.navigate(this.selected);
    else return;
    e.preventDefault();
  }

  private paint() {
    this.applyBtn.disabled = this.rejectBtn.disabled = !this.current();
    const rows = this.shown();
    if (!rows.length) {
      this.table.replaceChildren(h("div", { class: "pp-empty dim", role: "option", "aria-disabled": "true" }, this.matches.length ? "No match passes the filter." : "No matches. Function ID names library functions from its databases (Databases…); Run runs it again."));
      this.detail.replaceChildren();
      return;
    }
    this.table.replaceChildren(
      ...rows.map((m) =>
        h(
          "div",
          {
            class: "fid-row" + (m.entry === this.selected ? " active" : "") + ` fid-${(STATUS[m.status] ?? "").replace(" ", "-")}`,
            role: "option",
            "aria-selected": String(m.entry === this.selected),
            "data-testid": "fid-row",
            "data-entry": String(m.entry),
            "data-name": m.name,
            "data-status": STATUS[m.status] ?? "",
          },
          h("span", { class: "mono" }, fmtAddr(m.entry, this.host.addrWidth)),
          h("span", { class: "mono fid-now", title: m.currentName }, m.currentName),
          h("span", { class: "mono fid-name", title: m.name || m.candidates.map((c) => c.name).join("\n") }, m.name || `(${m.candidates.length} names)`),
          h("span", { class: "mono" }, m.score.toFixed(1)),
          h("span", { title: STATUS_TITLE[m.status] ?? "" }, STATUS[m.status] ?? ""),
          h("span", { class: "fid-lib", title: m.libraries.join("\n") }, m.libraries.join(", ")),
        ),
      ),
    );
    const m = this.current();
    if (!m) {
      this.detail.replaceChildren(h("div", { class: "dim fid-hint" }, "Select a match to see its candidates. Enter applies, Delete rejects, g goes there."));
      return;
    }
    this.detail.replaceChildren(
      h("div", { class: "dim fid-hint" }, `${m.verdict.replace("_", " ")} · hash ${m.fullHash} (${m.codeUnits} code units) · ${m.candidates.length} candidate${m.candidates.length === 1 ? "" : "s"} — click one to apply it`),
      ...m.candidates.map((c) =>
        h(
          "a",
          { class: "fid-cand link", href: "#", "data-testid": "fid-candidate", "data-candidate": c.name, onclick: (e: Event) => e.preventDefault(), title: `function ${c.functionScore.toFixed(2)} + callees ${c.childScore} + callers ${c.parentScore}${c.specific ? " (specific hash too)" : ""}` },
          h("span", { class: "mono" }, c.name),
          h("span", { class: "dim" }, ` ${c.score.toFixed(1)} · ${c.library} · ${c.database}`),
        ),
      ),
      m.comment ? h("pre", { class: "fid-comment dim" }, m.comment) : h("span"),
    );
  }

  /** Runs Function ID again, then reloads once the daemon is idle. */
  async run() {
    if (this.running) return;
    this.running = true;
    this.status.textContent = "running…";
    try {
      await this.host.rk.analysis.startAnalysis({ programId: this.host.programId, analyzers: ["function-id"], provenance: userProvenance() });
      for (let i = 0; i < 600; i++) {
        await new Promise((r) => setTimeout(r, 500));
        const s = await this.host.rk.analysis.getAnalysisStatus({ programId: this.host.programId });
        if (s.idle) break;
      }
    } catch (e) {
      toast(`Function ID failed: ${errText(e)}`, { kind: "error" });
    } finally {
      this.running = false;
    }
    await this.load();
  }

  async apply(name = "") {
    const m = this.current();
    if (!m) return toast("Select a match first");
    try {
      const r = await this.host.rk.analysis.applyFidMatch({ programId: this.host.programId, entry: m.entry, name, provenance: userProvenance("Function ID") });
      toast(`Named 0x${hex(m.entry)} ${name || m.name || m.candidates[0]?.name}`, { action: { label: "Undo", run: () => this.host.undo() } });
      await this.host.settle(r.revision);
      await this.load();
    } catch (e) {
      toast(`Apply failed: ${errText(e)}`, { kind: "error" });
    }
  }

  async reject() {
    const m = this.current();
    if (!m) return toast("Select a match first");
    try {
      const r = await this.host.rk.analysis.rejectFidMatch({ programId: this.host.programId, entry: m.entry, provenance: userProvenance("Function ID match rejected") });
      toast(`Rejected the match at 0x${hex(m.entry)}`, { action: { label: "Undo", run: () => this.host.undo() } });
      await this.host.settle(r.revision);
      await this.load();
    } catch (e) {
      toast(`Reject failed: ${errText(e)}`, { kind: "error" });
    }
  }

  /** The databases, to attach and detach (yours or the project's). */
  async databases() {
    let dbs: FidDatabase[];
    try {
      dbs = (await this.host.rk.analysis.listFidDatabases({ projectId: this.host.projectId, programId: this.host.programId })).databases;
    } catch (e) {
      return toast(`Function ID databases: ${errText(e)}`, { kind: "error" });
    }
    const box = h("div", { class: "modal fid-dbs", role: "dialog", "aria-modal": "true", "aria-label": "Function ID databases", tabindex: "-1", "data-testid": "fid-dbs" });
    const backdrop = h("div", { class: "backdrop top" }, box);
    const close = () => backdrop.remove();
    box.addEventListener("keydown", (e) => {
      if (e.key === "Escape") (e.preventDefault(), close());
    });
    const row = (d: FidDatabase) =>
      h(
        "div",
        { class: "fid-db" + (d.applies ? "" : " dim"), "data-testid": "fid-db", "data-id": d.id },
        h("input", {
          type: "checkbox",
          checked: d.attached,
          disabled: !!d.error,
          "aria-label": `Use ${d.name}`,
          onchange: (e: Event) => void this.toggle(d, (e.target as HTMLInputElement).checked),
        }),
        h("span", { class: "mono" }, d.name),
        h("span", { class: "dim" }, ` ${SCOPE[d.scope] ?? ""} · ${d.error || `${d.functions} functions · ${d.libraries.map((l) => `${l.family} ${l.version} ${l.variant} (${l.language})`.trim()).join(", ")}`}${d.applies ? "" : " · not for this program's language"}`),
      );
    box.append(
      h("div", { class: "modal-title" }, "Function ID databases"),
      ...dbs.map(row),
      h(
        "div",
        { class: "fid-db-actions" },
        h("button", { class: "btn small", "data-testid": "fid-attach", text: "Attach a file…", onclick: () => void this.attach(close) }),
        h("span", { class: "grow" }),
        h("button", { class: "btn small", "data-testid": "fid-dbs-close", text: "Close", onclick: close }),
      ),
      h("div", { class: "modal-hint" }, "A .fidbf (Ghidra's) or .rkfid file on the daemon's host. Unchecking a builtin detaches it for you; Run applies the change."),
    );
    backdrop.addEventListener("click", (e) => e.target === backdrop && close());
    document.body.append(backdrop);
    box.focus();
  }

  private async toggle(d: FidDatabase, on: boolean) {
    const scope = d.scope === FidScope.PROJECT ? FidScope.PROJECT : FidScope.USER;
    try {
      if (on) await this.host.rk.analysis.attachFidDatabase({ projectId: this.host.projectId, path: d.id, scope, provenance: userProvenance() });
      else await this.host.rk.analysis.detachFidDatabase({ projectId: this.host.projectId, id: d.id, scope, provenance: userProvenance() });
      toast(`${on ? "Attached" : "Detached"} ${d.name}; Run applies it`);
    } catch (e) {
      toast(`${errText(e)}`, { kind: "error" });
    }
  }

  private async attach(close: () => void) {
    const path = await ask({ title: "Attach a Function ID database (a path on the daemon's host)", placeholder: "/path/to/library.rkfid", validate: (v) => (v.trim().startsWith("/") ? null : "An absolute path") });
    if (path === null) return;
    try {
      const r = await this.host.rk.analysis.attachFidDatabase({ projectId: this.host.projectId, path: path.trim(), scope: FidScope.PROJECT, provenance: userProvenance() });
      toast(`Attached ${r.database?.name ?? path} to the project; Run applies it`);
      close();
    } catch (e) {
      toast(`Attach failed: ${errText(e)}`, { kind: "error" });
    }
  }
}
