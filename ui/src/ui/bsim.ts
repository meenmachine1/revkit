// BSim (features bsim, bsim-search; docs/bsim.md, docs/ui.md "BSim"):
// functions similar to this program's in a BSim database. The head picks
// the database (the project's attached ones) and searches: the function at
// the cursor, every function, or an overview (hit counts only). Options:
// similarity and confidence thresholds, matches per function, an
// executable or name filter, analysis names (FUN_...) left out. The table
// lists each searched function with its matches, best first (similarity,
// confidence, executable, the match's name and prototype); a double click
// or Enter on a match whose file is a program of the project opens the two
// side by side in Compare. Ingest adds this program to the database;
// Databases… creates one in the project or attaches one at a host path.

import type { BSimDatabase, BSimMatch, BSimQueryResult, Revkit } from "@revkit/api";
import { userProvenance } from "../api/client";
import { errText, fmtAddr, hex } from "../data/format";
import { ask, toast } from "./dialogs";
import { h } from "./dom";

export interface BsimHost {
  rk: Revkit;
  programId: string;
  projectId: string;
  addrWidth: number;
  features: Set<string>;
  /** The function at the cursor (listing or decompiler), if any. */
  currentFunction: () => { entry: bigint; name: string } | null;
  navigate: (address: bigint) => void;
  /** Opens two functions side by side in Compare. */
  compare: (a: { programId: string; entry: bigint; name: string }, b: { programId: string; entry: bigint; name: string }) => void;
}

type Mode = "function" | "all" | "overview";

const LAST_DB = "rk.bsim.database";

function pct(x: number) {
  return x.toFixed(3);
}

export class BsimView {
  private dbSelect: HTMLSelectElement;
  private status: HTMLElement;
  private table: HTMLElement;
  private sim: HTMLInputElement;
  private conf: HTMLInputElement;
  private max: HTMLInputElement;
  private exe: HTMLInputElement;
  private noDefault: HTMLInputElement;
  private databases: BSimDatabase[] = [];
  private results: BSimQueryResult[] = [];
  private mode: Mode = "function";
  private selected = -1;  // index into rows()
  private loaded = false;
  private searching = 0;

  constructor(
    root: HTMLElement,
    private host: BsimHost,
  ) {
    const search = this.host.features.has("bsim-search");
    this.status = h("span", { class: "dim count", "data-testid": "bsim-status" });
    this.dbSelect = h("select", { "aria-label": "BSim database", "data-testid": "bsim-database", title: "The database to search (the project's)" }) as HTMLSelectElement;
    this.dbSelect.addEventListener("change", () => {
      try {
        localStorage.setItem(LAST_DB, this.dbSelect.value);
      } catch {
        /* no storage */
      }
    });
    const num = (testid: string, value: string, title: string, step: string) =>
      h("input", { type: "number", class: "bsim-num", value, step, min: "0", title, "aria-label": title, "data-testid": testid }) as HTMLInputElement;
    this.sim = num("bsim-similarity", "0.7", "Similarity at least (cosine; Ghidra's default 0.7)", "0.05");
    this.conf = num("bsim-confidence", "0", "Confidence at least (BSim's significance; tiny functions score low)", "1");
    this.max = num("bsim-max", "5", "Matches per function", "1");
    this.exe = h("input", { class: "filter", placeholder: "Executable or name filter", spellcheck: "false", "aria-label": "Executable or function name filter", "data-testid": "bsim-filter", title: "An executable's name (or id) to search only it, or a function name to keep" }) as HTMLInputElement;
    this.noDefault = h("input", { type: "checkbox", checked: true, "data-testid": "bsim-no-default" }) as HTMLInputElement;
    this.table = h("div", { class: "bsim-table", role: "listbox", tabindex: "0", "aria-label": "BSim matches", "data-testid": "bsim-table" });
    const btn = (testid: string, text: string, title: string, run: () => void, enabled = true) =>
      h("button", { class: "btn small", "data-testid": testid, text, title, disabled: !enabled, onclick: run });
    root.replaceChildren(
      h(
        "div",
        { class: "panel-head view-head" },
        h("span", { class: "panel-title" }, "BSim"),
        this.status,
        h("span", { class: "grow" }),
        this.dbSelect,
        btn("bsim-databases", "Databases…", "Create a database in the project, or attach one", () => void this.manage()),
        btn("bsim-ingest", "Ingest", "Add this program to the database (its functions' signatures), replacing an earlier ingest of the same file", () => void this.ingest()),
      ),
      h(
        "div",
        { class: "bsim-bar" },
        btn("bsim-search-function", "This function", "Functions similar to the one at the cursor", () => void this.search("function"), search),
        btn("bsim-search-all", "All functions", "Every function of the program, those with matches", () => void this.search("all"), search),
        btn("bsim-overview", "Overview", "How many matches each function has", () => void this.search("overview"), search),
        h("label", { class: "dim small" }, "sim ≥ ", this.sim),
        h("label", { class: "dim small" }, "conf ≥ ", this.conf),
        h("label", { class: "dim small" }, "max ", this.max),
        h("label", { class: "ask-check dim small", title: "Leave out matches with analysis names (FUN_…): nothing to learn from them" }, this.noDefault, "named only"),
        this.exe,
      ),
      this.table,
    );
    this.table.addEventListener("click", (e) => {
      const row = (e.target as HTMLElement).closest<HTMLElement>("[data-row]");
      if (row) this.select(Number(row.dataset.row));
    });
    this.table.addEventListener("dblclick", (e) => {
      const row = (e.target as HTMLElement).closest<HTMLElement>("[data-row]");
      if (row) this.open(Number(row.dataset.row));
    });
    this.table.addEventListener("keydown", (e) => this.onKey(e));
    this.paint();
  }

  focus() {
    this.table.focus({ preventScroll: true });
  }

  ensureLoaded() {
    if (!this.loaded) void this.loadDatabases();
  }

  /** What the view shows (the e2e checks read it). */
  describe() {
    return {
      status: this.status.textContent ?? "",
      database: this.dbSelect.value,
      databases: this.databases.map((d) => d.name),
      mode: this.mode,
      rows: this.rows().map((r) =>
        r.match
          ? { function: r.query.name, match: r.match.function?.name ?? "", executable: r.match.executable?.name ?? "", similarity: r.match.similarity, programId: r.match.programId }
          : { function: r.query.name, hits: r.query.hitCount },
      ),
    };
  }

  async loadDatabases(prefer = "") {
    this.loaded = true;
    try {
      const r = await this.host.rk.bsim.listBSimDatabases({ projectId: this.host.projectId });
      this.databases = r.databases;
      let last = prefer;
      if (!last)
        try {
          last = localStorage.getItem(LAST_DB) ?? "";
        } catch {
          /* no storage */
        }
      this.dbSelect.replaceChildren(
        ...(r.databases.length
          ? r.databases.map((d) =>
              h("option", { value: d.id, title: d.error || `${d.id}\n${d.executables} executables, ${d.functions} functions`, disabled: !!d.error }, d.error ? `${d.name} (unavailable)` : d.name),
            )
          : [h("option", { value: "" }, "No database: Databases… creates one")]),
      );
      if (last && r.databases.some((d) => d.id === last)) this.dbSelect.value = last;
      if (!this.results.length) this.status.textContent = r.databases.length ? "" : "no database attached";
    } catch (e) {
      this.status.textContent = errText(e);
    }
  }

  private database(): string | null {
    const id = this.dbSelect.value;
    if (!id) {
      toast("Create or attach a BSim database first (Databases…)", { kind: "error" });
      return null;
    }
    return id;
  }

  /** Searches (the function at the cursor, every function, or counts only). */
  async search(mode: Mode, entry?: bigint) {
    const database = this.database();
    if (!database) return;
    let functions: { offset: bigint }[] = [];
    if (mode === "function") {
      const at = entry !== undefined ? { entry, name: "" } : this.host.currentFunction();
      if (!at) return toast("Put the cursor in a function first", { kind: "error" });
      functions = [{ offset: at.entry }];
    }
    const filter = this.exe.value.trim();
    const known = filter && this.databases.length ? filter : "";
    const n = ++this.searching;
    this.status.textContent = mode === "function" ? "searching…" : "signing and searching every function…";
    try {
      const r = await this.host.rk.bsim.searchBSim({
        projectId: this.host.projectId,
        database,
        programId: this.host.programId,
        functions,
        allFunctions: mode !== "function",
        minSimilarity: Number(this.sim.value) || 0,
        minConfidence: Number(this.conf.value) || 0,
        maxMatches: Math.max(1, Math.min(100, Number(this.max.value) || 5)),
        excludeDefaultNames: this.noDefault.checked,
        overview: mode === "overview",
        // A filter is an executable when one has that name or id; else a function name.
        ...(known ? await this.filterFor(database, known) : {}),
      });
      if (n !== this.searching) return;
      this.mode = mode;
      this.results =
        mode === "function"
          ? r.results
          : mode === "overview"
            ? [...r.results].filter((q) => !q.skipped).sort((a, b) => b.hitCount - a.hitCount || (a.function!.offset < b.function!.offset ? -1 : 1))
            : r.results.filter((q) => q.matches.length).sort((a, b) => b.matches[0].similarity - a.matches[0].similarity);
      const fns = r.results.filter((q) => !q.skipped).length;
      const hits = r.results.filter((q) => q.hitCount > 0).length;
      this.status.textContent =
        mode === "function"
          ? r.results[0]?.skipped
            ? `${r.results[0].name}: no signature (${r.results[0].skipped})`
            : `${r.results[0]?.name}: ${r.results[0]?.hitCount ?? 0} match${r.results[0]?.hitCount === 1 ? "" : "es"} · ${r.seconds.toFixed(1)} s`
          : `${hits} of ${fns} functions have matches · ${r.seconds.toFixed(1)} s`;
      this.selected = this.rows().length ? 0 : -1;
      this.paint();
    } catch (e) {
      if (n === this.searching) this.status.textContent = errText(e);
    }
  }

  private async filterFor(database: string, text: string): Promise<{ executables?: string[]; nameContains?: string }> {
    try {
      const r = await this.host.rk.bsim.listBSimExecutables({ projectId: this.host.projectId, database, filter: text });
      if (r.executables.some((e) => e.name === text || e.id.startsWith(text))) return { executables: [text] };
    } catch {
      /* treat it as a name */
    }
    return { nameContains: text };
  }

  private rows(): { query: BSimQueryResult; match?: BSimMatch }[] {
    const out: { query: BSimQueryResult; match?: BSimMatch }[] = [];
    for (const q of this.results) {
      if (this.mode === "overview" || !q.matches.length) out.push({ query: q });
      else for (const m of q.matches) out.push({ query: q, match: m });
    }
    return out;
  }

  // Moves the selection without repainting (a repaint between a double
  // click's two clicks would swallow the double click).
  private select(i: number) {
    this.selected = i;
    for (const el of this.table.querySelectorAll<HTMLElement>("[data-row]")) {
      const on = el.dataset.row === String(i);
      el.classList.toggle("active", on);
      el.setAttribute("aria-selected", String(on));
    }
    this.table.querySelector(`[data-row="${i}"]`)?.scrollIntoView({ block: "nearest" });
  }

  /** A match: side by side in Compare; a function (overview): search it. */
  private open(i: number) {
    const r = this.rows()[i];
    if (!r) return;
    if (!r.match) {
      if (this.mode === "overview" && r.query.hitCount > 0) void this.search("function", r.query.function!.offset);
      else this.host.navigate(r.query.function!.offset);
      return;
    }
    const m = r.match;
    if (!m.programId)
      return toast(`${m.executable?.name} isn't a program of this project: import it to compare (${m.executable?.path || m.executable?.id.slice(0, 12)})`, { kind: "error" });
    this.host.compare(
      { programId: this.host.programId, entry: r.query.function!.offset, name: r.query.name },
      { programId: m.programId, entry: m.function!.entry!.offset, name: m.function!.name },
    );
  }

  private onKey(e: KeyboardEvent) {
    const n = this.rows().length;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      if (n) this.select(Math.max(0, Math.min(n - 1, this.selected + (e.key === "ArrowDown" ? 1 : -1))));
    } else if (e.key === "Enter") this.open(this.selected);
    else if (e.key === "g" && this.rows()[this.selected]) this.host.navigate(this.rows()[this.selected].query.function!.offset);
    else return;
    e.preventDefault();
  }

  private paint() {
    const rows = this.rows();
    if (!rows.length) {
      this.table.replaceChildren(
        h(
          "div",
          { class: "pp-empty dim", role: "option", "aria-disabled": "true" },
          this.results.length
            ? "No function has matches above the thresholds."
            : "Search a BSim database for functions like this program's: This function (the one at the cursor), All functions, or an Overview of how many each has. Ingest adds this program to the database.",
        ),
      );
      return;
    }
    const head =
      this.mode === "overview"
        ? h("div", { class: "bsim-cols bsim-ov dim" }, h("span", {}, "Address"), h("span", {}, "Function"), h("span", {}, "Matches"), h("span", { title: "BSim's self-significance: how much a match can mean" }, "Weight"))
        : h("div", { class: "bsim-cols dim" }, h("span", {}, "Function"), h("span", {}, "Similarity"), h("span", {}, "Confidence"), h("span", {}, "Match"), h("span", {}, "Executable"));
    this.table.replaceChildren(
      head,
      ...rows.map((r, i) => {
        const first = i === 0 || rows[i - 1].query !== r.query;
        const attrs = { class: "bsim-row" + (i === this.selected ? " active" : "") + (first ? " first" : ""), role: "option", "aria-selected": String(i === this.selected), "data-row": String(i), "data-testid": "bsim-row" };
        if (this.mode === "overview")
          return h(
            "div",
            { ...attrs, class: attrs.class + " bsim-ov" },
            h("span", { class: "mono" }, fmtAddr(r.query.function!.offset, this.host.addrWidth)),
            h("span", { class: "mono", title: r.query.name }, r.query.name),
            h("span", { class: "mono" }, String(r.query.hitCount)),
            h("span", { class: "mono dim" }, r.query.selfSignificance.toFixed(1)),
          );
        const m = r.match;
        const fn = h("span", { class: "mono" + (first ? "" : " dim"), title: `${r.query.name} at 0x${hex(r.query.function!.offset)}${r.query.skipped ? ` (${r.query.skipped})` : ""}` }, first ? r.query.name : "");
        if (!m) return h("div", attrs, fn, h("span", { class: "dim" }, r.query.skipped ? `no signature: ${r.query.skipped}` : "no matches"), h("span", {}), h("span", {}), h("span", {}));
        return h(
          "div",
          { ...attrs, "data-match": m.function?.name ?? "", "data-program": m.programId },
          fn,
          h("span", { class: "mono" }, pct(m.similarity)),
          h("span", { class: "mono" }, m.confidence.toFixed(1)),
          h("span", { class: "mono bsim-match" + (m.function?.defaultName ? " dim" : ""), title: m.function?.prototype || m.function?.name || "" }, m.function?.name ?? ""),
          h("span", { class: m.programId ? "" : "dim", title: m.programId ? "In this project: Enter compares side by side" : `${m.executable?.path || ""}\n${m.executable?.id ?? ""}` }, m.executable?.name ?? ""),
        );
      }),
    );
  }

  /** Adds this program to the selected database. */
  async ingest() {
    const database = this.database();
    if (!database) return;
    this.status.textContent = "ingesting (signing every function)…";
    try {
      const r = await this.host.rk.bsim.ingestBSim({ projectId: this.host.projectId, database, programIds: [this.host.programId] });
      const p = r.programs[0];
      const left = Object.entries(p.excluded).map(([k, v]) => `${v} ${k}`).join(", ");
      this.status.textContent = `${p.replaced ? "replaced" : "ingested"}: ${p.functions} functions${left ? ` (left out: ${left})` : ""} in ${p.seconds.toFixed(1)} s`;
      if (p.warning) toast(p.warning);
      await this.loadDatabases(database);
    } catch (e) {
      this.status.textContent = errText(e);
    }
  }

  /** Create one in the project (by name), attach one (a host path), or detach the selected one. */
  async manage() {
    const choice = await ask({
      title: "BSim databases",
      hint: "A name creates bsim/NAME.rkbsim in the project's directory; an absolute path attaches the database there (or creates it; admin); -NAME detaches",
      placeholder: "name, /host/path/db.rkbsim, or -name to detach",
    });
    const v = choice?.trim();
    if (!v) return;
    try {
      if (v.startsWith("-")) {
        const name = v.slice(1).trim();
        const d = this.databases.find((x) => x.name === name || x.id === name);
        if (!d) return toast(`No database ${name}`, { kind: "error" });
        await this.host.rk.bsim.detachBSimDatabase({ projectId: this.host.projectId, database: d.id, provenance: userProvenance("detach BSim database") });
        toast(`Detached ${d.name}`);
        await this.loadDatabases();
      } else if (v.startsWith("/")) {
        let db: BSimDatabase | undefined;
        try {
          db = (await this.host.rk.bsim.attachBSimDatabase({ projectId: this.host.projectId, path: v, provenance: userProvenance("attach BSim database") })).database;
        } catch {
          db = (await this.host.rk.bsim.createBSimDatabase({ projectId: this.host.projectId, path: v, provenance: userProvenance("create BSim database") })).database;
        }
        toast(`Attached ${db?.name}`);
        await this.loadDatabases(db?.id);
      } else {
        const db = (await this.host.rk.bsim.createBSimDatabase({ projectId: this.host.projectId, name: v, provenance: userProvenance("create BSim database") })).database;
        toast(`Created ${db?.name}`);
        await this.loadDatabases(db?.id);
      }
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }
}
