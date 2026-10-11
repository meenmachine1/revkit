// Compare: version tracking between two programs of the project
// (DiffService, docs/diff.md). Tools → Compare (the palette) picks the
// analysed program (A) and the new one (B) and runs a session with
// progress; this view is its match table (sortable, filtered by tier,
// confidence, status and change kind, coloured by confidence; a accepts,
// r rejects the selected match; "what changed" summarizes each modified
// pair) over what changed inside the selected pair (feature diff-detail):
// both listings aligned by the instruction map with the changes
// highlighted, n / p to the next and previous difference (AlignedListing);
// Space switches to the graph diff (DiffGraphView) and the decompiled C
// (DiffCView). "Apply markup…" ports names, comments and prototypes from A
// to B as one revision; it can be undone (Ctrl+Z when B is this tab's
// program, or the run's Undo).
//
// Feature function-compare (api_minor 54): any two functions, in one
// program or two, without a session (openFunctions: Compare with… from a
// function's context menu or the function list), shown in the same panes;
// manual matching (m: match by hand, u: unmatch, a / r, a row's context
// menu, a candidate's button), each decision one undo step; token-level
// apply in the C pane (DiffCView).

import {
  DiffApplyPolicy,
  DiffChangeKind,
  DiffMarkupItem,
  DiffMatchStatus,
  DiffRunState,
  DiffSort,
  DiffTier,
  DiffUnmatchedReason,
  type DiffCandidate,
  type DiffCounts,
  type DiffMatch,
  type DiffSessionInfo,
  type DiffUnmatched,
  type ListingRow,
  type ProgramInfo,
  type Revkit,
} from "@revkit/api";
import { userProvenance } from "../api/client";
import type { Edits } from "../data/edits";
import { errText, hex } from "../data/format";
import type { Theme } from "../listing/theme";
import { toast } from "../ui/dialogs";
import { h, overlayRoot, prefs, typing } from "../ui/dom";
import { showMenu, type MenuItem } from "../ui/menu";
import { AlignedListing } from "./aligned";
import { DiffCView } from "./decomp";
import { DiffLineStatus, fetchDetail, forgetDetails, type PairDetail } from "./detail";
import { DiffGraphView } from "./graph";
import { pickFunction, type PickedFunction } from "./pick";

export interface DiffHost {
  rk: Revkit;
  projectId: string;
  /** This tab's program. */
  programId: string;
  addrWidth: number;
  /** Undo in this tab (Ctrl+Z) for an apply run on this tab's program. */
  edits: Edits;
  /** Shows an address of this tab's program. */
  navigate: (address: bigint) => void;
  /** Waits until this tab has applied a revision. */
  settle: (revision: bigint) => Promise<void>;
  theme: () => Theme;
  font: string;
  /** The daemon explains what changed inside a pair (feature diff-detail). */
  detail: boolean;
  /** The pair shown changed (the dockable Graph diff follows it). */
  onPair?: (pd: PairDetail | null, message: string) => void;
  /** Any two functions, manual matching's Unmatch, token-level apply (feature function-compare). */
  compare?: boolean;
}

type Lower = "listing" | "graph" | "c";

const TIER_NAMES: Record<number, string> = {
  [DiffTier.ACCEPTED]: "accepted",
  [DiffTier.NAME]: "name",
  [DiffTier.BYTES]: "bytes",
  [DiffTier.PCODE]: "p-code",
  [DiffTier.SHAPE_REFS]: "shape+refs",
  [DiffTier.SHAPE]: "shape",
  [DiffTier.REFS]: "refs",
  [DiffTier.CALL_ORDER]: "call order",
  [DiffTier.LONE]: "lone",
  [DiffTier.SIMILARITY]: "similarity",
  [DiffTier.NEIGHBOUR]: "neighbour",
};
const STATUS_NAMES: Record<number, string> = {
  [DiffMatchStatus.PROPOSED]: "proposed",
  [DiffMatchStatus.ACCEPTED]: "accepted",
  [DiffMatchStatus.APPLIED]: "applied",
};
const CHANGE_NAMES: Record<number, string> = {
  [DiffChangeKind.UNCHANGED]: "unchanged",
  [DiffChangeKind.MODIFIED]: "modified",
  [DiffChangeKind.ADDED]: "added",
  [DiffChangeKind.REMOVED]: "removed",
};
const REASON_NAMES: Record<number, string> = {
  [DiffUnmatchedReason.NO_CANDIDATE]: "no candidate",
  [DiffUnmatchedReason.TIE]: "tie",
  [DiffUnmatchedReason.WEAK]: "weak candidates",
};

/** Auto-apply threshold: matches at or above it are ported by default. */
const AUTO = 0.95;
const PAGE = 2000;

export function confidenceClass(c: number): string {
  return c >= AUTO ? "c-high" : c >= 0.8 ? "c-mid" : "c-low";
}

type Mode = "matches" | "unmatched-a" | "unmatched-b";

export class DiffView {
  readonly el: HTMLElement;
  private session: DiffSessionInfo | null = null;
  private rerunBtn!: HTMLButtonElement;
  private applyBtn!: HTMLButtonElement;
  private sessions: DiffSessionInfo[] = [];
  private rows: DiffMatch[] = [];
  private unmatched: DiffUnmatched[] = [];
  private counts: DiffCounts | null = null;
  private total = 0;
  private next = "";
  private selected = -1;
  private sort = DiffSort.ADDRESS_A;
  private descending = false;
  private mode: Mode = "matches";
  private loaded = false;
  private stale = false;
  private seq = 0;
  private poll = 0;
  private lastRun = "";
  private sessionSel: HTMLSelectElement;
  private status: HTMLElement;
  private table: HTMLElement;
  private list: HTMLElement;
  private more: HTMLButtonElement;
  private tierSel: HTMLSelectElement;
  private statusSel: HTMLSelectElement;
  private changeSel: HTMLSelectElement;
  private minConf: HTMLInputElement;
  private nameFilter: HTMLInputElement;
  private modeSel: HTMLSelectElement;
  private sideHeads: [HTMLElement, HTMLElement];
  private filterTimer = 0;
  readonly listing: AlignedListing;
  readonly graph: DiffGraphView;
  readonly cview: DiffCView;
  private lower: Lower = "listing";
  private lowerBtns: Record<Lower, HTMLButtonElement>;
  private count: HTMLElement;
  private shown: PairDetail | null = null;
  private shownMessage = "";
  private sideSeq = 0;
  /** Change summaries by "a:b" (SummarizeFunctionDiffs), for the table. */
  private summaries = new Map<string, string>();
  /** Two functions compared outside a session (openFunctions), or null. */
  private adhoc: { a: PickedFunction; b: PickedFunction } | null = null;
  private adhocHead: HTMLElement;

  constructor(
    root: HTMLElement,
    private host: DiffHost,
  ) {
    this.el = root;
    this.sessionSel = h("select", { class: "filter select", "aria-label": "Comparison", "data-testid": "diff-session" });
    this.sessionSel.addEventListener("change", () => {
      const s = this.sessions.find((x) => x.sessionId === this.sessionSel.value);
      if (s) void this.open(s);
    });
    this.status = h("span", { class: "dim diff-status", "data-testid": "diff-status" });
    const compare = h("button", { class: "btn small", "data-testid": "diff-new", text: "Compare…", onclick: () => void this.compare() });
    const apply = (this.applyBtn = h("button", { class: "btn small", "data-testid": "diff-apply", text: "Apply markup…", onclick: () => void this.applyDialog() }));
    const rerun = (this.rerunBtn = h("button", { class: "btn small", title: "Run again (incremental after edits)", text: "Re-run", onclick: () => void this.run() }));
    this.tierSel = h(
      "select",
      { class: "filter select", "aria-label": "Tier", "data-testid": "diff-tier" },
      h("option", { value: "" }, "All tiers"),
      ...Object.entries(TIER_NAMES).map(([v, n]) => h("option", { value: v }, n)),
    );
    this.statusSel = h(
      "select",
      { class: "filter select", "aria-label": "Status", "data-testid": "diff-status-filter" },
      h("option", { value: "" }, "Any status"),
      ...Object.entries(STATUS_NAMES).map(([v, n]) => h("option", { value: v }, n)),
    );
    this.changeSel = h(
      "select",
      { class: "filter select", "aria-label": "Change", "data-testid": "diff-change" },
      h("option", { value: "" }, "Any change"),
      h("option", { value: String(DiffChangeKind.UNCHANGED) }, "unchanged"),
      h("option", { value: String(DiffChangeKind.MODIFIED) }, "modified"),
    );
    this.minConf = h("input", { class: "filter diff-conf", type: "number", min: "0", max: "1", step: "0.05", value: "0", title: "Least confidence", "aria-label": "Least confidence", "data-testid": "diff-min-conf" });
    this.nameFilter = h("input", { class: "filter diff-name", placeholder: "Name contains", spellcheck: "false", "aria-label": "Name filter", "data-testid": "diff-filter" });
    this.modeSel = h(
      "select",
      { class: "filter select", "aria-label": "Show", "data-testid": "diff-mode" },
      h("option", { value: "matches" }, "Matches"),
      h("option", { value: "unmatched-a" }, "Only in A"),
      h("option", { value: "unmatched-b" }, "Only in B"),
    );
    for (const el of [this.tierSel, this.statusSel, this.changeSel, this.modeSel]) el.addEventListener("change", () => this.refilter());
    for (const el of [this.minConf, this.nameFilter])
      el.addEventListener("input", () => {
        clearTimeout(this.filterTimer);
        this.filterTimer = window.setTimeout(() => this.refilter(), 150);
      });
    this.list = h("div", { class: "diff-rows" });
    this.more = h("button", { class: "btn small diff-more", text: "Load more", hidden: true, onclick: () => void this.load(true) });
    this.table = h("div", { class: "diff-table", tabindex: "0", role: "grid", "aria-label": "Matches", "data-testid": "diff-table" }, this.list, this.more);
    this.table.addEventListener("keydown", (e) => this.onKey(e));
    this.table.addEventListener("mousedown", (e) => {
      const row = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (row) this.select(Number(row.dataset.i));
    });
    this.table.addEventListener("contextmenu", (e) => {
      const row = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (!row) return;
      e.preventDefault();
      this.select(Number(row.dataset.i));
      showMenu(this.rowMenu(), e.clientX, e.clientY, "Match actions");
    });
    this.list.addEventListener("click", (e) => {
      const b = (e.target as HTMLElement).closest<HTMLElement>("[data-cand]");
      if (!b) return;
      e.stopPropagation();
      const u = this.unmatched[Number(b.closest<HTMLElement>("[data-i]")?.dataset.i)];
      const c = u?.candidates[Number(b.dataset.cand)];
      if (!u || !c) return;
      const mine = u.function?.entry?.offset, theirs = c.function?.entry?.offset;
      void (this.mode === "unmatched-b" ? this.matchUnmatched(theirs, mine) : this.matchUnmatched(mine, theirs));
    });
    this.table.addEventListener("dblclick", (e) => {
      const row = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (row) this.goToSelected();
    });
    this.sideHeads = [h("span", { class: "diff-side-head mono", "data-testid": "diff-head-a" }, "A"), h("span", { class: "diff-side-head mono right", "data-testid": "diff-head-b" }, "B")];
    this.listing = new AlignedListing(host.addrWidth);
    this.graph = new DiffGraphView(host.theme(), host.font, "Graph diff");
    this.cview = new DiffCView({
      rk: host.rk,
      projectId: host.projectId,
      port: !!host.compare,
      onPorted: (r) => {
        this.recordUndo(r.toProgram, r.label, r.seqs);
        forgetDetails();
        if (this.adhoc) void this.renameAdhoc();
        else if (this.session) void this.load();
      },
    });
    this.count = h("span", { class: "diff-count dim", "data-testid": "diff-count" });
    this.listing.onHunk = (cur, total) => this.showCount(cur, total);
    this.listing.onSelect = (sel) => {
      this.graph.selectRow(sel.side, sel.row);
      this.cview.selectAddress(sel.side, sel.address);
    };
    this.graph.onSelectBlock = (side, block) => this.revealBlock(side, block);
    this.cview.onSelect = (side, address) => this.revealAddress(side, address);
    const nav = (label: string, title: string, dir: 1 | -1, testid: string) =>
      h("button", { class: "btn small", title, "data-testid": testid, onclick: () => this.goDiff(dir) }, label);
    const tab = (id: Lower, label: string, title: string) => h("button", { class: "btn small seg", title, "data-testid": `diff-show-${id}`, onclick: () => this.setLower(id) }, label);
    this.lowerBtns = {
      listing: tab("listing", "Listing", "Both listings, aligned (Space: the graph)"),
      graph: tab("graph", "Graph", "Both graphs, coloured by what changed (Space: the listing)"),
      c: tab("c", "C", "Both functions decompiled, changed lines highlighted"),
    };
    const split = h(
      "div",
      { class: "diff-split", "data-testid": "diff-split" },
      h(
        "div",
        { class: "diff-lower-head" },
        this.sideHeads[0],
        h(
          "span",
          { class: "diff-nav" },
          nav("\u2191", "Previous difference (p)", -1, "diff-prev"),
          this.count,
          nav("\u2193", "Next difference (n)", 1, "diff-next"),
          h("span", { class: "seg-group" }, this.lowerBtns.listing, this.lowerBtns.graph, this.lowerBtns.c),
        ),
        this.sideHeads[1],
      ),
      h("div", { class: "diff-lower-body" }, this.listing.el, this.graph.el, this.cview.el),
    );
    root.addEventListener("keydown", (e) => this.onLowerKey(e));
    this.adhocHead = h("div", { class: "diff-adhoc-head", "data-testid": "diff-adhoc", hidden: true });
    root.append(
      h("div", { class: "panel-head view-head" }, h("span", { class: "panel-title" }, "Compare"), this.sessionSel, this.status, h("span", { class: "spacer" }), rerun, apply, compare),
      this.adhocHead,
      h("div", { class: "fn-filter diff-filters" }, this.modeSel, this.tierSel, this.statusSel, this.changeSel, this.minConf, this.nameFilter),
      this.header(),
      this.table,
      split,
    );
    const saved = prefs.get("rk.diff.lower");
    this.setLower(saved === "graph" || saved === "c" ? saved : "listing", false);
    this.paintSides(null);
  }

  // ------------------------------------------------------------ sessions --

  /** First shown: the newest session with this program. */
  async ensureLoaded() {
    if (this.loaded && !this.stale) return;
    this.loaded = true;
    await this.loadSessions();
    if (this.session) await this.load();
  }

  private async loadSessions(pick?: string) {
    try {
      const r = await this.host.rk.diff.listDiffSessions({ projectId: this.host.projectId, programId: this.host.programId });
      this.sessions = r.sessions;
    } catch (e) {
      this.status.textContent = errText(e);
      return;
    }
    const want = pick ?? this.session?.sessionId ?? this.sessions[0]?.sessionId;
    this.sessionSel.replaceChildren(
      ...(this.sessions.length ? this.sessions : []).map((s) => h("option", { value: s.sessionId }, `${s.name} · ${s.sessionId}`)),
    );
    // Nothing to run again or apply until there is a comparison.
    this.rerunBtn.disabled = this.applyBtn.disabled = this.sessionSel.disabled = !this.sessions.length;
    if (!this.sessions.length) {
      this.sessionSel.append(h("option", { value: "" }, "No comparison yet"));
      this.session = null;
      this.status.textContent = "";
      this.list.replaceChildren(h("div", { class: "dim diff-empty" }, "Compare this program with another one of the project: Compare… (or the palette's “Compare programs”)."));
      return;
    }
    this.sessionSel.value = want ?? "";
    this.session = this.sessions.find((s) => s.sessionId === want) ?? this.sessions[0];
    this.showRun();
  }

  private async open(s: DiffSessionInfo) {
    this.leaveFunctions();
    this.session = s;
    this.selected = -1;
    this.showRun();
    await this.load();
  }

  /** Tools → Compare: pick A and B, create a session and run it. */
  async compare() {
    let programs: ProgramInfo[] = [];
    try {
      programs = (await this.host.rk.projects.listPrograms({ projectId: this.host.projectId })).programs;
    } catch (e) {
      return toast(errText(e), { kind: "error" });
    }
    if (programs.length < 2) return toast("Import another program into the project to compare with (Ctrl+O)", { kind: "error" });
    const choice = await compareDialog(programs, this.host.programId);
    if (!choice) return;
    try {
      const r = await this.host.rk.diff.createDiffSession({
        projectId: this.host.projectId,
        programA: choice.a,
        programB: choice.b,
        name: choice.name,
        options: { similarityTiers: choice.similarity ? ["bsim"] : [] },
        run: true,
        provenance: userProvenance("compare"),
      });
      this.leaveFunctions();
      await this.loadSessions(r.session?.sessionId);
      this.status.textContent = "starting…";
      this.watch();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  /** Shows a session made elsewhere (Compare with original) and follows its run. */
  async openSession(sessionId: string) {
    this.leaveFunctions();
    await this.loadSessions(sessionId);
    this.watch();
  }

  /** Runs the session again (after edits: only what changed is recomputed). */
  async run() {
    if (!this.session) return;
    try {
      await this.host.rk.diff.runDiff({ projectId: this.host.projectId, sessionId: this.session.sessionId });
      this.watch();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  /** Polls the run until it ends, showing its phase, then loads the table. */
  private watch() {
    clearTimeout(this.poll);
    const tick = async () => {
      if (!this.session) return;
      try {
        const st = await this.host.rk.diff.getDiffStatus({ projectId: this.host.projectId, sessionId: this.session.sessionId });
        if (st.session) this.session = st.session;
        this.showRun();
        if (st.session?.run?.state === DiffRunState.RUNNING) {
          this.poll = window.setTimeout(() => void tick(), 150);
          return;
        }
        if (st.session?.run?.state === DiffRunState.FAILED) toast(`Compare failed: ${st.session.run.message}`, { kind: "error" });
        await this.load();
      } catch (e) {
        this.status.textContent = errText(e);
      }
    };
    void tick();
  }

  private showRun() {
    const run = this.session?.run;
    if (!run) return;
    const counts = this.counts;
    if (run.state === DiffRunState.RUNNING) {
      this.status.textContent = `${run.phase} (${Math.round(run.progress * 100)}%)`;
      this.status.dataset.state = "running";
    } else {
      this.status.dataset.state = run.state === DiffRunState.SUCCEEDED ? "done" : "idle";
      this.status.textContent = counts
        ? `${counts.matched} matched (${counts.autoMatches} ≥ ${AUTO}, ${counts.unchanged} unchanged) · ${counts.unmatchedA} only in A · ${counts.unmatchedB} only in B`
        : run.state === DiffRunState.FAILED
          ? `failed: ${run.message}`
          : "";
    }
    this.status.title = this.session ? `${this.session.programA} (A) → ${this.session.programB} (B)` : "";
  }

  /** A DIFF_SESSION invalidation: reload when shown (else on show). */
  invalidate(sessionId: string) {
    // What changed inside pairs may have too (a decision retargets calls).
    forgetDetails();
    if (this.adhoc) return;
    this.summaries.clear();
    this.shown = null;
    if (!this.session || sessionId !== this.session.sessionId) {
      this.stale = true;
      return;
    }
    if (this.el.offsetParent !== null) void this.load();
    else this.stale = true;
  }

  // ---------------------------------------------------------------- table --

  private header(): HTMLElement {
    const col = (label: string, sort: DiffSort | null, cls: string) => {
      const el = h("span", { class: cls + (sort !== null ? " sortable" : ""), title: sort !== null ? "Sort" : "" }, label);
      if (sort !== null)
        el.addEventListener("click", () => {
          if (this.sort === sort) this.descending = !this.descending;
          else {
            this.sort = sort;
            this.descending = sort === DiffSort.CONFIDENCE || sort === DiffSort.SIMILARITY;
          }
          void this.load();
        });
      return el;
    };
    return h(
      "div",
      { class: "diff-row diff-head dim", "data-testid": "diff-head" },
      col("A", DiffSort.NAME_A, "d-name"),
      col("at", DiffSort.ADDRESS_A, "d-addr"),
      col("B", DiffSort.NAME_B, "d-name"),
      col("at", DiffSort.ADDRESS_B, "d-addr"),
      col("tier", DiffSort.TIER, "d-tier"),
      col("conf", DiffSort.CONFIDENCE, "d-conf"),
      col("sim", DiffSort.SIMILARITY, "d-sim"),
      col("status", DiffSort.STATUS, "d-st"),
      col("change", null, "d-ch"),
      col("what changed", null, "d-sum"),
    );
  }

  private refilter() {
    this.mode = this.modeSel.value as Mode;
    void this.load();
  }

  /** Loads (or with `more`, continues) the table at head. */
  async load(more = false) {
    if (!this.session) return;
    this.stale = false;
    const seq = ++this.seq;
    const s = this.session;
    try {
      if (this.mode !== "matches") {
        const r = await this.host.rk.diff.listUnmatched({
          projectId: this.host.projectId,
          sessionId: s.sessionId,
          side: this.mode === "unmatched-a" ? 1 : 2,
          nameContains: this.nameFilter.value.trim(),
          maxCandidates: 4,
          page: { pageSize: PAGE, pageToken: more ? this.next : "" },
        });
        if (seq !== this.seq) return;
        this.unmatched = more ? [...this.unmatched, ...r.functions] : r.functions;
        this.rows = [];
        this.next = r.page?.nextPageToken ?? "";
        this.total = Number(r.page?.totalCount ?? this.unmatched.length);
      } else {
        const tier = Number(this.tierSel.value);
        const status = Number(this.statusSel.value);
        const change = Number(this.changeSel.value);
        const r = await this.host.rk.diff.listMatches({
          projectId: this.host.projectId,
          sessionId: s.sessionId,
          filter: {
            tiers: tier ? [tier] : [],
            statuses: status ? [status] : [],
            changeKinds: change ? [change] : [],
            minConfidence: Number(this.minConf.value) || 0,
            nameContains: this.nameFilter.value.trim(),
          },
          sort: this.sort,
          descending: this.descending,
          page: { pageSize: PAGE, pageToken: more ? this.next : "" },
        });
        if (seq !== this.seq) return;
        this.rows = more ? [...this.rows, ...r.matches] : r.matches;
        this.unmatched = [];
        this.counts = r.counts ?? null;
        this.next = r.page?.nextPageToken ?? "";
        this.total = Number(r.page?.totalCount ?? this.rows.length);
      }
    } catch (e) {
      if (seq === this.seq) this.list.replaceChildren(h("div", { class: "error diff-empty" }, errText(e)));
      return;
    }
    this.showRun();
    this.paint();
    if (this.selected >= this.length()) this.selected = this.length() - 1;
    if (this.selected < 0 && this.length() > 0) this.selected = 0;
    this.highlight();
    void this.loadSides();
    void this.loadSummaries();
  }

  private length() {
    return this.mode === "matches" ? this.rows.length : this.unmatched.length;
  }

  private paint() {
    const w = this.host.addrWidth;
    if (this.mode === "matches") {
      this.list.replaceChildren(
        ...this.rows.map((m, i) =>
          h(
            "div",
            { class: `diff-row ${confidenceClass(m.confidence)}`, "data-i": i, "data-testid": "diff-row", title: m.evidence?.detail ?? "" },
            h("span", { class: "d-name" + (m.a?.defaultName ? " dim" : "") }, m.a?.name ?? ""),
            h("span", { class: "d-addr dim" }, hex(m.a?.entry?.offset ?? 0n, w)),
            h("span", { class: "d-name" + (m.b?.defaultName ? " dim" : "") }, m.b?.name ?? ""),
            h("span", { class: "d-addr dim" }, hex(m.b?.entry?.offset ?? 0n, w)),
            h("span", { class: "d-tier" }, TIER_NAMES[m.tier] ?? "?"),
            h("span", { class: "d-conf" }, h("i", { class: "conf-bar", style: `width:${Math.round(m.confidence * 100)}%` }), m.confidence.toFixed(2)),
            h("span", { class: "d-sim dim" }, m.similarity.toFixed(2)),
            h("span", { class: `d-st st-${STATUS_NAMES[m.status] ?? "x"}`, "data-testid": "diff-row-status" }, STATUS_NAMES[m.status] ?? "?"),
            h("span", { class: "d-ch dim" }, CHANGE_NAMES[m.changeKind] ?? ""),
            this.summaryCell(m),
          ),
        ),
      );
    } else {
      this.list.replaceChildren(
        ...this.unmatched.map((u, i) =>
          h(
            "div",
            { class: "diff-row unmatched", "data-i": i, "data-testid": "diff-row" },
            h("span", { class: "d-name" + (u.function?.defaultName ? " dim" : "") }, u.function?.name ?? ""),
            h("span", { class: "d-addr dim" }, hex(u.function?.entry?.offset ?? 0n, w)),
            h(
              "span",
              { class: "d-cands dim" },
              REASON_NAMES[u.reason] ?? "",
              ...u.candidates.slice(0, 3).map((c, k) =>
                h("button", { class: "link diff-cand", "data-cand": k, "data-testid": "diff-cand", title: `Match by hand with ${c.function?.name} (or m: pick any function)` }, `${c.function?.name} ${c.score.toFixed(2)}`),
              ),
            ),
          ),
        ),
      );
    }
    this.more.hidden = !this.next;
    this.more.textContent = `Load more (${this.length()} of ${this.total})`;
    if (!this.length()) this.list.append(h("div", { class: "dim diff-empty" }, this.mode === "matches" ? "No matches with these filters." : "Every function has a match."));
  }

  private summaryCell(m: DiffMatch): HTMLElement {
    if (m.changeKind !== DiffChangeKind.MODIFIED || !m.a?.entry || !m.b?.entry) return h("span", { class: "d-sum dim" });
    const k = `${m.a.entry.offset}:${m.b.entry.offset}`;
    const t = this.summaries.get(k) ?? "";
    return h("span", { class: "d-sum", "data-pair": k, "data-testid": "diff-row-summary", title: t }, t);
  }

  private select(i: number) {
    if (i < 0 || i >= this.length()) return;
    this.selected = i;
    this.highlight();
    void this.loadSides();
  }

  private highlight() {
    for (const el of this.list.querySelectorAll<HTMLElement>(".diff-row.active")) el.classList.remove("active");
    const el = this.list.querySelector<HTMLElement>(`[data-i="${this.selected}"]`);
    el?.classList.add("active");
    el?.scrollIntoView({ block: "nearest" });
  }

  focus() {
    this.table.focus({ preventScroll: true });
  }

  /** Shows a pair by its entries (the benchmark, scripts): the session's, matched or not. */
  async openPair(a: bigint, b: bigint): Promise<PairDetail | null> {
    const s = this.session;
    if (!s) return null;
    const pd = await fetchDetail(this.host.rk, this.host.projectId, { sessionId: s.sessionId, a, b, nameA: hex(a), nameB: hex(b), programA: s.programA, programB: s.programB });
    this.sideSeq++;
    this.show(pd);
    return pd;
  }

  /** The pair shown below the table (the dockable Graph diff starts from it). */
  shownPair(): PairDetail | null {
    return this.shown;
  }

  /** The selected match, if the table shows matches. */
  selectedMatch(): DiffMatch | null {
    return this.mode === "matches" ? (this.rows[this.selected] ?? null) : null;
  }

  private onKey(e: KeyboardEvent) {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const stop = () => {
      e.preventDefault();
      e.stopPropagation();
    };
    switch (e.key) {
      case "ArrowDown":
      case "j":
        stop();
        return this.select(Math.min(this.length() - 1, this.selected + 1));
      case "ArrowUp":
      case "k":
        stop();
        return this.select(Math.max(0, this.selected - 1));
      case "a":
        stop();
        return void this.accept();
      case "r":
        stop();
        return void this.reject();
      case "u":
        stop();
        return void this.unmatch();
      case "m":
        stop();
        return void this.matchWith();
      case "Enter":
        stop();
        return this.goToSelected();
    }
  }

  /** Accepts the selected match (a). */
  async accept() {
    const m = this.selectedMatch();
    if (!m || !this.session) return;
    try {
      const r = await this.host.rk.diff.acceptMatches({
        projectId: this.host.projectId,
        sessionId: this.session.sessionId,
        pairs: [{ entryA: m.a?.entry, entryB: m.b?.entry }],
        provenance: userProvenance("accepted in Compare"),
      });
      this.recordUndo(this.session.programB, `Accept ${m.a?.name} → ${m.b?.name}`, r.seqs);
      const next = this.selected + 1;
      await this.load();
      this.select(Math.min(next, this.length() - 1));
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  /** Rejects the selected match (r): it is never proposed again. */
  async reject() {
    const m = this.selectedMatch();
    if (!m || !this.session) return;
    try {
      const r = await this.host.rk.diff.rejectMatches({
        projectId: this.host.projectId,
        sessionId: this.session.sessionId,
        pairs: [{ entryA: m.a?.entry, entryB: m.b?.entry }],
        provenance: userProvenance("rejected in Compare"),
      });
      this.recordUndo(this.session.programB, `Reject ${m.a?.name} → ${m.b?.name}`, r.seqs);
      const at = this.selected;
      await this.load();
      this.select(Math.min(at, this.length() - 1));
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  /** u: undoes the decision on the selected match (accepted, applied): the matcher's proposal again. */
  async unmatch() {
    const m = this.selectedMatch();
    if (!m || !this.session) return;
    if (!this.host.compare) return toast("This daemon can't unmatch (feature function-compare)", { kind: "error" });
    if (m.status === DiffMatchStatus.PROPOSED) return toast("A proposed match has no decision to undo: r rejects it", { kind: "error" });
    try {
      const r = await this.host.rk.diff.unmatch({
        projectId: this.host.projectId,
        sessionId: this.session.sessionId,
        pairs: [{ entryA: m.a?.entry, entryB: m.b?.entry }],
        provenance: userProvenance("unmatched in Compare"),
      });
      this.recordUndo(this.session.programB, `Unmatch ${m.a?.name} → ${m.b?.name}`, r.seqs);
      const at = this.selected;
      await this.load();
      this.select(Math.min(at, this.length() - 1));
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  /** m: matches the selected function by hand with one picked on the other side (SetMatch). */
  async matchWith() {
    const s = this.session;
    if (!s) return;
    const m = this.selectedMatch();
    const u = this.mode !== "matches" ? this.unmatched[this.selected] : null;
    // From A's side unless the row is B's (Only in B).
    const fromB = this.mode === "unmatched-b";
    const mine = m ? m.a : u?.function;
    const entry = mine?.entry?.offset;
    if (entry === undefined) return;
    const programs = await this.programInfos();
    const other = fromB ? s.programA : s.programB;
    const suggestions = (u?.candidates ?? []).map((c: DiffCandidate) => ({ entry: c.function?.entry?.offset ?? 0n, name: c.function?.name ?? "", detail: `candidate ${c.score.toFixed(2)}${c.matched ? " (matched)" : ""}` }));
    const picked = await pickFunction(this.host.rk, {
      title: `Match ${mine?.name} (${fromB ? "B" : "A"}) by hand with a function of ${other}`,
      programs: programs.filter((p) => p.programId === other),
      program: other,
      suggestions,
      testid: "match-with",
      hint: "The match replaces any either function had; u undoes it.",
    });
    if (!picked) return;
    await (fromB ? this.matchUnmatched(picked.entry, entry) : this.matchUnmatched(entry, picked.entry));
  }

  /** Matches A's function with B's by hand (SetMatch): one undo step. */
  async matchUnmatched(a: bigint | undefined, b: bigint | undefined) {
    const s = this.session;
    if (!s || a === undefined || b === undefined) return;
    try {
      const r = await this.host.rk.diff.setMatch({
        projectId: this.host.projectId,
        sessionId: s.sessionId,
        entryA: { offset: a },
        entryB: { offset: b },
        provenance: userProvenance("matched by hand in Compare"),
      });
      this.recordUndo(s.programB, `Match ${hex(a)} → ${hex(b)}`, r.seqs);
      toast(`Matched ${hex(a)} with ${hex(b)} by hand`);
      await this.load();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  /** A row's context menu: the decisions on it. */
  private rowMenu(): MenuItem[] {
    const m = this.selectedMatch();
    if (m) {
      const decided = m.status !== DiffMatchStatus.PROPOSED;
      return [
        { label: "Accept", keys: "a", disabled: m.status === DiffMatchStatus.ACCEPTED, testid: "diff-menu-accept", run: () => this.accept() },
        { label: "Reject (never propose this pair again)", keys: "r", testid: "diff-menu-reject", run: () => this.reject() },
        { label: "Unmatch (undo the decision)", keys: "u", disabled: !decided || !this.host.compare, testid: "diff-menu-unmatch", run: () => this.unmatch() },
        { label: "Match A's function with…", keys: "m", testid: "diff-menu-match", run: () => this.matchWith() },
        { label: "Go to it", keys: "Enter", separator: true, testid: "diff-menu-go", run: () => this.goToSelected() },
      ];
    }
    const u = this.unmatched[this.selected];
    if (!u) return [];
    const fromB = this.mode === "unmatched-b";
    return [
      ...u.candidates.slice(0, 6).map((c, k) => ({
        label: `Match with ${c.function?.name} (${c.score.toFixed(2)})`,
        testid: `diff-menu-cand-${k}`,
        run: () => (fromB ? this.matchUnmatched(c.function?.entry?.offset, u.function?.entry?.offset) : this.matchUnmatched(u.function?.entry?.offset, c.function?.entry?.offset)),
      })),
      { label: "Match with…", keys: "m", separator: u.candidates.length > 0, testid: "diff-menu-match", run: () => this.matchWith() },
    ];
  }

  /** One undo step for an edit of `program`: Ctrl+Z when it is this tab's, and the toast's Undo. */
  recordUndo(program: string, label: string, seqs: bigint[]) {
    if (!seqs.length) return;
    if (program === this.host.programId) this.host.edits.record(label, seqs);
    toast(label, {
      action: {
        label: "Undo",
        run: async () => {
          try {
            await this.host.rk.assertions.retractAssertions({ programId: program, seqs, provenance: userProvenance("undo") });
            forgetDetails();
            DiffCView.forget(program);
            if (this.adhoc) void this.renameAdhoc();
            else void this.load();
            void this.cview.refresh();
          } catch (e) {
            toast(errText(e), { kind: "error" });
          }
        },
      },
      ms: 8000,
    });
  }

  private programs: ProgramInfo[] | null = null;
  private async programInfos(): Promise<ProgramInfo[]> {
    if (!this.programs) this.programs = (await this.host.rk.projects.listPrograms({ projectId: this.host.projectId })).programs;
    return this.programs;
  }

  // ------------------------------------------------------- two functions --

  /** Compare with…: picks the other function (any program of the project) and shows the pair. */
  async compareWith(from: PickedFunction) {
    let programs: ProgramInfo[];
    try {
      this.programs = null;
      programs = await this.programInfos();
    } catch (e) {
      return toast(errText(e), { kind: "error" });
    }
    const other = await pickFunction(this.host.rk, {
      title: `Compare ${from.name} with…`,
      programs,
      program: from.programId,
      exclude: from,
      testid: "compare-with",
      hint: "Any function of any program of the project, this one's too. Both are shown aligned (listing, graph, C); right-click a C token to apply it to the other side.",
    });
    if (other) await this.openFunctions(from, other);
  }

  /** Shows two functions (A and B) outside any session: the listing, graph and C panes, no table. */
  async openFunctions(a: PickedFunction, b: PickedFunction) {
    this.adhoc = { a, b };
    this.el.classList.add("diff-adhoc");
    this.adhocHead.hidden = false;
    this.paintAdhoc();
    await this.showFunctions();
  }

  private paintAdhoc() {
    if (!this.adhoc) return;
    const { a, b } = this.adhoc;
    const swap = h("button", { class: "btn small", "data-testid": "diff-adhoc-swap", title: "Swap A and B", onclick: () => void this.openFunctions(b, a) }, "Swap");
    const back = h("button", { class: "btn small", "data-testid": "diff-adhoc-close", title: "Back to the comparison of programs", onclick: () => this.leaveFunctions(true) }, "Close");
    const side = (x: PickedFunction, k: string) => h("span", { class: "mono" }, h("b", {}, k), ` ${x.name} `, h("span", { class: "dim" }, `${hex(x.entry)} · ${x.programId}`));
    this.adhocHead.replaceChildren(h("span", { class: "dim" }, "Comparing functions:"), side(a, "A"), h("span", { class: "dim" }, "↔"), side(b, "B"), h("span", { class: "spacer" }), swap, back);
    this.sideHeads[0].textContent = `A · ${a.programId} · ${a.name}`;
    this.sideHeads[1].textContent = `B · ${b.programId} · ${b.name}`;
  }

  /** The two functions' names again (after a port renamed one). */
  private async renameAdhoc() {
    const x = this.adhoc;
    if (!x) return;
    try {
      const [fa, fb] = await Promise.all(
        [x.a, x.b].map((f) => this.host.rk.queries.getFunction({ programId: f.programId, address: { offset: f.entry } }).then((r) => r.function?.name ?? f.name)),
      );
      if (this.adhoc !== x) return;
      this.adhoc = { a: { ...x.a, name: fa }, b: { ...x.b, name: fb } };
      this.paintAdhoc();
    } catch {
      // The names stay as they were.
    }
  }

  private async showFunctions() {
    const x = this.adhoc;
    if (!x) return;
    const seq = ++this.sideSeq;
    try {
      const pd = await fetchDetail(this.host.rk, this.host.projectId, { sessionId: "", a: x.a.entry, b: x.b.entry, nameA: x.a.name, nameB: x.b.name, programA: x.a.programId, programB: x.b.programId });
      if (seq !== this.sideSeq || this.adhoc !== x) return;
      this.show(pd);
    } catch (e) {
      if (seq === this.sideSeq) this.show(null, errText(e));
    }
  }

  /** Back to the session's table. */
  leaveFunctions(reload = false) {
    if (!this.adhoc) return;
    this.adhoc = null;
    this.el.classList.remove("diff-adhoc");
    this.adhocHead.hidden = true;
    if (reload) void this.loadSides();
  }

  /** The two functions shown outside a session (tests, scripts). */
  shownFunctions() {
    return this.adhoc;
  }

  /** Enter: the selected function in this tab's program. */
  private goToSelected() {
    if (!this.session) return;
    const m = this.selectedMatch();
    const u = this.mode !== "matches" ? this.unmatched[this.selected] : null;
    const onB = this.session.programB === this.host.programId;
    const entry = m ? (onB ? m.b?.entry?.offset : m.a?.entry?.offset) : u?.function?.entry?.offset;
    const mine = m ? true : (this.mode === "unmatched-b") === onB;
    if (entry !== undefined && mine) this.host.navigate(entry);
  }

  // ----------------------------------------------------------- side by side --

  private async loadSides() {
    if (this.adhoc) return;
    const s = this.session;
    if (!s) return this.paintSides(null);
    const m = this.selectedMatch();
    const u = this.mode !== "matches" ? this.unmatched[this.selected] : null;
    const seq = ++this.sideSeq;
    const fresh = (): boolean => seq === this.sideSeq && this.session === s;
    if (m?.a?.entry && m.b?.entry) {
      this.sideHeads[0].textContent = `A · ${s.programA} · ${m.a.name}`;
      this.sideHeads[1].textContent = `B · ${s.programB} · ${m.b.name}`;
      if (!this.host.detail) return this.show(null, "This daemon doesn't explain what changed inside a pair (feature diff-detail).");
      if (this.shown && this.shown.pair.sessionId === s.sessionId && this.shown.pair.a === m.a.entry.offset && this.shown.pair.b === m.b.entry.offset) return;
      try {
        const pd = await fetchDetail(this.host.rk, this.host.projectId, {
          sessionId: s.sessionId,
          a: m.a.entry.offset,
          b: m.b.entry.offset,
          nameA: m.a.name,
          nameB: m.b.name,
          programA: s.programA,
          programB: s.programB,
        });
        if (!fresh()) return;
        this.show(pd);
      } catch (e) {
        if (fresh()) this.show(null, errText(e));
      }
      return;
    }
    // An unmatched function: its side's listing alone.
    const side: "a" | "b" = this.mode === "unmatched-a" ? "a" : "b";
    const entry = u?.function?.entry?.offset;
    this.sideHeads[0].textContent = side === "a" && u ? `A · ${s.programA} · ${u.function?.name}` : "A";
    this.sideHeads[1].textContent = side === "b" && u ? `B · ${s.programB} · ${u.function?.name}` : "B";
    if (entry === undefined) return this.show(null);
    const rows = await this.fetchFunction(side === "a" ? s.programA : s.programB, entry);
    if (!fresh()) return;
    if (!rows) return this.show(null, "—");
    this.show(onlyOneSide(side, rows, s.sessionId, entry));
  }

  /** Shows a pair (or a message) in the listing, the graph, the C, and the dockable graph diff. */
  private show(pd: PairDetail | null, message = "") {
    this.shown = pd;
    this.shownMessage = message;
    this.listing.set(pd, message);
    if (this.lower === "graph") void this.graph.set(pd, message);
    if (this.lower === "c") void this.cview.set(pd, message);
    this.host.onPair?.(pd, message);
    const sum = pd?.detail.summary;
    this.split().title = sum?.text ?? "";
    this.split().dataset.pair = pd ? `${hex(pd.pair.a)}:${hex(pd.pair.b)}` : "";
  }

  private split(): HTMLElement {
    return this.el.querySelector<HTMLElement>("[data-testid=diff-split]")!;
  }

  private showCount(cur: number, total: number) {
    const d = this.shown?.detail;
    const sum = d?.summary;
    if (!d) {
      this.count.textContent = "";
      return;
    }
    const what = sum ? [sum.changed && `${sum.changed} changed`, sum.inserted && `${sum.inserted} inserted`, sum.deleted && `${sum.deleted} deleted`].filter(Boolean).join(", ") : "";
    this.count.textContent = total === 0 ? "no differences" : `${cur >= 0 ? `${cur + 1}/` : ""}${total} difference${total === 1 ? "" : "s"}${what ? ` · ${what}` : ""}`;
    this.count.title = sum?.text ?? "";
    this.count.dataset.total = String(total);
    this.count.dataset.current = String(cur);
  }

  /** Next (+1) or previous (-1) difference: the listing scrolls to it, the graph and the C follow. */
  goDiff(dir: 1 | -1) {
    this.listing.go(dir);
    const d = this.shown?.detail;
    const k = this.listing.currentHunk;
    if (!d || k < 0) return;
    const l = d.lines[d.hunks[k]];
    const side: "a" | "b" = l.b >= 0 ? "b" : "a";
    const row = side === "b" ? l.b : l.a;
    this.graph.selectRow(side, row);
    const r = (side === "a" ? d.rowsA : d.rowsB)[row];
    if (r?.address) this.cview.selectAddress(side, r.address.offset);
  }

  /** The listing, the graph diff or the C below the table. */
  setLower(which: Lower, remember = true) {
    this.lower = which;
    if (remember) prefs.set("rk.diff.lower", which);
    for (const [k, b] of Object.entries(this.lowerBtns)) b.classList.toggle("on", k === which);
    this.listing.el.hidden = which !== "listing";
    this.graph.el.hidden = which !== "graph";
    this.cview.el.hidden = which !== "c";
    this.split().dataset.lower = which;
    if (which === "graph") {
      void this.graph.set(this.shown, this.shownMessage).then(() => this.graph.resize());
    }
    if (which === "c") void this.cview.set(this.shown, this.shownMessage);
  }

  /** A block was picked in a graph: its first row in the listing (and the partner's). */
  revealBlock(side: "a" | "b", block: number) {
    const d = this.shown?.detail;
    if (!d) return;
    const bl = (side === "a" ? d.blocksA : d.blocksB)[block];
    if (!bl) return;
    this.listing.select(side, bl.firstRow, true);
    this.graph.selectBlock(side, block, false);
    const r = (side === "a" ? d.rowsA : d.rowsB)[bl.firstRow];
    if (r?.address) this.cview.selectAddress(side, r.address.offset);
  }

  /** An instruction was picked in the C: its row in the listing and its block in the graph. */
  revealAddress(side: "a" | "b", address: bigint) {
    const d = this.shown?.detail;
    if (!d) return;
    const rows = side === "a" ? d.rowsA : d.rowsB;
    const row = rows.findIndex((r) => r.address?.offset === address);
    if (row < 0) return;
    this.listing.select(side, row, true);
    this.graph.selectRow(side, row);
  }

  /** n / p: differences; Space: listing or graph (not while typing in a filter). */
  private onLowerKey(e: KeyboardEvent) {
    if (e.ctrlKey || e.metaKey || e.altKey || typing()) return;
    if (document.querySelector(".backdrop")) return;
    const stop = () => {
      e.preventDefault();
      e.stopPropagation();
    };
    if (e.key === "n") {
      stop();
      this.goDiff(1);
    } else if (e.key === "p") {
      stop();
      this.goDiff(-1);
    } else if (e.key === " " && (e.target as HTMLElement).closest(".diff-split, .diff-table")) {
      stop();
      this.setLower(this.lower === "graph" ? "listing" : "graph");
    }
  }

  private async fetchFunction(programId: string, entry: bigint | undefined): Promise<ListingRow[] | null> {
    if (entry === undefined) return null;
    try {
      const r = await this.host.rk.queries.getListing({
        programId,
        window: { case: "addresses", value: { start: { offset: entry }, maxRows: 400, rowsBefore: 0 } },
        omitBytes: true,
      });
      return r.rows.filter((row) => row.function?.offset === entry && row.tokens.length > 0);
    } catch {
      return null;
    }
  }

  private paintSides(_: null) {
    this.sideHeads[0].textContent = "A";
    this.sideHeads[1].textContent = "B";
    this.show(null);
  }

  /** Loads "what changed" for the modified rows shown (SummarizeFunctionDiffs), a few hundred at a time. */
  private async loadSummaries() {
    const s = this.session;
    if (!s || !this.host.detail || this.mode !== "matches") return;
    const want = this.rows.filter((m) => m.changeKind === DiffChangeKind.MODIFIED && m.a?.entry && m.b?.entry && !this.summaries.has(`${m.a.entry.offset}:${m.b.entry.offset}`));
    for (let i = 0; i < want.length; i += 200) {
      const chunk = want.slice(i, i + 200);
      try {
        const r = await this.host.rk.diff.summarizeFunctionDiffs({
          projectId: this.host.projectId,
          sessionId: s.sessionId,
          pairs: chunk.map((m) => ({ entryA: m.a!.entry, entryB: m.b!.entry })),
        });
        if (this.session !== s) return;
        for (const x of r.summaries) this.summaries.set(`${x.entryA?.offset}:${x.entryB?.offset}`, x.text);
      } catch {
        return;
      }
      for (const el of this.list.querySelectorAll<HTMLElement>("[data-pair]")) {
        const t = this.summaries.get(el.dataset.pair!);
        if (t !== undefined && el.textContent !== t) {
          el.textContent = t;
          el.title = t;
        }
      }
    }
  }

  // ---------------------------------------------------------------- apply --

  /** The Apply dialog: items, threshold, policy, a preview; one revision. */
  async applyDialog() {
    const s = this.session;
    if (!s) return toast("No comparison: Compare… first", { kind: "error" });
    const sel = this.selectedMatch();
    const o = await applyDialog(this.host.rk, s, sel);
    if (!o) return;
    try {
      const r = await this.host.rk.diff.applyMarkup({ ...o, projectId: this.host.projectId, sessionId: s.sessionId, provenance: userProvenance("apply markup") });
      if (!r.runId) return toast("Nothing to port: B already has these names, comments and prototypes.");
      this.lastRun = r.runId;
      const what = `${r.names} names, ${r.comments} comments, ${r.prototypes} prototypes (${r.types} types)`;
      // On this tab's program, Ctrl+Z undoes it like any edit.
      if (s.programB === this.host.programId) this.host.edits.record(`Apply markup from ${s.programA}`, r.seqs);
      toast(`Ported ${what} over ${r.pairs} matches`, { action: { label: "Undo", run: () => void this.revert(r.runId) }, ms: 8000 });
      if (s.programB === this.host.programId && r.snapshot) await this.host.settle(r.snapshot.revision);
      await this.load();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  /** Undoes an apply run (RevertApply). */
  async revert(runId = this.lastRun) {
    const s = this.session;
    if (!s || !runId) return;
    try {
      await this.host.rk.diff.revertApply({ projectId: this.host.projectId, sessionId: s.sessionId, runId, provenance: userProvenance("undo apply") });
      toast("Apply run undone");
      await this.load();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }
}

// ------------------------------------------------------------------ dialogs --

interface CompareChoice {
  a: string;
  b: string;
  name: string;
  /** Match what's left after the exact tiers by p-code similarity (BSim). */
  similarity: boolean;
}

function compareDialog(programs: ProgramInfo[], current: string): Promise<CompareChoice | null> {
  return new Promise((resolve) => {
    const opt = (p: ProgramInfo) => h("option", { value: p.programId }, `${p.name} (${p.programId})`);
    const a = h("select", { class: "filter", "data-testid": "compare-a", "aria-label": "Program A (analysed)" }, ...programs.map(opt));
    const b = h("select", { class: "filter", "data-testid": "compare-b", "aria-label": "Program B (new)" }, ...programs.map(opt));
    b.value = current;
    a.value = programs.find((p) => p.programId !== current)?.programId ?? programs[0].programId;
    const name = h("input", { class: "filter", placeholder: "Name (optional)", spellcheck: "false", "aria-label": "Name" });
    const similarity = h("input", { type: "checkbox", checked: true, "data-testid": "compare-similarity" }) as HTMLInputElement;
    const err = h("div", { class: "ask-error" });
    const go = h("button", { class: "btn primary", type: "button", text: "Compare", "data-testid": "compare-go" });
    const cancel = h("button", { class: "btn", type: "button", text: "Cancel" });
    const box = h(
      "div",
      { class: "modal diff-dialog", role: "dialog", "aria-label": "Compare programs", "data-testid": "compare-dialog" },
      h("div", { class: "modal-title" }, "Compare programs (version tracking)"),
      h("label", { class: "ask-label dim" }, "A: the analysed program (names, comments and prototypes come from it)", a),
      h("label", { class: "ask-label dim" }, "B: the new program", b),
      name,
      h(
        "label",
        { class: "diff-check", title: "Signs only the functions the exact tiers leave unmatched; slower when the builds differ a lot (another compiler or -O level). Never applied automatically." },
        similarity,
        " Also match similar code (p-code signatures)",
      ),
      h("div", { class: "modal-hint" }, "Matches functions by fingerprints and their call graph; nothing changes in B until you apply markup."),
      err,
      h("div", { class: "diff-actions" }, cancel, go),
    );
    const backdrop = h("div", { class: "backdrop" }, box);
    const done = (v: CompareChoice | null) => {
      backdrop.remove();
      resolve(v);
    };
    go.onclick = () => {
      if (a.value === b.value) {
        err.textContent = "Pick two different programs";
        return;
      }
      done({ a: a.value, b: b.value, name: name.value.trim(), similarity: similarity.checked });
    };
    cancel.onclick = () => done(null);
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") done(null);
      if (e.key === "Enter") go.click();
    });
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done(null);
    });
    overlayRoot().append(backdrop);
    go.focus();
  });
}

interface ApplyChoice {
  pairs: { entryA?: { offset: bigint }; entryB?: { offset: bigint } }[];
  minConfidence: number;
  items: DiffMarkupItem[];
  policy: DiffApplyPolicy;
}

function applyDialog(rk: Revkit, s: DiffSessionInfo, selected: DiffMatch | null): Promise<ApplyChoice | null> {
  return new Promise((resolve) => {
    const check = (label: string, testid: string) => {
      const c = h("input", { type: "checkbox", checked: true, "data-testid": testid });
      return { c, el: h("label", { class: "diff-check" }, c, ` ${label}`) };
    };
    const names = check("Names (over B's default names only)", "apply-names");
    const comments = check("Comments (function-level, and each instruction's at its partner in the instruction map)", "apply-comments");
    const protos = check("Prototypes (with their types, defined by hash)", "apply-prototypes");
    const threshold = h("input", { class: "filter diff-conf", type: "number", min: "0", max: "1", step: "0.01", value: String(AUTO), "data-testid": "apply-threshold", "aria-label": "Least confidence" });
    const policy = h(
      "select",
      { class: "filter select", "data-testid": "apply-policy", "aria-label": "Policy" },
      h("option", { value: String(DiffApplyPolicy.SAFE) }, "Safe: only where B has nothing"),
      h("option", { value: String(DiffApplyPolicy.ADD) }, "Add: append comments"),
      h("option", { value: String(DiffApplyPolicy.REPLACE) }, "Replace: over anything but a user's"),
    );
    const scope = h(
      "select",
      { class: "filter select", "data-testid": "apply-scope", "aria-label": "Which matches" },
      h("option", { value: "all" }, "Every match at or above the threshold"),
      selected ? h("option", { value: "one" }, `Only ${selected.a?.name} → ${selected.b?.name}`) : null,
    );
    const preview = h("div", { class: "dim diff-preview", "data-testid": "apply-preview" }, "…");
    const go = h("button", { class: "btn primary", type: "button", text: "Apply", "data-testid": "apply-go" });
    const cancel = h("button", { class: "btn", type: "button", text: "Cancel" });
    const choice = (): ApplyChoice => ({
      pairs: scope.value === "one" && selected ? [{ entryA: selected.a?.entry, entryB: selected.b?.entry }] : [],
      minConfidence: Number(threshold.value) || AUTO,
      items: [names.c.checked && DiffMarkupItem.NAMES, comments.c.checked && DiffMarkupItem.COMMENTS, protos.c.checked && DiffMarkupItem.PROTOTYPES].filter((x): x is DiffMarkupItem => x !== false),
      policy: Number(policy.value) as DiffApplyPolicy,
    });
    let seq = 0;
    const refresh = async () => {
      const mine = ++seq;
      const c = choice();
      if (!c.items.length) {
        preview.textContent = "Nothing selected";
        return;
      }
      try {
        const r = await rk.diff.applyMarkup({ ...c, projectId: s.projectId, sessionId: s.sessionId, dryRun: true, provenance: userProvenance() });
        if (mine !== seq) return;
        preview.textContent = `Would port ${r.names} names, ${r.comments} comments, ${r.prototypes} prototypes (${r.types} types) over ${r.pairs} matches; ${r.skipped} left alone.`;
      } catch (e) {
        if (mine === seq) preview.textContent = errText(e);
      }
    };
    for (const el of [names.c, comments.c, protos.c, policy, scope]) el.addEventListener("change", () => void refresh());
    threshold.addEventListener("input", () => void refresh());
    const box = h(
      "div",
      { class: "modal diff-dialog", role: "dialog", "aria-label": "Apply markup", "data-testid": "apply-dialog" },
      h("div", { class: "modal-title" }, `Apply markup from ${s.programA} to ${s.programB}`),
      names.el,
      comments.el,
      protos.el,
      h("label", { class: "ask-label dim" }, "Least confidence ", threshold),
      policy,
      scope,
      preview,
      h("div", { class: "diff-actions" }, cancel, go),
      h("div", { class: "modal-hint" }, "One revision, provenance migration:diff (the run is undoable as a whole). A user's own names and comments in B are never overwritten."),
    );
    const backdrop = h("div", { class: "backdrop" }, box);
    const done = (v: ApplyChoice | null) => {
      backdrop.remove();
      resolve(v);
    };
    go.onclick = () => done(choice());
    cancel.onclick = () => done(null);
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") done(null);
    });
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done(null);
    });
    overlayRoot().append(backdrop);
    go.focus();
    void refresh();
  });
}

/** An unmatched function's rows, all only on its side, as a pair detail the listing can show. */
function onlyOneSide(side: "a" | "b", rows: ListingRow[], sessionId: string, entry: bigint): PairDetail {
  const status = side === "a" ? DiffLineStatus.DELETED : DiffLineStatus.INSERTED;
  const drows = rows.map((r) => ({
    address: r.address,
    status,
    partner: -1,
    block: 0,
    moved: false,
    length: r.length,
    text: r.tokens.map((t) => t.text).join(""),
    tokens: r.tokens.map((t) => ({ text: t.text, kind: t.kind, target: t.target, operand: t.operandIndex ?? -1 })),
    label: r.labels[0]?.name ?? "",
    comment: r.comments.map((c) => c.text).join(" "),
    flow: r.flow,
  }));
  const detail = {
    blocksA: [],
    blocksB: [],
    rowsA: side === "a" ? drows : [],
    rowsB: side === "b" ? drows : [],
    lines: drows.map((_, i) => ({ a: side === "a" ? i : -1, b: side === "b" ? i : -1 })),
    hunks: [],
    references: [],
    summary: undefined,
    correlateMs: 0,
    totalMs: 0,
  } as unknown as PairDetail["detail"];
  return { pair: { sessionId, a: side === "a" ? entry : -1n, b: side === "b" ? entry : -1n, nameA: "", nameB: "", programA: "", programB: "" }, detail, revision: 0n, newCalls: new Set(), goneCalls: new Set() };
}
