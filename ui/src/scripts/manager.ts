// Scripts in the UI (ScriptService, feature scripts-host; docs/ui.md,
// "Scripts"): the Script Manager view (categories, search, run, edit, key
// bindings, recent runs with revert), the run's output panel (console,
// progress, Cancel, tracebacks linked to the editor), prompts through the
// standard dialogs, the trust confirmation, and every script as a palette
// command, a key (its @keybinding, or one bound here) and, for @context
// function/selection/address scripts, a context-menu entry. A run's edits
// are one undo step of this tab.

import { create } from "@bufbuild/protobuf";
import {
  normalizeKeybinding,
  runScript,
  scriptCategoryTree,
  scriptsForContext,
  setupScriptPython,
  ScriptLibrary,
  ScriptRunSchema,
  type Revkit,
  type RunScriptOutcome,
  type ScriptCategory,
  type ScriptError,
  type ScriptInfo,
  type ScriptPrompt,
  type ScriptRun,
  type ScriptTrustRequired,
} from "@revkit/api";
import { userProvenance } from "../api/client";
import { errText, hex } from "../data/format";
import { ask, choose, toast } from "../ui/dialogs";
import { h, overlayRoot, prefs } from "../ui/dom";
import type { MenuItem } from "../ui/menu";
import type { Command } from "../ui/palette";
import { NEW_SCRIPT, openEditor, type EditorHost } from "./editor";
import "./scripts.css";

export interface ScriptsHost {
  rk: Revkit;
  programId: string;
  projectId: string;
  /** The cursor (current_address). */
  location(): bigint | null;
  /** The function containing the cursor, if any. */
  currentFunction(): bigint | null;
  /** The listing's selection as an address range, when more than one row. */
  selection(): [bigint, bigint] | null;
  /** A run's assertions: one undo step of this tab. */
  recordUndo(label: string, seqs: bigint[]): void;
  /** Resolves once the views have seen this revision. */
  settle(rev: bigint): Promise<void>;
  /** Shows the Scripts view. */
  show(): void;
}

interface Running {
  script: ScriptInfo;
  runId: string;
  abort: AbortController;
  cancelled: boolean;
  started: number;
}

const KEYS_PREF = "rk.scriptKeys";

/** The UI's name for a key event ("Ctrl+Shift+R"), as normalizeKeybinding spells them. */
export function eventKeyName(e: KeyboardEvent): string {
  let key = e.key;
  if (/^Key[A-Z]$/.test(e.code)) key = e.code.slice(3);
  else if (/^Digit\d$/.test(e.code)) key = e.code.slice(5);
  else if (key.length === 1) key = key.toUpperCase();
  if (["Control", "Shift", "Alt", "Meta"].includes(key)) return "";
  const mods = [e.ctrlKey && "Ctrl", e.metaKey && "Meta", e.altKey && "Alt", e.shiftKey && "Shift"].filter(Boolean);
  return [...mods, key].join("+");
}

function present(...xs: (HTMLElement | null)[]): HTMLElement[] {
  return xs.filter((x): x is HTMLElement => x !== null);
}

function libraryName(s: ScriptInfo): string {
  return s.library === ScriptLibrary.SHIPPED ? "shipped" : s.library === ScriptLibrary.USER ? "mine" : s.library === ScriptLibrary.PROJECT ? `project ${s.projectId}` : "";
}

function when(ms: bigint | number): string {
  const d = new Date(Number(ms));
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export class Scripts {
  scripts: ScriptInfo[] = [];
  hostEnabled = false;
  hostDisabledReason = "";
  python = "";
  pythonProblem = "";
  /** Runs this tab started (their edits' session), for telling them from others'. */
  readonly ownRuns = new Set<string>();
  runs: ScriptRun[] = [];
  running: Running | null = null;
  readonly el: HTMLElement;
  private selected = "";
  private filter = "";
  private loaded = false;
  // View parts.
  private banner: HTMLElement;
  private search: HTMLInputElement;
  private tree: HTMLElement;
  private details: HTMLElement;
  private out: HTMLElement;
  private outHead: HTMLElement;
  private outTitle: HTMLElement;
  private outStatus: HTMLElement;
  private bar: HTMLElement;
  private barFill: HTMLElement;
  private barText: HTMLElement;
  private cancelBtn: HTMLButtonElement;
  private consoleEl: HTMLElement;
  private errorEl: HTMLElement;
  private runsEl: HTMLElement;
  /** Setting up Python (SetupScriptPython) now. */
  settingUp = false;
  /** The last setup's outcome (tests). */
  lastSetup: { ok: boolean; python: string; error: string; output: string } | null = null;
  /** The last run's outcome (tests). */
  last: { scriptId: string; runId: string; status: string; seqs: string[]; output: string; error: string; line: number } | null = null;
  private outputText = "";

  constructor(
    el: HTMLElement,
    private host: ScriptsHost,
  ) {
    this.el = el;
    this.banner = h("div", { class: "sm-banner", hidden: true, "data-testid": "scripts-banner", role: "status" });
    this.search = h("input", { class: "filter", placeholder: "Search scripts", spellcheck: "false", autocomplete: "off", "aria-label": "Search scripts", "data-testid": "scripts-search" });
    this.search.addEventListener("input", () => {
      this.filter = this.search.value.trim().toLowerCase();
      this.paintTree();
    });
    this.search.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        const first = this.visible()[0];
        if (first) void this.run(first);
      }
    });
    this.tree = h("div", { class: "sm-tree", role: "tree", "aria-label": "Scripts", "data-testid": "scripts-tree" });
    this.details = h("div", { class: "sm-details", "data-testid": "scripts-details" });
    this.outTitle = h("span", { class: "sm-out-title" });
    this.outStatus = h("span", { class: "dim", "data-testid": "script-status" });
    this.barFill = h("div", { class: "sm-bar-fill" });
    this.barText = h("span", { class: "sm-bar-text dim", "data-testid": "script-progress-text" });
    this.bar = h("div", { class: "sm-bar", role: "progressbar", "data-testid": "script-progress", hidden: true }, this.barFill);
    this.cancelBtn = h("button", { class: "btn small", type: "button", "data-testid": "script-cancel", disabled: true, onclick: () => void this.cancel() }, "Cancel");
    this.outHead = h("div", { class: "sm-out-head" }, this.outTitle, this.outStatus, h("span", { class: "spacer" }), this.cancelBtn);
    this.consoleEl = h("pre", { class: "sm-console mono", "data-testid": "script-console", "aria-live": "polite" });
    this.errorEl = h("div", { class: "sm-error", hidden: true, "data-testid": "script-error" });
    this.out = h("div", { class: "sm-out", hidden: true, "data-testid": "script-output" }, this.outHead, h("div", { class: "sm-bar-row" }, this.bar, this.barText), this.consoleEl, this.errorEl);
    this.runsEl = h("div", { class: "sm-runs", "data-testid": "script-runs" });
    el.replaceChildren(
      h(
        "div",
        { class: "panel-head sm-head" },
        h("span", { class: "panel-title" }, "Scripts"),
        h("span", { class: "spacer" }),
        h("button", { class: "btn small", type: "button", "data-testid": "scripts-new", title: "A new script in your library or the project's", onclick: () => void this.newScript() }, "New…"),
        h("button", { class: "btn small", type: "button", "data-testid": "scripts-refresh", onclick: () => void this.load() }, "Refresh"),
      ),
      this.banner,
      h("div", { class: "sm-search" }, this.search),
      this.tree,
      this.details,
      this.out,
      h("div", { class: "sm-section dim" }, "Recent runs"),
      this.runsEl,
    );
  }

  // ------------------------------------------------------------- loading --

  async load() {
    try {
      const r = await this.host.rk.scripts.listScripts({ projectId: this.host.projectId });
      this.scripts = r.scripts;
      this.hostEnabled = r.hostEnabled;
      this.hostDisabledReason = r.hostDisabledReason;
      this.python = r.python;
      this.pythonProblem = r.pythonProblem;
      this.loaded = true;
    } catch (e) {
      this.scripts = [];
      this.hostEnabled = false;
      this.hostDisabledReason = `Can't list scripts: ${errText(e)}`;
    }
    this.paintBanner();
    this.paintTree();
    this.paintDetails();
    void this.loadRuns();
  }

  /** Whether the daemon runs scripts (and consoles) for this user, and why not. */
  async hostStatus(): Promise<{ enabled: boolean; reason: string; pythonProblem: string }> {
    if (!this.loaded) await this.load();
    return { enabled: this.hostEnabled, reason: this.hostDisabledReason || this.pythonProblem, pythonProblem: this.hostEnabled ? this.pythonProblem : "" };
  }

  ensureLoaded() {
    if (!this.loaded) void this.load();
    else void this.loadRuns();
  }

  async loadRuns() {
    try {
      const r = await this.host.rk.scripts.listScriptRuns({ programId: this.host.programId, limit: 30 });
      // Runs this tab started that the daemon no longer lists stay.
      const have = new Set(r.runs.map((x) => x.runId));
      this.runs = [...r.runs, ...this.runs.filter((x) => !have.has(x.runId) && this.ownRuns.has(x.runId))];
    } catch {
      /* keep what we have */
    }
    this.paintRuns();
  }

  private paintBanner() {
    const msgs = [this.hostEnabled ? "" : this.hostDisabledReason || "This daemon doesn't run scripts for you.", this.pythonProblem].filter(Boolean);
    this.banner.hidden = msgs.length === 0;
    // No Python yet: one click makes the daemon's (SetupScriptPython, as rk-script setup).
    const setup =
      this.hostEnabled && this.pythonProblem
        ? h(
            "div",
            { class: "sm-banner-actions" },
            h(
              "button",
              {
                class: "btn primary small",
                type: "button",
                "data-testid": "scripts-setup-python",
                disabled: this.settingUp,
                title: "Makes ~/.local/share/revkit/pyenv: a Python environment with the revkit SDK (pip fetches its dependencies)",
                onclick: () => void this.setupPython(),
              },
              this.settingUp ? "Setting up Python…" : "Set up Python",
            ),
          )
        : null;
    this.banner.replaceChildren(...msgs.map((m) => h("div", {}, m)), ...present(setup));
  }

  /** Makes the daemon's script Python (SetupScriptPython), showing its output
   * in the output panel, then lists the scripts again. */
  async setupPython() {
    if (this.settingUp) return;
    this.settingUp = true;
    this.host.show();
    this.paintBanner();
    this.outputText = "";
    this.out.hidden = false;
    this.outTitle.textContent = "Setting up Python";
    this.outStatus.textContent = "running";
    this.out.dataset.status = "running";
    this.consoleEl.replaceChildren();
    this.errorEl.hidden = true;
    this.errorEl.replaceChildren();
    this.bar.hidden = true;
    this.barText.textContent = "";
    this.cancelBtn.disabled = true;
    let ok = false;
    let python = "";
    let error = "";
    try {
      const r = await setupScriptPython(this.host.rk, { onOutput: (t) => this.append(t, "stdout") });
      ok = r.ok;
      python = r.python;
      error = r.error;
    } catch (e) {
      error = errText(e);
    }
    this.settingUp = false;
    this.out.dataset.status = ok ? "ok" : "error";
    this.outStatus.textContent = ok ? `done · scripts run with ${python}` : "failed";
    if (ok) toast(`Python is set up: scripts run with ${python}`, { ms: 6000 });
    else {
      this.showError(undefined, error || "setting up Python failed");
      toast(`Setting up Python failed${error ? `: ${error}` : ""}`, { kind: "error" });
    }
    this.lastSetup = { ok, python, error, output: this.outputText };
    await this.load();
  }

  // ---------------------------------------------------------- the tree --

  private matches(s: ScriptInfo): boolean {
    if (!this.filter) return true;
    return [s.name, s.fileName, s.category, s.description, s.scriptId].some((x) => x.toLowerCase().includes(this.filter));
  }

  private visible(): ScriptInfo[] {
    return this.scripts.filter((s) => this.matches(s));
  }

  /** The key a script answers to: one bound here, else its @keybinding. */
  keyOf(s: ScriptInfo): string {
    const own = this.keyOverrides()[s.scriptId];
    return own !== undefined ? own : normalizeKeybinding(s.keybinding);
  }

  private keyOverrides(): Record<string, string> {
    try {
      return JSON.parse(prefs.get(KEYS_PREF) ?? "{}") as Record<string, string>;
    } catch {
      return {};
    }
  }

  private paintTree() {
    const root = scriptCategoryTree(this.visible());
    const node = (c: ScriptCategory): HTMLElement => {
      const kids = [...c.children.map(node), ...c.scripts.map((s) => this.row(s))];
      if (!c.path) return h("div", {}, ...kids);
      const d = h("details", { class: "sm-cat", open: true, "data-testid": "scripts-category", "data-category": c.path }, h("summary", {}, c.name), ...kids);
      return d;
    };
    this.tree.replaceChildren(
      this.scripts.length ? (this.visible().length ? node(root) : h("div", { class: "dim sm-empty" }, "No scripts match")) : h("div", { class: "dim sm-empty" }, this.loaded ? "No scripts" : "Loading…"),
    );
  }

  private row(s: ScriptInfo): HTMLElement {
    const key = this.keyOf(s);
    const r = h(
      "div",
      {
        class: "sm-row" + (s.scriptId === this.selected ? " active" : ""),
        role: "treeitem",
        tabindex: "0",
        title: `${s.description || s.name}\n${s.scriptId}`,
        "data-testid": "script-row",
        "data-script-id": s.scriptId,
        "aria-selected": String(s.scriptId === this.selected),
      },
      h("span", { class: "sm-name mono" }, s.name),
      h("span", { class: "sm-desc dim" }, s.description),
      s.library !== ScriptLibrary.SHIPPED ? h("span", { class: "sm-lib dim" }, libraryName(s)) : null,
      key ? h("kbd", {}, key) : null,
    );
    r.addEventListener("click", () => this.select(s.scriptId));
    r.addEventListener("dblclick", () => void this.run(s));
    r.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        e.stopPropagation();
        void this.run(s);
      }
    });
    return r;
  }

  select(scriptId: string) {
    this.selected = scriptId;
    for (const r of this.tree.querySelectorAll<HTMLElement>(".sm-row")) {
      const on = r.dataset.scriptId === scriptId;
      r.classList.toggle("active", on);
      r.setAttribute("aria-selected", String(on));
    }
    this.paintDetails();
  }

  private paintDetails() {
    const s = this.scripts.find((x) => x.scriptId === this.selected);
    if (!s) {
      this.details.replaceChildren(h("div", { class: "dim" }, "Select a script: Enter or a double-click runs it."));
      return;
    }
    const key = this.keyOf(s);
    this.details.replaceChildren(
      ...present(h("div", { class: "sm-d-title" }, h("span", { class: "mono" }, s.name), h("span", { class: "dim" }, ` · ${s.category || "Other"} · ${libraryName(s)} · @context ${s.context || "program"}`)),
      s.description ? h("div", { class: "sm-d-desc" }, s.description) : null,
      s.args.length
        ? h(
            "div",
            { class: "sm-d-args dim" },
            ...s.args.map((a) => h("div", {}, h("span", { class: "mono" }, `${a.name}:${a.type}${a.hasDefault ? `=${a.defaultValue}` : ""}`), a.description ? ` ${a.description}` : "")),
          )
        : null,
      s.errors.length ? h("div", { class: "sm-d-errors" }, ...s.errors.map((e) => h("div", {}, e))) : null,
      h("div", { class: "sm-d-meta dim mono" }, `${s.scriptId} · sha256 ${s.sha256.slice(0, 12)}${s.trusted ? "" : " · not yet confirmed"}`),
      h(
        "div",
        { class: "sm-d-buttons" },
        h("button", { class: "btn primary small", type: "button", "data-testid": "script-run", disabled: !this.hostEnabled || this.running !== null, onclick: () => void this.run(s) }, "Run"),
        h("button", { class: "btn small", type: "button", "data-testid": "script-edit", onclick: () => void this.edit(s) }, s.writable ? "Edit" : "View source"),
        h("button", { class: "btn small", type: "button", "data-testid": "script-bind", onclick: () => void this.bindKey(s) }, key ? `Key: ${key}` : "Bind key…"),
      )),
    );
  }

  // ------------------------------------------------------------- keys --

  private async bindKey(s: ScriptInfo) {
    const v = await ask({
      title: `Key for ${s.name} (e.g. Ctrl+Alt+R; empty: none)`,
      value: this.keyOf(s),
      hint: s.keybinding ? `Its @keybinding is "${s.keybinding}" · Enter to save · Esc to cancel` : "Enter to save · Esc to cancel",
      validate: (t) => (t.trim() === "" || normalizeKeybinding(t) ? null : "Name a key: Ctrl+Shift+R, Alt+F5, ..."),
    });
    if (v === null) return;
    const all = this.keyOverrides();
    all[s.scriptId] = v.trim() === "" ? "" : normalizeKeybinding(v);
    prefs.set(KEYS_PREF, JSON.stringify(all));
    this.paintTree();
    this.paintDetails();
  }

  /** Runs the script bound to this key, if any; true when it did. */
  handleKey(e: KeyboardEvent): boolean {
    if (!this.scripts.length) return false;
    const name = eventKeyName(e);
    if (!name) return false;
    const s = this.scripts.find((x) => this.keyOf(x) === name);
    if (!s) return false;
    e.preventDefault();
    e.stopPropagation();
    void this.run(s);
    return true;
  }

  // --------------------------------------------- palette and menus --

  commands(): Command[] {
    return [
      ...this.scripts.map((s) => ({
        id: `script-${s.scriptId}`,
        title: `Run script ${s.name}`,
        detail: s.description || undefined,
        keys: this.keyOf(s) || undefined,
        enabled: () => this.hostEnabled,
        run: () => void this.run(s),
      })),
      { id: "script-new", title: "Scripts: new script…", run: () => void this.newScript() },
      { id: "script-cancel", title: "Scripts: cancel the running script", enabled: () => this.running !== null, run: () => void this.cancel() },
      { id: "script-revert", title: "Scripts: revert a recent run…", run: () => void this.revertDialog() },
    ];
  }

  /** Context-menu entries for where the user is. */
  contextItems(): MenuItem[] {
    if (!this.hostEnabled) return [];
    const fn = this.host.currentFunction() !== null;
    const sel = this.host.selection() !== null;
    const addr = this.host.location() !== null;
    return scriptsForContext(this.scripts, { function: fn, selection: sel, address: addr }).map((s) => ({
      label: `Script: ${s.name}`,
      keys: this.keyOf(s) || undefined,
      testid: `ctx-script-${s.name}`,
      run: () => void this.run(s),
    }));
  }

  // ------------------------------------------------------------ running --

  /** Runs a script on this program, with the cursor and selection as its context. */
  async run(s: ScriptInfo) {
    if (!this.hostEnabled) return toast(this.hostDisabledReason || "This daemon doesn't run scripts", { kind: "error" });
    if (this.running) return toast(`${this.running.script.name} is still running`, { kind: "error" });
    this.host.show();
    const abort = new AbortController();
    const running: Running = { script: s, runId: "", abort, cancelled: false, started: performance.now() };
    this.running = running;
    this.outputText = "";
    this.out.hidden = false;
    this.outTitle.textContent = s.name;
    this.outStatus.textContent = "starting…";
    this.out.dataset.status = "running";
    this.consoleEl.replaceChildren();
    this.errorEl.hidden = true;
    this.errorEl.replaceChildren();
    this.bar.hidden = true;
    this.barText.textContent = "";
    this.cancelBtn.disabled = false;
    this.paintDetails();
    const loc = this.host.location();
    let outcome: RunScriptOutcome & { failure?: string };
    try {
      outcome = await runScript(
        this.host.rk,
        { scriptId: s.scriptId, programId: this.host.programId, address: loc ?? undefined, selection: this.host.selection() ?? undefined },
        {
          signal: abort.signal,
          onStarted: (st) => {
            running.runId = st.runId;
            this.ownRuns.add(st.runId);
            this.outStatus.textContent = "running";
            this.runs = [
              create(ScriptRunSchema, { runId: st.runId, scriptId: s.scriptId, name: s.name, version: s.sha256.slice(0, 12), programId: this.host.programId, status: "running", startedAtMs: st.startedAtMs }),
              ...this.runs.filter((r) => r.runId !== st.runId),
            ];
            this.paintRuns();
          },
          onOutput: (text, stream) => this.append(text, stream),
          onProgress: (cur, max, msg) => this.progress(cur, max, msg),
          onPrompt: (p) => this.prompt(p, s),
          onTrust: (t) => this.confirmTrust(t),
        },
      );
    } catch (e) {
      outcome = { runId: running.runId, status: running.cancelled ? "cancelled" : "error", failure: errText(e) };
    }
    this.running = null;
    this.cancelBtn.disabled = true;
    // The run's row, until the daemon's list says more.
    this.runs = this.runs.map((r) =>
      r.runId === outcome.runId && outcome.runId
        ? create(ScriptRunSchema, { ...r, status: outcome.status, assertions: outcome.result?.seqs.length ?? 0, revisions: outcome.result?.revisions ?? [], seconds: outcome.result?.seconds ?? 0, error: outcome.error?.message ?? "" })
        : r,
    );
    const seqs = outcome.result?.seqs ?? [];
    const status = outcome.status;
    this.out.dataset.status = status;
    const secs = outcome.result?.seconds ?? (performance.now() - running.started) / 1000;
    const n = seqs.length;
    if (status === "untrusted") {
      this.outStatus.textContent = "not run (not confirmed)";
    } else if (status === "ok") {
      if (!this.bar.hidden && !this.bar.classList.contains("indeterminate")) this.barFill.style.width = "100%";
      this.outStatus.textContent = `done in ${secs.toFixed(1)} s · ${n} edit${n === 1 ? "" : "s"}`;
    } else if (status === "cancelled") {
      this.outStatus.textContent = `cancelled after ${secs.toFixed(1)} s${n ? ` · ${n} edits committed earlier` : ""}`;
    } else {
      this.outStatus.textContent = `failed after ${secs.toFixed(1)} s`;
    }
    if (outcome.error && status !== "cancelled") this.showError(outcome.error);
    else if (outcome.failure) this.showError(undefined, outcome.failure);
    if (n) {
      this.host.recordUndo(`Script ${s.name} (${n} edit${n === 1 ? "" : "s"})`, seqs);
      toast(`${s.name} made ${n} edit${n === 1 ? "" : "s"} as script:${s.name}@${s.sha256.slice(0, 12)} · Ctrl+Z undoes them`, { ms: 6000 });
      const rev = outcome.result?.revisions.at(-1);
      if (rev) await this.host.settle(rev);
    } else if (status === "ok") toast(`${s.name}: done, no edits`);
    else if (status === "error") toast(`${s.name} failed${outcome.error?.message ? `: ${outcome.error.message}` : ""}`, { kind: "error" });
    this.last = {
      scriptId: s.scriptId,
      runId: outcome.runId,
      status,
      seqs: seqs.map(String),
      output: this.outputText,
      error: outcome.error?.message ?? outcome.failure ?? "",
      line: outcome.error?.line ?? 0,
    };
    if (outcome.trust) void this.load(); // trust changed (or not): repaint
    else if (s.library !== ScriptLibrary.SHIPPED && !s.trusted) void this.load();
    else void this.loadRuns();
    this.paintDetails();
  }

  private append(text: string, stream: string) {
    this.outputText += text;
    const span = h("span", { class: stream === "stderr" ? "sm-stderr" : "" }, text);
    const atEnd = this.consoleEl.scrollTop + this.consoleEl.clientHeight >= this.consoleEl.scrollHeight - 4;
    this.consoleEl.append(span);
    // Keep the console bounded (the text for tests too).
    while (this.consoleEl.childNodes.length > 4000) this.consoleEl.firstChild?.remove();
    if (atEnd) this.consoleEl.scrollTop = this.consoleEl.scrollHeight;
  }

  private progress(cur: bigint, max: bigint, msg: string) {
    this.bar.hidden = false;
    const indeterminate = max <= 0n;
    this.bar.classList.toggle("indeterminate", indeterminate);
    const pct = indeterminate ? 0 : Math.min(100, Number((cur * 1000n) / max) / 10);
    this.barFill.style.width = indeterminate ? "" : `${pct}%`;
    this.bar.setAttribute("aria-valuenow", String(cur));
    this.bar.setAttribute("aria-valuemax", String(max));
    this.bar.dataset.current = String(cur);
    this.bar.dataset.maximum = String(max);
    this.barText.textContent = `${indeterminate ? (cur ? String(cur) : "") : `${cur}/${max}`}${msg ? ` ${msg}` : ""}`;
  }

  private showError(err?: ScriptError, text?: string) {
    this.errorEl.hidden = false;
    const target = err ? this.scripts.find((x) => x.scriptId === err.scriptId) : undefined;
    this.errorEl.replaceChildren(
      ...present(h("div", { class: "sm-error-msg" }, err?.message || text || "failed"),
      err && target && err.line
        ? h(
            "button",
            { class: "link sm-error-link", type: "button", "data-testid": "script-error-link", onclick: () => void this.edit(target, err.line) },
            `${target.fileName}, line ${err.line}`,
          )
        : null,
      err?.traceback ? h("pre", { class: "sm-traceback mono", "data-testid": "script-traceback" }, err.traceback) : null),
    );
  }

  async cancel() {
    const r = this.running;
    if (!r) return;
    r.cancelled = true;
    this.outStatus.textContent = "cancelling…";
    this.cancelBtn.disabled = true;
    if (!r.runId) return r.abort.abort();
    try {
      await this.host.rk.scripts.cancelScript({ runId: r.runId });
    } catch (e) {
      toast(`Cancel: ${errText(e)}`, { kind: "error" });
      r.abort.abort();
    }
  }

  /** The cursor moved: a running script's current_address follows. */
  contextMoved() {
    const r = this.running;
    if (!r?.runId) return;
    const loc = this.host.location();
    const sel = this.host.selection();
    void this.host.rk.scripts
      .updateContext({
        runId: r.runId,
        context: {
          address: loc === null ? undefined : { offset: loc },
          selection: sel ? { first: { offset: sel[0] }, last: { offset: sel[1] } } : undefined,
        },
      })
      .catch(() => undefined);
  }

  // ------------------------------------------------------------ prompts --

  private prompt(p: ScriptPrompt, s: ScriptInfo): Promise<string | string[] | null> {
    return askForScript(p, s.name, this.host.location(), "the run");
  }

  private confirmTrust(t: ScriptTrustRequired): Promise<boolean> {
    return confirmTrust(t);
  }

  // ------------------------------------------------------------- editor --

  private editorHost(): EditorHost {
    return {
      rk: this.host.rk,
      projectId: this.host.projectId,
      saved: (s) => {
        this.selected = s.scriptId;
        void this.load();
      },
      run: (s) => {
        // Refresh first: a just-saved script's info (trust, hash) is newer.
        void this.load().then(() => this.run(this.scripts.find((x) => x.scriptId === s.scriptId) ?? s));
      },
    };
  }

  async edit(s: ScriptInfo, line?: number) {
    await openEditor(this.editorHost(), { script: s, line });
  }

  async newScript() {
    const lib = await choose<ScriptLibrary>("New script in", [
      { label: "My scripts", detail: "this daemon's user's library (~/.config/revkit/scripts)", value: ScriptLibrary.USER },
      { label: `Project ${this.host.projectId}`, detail: "kept with the project", value: ScriptLibrary.PROJECT },
    ]);
    if (lib === null) return;
    await openEditor(this.editorHost(), { source: NEW_SCRIPT, library: lib });
  }

  // ------------------------------------------------------ recent runs --

  private paintRuns() {
    if (!this.runs.length) {
      this.runsEl.replaceChildren(h("div", { class: "dim sm-empty" }, "No runs yet"));
      return;
    }
    this.runsEl.replaceChildren(
      ...this.runs.slice(0, 30).map((r) => {
        const here = r.programId === this.host.programId;
        const edits = r.assertions > 0 || r.revisions.length > 0;
        return h(
          "div",
          { class: `sm-run s-${r.status}`, "data-testid": "script-run-row", "data-run-id": r.runId, "data-status": r.status },
          h("span", { class: "sm-run-name mono" }, r.name),
          h("span", { class: "dim" }, ` ${r.status}${r.assertions ? ` · ${r.assertions} edit${r.assertions === 1 ? "" : "s"}` : ""} · ${when(r.startedAtMs)}${r.caller && !this.ownRuns.has(r.runId) ? ` · ${r.caller}` : ""}`),
          h("span", { class: "spacer" }),
          h(
            "button",
            {
              class: "btn small",
              type: "button",
              "data-testid": "script-run-revert",
              disabled: !here || !edits || r.status === "running",
              title: here ? "Retract everything this run asserted (RevertByProvenance on its session): one revision, undoable" : "Open its program to revert it",
              onclick: () => void this.revert(r),
            },
            "Revert this run",
          ),
        );
      }),
    );
  }

  async revert(r: ScriptRun) {
    try {
      const res = await this.host.rk.assertions.revertByProvenance({
        programId: r.programId,
        filter: { session: r.runId },
        provenance: userProvenance(`revert script run ${r.name} (${r.runId})`),
      });
      const seqs = res.retractions.map((a) => a.seq);
      if (!seqs.length) return toast(`Nothing left to revert of ${r.name}'s run`);
      this.host.recordUndo(`Revert script run ${r.name}`, seqs);
      toast(`Reverted ${r.name}'s run (${res.retractedSeqs.length} assertion${res.retractedSeqs.length === 1 ? "" : "s"}) · Ctrl+Z restores it`);
      await this.host.settle(res.snapshot?.revision ?? 0n);
    } catch (e) {
      toast(`Revert failed: ${errText(e)}`, { kind: "error" });
    }
  }

  private async revertDialog() {
    await this.loadRuns();
    const runs = this.runs.filter((r) => r.programId === this.host.programId && r.status !== "running" && (r.assertions > 0 || r.revisions.length > 0));
    if (!runs.length) return toast("No script runs with edits on this program");
    const r = await choose(
      "Revert a script run",
      runs.map((x) => ({ label: `${x.name} · ${x.status}`, detail: `${x.assertions} edits · ${when(x.startedAtMs)}${x.caller ? ` · ${x.caller}` : ""}`, value: x })),
    );
    if (r) await this.revert(r);
  }
}

/** The trust confirmation: the script's id, hash and source; Run pins the hash. */
/** A script's (or the console's) ask_* prompt through the standard dialogs:
 * the answer's text, a list for "choices", or null when dismissed (which
 * cancels `what`). */
export async function askForScript(p: ScriptPrompt, who: string, loc: bigint | null, what: string): Promise<string | string[] | null> {
  const title = p.message || p.name;
  const hint = `${who} asks${p.name ? ` (${p.name})` : ""} · Enter to answer · Esc cancels ${what}`;
  const def = p.hasDefault ? p.defaultValue : "";
  switch (p.kind) {
    case "yes_no":
      return choose(title, [
        { label: "Yes", value: "true", current: /^(1|true|yes|y|on)$/i.test(def) },
        { label: "No", value: "false", current: p.hasDefault && !/^(1|true|yes|y|on)$/i.test(def) },
      ]);
    case "choice":
      return choose(
        title,
        p.choices.map((c) => ({ label: c, value: c, current: c === def })),
      );
    case "choices":
      return chooseMany(title, p.choices, def ? def.split(",") : []);
    case "int":
    case "float":
      return ask({
        title,
        value: def,
        hint,
        validate: (v) => {
          const t = v.trim();
          if (p.kind === "int") return /^[-+]?(0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[bB][01]+|\d+)$/.test(t) ? null : "A whole number (decimal or 0x hex)";
          return t !== "" && Number.isFinite(Number(t)) ? null : "A number";
        },
      });
    case "address": {
      return ask({ title, value: def || (loc !== null ? `0x${hex(loc)}` : ""), hint: `${who} asks for an address or a symbol · Enter to answer · Esc cancels ${what}`, validate: (v) => (v.trim() ? null : "An address or a symbol") });
    }
    default:
      return ask({ title, value: def, hint });
  }
}


export function confirmTrust(t: ScriptTrustRequired): Promise<boolean> {
  return new Promise((resolve) => {
    const s = t.script;
    const restore = document.activeElement as HTMLElement | null;
    const why =
      t.reason === "changed"
        ? `It changed since you last confirmed it (sha256 ${t.previousSha256.slice(0, 12)} then).`
        : "You haven't run this script before.";
    const run = h("button", { class: "btn primary", type: "button", "data-testid": "script-trust-run" }, "Run it");
    const cancel = h("button", { class: "btn", type: "button", "data-testid": "script-trust-cancel" }, "Cancel");
    const box = h(
      "div",
      { class: "modal script-trust", role: "alertdialog", "aria-modal": "true", "aria-label": `Run ${s?.name ?? "script"}?`, "data-testid": "script-trust", tabindex: "-1" },
      h("div", { class: "modal-title" }, `Run ${s?.name ?? "this script"}?`),
      h(
        "div",
        { class: "st-why" },
        `${why} A script is full Python with the daemon's rights: it can read and write files and run programs. Read it before running it.`,
      ),
      h("div", { class: "st-meta mono dim" }, h("div", {}, s?.scriptId ?? ""), h("div", { "data-testid": "script-trust-sha" }, `sha256 ${s?.sha256 ?? ""}`)),
      h("pre", { class: "st-source mono", "data-testid": "script-trust-source" }, t.source),
      h("div", { class: "st-buttons" }, h("span", { class: "spacer" }), cancel, run),
      h("div", { class: "modal-hint" }, "Running pins this exact text (its hash) for you; a change asks again."),
    );
    const backdrop = h("div", { class: "backdrop top" }, box);
    const done = (v: boolean) => {
      backdrop.remove();
      restore?.focus({ preventScroll: true });
      resolve(v);
    };
    run.onclick = () => done(true);
    cancel.onclick = () => done(false);
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") done(false);
    });
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done(false);
    });
    overlayRoot().append(backdrop);
    cancel.focus();
  });
}

/** Several of a list (ask_choices): Space or a click toggles, Enter answers. */
export function chooseMany(title: string, choices: string[], initial: string[]): Promise<string[] | null> {
  return new Promise((resolve) => {
    const restore = document.activeElement as HTMLElement | null;
    const boxes = choices.map((c) => {
      const cb = h("input", { type: "checkbox", value: c, "data-testid": "choose-many-item" });
      cb.checked = initial.includes(c);
      return cb;
    });
    const box = h(
      "div",
      { class: "modal ask", role: "dialog", "aria-modal": "true", "aria-label": title, "data-testid": "choose-many", tabindex: "-1" },
      h("div", { class: "modal-title" }, title),
      h("div", { class: "sm-many" }, ...choices.map((c, i) => h("label", { class: "sm-many-row" }, boxes[i], h("span", {}, c)))),
      h("div", { class: "modal-hint" }, "Space toggles · Enter answers · Esc cancels the run"),
    );
    const backdrop = h("div", { class: "backdrop" }, box);
    const done = (v: string[] | null) => {
      backdrop.remove();
      restore?.focus({ preventScroll: true });
      resolve(v);
    };
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") done(null);
      else if (e.key === "Enter") {
        e.preventDefault();
        done(boxes.filter((b) => b.checked).map((b) => b.value));
      }
    });
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done(null);
    });
    overlayRoot().append(backdrop);
    (boxes[0] ?? box).focus();
  });
}
