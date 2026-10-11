// The Python console (docs/ui.md, "Python console"; feature script-console):
// a dockable view with a REPL bound to this program, run by the daemon in a
// live host per user and program (RunScript{interactive}). current_program,
// current_address, current_function and current_selection follow the
// cursor (UpdateContext); the revkit.script names are there, and Ghidra's
// (currentProgram, getFunctionAt, ...) with "Ghidra names". Enter runs the
// input (an open block continues on the next line; an empty line ends it),
// Shift+Enter adds a line, Up and Down walk the history (kept per user on
// the daemon), Tab completes from the live namespace, Ctrl+C interrupts (or
// drops the input), Ctrl+L clears. Each statement's edits are one undo step.

import { acceptCompletion, autocompletion, completionStatus, startCompletion } from "@codemirror/autocomplete";
import { defaultKeymap, history, historyKeymap, indentMore, insertNewlineAndIndent } from "@codemirror/commands";
import { indentUnit } from "@codemirror/language";
import { Compartment, EditorSelection, EditorState, Prec } from "@codemirror/state";
import { EditorView, keymap } from "@codemirror/view";
import { completeConsole, consoleRun, type ConsoleOutcome, type Revkit, type ScriptStarted } from "@revkit/api";
import { errText } from "../data/format";
import { toast } from "../ui/dialogs";
import { h, prefs } from "../ui/dom";
import { closeSignature, liveCompletions, signatureHelp } from "./assist";
import { askForScript } from "./manager";
import { python, pythonHighlight } from "./python";

export interface ConsoleHost {
  rk: Revkit;
  programId: string;
  /** The cursor (current_address). */
  location(): bigint | null;
  /** The listing's selection as an address range, when more than one row. */
  selection(): [bigint, bigint] | null;
  /** A statement's assertions: one undo step of this tab. */
  recordUndo(label: string, seqs: bigint[]): void;
  /** Resolves once the views have seen this revision. */
  settle(rev: bigint): Promise<void>;
  /** Whether the daemon runs scripts (and consoles) for this user, and why not. */
  hostStatus(): Promise<{ enabled: boolean; reason: string; pythonProblem: string }>;
  /** Makes or updates the daemon's script Python (the Script Manager's Set
   * up Python); true when scripts can run now. */
  setupPython(): Promise<boolean>;
  /** The console's edits are this tab's own (no "someone edited" toast). */
  own(runId: string): void;
  /** Shows the Python view. */
  show(): void;
}

const GHIDRA_PREF = "rk.consoleGhidra";
const MAX_NODES = 5000;

export class PythonConsole {
  readonly el: HTMLElement;
  /** The console's run id (UpdateContext, CancelScript). */
  runId = "";
  started: ScriptStarted | null = null;
  running = false;
  readOnly = false;
  /** Statements run (tests wait on it). */
  statements = 0;
  /** Statements, oldest first (the daemon's history, then this tab's). */
  history: string[] = [];
  /** The last statement's outcome (tests). */
  last: { input: string; status: string; more: boolean; stdout: string; stderr: string; seqs: string[]; runId: string; error: string } | null = null;
  private histPos = 0;
  private draft = "";
  private inBlock = false;
  private pendingSubmit = false;
  private abort: AbortController | null = null;
  private opening: Promise<void> | null = null;
  private ctxTimer = 0;
  private out: HTMLElement;
  private promptEl: HTMLElement;
  private statusEl: HTMLElement;
  private roBadge: HTMLElement;
  private interruptBtn: HTMLButtonElement;
  private ghidraBox: HTMLInputElement;
  private inputRow: HTMLElement;
  private view: EditorView;
  private editable = new Compartment();

  constructor(
    el: HTMLElement,
    private host: ConsoleHost,
  ) {
    this.el = el;
    this.statusEl = h("span", { class: "dim pc-status", "data-testid": "py-status" }, "not started");
    this.roBadge = h("span", { class: "pc-ro", hidden: true, "data-testid": "py-readonly", title: "You are a viewer: reads work, edits are refused" }, "read-only");
    this.interruptBtn = h("button", { class: "btn small", type: "button", disabled: true, title: "Ctrl+C: KeyboardInterrupt in the running statement", "data-testid": "py-interrupt", onclick: () => this.interrupt() }, "Interrupt");
    this.ghidraBox = h("input", { type: "checkbox", "data-testid": "py-ghidra" });
    this.ghidraBox.checked = prefs.get(GHIDRA_PREF) === "1";
    this.ghidraBox.onchange = () => {
      prefs.set(GHIDRA_PREF, this.ghidraBox.checked ? "1" : "0");
      this.info(this.ghidraBox.checked ? "Ghidra's names are bound: currentProgram, currentAddress, getFunctionAt, …" : "Ghidra's names are gone");
      if (this.runId && !this.running) void this.exec("", { quiet: true });
    };
    this.out = h("pre", { class: "pc-out mono", "data-testid": "py-output", "aria-live": "polite", tabindex: "0" });
    this.promptEl = h("span", { class: "pc-prompt mono", "data-testid": "py-prompt" }, ">>>");
    this.view = new EditorView({
      state: EditorState.create({
        doc: "",
        extensions: [
          history(),
          indentUnit.of("    "),
          EditorState.tabSize.of(4),
          python,
          pythonHighlight,
          autocompletion({
            override: [liveCompletions((text) => this.complete(text))],
            activateOnTyping: false,
            maxRenderedOptions: 80,
            interactionDelay: 0,
          }),
          signatureHelp((callee) => this.signatureOf(callee)),
          Prec.high(
            keymap.of([
              // Enter accepts an open completion, else runs the input.
              { key: "Enter", run: (v) => (completionStatus(v.state) ? (acceptCompletion(v), true) : (void this.submit(), true)) },
              { key: "Shift-Enter", run: insertNewlineAndIndent },
              { key: "ArrowUp", run: (v) => this.historyMove(v, -1) },
              { key: "ArrowDown", run: (v) => this.historyMove(v, 1) },
              { key: "Tab", run: (v) => this.tab(v) },
              { key: "Ctrl-c", run: (v) => this.ctrlC(v) },
              { key: "Ctrl-l", preventDefault: true, run: () => (this.clear(), true) },
              { key: "Escape", run: (v) => closeSignature(v) },
            ]),
          ),
          keymap.of([...historyKeymap, ...defaultKeymap]),
          EditorView.lineWrapping,
          this.editable.of(EditorView.editable.of(true)),
          EditorView.contentAttributes.of({ "aria-label": "Python input", "data-testid": "py-input" }),
          EditorView.theme({ ".cm-scroller": { fontFamily: "var(--mono)", fontSize: "12px" }, ".cm-content": { padding: "2px 0" } }),
        ],
      }),
    });
    this.inputRow = h("div", { class: "pc-input" }, this.promptEl, this.view.dom);
    // The app's single-key shortcuts never see what is typed here.
    this.inputRow.addEventListener("keydown", (e) => {
      if (!(e.ctrlKey || e.metaKey) || !["k", "p", "P"].includes(e.key)) e.stopPropagation();
    });
    this.out.addEventListener("click", () => {
      if (!window.getSelection()?.toString()) this.view.focus();
    });
    el.replaceChildren(
      h(
        "div",
        { class: "panel-head pc-head" },
        h("span", { class: "panel-title" }, "Python"),
        this.statusEl,
        this.roBadge,
        h("span", { class: "spacer" }),
        h("label", { class: "pc-ghidra dim", title: "Bind Ghidra's names (currentProgram, currentAddress, getFunctionAt, …) as Ghidra's Python console does" }, this.ghidraBox, " Ghidra names"),
        this.interruptBtn,
        h("button", { class: "btn small", type: "button", title: "Ctrl+L", "data-testid": "py-clear", onclick: () => this.clear() }, "Clear"),
        h("button", { class: "btn small", type: "button", title: "A new console: the namespace starts empty", "data-testid": "py-restart", onclick: () => void this.restart() }, "Restart"),
      ),
      this.out,
      this.inputRow,
    );
  }

  /** Opens the console (once): its banner and the history. */
  ensureOpen(): Promise<void> {
    this.opening ??= this.open();
    return this.opening;
  }

  focus() {
    void this.ensureOpen();
    this.view.focus();
  }

  private async open() {
    const st = await this.host.hostStatus();
    if (!st.enabled) {
      this.statusEl.textContent = "unavailable";
      this.append(`The daemon doesn't run Python for you: ${st.reason}\n`, "stderr");
      this.setEnabled(false);
      this.opening = null;
      return;
    }
    if (st.pythonProblem) {
      // No Python, or an SDK older than the daemon: say so, and offer to
      // set it up here (as the Script Manager does).
      this.statusEl.textContent = "unavailable";
      this.append(`${st.pythonProblem}\n`, "stderr");
      const btn: HTMLButtonElement = h("button", { class: "btn primary small", type: "button", "data-testid": "py-setup-python" }, "Set up Python");
      btn.onclick = async () => {
        btn.disabled = true;
        btn.textContent = "Setting up Python…";
        this.info("Setting up Python (its output is in the Scripts view)…");
        const ok = await this.host.setupPython();
        btn.remove();
        if (!ok) {
          this.append("Setting up Python failed; see the Scripts view.\n", "stderr");
          this.opening = null;
          return;
        }
        this.opening = null;
        this.host.show();
        await this.ensureOpen();
      };
      this.add(h("div", { class: "pc-setup" }, btn));
      this.setEnabled(false);
      this.opening = null;
      return;
    }
    this.setEnabled(true);
    this.statusEl.textContent = "starting…";
    await this.exec("", { quiet: true });
  }

  private setEnabled(on: boolean) {
    this.inputRow.classList.toggle("disabled", !on);
    this.view.dispatch({ effects: this.editable.reconfigure(EditorView.editable.of(on)) });
  }

  // ------------------------------------------------------------ running --

  /** Runs the input (Enter). While a statement runs, Enter waits for it. */
  async submit() {
    if (this.running) {
      this.pendingSubmit = true;
      return;
    }
    await this.ensureOpen();
    let text = this.view.state.doc.toString();
    const lines = text.split("\n");
    // In a block, an empty last line ends it (as in Python's REPL).
    if (this.inBlock && lines.length > 1 && lines[lines.length - 1].trim() === "") text = text.replace(/[ \t]*$/, "");
    await this.exec(text, {});
  }

  private async exec(input: string, o: { quiet?: boolean }) {
    this.running = true;
    this.interruptBtn.disabled = input === "";
    this.inputRow.classList.add("running");
    if (input) this.statusEl.textContent = "running…";
    const abort = new AbortController();
    this.abort = abort;
    let echoed = o.quiet || input === "";
    let stdout = "";
    let stderr = "";
    const echo = () => {
      if (echoed) return;
      echoed = true;
      this.echo(input);
    };
    let outcome: ConsoleOutcome;
    const loc = this.host.location();
    try {
      outcome = await consoleRun(
        this.host.rk,
        { programId: this.host.programId, input, address: loc ?? undefined, selection: this.host.selection() ?? undefined, ghidraNames: this.ghidraBox.checked },
        {
          signal: abort.signal,
          onStarted: (s) => this.onStarted(s),
          onOutput: (text, stream) => {
            echo();
            if (stream === "stderr") stderr += text;
            else stdout += text;
            this.append(text, stream);
          },
          onPrompt: (p) => {
            echo();
            return askForScript(p, "The console", this.host.location(), "the statement");
          },
        },
      );
    } catch (e) {
      outcome = { runId: this.runId, status: "failed", more: false, error: errText(e) };
    }
    this.abort = null;
    this.running = false;
    this.interruptBtn.disabled = true;
    this.inputRow.classList.remove("running");
    if (outcome.more) {
      // An open block: carry on writing it (after what was sent; anything
      // typed meanwhile stays after the new line).
      this.inBlock = true;
      this.promptEl.textContent = "...";
      const doc = this.view.state.doc.toString();
      const at = doc.startsWith(input) ? input.length : doc.length;
      const lastLine = input.slice(input.lastIndexOf("\n") + 1);
      const indent = (/^\s*/.exec(lastLine)?.[0] ?? "") + (/:\s*$/.test(lastLine) ? "    " : "");
      this.view.dispatch({ changes: { from: at, insert: "\n" + indent }, selection: EditorSelection.cursor(doc.length + 1 + indent.length) });
      this.statusEl.textContent = this.describe();
      this.flushPending();
      return;
    }
    if (input !== "") {
      echo();
      if (input.trim()) {
        const entry = input.replace(/\n+$/, "");
        if (this.history[this.history.length - 1] !== entry) this.history.push(entry);
      }
      this.inBlock = false;
      this.promptEl.textContent = ">>>";
      // What was typed while it ran stays.
      const doc = this.view.state.doc.toString();
      let keep = doc.startsWith(input) ? doc.slice(input.length).replace(/^\n/, "") : "";
      if (!keep.trim()) keep = "";
      this.view.dispatch({ changes: { from: 0, to: doc.length, insert: keep }, selection: EditorSelection.cursor(keep.length) });
      this.histPos = this.history.length;
      this.draft = "";
    }
    const seqs = outcome.result?.seqs ?? [];
    if (outcome.status === "failed") {
      this.append(`${outcome.error}\n`, "stderr");
      this.statusEl.textContent = "failed";
      this.opening = null;
    } else if (outcome.status === "died") {
      this.append(`${outcome.error}\n`, "stderr");
    } else if (outcome.status === "exit") {
      this.info("The console ended (exit()); the next statement starts a new one");
    }
    if (seqs.length) {
      const first = input.trim().split("\n")[0];
      this.host.recordUndo(`Console: ${first.length > 40 ? first.slice(0, 39) + "…" : first}`, seqs);
      this.info(`${seqs.length} edit${seqs.length === 1 ? "" : "s"} as script:console · Ctrl+Z undoes them`);
      const rev = outcome.result?.revisions.at(-1);
      if (rev) await this.host.settle(rev);
    }
    if (outcome.status !== "failed") this.statusEl.textContent = this.describe();
    this.flushPending();
    if (input !== "") {
      this.statements++;
      this.last = {
        input,
        status: outcome.status,
        more: outcome.more,
        stdout,
        stderr,
        seqs: seqs.map(String),
        runId: outcome.runId,
        error: outcome.error,
      };
    }
  }

  /** Enter pressed while the last call ran: run what is there now. */
  private flushPending() {
    if (!this.pendingSubmit) return;
    this.pendingSubmit = false;
    if (this.view.state.doc.length) queueMicrotask(() => void this.submit());
  }

  private onStarted(s: ScriptStarted) {
    const first = !this.started;
    this.started = s;
    this.runId = s.runId;
    this.host.own(s.runId);
    this.readOnly = s.readOnly;
    this.roBadge.hidden = !s.readOnly;
    if (first) {
      this.history = [...s.history];
      this.histPos = this.history.length;
      this.info(`Python ${s.pythonVersion} on ${s.programId} · revkit.script's names${this.ghidraBox.checked ? " and Ghidra's" : ""} · Tab completes (${s.completionEngine}) · help(rename)`);
      if (s.readOnly) this.info("Read-only: you are a viewer, so edits are refused");
    } else if (s.consoleStarted) {
      this.info("A new console (the old one ended): the namespace starts empty");
    }
  }

  private describe(): string {
    const s = this.started;
    return s ? `Python ${s.pythonVersion} · ${this.inBlock ? "block…" : "ready"}` : "";
  }

  /** Ctrl+C / Interrupt: KeyboardInterrupt in the running statement. */
  interrupt() {
    if (this.running && this.abort) {
      this.abort.abort();
      this.statusEl.textContent = "interrupting…";
    }
  }

  private ctrlC(v: EditorView): boolean {
    if (this.running) {
      this.interrupt();
      return true;
    }
    if (!v.state.selection.main.empty) return false; // copy
    // Drop the input, as a terminal does.
    const text = v.state.doc.toString();
    if (text) this.echo(text + "^C");
    this.inBlock = false;
    this.promptEl.textContent = ">>>";
    v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: "" } });
    this.histPos = this.history.length;
    return true;
  }

  clear() {
    this.out.replaceChildren();
  }

  /** Ends the console's host; the next statement (or this) starts another. */
  async restart() {
    if (this.runId) {
      try {
        await this.host.rk.scripts.cancelScript({ runId: this.runId });
      } catch (e) {
        toast(`Can't close the console: ${errText(e)}`, { kind: "error" });
      }
    }
    this.started = null;
    this.runId = "";
    this.opening = null;
    this.clear();
    await this.ensureOpen();
  }

  /** The cursor or the selection moved: current_* follow (debounced). */
  contextMoved() {
    if (!this.runId) return;
    clearTimeout(this.ctxTimer);
    this.ctxTimer = window.setTimeout(() => {
      const loc = this.host.location();
      const sel = this.host.selection();
      void this.host.rk.scripts
        .updateContext({
          runId: this.runId,
          context: {
            address: loc === null ? undefined : { offset: loc },
            selection: sel ? { first: { offset: sel[0] }, last: { offset: sel[1] } } : undefined,
          },
        })
        .catch(() => undefined);
    }, 150);
  }

  // ------------------------------------------------------- completion --

  private async complete(text: string) {
    if (!this.runId) return null;
    try {
      return await completeConsole(this.host.rk, this.host.programId, text, 200);
    } catch {
      return null;
    }
  }

  private async signatureOf(callee: string): Promise<{ signature: string; doc: string } | null> {
    const r = await this.complete(callee);
    const name = callee.split(".").pop() ?? callee;
    const c = r?.completions.find((x) => x.text === name && x.signature);
    return c ? { signature: c.signature, doc: c.doc } : null;
  }

  private tab(v: EditorView): boolean {
    if (completionStatus(v.state) === "active") return acceptCompletion(v);
    const pos = v.state.selection.main.head;
    const before = v.state.doc.sliceString(Math.max(0, pos - 1), pos);
    if (v.state.selection.main.empty && /[\w.]/.test(before)) return startCompletion(v);
    if (v.state.selection.main.empty) {
      v.dispatch(v.state.replaceSelection("    "));
      return true;
    }
    return indentMore(v);
  }

  // ---------------------------------------------------------- history --

  private historyMove(v: EditorView, dir: -1 | 1): boolean {
    if (completionStatus(v.state)) return false;
    const pos = v.state.selection.main.head;
    const line = v.state.doc.lineAt(pos).number;
    if (dir < 0 && line !== 1) return false;
    if (dir > 0 && line !== v.state.doc.lines) return false;
    const next = this.histPos + dir;
    if (next < 0 || next > this.history.length) return true;
    if (this.histPos === this.history.length) this.draft = v.state.doc.toString();
    this.histPos = next;
    const text = next === this.history.length ? this.draft : this.history[next];
    v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: text }, selection: EditorSelection.cursor(text.length) });
    this.inBlock = false;
    this.promptEl.textContent = ">>>";
    return true;
  }

  // ----------------------------------------------------------- output --

  private echo(input: string) {
    const lines = input.replace(/\n+$/, "").split("\n");
    this.add(h("span", { class: "pc-in" }, lines.map((l, i) => `${i ? "... " : ">>> "}${l}`).join("\n") + "\n"));
  }

  private info(text: string) {
    this.add(h("span", { class: "pc-info dim" }, text + "\n"));
  }

  private append(text: string, stream: string) {
    this.add(h("span", { class: stream === "stderr" ? "sm-stderr" : "" }, text));
  }

  private add(node: HTMLElement) {
    const atEnd = this.out.scrollTop + this.out.clientHeight >= this.out.scrollHeight - 4;
    this.out.append(node);
    while (this.out.childNodes.length > MAX_NODES) this.out.firstChild?.remove();
    if (atEnd) this.out.scrollTop = this.out.scrollHeight;
  }
}
