// The emulator view: one EmulatorService session for the open program.
// Self-contained (its DOM, styles and keys); the app docks `el` as a view
// (the side group by default) and gives it a host for showing the program
// counter. Session state
// is this client's, not facts: nothing here makes an assertion.
//
//   F7 step into · F8 step over · Shift+F8 step out · F9 continue

import {
  EmulatorRunMode,
  EmulatorStartMode,
  EmulatorStopKind,
  type CreateEmulatorSessionResponse,
  type EmulatorRegisterValue,
  type EmulatorState,
  type EmulatorStop,
  type Revkit,
} from "@revkit/api";
import { h } from "../ui/dom";
import "./emu.css";

export interface EmulatorHost {
  /** Execution stopped at `pc` (null: no session): show it. */
  showPc(pc: bigint | null): void;
  /** Breakpoints or the pc changed: redraw markers. */
  marksChanged(): void;
  /** Bring the panel into view (a session started). */
  show(): void;
  notify(text: string, error?: boolean): void;
}

const STOP_TEXT: Partial<Record<EmulatorStopKind, string>> = {
  [EmulatorStopKind.NONE]: "ready",
  [EmulatorStopKind.STEPPED]: "stepped",
  [EmulatorStopKind.STEP_LIMIT]: "step limit",
  [EmulatorStopKind.BREAKPOINT]: "breakpoint",
  [EmulatorStopKind.UNTIL]: "reached",
  [EmulatorStopKind.RETURNED]: "returned",
  [EmulatorStopKind.EXITED]: "exited",
  [EmulatorStopKind.HALTED]: "halted",
  [EmulatorStopKind.UNMAPPED]: "unmapped access",
  [EmulatorStopKind.PROTECTION]: "protection fault",
  [EmulatorStopKind.DECODE]: "bad instruction",
  [EmulatorStopKind.UNIMPLEMENTED]: "unimplemented",
  [EmulatorStopKind.USEROP]: "no handler",
  [EmulatorStopKind.SYSCALL]: "system call",
  [EmulatorStopKind.WATCHPOINT]: "watchpoint",
  [EmulatorStopKind.HOOK]: "hook",
  [EmulatorStopKind.DIVIDE_BY_ZERO]: "divide by zero",
  [EmulatorStopKind.MEMORY_LIMIT]: "memory limit",
  [EmulatorStopKind.TIME_LIMIT]: "time limit",
  [EmulatorStopKind.CANCELLED]: "cancelled",
  [EmulatorStopKind.SESSION_LIMIT]: "session step limit",
};
const FAULTS = new Set([
  EmulatorStopKind.UNMAPPED,
  EmulatorStopKind.PROTECTION,
  EmulatorStopKind.DECODE,
  EmulatorStopKind.UNIMPLEMENTED,
  EmulatorStopKind.USEROP,
  EmulatorStopKind.SYSCALL,
  EmulatorStopKind.DIVIDE_BY_ZERO,
  EmulatorStopKind.MEMORY_LIMIT,
]);

const hx = (v: bigint, w = 0) => v.toString(16).padStart(w, "0");
const MEM_ROWS = 8;

export class EmulatorPanel {
  readonly el: HTMLElement;
  /** Breakpoints, kept while no session runs and given to the next one. */
  readonly breakpoints = new Set<bigint>();
  session: CreateEmulatorSessionResponse | null = null;
  state: EmulatorState | null = null;
  stop: EmulatorStop | null = null;
  pc: bigint | null = null;
  busy = false;
  private entry: bigint | null = null;
  private memExpr = "";
  private memAt: bigint | null = null;

  private readonly title: HTMLElement;
  private readonly empty: HTMLElement = h(
    "div",
    { class: "emu-empty dim", "data-testid": "emu-empty" },
    "No emulation. Select an instruction and run \u201cEmulate from here\u201d (Ctrl+Shift+P); click the listing's gutter for breakpoints.",
  );
  private readonly status: HTMLElement;
  private readonly regsEl: HTMLElement;
  private readonly memInput: HTMLInputElement;
  private readonly memEl: HTMLElement;
  private readonly outEl: HTMLElement;
  private readonly buttons: Record<string, HTMLButtonElement> = {};

  constructor(
    private rk: Revkit,
    private programId: string,
    private host: EmulatorHost,
    private addrWidth = 8,
  ) {
    const button = (id: string, label: string, title: string, run: () => void) =>
      (this.buttons[id] = h("button", { class: "btn emu-btn", type: "button", title, "data-testid": `emu-${id}`, onclick: run }, label));
    this.title = h("span", { class: "dim", "data-testid": "emu-title" });
    this.status = h("span", { class: "emu-status", "data-testid": "emu-status" });
    this.regsEl = h("div", { class: "emu-regs mono", "data-testid": "emu-regs" });
    this.memInput = h("input", { class: "emu-mem-input mono", placeholder: "address or register", spellcheck: "false", "data-testid": "emu-mem-input" });
    this.memInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        this.memExpr = this.memInput.value.trim();
        void this.refreshMemory();
      }
      e.stopPropagation();
    });
    this.memEl = h("pre", { class: "emu-mem mono", "data-testid": "emu-mem" });
    this.outEl = h("pre", { class: "emu-out mono", "data-testid": "emu-out" });
    this.el = h(
      "section",
      { id: "emu", class: "pane view emu", "data-testid": "emulator" },
      h(
        "div",
        { class: "panel-head" },
        h("span", { class: "panel-title" }, "Emulator"),
        this.title,
        h(
          "span",
          { class: "emu-tools" },
          button("into", "Step", "Step into (F7)", () => void this.run(EmulatorRunMode.STEP_INTO)),
          button("over", "Over", "Step over (F8)", () => void this.run(EmulatorRunMode.STEP_OVER)),
          button("out", "Out", "Step out (Shift+F8)", () => void this.run(EmulatorRunMode.STEP_OUT)),
          button("run", "Continue", "Run to a breakpoint or a stop (F9)", () => void this.run(EmulatorRunMode.RUN)),
          button("restart", "Restart", "Start again from the same address", () => void this.restart()),
          button("close", "×", "Close the session", () => void this.close()),
        ),
        this.status,
      ),
      this.empty,
      h(
        "div",
        { class: "emu-body" },
        this.regsEl,
        h("div", { class: "emu-memwrap" }, h("div", { class: "emu-memhead" }, h("span", { class: "dim" }, "Memory"), this.memInput), this.memEl),
        this.outEl,
      ),
    );
    this.enable();
  }

  get active(): boolean {
    return this.session !== null;
  }

  /** Starts a session at `entry` (a Linux process at an ELF's entry point,
   * else a call into it; firmware runs bare). */
  async start(entry: bigint) {
    if (this.session) await this.close(false);
    this.entry = entry;
    this.busy = true;
    this.enable();
    try {
      this.session = await this.rk.emulator.createEmulatorSession({
        programId: this.programId,
        entry: { offset: entry },
        mode: EmulatorStartMode.UNSPECIFIED,
        breakpoints: [...this.breakpoints].map((b) => ({ offset: b })),
      });
    } catch (e) {
      this.busy = false;
      this.enable();
      this.host.notify(`Emulator: ${e instanceof Error ? e.message : e}`, true);
      return;
    }
    this.busy = false;
    this.el.classList.add("live");
    this.host.show();
    this.title.textContent = `${this.session.language} · from 0x${hx(entry)}`;
    if (!this.memExpr) this.memExpr = this.session.spRegister;
    this.memInput.value = this.memExpr;
    this.apply(this.session.state ?? null, this.session.state?.lastStop ?? null);
  }

  async run(mode: EmulatorRunMode) {
    if (!this.session || this.busy) return;
    this.busy = true;
    this.enable();
    this.status.textContent = "running…";
    try {
      const r = await this.rk.emulator.runEmulator({ sessionId: this.session.sessionId, mode });
      this.apply(r.state ?? null, r.stop ?? null);
    } catch (e) {
      this.host.notify(`Emulator: ${e instanceof Error ? e.message : e}`, true);
      this.status.textContent = "error";
    } finally {
      this.busy = false;
      this.enable();
    }
  }

  async restart() {
    if (this.entry !== null) await this.start(this.entry);
  }

  async close(hide = true) {
    const s = this.session;
    this.session = null;
    this.state = null;
    this.stop = null;
    this.pc = null;
    if (s) await this.rk.emulator.closeEmulatorSession({ sessionId: s.sessionId }).catch(() => {});
    if (hide) {
      this.el.classList.remove("live");
      this.title.textContent = "";
      this.status.textContent = "";
    }
    this.enable();
    this.host.showPc(null);
    this.host.marksChanged();
  }

  /** Adds or removes a breakpoint (the listing gutter). */
  async toggleBreakpoint(addr: bigint) {
    const add = !this.breakpoints.has(addr);
    if (add) this.breakpoints.add(addr);
    else this.breakpoints.delete(addr);
    this.host.marksChanged();
    if (!this.session) return;
    try {
      await this.rk.emulator.setEmulatorBreakpoints({
        sessionId: this.session.sessionId,
        add: add ? [{ offset: addr }] : [],
        remove: add ? [] : [{ offset: addr }],
      });
    } catch (e) {
      this.host.notify(`Emulator: ${e instanceof Error ? e.message : e}`, true);
    }
  }

  /** F7, F8, Shift+F8, F9 while a session is open; true if handled. */
  handleKey(e: KeyboardEvent): boolean {
    if (!this.session) return false;
    const mode =
      e.key === "F7" ? EmulatorRunMode.STEP_INTO
      : e.key === "F8" && e.shiftKey ? EmulatorRunMode.STEP_OUT
      : e.key === "F8" ? EmulatorRunMode.STEP_OVER
      : e.key === "F9" ? EmulatorRunMode.RUN
      : null;
    if (mode === null) return false;
    void this.run(mode);
    return true;
  }

  private enable() {
    const on = this.session !== null && !this.busy;
    for (const id of ["into", "over", "out", "run"]) this.buttons[id].disabled = !on;
    this.buttons.restart.disabled = this.busy || this.entry === null;
  }

  private apply(state: EmulatorState | null, stop: EmulatorStop | null) {
    this.state = state;
    this.stop = stop;
    this.pc = state?.pc?.offset ?? null;
    const kind = stop?.kind ?? EmulatorStopKind.NONE;
    const what = STOP_TEXT[kind] ?? "stopped";
    let text = `${what} at 0x${hx(this.pc ?? 0n, this.addrWidth)} · ${state?.steps ?? 0n} steps`;
    if (kind === EmulatorStopKind.EXITED || kind === EmulatorStopKind.RETURNED) text += ` · ${kind === EmulatorStopKind.EXITED ? "status" : "value"} ${stop?.exitCode}`;
    this.status.textContent = text;
    this.status.title = stop?.detail ?? "";
    this.status.classList.toggle("fault", FAULTS.has(kind));
    this.status.dataset.kind = what;
    this.renderRegisters(state?.registers ?? []);
    this.outEl.textContent = new TextDecoder().decode(state?.stdout ?? new Uint8Array()) + new TextDecoder().decode(state?.stderr ?? new Uint8Array());
    this.outEl.hidden = this.outEl.textContent === "";
    this.host.showPc(this.pc);
    this.host.marksChanged();
    void this.refreshMemory();
  }

  private renderRegisters(regs: EmulatorRegisterValue[]) {
    const cells = regs.map((r) => {
      const v = r.bytes.length ? [...r.bytes].reverse().reduce((a, b) => (a << 8n) | BigInt(b), 0n) : r.value;
      const width = r.size > 1 ? Math.min(r.size, 8) * 2 : 1;
      const value = h("span", { class: "emu-val", title: "Double-click to change" }, hx(v, width));
      value.addEventListener("dblclick", () => this.editRegister(r.name, value));
      return h("div", { class: `emu-reg${r.changed ? " changed" : ""}`, "data-reg": r.name }, h("span", { class: "emu-name" }, r.name), value);
    });
    this.regsEl.replaceChildren(...cells);
  }

  private editRegister(name: string, cell: HTMLElement) {
    if (!this.session) return;
    const input = h("input", { class: "emu-edit mono", value: cell.textContent ?? "" });
    cell.replaceChildren(input);
    input.focus();
    input.select();
    input.addEventListener("keydown", async (e) => {
      e.stopPropagation();
      if (e.key === "Escape") return this.renderRegisters(this.state?.registers ?? []);
      if (e.key !== "Enter") return;
      let value: bigint;
      try {
        value = BigInt(input.value.startsWith("0x") || /^-?\d+$/.test(input.value) ? input.value : `0x${input.value}`);
      } catch {
        this.host.notify(`Not a number: ${input.value}`, true);
        return;
      }
      try {
        const r = await this.rk.emulator.writeEmulatorRegisters({ sessionId: this.session!.sessionId, registers: [{ name, value: BigInt.asUintN(64, value) }] });
        this.apply(r.state ?? null, this.stop);
      } catch (err) {
        this.host.notify(`Emulator: ${err instanceof Error ? err.message : err}`, true);
      }
    });
  }

  /** The memory view: the address typed (hex), or a register's value. */
  private async refreshMemory() {
    if (!this.session) return;
    let at: bigint | null = null;
    const expr = this.memExpr;
    const reg = this.state?.registers.find((r) => r.name.toLowerCase() === expr.toLowerCase());
    if (reg) at = reg.value;
    else if (/^(0x)?[0-9a-f]+$/i.test(expr)) at = BigInt(expr.startsWith("0x") ? expr : `0x${expr}`);
    else if (expr) {
      try {
        const st = await this.rk.emulator.getEmulatorState({ sessionId: this.session.sessionId, state: { registers: [expr] } });
        at = st.state?.registers[0]?.value ?? null;
      } catch {
        at = null;
      }
    }
    if (at === null) {
      this.memEl.textContent = expr ? `${expr}: not an address or register` : "";
      return;
    }
    at &= ~0xfn;
    this.memAt = at;
    try {
      const r = await this.rk.emulator.readEmulatorMemory({ sessionId: this.session.sessionId, address: { offset: at }, length: 16 * MEM_ROWS });
      if (this.memAt !== at) return;
      const unmapped = new Set<number>();
      for (const u of r.unmapped) for (let i = 0; i < u.length; i++) unmapped.add(u.offset + i);
      const lines: string[] = [];
      for (let row = 0; row < MEM_ROWS; row++) {
        let hexs = "";
        let ascii = "";
        for (let i = 0; i < 16; i++) {
          const k = row * 16 + i;
          const b = r.data[k] ?? 0;
          hexs += (unmapped.has(k) ? "??" : b.toString(16).padStart(2, "0")) + (i === 7 ? "  " : " ");
          ascii += unmapped.has(k) ? " " : b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
        }
        lines.push(`${hx(at + BigInt(row * 16), this.addrWidth)}  ${hexs} ${ascii}`);
      }
      this.memEl.textContent = lines.join("\n");
    } catch (e) {
      this.memEl.textContent = e instanceof Error ? e.message : String(e);
    }
  }
}
