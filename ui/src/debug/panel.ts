// The Debugger view: one DebugService session for the open program, whatever
// runs it (revkit's emulator, a GDB remote stub, the program launched on the
// daemon's host). Self-contained (its DOM, styles and keys); the app docks
// `el` as a view and gives it a host for the pc mark and the selection.
// It keeps the emulator panel's element ids and test ids (#emu, emu-*), so
// "Emulate from here" works as it did. Session state is this client's, not
// facts: nothing here makes an assertion.
//
//   F7 step into · F8 step over · Shift+F8 step out · F9 continue
//
// Every stop is recorded; the timeline scrubber shows any recorded snapshot:
// registers, memory and the pc mark as they were (time travel).
//
// Firmware (feature firmware-emulation): "Emulator (machine…)" runs the
// program on a machine description (saved with the program, derived from
// it, or edited here); the timeline then marks the exceptions the CPU took,
// a UART takes typed input, and the run can stop on exceptions.

import {
  DebugBreakpointKind,
  DebugRunMode,
  DebugSnapshotKind,
  DebugStopKind,
  DebugTargetState,
  EmulatorStartMode,
  type CreateDebugSessionRequest,
  type CreateDebugSessionResponse,
  type DebugBreakpoint,
  type DebugFrame,
  type DebugInstruction,
  type DebugLocation,
  type DebugRegisterValue,
  type DebugState,
  type DebugStop,
  type CopyDebugMemoryResponse,
  DebugCopyMode,
  type EvaluateDebugResponse,
  type Revkit,
} from "@revkit/api";
import type { ValueItem } from "../ui/hover";
import { userProvenance } from "../api/client";
import { h } from "../ui/dom";
import { ask, askFields, choose } from "../ui/dialogs";
import "../emu/emu.css";
import "./debug.css";

/** Another project program (a library the pc is in) in a new tab, at an address. */
function openLibrary(programId: string, address?: bigint) {
  const u = new URL(location.href);
  u.searchParams.set("program", programId);
  u.hash = address !== undefined ? `#${address.toString(16)}` : "";
  window.open(u.toString(), "_blank", "noopener");
}

export interface DebuggerHost {
  /** Execution stands at `pc` (a program address; null: none, or outside the program): show it. */
  showPc(pc: bigint | null): void;
  /** Breakpoints or the pc changed: redraw markers. */
  marksChanged(): void;
  /** Bring the panel into view (a session started). */
  show(): void;
  notify(text: string, error?: boolean): void;
  /** The selected instruction, where the emulator starts. */
  selection(): bigint | null;
  /** A call-stack frame was chosen: show its pc (a program address) in the listing and decompiler. */
  showFrame?(pc: bigint): void;
}

export type RunName = "into" | "over" | "out" | "run";

/** A watch: an expression, in the innermost frame of `fn` when set (a function's variable), else in the selected frame. */
export interface Watch {
  expr: string;
  fn?: bigint;
  open?: boolean;
}
export interface WatchValue {
  text: string;
  type: string;
  error: string;
  changed: boolean;
  children: { name: string; text: string; type: string }[];
}
export type TargetChoice = "emulator" | "machine" | "remote" | "launch";

/** An exception the timeline recorded (a snapshot with an event). */
export interface TimelineEvent {
  index: bigint;
  kind: string;
  number: number;
  text: string;
}

const RUN_MODES: Record<RunName, DebugRunMode> = {
  into: DebugRunMode.STEP_INTO,
  over: DebugRunMode.STEP_OVER,
  out: DebugRunMode.STEP_OUT,
  run: DebugRunMode.RUN,
};

const STOP_TEXT: Partial<Record<DebugStopKind, string>> = {
  [DebugStopKind.NONE]: "ready",
  [DebugStopKind.STEPPED]: "stepped",
  [DebugStopKind.STEP_LIMIT]: "step limit",
  [DebugStopKind.BREAKPOINT]: "breakpoint",
  [DebugStopKind.UNTIL]: "reached",
  [DebugStopKind.RETURNED]: "returned",
  [DebugStopKind.EXITED]: "exited",
  [DebugStopKind.HALTED]: "halted",
  [DebugStopKind.UNMAPPED]: "unmapped access",
  [DebugStopKind.PROTECTION]: "protection fault",
  [DebugStopKind.DECODE]: "bad instruction",
  [DebugStopKind.UNIMPLEMENTED]: "unimplemented",
  [DebugStopKind.USEROP]: "no handler",
  [DebugStopKind.SYSCALL]: "system call",
  [DebugStopKind.WATCHPOINT]: "watchpoint",
  [DebugStopKind.HOOK]: "hook",
  [DebugStopKind.DIVIDE_BY_ZERO]: "divide by zero",
  [DebugStopKind.MEMORY_LIMIT]: "memory limit",
  [DebugStopKind.TIME_LIMIT]: "time limit",
  [DebugStopKind.CANCELLED]: "cancelled",
  [DebugStopKind.SESSION_LIMIT]: "session step limit",
  [DebugStopKind.SIGNAL]: "signal",
  [DebugStopKind.INTERRUPTED]: "interrupted",
  [DebugStopKind.RUNNING]: "running",
  [DebugStopKind.KILLED]: "killed",
  [DebugStopKind.DETACHED]: "detached",
  [DebugStopKind.DISCONNECTED]: "disconnected",
  [DebugStopKind.EXCEPTION]: "exception",
  [DebugStopKind.IDLE]: "idle",
};
const FAULTS = new Set([
  DebugStopKind.UNMAPPED,
  DebugStopKind.PROTECTION,
  DebugStopKind.DECODE,
  DebugStopKind.UNIMPLEMENTED,
  DebugStopKind.USEROP,
  DebugStopKind.SYSCALL,
  DebugStopKind.DIVIDE_BY_ZERO,
  DebugStopKind.MEMORY_LIMIT,
  DebugStopKind.SIGNAL,
  DebugStopKind.KILLED,
  DebugStopKind.DISCONNECTED,
]);
const SNAP_KIND: Record<number, string> = {
  [DebugSnapshotKind.STOP]: "stop",
  [DebugSnapshotKind.STEP]: "step",
  [DebugSnapshotKind.EDIT]: "edit",
};

const hx = (v: bigint, w = 0) => v.toString(16).padStart(w, "0");
const MEM_ROWS = 8;
const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));

export class DebuggerPanel {
  readonly el: HTMLElement;
  /** Breakpoints (program addresses), kept while no session runs and given to the next one. */
  readonly breakpoints = new Set<bigint>();
  session: CreateDebugSessionResponse | null = null;
  state: DebugState | null = null;
  stop: DebugStop | null = null;
  /** The pc shown, as a program address (null outside the program). */
  pc: bigint | null = null;
  busy = false;
  /** A live target is running (Pause stops it). */
  running = false;
  /** The snapshot shown when looking back; null: now. */
  shown: bigint | null = null;
  first = 0n;
  last = 0n;
  threads: { id: string; current: boolean }[] = [];
  modules: string[] = [];
  /** Exceptions on the timeline (sessions on a machine). */
  events: TimelineEvent[] = [];
  /** The call stack at the stop or snapshot shown (feature debugger-stack). */
  frames: DebugFrame[] = [];
  /** The frame whose registers show (0: the stop's own). */
  frame = 0;
  /** Breakpoint conditions, ignore counts and disabled state by program address (feature
   * debugger-conditions): given to each session, kept while none runs. */
  readonly bpOptions = new Map<bigint, { condition: string; ignoreCount: number; disabled: boolean }>();
  /** The session's breakpoints, as it last reported them. */
  bpList: DebugBreakpoint[] = [];
  /** Runtime disassembly (feature debugger-disassembly): the rows shown, and whether they follow the pc. */
  disasm: DebugInstruction[] = [];
  followPc = true;
  private disasmNext: bigint | null = null;
  /** Watch expressions (feature debugger-watches), kept per program in this browser. */
  watches: Watch[] = [];
  /** Their values at the stop or snapshot shown. */
  watchValues: WatchValue[] = [];
  /** Snapshots of the stops seen, in order: a watch is marked changed against the stop before. */
  private stops: bigint[] = [];
  /** The machine description the editor holds (derived or edited), when not a saved one as is. */
  machineText = "";
  private request: CreateDebugSessionRequest | null = null;
  /** The session an emulator was started from (Emulate from here), shown again when that emulator closes. */
  parent: { session: CreateDebugSessionResponse; request: CreateDebugSessionRequest | null; label: string } | null = null;
  private memExpr = "";
  private memAt: bigint | null = null;
  private outputSize = 0n;
  private output = "";
  private scrubTimer = 0;
  private generation = 0;

  private readonly title: HTMLElement;
  private readonly empty: HTMLElement;
  private readonly status: HTMLElement;
  /** "Open libc.so.6 at strlen": the pc in a library that is a project program (feature program-libraries). */
  private readonly libLink: HTMLButtonElement;
  private readonly targetSel: HTMLSelectElement;
  private readonly targetInput: HTMLInputElement;
  private readonly scrub: HTMLInputElement;
  private readonly scrubLabel: HTMLElement;
  private readonly liveBtn: HTMLButtonElement;
  private readonly resumeHereBtn: HTMLButtonElement;
  private readonly regsEl: HTMLElement;
  private readonly threadsEl: HTMLElement;
  private readonly stackEl: HTMLElement;
  private readonly watchBox: HTMLElement;
  private readonly bpBox: HTMLDetailsElement;
  private readonly bpEl: HTMLElement;
  private readonly disasmBox: HTMLDetailsElement;
  private readonly disasmEl: HTMLElement;
  private readonly disasmInput: HTMLInputElement;
  private readonly followBox: HTMLInputElement;
  private readonly watchList: HTMLElement;
  private readonly watchInput: HTMLInputElement;
  private readonly stackBox: HTMLDetailsElement;
  private readonly modulesBox: HTMLDetailsElement;
  private readonly modulesEl: HTMLElement;
  private readonly memInput: HTMLInputElement;
  private readonly memEl: HTMLElement;
  private readonly outEl: HTMLElement;
  private readonly buttons: Record<string, HTMLButtonElement> = {};
  private readonly machineRow: HTMLElement;
  private readonly machineSel: HTMLSelectElement;
  private readonly machineEdit: HTMLTextAreaElement;
  private readonly machineBox: HTMLDetailsElement;
  private readonly machineNotes: HTMLElement;
  private readonly eventsEl: HTMLElement;
  private readonly eventsLabel: HTMLElement;
  private readonly firmwareRow: HTMLElement;
  private readonly uartInput: HTMLInputElement;
  private readonly breakExc: HTMLInputElement;

  constructor(
    private rk: Revkit,
    private programId: string,
    private host: DebuggerHost,
    private addrWidth = 8,
    /** Live targets allowed (feature debugger-live). */
    live = false,
    /** Machines (feature firmware-emulation). */
    machines = false,
    /** The call stack (feature debugger-stack). */
    private stack = false,
    /** Values: watches and hovers (feature debugger-values). */
    readonly values = false,
    /** Runtime disassembly (feature debugger-disassembly). */
    readonly disassembly = false,
    /** Copying runtime memory into the program (feature debugger-copy). */
    readonly copy = false,
    /** Conditional breakpoints and the breakpoint table (feature debugger-conditions). */
    readonly conditions = false,
    /** An emulator from the session's state (feature debugger-emulate-from). */
    readonly emulateFrom = false,
  ) {
    const button = (id: string, label: string, title: string, run: () => void, testid = `emu-${id}`) =>
      (this.buttons[id] = h("button", { class: "btn emu-btn", type: "button", title, "data-testid": testid, onclick: run }, label));
    this.title = h("span", { class: "dim dbg-title", "data-testid": "emu-title" });
    this.status = h("span", { class: "emu-status", "data-testid": "emu-status" });
    this.libLink = h("button", { class: "link dbg-lib-link", type: "button", hidden: true, "data-testid": "dbg-library-link" }) as HTMLButtonElement;
    this.empty = h(
      "div",
      { class: "emu-empty dim", "data-testid": "emu-empty" },
      "No session. Pick a target and Start, or select an instruction and run “Emulate from here” (Ctrl+Shift+P); click the listing's gutter for breakpoints.",
    );
    this.targetSel = h(
      "select",
      { class: "dbg-target", "data-testid": "dbg-target", title: "What runs the program" },
      h("option", { value: "emulator" }, "Emulator"),
      h("option", { value: "machine", disabled: !machines, title: "Firmware on a machine description: memory, peripherals, interrupts" }, "Emulator (machine…)"),
      h("option", { value: "remote", disabled: !live }, "gdb remote host:port"),
      h("option", { value: "launch", disabled: !live }, "Launch locally"),
    );
    this.targetInput = h("input", { class: "dbg-target-input mono", spellcheck: "false", "data-testid": "dbg-target-input" });
    this.targetInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void this.connect();
      e.stopPropagation();
    });
    this.targetSel.addEventListener("change", () => this.targetChanged());
    // The machine picker: saved descriptions, derive one, edit and save.
    this.machineSel = h("select", { class: "dbg-target", "data-testid": "dbg-machine", title: "A machine saved with the program" });
    this.machineSel.addEventListener("change", () => void this.machineChosen());
    this.machineEdit = h("textarea", { class: "dbg-machine-json mono", spellcheck: "false", rows: 12, "data-testid": "dbg-machine-json", placeholder: "A machine description (JSON): docs/firmware-emulation.md" });
    this.machineEdit.addEventListener("keydown", (e) => e.stopPropagation());
    this.machineEdit.addEventListener("input", () => (this.machineText = this.machineEdit.value));
    this.machineNotes = h("div", { class: "dbg-machine-notes dim", "data-testid": "dbg-machine-notes" });
    this.machineBox = h(
      "details",
      { class: "dbg-machine-box" },
      h("summary", {}, "Edit"),
      this.machineEdit,
      this.machineNotes,
      h("button", { class: "btn emu-btn", type: "button", "data-testid": "dbg-machine-save", title: "Save this description with the program", onclick: () => void this.saveMachine() }, "Save as…"),
    );
    this.machineRow = h(
      "div",
      { class: "dbg-machine", hidden: true },
      this.machineSel,
      h("button", { class: "btn emu-btn", type: "button", "data-testid": "dbg-derive", title: "A starter machine from the program: its memory, the MMIO its code reaches, polling loops answered", onclick: () => void this.deriveMachine() }, "Derive"),
      this.machineBox,
    );
    // Firmware sessions: interrupts on the timeline, UART input, exception breakpoints.
    this.eventsEl = h("div", { class: "dbg-events", "data-testid": "dbg-events", title: "Exceptions the CPU took: click one to look at it" });
    this.eventsLabel = h("span", { class: "dbg-events-label dim", "data-testid": "dbg-events-label" });
    this.uartInput = h("input", { class: "dbg-target-input mono", placeholder: "to the UART (Enter sends a line)", spellcheck: "false", "data-testid": "dbg-uart-input" });
    this.uartInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void this.sendInput(this.uartInput.value + "\n");
      e.stopPropagation();
    });
    this.breakExc = h("input", { type: "checkbox", "data-testid": "dbg-break-exceptions" });
    this.breakExc.addEventListener("change", () => void this.setExceptionBreaks());
    this.firmwareRow = h(
      "div",
      { class: "dbg-firmware", hidden: true },
      h("label", { class: "dim", title: "Stop when the CPU takes an exception (IRQ, FIQ, SWI, SVC, SysTick, ...)" }, this.breakExc, " Break on exceptions"),
      this.uartInput,
    );
    this.scrub = h("input", { class: "dbg-scrub", type: "range", min: "0", max: "0", value: "0", "data-testid": "dbg-scrub", title: "Recorded snapshots: drag to look back" });
    this.scrub.addEventListener("input", () => this.scrubbed());
    this.scrub.addEventListener("keydown", (e) => e.stopPropagation());
    this.scrubLabel = h("span", { class: "dbg-scrub-label mono dim", "data-testid": "dbg-scrub-label" });
    this.liveBtn = h("button", { class: "btn emu-btn", type: "button", title: "Back to now", "data-testid": "dbg-live", onclick: () => void this.showSnapshot(null) }, "Now");
    this.resumeHereBtn = h(
      "button",
      { class: "btn emu-btn", type: "button", hidden: true, title: "Go back to this snapshot and continue from it (the emulator): the later snapshots are dropped, or kept as a trace", "data-testid": "dbg-resume-here", onclick: () => void this.rewind(this.shown) },
      "Resume from here",
    );
    this.regsEl = h("div", { class: "emu-regs mono", "data-testid": "emu-regs" });
    this.threadsEl = h("div", { class: "dbg-threads mono", "data-testid": "dbg-threads" });
    this.stackEl = h("div", { class: "dbg-stack mono", role: "listbox", "aria-label": "Call stack", "data-testid": "dbg-stack" });
    this.watchInput = h("input", { class: "dbg-target-input mono", placeholder: "add a watch: $RAX, *(int *)($RBP - 0x14), ctx->len", spellcheck: "false", "data-testid": "dbg-watch-input" });
    this.watchInput.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Enter" && this.watchInput.value.trim()) {
        this.addWatch(this.watchInput.value.trim());
        this.watchInput.value = "";
      }
    });
    this.watchList = h("div", { class: "dbg-watches mono", "data-testid": "dbg-watches" });
    this.watchBox = h("details", { class: "dbg-box dbg-watch-box", open: true, hidden: !values }, h("summary", {}, "Watches"), this.watchInput, this.watchList);
    this.disasmInput = h("input", { class: "dbg-target-input mono", placeholder: "address or expression: $RSP, 0x7ffff7c2a1ca, printf", spellcheck: "false", "data-testid": "dbg-disasm-input" });
    this.disasmInput.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Enter" && this.disasmInput.value.trim()) void this.disassembleExpr(this.disasmInput.value.trim());
    });
    this.followBox = h("input", { type: "checkbox", checked: true, "data-testid": "dbg-disasm-follow" });
    this.followBox.addEventListener("change", () => {
      this.followPc = this.followBox.checked;
      if (this.followPc) void this.showDisassembly(null);
    });
    this.disasmEl = h("div", { class: "dbg-disasm mono", role: "list", "aria-label": "Runtime disassembly", "data-testid": "dbg-disasm" });
    this.disasmBox = h(
      "details",
      { class: "dbg-box dbg-disasm-box", hidden: !disassembly, "data-testid": "dbg-disasm-box" },
      h("summary", {}, "Disassembly"),
      h("div", { class: "dbg-disasm-head" }, h("label", { class: "dim", title: "Show the instructions around the pc at each stop (always when the pc is outside the program)" }, this.followBox, " Follow pc"), this.disasmInput),
      this.disasmEl,
    );
    this.disasmBox.addEventListener("toggle", () => {
      if (this.disasmBox.open && !this.disasm.length) void this.showDisassembly(null);
    });
    this.bpEl = h("div", { class: "dbg-bps mono", role: "table", "aria-label": "Breakpoints", "data-testid": "dbg-bps" });
    this.bpBox = h("details", { class: "dbg-box dbg-bp-box", open: true, hidden: !conditions, "data-testid": "dbg-bp-box" }, h("summary", {}, "Breakpoints"), this.bpEl);
    this.watches = this.loadWatches();
    this.renderWatches();
    this.stackBox = h("details", { class: "dbg-box dbg-stack-box", open: true, hidden: !stack }, h("summary", {}, "Stack"), this.stackEl);
    this.modulesEl = h("div", { class: "dbg-modules mono", "data-testid": "dbg-modules" });
    this.modulesBox = h("details", { class: "dbg-box", "data-testid": "dbg-modules-box" }, h("summary", {}, "Modules"), this.modulesEl);
    this.modulesBox.addEventListener("toggle", () => void this.refreshModules());
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
        h("span", { class: "panel-title" }, "Debugger"),
        this.title,
        h(
          "span",
          { class: "emu-tools" },
          button("into", "Step", "Step into (F7)", () => void this.run("into")),
          button("over", "Over", "Step over (F8)", () => void this.run("over")),
          button("out", "Out", "Step out (Shift+F8)", () => void this.run("out")),
          button("run", "Continue", "Run to a breakpoint or a stop (F9)", () => void this.run("run")),
          button("pause", "Pause", "Stop the running target", () => void this.interrupt(), "dbg-pause"),
          button("fork", "Emulate", "Emulate from here: an emulator on this stop's (or snapshot's) registers and memory, read from the target when first touched; the target isn't changed", () => void this.emulateFromHere(), "dbg-emulate-here"),
          button("back", "Back", "Step back one instruction (Shift+F7): the emulator goes back to its previous snapshot", () => void this.rewind(null), "dbg-back"),
          button("restart", "Restart", "Start the same target again", () => void this.restart()),
          button("close", "×", "End the session (a launched process is killed)", () => void this.close()),
        ),
        this.status,
        this.libLink,
      ),
      h(
        "div",
        { class: "dbg-connect" },
        this.targetSel,
        this.targetInput,
        button("start", "Start", "Start a session on this target", () => void this.connect(), "dbg-start"),
        button("clearbp", "Clear breakpoints", "Remove every breakpoint", () => void this.clearBreakpoints(), "dbg-clear-bps"),
        this.machineRow,
      ),
      this.empty,
      h(
        "div",
        { class: "emu-body" },
        h("div", { class: "dbg-timeline" }, h("span", { class: "dim" }, "Timeline"), this.scrub, this.liveBtn, this.resumeHereBtn, this.eventsEl, this.eventsLabel, this.scrubLabel),
        this.firmwareRow,
        this.regsEl,
        this.watchBox,
        this.bpBox,
        this.disasmBox,
        h("div", { class: "dbg-lists" }, this.stackBox, h("details", { class: "dbg-box", open: true }, h("summary", {}, "Threads"), this.threadsEl), this.modulesBox),
        h("div", { class: "emu-memwrap" }, h("div", { class: "emu-memhead" }, h("span", { class: "dim" }, "Memory"), this.memInput), this.memEl),
        this.outEl,
      ),
    );
    this.targetChanged();
    this.enable();
  }

  get active(): boolean {
    return this.session !== null;
  }

  get historical(): boolean {
    return this.shown !== null && this.shown !== this.last;
  }

  /** Emulates from `entry` (a Linux process at an ELF's entry point, else a
   * call into it; firmware runs bare). */
  async start(entry: bigint | null) {
    this.targetSel.value = "emulator";
    this.targetChanged();
    await this.create({
      emulator: { entry: entry === null ? undefined : { offset: entry }, mode: EmulatorStartMode.UNSPECIFIED },
    });
  }

  /** Starts the target the picker names. */
  async connect() {
    const choice = this.targetSel.value as TargetChoice;
    const text = this.targetInput.value.trim();
    if (choice === "emulator") return this.start(this.host.selection());
    if (choice === "machine") {
      const name = this.machineSel.value;
      if (!name && !this.machineText.trim()) return this.host.notify("Pick a saved machine, Derive one, or write one under Edit", true);
      return this.create({ emulator: name && !this.machineText ? { machineName: name } : { machine: this.machineText } });
    }
    if (choice === "remote") {
      if (!text) return this.host.notify("Give the stub's host:port (gdbserver, qemu -gdb, OpenOCD :3333, J-Link :2331)", true);
      return this.create({ remote: { address: text } });
    }
    return this.create({ launch: { arguments: text ? text.split(/\s+/) : [] } });
  }

  private targetChanged() {
    const choice = this.targetSel.value as TargetChoice;
    this.targetInput.hidden = choice === "emulator" || choice === "machine";
    this.targetInput.placeholder = choice === "remote" ? "host:port or unix:/path" : "arguments";
    this.machineRow.hidden = choice !== "machine";
    if (choice === "machine") void this.refreshMachines();
  }

  // --- Machines (feature firmware-emulation) ---

  /** The machines saved with the program, in the picker. */
  async refreshMachines(select?: string) {
    try {
      const r = await this.rk.emulator.listMachines({ programId: this.programId });
      const keep = select ?? this.machineSel.value;
      this.machineSel.replaceChildren(
        h("option", { value: "" }, r.machines.length ? "(the description under Edit)" : "(no saved machines)"),
        ...r.machines.map((m) => h("option", { value: m.name, title: m.description }, m.name)),
      );
      if ([...this.machineSel.options].some((o) => o.value === keep)) this.machineSel.value = keep;
      else if (r.machines.length) this.machineSel.value = r.machines[0].name;
      await this.machineChosen();
    } catch (e) {
      this.host.notify(`Machines: ${errText(e)}`, true);
    }
  }

  private async machineChosen() {
    const name = this.machineSel.value;
    this.machineText = "";
    if (!name) return;
    try {
      const r = await this.rk.emulator.getMachine({ programId: this.programId, name });
      this.machineEdit.value = r.machine;
      this.machineNotes.textContent = r.info?.description ?? "";
    } catch (e) {
      this.host.notify(`Machine ${name}: ${errText(e)}`, true);
    }
  }

  /** A starter machine for the program, into the editor. */
  async deriveMachine() {
    this.status.textContent = "deriving a machine…";
    try {
      const r = await this.rk.emulator.deriveMachine({ programId: this.programId });
      this.machineSel.value = "";
      this.machineEdit.value = r.machine;
      this.machineText = r.machine;
      this.machineNotes.textContent = r.notes.join("\n");
      this.machineBox.open = true;
      this.status.textContent = `derived: ${r.mmioRegisters} MMIO registers, ${r.pollingLoops} polling loops answered`;
    } catch (e) {
      this.status.textContent = "";
      this.host.notify(`Derive a machine: ${errText(e)}`, true);
    }
  }

  async saveMachine() {
    const name = await ask({ title: "Save the machine as", value: this.machineSel.value || "board", placeholder: "a name: letters, digits, . _ -" });
    if (!name) return;
    try {
      await this.rk.emulator.saveMachine({ programId: this.programId, name, machine: this.machineEdit.value });
      await this.refreshMachines(name);
      this.host.notify(`Saved machine ${name}`);
    } catch (e) {
      this.host.notify(`Save the machine: ${errText(e)}`, true);
    }
  }

  private async sendInput(text: string) {
    if (!this.session) return;
    try {
      await this.rk.debugger.writeDebugInput({ sessionId: this.session.sessionId, data: new TextEncoder().encode(text) });
      this.uartInput.value = "";
    } catch (e) {
      this.host.notify(`Debugger: ${errText(e)}`, true);
    }
  }

  private async setExceptionBreaks() {
    if (!this.session) return;
    try {
      await this.rk.debugger.setDebugBreakpoints({ sessionId: this.session.sessionId, setExceptionBreaks: true, exceptionBreaks: this.breakExc.checked ? ["any"] : [] });
    } catch (e) {
      this.host.notify(`Debugger: ${errText(e)}`, true);
    }
  }

  /** The timeline's exceptions as marks under the scrubber. */
  private async refreshEvents() {
    if (!this.session?.machine) {
      this.events = [];
      this.eventsEl.replaceChildren();
      this.eventsLabel.textContent = "";
      return;
    }
    try {
      const t = await this.rk.debugger.getDebugTimeline({ sessionId: this.session.sessionId, eventsOnly: true, limit: 10000 });
      this.events = t.snapshots.map((s) => ({ index: s.index, kind: s.event, number: s.eventNumber, text: s.text }));
      const span = Number(t.last - t.first) || 1;
      const marks = this.events.map((ev) => {
        const left = (100 * Number(ev.index - t.first)) / span;
        const label = ev.kind === "return" ? "return" : `${ev.kind}${ev.number >= 0 && ev.kind !== "svc" ? ` ${ev.number}` : ""}`;
        const m = h("span", { class: `dbg-event ${ev.kind === "return" ? "ret" : "entry"}`, "data-kind": ev.kind, title: `#${ev.index} ${label}${ev.text ? ` · ${ev.text}` : ""}`, style: `left: ${left.toFixed(3)}%` });
        m.addEventListener("click", () => void this.showSnapshot(ev.index));
        return m;
      });
      this.eventsEl.replaceChildren(...marks);
      const taken = this.events.filter((e) => e.kind !== "return").length;
      this.eventsLabel.textContent = taken ? `${taken} exception${taken === 1 ? "" : "s"}` : "";
    } catch {
      /* the session went away */
    }
  }

  private async create(target: { emulator?: object; remote?: object; launch?: object }, keepParent = false) {
    if (this.session && keepParent) {
      this.parent = { session: this.session, request: this.request, label: this.title.textContent ?? "" };
      this.generation++;
      this.session = null;
    } else if (this.session) await this.close(false);
    const kind = Object.keys(target)[0] as "emulator" | "remote" | "launch";
    this.stops = [];
    const req = {
      programId: this.programId,
      target: { case: kind, value: (target as Record<string, object>)[kind] },
      breakpoints: [...this.breakpoints].map((b) => ({ address: { offset: b, program: true }, kind: DebugBreakpointKind.SOFTWARE, ...this.bpOptions.get(b) })),
    } as unknown as CreateDebugSessionRequest;
    this.request = req;
    this.busy = true;
    this.enable();
    this.status.textContent = kind === "emulator" ? "starting…" : "connecting…";
    try {
      this.session = await this.rk.debugger.createDebugSession(req);
    } catch (e) {
      this.busy = false;
      this.status.textContent = "";
      this.enable();
      this.host.notify(`Debugger: ${errText(e)}`, true);
      return;
    }
    this.generation++;
    this.busy = false;
    this.running = false;
    this.shown = null;
    this.output = "";
    this.outputSize = 0n;
    this.el.classList.add("live");
    this.el.dataset.target = this.session.targetKind;
    this.firmwareRow.hidden = !this.session.machine;
    this.breakExc.checked = false;
    this.events = [];
    if (this.session.machine) this.title.title = `${this.session.language} · ${this.session.machine.cpu} machine ${this.session.machine.name}`;
    this.host.show();
    this.title.textContent = this.parent ? `${this.session.description} · from ${this.parent.label}` : `${this.session.description}`;
    this.title.title = this.session.language;
    if (!this.memExpr) this.memExpr = this.session.spRegister;
    this.memInput.value = this.memExpr;
    await this.apply(this.session.state ?? null, this.session.state?.lastStop ?? null);
  }

  async run(mode: RunName) {
    if (!this.session || this.busy || this.running) return;
    const id = this.session.sessionId;
    this.busy = true;
    this.enable();
    this.status.textContent = "running…";
    try {
      const r = await this.rk.debugger.resumeDebugSession({ sessionId: id, mode: RUN_MODES[mode], timeLimitMs: 2000, state: { outputOffset: this.outputSize, includeThreads: true } });
      this.shown = null;
      await this.apply(r.state ?? null, r.stop ?? null);
      if (r.stop?.kind === DebugStopKind.RUNNING) void this.follow();
    } catch (e) {
      this.host.notify(`Debugger: ${errText(e)}`, true);
      this.status.textContent = "error";
    } finally {
      this.busy = false;
      this.enable();
    }
  }

  /** Back to snapshot `to` and on from there (null: one instruction back).
   * Going back past several snapshots asks whether to keep them as a trace. */
  async rewind(to: bigint | null) {
    if (!this.session || this.busy || this.running || !this.state?.rewindable) return;
    let save = "";
    if (to !== null) {
      const later = this.last - to;
      const name = `branch-${to}-${Date.now().toString(36)}`;
      const choice = await choose<"drop" | "keep">(`Resume from snapshot ${to}?`, [
        { label: `Drop the ${later} later snapshot${later === 1n ? "" : "s"}`, detail: "and continue from this one", value: "drop" },
        { label: "Keep them as a trace, then go back", detail: `saved as ${name}: open it later as the target "trace:${name}"`, value: "keep" },
      ]);
      if (!choice) return;
      if (choice === "keep") save = name;
    }
    const id = this.session.sessionId;
    this.busy = true;
    this.enable();
    try {
      const r = await this.rk.debugger.rewindDebugSession({
        sessionId: id,
        snapshot: to ?? undefined,
        stepBack: to === null,
        saveBranchAs: save,
        state: { outputOffset: 0n, includeThreads: true },
      } as never);
      if (this.session?.sessionId !== id) return;
      this.output = "";
      this.outputSize = 0n;
      this.shown = null;
      this.el.classList.remove("historical");
      const at = r.state?.lastSnapshot ?? 0n;
      this.stops = this.stops.filter((s) => s <= at);
      this.busy = false;
      await this.apply(r.state ?? null, r.stop ?? null);
      if (r.saved?.name) this.host.notify(`The later snapshots are saved as trace ${r.saved.name}`);
    } catch (e) {
      this.host.notify(`Debugger: ${errText(e)}`, true);
    } finally {
      this.busy = false;
      this.enable();
    }
  }

  /** While a live target runs: wait for its stop. */
  private async follow() {
    const gen = this.generation;
    this.running = true;
    this.enable();
    while (this.session && gen === this.generation && this.running) {
      try {
        const r = await this.rk.debugger.waitDebugSession({ sessionId: this.session.sessionId, waitMs: 1000, state: { outputOffset: this.outputSize, includeThreads: true } });
        if (gen !== this.generation) return;
        if (r.stop?.kind !== DebugStopKind.RUNNING) {
          this.running = false;
          await this.apply(r.state ?? null, r.stop ?? null);
        } else if (r.state) {
          this.appendOutput(r.state);
        }
      } catch (e) {
        this.running = false;
        this.host.notify(`Debugger: ${errText(e)}`, true);
      }
    }
    this.running = false;
    this.enable();
  }

  async interrupt() {
    if (!this.session) return;
    try {
      await this.rk.debugger.interruptDebugSession({ sessionId: this.session.sessionId });
    } catch (e) {
      this.host.notify(`Debugger: ${errText(e)}`, true);
    }
  }

  async restart() {
    if (!this.request) return;
    const kind = this.request.target.case;
    const value = this.request.target.value as object;
    if (kind === "emulator" || kind === "remote" || kind === "launch") await this.create({ [kind]: value });
  }

  async close(hide = true) {
    const s = this.session;
    if (this.parent && s) {
      // An emulator from another session's state: back to that session.
      const p = this.parent;
      this.parent = null;
      await this.rk.debugger.closeDebugSession({ sessionId: s.sessionId }).catch(() => {});
      this.generation++;
      this.session = p.session;
      this.request = p.request;
      this.shown = null;
      this.output = "";
      this.outputSize = 0n;
      this.el.dataset.target = p.session.targetKind;
      this.title.textContent = p.label;
      try {
        const st = await this.rk.debugger.getDebugState({ sessionId: p.session.sessionId, state: { includeThreads: true } });
        await this.apply(st.state ?? null, st.state?.lastStop ?? null);
      } catch (e) {
        this.host.notify(`Debugger: ${errText(e)}`, true);
        await this.close(hide);
      }
      return;
    }
    this.generation++;
    this.session = null;
    this.state = null;
    this.stop = null;
    this.pc = null;
    this.running = false;
    this.shown = null;
    if (s) await this.rk.debugger.closeDebugSession({ sessionId: s.sessionId }).catch(() => {});
    if (hide) {
      this.el.classList.remove("live");
      this.title.textContent = "";
      this.status.textContent = "";
      delete this.el.dataset.target;
      this.firmwareRow.hidden = true;
      this.events = [];
      this.eventsEl.replaceChildren();
      this.eventsLabel.textContent = "";
    }
    this.enable();
    this.host.showPc(null);
    this.host.marksChanged();
  }

  /** Adds or removes a breakpoint at a program address (the listing gutter). */
  async toggleBreakpoint(addr: bigint) {
    const add = !this.breakpoints.has(addr);
    if (add) this.breakpoints.add(addr);
    else this.breakpoints.delete(addr);
    this.host.marksChanged();
    if (!this.session) return;
    const where = { offset: addr, program: true };
    if (!add) this.bpOptions.delete(addr);
    try {
      const r = await this.rk.debugger.setDebugBreakpoints({
        sessionId: this.session.sessionId,
        add: add ? [{ address: where, kind: DebugBreakpointKind.SOFTWARE, ...this.bpOptions.get(addr) }] : [],
        remove: add ? [] : [where],
      } as never);
      this.bpList = r.breakpoints;
      this.renderBreakpoints();
      const bad = r.breakpoints.find((b) => b.location?.programAddress?.offset === addr && b.error);
      if (bad) this.host.notify(`Breakpoint at 0x${hx(addr)}: ${bad.error}`, true);
    } catch (e) {
      this.host.notify(`Debugger: ${errText(e)}`, true);
    }
  }

  async clearBreakpoints() {
    this.breakpoints.clear();
    this.bpOptions.clear();
    this.bpList = [];
    this.renderBreakpoints();
    this.host.marksChanged();
    if (this.session) await this.rk.debugger.setDebugBreakpoints({ sessionId: this.session.sessionId, clear: true }).catch(() => {});
  }

  /** F7, F8, Shift+F8, F9 while a session is open (Shift+F7 steps back); true if handled. */
  handleKey(e: KeyboardEvent): boolean {
    if (!this.session) return false;
    if (e.key === "F7" && e.shiftKey) {
      if (this.state?.rewindable) void this.rewind(null);
      return true;
    }
    const mode: RunName | null =
      e.key === "F7" ? "into" : e.key === "F8" && e.shiftKey ? "out" : e.key === "F8" ? "over" : e.key === "F9" ? "run" : null;
    if (mode === null) return false;
    void this.run(mode);
    return true;
  }

  private enable() {
    const on = this.session !== null && !this.busy && !this.running;
    const stopped = on && this.state?.targetState === DebugTargetState.STOPPED;
    for (const id of ["into", "over", "out", "run"]) this.buttons[id].disabled = !stopped;
    this.buttons.pause.disabled = !this.running;
    this.buttons.fork.hidden = !this.emulateFrom || !this.session || this.parent !== null;
    this.buttons.fork.disabled = !this.session || this.busy || this.running;
    const rewindable = !!this.state?.rewindable;
    this.buttons.back.hidden = !rewindable;
    this.buttons.back.disabled = !on || !rewindable || this.historical || this.last <= this.first;
    this.resumeHereBtn.hidden = !rewindable || !this.historical;
    this.resumeHereBtn.disabled = !on;
    this.buttons.restart.disabled = this.busy || this.request === null;
    this.buttons.start.disabled = this.busy;
  }

  private appendOutput(state: DebugState) {
    if (state.output.length) this.output += new TextDecoder().decode(state.output);
    this.outputSize = state.outputSize;
    if (this.output.length > 1 << 20) this.output = this.output.slice(-(1 << 20));
    this.outEl.textContent = this.output;
    this.outEl.hidden = this.output === "";
  }

  private async apply(state: DebugState | null, stop: DebugStop | null) {
    this.state = state;
    this.stop = stop;
    if (state && !this.historical) this.appendOutput(state);
    const loc = state?.pc;
    this.pc = loc?.programAddress?.offset ?? null;
    const runtime = loc?.address?.offset ?? 0n;
    const kind = stop?.kind ?? DebugStopKind.NONE;
    const what = STOP_TEXT[kind] ?? "stopped";
    // In a library that is a project program: "libc.so.6!strlen+0x10" (api_minor 70).
    const where =
      this.pc !== null
        ? `0x${hx(this.pc, this.addrWidth)}`
        : loc?.libraryFunction
          ? `${loc.module}!${loc.libraryFunction} (0x${hx(runtime)})`
          : `0x${hx(runtime)}${loc?.module ? ` (${loc.module})` : ""}`;
    let text = this.running ? "running" : `${what} at ${where} · ${state?.steps ?? 0n} ${this.session?.targetKind === "emulator" ? "steps" : "stops"}`;
    if (kind === DebugStopKind.EXITED || kind === DebugStopKind.RETURNED) text += ` · ${kind === DebugStopKind.EXITED ? "status" : "value"} ${stop?.exitCode}`;
    if (state?.machine) text += ` · tick ${state.tick}${state.waiting ? " · waiting for an interrupt" : ""}`;
    if (this.historical) text = `snapshot ${this.shown} · ${text}`;
    this.status.textContent = text;
    this.status.title = stop?.detail ?? "";
    this.showLibraryLink(this.pc === null ? loc : undefined);
    this.status.classList.toggle("fault", FAULTS.has(kind));
    this.status.dataset.kind = this.running ? "running" : what;
    this.frame = 0;
    this.renderRegisters(state?.registers ?? []);
    this.threads = (state?.threads ?? []).map((t) => ({ id: t.id, current: t.current }));
    if (state && !this.historical) {
      this.bpList = state.breakpoints;
      this.renderBreakpoints();
    }
    this.host.showPc(this.pc);
    this.host.marksChanged();
    this.enable();
    if (!this.historical) {
      this.last = state?.lastSnapshot ?? 0n;
      await this.refreshTimeline();
      await this.refreshThreads();
      if (this.modulesBox.open) await this.refreshModules();
    }
    void this.refreshMemory();
    if (!this.historical && state && stop && this.stops[this.stops.length - 1] !== state.lastSnapshot) this.stops.push(state.lastSnapshot);
    await this.refreshStack();
    await this.refreshWatches();
    // The pc outside the program (a library, unpacked code): the listing can't show it, this can.
    if (this.disassembly && this.followPc && (this.disasmBox.open || (this.pc === null && state?.pc?.address))) await this.showDisassembly(null);
  }

  // --- The breakpoint table (feature debugger-conditions) ---

  /** The session's breakpoint at a program address, if any. */
  private bpAt(addr: bigint): DebugBreakpoint | undefined {
    return this.bpList.find((b) => b.location?.programAddress?.offset === addr);
  }

  private renderBreakpoints() {
    if (!this.conditions) return;
    const addrs = new Set<bigint>([...this.breakpoints]);
    for (const b of this.bpList) if (b.location?.programAddress) addrs.add(b.location.programAddress.offset);
    const rows = [...addrs].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).map((addr) => {
      const b = this.bpAt(addr);
      const o = this.bpOptions.get(addr);
      const disabled = b ? b.disabled : !!o?.disabled;
      const condition = b ? b.condition : (o?.condition ?? "");
      const ignore = b ? b.ignoreCount : (o?.ignoreCount ?? 0);
      const enable = h("input", { type: "checkbox", checked: !disabled, title: "Enabled", "aria-label": `Enable the breakpoint at 0x${hx(addr)}`, "data-testid": "dbg-bp-enabled" });
      enable.addEventListener("click", (e) => e.stopPropagation());
      enable.addEventListener("change", () => void this.setBreakpointOptions(addr, { disabled: !enable.checked }));
      const remove = h("button", { class: "btn dbg-watch-x", type: "button", title: "Remove this breakpoint", "aria-label": `Remove the breakpoint at 0x${hx(addr)}`, "data-testid": "dbg-bp-remove" }, "×");
      remove.addEventListener("click", (e) => {
        e.stopPropagation();
        void this.toggleBreakpoint(addr);
      });
      const cond = h(
        "span",
        { class: `dbg-bp-cond${condition ? "" : " dim"}`, "data-testid": "dbg-bp-condition", title: b?.conditionError ? `The condition failed: ${b.conditionError}` : "Double-click to set the condition and ignore count" },
        condition ? `if ${condition}` : "always",
        ignore ? ` · skip ${ignore}` : "",
        b?.conditionError ? " ⚠" : "",
      );
      const row = h(
        "div",
        { class: `dbg-bp${disabled ? " disabled" : ""}${b?.error ? " bad" : ""}`, role: "row", "data-testid": "dbg-bp", "data-address": hx(addr), title: `0x${hx(addr)}${b?.error ? ` · not inserted: ${b.error}` : ""}. Click to show it; double-click to edit its condition` },
        enable,
        h("span", { class: "dbg-bp-addr" }, `0x${hx(addr, this.addrWidth)}`),
        cond,
        h("span", { class: "dbg-bp-hits dim", "data-testid": "dbg-bp-hits" }, b ? `${b.hits} hit${b.hits === 1n ? "" : "s"}` : ""),
        remove,
      );
      row.addEventListener("click", () => this.host.showFrame?.(addr));
      row.addEventListener("dblclick", () => void this.editBreakpoint(addr));
      return row;
    });
    this.bpEl.replaceChildren(...(rows.length ? rows : [h("div", { class: "dim" }, "no breakpoints: click the listing's gutter, or press F2")]));
  }

  /** Asks for the breakpoint's condition and ignore count (adding the breakpoint when there is none). */
  async editBreakpoint(addr: bigint) {
    const b = this.bpAt(addr);
    const o = this.bpOptions.get(addr);
    const f = await askFields(`Breakpoint at 0x${hx(addr)}`, [
      { name: "condition", label: "Condition (stop only when it holds; empty: always)", value: b?.condition ?? o?.condition ?? "", placeholder: "$RDI == 3, n > 10 && *(int *)p == 0" },
      { name: "ignore", label: "Ignore count (hits to pass over first)", value: String(b?.ignoreCount ?? o?.ignoreCount ?? 0), placeholder: "0" },
    ]);
    if (!f) return;
    const ignore = Number.parseInt(f.ignore || "0", 10);
    if (!Number.isFinite(ignore) || ignore < 0) return this.host.notify(`Not a count: ${f.ignore}`, true);
    if (!this.breakpoints.has(addr)) await this.toggleBreakpoint(addr);
    await this.setBreakpointOptions(addr, { condition: f.condition.trim(), ignoreCount: ignore });
  }

  /** Sets a breakpoint's condition, ignore count or disabled state, in the session when one runs. */
  async setBreakpointOptions(addr: bigint, change: { condition?: string; ignoreCount?: number; disabled?: boolean }) {
    const prev = this.bpOptions.get(addr) ?? { condition: "", ignoreCount: 0, disabled: false };
    const next = { ...prev, ...change };
    const b = this.bpAt(addr);
    if (this.session && b) {
      try {
        const r = await this.rk.debugger.setDebugBreakpoints({ sessionId: this.session.sessionId, update: [{ id: b.id, ...change }] } as never);
        this.bpList = r.breakpoints;
      } catch (e) {
        this.host.notify(`Breakpoint: ${errText(e)}`, true);
        this.renderBreakpoints();
        return;
      }
    }
    this.bpOptions.set(addr, next);
    this.renderBreakpoints();
    this.host.marksChanged();
  }

  // --- Copying runtime memory ---

  /** Copies target memory at `expr` (`length` bytes, 0: its mapped region) into the program; null after telling why not. */
  async copyMemory(expr: string, length: bigint, mode: "block" | "patch" | "program", name: string): Promise<CopyDebugMemoryResponse | null> {
    if (!this.copy || !this.session) return null;
    const v = (await this.evaluate([{ case: "expression", value: expr }]))?.values[0];
    const at = v?.hex ? BigInt(v.hex) : v?.address;
    if (!v || at === undefined) {
      this.host.notify(`Copy: ${v?.error || "no stopped session"}`, true);
      return null;
    }
    try {
      return await this.rk.debugger.copyDebugMemory({
        sessionId: this.session.sessionId,
        address: { offset: at },
        length,
        region: length === 0n,
        mode: mode === "block" ? DebugCopyMode.BLOCK : mode === "patch" ? DebugCopyMode.PATCH : DebugCopyMode.NEW_PROGRAM,
        name,
        snapshot: this.historical ? (this.shown ?? undefined) : undefined,
        provenance: userProvenance("copy runtime memory"),
      } as never);
    } catch (e) {
      this.host.notify(`Copy: ${errText(e)}`, true);
      return null;
    }
  }

  // --- An emulator from this state ---

  private takeParent() {
    const p = this.parent;
    this.parent = null;
    return p;
  }

  /** Emulate from here: an emulator session on this stop's (or the shown
   * snapshot's) registers and memory; closing it comes back here. */
  async emulateFromHere() {
    if (!this.emulateFrom || !this.session || this.busy || this.running || this.parent) return;
    await this.create({ emulator: { fromSession: this.session.sessionId, fromSnapshot: this.historical ? (this.shown ?? undefined) : undefined } }, true);
    if (!this.session) {
      // It failed: back to where we were.
      const p = this.takeParent();
      if (p) {
        this.session = p.session;
        this.request = p.request;
        this.title.textContent = p.label;
        const st = await this.rk.debugger.getDebugState({ sessionId: p.session.sessionId, state: { includeThreads: true } }).catch(() => null);
        await this.apply(st?.state ?? null, st?.state?.lastStop ?? null);
      }
    }
  }

  // --- Runtime disassembly ---

  /** Evaluates `expr` to an address and disassembles there (no longer following the pc). */
  async disassembleExpr(expr: string) {
    const r = await this.evaluate([{ case: "expression", value: expr }]);
    const v = r?.values[0];
    const at = v?.hex ? BigInt(v.hex) : v?.address;
    if (!v || at === undefined) {
      this.host.notify(`Disassemble: ${v?.error || "no stopped session"}`, true);
      return;
    }
    this.followPc = false;
    this.followBox.checked = false;
    await this.showDisassembly(at);
  }

  /** Instructions at a runtime address (null: around the pc), replacing the rows; `more` appends after them. */
  async showDisassembly(at: bigint | null, more = false) {
    if (!this.disassembly || !this.session || this.running) return;
    const id = this.session.sessionId;
    try {
      const r = await this.rk.debugger.disassembleDebugMemory({
        sessionId: id,
        address: more ? { offset: this.disasmNext ?? 0n } : at === null ? undefined : { offset: at },
        snapshot: this.historical ? (this.shown ?? undefined) : undefined,
        count: more ? 32 : 24,
        before: more || at !== null ? 0 : 6,
      } as never);
      if (this.session?.sessionId !== id) return;
      this.disasm = more ? [...this.disasm, ...r.instructions] : r.instructions;
      this.disasmNext = r.next;
      this.disasmBox.open = true;
      this.renderDisassembly(r.unreadable && !more ? "memory at that address is not readable" : "");
      if (!more) this.disasmEl.querySelector(".dbg-insn.pc")?.scrollIntoView({ block: "center" });
    } catch (e) {
      this.disasm = [];
      this.renderDisassembly(errText(e));
    }
  }

  private renderDisassembly(note: string) {
    const rows = this.disasm.map((ins) => {
      const runtime = ins.location?.address?.offset ?? 0n;
      const program = ins.location?.programAddress?.offset;
      const bytes = [...ins.bytes].map((b) => b.toString(16).padStart(2, "0")).join(" ");
      const target = ins.target !== undefined ? h("span", { class: "dbg-insn-target", title: "Disassemble there", "data-testid": "dbg-insn-target" }, ` → ${ins.targetSymbol || `0x${hx(ins.target)}`}`) : null;
      target?.addEventListener("click", (e) => {
        e.stopPropagation();
        this.followPc = false;
        this.followBox.checked = false;
        void this.showDisassembly(ins.target!);
      });
      const row = h(
        "div",
        {
          class: `dbg-insn${ins.pc ? " pc" : ""}${ins.error ? " bad" : ""}${program !== undefined ? " in-program" : ""}`,
          role: "listitem",
          "data-testid": "dbg-insn",
          "data-address": hx(runtime),
          ...(program !== undefined ? { "data-program": hx(program) } : {}),
          title: `${ins.location?.module ? `${ins.location.module} · ` : ""}0x${hx(runtime)}${program !== undefined ? ` (program 0x${hx(program)}): click to show it in the listing` : ""}${ins.error ? ` · ${ins.error}` : ""}`,
        },
        h("span", { class: "dbg-insn-mark" }, ins.pc ? "▶" : ins.breakpoint ? "●" : " "),
        h("span", { class: "dbg-insn-addr" }, hx(runtime, this.addrWidth)),
        h("span", { class: "dbg-insn-sym dim" }, ins.symbol),
        h("span", { class: "dbg-insn-bytes dim" }, bytes),
        h("span", { class: "dbg-insn-text" }, `${ins.mnemonic} ${ins.operands}`.trim(), ...(target ? [target] : [])),
      );
      if (program !== undefined) row.addEventListener("click", () => this.host.showFrame?.(program));
      return row;
    });
    const more = h("button", { class: "btn emu-btn", type: "button", "data-testid": "dbg-disasm-more", title: "The next instructions", onclick: () => void this.showDisassembly(null, true) }, "More");
    this.disasmEl.replaceChildren(...(note ? [h("div", { class: "dim" }, note)] : []), ...rows, ...(rows.length ? [more] : []));
  }

  // --- Values (watches, hovers) ---

  private watchKey() {
    return `revkit.watches.${this.programId}`;
  }

  private loadWatches(): Watch[] {
    try {
      const raw = JSON.parse(localStorage.getItem(this.watchKey()) ?? "[]") as { expr: string; fn?: string }[];
      return raw.filter((w) => typeof w.expr === "string").map((w) => ({ expr: w.expr, fn: w.fn ? BigInt(w.fn) : undefined }));
    } catch {
      return [];
    }
  }

  private saveWatches() {
    try {
      localStorage.setItem(this.watchKey(), JSON.stringify(this.watches.map((w) => ({ expr: w.expr, fn: w.fn?.toString() }))));
    } catch {
      /* private window: kept for this page only */
    }
  }

  /** Adds a watch (`fn`: evaluate in that function's innermost frame) and shows it. */
  addWatch(expr: string, fn?: bigint) {
    if (!this.values) return;
    if (!this.watches.some((w) => w.expr === expr && w.fn === fn)) this.watches.push({ expr, fn });
    this.saveWatches();
    this.host.show();
    void this.refreshWatches();
  }

  removeWatch(i: number) {
    this.watches.splice(i, 1);
    this.saveWatches();
    void this.refreshWatches();
  }

  /** The stop before the one shown: what a watch's changed mark compares with. */
  private previousStop(): bigint | undefined {
    const at = this.historical ? (this.shown ?? this.last) : this.last;
    let prev: bigint | undefined;
    for (const s of this.stops) if (s < at) prev = s;
    return prev;
  }

  private async refreshWatches() {
    if (!this.values) return;
    let values: WatchValue[] = this.watches.map(() => ({ text: "", type: "", error: "", changed: false, children: [] }));
    if (this.watches.length && this.session && !this.running) {
      const r = await this.evaluateWatches(this.previousStop());
      if (r) values = r;
    }
    this.watchValues = values;
    this.renderWatches();
  }

  private async evaluateWatches(compare?: bigint): Promise<WatchValue[] | null> {
    if (!this.session) return null;
    try {
      const r = await this.rk.debugger.evaluateDebug({
        sessionId: this.session.sessionId,
        snapshot: this.historical ? (this.shown ?? undefined) : undefined,
        frame: this.frame,
        compareSnapshot: compare,
        items: this.watches.map((w) => ({ what: { case: "expression", value: w.expr }, frameFunction: w.fn !== undefined ? { offset: w.fn } : undefined })),
      } as never);
      return r.values.map((v) => ({ text: v.text, type: v.type, error: v.error, changed: v.changed, children: v.children.map((c) => ({ name: c.name, text: c.text, type: c.type })) }));
    } catch (e) {
      return this.watches.map(() => ({ text: "", type: "", error: errText(e), changed: false, children: [] }));
    }
  }

  private renderWatches() {
    const rows = this.watches.map((w, i) => {
      const v = this.watchValues[i];
      const remove = h("button", { class: "btn dbg-watch-x", type: "button", title: "Remove this watch", "aria-label": `Remove watch ${w.expr}`, "data-testid": "dbg-watch-remove" }, "×");
      remove.addEventListener("click", (e) => {
        e.stopPropagation();
        this.removeWatch(i);
      });
      const expandable = !!v && v.children.length > 0;
      const value = h("span", { class: `dbg-watch-value${v?.error ? " dim" : ""}`, "data-testid": "dbg-watch-value", title: v?.error || v?.text || "" }, v?.error ? v.error : (v?.text ?? ""));
      const row = h(
        "div",
        {
          class: `dbg-watch${v?.changed ? " changed" : ""}`,
          "data-testid": "dbg-watch",
          "data-expr": w.expr,
          ...(v?.changed ? { "data-changed": "" } : {}),
          title: `${w.expr}${w.fn !== undefined ? ` (in 0x${hx(w.fn)}'s frame)` : ""}${v?.type ? ` : ${v.type}` : ""}${expandable ? ". Click for its fields" : ""}. Double-click to edit`,
        },
        h("span", { class: "dbg-watch-toggle dim" }, expandable ? (w.open ? "▾" : "▸") : " "),
        h("span", { class: "dbg-watch-expr" }, w.expr),
        value,
        h("span", { class: "dbg-watch-type dim" }, v?.type ?? ""),
        remove,
      );
      row.addEventListener("click", () => {
        if (!expandable) return;
        w.open = !w.open;
        this.renderWatches();
      });
      row.addEventListener("dblclick", () => void this.editWatch(i));
      const kids = expandable && w.open ? v.children.map((c) => h("div", { class: "dbg-watch-child", "data-testid": "dbg-watch-child" }, h("span", { class: "dbg-watch-expr" }, `  .${c.name.startsWith("[") ? c.name.slice(0) : c.name}`), h("span", { class: "dbg-watch-value" }, c.text), h("span", { class: "dbg-watch-type dim" }, c.type))) : [];
      return h("div", {}, row, ...kids);
    });
    this.watchList.replaceChildren(...(rows.length ? rows : [h("div", { class: "dim" }, "no watches: add one above, or from a variable's right-click menu")]));
  }

  private async editWatch(i: number) {
    const w = this.watches[i];
    if (!w) return;
    const next = await ask({ title: "Watch expression", value: w.expr, placeholder: "a C expression" });
    if (next === null) return;
    if (!next.trim()) return this.removeWatch(i);
    w.expr = next.trim();
    this.saveWatches();
    await this.refreshWatches();
  }

  /** Values at the stop or the snapshot shown, in `frame` (unset: the
   * innermost frame in the item's function); null without a stopped session. */
  async evaluate(items: ValueItem[], frame?: number, compareSnapshot?: bigint): Promise<EvaluateDebugResponse | null> {
    if (!this.values || !this.session || this.running || this.busy) return null;
    try {
      return await this.rk.debugger.evaluateDebug({
        sessionId: this.session.sessionId,
        snapshot: this.historical ? (this.shown ?? undefined) : undefined,
        frame,
        compareSnapshot,
        items: items.map((what) => ({ what })),
      } as never);
    } catch {
      return null;
    }
  }

  // --- The call stack ---

  /** Unwinds the stop (or the snapshot shown) and lists its frames. */
  private async refreshStack() {
    if (!this.stack || !this.session) return;
    const id = this.session.sessionId;
    if (this.running || (this.state?.targetState !== DebugTargetState.STOPPED && !this.historical && this.state?.targetState !== DebugTargetState.REPLAY)) {
      this.frames = [];
      this.stackEl.replaceChildren(h("div", { class: "dim" }, this.running ? "running" : "—"));
      return;
    }
    try {
      const r = await this.rk.debugger.getDebugBacktrace({ sessionId: id, snapshot: this.historical ? (this.shown ?? undefined) : undefined, maxFrames: 64 });
      if (this.session?.sessionId !== id) return;
      this.frames = r.frames;
      if (r.unsupported) {
        this.stackEl.replaceChildren(h("div", { class: "dim" }, r.unsupported));
        return;
      }
      this.renderStack();
    } catch (e) {
      this.frames = [];
      this.stackEl.replaceChildren(h("div", { class: "dim" }, errText(e)));
    }
  }

  /** "Open libc.so.6 at strlen" beside the status, when the pc is in a library that is a project program. */
  private showLibraryLink(loc: DebugLocation | undefined) {
    const id = loc?.libraryProgramId;
    this.libLink.hidden = !id;
    if (!id || !loc) return;
    const at = loc.libraryAddress?.offset;
    this.libLink.textContent = `Open ${loc.module}${loc.libraryFunction ? ` at ${loc.libraryFunction}` : ""}`;
    this.libLink.title = `Open ${id} in a new tab, at 0x${at !== undefined ? hx(at) : "?"} (its listing and decompiler)`;
    this.libLink.onclick = () => openLibrary(id, at);
  }

  private frameText(f: DebugFrame): string {
    const at = f.pc?.programAddress?.offset;
    // A library frame named from the library program: "libc.so.6!strlen+0x10".
    const lib = f.pc?.libraryProgramId && f.function ? `${f.pc.module}!` : "";
    const fn = f.function ? `${lib}${f.function}${f.functionOffset ? `+0x${hx(f.functionOffset)}` : ""}` : f.pc?.module ? `${f.pc.module}+0x${hx(f.pc.moduleOffset)}` : "?";
    return `#${f.level} ${fn}  ${at !== undefined ? `0x${hx(at, this.addrWidth)}` : `0x${hx(f.pc?.address?.offset ?? 0n)}`}`;
  }

  private renderStack() {
    const rows = this.frames.map((f, i) => {
      const row = h(
        "div",
        {
          class: `dbg-frame${i === this.frame ? " current" : ""}${f.how === "stack scan" ? " guessed" : ""}`,
          role: "option",
          "aria-selected": String(i === this.frame),
          "data-frame": String(i),
          "data-testid": "dbg-frame",
          title: `${f.pc?.module ? `${f.pc.module} · ` : ""}runtime 0x${hx(f.pc?.address?.offset ?? 0n)} · sp 0x${hx(f.sp)} · found by ${f.how}${f.how === "stack scan" ? " (a guess)" : ""}. Click to show it and its registers`,
        },
        h("span", { class: "dbg-frame-text" }, this.frameText(f)),
        h("span", { class: "dbg-frame-how dim" }, f.how),
      );
      row.addEventListener("click", () => this.selectFrame(i));
      return row;
    });
    this.stackEl.replaceChildren(...(rows.length ? rows : [h("div", { class: "dim" }, "no frames")]));
  }

  /** Shows frame `i`: its pc in the listing and decompiler, its registers here. */
  selectFrame(i: number) {
    const f = this.frames[i];
    if (!f) return;
    this.frame = i;
    this.renderStack();
    this.renderRegisters(i === 0 ? (this.state?.registers ?? []) : f.registers, i > 0);
    void this.refreshWatches();
    const at = f.pc?.programAddress?.offset;
    this.showLibraryLink(at === undefined ? f.pc : undefined);
    if (at !== undefined) this.host.showFrame?.(at);
    else if (this.disassembly && f.pc?.address) {
      // Outside the program: its instructions here, since the listing can't show them.
      this.followPc = false;
      this.followBox.checked = false;
      void this.showDisassembly(f.pc.address.offset);
    } else this.host.notify(`Frame #${i} is outside the program (${f.pc?.module || "unknown module"})`);
  }

  // --- The timeline ---

  private async refreshTimeline() {
    if (!this.session) return;
    try {
      const t = await this.rk.debugger.getDebugTimeline({ sessionId: this.session.sessionId, fromSnapshot: this.last, limit: 1 });
      this.first = t.first;
      this.last = t.last;
      this.scrub.min = String(t.first);
      this.scrub.max = String(t.last);
      if (this.shown === null) this.scrub.value = String(t.last);
      this.scrubLabel.textContent = `${t.count} snapshots${t.dropped ? ` (${t.dropped} dropped)` : ""}`;
    } catch {
      /* the session went away */
    }
    await this.refreshEvents();
  }

  private scrubbed() {
    window.clearTimeout(this.scrubTimer);
    this.scrubTimer = window.setTimeout(() => void this.showSnapshot(BigInt(this.scrub.value)), 40);
  }

  /** Shows a recorded snapshot (null: now). */
  async showSnapshot(snap: bigint | null) {
    if (!this.session) return;
    if (snap !== null && snap >= this.last) snap = null;
    this.shown = snap;
    this.scrub.value = String(snap ?? this.last);
    this.el.classList.toggle("historical", snap !== null);
    const id = this.session.sessionId;
    try {
      const st = await this.rk.debugger.getDebugState({ sessionId: id, snapshot: snap ?? undefined, state: { includeThreads: snap === null } });
      if (this.session?.sessionId !== id) return;
      let stop = st.state?.lastStop ?? null;
      if (snap !== null) {
        const t = await this.rk.debugger.getDebugTimeline({ sessionId: id, fromSnapshot: snap, limit: 1 });
        const s = t.snapshots[0];
        if (s) {
          this.scrubLabel.textContent = `#${snap} ${SNAP_KIND[s.kind] ?? ""}${s.event ? ` · ${s.event}` : ""}${s.text ? ` · ${s.text}` : ""}${s.changed.length ? ` · ${s.changed.join(" ")}` : ""}`;
        }
      } else {
        stop = this.stop ?? stop;
      }
      await this.apply(st.state ?? null, stop);
    } catch (e) {
      this.host.notify(`Debugger: ${errText(e)}`, true);
    }
  }

  // --- Threads and modules ---

  private async refreshThreads() {
    const threads = this.state?.threads ?? [];
    const rows = threads.map((t) => {
      const loc = t.pc?.programAddress?.offset ?? t.pc?.address?.offset;
      const row = h(
        "div",
        { class: `dbg-thread${t.current ? " current" : ""}`, "data-thread": t.id, title: "Click to show this thread" },
        `${t.current ? "▶" : " "} ${t.id}${t.name ? ` ${t.name}` : ""}${loc !== undefined ? ` 0x${hx(loc)}` : ""}`,
      );
      row.addEventListener("click", () => void this.selectThread(t.id));
      return row;
    });
    this.threadsEl.replaceChildren(...(rows.length ? rows : [h("div", { class: "dim" }, this.state?.thread ? `thread ${this.state.thread}` : "—")]));
  }

  private async selectThread(id: string) {
    if (!this.session || this.historical) return;
    try {
      const r = await this.rk.debugger.selectDebugThread({ sessionId: this.session.sessionId, threadId: id, state: { includeThreads: true } });
      await this.apply(r.state ?? null, this.stop);
    } catch (e) {
      this.host.notify(`Debugger: ${errText(e)}`, true);
    }
  }

  private async refreshModules() {
    if (!this.session || !this.modulesBox.open) return;
    try {
      const r = await this.rk.debugger.listDebugModules({ sessionId: this.session.sessionId });
      this.modules = r.modules.map((m) => m.name);
      const m = r.mapping;
      const head = h("div", { class: "dim" }, m?.known ? `slide ${m.slide < 0n ? "-" : ""}0x${hx(m.slide < 0n ? -m.slide : m.slide)} (${m.how})` : `mapping unknown (${m?.how ?? ""})`);
      const rows = r.modules.map((mod) =>
        h("div", { class: `dbg-module${mod.program ? " program" : ""}`, "data-module": mod.name }, `0x${hx(mod.base)} ${mod.name}${mod.size ? ` +0x${hx(mod.size)}` : ""}${mod.main ? " (main)" : ""}`),
      );
      this.modulesEl.replaceChildren(head, ...rows);
    } catch (e) {
      this.modulesEl.textContent = errText(e);
    }
  }

  // --- Registers and memory ---

  private renderRegisters(regs: DebugRegisterValue[], frame = false) {
    this.regsEl.classList.toggle("frame", frame);
    this.regsEl.title = frame ? `Frame #${this.frame}'s registers, as the unwinding restored them (click #0 for the stop's)` : "";
    const cells = regs.map((r) => {
      const v = r.bytes.length ? [...r.bytes].reverse().reduce((a, b) => (a << 8n) | BigInt(b), 0n) : r.value;
      const width = r.size > 1 ? Math.min(r.size, 8) * 2 : 1;
      const value = h("span", { class: "emu-val", title: this.historical ? "As recorded" : "Double-click to change" }, hx(v, width));
      if (!frame) value.addEventListener("dblclick", () => this.editRegister(r.name, value));
      return h("div", { class: `emu-reg${r.changed ? " changed" : ""}`, "data-reg": r.name }, h("span", { class: "emu-name" }, r.name), value);
    });
    this.regsEl.replaceChildren(...cells);
  }

  private editRegister(name: string, cell: HTMLElement) {
    if (!this.session || this.historical || this.state?.targetState !== DebugTargetState.STOPPED) return;
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
        const r = await this.rk.debugger.writeDebugRegisters({ sessionId: this.session!.sessionId, registers: [{ name, value: BigInt.asUintN(64, value) }] });
        await this.apply(r.state ?? null, this.stop);
      } catch (err) {
        this.host.notify(`Debugger: ${errText(err)}`, true);
      }
    });
  }

  /** The memory view: the address typed (hex, runtime), or a register's value. */
  private async refreshMemory() {
    if (!this.session) return;
    let at: bigint | null = null;
    const expr = this.memExpr;
    const reg = this.state?.registers.find((r) => r.name.toLowerCase() === expr.toLowerCase());
    if (reg) at = reg.value;
    else if (/^(0x)?[0-9a-f]+$/i.test(expr)) at = BigInt(expr.startsWith("0x") ? expr : `0x${expr}`);
    else if (expr) {
      try {
        const st = await this.rk.debugger.getDebugState({ sessionId: this.session.sessionId, snapshot: this.shown ?? undefined, state: { registers: [expr] } });
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
      const r = await this.rk.debugger.readDebugMemory({
        sessionId: this.session.sessionId,
        address: { offset: at, program: false },
        length: 16 * MEM_ROWS,
        snapshot: this.shown ?? undefined,
      });
      if (this.memAt !== at) return;
      const missing = new Set<number>();
      for (const u of r.unavailable) for (let i = 0; i < u.length; i++) missing.add(u.offset + i);
      const stale = new Set<number>();
      for (const u of r.stale) for (let i = 0; i < u.length; i++) stale.add(u.offset + i);
      const lines: HTMLElement[] = [];
      for (let row = 0; row < MEM_ROWS; row++) {
        const parts: (HTMLElement | string)[] = [`${hx(at + BigInt(row * 16), this.addrWidth)}  `];
        let ascii = "";
        for (let i = 0; i < 16; i++) {
          const k = row * 16 + i;
          const b = r.data[k] ?? 0;
          const text = missing.has(k) ? "??" : b.toString(16).padStart(2, "0");
          parts.push(stale.has(k) ? h("span", { class: "dbg-stale", title: "Recorded earlier; may have changed" }, text) : text);
          parts.push(i === 7 ? "  " : " ");
          ascii += missing.has(k) ? " " : b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
        }
        parts.push(` ${ascii}`);
        lines.push(h("div", {}, ...parts));
      }
      this.memEl.replaceChildren(...lines);
    } catch (e) {
      this.memEl.textContent = errText(e);
    }
  }
}
