// Register values over address ranges (feature register-values; Ghidra's
// register manager and its Set Register Values dialog): the ranges where a
// register holds a constant, the user's and analysis's (the loader's MIPS
// _gp, the PowerPC TOC), which analysis's references and the decompiler
// take as known there.
//
// The view lists them by register, then address, with who set each; a
// register filter; click (or Enter) goes to the range's start; Delete
// clears the selected range (one undo step). The dialog sets a value (or
// clears one) over the listing's selection or a function's body.

import { type RegisterDescription, type RegisterValueRange, type Revkit } from "@revkit/api";
import { Edits } from "../data/edits";
import { errText, fmtAddr, hex, originClass, originText, parseAddress } from "../data/format";
import { toast } from "./dialogs";
import { h, overlayRoot } from "./dom";

const MAX_ROWS = 5000;

export interface RegisterValuesHost {
  rk: Revkit;
  programId: string;
  addrWidth: number;
  edits: Edits;
  navigate(address: bigint): void;
  /** Opens the dialog with this register and range filled in. */
  set(register: string, first: bigint, last: bigint): void;
  undo(): void;
  settle(revision: bigint): Promise<void>;
}

/** Who set a range, in a word: "analysis (mips-gp)" or the assertion's author. */
export function setBy(r: RegisterValueRange): string {
  const o = r.origin?.source;
  if (o?.case === "derived") return `analysis (${o.value.rule.split(":").pop() ?? o.value.rule})`;
  return originText(r.origin);
}

let registerCache: { program: string; registers: Promise<RegisterDescription[]> } | null = null;

/** The registers values may be set on (once per program). */
export function valueRegisters(rk: Revkit, programId: string): Promise<RegisterDescription[]> {
  if (registerCache?.program !== programId) {
    const registers = rk.queries
      .listRegisterValues({ programId, page: { pageSize: 1 } })
      .then((r) => r.registers)
      .catch((e) => {
        registerCache = null;
        throw e;
      });
    registerCache = { program: programId, registers };
  }
  return registerCache.registers;
}

export class RegisterValuesView {
  private ranges: RegisterValueRange[] = [];
  private seq = 0;
  private list: HTMLElement;
  private reg: HTMLSelectElement;
  private count: HTMLElement;
  private active = -1;
  private loaded = false;
  private settled = false;

  constructor(
    root: HTMLElement,
    private host: RegisterValuesHost,
  ) {
    this.reg = h("select", { class: "filter select", "aria-label": "Register", "data-testid": "regvalues-register" }, h("option", { value: "" }, "All registers"));
    this.count = h("span", { class: "dim count", "data-testid": "regvalues-count" });
    const add = h("button", { class: "btn small", type: "button", "data-testid": "regvalues-add", title: "Set a register value over a range" }, "Set…");
    add.addEventListener("click", () => this.host.set(this.reg.value, 0n, 0n));
    this.list = h("div", { class: "regvalues-list", tabindex: "0", role: "listbox", "aria-label": "Register values", "data-testid": "regvalues-list" });
    const head = h(
      "div",
      { class: "data-row data-head dim regvalues-row" },
      h("span", {}, "Register"),
      h("span", {}, "First"),
      h("span", {}, "Last"),
      h("span", {}, "Value"),
      h("span", {}, "Set by"),
    );
    root.append(h("div", { class: "panel-head view-head" }, h("span", { class: "panel-title" }, "Register values"), this.count), h("div", { class: "fn-filter data-filters" }, this.reg, add), head, this.list);
    this.reg.addEventListener("change", () => void this.load());
    this.list.addEventListener("keydown", (e) => this.onKey(e));
    this.list.addEventListener("mousedown", (e) => {
      const el = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (!el) return;
      e.preventDefault();
      this.list.focus();
      this.active = Number(el.dataset.i);
      this.paint();
      if (e.detail >= 2) {
        const r = this.ranges[this.active];
        if (r) this.host.set(r.registerName, r.range?.first?.offset ?? 0n, r.range?.last?.offset ?? 0n);
      } else {
        this.open();
      }
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

  async load() {
    this.loaded = true;
    const seq = ++this.seq;
    try {
      const out: RegisterValueRange[] = [];
      let token = "";
      let total = 0;
      for (;;) {
        const r = await this.host.rk.queries.listRegisterValues({ programId: this.host.programId, registerName: this.reg.value, page: { pageSize: 1000, pageToken: token } });
        if (seq !== this.seq) return;
        out.push(...r.ranges);
        total = Number(r.total);
        token = r.page?.nextPageToken ?? "";
        if (!token || out.length >= MAX_ROWS) break;
      }
      this.ranges = out;
      if (!this.reg.value) this.fillRegisters(out);
      this.count.textContent = `${total.toLocaleString()} ${total === 1 ? "range" : "ranges"}${out.length < total ? ` (first ${out.length.toLocaleString()})` : ""}`;
    } catch (e) {
      if (seq !== this.seq) return;
      this.ranges = [];
      this.count.textContent = errText(e);
    }
    this.settled = true;
    this.active = Math.min(this.active, this.ranges.length - 1);
    this.paint();
  }

  /** The filter's registers: those with a value somewhere. */
  private fillRegisters(ranges: RegisterValueRange[]) {
    const have = new Set([...this.reg.options].map((o) => o.value));
    for (const name of [...new Set(ranges.map((r) => r.registerName))].sort()) if (!have.has(name)) this.reg.append(h("option", { value: name }, name));
  }

  private paint() {
    const out: HTMLElement[] = this.ranges.map((r, i) => {
      const first = r.range?.first?.offset ?? 0n;
      const last = r.range?.last?.offset ?? 0n;
      return h(
        "div",
        {
          class: "data-row regvalues-row" + (i === this.active ? " active" : ""),
          "data-i": i,
          "data-testid": "regvalue-row",
          "data-register": r.registerName,
          "data-first": hex(first),
          "data-last": hex(last),
          "data-value": hex(r.value),
          role: "option",
          "aria-selected": String(i === this.active),
          title: `${r.registerName} = 0x${hex(r.value)} from ${fmtAddr(first)} to ${fmtAddr(last)}\nset by ${setBy(r)}\n\nClick to go there; double-click to change; Delete to clear`,
        },
        h("span", { class: "rv-reg" }, r.registerName),
        h("span", { class: "d-addr" }, fmtAddr(first, this.host.addrWidth)),
        h("span", { class: "d-addr" }, fmtAddr(last, this.host.addrWidth)),
        h("span", { class: "rv-val" }, `0x${hex(r.value)}`),
        h("span", { class: `dim o-${originClass(r.origin)}` }, setBy(r)),
      );
    });
    if (!this.ranges.length) out.push(h("div", { class: "notes-empty dim", role: "option", "aria-disabled": "true" }, !this.settled ? "Loading…" : "No register values"));
    this.list.replaceChildren(...out);
    this.list.querySelector(".active")?.scrollIntoView({ block: "nearest" });
  }

  private open() {
    const r = this.ranges[this.active];
    if (r?.range?.first) this.host.navigate(r.range.first.offset);
  }

  /** Clears the selected range: no value there (one undo step). */
  private async clearActive() {
    const r = this.ranges[this.active];
    if (!r?.range?.first || !r.range.last) return;
    const first = r.range.first.offset, last = r.range.last.offset;
    try {
      const done = await this.host.edits.bodies(`Clear ${r.registerName} from ${fmtAddr(first)}`, [Edits.registerValueBody(r.registerName, first, last, null)]);
      toast(`${r.registerName} has no value from ${fmtAddr(first)} to ${fmtAddr(last)}`, { action: { label: "Undo", run: () => this.host.undo() } });
      await this.host.settle(done.revision);
    } catch (e) {
      toast(`Clear register value failed: ${errText(e)}`, { kind: "error" });
    }
  }

  private onKey(e: KeyboardEvent) {
    const move = (to: number) => {
      this.active = Math.max(0, Math.min(this.ranges.length - 1, to));
      this.paint();
    };
    switch (e.key) {
      case "ArrowDown":
        move(this.active + 1);
        break;
      case "ArrowUp":
        move(this.active - 1);
        break;
      case "Enter":
        if (this.active < 0) move(0);
        this.open();
        break;
      case "Delete":
      case "Backspace":
        void this.clearActive();
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
  }

  /** The rows loaded (tests). */
  visible() {
    return this.ranges.slice(0, 200).map((r) => ({ register: r.registerName, first: hex(r.range?.first?.offset ?? 0n), last: hex(r.range?.last?.offset ?? 0n), value: hex(r.value), by: setBy(r) }));
  }
}

export interface SetRegisterValueOptions {
  rk: Revkit;
  programId: string;
  edits: Edits;
  register: string;
  /** The ranges to set over (the selection, or a function's body), inclusive. */
  ranges: { first: bigint; last: bigint }[];
  /** What the ranges are, for the title ("the selection", "bump"). */
  what: string;
  clear?: boolean;
  undo(): void;
  settle(revision: bigint): Promise<void>;
}

/** Parses "0x418ff0", "418ff0h", a decimal "1234" or "-8". */
function parseValue(s: string, size: number): bigint | null {
  const t = s.trim().replace(/_/g, "");
  let v: bigint;
  try {
    if (/^-?0x[0-9a-f]+$/i.test(t) || /^-?[0-9]+$/.test(t)) v = BigInt(t);
    else if (/^[0-9a-f]+h$/i.test(t)) v = BigInt("0x" + t.slice(0, -1));
    else if (/^[0-9a-f]+$/i.test(t)) v = BigInt("0x" + t);
    else return null;
  } catch {
    return null;
  }
  const bits = BigInt(8 * Math.max(1, Math.min(8, size || 8)));
  if (v < 0n) v = (1n << bits) + v;
  if (v < 0n || v >= 1n << bits) return null;
  return v;
}

/**
 * Ghidra's Set Register Values: a register (typed, with the language's
 * registers to choose from), a value, the range (the selection or a
 * function's body, editable as first and last), and "No value (clear)".
 * Enter applies, as one undo step.
 */
export async function setRegisterValueDialog(o: SetRegisterValueOptions): Promise<string | null> {
  let regs: RegisterDescription[] = [];
  try {
    regs = await valueRegisters(o.rk, o.programId);
  } catch (e) {
    toast(`Set register value: ${errText(e)}`, { kind: "error" });
    return null;
  }
  return new Promise((resolve) => {
    const restore = document.activeElement as HTMLElement | null;
    const listId = `regs-${Math.random().toString(36).slice(2)}`;
    const datalist = h("datalist", { id: listId }, ...regs.map((r) => h("option", { value: r.name }, `${r.size} bytes`)));
    const reg = h("input", { class: "ask-input", placeholder: "gp, r2, r13…", list: listId, spellcheck: "false", autocomplete: "off", "aria-label": "Register", "data-testid": "regvalue-register" }) as HTMLInputElement;
    reg.value = o.register;
    const val = h("input", { class: "ask-input", placeholder: "0x418ff0", spellcheck: "false", autocomplete: "off", "aria-label": "Value", "data-testid": "regvalue-value" }) as HTMLInputElement;
    const one = o.ranges.length === 1 ? o.ranges[0] : null;
    const first = h("input", { class: "ask-input", spellcheck: "false", autocomplete: "off", "aria-label": "First address", "data-testid": "regvalue-first" }) as HTMLInputElement;
    const last = h("input", { class: "ask-input", spellcheck: "false", autocomplete: "off", "aria-label": "Last address", "data-testid": "regvalue-last" }) as HTMLInputElement;
    if (one) {
      first.value = one.first ? hex(one.first) : "";
      last.value = one.last ? hex(one.last) : "";
    }
    const clear = h("input", { type: "checkbox", "data-testid": "regvalue-clear" }) as HTMLInputElement;
    clear.checked = !!o.clear;
    const sync = () => {
      val.disabled = clear.checked;
    };
    clear.addEventListener("change", sync);
    sync();
    const err = h("div", { class: "ask-error", "data-testid": "ask-error" });
    const rangeRow = one
      ? h("div", { class: "ask-row" }, h("label", { class: "ask-label dim" }, h("span", { class: "ask-field-name" }, "From"), first), h("label", { class: "ask-label dim" }, h("span", { class: "ask-field-name" }, "To (inclusive)"), last))
      : h("div", { class: "dim" }, `Over ${o.what}: ${o.ranges.length} ranges`);
    const box = h(
      "div",
      { class: "modal ask", role: "dialog", "aria-modal": "true", "aria-label": "Set register value", "data-testid": "regvalue-dialog" },
      h("div", { class: "modal-title" }, `Set register value over ${o.what}`),
      datalist,
      h("label", { class: "ask-label dim" }, h("span", { class: "ask-field-name" }, "Register"), reg),
      h("label", { class: "ask-label dim" }, h("span", { class: "ask-field-name" }, "Value"), val),
      rangeRow,
      h("label", { class: "ask-control ask-check" }, clear, h("span", {}, "No value here (clear, over analysis's own)")),
      err,
      h("div", { class: "modal-hint" }, "Enter to apply · Esc to cancel · analysis and the decompiler take the register as this constant there"),
    );
    const backdrop = h("div", { class: "backdrop" }, box);
    const done = (register: string | null) => {
      backdrop.remove();
      restore?.focus({ preventScroll: true });
      resolve(register);
    };
    let busy = false;
    const apply = async () => {
      if (busy) return;
      const name = reg.value.trim();
      const desc = regs.find((r) => r.name === name) ?? regs.find((r) => r.name.toLowerCase() === name.toLowerCase());
      if (!desc) {
        err.textContent = name ? `${name} isn't a register values can be set on` : "Which register?";
        return;
      }
      let value: bigint | null = null;
      if (!clear.checked) {
        value = parseValue(val.value, desc.size);
        if (value === null) {
          err.textContent = `The value must be a number that fits ${desc.name} (${desc.size} bytes)`;
          return;
        }
      }
      let ranges = o.ranges;
      if (one) {
        const a = parseAddress(first.value), b = parseAddress(last.value);
        if (a === null || b === null || b < a) {
          err.textContent = "From and To must be addresses, From first";
          return;
        }
        ranges = [{ first: a, last: b }];
      }
      busy = true;
      const label = value === null ? `Clear ${desc.name} over ${o.what}` : `Set ${desc.name} = 0x${hex(value)} over ${o.what}`;
      try {
        const r = await o.edits.bodies(label, ranges.map((x) => Edits.registerValueBody(desc.name, x.first, x.last, value)));
        done(desc.name);
        toast(value === null ? `${desc.name} has no value over ${o.what}` : `${desc.name} = 0x${hex(value)} over ${o.what}`, { action: { label: "Undo", run: () => o.undo() } });
        await o.settle(r.revision);
      } catch (e) {
        busy = false;
        err.textContent = errText(e);
      }
    };
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") done(null);
      else if (e.key === "Enter") {
        e.preventDefault();
        void apply();
      }
    });
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done(null);
    });
    overlayRoot().append(backdrop);
    (reg.value ? (clear.checked ? first : val) : reg).focus();
  });
}
