// Patching in the UI (PatchService, docs/patching.md): the inline
// instruction editor over the listing (Ctrl+Shift+G, Ghidra's key), the
// bytes editor for a selection (Ctrl+Shift+H), the Patches view, and the
// export dialog with checksum fixups and their detector. Every write is a
// Patch assertion: undoable with Ctrl+Z like any edit, and every view
// (listing, graph, decompiler, other tabs) updates from the subscription.

import { create } from "@bufbuild/protobuf";
import {
  ChecksumAlgorithm,
  ChecksumSpecSchema,
  ExportFixupSchema,
  ExportFormat,
  ExportSettingsSchema,
  QueryKind,
  type AssembleResponse,
  type AssemblyCandidate,
  type ChecksumHit,
  type ChecksumSpec,
  type ExportFixup,
  type ExportProgramResponse,
  type ExportSettings,
  type PatchInfo,
  type Revkit,
  type RevisionEvent,
} from "@revkit/api";
import { userProvenance } from "../api/client";
import type { Edits } from "../data/edits";
import { errText, hex } from "../data/format";
import { toast } from "../ui/dialogs";
import { h, overlayRoot } from "../ui/dom";
import "./patch.css";

export interface PatchHost {
  rk: Revkit;
  programId: string;
  addrWidth: number;
  edits: Edits;
  /** Waits until this tab has applied a revision (its views are current). */
  settle: (rev: bigint) => Promise<void>;
  navigate: (addr: bigint) => void;
  /** ARM: offer writing Thumb (or ARM) code where the listing has none. */
  isaToggle: boolean;
  /** "Compare with original" (feature diff): opens the Compare view. */
  compareWithOriginal?: () => Promise<void>;
}

const HEX = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join(" ");

/** Hex text ("e2 80 00 5f", "e280005f") to bytes; null if it isn't hex. */
export function parseHex(s: string): Uint8Array | null {
  const t = s.replace(/0x/gi, "").replace(/[\s,]+/g, "");
  if (!t.length || t.length % 2 || /[^0-9a-f]/i.test(t)) return null;
  const out = new Uint8Array(t.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(t.slice(2 * i, 2 * i + 2), 16);
  return out;
}

// ---------------------------------------------------------- the inline editor --

/**
 * The line being patched becomes an editor over its listing row: the text
 * as the listing prints it, assembled as you type (debounced), with the
 * encodings found (ranked: shortest, then the current encoding's style),
 * the parser's error and where, and completions at the cursor. Enter
 * writes the highlighted encoding.
 */
export class PatchEditor {
  readonly el: HTMLElement;
  private input: HTMLInputElement;
  private list: HTMLElement;
  private err: HTMLElement;
  private ctxChip: HTMLElement;
  private pad: HTMLInputElement;
  private thumb: HTMLInputElement | null = null;
  private address = 0n;
  private seq = 0;
  private timer = 0;
  private resp: AssembleResponse | null = null;
  /** The text `resp` answers (a key typed since makes it stale). */
  private respText = "";
  private active = 0;
  /** Completion mode: the list shows completions (Tab inserts one). */
  private completing = false;
  private busy = false;
  private restore: HTMLElement | null = null;
  onClose: (() => void) | null = null;

  constructor(private host: PatchHost) {
    this.input = h("input", { class: "pe-input mono", spellcheck: "false", autocomplete: "off", "data-testid": "patch-input", "aria-label": "Instruction" });
    this.list = h("div", { class: "pe-list", role: "listbox", "data-testid": "patch-list" });
    this.err = h("div", { class: "pe-error mono", "data-testid": "patch-error" });
    this.ctxChip = h("span", { class: "pe-ctx dim" });
    this.pad = h("input", { type: "checkbox", "data-testid": "patch-pad" });
    const title = h("div", { class: "pe-head" }, h("span", { class: "pe-title" }, "Patch instruction"), this.ctxChip);
    if (host.isaToggle) {
      this.thumb = h("input", { type: "checkbox", "data-testid": "patch-thumb", onchange: () => this.schedule(0) });
      title.append(h("label", { class: "pe-opt", title: "Assemble as Thumb (TMode=1) instead of what the listing decodes here" }, this.thumb, "Thumb"));
    }
    this.el = h(
      "div",
      { class: "patch-editor", role: "dialog", "aria-label": "Patch instruction", "data-testid": "patch-editor" },
      title,
      this.input,
      this.err,
      this.list,
      h(
        "div",
        { class: "pe-foot dim" },
        h("span", {}, "Enter patch · ↑↓ encoding · Tab complete · Esc cancel"),
        h("label", { class: "pe-opt", title: "Fill the rest of a longer instruction with NOPs" }, this.pad, "Pad with NOPs"),
      ),
    );
    this.input.addEventListener("input", () => {
      this.completing = /[A-Za-z_.]$/.test(this.input.value.slice(0, this.input.selectionStart ?? 0));
      this.schedule(120);
    });
    this.input.addEventListener("keydown", (e) => this.onKey(e));
    this.list.addEventListener("mousedown", (e) => {
      const el = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (!el) return;
      e.preventDefault();
      this.active = Number(el.dataset.i);
      if (this.completing) this.complete();
      else void this.commit();
    });
  }

  get isOpen() {
    return this.el.isConnected;
  }

  /** Opens over a row: `text` is what the listing shows there, `at` the row's client rectangle. */
  open(address: bigint, text: string, at: { left: number; top: number; width: number }) {
    this.restore = document.activeElement as HTMLElement | null;
    this.address = address;
    this.resp = null;
    this.active = 0;
    this.completing = false;
    this.err.textContent = "";
    this.list.replaceChildren();
    this.input.value = text;
    if (this.thumb) this.thumb.checked = false;
    this.ctxChip.textContent = `0x${hex(address, this.host.addrWidth)}`;
    overlayRoot().append(this.el);
    this.el.style.left = `${Math.max(8, at.left)}px`;
    this.el.style.top = `${Math.max(8, at.top)}px`;
    this.el.style.width = `${Math.min(Math.max(520, at.width * 0.6), innerWidth - at.left - 16)}px`;
    this.input.focus();
    this.input.setSelectionRange(text.length, text.length);
    this.schedule(0);
  }

  close() {
    clearTimeout(this.timer);
    this.el.remove();
    this.restore?.focus({ preventScroll: true });
    this.onClose?.();
  }

  private schedule(ms: number) {
    clearTimeout(this.timer);
    this.timer = window.setTimeout(() => void this.assemble(), ms);
  }

  private context(): Record<string, number> {
    return this.thumb?.checked ? { TMode: 1 } : {};
  }

  private async assemble() {
    const seq = ++this.seq;
    const text = this.input.value;
    try {
      const r = await this.host.rk.patch.assemble({
        programId: this.host.programId,
        address: { offset: this.address },
        text,
        cursor: this.input.selectionStart ?? text.length,
        complete: true,
        context: this.context(),
      });
      if (seq !== this.seq) return;
      this.resp = r;
      this.respText = text;
      this.active = 0;
      this.paint();
    } catch (e) {
      if (seq !== this.seq) return;
      this.err.textContent = errText(e);
    }
  }

  private items(): { label: string; detail: string; cand?: AssemblyCandidate; completion?: string }[] {
    const r = this.resp;
    if (!r) return [];
    if (this.completing && r.completions.length) {
      const partial = this.input.value.slice(r.completionFrom, this.input.selectionStart ?? undefined).toLowerCase();
      return r.completions.filter((c) => !c.startsWith("<") || !partial).slice(0, 40).map((c) => ({ label: c, detail: c.startsWith("<") ? "operand" : "", completion: c }));
    }
    return r.candidates.map((c) => ({
      label: c.text,
      detail: `${HEX(c.bytes)}  ${c.bytes.length} B${c.current ? " · current" : c.hamming ? ` · ${c.hamming} bit${c.hamming === 1 ? "" : "s"} changed` : ""}`,
      cand: c,
    }));
  }

  private paint() {
    const r = this.resp;
    if (!r) return;
    const ctx = r.context ? ` · ${r.context}` : "";
    this.ctxChip.textContent = `0x${hex(this.address, this.host.addrWidth)} · now ${r.currentText || "(no instruction)"}${ctx}`;
    if (this.completing && r.completions.length) {
      this.err.textContent = "";
      delete this.el.dataset.error;
    } else if (r.error && !r.candidates.length) {
      // Where the text stopped parsing, and what could come there.
      const col = r.errorColumn >= 0 ? r.errorColumn : this.input.value.length;
      const exp = r.expected.length ? ` — expected ${r.expected.slice(0, 12).join(" ")}${r.expected.length > 12 ? " …" : ""}` : "";
      const parts: Node[] = [h("div", {}, r.error + exp)];
      if (r.errorColumn >= 0) parts.push(h("div", { class: "pe-caret" }, this.input.value.slice(0, col).replace(/[^\t]/g, " ") + "^"));
      this.err.replaceChildren(...parts);
      this.el.dataset.error = "1";
    } else {
      this.err.textContent = r.truncated ? "more encodings exist than are shown" : "";
      delete this.el.dataset.error;
    }
    const items = this.items();
    this.active = Math.min(this.active, Math.max(0, items.length - 1));
    this.list.replaceChildren(
      ...items.map((it, i) =>
        h(
          "div",
          { class: "pe-item" + (i === this.active ? " active" : "") + (it.cand?.current ? " current" : ""), "data-i": i, role: "option" },
          h("span", { class: "pe-label mono" }, it.label),
          h("span", { class: "pe-detail mono dim" }, it.detail),
        ),
      ),
    );
    this.el.dataset.mode = this.completing && r.completions.length ? "complete" : "candidates";
  }

  private onKey(e: KeyboardEvent) {
    e.stopPropagation();
    const items = this.items();
    if (e.key === "Escape") {
      e.preventDefault();
      if (this.completing) {
        this.completing = false;
        this.paint();
      } else this.close();
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      this.active = Math.max(0, Math.min(items.length - 1, this.active + (e.key === "ArrowDown" ? 1 : -1)));
      this.paint();
    } else if (e.key === "Tab") {
      e.preventDefault();
      if (!this.completing) {
        this.completing = true;
        this.schedule(0);
      } else this.complete();
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (this.completing && this.resp?.completions.length) this.complete();
      else void this.commit();
    } else if (e.key === " " && e.ctrlKey) {
      e.preventDefault();
      this.completing = true;
      this.schedule(0);
    }
  }

  private complete() {
    if (this.respText !== this.input.value) {
      // Typed faster than the daemon answered: show its completions first.
      this.completing = true;
      clearTimeout(this.timer);
      void this.assemble();
      return;
    }
    const it = this.items()[this.active];
    const r = this.resp;
    if (!it?.completion || !r || it.completion.startsWith("<")) {
      this.completing = false;
      return this.paint();
    }
    const cursor = this.input.selectionStart ?? this.input.value.length;
    const v = this.input.value;
    const next = v.slice(0, r.completionFrom) + it.completion + v.slice(cursor);
    this.input.value = next;
    const at = r.completionFrom + it.completion.length;
    this.input.setSelectionRange(at, at);
    this.completing = false;
    this.schedule(0);
  }

  private async commit() {
    if (this.busy) return;
    clearTimeout(this.timer);
    await this.assemble();
    const r = this.resp;
    const chosen = r?.candidates[this.completing ? 0 : this.active] ?? r?.candidates[0];
    if (!r || !chosen) {
      toast(r?.error || "nothing to patch", { kind: "error" });
      return;
    }
    if (chosen.current && !this.pad.checked) {
      this.close();
      return toast("The bytes there already are this instruction");
    }
    this.busy = true;
    this.el.classList.add("busy");
    try {
      const text = this.input.value.trim();
      const resp = await this.host.rk.patch.patchInstruction({
        programId: this.host.programId,
        address: { offset: this.address },
        text,
        bytes: chosen.bytes,
        pad: this.pad.checked,
        context: this.context(),
        provenance: userProvenance("patch"),
      });
      this.host.edits.record(`Patch ${text}`, resp.seqs);
      this.close();
      toast(`Patched 0x${hex(this.address, this.host.addrWidth)}: ${resp.text}${resp.padding.length ? ` (+${resp.padding.length} bytes of NOPs)` : ""}`);
      void this.host.settle(resp.revision);
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      this.busy = false;
      this.el.classList.remove("busy");
    }
  }
}

// -------------------------------------------------------------- bytes editor --

/** Edits the bytes of [start, start + length): hex or text, written as one patch (one revision). */
export async function patchBytesDialog(host: PatchHost, start: bigint, length: number): Promise<void> {
  const n = Math.min(Math.max(1, length), 4096);
  let current: Uint8Array;
  try {
    current = (await host.rk.queries.readMemory({ programId: host.programId, address: { offset: start }, length: n })).data;
  } catch (e) {
    return toast(errText(e), { kind: "error" });
  }
  if (!current.length) return toast(`0x${hex(start)} has no bytes to patch`, { kind: "error" });
  return new Promise((resolve) => {
    const restore = document.activeElement as HTMLElement | null;
    const mode = h("select", { class: "pb-mode", "data-testid": "patch-bytes-mode" }, h("option", { value: "hex" }, "Hex"), h("option", { value: "text" }, "Text (ASCII)"));
    const area = h("textarea", { class: "ask-input mono pb-area", rows: Math.min(12, Math.ceil(current.length / 16) + 1), spellcheck: "false", "data-testid": "patch-bytes-input" });
    const preview = h("div", { class: "pb-preview mono dim" });
    const err = h("div", { class: "ask-error" });
    const asHex = (b: Uint8Array) => {
      const lines: string[] = [];
      for (let i = 0; i < b.length; i += 16) lines.push(HEX(b.subarray(i, i + 16)));
      return lines.join("\n");
    };
    const asText = (b: Uint8Array) => [...b].map((x) => (x >= 0x20 && x < 0x7f ? String.fromCharCode(x) : ".")).join("");
    area.value = asHex(current);
    const parse = (): Uint8Array | null => {
      if (mode.value === "hex") return parseHex(area.value);
      const enc = new TextEncoder().encode(area.value);
      return enc;
    };
    const show = () => {
      const b = parse();
      if (!b) {
        preview.textContent = "not hex";
        return;
      }
      let changed = 0;
      for (let i = 0; i < b.length; i++) changed += i >= current.length || b[i] !== current[i] ? 1 : 0;
      preview.textContent = `${b.length} bytes, ${changed} changed · ${asText(b.subarray(0, 64))}`;
    };
    area.addEventListener("input", show);
    mode.addEventListener("change", () => {
      area.value = mode.value === "hex" ? asHex(parse() ?? current) : asText(current);
      show();
    });
    const box = h(
      "div",
      { class: "modal ask pb", role: "dialog", "aria-label": "Patch bytes", "data-testid": "patch-bytes" },
      h("div", { class: "modal-title" }, `Patch bytes at 0x${hex(start, host.addrWidth)} (${current.length} bytes)`),
      h("label", { class: "ask-label dim" }, "Edit as ", mode),
      area,
      preview,
      err,
      h("div", { class: "modal-hint" }, "Ctrl+Enter to patch · Esc to cancel · one patch, undone with Ctrl+Z"),
    );
    const backdrop = h("div", { class: "backdrop" }, box);
    const done = () => {
      backdrop.remove();
      restore?.focus({ preventScroll: true });
      resolve();
    };
    box.addEventListener("keydown", async (e) => {
      e.stopPropagation();
      if (e.key === "Escape") return done();
      if (e.key !== "Enter" || !(e.ctrlKey || e.metaKey)) return;
      e.preventDefault();
      const b = parse();
      if (!b) {
        err.textContent = "Enter hex bytes (\"e2 80 00 5f\")";
        return;
      }
      // Only the changed span: the first through the last changed byte.
      let first = -1;
      let last = -1;
      for (let i = 0; i < b.length; i++)
        if (i >= current.length || b[i] !== current[i]) {
          if (first < 0) first = i;
          last = i;
        }
      if (first < 0) return done();
      try {
        const r = await host.rk.patch.patchBytes({
          programId: host.programId,
          address: { offset: start + BigInt(first) },
          data: b.subarray(first, last + 1),
          provenance: userProvenance("patch bytes"),
        });
        host.edits.record(`Patch ${last - first + 1} bytes at 0x${hex(start + BigInt(first))}`, r.seqs);
        toast(`Patched ${last - first + 1} bytes at 0x${hex(start + BigInt(first), host.addrWidth)}`);
        void host.settle(r.revision);
        done();
      } catch (ex) {
        err.textContent = errText(ex);
      }
    });
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done();
    });
    overlayRoot().append(backdrop);
    show();
    area.focus();
  });
}

// ------------------------------------------------------------- the Patches view --

/** The program's patches: what changed, from what, by whom; revert, go to, export. */
export class PatchesView {
  private table: HTMLElement;
  private status: HTMLElement;
  private revertAllBtn: HTMLButtonElement;
  private stale = true;
  patches: PatchInfo[] = [];

  constructor(
    readonly el: HTMLElement,
    private host: PatchHost,
  ) {
    this.status = h("span", { class: "dim", "data-testid": "patches-status" });
    this.table = h("div", { class: "pp-table", "data-testid": "patches-table" }, h("div", { class: "pp-empty dim" }, "Loading…"));
    this.revertAllBtn = h("button", { class: "btn small", "data-testid": "patches-revert-all", text: "Revert all", disabled: true, onclick: () => void this.revertAll() });
    el.replaceChildren(
      h(
        "div",
        { class: "panel-head pp-head" },
        h("span", { class: "panel-title" }, "Patches"),
        this.status,
        h("span", { class: "grow" }),
        host.compareWithOriginal ? h("button", { class: "btn small", "data-testid": "patches-compare", text: "Compare with original", onclick: () => void host.compareWithOriginal!() }) : null,
        h("button", { class: "btn small", "data-testid": "patches-export", text: "Export…", onclick: () => void exportDialog(host) }),
        this.revertAllBtn,
      ),
      this.table,
    );
  }

  ensureLoaded() {
    if (this.stale) void this.load();
  }

  markStale() {
    this.stale = true;
  }

  /** Reloads when an event says patches changed (or marks stale when hidden). */
  onRevision(ev: RevisionEvent, visible: boolean) {
    const hit = ev.invalidated.some((q) => q.programId === this.host.programId && q.kind === QueryKind.PATCHES);
    if (!hit) return;
    if (visible) void this.load();
    else this.stale = true;
  }

  async load() {
    this.stale = false;
    try {
      const r = await this.host.rk.patch.listPatches({ programId: this.host.programId });
      this.patches = r.patches;
      this.status.textContent = `${r.patches.length} patch${r.patches.length === 1 ? "" : "es"}, ${r.patchedBytes} bytes`;
      this.paint();
    } catch (e) {
      this.status.textContent = errText(e);
    }
  }

  private paint() {
    const w = this.host.addrWidth;
    this.revertAllBtn.disabled = !this.patches.length;
    if (!this.patches.length) {
      this.table.replaceChildren(h("div", { class: "pp-empty dim" }, "No patches. Patch an instruction with Ctrl+Shift+G, bytes with Ctrl+Shift+H."));
      return;
    }
    this.table.replaceChildren(
      ...this.patches.map((p) => {
        const addr = p.address?.offset ?? 0n;
        const was = p.originalText || HEX(p.original);
        const now = p.text || HEX(p.bytes);
        const who = `${p.provenance?.id || "?"} · r${p.revision}`;
        // Two lines: where, what it was and is now; then the function,
        // the bytes and who patched it.
        return h(
          "div",
          { class: "pp-row", "data-testid": "patch-row", "data-address": hex(addr) },
          h(
            "div",
            { class: "pp-main" },
            h("a", { class: "mono link", href: "#", onclick: (e: Event) => (e.preventDefault(), this.host.navigate(addr)) }, hex(addr, w)),
            h("span", { class: "mono pp-was", title: was }, was),
            h("span", { class: "dim" }, "→"),
            h("span", { class: "mono pp-now", title: p.typedText ? `typed: ${p.typedText}` : now }, now + (p.shadowedBytes ? ` (${p.shadowedBytes} bytes overridden)` : "")),
            h("button", { class: "btn small", "data-testid": "patch-revert", text: "Revert", onclick: () => void this.revert(p) }),
          ),
          h(
            "div",
            { class: "pp-sub dim" },
            h("span", {}, p.functionName || "(no function)"),
            h("span", { class: "mono" }, `${HEX(p.original)} → ${HEX(p.bytes)}`),
            h("span", {}, who),
          ),
        );
      }),
    );
  }

  async revert(p: PatchInfo) {
    try {
      const r = await this.host.rk.patch.revertPatches({ programId: this.host.programId, seqs: [p.seq], provenance: userProvenance("revert patch") });
      this.host.edits.record(`Revert patch at 0x${hex(p.address?.offset ?? 0n)}`, r.seqs);
      void this.host.settle(r.revision);
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }

  async revertAll() {
    if (!this.patches.length) return;
    try {
      const r = await this.host.rk.patch.revertPatches({ programId: this.host.programId, seqs: this.patches.map((p) => p.seq), provenance: userProvenance("revert all patches") });
      this.host.edits.record(`Revert ${this.patches.length} patches`, r.seqs);
      void this.host.settle(r.revision);
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  }
}

// ----------------------------------------------------------------- export --

const ALGORITHMS = Object.entries(ChecksumAlgorithm)
  .filter(([k, v]) => typeof v === "number" && v !== 0 && isNaN(Number(k)))
  .map(([k, v]) => ({ name: k.toLowerCase().replace(/_/g, "-"), value: v as ChecksumAlgorithm }));

function specText(s: ChecksumSpec): string {
  const alg = ALGORITHMS.find((a) => a.value === s.algorithm)?.name ?? "?";
  const end = s.end === 0n ? "EOF" : s.end < 0n ? `EOF-0x${(-s.end).toString(16)}` : `0x${s.end.toString(16)}`;
  const where = s.field ? ` → 0x${s.fieldOffset.toString(16)} (${s.fieldWidth} B, ${s.fieldBigEndian ? "BE" : "LE"})` : s.name ? " → file name" : "";
  return `${alg} over 0x${s.start.toString(16)}..${end}${s.skipPadding ? " (no padding)" : ""}${where}`;
}

/** Downloads bytes as a file the browser saves. */
function download(data: Uint8Array, name: string) {
  const url = URL.createObjectURL(new Blob([new Uint8Array(data)], { type: "application/octet-stream" }));
  const a = h("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** The export dialog: format, fixups (with the detector), the file name template; Export downloads the verified file. */
export async function exportDialog(host: PatchHost): Promise<ExportProgramResponse | null> {
  let settings: ExportSettings | undefined;
  let fileName = "";
  try {
    const s = await host.rk.patch.getExportSettings({ programId: host.programId });
    settings = s.settings;
    fileName = s.fileName;
  } catch (e) {
    toast(errText(e), { kind: "error" });
    return null;
  }
  const fixups: ExportFixup[] = [...(settings?.fixups ?? [])];
  return new Promise((resolve) => {
    const restore = document.activeElement as HTMLElement | null;
    const format = h(
      "select",
      { "data-testid": "export-format" },
      h("option", { value: String(ExportFormat.FILE) }, "The whole file (header kept)"),
      h("option", { value: String(ExportFormat.IMAGE) }, "Only the loaded image (raw imports)"),
    );
    if (settings?.format === ExportFormat.IMAGE) format.value = String(ExportFormat.IMAGE);
    const template = h("input", { class: "ask-input mono", placeholder: "{NAME}_{SUM:08X}{EXT}", value: settings?.fileNameTemplate ?? "", spellcheck: "false", "data-testid": "export-template" });
    const fixList = h("div", { class: "ex-fixups", "data-testid": "export-fixups" });
    const detectIn = h("input", { class: "ask-input mono", placeholder: "a file name with the checksum in it, or the value (0x…)", value: fileName, spellcheck: "false", "data-testid": "export-detect-input" });
    const hits = h("div", { class: "ex-hits", "data-testid": "export-hits" });
    const result = h("div", { class: "ex-result", "data-testid": "export-result" });
    const err = h("div", { class: "ask-error" });

    // A new checksum fixup's fields.
    const alg = h("select", { "data-testid": "export-alg" }, ...ALGORITHMS.filter((a) => a.name !== "pe").map((a) => h("option", { value: String(a.value) }, a.name)));
    alg.value = String(ChecksumAlgorithm.SUM32);
    const range = h("input", { class: "mono ex-small", placeholder: "0..EOF", value: "0..EOF", "data-testid": "export-range" });
    const target = h("select", { "data-testid": "export-target" }, h("option", { value: "name" }, "into the file name"), h("option", { value: "field" }, "into a field"));
    const field = h("input", { class: "mono ex-small", placeholder: "offset", "data-testid": "export-field" });
    const width = h("select", {}, h("option", { value: "4" }, "4 B"), h("option", { value: "2" }, "2 B"), h("option", { value: "1" }, "1 B"));
    const endian = h("select", {}, h("option", { value: "le" }, "LE"), h("option", { value: "be" }, "BE"));

    const paintFixups = () =>
      fixList.replaceChildren(
        ...(fixups.length
          ? fixups.map((f, i) =>
              h(
                "div",
                { class: "ex-fixup" },
                h("span", { class: "mono" }, f.kind.case === "peChecksum" ? "PE optional header CheckSum" : f.kind.case === "checksum" ? specText(f.kind.value) : "?"),
                h("button", { class: "link", text: "remove", onclick: () => (fixups.splice(i, 1), paintFixups()) }),
              ),
            )
          : [h("span", { class: "dim" }, "No fixups: the file as patched.")]),
      );
    const parseNum = (s: string): bigint | null => {
      const t = s.trim();
      if (!t) return null;
      try {
        return BigInt(t.startsWith("0x") || t.startsWith("-0x") ? t.replace("-0x", "-0x") : t);
      } catch {
        return null;
      }
    };
    const addChecksum = () => {
      const [a, b] = range.value.split("..");
      const start = parseNum(a ?? "0") ?? 0n;
      let end = 0n;
      const bt = (b ?? "EOF").trim().toUpperCase();
      if (bt.startsWith("EOF-")) end = -(parseNum(bt.slice(4).toLowerCase()) ?? 0n);
      else if (bt !== "EOF" && bt) end = parseNum(b!) ?? 0n;
      const isField = target.value === "field";
      const off = parseNum(field.value);
      if (isField && off === null) return (err.textContent = "Give the field's offset");
      fixups.push(
        create(ExportFixupSchema, {
          kind: {
            case: "checksum",
            value: create(ChecksumSpecSchema, {
              algorithm: Number(alg.value) as ChecksumAlgorithm,
              start,
              end,
              field: isField,
              fieldOffset: off ?? 0n,
              fieldWidth: Number(width.value),
              fieldBigEndian: endian.value === "be",
              name: !isField,
            }),
          },
        }),
      );
      err.textContent = "";
      paintFixups();
    };
    const detect = async () => {
      hits.replaceChildren(h("span", { class: "dim" }, "searching…"));
      const v = detectIn.value.trim();
      const isValue = /^(0x)?[0-9a-f]+$/i.test(v) && !v.includes(".");
      try {
        const r = await host.rk.patch.detectChecksum({ programId: host.programId, expected: isValue ? v : "", fileName: isValue ? "" : v });
        if (!r.hits.length) {
          hits.replaceChildren(h("span", { class: "dim" }, `No rule found (${r.tried} sums and CRCs over ${v ? "the file" : "it"} tried).`));
          return;
        }
        hits.replaceChildren(
          ...r.hits.slice(0, 8).map((hit: ChecksumHit) =>
            h(
              "div",
              { class: "ex-hit", "data-testid": "export-hit" },
              h("span", { class: "mono" }, hit.evidence),
              h("button", {
                class: "btn small",
                text: "Use",
                onclick: () => {
                  fixups.push(create(ExportFixupSchema, { kind: { case: "checksum", value: hit.spec! } }));
                  if (hit.fileNameTemplate) template.value = hit.fileNameTemplate;
                  paintFixups();
                },
              }),
            ),
          ),
        );
      } catch (e) {
        hits.replaceChildren(h("span", { class: "ask-error" }, errText(e)));
      }
    };
    const current = (): ExportSettings => create(ExportSettingsSchema, { format: Number(format.value) as ExportFormat, fixups, fileNameTemplate: template.value.trim() });
    const save = async () => {
      try {
        await host.rk.patch.setExportSettings({ programId: host.programId, settings: current(), provenance: userProvenance("export settings") });
        toast("Export settings saved with the program");
      } catch (e) {
        err.textContent = errText(e);
      }
    };
    const run = async () => {
      result.replaceChildren(h("span", { class: "dim" }, "exporting and verifying…"));
      err.textContent = "";
      try {
        const r = await host.rk.patch.exportProgram({ programId: host.programId, settings: current() });
        const v = r.verification;
        result.replaceChildren(
          h("div", { class: "mono", "data-testid": "export-name" }, r.fileName),
          h("div", { class: "dim" }, `${r.size} bytes · sha256 ${r.sha256.slice(0, 16)}… · ${r.changes.length} change${r.changes.length === 1 ? "" : "s"}`),
          ...r.fixups.map((f) => h("div", { class: "mono dim" }, f)),
          h("div", { class: v?.ok ? "ex-ok" : "ask-error", "data-testid": "export-verify" }, v ? (v.ok ? "✓ " : "✗ ") + v.detail : "not verified"),
        );
        download(r.data, r.fileName || "export.bin");
        resolve(r);
      } catch (e) {
        result.replaceChildren();
        err.textContent = errText(e);
      }
    };
    const box = h(
      "div",
      { class: "modal ex", role: "dialog", "aria-label": "Export program", "data-testid": "export-dialog" },
      h("div", { class: "modal-title" }, "Export the patched program"),
      h("label", { class: "ex-line" }, h("span", { class: "dim" }, "Format"), format),
      h("div", { class: "ex-section dim" }, "Fixups (applied in order: fields, the PE CheckSum, then the file name)"),
      fixList,
      h(
        "div",
        { class: "ex-line" },
        alg,
        h("span", { class: "dim" }, "over"),
        range,
        target,
        field,
        width,
        endian,
        h("button", { class: "btn small", text: "Add checksum", "data-testid": "export-add", onclick: addChecksum }),
        h("button", {
          class: "btn small",
          text: "Add PE CheckSum",
          onclick: () => (fixups.push(create(ExportFixupSchema, { kind: { case: "peChecksum", value: true } })), paintFixups()),
        }),
      ),
      h("div", { class: "ex-section dim" }, "Detect the rule from a file name or value"),
      h("div", { class: "ex-line" }, detectIn, h("button", { class: "btn small", text: "Detect", "data-testid": "export-detect", onclick: () => void detect() })),
      hits,
      h("label", { class: "ex-line" }, h("span", { class: "dim" }, "File name"), template),
      err,
      result,
      h(
        "div",
        { class: "ex-buttons" },
        h("button", { class: "btn", text: "Save settings", "data-testid": "export-save", onclick: () => void save() }),
        h("button", { class: "btn primary", text: "Export", "data-testid": "export-run", onclick: () => void run() }),
        h("button", { class: "btn", text: "Close", onclick: () => done() }),
      ),
    );
    const backdrop = h("div", { class: "backdrop" }, box);
    const done = () => {
      backdrop.remove();
      restore?.focus({ preventScroll: true });
      resolve(null);
    };
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") done();
    });
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done();
    });
    paintFixups();
    overlayRoot().append(backdrop);
    template.focus();
  });
}
