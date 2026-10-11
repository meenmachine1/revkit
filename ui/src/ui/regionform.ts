// A memory region editor: one form for every kind of region a program's
// memory map can gain (docs/memory-map.md) — uninitialized RAM, zero-filled
// memory, memory-mapped I/O, and bytes from another file at an address
// (Ghidra's "Add To Program"), uploaded or chosen on the daemon's host —
// and for changing one (an image block: only its name, permissions and
// volatile flag). Standalone: it knows nothing of the daemon but what its
// caller passes, so the Open dialog's raw regions could use it too
// (`kinds` without "file", `submit` collecting the region).
//
// The form stays open on an error: the caller's `submit` resolves to the
// daemon's message (an overlap names the block), shown under the fields.

import { formatSize, type HostFile } from "./hostfiles";
import { h, overlayRoot } from "./dom";

export type RegionKind = "ram" | "zero" | "mmio" | "file";

export const KIND_LABELS: Record<RegionKind, string> = {
  ram: "Uninitialized RAM",
  zero: "Zero-filled memory",
  mmio: "Memory-mapped I/O (volatile)",
  file: "Bytes from a file",
};

export type RegionFile = { source: "upload"; name: string; bytes: Uint8Array } | { source: "host"; name: string; path: string };

export interface RegionDraft {
  kind: RegionKind;
  name: string;
  start: bigint;
  /** 0 with a file: its bytes' length. */
  size: bigint;
  read: boolean;
  write: boolean;
  execute: boolean;
  isVolatile: boolean;
  /** Zero-filled (or a file's bytes) rather than no contents. */
  initialized: boolean;
  file?: RegionFile;
  fileOffset: bigint;
  /** 0: to the end of the file. */
  length: bigint;
}

export interface RegionFormOptions {
  title: string;
  /** What the primary button says ("Add", "Save"). */
  action: string;
  /** "image": one of the image's own blocks (name, permissions, volatile only). */
  mode?: "add" | "edit" | "image";
  initial?: Partial<RegionDraft>;
  /** The kinds offered (default: all). */
  kinds?: RegionKind[];
  /** Offers the daemon host's files (feature host-files). */
  browseHost?: () => Promise<HostFile | null>;
  /** Offers an upload from this computer. */
  pickUpload?: () => Promise<File | null>;
  /** Commits the region: the daemon's error, or null when it took it. */
  submit: (d: RegionDraft) => Promise<string | null>;
}

const hexOf = (v: bigint | undefined) => (v === undefined ? "" : v.toString(16));

/** "1000", "0x1000", "4k", "1m" (sizes); null when it isn't a number. */
export function parseHexSize(s: string): bigint | null {
  const t = s.trim().toLowerCase().replace(/_/g, "");
  if (!t) return null;
  const m = /^(0x)?([0-9a-f]+)$/.exec(t);
  if (m) return BigInt("0x" + m[2]);
  const k = /^([0-9]+)\s*([km])$/.exec(t);
  if (k) return BigInt(k[1]) * (k[2] === "k" ? 1024n : 1048576n);
  return null;
}

/** The kind a region's flags say. */
export function kindOf(r: { initialized: boolean; isVolatile: boolean; file?: boolean }): RegionKind {
  if (r.file) return "file";
  if (r.isVolatile && !r.initialized) return "mmio";
  return r.initialized ? "zero" : "ram";
}

/** Resolves true when the region was submitted, false when cancelled. */
export function regionForm(o: RegionFormOptions): Promise<boolean> {
  return new Promise((resolve) => {
    const restore = document.activeElement as HTMLElement | null;
    const mode = o.mode ?? "add";
    const init = o.initial ?? {};
    const kinds = o.kinds ?? (["ram", "zero", "mmio", "file"] as RegionKind[]);
    let file: RegionFile | undefined = init.file;

    const input = (testid: string, label: string, value: string, placeholder = "") =>
      h("input", { class: "ask-input", "aria-label": label, placeholder, spellcheck: "false", autocomplete: "off", "data-testid": testid, value }) as HTMLInputElement;
    const check = (testid: string, label: string, on: boolean) => {
      const box = h("input", { type: "checkbox", "data-testid": testid, "aria-label": label }) as HTMLInputElement;
      box.checked = on;
      return { box, el: h("label", { class: "rf-check" }, box, label) };
    };
    const kind = h("select", { class: "filter select", "aria-label": "Kind of region", "data-testid": "rf-kind" }, ...kinds.map((k) => h("option", { value: k }, KIND_LABELS[k]))) as HTMLSelectElement;
    kind.value = init.kind && kinds.includes(init.kind) ? init.kind : kinds[0];
    const name = input("rf-name", "Name", init.name ?? "", "sram");
    const start = input("rf-start", "Start address (hex)", hexOf(init.start), "20000000");
    const size = input("rf-size", "Size (hex)", init.size ? hexOf(init.size) : "", "1000");
    const r = check("rf-read", "Read", init.read ?? true);
    const w = check("rf-write", "Write", init.write ?? true);
    const x = check("rf-exec", "Execute", init.execute ?? false);
    const vol = check("rf-volatile", "Volatile (I/O)", init.isVolatile ?? false);
    const zero = check("rf-initialized", "Zero-filled", init.initialized ?? false);
    const fileName = h("span", { class: "rf-file-name dim", "data-testid": "rf-file" }, file ? describeFile(file) : "No file chosen");
    const upload = o.pickUpload
      ? h("button", { class: "btn small", type: "button", "data-testid": "rf-upload", text: "Upload…" })
      : null;
    const host = o.browseHost
      ? h("button", { class: "btn small", type: "button", "data-testid": "rf-host", text: "Daemon host…" })
      : null;
    const offset = input("rf-offset", "Offset in the file (hex)", init.fileOffset ? hexOf(init.fileOffset) : "", "0");
    const length = input("rf-length", "Bytes to take (hex)", init.length ? hexOf(init.length) : "", "to the end");
    const err = h("div", { class: "ask-error", role: "alert", "data-testid": "rf-error" });
    const submit = h("button", { class: "btn primary", type: "button", "data-testid": "rf-submit", text: o.action });
    const cancel = h("button", { class: "btn", type: "button", "data-testid": "rf-cancel", text: "Cancel" });

    const row = (label: string, ...field: (HTMLElement | null)[]) => h("label", { class: "ask-label dim rf-row" }, h("span", { class: "ask-field-name" }, label), ...field);
    const fileRows = h(
      "div",
      { class: "rf-file" },
      h("div", { class: "rf-row rf-pick" }, h("span", { class: "ask-field-name dim" }, "File"), fileName, upload, host),
      row("Offset", offset),
      row("Length", length),
    );
    const kindRow = row("Kind", kind);
    const sizeRow = row("Size", size);
    const box = h(
      "div",
      { class: "modal ask region-form", role: "dialog", "aria-modal": "true", "aria-label": o.title, tabindex: "-1", "data-testid": "region-form" },
      h("div", { class: "modal-title" }, o.title),
      mode === "add" ? kindRow : null,
      row("Name", name),
      row("Start", start),
      sizeRow,
      fileRows,
      h("div", { class: "rf-row rf-checks" }, h("span", { class: "ask-field-name dim" }, "Access"), r.el, w.el, x.el, vol.el, zero.el),
      err,
      h("div", { class: "rf-actions" }, h("span", { class: "modal-hint" }, "Enter to save · Esc to cancel"), h("span", { class: "spacer" }), cancel, submit),
    );
    const backdrop = h("div", { class: "backdrop top" }, box);

    // What the kind decides.
    const sync = () => {
      const k = kind.value as RegionKind;
      const isFile = mode === "add" ? k === "file" : !!file;
      fileRows.hidden = !isFile || mode !== "add";
      size.placeholder = isFile ? "the bytes' length" : "1000";
      zero.el.hidden = isFile || mode === "image";
      if (mode === "add" && k === "mmio") vol.box.checked = true;
      if (mode === "add") zero.box.checked = k === "zero";
    };
    if (mode === "image") {
      start.disabled = true;
      size.disabled = true;
    }
    kind.addEventListener("change", sync);
    zero.box.addEventListener("change", () => {
      if (mode === "add" && kind.value !== "file") kind.value = zero.box.checked ? "zero" : vol.box.checked ? "mmio" : "ram";
    });
    sync();

    const done = (v: boolean) => {
      backdrop.remove();
      restore?.focus({ preventScroll: true });
      resolve(v);
    };
    const setFile = (f: RegionFile) => {
      file = f;
      fileName.textContent = describeFile(f);
      fileName.classList.remove("dim");
      if (!name.value.trim()) name.value = f.name.replace(/\.[^.]*$/, "").replace(/[^\w.-]/g, "_").slice(0, 40);
    };
    upload?.addEventListener("click", async () => {
      const f = await o.pickUpload!();
      if (f) setFile({ source: "upload", name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) });
    });
    host?.addEventListener("click", async () => {
      const f = await o.browseHost!();
      if (f) setFile({ source: "host", name: f.name, path: f.path });
    });

    let busy = false;
    const go = async () => {
      if (busy) return;
      const fail = (m: string) => {
        err.textContent = m;
        box.dataset.error = "1";
      };
      const k = mode === "add" ? (kind.value as RegionKind) : kindOf({ initialized: zero.box.checked, isVolatile: vol.box.checked, file: !!file });
      if (!name.value.trim()) return fail("A region needs a name");
      const s = parseHexSize(start.value);
      if (s === null) return fail(`Start "${start.value}" is not a hex address`);
      const isFile = k === "file";
      const z = size.value.trim() ? parseHexSize(size.value) : isFile ? 0n : null;
      if (z === null) return fail(size.value.trim() ? `Size "${size.value}" is not a hex number` : "A region needs a size");
      if (!isFile && z === 0n) return fail("A region can't be empty");
      if (isFile && mode === "add" && !file) return fail("Choose a file: upload one" + (o.browseHost ? " or pick one on the daemon's host" : ""));
      const off = offset.value.trim() ? parseHexSize(offset.value) : 0n;
      const len = length.value.trim() ? parseHexSize(length.value) : 0n;
      if (off === null || len === null) return fail("Offset and length are hex numbers");
      const draft: RegionDraft = {
        kind: k,
        name: name.value.trim(),
        start: s,
        size: z,
        read: r.box.checked,
        write: w.box.checked,
        execute: x.box.checked,
        isVolatile: vol.box.checked,
        initialized: isFile || zero.box.checked || (mode === "image" && (init.initialized ?? true)) || (mode === "edit" && !!file && (init.initialized ?? true)),
        file,
        fileOffset: off,
        length: len,
      };
      busy = true;
      box.classList.add("busy");
      submit.disabled = true;
      let problem: string | null;
      try {
        problem = await o.submit(draft);
      } catch (e) {
        problem = e instanceof Error ? e.message : String(e);
      }
      busy = false;
      box.classList.remove("busy");
      submit.disabled = false;
      if (problem) fail(problem);
      else done(true);
    };
    submit.addEventListener("click", () => void go());
    cancel.addEventListener("click", () => done(false));
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") done(false);
      else if (e.key === "Enter" && (e.target as HTMLElement).tagName !== "BUTTON") {
        e.preventDefault();
        void go();
      }
    });
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done(false);
    });
    overlayRoot().append(backdrop);
    (mode === "add" ? kind : name).focus();
  });
}

function describeFile(f: RegionFile): string {
  return f.source === "upload" ? `${f.name} (${formatSize(BigInt(f.bytes.length))}, uploaded)` : f.path;
}
