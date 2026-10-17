// Data settings (feature data-settings, docs/listing-edit.md#data-settings):
// Ghidra's Data > Settings and Default Settings in one form. How the data
// item at the cursor displays (or, with "Every <type>", the type's default
// settings): an integer's format, signedness, byte order and padding, a
// string's charset and termination, a pointer's kind, mask and shift, and
// the item's mutability. "Default" leaves a setting to the type's
// defaults (the item) or to how the type shows (the type).
//
// Standalone: it knows nothing of the daemon but what its caller passes;
// `submit` resolves to the daemon's error (shown under the fields) or null.

import { create } from "@bufbuild/protobuf";
import {
  DataEndian,
  DataFormat,
  DataPadding,
  DataSettingsSchema,
  DataSignedness,
  Mutability,
  PointerKind,
  StringTermination,
  type DataSettings,
} from "@revkit/api";
import { h, overlayRoot } from "./dom";

/** What a row's value is, for which settings to offer. */
export type DataValueKind = "integer" | "float" | "string" | "pointer" | "aggregate";

export const CHARSETS = ["US-ASCII", "ISO-8859-1", "windows-1252", "UTF-8", "UTF-16", "UTF-16LE", "UTF-16BE", "UTF-32", "UTF-32LE", "UTF-32BE"];

export interface DataSettingsFormOptions {
  /** The item ("dword at 00404010"). */
  what: string;
  /** The type its defaults are kept by (ListingRow.data_settings_type). */
  typeName: string;
  kind: DataValueKind;
  /** The row's own settings and its type's defaults. */
  own?: DataSettings;
  typeDefaults?: DataSettings;
  /** Offer mutability (the item's bytes; not for a type's defaults), and its current one. */
  mutability?: Mutability;
  /** Commits: the daemon's error, or null when it took them. */
  submit: (scope: "item" | "type", settings: DataSettings, mutability: Mutability | null) => Promise<string | null>;
}

type Opt = [string, string];

const FORMAT: Opt[] = [["0", "Default"], [`${DataFormat.HEX}`, "Hex (2ah)"], [`${DataFormat.DECIMAL}`, "Decimal (42)"], [`${DataFormat.OCTAL}`, "Octal (52o)"], [`${DataFormat.BINARY}`, "Binary (101010b)"], [`${DataFormat.CHAR}`, "Char ('*')"]];
const SIGN: Opt[] = [["0", "Default"], [`${DataSignedness.SIGNED}`, "Signed"], [`${DataSignedness.UNSIGNED}`, "Unsigned"]];
const ENDIAN: Opt[] = [["0", "Default (the program's)"], [`${DataEndian.LITTLE}`, "Little endian"], [`${DataEndian.BIG}`, "Big endian"]];
const PADDING: Opt[] = [["0", "Default"], [`${DataPadding.PADDED}`, "Padded (leading zeros)"], [`${DataPadding.UNPADDED}`, "Unpadded"]];
const TERM: Opt[] = [["0", "Default"], [`${StringTermination.NUL}`, "At the first NUL"], [`${StringTermination.ALL}`, "Every character (NULs as \\0)"]];
const POINTER: Opt[] = [["0", "Default (an address)"], [`${PointerKind.ABSOLUTE}`, "Absolute address"], [`${PointerKind.IMAGE_BASE_OFFSET}`, "Image base offset (RVA)"], [`${PointerKind.RELATIVE}`, "Relative to the pointer"]];
const MUTABILITY: Opt[] = [["0", "Unchanged"], [`${Mutability.CONSTANT}`, "Constant (never written)"], [`${Mutability.VOLATILE}`, "Volatile (memory-mapped I/O)"], [`${Mutability.NORMAL}`, "Writable (normal)"], [`${Mutability.DEFAULT}`, "As the memory map says"]];

/** A one-line summary of settings ("decimal, signed"); "" when none is set. */
export function describeSettings(s?: DataSettings): string {
  if (!s) return "";
  const out: string[] = [];
  const name = (opts: Opt[], v: number) => opts.find((o) => o[0] === `${v}`)?.[1].replace(/ \(.*\)$/, "").toLowerCase() ?? "";
  if (s.format) out.push(name(FORMAT, s.format));
  if (s.signedness) out.push(name(SIGN, s.signedness));
  if (s.endian) out.push(name(ENDIAN, s.endian));
  if (s.padding) out.push(name(PADDING, s.padding));
  if (s.charset) out.push(s.charset);
  if (s.termination) out.push(s.termination === StringTermination.ALL ? "every character" : "to the first NUL");
  if (s.pointerKind) out.push(name(POINTER, s.pointerKind));
  if (s.pointerMask !== undefined) out.push(`mask ${s.pointerMask.toString(16)}`);
  if (s.pointerShift !== undefined) out.push(`shift ${s.pointerShift}`);
  return out.join(", ");
}

/** Resolves true when settings were saved, false when cancelled. */
export function dataSettingsForm(o: DataSettingsFormOptions): Promise<boolean> {
  return new Promise((resolve) => {
    const restore = document.activeElement as HTMLElement | null;
    const select = (testid: string, label: string, opts: Opt[]) =>
      h("select", { class: "filter select", "aria-label": label, "data-testid": testid }, ...opts.map(([v, t]) => h("option", { value: v }, t))) as HTMLSelectElement;
    const input = (testid: string, label: string, placeholder: string) =>
      h("input", { class: "ask-input", "aria-label": label, placeholder, spellcheck: "false", autocomplete: "off", "data-testid": testid }) as HTMLInputElement;
    const scope = select("ds-scope", "Apply to", [["item", `This item (${o.what})`], ["type", `Every ${o.typeName} (default settings)`]]);
    const format = select("ds-format", "Format", FORMAT);
    const sign = select("ds-sign", "Signedness", SIGN);
    const endian = select("ds-endian", "Byte order", ENDIAN);
    const padding = select("ds-padding", "Padding", PADDING);
    const charset = select("ds-charset", "Charset", [["", "Default"], ...CHARSETS.map((c): Opt => [c, c])]);
    const term = select("ds-term", "Termination", TERM);
    const pointer = select("ds-pointer", "Pointer", POINTER);
    const mask = input("ds-mask", "Pointer mask (hex)", "all bits");
    const shift = input("ds-shift", "Pointer shift (bits, negative: right)", "0");
    const mut = select("ds-mutability", "Mutability", MUTABILITY);
    const inherited = h("div", { class: "dim ds-inherited", "data-testid": "ds-inherited" });
    const err = h("div", { class: "ask-error", role: "alert", "data-testid": "ds-error" });
    const submit = h("button", { class: "btn primary", type: "button", "data-testid": "ds-submit", text: "Save" });
    const reset = h("button", { class: "btn", type: "button", "data-testid": "ds-reset", text: "All default", title: "Every setting back to Default (removes the settings)" });
    const cancel = h("button", { class: "btn", type: "button", "data-testid": "ds-cancel", text: "Cancel" });
    const row = (label: string, field: HTMLElement) => h("label", { class: "ask-label dim rf-row" }, h("span", { class: "ask-field-name" }, label), field);
    const integer = o.kind === "integer";
    const groups = {
      integer: [row("Format", format), row("Signedness", sign), row("Padding", padding)],
      endian: [row("Byte order", endian)],
      string: [row("Charset", charset), row("Termination", term)],
      pointer: [row("Pointer", pointer), row("Mask", mask), row("Shift", shift)],
    };
    const mutRow = row("Mutability", mut);
    const box = h(
      "div",
      { class: "modal ask region-form data-settings", role: "dialog", "aria-modal": "true", "aria-label": `Data settings: ${o.what}`, tabindex: "-1", "data-testid": "data-settings" },
      h("div", { class: "modal-title" }, `Data settings: ${o.what}`),
      row("Apply to", scope),
      ...(integer ? groups.integer : []),
      ...(o.kind !== "aggregate" ? groups.endian : []),
      ...(o.kind === "string" ? groups.string : []),
      ...(o.kind === "pointer" ? groups.pointer : []),
      o.mutability !== undefined ? mutRow : null,
      inherited,
      err,
      h("div", { class: "rf-actions" }, h("span", { class: "modal-hint" }, "Enter to save · Esc to cancel"), h("span", { class: "spacer" }), reset, cancel, submit),
    );
    const backdrop = h("div", { class: "backdrop top" }, box);

    const load = (s?: DataSettings) => {
      format.value = `${s?.format ?? 0}`;
      sign.value = `${s?.signedness ?? 0}`;
      endian.value = `${s?.endian ?? 0}`;
      padding.value = `${s?.padding ?? 0}`;
      charset.value = s?.charset && CHARSETS.includes(s.charset) ? s.charset : "";
      term.value = `${s?.termination ?? 0}`;
      pointer.value = `${s?.pointerKind ?? 0}`;
      mask.value = s?.pointerMask !== undefined ? s.pointerMask.toString(16) : "";
      shift.value = s?.pointerShift !== undefined ? `${s.pointerShift}` : "";
    };
    const sync = () => {
      const item = scope.value === "item";
      mutRow.hidden = !item;
      load(item ? o.own : o.typeDefaults);
      const d = describeSettings(o.typeDefaults);
      inherited.textContent = item && d ? `Default here: every ${o.typeName}'s settings (${d})` : "";
    };
    scope.addEventListener("change", sync);
    sync();

    const done = (v: boolean) => {
      backdrop.remove();
      restore?.focus({ preventScroll: true });
      resolve(v);
    };
    let busy = false;
    const go = async (clear = false) => {
      if (busy) return;
      const fail = (m: string) => {
        err.textContent = m;
        box.dataset.error = "1";
      };
      if (clear) load(undefined);
      let pointerMask: bigint | undefined;
      let pointerShift: number | undefined;
      if (mask.value.trim()) {
        if (!/^(0x)?[0-9a-f]{1,16}$/i.test(mask.value.trim())) return fail(`Mask "${mask.value}" is not a hex number`);
        pointerMask = BigInt("0x" + mask.value.trim().replace(/^0x/i, ""));
        if (pointerMask === 0n) return fail("A mask of 0 keeps no bit");
      }
      if (shift.value.trim()) {
        const n = Number(shift.value.trim());
        if (!Number.isInteger(n) || n < -63 || n > 63) return fail("Shift is a whole number from -63 to 63");
        pointerShift = n;
      }
      const settings = create(DataSettingsSchema, {
        format: Number(format.value),
        signedness: Number(sign.value),
        endian: Number(endian.value),
        padding: Number(padding.value),
        charset: charset.value,
        termination: Number(term.value),
        pointerKind: Number(pointer.value),
        pointerMask,
        pointerShift,
      });
      const m = scope.value === "item" && o.mutability !== undefined && mut.value !== "0" ? (Number(mut.value) as Mutability) : null;
      busy = true;
      box.classList.add("busy");
      submit.disabled = true;
      let problem: string | null;
      try {
        problem = await o.submit(scope.value as "item" | "type", settings, m);
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
    reset.addEventListener("click", () => void go(true));
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
    (integer ? format : scope).focus();
  });
}
