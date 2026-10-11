// Raw layout detection in the Open dialog (feature "raw-detect", api_minor
// 23): what the daemon suggests for a file that isn't ELF or PE, shown on the
// raw binary fields it is for.
//
// A suggested field keeps its input editable and adds a row under it: a
// confidence chip per answer (high, medium, low), a "why" expander with the
// daemon's evidence sentences, and for the language an alternatives menu.
// The value goes into the input only while the user hasn't put one of their
// own there; a field the user edited says so and offers the suggestion
// back. A refusal is a box with its reason and the closest guesses, none of
// them applied. Nothing here imports: the dialog's Import as raw does, when
// the user presses it.

import {
  DetectConfidence, RawDetectPhase, RawRegionKind, RawSegmentKind, confidenceName, type DetectRawLayoutResponse,
  type GetRawDetectProgressResponse, type MemoryRegion, type RawLayoutSuggestion, type RawRegionSuggestion,
} from "@revkit/api";
import { h } from "./dom";
import type { ProgressShown } from "./importprogress";

export type Level = "high" | "medium" | "low" | "none";

export interface Chip {
  text: string;
  level: Level;
  title: string;
}

/** What detection says of one field. */
export interface FieldSuggestion {
  /** As the field spells it; "" when there is nothing to put there. */
  value: string;
  chips: Chip[];
  /** The evidence, a sentence each. */
  why: string[];
}

const LEVEL_TEXT: Record<Level, string> = {
  high: "high confidence: meant to be relied on",
  medium: "medium confidence: check it",
  low: "low confidence: a guess to check",
  none: "",
};

function chip(c: Chip): HTMLElement {
  return h("span", { class: `badge conf conf-${c.level}`, "data-testid": "raw-chip", "data-level": c.level, title: c.title }, c.text);
}

function whyBox(sentences: string[], what: string): HTMLElement {
  return h(
    "details",
    { class: "raw-why", "data-testid": "raw-why" },
    h("summary", { "aria-label": `Why: the evidence for ${what}` }, "why"),
    h("ul", {}, ...sentences.map((t) => h("li", {}, t))),
  );
}

/** An input of the raw options with detection's suggestion under it. */
export class SuggestedField {
  readonly el: HTMLElement;
  /** Opens the alternatives menu at the button; unset: no button. */
  onAlternatives?: (anchor: HTMLElement) => void;
  private row: HTMLElement;
  private suggestion: FieldSuggestion | null = null;
  /** The value detection last put in the input (null: none). */
  private applied: string | null = null;

  /** `key` names it in test ids; `name` in what people read. */
  constructor(
    readonly input: HTMLInputElement | HTMLTextAreaElement,
    key: string,
    private name: string,
    private same: (a: string, b: string) => boolean = (a, b) => a.trim() === b.trim(),
    wide = false,
  ) {
    this.row = h("div", { class: "raw-suggest", hidden: true, "data-testid": `raw-suggest-${key}` });
    this.el = h("div", { class: "raw-field" + (wide ? " wide" : ""), "data-testid": `raw-field-${key}`, "data-state": "none" }, input, this.row);
    input.addEventListener("input", () => this.render());
  }

  /** The input holds a value the user put there (not empty, not detection's). */
  get own(): boolean {
    const v = this.input.value;
    return v.trim() !== "" && !(this.applied !== null && this.same(v, this.applied));
  }

  get state(): "none" | "suggested" | "edited" {
    if (!this.suggestion) return "none";
    return this.same(this.input.value, this.suggestion.value) ? "suggested" : "edited";
  }

  /** Shows `s` and, unless the user's own value is there (or `force`: the user chose it), puts its value in the input. */
  suggest(s: FieldSuggestion | null, force = false) {
    if (!s) return this.clear();
    if (force || !this.own) this.write(s.value);
    this.suggestion = s;
    this.render();
  }

  /** Forgets the suggestion; what detection wrote goes with it, what the user wrote stays. */
  clear() {
    if (this.applied !== null && !this.own) this.write("");
    this.suggestion = null;
    this.applied = null;
    this.render();
  }

  private write(value: string) {
    this.input.value = value;
    this.applied = value;
    this.input.dispatchEvent(new Event("input"));
  }

  private render() {
    const s = this.suggestion;
    const state = this.state;
    this.el.dataset.state = state;
    this.row.hidden = !s;
    if (!s) return this.row.replaceChildren();
    const parts: HTMLElement[] = [];
    if (state === "suggested") {
      parts.push(...s.chips.map(chip));
    } else {
      parts.push(chip({ text: "edited", level: "none", title: `Your value. Detection suggested ${s.value || "nothing"} for the ${this.name}.` }));
      if (s.value)
        parts.push(h("button", {
          class: "btn small raw-use",
          type: "button",
          "data-testid": "raw-use",
          title: `Replace your value with the suggestion (${s.chips.map((c) => c.text).join(", ")})`,
          onclick: () => this.suggest(s, true),
          text: `Use ${s.value.length > 28 ? s.value.slice(0, 27) + "…" : s.value}`,
        }));
    }
    if (this.onAlternatives) {
      const alt = h("button", { class: "btn small raw-alt", type: "button", "aria-haspopup": "menu", "data-testid": "raw-alternatives", text: "Alternatives ▾" });
      alt.addEventListener("click", () => this.onAlternatives?.(alt));
      parts.push(alt);
    }
    if (s.why.length) parts.push(whyBox(s.why, `the ${this.name}`));
    // Keep an open "why" open across a repaint (each keystroke repaints).
    const open = this.row.querySelector("details")?.open;
    this.row.replaceChildren(...parts);
    if (open) this.row.querySelector("details")?.setAttribute("open", "");
  }
}

const hex = (v: bigint) => "0x" + v.toString(16);

/** "ARM:LE:32:v8", with the compiler only when it isn't the default. */
export function shortLanguage(language: string, compiler = ""): string {
  const parts = language.split(":");
  const id = parts.slice(0, 4).join(":");
  const c = compiler || parts[4] || "";
  return c && c !== "default" ? `${id}:${c}` : id;
}

/** A suggestion's language as the raw field spells it. */
export function languageOf(s: RawLayoutSuggestion): string {
  return shortLanguage(s.options?.languageId ?? "", s.options?.compilerSpecId ?? "");
}

/** "name:start:size:perms[:init][:volatile]", as the regions field reads it. */
export function formatRegion(r: MemoryRegion): string {
  const perms = (r.read ? "r" : "-") + (r.write ? "w" : "-") + (r.execute ? "x" : "-");
  return `${r.name}:${r.start.toString(16)}:${r.size.toString(16)}:${perms}${r.initialized ? ":init" : ""}${r.isVolatile ? ":volatile" : ""}`;
}

function level(c: DetectConfidence): Level {
  return confidenceName(c) || "low";
}

/** The suggestion, field by field. `language` replaces its language by one of its tie group. */
export function fieldSuggestions(s: RawLayoutSuggestion, language = languageOf(s)): Record<"language" | "base" | "offset" | "regions", FieldSuggestion | null> {
  const o = s.options;
  const about = (...what: string[]) => s.evidence.filter((e) => what.includes(e.about)).map((e) => e.text);
  const known = ["base", "offset", "regions"];
  const languageWhy = s.evidence.filter((e) => !known.includes(e.about)).map((e) => e.text);
  if (s.tieGroup.length)
    languageWhy.push(`The same evidence fits ${s.tieGroup.length} other language${s.tieGroup.length === 1 ? "" : "s"} of this processor (Alternatives lists them): the variant is the one to check.`);
  if (s.languagePinned) languageWhy.push("The language you chose is among those the evidence fits.");
  const p = level(s.processorConfidence), v = level(s.variantConfidence), b = level(s.baseConfidence), off = level(s.offsetConfidence);
  const hasBase = !!o?.hasImageBase;
  const baseWhy = about("base");
  if (!hasBase && !baseWhy.length) baseWhy.push("Detection worked out the load address for its best suggestion only.");
  const offsetWhy = about("offset");
  if (!offsetWhy.length) offsetWhy.push(hasBase ? "Nothing says the image starts anywhere but at the start of the file." : "Without a load address nothing says where the image starts: the start of the file is assumed.");
  const regions = (o?.regions ?? []).map(formatRegion);
  return {
    language: {
      value: language,
      chips: [
        { text: `processor ${p}`, level: p, title: `The processor family, byte order and address size: ${LEVEL_TEXT[p]}` },
        { text: `variant ${v}`, level: v, title: `The variant within the family: ${LEVEL_TEXT[v]}` },
      ],
      why: languageWhy,
    },
    base: {
      value: hasBase ? hex(o!.imageBase) : "",
      chips: [hasBase
        ? { text: b, level: b, title: `The load address: ${LEVEL_TEXT[b]}` }
        : { text: "undetermined", level: "low", title: "No load address could be worked out: the image loads at 0 unless you set one" }],
      why: baseWhy,
    },
    offset: {
      value: hasBase || (o?.rawOffset ?? 0n) !== 0n ? hex(o?.rawOffset ?? 0n) : "",
      chips: [{ text: off, level: off, title: `The image's offset in the file: ${LEVEL_TEXT[off]}` }],
      why: offsetWhy,
    },
    regions: regions.length
      ? { value: regions.join("\n"), chips: [{ text: "suggested", level: "none", title: "Memory the code uses beside the image: each region's confidence and evidence are below" }], why: about("regions") }
      : null,
  };
}

const REGION_KINDS: Record<number, [string, string]> = {
  [RawRegionKind.RAM]: ["RAM", "read and written memory"],
  [RawRegionKind.MMIO]: ["MMIO", "devices' registers (volatile)"],
  [RawRegionKind.UNKNOWN]: ["memory", "memory the code accesses; nothing says whether it is RAM or devices' registers"],
};

/** A ticked region the loader would refuse: what it overlaps, and the line(s) it clips to (none: it is all inside). */
export interface Overlap {
  /** "overlaps the image (0x0–0x1a49)". */
  message: string;
  clipped: string[];
}

/** The ticked lines that overlap the image or another region, by line. */
export type OverlapCheck = (lines: string[]) => Map<string, Overlap>;

type Row = { row: HTMLElement; box: HTMLInputElement; input: HTMLInputElement; err: HTMLElement; level: Level; current: string; shown: string };

/**
 * Detection's regions, a row each under the regions box: whether it is in
 * the box (a checkbox), the region as an editable line, a chip with its
 * kind and confidence, and its evidence. The box stays what is imported:
 * a row's edits and its checkbox change its line there, and what the user
 * types in the box is never overwritten (a row whose line isn't there is
 * shown unticked). Regions of unknown kind start unticked. Buttons above
 * the rows tick the high-confidence ones only, all or none.
 *
 * With a `checker`, a ticked line the loader would refuse (it overlaps the
 * image or another region) gets an inline error with Clip (to what lies
 * outside) and Untick; one typed in the box without a row is listed in
 * `problems`, with Clip and Remove.
 */
export class RegionRows {
  readonly el: HTMLElement;
  /** The box's own lines that overlap, under the rows. */
  readonly problems: HTMLElement;
  checker?: OverlapCheck;
  private rows: Row[] = [];
  private head: HTMLElement;
  private tools: HTMLElement;
  private problemsKey = "";
  private found = new Map<string, Overlap>();

  constructor(private area: HTMLTextAreaElement) {
    this.el = h("div", { class: "raw-region-rows", hidden: true, role: "group", "aria-label": "Memory regions detection suggests", "data-testid": "raw-region-rows" });
    this.problems = h("div", { class: "raw-region-problems", hidden: true, "data-testid": "raw-region-problems" });
    this.head = h("div", { class: "dim", "data-testid": "raw-region-count" });
    const tool = (text: string, testid: string, title: string, tick: (r: Row) => boolean) =>
      h("button", { class: "btn small", type: "button", "data-testid": testid, title, text, onclick: () => this.tickWhere(tick) });
    this.tools = h(
      "div",
      { class: "raw-region-tools" },
      tool("High confidence only", "raw-regions-high", "Tick the regions detection is highly confident of and untick the rest", (r) => r.level === "high"),
      tool("Select all", "raw-regions-all", "Tick every suggested region", () => true),
      tool("Select none", "raw-regions-none", "Untick every suggested region", () => false),
    );
    area.addEventListener("input", () => this.sync());
  }

  private lines(): string[] {
    return this.area.value.split("\n").map((l) => l.trim()).filter(Boolean);
  }

  private setLines(lines: string[]) {
    this.area.value = lines.join("\n");
    this.area.dispatchEvent(new Event("input"));
  }

  /** Ticks the rows `tick` says, unticks the rest; the box's other lines stay. */
  private tickWhere(tick: (r: Row) => boolean) {
    const mine = new Set(this.rows.map((r) => r.current));
    const lines = this.lines().filter((l) => !mine.has(l));
    for (const r of this.rows) if (tick(r) && r.current) lines.push(r.current);
    this.setLines(lines);
  }

  show(details: RawRegionSuggestion[]) {
    this.rows = [];
    const rows = details.filter((d) => d.region).map((d, i) => {
      const spec = formatRegion(d.region!);
      const [kind, kindText] = REGION_KINDS[d.kind] ?? ["memory", "memory"];
      const lv = level(d.confidence);
      const box = h("input", { type: "checkbox", "data-testid": "raw-region-include", "aria-label": `Import ${spec}` }) as HTMLInputElement;
      const input = h("input", { class: "path-input raw-region-spec", spellcheck: "false", value: spec, "aria-label": `Region (${kind}): name:start:size[:perms][:init|uninit|volatile]`, "data-testid": "raw-region-spec" }) as HTMLInputElement;
      const err = h("div", { class: "raw-region-error", hidden: true, id: `raw-region-error-${i}`, "data-testid": "raw-region-error" });
      const entry: Row = { row: h("div"), box, input, err, level: lv, current: spec, shown: "" };
      entry.row = h(
        "div",
        { class: "raw-region-row", "data-testid": "raw-region-row", "data-kind": kind.toLowerCase(), "data-level": lv },
        box,
        input,
        chip({ text: `${kind} ${lv}`, level: lv, title: `${kindText}: ${LEVEL_TEXT[lv]}` }),
        d.evidence.length ? whyBox(d.evidence, `the region ${spec}`) : null,
        err,
      );
      input.addEventListener("keydown", (e) => e.stopPropagation());
      input.addEventListener("input", () => {
        const next = input.value.trim();
        const lines = this.lines();
        const at = lines.indexOf(entry.current);
        entry.current = next;
        if (at < 0) return this.sync();
        if (next) lines[at] = next;
        else lines.splice(at, 1);
        this.setLines(lines);
      });
      box.addEventListener("change", () => {
        const lines = this.lines().filter((l) => l !== entry.current);
        if (box.checked && entry.current) lines.push(entry.current);
        this.setLines(lines);
      });
      this.rows.push(entry);
      return entry.row;
    });
    this.el.replaceChildren(...(rows.length ? [this.tools, this.head, ...rows] : []));
    this.el.hidden = !rows.length;
    this.sync();
  }

  clear() {
    this.rows = [];
    this.el.replaceChildren();
    this.el.hidden = true;
    this.sync();
  }

  /** Checks again (the image's range changed); the number of lines that overlap. */
  refresh(): number {
    this.sync();
    return this.found.size;
  }

  /** Focuses the first overlap's first button. */
  focusProblem() {
    const at = [...this.rows.map((r) => r.err), this.problems].find((e) => !e.hidden);
    (at?.querySelector("button") as HTMLElement | null)?.focus();
  }

  /** Replaces `line` in the box by `by` (empty: removes it); a row showing it follows the first. */
  private replace(line: string, by: string[]) {
    const lines = this.lines();
    const at = lines.indexOf(line);
    if (at < 0) return;
    lines.splice(at, 1, ...by);
    const row = this.rows.find((r) => r.current === line);
    if (row && by.length) {
      row.current = by[0];
      row.input.value = by[0];
    }
    this.setLines(lines);
    (row?.input ?? this.area).focus();
  }

  private fix(o: Overlap, line: string, name: string, untick: () => void, untickText: string, testid: string): HTMLElement[] {
    return [
      h("span", { class: "error", "data-testid": `${testid}-text` }, o.message),
      o.clipped.length
        ? h("button", {
            class: "btn small",
            type: "button",
            "data-testid": "raw-region-clip",
            "aria-label": `Clip region ${name} to ${o.clipped.join(" and ")}`,
            title: `Keep what lies outside: ${o.clipped.join(", ")}`,
            text: "Clip",
            onclick: () => this.replace(line, o.clipped),
          })
        : null,
      h("button", { class: "btn small", type: "button", "data-testid": `raw-region-${untickText.toLowerCase()}`, "aria-label": `${untickText} region ${name}`, text: untickText, onclick: untick }),
    ].filter((x): x is HTMLElement => !!x);
  }

  /** Ticks the rows whose line is in the box, and marks the lines that overlap. */
  private sync() {
    const lines = this.lines();
    const inBox = new Set(lines);
    this.found = this.checker?.(lines) ?? new Map();
    const shownByRow = new Set<string>();
    for (const r of this.rows) {
      r.box.checked = inBox.has(r.current);
      r.row.dataset.included = String(r.box.checked);
      const o = r.box.checked ? this.found.get(r.current) : undefined;
      if (o) shownByRow.add(r.current);
      const key = o ? `${r.current}|${o.message}|${o.clipped.join(",")}` : "";
      if (key === r.shown) continue;
      r.shown = key;
      r.err.hidden = !o;
      r.row.dataset.overlaps = String(!!o);
      if (o) {
        r.input.setAttribute("aria-invalid", "true");
        r.input.setAttribute("aria-describedby", r.err.id);
        const name = r.current.split(":")[0];
        r.err.replaceChildren(...this.fix(o, r.current, name, () => {
          r.box.checked = false;
          r.box.dispatchEvent(new Event("change"));
          r.box.focus();
        }, "Untick", "raw-region-error"));
      } else {
        r.input.removeAttribute("aria-invalid");
        r.input.removeAttribute("aria-describedby");
        r.err.replaceChildren();
      }
    }
    const typed = [...this.found].filter(([l]) => !shownByRow.has(l));
    const key = typed.map(([l, o]) => `${l}|${o.message}|${o.clipped.join(",")}`).join("\n");
    if (key !== this.problemsKey) {
      this.problemsKey = key;
      this.problems.hidden = !typed.length;
      this.problems.replaceChildren(...typed.map(([l, o]) =>
        h("div", { class: "raw-region-problem", "data-testid": "raw-region-problem" },
          h("span", { class: "mono" }, l),
          ...this.fix(o, l, l.split(":")[0], () => this.replace(l, []), "Remove", "raw-region-problem"))));
    }
    const ticked = this.rows.filter((r) => r.box.checked).length;
    this.head.textContent = `Regions detection suggests: ${ticked} of ${this.rows.length} ticked (ticked ones are in the box above).`;
  }
}

const REFUSALS: Record<string, string> = {
  "high-entropy": "The file looks compressed or encrypted",
  "not-code": "The file is text or fill, not code",
  "unknown-processor": "No known processor's code was recognised",
  "too-small": "The file is too small to tell",
};

/** A refusal's reason, for people. An unknown reason is shown as it is. */
export function refusalTitle(reason: string): string {
  return REFUSALS[reason] ?? `Not detected (${reason})`;
}

/** The refusal of `file` with its closest guesses; `use(i)` applies suggestion `i` when the user asks. */
export function refusalBox(r: DetectRawLayoutResponse, file: string, use: (index: number) => void): HTMLElement {
  const guesses = r.suggestions.map((s, i) => {
    const p = level(s.processorConfidence);
    const lang = languageOf(s);
    return h(
      "div",
      { class: "raw-guess", "data-testid": "raw-guess" },
      h("button", { class: "btn small", type: "button", "data-testid": "raw-guess-use", title: `Fill the raw binary fields with this guess`, onclick: () => use(i), text: `Use ${lang}` }),
      chip({ text: `processor ${p}`, level: p, title: `A guess, not an answer: ${LEVEL_TEXT[p]}` }),
      s.evidence.length ? whyBox(s.evidence.map((e) => e.text), lang) : null,
    );
  });
  return h(
    "div",
    { class: "raw-refusal", role: "group", "aria-label": "Detection refused", "data-testid": "raw-refusal", "data-reason": r.refusal?.reason ?? "" },
    h("div", { class: "raw-refusal-title" }, `${file}: not detected. ${refusalTitle(r.refusal?.reason ?? "")}`, h("span", { class: "dim mono" }, ` (${r.refusal?.reason ?? ""})`)),
    h("div", { class: "raw-refusal-detail" }, r.refusal?.detail ?? ""),
    guesses.length
      ? h("div", { class: "raw-guesses" }, h("div", { class: "dim" }, "Closest guesses, none applied:"), ...guesses)
      : h("div", { class: "dim" }, "Set the raw binary options by hand."),
  );
}

const SEGMENTS: Record<number, [string, string]> = {
  [RawSegmentKind.CODE]: ["code", "code-like"],
  [RawSegmentKind.TEXT]: ["text", "text"],
  [RawSegmentKind.PADDING]: ["padding", "padding"],
  [RawSegmentKind.HIGH_ENTROPY]: ["dense", "compressed or encrypted"],
};

/** The file as a strip of what each stretch looks like, with a legend. */
export function segmentStrip(r: DetectRawLayoutResponse): HTMLElement | null {
  const total = Number(r.fileSize);
  if (!total || !r.segments.length) return null;
  // At most 200 pieces: a file of many small segments is drawn by what
  // each two-hundredth of it mostly is.
  type Piece = { offset: number; size: number; kind: number };
  let pieces: Piece[] = r.segments.map((s) => ({ offset: Number(s.offset), size: Number(s.size), kind: s.kind }));
  const sums = new Map<number, number>();
  for (const p of pieces) sums.set(p.kind, (sums.get(p.kind) ?? 0) + p.size);
  if (pieces.length > 200) {
    const step = total / 200;
    const buckets: Map<number, number>[] = Array.from({ length: 200 }, () => new Map());
    for (const p of pieces)
      for (let at = p.offset; at < p.offset + p.size; ) {
        const b = Math.min(199, Math.floor(at / step));
        const end = Math.min(p.offset + p.size, Math.max(at + 1, Math.ceil((b + 1) * step)));
        buckets[b].set(p.kind, (buckets[b].get(p.kind) ?? 0) + end - at);
        at = end;
      }
    pieces = buckets.map((m, i) => ({ offset: Math.round(i * step), size: Math.round(step), kind: [...m.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? 0 }));
  }
  const pct = (n: number) => (n / total >= 0.995 ? "100%" : n / total < 0.01 ? "<1%" : `${Math.round((100 * n) / total)}%`);
  const legend = [...sums.entries()].sort((a, b) => b[1] - a[1]).map(([k, n]) => `${SEGMENTS[k]?.[1] ?? "other"} ${pct(n)}`).join(" · ");
  return h(
    "div",
    { class: "raw-segments", "data-testid": "raw-segments" },
    h(
      "div",
      { class: "raw-segments-bar", role: "img", "aria-label": `What the file looks like: ${legend}` },
      ...pieces.map((p) =>
        h("span", { class: `seg seg-${SEGMENTS[p.kind]?.[0] ?? "other"}`, style: `flex-grow:${p.size}`, title: `${SEGMENTS[p.kind]?.[1] ?? "other"}: ${hex(BigInt(p.offset))} to ${hex(BigInt(p.offset + p.size))}` })),
    ),
    h("div", { class: "raw-segments-legend dim" }, `The file: ${legend}`),
  );
}

const PHASE_NAMES: Record<number, string> = {
  [RawDetectPhase.QUEUED]: "Waiting for another detection",
  [RawDetectPhase.READING]: "Reading the file",
  [RawDetectPhase.SEGMENTS]: "Mapping the file",
  [RawDetectPhase.PROCESSOR]: "Trying each processor",
  [RawDetectPhase.LAYOUT]: "Working out the load address and variant",
  [RawDetectPhase.DONE]: "Detection done",
};

/** A progress poll as the dialog's bar shows it (importprogress.ts). */
export function detectProgress(p: GetRawDetectProgressResponse): ProgressShown {
  const name = PHASE_NAMES[p.phase] ?? "Detecting";
  return { text: p.message || name, fraction: p.progress, phase: RawDetectPhase[p.phase] ?? String(p.phase), announce: name, done: p.done, error: !!p.error || p.cancelled };
}

/** One line saying what was detected, for the dialog's status. */
export function summary(s: RawLayoutSuggestion): string {
  const o = s.options;
  const parts = [`${languageOf(s)} (processor ${level(s.processorConfidence)})`];
  parts.push(o?.hasImageBase ? `load address ${hex(o.imageBase)} (${level(s.baseConfidence)})` : "load address undetermined");
  if (o?.rawOffset) parts.push(`a ${hex(o.rawOffset)}-byte header (${level(s.offsetConfidence)})`);
  return parts.join(", ");
}
