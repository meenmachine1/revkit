// Keymap presets (docs/ui.md, "Keymap presets"): revkit's actions bound to
// the keys of Ghidra (the default), IDA Pro or Binary Ninja. The page's key
// handler (app.ts onKey) asks this table which actions a key press means;
// menus, the palette, tooltips and the cheat sheet show the active preset's
// keys from it too. The choice is per viewer (localStorage, rk.keymap).
//
// A chord is written as KeyboardEvent describes it:
//   - a printable key without Ctrl or Alt is the character it types, so
//     Shift is in the character: "n", "N" (Shift+N), ";", ":" (Shift+;),
//     "{" (Shift+[);
//   - anything else is its modifiers (Ctrl, Alt, Shift, in that order) and
//     the key: "Ctrl+Shift+F", "Alt+ArrowLeft", "Ctrl+Enter", "Shift+F3",
//     "Escape", "Tab", "Space". Letters with Ctrl or Alt are upper case
//     and come from KeyboardEvent.code (layout and Alt+letter independent).
//
// Every binding in IDA's and Binary Ninja's columns is one of their
// documented defaults (the sources are in docs/ui.md); Ghidra's are from
// Ghidra 12.1's sources. An action a tool has no documented default for
// keeps revkit's key in that preset, unless the preset gives that key to
// another action.

import { prefs } from "./dom";

export type PresetId = "ghidra" | "ida" | "binja";

export const PRESETS: { id: PresetId; name: string }[] = [
  { id: "ghidra", name: "Ghidra" },
  { id: "ida", name: "IDA Pro" },
  { id: "binja", name: "Binary Ninja" },
];

/** revkit's own keys: what an action keeps when a preset doesn't bind it. */
const BASE: Record<string, string[]> = {
  goto: ["Ctrl+K", "g"],
  back: ["Alt+ArrowLeft"],
  forward: ["Alt+ArrowRight"],
  rename: ["n", "F2"],
  retype: ["y"],
  comment: [";"],
  xrefs: ["x"],
  follow: ["Enter"],
  // F creates a function; at a function's entry it edits it (Ghidra's Edit Function).
  "fn-create": ["f"],
  "fn-remove": ["F"],
  flow: ["o"],
  note: ["N"],
  prov: ["i"],
  bytes: ["B"],
  "eq-set": ["E"],
  "ref-add": ["R"],
  "auto-struct": ["{"],
  "toggle-graph": ["Space"],
  undo: ["Ctrl+Z"],
  redo: ["Ctrl+Shift+Z", "Ctrl+Y"],
  "search-memory": ["s", "Ctrl+Shift+E"],
  "search-text": ["Ctrl+Shift+F"],
  "search-next": ["F3"],
  "search-prev": ["Shift+F3"],
  "copy-special": ["Ctrl+Shift+C"],
  "patch-insn": ["Ctrl+Shift+G"],
  "patch-bytes": ["Ctrl+Shift+H"],
  functions: ["Ctrl+1"],
  "view-listing": ["Ctrl+2"],
  "view-decomp": ["Ctrl+3"],
  "view-graph": ["Ctrl+4"],
  "view-calls": ["Ctrl+5"],
  "view-strings": ["Ctrl+6"],
  "view-types": ["Ctrl+7"],
  "view-emu": ["Ctrl+8"],
  "view-diff": ["Ctrl+9"],
  "view-diffgraph": ["Ctrl+Shift+9"],
  "view-memory": ["Ctrl+Shift+M"],
  "view-scripts": ["Ctrl+Shift+S"],
  // The listing's editing keys (feature listing-edit).
  "le-disasm": ["d"],
  "le-clear": ["c"],
  "le-cycle": ["b"],
  "le-data-char": ["'"],
  "le-data-string": ['"'],
  "le-array": ["["],
  "le-type": ["t"],
  "le-data-pointer": ["p"],
  "le-expand": ["+", "="],
  "le-collapse": ["-"],
  // The decompiler's highlight: next and previous highlighted token
  // (Ghidra's Ctrl+. and Ctrl+,; its slices have no keys).
  "slice-next": ["Ctrl+."],
  "slice-prev": ["Ctrl+,"],
};

/**
 * Each preset's own keys. An action listed here gets exactly these keys (a
 * preset that keeps one of revkit's keys beside the tool's lists it); an
 * action not listed keeps revkit's, minus any key the preset uses.
 */
const PRESET_KEYS: Record<PresetId, Record<string, string[]>> = {
  // Ghidra 12.1 (Ghidra/Features/Base and Decompiler sources): G Go To;
  // L rename (Add/Edit Label, the decompiler's Rename); Ctrl+L Retype;
  // ; Set Comment; Ctrl+Shift+F Find References To; F Create Function
  // (Edit Function at a function's entry);
  // Ctrl+F Search Program Text; S Search Memory;
  // F3/Shift+F3 repeat it; Ctrl+D Add Bookmark; Ctrl+E the decompiler;
  // Alt+←/→; Ctrl+Z, Ctrl+Shift+Z. revkit's N, F2, Y, X stay as well.
  ghidra: {
    rename: ["l", "n", "F2"],
    retype: ["Ctrl+L", "y"],
    xrefs: ["Ctrl+Shift+F", "x"],
    "search-text": ["Ctrl+F"],
    note: ["Ctrl+D", "N"],
    "view-decomp": ["Ctrl+3", "Ctrl+E"],
  },
  // IDA Pro (Hex-Rays' shortcut reference, IDA 9.x): G, Esc back,
  // Ctrl+Enter forward, N rename, Y set type, X xrefs, ; and : comments,
  // P create function, C code, D data, A string, U undefine, Tab and F5
  // the decompiler, Alt+T text search, Ctrl+T next, Alt+B bytes, Alt+I
  // immediate values, Alt+M mark position, Alt+P edit function, F2 breakpoint, Shift+F12
  // strings, Shift+F3 functions, Ctrl+Z, Ctrl+Shift+Z.
  ida: {
    back: ["Escape", "Alt+ArrowLeft"],
    forward: ["Ctrl+Enter", "Alt+ArrowRight"],
    rename: ["n"],
    retype: ["y"],
    comment: [";", ":"],
    xrefs: ["x"],
    "fn-create": ["p"],
    "fn-edit": ["Alt+P"],
    "le-disasm": ["c"],
    "le-cycle": ["d"],
    "le-data-string": ["a"],
    "le-clear": ["u"],
    "toggle-decomp": ["Tab"],
    "view-decomp": ["Ctrl+3", "F5"],
    "search-text": ["Alt+T"],
    "search-next": ["Ctrl+T", "F3"],
    "search-memory": ["Alt+B"],
    "search-scalars": ["Alt+I"],
    note: ["Alt+M"],
    "emu-break": ["F2"],
    "view-strings": ["Ctrl+6", "Shift+F12"],
    functions: ["Ctrl+1", "Shift+F3"],
  },
  // Binary Ninja (docs.binary.ninja, "Default Hotkeys", Windows/Linux): G,
  // Esc and Ctrl+[ back, Ctrl+] forward, N name, Y type, ; comment, X
  // cross references, P create function, U undefine, D cycle data widths,
  // 1/2/4/8 widths, A string, R character, O pointer, E edit instruction,
  // H hex view, T types, Space linear/graph, Tab and F5 Pseudo C.
  binja: {
    back: ["Escape", "Ctrl+[", "Alt+ArrowLeft"],
    forward: ["Ctrl+]", "Alt+ArrowRight"],
    rename: ["n"],
    retype: ["y"],
    comment: [";"],
    xrefs: ["x"],
    "fn-create": ["p"],
    "le-clear": ["u"],
    "le-cycle": ["d"],
    "le-data-byte": ["1"],
    "le-data-word": ["2"],
    "le-data-dword": ["4"],
    "le-data-qword": ["8"],
    "le-data-string": ["a"],
    "le-data-char": ["r"],
    "le-data-pointer": ["o"],
    "patch-insn": ["e", "Ctrl+Shift+G"],
    "view-bytes": ["h"],
    "view-types": ["Ctrl+7", "t"],
    "toggle-decomp": ["Tab", "F5"],
  },
};

const KEY = "rk.keymap";

/** The preset this viewer chose (Ghidra unless they chose another). */
export function storedPreset(): PresetId {
  const v = prefs.get(KEY);
  return PRESETS.some((p) => p.id === v) ? (v as PresetId) : "ghidra";
}

/** The chord a key press is (see the notes at the top). */
export function eventChord(e: KeyboardEvent): string {
  const ctrl = e.ctrlKey || e.metaKey;
  const k = e.key;
  if (k.length === 1 && !ctrl && !e.altKey) return k === " " ? "Space" : k;
  let key = k;
  if (/^Key[A-Z]$/.test(e.code)) key = e.code.slice(3);
  else if (/^Digit\d$/.test(e.code)) key = e.code.slice(5);
  else if (k === " ") key = "Space";
  else if (k.length === 1) key = k.toUpperCase();
  return `${ctrl ? "Ctrl+" : ""}${e.altKey ? "Alt+" : ""}${e.shiftKey && (key.length > 1 || /[A-Z0-9]/.test(key)) ? "Shift+" : ""}${key}`;
}

/** A chord as menus and the cheat sheet show it ("N", "Shift+N", "Esc", "Alt+←"). */
export function chordLabel(c: string): string {
  const shifted: Record<string, string> = { "{": "Shift+[", "}": "Shift+]", ":": "Shift+;", '"': "Shift+'", "<": "Shift+,", ">": "Shift+." };
  if (c.length === 1) {
    if (/[a-z]/.test(c)) return c.toUpperCase();
    if (/[A-Z]/.test(c)) return `Shift+${c}`;
    return shifted[c] ?? c;
  }
  return c.replace("ArrowLeft", "←").replace("ArrowRight", "→").replace("ArrowUp", "↑").replace("ArrowDown", "↓").replace("Escape", "Esc");
}

/** Does a chord work while the focus is in a text field? Only Ctrl or Alt
 * chords other than Enter (a field's own Ctrl+Enter submits it). */
export function chordWhileTyping(c: string): boolean {
  return /^(Ctrl|Alt)\+/.test(c) && !c.endsWith("+Enter");
}

export class Keymap {
  preset: PresetId;
  private byAction = new Map<string, string[]>();
  private byChord = new Map<string, string[]>();
  /** Called after the preset changed (menus and tooltips refresh). */
  onChange: (() => void) | null = null;

  constructor(preset: PresetId = storedPreset()) {
    this.preset = preset;
    this.build();
  }

  get name(): string {
    return PRESETS.find((p) => p.id === this.preset)!.name;
  }

  set(preset: PresetId) {
    if (preset === this.preset) return;
    this.preset = preset;
    prefs.set(KEY, preset);
    this.build();
    this.onChange?.();
  }

  private build() {
    const own = PRESET_KEYS[this.preset];
    const taken = new Set(Object.values(own).flat());
    this.byAction.clear();
    for (const [id, keys] of Object.entries(BASE)) if (!(id in own)) this.byAction.set(id, keys.filter((k) => !taken.has(k)));
    for (const [id, keys] of Object.entries(own)) this.byAction.set(id, [...keys]);
    this.byChord.clear();
    for (const [id, keys] of this.byAction) for (const k of keys) this.byChord.set(k, [...(this.byChord.get(k) ?? []), id]);
  }

  /** The chords bound to an action (none: []). */
  keys(action: string): string[] {
    return this.byAction.get(action) ?? [];
  }

  /** The actions a chord is bound to, in the table's order. */
  actions(chord: string): string[] {
    return this.byChord.get(chord) ?? [];
  }

  /** An action's keys for display ("L / N / F2"), or undefined if it has none. */
  label(action: string, extra?: string): string | undefined {
    const ks = this.keys(action).map(chordLabel);
    if (extra) ks.push(extra);
    return ks.length ? ks.join(" / ") : undefined;
  }

  /** Every bound action and its keys (the cheat sheet). */
  bindings(): [string, string[]][] {
    return [...this.byAction].filter(([, k]) => k.length > 0);
  }
}

/** Each preset's table, for docs and tests: action -> keys. */
export function presetTable(preset: PresetId): Record<string, string[]> {
  return Object.fromEntries(new Keymap(preset).bindings());
}
