// Unit tests for the keymap presets (src/ui/keymap.ts; docs/ui.md, "Keymap presets").

import assert from "node:assert/strict";
import { Keymap, PRESETS, chordLabel, chordWhileTyping, eventChord } from "../src/ui/keymap";

const ev = (key: string, code: string, mods: { ctrl?: boolean; alt?: boolean; shift?: boolean; meta?: boolean } = {}) =>
  ({ key, code, ctrlKey: !!mods.ctrl, altKey: !!mods.alt, shiftKey: !!mods.shift, metaKey: !!mods.meta }) as KeyboardEvent;

// Printable keys are their character; Shift is in it.
assert.equal(eventChord(ev("n", "KeyN")), "n");
assert.equal(eventChord(ev("N", "KeyN", { shift: true })), "N");
assert.equal(eventChord(ev(":", "Semicolon", { shift: true })), ":");
assert.equal(eventChord(ev("{", "BracketLeft", { shift: true })), "{");
assert.equal(eventChord(ev(" ", "Space")), "Space");
// Modifier chords: letters and digits from the code, Shift spelled out.
assert.equal(eventChord(ev("F", "KeyF", { ctrl: true, shift: true })), "Ctrl+Shift+F");
assert.equal(eventChord(ev("l", "KeyL", { ctrl: true })), "Ctrl+L");
assert.equal(eventChord(ev("l", "KeyL", { meta: true })), "Ctrl+L");
assert.equal(eventChord(ev("†", "KeyT", { alt: true })), "Alt+T");
assert.equal(eventChord(ev("(", "Digit9", { ctrl: true, shift: true })), "Ctrl+Shift+9");
assert.equal(eventChord(ev("[", "BracketLeft", { ctrl: true })), "Ctrl+[");
assert.equal(eventChord(ev("Enter", "Enter", { ctrl: true })), "Ctrl+Enter");
assert.equal(eventChord(ev("F3", "F3", { shift: true })), "Shift+F3");
assert.equal(eventChord(ev("Escape", "Escape")), "Escape");
assert.equal(eventChord(ev("ArrowLeft", "ArrowLeft", { alt: true })), "Alt+ArrowLeft");

assert.equal(chordLabel("n"), "N");
assert.equal(chordLabel("N"), "Shift+N");
assert.equal(chordLabel("{"), "Shift+[");
assert.equal(chordLabel(":"), "Shift+;");
assert.equal(chordLabel("Alt+ArrowLeft"), "Alt+←");
assert.equal(chordLabel("Escape"), "Esc");
assert.ok(chordWhileTyping("Ctrl+F") && chordWhileTyping("Alt+ArrowLeft"));
assert.ok(!chordWhileTyping("n") && !chordWhileTyping("Ctrl+Enter") && !chordWhileTyping("F3") && !chordWhileTyping("Escape"));

// Each preset binds a key to at most one action.
for (const p of PRESETS) {
  const km = new Keymap(p.id);
  const seen = new Map<string, string>();
  for (const [id, keys] of km.bindings())
    for (const k of keys) {
      assert.ok(!seen.has(k), `${p.id}: ${k} is bound to ${seen.get(k)} and ${id}`);
      seen.set(k, id);
    }
}

// The bindings the presets are for.
const g = new Keymap("ghidra"), ida = new Keymap("ida"), bn = new Keymap("binja");
assert.deepEqual(g.actions("l"), ["rename"]);
assert.deepEqual(g.actions("n"), ["rename"]); // revkit's N stays in the default
assert.deepEqual(g.actions("Ctrl+L"), ["retype"]);
assert.deepEqual(g.actions("Ctrl+Shift+F"), ["xrefs"]);
assert.deepEqual(g.actions("Ctrl+F"), ["search-text"]);
assert.deepEqual(g.actions("Ctrl+E"), ["view-decomp"]);
assert.deepEqual(g.actions("f"), ["fn-create"]);
assert.deepEqual(g.actions("d"), ["le-disasm"]);
assert.deepEqual(g.actions("Tab"), []);
assert.equal(g.label("rename"), "L / N / F2");

assert.deepEqual(ida.actions("l"), []);
assert.deepEqual(ida.actions("n"), ["rename"]);
assert.deepEqual(ida.actions("Escape"), ["back"]);
assert.deepEqual(ida.actions("Ctrl+Enter"), ["forward"]);
assert.deepEqual(ida.actions(":"), ["comment"]);
assert.deepEqual(ida.actions("c"), ["le-disasm"]);
assert.deepEqual(ida.actions("d"), ["le-cycle"]);
assert.deepEqual(ida.actions("a"), ["le-data-string"]);
assert.deepEqual(ida.actions("u"), ["le-clear"]);
assert.deepEqual(ida.actions("p"), ["fn-create"]);
assert.deepEqual(ida.actions("Tab"), ["toggle-decomp"]);
assert.deepEqual(ida.actions("F5"), ["view-decomp"]);
assert.deepEqual(ida.actions("Alt+T"), ["search-text"]);
assert.deepEqual(ida.actions("Ctrl+L"), []);
assert.deepEqual(ida.keys("le-data-pointer"), []); // P creates a function in IDA

assert.deepEqual(bn.actions("Escape"), ["back"]);
assert.deepEqual(bn.actions("Ctrl+["), ["back"]);
assert.deepEqual(bn.actions("Ctrl+]"), ["forward"]);
assert.deepEqual(bn.actions("o"), ["le-data-pointer"]);
assert.deepEqual(bn.keys("flow"), []); // O is BN's pointer
assert.deepEqual(bn.actions("Tab"), ["toggle-decomp"]);
assert.deepEqual(bn.actions("F5"), ["toggle-decomp"]);
assert.deepEqual(bn.actions("4"), ["le-data-dword"]);
console.log("ok   keymap presets");
