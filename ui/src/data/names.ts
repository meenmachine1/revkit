// How demangled names show (docs/demangle.md, api_minor 40, feature
// "demangle"): the daemon names a mangled symbol by Ghidra's short form
// ("geo::Circle::scale") and sends its other spellings (DemangledName:
// the mangled symbol, the demangler's whole output) wherever it shows one.
// The setting picks the spelling every view shows: the short form (the
// default, also the decompiler's), the full signature, or the mangled
// name. A rename shows as itself: the daemon sends no other spellings then.

import { showName as sdkShowName, showNameIn as sdkShowNameIn, type DemangledName, type NameForm } from "@revkit/api";
import { prefs } from "../ui/dom";

export type { NameForm };

const KEY = "rk.names";
let form: NameForm = ((): NameForm => {
  const v = prefs.get(KEY);
  return v === "full" || v === "mangled" ? v : "short";
})();
const listeners = new Set<() => void>();

export function nameForm(): NameForm {
  return form;
}

export function setNameForm(f: NameForm) {
  if (f === form) return;
  form = f;
  prefs.set(KEY, f);
  for (const l of listeners) l();
}

/** Called after the setting changes (views re-render their names). */
export function onNameForm(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export const NAME_FORMS: { form: NameForm; label: string }[] = [
  { form: "short", label: "demangled, short (Ghidra's short names, no parameters)" },
  { form: "full", label: "demangled, full signatures" },
  { form: "mangled", label: "mangled (as the file spells them)" },
];

/** The spelling of `name` to show, given its other spellings (if any). */
export function showName(name: string, demangled: DemangledName | undefined, f: NameForm = form): string {
  return sdkShowName(name, demangled, f);
}

/**
 * `text` with `name` in it shown as the setting says: the signature line of
 * a function ("undefined geo::Circle::scale(geo::Circle *this)").
 */
export function showNameIn(text: string, name: string, demangled: DemangledName | undefined, f: NameForm = form): string {
  return sdkShowNameIn(text, name, demangled, f);
}

/** A tooltip line with the other spellings ("" when there are none). */
export function otherSpellings(name: string, demangled: DemangledName | undefined): string {
  if (!demangled) return "";
  const lines: string[] = [];
  if (demangled.full && demangled.full !== name) lines.push(`demangled: ${demangled.full}`);
  if (demangled.mangled) lines.push(`mangled: ${demangled.mangled}`);
  return lines.join("\n");
}

/**
 * For a search result: the spelling the query matched when it isn't the
 * shown one ("mangled _ZN3geo… · "), so a hit on the mangled name says why.
 */
export function matchedSpelling(name: string, demangled: DemangledName | undefined, query: string, f: NameForm = form): string {
  if (!demangled || !query) return "";
  const shown = showName(name, demangled, f).toLowerCase();
  if (shown.includes(query)) return "";
  if (demangled.mangled.toLowerCase().includes(query)) return `mangled ${demangled.mangled} · `;
  if (name.toLowerCase().includes(query)) return `${name} · `;
  return "";
}
