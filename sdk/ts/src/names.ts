// Demangled names (api_minor 40, feature "demangle"; docs/demangle.md): the
// daemon names a mangled symbol by Ghidra's short form, the qualified name
// without parameters ("geo::Shape::scale"), and sends its other spellings
// (DemangledName: the mangled symbol, the demangler's whole output) wherever
// it shows one: Function, Symbol, Label, ListingToken, ListingHeader and
// CodeToken `.demangled`. A rename shows as itself: no other spellings then.
//
//   showName(f.name, f.demangled, "mangled")   // "_ZN3geo5Shape5scaleEd"
//   showName(f.name, f.demangled, "full")      // "geo::Shape::scale(double)"
import type { DemangledName } from "./gen/revkit/v1/common_pb";

export const DEMANGLE_FEATURE = "demangle";

/** short: the daemon's name (the default); full: with parameters; mangled: as the file spells it. */
export type NameForm = "short" | "full" | "mangled";

/** The spelling of `name` to show, given its other spellings (if any). */
export function showName(name: string, demangled: DemangledName | undefined, form: NameForm): string {
  if (!demangled || form === "short") return name;
  if (form === "mangled") return demangled.mangled || name;
  return demangled.full || name;
}

/**
 * `text` with `name` in it (where a parameter list follows it, as in a
 * prototype) spelled as `form` says.
 */
export function showNameIn(text: string, name: string, demangled: DemangledName | undefined, form: NameForm): string {
  const shown = showName(name, demangled, form);
  if (shown === name || !name) return text;
  const at = text.indexOf(name + "(");
  return at < 0 ? text : text.slice(0, at) + shown + text.slice(at + name.length);
}
