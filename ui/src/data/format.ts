// Small formatting helpers shared by the views.

import { ProvenanceKind, type FactOrigin, type Provenance } from "@revkit/api";

export function hex(a: bigint, width = 0): string {
  return a.toString(16).padStart(width, "0");
}

// ---- Address spaces (api_minor 26, feature "address-spaces") ----------------
//
// A program whose language has several memory spaces (AVR's code and mem,
// the 8051's CODE, INTMEM, EXTMEM and SFR) or word-addressed code folds every
// address into one 64-bit offset: a space's addresses sit at its key base,
// in bytes. The views show them as Ghidra does, space:offset with the offset
// in the space's addressable units: AVR's code:003a is byte 0x74.

export interface SpaceView {
  name: string;
  keyBase: bigint;
  wordSize: number;
  digits: number; // hex digits an offset is padded to (the space's size)
  isDefault: boolean;
}

let spaceViews: SpaceView[] = [];
let showSpaces = false;

/** Sets the open program's spaces (ProgramSummary.spaces). */
export function setAddressSpaces(list: { name: string; keyBase: bigint; wordSize: number; size: number; isDefault: boolean; alias: boolean; kind: number }[] | undefined): void {
  const RAM = 2; // AddressSpaceKind.RAM
  spaceViews = (list ?? [])
    .filter((s) => s.kind === RAM && !s.alias && (s.isDefault || s.keyBase !== 0n))
    .map((s) => ({ name: s.name, keyBase: s.keyBase, wordSize: Math.max(1, s.wordSize), digits: Math.min(8, Math.max(2, 2 * s.size)), isDefault: s.isDefault }))
    .sort((a, b) => (a.keyBase < b.keyBase ? -1 : a.keyBase > b.keyBase ? 1 : 0));
  showSpaces = spaceViews.length > 1 || spaceViews.some((s) => s.wordSize > 1);
}

/** The spaces addresses can name, the default first; empty for a single byte-addressed space. */
export function addressSpaces(): readonly SpaceView[] {
  return showSpaces ? spaceViews : [];
}

/** The space a folded address is in (null: no spaces shown). */
export function spaceOf(a: bigint): SpaceView | null {
  if (!showSpaces) return null;
  let found: SpaceView | null = null;
  for (const s of spaceViews) if (a >= s.keyBase) found = s;
  return found;
}

/** An address as the views show it: "401000", or "code:003a" / "mem:0100" in a program with spaces. */
export function fmtAddr(a: bigint, width = 0): string {
  const s = spaceOf(a);
  if (!s) return hex(a, width);
  const units = (a - s.keyBase) / BigInt(s.wordSize);
  return `${s.name}:${hex(units, s.digits)}`;
}

/** A note on how a space counts, for tooltips: "code counts 2-byte words". */
export function spaceUnitNote(a: bigint): string {
  const s = spaceOf(a);
  if (!s) return "";
  return s.wordSize > 1 ? `${s.name} counts ${s.wordSize}-byte words (byte offset 0x${hex(a - s.keyBase)})` : `${s.name} counts bytes`;
}

/**
 * Parses "401000", "0x401000", "h'401000'"-free hex; in a program with
 * spaces also "space:offset" (the offset in the space's units, "mem:0x100")
 * and bare offsets in the default space's units. null if not an address.
 */
export function parseAddress(s: string): bigint | null {
  let t = s.trim();
  let space: SpaceView | undefined;
  const colon = t.indexOf(":");
  if (colon > 0) {
    const name = t.slice(0, colon).toLowerCase();
    space = spaceViews.find((v) => v.name.toLowerCase() === name);
    if (!space) return null;
    t = t.slice(colon + 1);
  } else if (showSpaces) {
    space = spaceViews.find((v) => v.isDefault);
  }
  t = t.replace(/^0x/i, "").replace(/h$/i, "");
  if (!/^[0-9a-f]{1,16}$/i.test(t)) return null;
  const v = BigInt("0x" + t);
  return space ? space.keyBase + v * BigInt(space.wordSize) : v;
}

const KIND_TEXT: Record<number, string> = {
  [ProvenanceKind.USER]: "user",
  [ProvenanceKind.IMPORT]: "import",
  [ProvenanceKind.AGENT]: "agent",
  [ProvenanceKind.ANALYSIS]: "analysis",
  [ProvenanceKind.MIGRATION]: "migration",
  [ProvenanceKind.PLUGIN]: "plugin",
  [ProvenanceKind.SCRIPT]: "script",
};

export function provKind(k: ProvenanceKind): string {
  return KIND_TEXT[k] ?? "unknown";
}

/** Canonical "kind:id[@version]". */
export function provText(p: Provenance | undefined): string {
  if (!p) return "unknown";
  return `${provKind(p.kind)}:${p.id || "?"}${p.version ? "@" + p.version : ""}`;
}

/** Who said it, for a badge: the canonical form, or for a script someone
 * ran (Provenance.onBehalfOf, api_minor 29) "alice via script:fix-names". */
export function provBadge(p: Provenance | undefined): string {
  if (!p) return "unknown";
  if (!p.onBehalfOf) return provText(p);
  const who = p.onBehalfOf.startsWith("user:") ? p.onBehalfOf.slice("user:".length) : p.onBehalfOf;
  return `${who} via ${provKind(p.kind)}:${p.id || "?"}`;
}

/** A short class name for coloring by who said it. */
export function originClass(o: FactOrigin | undefined): "user" | "agent" | "import" | "derived" | "none" {
  if (!o || o.source.case === undefined) return "none";
  if (o.source.case === "derived") return "derived";
  const k = o.source.value.provenance?.kind;
  if (k === ProvenanceKind.USER) return "user";
  // Plugins and scripts rank with agents, and are colored as they are.
  if (k === ProvenanceKind.AGENT || k === ProvenanceKind.PLUGIN || k === ProvenanceKind.SCRIPT) return "agent";
  return "import";
}

export function originText(o: FactOrigin | undefined): string {
  if (!o || o.source.case === undefined) return "no value";
  if (o.source.case === "derived") return `derived · ${o.source.value.rule}`;
  return provBadge(o.source.value.provenance);
}

export function ago(ms: number): string {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return new Date(ms).toLocaleDateString();
}

export function errText(e: unknown): string {
  if (e && typeof e === "object" && "rawMessage" in e) return String((e as { rawMessage: string }).rawMessage);
  return e instanceof Error ? e.message : String(e);
}
