// The Open dialog's columns as text (ui/open.ts): a language id as an
// architecture people read, a format's name, a date, the sort and the
// search. Pure, for the unit tests (test/programs.ts).

/** Processor names as they are usually written. */
const PROCESSORS: Record<string, string> = {
  AARCH64: "AArch64",
  RISCV: "RISC-V",
  "x86": "x86",
  ARM: "ARM",
  MIPS: "MIPS",
  PowerPC: "PowerPC",
  sparc: "SPARC",
  SuperH: "SuperH",
  SuperH4: "SuperH-4",
  tricore: "TriCore",
  Xtensa: "Xtensa",
  AVR8: "AVR",
  "68000": "68000",
  "8051": "8051",
  "6502": "6502",
  "Z80": "Z80",
};

/** A variant worth showing: "v4t" as ARM writes it (v4T), "default" not at all. */
function variantText(v: string, processor: string): string {
  if (!v || v === "default" || v.toLowerCase() === processor.toLowerCase()) return "";
  const t = /^v(\d+)t$/i.exec(v);
  if (t) return `v${t[1]}T`;
  return v;
}

/**
 * "ARM:LE:32:v4t" as "ARM · 32-bit · LE (v4T)"; "x86:LE:64:default" as
 * "x86 · 64-bit · LE". Anything not shaped like a language id comes back
 * as it is.
 */
export function archText(languageId: string): string {
  const parts = languageId.split(":");
  if (parts.length < 3 || !/^\d+$/.test(parts[2]) || !/^(LE|BE)$/.test(parts[1])) return languageId;
  const [proc, endian, bits, variant = ""] = parts;
  const name = PROCESSORS[proc] ?? proc;
  const v = variantText(variant, proc);
  return `${name} · ${bits}-bit · ${endian}${v ? ` (${v})` : ""}`;
}

/** "elf" as "ELF", "raw" as "Raw binary". */
export function formatText(format: string): string {
  const f = format.toLowerCase();
  const known: Record<string, string> = { elf: "ELF", pe: "PE", macho: "Mach-O", "mach-o": "Mach-O", raw: "Raw binary", ihex: "Intel HEX", srec: "Motorola S-records", coff: "COFF" };
  return known[f] ?? (format ? format.toUpperCase() : "—");
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** A date for a column: "6 min ago" under a day, else "Oct 7, 2026". */
export function dateText(ms: number, now = Date.now()): string {
  if (!ms) return "";
  const s = Math.round((now - ms) / 1000);
  if (s >= 0 && s < 86400) {
    if (s < 45) return "just now";
    if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min ago`;
    const h = Math.round(s / 3600);
    return `${h} hour${h === 1 ? "" : "s"} ago`;
  }
  const d = new Date(ms);
  return `${MONTHS[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}`;
}

/** The full date and time, for the details. */
export function dateTimeText(ms: number): string {
  if (!ms) return "";
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${MONTHS[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Bytes as "64.0 KB". */
export function sizeText(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1 << 20) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1 << 30) return `${(n / (1 << 20)).toFixed(1)} MB`;
  return `${(n / (1 << 30)).toFixed(1)} GB`;
}

/** What a row is sorted and searched by. */
export interface ProgramRowInfo {
  name: string;
  languageId: string;
  format: string;
  folderPath: string;
  /** Imported, ms since the epoch. */
  importedMs: number;
  /** The status's rank: open here, analyzing, ready, error, deleted. */
  status: string;
}

export type SortKey = "name" | "arch" | "date" | "status";
export interface Sort {
  key: SortKey;
  dir: 1 | -1;
}

const byName = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });

/** Orders two programs by `s`, the name breaking ties. */
export function comparePrograms(a: ProgramRowInfo, b: ProgramRowInfo, s: Sort): number {
  let c = 0;
  if (s.key === "arch") c = byName(archText(a.languageId), archText(b.languageId));
  else if (s.key === "date") c = a.importedMs - b.importedMs;
  else if (s.key === "status") c = byName(a.status, b.status);
  if (c === 0 && s.key !== "name") return byName(a.name, b.name);
  return (c || byName(a.name, b.name)) * s.dir;
}

/** Folders by name: ascending, or descending when the names are sorted so. */
export function compareFolders(a: string, b: string, s: Sort): number {
  return byName(a, b) * (s.key === "name" ? s.dir : 1);
}

/**
 * Does `p` match the search `q`: every word of it is in the name, the
 * architecture (as shown or as the language id), the format or the folder.
 */
export function matchesQuery(p: ProgramRowInfo, q: string): boolean {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const hay = [p.name, p.languageId, archText(p.languageId), p.format, formatText(p.format), p.folderPath].join("\n").toLowerCase();
  return words.every((w) => hay.includes(w));
}
