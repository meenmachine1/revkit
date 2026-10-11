// Previews (api_minor 47, feature "hover"; docs/ui.md "Hover cards"): what
// the UI's hover cards show, from the existing read calls, for any client.
//
//   const p = await preview(rk, programId, 0x401000n);
//   p.kind === "function" ? p.signature + "\n" + p.lines.join("\n") : p.lines.join("\n");
//   scalarText(0x41n, 32);   // { hex: "0x41", unsigned: "65", signed: "65", chars: "'A'" }
import type { DecompiledFunction } from "./gen/revkit/v1/decompile_pb";
import type { Revkit } from "./index";

export const HOVER_FEATURE = "hover";

/** Lines of C a function's preview has, after its signature line. */
export const PREVIEW_LINES = 12;

/** A decompiled function's text, line by line, as the decompiler prints it. */
export function decompiledLines(fn: DecompiledFunction): string[] {
  return fn.lines.map((l) => "  ".repeat(l.indent) + l.tokens.map((t) => t.text).join(""));
}

/**
 * The first lines of a function's C: its signature, the opening brace and
 * the body's first statements (the local declarations, up to the first
 * blank line, skipped), then "  …" when there is more.
 */
export function previewLines(fn: DecompiledFunction, n = PREVIEW_LINES): string[] {
  const all = decompiledLines(fn);
  const open = all.findIndex((l) => l.trim() === "{");
  if (open < 0) return all.slice(0, n);
  const out = all.slice(0, open + 1);
  const blank = all.findIndex((l, j) => j > open && l.trim() === "");
  let i = blank > open && blank < open + 40 ? blank + 1 : open + 1;
  for (; i < all.length && out.length < n; i++) if (all[i].trim()) out.push(all[i]);
  if (i < all.length) out.push("  …");
  return out;
}

export interface ScalarText {
  hex: string;
  unsigned: string;
  signed: string;
  /** As a C character constant ('A', 'ELF'), when every byte prints. */
  chars: string | null;
}

/** A scalar's spellings in `bits` bits (8 to 64): hex, decimal, characters. */
export function scalarText(value: bigint, bits = 64): ScalarText {
  const w = BigInt(Math.max(8, Math.min(64, bits || 64)));
  const u = value & ((1n << w) - 1n);
  const s = u >= 1n << (w - 1n) ? u - (1n << w) : u;
  let chars: string | null = null;
  if (u !== 0n) {
    const bytes: number[] = [];
    for (let v = u; v > 0n; v >>= 8n) bytes.unshift(Number(v & 0xffn));
    const esc: Record<number, string> = { 0: "\\0", 7: "\\a", 8: "\\b", 9: "\\t", 10: "\\n", 11: "\\v", 12: "\\f", 13: "\\r", 39: "\\'", 92: "\\\\" };
    if (bytes.every((b) => (b >= 0x20 && b < 0x7f) || esc[b] !== undefined)) chars = "'" + bytes.map((b) => esc[b] ?? String.fromCharCode(b)).join("") + "'";
  }
  return { hex: "0x" + u.toString(16), unsigned: u.toString(), signed: s.toString(), chars };
}

export type Preview =
  | { kind: "function"; address: bigint; name: string; signature: string; lines: string[] }
  | { kind: "data"; address: bigint; name: string; lines: string[] };

/**
 * What is at `address`: a function's signature and first lines of C (its
 * listing rows when it doesn't decompile), else the listing's rows from
 * there (`rows` of them) and the name of the symbol at it.
 */
export async function preview(rk: Revkit, programId: string, address: bigint, opts: { lines?: number; rows?: number; timeoutMs?: number } = {}): Promise<Preview> {
  const rows = async () => {
    const r = await rk.queries.getListing({ programId, window: { case: "addresses", value: { start: { offset: address }, maxRows: opts.rows ?? 8 } } });
    return r.rows.map((x) => {
      const label = x.labels[0]?.name;
      const text = x.tokens.map((t) => t.text).join("");
      return `${x.address?.offset.toString(16) ?? ""}  ${label ? label + ": " : ""}${text}`.trimEnd();
    });
  };
  let fn;
  try {
    fn = (await rk.queries.getFunction({ programId, address: { offset: address } })).function;
  } catch {
    fn = undefined;
  }
  if (fn) {
    let lines: string[] | null = null;
    try {
      const r = await rk.queries.decompile({ programId, function: { offset: address }, options: { timeoutMs: opts.timeoutMs ?? 5000 } });
      if (r.function && !r.failure) lines = previewLines(r.function, opts.lines ?? PREVIEW_LINES);
    } catch {
      lines = null;
    }
    // No prototype recorded: the decompiler's signature line.
    const signature = fn.prototype || (lines && lines.length > 1 ? lines[0] : fn.name);
    return { kind: "function", address, name: fn.name, signature, lines: lines ?? (await rows()) };
  }
  const syms = await rk.queries.listSymbols({ programId, range: { first: { offset: address }, last: { offset: address } }, page: { pageSize: 4 } });
  return { kind: "data", address, name: syms.symbols.find((s) => s.address?.offset === address)?.name ?? "", lines: await rows() };
}
