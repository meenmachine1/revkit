// Batch reads for scripts (api_minor 29, feature "script-batch"; docs/scripting.md):
// DecompileMany and ListInstructions as async iterables, FindBytes with
// "48 8b ?? 05" patterns, and the script provenance kind
// (PROVENANCE_KIND_SCRIPT, Provenance.onBehalfOf, feature "script-provenance").
import type { Revkit } from "./index";
import type { InstructionDetail } from "./gen/revkit/v1/listing_pb";
import type { DecompileManyResponse } from "./gen/revkit/v1/query_pb";

export const SCRIPT_BATCH_FEATURE = "script-batch";
export const SCRIPT_PROVENANCE_FEATURE = "script-provenance";

const ALL = (1n << 64n) - 1n;

/** FindBytes' pattern and mask from text: hex digits, "?" for a nibble that
 * may be anything, spaces ignored ("48 8b ?? 05", "4?"). The mask is empty
 * when every bit must match. */
export function bytePattern(text: string): { pattern: Uint8Array; mask: Uint8Array } {
  const t = text.replace(/\s+/g, "");
  if (!t || t.length % 2) throw new Error(`byte pattern "${text}": an even number of hex digits or ?`);
  const pattern = new Uint8Array(t.length / 2), mask = new Uint8Array(t.length / 2);
  let exact = true;
  for (let i = 0; i < pattern.length; i++) {
    let v = 0, m = 0;
    for (const c of t.slice(2 * i, 2 * i + 2)) {
      v <<= 4;
      m <<= 4;
      if (c !== "?") {
        const d = parseInt(c, 16);
        if (Number.isNaN(d)) throw new Error(`byte pattern "${text}": "${c}" is not a hex digit`);
        v |= d;
        m |= 0xf;
      }
    }
    pattern[i] = v;
    mask[i] = m;
    exact &&= m === 0xff;
  }
  return { pattern, mask: exact ? new Uint8Array() : mask };
}

export interface DecompileManyOptions {
  /** Entry points; omitted: every function. */
  functions?: bigint[];
  includeText?: boolean;
  parallelism?: number;
  timeoutMs?: number;
  /** Pin a revision (0: the head when the call starts). */
  revision?: bigint;
  signal?: AbortSignal;
}

/** Decompiled functions in completion order, each with its request index. */
export async function* decompileMany(rk: Revkit, programId: string, o: DecompileManyOptions = {}): AsyncGenerator<DecompileManyResponse> {
  yield* rk.queries.decompileMany(
    {
      programId,
      functions: (o.functions ?? []).map((offset) => ({ offset })),
      all: o.functions === undefined,
      read: { revision: o.revision ?? 0n },
      options: { includeText: o.includeText ?? false, timeoutMs: o.timeoutMs ?? 0 },
      parallelism: o.parallelism ?? 0,
    },
    { signal: o.signal },
  );
}

/** Where a pattern occurs ("48 8b ?? 05", or bytes and a mask), in address order. */
export async function findBytes(
  rk: Revkit,
  programId: string,
  pattern: string | Uint8Array,
  o: { mask?: Uint8Array; first?: bigint; last?: bigint; maxResults?: number; alignment?: number; executableOnly?: boolean } = {},
): Promise<{ addresses: bigint[]; truncated: boolean }> {
  const p = typeof pattern === "string" ? bytePattern(pattern) : { pattern, mask: o.mask ?? new Uint8Array() };
  const r = await rk.queries.findBytes({
    programId,
    pattern: p.pattern,
    mask: p.mask,
    range: { first: { offset: o.first ?? 0n }, last: { offset: o.last ?? ALL } },
    maxResults: o.maxResults ?? 0,
    alignment: o.alignment ?? 0,
    executableOnly: o.executableOnly ?? false,
  });
  return { addresses: r.addresses.map((a) => a.offset), truncated: r.truncated };
}

/** Instructions with p-code in a range or a function's body, in address order. */
export async function* listInstructions(
  rk: Revkit,
  programId: string,
  where: { first: bigint; last: bigint } | { function: bigint },
  o: { omitPcode?: boolean; limit?: number; signal?: AbortSignal } = {},
): AsyncGenerator<InstructionDetail> {
  const scope =
    "function" in where
      ? { case: "function" as const, value: { offset: where.function } }
      : { case: "range" as const, value: { first: { offset: where.first }, last: { offset: where.last } } };
  for await (const batch of rk.queries.listInstructions({ programId, scope, omitPcode: o.omitPcode ?? false, limit: o.limit ?? 0 }, { signal: o.signal }))
    yield* batch.instructions;
}
