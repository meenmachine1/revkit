// The searches (api_minor 41, feature "search"; docs/api.md "Search"):
// SearchMemory, SearchText, SearchScalars and SearchDecompiled as one call
// each that gathers the streamed matches, reports progress and stops on an
// AbortSignal. The UI's search dialogs and results tables use them; scripts
// can too.
import type { Revkit } from "./index";
import type { MessageInitShape } from "@bufbuild/protobuf";
import {
  type DecompiledMatch,
  type FindTypeUsesRequestSchema,
  type FindTypeUsesResponse,
  type MemoryMatch,
  type ScalarMatch,
  type SearchDecompiledRequestSchema,
  type SearchDecompiledResponse,
  type SearchMemoryRequestSchema,
  type SearchMemoryResponse,
  type SearchScalarsRequestSchema,
  type SearchScalarsResponse,
  type SearchTextRequestSchema,
  type SearchTextResponse,
  type TextMatch,
  type TypeUse,
} from "./gen/revkit/v1/query_pb";

export const SEARCH_FEATURE = "search";

export interface SearchOptions<R> {
  /** Every message as it arrives: progress (bytes, rows or functions done of the total). */
  onProgress?: (message: R) => void;
  signal?: AbortSignal;
}

export interface SearchResult<M, R> {
  matches: M[];
  /** The last message: truncated, elapsed_ms, a memory search's pattern. */
  last: R | undefined;
}

async function gather<M, R extends { matches: M[] }>(stream: AsyncIterable<R>, o: SearchOptions<R>): Promise<SearchResult<M, R>> {
  const matches: M[] = [];
  let last: R | undefined;
  for await (const m of stream) {
    for (const x of m.matches) matches.push(x);
    last = m;
    o.onProgress?.(m);
  }
  return { matches, last };
}

/** Ghidra's Search Memory: hex, string, decimal, float, double, binary or regex, in a scope, from a start. */
export function searchMemory(
  rk: Revkit,
  request: MessageInitShape<typeof SearchMemoryRequestSchema>,
  o: SearchOptions<SearchMemoryResponse> = {},
): Promise<SearchResult<MemoryMatch, SearchMemoryResponse>> {
  return gather(rk.queries.searchMemory(request, { signal: o.signal }), o);
}

/** Ghidra's Search Program Text: what the listing shows, as text or a regex. */
export function searchText(
  rk: Revkit,
  request: MessageInitShape<typeof SearchTextRequestSchema>,
  o: SearchOptions<SearchTextResponse> = {},
): Promise<SearchResult<TextMatch, SearchTextResponse>> {
  return gather(rk.queries.searchText(request, { signal: o.signal }), o);
}

/** Instructions and defined data using a scalar value or one in a range. */
export function searchScalars(
  rk: Revkit,
  request: MessageInitShape<typeof SearchScalarsRequestSchema>,
  o: SearchOptions<SearchScalarsResponse> = {},
): Promise<SearchResult<ScalarMatch, SearchScalarsResponse>> {
  return gather(rk.queries.searchScalars(request, { signal: o.signal }), o);
}

/** Decompiled C of every function or some, over DecompileMany's workers and cache. */
export function searchDecompiled(
  rk: Revkit,
  request: MessageInitShape<typeof SearchDecompiledRequestSchema>,
  o: SearchOptions<SearchDecompiledResponse> = {},
): Promise<SearchResult<DecompiledMatch, SearchDecompiledResponse>> {
  return gather(rk.queries.searchDecompiled(request, { signal: o.signal }), o);
}

/** Where a struct or union, or one field (field_offset, and field_name for
 * a union's member), is used in the decompiled C of every function or some
 * (api_minor 53, feature "type-uses"): FIELD uses with their access, and
 * the type named in declarations and casts. */
export async function findTypeUses(
  rk: Revkit,
  request: MessageInitShape<typeof FindTypeUsesRequestSchema>,
  o: SearchOptions<FindTypeUsesResponse> = {},
): Promise<SearchResult<TypeUse, FindTypeUsesResponse>> {
  const matches: TypeUse[] = [];
  let last: FindTypeUsesResponse | undefined;
  for await (const m of rk.queries.findTypeUses(request, { signal: o.signal })) {
    for (const x of m.uses) matches.push(x);
    last = m;
    o.onProgress?.(m);
  }
  return { matches, last };
}

export const TYPE_USES_FEATURE = "type-uses";
export const CALL_SIGNATURE_FEATURE = "call-signature-override";

/** The matched part of a text or decompiled match (match_start and
 * match_length count UTF-8 bytes): [before, match, after] as JS strings. */
export function splitMatch(text: string, matchStart: number, matchLength: number): [string, string, string] {
  const bytes = new TextEncoder().encode(text);
  const dec = new TextDecoder();
  return [
    dec.decode(bytes.subarray(0, matchStart)),
    dec.decode(bytes.subarray(matchStart, matchStart + matchLength)),
    dec.decode(bytes.subarray(matchStart + matchLength)),
  ];
}
