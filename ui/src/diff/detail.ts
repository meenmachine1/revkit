// What changed inside a matched pair (GetFunctionDiff with detail,
// api_minor 17, feature diff-detail), fetched once per pair and revision
// and shared by the aligned listing, the graph diff and the decompiled C.

import { DiffBlockStatus, DiffLineStatus, DiffReferenceKind, DiffSide, type DiffDetail, type Revkit } from "@revkit/api";

export { DiffBlockStatus, DiffLineStatus };

export interface Pair {
  /** Empty: two functions compared outside a session (CompareFunctions, feature function-compare). */
  sessionId: string;
  a: bigint;
  b: bigint;
  /** Display names. */
  nameA: string;
  nameB: string;
  programA: string;
  programB: string;
}

export interface PairDetail {
  pair: Pair;
  detail: DiffDetail;
  revision: bigint;
  /** B rows (by index) that call a function only in B: labelled "new". */
  newCalls: Set<number>;
  /** A rows that called a function only in A. */
  goneCalls: Set<number>;
}

const cache = new Map<string, PairDetail>();
const order: string[] = [];
const MAX = 64;

function key(projectId: string, p: Pair) {
  return `${projectId}|${p.sessionId}|${p.a}|${p.b}`;
}

/** Drops what is cached (an edit to either program, a decision). */
export function forgetDetails() {
  cache.clear();
  order.length = 0;
}

export async function fetchDetail(rk: Revkit, projectId: string, pair: Pair): Promise<PairDetail> {
  const k = key(projectId, pair);
  const hit = cache.get(k);
  if (hit) return hit;
  const r = pair.sessionId
    ? await rk.diff.getFunctionDiff({
        projectId,
        sessionId: pair.sessionId,
        entryA: { offset: pair.a },
        entryB: { offset: pair.b },
        detail: true,
        omitBytes: true,
      })
    : await rk.diff.compareFunctions({
        projectId,
        programA: pair.programA,
        programB: pair.programB,
        entryA: { offset: pair.a },
        entryB: { offset: pair.b },
        omitBytes: true,
      });
  const detail = r.detail!;
  const newCalls = new Set<number>(), goneCalls = new Set<number>();
  for (const ref of detail.references)
    if (ref.kind === DiffReferenceKind.CALL && ref.unmatched) (ref.side === DiffSide.B ? newCalls : goneCalls).add(ref.row);
  const out: PairDetail = { pair, detail, revision: r.snapshot?.revision ?? 0n, newCalls, goneCalls };
  cache.set(k, out);
  order.push(k);
  while (order.length > MAX) cache.delete(order.shift()!);
  return out;
}

/** Whether a line differs (it starts or continues a difference). */
export function lineDiffers(d: DiffDetail, i: number): boolean {
  const l = d.lines[i];
  if (l.a < 0 || l.b < 0) {
    const r = l.a >= 0 ? d.rowsA[l.a] : d.rowsB[l.b];
    return r.status !== DiffLineStatus.UNSPECIFIED;
  }
  const r = d.rowsA[l.a];
  return r.moved || (r.status !== DiffLineStatus.EQUAL && r.status !== DiffLineStatus.UNSPECIFIED);
}

/** The colour names of block statuses (CSS classes, the graph's palette). */
export function blockClass(s: DiffBlockStatus): "same" | "mod" | "add" | "del" {
  switch (s) {
    case DiffBlockStatus.MODIFIED:
      return "mod";
    case DiffBlockStatus.ADDED:
      return "add";
    case DiffBlockStatus.REMOVED:
      return "del";
    default:
      return "same";
  }
}

/** Token texts of a changed pair that differ (indexes into each row's tokens), by LCS over non-blank tokens. */
export function tokenDiff(a: { text: string }[], b: { text: string }[]): [Set<number>, Set<number>] {
  const ia = a.map((t, i) => [t.text, i] as const).filter(([t]) => t.trim() !== "");
  const ib = b.map((t, i) => [t.text, i] as const).filter(([t]) => t.trim() !== "");
  const n = ia.length, m = ib.length;
  const t = new Uint16Array((n + 1) * (m + 1));
  for (let x = n - 1; x >= 0; x--)
    for (let y = m - 1; y >= 0; y--)
      t[x * (m + 1) + y] = ia[x][0] === ib[y][0] ? t[(x + 1) * (m + 1) + y + 1] + 1 : Math.max(t[(x + 1) * (m + 1) + y], t[x * (m + 1) + y + 1]);
  const keepA = new Set<number>(), keepB = new Set<number>();
  for (let x = 0, y = 0; x < n && y < m; ) {
    if (ia[x][0] === ib[y][0]) {
      keepA.add(ia[x][1]);
      keepB.add(ib[y][1]);
      x++;
      y++;
    } else if (t[(x + 1) * (m + 1) + y] >= t[x * (m + 1) + y + 1]) x++;
    else y++;
  }
  return [new Set(ia.map(([, i]) => i).filter((i) => !keepA.has(i))), new Set(ib.map(([, i]) => i).filter((i) => !keepB.has(i)))];
}
