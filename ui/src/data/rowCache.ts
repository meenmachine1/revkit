// Paged row cache with LRU eviction, nearby-page prefetch, request limiting
// and revision-aware invalidation.
//
// The view calls `want(first, last, direction)` once per frame with the
// visible range. The cache keeps a priority list (visible pages first, then
// prefetch in the scroll direction) and keeps at most `maxInFlight` page
// requests outstanding.
//
// Invalidation follows the subscription stream (docs/api.md, "Subscriptions
// and cache invalidation"): a LISTING range marks the pages holding rows in
// that address range stale, an unset range (row numbering may have changed)
// marks everything stale. Stale pages that are visible keep drawing until
// their refetch lands. A page fetched at a revision older than the newest
// invalidation is stored but stays stale, so a response that raced an edit
// is refetched rather than kept.
//
// Renumbering: when an edit adds or removes rows (code defined, a label or
// a comment line with header rows), the event says which row windows
// changed (RowShift). Cached rows are moved to their new numbers and
// responses computed before the change are mapped the same way when they
// land, so the view keeps its place and nothing is refetched but the
// changed rows. Only a change the event can't describe (total rows
// differing without one) drops everything.

import { RowKind, type ListingRow, type ListingSource, type RowShift } from "./types";

interface Shift {
  revision: bigint;
  windows: RowShift[];
}

/** New row number of `row` after `windows` (sorted), or null when the row
 * was inside a window that changed. */
export function shiftRow(row: number, windows: RowShift[]): number | null {
  let delta = 0;
  for (const w of windows) {
    if (row >= w.prevFirst + w.prevCount) delta += w.count - w.prevCount;
    else if (row >= w.prevFirst) return null;
    else break;
  }
  return row + delta;
}

export interface RowCacheOptions {
  pageSize?: number;
  /** Max cached pages (LRU). */
  capacity?: number;
  /** Pages prefetched beyond the viewport in the scroll direction. */
  prefetchAhead?: number;
  /** Pages kept/prefetched behind the viewport. */
  prefetchBehind?: number;
  maxInFlight?: number;
}

interface Page {
  rows: (ListingRow | undefined)[];
  filled: number;
  /** Invalidated; still drawn until the refetch lands. */
  stale: boolean;
  revision: bigint;
}

export interface CacheStats {
  requests: number;
  aborted: number;
  rowsReceived: number;
  fetchMsTotal: number;
  fetchMsMax: number;
  evictions: number;
  /** Recent request latencies, ms (bounded). */
  latencies: number[];
}

export class RowCache {
  readonly pageSize: number;
  private capacity: number;
  private ahead: number;
  private behind: number;
  private maxInFlight: number;

  private pages = new Map<number, Page>(); // insertion order = LRU order
  private inFlight = new Map<number, AbortController>();
  private wanted: number[] = [];
  private listeners = new Set<() => void>();
  rowCount = 0;
  /** Highest revision any response or event has shown us. */
  revision = 0n;
  /** Pages computed before this revision may predate an invalidation. */
  private minRevision = 0n;
  /** Called when a response reports a different total row count. */
  onRowCount: ((total: number) => void) | null = null;
  /** Called after rows were renumbered (the view moves its scroll and selection). */
  onShift: ((map: (row: number) => number | null, before: (row: number) => ListingRow | undefined) => void) | null = null;
  /** Recent renumberings, oldest first, to map late responses. */
  private shifts: Shift[] = [];
  /** Responses older than this predate a renumbering we no longer track. */
  private shiftFloor = 0n;
  stats: CacheStats = { requests: 0, aborted: 0, rowsReceived: 0, fetchMsTotal: 0, fetchMsMax: 0, evictions: 0, latencies: [] };

  constructor(
    private source: ListingSource,
    opts: RowCacheOptions = {},
  ) {
    this.pageSize = opts.pageSize ?? 256;
    this.capacity = opts.capacity ?? 96;
    this.ahead = opts.prefetchAhead ?? 2;
    this.behind = opts.prefetchBehind ?? 1;
    this.maxInFlight = opts.maxInFlight ?? 6;
  }

  /** Called when new rows land (the view schedules a redraw). */
  onUpdate(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  /** Bumped whenever cached rows change (views cache what they derive). */
  version = 0;

  private notify() {
    this.version++;
    for (const l of this.listeners) l();
  }

  get(row: number): ListingRow | undefined {
    const p = this.pages.get(Math.floor(row / this.pageSize));
    return p?.rows[row % this.pageSize];
  }

  /** Mark a page as recently used without fetching. */
  private touch(idx: number, p: Page) {
    this.pages.delete(idx);
    this.pages.set(idx, p);
  }

  /** Declare the visible range; direction is +1 (down), -1 (up) or 0. */
  want(first: number, last: number, direction: number, predictedFirst?: number) {
    const ps = this.pageSize;
    const maxPage = Math.max(0, Math.ceil(this.rowCount / ps) - 1);
    const p0 = Math.max(0, Math.floor(first / ps));
    const p1 = Math.min(maxPage, Math.floor(Math.max(first, last) / ps));
    const list: number[] = [];
    for (let p = p0; p <= p1; p++) list.push(p);
    // Fast drags/flings move past the prefetch window every frame: also fetch
    // where the view is predicted to be next frame.
    if (predictedFirst !== undefined) {
      const q0 = Math.max(0, Math.floor(predictedFirst / ps));
      const q1 = Math.min(maxPage, Math.floor((predictedFirst + (last - first)) / ps));
      for (let p = q0; p <= q1; p++) if (p < p0 || p > p1) list.push(p);
    }
    // Neighbour prefetch is useless while jumping a viewport or more per frame.
    const fast = predictedFirst !== undefined;
    const fwd = fast ? 0 : direction >= 0 ? this.ahead : this.behind;
    const back = fast ? 0 : direction >= 0 ? this.behind : this.ahead;
    for (let i = 1; i <= Math.max(fwd, back); i++) {
      if (i <= fwd && p1 + i <= maxPage) list.push(p1 + i);
      if (i <= back && p0 - i >= 0) list.push(p0 - i);
    }
    for (const p of list) {
      const page = this.pages.get(p);
      if (page) this.touch(p, page);
    }
    this.wanted = list;
    this.pump();
  }

  private pump() {
    // In-flight requests are never aborted when they fall out of the wanted
    // set: with fetch latency near a frame, aborting starves a fast drag of
    // all data, while a late page is still drawable (the view holds the most
    // recent loaded position). Only not-yet-issued work is dropped, which the
    // wanted list being rebuilt every frame does implicitly.
    for (const p of this.wanted) {
      if (this.inFlight.size >= this.maxInFlight) break;
      if (this.inFlight.has(p)) continue;
      const page = this.pages.get(p);
      if (page && !page.stale && page.filled >= this.pageLen(p)) continue;
      this.fetchPage(p);
    }
  }

  private pageLen(p: number): number {
    return Math.max(0, Math.min(this.pageSize, this.rowCount - p * this.pageSize));
  }

  private fetchPage(p: number) {
    const ac = new AbortController();
    this.inFlight.set(p, ac);
    this.stats.requests++;
    const t0 = performance.now();
    this.source.rows(p * this.pageSize, this.pageSize, ac.signal).then(
      (res) => {
        // Invalidated while in flight: a newer request owns the page.
        if (this.inFlight.get(p) !== ac) return;
        this.inFlight.delete(p);
        const dt = performance.now() - t0;
        this.stats.fetchMsTotal += dt;
        this.stats.fetchMsMax = Math.max(this.stats.fetchMsMax, dt);
        if (this.stats.latencies.length < 20000) this.stats.latencies.push(dt);
        this.insert(res.startRow, res.rows, res.revision, res.totalRows);
        this.pump();
      },
      (err) => {
        if (this.inFlight.get(p) === ac) this.inFlight.delete(p);
        if (ac.signal.aborted) {
          this.stats.aborted++;
          return;
        }
        console.warn("page fetch failed", p, err);
        // Retry later rather than hammering a failing daemon every frame.
        setTimeout(() => this.pump(), 500);
      },
    );
  }

  /**
   * Maps a row number computed at `revision` to the current numbering:
   * null if it was renumbered away, or if `revision` predates the
   * renumberings this cache remembers.
   */
  mapRow(row: number, revision: bigint): number | null {
    if (revision < this.shiftFloor) return null;
    let r: number | null = row;
    for (const s of this.shifts) {
      if (s.revision <= revision) continue;
      r = shiftRow(r, s.windows);
      if (r === null) return null;
    }
    return r;
  }

  /** Total rows at `revision`, in the current numbering. */
  private mapTotal(total: number, revision: bigint): number {
    for (const s of this.shifts) if (s.revision > revision) for (const w of s.windows) total += w.count - w.prevCount;
    return total;
  }

  /**
   * Rows were renumbered at `revision` (windows sorted by prevFirst): moves
   * every cached row computed before it, drops the rows inside the
   * windows, and adjusts the row count.
   */
  applyShift(revision: bigint, windows: RowShift[]) {
    windows = [...windows].sort((a, b) => a.prevFirst - b.prevFirst);
    const delta = windows.reduce((n, w) => n + w.count - w.prevCount, 0);
    this.shifts.push({ revision, windows });
    while (this.shifts.length > 64) this.shiftFloor = this.shifts.shift()!.revision;
    const ps = this.pageSize;
    const moved: [number, ListingRow][] = [];
    const meta = new Map<number, { stale: boolean; revision: bigint }>();
    for (const [idx, page] of this.pages) {
      for (let i = 0; i < page.rows.length; i++) {
        const r = page.rows[i];
        if (!r) continue;
        const at = r.revision >= revision ? idx * ps + i : shiftRow(idx * ps + i, windows);
        if (at === null) continue;
        moved.push([at, r]);
        const m = meta.get(Math.floor(at / ps));
        if (!m) meta.set(Math.floor(at / ps), { stale: page.stale, revision: page.revision });
        else m.stale ||= page.stale;
      }
    }
    // In-flight pages are mapped when they land (insert); their slots are
    // re-requested if needed.
    for (const ac of this.inFlight.values()) ac.abort();
    this.inFlight.clear();
    const before = new Map(this.pages);
    this.pages.clear();
    this.rowCount += delta;
    for (const [at, r] of moved) {
      if (at < 0 || at >= this.rowCount) continue;
      const idx = Math.floor(at / ps);
      let page = this.pages.get(idx);
      if (!page) {
        const m = meta.get(idx)!;
        page = { rows: new Array(ps), filled: 0, stale: m.stale, revision: m.revision };
        this.pages.set(idx, page);
      }
      const off = at - idx * ps;
      if (page.rows[off] === undefined) page.filled++;
      page.rows[off] = r.row === at ? r : { ...r, row: at };
    }
    if (revision > this.revision) this.revision = revision;
    this.onShift?.(
      (row) => shiftRow(row, windows),
      (row) => before.get(Math.floor(row / ps))?.rows[row % ps],
    );
    this.pump();
    this.notify();
  }

  /** Insert rows from any response (paged or around-address). */
  insert(startRow: number, rows: ListingRow[], revision: bigint, totalRows?: number) {
    if (revision > this.revision) this.revision = revision;
    if (revision < this.shiftFloor) return;
    // Computed before a renumbering we have applied: move it the same way.
    if (this.shifts.length && revision < this.shifts[this.shifts.length - 1].revision) {
      const mapped: [number, ListingRow][] = [];
      rows.forEach((r, i) => {
        const at = this.mapRow(startRow + i, revision);
        if (at !== null) mapped.push([at, r]);
      });
      if (totalRows !== undefined) totalRows = this.mapTotal(totalRows, revision);
      this.insertMapped(mapped, revision, totalRows);
      return;
    }
    this.insertMapped(
      rows.map((r, i) => [startRow + i, r]),
      revision,
      totalRows,
    );
  }

  private insertMapped(rows: [number, ListingRow][], revision: bigint, totalRows?: number) {
    if (totalRows !== undefined && totalRows !== this.rowCount) {
      // Row numbering changed under us: everything cached is suspect.
      const shifted = this.rowCount !== 0;
      this.rowCount = totalRows;
      if (shifted) {
        this.dropAll();
        this.onRowCount?.(totalRows);
      }
    }
    const ps = this.pageSize;
    const old = revision < this.minRevision;
    for (const [r, row] of rows) {
      if (r < 0 || r >= this.rowCount) continue;
      const idx = Math.floor(r / ps);
      let page = this.pages.get(idx);
      if (!page) {
        page = { rows: new Array(ps), filled: 0, stale: false, revision };
        this.pages.set(idx, page);
      }
      const off = r - idx * ps;
      if (page.rows[off] === undefined) page.filled++;
      page.rows[off] = row.row === r ? row : { ...row, row: r };
      page.revision = revision;
      page.stale = old;
    }
    this.stats.rowsReceived += rows.length;
    this.evict();
    this.notify();
  }

  private evict() {
    const keep = new Set(this.wanted);
    while (this.pages.size > this.capacity) {
      let victim: number | undefined;
      for (const k of this.pages.keys()) {
        if (!keep.has(k)) {
          victim = k;
          break;
        }
      }
      if (victim === undefined) break;
      this.pages.delete(victim);
      this.stats.evictions++;
    }
  }

  private pageOverlaps(page: Page, lo: bigint, hi: bigint): boolean {
    let first: ListingRow | undefined;
    let last: ListingRow | undefined;
    for (const r of page.rows) {
      if (!r) continue;
      if (!first) first = r;
      last = r;
    }
    if (!first || !last) return false;
    return first.address <= hi && last.address + BigInt(Math.max(1, last.length)) - 1n >= lo;
  }

  private markStale(p: number, page: Page, wanted: Set<number>) {
    // Visible/prefetched pages keep drawing old rows until the refetch lands.
    if (wanted.has(p)) page.stale = true;
    else this.pages.delete(p);
    const ac = this.inFlight.get(p);
    if (ac) {
      ac.abort();
      this.inFlight.delete(p);
    }
  }

  private bump(revision: bigint) {
    if (revision > this.minRevision) this.minRevision = revision;
    if (revision > this.revision) this.revision = revision;
  }

  /** Rows touching [lo, hi] changed at `revision`. */
  invalidateRange(lo: bigint, hi: bigint, revision: bigint) {
    this.bump(revision);
    const wanted = new Set(this.wanted);
    for (const [p, page] of [...this.pages]) if (this.pageOverlaps(page, lo, hi)) this.markStale(p, page, wanted);
    // Requests in flight are stored stale if computed before `revision`.
    this.pump();
    this.notify();
  }

  /** Everything changed (row numbering may have shifted). */
  invalidateAll(revision: bigint) {
    this.bump(revision);
    const wanted = new Set(this.wanted);
    for (const [p, page] of [...this.pages]) this.markStale(p, page, wanted);
    this.pump();
    this.notify();
  }

  private dropAll() {
    for (const ac of this.inFlight.values()) ac.abort();
    this.inFlight.clear();
    this.pages.clear();
  }

  clear() {
    this.dropAll();
    this.notify();
  }

  /** Search non-stale cached rows for the code unit containing `address`; -1 if none. */
  findCached(address: bigint): number {
    for (const [idx, page] of this.pages) {
      if (page.stale) continue;
      const rows = page.rows;
      for (let i = 0; i < rows.length; i++) {
        const r = rows[i];
        if (r && r.kind !== RowKind.Header && address >= r.address && address < r.address + BigInt(Math.max(1, r.length))) return idx * this.pageSize + i;
      }
    }
    return -1;
  }

  get cachedPages() {
    return this.pages.size;
  }
  get pendingRequests() {
    return this.inFlight.size;
  }
}
