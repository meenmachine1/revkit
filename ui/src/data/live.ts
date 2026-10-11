// The tab's one subscription stream (docs/api.md: one stream per tab, since
// browsers allow six HTTP/1.1 connections per origin). It resumes from the
// last applied revision after a drop, and turns Hello.resync_required into a
// full invalidation.

import type { Presence, RevisionEvent, Revkit } from "@revkit/api";

export type LiveState = "connecting" | "live" | "reconnecting" | "paused";

export interface LiveHandlers {
  /** One committed revision, in order. */
  onRevision(ev: RevisionEvent): void;
  /** Our caches can't be brought up to date incrementally. */
  onResync(head: bigint): void;
  onState(s: LiveState, head: bigint): void;
  /** A collaborator's cursor appeared, moved or left (with presence). */
  onPresence?(p: Presence): void;
}

export class Live {
  head = 0n;
  private abort = new AbortController();
  private waiters: { rev: bigint; resolve: () => void }[] = [];
  /** The current stream's own abort (pause ends it), and the pause gate. */
  private streamAbort: AbortController | null = null;
  private pauses = 0;
  private gate: Promise<void> | null = null;
  private release: (() => void) | null = null;
  /** Ends the wait before the next attempt (kick). */
  private wake: (() => void) | null = null;
  private delay = 500;

  constructor(
    private rk: Revkit,
    private projectId: string,
    private programId: string,
    private h: LiveHandlers,
    startRevision: bigint,
    /** Also stream presence (feature "presence"). */
    private presence = false,
  ) {
    this.head = startRevision;
    void this.loop();
  }

  stop() {
    this.abort.abort();
    this.release?.();
  }

  /**
   * Ends the stream until the returned function is called (nested pauses
   * count), e.g. while a native dialog is open; it then resumes from the
   * last revision it applied, so nothing is missed.
   */
  pause(): () => void {
    if (this.pauses++ === 0) {
      this.gate = new Promise((r) => (this.release = r));
      this.streamAbort?.abort();
    }
    let done = false;
    return () => {
      if (done) return;
      done = true;
      if (--this.pauses === 0) {
        this.gate = null;
        this.release?.();
        this.release = null;
      }
    };
  }

  /** Tries again now instead of after the backoff (the daemon is back). */
  kick() {
    this.delay = 500;
    this.wake?.();
  }

  /** Resolves once the stream has delivered `rev` (or after `ms`). */
  waitFor(rev: bigint, ms = 3000): Promise<void> {
    if (this.head >= rev) return Promise.resolve();
    return new Promise((resolve) => {
      const w = { rev, resolve };
      this.waiters.push(w);
      setTimeout(() => {
        this.waiters = this.waiters.filter((x) => x !== w);
        resolve();
      }, ms);
    });
  }

  private advance(rev: bigint) {
    if (rev > this.head) this.head = rev;
    this.waiters = this.waiters.filter((w) => {
      if (w.rev > this.head) return true;
      w.resolve();
      return false;
    });
  }

  private async loop() {
    let first = true;
    const signal = this.abort.signal;
    while (!signal.aborted) {
      if (this.gate) {
        this.h.onState("paused", this.head);
        await this.gate;
        if (signal.aborted) return;
      }
      this.h.onState(first ? "connecting" : "reconnecting", this.head);
      const own = new AbortController();
      this.streamAbort = own;
      const stop = () => own.abort();
      signal.addEventListener("abort", stop, { once: true });
      try {
        const stream = this.rk.subscriptions.subscribe(
          { projectId: this.projectId, programIds: [this.programId], fromRevision: this.head, includeAssertions: true, heartbeatSeconds: 10, includePresence: this.presence },
          { signal: own.signal },
        );
        for await (const msg of stream) {
          this.delay = 500;
          const ev = msg.event;
          switch (ev.case) {
            case "hello":
              this.h.onState("live", ev.value.headRevision);
              if (ev.value.resyncRequired) this.h.onResync(ev.value.headRevision);
              this.advance(ev.value.headRevision);
              break;
            case "revision":
              this.h.onRevision(ev.value);
              this.advance(ev.value.revision);
              this.h.onState("live", this.head);
              break;
            case "presence":
              this.h.onPresence?.(ev.value);
              break;
            case "heartbeat":
              if (ev.value.headRevision > this.head) {
                // A revision for other programs; nothing of ours changed.
                this.advance(ev.value.headRevision);
              }
              this.h.onState("live", this.head);
              break;
          }
        }
      } catch (e) {
        if (signal.aborted) return;
        if (!own.signal.aborted) console.warn("subscription dropped", e);
      } finally {
        signal.removeEventListener("abort", stop);
        this.streamAbort = null;
      }
      first = false;
      if (signal.aborted) return;
      // Paused: wait at the gate, no backoff.
      if (own.signal.aborted && this.gate) continue;
      this.h.onState("reconnecting", this.head);
      const wait = this.delay;
      this.delay = Math.min(this.delay * 2, 5000);
      await new Promise<void>((r) => {
        const t = setTimeout(r, wait);
        this.wake = () => {
          clearTimeout(t);
          r();
        };
      });
      this.wake = null;
    }
  }
}
