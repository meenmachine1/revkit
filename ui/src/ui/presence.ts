// Collaborators' cursors (feature "presence"): this tab publishes where it
// is (UpdatePresence, refreshed before it expires, removed on leaving) and
// the subscription streams everyone else's. Entries are ephemeral: never in
// the assertion log.

import { create } from "@bufbuild/protobuf";
import { PresenceSchema, type Presence, type Revkit } from "@revkit/api";
import { SESSION, userName, userProvenance } from "../api/client";

const TTL = 30;

export interface Cursor {
  clientId: string;
  name: string;
  address: bigint | null;
  view: string;
  color: string;
  expires: number;
}

const COLORS = ["#f778ba", "#3fb950", "#d29922", "#a371f7", "#39c5cf", "#ff7b72"];

function colorOf(id: string): string {
  let h = 0;
  for (const c of id) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return COLORS[h % COLORS.length];
}

export class Collaborators {
  /** Other clients in this program, by client id. */
  cursors = new Map<string, Cursor>();
  onChange: (() => void) | null = null;
  private timer = 0;
  private last: { address: bigint | null; view: string } = { address: null, view: "" };
  private refresh = 0;

  constructor(
    private rk: Revkit,
    private projectId: string,
    private programId: string,
  ) {
    this.refresh = window.setInterval(() => {
      void this.send();
      this.expire();
    }, (TTL / 2) * 1000);
    addEventListener("pagehide", () => void this.send(true));
  }

  /** This tab moved: publish it shortly (debounced). */
  moved(address: bigint | null, view: string) {
    if (address === this.last.address && view === this.last.view) return;
    this.last = { address, view };
    clearTimeout(this.timer);
    this.timer = window.setTimeout(() => void this.send(), 150);
  }

  private async send(left = false) {
    const p = create(PresenceSchema, {
      clientId: SESSION,
      who: userProvenance(),
      displayName: userName(),
      programId: this.programId,
      address: this.last.address === null ? undefined : { offset: this.last.address },
      view: this.last.view,
      left,
    });
    try {
      await this.rk.presence.updatePresence({ projectId: this.projectId, presence: p, ttlSeconds: TTL });
    } catch {
      /* best effort */
    }
  }

  /** An entry from the stream (or the list at start). */
  update(p: Presence) {
    if (p.clientId === SESSION) return;
    if (p.left || p.programId !== this.programId) this.cursors.delete(p.clientId);
    else
      this.cursors.set(p.clientId, {
        clientId: p.clientId,
        name: p.displayName || p.who?.id || p.clientId,
        address: p.address ? p.address.offset : null,
        view: p.view,
        color: colorOf(p.clientId),
        expires: p.expiresAt ? Number(p.expiresAt.seconds) * 1000 : Date.now() + TTL * 1000,
      });
    this.onChange?.();
  }

  private expire() {
    const now = Date.now();
    let changed = false;
    for (const [id, c] of this.cursors)
      if (c.expires < now) {
        this.cursors.delete(id);
        changed = true;
      }
    if (changed) this.onChange?.();
  }

  /** Cursors by address, for the listing. */
  byAddress(): Map<bigint, Cursor[]> {
    const m = new Map<bigint, Cursor[]>();
    for (const c of this.cursors.values()) if (c.address !== null) m.set(c.address, [...(m.get(c.address) ?? []), c]);
    return m;
  }

  stop() {
    clearInterval(this.refresh);
  }
}
