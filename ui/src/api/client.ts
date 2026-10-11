// The one place the UI builds its revkit.v1 client. Everything goes through
// the public API (sdk/ts, Connect-ES) over HTTP: same-origin when rk-daemon
// serves the bundle, or ?api=<url> (the Tauri shell, the Vite dev server).
//
// Authentication (docs/security.md): served by the daemon, the page logs in
// with a session cookie the daemon keeps HttpOnly, and sends the session's
// CSRF token with every call; WhoAmI recovers both after a reload. Talking
// to a daemon on another origin (the Tauri shell), the cookie can't follow
// (SameSite=Strict), so the page keeps the session token itself and sends
// it as a bearer token.

import { Code, ConnectError, type Interceptor } from "@connectrpc/connect";
import { createRevkit, type Revkit, ProvenanceKind, credentialsInterceptor, type Identity } from "@revkit/api";
import { createConnectTransport } from "@connectrpc/connect-web";
import { create } from "@bufbuild/protobuf";
import { ProvenanceSchema, type Provenance } from "@revkit/api";
import { prefs } from "../ui/dom";

export type { Revkit };

export const CLIENT_NAME = "rk-web/0.1";

/** This page's credentials. */
export const session = {
  /** The daemon requires authentication (WhoAmI.auth_enabled). */
  authEnabled: false,
  identity: undefined as Identity | undefined,
  csrf: undefined as string | undefined,
  /** Only for a daemon on another origin (no cookie). */
  token: undefined as string | undefined,
  /** Called when a call comes back UNAUTHENTICATED: the session ended. */
  onEnded: undefined as (() => void) | undefined,
};

function sessionEnded(): Interceptor {
  return (next) => async (req) => {
    try {
      return await next(req);
    } catch (e) {
      if (session.identity && e instanceof ConnectError && e.code === Code.Unauthenticated) {
        session.identity = undefined;
        session.onEnded?.();
      }
      throw e;
    }
  };
}

/** While the daemon is unreachable (the status chip is red, ui/daemon.ts),
 * a failed call says so, instead of "Failed to fetch": the page is
 * read-only until the daemon is back. */
function daemonDown(): Interceptor {
  return (next) => async (req) => {
    try {
      return await next(req);
    } catch (e) {
      // fetch() itself fails with a TypeError, which the transport makes a
      // ConnectError (unknown) outside the interceptors.
      const network = !(e instanceof ConnectError) || e.code === Code.Unavailable || e.code === Code.Unknown;
      const state = document.body.dataset.daemon;
      if ((state === "disconnected" || state === "restarting") && network && !req.signal.aborted)
        throw new ConnectError(state === "restarting" ? "the daemon is restarting; the page is read-only until it is back" : "the daemon is disconnected; the page is read-only until it is back", Code.Unavailable, undefined, undefined, e);
      throw e;
    }
  };
}

export function connect(baseUrl: string, binary = true): Revkit {
  return createRevkit(
    createConnectTransport({
      baseUrl,
      useBinaryFormat: binary,
      interceptors: [credentialsInterceptor({ token: () => session.token, csrf: () => session.csrf }), sessionEnded(), daemonDown()],
    }),
  );
}

/** Where a cross-origin page keeps its session token. */
export function tokenKey(baseUrl: string): string {
  return `rk.session:${new URL(baseUrl, location.href).origin}`;
}

/** A random id for this tab; edits carry it as Provenance.session so a
 * tab can tell its own revisions from other clients'. */
export const SESSION = (() => {
  const b = new Uint8Array(6);
  crypto.getRandomValues(b);
  return "web-" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
})();

/** The name on this tab's edits: the signed-in account, else the chosen one. */
export function userName(): string {
  if (session.identity) return session.identity.name;
  const q = new URLSearchParams(location.search).get("user");
  if (q) return q;
  return prefs.get("rk.user") || "local";
}

export function setUserName(name: string) {
  prefs.set("rk.user", name);
}

export function userProvenance(reason = ""): Provenance {
  return create(ProvenanceSchema, {
    // Signed in, the daemon stamps who we are (and refuses anyone else).
    kind: session.authEnabled ? ProvenanceKind.UNSPECIFIED : ProvenanceKind.USER,
    id: session.authEnabled ? "" : userName(),
    session: SESSION,
    tool: CLIENT_NAME,
    reason,
  });
}
