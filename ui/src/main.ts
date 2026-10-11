import "@fontsource/jetbrains-mono/400.css";
import "./style.css";
import { CLIENT_NAME, connect, session, tokenKey } from "./api/client";
import { App, FONT } from "./app";
import { Bench } from "./bench/harness";
import { errText } from "./data/format";
import { $, h, prefs } from "./ui/dom";
import { showOpenDialog } from "./ui/open";
import { showLogin } from "./ui/login";
import { DaemonStatus } from "./ui/daemon";
import { installFocusTrap } from "./ui/focustrap";
import { installDialogResize } from "./ui/dialogsize";
import { Code, ConnectError } from "@connectrpc/connect";
import type { Revkit } from "@revkit/api";

const params = new URLSearchParams(location.search);
// The daemon base URL: same origin when rk-daemon serves the bundle (browser
// mode), ?api= otherwise (the Tauri shell loads its bundled copy from
// tauri://localhost and passes http://127.0.0.1:50052).
const api = params.get("api") ?? (location.protocol.startsWith("http") ? location.origin : "http://127.0.0.1:50052");
const binary = params.get("format") !== "json";
const storedTheme = prefs.get("rk.theme");
const dark = (params.get("theme") ?? storedTheme ?? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")) !== "light";
document.documentElement.dataset.theme = dark ? "dark" : "light";
installFocusTrap();
installDialogResize();

function fatal(msg: string) {
  const main = document.querySelector("main")!;
  main.replaceChildren(h("div", { class: "empty" }, h("div", {}, h("h3", {}, "Can't start"), h("p", { class: "mono pre" }, msg), h("p", {}, `Daemon: ${api}`))));
  $("program").textContent = "error";
  document.body.dataset.ready = "error";
}

/** The daemon on another origin (the Tauri shell): no cookie, a bearer token. */
const crossOrigin = new URL(api, location.href).origin !== location.origin;

function login(rk: Revkit, message?: string) {
  showLogin({
    daemon: api,
    message,
    login: async (username, password) => {
      try {
        const r = await rk.auth.login({ username, password, sessionCookie: !crossOrigin, client: CLIENT_NAME });
        if (crossOrigin) prefs.set(tokenKey(api), r.token);
        location.reload();
        return null;
      } catch (e) {
        if (e instanceof ConnectError && e.code === Code.Unauthenticated) return "Wrong account name or password.";
        if (e instanceof ConnectError && e.code === Code.ResourceExhausted) return e.rawMessage;
        return errText(e);
      }
    },
  });
}

/** Signs out and shows the login page (the palette's and the toolbar's Log out). */
async function logout(rk: Revkit) {
  try {
    await rk.auth.logout({});
  } catch {
    /* the session may be gone already */
  }
  if (crossOrigin) prefs.set(tokenKey(api), "");
  location.reload();
}

/** Who we are, or the login page. False when the page must wait for a login. */
async function authenticate(rk: Revkit, features: string[]): Promise<boolean> {
  if (!features.includes("auth")) return true;  // a daemon before api_minor 13
  if (crossOrigin) session.token = prefs.get(tokenKey(api)) || undefined;
  const who = await rk.auth.whoAmI({});
  session.authEnabled = who.authEnabled;
  if (!who.authEnabled) return true;
  if (!who.identity) {
    session.token = undefined;
    login(rk);
    return false;
  }
  session.identity = who.identity;
  session.csrf = who.csrfToken || undefined;
  session.onEnded = () => login(rk, "Your session has ended; sign in again.");
  return true;
}

async function main() {
  // Measure glyphs only after the webfont is in; otherwise charW is wrong.
  await document.fonts.load(`13px ${FONT}`);
  await document.fonts.ready;

  const rk = connect(api, binary);
  // Bottom left: the daemon's status (connected, connecting, disconnected).
  let app: App | null = null;
  const daemon = new DaemonStatus({ rk, api, client: CLIENT_NAME, onReconnect: () => app?.live?.kick() });
  Object.assign(window, { __daemon: daemon });
  let features: string[] = [];
  try {
    const info = await rk.meta.getServerInfo({ client: CLIENT_NAME });
    daemon.connected(info);
    features = info.features;
    if (info.apiMajor !== "v1") throw new Error(`daemon serves API ${info.apiMajor}, this UI speaks v1`);
  } catch (e) {
    const cross = new URL(api, location.href).origin !== location.origin;
    if (daemon.state !== "connected") {
      // Reloads once the daemon answers (Reconnect, or the desktop's Start).
      daemon.failed(e);
      daemon.reloadWhenBack = true;
    }
    return fatal(
      `Can't reach rk-daemon: ${errText(e)}` +
        (cross ? `\nThe UI runs at ${location.origin}; start the daemon with --allow-origin ${location.origin} so it accepts calls from here.` : ""),
    );
  }

  if (!(await authenticate(rk, features))) return;

  let programId = params.get("program");
  if (!programId) {
    // One program: open it. Otherwise ask.
    const ids: string[] = [];
    const { projects } = await rk.projects.listProjects({});
    for (const p of projects.filter((p) => p.open)) {
      const r = await rk.projects.listPrograms({ projectId: p.projectId });
      ids.push(...r.programs.map((x) => x.programId));
    }
    if (ids.length === 1) programId = ids[0];
    else {
      $("program").textContent = "Open a program";
      document.body.dataset.ready = "open";
      showOpenDialog(rk, {
        required: true,
        features,
        onOpen: (id, address) => {
          const u = new URL(location.href);
          u.searchParams.set("program", id);
          if (address !== undefined) u.hash = `#${address.toString(16)}`;
          location.href = u.toString();
        },
      });
      return;
    }
  }

  app = new App({ rk, programId, params, dark, features, daemon, logout: session.authEnabled ? () => void logout(rk) : undefined });
  try {
    await app.start();
  } catch (e) {
    console.error(e);
    return fatal(`${programId}: ${errText(e)}`);
  }

  const bench = new Bench({ view: app.view, cache: app.cache, targets: () => app.jumpTargets });
  Object.assign(window, { __revkit: { app, view: app.view, cache: app.cache, rk }, __bench: bench });
  document.body.dataset.ready = "1";

  // Self-driving benchmark for engines Playwright can't drive (the Tauri
  // shell's WebKitGTK): ?autobench=<label>&sink=<url> runs every scenario
  // and POSTs the result to bench/sink.ts.
  const label = params.get("autobench");
  if (label) {
    // Measure what a user gets: after the render scale is chosen.
    await app.renderScaleChosen;
    await new Promise((r) => setTimeout(r, 1000));
    const only = params.get("only")?.split(",");
    let body: string;
    try {
      const probe = { probeMs: app.probeMs, idleMs: app.probeIdleMs, lowMs: app.probeLowMs, renderDpr: app.view.renderDpr, nativeDpr: window.devicePixelRatio, note: app.renderNote };
      body = JSON.stringify({ label, ok: true, probe, ...(await bench.runAll(only)) });
    } catch (e) {
      body = JSON.stringify({ label, ok: false, error: String(e) });
    }
    const sink = params.get("sink") ?? "http://127.0.0.1:8790";
    await fetch(`${sink}/results?label=${encodeURIComponent(label)}`, { method: "POST", body });
    document.body.dataset.benchDone = "1";
  }
}

main().catch((e) => {
  console.error(e);
  fatal(errText(e));
});
