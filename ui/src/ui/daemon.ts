// The daemon status chip, bottom left of the status bar (docs/ui.md,
// "Daemon status"): connected (green: the daemon's version and the
// project), busy (amber: it is there but hasn't answered a check in time),
// connecting, or disconnected (red). Clicking it opens a popover
// with the server version, API, uptime and the address the page talks to.
//
// Disconnected in a browser, the page keeps what it has loaded, read-only,
// and offers Reconnect and the command that starts the daemon again (with
// the flags it ran with, when the daemon told an admin). In the desktop app
// (Tauri), the popover also starts, stops and restarts the app's own daemon
// and shows its log, through the shell's daemon_* commands (main.rs): the
// only Tauri IPC the UI uses, and only when it runs there.

import { Code, ConnectError } from "@connectrpc/connect";
import { Role, type Revkit } from "@revkit/api";
import { session } from "../api/client";
import { errText } from "../data/format";
import { toast } from "./dialogs";
import { h, overlayRoot, prefs } from "./dom";

export type DaemonState = "connecting" | "connected" | "busy" | "disconnected" | "restarting";

/** How long a restart may take before the chip says disconnected. */
const RESTART_MS = 90_000;
/** How long the daemon may leave checks unanswered before the chip says disconnected. */
const BUSY_MS = 60_000;

/** What GetServerInfo said, and when. */
interface Info {
  serverVersion: string;
  apiMajor: string;
  apiMinor: number;
  uptimeSeconds: number;
  at: number;
  launchArgs: string[];
  socketActivated: boolean;
  features: string[];
}

/** The desktop shell's view of its daemon (main.rs, DaemonStatus). */
export interface DesktopDaemon {
  /** The shell started this daemon (not REVKIT_DAEMON / REVKIT_UI_URL). */
  managed: boolean;
  running: boolean;
  pid: number | null;
  url: string | null;
  /** How the last one ended ("exit status: 1", "signal: 9"), if it did. */
  exit: string | null;
  logPath: string | null;
  /** The log's last lines. */
  logTail: string[];
  /** A fresh token, when the shell made one for a new address. */
  token?: string | null;
}

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

/** The shell's commands, when the page runs in the desktop app. */
function tauriInvoke(): Invoke | null {
  const t = (window as unknown as { __TAURI_INTERNALS__?: { invoke?: Invoke } }).__TAURI_INTERNALS__;
  return t && typeof t.invoke === "function" ? (cmd, args) => t.invoke!(cmd, args ?? {}) : null;
}

/** POSIX shell quoting for a copied command line. */
export function shellQuote(a: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`;
}

function fmtUptime(s: number): string {
  s = Math.max(0, Math.floor(s));
  const d = Math.floor(s / 86400);
  const hh = Math.floor((s % 86400) / 3600);
  const mm = Math.floor((s % 3600) / 60);
  if (d) return `${d} d ${hh} h`;
  if (hh) return `${hh} h ${mm} min`;
  if (mm) return `${mm} min ${s % 60} s`;
  return `${s} s`;
}

export interface DaemonStatusOptions {
  rk: Revkit;
  /** The daemon's base URL (same origin, or ?api=). */
  api: string;
  client: string;
  /** Called when the daemon is back after a disconnect (the page's own
   * reconnect: the subscription stream retries at once). */
  onReconnect?: () => void;
}

export class DaemonStatus {
  state: DaemonState = "connecting";
  info: Info | null = null;
  project = "";
  /** The page could not start (fatal): reload once the daemon is back. */
  reloadWhenBack = false;
  readonly desktop: Invoke | null = tauriInvoke();
  desktopState: DesktopDaemon | null = null;

  private chip: HTMLButtonElement;
  private label: HTMLSpanElement;
  private action: HTMLButtonElement;
  private pop: HTMLElement | null = null;
  private timer: number | undefined;
  /** When checks started timing out (state "busy"). */
  private busySince = 0;
  private tick: number | undefined;
  private probing: Promise<boolean> | null = null;
  private lastError = "";
  private busy = "";
  /** Lost since the last answer (a reconnect is due when it is back). */
  private down = false;
  /** A restart asked for (Date.now()), until the new daemon answers. */
  private restartAt = 0;
  /** The page's bundle when the restart was asked for (reload if it changed). */
  private restartBundle: string | null = null;
  private justRestarted = false;
  /** Other clients of this program, by name (the app's presence). */
  others: (() => string[]) | null = null;

  constructor(private o: DaemonStatusOptions) {
    this.label = h("span", { class: "st-daemon-text" }, "connecting");
    this.chip = h(
      "button",
      { id: "st-daemon", class: "st-daemon connecting", type: "button", "data-testid": "daemon-chip", "data-state": "connecting", "aria-haspopup": "dialog", title: "Daemon status", onclick: () => this.toggle() },
      h("i", { "aria-hidden": "true" }),
      this.label,
    );
    // Beside a red chip: Reconnect (browser) or Start daemon (desktop).
    this.action = h("button", { class: "btn st-daemon-action", type: "button", hidden: true, "data-testid": "daemon-action", onclick: () => void this.primary() });
    const bar = document.getElementById("statusbar");
    bar?.prepend(this.chip, this.action);
    // Known flags from an earlier visit, until the daemon says.
    try {
      const saved = JSON.parse(prefs.get(this.argsKey()) ?? "null") as { args: string[]; socket: boolean } | null;
      if (saved) this.info = { serverVersion: "", apiMajor: "", apiMinor: 0, uptimeSeconds: 0, at: 0, launchArgs: saved.args, socketActivated: saved.socket, features: [] };
    } catch {
      /* none */
    }
    document.body.dataset.daemon = "connecting";
  }

  private argsKey() {
    return `rk.daemonArgs:${this.o.api}`;
  }

  /** The address the page talks to, as typed in a browser. */
  get address(): string {
    return new URL(this.o.api, location.href).origin;
  }

  setProject(p: string) {
    this.project = p;
    this.render();
  }

  /** GetServerInfo answered (main.ts's first call, or a probe). */
  connected(r: { serverVersion: string; apiMajor: string; apiMinor: number; uptimeSeconds: bigint; launchArgs: string[]; socketActivated: boolean; features?: string[] }) {
    if (this.state === "restarting") {
      // The old daemon may answer once more before it goes: wait for one
      // that started after the restart was asked for.
      const fresh = Number(r.uptimeSeconds) * 1000 <= Date.now() - this.restartAt + 1000;
      if (!fresh) return this.setState("restarting");
      return void this.restarted(r);
    }
    const prevArgs = this.info?.launchArgs ?? [];
    this.info = {
      serverVersion: r.serverVersion,
      apiMajor: r.apiMajor,
      apiMinor: r.apiMinor,
      uptimeSeconds: Number(r.uptimeSeconds),
      at: Date.now(),
      // An answer without them (not an admin, an older daemon) keeps what we knew.
      launchArgs: r.launchArgs.length ? [...r.launchArgs] : prevArgs,
      socketActivated: r.socketActivated,
      features: [...(r.features ?? [])],
    };
    if (r.launchArgs.length || r.socketActivated) prefs.set(this.argsKey(), JSON.stringify({ args: this.info.launchArgs, socket: r.socketActivated }));
    this.lastError = "";
    this.setState("connected");
    if (this.reloadWhenBack) return location.reload();
    if (this.down) {
      this.down = false;
      toast(this.justRestarted ? "Daemon restarted" : "Daemon is back");
      this.justRestarted = false;
      this.o.onReconnect?.();
    }
  }

  /** A call could not reach the daemon. */
  failed(e: unknown) {
    this.lastError = errText(e);
    // A check that timed out reached a daemon too occupied to answer in
    // time: a long job (analysis in a new language, say) holds the
    // browser's few connections to it. That's busy, not gone, for up to
    // BUSY_MS; a refused or dropped connection is gone at once.
    if (e instanceof ConnectError && e.code === Code.DeadlineExceeded && (this.state === "connected" || this.state === "busy")) {
      if (this.state === "connected") this.busySince = Date.now();
      if (Date.now() - this.busySince < BUSY_MS) return this.setState("busy");
    }
    // Down for a restart: expected, until it takes too long.
    if (this.state === "restarting" && Date.now() - this.restartAt < RESTART_MS) return this.setState("restarting");
    if (this.state === "restarting") toast("The daemon didn't come back after the restart; see its log", { kind: "error", ms: 8000 });
    const was = this.state;
    this.down = true;
    this.setState("disconnected");
    if (was === "connected") toast("Lost the daemon: the page keeps what it has loaded, read-only, until it is back", { kind: "error", ms: 6000 });
    if (this.desktop) void this.refreshDesktop();
  }

  /** The subscription stream's state (Live): a drop is checked at once. */
  noteStream(s: string) {
    if (s === "reconnecting" && (this.state === "connected" || this.state === "busy" || this.state === "restarting")) void this.probe();
  }

  /** Asks the daemon; true when it answered. One at a time. */
  probe(): Promise<boolean> {
    if (this.probing) return this.probing;
    this.probing = (async () => {
      try {
        const r = await this.o.rk.meta.getServerInfo({ client: this.o.client }, { timeoutMs: 4000 });
        this.connected(r);
        return true;
      } catch (e) {
        this.failed(e);
        return false;
      } finally {
        this.probing = null;
      }
    })();
    return this.probing;
  }

  private setState(s: DaemonState) {
    this.state = s;
    document.body.dataset.daemon = s;
    // Checked every 15 s while connected, every 3 s while busy or not
    // connected, twice a second while restarting.
    clearTimeout(this.timer);
    this.timer = window.setTimeout(() => void this.probe(), s === "connected" ? 15000 : s === "restarting" ? 500 : 3000);
    this.render();
  }

  /** The command that starts this daemon again, and whether its flags are known. */
  startCommand(): { cmd: string; known: boolean } {
    const i = this.info;
    if (i?.socketActivated) return { cmd: "systemctl --user start revkit-daemon.service", known: true };
    if (i?.launchArgs.length) return { cmd: i.launchArgs.map(shellQuote).join(" "), known: true };
    const u = new URL(this.o.api, location.href);
    const port = u.port || (u.protocol === "https:" ? "443" : "80");
    return { cmd: `rk-daemon --http ${u.hostname}:${port}`, known: false };
  }

  private chipText(): string {
    switch (this.state) {
      case "connecting":
        return "connecting…";
      case "restarting":
        return "restarting…";
      case "busy":
        return "busy…";
      case "disconnected":
        return this.desktop && this.desktopState?.managed && !this.desktopState.running ? "daemon stopped" : "disconnected";
      case "connected": {
        // "rk-daemon 0.1.0 (git abc1234)" -> "rk-daemon 0.1.0"
        const v = (this.info?.serverVersion ?? "").replace(/\s*\(.*\)$/, "") || "rk-daemon";
        return this.project ? `${v} · ${this.project}` : v;
      }
    }
  }

  private render() {
    this.chip.className = `st-daemon ${this.state}`;
    this.chip.dataset.state = this.state;
    this.label.textContent = this.chipText();
    this.chip.title =
      this.state === "connected"
        ? `Connected to ${this.address}`
        : this.state === "busy"
          ? `The daemon at ${this.address} is busy (a long analysis, say): the page waits for it`
          : this.state === "connecting"
            ? `Connecting to ${this.address}`
            : this.state === "restarting"
              ? `The daemon at ${this.address} is restarting`
              : `Can't reach the daemon at ${this.address}`;
    const managed = !!(this.desktop && this.desktopState?.managed);
    const down = this.state === "disconnected";
    this.action.hidden = !down;
    this.action.textContent = managed && !this.desktopState!.running ? "Start daemon" : "Reconnect";
    this.action.disabled = !!this.busy;
    if (this.pop) this.fillPopover();
  }

  /** The red chip's button. */
  private async primary() {
    if (this.desktop && this.desktopState?.managed && !this.desktopState.running) return this.control("start");
    return this.reconnect();
  }

  async reconnect() {
    this.setState("connecting");
    await this.probe();
  }

  // ------------------------------------------------------------- popover --

  private toggle() {
    if (this.pop) return this.close();
    this.pop = h("div", { class: "popover daemon-pop", role: "dialog", "aria-label": "Daemon", "data-testid": "daemon-popover" });
    document.body.append(this.pop);
    this.fillPopover();
    if (this.desktop) void this.refreshDesktop();
    this.tick = window.setInterval(() => this.updateUptime(), 1000);
    // At once (the opening click's mousedown is over), not in a timer: a
    // background tab may run timers late.
    document.addEventListener("mousedown", this.outside, true);
    document.addEventListener("keydown", this.escape, true);
  }

  private outside = (e: MouseEvent) => {
    const t = e.target as Node;
    if (this.pop && !this.pop.contains(t) && !this.chip.contains(t)) this.close();
  };

  private escape = (e: KeyboardEvent) => {
    if (e.key === "Escape" && this.pop) {
      e.stopPropagation();
      this.close();
      this.chip.focus();
    }
  };

  close() {
    this.pop?.remove();
    this.pop = null;
    clearInterval(this.tick);
    document.removeEventListener("mousedown", this.outside, true);
    document.removeEventListener("keydown", this.escape, true);
  }

  private uptimeNow(): number | null {
    const i = this.info;
    if (!i || !i.at || this.state !== "connected") return null;
    return i.uptimeSeconds + (Date.now() - i.at) / 1000;
  }

  private updateUptime() {
    const el = this.pop?.querySelector("[data-testid=daemon-uptime]");
    const u = this.uptimeNow();
    if (el && u !== null) el.textContent = fmtUptime(u);
  }

  private fillPopover() {
    const pop = this.pop!;
    const i = this.info;
    const row = (k: string, v: string | Node, id?: string) => h("div", { class: "dp-row" }, h("span", { class: "dim" }, k), h("span", { class: "mono", "data-testid": id }, v));
    const head = h(
      "div",
      { class: "dp-head" },
      h("span", { class: `st-daemon-dot ${this.state}` }),
      h("strong", {}, "rk-daemon"),
      h("span", { class: "dim", "data-testid": "daemon-pop-state" }, this.state),
    );
    const rows: Node[] = [];
    const connected = this.state === "connected" || this.state === "busy";
    if (i?.serverVersion) rows.push(row("Server", i.serverVersion + (connected ? "" : " (last seen)"), "daemon-version"));
    if (i?.apiMajor) rows.push(row("API", `${i.apiMajor}.${i.apiMinor}`, "daemon-api"));
    const up = this.uptimeNow();
    if (up !== null) rows.push(row("Uptime", fmtUptime(up), "daemon-uptime"));
    rows.push(row("Address", this.address, "daemon-address"));
    if (this.project) rows.push(row("Project", this.project));
    if (i?.socketActivated) rows.push(h("div", { class: "dim" }, "Started by systemd on the first connection (socket activation)."));

    const body: Node[] = [head, ...rows];
    const ds = this.desktopState;
    if (this.desktop && ds?.managed) {
      body.push(this.desktopControls(ds));
    } else if (!connected && this.state !== "connecting") {
      body.push(this.browserHelp());
    } else if (this.desktop && ds && !ds.managed) {
      body.push(h("div", { class: "dim" }, "This daemon was not started by the app (REVKIT_DAEMON); start and stop it where it runs."));
    }
    if (this.state === "restarting") body.push(h("div", { class: "dim", "data-testid": "daemon-restarting" }, "Restarting: the page reconnects when the daemon is back."));
    else if (this.state === "busy")
      body.push(
        h(
          "div",
          { class: "dim", "data-testid": "daemon-busy" },
          `Busy for ${Math.round((Date.now() - this.busySince) / 1000)} s: it is running but hasn't answered a check in time (a long analysis, say). The page stays usable; what it asks for arrives when the daemon is done.`,
        ),
      );
    else if (connected && this.canRestart() && !(this.desktop && ds?.managed))
      body.push(
        h(
          "div",
          { class: "dp-actions" },
          h("button", { class: "btn", type: "button", disabled: !!this.busy, "data-testid": "daemon-restart-browser", title: "Save the projects, stop, and start rk-daemon again with the same command line", onclick: () => void this.restartDaemon() }, "Restart daemon…"),
        ),
      );
    pop.replaceChildren(...body);
    // Bottom left, above the status bar.
    const r = this.chip.getBoundingClientRect();
    pop.style.left = `${Math.max(8, r.left)}px`;
    pop.style.bottom = `${Math.max(8, innerHeight - r.top + 6)}px`;
    pop.style.top = "auto";
  }

  /** Disconnected in a browser: Reconnect, and how to start the daemon. */
  private browserHelp(): Node {
    const { cmd, known } = this.startCommand();
    const code = h("code", { class: "dp-cmd mono", "data-testid": "daemon-start-cmd" }, cmd);
    const copy = h("button", { class: "btn", type: "button", "data-testid": "daemon-copy", onclick: () => void this.copy(cmd, copy) }, "Copy");
    return h(
      "div",
      { class: "dp-down" },
      h("div", {}, `Can't reach the daemon at ${this.address}.`, this.lastError ? h("span", { class: "dim" }, ` (${this.lastError})`) : null),
      h("div", { class: "dim" }, "The page keeps what it has loaded, read-only. Start the daemon, then Reconnect."),
      h("div", { class: "dp-cmd-row" }, code, copy),
      known ? null : h("div", { class: "dim" }, "The flags it ran with are not known here (only admins see them): add your --project-dir and others."),
      this.info?.socketActivated ? h("div", { class: "dim" }, "With the socket enabled, Reconnect alone starts it again.") : null,
      h("div", { class: "dp-actions" }, h("button", { class: "btn primary", type: "button", "data-testid": "daemon-reconnect", onclick: () => void this.reconnect() }, "Reconnect")),
    );
  }

  private async copy(text: string, btn: HTMLElement) {
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch {
      // No clipboard permission (an insecure origin): select it for Ctrl+C.
      const code = this.pop?.querySelector("[data-testid=daemon-start-cmd]");
      if (code) {
        const range = document.createRange();
        range.selectNodeContents(code);
        const sel = getSelection();
        sel?.removeAllRanges();
        sel?.addRange(range);
        ok = document.execCommand?.("copy") ?? false;
      }
    }
    btn.textContent = ok ? "Copied" : "Press Ctrl+C";
    btn.dataset.copied = ok ? "1" : "0";
    setTimeout(() => (btn.textContent = "Copy"), 1500);
  }

  // ------------------------------------------------------------ restart --

  /** The daemon can restart itself (feature daemon-restart), and we are an admin. */
  canRestart(): boolean {
    if (!this.info?.features.includes("daemon-restart")) return false;
    return !session.authEnabled || session.identity?.role === Role.ADMIN;
  }

  /** The page's own script and stylesheet (Vite's hashed names): its build. */
  private static bundleOf(html: string): string {
    return [...html.matchAll(/<(?:script|link)\b[^>]*\b(?:src|href)="([^"]*\/assets\/[^"]+)"/g)].map((m) => m[1]).sort().join(" ");
  }

  /** The bundle the daemon serves now, when it serves this page (same origin). */
  private async servedBundle(): Promise<string | null> {
    if (new URL(this.o.api, location.href).origin !== location.origin || !location.protocol.startsWith("http")) return null;
    try {
      const r = await fetch(new URL("/", location.href), { cache: "no-store" });
      return r.ok ? DaemonStatus.bundleOf(await r.text()) : null;
    } catch {
      return null;
    }
  }

  /** Restart daemon…: say what it drops, ask, restart, follow it back. */
  async restartDaemon() {
    if (this.busy) return;
    this.close();
    let dry: { mode: string; openStreams: number };
    try {
      dry = await this.o.rk.meta.restartDaemon({ dryRun: true });
    } catch (e) {
      return void toast(`Can't restart the daemon: ${errText(e)}`, { kind: "error" });
    }
    // Our own update stream is one of those open.
    const own = document.body.dataset.live === "live" ? 1 : 0;
    const others = Math.max(0, dry.openStreams - own);
    const names = this.others?.() ?? [];
    if (!(await this.confirmRestart(dry.mode, others, names))) return;
    this.restartBundle = DaemonStatus.bundleOf(document.documentElement.outerHTML);
    try {
      await this.o.rk.meta.restartDaemon({ reason: `from the web UI${session.identity ? ` (${session.identity.name})` : ""}` });
    } catch (e) {
      return void toast(`Can't restart the daemon: ${errText(e)}`, { kind: "error" });
    }
    this.restartAt = Date.now();
    this.down = true;
    this.setState("restarting");
    toast(dry.mode === "exit" ? "Restarting: the daemon exits, and systemd starts it again when the page reconnects" : "Restarting the daemon…");
  }

  /** The new daemon answered. */
  private async restarted(r: Parameters<DaemonStatus["connected"]>[0]) {
    this.restartAt = 0;
    // A new UI build (the daemon was updated): load it.
    const served = await this.servedBundle();
    if (served && this.restartBundle && served !== this.restartBundle) {
      document.body.dataset.daemon = "reloading";
      return location.reload();
    }
    this.state = "connected";
    this.justRestarted = true;
    this.connected(r);
  }

  private confirmRestart(mode: string, others: number, names: string[]): Promise<boolean> {
    return new Promise((resolve) => {
      const restore = document.activeElement as HTMLElement | null;
      const done = (ok: boolean) => {
        back.remove();
        restore?.focus({ preventScroll: true });
        resolve(ok);
      };
      const ok = h("button", { class: "btn primary", type: "button", "data-testid": "restart-confirm-ok", onclick: () => done(true) }, "Restart");
      const cancel = h("button", { class: "btn", type: "button", "data-testid": "restart-confirm-cancel", onclick: () => done(false) }, "Cancel");
      const who = names.length ? ` (${[...new Set(names)].slice(0, 6).join(", ")}${names.length > 6 ? ", …" : ""} on this program)` : "";
      const box = h(
        "div",
        { class: "modal restart-confirm", role: "alertdialog", "aria-modal": "true", tabindex: "-1", "aria-label": "Restart the daemon?", "data-testid": "restart-confirm" },
        h("div", { class: "modal-title" }, "Restart the daemon?"),
        h(
          "p",
          {},
          mode === "exit"
            ? "rk-daemon saves its projects, stops its workers and scripts, and exits; systemd starts it again (socket activation) when this page reconnects."
            : "rk-daemon saves its projects, stops its workers and scripts, and starts again with the same command line. This page reconnects by itself, and reloads if the daemon now serves a newer UI.",
        ),
        others > 0
          ? h("p", { class: "error", "data-testid": "restart-others" }, `${others} other connection${others === 1 ? "" : "s"}${who} will be dropped: other tabs and windows, agents (MCP, the SDK) and running scripts lose the daemon for a moment and must reconnect.`)
          : h("p", { class: "dim", "data-testid": "restart-others" }, "No other client is following the daemon now (no other tab, window or agent with an update stream)."),
        h("div", { class: "dp-actions" }, h("span", { class: "spacer" }), cancel, ok),
      );
      const back: HTMLElement = h("div", { class: "backdrop" }, box);
      box.addEventListener("keydown", (e) => {
        e.stopPropagation();
        if (e.key === "Escape") done(false);
      });
      back.addEventListener("mousedown", (e) => {
        if (e.target === back) done(false);
      });
      overlayRoot().append(back);
      cancel.focus();
    });
  }

  // ---------------------------------------------------- desktop (Tauri) --

  async refreshDesktop() {
    if (!this.desktop) return;
    try {
      this.desktopState = await this.desktop<DesktopDaemon>("daemon_status");
    } catch (e) {
      console.warn("daemon_status", e);
    }
    this.render();
  }

  private desktopControls(ds: DesktopDaemon): Node {
    const btn = (label: string, what: "start" | "stop" | "restart", primary = false, disabled = false) =>
      h("button", { class: `btn${primary ? " primary" : ""}`, type: "button", disabled: disabled || !!this.busy, "data-testid": `daemon-${what}`, onclick: () => void this.control(what) }, this.busy === what ? `${label}…` : label);
    const stopped = !ds.running;
    const parts: Node[] = [];
    if (stopped) {
      parts.push(h("div", { class: "error" }, ds.exit ? `The daemon stopped (${ds.exit}).` : "The daemon is not running."));
      if (ds.logTail.length) parts.push(h("pre", { class: "dp-log mono", "data-testid": "daemon-log-tail" }, ds.logTail.join("\n")));
    } else if (ds.pid) {
      parts.push(h("div", { class: "dp-row" }, h("span", { class: "dim" }, "Process"), h("span", { class: "mono" }, `pid ${ds.pid}`)));
    }
    parts.push(
      h(
        "div",
        { class: "dp-actions" },
        btn("Start daemon", "start", stopped, !stopped),
        btn("Stop", "stop", false, stopped),
        btn("Restart", "restart"),
        h("button", { class: "btn", type: "button", "data-testid": "daemon-log", onclick: () => void this.showLog() }, "Show daemon log"),
      ),
    );
    return h("div", { class: "dp-desktop" }, ...parts);
  }

  /** Start, stop or restart the app's daemon. */
  async control(what: "start" | "stop" | "restart") {
    if (!this.desktop || this.busy) return;
    this.busy = what;
    this.render();
    try {
      const ds = await this.desktop<DesktopDaemon>(`daemon_${what}`);
      this.desktopState = ds;
      if (what === "stop") {
        this.failed(new Error("stopped from the app"));
      } else if (ds.url && new URL(ds.url).origin !== this.address) {
        // Another port this time: the page follows it (with the token for it).
        if (ds.token) prefs.set(`rk.session:${new URL(ds.url).origin}`, ds.token);
        const u = new URL(location.href);
        u.searchParams.set("api", ds.url);
        location.href = u.toString();
        return;
      } else {
        await this.reconnect();
      }
    } catch (e) {
      toast(`Daemon: ${errText(e)}`, { kind: "error" });
      await this.refreshDesktop();
    } finally {
      this.busy = "";
      this.render();
    }
  }

  private async showLog() {
    if (!this.desktop) return;
    let text = "";
    let path = "";
    try {
      const r = await this.desktop<{ path: string; text: string }>("daemon_log");
      text = r.text;
      path = r.path;
    } catch (e) {
      text = errText(e);
    }
    const pre = h("pre", { class: "dp-log-full mono", "data-testid": "daemon-log-text" }, text || "(empty)");
    const back: HTMLDivElement = h("div", { class: "backdrop top" });
    const close = () => back.remove();
    back.addEventListener("click", (e) => e.target === back && close());
    back.append(
      h(
        "div",
        { class: "modal daemon-log", role: "dialog", "aria-label": "Daemon log" },
        h("div", { class: "modal-title" }, "Daemon log"),
        path ? h("div", { class: "modal-hint mono" }, path) : null,
        pre,
        h("div", { class: "dp-actions" }, h("button", { class: "btn", type: "button", onclick: close }, "Close")),
      ),
    );
    back.addEventListener("keydown", (e) => e.key === "Escape" && close());
    document.getElementById("overlays")?.append(back);
    pre.scrollTop = pre.scrollHeight;
    (back.querySelector("button") as HTMLButtonElement | null)?.focus();
  }
}
