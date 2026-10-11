// About revkit: this UI's version (VERSION at the source root, baked in by
// vite.config.ts) and the daemon's (GetServerInfo), with where to read more.

import type { Revkit } from "@revkit/api";
import { CLIENT_NAME } from "../api/client";
import { errText } from "../data/format";
import { h, overlayRoot } from "./dom";

export const UI_VERSION = `${__REVKIT_VERSION__} (git ${__REVKIT_GIT_SHA__})`;

// Styled inline, so the About box adds nothing to style.css.
const LIST = "display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; margin: 0;";
const VALUE = "margin: 0; overflow-wrap: anywhere;";

export async function showAbout(rk: Revkit): Promise<void> {
  const daemonUrl = new URLSearchParams(location.search).get("api") ?? location.origin;
  let server: Node;
  try {
    const info = await rk.meta.getServerInfo({ client: CLIENT_NAME });
    server = h(
      "dl",
      { class: "about-list", style: LIST },
      h("dt", {}, "Daemon"),
      h("dd", { class: "mono", style: VALUE, "data-testid": "about-server" }, info.serverVersion || "(unknown)"),
      h("dt", {}, "API"),
      h("dd", { class: "mono", style: VALUE }, `revkit.${info.apiMajor} minor ${info.apiMinor}`),
      h("dt", {}, "Features"),
      h("dd", { class: "mono dim", style: VALUE + " font-size: 11px;" }, info.features.join(", ")),
      h("dt", {}, "URL"),
      h("dd", { class: "mono", style: VALUE }, daemonUrl),
    );
  } catch (e) {
    server = h("p", { class: "ask-error" }, `Can't reach the daemon: ${errText(e)}`);
  }
  const close = () => {
    backdrop.remove();
    restore?.focus({ preventScroll: true });
  };
  const restore = document.activeElement as HTMLElement | null;
  const box = h(
    "div",
    { class: "modal about", role: "dialog", tabindex: "-1", "aria-label": "About revkit", "data-testid": "about" },
    h("div", { class: "modal-title" }, "About revkit"),
    h("dl", { class: "about-list", style: LIST }, h("dt", {}, "Web UI"), h("dd", { class: "mono", style: VALUE, "data-testid": "about-ui" }, UI_VERSION)),
    server,
    h(
      "p",
      { class: "dim" },
      "revkit links Ghidra's decompiler and SLEIGH engine (Apache-2.0, National Security Agency). " +
        "Getting started, the API and third-party licenses: docs/getting-started.md and THIRD_PARTY_NOTICES.md " +
        "(share/doc/revkit in a package).",
    ),
    h("div", { class: "modal-hint" }, "Esc or click outside to close"),
  );
  const backdrop = h("div", { class: "backdrop" }, box);
  box.addEventListener("keydown", (e) => {
    e.stopPropagation();
    if (e.key === "Escape" || e.key === "Enter") close();
  });
  backdrop.addEventListener("mousedown", (e) => {
    if (e.target === backdrop) close();
  });
  overlayRoot().append(backdrop);
  box.focus();
}
