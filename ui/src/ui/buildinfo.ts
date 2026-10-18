// Build info (api_minor 88, feature "build-info"; docs/build-info.md and
// docs/ui.md "Build info"): what toolchain built a program and from what,
// as the file says (QueryService.GetBuildInfo). Go: the version, the main
// module, the build settings and the dependency modules (versions, sums,
// replacements) and its function table (pclntab). Rust: cargo-auditable's crates and their dependency edges,
// the rustc version and commits. A filter narrows the module and crate
// tables; Copy copies the Go module text as `go version -m` prints it.

import type { GetBuildInfoResponse, Revkit } from "@revkit/api";
import { errText } from "../data/format";
import { toast } from "./dialogs";
import { h, overlayRoot } from "./dom";

export const BUILD_INFO_FEATURE = "build-info";

/** One line for a details panel: "Go go1.22.3 · 14 modules", "Rust · 52 crates (rustc 1.79.0)", "none". */
export function buildInfoSummary(r: GetBuildInfoResponse): string {
  const parts: string[] = [];
  if (r.go) parts.push(`Go ${r.go.goVersion} · ${r.go.deps.length} module${r.go.deps.length === 1 ? "" : "s"}`);
  else if (r.goPclntab) parts.push(`Go (pclntab ${r.goPclntab.layout} layout) · ${r.goPclntab.functionsRead} functions`);
  const rustc = r.rustcVersion.match(/^rustc version (\S+)/)?.[1];
  if (r.rust) parts.push(`Rust · ${r.rust.packages.length} crate${r.rust.packages.length === 1 ? "" : "s"}${rustc ? ` (rustc ${rustc})` : ""}`);
  else if (rustc) parts.push(`Rust (rustc ${rustc})`);
  else if (r.rustcCommits.length) parts.push("Rust");
  return parts.join(" · ") || (r.warnings.length ? `unreadable: ${r.warnings[0]}` : "none");
}

const hex = (v: bigint) => "0x" + v.toString(16);

export function showBuildInfoDialog(rk: Revkit, o: { programId: string; programName: string }) {
  const restore = document.activeElement as HTMLElement | null;
  const body = h("div", { class: "bi-body", "data-testid": "bi-body" }, h("div", { class: "dim" }, "Loading…"));
  const filter = h("input", { class: "filter bi-filter", spellcheck: "false", placeholder: "Filter modules and crates", "aria-label": "Filter modules and crates", "data-testid": "bi-filter" }) as HTMLInputElement;
  const close = () => {
    backdrop.remove();
    restore?.focus({ preventScroll: true });
  };
  const box = h(
    "div",
    { class: "modal bi", role: "dialog", tabindex: "-1", "aria-label": `Build info of ${o.programName}`, "data-testid": "bi-dialog" },
    h("div", { class: "libs-head" }, h("div", { class: "modal-title" }, `Build info of ${o.programName}`), h("span", { class: "spacer" }), filter, h("button", { class: "btn", type: "button", "data-testid": "bi-close", onclick: close, text: "Close" })),
    body,
    h("div", { class: "modal-hint" }, "From the file: Go's .go.buildinfo and pclntab, cargo-auditable's .dep-v0, rustc's markers · Esc closes"),
  );
  const backdrop = h("div", { class: "backdrop" }, box);
  box.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      close();
    }
  });
  backdrop.addEventListener("mousedown", (e) => {
    if (e.target === backdrop) close();
  });

  const fields = (rows: [string, string | Node, string?][]) =>
    h("dl", { class: "bi-fields" }, ...rows.flatMap(([k, v, testid]) => [h("dt", {}, k), h("dd", { class: "mono", "data-testid": testid, title: typeof v === "string" ? v : undefined }, v)]));
  const table = (testid: string, head: string[], rows: HTMLElement[], cls = "") =>
    h("div", { class: "bi-table", role: "table", "data-testid": testid }, h("div", { class: `bi-row bi-th ${cls}`, role: "row" }, ...head.map((c) => h("span", { role: "columnheader" }, c))), ...rows);
  const cell = (text: string, cls = "mono") => h("span", { class: cls, role: "cell", title: text }, text);

  // Go's function table (api_minor 93, feature "go-pclntab"; docs/go.md):
  // what named the functions at import.
  const pclntabRow = (t: NonNullable<GetBuildInfoResponse["goPclntab"]>): [string, string, string] => [
    "Function table",
    `${t.functionsRead} functions, ${t.fileCount} files · pclntab ${t.layout} layout at ${hex(t.address?.offset ?? 0n)} (${t.foundBy === "scan" ? "found by its magic" : t.foundBy})`,
    "bi-go-pclntab",
  ];

  const render = (r: GetBuildInfoResponse) => {
    const parts: HTMLElement[] = [];
    if (r.go) {
      const g = r.go;
      const settings = new Map(g.settings.map((s) => [s.key, s.value]));
      const vcs = settings.get("vcs.revision");
      const copy = h("button", {
        class: "btn small",
        type: "button",
        "data-testid": "bi-copy-go",
        title: "Copy the module text as `go version -m` prints it",
        onclick: () => void navigator.clipboard?.writeText(`${g.goVersion}\n${g.moduleText}`).then(() => toast("Copied the Go build info"), (e) => toast(errText(e), { kind: "error" })),
        text: "Copy",
      });
      parts.push(
        h("div", { class: "bi-section-head" }, h("h3", {}, "Go"), copy),
        fields([
          ["Go version", g.goVersion, "bi-go-version"],
          ["Main module", g.main ? `${g.main.path} ${g.main.version}` : "—", "bi-go-main"],
          ["Package", g.path || "—"],
          ...(settings.has("GOOS") ? [["Target", `${settings.get("GOOS")}/${settings.get("GOARCH") ?? "?"}`] as [string, string]] : []),
          ...(vcs ? [["Revision", `${vcs}${settings.get("vcs.modified") === "true" ? " (modified)" : ""}${settings.get("vcs.time") ? ` · ${settings.get("vcs.time")}` : ""}`] as [string, string]] : []),
          ["Format", `${g.format === "inline" ? "Go 1.18+ (inline strings)" : "before Go 1.18 (pointers)"} at ${hex(g.address?.offset ?? 0n)}`],
          ...(r.goPclntab ? [pclntabRow(r.goPclntab)] : []),
        ]),
      );
      if (g.settings.length)
        parts.push(
          h("details", { class: "bi-details", open: true }, h("summary", {}, `Build settings (${g.settings.length})`), table("bi-go-settings", ["Setting", "Value"], g.settings.map((s) => h("div", { class: "bi-row bi-kv", role: "row", "data-filter": `${s.key} ${s.value}`.toLowerCase() }, cell(s.key), cell(s.value))), "bi-kv")),
        );
      parts.push(
        h(
          "details",
          { class: "bi-details", open: true },
          h("summary", {}, `Dependencies (${g.deps.length})`),
          g.deps.length
            ? table(
                "bi-go-deps",
                ["Module", "Version", "Replaced by", "Sum"],
                g.deps.map((d) => {
                  const rep = d.replacement ? [d.replacement.path, d.replacement.version].filter(Boolean).join(" ") : "";
                  return h("div", { class: "bi-row bi-dep", role: "row", "data-testid": "bi-go-dep", "data-filter": `${d.path} ${d.version} ${rep}`.toLowerCase() }, cell(d.path), cell(d.version), cell(rep || "—", rep ? "mono" : "dim"), cell(d.sum || "—", d.sum ? "mono dim" : "dim"));
                }),
              )
            : h("div", { class: "dim" }, "No dependency modules (only the standard library)."),
        ),
      );
      if (g.unparsed.length) parts.push(h("div", { class: "bi-warn" }, `Lines not understood: ${g.unparsed.join(" · ")}`));
    } else if (r.goPclntab) {
      // No build info (removed, or a Go before 1.13), but the function table.
      parts.push(h("div", { class: "bi-section-head" }, h("h3", {}, "Go")), fields([pclntabRow(r.goPclntab)]));
    }
    for (const w of r.goPclntab?.warnings ?? []) parts.push(h("div", { class: "bi-warn" }, `Function table: ${w}`));
    if (r.rust || r.rustcVersion || r.rustcCommits.length) {
      parts.push(h("div", { class: "bi-section-head" }, h("h3", {}, "Rust")));
      const root = r.rust?.root !== undefined ? r.rust.packages[r.rust.root] : undefined;
      parts.push(
        fields([
          ...(root ? [["Crate", `${root.name} ${root.version}`, "bi-rust-root"] as [string, string, string]] : []),
          ...(r.rustcVersion ? [["rustc", r.rustcVersion.replace(/^rustc version /, ""), "bi-rustc"] as [string, string, string]] : []),
          ...(r.rustcCommits.length ? [["rustc commit", r.rustcCommits.join(", ")] as [string, string]] : []),
        ]),
      );
      if (r.rust) {
        const pk = r.rust.packages;
        parts.push(
          h(
            "details",
            { class: "bi-details", open: true },
            h("summary", {}, `Crates (${pk.length}, cargo-auditable)`),
            table(
              "bi-rust-crates",
              ["Crate", "Version", "Source", "Depends on"],
              pk.map((p) => {
                const deps = p.dependencies.map((i) => pk[i]?.name ?? `#${i}`).join(", ");
                return h(
                  "div",
                  { class: "bi-row bi-dep" + (p.root ? " root" : ""), role: "row", "data-testid": "bi-rust-crate", "data-filter": `${p.name} ${p.version} ${p.source}`.toLowerCase() },
                  cell(p.name + (p.kind === "build" ? " (build)" : "")),
                  cell(p.version),
                  cell(p.source, "dim"),
                  cell(deps || "—", deps ? "mono" : "dim"),
                );
              }),
            ),
          ),
        );
      } else {
        parts.push(h("div", { class: "dim" }, "No dependency list: built without cargo auditable."));
      }
    }
    for (const w of r.warnings) parts.push(h("div", { class: "bi-warn", "data-testid": "bi-warning" }, w));
    if (!parts.length) parts.push(h("div", { class: "dim", "data-testid": "bi-none" }, "No build metadata in this file: no Go build info, no cargo-auditable dependency list, no rustc markers."));
    body.replaceChildren(...parts);
  };
  filter.addEventListener("input", () => {
    const q = filter.value.trim().toLowerCase();
    for (const row of body.querySelectorAll<HTMLElement>(".bi-row[data-filter]")) row.hidden = !!q && !row.dataset.filter!.includes(q);
  });
  overlayRoot().append(backdrop);
  box.focus();
  void rk.queries.getBuildInfo({ programId: o.programId }).then(render, (e) => body.replaceChildren(h("div", { class: "bi-warn" }, errText(e))));
}
