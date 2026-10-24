// The decomp knowledge base (api_minor 105, feature "decomp-kb"; docs/decomp-kb.md
// and docs/ui.md "Decomp knowledge base"): File → Apply decomp knowledge base…
// picks a KB directory on the daemon's host, matches the program (or every
// program of its folder: a game's modules) against it
// (ProjectService.ApplyDecompKb), and lists the matches by kind: exact
// (the name and the verbatim source), candidates (same instructions, other
// constants), near (BSim's closest KB function, its source as a starting
// scratch, with the similarity and the instruction diff) and ambiguous.
// Selecting a match shows its source and diff. Apply names renames the
// exact matches with placeholder names; Export… writes the symbols.txt
// changes, the matched sources and the scratches to a folder on the host.

import type { ApplyDecompKbResponse, DecompKbMatch, Revkit } from "@revkit/api";
import { userProvenance } from "../api/client";
import { errText } from "../data/format";
import { toast } from "./dialogs";
import { h, overlayRoot } from "./dom";
import { browseHost } from "./hostfiles";

export const DECOMP_KB_FEATURE = "decomp-kb";

const hex = (v: bigint) => "0x" + v.toString(16).padStart(8, "0");

export interface DecompKbOptions {
  rk: Revkit;
  projectId: string;
  /** The program the dialog starts from; its folder is the game. */
  programId: string;
  onOpen: (programId: string, address: bigint) => void;
  /** Called after names were applied (the program's revision), to let the views catch up. */
  onApplied?: (revision: bigint) => Promise<unknown>;
}

/** The kind a match is listed under. */
export function matchKind(m: DecompKbMatch): "exact" | "call" | "candidate" | "near" | "ambiguous" {
  if (m.verdict === "exact" && m.reason.startsWith("several")) return "ambiguous";
  if (m.verdict === "near") return "near";
  if (m.verdict === "call") return "call";
  if (m.verdict === "candidate") return "candidate";
  return "exact";
}

const KINDS: { kind: ReturnType<typeof matchKind>; title: string }[] = [
  { kind: "exact", title: "Exact" },
  { kind: "call", title: "Through their callers" },
  { kind: "candidate", title: "Candidates" },
  { kind: "near", title: "Near (BSim)" },
  { kind: "ambiguous", title: "Ambiguous" },
];

/** File → Apply decomp knowledge base…: choose the KB, then the matches. */
export async function applyDecompKbDialog(o: DecompKbOptions) {
  const kbPath = await browseHost(o.rk, { title: "The decomp knowledge base's folder (kb.json)", folders: true, remember: "rk.decompkb.lastDir" });
  if (!kbPath) return;
  // The game: the program's folder, when it has one.
  let folderId = "";
  let folderPath = "";
  try {
    const lp = await o.rk.projects.listPrograms({ projectId: o.projectId });
    const me = lp.programs.find((p) => p.programId === o.programId);
    folderId = me?.folderId ?? "";
    folderPath = lp.folders.find((f) => f.folderId === folderId)?.path ?? "";
  } catch {
    // This program alone.
  }
  const restore = document.activeElement as HTMLElement | null;
  const scope = h("select", { class: "input small", "data-testid": "kb-scope", "aria-label": "Programs" },
    h("option", { value: "program" }, "This program"),
    ...(folderId ? [h("option", { value: "folder", selected: true }, `Its folder ${folderPath || ""} (the game's modules)`)] : []),
  ) as HTMLSelectElement;
  const near = h("input", { type: "checkbox", checked: true, "data-testid": "kb-near" }) as HTMLInputElement;
  const run = h("button", { class: "btn small", type: "button", "data-testid": "kb-run", text: "Match" }) as HTMLButtonElement;
  const applyBtn = h("button", { class: "btn small primary", type: "button", disabled: true, "data-testid": "kb-apply", text: "Apply names" }) as HTMLButtonElement;
  const exportBtn = h("button", { class: "btn small", type: "button", disabled: true, "data-testid": "kb-export", text: "Export…" }) as HTMLButtonElement;
  const body = h("div", { class: "bi-body", "data-testid": "kb-body" }, h("div", { class: "dim" }, "Working…"));
  const detail = h("pre", { class: "mono nds-pre kb-detail", "data-testid": "kb-detail", hidden: true });
  const close = () => {
    backdrop.remove();
    restore?.focus({ preventScroll: true });
  };
  const box = h(
    "div",
    { class: "modal bi nds kb", role: "dialog", tabindex: "-1", "aria-label": "Apply decomp knowledge base", "data-testid": "kb-dialog" },
    h("div", { class: "libs-head" }, h("div", { class: "modal-title" }, "Apply decomp knowledge base"), h("span", { class: "spacer" }), exportBtn, applyBtn, h("button", { class: "btn", type: "button", "data-testid": "kb-close", onclick: () => close(), text: "Close" })),
    h("div", { class: "kb-opts" }, h("span", { class: "mono dim", title: kbPath }, kbPath), scope, h("label", { class: "kb-check" }, near, " Near matches (BSim)"), run),
    body,
    detail,
    h("div", { class: "modal-hint" }, "Exact: same Function ID hashes, the name and verbatim source · Through callers: called where the KB's caller calls it · Candidate: same instructions, other constants · Near: BSim's closest KB function as a starting scratch · Esc closes"),
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
  overlayRoot().append(backdrop);
  box.focus();

  let applied = false;
  const request = (extra: { apply?: boolean; exportDir?: string }) => ({
    projectId: o.projectId,
    kbPath,
    programIds: scope.value === "folder" ? [] : [o.programId],
    folderId: scope.value === "folder" ? folderId : "",
    near: near.checked,
    apply: extra.apply ?? false,
    exportDir: extra.exportDir ?? "",
    provenance: userProvenance("Apply decomp knowledge base"),
  });
  const showDetail = (m: DecompKbMatch) => {
    const f = m.functions[0];
    const lines: string[] = [];
    if (f) {
      lines.push(`${f.name || f.symbol}  (${f.game} ${f.module} ${hex(f.address)}${f.unit ? ", " + f.unit : ""})`);
      if (f.compiler || f.flags) lines.push(`matches with ${f.compiler}${f.flags ? ", " + f.flags : ""}${f.status ? " (" + f.status + ")" : ""}`);
      if (m.verdict === "near") lines.push(`similarity ${m.similarity.toFixed(3)}, confidence ${m.confidence.toFixed(1)}`);
      if (m.functions.length > 1) lines.push(`also: ${m.functions.slice(1, 6).map((x) => x.symbol).join(", ")}`);
      if (m.reason) lines.push(m.reason);
      lines.push("", f.text || "(no source text in the KB)");
    }
    if (m.diff) lines.push("", "Instructions, the KB function's (-) to this one's (+):", m.diff);
    detail.textContent = lines.join("\n");
    detail.hidden = false;
  };
  const render = (r: ApplyDecompKbResponse) => {
    const groups = KINDS.map(({ kind, title }) => ({ kind, title, items: r.matches.filter((m) => matchKind(m) === kind) }));
    const sections = groups
      .filter((g) => g.items.length)
      .map((g) =>
        h(
          "details",
          { class: "bi-details kb-group", open: g.kind !== "ambiguous", "data-testid": `kb-group-${g.kind}` },
          h("summary", {}, `${g.title} (${g.items.length})`),
          h(
            "div",
            { class: "bi-table", role: "table" },
            h("div", { class: "bi-row kb-row bi-th", role: "row" }, ...["Address", "Now", "KB function", g.kind === "near" ? "Similarity" : "Unit", ""].map((c) => h("span", { role: "columnheader" }, c))),
            ...g.items.slice(0, 2000).map((m) => {
              const f = m.functions[0];
              const at = m.address?.offset ?? 0n;
              return h(
                "div",
                { class: "bi-row kb-row", role: "row", tabindex: "0", "data-testid": `kb-match-${g.kind}`, "data-address": hex(at), onclick: () => showDetail(m), onkeydown: (e: Event) => { if ((e as KeyboardEvent).key === "Enter") showDetail(m); } },
                h("span", { class: "mono", role: "cell" }, hex(at)),
                h("span", { class: "mono", role: "cell", title: m.currentName }, m.currentName),
                h("span", { class: "mono", role: "cell", title: f ? `${f.symbol} (${f.game} ${f.module})` : "" }, f ? (f.anonymous ? `${f.name} (source)` : f.name || f.symbol) : "—"),
                h("span", { class: "mono", role: "cell", title: f?.unit ?? "" }, g.kind === "near" ? m.similarity.toFixed(3) : f?.unit || "—"),
                h("span", { role: "cell" }, m.applied ? h("span", { class: "dim" }, "applied") : h("button", { class: "btn small", type: "button", onclick: (e: Event) => { e.stopPropagation(); close(); o.onOpen(m.programId, at); }, text: "Go" })),
              );
            }),
          ),
        ),
      );
    body.replaceChildren(
      h("div", { "data-testid": "kb-summary" }, `${r.hashed} functions hashed: ${r.exact} exact, ${r.byCall} through their callers, ${r.candidates} candidates, ${r.near} near${r.ambiguous ? `, ${r.ambiguous} ambiguous` : ""}${r.applied ? `; ${r.applied} applied` : ""}`),
      ...(sections.length ? sections : [h("div", { class: "dim" }, "No matches.")]),
      ...(r.warnings.length ? [h("details", { class: "bi-details" }, h("summary", {}, `${r.warnings.length} warning${r.warnings.length === 1 ? "" : "s"}`), h("pre", { class: "mono nds-pre" }, r.warnings.join("\n")))] : []),
    );
    applyBtn.disabled = applied || r.exact + r.byCall === 0;
    exportBtn.disabled = r.matches.length === 0;
  };
  const match = async () => {
    run.disabled = true;
    detail.hidden = true;
    body.replaceChildren(h("div", { class: "dim" }, near.checked ? "Matching (near matches decompile each function left)…" : "Matching…"));
    try {
      render(await o.rk.projects.applyDecompKb(request({ apply: applied })));
    } catch (e) {
      body.replaceChildren(h("div", { class: "error", "data-testid": "kb-error" }, errText(e)));
    } finally {
      run.disabled = false;
    }
  };
  run.onclick = () => void match();
  applyBtn.onclick = async () => {
    applyBtn.disabled = true;
    try {
      const r = await o.rk.projects.applyDecompKb(request({ apply: true }));
      applied = true;
      render(r);
      toast(`Applied ${r.applied} match${r.applied === 1 ? "" : "es"} from the knowledge base`);
      if (r.snapshot && o.programId) await o.onApplied?.(r.snapshot.revision).catch(() => undefined);
    } catch (e) {
      toast(errText(e), { kind: "error" });
      applyBtn.disabled = false;
    }
  };
  exportBtn.onclick = async () => {
    const dir = await browseHost(o.rk, { title: "Export the matches to a folder (symbols.txt, src/, scratch/)", folders: true, remember: "rk.decompkb.exportDir" });
    if (!dir) return;
    exportBtn.disabled = true;
    try {
      const r = await o.rk.projects.applyDecompKb(request({ apply: applied, exportDir: dir }));
      render(r);
      const x = r.exported;
      toast(x ? `Exported ${x.files.length} file${x.files.length === 1 ? "" : "s"} to ${x.dir}: ${x.sources} units, ${x.scratches} scratches, ${x.symbolsFiles} symbols.txt` : "Nothing exported");
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      exportBtn.disabled = false;
    }
  };
  await match();
}
