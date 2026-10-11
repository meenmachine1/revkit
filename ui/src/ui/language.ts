// Change language… (api_minor 73, feature "set-language"; docs/ui.md
// "Changing the language"): which variant of the program's processor fits
// its code (CompareLanguages: every variant in the program's byte order
// swept over samples of its executable bytes, with what auto-detection
// picks), and switching to one in place (SetProgramLanguage: same bytes and
// addresses, every edit kept, analysis run again; one undo step). Another
// language of the processor (the other byte order, say) can be picked from
// the list below the table.

import type { AvailableLanguage, CompareLanguagesResponse, LanguageFit, Revkit } from "@revkit/api";
import { userProvenance } from "../api/client";
import { errText } from "../data/format";
import { toast } from "./dialogs";
import { h, overlayRoot } from "./dom";

export const LANGUAGE_FEATURE = "set-language";

export interface LanguageOptions {
  programId: string;
  programName: string;
  /** Records the change for Ctrl+Z / the history. */
  recordUndo: (label: string, seqs: bigint[]) => void;
  undo: () => void;
  /** Waits until the views have caught up with a revision. */
  settle: (revision: bigint) => Promise<void>;
}

const pct = (x: number) => `${(x * 100).toFixed(1)}%`;
const n = (x: bigint) => Number(x).toLocaleString();

/** "ARM:LE:32:v7" and mode "thumb" → "v7 · Thumb". */
export function variantLabel(languageId: string, mode: string): string {
  const parts = languageId.split(":");
  const variant = parts.length >= 4 ? parts.slice(3).join(":") : languageId;
  const order = parts[1] === "BE" ? " (big-endian)" : "";
  return `${variant}${order}${mode ? ` · ${mode[0].toUpperCase()}${mode.slice(1)}` : ""}`;
}

/** The fits in the order the table shows: the pick, the current language, then by how fully they decode. */
export function orderFits(fits: LanguageFit[]): LanguageFit[] {
  const score = (f: LanguageFit) => (f.recommended ? 2 : 0) + (f.current ? 1 : 0);
  return [...fits].sort(
    (a, b) =>
      score(b) - score(a) ||
      Number(a.reachedInvalid - b.reachedInvalid) ||
      Number(b.reached - a.reached) ||
      b.decoded - a.decoded ||
      a.languageId.localeCompare(b.languageId) ||
      a.mode.localeCompare(b.mode),
  );
}

export async function showLanguageDialog(rk: Revkit, o: LanguageOptions) {
  const restore = document.activeElement as HTMLElement | null;
  let current = "";
  let currentCompiler = "";
  try {
    const s = (await rk.projects.getProgramSummary({ programId: o.programId })).summary;
    current = s?.language?.languageId ?? "";
    currentCompiler = s?.language?.compilerSpecId ?? "";
  } catch (e) {
    toast(errText(e), { kind: "error" });
    return;
  }
  const processor = current.split(":")[0];
  let languages: AvailableLanguage[] = [];
  try {
    languages = (await rk.projects.listLanguages({})).languages.filter((l) => l.processor === processor && !l.deprecated);
  } catch {
    languages = [];
  }

  let chosen = current;
  const table = h("div", { class: "lang-table", role: "listbox", "aria-label": "Variants", "data-testid": "lang-table" }, h("div", { class: "dim lang-busy" }, "Comparing the variants on the program's code…"));
  const meta = h("div", { class: "lang-meta dim", "data-testid": "lang-meta" });
  const why = h("div", { class: "lang-why", "data-testid": "lang-why" });
  // While a switch runs: the program is analyzed again in the new language
  // before the call returns (as long as the import's analysis took).
  const progress = h("div", { class: "dim lang-busy", "data-testid": "lang-progress", hidden: true });
  const other = h(
    "select",
    { class: "filter select", "aria-label": "Any language of the processor", "data-testid": "lang-other" },
    ...languages.map((l) => h("option", { value: l.languageId }, `${l.languageId}${l.description ? ` — ${l.description}` : ""}`)),
  ) as HTMLSelectElement;
  const compiler = h("select", { class: "filter select", "aria-label": "Compiler spec", "data-testid": "lang-compiler" }) as HTMLSelectElement;
  const apply = h("button", { class: "btn primary", type: "button", "data-testid": "lang-apply", disabled: true, onclick: () => void switchTo() }, "Switch");
  const close = () => {
    backdrop.remove();
    restore?.focus({ preventScroll: true });
  };
  const back = h("button", { class: "btn", type: "button", "data-testid": "lang-imported", title: "Back to the language the program was imported with", onclick: () => void switchTo(true) }, "Imported language");
  const box = h(
    "div",
    { class: "modal lang", role: "dialog", "aria-modal": "true", tabindex: "-1", "aria-label": `Language of ${o.programName}`, "data-testid": "lang-dialog" },
    h("div", { class: "modal-title" }, `Language of ${o.programName}`),
    h("div", { class: "lang-current", "data-testid": "lang-current" }, h("span", { class: "dim" }, "Now "), h("span", { class: "mono" }, `${current}${currentCompiler ? `:${currentCompiler}` : ""}`)),
    h("div", { class: "lang-section-title" }, "Which variant fits the code"),
    table,
    meta,
    why,
    h("div", { class: "lang-pick" }, h("label", { class: "dim" }, "Language", other), h("label", { class: "dim" }, "Compiler", compiler)),
    progress,
    h("div", { class: "modal-hint" }, "The same bytes at the same addresses: names, comments and types stay, and analysis runs again in the new language. One undo step."),
    h("div", { class: "lang-buttons" }, back, h("span", { class: "spacer" }), h("button", { class: "btn", type: "button", "data-testid": "lang-cancel", onclick: close }, "Cancel"), apply),
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

  const compilersOf = (id: string) => languages.find((l) => l.languageId === id)?.compilerSpecIds ?? [];
  const choose = (id: string) => {
    chosen = id;
    if (other.value !== id && [...other.options].some((x) => x.value === id)) other.value = id;
    const cs = compilersOf(id);
    compiler.replaceChildren(...cs.map((c) => h("option", { value: c }, c)));
    if (id === current && cs.includes(currentCompiler)) compiler.value = currentCompiler;
    for (const r of table.querySelectorAll<HTMLElement>(".lang-row")) r.setAttribute("aria-selected", String(r.dataset.language === id));
    sync();
  };
  const sync = () => {
    const same = chosen === current && (compiler.value || currentCompiler) === currentCompiler;
    apply.disabled = same || !chosen;
    apply.textContent = same ? "Switch" : `Switch to ${variantLabel(chosen, "").replace(/ \(big-endian\)$/, "")}`;
  };
  other.addEventListener("change", () => choose(other.value));
  compiler.addEventListener("change", sync);
  choose(current);

  const switchTo = async (imported = false) => {
    apply.disabled = true;
    back.disabled = true;
    const target = imported ? "the imported language" : variantLabel(chosen, "").replace(/ \(big-endian\)$/, "");
    progress.textContent = `Switching to ${target}: analyzing the program again in it… (as long as its import took; Cancel only closes this)`;
    progress.hidden = false;
    try {
      const r = await rk.projects.setProgramLanguage({
        programId: o.programId,
        languageId: imported ? "" : chosen,
        compilerSpecId: imported ? "" : compiler.value,
        provenance: userProvenance(imported ? "back to the imported language" : `the code is ${chosen}`),
      });
      close();
      if (!r.assertion) {
        toast(imported ? "Already in the imported language" : "Already in that language");
        return;
      }
      const label = `Language ${r.previousLanguageId} → ${r.languageId || "as imported"}`;
      o.recordUndo(label, [r.assertion.seq]);
      // Analyzed in it already: the call returns once the analysis is done.
      toast(label, { action: { label: "Undo", run: () => o.undo() } });
      if (r.snapshot?.revision) await o.settle(r.snapshot.revision);
    } catch (e) {
      apply.disabled = false;
      back.disabled = false;
      progress.hidden = true;
      toast(errText(e), { kind: "error" });
    }
  };

  let fits: CompareLanguagesResponse;
  try {
    fits = await rk.projects.compareLanguages({ programId: o.programId });
  } catch (e) {
    table.replaceChildren(h("div", { class: "error" }, errText(e)));
    return;
  }
  const rows = orderFits(fits.fits);
  meta.textContent = `${n(fits.bytes)} bytes of code in ${fits.samples} samples, ${fits.elapsedSeconds.toFixed(1)} s`;
  const head = h(
    "div",
    { class: "lang-row lang-head", role: "presentation" },
    h("span", {}, "Variant"),
    h("span", {}, "Decoded"),
    h("span", { title: "Places nothing decodes" }, "Invalid"),
    h("span", { title: "Decoded, but the language has no semantics for them" }, "Unimpl."),
    h("span", { title: "Instructions branches and calls land on and run through" }, "Reached"),
    h("span", { title: "Reached runs cut short by bytes that don't decode" }, "Cut short"),
    h("span", {}, ""),
  );
  const pick = rows.find((f) => f.recommended);
  why.textContent = pick ? `Auto-detection picks ${variantLabel(pick.languageId, pick.mode)}: ${pick.note}` : "";
  table.replaceChildren(
    head,
    ...rows.map((f) => {
      const bar = h("span", { class: "lang-bar" }, h("span", { class: "lang-bar-fill", style: `width:${Math.round(f.decoded * 100)}%` }));
      const row = h(
        "div",
        {
          class: `lang-row${f.recommended ? " pick" : ""}${f.current ? " current" : ""}${f.compatible ? "" : " incompatible"}`,
          role: "option",
          tabindex: "0",
          "data-language": f.languageId,
          "data-testid": "lang-row",
          title: f.compatible ? f.description : `${f.description} — lays memory out differently: import the file again in it`,
        },
        h("span", { class: "mono lang-variant" }, variantLabel(f.languageId, f.mode)),
        h("span", { class: "lang-decoded" }, bar, h("span", { class: "mono" }, pct(f.decoded))),
        h("span", { class: `mono${f.invalid ? "" : " dim"}` }, n(f.invalid)),
        h("span", { class: `mono${f.unimplemented ? "" : " dim"}` }, n(f.unimplemented)),
        h("span", { class: "mono" }, n(f.reached)),
        h("span", { class: `mono${f.reachedInvalid ? " warn" : " dim"}` }, n(f.reachedInvalid)),
        h(
          "span",
          { class: "lang-badges" },
          f.recommended ? h("span", { class: "lang-chip pick", "data-testid": "lang-pick" }, "detection's pick") : null,
          f.current ? h("span", { class: "lang-chip", "data-testid": "lang-now" }, "current") : null,
        ),
      );
      if (f.compatible) {
        row.addEventListener("click", () => choose(f.languageId));
        row.addEventListener("keydown", (e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            choose(f.languageId);
          }
        });
      }
      return row;
    }),
  );
  choose(chosen);
}
