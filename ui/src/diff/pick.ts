// Picking a function of any program of the project (Compare with…, Match
// with…): a program, a name filter (the daemon's name_contains) and the
// first functions that match, best first: suggestions (a diff's candidates)
// above the rest. Arrow keys move, Enter or a click picks, Escape cancels.

import type { ProgramInfo, Revkit } from "@revkit/api";
import { errText, hex } from "../data/format";
import { h, overlayRoot } from "../ui/dom";

export interface PickedFunction {
  programId: string;
  entry: bigint;
  name: string;
}

export interface PickOptions {
  title: string;
  /** Programs to choose from (one: no choice). */
  programs: ProgramInfo[];
  program: string;
  /** Shown first, under "Suggested", while the filter is empty. */
  suggestions?: { entry: bigint; name: string; detail?: string }[];
  /** Left out of the list (the function compared from). */
  exclude?: { programId: string; entry: bigint };
  hint?: string;
  testid?: string;
}

export function pickFunction(rk: Revkit, o: PickOptions): Promise<PickedFunction | null> {
  return new Promise((resolve) => {
    const restore = document.activeElement as HTMLElement | null;
    const prog = h(
      "select",
      { class: "filter select", "aria-label": "Program", "data-testid": "pick-fn-program", disabled: o.programs.length < 2 },
      ...o.programs.map((p) => h("option", { value: p.programId }, `${p.name} (${p.programId})`)),
    );
    prog.value = o.program;
    const filter = h("input", { class: "filter", placeholder: "Function name contains", spellcheck: "false", "aria-label": "Function name", "data-testid": "pick-fn-filter" });
    const list = h("div", { class: "pick-fn-list", role: "listbox", "aria-label": "Functions", "data-testid": "pick-fn-list" });
    const status = h("div", { class: "dim pick-fn-status" });
    let items: { entry: bigint; name: string; detail: string }[] = [];
    let active = 0;
    let seq = 0;
    let timer = 0;
    /** The newest load: Enter right after typing waits for it. */
    let loading: Promise<void> = Promise.resolve();
    const paint = () => {
      list.replaceChildren(
        ...items.map((it, i) =>
          h(
            "div",
            { class: `palette-item${i === active ? " active" : ""}`, role: "option", "aria-selected": String(i === active), "data-i": i, "data-testid": "pick-fn-item" },
            h("span", { class: "pi-label" }, it.name),
            h("span", { class: "pi-detail dim" }, it.detail),
          ),
        ),
      );
      list.querySelector(".active")?.scrollIntoView({ block: "nearest" });
    };
    const load = async () => {
      const mine = ++seq;
      const query = filter.value.trim();
      const out: typeof items = [];
      const excluded = (e: bigint) => o.exclude?.programId === prog.value && o.exclude.entry === e;
      if (!query && prog.value === o.program)
        for (const s of o.suggestions ?? []) if (!excluded(s.entry)) out.push({ entry: s.entry, name: s.name, detail: s.detail ?? `suggested · ${hex(s.entry)}` });
      try {
        const r = await rk.queries.listFunctions({ programId: prog.value, nameContains: query, page: { pageSize: 60 } });
        if (mine !== seq) return;
        for (const f of r.functions) {
          const e = f.entry?.offset;
          if (e === undefined || excluded(e) || out.some((x) => x.entry === e)) continue;
          out.push({ entry: e, name: f.name, detail: hex(e) });
        }
        status.textContent = r.page?.totalCount && Number(r.page.totalCount) > r.functions.length ? `first ${r.functions.length} of ${r.page.totalCount}: type to narrow` : "";
      } catch (e) {
        if (mine === seq) status.textContent = errText(e);
      }
      items = out;
      active = 0;
      paint();
    };
    const box = h(
      "div",
      { class: "modal diff-dialog pick-fn", role: "dialog", "aria-label": o.title, "data-testid": o.testid ?? "pick-fn" },
      h("div", { class: "modal-title" }, o.title),
      prog,
      filter,
      list,
      status,
      o.hint ? h("div", { class: "modal-hint" }, o.hint) : null,
    );
    const backdrop = h("div", { class: "backdrop" }, box);
    const done = (v: PickedFunction | null) => {
      backdrop.remove();
      restore?.focus({ preventScroll: true });
      resolve(v);
    };
    const pick = (i: number) => {
      const it = items[i];
      if (it) done({ programId: prog.value, entry: it.entry, name: it.name });
    };
    const reload = () => {
      clearTimeout(timer);
      timer = 0;
      loading = load();
    };
    prog.addEventListener("change", reload);
    filter.addEventListener("input", () => {
      clearTimeout(timer);
      timer = window.setTimeout(reload, 120);
    });
    list.addEventListener("mousedown", (e) => {
      const row = (e.target as HTMLElement).closest<HTMLElement>("[data-i]");
      if (row) pick(Number(row.dataset.i));
    });
    box.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") done(null);
      else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        active = Math.max(0, Math.min(items.length - 1, active + (e.key === "ArrowDown" ? 1 : -1)));
        paint();
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (timer) reload();
        void loading.then(() => pick(active));
      }
    });
    backdrop.addEventListener("mousedown", (e) => {
      if (e.target === backdrop) done(null);
    });
    overlayRoot().append(backdrop);
    filter.focus();
    loading = load();
  });
}
